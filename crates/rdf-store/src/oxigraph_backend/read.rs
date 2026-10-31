//! Reconstructing a [`Catalog`] from the quads in its named graph.

use super::*;

impl OxigraphCatalogCache {
    /// Reconstruct the [`Catalog`] stored in `graph` for `node`, if any
    /// (`None` when the graph holds no `dcat:Catalog` resource at all -
    /// i.e. nothing has ever been upserted for this node).
    pub(super) fn load_catalog(
        &self,
        node: &NodeId,
        graph: &NamedNode,
    ) -> StoreResult<Option<Catalog>> {
        let base = node_base(node);
        let catalog_class_term = Term::from(dcat_catalog_class());
        let type_pred = rdf_type();

        let Some(first) = self
            .quads(None, Some(&type_pred), Some(&catalog_class_term), graph)?
            .into_iter()
            .next()
        else {
            return Ok(None);
        };
        let catalog_subject = match first.subject {
            NamedOrBlankNode::NamedNode(node) => node,
            NamedOrBlankNode::BlankNode(_) => {
                return Err(StoreError::Backend(
                    "catalog subject must be a named node".to_string(),
                ));
            }
        };
        let catalog_id =
            strip_prefix_decode(catalog_subject.as_str(), &format!("{base}/catalogs/"))?;

        let participant_id = self
            .first_object(&catalog_subject, &participant_id_pred(), graph)?
            .as_ref()
            .map(term_as_string)
            .transpose()?;

        let dataset_pred = dcat_dataset_pred();
        let service_pred = dcat_service_pred();

        let reserved_catalog_preds = [
            type_pred.clone(),
            participant_id_pred(),
            dataset_pred.clone(),
            service_pred.clone(),
        ];
        let mut properties = BTreeMap::new();
        for quad in self.quads(Some(&catalog_subject), None, None, graph)? {
            if reserved_catalog_preds.contains(&quad.predicate) {
                continue;
            }
            properties.insert(
                decode_property_key(&quad.predicate),
                term_as_string(&quad.object)?,
            );
        }

        let mut dataset_entries = Vec::new();
        for quad in self.quads(Some(&catalog_subject), Some(&dataset_pred), None, graph)? {
            let dataset_subject = expect_named_node(quad.object, "a dcat:dataset reference")?;
            dataset_entries.push(self.load_dataset(&base, &dataset_subject, graph)?);
        }
        dataset_entries.sort_by_key(|(index, _)| *index);
        let datasets = dataset_entries
            .into_iter()
            .map(|(_, dataset)| dataset)
            .collect();

        let mut service_entries = Vec::new();
        for quad in self.quads(Some(&catalog_subject), Some(&service_pred), None, graph)? {
            let service_subject = expect_named_node(quad.object, "a dcat:service reference")?;
            service_entries.push(self.load_data_service(&base, &service_subject, graph)?);
        }
        service_entries.sort_by_key(|(index, _)| *index);
        let data_services = service_entries
            .into_iter()
            .map(|(_, service)| service)
            .collect();

        Ok(Some(Catalog {
            id: catalog_id,
            origin_node: node.clone(),
            participant_id,
            datasets,
            data_services,
            properties,
        }))
    }

    pub(super) fn load_dataset(
        &self,
        base: &str,
        subject: &NamedNode,
        graph: &NamedNode,
    ) -> StoreResult<(usize, Dataset)> {
        let id = strip_prefix_decode(subject.as_str(), &format!("{base}/datasets/"))?;
        let index = self.sequence_index(subject, graph)?;
        let distribution_pred = dcat_distribution_pred();

        let mut distribution_entries = Vec::new();
        for quad in self.quads(Some(subject), Some(&distribution_pred), None, graph)? {
            let distribution_subject =
                expect_named_node(quad.object, "a dcat:distribution reference")?;
            distribution_entries.push(self.load_distribution(
                base,
                &distribution_subject,
                graph,
            )?);
        }
        distribution_entries.sort_by_key(|(index, _)| *index);
        let distributions = distribution_entries
            .into_iter()
            .map(|(_, distribution)| distribution)
            .collect();

        let has_policy_pred = odrl_has_policy_pred();
        let mut policy_entries = Vec::new();
        for quad in self.quads(Some(subject), Some(&has_policy_pred), None, graph)? {
            let policy_subject = expect_named_node(quad.object, "an odrl:hasPolicy reference")?;
            policy_entries.push(self.load_policy(&policy_subject, graph)?);
        }
        policy_entries.sort_by_key(|(index, _)| *index);
        let policies = policy_entries
            .into_iter()
            .map(|(_, policy)| policy)
            .collect();

        let reserved = [
            rdf_type(),
            sequence_index_pred(),
            distribution_pred,
            has_policy_pred,
        ];
        let mut properties = BTreeMap::new();
        for quad in self.quads(Some(subject), None, None, graph)? {
            if reserved.contains(&quad.predicate) {
                continue;
            }
            properties.insert(
                decode_property_key(&quad.predicate),
                term_as_string(&quad.object)?,
            );
        }

        Ok((
            index,
            Dataset {
                id,
                properties,
                distributions,
                policies,
            },
        ))
    }

    pub(super) fn load_policy(
        &self,
        subject: &NamedNode,
        graph: &NamedNode,
    ) -> StoreResult<(usize, Policy)> {
        let index = self.sequence_index(subject, graph)?;
        let kind_term = self
            .first_object(subject, &rdf_type(), graph)?
            .ok_or_else(|| {
                StoreError::Backend(format!("{} is missing rdf:type", subject.as_str()))
            })?;
        let kind_node = expect_named_node(kind_term, "a policy's rdf:type")?;
        let kind = policy_kind_from_class(&kind_node)?;

        let id = self
            .first_object(subject, &policy_id_pred(), graph)?
            .as_ref()
            .map(term_as_string)
            .transpose()?;
        let assigner = self
            .first_object(subject, &odrl_assigner_pred(), graph)?
            .as_ref()
            .map(term_as_string)
            .transpose()?;
        let assignee = self
            .first_object(subject, &odrl_assignee_pred(), graph)?
            .as_ref()
            .map(term_as_string)
            .transpose()?;

        let permissions = self.load_rules(subject, &odrl_permission_pred(), graph)?;
        let prohibitions = self.load_rules(subject, &odrl_prohibition_pred(), graph)?;
        let obligations = self.load_rules(subject, &odrl_obligation_pred(), graph)?;

        Ok((
            index,
            Policy {
                id,
                kind,
                assigner,
                assignee,
                permissions,
                prohibitions,
                obligations,
            },
        ))
    }

    /// Every rule (permission/prohibition/obligation, depending on
    /// `predicate`) attached to `policy_subject`, sorted by
    /// `fcns:sequenceIndex`.
    pub(super) fn load_rules(
        &self,
        policy_subject: &NamedNode,
        predicate: &NamedNode,
        graph: &NamedNode,
    ) -> StoreResult<Vec<Rule>> {
        let mut entries = Vec::new();
        for quad in self.quads(Some(policy_subject), Some(predicate), None, graph)? {
            let rule_subject = expect_named_node(quad.object, "an odrl rule reference")?;
            entries.push(self.load_rule(&rule_subject, graph)?);
        }
        entries.sort_by_key(|(index, _)| *index);
        Ok(entries.into_iter().map(|(_, rule)| rule).collect())
    }

    pub(super) fn load_rule(
        &self,
        subject: &NamedNode,
        graph: &NamedNode,
    ) -> StoreResult<(usize, Rule)> {
        let index = self.sequence_index(subject, graph)?;
        let action = self
            .first_object(subject, &odrl_action_pred(), graph)?
            .as_ref()
            .map(term_as_string)
            .transpose()?
            .ok_or_else(|| {
                StoreError::Backend(format!("{} is missing odrl:action", subject.as_str()))
            })?;

        let constraint_pred = odrl_constraint_pred();
        let mut constraint_entries = Vec::new();
        for quad in self.quads(Some(subject), Some(&constraint_pred), None, graph)? {
            let constraint_subject =
                expect_named_node(quad.object, "an odrl:constraint reference")?;
            // 0: a rule's own top-level constraints are depth 0 - see
            // [`write_constraint`]'s doc comment for the numbering.
            constraint_entries.push(self.load_constraint(&constraint_subject, graph, 0)?);
        }
        constraint_entries.sort_by_key(|(index, _)| *index);
        let constraints = constraint_entries
            .into_iter()
            .map(|(_, constraint)| constraint)
            .collect();

        Ok((
            index,
            Rule {
                action,
                constraints,
            },
        ))
    }

    /// Load the constraint at `subject`, atomic or logical, at `depth`
    /// levels of logical nesting below its rule's own top-level
    /// `constraint` list (0 for a top-level entry - matches
    /// [`write_constraint`]'s own numbering). Dispatches on which
    /// shape `subject` actually carries: `odrl:leftOperand` present
    /// means atomic (the existing, pre-logical-support behavior,
    /// unchanged); otherwise, whichever of
    /// [`logical_constraint_preds`]'s four predicates `subject` carries
    /// means logical, with that predicate's linked children loaded
    /// recursively (sorted by their own `fcns:sequenceIndex`, the same
    /// ordering bookkeeping every other list in this store uses - see
    /// the module doc's "Ordering" section) and re-wrapped in the
    /// matching combinator.
    pub(super) fn load_constraint(
        &self,
        subject: &NamedNode,
        graph: &NamedNode,
        depth: usize,
    ) -> StoreResult<(usize, Constraint)> {
        if depth > MAX_CONSTRAINT_DEPTH {
            return Err(StoreError::Backend(format!(
                "{} is nested past the maximum supported logical constraint depth ({MAX_CONSTRAINT_DEPTH})",
                subject.as_str()
            )));
        }
        let index = self.sequence_index(subject, graph)?;

        if let Some(left_operand_term) =
            self.first_object(subject, &odrl_left_operand_pred(), graph)?
        {
            let left_operand = term_as_string(&left_operand_term)?;
            let operator = self
                .first_object(subject, &odrl_operator_pred(), graph)?
                .as_ref()
                .map(term_as_string)
                .transpose()?
                .ok_or_else(|| {
                    StoreError::Backend(format!("{} is missing odrl:operator", subject.as_str()))
                })?;
            let right_operand = self
                .first_object(subject, &odrl_right_operand_pred(), graph)?
                .as_ref()
                .map(term_as_string)
                .transpose()?
                .ok_or_else(|| {
                    StoreError::Backend(format!(
                        "{} is missing odrl:rightOperand",
                        subject.as_str()
                    ))
                })?;

            return Ok((
                index,
                Constraint::atomic(left_operand, operator, right_operand),
            ));
        }

        for (predicate, build) in logical_constraint_preds() {
            let child_quads = self.quads(Some(subject), Some(&predicate), None, graph)?;
            if child_quads.is_empty() {
                continue;
            }
            let mut child_entries = Vec::new();
            for quad in child_quads {
                let child_subject =
                    expect_named_node(quad.object, "a logical constraint child reference")?;
                child_entries.push(self.load_constraint(&child_subject, graph, depth + 1)?);
            }
            child_entries.sort_by_key(|(index, _)| *index);
            let children = child_entries.into_iter().map(|(_, c)| c).collect();
            return Ok((index, build(children)));
        }

        Err(StoreError::Backend(format!(
            "{} is missing odrl:leftOperand and carries none of odrl:and/odrl:or/odrl:xone/odrl:andSequence",
            subject.as_str()
        )))
    }

    pub(super) fn load_distribution(
        &self,
        base: &str,
        subject: &NamedNode,
        graph: &NamedNode,
    ) -> StoreResult<(usize, Distribution)> {
        let index = self.sequence_index(subject, graph)?;
        let format = self
            .first_object(subject, &dct_format_pred(), graph)?
            .as_ref()
            .map(term_as_string)
            .transpose()?
            .ok_or_else(|| {
                StoreError::Backend(format!("{} is missing dct:format", subject.as_str()))
            })?;
        let access_service_term = self
            .first_object(subject, &dcat_access_service_pred(), graph)?
            .ok_or_else(|| {
                StoreError::Backend(format!(
                    "{} is missing dcat:accessService",
                    subject.as_str()
                ))
            })?;
        let access_service_node =
            expect_named_node(access_service_term, "dcat:accessService's object")?;
        let access_service =
            strip_prefix_decode(access_service_node.as_str(), &format!("{base}/services/"))?;

        Ok((
            index,
            Distribution {
                format,
                access_service,
            },
        ))
    }

    pub(super) fn load_data_service(
        &self,
        base: &str,
        subject: &NamedNode,
        graph: &NamedNode,
    ) -> StoreResult<(usize, DataService)> {
        let id = strip_prefix_decode(subject.as_str(), &format!("{base}/services/"))?;
        let index = self.sequence_index(subject, graph)?;
        let endpoint_url = self
            .first_object(subject, &dcat_endpoint_url_pred(), graph)?
            .as_ref()
            .map(term_as_string)
            .transpose()?
            .ok_or_else(|| {
                StoreError::Backend(format!("{} is missing dcat:endpointURL", subject.as_str()))
            })?;
        let endpoint_description = self
            .first_object(subject, &dcat_endpoint_description_pred(), graph)?
            .as_ref()
            .map(term_as_string)
            .transpose()?;

        Ok((
            index,
            DataService {
                id,
                endpoint_url,
                endpoint_description,
            },
        ))
    }
}
