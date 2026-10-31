//! Writing a [`Catalog`] into its named graph as decomposed RDF quads.

use super::*;

impl OxigraphCatalogCache {
    /// Write every triple for `catalog` into `graph` - see the
    /// `oxigraph_backend` module doc for the exact mapping.
    pub(super) fn write_catalog(&self, catalog: &Catalog, graph: &NamedNode) -> StoreResult<()> {
        let base = node_base(&catalog.origin_node);
        let catalog_node = catalog_iri(&base, &catalog.id);

        self.insert(
            &catalog_node,
            &rdf_type(),
            &Term::from(dcat_catalog_class()),
            graph,
        )?;

        if let Some(participant_id) = &catalog.participant_id {
            self.insert(
                &catalog_node,
                &participant_id_pred(),
                &Term::from(Literal::from(participant_id.clone())),
                graph,
            )?;
        }

        for (key, value) in &catalog.properties {
            self.insert(
                &catalog_node,
                &property_predicate(key),
                &Term::from(Literal::from(value.clone())),
                graph,
            )?;
        }

        for (index, dataset) in catalog.datasets.iter().enumerate() {
            let dataset_node = dataset_iri(&base, &dataset.id);
            self.insert(
                &catalog_node,
                &dcat_dataset_pred(),
                &Term::from(dataset_node.clone()),
                graph,
            )?;
            self.insert(
                &dataset_node,
                &rdf_type(),
                &Term::from(dcat_dataset_class()),
                graph,
            )?;
            self.insert(
                &dataset_node,
                &sequence_index_pred(),
                &Term::from(Literal::from(index as i64)),
                graph,
            )?;

            for (key, value) in &dataset.properties {
                self.insert(
                    &dataset_node,
                    &property_predicate(key),
                    &Term::from(Literal::from(value.clone())),
                    graph,
                )?;
            }

            for (dist_index, distribution) in dataset.distributions.iter().enumerate() {
                let distribution_node = distribution_iri(&base, &dataset.id, dist_index);
                self.insert(
                    &dataset_node,
                    &dcat_distribution_pred(),
                    &Term::from(distribution_node.clone()),
                    graph,
                )?;
                self.insert(
                    &distribution_node,
                    &rdf_type(),
                    &Term::from(dcat_distribution_class()),
                    graph,
                )?;
                self.insert(
                    &distribution_node,
                    &sequence_index_pred(),
                    &Term::from(Literal::from(dist_index as i64)),
                    graph,
                )?;
                self.insert(
                    &distribution_node,
                    &dct_format_pred(),
                    &Term::from(Literal::from(distribution.format.clone())),
                    graph,
                )?;
                let access_service_node = service_iri(&base, &distribution.access_service);
                self.insert(
                    &distribution_node,
                    &dcat_access_service_pred(),
                    &Term::from(access_service_node),
                    graph,
                )?;
            }

            for (policy_index, policy) in dataset.policies.iter().enumerate() {
                let policy_node = policy_iri(&base, &dataset.id, policy_index);
                self.insert(
                    &dataset_node,
                    &odrl_has_policy_pred(),
                    &Term::from(policy_node.clone()),
                    graph,
                )?;
                self.write_policy(policy, &policy_node, policy_index, graph)?;
            }
        }

        for (index, service) in catalog.data_services.iter().enumerate() {
            let service_node = service_iri(&base, &service.id);
            self.insert(
                &catalog_node,
                &dcat_service_pred(),
                &Term::from(service_node.clone()),
                graph,
            )?;
            self.insert(
                &service_node,
                &rdf_type(),
                &Term::from(dcat_data_service_class()),
                graph,
            )?;
            self.insert(
                &service_node,
                &sequence_index_pred(),
                &Term::from(Literal::from(index as i64)),
                graph,
            )?;
            self.insert(
                &service_node,
                &dcat_endpoint_url_pred(),
                &iri_or_literal_term(&service.endpoint_url),
                graph,
            )?;
            if let Some(description) = &service.endpoint_description {
                self.insert(
                    &service_node,
                    &dcat_endpoint_description_pred(),
                    &Term::from(Literal::from(description.clone())),
                    graph,
                )?;
            }
        }

        Ok(())
    }

    /// Write every triple for one harvested `policy` into `policy_node`.
    /// See the `oxigraph_backend` module doc's "Triples emitted" section (policy resource
    /// bullets) for the exact mapping.
    pub(super) fn write_policy(
        &self,
        policy: &Policy,
        policy_node: &NamedNode,
        index: usize,
        graph: &NamedNode,
    ) -> StoreResult<()> {
        self.insert(
            policy_node,
            &rdf_type(),
            &Term::from(odrl_policy_class(policy.kind)),
            graph,
        )?;
        self.insert(
            policy_node,
            &sequence_index_pred(),
            &Term::from(Literal::from(index as i64)),
            graph,
        )?;
        if let Some(id) = &policy.id {
            self.insert(
                policy_node,
                &policy_id_pred(),
                &Term::from(Literal::from(id.clone())),
                graph,
            )?;
        }
        if let Some(assigner) = &policy.assigner {
            self.insert(
                policy_node,
                &odrl_assigner_pred(),
                &iri_or_literal_term(assigner),
                graph,
            )?;
        }
        if let Some(assignee) = &policy.assignee {
            self.insert(
                policy_node,
                &odrl_assignee_pred(),
                &iri_or_literal_term(assignee),
                graph,
            )?;
        }

        self.write_rules(
            &policy.permissions,
            policy_node,
            &odrl_permission_pred(),
            "permissions",
            graph,
        )?;
        self.write_rules(
            &policy.prohibitions,
            policy_node,
            &odrl_prohibition_pred(),
            "prohibitions",
            graph,
        )?;
        self.write_rules(
            &policy.obligations,
            policy_node,
            &odrl_obligation_pred(),
            "obligations",
            graph,
        )?;
        Ok(())
    }

    /// Write one permission/prohibition/obligation list (`rules`) of
    /// `policy_node`, linked via `predicate` and identified under
    /// `segment` (see [`rule_iri`]).
    pub(super) fn write_rules(
        &self,
        rules: &[Rule],
        policy_node: &NamedNode,
        predicate: &NamedNode,
        segment: &str,
        graph: &NamedNode,
    ) -> StoreResult<()> {
        for (index, rule) in rules.iter().enumerate() {
            let rule_node = rule_iri(policy_node.as_str(), segment, index);
            self.insert(
                policy_node,
                predicate,
                &Term::from(rule_node.clone()),
                graph,
            )?;
            self.write_rule(rule, &rule_node, index, graph)?;
        }
        Ok(())
    }

    pub(super) fn write_rule(
        &self,
        rule: &Rule,
        rule_node: &NamedNode,
        index: usize,
        graph: &NamedNode,
    ) -> StoreResult<()> {
        self.insert(
            rule_node,
            &sequence_index_pred(),
            &Term::from(Literal::from(index as i64)),
            graph,
        )?;
        self.insert(
            rule_node,
            &odrl_action_pred(),
            &iri_or_literal_term(&rule.action),
            graph,
        )?;
        for (index, constraint) in rule.constraints.iter().enumerate() {
            let constraint_node = constraint_iri(rule_node.as_str(), index);
            self.insert(
                rule_node,
                &odrl_constraint_pred(),
                &Term::from(constraint_node.clone()),
                graph,
            )?;
            // 0: a rule's own top-level constraints are depth 0, the
            // same numbering `crawler::parse_constraint` uses for a
            // rule's top-level `constraint` entries.
            self.write_constraint(constraint, &constraint_node, index, 0, graph)?;
        }
        Ok(())
    }

    /// Write every triple for one `constraint` (atomic or logical,
    /// arbitrarily nested) into `constraint_node`, at `index` among its
    /// own siblings and `depth` levels of logical nesting below its
    /// rule's own top-level `constraint` list (0 for a top-level
    /// entry - see [`write_rule`]). `rightOperand` is always written as
    /// a plain literal, never through [`iri_or_literal_term`] - see the
    /// `oxigraph_backend` module doc's "Triples emitted" section (constraint resource
    /// bullets) for why.
    ///
    /// A [`Constraint::Logical`] writes one `odrl:and`/`odrl:or`/
    /// `odrl:xone`/`odrl:andSequence` link triple per child (matching
    /// the combinator), then recurses into [`write_constraint`] for
    /// each child at `depth + 1` - see the `oxigraph_backend` module doc's "Logical
    /// constraint groups" note. Bounded by [`MAX_CONSTRAINT_DEPTH`]: a
    /// child that would be written past the bound is skipped entirely,
    /// including its link triple, so no dangling/incomplete constraint
    /// resource is ever left in the graph - mirroring
    /// `crawler::parse_constraint` dropping an over-deep entry from the
    /// parsed `Vec` outright rather than including a truncated one.
    pub(super) fn write_constraint(
        &self,
        constraint: &Constraint,
        constraint_node: &NamedNode,
        index: usize,
        depth: usize,
        graph: &NamedNode,
    ) -> StoreResult<()> {
        self.insert(
            constraint_node,
            &sequence_index_pred(),
            &Term::from(Literal::from(index as i64)),
            graph,
        )?;
        match constraint {
            Constraint::Atomic(atomic) => {
                self.insert(
                    constraint_node,
                    &odrl_left_operand_pred(),
                    &iri_or_literal_term(&atomic.left_operand),
                    graph,
                )?;
                self.insert(
                    constraint_node,
                    &odrl_operator_pred(),
                    &iri_or_literal_term(&atomic.operator),
                    graph,
                )?;
                self.insert(
                    constraint_node,
                    &odrl_right_operand_pred(),
                    &Term::from(Literal::from(atomic.right_operand.clone())),
                    graph,
                )?;
            }
            Constraint::Logical(logical) => {
                // A child would be written at `depth + 1`; skip the
                // whole remaining sibling list once that would exceed
                // the bound (uniform across siblings - see this fn's
                // own doc comment) rather than writing a partially
                // truncated group.
                if depth >= MAX_CONSTRAINT_DEPTH {
                    return Ok(());
                }
                let (predicate, children): (NamedNode, &[Constraint]) = match logical {
                    LogicalConstraint::And(children) => (odrl_and_pred(), children),
                    LogicalConstraint::Or(children) => (odrl_or_pred(), children),
                    LogicalConstraint::Xone(children) => (odrl_xone_pred(), children),
                    LogicalConstraint::AndSequence(children) => {
                        (odrl_and_sequence_pred(), children)
                    }
                };
                for (child_index, child) in children.iter().enumerate() {
                    let child_node = constraint_iri(constraint_node.as_str(), child_index);
                    self.insert(
                        constraint_node,
                        &predicate,
                        &Term::from(child_node.clone()),
                        graph,
                    )?;
                    self.write_constraint(child, &child_node, child_index, depth + 1, graph)?;
                }
            }
        }
        Ok(())
    }
}
