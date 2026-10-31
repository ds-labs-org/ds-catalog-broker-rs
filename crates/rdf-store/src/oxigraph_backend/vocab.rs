//! Fixed vocabulary terms.
//!
//! Constructed on demand rather than cached in a `static` - cheap to build,
//! and keeps this module free of `lazy_static`/`OnceLock` machinery for a
//! handful of constant IRIs, matching the style the JSON-blob version of
//! this module used for its own single `catalogJson` predicate.

use super::*;

pub(super) fn iri(value: impl Into<String>) -> NamedNode {
    NamedNode::new(value).expect("constant/percent-encoded IRI is valid")
}

pub(super) fn dcat(local: &str) -> NamedNode {
    iri(format!("{DCAT_NS}{local}"))
}

pub(super) fn dct(local: &str) -> NamedNode {
    iri(format!("{DCT_NS}{local}"))
}

pub(super) fn internal(local: &str) -> NamedNode {
    iri(format!("{INTERNAL_NS}{local}"))
}

pub(super) fn rdf_type() -> NamedNode {
    iri(RDF_TYPE_IRI)
}

pub(super) fn dcat_catalog_class() -> NamedNode {
    dcat("Catalog")
}

pub(super) fn dcat_dataset_class() -> NamedNode {
    dcat("Dataset")
}

pub(super) fn dcat_distribution_class() -> NamedNode {
    dcat("Distribution")
}

pub(super) fn dcat_data_service_class() -> NamedNode {
    dcat("DataService")
}

pub(super) fn dcat_dataset_pred() -> NamedNode {
    dcat("dataset")
}

pub(super) fn dcat_service_pred() -> NamedNode {
    dcat("service")
}

pub(super) fn dcat_distribution_pred() -> NamedNode {
    dcat("distribution")
}

pub(super) fn dcat_access_service_pred() -> NamedNode {
    dcat("accessService")
}

pub(super) fn dcat_endpoint_url_pred() -> NamedNode {
    dcat("endpointURL")
}

pub(super) fn dcat_endpoint_description_pred() -> NamedNode {
    dcat("endpointDescription")
}

pub(super) fn dct_format_pred() -> NamedNode {
    dct("format")
}

pub(super) fn participant_id_pred() -> NamedNode {
    internal("participantId")
}

pub(super) fn sequence_index_pred() -> NamedNode {
    internal("sequenceIndex")
}

pub(super) fn odrl(local: &str) -> NamedNode {
    iri(format!("{ODRL_NS}{local}"))
}

pub(super) fn odrl_has_policy_pred() -> NamedNode {
    odrl("hasPolicy")
}

pub(super) fn odrl_permission_pred() -> NamedNode {
    odrl("permission")
}

pub(super) fn odrl_prohibition_pred() -> NamedNode {
    odrl("prohibition")
}

pub(super) fn odrl_obligation_pred() -> NamedNode {
    odrl("obligation")
}

pub(super) fn odrl_action_pred() -> NamedNode {
    odrl("action")
}

pub(super) fn odrl_constraint_pred() -> NamedNode {
    odrl("constraint")
}

pub(super) fn odrl_left_operand_pred() -> NamedNode {
    odrl("leftOperand")
}

pub(super) fn odrl_operator_pred() -> NamedNode {
    odrl("operator")
}

pub(super) fn odrl_right_operand_pred() -> NamedNode {
    odrl("rightOperand")
}

pub(super) fn odrl_and_pred() -> NamedNode {
    odrl("and")
}

pub(super) fn odrl_or_pred() -> NamedNode {
    odrl("or")
}

pub(super) fn odrl_xone_pred() -> NamedNode {
    odrl("xone")
}

pub(super) fn odrl_and_sequence_pred() -> NamedNode {
    odrl("andSequence")
}

/// Constructor signature shared by [`Constraint::and`],
/// [`Constraint::or`], [`Constraint::xone`], and
/// [`Constraint::and_sequence`] - factored into a named alias purely
/// so [`logical_constraint_preds`]'s own type stays readable, mirroring
/// `crawler::LogicalConstraintBuilder`.
pub(super) type LogicalConstraintBuilder = fn(Vec<Constraint>) -> Constraint;

/// The four `odrl:`-namespaced logical-group predicates, each paired
/// with the `catalog_core::Constraint` constructor for that combinator,
/// in the same fixed precedence [`crawler::LOGICAL_CONSTRAINT_KEYS`]
/// uses when parsing (`xone`, then `or`, then `and`, then
/// `andSequence`): [`OxigraphCatalogCache::load_constraint`] checks
/// them in this order, so a hand-crafted constraint resource carrying
/// more than one (malformed - this store's own write path only ever
/// emits one) is at least read back the same way `crawler` would parse
/// the equivalent malformed JSON-LD, rather than an arbitrary one.
pub(super) fn logical_constraint_preds() -> [(NamedNode, LogicalConstraintBuilder); 4] {
    [
        (odrl_xone_pred(), Constraint::xone),
        (odrl_or_pred(), Constraint::or),
        (odrl_and_pred(), Constraint::and),
        (odrl_and_sequence_pred(), Constraint::and_sequence),
    ]
}

pub(super) fn odrl_assigner_pred() -> NamedNode {
    odrl("assigner")
}

pub(super) fn odrl_assignee_pred() -> NamedNode {
    odrl("assignee")
}

/// `Policy.id`'s literal home - see the `oxigraph_backend` module doc's "Triples emitted"
/// section (policy resource bullets) for why this is a fallback
/// `fcns:` term rather than an ODRL one.
pub(super) fn policy_id_pred() -> NamedNode {
    internal("policyId")
}

/// The `odrl:<Kind>` class matching a [`PolicyKind`].
pub(super) fn odrl_policy_class(kind: PolicyKind) -> NamedNode {
    match kind {
        PolicyKind::Set => odrl("Set"),
        PolicyKind::Offer => odrl("Offer"),
        PolicyKind::Agreement => odrl("Agreement"),
    }
}

/// Inverse of [`odrl_policy_class`]: which [`PolicyKind`] a policy
/// resource's `rdf:type` object names.
pub(super) fn policy_kind_from_class(class: &NamedNode) -> StoreResult<PolicyKind> {
    if *class == odrl_policy_class(PolicyKind::Set) {
        Ok(PolicyKind::Set)
    } else if *class == odrl_policy_class(PolicyKind::Offer) {
        Ok(PolicyKind::Offer)
    } else if *class == odrl_policy_class(PolicyKind::Agreement) {
        Ok(PolicyKind::Agreement)
    } else {
        Err(StoreError::Backend(format!(
            "unrecognized ODRL policy type IRI: {}",
            class.as_str()
        )))
    }
}

/// The key/value-property fallback predicate for a key that isn't
/// already an absolute IRI - see the `oxigraph_backend` module doc's "Generic properties".
pub(super) fn property_predicate(key: &str) -> NamedNode {
    if let Ok(existing) = NamedNode::new(key) {
        existing
    } else {
        iri(format!(
            "{INTERNAL_PROPERTY_PREFIX}{}",
            urlencoding::encode(key)
        ))
    }
}

/// Inverse of [`property_predicate`]: recover the original property key
/// from a predicate IRI.
pub(super) fn decode_property_key(pred: &NamedNode) -> String {
    match pred.as_str().strip_prefix(INTERNAL_PROPERTY_PREFIX) {
        Some(rest) => urlencoding::decode(rest)
            .map(|cow| cow.into_owned())
            .unwrap_or_else(|_| rest.to_string()),
        None => pred.as_str().to_string(),
    }
}
