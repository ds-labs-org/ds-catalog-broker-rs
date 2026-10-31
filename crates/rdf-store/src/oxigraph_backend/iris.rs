//! Resource IRI construction, and decoding terms read back from the store.

use super::*;

/// The base IRI for `node`'s named graph, also the prefix every
/// resource IRI within that graph is built from. Percent-encoding the
/// node id guarantees a valid IRI regardless of what characters the id
/// contains.
pub(super) fn node_base(node: &NodeId) -> String {
    format!("{NODE_NS}{}", urlencoding::encode(&node.0))
}

/// The subject / named-graph IRI for `node`.
pub(super) fn node_iri(node: &NodeId) -> NamedNode {
    iri(node_base(node))
}

pub(super) fn catalog_iri(node_base: &str, catalog_id: &str) -> NamedNode {
    iri(format!(
        "{node_base}/catalogs/{}",
        urlencoding::encode(catalog_id)
    ))
}

pub(super) fn dataset_iri(node_base: &str, dataset_id: &str) -> NamedNode {
    iri(format!(
        "{node_base}/datasets/{}",
        urlencoding::encode(dataset_id)
    ))
}

/// The stable resource IRI a harvested dataset is stored under in this
/// store's semantic cache - the exact string a `?x a dcat:Dataset`
/// SPARQL binding for that dataset resolves to (see this module's own
/// doc comment, "Resource IRIs"). Exposed publicly (unlike the private
/// [`dataset_iri`] this wraps) so a caller layering per-caller ODRL
/// policy filtering on top of
/// [`OxigraphCatalogCache::sparql_query_json_restricted`] (gap analysis
/// §3.4's SPARQL surface, in `ds-catalog-broker-rs`) can compute the
/// same allow-list of visible dataset IRIs this store itself would
/// produce, from the same
/// `NodeId`/dataset-id pairs `CatalogCache::query` already hands back,
/// without duplicating this module's own IRI-construction scheme (or
/// - worse - re-deriving it from a printed/re-parsed IRI string).
pub fn dataset_resource_iri(node: &NodeId, dataset_id: &str) -> String {
    dataset_iri(&node_base(node), dataset_id).into_string()
}

pub(super) fn distribution_iri(node_base: &str, dataset_id: &str, index: usize) -> NamedNode {
    iri(format!(
        "{node_base}/datasets/{}/distributions/{index}",
        urlencoding::encode(dataset_id)
    ))
}

pub(super) fn service_iri(node_base: &str, service_id: &str) -> NamedNode {
    iri(format!(
        "{node_base}/services/{}",
        urlencoding::encode(service_id)
    ))
}

/// The stable resource IRI a harvested data service is stored under -
/// the service counterpart of [`dataset_resource_iri`], for building
/// the allow-list [`OxigraphCatalogCache::sparql_query_json_restricted`]
/// takes.
pub fn service_resource_iri(node: &NodeId, service_id: &str) -> String {
    service_iri(&node_base(node), service_id).into_string()
}

pub(super) fn policy_iri(node_base: &str, dataset_id: &str, index: usize) -> NamedNode {
    iri(format!(
        "{node_base}/datasets/{}/policies/{index}",
        urlencoding::encode(dataset_id)
    ))
}

/// A permission/prohibition/obligation resource IRI - `segment` is
/// `"permissions"`, `"prohibitions"`, or `"obligations"` (see the
/// module doc's "Resource IRIs").
pub(super) fn rule_iri(policy_iri: &str, segment: &str, index: usize) -> NamedNode {
    iri(format!("{policy_iri}/{segment}/{index}"))
}

pub(super) fn constraint_iri(rule_iri: &str, index: usize) -> NamedNode {
    iri(format!("{rule_iri}/constraints/{index}"))
}

/// Strip `prefix` off `iri` and percent-decode the remainder - the
/// inverse of how every resource IRI above was built from an id.
pub(super) fn strip_prefix_decode(iri: &str, prefix: &str) -> StoreResult<String> {
    let rest = iri.strip_prefix(prefix).ok_or_else(|| {
        StoreError::Backend(format!("expected IRI '{iri}' to start with '{prefix}'"))
    })?;
    urlencoding::decode(rest)
        .map(|cow| cow.into_owned())
        .map_err(|e| StoreError::Backend(format!("invalid percent-encoding in '{iri}': {e}")))
}

pub(super) fn decode_node_id(graph_iri: &NamedNode) -> StoreResult<NodeId> {
    strip_prefix_decode(graph_iri.as_str(), NODE_NS).map(NodeId::new)
}

/// `value` as an IRI object when it parses as one, falling back to a
/// plain string literal when it doesn't - defensive, since every
/// caller of this helper is feeding it crawled/harvested data this
/// store should never reject for being the "wrong" shape. Originally
/// written just for `dcat:endpointURL` (the faithful DCAT reading of
/// its `rdfs:Resource` range); reused unchanged for the ODRL mapping's
/// `odrl:assigner`/`odrl:assignee`/`odrl:action`/`odrl:leftOperand`/
/// `odrl:operator` (see the module doc's "Triples emitted" section) -
/// none of those give a stronger guarantee than `endpoint_url` did
/// that a harvested value is already IRI-shaped.
pub(super) fn iri_or_literal_term(value: &str) -> Term {
    match NamedNode::new(value) {
        Ok(node) => Term::from(node),
        Err(_) => Term::from(Literal::from(value.to_string())),
    }
}

/// A literal's lexical value, or a `NamedNode`'s IRI string - covers
/// both shapes [`iri_or_literal_term`] can produce, so loading is
/// agnostic to which one a given stored value took.
pub(super) fn term_as_string(term: &Term) -> StoreResult<String> {
    match term {
        Term::Literal(lit) => Ok(lit.value().to_string()),
        Term::NamedNode(node) => Ok(node.as_str().to_string()),
        other => Err(StoreError::Backend(format!(
            "expected a literal or IRI term, got {other:?}"
        ))),
    }
}

pub(super) fn expect_named_node(term: Term, context: &str) -> StoreResult<NamedNode> {
    match term {
        Term::NamedNode(node) => Ok(node),
        other => Err(StoreError::Backend(format!(
            "expected a named node for {context}, got {other:?}"
        ))),
    }
}
