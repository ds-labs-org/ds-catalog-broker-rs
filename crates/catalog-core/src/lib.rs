//! Minimal domain types for the federated catalog rewrite.
//!
//! Modeled loosely on Eclipse EDC's `federated-catalog-spi` / `catalog-spi`
//! Java modules, but deliberately smaller: only what the `rdf-store` cache
//! trait needs to operate on. This is not a port - fields and shapes are a
//! from-scratch Rust design, not a transliteration of the Java classes.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Identifier of a dataspace participant / crawl target node.
///
/// Corresponds to the `id` field of EDC's `TargetNode` record
/// (spi/crawler-spi).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId(pub String);

impl NodeId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A participant known to the crawler: enough to address it and pick a
/// protocol to speak.
///
/// Analogous to EDC's `TargetNode` record (spi/crawler-spi).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetNode {
    pub id: NodeId,
    pub name: String,
    pub target_url: String,
    pub supported_protocols: Vec<String>,
}

/// One unit of crawl work: a target node plus how many times it has
/// already been retried in the current cycle.
///
/// EDC has no standalone `WorkItem` type at v0.18.0 - the equivalent is a
/// private `TargetNodeRetryCount` record local to `CatalogCrawlerManager`,
/// scoped to a single crawl attempt. It's promoted to a first-class,
/// public type here because a from-scratch design is free to name it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrawlWorkItem {
    pub node: TargetNode,
    pub retries: u32,
}

impl CrawlWorkItem {
    pub fn new(node: TargetNode) -> Self {
        Self { node, retries: 0 }
    }
}

/// One concrete access method for a dataset: a data-plane endpoint plus
/// the format it serves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Distribution {
    pub format: String,
    pub access_service: String,
}

/// A dataspace protocol-facing description of a data service (e.g. a
/// connector's DSP endpoint).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataService {
    pub id: String,
    pub endpoint_url: String,
    #[serde(default)]
    pub endpoint_description: Option<String>,
}

/// The ODRL `@type` of a [`Policy`]: how binding it currently is.
///
/// Mirrors ODRL's three policy subclasses (<https://www.w3.org/TR/odrl-model/#policy>).
/// A catalog broker only ever *harvests* policies attached to a crawled
/// participant's `dcat:Dataset` via `odrl:hasPolicy` - it never negotiates,
/// so in practice every policy this crate constructs from a crawl is an
/// `Offer` (the pre-negotiation ODRL type DSP catalogs advertise). `Set` and
/// `Agreement` are modeled anyway because they are valid ODRL policy types
/// and a faithful cache must not reject or coerce a participant that (contrary
/// to typical DSP usage) advertises one of the other two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PolicyKind {
    #[default]
    Set,
    Offer,
    Agreement,
}

/// The payload of [`Constraint::Atomic`]: `leftOperand operator
/// rightOperand`, e.g. `odrl:dateTime lteq "2027-01-01T00:00:00Z"`
/// (<https://www.w3.org/TR/odrl-model/#constraint-atomic>). Split out as
/// its own type (rather than inlining these three fields directly into
/// [`Constraint`]) purely so [`Constraint`]'s own doc comment has a single
/// concrete atomic shape to point readers at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicConstraint {
    pub left_operand: String,
    pub operator: String,
    pub right_operand: String,
}

/// A *logical* ODRL constraint: a named Boolean combinator over nested
/// child [`Constraint`]s
/// (<https://www.w3.org/TR/odrl-model/#constraint-logical>). The payload
/// of [`Constraint::Logical`].
///
/// Each variant is renamed to its own `odrl:`-prefixed wire key
/// (`{"odrl:and": [...]}`, `{"odrl:xone": [...]}`, etc.) rather than left
/// at serde's default (which would use the bare Rust variant name, and -
/// worse - would make `And`/`Or`/`Xone`/`AndSequence` indistinguishable
/// from each other on deserialize, since all four wrap the identical
/// `Vec<Constraint>` shape). A distinct key per variant is not optional
/// here: `and`/`or`/`xone` mean genuinely different things to evaluate
/// (all children / at least one / exactly one), so collapsing them into
/// one untagged "array of children" shape would silently discard which
/// combinator a crawled policy actually specified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogicalConstraint {
    #[serde(rename = "odrl:and")]
    And(Vec<Constraint>),
    #[serde(rename = "odrl:or")]
    Or(Vec<Constraint>),
    #[serde(rename = "odrl:xone")]
    Xone(Vec<Constraint>),
    #[serde(rename = "odrl:andSequence")]
    AndSequence(Vec<Constraint>),
}

/// One ODRL constraint attached to a [`Rule`]: either [`Atomic`](Constraint::Atomic)
/// (`leftOperand operator rightOperand`) or [`Logical`](Constraint::Logical)
/// (a named Boolean group - `odrl:and`/`odrl:or`/`odrl:xone`/
/// `odrl:andSequence` - of further nested `Constraint`s). Both shapes are
/// part of the real W3C ODRL constraint model
/// (<https://www.w3.org/TR/odrl-model/#constraint>); earlier revisions of
/// this type modeled only the atomic half, with a crawled logical-group
/// constraint skipped (one constraint at a time, not the enclosing policy)
/// rather than represented - a deliberate, documented scope cut for gap
/// analysis §3.4. This enum closes that cut: `Constraint` can now hold
/// either shape end to end, though *using* the logical half in the
/// crawler/rdf-store parsing path and in policy-filtering evaluation is
/// separate, later work this type alone does not finish - see gap
/// analysis §3.4 for the punch list and current status.
///
/// **Design: a Rust enum, not a flat struct with `Option<Vec<Constraint>>`
/// and/or/xone/and_sequence fields** (the shape `ds-odrl-engine-rs`'s own
/// `engine::Constraint` uses - see that type's doc comment). The engine's
/// flat-struct design exists specifically to preserve an established flat
/// wire contract for its own existing external consumers without a
/// breaking rename; this type has no such external consumer to protect,
/// and an enum makes the atomic/logical distinction exhaustively
/// pattern-matchable (`match constraint { Constraint::Atomic(a) => ...,
/// Constraint::Logical(l) => ... }`) rather than a caller having to check
/// four `Option` fields to find out which, if any, is `Some`. This is
/// also the same shape the real
/// `edc_connector_client::types::policy::Constraint` enum already uses for
/// this exact atomic-vs-logical distinction (`Constraint::Atomic` /
/// `Constraint::MultiplicityConstraint`, with its own `and`/`or`/`xone`
/// constructors) - already a dev-dependency of `ds-catalog-broker-rs` for
/// management-API wire compatibility, so this crate's own `Constraint`
/// now agrees with a real upstream type on how to model the same problem.
///
/// `#[serde(untagged)]`: [`AtomicConstraint`] requires all three of
/// `left_operand`/`operator`/`right_operand`, and every
/// [`LogicalConstraint`] variant supplies none of them (each is tagged by
/// its own distinct `odrl:...` key instead) - so the two payloads are
/// always structurally distinguishable on the wire, with no ambiguity for
/// serde to resolve by declaration order. This keeps an atomic
/// constraint's own JSON exactly as flat as before this enum existed
/// (`{"left_operand": ..., "operator": ..., "right_operand": ...}`, no
/// wrapping `"Atomic"`/`"atomic"` tag key) - the atomic wire shape is
/// unchanged, additive-only, per this crate's own round-trip tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Constraint {
    Atomic(AtomicConstraint),
    Logical(LogicalConstraint),
}

impl Constraint {
    /// Build an atomic constraint from its three parts - the direct
    /// replacement for the bare `Constraint { left_operand, operator,
    /// right_operand }` struct literal every caller used before
    /// `Constraint` became an enum (a plain struct literal naming
    /// `Constraint` no longer type-checks once the type has variants).
    pub fn atomic(
        left_operand: impl Into<String>,
        operator: impl Into<String>,
        right_operand: impl Into<String>,
    ) -> Self {
        Constraint::Atomic(AtomicConstraint {
            left_operand: left_operand.into(),
            operator: operator.into(),
            right_operand: right_operand.into(),
        })
    }

    /// `odrl:and`: satisfied when every nested child is satisfied. See
    /// `tests::logical_and_constraint_round_trips_through_json_preserving_nested_order`.
    pub fn and(children: Vec<Constraint>) -> Self {
        Constraint::Logical(LogicalConstraint::And(children))
    }

    /// `odrl:or`: satisfied when at least one nested child is satisfied.
    pub fn or(children: Vec<Constraint>) -> Self {
        Constraint::Logical(LogicalConstraint::Or(children))
    }

    /// `odrl:xone`: satisfied when exactly one nested child is satisfied.
    pub fn xone(children: Vec<Constraint>) -> Self {
        Constraint::Logical(LogicalConstraint::Xone(children))
    }

    /// `odrl:andSequence`: per the W3C ODRL 2.2 Vocabulary, satisfied when
    /// every nested child is satisfied *in the order specified*. Nothing
    /// in this crate's domain model captures an execution trace to check
    /// that ordering against (crawled/stored data is a snapshot, not a
    /// timeline), so this is carried as its own distinct, honestly-named
    /// variant rather than silently aliased to `and` - see
    /// [`LogicalConstraint::AndSequence`].
    pub fn and_sequence(children: Vec<Constraint>) -> Self {
        Constraint::Logical(LogicalConstraint::AndSequence(children))
    }
}

/// One ODRL rule entry: a single `permission`, `prohibition`, or
/// `obligation` inside a [`Policy`].
///
/// ODRL gives permission/prohibition/obligation the same shape (an `action`
/// plus zero or more `constraint`s
/// (<https://www.w3.org/TR/odrl-model/#rule>)), so one type covers all
/// three; which list a given `Rule` lives in (see [`Policy::permissions`],
/// [`Policy::prohibitions`], [`Policy::obligations`]) is what distinguishes
/// them, exactly as in the ODRL JSON-LD serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub action: String,
    #[serde(default)]
    pub constraints: Vec<Constraint>,
}

/// A harvested ODRL policy, as faithfully preserved from a crawled
/// participant's `dcat:Dataset` / `odrl:hasPolicy` triples.
///
/// This is real policy data derived from what a crawled participant
/// actually advertised - not the hardcoded placeholder the now-removed
/// http-api DSP layer used to emit (see gap analysis §3.4). A read-only
/// catalog broker has no negotiation capability of its own, so "honoring"
/// a harvested policy here means: preserve it faithfully end to end
/// (crawl -> semantic cache -> management API), and make it available to
/// callers rather than inventing or dropping it. Whether the broker should
/// also *filter* what it re-serves based on policy content (e.g. hide a
/// dataset from a caller not entitled under its policy) is an open design
/// question this type intentionally does not answer - see gap analysis
/// §3.4 for why that's flagged rather than guessed at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub kind: PolicyKind,
    #[serde(default)]
    pub assigner: Option<String>,
    #[serde(default)]
    pub assignee: Option<String>,
    #[serde(default)]
    pub permissions: Vec<Rule>,
    #[serde(default)]
    pub prohibitions: Vec<Rule>,
    #[serde(default)]
    pub obligations: Vec<Rule>,
}

/// One offered dataset: its id, arbitrary properties, the distributions
/// it's available through, and the ODRL policies a crawled participant
/// attached to it.
///
/// EDC's `Dataset` carries `offers: Map<String, Policy>`; the equivalent
/// here is `policies`, harvested faithfully from a crawled participant's
/// `odrl:hasPolicy` triples rather than invented - see [`Policy`]'s doc
/// comment and gap analysis §3.4.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dataset {
    pub id: String,
    #[serde(default)]
    pub properties: BTreeMap<String, String>,
    #[serde(default)]
    pub distributions: Vec<Distribution>,
    #[serde(default)]
    pub policies: Vec<Policy>,
}

/// A crawled catalog: one participant's advertised datasets and data
/// services, as fetched by a single crawl of `origin_node`.
///
/// Modeled after EDC's `Catalog extends Dataset` (spi/control-plane/catalog-spi),
/// flattened here rather than inheriting from `Dataset` since Rust has no
/// class inheritance and the cache only ever stores whole catalogs, never
/// a bare `Dataset` standing in for one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Catalog {
    pub id: String,
    pub origin_node: NodeId,
    #[serde(default)]
    pub participant_id: Option<String>,
    #[serde(default)]
    pub datasets: Vec<Dataset>,
    #[serde(default)]
    pub data_services: Vec<DataService>,
    #[serde(default)]
    pub properties: BTreeMap<String, String>,
}

impl Catalog {
    pub fn new(id: impl Into<String>, origin_node: NodeId) -> Self {
        Self {
            id: id.into(),
            origin_node,
            participant_id: None,
            datasets: Vec::new(),
            data_services: Vec::new(),
            properties: BTreeMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_new_has_empty_collections() {
        let cat = Catalog::new("cat-1", NodeId::new("node-1"));
        assert_eq!(cat.id, "cat-1");
        assert_eq!(cat.origin_node, NodeId::new("node-1"));
        assert!(cat.datasets.is_empty());
        assert!(cat.data_services.is_empty());
    }

    #[test]
    fn crawl_work_item_starts_at_zero_retries() {
        let node = TargetNode {
            id: NodeId::new("node-1"),
            name: "node-1".into(),
            target_url: "https://example.org/dsp".into(),
            supported_protocols: vec!["dataspace-protocol-http".into()],
        };
        let item = CrawlWorkItem::new(node);
        assert_eq!(item.retries, 0);
    }

    #[test]
    fn node_id_display_matches_inner_string() {
        let id = NodeId::new("abc");
        assert_eq!(id.to_string(), "abc");
    }

    #[test]
    fn policy_kind_defaults_to_set() {
        assert_eq!(PolicyKind::default(), PolicyKind::Set);
    }

    #[test]
    fn dataset_with_no_policies_round_trips_via_serde_default() {
        // Older/simpler JSON (predating this field) must still deserialize:
        // `policies` is #[serde(default)] precisely so a Dataset with no
        // `policies` key at all comes back as an empty Vec, not an error.
        let json = serde_json::json!({
            "id": "ds-1",
            "properties": {},
            "distributions": [],
        });
        let dataset: Dataset = serde_json::from_value(json).expect("deserializes");
        assert!(dataset.policies.is_empty());

        let round_tripped: Dataset =
            serde_json::from_str(&serde_json::to_string(&dataset).unwrap()).unwrap();
        assert_eq!(round_tripped, dataset);
    }

    #[test]
    fn policy_with_full_shape_round_trips_through_json() {
        let policy = Policy {
            id: Some("policy-1".into()),
            kind: PolicyKind::Offer,
            assigner: Some("did:example:provider".into()),
            assignee: Some("did:example:consumer".into()),
            permissions: vec![Rule {
                action: "use".into(),
                constraints: vec![Constraint::atomic(
                    "odrl:dateTime",
                    "lteq",
                    "2027-01-01T00:00:00Z",
                )],
            }],
            prohibitions: vec![Rule {
                action: "distribute".into(),
                constraints: Vec::new(),
            }],
            obligations: Vec::new(),
        };

        let json = serde_json::to_string(&policy).expect("serializes");
        let round_tripped: Policy = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(round_tripped, policy);

        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["kind"], "Offer");
        assert_eq!(value["id"], "policy-1");
        assert_eq!(value["permissions"][0]["action"], "use");
        assert_eq!(
            value["permissions"][0]["constraints"][0]["right_operand"],
            "2027-01-01T00:00:00Z"
        );
        // obligations was empty - #[serde(default)] means it's fine either
        // way whether present-and-empty or omitted, but our derive always
        // emits it (no skip_serializing_if), so assert it's there and empty.
        assert!(value["obligations"].as_array().unwrap().is_empty());
    }

    #[test]
    fn dataset_with_policies_round_trips() {
        let dataset = Dataset {
            id: "ds-1".into(),
            properties: BTreeMap::new(),
            distributions: Vec::new(),
            policies: vec![Policy {
                id: None,
                kind: PolicyKind::Offer,
                assigner: None,
                assignee: None,
                permissions: vec![Rule {
                    action: "use".into(),
                    constraints: Vec::new(),
                }],
                prohibitions: Vec::new(),
                obligations: Vec::new(),
            }],
        };

        let round_tripped: Dataset =
            serde_json::from_str(&serde_json::to_string(&dataset).unwrap()).unwrap();
        assert_eq!(round_tripped, dataset);
        assert_eq!(round_tripped.policies[0].kind, PolicyKind::Offer);
    }

    #[test]
    fn logical_and_constraint_round_trips_through_json_preserving_nested_order() {
        // GREEN (gap analysis §3.4): `Constraint` now has a `Logical`
        // variant (see its own doc comment) that can represent an
        // `odrl:and` logical grouping of nested sub-constraints. This
        // asserts that a logical `and` of two atomic sub-constraints can
        // be constructed and round-trips through serde_json (serialize
        // then deserialize back to an equal value), preserving the nested
        // structure and the child order (dateTime gteq before dateTime
        // lteq).
        let starts_after = Constraint::atomic("odrl:dateTime", "gteq", "2026-01-01T00:00:00Z");
        let ends_before = Constraint::atomic("odrl:dateTime", "lteq", "2027-01-01T00:00:00Z");
        let logical = Constraint::and(vec![starts_after.clone(), ends_before.clone()]);

        let json = serde_json::to_string(&logical).expect("serializes");
        let round_tripped: Constraint = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(
            round_tripped, logical,
            "nested structure and order must survive a JSON round trip"
        );
    }
}
