//! Storage abstraction for the federated catalog cache.
//!
//! Named `rdf-store` because a crawled catalog is expected to eventually be
//! represented as an RDF named graph (one graph per participant), but the
//! [`CatalogCache`] trait itself is backend-agnostic. Which RDF store (or
//! whether RDF at all, vs. e.g. a plain document store) backs this is a
//! decision being made iteratively - see the `dataspace` study repo's
//! `docs/spikes/` for the exploration behind that choice - so this crate
//! only fixes the shape of the trait plus one in-memory implementation
//! good enough to unblock `ds-catalog-broker-rs` and its own tests.
//!
//! The trait mirrors Eclipse EDC's `FederatedCatalogCache` SPI
//! (`save`/`query`/`deleteExpired`/`expireAll`) but adapted to a
//! from-scratch design: EDC's mark-then-sweep expiry (`deleteExpired` +
//! `expireAll` called every crawl tick) is replaced here by an explicit
//! `delete(node)`, since the tick/expiry policy belongs to a future
//! crawler crate, not to the storage trait itself. Like EDC, each
//! participant's crawled catalog is upserted as a whole unit keyed by
//! origin node - not decomposed into per-dataset rows - mirroring EDC's
//! choice to key the whole `Catalog` object graph by origin node URL.
//!
//! ## Intended future backend: Oxigraph
//!
//! A research spike in the `dataspace` study repo (`docs/spikes/`) surveyed
//! the available Rust RDF/quad-store crates against this trait's shape -
//! a named-graph quad store, one graph per
//! crawled source-node IRI, upserted wholesale on crawl, removed via an
//! explicit delete - and recommended **[Oxigraph](https://crates.io/crates/oxigraph)**
//! as the eventual backend:
//!
//! - It is the only surveyed candidate that both matches the shape (named
//!   graphs, full SPARQL 1.1 Query/Update/Federated Query) and has a
//!   maturity track record to build on now: ~8 years old, actively
//!   maintained, ~700k crates.io downloads, dual Apache-2.0/MIT, with a
//!   persistent RocksDB-backed store.
//! - `cool-japan/oxirs` is the closer long-term architectural fit
//!   (async-native, purpose-built on-disk format, also named-graph
//!   capable) but at spike time was a 14-month-old, effectively
//!   single-maintainer workspace whose persistent backend had shipped only
//!   five weeks earlier, with unaudited test/scale claims - not a
//!   foundation to bet this rewrite's first concrete cache backend on.
//! - No other surveyed crate (Sophia, terminusdb-store, hdt, Grafeo,
//!   kglite, rust-rdftk) beat Oxigraph on the combination of shape-fit and
//!   maturity.
//!
//! ## Implemented backend: `oxigraph_backend`, on top of `contreforts-kg`
//!
//! [`oxigraph_backend::OxigraphCatalogCache`] is the real Oxigraph-backed
//! implementation the section above anticipated. It is built on
//! [`contreforts-kg`](https://labs.deepthought-solutions.net/contreforts/contreforts-kg),
//! an existing, actively-maintained internal Oxigraph wrapper
//! (`GraphStore` / `QueryEngine`) from a separate private repo the same
//! owner controls, rather than depending on the bare `oxigraph` crate's
//! `Store` directly. That is a deliberate choice, not an oversight: it
//! reuses store-open, named-graph insert/remove, and SPARQL-evaluation
//! plumbing that already exists and is exercised elsewhere, instead of
//! re-implementing it from scratch here. The tradeoff accepted for that
//! reuse is a coupling to a private, different-domain (knowledge-graph
//! tooling, not dataspaces) repo, vendored as a git submodule (see
//! `vendor/README.md`) - acceptable because `contreforts-kg` is a thin
//! wrapper (this crate still depends on `oxigraph` directly too, pinned to
//! the same `"0.5"` range, to construct `NamedNode`/`Literal`/`Term`
//! values), not because the coupling itself is free.
//!
//! The quad mapping has moved past the original "first cut" blob-JSON
//! bridge (one opaque `catalogJson` literal per graph) to a real RDF
//! decomposition: `Catalog`/`Dataset`/`Distribution`/`DataService` each
//! become their own resource, related by real DCAT object properties, per
//! gap analysis §3.2 (`docs/gap-analysis-2026-08-27.md`). See
//! [`oxigraph_backend`]'s module doc for the exact subject/predicate/object
//! mapping - the ADR-equivalent record this doc comment previously
//! deferred to. `catalog-core::Dataset` now carries a real ODRL `Policy`
//! model (`Dataset.policies`, gap analysis §3.4), harvested from a crawled
//! participant's `odrl:hasPolicy` triples rather than invented, and
//! `oxigraph_backend` preserves it faithfully as real `odrl:` triples too -
//! see that module's own doc comment for the exact mapping, including the
//! deliberate atomic-constraints-only scope cut it inherits from
//! `catalog_core::Constraint`.

use async_trait::async_trait;
use catalog_core::{Catalog, NodeId};
use thiserror::Error;

/// Errors a [`CatalogCache`] backend can report.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("catalog store backend error: {0}")]
    Backend(String),
}

pub type StoreResult<T> = Result<T, StoreError>;

/// A query over stored catalogs.
///
/// Deliberately minimal - a from-scratch analogue of EDC's `QuerySpec`,
/// sized to what the in-memory backend here can serve. A real RDF backend
/// will likely need a richer query shape (e.g. SPARQL passthrough); that
/// is expected to extend or replace this type, not be forced through it.
#[derive(Debug, Clone, Default)]
pub struct CatalogQuery {
    pub origin_node: Option<NodeId>,
    pub offset: usize,
    pub limit: Option<usize>,
}

impl CatalogQuery {
    /// No filter, no offset, no limit.
    pub fn all() -> Self {
        Self::default()
    }

    /// Only the catalog crawled from `node`, if any.
    pub fn for_node(node: NodeId) -> Self {
        Self {
            origin_node: Some(node),
            ..Self::default()
        }
    }
}

/// Storage for crawled catalogs, one named graph per origin node.
///
/// Implementations must be safe to share across crawl tasks (`Send +
/// Sync`) since a real crawler runs multiple concurrent fetches.
#[async_trait]
pub trait CatalogCache: Send + Sync {
    /// Insert or replace the named graph for `catalog.origin_node`.
    ///
    /// Re-crawling the same node always overwrites its prior catalog
    /// wholesale, matching EDC's upsert-by-origin-node-url behavior.
    async fn upsert(&self, catalog: Catalog) -> StoreResult<()>;

    /// Return stored catalogs matching `query`.
    async fn query(&self, query: CatalogQuery) -> StoreResult<Vec<Catalog>>;

    /// Remove the named graph for `node`, if present.
    ///
    /// Returns `true` if a catalog was actually removed.
    async fn delete(&self, node: &NodeId) -> StoreResult<bool>;
}

/// A simple, non-persistent [`CatalogCache`] backed by an in-process map.
///
/// This exists so `ds-catalog-broker-rs` (and this crate's own tests) have something
/// to run against while the real RDF-backed implementation is chosen; it
/// is not intended to be the production backend.
pub mod memory {
    use super::*;
    use std::collections::HashMap;
    use tokio::sync::RwLock;

    #[derive(Default)]
    pub struct InMemoryCatalogCache {
        graphs: RwLock<HashMap<NodeId, Catalog>>,
    }

    impl InMemoryCatalogCache {
        pub fn new() -> Self {
            Self::default()
        }
    }

    #[async_trait]
    impl CatalogCache for InMemoryCatalogCache {
        async fn upsert(&self, catalog: Catalog) -> StoreResult<()> {
            let mut graphs = self.graphs.write().await;
            graphs.insert(catalog.origin_node.clone(), catalog);
            Ok(())
        }

        async fn query(&self, query: CatalogQuery) -> StoreResult<Vec<Catalog>> {
            let graphs = self.graphs.read().await;
            let mut results: Vec<Catalog> = graphs
                .values()
                .filter(|catalog| match &query.origin_node {
                    Some(node) => &catalog.origin_node == node,
                    None => true,
                })
                .cloned()
                .collect();
            // Deterministic ordering: HashMap iteration order isn't
            // stable, and callers (e.g. ds-catalog-broker-rs) need reproducible
            // pagination.
            results.sort_by(|a, b| a.id.cmp(&b.id));

            let skipped = results.into_iter().skip(query.offset);
            let limited: Vec<Catalog> = match query.limit {
                Some(limit) => skipped.take(limit).collect(),
                None => skipped.collect(),
            };
            Ok(limited)
        }

        async fn delete(&self, node: &NodeId) -> StoreResult<bool> {
            let mut graphs = self.graphs.write().await;
            Ok(graphs.remove(node).is_some())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn sample_catalog(node: &str, id: &str) -> Catalog {
            Catalog::new(id, NodeId::new(node))
        }

        #[tokio::test]
        async fn upsert_then_query_all_returns_it() {
            let cache = InMemoryCatalogCache::new();
            cache
                .upsert(sample_catalog("node-1", "cat-1"))
                .await
                .unwrap();

            let results = cache.query(CatalogQuery::all()).await.unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].id, "cat-1");
        }

        #[tokio::test]
        async fn upsert_replaces_prior_catalog_for_same_node() {
            let cache = InMemoryCatalogCache::new();
            cache
                .upsert(sample_catalog("node-1", "cat-1"))
                .await
                .unwrap();
            cache
                .upsert(sample_catalog("node-1", "cat-2"))
                .await
                .unwrap();

            let results = cache.query(CatalogQuery::all()).await.unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].id, "cat-2");
        }

        #[tokio::test]
        async fn query_for_node_filters_by_origin() {
            let cache = InMemoryCatalogCache::new();
            cache
                .upsert(sample_catalog("node-1", "cat-1"))
                .await
                .unwrap();
            cache
                .upsert(sample_catalog("node-2", "cat-2"))
                .await
                .unwrap();

            let results = cache
                .query(CatalogQuery::for_node(NodeId::new("node-2")))
                .await
                .unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].id, "cat-2");
        }

        #[tokio::test]
        async fn query_respects_offset_and_limit() {
            let cache = InMemoryCatalogCache::new();
            for i in 0..5 {
                cache
                    .upsert(sample_catalog(&format!("node-{i}"), &format!("cat-{i}")))
                    .await
                    .unwrap();
            }

            let results = cache
                .query(CatalogQuery {
                    origin_node: None,
                    offset: 2,
                    limit: Some(2),
                })
                .await
                .unwrap();
            assert_eq!(
                results.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
                vec!["cat-2", "cat-3"]
            );
        }

        #[tokio::test]
        async fn delete_removes_catalog_and_reports_result() {
            let cache = InMemoryCatalogCache::new();
            cache
                .upsert(sample_catalog("node-1", "cat-1"))
                .await
                .unwrap();

            let removed = cache.delete(&NodeId::new("node-1")).await.unwrap();
            assert!(removed);

            let results = cache.query(CatalogQuery::all()).await.unwrap();
            assert!(results.is_empty());

            let removed_again = cache.delete(&NodeId::new("node-1")).await.unwrap();
            assert!(!removed_again);
        }
    }
}

/// A real, Oxigraph-backed [`CatalogCache`], built on `contreforts-kg`'s
/// `GraphStore` rather than the bare `oxigraph` crate's `Store` directly.
///
/// See this module's own doc comment above ("Implemented backend") for why
/// `contreforts-kg` rather than raw `oxigraph`.
///
/// ## Quad mapping (real RDF decomposition - gap analysis §3.2)
///
/// Reuses [DCAT](http://www.w3.org/ns/dcat#) terms wherever a genuine DCAT
/// property/class fits `catalog-core`'s domain model, matching the
/// Dataspace Protocol's own stated approach ("The Catalog Protocol reuses
/// properties from the DCAT and ODRL vocabularies" - `catalog.protocol.md`,
/// "Introduction"). One non-DCAT/ODRL term is reused for the same reason:
/// [Dublin Core Terms](http://purl.org/dc/terms/)' `dct:format`, which is
/// what DCAT/DSP tooling itself actually uses for a `Distribution`'s
/// format (including the real DSP `2025-1` JSON-LD context, which maps its
/// `format` term to `dct:format` - confirmed against this project's own,
/// now-removed `http-api` DSP layer, whose `DspDistribution.format` field
/// serialized under that same context). Everything else with no DCAT/ODRL
/// (or DCTERMS) equivalent falls back to this project's own
/// `https://federated-catalog-rs.internal/ns#` namespace.
///
/// **ODRL terms, real and harvested (gap analysis §3.4).** `catalog-core::Dataset`
/// now carries `policies: Vec<Policy>` - real ODRL policy data derived from
/// a crawled participant's own `odrl:hasPolicy` triples, not the hardcoded
/// placeholder the now-removed `http-api` DSP-serving layer used to emit
/// (see `Policy`'s own doc comment). A read-only catalog broker has no
/// negotiation capability of its own, so "honoring" a harvested policy
/// means preserving it faithfully end to end; this store's half of that is
/// decomposing each `Policy` into real `odrl:` resources and triples
/// (below), exactly the way `Catalog`/`Dataset`/`Distribution`/`DataService`
/// are already decomposed into real `dcat:` ones, rather than folding
/// policy data into the generic `Dataset.properties` bag or an opaque
/// blob.
///
/// **Logical constraint groups (gap analysis §3.4, closed).** A
/// constraint resource `<constraint>` is either the atomic shape above, or
/// a *logical* group - `<constraint> odrl:and <child> .` / `odrl:or` /
/// `odrl:xone` / `odrl:andSequence`, one triple per
/// [`catalog_core::LogicalConstraint`] child, each real ODRL term reused
/// exactly the way `odrl:leftOperand`/`odrl:operator` are reused for the
/// atomic shape above. `<child>` is itself a full constraint resource -
/// built from the *parent constraint's* own IRI the same way a top-level
/// constraint is built from its rule's IRI (see [`constraint_iri`]), so
/// nesting reuses the exact same resource-naming scheme at every depth -
/// carrying its own `fcns:sequenceIndex` (its position among its
/// siblings) and, recursively, either shape again. A constraint resource
/// therefore carries **at most one** of `odrl:leftOperand` or one of the
/// four logical predicates, never both - `load_constraint` reads whichever
/// is present, atomic taking precedence should a hand-crafted graph
/// (outside this store's own writes) carry both.
///
/// Recursion depth - both writing and reading - is bounded by
/// `MAX_CONSTRAINT_DEPTH` (64), the exact same bound and rationale as
/// `crawler::MAX_CONSTRAINT_DEPTH` and
/// `ds-odrl-engine-rs::engine::constraint::MAX_CONSTRAINT_DEPTH`: a
/// constraint nested past the bound is dropped (not written, with no
/// dangling triple left behind) on write, the same way
/// `crawler::parse_constraint` drops one past its own bound rather than
/// growing a parser's call stack unboundedly - and reading back a graph
/// that somehow carries one anyway (not producible by this store's own
/// write path, but defended against regardless, e.g. a hand-written
/// fixture or a future non-`crawler` producer) errors out rather than
/// recursing without bound.
///
/// ### Namespaces
///
/// | Prefix | IRI |
/// |---|---|
/// | `dcat:` | `http://www.w3.org/ns/dcat#` |
/// | `dct:` | `http://purl.org/dc/terms/` |
/// | `odrl:` | `http://www.w3.org/ns/odrl/2/` |
/// | `rdf:` | `http://www.w3.org/1999/02/22-rdf-syntax-ns#` |
/// | `fcns:` (fallback) | `https://federated-catalog-rs.internal/ns#` |
///
/// ### Resource IRIs
///
/// For an origin node whose [`NodeId`] is `<node>` (percent-encoded
/// throughout, so any character the id contains still yields a valid
/// IRI), let `<base>` = `https://federated-catalog-rs.internal/nodes/<node>`:
///
/// - **Named graph** (one per origin node, matching the trait's contract):
///   `<base>`.
/// - **Catalog resource**: `<base>/catalogs/<catalog.id>`.
/// - **Dataset resource**: `<base>/datasets/<dataset.id>`.
/// - **Distribution resource**: `<base>/datasets/<dataset.id>/distributions/<index>`
///   - a distribution has no id of its own in the domain model, so it is
///     identified by its position in `dataset.distributions` instead of a
///     blank node (predictable, queryable IRIs beat blank nodes here, and
///     the index doubles as the ordering key - see "Ordering" below).
/// - **DataService resource**: `<base>/services/<data_service.id>`.
/// - **Policy resource**: `<base>/datasets/<dataset.id>/policies/<index>` -
///   like a distribution, a harvested policy is identified by its position
///   in `dataset.policies` rather than by `Policy.id`: that field is an
///   arbitrary, optional string harvested from the crawl (possibly absent,
///   possibly not IRI-safe), not a trusted identifier this store can mint
///   a resource IRI from. When present it is preserved separately as a
///   literal instead (`fcns:policyId`, see "Triples emitted" below).
/// - **Permission / Prohibition / Obligation resource** (one shape, shared
///   by all three - see [`Rule`]): `<policy>/permissions/<index>`,
///   `<policy>/prohibitions/<index>`, `<policy>/obligations/<index>`
///   respectively. Each list's `<index>` restarts at 0 independently of
///   the other two - they live under different path segments, so a
///   permission and a prohibition at the same position never collide.
/// - **Constraint resource**: `<parent>/constraints/<index>`, where
///   `<parent>` is whichever permission/prohibition/obligation resource
///   IRI the constraint directly belongs to for a rule's own top-level
///   constraint, **or another constraint resource IRI** for a child of a
///   logical (`odrl:and`/`odrl:or`/`odrl:xone`/`odrl:andSequence`) group -
///   nesting reuses this exact same `<parent>/constraints/<index>` scheme
///   at every depth, so e.g. an `odrl:xone`'s second child, itself an
///   `odrl:and`'s first child, gets
///   `<rule>/constraints/<xone-index>/constraints/<and-index>/constraints/0`.
///   See "Triples emitted" below for the logical-group predicates
///   themselves.
///
/// `Distribution.access_service` is a bare `String` in the domain model,
/// not a typed foreign key - it is resolved to a DataService resource IRI
/// using the exact same `<base>/services/<id>` scheme a real `DataService`
/// would get, so a distribution whose `access_service` matches a data
/// service actually present in the same catalog naturally points at that
/// same resource. A dangling reference (no such service) still round-trips
/// correctly: decoding only ever needs to strip the known prefix and
/// percent-decode the remainder, it never requires the target to exist.
///
/// ### Triples emitted, subject/predicate/object
///
/// For catalog resource `<catalog>`:
/// - `<catalog> rdf:type dcat:Catalog .`
/// - `<catalog> fcns:participantId "<participant_id>"` - only if
///   `Catalog.participant_id` is `Some`. DSP's own `participantId` is a
///   dataspace-specific concept with no DCAT/ODRL equivalent, so it falls
///   back to this project's own namespace per the rule above.
/// - `<catalog> dcat:dataset <dataset> .` - one per `Catalog.datasets`
///   entry (`dcat:dataset` is DCAT's real Catalog-to-Dataset property).
/// - `<catalog> dcat:service <service> .` - one per `Catalog.data_services`
///   entry (`dcat:service`, DCAT3's real Catalog-to-DataService property).
/// - `<catalog> <property-predicate> "<value>"` - one per
///   `Catalog.properties` entry; see "Generic properties" below.
///
/// For each dataset resource `<dataset>` (from `Catalog.datasets`):
/// - `<dataset> rdf:type dcat:Dataset .`
/// - `<dataset> fcns:sequenceIndex "<index>"^^xsd:integer .` - see
///   "Ordering" below.
/// - `<dataset> dcat:distribution <distribution> .` - one per
///   `Dataset.distributions` entry (`dcat:distribution` is DCAT's real
///   Dataset-to-Distribution property).
/// - `<dataset> odrl:hasPolicy <policy> .` - one per `Dataset.policies`
///   entry (`odrl:hasPolicy` is ODRL's real property for attaching a
///   policy to an asset, and the exact term DSP catalogs advertise offers
///   under).
/// - `<dataset> <property-predicate> "<value>"` - one per
///   `Dataset.properties` entry; see "Generic properties" below.
///
/// For each policy resource `<policy>` (from `Dataset.policies`):
/// - `<policy> rdf:type odrl:<Kind> .` - `odrl:Set` / `odrl:Offer` /
///   `odrl:Agreement`, matching `Policy.kind` (see [`PolicyKind`]).
/// - `<policy> fcns:sequenceIndex "<index>"^^xsd:integer .` - see
///   "Ordering" below.
/// - `<policy> fcns:policyId "<id>"` - only if `Policy.id` is `Some`. Not
///   an ODRL term: in a real JSON-LD/RDF reading, a policy's `@id` *is*
///   its subject IRI, but this store already mints its own positional
///   subject IRI for a policy (see "Resource IRIs" above), so the
///   harvested `@id` string needs a separate home to round-trip - there is
///   no DCAT/ODRL term for "this resource's externally-advertised id, kept
///   as a plain literal", so it falls back to this project's own
///   namespace per the "Generic properties" rule below.
/// - `<policy> odrl:assigner "<assigner>"` / `<policy> odrl:assignee "<assignee>"` -
///   only if `Policy.assigner` / `Policy.assignee` is `Some`, as an IRI
///   when the value parses as one (e.g. a DID) or a plain literal
///   otherwise - the same IRI-or-literal treatment `dcat:endpointURL` gets
///   below, for the same reason: ODRL's formal range for both properties
///   is `odrl:Party` (an IRI-identified resource), but a harvested value
///   isn't guaranteed to already be a valid IRI.
/// - `<policy> odrl:permission <rule> .` / `<policy> odrl:prohibition <rule> .` /
///   `<policy> odrl:obligation <rule> .` - one per entry in
///   `Policy.permissions` / `Policy.prohibitions` / `Policy.obligations`
///   respectively (ODRL's real property for each rule kind).
///
/// For each rule resource `<rule>` (a permission/prohibition/obligation,
/// from `Policy.permissions`/`prohibitions`/`obligations`):
/// - `<rule> fcns:sequenceIndex "<index>"^^xsd:integer .`
/// - `<rule> odrl:action ...` - `Rule.action`, IRI-or-literal (ODRL
///   actions are often a bare keyword like `"use"`, but can also be a full
///   IRI, so the same fallback as `dcat:endpointURL`/`odrl:assigner`
///   applies).
/// - `<rule> odrl:constraint <constraint> .` - one per `Rule.constraints`
///   entry.
///
/// For each constraint resource `<constraint>` (from `Rule.constraints`,
/// or recursively from a logical constraint's own children - see
/// "Resource IRIs" above): first, always,
/// `<constraint> fcns:sequenceIndex "<index>"^^xsd:integer .` (this
/// resource's position among its own siblings, atomic or logical alike);
/// then, depending on [`catalog_core::Constraint`]'s shape:
///
/// - [`Atomic`](catalog_core::Constraint::Atomic):
///   - `<constraint> odrl:leftOperand ...` - `Constraint.left_operand`,
///     IRI-or-literal.
///   - `<constraint> odrl:operator ...` - `Constraint.operator`,
///     IRI-or-literal.
///   - `<constraint> odrl:rightOperand "<value>"` - `Constraint.right_operand`,
///     **always** a plain literal, never minted as an IRI even when the
///     value happens to parse as one: a `rightOperand` is a value being
///     compared against, not an identifier for another resource, so
///     giving it the IRI-or-literal treatment would change its RDF shape
///     based on incidental string content rather than ODRL semantics.
/// - [`Logical`](catalog_core::Constraint::Logical) - exactly one of:
///   - `<constraint> odrl:and <child> .` - one per
///     [`LogicalConstraint::And`](catalog_core::LogicalConstraint::And)
///     child, in order.
///   - `<constraint> odrl:or <child> .` - one per
///     [`LogicalConstraint::Or`](catalog_core::LogicalConstraint::Or)
///     child, in order.
///   - `<constraint> odrl:xone <child> .` - one per
///     [`LogicalConstraint::Xone`](catalog_core::LogicalConstraint::Xone)
///     child, in order.
///   - `<constraint> odrl:andSequence <child> .` - one per
///     [`LogicalConstraint::AndSequence`](catalog_core::LogicalConstraint::AndSequence)
///     child, in order.
///
///   Each `<child>` is itself a full constraint resource (see "Resource
///   IRIs" above), recursively either shape again - up to
///   `MAX_CONSTRAINT_DEPTH` (64) levels deep, matching
///   `crawler::MAX_CONSTRAINT_DEPTH`; a child nested past that bound is
///   dropped entirely (no `odrl:and`/`odrl:or`/`odrl:xone`/
///   `odrl:andSequence` link triple written for it, and none of its own
///   triples either) rather than growing this store's own recursive
///   write/read past a safe bound.
///
/// For each distribution resource `<distribution>` (from
/// `Dataset.distributions`):
/// - `<distribution> rdf:type dcat:Distribution .`
/// - `<distribution> fcns:sequenceIndex "<index>"^^xsd:integer .`
/// - `<distribution> dct:format "<format>" .`
/// - `<distribution> dcat:accessService <service> .` - `<service>` is the
///   `<base>/services/<access_service>` IRI described above (`dcat:accessService`
///   is DCAT's real Distribution-to-DataService property).
///
/// For each data service resource `<service>` (from `Catalog.data_services`):
/// - `<service> rdf:type dcat:DataService .`
/// - `<service> fcns:sequenceIndex "<index>"^^xsd:integer .`
/// - `<service> dcat:endpointURL <endpoint_url>` (or, if `endpoint_url`
///   does not parse as a valid IRI - untrusted crawled data, not something
///   this store should reject - `"<endpoint_url>"` as a plain literal
///   instead). DCAT defines `dcat:endpointURL`'s range as `rdfs:Resource`,
///   i.e. an IRI, not a literal; since the domain field already holds a
///   URL string, minting it as the object IRI directly (rather than
///   wrapping it in a literal) is the more faithful reading of the real
///   DCAT term.
/// - `<service> dcat:endpointDescription "<endpoint_description>"` - only
///   if `DataService.endpoint_description` is `Some`. Stored as a plain
///   literal rather than an IRI even though DCAT's formal range for this
///   property is also `rdfs:Resource`: this domain field holds free text
///   (e.g. `"dataspace-protocol-http:1.0"`, see `seed_sample_catalog`), not
///   a URL, and DCAT's own usage note allows literal values in practice.
///
/// ### Generic properties (`Catalog.properties` / `Dataset.properties`)
///
/// `catalog-core`'s `properties: BTreeMap<String, String>` is an arbitrary
/// key/value bag - EDC's `Dataset`/`Asset` have the same shape, keyed by
/// whatever property IRI or name the source used. Each entry becomes
/// exactly one triple, `<resource> <predicate> "<value>"`, where
/// `<predicate>` is:
/// - the key itself, reused as-is, **if** it already parses as an absolute
///   IRI (so a crawler that already normalized a key to a real vocabulary
///   term - e.g. `http://www.w3.org/ns/dcat#keyword` - gets a genuine
///   triple using that term, not a synthesized one); otherwise
/// - `fcns:property/<percent-encoded key>` - the documented fallback.
///
/// `crawler::collect_datasets_and_services` now populates `Dataset.properties`
/// with a real crawled dataset's optional descriptors (`title`,
/// `description`, `version`, `creatorName`, `thumbnail`, `keywords`, each
/// only when the source DSP JSON actually carries it - see that function's
/// own doc comment) - `POST /api/management/v4/catalogs/request` reads
/// them straight back out through this exact mechanism to populate the
/// real `edc_federated_catalog_client::models::Dataset`'s own optional
/// fields. None of those keys are absolute IRIs, so all of them take the
/// `fcns:property/<key>` fallback path above, not the passthrough one -
/// but whatever ends up in that map, including any future policy-relevant
/// data, is faithfully represented as a triple, never silently dropped.
///
/// **Known limitation, not exercised by any current producer**: a
/// property key that happens to be exactly one of this mapping's own
/// reserved predicate IRIs would collide with this mapping's own
/// structural triples. For `Catalog.properties` and `Dataset.properties`
/// specifically (the only two generic key/value bags in the domain model
/// today - `Policy`/`Rule`/`Constraint` carry no such bag to collide
/// against): `rdf:type`, `dcat:dataset`, `dcat:service`,
/// `dcat:distribution`, `dcat:accessService`, `dcat:endpointURL`,
/// `dcat:endpointDescription`, `dct:format`, `fcns:participantId`,
/// `fcns:sequenceIndex`, and (new with the ODRL mapping above)
/// `odrl:hasPolicy` for `Dataset.properties`. The rest of the ODRL mapping's
/// own structural predicates - `odrl:permission`, `odrl:prohibition`,
/// `odrl:obligation`, `odrl:action`, `odrl:constraint`,
/// `odrl:leftOperand`, `odrl:operator`, `odrl:rightOperand`,
/// `odrl:assigner`, `odrl:assignee`, `odrl:and`, `odrl:or`, `odrl:xone`,
/// `odrl:andSequence`, and `fcns:policyId` - are reserved on
/// `Policy`/`Rule`/`Constraint` resources the same way, but those types
/// have no generic property map at all, so there is nothing for them to
/// collide with today either way. Flagged rather than defended against,
/// since nothing produces a colliding key today.
///
/// **Test coverage**: this crate's own tests prove the generic-properties
/// round trip through a real `OxigraphCatalogCache` (write, then read
/// back) with synthetic keys (e.g. `assetType`), and
/// `ds_catalog_broker_rs`'s
/// `catalog_request_route_serves_crawled_dataset_descriptors_from_a_real_oxigraph_store`
/// covers the full chain: the crawler parses a DSP dataset's
/// `title`/`description`/etc., upserts it into *this* store, and the
/// management API reads it back out.
///
/// ### Ordering (`fcns:sequenceIndex`)
///
/// `Catalog.datasets`, `Dataset.distributions`, `Catalog.data_services`,
/// `Dataset.policies`, `Policy.permissions`/`prohibitions`/`obligations`,
/// and `Rule.constraints` are all `Vec`s - order (and, for distributions
/// and constraints, even exact duplicates) is part of `Catalog`'s
/// `PartialEq`, but RDF triples are an unordered set. Each
/// dataset/distribution/data-service/policy/rule/constraint resource
/// therefore carries an explicit `fcns:sequenceIndex` integer literal
/// recording its original position within its own parent list, and
/// `query()` sorts by it when reconstructing each `Vec` - this is pure
/// bookkeeping to make an ordered domain type round-trip through an
/// unordered store faithfully, not domain data, hence the fallback
/// namespace rather than a borrowed vocabulary term (neither DCAT nor ODRL
/// has a concept of list ordering for any of these).
///
/// This also implicitly assumes `Dataset.id` (and `DataService.id`) are
/// unique within one catalog: two datasets sharing an id would collide
/// onto the same `<base>/datasets/<id>` resource. This mirrors real DSP
/// semantics (a JSON-LD node's `@id` is inherently unique - that is what
/// `@id` means) and is not otherwise enforced by `catalog-core::Dataset`.
pub mod oxigraph_backend {
    use super::*;
    use catalog_core::{
        Constraint, DataService, Dataset, Distribution, LogicalConstraint, Policy, PolicyKind, Rule,
    };
    use contreforts_kg::GraphError;
    use contreforts_kg::store::GraphStore;
    use oxigraph::model::{
        GraphName, GraphNameRef, Literal, NamedNode, NamedOrBlankNode, NamedOrBlankNodeRef, Quad,
        Term,
    };
    pub use oxigraph::sparql::CancellationToken;
    use oxigraph::sparql::results::{QueryResultsFormat, QueryResultsSerializer};
    use oxigraph::sparql::{
        PreparedSparqlQuery, QueryEvaluationError, QueryResults, SparqlEvaluator,
    };
    use oxigraph::store::StorageError;
    use spareval::{InternalQuad, QueryableDataset};
    use std::collections::{BTreeMap, BTreeSet};

    const NODE_NS: &str = "https://federated-catalog-rs.internal/nodes/";
    const INTERNAL_NS: &str = "https://federated-catalog-rs.internal/ns#";
    const INTERNAL_PROPERTY_PREFIX: &str = "https://federated-catalog-rs.internal/ns#property/";
    const DCAT_NS: &str = "http://www.w3.org/ns/dcat#";
    const DCT_NS: &str = "http://purl.org/dc/terms/";
    const ODRL_NS: &str = "http://www.w3.org/ns/odrl/2/";
    const RDF_TYPE_IRI: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

    /// Bounds how many nested `odrl:and`/`odrl:or`/`odrl:xone`/
    /// `odrl:andSequence` levels [`OxigraphCatalogCache::write_constraint`]
    /// and [`OxigraphCatalogCache::load_constraint`] will recurse into for
    /// one constraint tree - the exact same value and rationale as
    /// `crawler::MAX_CONSTRAINT_DEPTH` (deliberately kept in sync with it,
    /// and in turn with `ds-odrl-engine-rs::engine::constraint::MAX_CONSTRAINT_DEPTH`):
    /// a policy this store persists but the engine would then refuse to
    /// evaluate (or vice versa) would be a confusing, hard-to-diagnose
    /// mismatch between "stored" and "enforceable" for the exact same
    /// input. Applied independently of `crawler`'s own bound - a
    /// `Constraint` tree can reach this store from any caller, not only
    /// `crawler::parse_catalog_response`, so this store defends its own
    /// write/read recursion rather than trusting an upstream producer to
    /// have already bounded it.
    const MAX_CONSTRAINT_DEPTH: usize = 64;

    impl From<GraphError> for StoreError {
        fn from(err: GraphError) -> Self {
            StoreError::Backend(err.to_string())
        }
    }

    impl From<StorageError> for StoreError {
        fn from(err: StorageError) -> Self {
            StoreError::Backend(err.to_string())
        }
    }

    /// Errors specific to evaluating an arbitrary SPARQL query through
    /// [`OxigraphCatalogCache::sparql_query_json`] - kept distinct from
    /// [`StoreError`] because these are about a caller-supplied query
    /// string (usually the caller's own fault: bad syntax, an
    /// unsupported query form), not about the store itself.
    #[derive(Debug, Error)]
    pub enum SparqlError {
        /// The query string failed to parse as a SPARQL **Query** (the
        /// `SELECT`/`ASK`/`CONSTRUCT`/`DESCRIBE` grammar). This is also
        /// what happens for a SPARQL **Update** operation submitted here
        /// (`INSERT DATA`, `DELETE`, `LOAD`, `CLEAR`, ...): those belong to
        /// a different grammar entirely, one this method never parses
        /// with (see the method's own doc comment on why that alone is
        /// the read-only guarantee, not a separate check bolted on after).
        #[error("invalid SPARQL query: {0}")]
        Parse(String),
        /// The query parsed but failed during evaluation (e.g. a type
        /// error in a `FILTER` expression).
        #[error("SPARQL query evaluation failed: {0}")]
        Evaluation(String),
        /// The query was a well-formed `CONSTRUCT`/`DESCRIBE` - this
        /// method only serializes `SELECT`/`ASK` results (the gap
        /// analysis's stated minimum), since a graph result needs a
        /// different response media type (an RDF serialization, not
        /// `application/sparql-results+json`) that is out of scope here.
        #[error(
            "CONSTRUCT/DESCRIBE queries are not supported by this endpoint - only SELECT and ASK are"
        )]
        UnsupportedGraphResult,
        /// Writing the (already-evaluated) result set as
        /// `application/sparql-results+json` failed. Distinguished from
        /// `Evaluation` because a query that reaches this point already
        /// evaluated successfully - a failure here points at the
        /// serializer/writer, not at the caller's query.
        #[error("failed to serialize SPARQL results: {0}")]
        Serialize(String),
        /// [`SparqlLimits::cancellation`] was cancelled before evaluation
        /// finished - `ds-catalog-broker-rs` cancels it when a query runs
        /// past its time limit.
        #[error("SPARQL query was cancelled before it finished")]
        Cancelled,
        /// The query produced more solutions than
        /// [`SparqlLimits::max_rows`] allows. Evaluation stops at the first
        /// row over the limit; nothing is returned rather than a silently
        /// truncated result.
        #[error("SPARQL query returned more than {0} rows - add a LIMIT or narrow the query")]
        TooManyRows(usize),
    }

    /// Bounds on one [`OxigraphCatalogCache::sparql_query_json_limited`]
    /// evaluation. The default bounds nothing.
    #[derive(Clone, Default)]
    pub struct SparqlLimits {
        /// Checked by oxigraph on every triple-pattern lookup and result
        /// row: once cancelled, evaluation stops with
        /// [`SparqlError::Cancelled`] instead of running to completion.
        pub cancellation: Option<CancellationToken>,
        /// The most `SELECT` solutions a result may hold
        /// ([`SparqlError::TooManyRows`] beyond it).
        pub max_rows: Option<usize>,
    }

    pub type SparqlQueryResult<T> = Result<T, SparqlError>;

    // --- Fixed vocabulary terms -------------------------------------------------
    //
    // Constructed on demand rather than cached in a `static` - cheap to build,
    // and keeps this module free of `lazy_static`/`OnceLock` machinery for a
    // handful of constant IRIs, matching the style the JSON-blob version of
    // this module used for its own single `catalogJson` predicate.

    fn iri(value: impl Into<String>) -> NamedNode {
        NamedNode::new(value).expect("constant/percent-encoded IRI is valid")
    }

    fn dcat(local: &str) -> NamedNode {
        iri(format!("{DCAT_NS}{local}"))
    }

    fn dct(local: &str) -> NamedNode {
        iri(format!("{DCT_NS}{local}"))
    }

    fn internal(local: &str) -> NamedNode {
        iri(format!("{INTERNAL_NS}{local}"))
    }

    fn rdf_type() -> NamedNode {
        iri(RDF_TYPE_IRI)
    }

    fn dcat_catalog_class() -> NamedNode {
        dcat("Catalog")
    }

    fn dcat_dataset_class() -> NamedNode {
        dcat("Dataset")
    }

    fn dcat_distribution_class() -> NamedNode {
        dcat("Distribution")
    }

    fn dcat_data_service_class() -> NamedNode {
        dcat("DataService")
    }

    fn dcat_dataset_pred() -> NamedNode {
        dcat("dataset")
    }

    fn dcat_service_pred() -> NamedNode {
        dcat("service")
    }

    fn dcat_distribution_pred() -> NamedNode {
        dcat("distribution")
    }

    fn dcat_access_service_pred() -> NamedNode {
        dcat("accessService")
    }

    fn dcat_endpoint_url_pred() -> NamedNode {
        dcat("endpointURL")
    }

    fn dcat_endpoint_description_pred() -> NamedNode {
        dcat("endpointDescription")
    }

    fn dct_format_pred() -> NamedNode {
        dct("format")
    }

    fn participant_id_pred() -> NamedNode {
        internal("participantId")
    }

    fn sequence_index_pred() -> NamedNode {
        internal("sequenceIndex")
    }

    fn odrl(local: &str) -> NamedNode {
        iri(format!("{ODRL_NS}{local}"))
    }

    fn odrl_has_policy_pred() -> NamedNode {
        odrl("hasPolicy")
    }

    fn odrl_permission_pred() -> NamedNode {
        odrl("permission")
    }

    fn odrl_prohibition_pred() -> NamedNode {
        odrl("prohibition")
    }

    fn odrl_obligation_pred() -> NamedNode {
        odrl("obligation")
    }

    fn odrl_action_pred() -> NamedNode {
        odrl("action")
    }

    fn odrl_constraint_pred() -> NamedNode {
        odrl("constraint")
    }

    fn odrl_left_operand_pred() -> NamedNode {
        odrl("leftOperand")
    }

    fn odrl_operator_pred() -> NamedNode {
        odrl("operator")
    }

    fn odrl_right_operand_pred() -> NamedNode {
        odrl("rightOperand")
    }

    fn odrl_and_pred() -> NamedNode {
        odrl("and")
    }

    fn odrl_or_pred() -> NamedNode {
        odrl("or")
    }

    fn odrl_xone_pred() -> NamedNode {
        odrl("xone")
    }

    fn odrl_and_sequence_pred() -> NamedNode {
        odrl("andSequence")
    }

    /// Constructor signature shared by [`Constraint::and`],
    /// [`Constraint::or`], [`Constraint::xone`], and
    /// [`Constraint::and_sequence`] - factored into a named alias purely
    /// so [`logical_constraint_preds`]'s own type stays readable, mirroring
    /// `crawler::LogicalConstraintBuilder`.
    type LogicalConstraintBuilder = fn(Vec<Constraint>) -> Constraint;

    /// The four `odrl:`-namespaced logical-group predicates, each paired
    /// with the `catalog_core::Constraint` constructor for that combinator,
    /// in the same fixed precedence [`crawler::LOGICAL_CONSTRAINT_KEYS`]
    /// uses when parsing (`xone`, then `or`, then `and`, then
    /// `andSequence`): [`OxigraphCatalogCache::load_constraint`] checks
    /// them in this order, so a hand-crafted constraint resource carrying
    /// more than one (malformed - this store's own write path only ever
    /// emits one) is at least read back the same way `crawler` would parse
    /// the equivalent malformed JSON-LD, rather than an arbitrary one.
    fn logical_constraint_preds() -> [(NamedNode, LogicalConstraintBuilder); 4] {
        [
            (odrl_xone_pred(), Constraint::xone),
            (odrl_or_pred(), Constraint::or),
            (odrl_and_pred(), Constraint::and),
            (odrl_and_sequence_pred(), Constraint::and_sequence),
        ]
    }

    fn odrl_assigner_pred() -> NamedNode {
        odrl("assigner")
    }

    fn odrl_assignee_pred() -> NamedNode {
        odrl("assignee")
    }

    /// `Policy.id`'s literal home - see the module doc's "Triples emitted"
    /// section (policy resource bullets) for why this is a fallback
    /// `fcns:` term rather than an ODRL one.
    fn policy_id_pred() -> NamedNode {
        internal("policyId")
    }

    /// The `odrl:<Kind>` class matching a [`PolicyKind`].
    fn odrl_policy_class(kind: PolicyKind) -> NamedNode {
        match kind {
            PolicyKind::Set => odrl("Set"),
            PolicyKind::Offer => odrl("Offer"),
            PolicyKind::Agreement => odrl("Agreement"),
        }
    }

    /// Inverse of [`odrl_policy_class`]: which [`PolicyKind`] a policy
    /// resource's `rdf:type` object names.
    fn policy_kind_from_class(class: &NamedNode) -> StoreResult<PolicyKind> {
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
    /// already an absolute IRI - see the module doc's "Generic properties".
    fn property_predicate(key: &str) -> NamedNode {
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
    fn decode_property_key(pred: &NamedNode) -> String {
        match pred.as_str().strip_prefix(INTERNAL_PROPERTY_PREFIX) {
            Some(rest) => urlencoding::decode(rest)
                .map(|cow| cow.into_owned())
                .unwrap_or_else(|_| rest.to_string()),
            None => pred.as_str().to_string(),
        }
    }

    // --- Resource IRI construction ----------------------------------------------

    /// The base IRI for `node`'s named graph, also the prefix every
    /// resource IRI within that graph is built from. Percent-encoding the
    /// node id guarantees a valid IRI regardless of what characters the id
    /// contains.
    fn node_base(node: &NodeId) -> String {
        format!("{NODE_NS}{}", urlencoding::encode(&node.0))
    }

    /// The subject / named-graph IRI for `node`.
    fn node_iri(node: &NodeId) -> NamedNode {
        iri(node_base(node))
    }

    fn catalog_iri(node_base: &str, catalog_id: &str) -> NamedNode {
        iri(format!(
            "{node_base}/catalogs/{}",
            urlencoding::encode(catalog_id)
        ))
    }

    fn dataset_iri(node_base: &str, dataset_id: &str) -> NamedNode {
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

    fn distribution_iri(node_base: &str, dataset_id: &str, index: usize) -> NamedNode {
        iri(format!(
            "{node_base}/datasets/{}/distributions/{index}",
            urlencoding::encode(dataset_id)
        ))
    }

    fn service_iri(node_base: &str, service_id: &str) -> NamedNode {
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

    fn policy_iri(node_base: &str, dataset_id: &str, index: usize) -> NamedNode {
        iri(format!(
            "{node_base}/datasets/{}/policies/{index}",
            urlencoding::encode(dataset_id)
        ))
    }

    /// A permission/prohibition/obligation resource IRI - `segment` is
    /// `"permissions"`, `"prohibitions"`, or `"obligations"` (see the
    /// module doc's "Resource IRIs").
    fn rule_iri(policy_iri: &str, segment: &str, index: usize) -> NamedNode {
        iri(format!("{policy_iri}/{segment}/{index}"))
    }

    fn constraint_iri(rule_iri: &str, index: usize) -> NamedNode {
        iri(format!("{rule_iri}/constraints/{index}"))
    }

    /// Strip `prefix` off `iri` and percent-decode the remainder - the
    /// inverse of how every resource IRI above was built from an id.
    fn strip_prefix_decode(iri: &str, prefix: &str) -> StoreResult<String> {
        let rest = iri.strip_prefix(prefix).ok_or_else(|| {
            StoreError::Backend(format!("expected IRI '{iri}' to start with '{prefix}'"))
        })?;
        urlencoding::decode(rest)
            .map(|cow| cow.into_owned())
            .map_err(|e| StoreError::Backend(format!("invalid percent-encoding in '{iri}': {e}")))
    }

    fn decode_node_id(graph_iri: &NamedNode) -> StoreResult<NodeId> {
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
    fn iri_or_literal_term(value: &str) -> Term {
        match NamedNode::new(value) {
            Ok(node) => Term::from(node),
            Err(_) => Term::from(Literal::from(value.to_string())),
        }
    }

    /// A literal's lexical value, or a `NamedNode`'s IRI string - covers
    /// both shapes [`iri_or_literal_term`] can produce, so loading is
    /// agnostic to which one a given stored value took.
    fn term_as_string(term: &Term) -> StoreResult<String> {
        match term {
            Term::Literal(lit) => Ok(lit.value().to_string()),
            Term::NamedNode(node) => Ok(node.as_str().to_string()),
            other => Err(StoreError::Backend(format!(
                "expected a literal or IRI term, got {other:?}"
            ))),
        }
    }

    fn expect_named_node(term: Term, context: &str) -> StoreResult<NamedNode> {
        match term {
            Term::NamedNode(node) => Ok(node),
            other => Err(StoreError::Backend(format!(
                "expected a named node for {context}, got {other:?}"
            ))),
        }
    }

    /// A [`CatalogCache`] backed by a real `contreforts_kg::store::GraphStore`
    /// (Oxigraph under the hood).
    pub struct OxigraphCatalogCache {
        store: GraphStore,
    }

    impl OxigraphCatalogCache {
        /// Wrap an in-memory Oxigraph store. Useful for tests, and for any
        /// caller that wants the real RDF/SPARQL machinery without
        /// persistence.
        pub fn in_memory() -> StoreResult<Self> {
            let store = GraphStore::in_memory()?;
            Ok(Self { store })
        }

        /// Quads matching the given pattern, always scoped to `graph` -
        /// every read this backend does is graph-scoped, so `graph` is a
        /// required parameter here rather than another `Option`.
        fn quads(
            &self,
            subject: Option<&NamedNode>,
            predicate: Option<&NamedNode>,
            object: Option<&Term>,
            graph: &NamedNode,
        ) -> StoreResult<Vec<Quad>> {
            self.store
                .inner()
                .quads_for_pattern(
                    subject.map(|s| s.into()),
                    predicate.map(|p| p.into()),
                    object.map(|o| o.into()),
                    Some(graph.into()),
                )
                .collect::<Result<Vec<_>, _>>()
                .map_err(StoreError::from)
        }

        /// The first object found for `(subject, predicate, ?, graph)`, if
        /// any.
        fn first_object(
            &self,
            subject: &NamedNode,
            predicate: &NamedNode,
            graph: &NamedNode,
        ) -> StoreResult<Option<Term>> {
            Ok(self
                .quads(Some(subject), Some(predicate), None, graph)?
                .into_iter()
                .next()
                .map(|quad| quad.object))
        }

        fn sequence_index(&self, subject: &NamedNode, graph: &NamedNode) -> StoreResult<usize> {
            let term = self
                .first_object(subject, &sequence_index_pred(), graph)?
                .ok_or_else(|| {
                    StoreError::Backend(format!(
                        "{} is missing fcns:sequenceIndex",
                        subject.as_str()
                    ))
                })?;
            match term {
                Term::Literal(lit) => lit
                    .value()
                    .parse::<usize>()
                    .map_err(|e| StoreError::Backend(format!("invalid sequenceIndex: {e}"))),
                other => Err(StoreError::Backend(format!(
                    "sequenceIndex must be a literal, got {other:?}"
                ))),
            }
        }

        /// Whether `graph` currently holds any quad at all.
        fn graph_nonempty(&self, graph: &NamedNode) -> StoreResult<bool> {
            Ok(!self.quads(None, None, None, graph)?.is_empty())
        }

        /// Remove every quad in `graph`, regardless of subject - the
        /// "replace wholesale" half of `upsert`, and all of `delete`.
        fn clear_named_graph(&self, graph: &NamedNode) -> StoreResult<()> {
            self.store.inner().remove_named_graph(graph)?;
            Ok(())
        }

        fn insert(
            &self,
            subject: &NamedNode,
            predicate: &NamedNode,
            object: &Term,
            graph: &NamedNode,
        ) -> StoreResult<()> {
            self.store
                .insert_in_named_graph(subject, predicate, object, graph)?;
            Ok(())
        }

        /// Write every triple for `catalog` into `graph` - see this
        /// module's own doc comment for the exact mapping.
        fn write_catalog(&self, catalog: &Catalog, graph: &NamedNode) -> StoreResult<()> {
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
        /// See the module doc's "Triples emitted" section (policy resource
        /// bullets) for the exact mapping.
        fn write_policy(
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
        fn write_rules(
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

        fn write_rule(
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
        /// module doc's "Triples emitted" section (constraint resource
        /// bullets) for why.
        ///
        /// A [`Constraint::Logical`] writes one `odrl:and`/`odrl:or`/
        /// `odrl:xone`/`odrl:andSequence` link triple per child (matching
        /// the combinator), then recurses into [`write_constraint`] for
        /// each child at `depth + 1` - see the module doc's "Logical
        /// constraint groups" note. Bounded by [`MAX_CONSTRAINT_DEPTH`]: a
        /// child that would be written past the bound is skipped entirely,
        /// including its link triple, so no dangling/incomplete constraint
        /// resource is ever left in the graph - mirroring
        /// `crawler::parse_constraint` dropping an over-deep entry from the
        /// parsed `Vec` outright rather than including a truncated one.
        fn write_constraint(
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

        /// Reconstruct the [`Catalog`] stored in `graph` for `node`, if any
        /// (`None` when the graph holds no `dcat:Catalog` resource at all -
        /// i.e. nothing has ever been upserted for this node).
        fn load_catalog(&self, node: &NodeId, graph: &NamedNode) -> StoreResult<Option<Catalog>> {
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

        fn load_dataset(
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

        fn load_policy(
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
        fn load_rules(
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

        fn load_rule(&self, subject: &NamedNode, graph: &NamedNode) -> StoreResult<(usize, Rule)> {
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
        fn load_constraint(
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
                        StoreError::Backend(format!(
                            "{} is missing odrl:operator",
                            subject.as_str()
                        ))
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

        fn load_distribution(
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

        fn load_data_service(
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

        /// Evaluate an arbitrary, caller-supplied SPARQL query and return
        /// the result serialized as
        /// [`application/sparql-results+json`](https://www.w3.org/TR/sparql11-results-json/)
        /// bytes - the HTTP surface in `ds-catalog-broker-rs` (gap analysis
        /// §3.3) writes these bytes straight through as the response body.
        ///
        /// ## Why this lives here, not on the `CatalogCache` trait
        ///
        /// SPARQL evaluation is an Oxigraph-specific capability with no
        /// equivalent in [`memory::InMemoryCatalogCache`] (a plain
        /// `HashMap`, not an RDF store at all) - forcing every backend to
        /// implement it would mean either a panic/`Err` stub on the
        /// in-memory side or inventing a query language the in-memory
        /// backend could actually serve, neither of which is worth it for
        /// a backend that exists only to unblock tests and the
        /// no-crawler-configured default (see this crate's module doc).
        /// So this is an inherent method on the concrete
        /// [`OxigraphCatalogCache`] type instead - additive, doesn't touch
        /// the trait's signature at all. The HTTP layer holds an
        /// `Option<Arc<OxigraphCatalogCache>>` alongside its
        /// `Arc<dyn CatalogCache>` and answers "SPARQL not available" (501)
        /// when it's `None`, i.e. whenever the in-memory backend is
        /// running.
        ///
        /// ## Why the whole store, not one named graph, by default
        ///
        /// A crawled catalog's triples live in a per-origin-node named
        /// graph (this module's own "Named graph" mapping above), not the
        /// default graph - so a plain `SELECT * WHERE { ?s ?p ?o }` with no
        /// `GRAPH` clause would, under SPARQL's normal rules, match only
        /// the (always-empty) default graph and never see any harvested
        /// data at all. That would silently defeat "search everything I've
        /// harvested", the primary use case the gap analysis calls out.
        /// Instead, whenever the query itself does not already specify its
        /// own dataset (no `FROM`/`FROM NAMED`, checked via
        /// `QueryDataset::is_default_dataset`), this method sets the
        /// query's default graph to the union of every named graph in the
        /// store (`QueryDataset::set_default_graph_as_union`) before
        /// executing it - so a plain triple pattern with no `GRAPH` clause
        /// searches every harvested participant's graph at once, which is
        /// what "the whole store" should mean here.
        ///
        /// A caller that wants to scope to one participant still can,
        /// without any bespoke query-param feature, via SPARQL's own
        /// `GRAPH <iri>` clause (the exact graph IRI scheme is documented
        /// above, under "Resource IRIs") - or via the query's own
        /// `FROM`/`FROM NAMED`, which this method leaves untouched when
        /// present (`is_default_dataset()` is only true when the query
        /// didn't specify one itself). That satisfies the gap analysis's
        /// stretch goal ("via SPARQL's own GRAPH clause... rather than a
        /// bespoke query-param feature") without any extra code here.
        ///
        /// ## Why this is inherently read-only
        ///
        /// This method only ever calls [`SparqlEvaluator::parse_query`],
        /// which parses the SPARQL 1.1 **Query** grammar
        /// (`SELECT`/`ASK`/`CONSTRUCT`/`DESCRIBE`) - never
        /// `SparqlEvaluator::parse_update` or `Store::update`, which is
        /// the only code path in `oxigraph` that can mutate a store via
        /// SPARQL. A SPARQL Update string (`INSERT DATA { ... }`,
        /// `DELETE ...`, `LOAD`, `CLEAR`, ...) simply fails to parse as a
        /// Query - it is not reachable through this method at all, not
        /// merely rejected after being recognized. See
        /// `sparql_update_operation_is_rejected_not_silently_ignored`
        /// below for a test proving this.
        ///
        /// ## Result shape
        ///
        /// - `ASK` -> `{"head":{},"boolean":<bool>}`.
        /// - `SELECT` -> `{"head":{"vars":[...]},"results":{"bindings":[...]}}`,
        ///   using `oxigraph`'s own `sparesults`-backed serializer, so IRI
        ///   vs. literal vs. blank node, datatypes, and language tags all
        ///   come out exactly per the W3C JSON Results spec - this method
        ///   never hand-rolls that format.
        /// - `CONSTRUCT`/`DESCRIBE` -> `Err(SparqlError::UnsupportedGraphResult)`,
        ///   see that variant's own doc comment.
        pub fn sparql_query_json(&self, query: &str) -> SparqlQueryResult<Vec<u8>> {
            self.sparql_query_json_limited(query, None, &SparqlLimits::default())
        }

        /// [`Self::sparql_query_json`], evaluated over only the part of the
        /// store a caller may see: every harvested dataset or data service
        /// whose resource IRI ([`dataset_resource_iri`],
        /// [`service_resource_iri`]) is not in `visible_resource_iris` is
        /// treated as absent, along with everything minted under it.
        ///
        /// ## Why hide at the data level, not only in the query
        ///
        /// Rewriting the caller's query can only restrict the variables
        /// it recognizes as a dataset subject: a sibling `UNION`/`OPTIONAL`
        /// branch, or any triple pattern on another variable, can still
        /// read a hidden dataset's triples. Filtering the data the query
        /// runs over is sound for every query shape, because no pattern
        /// can match a triple that is not there.
        ///
        /// ## What is hidden
        ///
        /// A quad is dropped when its subject or object belongs to a
        /// dataset or data service ([`owning_resource_iri`]) that is not in
        /// `visible_resource_iris` - so the catalog's own `dcat:dataset` /
        /// `dcat:service` links to it disappear too. This store never mints
        /// blank nodes, so every such resource is reachable that way.
        ///
        /// - **An allow-list, not a deny-list.** A dataset or service
        ///   harvested after the caller computed its allow-list (a crawl
        ///   landing mid-request) is hidden, not leaked.
        /// - **No position numbers.** Every `internal:sequenceIndex` quad is
        ///   dropped: visible datasets would otherwise keep their original
        ///   positions, and the gaps would show where hidden ones were.
        ///
        /// ## Cost
        ///
        /// Nothing is copied: the query runs through oxigraph's own
        /// evaluator over a [`VisibleDataset`] view of the live store,
        /// which filters each triple-pattern lookup as it happens. A
        /// lookup whose bound subject or object belongs to a hidden
        /// resource returns nothing without reading the store, so its cost
        /// doesn't depend on whether that resource exists. A lookup by a
        /// literal value (e.g. a guessed title) still reads and discards
        /// hidden matches, so its timing can differ slightly when one
        /// exists.
        ///
        /// ## Known differences from [`Self::sparql_query_json`]
        ///
        /// - **Not one snapshot.** Each lookup reads the store as it is at
        ///   that moment (unlike `sparql_query_json`, which reads one
        ///   snapshot per query), and the caller computes
        ///   `visible_resource_iris` before evaluation starts. A crawl
        ///   landing mid-request can therefore show an allow-listed
        ///   dataset's newer triples. It cannot show anything not on the
        ///   allow-list.
        /// - **No numeric canonicalization.** Terms are compared as written:
        ///   `"01"^^xsd:integer` in a query doesn't match a stored `1`. The
        ///   only typed numbers this store writes are the position numbers
        ///   this view drops anyway.
        pub fn sparql_query_json_restricted(
            &self,
            query: &str,
            visible_resource_iris: &BTreeSet<String>,
        ) -> SparqlQueryResult<Vec<u8>> {
            self.sparql_query_json_limited(
                query,
                Some(visible_resource_iris),
                &SparqlLimits::default(),
            )
        }

        /// [`Self::sparql_query_json`] (`visible_resource_iris: None`) or
        /// [`Self::sparql_query_json_restricted`] (`Some`), bounded by
        /// `limits` - see [`SparqlLimits`].
        pub fn sparql_query_json_limited(
            &self,
            query: &str,
            visible_resource_iris: Option<&BTreeSet<String>>,
            limits: &SparqlLimits,
        ) -> SparqlQueryResult<Vec<u8>> {
            let prepared = Self::prepare_sparql(query, limits.cancellation.clone())?;
            let results = match visible_resource_iris {
                None => prepared.on_store(self.store.inner()).execute(),
                Some(visible_resource_iris) => prepared
                    .on_queryable_dataset(VisibleDataset {
                        store: self.store.inner(),
                        visible_resource_iris,
                    })
                    .execute(),
            }
            .map_err(evaluation_error)?;
            serialize_sparql_results(results, limits.max_rows)
        }

        /// Parses `query` (Query grammar only - see "Why this is inherently
        /// read-only" on [`Self::sparql_query_json`]) and defaults its
        /// dataset to the union of every named graph.
        fn prepare_sparql(
            query: &str,
            cancellation: Option<CancellationToken>,
        ) -> SparqlQueryResult<PreparedSparqlQuery> {
            let mut evaluator = SparqlEvaluator::new();
            if let Some(token) = cancellation {
                evaluator = evaluator.with_cancellation_token(token);
            }
            let mut prepared = evaluator
                .parse_query(query)
                .map_err(|err| SparqlError::Parse(err.to_string()))?;

            if prepared.dataset().is_default_dataset() {
                prepared.dataset_mut().set_default_graph_as_union();
            }
            Ok(prepared)
        }
    }

    fn evaluation_error(err: QueryEvaluationError) -> SparqlError {
        match err {
            QueryEvaluationError::Cancelled => SparqlError::Cancelled,
            err => SparqlError::Evaluation(err.to_string()),
        }
    }

    fn serialize_sparql_results(
        results: QueryResults<'_>,
        max_rows: Option<usize>,
    ) -> SparqlQueryResult<Vec<u8>> {
        let serializer = QueryResultsSerializer::from_format(QueryResultsFormat::Json);
        match results {
            QueryResults::Boolean(value) => serializer
                .serialize_boolean_to_writer(Vec::new(), value)
                .map_err(|err| SparqlError::Serialize(err.to_string())),
            QueryResults::Solutions(solutions) => {
                let variables = solutions.variables().to_vec();
                let mut writer = serializer
                    .serialize_solutions_to_writer(Vec::new(), variables)
                    .map_err(|err| SparqlError::Serialize(err.to_string()))?;
                for (row, solution) in solutions.enumerate() {
                    if let Some(max_rows) = max_rows
                        && row >= max_rows
                    {
                        return Err(SparqlError::TooManyRows(max_rows));
                    }
                    let solution = solution.map_err(evaluation_error)?;
                    writer
                        .serialize(&solution)
                        .map_err(|err| SparqlError::Serialize(err.to_string()))?;
                }
                writer
                    .finish()
                    .map_err(|err| SparqlError::Serialize(err.to_string()))
            }
            QueryResults::Graph(_) => Err(SparqlError::UnsupportedGraphResult),
        }
    }

    /// The harvested resource `iri` belongs to, for allow-list purposes.
    /// Fails closed: anything this store minted under a node other than
    /// the node IRI itself and its catalogs belongs to *something*, and is
    /// visible only when that something is on the allow-list.
    ///
    /// - `None` (never gated): any IRI outside [`NODE_NS`], the node IRI
    ///   itself, and `{node_base}/catalogs/...`, which `GET /catalog` shows
    ///   every caller too.
    /// - `{node_base}/datasets/{id}` or `{node_base}/services/{id}`, for
    ///   that IRI or anything minted under it. `id` may be empty: an
    ///   `"@id": ""` dataset is still that dataset ([`dataset_resource_iri`]
    ///   with an empty id produces exactly this owner).
    /// - `iri` itself, for anything else under a node: nothing is allowed
    ///   to list it, so it stays hidden.
    ///
    /// Node, dataset and service ids are percent-encoded, so none of them
    /// can contain a literal `/`.
    fn owning_resource_iri(iri: &str) -> Option<&str> {
        let rest = iri.strip_prefix(NODE_NS)?;
        let (node, tail) = rest.split_once('/')?;
        let (kind, after_kind) = tail.split_once('/').unwrap_or((tail, ""));
        match kind {
            "catalogs" => None,
            "datasets" | "services" if tail.len() > kind.len() => {
                let id = after_kind.split('/').next().unwrap_or("");
                Some(&iri[..NODE_NS.len() + node.len() + 1 + kind.len() + 1 + id.len()])
            }
            _ => Some(iri),
        }
    }

    /// `internal:sequenceIndex`, as a constant string so the per-quad check
    /// in [`quad_is_visible`] doesn't rebuild and re-validate the IRI.
    const SEQUENCE_INDEX_IRI: &str = "https://federated-catalog-rs.internal/ns#sequenceIndex";

    /// Whether `iri` is outside every resource, or belongs to one on
    /// `visible_resource_iris` - see [`owning_resource_iri`].
    fn iri_is_visible(iri: &str, visible_resource_iris: &BTreeSet<String>) -> bool {
        owning_resource_iri(iri).is_none_or(|owner| visible_resource_iris.contains(owner))
    }

    /// Whether a caller restricted to `visible_resource_iris` may see
    /// `quad` - see [`OxigraphCatalogCache::sparql_query_json_restricted`].
    fn quad_is_visible(quad: &Quad, visible_resource_iris: &BTreeSet<String>) -> bool {
        if quad.predicate.as_str() == SEQUENCE_INDEX_IRI {
            return false;
        }
        let subject_visible = match &quad.subject {
            NamedOrBlankNode::NamedNode(node) => {
                iri_is_visible(node.as_str(), visible_resource_iris)
            }
            NamedOrBlankNode::BlankNode(_) => true,
        };
        let object_visible = match &quad.object {
            Term::NamedNode(node) => iri_is_visible(node.as_str(), visible_resource_iris),
            Term::BlankNode(_) | Term::Literal(_) => true,
            // A triple term (only with oxigraph's RDF 1.2 support, which this
            // workspace doesn't enable, and never written by this store):
            // hidden rather than inspected.
            #[allow(unreachable_patterns)]
            _ => false,
        };
        subject_visible && object_visible
    }

    /// Whether `graph` holds a `dcat:Catalog` type quad.
    fn graph_holds_a_catalog(
        store: &oxigraph::store::Store,
        graph: NamedOrBlankNodeRef<'_>,
    ) -> Result<bool, StorageError> {
        store
            .quads_for_pattern(
                None,
                Some(rdf_type().as_ref()),
                Some(dcat_catalog_class().as_ref().into()),
                Some(graph.into()),
            )
            .next()
            .transpose()
            .map(|quad| quad.is_some())
    }

    /// The live store, minus every quad [`quad_is_visible`] rejects, as a
    /// dataset oxigraph's SPARQL evaluator can query directly. Terms are
    /// passed through as plain [`Term`]s; `FROM`/`FROM NAMED` and the
    /// default-graph-as-union setting are applied by the evaluator on top
    /// of this view, exactly as for [`Store`](oxigraph::store::Store).
    #[derive(Clone, Copy)]
    struct VisibleDataset<'a> {
        store: &'a oxigraph::store::Store,
        visible_resource_iris: &'a BTreeSet<String>,
    }

    impl<'a> QueryableDataset<'a> for VisibleDataset<'a> {
        type InternalTerm = Term;
        type Error = StorageError;

        fn internal_quads_for_pattern(
            &self,
            subject: Option<&Term>,
            predicate: Option<&Term>,
            object: Option<&Term>,
            graph_name: Option<Option<&Term>>,
        ) -> impl Iterator<Item = Result<InternalQuad<Term>, StorageError>> + use<'a> {
            let Self {
                store,
                visible_resource_iris,
            } = *self;

            // A bound term that cannot appear in that position (a literal
            // subject, a non-IRI predicate, a literal graph name) matches
            // nothing.
            let subject = match subject {
                None => Some(None),
                Some(Term::NamedNode(node)) => Some(Some(NamedOrBlankNodeRef::from(node))),
                Some(Term::BlankNode(node)) => Some(Some(NamedOrBlankNodeRef::from(node))),
                Some(_) => None,
            };
            let predicate = match predicate {
                None => Some(None),
                Some(Term::NamedNode(node)) => Some(Some(node.as_ref())),
                Some(_) => None,
            };
            // `None` = any named graph (not the default one), per
            // `QueryableDataset`'s contract.
            let graph = match graph_name {
                None => Some(None),
                Some(None) => Some(Some(GraphNameRef::DefaultGraph)),
                Some(Some(Term::NamedNode(node))) => Some(Some(GraphNameRef::from(node))),
                Some(Some(Term::BlankNode(node))) => Some(Some(GraphNameRef::from(node))),
                Some(Some(_)) => None,
            };
            let named_graphs_only = graph_name.is_none();

            // A bound subject or object owned by a hidden resource can match
            // nothing visible: answer without reading the store, so lookup
            // cost doesn't reveal whether the hidden resource exists.
            let bound_iri_hidden = [
                subject.flatten(),
                object.and_then(|o| match o {
                    Term::NamedNode(node) => Some(NamedOrBlankNodeRef::from(node)),
                    _ => None,
                }),
            ]
            .into_iter()
            .flatten()
            .any(|term| match term {
                NamedOrBlankNodeRef::NamedNode(node) => {
                    !iri_is_visible(node.as_str(), visible_resource_iris)
                }
                NamedOrBlankNodeRef::BlankNode(_) => false,
            });

            let quads = match (subject, predicate, graph) {
                _ if bound_iri_hidden => None,
                (Some(subject), Some(predicate), Some(graph)) => Some(store.quads_for_pattern(
                    subject,
                    predicate,
                    object.map(Term::as_ref),
                    graph,
                )),
                _ => None,
            };

            quads.into_iter().flatten().filter_map(move |quad| {
                let quad = match quad {
                    Ok(quad) => quad,
                    Err(err) => return Some(Err(err)),
                };
                if named_graphs_only && quad.graph_name.is_default_graph() {
                    return None;
                }
                if !quad_is_visible(&quad, visible_resource_iris) {
                    return None;
                }
                Some(Ok(InternalQuad {
                    subject: quad.subject.into(),
                    predicate: quad.predicate.into(),
                    object: quad.object,
                    graph_name: match quad.graph_name {
                        GraphName::DefaultGraph => None,
                        GraphName::NamedNode(node) => Some(node.into()),
                        GraphName::BlankNode(node) => Some(node.into()),
                    },
                }))
            })
        }

        /// Every named graph holding a catalog. Each graph this store
        /// writes holds its `dcat:Catalog` type quad, which is never
        /// hidden, so this lists exactly the graphs with visible content -
        /// straight from the store's graph index rather than the trait's
        /// default full-quad scan, which made `GRAPH ?g {}` cost a scan of
        /// the whole store per evaluation.
        fn internal_named_graphs(
            &self,
        ) -> impl Iterator<Item = Result<Term, StorageError>> + use<'a> {
            let store = self.store;
            store.named_graphs().filter_map(move |graph| match graph {
                Err(err) => Some(Err(err)),
                Ok(graph) => match graph_holds_a_catalog(store, graph.as_ref()) {
                    Ok(true) => Some(Ok(graph.into())),
                    Ok(false) => None,
                    Err(err) => Some(Err(err)),
                },
            })
        }

        fn contains_internal_graph_name(&self, graph_name: &Term) -> Result<bool, StorageError> {
            match graph_name {
                Term::NamedNode(node) => graph_holds_a_catalog(self.store, node.as_ref().into()),
                Term::BlankNode(node) => graph_holds_a_catalog(self.store, node.as_ref().into()),
                _ => Ok(false),
            }
        }

        fn internalize_term(&self, term: Term) -> Result<Term, StorageError> {
            Ok(term)
        }

        fn externalize_term(&self, term: Term) -> Result<Term, StorageError> {
            Ok(term)
        }
    }

    #[async_trait]
    impl CatalogCache for OxigraphCatalogCache {
        async fn upsert(&self, catalog: Catalog) -> StoreResult<()> {
            let graph = node_iri(&catalog.origin_node);
            // Insert-or-replace: clear any prior graph for this node first,
            // matching the in-memory impl's `HashMap::insert` overwrite
            // semantics (and EDC's upsert-by-origin-node-url behavior).
            self.clear_named_graph(&graph)?;
            self.write_catalog(&catalog, &graph)?;
            Ok(())
        }

        async fn query(&self, query: CatalogQuery) -> StoreResult<Vec<Catalog>> {
            let mut results: Vec<Catalog> = Vec::new();

            match &query.origin_node {
                Some(node) => {
                    let graph = node_iri(node);
                    if let Some(catalog) = self.load_catalog(node, &graph)? {
                        results.push(catalog);
                    }
                }
                None => {
                    let graph_names: Vec<NamedOrBlankNode> = self
                        .store
                        .inner()
                        .named_graphs()
                        .collect::<Result<_, _>>()?;
                    for graph in graph_names {
                        let NamedOrBlankNode::NamedNode(graph_iri) = graph else {
                            // This backend never writes blank-node graphs.
                            continue;
                        };
                        let node = decode_node_id(&graph_iri)?;
                        if let Some(catalog) = self.load_catalog(&node, &graph_iri)? {
                            results.push(catalog);
                        }
                    }
                }
            }

            // Same deterministic ordering + pagination as `memory`'s
            // implementation, so the two backends are behavior-equivalent.
            results.sort_by(|a, b| a.id.cmp(&b.id));

            let skipped = results.into_iter().skip(query.offset);
            let limited: Vec<Catalog> = match query.limit {
                Some(limit) => skipped.take(limit).collect(),
                None => skipped.collect(),
            };
            Ok(limited)
        }

        async fn delete(&self, node: &NodeId) -> StoreResult<bool> {
            let graph = node_iri(node);
            let existed = self.graph_nonempty(&graph)?;
            if existed {
                self.clear_named_graph(&graph)?;
            }
            Ok(existed)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use catalog_core::LogicalConstraint;

        fn sample_catalog(node: &str, id: &str) -> Catalog {
            Catalog::new(id, NodeId::new(node))
        }

        fn cache() -> OxigraphCatalogCache {
            OxigraphCatalogCache::in_memory().unwrap()
        }

        /// A catalog exercising every field the domain model has: nested
        /// datasets with properties, distributions, and a policy, a data
        /// service, a participant id, and catalog-level properties. Used by
        /// the round-trip and real-decomposition tests below. A more
        /// elaborate, ordering-focused policy fixture lives separately in
        /// `policy_catalog` below - kept out of this shared fixture so it
        /// doesn't perturb the quad-count/predicate assertions the other
        /// tests below make against `rich_catalog`.
        fn rich_catalog() -> Catalog {
            let mut catalog = Catalog::new("cat-rich", NodeId::new("node-rich"));
            catalog.participant_id = Some("did:example:rich-participant".to_string());
            catalog.properties.insert(
                "http://www.w3.org/ns/dcat#keyword".to_string(),
                "logistics".to_string(),
            );
            catalog
                .properties
                .insert("internalLabel".to_string(), "demo".to_string());

            let mut ds1_properties = BTreeMap::new();
            ds1_properties.insert("assetType".to_string(), "data.rest".to_string());
            catalog.datasets.push(Dataset {
                id: "ds-1".to_string(),
                properties: ds1_properties,
                distributions: vec![
                    Distribution {
                        format: "application/json".to_string(),
                        access_service: "svc-1".to_string(),
                    },
                    Distribution {
                        format: "application/xml".to_string(),
                        access_service: "svc-1".to_string(),
                    },
                ],
                policies: vec![Policy {
                    id: None,
                    kind: PolicyKind::Set,
                    assigner: None,
                    assignee: None,
                    permissions: vec![Rule {
                        action: "use".to_string(),
                        constraints: Vec::new(),
                    }],
                    prohibitions: Vec::new(),
                    obligations: Vec::new(),
                }],
            });
            catalog.datasets.push(Dataset {
                id: "ds-2".to_string(),
                properties: BTreeMap::new(),
                distributions: vec![Distribution {
                    format: "text/csv".to_string(),
                    access_service: "svc-2".to_string(),
                }],
                policies: Vec::new(),
            });

            catalog.data_services.push(DataService {
                id: "svc-1".to_string(),
                endpoint_url: "https://example.org/dsp".to_string(),
                endpoint_description: Some("dataspace-protocol-http:1.0".to_string()),
            });
            catalog.data_services.push(DataService {
                id: "svc-2".to_string(),
                endpoint_url: "https://example.org/other-dsp".to_string(),
                endpoint_description: None,
            });

            catalog
        }

        #[tokio::test]
        async fn upsert_then_query_all_returns_it() {
            let cache = cache();
            cache
                .upsert(sample_catalog("node-1", "cat-1"))
                .await
                .unwrap();

            let results = cache.query(CatalogQuery::all()).await.unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].id, "cat-1");
        }

        #[tokio::test]
        async fn upsert_replaces_prior_catalog_for_same_node() {
            let cache = cache();
            cache
                .upsert(sample_catalog("node-1", "cat-1"))
                .await
                .unwrap();
            cache
                .upsert(sample_catalog("node-1", "cat-2"))
                .await
                .unwrap();

            let results = cache.query(CatalogQuery::all()).await.unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].id, "cat-2");
        }

        #[tokio::test]
        async fn query_for_node_filters_by_origin() {
            let cache = cache();
            cache
                .upsert(sample_catalog("node-1", "cat-1"))
                .await
                .unwrap();
            cache
                .upsert(sample_catalog("node-2", "cat-2"))
                .await
                .unwrap();

            let results = cache
                .query(CatalogQuery::for_node(NodeId::new("node-2")))
                .await
                .unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].id, "cat-2");
        }

        #[tokio::test]
        async fn query_respects_offset_and_limit() {
            let cache = cache();
            for i in 0..5 {
                cache
                    .upsert(sample_catalog(&format!("node-{i}"), &format!("cat-{i}")))
                    .await
                    .unwrap();
            }

            let results = cache
                .query(CatalogQuery {
                    origin_node: None,
                    offset: 2,
                    limit: Some(2),
                })
                .await
                .unwrap();
            assert_eq!(
                results.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
                vec!["cat-2", "cat-3"]
            );
        }

        #[tokio::test]
        async fn delete_removes_catalog_and_reports_result() {
            let cache = cache();
            cache
                .upsert(sample_catalog("node-1", "cat-1"))
                .await
                .unwrap();

            let removed = cache.delete(&NodeId::new("node-1")).await.unwrap();
            assert!(removed);

            let results = cache.query(CatalogQuery::all()).await.unwrap();
            assert!(results.is_empty());

            let removed_again = cache.delete(&NodeId::new("node-1")).await.unwrap();
            assert!(!removed_again);
        }

        /// The correctness bar from gap analysis §3.2 (extended by §3.4):
        /// round-tripping a catalog that exercises every field (nested
        /// datasets, properties with both an already-IRI key and a plain
        /// key, distributions, a harvested policy, data services,
        /// participant id) through real triples must reproduce the exact
        /// same domain value, order included. `ds-2` deliberately carries
        /// no policy at all - regression coverage that a dataset predating
        /// this feature (or one whose participant just advertised none)
        /// still round-trips its `policies` field to an empty `Vec`, not
        /// an error or `None`.
        #[tokio::test]
        async fn round_trips_a_catalog_exercising_every_field_exactly() {
            let cache = cache();
            let original = rich_catalog();
            cache.upsert(original.clone()).await.unwrap();

            let results = cache
                .query(CatalogQuery::for_node(NodeId::new("node-rich")))
                .await
                .unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0], original);
            assert!(
                results[0].datasets[1].policies.is_empty(),
                "ds-2 carries no policy and must round-trip to an empty Vec"
            );
        }

        /// A more elaborate policy than `rich_catalog`'s: two permissions
        /// (proving `Policy.permissions`' `Vec` order survives an unordered
        /// triple store, not just its presence), the first with two
        /// constraints (same proof for `Rule.constraints`), a prohibition
        /// with no constraints, no obligations, an explicit `Offer` kind
        /// (not the `Set` default), an id, an assigner, and an assignee -
        /// covering every `Policy`/`Rule`/`Constraint` field at least once.
        fn policy_catalog() -> Catalog {
            let mut catalog = Catalog::new("cat-policy", NodeId::new("node-policy"));
            catalog.datasets.push(Dataset {
                id: "ds-policy".to_string(),
                properties: BTreeMap::new(),
                distributions: Vec::new(),
                policies: vec![Policy {
                    id: Some("policy-1".to_string()),
                    kind: PolicyKind::Offer,
                    assigner: Some("did:example:assigner".to_string()),
                    assignee: Some("did:example:assignee".to_string()),
                    permissions: vec![
                        Rule {
                            action: "use".to_string(),
                            constraints: vec![
                                Constraint::atomic("dateTime", "lteq", "2027-01-01T00:00:00Z"),
                                Constraint::atomic("count", "lteq", "100"),
                            ],
                        },
                        Rule {
                            action: "distribute".to_string(),
                            constraints: Vec::new(),
                        },
                    ],
                    prohibitions: vec![Rule {
                        action: "modify".to_string(),
                        constraints: Vec::new(),
                    }],
                    obligations: Vec::new(),
                }],
            });
            catalog
        }

        #[tokio::test]
        async fn round_trips_a_dataset_policy_with_full_shape_and_preserves_ordering() {
            let cache = cache();
            let original = policy_catalog();
            cache.upsert(original.clone()).await.unwrap();

            let results = cache
                .query(CatalogQuery::for_node(NodeId::new("node-policy")))
                .await
                .unwrap();
            assert_eq!(results.len(), 1);
            // Exhaustive: `Vec`'s `PartialEq` is order-sensitive, so this
            // alone already proves permission/constraint order survived.
            assert_eq!(results[0], original);

            // Spelled out explicitly too, so the ordering claim is legible
            // without cross-referencing `policy_catalog` above.
            let policy = &results[0].datasets[0].policies[0];
            assert_eq!(policy.permissions[0].action, "use");
            let Constraint::Atomic(first) = &policy.permissions[0].constraints[0] else {
                panic!("expected an atomic constraint");
            };
            assert_eq!(first.left_operand, "dateTime");
            let Constraint::Atomic(second) = &policy.permissions[0].constraints[1] else {
                panic!("expected an atomic constraint");
            };
            assert_eq!(second.left_operand, "count");
            assert_eq!(policy.permissions[1].action, "distribute");
            assert!(policy.permissions[1].constraints.is_empty());
            assert_eq!(policy.prohibitions.len(), 1);
            assert!(policy.prohibitions[0].constraints.is_empty());
            assert!(policy.obligations.is_empty());
            assert_eq!(policy.kind, PolicyKind::Offer);
            assert_eq!(policy.id.as_deref(), Some("policy-1"));
            assert_eq!(policy.assigner.as_deref(), Some("did:example:assigner"));
            assert_eq!(policy.assignee.as_deref(), Some("did:example:assignee"));
        }

        /// RED (gap analysis §3.4): `catalog_core::Constraint` now has a
        /// `Logical` variant (`odrl:and`/`odrl:or`/`odrl:xone`/
        /// `odrl:andSequence`, nesting arbitrarily - see that type's own
        /// doc comment), but this store's `write_constraint`/
        /// `load_constraint` still only handle the `Atomic` shape
        /// (`write_constraint`'s own doc comment says so explicitly:
        /// "This store still only ever writes the `Atomic` shape"). This
        /// asserts a policy carrying a *nested* logical constraint - an
        /// `odrl:xone` whose second child is itself a nested `odrl:and` of
        /// two atomic leaves - survives `upsert` then `query` byte for
        /// byte: which combinator was used at each level, and the exact
        /// child order at each level, both preserved.
        ///
        /// Expected to fail today: `write_constraint` silently no-ops on
        /// `Constraint::Logical` (see its own doc comment for why silent),
        /// so no `odrl:leftOperand`/`odrl:operator`/`odrl:rightOperand`
        /// triples - nor anything describing the `odrl:xone`/`odrl:and`
        /// grouping itself or its children - are ever written for that
        /// constraint node. `load_constraint` then unconditionally requires
        /// `odrl:leftOperand` on every constraint subject, so reading the
        /// policy back errors out (`StoreError::Backend("... is missing
        /// odrl:leftOperand")`) instead of returning the original nested
        /// structure.
        #[tokio::test]
        async fn round_trips_a_nested_logical_constraint_preserving_structure_and_order() {
            let cache = cache();
            let mut catalog = Catalog::new("cat-logical", NodeId::new("node-logical"));

            let nested_and = Constraint::and(vec![
                Constraint::atomic("odrl:dateTime", "gteq", "2026-01-01T00:00:00Z"),
                Constraint::atomic("odrl:dateTime", "lteq", "2027-01-01T00:00:00Z"),
            ]);
            let top_level_xone = Constraint::xone(vec![
                Constraint::atomic("odrl:spatial", "eq", "https://example.org/place/eu"),
                nested_and,
            ]);

            catalog.datasets.push(Dataset {
                id: "ds-logical".to_string(),
                properties: BTreeMap::new(),
                distributions: Vec::new(),
                policies: vec![Policy {
                    id: Some("policy-logical".to_string()),
                    kind: PolicyKind::Offer,
                    assigner: None,
                    assignee: None,
                    permissions: vec![Rule {
                        action: "use".to_string(),
                        constraints: vec![top_level_xone.clone()],
                    }],
                    prohibitions: Vec::new(),
                    obligations: Vec::new(),
                }],
            });

            cache.upsert(catalog.clone()).await.unwrap();

            let results = cache
                .query(CatalogQuery::for_node(NodeId::new("node-logical")))
                .await
                .unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(
                results[0], catalog,
                "a nested logical constraint must round-trip byte for byte - \
                 combinator, nested structure, and child order all included"
            );

            // Spelled out explicitly too, so the nesting/order claim is
            // legible without cross-referencing the fixture above.
            let constraint = &results[0].datasets[0].policies[0].permissions[0].constraints[0];
            let Constraint::Logical(LogicalConstraint::Xone(children)) = constraint else {
                panic!(
                    "expected the top-level constraint to round-trip as odrl:xone, got {constraint:?}"
                );
            };
            assert_eq!(children.len(), 2, "xone must keep both children, in order");
            let Constraint::Atomic(first) = &children[0] else {
                panic!(
                    "expected xone's first child to stay atomic (spatial eq), got {:?}",
                    children[0]
                );
            };
            assert_eq!(first.left_operand, "odrl:spatial");
            let Constraint::Logical(LogicalConstraint::And(nested_children)) = &children[1] else {
                panic!(
                    "expected xone's second child to round-trip as a nested odrl:and, got {:?}",
                    children[1]
                );
            };
            assert_eq!(
                nested_children.len(),
                2,
                "nested and must keep both children, in order"
            );
            let Constraint::Atomic(nested_first) = &nested_children[0] else {
                panic!("expected the nested and's first child to stay atomic");
            };
            assert_eq!(nested_first.operator, "gteq");
            let Constraint::Atomic(nested_second) = &nested_children[1] else {
                panic!("expected the nested and's second child to stay atomic");
            };
            assert_eq!(nested_second.operator, "lteq");
        }

        /// Regression coverage for every dataset that predates this
        /// feature (or whose participant simply advertised no policy at
        /// all): `Dataset.policies` must round-trip to an empty `Vec`, not
        /// an error, and no stray `odrl:hasPolicy` triple should exist for
        /// it.
        #[tokio::test]
        async fn dataset_with_no_policies_round_trips_to_an_empty_vec() {
            let cache = cache();
            let mut catalog = Catalog::new("cat-no-policy", NodeId::new("node-no-policy"));
            catalog.datasets.push(Dataset {
                id: "ds-1".to_string(),
                properties: BTreeMap::new(),
                distributions: Vec::new(),
                policies: Vec::new(),
            });
            cache.upsert(catalog.clone()).await.unwrap();

            let results = cache
                .query(CatalogQuery::for_node(NodeId::new("node-no-policy")))
                .await
                .unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0], catalog);
            assert!(results[0].datasets[0].policies.is_empty());

            let graph = node_iri(&NodeId::new("node-no-policy"));
            let policy_links = cache
                .quads(None, Some(&odrl_has_policy_pred()), None, &graph)
                .unwrap();
            assert!(policy_links.is_empty());
        }

        /// Proves real ODRL decomposition happened, the same way
        /// `a_direct_quad_pattern_query_finds_a_distribution_format_by_its_real_dcat_predicate`
        /// proves it for DCAT: a direct quad-pattern query using the real
        /// `odrl:hasPolicy`/`rdf:type` predicates finds the policy this
        /// store wrote, reachable from the dataset by a genuine ODRL link,
        /// not just present somewhere in the graph.
        #[tokio::test]
        async fn a_direct_quad_pattern_query_finds_a_policy_by_its_real_odrl_predicates() {
            let cache = cache();
            cache.upsert(policy_catalog()).await.unwrap();

            let graph = node_iri(&NodeId::new("node-policy"));
            let dataset_subject = dataset_iri(&node_base(&NodeId::new("node-policy")), "ds-policy");
            let policy_links = cache
                .quads(
                    Some(&dataset_subject),
                    Some(&odrl_has_policy_pred()),
                    None,
                    &graph,
                )
                .unwrap();
            assert_eq!(policy_links.len(), 1);

            let policy_subject = match &policy_links[0].object {
                Term::NamedNode(node) => node.clone(),
                other => panic!("expected a named node object, got {other:?}"),
            };
            let type_matches = cache
                .quads(
                    Some(&policy_subject),
                    Some(&rdf_type()),
                    Some(&Term::from(odrl_policy_class(PolicyKind::Offer))),
                    &graph,
                )
                .unwrap();
            assert_eq!(
                type_matches.len(),
                1,
                "expected the harvested policy to carry a real odrl:Offer rdf:type"
            );
        }

        /// Proves real decomposition happened: a direct quad-pattern query
        /// against the store, using the real `dct:format` predicate IRI,
        /// finds a specific distribution's format. This is impossible
        /// against the old JSON-blob representation, where the entire
        /// catalog was one opaque literal object and no predicate other
        /// than `fcns:catalogJson` ever existed in the store.
        #[tokio::test]
        async fn a_direct_quad_pattern_query_finds_a_distribution_format_by_its_real_dcat_predicate()
         {
            let cache = cache();
            cache.upsert(rich_catalog()).await.unwrap();

            let graph = node_iri(&NodeId::new("node-rich"));
            let matches = cache
                .quads(
                    None,
                    Some(&dct_format_pred()),
                    Some(&Term::from(Literal::from("application/xml".to_string()))),
                    &graph,
                )
                .unwrap();
            assert_eq!(
                matches.len(),
                1,
                "expected exactly one distribution with this format"
            );

            // And the subject that carries it really is a dcat:Distribution
            // reachable from ds-1 via the real dcat:distribution property -
            // not just a coincidentally-matching literal floating in the
            // graph.
            let distribution_subject = match &matches[0].subject {
                NamedOrBlankNode::NamedNode(n) => n.clone(),
                other => panic!("expected a named node subject, got {other:?}"),
            };
            let type_matches = cache
                .quads(
                    Some(&distribution_subject),
                    Some(&rdf_type()),
                    Some(&Term::from(dcat_distribution_class())),
                    &graph,
                )
                .unwrap();
            assert_eq!(type_matches.len(), 1);
        }

        /// Same proof as above, but via a real SPARQL ASK through
        /// `contreforts_kg::QueryEngine` (the "SPARQL ASK" option gap
        /// analysis §3.2 calls out), scoped to one named graph.
        #[tokio::test]
        async fn sparql_ask_finds_a_dataset_via_the_real_dcat_dataset_link() {
            let cache = cache();
            cache.upsert(rich_catalog()).await.unwrap();

            let engine = contreforts_kg::QueryEngine::new(&cache.store);
            let found = engine
                .ask(&format!(
                    "PREFIX dcat: <{DCAT_NS}> ASK {{ GRAPH <{}> {{ \
                         ?catalog a dcat:Catalog ; dcat:dataset ?dataset . \
                         ?dataset a dcat:Dataset . \
                         ?dataset dcat:distribution ?distribution . \
                         ?distribution dcat:accessService ?service . \
                         ?service a dcat:DataService \
                     }} }}",
                    node_iri(&NodeId::new("node-rich")).as_str()
                ))
                .unwrap();
            assert!(
                found,
                "expected the real dcat:dataset/distribution/accessService chain to be queryable"
            );
        }

        /// A property whose key is already a real vocabulary IRI is stored
        /// under that exact predicate, not this project's fallback
        /// namespace - proving "reuse the term when one genuinely fits"
        /// actually happens, not just documented.
        #[tokio::test]
        async fn a_property_keyed_by_a_real_vocabulary_iri_is_stored_under_that_predicate() {
            let cache = cache();
            cache.upsert(rich_catalog()).await.unwrap();

            let graph = node_iri(&NodeId::new("node-rich"));
            let keyword_pred = iri("http://www.w3.org/ns/dcat#keyword");
            let matches = cache
                .quads(None, Some(&keyword_pred), None, &graph)
                .unwrap();
            assert_eq!(matches.len(), 1);
            assert_eq!(term_as_string(&matches[0].object).unwrap(), "logistics");
        }

        /// `upsert` replacing a node's graph wholesale must also drop the
        /// old catalog's decomposed triples, not just its top-level
        /// resource - otherwise a re-crawl with fewer datasets would leak
        /// orphaned dataset/distribution triples forever.
        #[tokio::test]
        async fn upsert_wholesale_replacement_drops_the_prior_catalogs_decomposed_triples() {
            let cache = cache();
            cache.upsert(rich_catalog()).await.unwrap();

            let mut smaller = Catalog::new("cat-smaller", NodeId::new("node-rich"));
            smaller.datasets.push(Dataset {
                id: "only-dataset".to_string(),
                properties: BTreeMap::new(),
                distributions: vec![],
                policies: Vec::new(),
            });
            cache.upsert(smaller.clone()).await.unwrap();

            let results = cache
                .query(CatalogQuery::for_node(NodeId::new("node-rich")))
                .await
                .unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0], smaller);

            // No leftover triples from `rich_catalog`'s ds-1/ds-2/svc-1/svc-2.
            let graph = node_iri(&NodeId::new("node-rich"));
            let all_quads = cache.quads(None, None, None, &graph).unwrap();
            let leaked_old_dataset = all_quads.iter().any(|q| {
                matches!(&q.subject, NamedOrBlankNode::NamedNode(n) if n.as_str().contains("ds-1") || n.as_str().contains("ds-2"))
            });
            assert!(
                !leaked_old_dataset,
                "old catalog's dataset triples must not survive a wholesale upsert"
            );
        }

        // --- `sparql_query_json` (gap analysis §3.3) --------------------------

        /// A plain `SELECT` with no `GRAPH`/`FROM` clause at all must still
        /// find data crawled from two *different* origin nodes (two
        /// separate named graphs) - proving the "whole store by default"
        /// union-graph behavior documented on `sparql_query_json`, not just
        /// that the method returns something.
        #[tokio::test]
        async fn sparql_query_json_select_with_no_graph_clause_searches_every_named_graph() {
            let cache = cache();
            cache
                .upsert(sample_catalog("node-a", "cat-a"))
                .await
                .unwrap();
            cache
                .upsert(sample_catalog("node-b", "cat-b"))
                .await
                .unwrap();

            let bytes = cache
                .sparql_query_json(&format!(
                    "PREFIX dcat: <{DCAT_NS}> SELECT ?catalog WHERE {{ ?catalog a dcat:Catalog }}"
                ))
                .unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

            assert_eq!(parsed["head"]["vars"], serde_json::json!(["catalog"]));
            let bindings = parsed["results"]["bindings"].as_array().unwrap();
            assert_eq!(
                bindings.len(),
                2,
                "expected one dcat:Catalog per origin node, got {parsed}"
            );
            let mut catalog_iris: Vec<&str> = bindings
                .iter()
                .map(|b| b["catalog"]["value"].as_str().unwrap())
                .collect();
            catalog_iris.sort_unstable();
            assert!(catalog_iris[0].contains("node-a") && catalog_iris[0].contains("cat-a"));
            assert!(catalog_iris[1].contains("node-b") && catalog_iris[1].contains("cat-b"));
            // And the JSON Results type/value shape is real, not
            // hand-rolled: a resource binding must come back as a `uri`.
            assert_eq!(bindings[0]["catalog"]["type"], serde_json::json!("uri"));
        }

        /// The `GRAPH <iri>` clause (the documented stretch-goal way to
        /// scope a query to one participant) finds only that participant's
        /// data, even though the store as a whole holds two.
        #[tokio::test]
        async fn sparql_query_json_graph_clause_scopes_to_one_participant() {
            let cache = cache();
            cache
                .upsert(sample_catalog("node-a", "cat-a"))
                .await
                .unwrap();
            cache
                .upsert(sample_catalog("node-b", "cat-b"))
                .await
                .unwrap();

            let scoped_graph = node_iri(&NodeId::new("node-b"));
            let bytes = cache
                .sparql_query_json(&format!(
                    "PREFIX dcat: <{DCAT_NS}> SELECT ?catalog WHERE {{ GRAPH <{}> {{ ?catalog a dcat:Catalog }} }}",
                    scoped_graph.as_str()
                ))
                .unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let bindings = parsed["results"]["bindings"].as_array().unwrap();
            assert_eq!(bindings.len(), 1);
            assert!(
                bindings[0]["catalog"]["value"]
                    .as_str()
                    .unwrap()
                    .contains("node-b")
            );
        }

        /// A real `ASK` query, through the same HTTP-facing method,
        /// against real harvested-looking data (the "rich" catalog fixture
        /// used elsewhere in this module).
        #[tokio::test]
        async fn sparql_query_json_ask_returns_the_spec_shaped_boolean_result() {
            let cache = cache();
            cache.upsert(rich_catalog()).await.unwrap();

            let bytes = cache
                .sparql_query_json(&format!(
                    "PREFIX dcat: <{DCAT_NS}> ASK {{ ?d a dcat:Dataset ; dcat:distribution ?dist . ?dist dcat:accessService ?svc }}"
                ))
                .unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(parsed, serde_json::json!({"head": {}, "boolean": true}));
        }

        /// A SPARQL **Update** operation (`INSERT DATA`) must never be
        /// reachable through this method - proving the "read-only by
        /// construction" claim in `sparql_query_json`'s own doc comment,
        /// not just documenting it.
        #[tokio::test]
        async fn sparql_update_operation_is_rejected_not_silently_ignored() {
            let cache = cache();
            cache
                .upsert(sample_catalog("node-1", "cat-1"))
                .await
                .unwrap();

            let attempted_injection = format!(
                "PREFIX dcat: <{DCAT_NS}> INSERT DATA {{ GRAPH <{}> {{ <urn:x> a dcat:Catalog }} }}",
                node_iri(&NodeId::new("node-1")).as_str()
            );
            let outcome = cache.sparql_query_json(&attempted_injection);
            assert!(
                matches!(outcome, Err(SparqlError::Parse(_))),
                "expected an Update operation to fail to parse as a Query, got {outcome:?}"
            );

            // And, just as importantly, nothing was actually inserted -
            // the store is unaffected by the attempt.
            let results = cache.query(CatalogQuery::all()).await.unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].id, "cat-1");
        }

        /// `CONSTRUCT` is a well-formed Query, just not one this method
        /// serializes (see `SparqlError::UnsupportedGraphResult`'s own doc
        /// comment) - it must fail cleanly, not panic or silently return
        /// an empty/wrong result.
        #[tokio::test]
        async fn sparql_query_json_rejects_construct_queries_cleanly() {
            let cache = cache();
            cache
                .upsert(sample_catalog("node-1", "cat-1"))
                .await
                .unwrap();

            let outcome = cache.sparql_query_json("CONSTRUCT { ?s ?p ?o } WHERE { ?s ?p ?o }");
            assert!(matches!(outcome, Err(SparqlError::UnsupportedGraphResult)));
        }

        /// A syntactically invalid query string is a `Parse` error, not a
        /// panic and not silently empty results.
        #[tokio::test]
        async fn sparql_query_json_rejects_malformed_query_syntax() {
            let cache = cache();
            let outcome = cache.sparql_query_json("this is not sparql at all");
            assert!(matches!(outcome, Err(SparqlError::Parse(_))));
        }

        // --- `sparql_query_json_limited` --------------------------------------

        #[tokio::test]
        async fn sparql_query_json_limited_stops_once_cancelled() {
            let cache = cache();
            cache
                .upsert(sample_catalog("node-1", "cat-1"))
                .await
                .unwrap();
            let token = CancellationToken::new();
            token.cancel();
            let limits = SparqlLimits {
                cancellation: Some(token),
                max_rows: None,
            };
            let visible = BTreeSet::new();
            for visible in [None, Some(&visible)] {
                let outcome = cache.sparql_query_json_limited(
                    "SELECT * WHERE { ?a ?b ?c . ?d ?e ?f }",
                    visible,
                    &limits,
                );
                assert!(
                    matches!(outcome, Err(SparqlError::Cancelled)),
                    "got {outcome:?}"
                );
            }
        }

        #[tokio::test]
        async fn sparql_query_json_limited_rejects_more_rows_than_max_rows() {
            let cache = cache();
            cache
                .upsert(sample_catalog("node-a", "cat-a"))
                .await
                .unwrap();
            cache
                .upsert(sample_catalog("node-b", "cat-b"))
                .await
                .unwrap();
            let query = format!(
                "PREFIX dcat: <{DCAT_NS}> SELECT ?catalog WHERE {{ ?catalog a dcat:Catalog }}"
            );
            let limited = |max_rows| SparqlLimits {
                cancellation: None,
                max_rows: Some(max_rows),
            };

            let outcome = cache.sparql_query_json_limited(&query, None, &limited(1));
            assert!(
                matches!(outcome, Err(SparqlError::TooManyRows(1))),
                "got {outcome:?}"
            );

            let bytes = cache
                .sparql_query_json_limited(&query, None, &limited(2))
                .expect("exactly max_rows rows is within the limit");
            let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(parsed["results"]["bindings"].as_array().unwrap().len(), 2);
        }

        // --- `sparql_query_json_restricted` -----------------------------------

        /// Every binding value (IRI or literal) of a `SELECT` result body.
        fn binding_values(bytes: &[u8]) -> Vec<String> {
            let parsed: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            parsed["results"]["bindings"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|binding| {
                    binding
                        .as_object()
                        .unwrap()
                        .values()
                        .map(|term| term["value"].as_str().unwrap().to_string())
                        .collect::<Vec<_>>()
                })
                .collect()
        }

        #[test]
        fn owning_resource_iri_maps_every_resource_minted_under_a_dataset_or_service_to_it() {
            let node = NodeId::new("node/a");
            let dataset = dataset_resource_iri(&node, "ds/1");
            let service = service_resource_iri(&node, "svc/1");
            let base = node_base(&node);
            let policy = policy_iri(&base, "ds/1", 0);
            let rule = rule_iri(policy.as_str(), "permissions", 0);
            for iri in [
                dataset.clone(),
                distribution_iri(&base, "ds/1", 0).into_string(),
                policy.as_str().to_string(),
                constraint_iri(rule.as_str(), 0).into_string(),
            ] {
                assert_eq!(owning_resource_iri(&iri), Some(dataset.as_str()), "{iri}");
            }
            assert_eq!(owning_resource_iri(&service), Some(service.as_str()));

            // An empty id is still a resource: `"@id": ""` must be gated
            // like any other dataset or service.
            let empty_dataset = dataset_resource_iri(&node, "");
            assert_eq!(empty_dataset, format!("{base}/datasets/"));
            for iri in [
                empty_dataset.clone(),
                distribution_iri(&base, "", 0).into_string(),
                policy_iri(&base, "", 0).into_string(),
            ] {
                assert_eq!(
                    owning_resource_iri(&iri),
                    Some(empty_dataset.as_str()),
                    "{iri}"
                );
            }
            let empty_service = service_resource_iri(&node, "");
            assert_eq!(
                owning_resource_iri(&empty_service),
                Some(empty_service.as_str())
            );

            // Fails closed: anything else minted under a node belongs to
            // itself, so no allow-list can contain it.
            for iri in [format!("{base}/datasets"), format!("{base}/other/x")] {
                assert_eq!(owning_resource_iri(&iri), Some(iri.as_str()), "{iri}");
            }

            for iri in [
                node_iri(&node).into_string(),
                catalog_iri(&base, "cat/datasets/x").into_string(),
                "http://www.w3.org/ns/dcat#Dataset".to_string(),
            ] {
                assert_eq!(owning_resource_iri(&iri), None, "{iri}");
            }
        }

        #[test]
        fn sequence_index_iri_constant_matches_the_predicate_the_store_writes() {
            assert_eq!(SEQUENCE_INDEX_IRI, sequence_index_pred().as_str());
        }

        /// A dataset and a service published with `"@id": ""` must be
        /// hidden like any other when they are not on the allow-list.
        #[tokio::test]
        async fn sparql_query_json_restricted_hides_empty_id_resources() {
            let cache = cache();
            let node = NodeId::new("node-e");
            let mut catalog = Catalog::new("cat-e", node.clone());
            let mut properties = BTreeMap::new();
            properties.insert("title".to_string(), "TOP SECRET".to_string());
            catalog.datasets.push(Dataset {
                id: String::new(),
                properties,
                distributions: vec![Distribution {
                    format: "application/json".to_string(),
                    access_service: String::new(),
                }],
                policies: Vec::new(),
            });
            catalog.datasets.push(Dataset {
                id: "open".to_string(),
                properties: BTreeMap::new(),
                distributions: vec![],
                policies: Vec::new(),
            });
            catalog.data_services.push(DataService {
                id: String::new(),
                endpoint_url: "https://secret-partner.example/dsp".to_string(),
                endpoint_description: None,
            });
            cache.upsert(catalog).await.unwrap();

            let visible = BTreeSet::from([dataset_resource_iri(&node, "open")]);
            let values = binding_values(
                &cache
                    .sparql_query_json_restricted("SELECT ?s ?p ?o WHERE { ?s ?p ?o }", &visible)
                    .unwrap(),
            );
            assert!(
                !values
                    .iter()
                    .any(|v| v.contains("TOP SECRET") || v.contains("secret-partner")),
                "an empty-id dataset or service off the allow-list must be hidden. Got: {values:?}"
            );
            assert!(values.contains(&dataset_resource_iri(&node, "open")));
        }

        /// With every resource on the allow-list, the view must answer
        /// exactly like the store for a spread of query shapes.
        #[tokio::test]
        async fn sparql_query_json_restricted_matches_the_store_when_everything_is_visible() {
            let cache = cache();
            let mut catalog = rich_catalog();
            catalog.datasets[0].policies = policy_catalog().datasets[0].policies.clone();
            cache.upsert(catalog.clone()).await.unwrap();
            cache
                .upsert(sample_catalog("node-a", "cat-a"))
                .await
                .unwrap();
            let node = &catalog.origin_node;
            let visible: BTreeSet<String> = catalog
                .datasets
                .iter()
                .map(|d| dataset_resource_iri(node, &d.id))
                .chain(
                    catalog
                        .data_services
                        .iter()
                        .map(|s| service_resource_iri(node, &s.id)),
                )
                .collect();
            let graph = node_iri(node).into_string();

            for query in [
                format!(
                    "SELECT ?s ?p ?o WHERE {{ ?s ?p ?o FILTER(?p != <{SEQUENCE_INDEX_IRI}>) }}"
                ),
                format!("SELECT ?g ?s WHERE {{ GRAPH ?g {{ ?s a <{DCAT_NS}Dataset> }} }}"),
                "SELECT ?g WHERE { GRAPH ?g {} }".to_string(),
                format!("SELECT ?s WHERE {{ GRAPH <{graph}> {{ ?s a <{DCAT_NS}Dataset> }} }}"),
                format!("SELECT ?s FROM <{graph}> WHERE {{ ?s a <{DCAT_NS}Distribution> }}"),
                format!("SELECT ?g FROM NAMED <{graph}> WHERE {{ GRAPH ?g {{}} }}"),
                format!(
                    "SELECT ?d (COUNT(?x) AS ?n) WHERE {{ ?d a <{DCAT_NS}Dataset> . \
                     OPTIONAL {{ ?d <{DCAT_NS}distribution> ?x }} }} GROUP BY ?d"
                ),
                format!(
                    "SELECT ?s ?o WHERE {{ ?s <{DCAT_NS}dataset>/<{DCAT_NS}distribution>* ?o }}"
                ),
                format!(
                    "SELECT ?s WHERE {{ ?s a <{DCAT_NS}Dataset> \
                     MINUS {{ ?s <{DCAT_NS}distribution> ?x }} }}"
                ),
                "ASK { ?s ?p ?o }".to_string(),
            ] {
                let mut expected = binding_rows(&cache.sparql_query_json(&query).unwrap());
                let mut got = binding_rows(
                    &cache
                        .sparql_query_json_restricted(&query, &visible)
                        .unwrap(),
                );
                expected.sort();
                got.sort();
                assert_eq!(got, expected, "{query}");
            }
        }

        /// Each result row (or the ASK boolean) as one comparable string.
        fn binding_rows(bytes: &[u8]) -> Vec<String> {
            let parsed: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            if let Some(boolean) = parsed.get("boolean") {
                return vec![boolean.to_string()];
            }
            parsed["results"]["bindings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row.to_string())
                .collect()
        }

        /// Everything not on the allow-list is unreachable, even by
        /// `?s ?p ?o`, which no query rewrite could scope: a hidden
        /// dataset's own triples, every resource minted under it, the
        /// catalog's link to it, a data service not on the list, and a
        /// dataset harvested after the allow-list was computed. Everything
        /// on it stays, including a same-id dataset from another
        /// participant.
        #[tokio::test]
        async fn sparql_query_json_restricted_shows_only_allow_listed_resources() {
            let cache = cache();
            let mut catalog = rich_catalog();
            catalog.datasets.push(Dataset {
                id: "ds-10".to_string(),
                properties: BTreeMap::new(),
                distributions: vec![],
                policies: Vec::new(),
            });
            cache.upsert(catalog).await.unwrap();
            let mut other = Catalog::new("cat-other", NodeId::new("node-other"));
            other.datasets.push(Dataset {
                id: "ds-1".to_string(),
                properties: BTreeMap::new(),
                distributions: vec![],
                policies: Vec::new(),
            });
            cache.upsert(other).await.unwrap();

            let rich = NodeId::new("node-rich");
            let hidden_dataset = dataset_resource_iri(&rich, "ds-1");
            let hidden_service = service_resource_iri(&rich, "svc-1");
            let visible = BTreeSet::from([
                dataset_resource_iri(&rich, "ds-2"),
                dataset_resource_iri(&rich, "ds-10"),
                service_resource_iri(&rich, "svc-2"),
                dataset_resource_iri(&NodeId::new("node-other"), "ds-1"),
            ]);

            // Harvested after `visible` was computed, so not on it.
            let mut late = Catalog::new("cat-late", NodeId::new("node-late"));
            late.datasets.push(Dataset {
                id: "late-ds".to_string(),
                properties: BTreeMap::new(),
                distributions: vec![],
                policies: Vec::new(),
            });
            cache.upsert(late).await.unwrap();

            let bytes = cache
                .sparql_query_json_restricted("SELECT ?s ?p ?o WHERE { ?s ?p ?o }", &visible)
                .unwrap();
            let values = binding_values(&bytes);

            for hidden in [&hidden_dataset, &hidden_service] {
                assert!(
                    !values
                        .iter()
                        .any(|v| v == hidden || v.starts_with(&format!("{hidden}/"))),
                    "no triple may mention {hidden} or anything minted under it. Got: {values:?}"
                );
            }
            assert!(
                !values.iter().any(|v| v == "data.rest"),
                "the hidden dataset's own literal properties must not be reachable"
            );
            assert!(
                !values.iter().any(|v| v.contains("late-ds")),
                "a dataset harvested after the allow-list was computed must stay hidden"
            );
            assert!(
                !values.iter().any(|v| v.ends_with("#sequenceIndex")),
                "position numbers must not be exposed"
            );
            for still_visible in &visible {
                assert!(
                    values.contains(still_visible),
                    "{still_visible} must stay visible. Got: {values:?}"
                );
            }

            let unrestricted = binding_values(
                &cache
                    .sparql_query_json("SELECT ?s ?p ?o WHERE { ?s ?p ?o }")
                    .unwrap(),
            );
            assert!(
                unrestricted.contains(&hidden_dataset),
                "without restriction, the same query must still see every dataset"
            );
        }

        /// The view must behave like the store for the query shapes that
        /// depend on graph handling and aggregation: `GRAPH ?g`, `FROM`,
        /// `ASK` and `COUNT`.
        #[tokio::test]
        async fn sparql_query_json_restricted_supports_graph_from_ask_and_count() {
            let cache = cache();
            cache.upsert(rich_catalog()).await.unwrap();
            let rich = NodeId::new("node-rich");
            let visible = BTreeSet::from([
                dataset_resource_iri(&rich, "ds-2"),
                service_resource_iri(&rich, "svc-2"),
            ]);
            let graph = node_iri(&rich).into_string();
            let dataset_count = |bytes: &[u8]| -> String {
                let parsed: serde_json::Value = serde_json::from_slice(bytes).unwrap();
                parsed["results"]["bindings"][0]["n"]["value"]
                    .as_str()
                    .unwrap()
                    .to_string()
            };

            let count_query = format!(
                "PREFIX dcat: <{DCAT_NS}> \
                 SELECT (COUNT(*) AS ?n) WHERE {{ ?d a dcat:Dataset }}"
            );
            assert_eq!(
                dataset_count(&cache.sparql_query_json(&count_query).unwrap()),
                "2"
            );
            assert_eq!(
                dataset_count(
                    &cache
                        .sparql_query_json_restricted(&count_query, &visible)
                        .unwrap()
                ),
                "1",
                "COUNT must not count hidden datasets"
            );

            let graph_query = format!(
                "PREFIX dcat: <{DCAT_NS}> \
                 SELECT (COUNT(*) AS ?n) WHERE {{ GRAPH ?g {{ ?d a dcat:Dataset }} }}"
            );
            assert_eq!(
                dataset_count(
                    &cache
                        .sparql_query_json_restricted(&graph_query, &visible)
                        .unwrap()
                ),
                "1"
            );

            let from_query = format!(
                "PREFIX dcat: <{DCAT_NS}> \
                 SELECT (COUNT(*) AS ?n) FROM <{graph}> WHERE {{ ?d a dcat:Dataset }}"
            );
            assert_eq!(
                dataset_count(
                    &cache
                        .sparql_query_json_restricted(&from_query, &visible)
                        .unwrap()
                ),
                "1"
            );

            let hidden = dataset_resource_iri(&rich, "ds-1");
            let ask = |query: &str| -> serde_json::Value {
                let bytes = cache.sparql_query_json_restricted(query, &visible).unwrap();
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["boolean"].clone()
            };
            assert_eq!(ask(&format!("ASK {{ <{hidden}> ?p ?o }}")), false);
            assert_eq!(
                ask(&format!(
                    "ASK {{ <{}> ?p ?o }}",
                    dataset_resource_iri(&rich, "ds-2")
                )),
                true
            );
        }
    }
}
