//! A real, Oxigraph-backed [`CatalogCache`], built on `contreforts-kg`'s
//! `GraphStore` rather than the bare `oxigraph` crate's `Store` directly.
//!
//! See this module's own doc comment above ("Implemented backend") for why
//! `contreforts-kg` rather than raw `oxigraph`.
//!
//! ## Quad mapping (real RDF decomposition - gap analysis §3.2)
//!
//! Reuses [DCAT](http://www.w3.org/ns/dcat#) terms wherever a genuine DCAT
//! property/class fits `catalog-core`'s domain model, matching the
//! Dataspace Protocol's own stated approach ("The Catalog Protocol reuses
//! properties from the DCAT and ODRL vocabularies" - `catalog.protocol.md`,
//! "Introduction"). One non-DCAT/ODRL term is reused for the same reason:
//! [Dublin Core Terms](http://purl.org/dc/terms/)' `dct:format`, which is
//! what DCAT/DSP tooling itself actually uses for a `Distribution`'s
//! format (including the real DSP `2025-1` JSON-LD context, which maps its
//! `format` term to `dct:format` - confirmed against this project's own,
//! now-removed `http-api` DSP layer, whose `DspDistribution.format` field
//! serialized under that same context). Everything else with no DCAT/ODRL
//! (or DCTERMS) equivalent falls back to this project's own
//! `https://federated-catalog-rs.internal/ns#` namespace.
//!
//! **ODRL terms, real and harvested (gap analysis §3.4).** `catalog-core::Dataset`
//! now carries `policies: Vec<Policy>` - real ODRL policy data derived from
//! a crawled participant's own `odrl:hasPolicy` triples, not the hardcoded
//! placeholder the now-removed `http-api` DSP-serving layer used to emit
//! (see `Policy`'s own doc comment). A read-only catalog broker has no
//! negotiation capability of its own, so "honoring" a harvested policy
//! means preserving it faithfully end to end; this store's half of that is
//! decomposing each `Policy` into real `odrl:` resources and triples
//! (below), exactly the way `Catalog`/`Dataset`/`Distribution`/`DataService`
//! are already decomposed into real `dcat:` ones, rather than folding
//! policy data into the generic `Dataset.properties` bag or an opaque
//! blob.
//!
//! **Logical constraint groups (gap analysis §3.4, closed).** A
//! constraint resource `<constraint>` is either the atomic shape above, or
//! a *logical* group - `<constraint> odrl:and <child> .` / `odrl:or` /
//! `odrl:xone` / `odrl:andSequence`, one triple per
//! [`catalog_core::LogicalConstraint`] child, each real ODRL term reused
//! exactly the way `odrl:leftOperand`/`odrl:operator` are reused for the
//! atomic shape above. `<child>` is itself a full constraint resource -
//! built from the *parent constraint's* own IRI the same way a top-level
//! constraint is built from its rule's IRI (see [`constraint_iri`]), so
//! nesting reuses the exact same resource-naming scheme at every depth -
//! carrying its own `fcns:sequenceIndex` (its position among its
//! siblings) and, recursively, either shape again. A constraint resource
//! therefore carries **at most one** of `odrl:leftOperand` or one of the
//! four logical predicates, never both - `load_constraint` reads whichever
//! is present, atomic taking precedence should a hand-crafted graph
//! (outside this store's own writes) carry both.
//!
//! Recursion depth - both writing and reading - is bounded by
//! `MAX_CONSTRAINT_DEPTH` (64), the exact same bound and rationale as
//! `crawler::MAX_CONSTRAINT_DEPTH` and
//! `ds-odrl-engine-rs::engine::constraint::MAX_CONSTRAINT_DEPTH`: a
//! constraint nested past the bound is dropped (not written, with no
//! dangling triple left behind) on write, the same way
//! `crawler::parse_constraint` drops one past its own bound rather than
//! growing a parser's call stack unboundedly - and reading back a graph
//! that somehow carries one anyway (not producible by this store's own
//! write path, but defended against regardless, e.g. a hand-written
//! fixture or a future non-`crawler` producer) errors out rather than
//! recursing without bound.
//!
//! ### Namespaces
//!
//! | Prefix | IRI |
//! |---|---|
//! | `dcat:` | `http://www.w3.org/ns/dcat#` |
//! | `dct:` | `http://purl.org/dc/terms/` |
//! | `odrl:` | `http://www.w3.org/ns/odrl/2/` |
//! | `rdf:` | `http://www.w3.org/1999/02/22-rdf-syntax-ns#` |
//! | `fcns:` (fallback) | `https://federated-catalog-rs.internal/ns#` |
//!
//! ### Resource IRIs
//!
//! For an origin node whose [`NodeId`] is `<node>` (percent-encoded
//! throughout, so any character the id contains still yields a valid
//! IRI), let `<base>` = `https://federated-catalog-rs.internal/nodes/<node>`:
//!
//! - **Named graph** (one per origin node, matching the trait's contract):
//!   `<base>`.
//! - **Catalog resource**: `<base>/catalogs/<catalog.id>`.
//! - **Dataset resource**: `<base>/datasets/<dataset.id>`.
//! - **Distribution resource**: `<base>/datasets/<dataset.id>/distributions/<index>`
//!   - a distribution has no id of its own in the domain model, so it is
//!     identified by its position in `dataset.distributions` instead of a
//!     blank node (predictable, queryable IRIs beat blank nodes here, and
//!     the index doubles as the ordering key - see "Ordering" below).
//! - **DataService resource**: `<base>/services/<data_service.id>`.
//! - **Policy resource**: `<base>/datasets/<dataset.id>/policies/<index>` -
//!   like a distribution, a harvested policy is identified by its position
//!   in `dataset.policies` rather than by `Policy.id`: that field is an
//!   arbitrary, optional string harvested from the crawl (possibly absent,
//!   possibly not IRI-safe), not a trusted identifier this store can mint
//!   a resource IRI from. When present it is preserved separately as a
//!   literal instead (`fcns:policyId`, see "Triples emitted" below).
//! - **Permission / Prohibition / Obligation resource** (one shape, shared
//!   by all three - see [`Rule`]): `<policy>/permissions/<index>`,
//!   `<policy>/prohibitions/<index>`, `<policy>/obligations/<index>`
//!   respectively. Each list's `<index>` restarts at 0 independently of
//!   the other two - they live under different path segments, so a
//!   permission and a prohibition at the same position never collide.
//! - **Constraint resource**: `<parent>/constraints/<index>`, where
//!   `<parent>` is whichever permission/prohibition/obligation resource
//!   IRI the constraint directly belongs to for a rule's own top-level
//!   constraint, **or another constraint resource IRI** for a child of a
//!   logical (`odrl:and`/`odrl:or`/`odrl:xone`/`odrl:andSequence`) group -
//!   nesting reuses this exact same `<parent>/constraints/<index>` scheme
//!   at every depth, so e.g. an `odrl:xone`'s second child, itself an
//!   `odrl:and`'s first child, gets
//!   `<rule>/constraints/<xone-index>/constraints/<and-index>/constraints/0`.
//!   See "Triples emitted" below for the logical-group predicates
//!   themselves.
//!
//! `Distribution.access_service` is a bare `String` in the domain model,
//! not a typed foreign key - it is resolved to a DataService resource IRI
//! using the exact same `<base>/services/<id>` scheme a real `DataService`
//! would get, so a distribution whose `access_service` matches a data
//! service actually present in the same catalog naturally points at that
//! same resource. A dangling reference (no such service) still round-trips
//! correctly: decoding only ever needs to strip the known prefix and
//! percent-decode the remainder, it never requires the target to exist.
//!
//! ### Triples emitted, subject/predicate/object
//!
//! For catalog resource `<catalog>`:
//! - `<catalog> rdf:type dcat:Catalog .`
//! - `<catalog> fcns:participantId "<participant_id>"` - only if
//!   `Catalog.participant_id` is `Some`. DSP's own `participantId` is a
//!   dataspace-specific concept with no DCAT/ODRL equivalent, so it falls
//!   back to this project's own namespace per the rule above.
//! - `<catalog> dcat:dataset <dataset> .` - one per `Catalog.datasets`
//!   entry (`dcat:dataset` is DCAT's real Catalog-to-Dataset property).
//! - `<catalog> dcat:service <service> .` - one per `Catalog.data_services`
//!   entry (`dcat:service`, DCAT3's real Catalog-to-DataService property).
//! - `<catalog> <property-predicate> "<value>"` - one per
//!   `Catalog.properties` entry; see "Generic properties" below.
//!
//! For each dataset resource `<dataset>` (from `Catalog.datasets`):
//! - `<dataset> rdf:type dcat:Dataset .`
//! - `<dataset> fcns:sequenceIndex "<index>"^^xsd:integer .` - see
//!   "Ordering" below.
//! - `<dataset> dcat:distribution <distribution> .` - one per
//!   `Dataset.distributions` entry (`dcat:distribution` is DCAT's real
//!   Dataset-to-Distribution property).
//! - `<dataset> odrl:hasPolicy <policy> .` - one per `Dataset.policies`
//!   entry (`odrl:hasPolicy` is ODRL's real property for attaching a
//!   policy to an asset, and the exact term DSP catalogs advertise offers
//!   under).
//! - `<dataset> <property-predicate> "<value>"` - one per
//!   `Dataset.properties` entry; see "Generic properties" below.
//!
//! For each policy resource `<policy>` (from `Dataset.policies`):
//! - `<policy> rdf:type odrl:<Kind> .` - `odrl:Set` / `odrl:Offer` /
//!   `odrl:Agreement`, matching `Policy.kind` (see [`PolicyKind`]).
//! - `<policy> fcns:sequenceIndex "<index>"^^xsd:integer .` - see
//!   "Ordering" below.
//! - `<policy> fcns:policyId "<id>"` - only if `Policy.id` is `Some`. Not
//!   an ODRL term: in a real JSON-LD/RDF reading, a policy's `@id` *is*
//!   its subject IRI, but this store already mints its own positional
//!   subject IRI for a policy (see "Resource IRIs" above), so the
//!   harvested `@id` string needs a separate home to round-trip - there is
//!   no DCAT/ODRL term for "this resource's externally-advertised id, kept
//!   as a plain literal", so it falls back to this project's own
//!   namespace per the "Generic properties" rule below.
//! - `<policy> odrl:assigner "<assigner>"` / `<policy> odrl:assignee "<assignee>"` -
//!   only if `Policy.assigner` / `Policy.assignee` is `Some`, as an IRI
//!   when the value parses as one (e.g. a DID) or a plain literal
//!   otherwise - the same IRI-or-literal treatment `dcat:endpointURL` gets
//!   below, for the same reason: ODRL's formal range for both properties
//!   is `odrl:Party` (an IRI-identified resource), but a harvested value
//!   isn't guaranteed to already be a valid IRI.
//! - `<policy> odrl:permission <rule> .` / `<policy> odrl:prohibition <rule> .` /
//!   `<policy> odrl:obligation <rule> .` - one per entry in
//!   `Policy.permissions` / `Policy.prohibitions` / `Policy.obligations`
//!   respectively (ODRL's real property for each rule kind).
//!
//! For each rule resource `<rule>` (a permission/prohibition/obligation,
//! from `Policy.permissions`/`prohibitions`/`obligations`):
//! - `<rule> fcns:sequenceIndex "<index>"^^xsd:integer .`
//! - `<rule> odrl:action ...` - `Rule.action`, IRI-or-literal (ODRL
//!   actions are often a bare keyword like `"use"`, but can also be a full
//!   IRI, so the same fallback as `dcat:endpointURL`/`odrl:assigner`
//!   applies).
//! - `<rule> odrl:constraint <constraint> .` - one per `Rule.constraints`
//!   entry.
//!
//! For each constraint resource `<constraint>` (from `Rule.constraints`,
//! or recursively from a logical constraint's own children - see
//! "Resource IRIs" above): first, always,
//! `<constraint> fcns:sequenceIndex "<index>"^^xsd:integer .` (this
//! resource's position among its own siblings, atomic or logical alike);
//! then, depending on [`catalog_core::Constraint`]'s shape:
//!
//! - [`Atomic`](catalog_core::Constraint::Atomic):
//!   - `<constraint> odrl:leftOperand ...` - `Constraint.left_operand`,
//!     IRI-or-literal.
//!   - `<constraint> odrl:operator ...` - `Constraint.operator`,
//!     IRI-or-literal.
//!   - `<constraint> odrl:rightOperand "<value>"` - `Constraint.right_operand`,
//!     **always** a plain literal, never minted as an IRI even when the
//!     value happens to parse as one: a `rightOperand` is a value being
//!     compared against, not an identifier for another resource, so
//!     giving it the IRI-or-literal treatment would change its RDF shape
//!     based on incidental string content rather than ODRL semantics.
//! - [`Logical`](catalog_core::Constraint::Logical) - exactly one of:
//!   - `<constraint> odrl:and <child> .` - one per
//!     [`LogicalConstraint::And`]
//!     child, in order.
//!   - `<constraint> odrl:or <child> .` - one per
//!     [`LogicalConstraint::Or`]
//!     child, in order.
//!   - `<constraint> odrl:xone <child> .` - one per
//!     [`LogicalConstraint::Xone`]
//!     child, in order.
//!   - `<constraint> odrl:andSequence <child> .` - one per
//!     [`LogicalConstraint::AndSequence`]
//!     child, in order.
//!
//!   Each `<child>` is itself a full constraint resource (see "Resource
//!   IRIs" above), recursively either shape again - up to
//!   `MAX_CONSTRAINT_DEPTH` (64) levels deep, matching
//!   `crawler::MAX_CONSTRAINT_DEPTH`; a child nested past that bound is
//!   dropped entirely (no `odrl:and`/`odrl:or`/`odrl:xone`/
//!   `odrl:andSequence` link triple written for it, and none of its own
//!   triples either) rather than growing this store's own recursive
//!   write/read past a safe bound.
//!
//! For each distribution resource `<distribution>` (from
//! `Dataset.distributions`):
//! - `<distribution> rdf:type dcat:Distribution .`
//! - `<distribution> fcns:sequenceIndex "<index>"^^xsd:integer .`
//! - `<distribution> dct:format "<format>" .`
//! - `<distribution> dcat:accessService <service> .` - `<service>` is the
//!   `<base>/services/<access_service>` IRI described above (`dcat:accessService`
//!   is DCAT's real Distribution-to-DataService property).
//!
//! For each data service resource `<service>` (from `Catalog.data_services`):
//! - `<service> rdf:type dcat:DataService .`
//! - `<service> fcns:sequenceIndex "<index>"^^xsd:integer .`
//! - `<service> dcat:endpointURL <endpoint_url>` (or, if `endpoint_url`
//!   does not parse as a valid IRI - untrusted crawled data, not something
//!   this store should reject - `"<endpoint_url>"` as a plain literal
//!   instead). DCAT defines `dcat:endpointURL`'s range as `rdfs:Resource`,
//!   i.e. an IRI, not a literal; since the domain field already holds a
//!   URL string, minting it as the object IRI directly (rather than
//!   wrapping it in a literal) is the more faithful reading of the real
//!   DCAT term.
//! - `<service> dcat:endpointDescription "<endpoint_description>"` - only
//!   if `DataService.endpoint_description` is `Some`. Stored as a plain
//!   literal rather than an IRI even though DCAT's formal range for this
//!   property is also `rdfs:Resource`: this domain field holds free text
//!   (e.g. `"dataspace-protocol-http:1.0"`, see `seed_sample_catalog`), not
//!   a URL, and DCAT's own usage note allows literal values in practice.
//!
//! ### Generic properties (`Catalog.properties` / `Dataset.properties`)
//!
//! `catalog-core`'s `properties: BTreeMap<String, String>` is an arbitrary
//! key/value bag - EDC's `Dataset`/`Asset` have the same shape, keyed by
//! whatever property IRI or name the source used. Each entry becomes
//! exactly one triple, `<resource> <predicate> "<value>"`, where
//! `<predicate>` is:
//! - the key itself, reused as-is, **if** it already parses as an absolute
//!   IRI (so a crawler that already normalized a key to a real vocabulary
//!   term - e.g. `http://www.w3.org/ns/dcat#keyword` - gets a genuine
//!   triple using that term, not a synthesized one); otherwise
//! - `fcns:property/<percent-encoded key>` - the documented fallback.
//!
//! `crawler::collect_datasets_and_services` now populates `Dataset.properties`
//! with a real crawled dataset's optional descriptors (`title`,
//! `description`, `version`, `creatorName`, `thumbnail`, `keywords`, each
//! only when the source DSP JSON actually carries it - see that function's
//! own doc comment) - `POST /api/management/v4/catalogs/request` reads
//! them straight back out through this exact mechanism to populate the
//! real `edc_federated_catalog_client::models::Dataset`'s own optional
//! fields. None of those keys are absolute IRIs, so all of them take the
//! `fcns:property/<key>` fallback path above, not the passthrough one -
//! but whatever ends up in that map, including any future policy-relevant
//! data, is faithfully represented as a triple, never silently dropped.
//!
//! **Known limitation, not exercised by any current producer**: a
//! property key that happens to be exactly one of this mapping's own
//! reserved predicate IRIs would collide with this mapping's own
//! structural triples. For `Catalog.properties` and `Dataset.properties`
//! specifically (the only two generic key/value bags in the domain model
//! today - `Policy`/`Rule`/`Constraint` carry no such bag to collide
//! against): `rdf:type`, `dcat:dataset`, `dcat:service`,
//! `dcat:distribution`, `dcat:accessService`, `dcat:endpointURL`,
//! `dcat:endpointDescription`, `dct:format`, `fcns:participantId`,
//! `fcns:sequenceIndex`, and (new with the ODRL mapping above)
//! `odrl:hasPolicy` for `Dataset.properties`. The rest of the ODRL mapping's
//! own structural predicates - `odrl:permission`, `odrl:prohibition`,
//! `odrl:obligation`, `odrl:action`, `odrl:constraint`,
//! `odrl:leftOperand`, `odrl:operator`, `odrl:rightOperand`,
//! `odrl:assigner`, `odrl:assignee`, `odrl:and`, `odrl:or`, `odrl:xone`,
//! `odrl:andSequence`, and `fcns:policyId` - are reserved on
//! `Policy`/`Rule`/`Constraint` resources the same way, but those types
//! have no generic property map at all, so there is nothing for them to
//! collide with today either way. Flagged rather than defended against,
//! since nothing produces a colliding key today.
//!
//! **Test coverage**: this crate's own tests prove the generic-properties
//! round trip through a real `OxigraphCatalogCache` (write, then read
//! back) with synthetic keys (e.g. `assetType`), and
//! `ds_catalog_broker_rs`'s
//! `catalog_request_route_serves_crawled_dataset_descriptors_from_a_real_oxigraph_store`
//! covers the full chain: the crawler parses a DSP dataset's
//! `title`/`description`/etc., upserts it into *this* store, and the
//! management API reads it back out.
//!
//! ### Ordering (`fcns:sequenceIndex`)
//!
//! `Catalog.datasets`, `Dataset.distributions`, `Catalog.data_services`,
//! `Dataset.policies`, `Policy.permissions`/`prohibitions`/`obligations`,
//! and `Rule.constraints` are all `Vec`s - order (and, for distributions
//! and constraints, even exact duplicates) is part of `Catalog`'s
//! `PartialEq`, but RDF triples are an unordered set. Each
//! dataset/distribution/data-service/policy/rule/constraint resource
//! therefore carries an explicit `fcns:sequenceIndex` integer literal
//! recording its original position within its own parent list, and
//! `query()` sorts by it when reconstructing each `Vec` - this is pure
//! bookkeeping to make an ordered domain type round-trip through an
//! unordered store faithfully, not domain data, hence the fallback
//! namespace rather than a borrowed vocabulary term (neither DCAT nor ODRL
//! has a concept of list ordering for any of these).
//!
//! This also implicitly assumes `Dataset.id` (and `DataService.id`) are
//! unique within one catalog: two datasets sharing an id would collide
//! onto the same `<base>/datasets/<id>` resource. This mirrors real DSP
//! semantics (a JSON-LD node's `@id` is inherently unique - that is what
//! `@id` means) and is not otherwise enforced by `catalog-core::Dataset`.

use async_trait::async_trait;
use catalog_core::{Catalog, NodeId};
use catalog_core::{
    Constraint, DataService, Dataset, Distribution, LogicalConstraint, Policy, PolicyKind, Rule,
};
use contreforts_kg::GraphError;
use contreforts_kg::store::GraphStore;
use oxigraph::model::{
    GraphName, GraphNameRef, Literal, NamedNode, NamedOrBlankNode, NamedOrBlankNodeRef, Quad, Term,
};
pub use oxigraph::sparql::CancellationToken;
use oxigraph::sparql::results::{QueryResultsFormat, QueryResultsSerializer};
use oxigraph::sparql::{PreparedSparqlQuery, QueryEvaluationError, QueryResults, SparqlEvaluator};
use oxigraph::store::StorageError;
use spareval::{InternalQuad, QueryableDataset};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

use crate::{CatalogCache, CatalogQuery, StoreError, StoreResult};

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

// The submodules below split `OxigraphCatalogCache`'s implementation by
// concern and share this module's imports and constants via `use super::*`.
mod iris;
mod read;
mod sparql;
#[cfg(test)]
mod tests;
mod vocab;
mod write;

use iris::*;
pub use iris::{dataset_resource_iri, service_resource_iri};
use vocab::*;

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
