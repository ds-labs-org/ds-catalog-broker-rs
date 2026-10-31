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

mod cache;
pub mod memory;
pub mod oxigraph_backend;

pub use cache::{CatalogCache, CatalogQuery, StoreError, StoreResult};
