//! The backend-agnostic [`CatalogCache`] trait and its query/error types.

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
/// sized to what the routes need. Richer queries go through SPARQL
/// (`OxigraphCatalogCache::sparql_query_json`), not through this type.
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
///
/// Writes are atomic per origin node: a `query` running alongside an
/// `upsert` or `delete` of the same node sees the catalog as it was
/// before the write or as it is after it, never a partly written one.
#[async_trait]
pub trait CatalogCache: Send + Sync {
    /// Insert or replace the named graph for `catalog.origin_node`.
    ///
    /// Re-crawling the same node always overwrites its prior catalog
    /// wholesale, matching EDC's upsert-by-origin-node-url behavior. The
    /// old catalog stays readable until the new one replaces it in one
    /// step.
    async fn upsert(&self, catalog: Catalog) -> StoreResult<()>;

    /// Return stored catalogs matching `query`.
    async fn query(&self, query: CatalogQuery) -> StoreResult<Vec<Catalog>>;

    /// Remove the named graph for `node`, if present.
    ///
    /// Returns `true` if a catalog was actually removed.
    async fn delete(&self, node: &NodeId) -> StoreResult<bool>;
}
