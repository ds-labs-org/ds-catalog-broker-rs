//! A simple, non-persistent [`CatalogCache`] backed by an in-process map.
//!
//! This exists so `ds-catalog-broker-rs` (and this crate's own tests) have something
//! to run against while the real RDF-backed implementation is chosen; it
//! is not intended to be the production backend.

use async_trait::async_trait;
use catalog_core::{Catalog, NodeId};
use std::collections::HashMap;
use tokio::sync::RwLock;

use crate::{CatalogCache, CatalogQuery, StoreResult};

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
