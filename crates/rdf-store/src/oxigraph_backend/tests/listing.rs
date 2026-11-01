// --- Stable listing order, undecodable graph names (#37) --------------

use super::*;

/// Participants that share a catalog id must come back in the same order
/// on every call, so offset/limit pages neither repeat nor skip one.
#[tokio::test]
async fn catalogs_sharing_an_id_list_in_a_stable_order_by_origin_node() {
    let cache = cache();
    for node in ["node-e", "node-b", "node-d", "node-a", "node-c"] {
        cache.upsert(sample_catalog(node, "catalog")).await.unwrap();
    }

    for _ in 0..20 {
        let all = cache.query(CatalogQuery::all()).await.unwrap();
        let nodes: Vec<&str> = all.iter().map(|c| c.origin_node.0.as_str()).collect();
        assert_eq!(nodes, ["node-a", "node-b", "node-c", "node-d", "node-e"]);
    }

    let mut paged = Vec::new();
    for offset in 0..5 {
        let mut query = CatalogQuery::all();
        query.offset = offset;
        query.limit = Some(1);
        let page = cache.query(query).await.unwrap();
        paged.push(page[0].origin_node.0.clone());
    }
    assert_eq!(paged, ["node-a", "node-b", "node-c", "node-d", "node-e"]);
}

/// A named graph this backend did not write (outside the node namespace,
/// or with bad percent-encoding) must not fail the whole listing.
#[tokio::test]
async fn an_undecodable_graph_name_is_left_out_of_reading_all_catalogs() {
    let cache = cache();
    cache
        .upsert(sample_catalog("node-good", "cat-good"))
        .await
        .unwrap();
    for graph in [
        "http://example.org/foreign-graph".to_string(),
        format!("{NODE_NS}%FF%FE"),
    ] {
        let graph = NamedNode::new(graph).unwrap();
        cache
            .store
            .inner()
            .insert(&Quad::new(
                NamedNode::new("http://example.org/s").unwrap(),
                NamedNode::new("http://example.org/p").unwrap(),
                Literal::from("o"),
                graph,
            ))
            .unwrap();
    }

    let all = cache.query(CatalogQuery::all()).await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].origin_node, NodeId::new("node-good"));
}
