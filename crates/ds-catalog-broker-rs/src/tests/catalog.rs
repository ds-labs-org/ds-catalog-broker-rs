use super::*;

#[tokio::test]
async fn health_returns_ok() {
    let app = build_router(test_state());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: HealthResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed.status, "ok");
}

#[tokio::test]
async fn catalog_endpoint_returns_empty_list_when_cache_is_empty() {
    let app = build_router(test_state());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/catalog")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: CatalogListResponse = serde_json::from_slice(&body).unwrap();
    assert!(parsed.catalogs.is_empty());
}

#[tokio::test]
async fn catalog_endpoint_returns_upserted_catalog() {
    let state = test_state();
    let node = NodeId::new("node-1");
    state
        .cache
        .upsert(Catalog::new("cat-1", node.clone()))
        .await
        .unwrap();

    let app = build_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/catalog?node_id=node-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: CatalogListResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed.catalogs.len(), 1);
    assert_eq!(parsed.catalogs[0].id, "cat-1");
}

#[tokio::test]
async fn catalog_endpoint_serves_seeded_sample_catalog() {
    let state = test_state();
    seed_sample_catalog(&*state.cache).await.unwrap();

    let app = build_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/catalog?node_id=sample-participant")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: CatalogListResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed.catalogs.len(), 1);
    let catalog = &parsed.catalogs[0];
    assert_eq!(catalog.id, "sample-catalog");
    assert_eq!(catalog.origin_node, NodeId::new("sample-participant"));
    assert_eq!(catalog.datasets.len(), 2);
    let dataset_ids: Vec<&str> = catalog.datasets.iter().map(|d| d.id.as_str()).collect();
    assert_eq!(dataset_ids, vec!["CAT0101", "CAT0102"]);
    assert_eq!(catalog.data_services.len(), 1);
}

#[tokio::test]
async fn catalog_endpoint_filters_by_unknown_node_id() {
    let state = test_state();
    state
        .cache
        .upsert(Catalog::new("cat-1", NodeId::new("node-1")))
        .await
        .unwrap();

    let app = build_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/catalog?node_id=does-not-exist")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: CatalogListResponse = serde_json::from_slice(&body).unwrap();
    assert!(parsed.catalogs.is_empty());
}
