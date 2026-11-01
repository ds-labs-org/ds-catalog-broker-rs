use super::*;

// --- `/sparql` (gap analysis §3.3) --------------------------------------

/// `AppState` wired the way `main.rs` wires it once
/// the config lists a `broker:participant`: a real Oxigraph-backed cache, with
/// `AppState::sparql` pointed at that same store so `/sparql` is live.
pub(super) fn sparql_test_state() -> AppState {
    let store = Arc::new(rdf_store::oxigraph_backend::OxigraphCatalogCache::in_memory().unwrap());
    let cache: Arc<dyn CatalogCache> = store.clone();
    AppState::new(cache).with_sparql(Some(store))
}

/// A small but real per-participant catalog - same shape as
/// `seed_sample_catalog`'s fixture (one dataset, one distribution, one
/// data service), parameterized by origin node so two distinct
/// participants' worth of real, differently-shaped data can be seeded
/// side by side, which is what the SPARQL tests below need to prove a
/// query genuinely spans more than one harvested participant.
pub(super) fn participant_catalog(node_id: &str, catalog_id: &str, dataset_id: &str) -> Catalog {
    let mut catalog = Catalog::new(catalog_id, NodeId::new(node_id));
    catalog.participant_id = Some(format!("did:example:{node_id}"));
    let service_id = format!("{dataset_id}-svc");
    catalog.datasets.push(Dataset {
        id: dataset_id.to_string(),
        properties: Default::default(),
        distributions: vec![Distribution {
            format: "application/json".to_string(),
            access_service: service_id.clone(),
        }],
        policies: Vec::new(),
    });
    catalog.data_services.push(DataService {
        id: service_id,
        endpoint_url: format!("https://{node_id}.example.org/dsp"),
        endpoint_description: Some("dataspace-protocol-http:1.0".to_string()),
    });
    catalog
}

/// The real end-to-end path this gap analysis item asks for: two
/// seeded origin nodes, a real SPARQL SELECT sent through the actual
/// `GET /sparql` HTTP route (not `OxigraphCatalogCache::sparql_query_json`
/// called directly), and assertions on the real parsed
/// `application/sparql-results+json` body - proving GET, the default
/// whole-store scope, the real Oxigraph evaluator, and the real JSON
/// serialization all actually work together through the router.
#[tokio::test]
async fn sparql_get_select_finds_datasets_from_both_seeded_participants() {
    let state = sparql_test_state();
    state
        .cache
        .upsert(participant_catalog("node-a", "cat-a", "DATASET-A"))
        .await
        .unwrap();
    state
        .cache
        .upsert(participant_catalog("node-b", "cat-b", "DATASET-B"))
        .await
        .unwrap();

    let app = build_router(state);
    let query = "PREFIX dcat: <http://www.w3.org/ns/dcat#> \
                 SELECT ?dataset WHERE { ?dataset a dcat:Dataset }";
    let uri = format!("/sparql?query={}", urlencoding::encode(query));
    let response = app
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("Accept", "application/sparql-results+json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .unwrap(),
        "application/sparql-results+json"
    );

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["head"]["vars"], serde_json::json!(["dataset"]));
    let bindings = parsed["results"]["bindings"].as_array().unwrap();
    assert_eq!(
        bindings.len(),
        2,
        "expected one dataset per seeded participant, got {parsed}"
    );
    let mut dataset_iris: Vec<&str> = bindings
        .iter()
        .map(|b| b["dataset"]["value"].as_str().unwrap())
        .collect();
    dataset_iris.sort_unstable();
    assert!(dataset_iris[0].contains("node-a") && dataset_iris[0].contains("DATASET-A"));
    assert!(dataset_iris[1].contains("node-b") && dataset_iris[1].contains("DATASET-B"));
    assert_eq!(bindings[0]["dataset"]["type"], serde_json::json!("uri"));
}

/// The other mandated submission mechanism: `POST` with
/// `application/x-www-form-urlencoded` and a `query` form field (see
/// `sparql_route_post`'s doc comment for why this style was chosen
/// over raw `application/sparql-query` bodies). Same real end-to-end
/// path and assertions as the GET test above.
#[tokio::test]
async fn sparql_post_form_encoded_select_finds_seeded_dataset() {
    let state = sparql_test_state();
    state
        .cache
        .upsert(participant_catalog("node-a", "cat-a", "DATASET-A"))
        .await
        .unwrap();

    let app = build_router(state);
    let query = "PREFIX dcat: <http://www.w3.org/ns/dcat#> \
                 SELECT ?dataset WHERE { ?dataset a dcat:Dataset }";
    let form_body = format!("query={}", urlencoding::encode(query));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/sparql")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from(form_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let bindings = parsed["results"]["bindings"].as_array().unwrap();
    assert_eq!(bindings.len(), 1);
    assert!(
        bindings[0]["dataset"]["value"]
            .as_str()
            .unwrap()
            .contains("DATASET-A")
    );
}

/// A real SPARQL ASK, through the HTTP route, producing the
/// spec-shaped `{"head":{},"boolean":true}` body.
#[tokio::test]
async fn sparql_get_ask_returns_true_over_http() {
    let state = sparql_test_state();
    state
        .cache
        .upsert(participant_catalog("node-a", "cat-a", "DATASET-A"))
        .await
        .unwrap();

    let app = build_router(state);
    let query = "PREFIX dcat: <http://www.w3.org/ns/dcat#> ASK { ?d a dcat:Dataset }";
    let uri = format!("/sparql?query={}", urlencoding::encode(query));
    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed, serde_json::json!({"head": {}, "boolean": true}));
}

/// The in-memory backend (no `broker:participant`, `AppState::sparql`
/// is `None`) has no SPARQL capability at all - `/sparql` must say so
/// plainly (501), not 404 (the route exists) and not pretend to
/// answer.
#[tokio::test]
async fn sparql_endpoint_returns_501_when_no_oxigraph_backend_is_configured() {
    let app = build_router(test_state());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/sparql?query=ASK%20%7B%20%3Fs%20%3Fp%20%3Fo%20%7D")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn sparql_endpoint_requires_a_query_parameter() {
    let app = build_router(sparql_test_state());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/sparql")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// `Accept` demanding a representation this endpoint doesn't produce
/// is 406, not a silent fallback to JSON anyway.
#[tokio::test]
async fn sparql_endpoint_rejects_an_unacceptable_accept_header() {
    let app = build_router(sparql_test_state());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/sparql?query=ASK%20%7B%20%3Fs%20%3Fp%20%3Fo%20%7D")
                .header("Accept", "text/html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
}

/// A SPARQL Update sent to this read-only endpoint must be rejected,
/// and must not mutate the store - the real proof (through HTTP, not
/// a direct backend call) that this product's "read-only, never
/// originates data" rule actually holds at the surface a caller would
/// use.
#[tokio::test]
async fn sparql_endpoint_rejects_an_update_operation_and_leaves_the_store_unchanged() {
    let state = sparql_test_state();
    state
        .cache
        .upsert(participant_catalog("node-a", "cat-a", "DATASET-A"))
        .await
        .unwrap();
    let cache_handle = state.cache.clone();

    let app = build_router(state);
    let injection = "PREFIX dcat: <http://www.w3.org/ns/dcat#> \
                      INSERT DATA { GRAPH <urn:x> { <urn:y> a dcat:Catalog } }";
    let uri = format!("/sparql?query={}", urlencoding::encode(injection));
    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let results = cache_handle.query(CatalogQuery::all()).await.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, "cat-a");
}
