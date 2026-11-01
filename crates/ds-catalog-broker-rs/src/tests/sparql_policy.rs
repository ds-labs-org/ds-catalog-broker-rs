use super::*;

// --- SPARQL ODRL policy-based filtering (gap analysis §3.4)
// ------------------------------------------------------------------
//
// The last of gap analysis §3.4's three serving surfaces: `GET`/
// `POST /sparql` evaluates every filtered query over a view of the
// store holding only what `odrl_filter::dataset_is_visible` (via
// `visible_resource_iris`) lets the caller see - see `sparql_route`'s
// own doc comment, and `rdf_store::oxigraph_backend`'s
// `sparql_query_json_restricted` for the view itself. Named graphs in
// the semantic cache are per-*participant* while ODRL policies are
// per-*dataset*, so the view filters each quad by the dataset or
// service resource it belongs to rather than by graph.
//
// Per this session's own prior-art lesson (silent over-permission is
// the failure mode that matters, not a loud error), every "hidden"
// assertion below checks a policy-gated dataset's actual *absence*
// from the parsed SPARQL JSON results, mirroring the REST-surface
// negative-test discipline in `policy.rs` - not merely that the response still
// parses.

/// Same idea as `oauth2_sparql_state`, but seeded with a caller-
/// supplied catalog (via `test_state()`'s real Oxigraph
/// backend) rather than the fixed single-dataset `participant_catalog`
/// fixture - the SPARQL analogue of `oauth2_state_with_catalog`, which
/// does the same thing for `GET /catalog`/the management API.
async fn oauth2_sparql_state_with_catalog(
    catalog: Catalog,
    configure: impl FnOnce(&mut OAuth2Config),
) -> (AppState, oauth2::test_support::TestKey) {
    let key = generate_key("sparql-policy-filter-key");
    let jwks_uri = spawn_jwks_server(serde_json::json!({"keys": [ec_jwk(&key, None)]})).await;
    let mut config = oauth2_config(jwks_uri);
    configure(&mut config);
    let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), config)
        .await
        .expect("fetch mock JWKS");

    let state = test_state();
    state.cache.upsert(catalog).await.unwrap();
    let state = state.with_oauth2(Some(Arc::new(verifier)));
    (state, key)
}

/// `SELECT ?dataset WHERE { ?dataset a dcat:Dataset }` - the same
/// bindable-dataset-IRI query shape `sparql_get_select_finds_datasets_from_both_seeded_participants`
/// already uses in `sparql.rs`, run here against a catalog that mixes an open
/// and a policy-gated dataset (`catalog_with_open_and_gated_datasets`,
/// from the REST-surface filtering tests in `policy.rs`).
fn dataset_iri_query() -> String {
    "PREFIX dcat: <http://www.w3.org/ns/dcat#> \
     SELECT ?dataset WHERE { ?dataset a dcat:Dataset }"
        .to_string()
}

/// Every `?dataset` binding's IRI string from a parsed
/// `application/sparql-results+json` body, as produced by
/// [`dataset_iri_query`].
fn dataset_iris_of(parsed: &serde_json::Value) -> Vec<&str> {
    parsed["results"]["bindings"]
        .as_array()
        .expect("a SELECT response has a results.bindings array")
        .iter()
        .map(|binding| {
            binding["dataset"]["value"]
                .as_str()
                .expect("each binding has a dataset IRI")
        })
        .collect()
}

#[tokio::test]
async fn sparql_hides_a_policy_gated_datasets_iri_from_a_caller_without_the_required_claim() {
    let (state, key) = oauth2_sparql_state_with_catalog(
        catalog_with_open_and_gated_datasets("node-a", "cat-a"),
        |_| {},
    )
    .await;
    let app = build_router(state);
    let token = sign_es256(&key, base_claims());

    let uri = format!(
        "/sparql?query={}",
        urlencoding::encode(&dataset_iri_query())
    );
    let response = app
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("Authorization", bearer(&token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let dataset_iris = dataset_iris_of(&parsed);
    assert!(
        !dataset_iris.iter().any(|iri| iri.contains("GATED-DATASET")),
        "a SPARQL query that binds a dataset's subject IRI must not return one the caller's \
         claims don't entitle them to under its harvested ODRL policy, mirroring GET \
         /catalog's own entitlement gate. Got dataset IRIs: {dataset_iris:?}"
    );
    assert!(
        dataset_iris.iter().any(|iri| iri.contains("OPEN-DATASET")),
        "an unrelated, policy-free dataset must remain visible. Got dataset IRIs: \
         {dataset_iris:?}"
    );
}

/// The positive companion to the "hides" test above, pinned down
/// together the same way the REST-surface section does: a caller
/// whose claims *do* satisfy the gated dataset's policy must still see
/// it once real filtering is wired.
#[tokio::test]
async fn sparql_shows_a_policy_gated_datasets_iri_to_a_caller_with_the_required_claim() {
    let (state, key) = oauth2_sparql_state_with_catalog(
        catalog_with_open_and_gated_datasets("node-a", "cat-a"),
        |_| {},
    )
    .await;
    let app = build_router(state);
    let token = sign_es256(&key, eu_resident_claims());

    let uri = format!(
        "/sparql?query={}",
        urlencoding::encode(&dataset_iri_query())
    );
    let response = app
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("Authorization", bearer(&token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let dataset_iris = dataset_iris_of(&parsed);
    assert!(
        dataset_iris.iter().any(|iri| iri.contains("GATED-DATASET")),
        "a caller whose claims satisfy the dataset's policy must still see it. Got dataset \
         IRIs: {dataset_iris:?}"
    );
    assert!(dataset_iris.iter().any(|iri| iri.contains("OPEN-DATASET")));
}

/// The unauthenticated case, mirroring
/// `get_catalog_filters_by_policy_even_when_oauth2_is_disabled_matching_the_default_config`:
/// with no OAuth2 verifier configured at all, filtering must still run
/// against an empty claims map, per
/// `PolicyFilterConfig::filter_when_oauth2_disabled`'s default
/// (`true`).
#[tokio::test]
async fn sparql_filters_by_policy_even_when_oauth2_is_disabled_matching_the_default_config() {
    let state = test_state();
    state
        .cache
        .upsert(catalog_with_open_and_gated_datasets("node-a", "cat-a"))
        .await
        .unwrap();
    assert!(
        state.policy_filter.filter_when_oauth2_disabled,
        "this test exercises PolicyFilterConfig's own default; update it if that default \
         ever changes"
    );
    let app = build_router(state);

    let uri = format!(
        "/sparql?query={}",
        urlencoding::encode(&dataset_iri_query())
    );
    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let dataset_iris = dataset_iris_of(&parsed);
    assert!(
        !dataset_iris.iter().any(|iri| iri.contains("GATED-DATASET")),
        "with no OAuth2 verifier configured at all, filtering must still run against an \
         empty claims map - an unauthenticated caller must not see a dataset whose policy \
         requires a claim they cannot possibly present. Got dataset IRIs: {dataset_iris:?}"
    );
    assert!(dataset_iris.iter().any(|iri| iri.contains("OPEN-DATASET")));
}

/// A query with no dataset-subject-shaped variable anywhere in it
/// (`?s ?p ?o`, nothing ties any of them to a dataset) is answered,
/// not rejected, under the default config: it is evaluated over only
/// the datasets and data services the caller may see, so the gated
/// dataset's triples stay out of it.
#[tokio::test]
async fn sparql_answers_a_query_with_no_dataset_variable_over_only_visible_datasets() {
    let values = unauthenticated_sparql_binding_values(
        "SELECT ?s ?p ?o WHERE { ?s ?p ?o }",
        odrl_filter::PolicyFilterConfig::default(),
    )
    .await;
    assert!(
        !values.iter().any(|v| v.contains("GATED-DATASET")),
        "a gated dataset's triples must stay hidden. Got: {values:?}"
    );
    assert!(
        values.iter().any(|v| v.contains("OPEN-DATASET")),
        "the open dataset's triples must be returned. Got: {values:?}"
    );
}

// --- SPARQL: query shapes that do not bind a dataset variable -------
//
// A sibling `UNION`/`OPTIONAL` branch, or a pattern on any variable
// other than a `?x a dcat:Dataset` subject, must not reach a gated
// dataset's triples either.

/// Every binding value (IRI or literal) anywhere in a parsed
/// `application/sparql-results+json` body.
fn all_binding_values(parsed: &serde_json::Value) -> Vec<String> {
    parsed["results"]["bindings"]
        .as_array()
        .expect("a SELECT response has a results.bindings array")
        .iter()
        .flat_map(|binding| {
            binding
                .as_object()
                .expect("each binding is an object")
                .values()
                .map(|term| term["value"].as_str().unwrap_or_default().to_string())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Runs `query` unauthenticated (so filtering runs against an empty
/// claims map, per `PolicyFilterConfig`'s default) against the open +
/// gated catalog, with `policy_filter` applied, and returns every
/// binding value in the 200 response.
async fn unauthenticated_sparql_binding_values(
    query: &str,
    policy_filter: odrl_filter::PolicyFilterConfig,
) -> Vec<String> {
    unauthenticated_sparql_binding_values_over(
        catalog_with_open_and_gated_datasets("node-a", "cat-a"),
        query,
        policy_filter,
    )
    .await
}

/// [`unauthenticated_sparql_binding_values`] over a caller-supplied
/// catalog.
async fn unauthenticated_sparql_binding_values_over(
    catalog: Catalog,
    query: &str,
    policy_filter: odrl_filter::PolicyFilterConfig,
) -> Vec<String> {
    let state = test_state().with_policy_filter(policy_filter);
    state.cache.upsert(catalog).await.unwrap();
    let app = build_router(state);

    let uri = format!("/sparql?query={}", urlencoding::encode(query));
    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "query: {query}");

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    all_binding_values(&parsed)
}

#[tokio::test]
async fn sparql_union_sibling_branch_does_not_leak_a_gated_datasets_triples() {
    let values = unauthenticated_sparql_binding_values(
        "PREFIX dcat: <http://www.w3.org/ns/dcat#> \
         SELECT * WHERE { { ?x a dcat:Dataset } UNION { ?s ?p ?o } }",
        odrl_filter::PolicyFilterConfig::default(),
    )
    .await;
    assert!(
        !values.iter().any(|v| v.contains("GATED-DATASET")),
        "the `?s ?p ?o` UNION branch is not tied to the recognized `?x` dataset variable, \
         but must still not expose a gated dataset's triples. Got: {values:?}"
    );
    assert!(
        values.iter().any(|v| v.contains("OPEN-DATASET")),
        "the open dataset's triples must stay visible. Got: {values:?}"
    );
}

#[tokio::test]
async fn sparql_optional_branch_does_not_leak_a_gated_datasets_triples() {
    let values = unauthenticated_sparql_binding_values(
        "PREFIX dcat: <http://www.w3.org/ns/dcat#> \
         SELECT * WHERE { ?x a dcat:Dataset OPTIONAL { ?s ?p ?o } }",
        odrl_filter::PolicyFilterConfig::default(),
    )
    .await;
    assert!(
        !values.iter().any(|v| v.contains("GATED-DATASET")),
        "an OPTIONAL branch reading triples through an unrecognized variable must not \
         expose a gated dataset's triples. Got: {values:?}"
    );
    assert!(values.iter().any(|v| v.contains("OPEN-DATASET")));
}

/// The open + gated catalog, plus a data service only the gated
/// dataset uses (its endpoint names the gated partner) and one no
/// dataset uses.
fn catalog_with_a_gated_only_service() -> Catalog {
    let mut catalog = catalog_with_open_and_gated_datasets("node-a", "cat-a");
    catalog.data_services.push(DataService {
        id: "GATED-SVC".to_string(),
        endpoint_url: "https://secret-partner.example/dsp".to_string(),
        endpoint_description: Some("secret endpoint".to_string()),
    });
    catalog.data_services.push(DataService {
        id: "UNUSED-SVC".to_string(),
        endpoint_url: "https://unused.example/dsp".to_string(),
        endpoint_description: None,
    });
    let gated = catalog
        .datasets
        .iter_mut()
        .find(|d| d.id == "GATED-DATASET")
        .unwrap();
    gated.distributions[0].access_service = "GATED-SVC".to_string();
    catalog
}

#[tokio::test]
async fn sparql_hides_a_data_service_only_a_gated_dataset_uses() {
    let values = unauthenticated_sparql_binding_values_over(
        catalog_with_a_gated_only_service(),
        "SELECT * WHERE { ?s ?p ?o }",
        odrl_filter::PolicyFilterConfig::default(),
    )
    .await;
    assert!(
        !values
            .iter()
            .any(|v| v.contains("GATED-SVC") || v.contains("secret")),
        "a data service referenced only by a hidden dataset must be hidden too. Got: {values:?}"
    );
    for still_visible in ["OPEN-DATASET-svc", "UNUSED-SVC"] {
        assert!(
            values.iter().any(|v| v.contains(still_visible)),
            "{still_visible} must stay visible. Got: {values:?}"
        );
    }
}

/// `GET /catalog` must hide the same services `/sparql` does.
#[tokio::test]
async fn get_catalog_hides_a_data_service_only_a_gated_dataset_uses() {
    let state = test_state();
    state
        .cache
        .upsert(catalog_with_a_gated_only_service())
        .await
        .unwrap();
    let app = build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/catalog?node_id=node-a")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: CatalogListResponse = serde_json::from_slice(&body).unwrap();
    let service_ids: Vec<&str> = parsed.catalogs[0]
        .data_services
        .iter()
        .map(|s| s.id.as_str())
        .collect();
    assert!(!service_ids.contains(&"GATED-SVC"), "Got: {service_ids:?}");
    assert!(
        service_ids.contains(&"OPEN-DATASET-svc"),
        "Got: {service_ids:?}"
    );
    assert!(service_ids.contains(&"UNUSED-SVC"), "Got: {service_ids:?}");
}

/// Visible datasets must not carry position numbers that leave gaps
/// where hidden datasets used to be.
#[tokio::test]
async fn sparql_does_not_reveal_hidden_datasets_through_position_gaps() {
    let mut catalog = catalog_with_open_and_gated_datasets("node-a", "cat-a");
    catalog.datasets.reverse();
    assert_eq!(catalog.datasets[0].id, "GATED-DATASET");

    let values = unauthenticated_sparql_binding_values_over(
        catalog,
        "SELECT ?x ?i WHERE { ?x a <http://www.w3.org/ns/dcat#Dataset> \
         OPTIONAL { ?x <https://federated-catalog-rs.internal/ns#sequenceIndex> ?i } }",
        odrl_filter::PolicyFilterConfig::default(),
    )
    .await;
    assert!(
        values.iter().any(|v| v.contains("OPEN-DATASET")),
        "the open dataset itself must stay visible. Got: {values:?}"
    );
    assert!(
        !values.iter().any(|v| v == "1"),
        "the open dataset's original position (1, after the hidden one) must not be exposed. Got: {values:?}"
    );
}

/// A gated dataset published with `"@id": ""` must be hidden like any
/// other, end to end through the route.
#[tokio::test]
async fn sparql_hides_a_gated_dataset_with_an_empty_id() {
    let mut catalog = catalog_with_open_and_gated_datasets("node-a", "cat-a");
    let gated = catalog
        .datasets
        .iter_mut()
        .find(|d| d.id == "GATED-DATASET")
        .unwrap();
    gated.id = String::new();
    gated
        .properties
        .insert("title".to_string(), "TOP SECRET".to_string());

    let values = unauthenticated_sparql_binding_values_over(
        catalog,
        "PREFIX dcat: <http://www.w3.org/ns/dcat#> \
         SELECT * WHERE { { ?x a dcat:Dataset } UNION { ?s ?p ?o } }",
        odrl_filter::PolicyFilterConfig::default(),
    )
    .await;
    assert!(
        !values.iter().any(|v| v.contains("TOP SECRET")),
        "an empty-id gated dataset must not leak. Got: {values:?}"
    );
    assert!(values.iter().any(|v| v.contains("OPEN-DATASET")));
}

// --- SPARQL time and size limits ---------------------------------------

/// Runs `query` unauthenticated against the open + gated catalog with
/// `limits` applied, returning the status and body.
async fn sparql_with_limits(query: &str, limits: SparqlLimitsConfig) -> (StatusCode, String) {
    let state = test_state().with_sparql_limits(limits);
    state
        .cache
        .upsert(catalog_with_open_and_gated_datasets("node-a", "cat-a"))
        .await
        .unwrap();
    let app = build_router(state);
    let uri = format!("/sparql?query={}", urlencoding::encode(query));
    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn sparql_cancels_a_query_that_runs_past_its_time_limit_with_503() {
    let started = std::time::Instant::now();
    let (status, body) = sparql_with_limits(
        "SELECT * WHERE { ?a ?b ?c . ?d ?e ?f . ?g ?h ?i . ?j ?k ?l }",
        SparqlLimitsConfig {
            timeout: Duration::from_millis(50),
            max_rows: usize::MAX,
        },
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body: {body}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the response must not wait for the runaway query to finish"
    );
}

#[tokio::test]
async fn sparql_rejects_a_result_over_the_row_cap_with_400() {
    let (status, body) = sparql_with_limits(
        "SELECT * WHERE { ?s ?p ?o }",
        SparqlLimitsConfig {
            max_rows: 1,
            ..Default::default()
        },
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert!(body.contains("LIMIT"), "body: {body}");
}

#[tokio::test]
async fn sparql_answers_a_result_within_the_row_cap() {
    let (status, body) = sparql_with_limits(
        "SELECT * WHERE { ?s ?p ?o } LIMIT 3",
        SparqlLimitsConfig {
            max_rows: 3,
            ..Default::default()
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
}
