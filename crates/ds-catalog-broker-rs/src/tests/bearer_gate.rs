use super::*;

// --- OAuth2 Bearer gating (docs/oauth2-bearer-gating-2026-08-28.md) ---
//
// Router-level, through the real `build_router` + `oneshot` - not
// `OAuth2Verifier::verify` called directly (that's already covered,
// thoroughly, by `oauth2.rs`'s own unit tests). What these prove is
// the wiring: that `check_oauth2_bearer` actually gates these two
// routes and only these two, and that the mock JWKS server is reached
// over a real HTTP fetch (`OAuth2Verifier::fetch`), not a pre-parsed
// fixture - see `oauth2::test_support::spawn_jwks_server`.

pub(super) fn oauth2_config(jwks_uri: String) -> OAuth2Config {
    OAuth2Config {
        jwks_uri,
        issuer: None,
        audience: None,
        required_scope: None,
    }
}

/// `test_state()`, seeded the same way `catalog_endpoint_serves_seeded_sample_catalog`
/// is, with the OAuth2 gate wired up against a real mock JWKS server -
/// `configure` gets to adjust `issuer`/`audience`/`required_scope`
/// before the JWKS is fetched. Returns the state alongside the signing
/// key so each test can mint its own tokens.
pub(super) async fn oauth2_catalog_state(
    configure: impl FnOnce(&mut OAuth2Config),
) -> (AppState, oauth2::test_support::TestKey) {
    let key = generate_key("catalog-key");
    let jwks_uri = spawn_jwks_server(serde_json::json!({"keys": [ec_jwk(&key, None)]})).await;
    let mut config = oauth2_config(jwks_uri);
    configure(&mut config);
    let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), config)
        .await
        .expect("fetch mock JWKS");

    let state = test_state();
    seed_sample_catalog(&*state.cache).await.unwrap();
    let state = state.with_oauth2(Some(Arc::new(verifier)));
    (state, key)
}

/// Same idea as `oauth2_catalog_state`, but built on `test_state()`
/// (a real Oxigraph backend, one seeded participant) so `/sparql` has
/// something real to answer once a valid token clears the gate.
pub(super) async fn oauth2_sparql_state(
    configure: impl FnOnce(&mut OAuth2Config),
) -> (AppState, oauth2::test_support::TestKey) {
    let key = generate_key("sparql-key");
    let jwks_uri = spawn_jwks_server(serde_json::json!({"keys": [ec_jwk(&key, None)]})).await;
    let mut config = oauth2_config(jwks_uri);
    configure(&mut config);
    let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), config)
        .await
        .expect("fetch mock JWKS");

    let state = test_state();
    state
        .cache
        .upsert(participant_catalog("node-a", "cat-a", "DATASET-A"))
        .await
        .unwrap();
    let state = state.with_oauth2(Some(Arc::new(verifier)));
    (state, key)
}

pub(super) fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

#[tokio::test]
async fn catalog_route_401s_with_www_authenticate_when_no_token_is_given() {
    let (state, _key) = oauth2_catalog_state(|_| {}).await;
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
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(axum::http::header::WWW_AUTHENTICATE)
            .unwrap(),
        "Bearer"
    );
}

#[tokio::test]
async fn catalog_route_401s_on_a_garbage_bearer_token() {
    let (state, _key) = oauth2_catalog_state(|_| {}).await;
    let app = build_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/catalog?node_id=sample-participant")
                .header("Authorization", bearer("not-a-real-jwt"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn catalog_route_401s_for_a_token_with_the_wrong_audience_when_audience_is_configured() {
    let (state, key) =
        oauth2_catalog_state(|config| config.audience = Some("expected-audience".to_string()))
            .await;
    let app = build_router(state);

    let mut claims = base_claims();
    claims["aud"] = serde_json::json!("someone-else");
    let token = sign_es256(&key, claims);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/catalog?node_id=sample-participant")
                .header("Authorization", bearer(&token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn catalog_route_403s_when_required_scope_is_missing() {
    let (state, key) =
        oauth2_catalog_state(|config| config.required_scope = Some("catalog:read".to_string()))
            .await;
    let app = build_router(state);

    let mut claims = base_claims();
    claims["scope"] = serde_json::json!("sparql:read");
    let token = sign_es256(&key, claims);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/catalog?node_id=sample-participant")
                .header("Authorization", bearer(&token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn catalog_route_200s_with_the_real_body_for_a_fully_valid_token() {
    let (state, key) = oauth2_catalog_state(|_| {}).await;
    let app = build_router(state);
    let token = sign_es256(&key, base_claims());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/catalog?node_id=sample-participant")
                .header("Authorization", bearer(&token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: CatalogListResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed.catalogs.len(), 1);
    assert_eq!(parsed.catalogs[0].id, "sample-catalog");
}

#[tokio::test]
async fn health_route_stays_reachable_without_a_token_even_when_oauth2_is_configured() {
    let (state, _key) = oauth2_catalog_state(|_| {}).await;
    let app = build_router(state);
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
}

#[tokio::test]
async fn sparql_route_401s_with_www_authenticate_when_no_token_is_given() {
    let (state, _key) = oauth2_sparql_state(|_| {}).await;
    let app = build_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/sparql?query=ASK%20%7B%20%3Fs%20%3Fp%20%3Fo%20%7D")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(axum::http::header::WWW_AUTHENTICATE)
            .unwrap(),
        "Bearer"
    );
}

#[tokio::test]
async fn sparql_route_403s_when_required_scope_is_missing() {
    let (state, key) =
        oauth2_sparql_state(|config| config.required_scope = Some("sparql:read".to_string())).await;
    let app = build_router(state);

    let token = sign_es256(&key, base_claims());
    let query = "PREFIX dcat: <http://www.w3.org/ns/dcat#> ASK { ?d a dcat:Dataset }";
    let uri = format!("/sparql?query={}", urlencoding::encode(query));

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
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn sparql_get_route_200s_with_the_real_body_for_a_fully_valid_token() {
    let (state, key) = oauth2_sparql_state(|_| {}).await;
    let app = build_router(state);
    let token = sign_es256(&key, base_claims());

    let query = "PREFIX dcat: <http://www.w3.org/ns/dcat#> \
                 SELECT ?dataset WHERE { ?dataset a dcat:Dataset }";
    let uri = format!("/sparql?query={}", urlencoding::encode(query));
    let response = app
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("Authorization", bearer(&token))
                .header("Accept", "application/sparql-results+json")
                .body(Body::empty())
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

#[tokio::test]
async fn sparql_post_route_200s_with_the_real_body_for_a_fully_valid_token() {
    let (state, key) = oauth2_sparql_state(|_| {}).await;
    let app = build_router(state);
    let token = sign_es256(&key, base_claims());

    let query = "PREFIX dcat: <http://www.w3.org/ns/dcat#> \
                 SELECT ?dataset WHERE { ?dataset a dcat:Dataset }";
    let form_body = format!("query={}", urlencoding::encode(query));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/sparql")
                .header("Authorization", bearer(&token))
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
