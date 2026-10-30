use super::*;

// --- ODRL policy-based dataset visibility filtering (gap analysis
// §3.4) ----------------------------------------------------------------
//
// `odrl_filter::dataset_is_visible` (and the rest of that module)
// already worked end to end before this section - see
// `crates/ds-catalog-broker-rs/src/odrl_filter.rs`'s own module doc and
// test suite. This section proves the remaining wiring of that
// decision into `GET /catalog` and
// `POST /api/management/v4/catalogs/request`
// (`filter_catalogs_by_policy`, called from both routes): every
// harvested dataset used to be listed to every caller regardless of
// its policy content - exactly the "nothing filters on policy content
// today" gap the gap analysis names - and these tests are the proof
// that gap is now closed on these two surfaces.
//
// Per this session's own prior-art lesson
// (`docs/spikes/2026-08-27-edc-catalog-metadata-exposure-policy.md`'s
// central finding: the real failure mode is *silent over-permission*,
// not a loud error), every "hidden" assertion below checks for the
// gated dataset's actual *absence* from the parsed response body, not
// merely that the response still deserializes/round-trips - this
// repo's existing tests, before this section, only ever assert that.
//
// Two design decisions this section pins down (both left open by the
// gap analysis itself), in addition to `odrl_filter::PolicyFilterConfig`'s
// own three:
//
// 1. **Which ODRL action these two catalog-*listing* surfaces check.**
//    Fixed to `odrl:use` (`CATALOG_VISIBILITY_ACTION`, defined in
//    `routes::policy` and reused here as `TEST_CATALOG_VISIBILITY_ACTION`
//    below) - ODRL's own general-purpose "make use of this asset"
//    action, not a bespoke broker-specific action string no real
//    crawled policy would ever grant/deny. Listing/browsing a dataset
//    in this broker's own re-served catalog is the closest fit to
//    that action; actually transferring the underlying data stays
//    entirely the connector's own, separate DSP contract-negotiation
//    concern this broker never participates in.
// 2. **A `Catalog`/offer left with zero visible datasets after
//    filtering is kept, not omitted** - with an empty `datasets`/
//    `dataset` list, not dropped from the response entirely. Chosen
//    for consistency with how `CatalogRequestDataset`'s own
//    `#[serde(skip_serializing_if = "Vec::is_empty")]` already treats
//    "no datasets" as an ordinary, representable state (see
//    `catalog_request_route_response_serves_has_policy_as_an_empty_array_when_dataset_has_no_policies`
//    in `management.rs` for the same "empty, not omitted" convention already used
//    elsewhere in these tests) - a participant a caller has zero
//    entitlement into still gets to be *known about*, just with
//    nothing they may see inside it.

/// The ODRL action `GET /catalog` and the management API check when
/// deciding whether a caller may see a harvested dataset at all - see
/// this section's own doc comment, decision 1. A local alias for
/// `super::CATALOG_VISIBILITY_ACTION` (the same constant
/// `filter_catalogs_by_policy` actually uses) so these tests assert
/// against the real production value by name, not a copy that could
/// silently drift from it.
const TEST_CATALOG_VISIBILITY_ACTION: &str = CATALOG_VISIBILITY_ACTION;

/// One `catalog_core::Policy` granting `TEST_CATALOG_VISIBILITY_ACTION`
/// only to a caller whose claims carry `role = "eu-resident"` - an
/// ordinary, mappable atomic constraint (no unmappable-operator edge
/// case involved; that's `odrl_filter.rs`'s own test suite's job, not
/// this one's).
fn eu_resident_only_policy() -> Policy {
    Policy {
        id: Some("eu-resident-only-offer".to_string()),
        kind: PolicyKind::Offer,
        assigner: None,
        assignee: None,
        permissions: vec![Rule {
            action: TEST_CATALOG_VISIBILITY_ACTION.to_string(),
            constraints: vec![Constraint::atomic("role", "eq", "eu-resident")],
        }],
        prohibitions: Vec::new(),
        obligations: Vec::new(),
    }
}

/// A JWT claims object satisfying [`eu_resident_only_policy`] - `base_claims()`
/// plus `role = "eu-resident"`.
pub(super) fn eu_resident_claims() -> serde_json::Value {
    let mut claims = base_claims();
    claims["role"] = serde_json::json!("eu-resident");
    claims
}

/// One catalog with two datasets: `OPEN-DATASET` (no policies at all,
/// visible under `NoPolicyVisibility`'s default `Open` regardless of
/// caller) and `GATED-DATASET` (one policy, [`eu_resident_only_policy`],
/// visible only to a caller whose claims satisfy it).
pub(super) fn catalog_with_open_and_gated_datasets(node_id: &str, catalog_id: &str) -> Catalog {
    let mut catalog = participant_catalog(node_id, catalog_id, "OPEN-DATASET");
    let service_id = catalog.data_services[0].id.clone();
    catalog.datasets.push(Dataset {
        id: "GATED-DATASET".to_string(),
        properties: Default::default(),
        distributions: vec![Distribution {
            format: "application/json".to_string(),
            access_service: service_id,
        }],
        policies: vec![eu_resident_only_policy()],
    });
    catalog
}

/// A catalog whose *only* dataset is gated - for the "zero visible
/// datasets left" decision tests (this section's own doc comment,
/// decision 2).
fn catalog_with_only_a_gated_dataset(node_id: &str, catalog_id: &str) -> Catalog {
    let mut catalog = participant_catalog(node_id, catalog_id, "GATED-ONLY-DATASET");
    catalog.datasets[0].policies.push(eu_resident_only_policy());
    catalog
}

/// Same idea as `oauth2_catalog_state`, but seeded with a caller-
/// supplied catalog rather than always `seed_sample_catalog`'s fixed
/// one, so these tests can exercise the OAuth2 + policy-filtering
/// interaction against a catalog shaped for that purpose.
pub(super) async fn oauth2_state_with_catalog(
    catalog: Catalog,
    configure: impl FnOnce(&mut OAuth2Config),
) -> (AppState, oauth2::test_support::TestKey) {
    let key = generate_key("policy-filter-key");
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

fn dataset_ids_of(catalog: &Catalog) -> Vec<&str> {
    catalog.datasets.iter().map(|d| d.id.as_str()).collect()
}

// --- `GET /catalog` ---------------------------------------------------

#[tokio::test]
async fn get_catalog_hides_a_policy_gated_dataset_from_a_caller_without_the_required_claim() {
    let (state, key) = oauth2_state_with_catalog(
        catalog_with_open_and_gated_datasets("node-a", "cat-a"),
        |_| {},
    )
    .await;
    let app = build_router(state);
    let token = sign_es256(&key, base_claims());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/catalog?node_id=node-a")
                .header("Authorization", bearer(&token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: CatalogListResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        parsed.catalogs.len(),
        1,
        "the catalog itself must still be listed even though one of its datasets ends up \
         hidden"
    );
    let dataset_ids = dataset_ids_of(&parsed.catalogs[0]);
    assert!(
        !dataset_ids.contains(&"GATED-DATASET"),
        "a dataset whose only policy requires a 'role=eu-resident' claim the caller's token \
         doesn't carry must be entirely absent from the response, not merely present-but-\
         unusable - silent over-permission is the failure mode that matters here. Got \
         dataset ids: {dataset_ids:?}"
    );
    assert!(
        dataset_ids.contains(&"OPEN-DATASET"),
        "an unrelated, policy-free dataset in the same catalog must remain visible. Got \
         dataset ids: {dataset_ids:?}"
    );
}

#[tokio::test]
async fn get_catalog_shows_a_policy_gated_dataset_to_a_caller_with_the_required_claim() {
    let (state, key) = oauth2_state_with_catalog(
        catalog_with_open_and_gated_datasets("node-a", "cat-a"),
        |_| {},
    )
    .await;
    let app = build_router(state);
    let token = sign_es256(&key, eu_resident_claims());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/catalog?node_id=node-a")
                .header("Authorization", bearer(&token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: CatalogListResponse = serde_json::from_slice(&body).unwrap();
    let dataset_ids = dataset_ids_of(&parsed.catalogs[0]);
    assert!(
        dataset_ids.contains(&"GATED-DATASET"),
        "a caller whose claims satisfy the dataset's policy must still see it. Got dataset \
         ids: {dataset_ids:?}"
    );
    assert!(dataset_ids.contains(&"OPEN-DATASET"));
}

#[tokio::test]
async fn get_catalog_filters_by_policy_even_when_oauth2_is_disabled_matching_the_default_config() {
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
    let dataset_ids = dataset_ids_of(&parsed.catalogs[0]);
    assert!(
        !dataset_ids.contains(&"GATED-DATASET"),
        "with no OAuth2 verifier configured at all, filtering must still run against an \
         empty claims map, per PolicyFilterConfig::filter_when_oauth2_disabled's default \
         (true) - an unauthenticated caller must not see a dataset whose policy requires a \
         claim they cannot possibly present. Got dataset ids: {dataset_ids:?}"
    );
    assert!(dataset_ids.contains(&"OPEN-DATASET"));
}

#[tokio::test]
async fn get_catalog_keeps_a_catalog_with_an_empty_datasets_list_when_every_dataset_is_hidden() {
    let state = test_state();
    state
        .cache
        .upsert(catalog_with_only_a_gated_dataset("node-b", "cat-b"))
        .await
        .unwrap();
    let app = build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/catalog?node_id=node-b")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: CatalogListResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        parsed.catalogs.len(),
        1,
        "a catalog left with zero visible datasets must still be listed, with an empty \
         datasets array - not omitted entirely (this file's own documented answer to gap \
         analysis §3.4's open question)"
    );
    assert!(
        parsed.catalogs[0].datasets.is_empty(),
        "every dataset in this catalog is policy-gated against an unauthenticated caller, \
         so none should remain. Got: {:?}",
        dataset_ids_of(&parsed.catalogs[0])
    );
}

// --- `POST /api/management/v4/catalogs/request` -----------------------

#[tokio::test]
async fn catalog_request_route_hides_a_policy_gated_dataset_from_a_caller_without_the_required_claim()
 {
    let (state, key) = oauth2_state_with_catalog(
        catalog_with_open_and_gated_datasets("node-a", "cat-a"),
        |_| {},
    )
    .await;
    let app = build_router(state);
    let token = sign_es256(&key, base_claims());

    let request = Request::builder()
        .method("POST")
        .uri("/api/management/v4/catalogs/request")
        .header("Authorization", bearer(&token))
        .header("Content-Type", "application/json")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let offers: Vec<FederatedCatalogOffer> = serde_json::from_slice(&body).unwrap();
    assert_eq!(offers.len(), 1);
    let dataset_ids: Vec<&str> = offers[0].dataset.iter().map(|d| d.id.as_str()).collect();
    assert!(
        !dataset_ids.contains(&"GATED-DATASET"),
        "same entitlement gap as GET /catalog, on the management API surface - the gated \
         dataset must be entirely absent. Got dataset ids: {dataset_ids:?}"
    );
    assert!(dataset_ids.contains(&"OPEN-DATASET"));
}

#[tokio::test]
async fn catalog_request_route_shows_a_policy_gated_dataset_to_a_caller_with_the_required_claim() {
    let (state, key) = oauth2_state_with_catalog(
        catalog_with_open_and_gated_datasets("node-a", "cat-a"),
        |_| {},
    )
    .await;
    let app = build_router(state);
    let token = sign_es256(&key, eu_resident_claims());

    let request = Request::builder()
        .method("POST")
        .uri("/api/management/v4/catalogs/request")
        .header("Authorization", bearer(&token))
        .header("Content-Type", "application/json")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let offers: Vec<FederatedCatalogOffer> = serde_json::from_slice(&body).unwrap();
    let dataset_ids: Vec<&str> = offers[0].dataset.iter().map(|d| d.id.as_str()).collect();
    assert!(
        dataset_ids.contains(&"GATED-DATASET"),
        "a caller whose claims satisfy the dataset's policy must still see it here too. Got \
         dataset ids: {dataset_ids:?}"
    );
}

#[tokio::test]
async fn catalog_request_route_filters_by_policy_even_when_oauth2_is_disabled_matching_the_default_config()
 {
    let state = test_state();
    state
        .cache
        .upsert(catalog_with_open_and_gated_datasets("node-a", "cat-a"))
        .await
        .unwrap();
    assert!(state.policy_filter.filter_when_oauth2_disabled);
    let app = build_router(state);

    let response = app.oneshot(catalog_request(Body::empty())).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let offers: Vec<FederatedCatalogOffer> = serde_json::from_slice(&body).unwrap();
    let dataset_ids: Vec<&str> = offers[0].dataset.iter().map(|d| d.id.as_str()).collect();
    assert!(
        !dataset_ids.contains(&"GATED-DATASET"),
        "no OAuth2 verifier configured at all must still filter against an empty claims \
         map, per the default PolicyFilterConfig::filter_when_oauth2_disabled=true. Got \
         dataset ids: {dataset_ids:?}"
    );
    assert!(dataset_ids.contains(&"OPEN-DATASET"));
}

#[tokio::test]
async fn catalog_request_route_keeps_an_offer_with_an_empty_dataset_array_when_every_dataset_is_hidden()
 {
    let state = test_state();
    state
        .cache
        .upsert(catalog_with_only_a_gated_dataset("node-b", "cat-b"))
        .await
        .unwrap();
    let app = build_router(state);

    let response = app.oneshot(catalog_request(Body::empty())).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let offers: Vec<FederatedCatalogOffer> = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        offers.len(),
        1,
        "an offer for a catalog left with zero visible datasets must still be listed, with \
         an empty dataset array - not omitted entirely, matching GET /catalog's own answer \
         to the same design question"
    );
    assert!(
        offers[0].dataset.is_empty(),
        "every dataset in this catalog is policy-gated against an unauthenticated caller. \
         Got: {:?}",
        offers[0].dataset.iter().map(|d| &d.id).collect::<Vec<_>>()
    );
}

/// The ODRL policy filter must run *before* the `datasets.id`
/// `filterExpression` post-filter (see `catalog_request_route`'s doc
/// comment) - a caller not entitled to `GATED-DATASET` must not be
/// able to retrieve it merely by asking for it by id.
#[tokio::test]
async fn catalog_request_route_dataset_id_filter_does_not_resurrect_a_policy_hidden_dataset() {
    let (state, key) = oauth2_state_with_catalog(
        catalog_with_open_and_gated_datasets("node-a", "cat-a"),
        |_| {},
    )
    .await;
    let app = build_router(state);
    let token = sign_es256(&key, base_claims());

    let request_body = serde_json::json!({
        "@type": "QuerySpec",
        "filterExpression": [
            {"operandLeft": "datasets.id", "operator": "=", "operandRight": "GATED-DATASET"}
        ],
    });
    let request = Request::builder()
        .method("POST")
        .uri("/api/management/v4/catalogs/request")
        .header("Authorization", bearer(&token))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let offers: Vec<FederatedCatalogOffer> = serde_json::from_slice(&body).unwrap();
    assert!(
        offers.is_empty(),
        "asking for GATED-DATASET by id via filterExpression must not resurrect it for a \
         caller the ODRL policy filter would otherwise hide it from - the policy filter must \
         run first, so no offer contains it and the id filter then drops the offer entirely. \
         Got offers: {offers:?}"
    );
}
