use super::*;

// --- `POST /api/management/v4/catalogs/request` -----------------------
//
// Wire-compatibility with the real, already-published
// `edc-federated-catalog-client` 0.2.5 crate (a *dev*-dependency only -
// see this crate's own Cargo.toml) is the whole point of this route,
// so these tests deserialize its real response bodies with that
// crate's own `FederatedCatalogOffer` type rather than a local
// stand-in - a genuine round-trip proof, not just "200 and looks like
// JSON".

pub(super) fn catalog_request(body: Body) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/management/v4/catalogs/request")
        .header("Content-Type", "application/json")
        .body(body)
        .unwrap()
}

/// The strongest proof this route needs: a real `Vec<catalog_core::Catalog>`
/// fixture - including a real, non-trivial harvested `catalog_core::Policy`
/// (gap analysis §3.4) - seeded into a real cache, queried through the
/// real router via `oneshot` with the real client's own
/// `ListOfferBody::default()` as the request body, and the raw response
/// bytes literally deserialized with
/// `Vec<edc_federated_catalog_client::models::FederatedCatalogOffer>` -
/// asserting on the parsed Rust struct's fields, which only compiles
/// and passes if the wire format genuinely matches field for field.
/// The policy assertions below are the single most important ones in
/// this test: they prove a real, unmodified EDC Federated Catalog UI
/// component would actually understand the harvested policy content
/// this route serves, not just that an array happens to be non-empty.
#[tokio::test]
async fn catalog_request_route_response_deserializes_with_the_real_client_offer_type() {
    let state = test_state();
    let mut catalog = participant_catalog("node-a", "cat-a", "DATASET-A");
    catalog.datasets[0].policies.push(Policy {
        id: Some("policy-1".to_string()),
        kind: PolicyKind::Offer,
        assigner: Some("did:example:node-a".to_string()),
        assignee: None,
        permissions: vec![Rule {
            action: "odrl:use".to_string(),
            constraints: vec![Constraint::atomic(
                "odrl:dateTime",
                "odrl:lteq",
                "2027-01-01T00:00:00Z",
            )],
        }],
        prohibitions: vec![Rule {
            action: "odrl:distribute".to_string(),
            constraints: Vec::new(),
        }],
        obligations: Vec::new(),
    });
    state.cache.upsert(catalog).await.unwrap();

    let app = build_router(state);
    let request_body = serde_json::to_vec(&ListOfferBody::default()).unwrap();
    let response = app
        .oneshot(catalog_request(Body::from(request_body)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let offers: Vec<FederatedCatalogOffer> = serde_json::from_slice(&body).expect(
        "response body must deserialize with the real edc-federated-catalog-client crate's \
         own FederatedCatalogOffer type",
    );

    assert_eq!(offers.len(), 1);
    let offer = &offers[0];
    assert_eq!(offer.id, "cat-a");
    assert_eq!(offer.r#type, "Catalog");
    assert_eq!(offer.participant_id.id, "did:example:node-a");
    assert_eq!(offer.originator, "did:example:node-a");
    assert_eq!(offer.service.endpoint_url, "https://node-a.example.org/dsp");
    assert_eq!(
        offer.service.endpoint_description,
        "dataspace-protocol-http:1.0"
    );
    assert_eq!(offer.dataset.len(), 1);
    let dataset = &offer.dataset[0];
    assert_eq!(dataset.id, "DATASET-A");
    assert_eq!(dataset.r#type, "Dataset");
    assert_eq!(dataset.name, "DATASET-A");
    assert_eq!(dataset.content_type, "application/json");
    assert_eq!(dataset.title, None);
    assert_eq!(dataset.description, None);
    assert_eq!(dataset.version, None);
    assert_eq!(dataset.creator, None);
    assert_eq!(dataset.thumbnail, None);
    assert!(dataset.keywords.is_empty());

    // The real proof: the harvested policy round-tripped through this
    // route's hand-built JSON and came back out as a genuine
    // `edc_connector_client::types::policy::Policy`, with every field
    // this test seeded intact.
    assert_eq!(dataset.has_policy.len(), 1);
    let policy = &dataset.has_policy[0];
    assert_eq!(policy.id(), Some(&"policy-1".to_string()));
    assert_eq!(policy.kind(), &RealPolicyKind::Offer);
    assert_eq!(policy.assigner(), Some(&"did:example:node-a".to_string()));
    assert_eq!(policy.assignee(), None);

    assert_eq!(policy.permissions().len(), 1);
    let permission = &policy.permissions()[0];
    assert_eq!(permission.action().id(), "odrl:use");
    assert_eq!(permission.constraints().len(), 1);
    let RealConstraint::Atomic(atomic) = &permission.constraints()[0] else {
        panic!("expected an atomic constraint, got a logical-group constraint");
    };
    assert!(matches!(
        &atomic.left_operand,
        LeftOperand::Simple(value) if value == "odrl:dateTime"
    ));
    assert!(matches!(
        &atomic.operator,
        Operator::Simple(value) if value == "odrl:lteq"
    ));
    assert_eq!(
        atomic.right_operand,
        PropertyValue(serde_json::Value::String(
            "2027-01-01T00:00:00Z".to_string()
        ))
    );

    assert_eq!(policy.prohibitions().len(), 1);
    let prohibition = &policy.prohibitions()[0];
    assert_eq!(prohibition.action().id(), "odrl:distribute");
    assert!(prohibition.constraints().is_empty());

    assert!(policy.obligations().is_empty());
}

/// Regression coverage for the empty case: a harvested dataset with no
/// policies at all must still serve `hasPolicy` as an empty JSON array,
/// not `null` or an omitted key - the real
/// `edc_connector_client::types::policy::Policy`-backed field has no
/// `#[serde(default)]`, so it's required on the wire even when there is
/// nothing to put in it.
#[tokio::test]
async fn catalog_request_route_response_serves_has_policy_as_an_empty_array_when_dataset_has_no_policies()
 {
    let state = test_state();
    state
        .cache
        .upsert(participant_catalog("node-a", "cat-a", "DATASET-A"))
        .await
        .unwrap();

    let app = build_router(state);
    let request_body = serde_json::to_vec(&ListOfferBody::default()).unwrap();
    let response = app
        .oneshot(catalog_request(Body::from(request_body)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let raw: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let has_policy =
        &raw[0]["http://www.w3.org/ns/dcat#dataset"][0]["http://www.w3.org/ns/odrl/2/hasPolicy"];
    assert_eq!(
        has_policy,
        &serde_json::Value::Array(Vec::new()),
        "hasPolicy must be an explicit empty array, not omitted or null: {raw}"
    );

    // Also proves it round-trips through the real client type with a
    // genuinely empty policy list, not just that our own raw JSON looks
    // right.
    let offers: Vec<FederatedCatalogOffer> = serde_json::from_slice(&body).unwrap();
    assert!(offers[0].dataset[0].has_policy.is_empty());
}

/// The other half of the fixture above: every optional descriptive
/// `catalog_core::Dataset.properties` entry
/// (`title`/`description`/`version`/`creatorName`/`thumbnail`/
/// `keywords`) populated, proving the whole chain - properties bag ->
/// `dataset_to_offer` -> this route's JSON response -> the real
/// `edc-federated-catalog-client` crate's own deserialization - actually
/// carries them through, not just that it compiles.
#[tokio::test]
async fn catalog_request_route_response_carries_optional_dataset_descriptors_through_to_the_real_client_type()
 {
    let state = test_state();
    let mut catalog = participant_catalog("node-a", "cat-a", "DATASET-A");
    let dataset = &mut catalog.datasets[0];
    dataset
        .properties
        .insert("title".to_string(), "Soil Moisture Readings".to_string());
    dataset.properties.insert(
        "description".to_string(),
        "Hourly soil moisture readings from field sensors.".to_string(),
    );
    dataset
        .properties
        .insert("version".to_string(), "1.2.0".to_string());
    dataset
        .properties
        .insert("creatorName".to_string(), "Acme Sensors Inc.".to_string());
    dataset.properties.insert(
        "thumbnail".to_string(),
        "https://example.org/thumbnails/soil-moisture.png".to_string(),
    );
    dataset.properties.insert(
        "keywords".to_string(),
        "soil, moisture ,sensors".to_string(),
    );
    state.cache.upsert(catalog).await.unwrap();

    let app = build_router(state);
    let response = app.oneshot(catalog_request(Body::empty())).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let offers: Vec<FederatedCatalogOffer> = serde_json::from_slice(&body).expect(
        "response body must deserialize with the real edc-federated-catalog-client crate's \
         own FederatedCatalogOffer type",
    );
    assert_eq!(offers.len(), 1);
    let dataset = &offers[0].dataset[0];

    assert_eq!(dataset.title.as_deref(), Some("Soil Moisture Readings"));
    assert_eq!(
        dataset.description.as_deref(),
        Some("Hourly soil moisture readings from field sensors.")
    );
    assert_eq!(dataset.version.as_deref(), Some("1.2.0"));
    let creator = dataset
        .creator
        .as_ref()
        .expect("creator must be present when creatorName is set");
    assert_eq!(creator.name, "Acme Sensors Inc.");
    assert_eq!(
        creator.thumbnail.resource, "https://example.org/thumbnails/soil-moisture.png",
        "creator has no dedicated thumbnail property in the bag, so it reuses the \
         dataset's own thumbnail"
    );
    assert_eq!(
        dataset
            .thumbnail
            .as_ref()
            .expect("thumbnail must be present")
            .resource,
        "https://example.org/thumbnails/soil-moisture.png"
    );
    assert_eq!(
        dataset.keywords,
        vec![
            "soil".to_string(),
            "moisture".to_string(),
            "sensors".to_string()
        ],
        "keywords must be split on ',' and each entry trimmed"
    );
}

/// The whole chain the test above skips: the real crawler fetches a
/// DSP catalog carrying every optional descriptor from a mock
/// participant, upserts it into a real `OxigraphCatalogCache`, and the
/// management API reads it back out of that store into the real
/// client's `FederatedCatalogOffer`.
#[tokio::test]
async fn catalog_request_route_serves_crawled_dataset_descriptors_from_a_real_oxigraph_store() {
    let dsp_catalog = serde_json::json!({
        "@id": "cat-a",
        "participantId": "did:example:node-a",
        "dataset": [{
            "@id": "DATASET-A",
            "title": "Soil Moisture Readings",
            "description": "Hourly soil moisture readings from field sensors.",
            "version": "1.2.0",
            "creatorName": "Acme Sensors Inc.",
            "thumbnail": "https://example.org/thumbnails/soil-moisture.png",
            "keywords": "soil, moisture ,sensors",
            "distribution": [{"format": "application/json", "accessService": "svc-1"}]
        }],
        "service": [{"@id": "svc-1", "endpointURL": "https://node-a.example/dsp"}]
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let participant_app = Router::new().route(
        "/dsp/catalog/request",
        post(move || {
            let dsp_catalog = dsp_catalog.clone();
            async move { Json(dsp_catalog) }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, participant_app).await });

    let state = sparql_test_state();
    let participants = [crawler::ParticipantEntry {
        id: "node-a".to_string(),
        name: "Node A".to_string(),
        catalog_request_url: format!("http://{addr}/dsp/catalog/request"),
        credential_protocol: crawler::CredentialProtocol::None,
        provider_did: None,
        oid4vp_response_uri: None,
    }];
    let summary = crawler::crawl_once(
        &reqwest::Client::new(),
        &participants,
        None,
        &*state.cache,
        &crawler::CrawlLimits::default(),
    )
    .await;
    assert_eq!(
        summary.succeeded, 1,
        "crawl failures: {:?}",
        summary.failures
    );

    let app = build_router(state);
    let response = app.oneshot(catalog_request(Body::empty())).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let offers: Vec<FederatedCatalogOffer> = serde_json::from_slice(&body).unwrap();
    assert_eq!(offers.len(), 1);
    let dataset = &offers[0].dataset[0];

    assert_eq!(dataset.title.as_deref(), Some("Soil Moisture Readings"));
    assert_eq!(
        dataset.description.as_deref(),
        Some("Hourly soil moisture readings from field sensors.")
    );
    assert_eq!(dataset.version.as_deref(), Some("1.2.0"));
    let creator = dataset.creator.as_ref().expect("creator must be present");
    assert_eq!(creator.name, "Acme Sensors Inc.");
    assert_eq!(
        dataset
            .thumbnail
            .as_ref()
            .expect("thumbnail must be present")
            .resource,
        "https://example.org/thumbnails/soil-moisture.png"
    );
    assert_eq!(
        dataset.keywords,
        vec![
            "soil".to_string(),
            "moisture".to_string(),
            "sensors".to_string()
        ]
    );
}

/// The `datasets.id`/`=` `filterExpression` constraint - the exact
/// shape `FederatedCatalogClient::get_offer_by_dataset_id` sends
/// client-side - narrows the response down to only offers containing a
/// dataset with that id.
#[tokio::test]
async fn catalog_request_route_filters_by_the_datasets_id_constraint() {
    let state = test_state();
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
    let request_body = serde_json::json!({
        "@context": {"@vocab": "https://w3id.org/edc/v0.0.1/ns/"},
        "@type": "QuerySpec",
        "filterExpression": [
            {"operandLeft": "datasets.id", "operator": "=", "operandRight": "DATASET-B"}
        ],
    });
    let response = app
        .oneshot(catalog_request(Body::from(
            serde_json::to_vec(&request_body).unwrap(),
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let offers: Vec<FederatedCatalogOffer> = serde_json::from_slice(&body).unwrap();
    assert_eq!(offers.len(), 1);
    assert_eq!(offers[0].id, "cat-b");
    assert_eq!(offers[0].dataset[0].id, "DATASET-B");
}

/// An unrecognized/irrelevant constraint (anything other than
/// `datasets.id`/`=`) must not silently empty the result - the full,
/// unfiltered list comes back instead, per this route's documented
/// leniency.
#[tokio::test]
async fn catalog_request_route_ignores_an_unrecognized_constraint() {
    let state = test_state();
    state
        .cache
        .upsert(participant_catalog("node-a", "cat-a", "DATASET-A"))
        .await
        .unwrap();

    let app = build_router(state);
    let request_body = serde_json::json!({
        "@type": "QuerySpec",
        "filterExpression": [
            {"operandLeft": "originator", "operator": "=", "operandRight": "someone-else"}
        ],
    });
    let response = app
        .oneshot(catalog_request(Body::from(
            serde_json::to_vec(&request_body).unwrap(),
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let offers: Vec<FederatedCatalogOffer> = serde_json::from_slice(&body).unwrap();
    assert_eq!(offers.len(), 1);
    assert_eq!(offers[0].id, "cat-a");
}

/// A missing/malformed body must not 400 - "be lenient rather than
/// fragile" (this route's own doc comment) - a real client always
/// sends *some* `QuerySpec` body, but this proves an empty or garbage
/// one still gets the full, unfiltered offer list back rather than an
/// error.
#[tokio::test]
async fn catalog_request_route_treats_a_missing_or_malformed_body_as_no_filter() {
    let state = test_state();
    state
        .cache
        .upsert(participant_catalog("node-a", "cat-a", "DATASET-A"))
        .await
        .unwrap();

    for body in [Body::empty(), Body::from("not json at all")] {
        let app = build_router(state.clone());
        let response = app.oneshot(catalog_request(body)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response_body = response.into_body().collect().await.unwrap().to_bytes();
        let offers: Vec<FederatedCatalogOffer> = serde_json::from_slice(&response_body).unwrap();
        assert_eq!(offers.len(), 1);
        assert_eq!(offers[0].id, "cat-a");
    }
}

/// A catalog with zero data services cannot produce a valid offer (a
/// `FederatedCatalogOffer`'s `service` field is a single required
/// `Service`, not `Option`/`Vec`) - it must be skipped, not fabricated
/// or errored on, and it must not affect offers for catalogs that do
/// have a data service.
#[tokio::test]
async fn catalog_request_route_skips_a_catalog_with_no_data_services() {
    let state = test_state();
    let mut no_service_catalog = Catalog::new("cat-no-service", NodeId::new("node-c"));
    no_service_catalog.datasets.push(Dataset {
        id: "DATASET-C".to_string(),
        properties: Default::default(),
        distributions: vec![],
        policies: Vec::new(),
    });
    state.cache.upsert(no_service_catalog).await.unwrap();
    state
        .cache
        .upsert(participant_catalog("node-a", "cat-a", "DATASET-A"))
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
        "the no-data-service catalog must be skipped, not turned into a broken offer"
    );
    assert_eq!(offers[0].id, "cat-a");
}

/// Same OAuth2 Bearer gate as `GET /catalog` and `GET`/`POST /sparql`
/// (`check_oauth2_bearer`) - no token, gating configured: `401` with
/// `WWW-Authenticate: Bearer`, same as those two routes.
#[tokio::test]
async fn catalog_request_route_401s_with_www_authenticate_when_no_token_is_given() {
    let (state, _key) = oauth2_catalog_state(|_| {}).await;
    let app = build_router(state);
    let response = app.oneshot(catalog_request(Body::empty())).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(axum::http::header::WWW_AUTHENTICATE)
            .unwrap(),
        "Bearer"
    );
}

/// A fully valid token clears the gate and the real body comes back,
/// still wire-compatible with the real client's `FederatedCatalogOffer`.
#[tokio::test]
async fn catalog_request_route_200s_with_the_real_body_for_a_fully_valid_token() {
    let (state, key) = oauth2_catalog_state(|_| {}).await;
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
    assert_eq!(offers[0].id, "sample-catalog");
}
