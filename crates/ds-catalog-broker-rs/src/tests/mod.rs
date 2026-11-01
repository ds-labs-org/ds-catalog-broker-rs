//! Router-level tests, through the real `build_router` and `oneshot`, one
//! module per API surface.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::Request;
use axum::{Json, Router, http::StatusCode, routing::post};
use catalog_core::Constraint;
use catalog_core::{Catalog, DataService, Dataset, Distribution, NodeId, Policy, PolicyKind, Rule};
use edc_connector_client::types::policy::{
    Constraint as RealConstraint, LeftOperand, Operator, PolicyKind as RealPolicyKind,
};
use edc_connector_client::types::properties::PropertyValue;
use edc_federated_catalog_client::ListOfferBody;
use edc_federated_catalog_client::models::FederatedCatalogOffer;
use http_body_util::BodyExt;
use rdf_store::oxigraph_backend::OxigraphCatalogCache;
use rdf_store::{CatalogCache, CatalogQuery};
use tower::ServiceExt;

use crate::oauth2::test_support::{
    base_claims, ec_jwk, generate_key, sign_es256, spawn_jwks_server,
};
use crate::oauth2::{self, OAuth2Config, OAuth2Verifier};
use crate::routes::{
    HealthResponse, catalog::CatalogListResponse, policy::CATALOG_VISIBILITY_ACTION,
};
use crate::{AppState, SparqlLimitsConfig, config, odrl_filter};
use crate::{build_router, crawl_limits_from_settings};
use sample::seed_sample_catalog;

mod bearer_gate;
mod blocking;
mod catalog;
mod management;
mod policy;
mod ready;
mod sample;
mod serving;
mod sparql;
mod sparql_policy;

// Fixtures more than one surface's tests use.
use bearer_gate::{bearer, oauth2_catalog_state, oauth2_config};
use management::catalog_request;
use policy::{catalog_with_open_and_gated_datasets, eu_resident_claims};
use sparql::participant_catalog;

fn test_state() -> AppState {
    AppState::new(Arc::new(OxigraphCatalogCache::in_memory().unwrap()))
}

#[test]
fn sparql_limits_come_from_the_broker_config() {
    let settings =
        config::BrokerSettings::from_values([("sparqlMaxConcurrent".to_string(), "2".to_string())])
            .unwrap();
    let limits = SparqlLimitsConfig::from_settings(&settings);
    assert_eq!(limits.max_concurrent, 2);
    assert_eq!(
        limits.timeout,
        SparqlLimitsConfig::default().timeout,
        "an unset value is the default"
    );
}

#[test]
fn crawl_limits_come_from_the_broker_config() {
    let settings = config::BrokerSettings::from_values([
        ("crawlTimeoutMs".to_string(), "1500".to_string()),
        ("crawlConcurrency".to_string(), "2".to_string()),
    ])
    .unwrap();
    let limits = crawl_limits_from_settings(&settings);
    assert_eq!(limits.participant_timeout, Duration::from_millis(1500));
    assert_eq!(limits.concurrency, 2);
    assert_eq!(
        limits.max_catalog_age,
        crawler::CrawlLimits::default().max_catalog_age,
        "an unset value is the default"
    );
}
