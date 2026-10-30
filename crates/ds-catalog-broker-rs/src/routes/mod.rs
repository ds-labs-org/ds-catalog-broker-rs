//! The HTTP router and its route handlers, one module per API surface.

use axum::{
    Json, Router,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};

use crate::AppState;

mod auth;
pub(crate) mod catalog;
mod holder;
mod management;
pub(crate) mod policy;
mod sparql;

use catalog::get_catalog;
use holder::{holder_did_document_route, holder_presentation_query_route};
use management::catalog_request_route;
use sparql::{sparql_route_get, sparql_route_post};

/// Build the router. Kept separate from `main` so tests (and, later,
/// alternative binaries) can exercise it without binding a real socket.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/catalog", get(get_catalog))
        // The SPARQL 1.1 Protocol query surface (gap analysis §3.3) - see
        // `sparql_route`'s own doc comment for the exact request/response
        // shape supported.
        .route("/sparql", get(sparql_route_get).post(sparql_route_post))
        // This product's own federated catalog Management API surface,
        // wire-compatible with the real, already-published
        // `edc-federated-catalog-client` crate - see
        // `catalog_request_route`'s doc comment for the exact request/
        // response shape.
        .route(
            "/api/management/v4/catalogs/request",
            post(catalog_request_route),
        )
        // This connector's own DCP *holder* identity (see `AppState::holder`'s
        // doc comment) - this participant's own credential-presentation
        // capability for crawling a DCP-gated remote participant. Both
        // routes 404 when no holder is configured.
        .route("/dsp/holder/did.json", get(holder_did_document_route))
        .route(
            "/dsp/holder/presentations/query",
            post(holder_presentation_query_route),
        )
        .with_state(state)
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct HealthResponse {
    pub(crate) status: String,
}

pub(crate) async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}

#[derive(Debug, Serialize)]
pub(crate) struct ErrorResponse {
    error: String,
}
