//! `GET`/`POST /sparql`: the SPARQL 1.1 Protocol query surface (gap
//! analysis §3.3).

use std::sync::Arc;

use axum::{
    Form, Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use rdf_store::CatalogQuery;
use rdf_store::oxigraph_backend::{CancellationToken, SparqlError, SparqlLimits};
use serde::Deserialize;

use super::ErrorResponse;
use super::auth::check_oauth2_bearer;
use super::policy::{engine_claims_from_bearer, should_filter_by_policy, visible_resource_iris};
use crate::AppState;

/// `application/sparql-results+json`, the one result media type this
/// endpoint produces (gap analysis §3.3's stated minimum).
pub(super) const SPARQL_RESULTS_JSON: &str = "application/sparql-results+json";

/// `GET /sparql?query=...` - the SPARQL 1.1 Protocol's URL-encoded GET
/// form. See [`sparql_route`] for the shared handling.
#[derive(Debug, Deserialize)]
pub(super) struct SparqlGetParams {
    query: Option<String>,
}

pub(super) async fn sparql_route_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<SparqlGetParams>,
) -> impl IntoResponse {
    sparql_route(state, headers, params.query).await
}

/// `POST /sparql` with `Content-Type: application/x-www-form-urlencoded`
/// and a `query` form field - the SPARQL 1.1 Protocol's other mandated
/// way to submit a query.
///
/// The protocol also allows a second POST style - a raw SPARQL string as
/// the body with `Content-Type: application/sparql-query` - but requires
/// only "at least one" query mechanism beyond plain GET, per the gap
/// analysis's own framing of the spec ("query" parameter over GET/POST).
/// Form-encoded POST is implemented here (this is that "at least one");
/// direct `application/sparql-query` bodies are not. Chosen over the raw
/// form because it composes with a plain HTML `<form>` and with the
/// default POST mode of common SPARQL client libraries (e.g. Python's
/// `SPARQLWrapper`), needing no bespoke `Content-Type` handling in this
/// router beyond the URL-encoded body Axum's own `Form` extractor already
/// parses.
#[derive(Debug, Deserialize)]
pub(super) struct SparqlPostForm {
    query: Option<String>,
}

pub(super) async fn sparql_route_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SparqlPostForm>,
) -> impl IntoResponse {
    sparql_route(state, headers, form.query).await
}

/// Whether `headers`' `Accept` value (if any) allows an
/// `application/sparql-results+json` response.
///
/// A missing `Accept` header allows it (HTTP's own "no preference"
/// default). Otherwise, at least one comma-separated media range must be
/// `application/sparql-results+json`, the bare `application/json` (a
/// reasonable specific-enough match for a JSON-speaking client that
/// doesn't know the SPARQL-specific type), or a wildcard (`*/*`,
/// `application/*`) - any `;q=...` parameter is ignored, since there is
/// only one representation on offer here to weight against.
pub(super) fn accepts_sparql_results_json(headers: &HeaderMap) -> bool {
    let Some(accept) = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
    else {
        return true;
    };
    accept.split(',').any(|range| {
        matches!(
            range.split(';').next().unwrap_or("").trim(),
            SPARQL_RESULTS_JSON | "application/json" | "*/*" | "application/*"
        )
    })
}

/// Shared `GET`/`POST /sparql` handling - see `build_router`'s doc
/// comment for why both exist, and `rdf_store::oxigraph_backend`'s
/// `sparql_query_json` for the actual evaluation this delegates to
/// (read-only by construction, whole-store-by-default, real
/// `application/sparql-results+json` output).
///
/// - No `sparql` backend configured (`AppState::sparql` is `None`, i.e.
///   the in-memory cache is running - see that field's doc comment): 501
///   Not Implemented. This is a genuine backend limitation, not a
///   not-yet-built route, hence 501 rather than 404.
/// - `Accept` header present and none of its media ranges match
///   `application/sparql-results+json` (see `accepts_sparql_results_json`):
///   406 Not Acceptable.
/// - Missing/empty `query`: 400 Bad Request.
/// - ODRL policy-based filtering (gap analysis §3.4) runs next, whenever
///   [`should_filter_by_policy`] says it should: the query is evaluated
///   over only the datasets and data services the caller may see
///   (`OxigraphCatalogCache::sparql_query_json_restricted`, allow-list
///   from [`visible_resource_iris`], the same per-dataset decision
///   `filter_catalogs_by_policy` makes for `GET /catalog`/the management
///   API). Hidden data is absent from what the query reads, so every
///   query shape is answered and none can reach it. When filtering is
///   off entirely (OAuth2 disabled and
///   `PolicyFilterConfig::filter_when_oauth2_disabled` set to `false`),
///   the query runs over the whole store.
/// - Query fails to parse, fails to evaluate, or is a `CONSTRUCT`/
///   `DESCRIBE` (unsupported result shape - see `SparqlError`'s own doc
///   comments): 400 Bad Request with a plain-text explanation - these are
///   all the caller's own query's fault.
/// - Evaluation runs on the blocking pool under [`SparqlLimitsConfig`](crate::SparqlLimitsConfig):
///   past `timeout` it is cancelled and the caller gets 503 Service
///   Unavailable; a result over `max_rows` rows is 400 Bad Request.
/// - Otherwise: 200 with an `application/sparql-results+json` body.
///
/// Checked first, ahead of all of the above: the OAuth2 Bearer gate (see
/// `check_oauth2_bearer`'s doc comment) - `401`/`403` when
/// `AppState::oauth2` is configured and the caller's token doesn't clear
/// it; unchanged behavior (falls straight through to the checks above)
/// when it isn't configured at all.
pub(super) async fn sparql_route(
    state: AppState,
    headers: HeaderMap,
    query: Option<String>,
) -> axum::response::Response {
    let claims = match check_oauth2_bearer(&state, &headers) {
        Ok(claims) => claims,
        Err(response) => return *response,
    };

    let Some(sparql) = &state.sparql else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "this instance is running the in-memory catalog cache, which has no SPARQL \
             (Oxigraph) backend - configure a broker:participant to enable the SPARQL endpoint"
                .to_string(),
        )
            .into_response();
    };

    if !accepts_sparql_results_json(&headers) {
        return (
            StatusCode::NOT_ACCEPTABLE,
            format!("this endpoint only produces {SPARQL_RESULTS_JSON}"),
        )
            .into_response();
    }

    let query = match query.filter(|q| !q.trim().is_empty()) {
        Some(query) => query,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "missing required 'query' parameter".to_string(),
            )
                .into_response();
        }
    };

    let visible_resources = if should_filter_by_policy(&state) {
        let engine_claims = engine_claims_from_bearer(claims.as_ref());
        let catalogs = match state.cache.query(CatalogQuery::all()).await {
            Ok(catalogs) => catalogs,
            Err(err) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: err.to_string(),
                    }),
                )
                    .into_response();
            }
        };
        Some(visible_resource_iris(&catalogs, &engine_claims, &state))
    } else {
        None
    };

    // Evaluation is synchronous and can be slow, so it runs on the
    // blocking pool, never on an async worker. On timeout the token makes
    // oxigraph stop at its next lookup or row instead of running on.
    let cancellation = CancellationToken::new();
    let limits = SparqlLimits {
        cancellation: Some(cancellation.clone()),
        max_rows: Some(state.sparql_limits.max_rows),
    };
    let sparql = Arc::clone(sparql);
    let evaluation = tokio::task::spawn_blocking(move || {
        sparql.sparql_query_json_limited(&query, visible_resources.as_ref(), &limits)
    });
    let result = match tokio::time::timeout(state.sparql_limits.timeout, evaluation).await {
        Ok(Ok(result)) => result,
        Ok(Err(join_error)) => {
            tracing::error!(error = %join_error, "SPARQL evaluation task failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "SPARQL evaluation failed".to_string(),
            )
                .into_response();
        }
        Err(_elapsed) => {
            cancellation.cancel();
            Err(SparqlError::Cancelled)
        }
    };
    match result {
        Ok(body) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, SPARQL_RESULTS_JSON)],
            body,
        )
            .into_response(),
        Err(
            err @ (SparqlError::Parse(_)
            | SparqlError::Evaluation(_)
            | SparqlError::UnsupportedGraphResult),
        ) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
        Err(SparqlError::Cancelled) => (
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "SPARQL query ran past the {} ms time limit and was stopped - add a LIMIT or \
                 narrow the query",
                state.sparql_limits.timeout.as_millis()
            ),
        )
            .into_response(),
        Err(err @ SparqlError::TooManyRows(_)) => {
            (StatusCode::BAD_REQUEST, err.to_string()).into_response()
        }
        Err(err @ SparqlError::Serialize(_)) => {
            tracing::error!(error = %err, "failed to serialize SPARQL results");
            (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
        }
    }
}
