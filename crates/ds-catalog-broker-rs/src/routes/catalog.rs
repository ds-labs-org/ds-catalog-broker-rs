//! `GET /catalog`.

use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
    response::IntoResponse,
};
use catalog_core::{Catalog, NodeId};
use rdf_store::{CatalogCache, CatalogQuery};
use serde::{Deserialize, Serialize};

use super::ErrorResponse;
use super::auth::check_oauth2_bearer;
use super::policy::{ServiceFiltering, filter_catalogs_by_policy};
use crate::AppState;

/// Optional filter for `GET /catalog`: `?node_id=...` narrows to the
/// catalog crawled from a single origin node.
#[derive(Debug, Deserialize)]
pub(super) struct CatalogParams {
    node_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct CatalogListResponse {
    pub(crate) catalogs: Vec<Catalog>,
}

pub(super) async fn get_catalog(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<CatalogParams>,
) -> impl IntoResponse {
    let claims = match check_oauth2_bearer(&state, &headers) {
        Ok(claims) => claims,
        Err(response) => return *response,
    };

    let query = match params.node_id {
        Some(node_id) => CatalogQuery::for_node(NodeId::new(node_id)),
        None => CatalogQuery::all(),
    };

    match state.cache.query(query).await {
        Ok(mut catalogs) => {
            filter_catalogs_by_policy(
                &mut catalogs,
                claims.as_ref(),
                &state,
                ServiceFiltering::HideGatedOnly,
            );
            Json(CatalogListResponse { catalogs }).into_response()
        }
        Err(err) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: err.to_string(),
            }),
        )
            .into_response(),
    }
}
