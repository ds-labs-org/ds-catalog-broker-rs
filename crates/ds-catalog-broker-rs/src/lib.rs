//! Axum HTTP server skeleton for the federated catalog rewrite.
//!
//! Exposes a health check and a `GET /catalog` endpoint backed by
//! `rdf-store`'s `CatalogCache` trait. The catalog endpoint is
//! intentionally thin - it exists to prove the wiring between
//! `ds-catalog-broker-rs`, `catalog-core` types, and the `rdf-store` cache trait works
//! end to end, not to be a finished Management API. Query parameters,
//! pagination shape, and response JSON-LD framing (EDC's Management API
//! returns `dspace:`/`edc:` JSON-LD) are all deferred to a later
//! iteration.

use std::collections::BTreeSet;
use std::sync::Arc;

pub mod oauth2;
pub mod odrl_filter;
pub mod sparql_rewrite;

use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::{
        HeaderMap, StatusCode,
        header::{AUTHORIZATION, WWW_AUTHENTICATE},
    },
    response::IntoResponse,
    routing::{get, post},
};
use catalog_core::{Catalog, DataService, Dataset, Distribution, NodeId, Policy, PolicyKind, Rule};
pub use dcp_core::HolderIdentity;
pub use oauth2::{OAuth2Config, OAuth2Verifier, VerifyError};
use rdf_store::oxigraph_backend::{OxigraphCatalogCache, SparqlError};
use rdf_store::{CatalogCache, CatalogQuery, StoreResult};
use serde::{Deserialize, Serialize};

/// Shared application state: the cache, behind a trait object so the
/// concrete backend (in-memory today, RDF-backed later) is an
/// implementation detail of `main`, not of the router.
#[derive(Clone)]
pub struct AppState {
    pub cache: Arc<dyn CatalogCache>,
    /// Shared HTTP client for this connector's own DCP *holder* role's
    /// outbound calls - `reqwest::Client` is cheap to clone (internally
    /// `Arc`-backed) and reuses connection pooling, so one instance lives
    /// on `AppState` rather than being constructed per request.
    pub http: reqwest::Client,
    /// This connector's own DCP *holder* identity - set only when a
    /// crawler config with a `[holder]` section was loaded (see `main.rs`).
    /// `None` means this connector presents no credential of its own and
    /// the two `/dsp/holder/*` routes below 404.
    pub holder: Option<Arc<HolderIdentity>>,
    /// The concrete Oxigraph-backed cache, held *in addition to* the
    /// type-erased `cache` field above, purely so `GET`/`POST /sparql` can
    /// reach `OxigraphCatalogCache::sparql_query_json` - a capability that
    /// exists on that concrete type, not on the `CatalogCache` trait (see
    /// that method's own doc comment for why). `Some` exactly when `cache`
    /// is backed by Oxigraph (i.e. `CRAWLER_CONFIG_PATH` was set, see
    /// `main.rs`); `None` when it's the plain in-memory backend, in which
    /// case `/sparql` answers 501 rather than pretending to support a
    /// query language that backend doesn't implement.
    pub sparql: Option<Arc<OxigraphCatalogCache>>,
    /// The OAuth2 Bearer resource-server gate for `GET /catalog` and
    /// `GET`/`POST /sparql` - see `oauth2`'s module doc and
    /// `docs/oauth2-bearer-gating-2026-08-28.md`. `Some` means gating is
    /// active (set only when `OAUTH2_JWKS_URI` was configured, see
    /// `main.rs`); `None` (the default) leaves both routes exactly as
    /// unauthenticated as before this feature existed. Never gates
    /// `/health` or the two `/dsp/holder/*` routes - those are unaffected
    /// by this field entirely.
    pub oauth2: Option<Arc<OAuth2Verifier>>,
    /// ODRL policy-based dataset-visibility filtering configuration (gap
    /// analysis §3.4) - see `odrl_filter::PolicyFilterConfig`'s own doc
    /// comment for the three conservative-by-default judgment calls it
    /// makes explicit. Defaults to `PolicyFilterConfig::default()`.
    ///
    /// Consulted by `filter_catalogs_by_policy`, called from both
    /// `GET /catalog` and `POST /api/management/v4/catalogs/request` -
    /// see this file's own `tests` module (the "ODRL policy-based dataset
    /// visibility filtering" section) for the behavior this drives.
    pub policy_filter: odrl_filter::PolicyFilterConfig,
}

impl AppState {
    pub fn new(cache: Arc<dyn CatalogCache>) -> Self {
        Self {
            cache,
            http: reqwest::Client::new(),
            holder: None,
            sparql: None,
            oauth2: None,
            policy_filter: odrl_filter::PolicyFilterConfig::default(),
        }
    }

    /// Builder-style setter for this connector's own DCP holder identity.
    /// See the `holder` field's doc comment.
    pub fn with_holder(mut self, holder: Option<Arc<HolderIdentity>>) -> Self {
        self.holder = holder;
        self
    }

    /// Builder-style setter wiring up the SPARQL endpoint against a real
    /// Oxigraph-backed cache. See the `sparql` field's doc comment.
    pub fn with_sparql(mut self, sparql: Option<Arc<OxigraphCatalogCache>>) -> Self {
        self.sparql = sparql;
        self
    }

    /// Builder-style setter for the OAuth2 Bearer gate. See the `oauth2`
    /// field's doc comment.
    pub fn with_oauth2(mut self, oauth2: Option<Arc<OAuth2Verifier>>) -> Self {
        self.oauth2 = oauth2;
        self
    }

    /// Builder-style setter for the ODRL policy-filtering config. See the
    /// `policy_filter` field's doc comment.
    pub fn with_policy_filter(mut self, policy_filter: odrl_filter::PolicyFilterConfig) -> Self {
        self.policy_filter = policy_filter;
        self
    }
}

/// Seed `cache` with one sample catalog, so a freshly started server (or a
/// test) has something real to serve from `GET /catalog` before any
/// crawler exists to populate it.
///
/// This stands in for the not-yet-built crawler: it upserts exactly the
/// same way a real crawl result would, through the public `CatalogCache`
/// trait, so it exercises the same end-to-end path as production code
/// rather than poking the cache's internals.
///
/// Dataset ids (`CAT0101`, `CAT0102`) are deliberately aligned with
/// `vendor/eclipse-edc-connector`'s own DSP-TCK seed data
/// (`system-tests/tck/tck-extension/.../DataSeed.java`), specifically the
/// `CAT0xxx`-prefixed subset it reserves for the catalog-protocol test
/// group (as opposed to its `ACN0xxx`/`ATP0xxx` ids, used by the
/// contract-negotiation/transfer-process groups this project doesn't
/// implement). This gives the Rust and EDC catalog-request responses the
/// same dataset *count and ids* to compare against
/// (`compliance/benchmark-2026-08-27.md`), even though the two
/// implementations still diverge on everything else about how those
/// datasets are represented on the wire (see that report's fidelity
/// section).
pub async fn seed_sample_catalog(cache: &dyn CatalogCache) -> StoreResult<()> {
    let node = NodeId::new("sample-participant");
    let mut catalog = Catalog::new("sample-catalog", node);
    catalog.participant_id = Some("did:example:sample-participant".to_string());
    for dataset_id in ["CAT0101", "CAT0102"] {
        catalog.datasets.push(Dataset {
            id: dataset_id.to_string(),
            properties: Default::default(),
            distributions: vec![Distribution {
                format: "application/json".to_string(),
                access_service: "sample-data-service".to_string(),
            }],
            policies: Vec::new(),
        });
    }
    catalog.data_services.push(DataService {
        id: "sample-data-service".to_string(),
        endpoint_url: "https://sample.example.org/dsp".to_string(),
        endpoint_description: Some("dataspace-protocol-http:1.0".to_string()),
    });

    cache.upsert(catalog).await
}

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

/// `GET /dsp/holder/did.json` - this connector's own holder `did:web`
/// document, so a remote relying party this connector queried (via
/// `HolderIdentity::mint_self_issued_token`) can resolve the key that
/// signs the `VerifiablePresentation` `holder_presentation_query_route`
/// returns.
async fn holder_did_document_route(State(state): State<AppState>) -> impl IntoResponse {
    match &state.holder {
        Some(holder) => (StatusCode::OK, Json(holder.own_did_document())).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// `POST /dsp/holder/presentations/query` - this connector's Presentation
/// API, called back by a relying party this connector previously queried
/// as a DCP holder (see `HolderIdentity::answer_presentation_query`'s doc
/// comment for the full flow this is the receiving half of).
///
/// No holder configured: 404 (same gating as `holder_did_document_route`).
/// Missing/malformed `Authorization` header, or a token that fails
/// verification: 401. Otherwise: 200 with a `PresentationResponseMessage`
/// body wrapping this connector's own stored credential.
async fn holder_presentation_query_route(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(holder) = &state.holder else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let token = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty());
    let Some(token) = token else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    match holder.answer_presentation_query(token, &state.http).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => {
            tracing::warn!(error = %err, "holder presentation query failed");
            StatusCode::UNAUTHORIZED.into_response()
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct HealthResponse {
    status: String,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}

/// Optional filter for `GET /catalog`: `?node_id=...` narrows to the
/// catalog crawled from a single origin node.
#[derive(Debug, Deserialize)]
struct CatalogParams {
    node_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CatalogListResponse {
    catalogs: Vec<Catalog>,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

/// Enforces the OAuth2 Bearer gate (see `AppState::oauth2`'s doc comment
/// and `docs/oauth2-bearer-gating-2026-08-28.md`'s "Response shape") for
/// `GET /catalog`, `GET`/`POST /sparql`, and
/// `POST /api/management/v4/catalogs/request` - the three routes this
/// mechanism gates. `Ok(claims)` means the caller may proceed:
/// `Ok(None)` when gating is off (`state.oauth2` is `None`, so there is no
/// verified token and therefore no claims at all), `Ok(Some(claims))` when
/// the caller presented a valid, sufficiently-scoped token - `claims` is
/// exactly `OAuth2Verifier::verify`'s own decoded JWT claims object, meant
/// to be fed to `odrl_filter::jwt_claims_to_engine_claims` by callers that
/// go on to do ODRL policy-based dataset filtering (gap analysis §3.4).
/// `Err(response)` is the exact response the caller should get instead of
/// running the route's own handler.
///
/// - No/malformed `Authorization: Bearer` header, or a token that fails
///   verification for any reason other than scope (unknown `kid`, bad
///   signature, expired, wrong `iss`/`aud`): `401` with a
///   `WWW-Authenticate: Bearer` header (RFC 6750).
/// - Valid token, missing the configured required scope: `403` (no
///   `WWW-Authenticate` header - the caller authenticated fine, it's an
///   authorization failure, not an authentication one).
fn check_oauth2_bearer(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<serde_json::Value>, Box<axum::response::Response>> {
    let Some(verifier) = &state.oauth2 else {
        return Ok(None);
    };

    let token = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty());
    let Some(token) = token else {
        return Err(Box::new(unauthorized_bearer_response()));
    };

    match verifier.verify(token) {
        Ok(claims) => Ok(Some(claims)),
        Err(VerifyError::InsufficientScope(scope)) => Err(Box::new(
            (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: format!("token is missing required scope '{scope}'"),
                }),
            )
                .into_response(),
        )),
        Err(err) => {
            tracing::warn!(error = %err, "oauth2 bearer token verification failed");
            Err(Box::new(unauthorized_bearer_response()))
        }
    }
}

fn unauthorized_bearer_response() -> axum::response::Response {
    (
        StatusCode::UNAUTHORIZED,
        [(WWW_AUTHENTICATE, "Bearer")],
        Json(ErrorResponse {
            error: "missing or invalid bearer token".to_string(),
        }),
    )
        .into_response()
}

/// The ODRL action `GET /catalog` and the management API check when
/// deciding whether a caller may see a harvested dataset at all (gap
/// analysis §3.4). Fixed to ODRL's own general-purpose "make use of this
/// asset" action rather than a bespoke broker-specific action string no
/// real crawled policy would ever grant/deny - listing/browsing a dataset
/// in this broker's own re-served catalog is the closest fit to that
/// action; actually transferring the underlying data stays entirely the
/// connector's own, separate DSP contract-negotiation concern this broker
/// never participates in.
const CATALOG_VISIBILITY_ACTION: &str = "odrl:use";

/// Whether ODRL policy-based dataset filtering (gap analysis §3.4) should
/// run at all for this request: always once an OAuth2 Bearer gate is
/// configured (`check_oauth2_bearer` already produced a genuine, if
/// possibly claim-sparse, verified identity to evaluate against), and
/// otherwise per `PolicyFilterConfig::filter_when_oauth2_disabled` - see
/// that field's own doc comment for why its default keeps filtering on
/// even then, evaluated against an empty claims map.
fn should_filter_by_policy(state: &AppState) -> bool {
    state.oauth2.is_some() || state.policy_filter.filter_when_oauth2_disabled
}

/// `check_oauth2_bearer`'s own verified-claims output (`None` when OAuth2
/// is disabled), converted to `ds-odrl-engine-rs`'s own claims shape and
/// layered with host-synthesized context claims - the one path every
/// caller of `odrl_filter::dataset_is_visible` in this file goes through
/// first, shared by [`filter_catalogs_by_policy`] (`GET /catalog`/the
/// management API) and [`visible_dataset_resource_iris`] (`sparql_route`'s
/// own query-rewriting filtering) alike, so the two surfaces can never
/// silently diverge on how a bearer token's claims get mapped.
fn engine_claims_from_bearer(claims: Option<&serde_json::Value>) -> engine::Claims {
    odrl_filter::with_context_claims(odrl_filter::jwt_claims_to_engine_claims(
        claims.unwrap_or(&serde_json::Value::Null),
    ))
}

/// Removes, from each of `catalogs`, every dataset
/// `odrl_filter::dataset_is_visible` says the caller identified by
/// `claims` is not entitled to see for [`CATALOG_VISIBILITY_ACTION`] - the
/// shared filtering step both `GET /catalog` and
/// `POST /api/management/v4/catalogs/request` apply (gap analysis §3.4). A
/// no-op (per [`should_filter_by_policy`]) when OAuth2 is off and
/// `PolicyFilterConfig::filter_when_oauth2_disabled` was explicitly set to
/// `false`.
///
/// A catalog left with zero visible datasets is kept, with an empty
/// `datasets` list, not dropped - `catalog_request_route`'s own doc
/// comment (decision 2) records why: consistent with
/// `CatalogRequestDataset`'s existing empty-vs-omitted convention, a
/// participant a caller has zero entitlement into still gets to be known
/// about, just with nothing they may see inside it.
fn filter_catalogs_by_policy(
    catalogs: &mut [Catalog],
    claims: Option<&serde_json::Value>,
    state: &AppState,
) {
    if !should_filter_by_policy(state) {
        return;
    }

    let engine_claims = engine_claims_from_bearer(claims);
    for catalog in catalogs.iter_mut() {
        catalog.datasets.retain(|dataset| {
            odrl_filter::dataset_is_visible(
                dataset,
                &engine_claims,
                CATALOG_VISIBILITY_ACTION,
                &state.policy_filter,
            )
        });
    }
}

/// The allow-list of dataset *resource IRIs* (exactly as
/// `rdf_store::oxigraph_backend::dataset_resource_iri` - and therefore a
/// real `?x a dcat:Dataset` SPARQL binding - would spell them) the caller
/// identified by `engine_claims` is entitled to see across every harvested
/// `catalogs`, for [`CATALOG_VISIBILITY_ACTION`] - the same per-dataset
/// decision [`filter_catalogs_by_policy`] already makes for
/// `GET /catalog`/the management API, reused here for `sparql_route`'s own
/// query-rewriting filtering (gap analysis §3.4,
/// `sparql_rewrite::restrict_to_visible_dataset_iris`'s own allow-list
/// input).
fn visible_dataset_resource_iris(
    catalogs: &[Catalog],
    engine_claims: &engine::Claims,
    state: &AppState,
) -> BTreeSet<String> {
    catalogs
        .iter()
        .flat_map(|catalog| {
            catalog
                .datasets
                .iter()
                .filter(move |dataset| {
                    odrl_filter::dataset_is_visible(
                        dataset,
                        engine_claims,
                        CATALOG_VISIBILITY_ACTION,
                        &state.policy_filter,
                    )
                })
                .map(move |dataset| {
                    rdf_store::oxigraph_backend::dataset_resource_iri(
                        &catalog.origin_node,
                        &dataset.id,
                    )
                })
        })
        .collect()
}

async fn get_catalog(
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
            filter_catalogs_by_policy(&mut catalogs, claims.as_ref(), &state);
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

// --- `POST /api/management/v4/catalogs/request` -------------------------
//
// This product's own federated catalog Management API surface. Its wire
// format is not this project's to invent: it must match what the real,
// already-published `edc-federated-catalog-client` crate
// (https://github.com/dataspace-rs/edc-federated-catalog-client, pinned at
// 0.2.5 as a *dev*-dependency below - see this crate's own Cargo.toml for
// why not a normal one) actually sends and parses -
// `FederatedCatalogClient::list_offers`/`get_offer_by_dataset_id` both
// `POST {endpoint}/api/management/v4/catalogs/request` with a
// `QuerySpec`-shaped body and expect a `Vec<FederatedCatalogOffer>` back
// (see that crate's `src/lib.rs`). The response types just below
// (`CatalogRequestOffer` and friends) are hand-written, field-for-field,
// against that crate's `src/models/federated_catalog_offer.rs`,
// `dataset.rs`, `service.rs`, and `participant_id.rs` - not derived from
// them, since production code here doesn't depend on that crate at all
// (only this file's own tests do) - but proven wire-identical by those
// same tests, which deserialize a real response body from this route with
// the real client crate's own `FederatedCatalogOffer` type.

/// One offer, matching `edc-federated-catalog-client`'s
/// `models::FederatedCatalogOffer` exactly: `@id`/`@type` JSON-LD framing,
/// a `dcat:dataset` array (omitted, not emitted empty, when there are no
/// datasets - the real struct defaults it on deserialize either way), a
/// single required `dcat:service` (see `catalog_to_offer`'s doc comment
/// for why a catalog with no data services can't produce one of these at
/// all), a required `participantId` object, and a required `originator`
/// string.
#[derive(Debug, Serialize)]
struct CatalogRequestOffer {
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@type")]
    r#type: String,
    #[serde(
        rename = "http://www.w3.org/ns/dcat#dataset",
        skip_serializing_if = "Vec::is_empty"
    )]
    dataset: Vec<CatalogRequestDataset>,
    #[serde(rename = "http://www.w3.org/ns/dcat#service")]
    service: CatalogRequestService,
    #[serde(rename = "participantId")]
    participant_id: CatalogRequestParticipantId,
    originator: String,
}

/// Matches `models::Dataset`. `has_policy` is always present (the real
/// struct has no `#[serde(default)]` on that field, so it's required on
/// the wire) and now carries this dataset's real, harvested
/// `catalog_core::Policy` entries, built by `dataset_to_offer` from
/// `catalog_core::Dataset.policies` - genuine ODRL data preserved from
/// what a crawled participant actually advertised, not the placeholder
/// this route used to emit unconditionally (`docs/gap-analysis-2026-08-27.md`
/// §3.4). It's an empty array, never omitted, when the harvested dataset
/// had no policies at all.
///
/// `title`/`description`/`version`/`creator`/`thumbnail`/`keywords` are the
/// optional descriptive fields sourced from `catalog_core::Dataset.properties`
/// (see `dataset_to_offer`) - each is omitted from the wire, not emitted
/// `null`/empty, when the source data doesn't have it, matching the real
/// struct's own `#[serde(default)]` on every one of these fields (so a
/// caller reading with that struct sees exactly `None`/`vec![]`, not a
/// spurious explicit null).
#[derive(Debug, Serialize)]
struct CatalogRequestDataset {
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@type")]
    r#type: String,
    /// One `serde_json::Value` per `catalog_core::Policy`, built by
    /// `dataset_to_offer` via `policy_to_json` - hand-built JSON rather
    /// than the real `edc_connector_client::types::policy::Policy` type
    /// (see this struct's own doc comment for why: this route
    /// deliberately doesn't depend on that crate in production code) but
    /// shaped to satisfy every one of that type's required-field rules,
    /// so a real client deserializes it into a genuine `Policy`, not an
    /// approximation of one.
    #[serde(rename = "http://www.w3.org/ns/odrl/2/hasPolicy")]
    has_policy: Vec<serde_json::Value>,
    name: String,
    #[serde(rename = "contenttype")]
    content_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    creator: Option<CatalogRequestCreator>,
    #[serde(skip_serializing_if = "Option::is_none")]
    thumbnail: Option<CatalogRequestThumbnail>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    keywords: Vec<String>,
}

/// Matches `models::Creator` - both fields are required on the real struct
/// (no `#[serde(default)]` on either), so a `CatalogRequestCreator` is only
/// ever constructed with both filled in. See `dataset_to_offer`'s doc
/// comment for how `thumbnail` gets filled when the source data has no
/// creator-specific one of its own.
#[derive(Debug, Serialize)]
struct CatalogRequestCreator {
    name: String,
    thumbnail: CatalogRequestThumbnail,
}

/// Matches `models::Thumbnail` - its one field, `resource`, is required
/// there (no `#[serde(default)]`).
#[derive(Debug, Serialize)]
struct CatalogRequestThumbnail {
    resource: String,
}

/// Matches `models::Service` - all four fields required (`endpoint_description`
/// is a plain `String` there, not `Option<String>` like
/// `catalog_core::DataService::endpoint_description`, hence the
/// `unwrap_or_default` in `catalog_to_offer`).
#[derive(Debug, Serialize)]
struct CatalogRequestService {
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@type")]
    r#type: String,
    #[serde(rename = "http://www.w3.org/ns/dcat#endpointDescription")]
    endpoint_description: String,
    #[serde(rename = "http://www.w3.org/ns/dcat#endpointURL")]
    endpoint_url: String,
}

/// Matches `models::ParticipantId`.
#[derive(Debug, Serialize)]
struct CatalogRequestParticipantId {
    #[serde(rename = "@id")]
    id: String,
}

/// Converts one cached `catalog_core::Catalog` into the wire shape above -
/// `None` when `catalog.data_services` is empty. A `FederatedCatalogOffer`'s
/// `service` field is a single required `Service`, not `Option`/`Vec`, so
/// a catalog with zero data services simply cannot produce a valid offer;
/// `catalog_request_route` skips these and logs how many, rather than
/// fabricating a placeholder service. When one or more data services do
/// exist, the first (`data_services[0]`) is used.
///
/// Field mapping notes (everything not explicitly called out is a direct
/// copy):
/// - `participantId`/`originator`: `catalog.participant_id` when the crawl
///   recorded one (a DID, typically), else `catalog.origin_node`'s id - the
///   best identifier this product actually has for who this catalog came
///   from.
/// - dataset `name`/`contenttype`: `catalog_core::Dataset` has no separate
///   "name" or "content type" field, so `name` is `dataset.id` (the best
///   available stand-in) and `contenttype` is the first distribution's
///   format string, or an empty string when the dataset has none.
/// - dataset `title`/`description`/`version`/`creator`/`thumbnail`/
///   `keywords`: read back out of `dataset.properties` under the same keys
///   `crawler::collect_datasets_and_services` writes them under - see
///   `dataset_to_offer`'s own doc comment for the exact mapping, including
///   how `creator`/`keywords` are built up from flatter string properties.
fn catalog_to_offer(catalog: &Catalog) -> Option<CatalogRequestOffer> {
    let data_service = catalog.data_services.first()?;
    let participant_id = catalog
        .participant_id
        .clone()
        .unwrap_or_else(|| catalog.origin_node.0.clone());

    Some(CatalogRequestOffer {
        id: catalog.id.clone(),
        r#type: "Catalog".to_string(),
        dataset: catalog.datasets.iter().map(dataset_to_offer).collect(),
        service: CatalogRequestService {
            id: data_service.id.clone(),
            r#type: "DataService".to_string(),
            endpoint_description: data_service
                .endpoint_description
                .clone()
                .unwrap_or_default(),
            endpoint_url: data_service.endpoint_url.clone(),
        },
        participant_id: CatalogRequestParticipantId {
            id: participant_id.clone(),
        },
        originator: participant_id,
    })
}

/// Builds one `hasPolicy` entry from a harvested `catalog_core::Policy`,
/// as a raw `serde_json::Value` (see `CatalogRequestDataset::has_policy`'s
/// doc comment for why this is hand-built JSON rather than the real
/// `edc_connector_client::types::policy::Policy` type).
///
/// Every key emitted here exists because the real struct requires it with
/// no `#[serde(default)]` (verified against
/// `edc-connector-client-next` 0.6.8's `src/types/policy.rs`); every key
/// omitted exists because the real struct marks it optional
/// (`Option` with `skip_serializing_if`, or a `Vec` with `#[serde(default)]`)
/// and this route follows its own established convention elsewhere in this
/// file of omitting rather than emitting empty/null placeholders:
///
/// - `@type` is always present - `Policy.kind` has no `#[serde(default)]`,
///   so it's required on the wire even though `PolicyKind` itself derives
///   `Default`.
/// - `@id` only when `Policy.id` is `Some`.
/// - `odrl:assigner`/`odrl:assignee` only when `Some` - and under exactly
///   those prefixed keys, not the plain `assigner`/`assignee` names, since
///   the real struct's `assigner`/`assignee` fields carry no plain
///   `#[serde(rename)]`, only `alias`es for the prefixed and full-IRI forms
///   (aliases apply only on *read*; emitting the plain name would silently
///   fail to round-trip through the real type).
/// - `permission`/`prohibition`/`obligation` arrays only when non-empty.
/// - each `Rule` -> `{"action": ..., "constraint": [...]}`, `action` always
///   present (required on the real `Permission`/`Prohibition`/`Obligation`
///   types), `constraint` only when non-empty.
/// - each atomic `Constraint` -> `{"leftOperand": ..., "operator": ...,
///   "rightOperand": ...}`, all three always present - the real
///   `AtomicConstraint` requires all three with no defaults. A `Logical`
///   `catalog_core::Constraint` (gap analysis §3.4 - `Constraint` now
///   models both shapes, see its own doc comment) is skipped here rather
///   than mis-emitted as if it were atomic: mapping a logical group to the
///   real client's own `MultiplicityConstraint` wire shape is separate,
///   not-yet-done work this route does not perform yet, and no current
///   producer constructs a `Logical` constraint in the first place.
fn policy_to_json(policy: &Policy) -> serde_json::Value {
    let kind = match policy.kind {
        PolicyKind::Set => "Set",
        PolicyKind::Offer => "Offer",
        PolicyKind::Agreement => "Agreement",
    };
    let mut value = serde_json::json!({ "@type": kind });
    let object = value.as_object_mut().expect("built as a JSON object above");

    if let Some(id) = &policy.id {
        object.insert("@id".to_string(), serde_json::Value::String(id.clone()));
    }
    if let Some(assigner) = &policy.assigner {
        object.insert(
            "odrl:assigner".to_string(),
            serde_json::Value::String(assigner.clone()),
        );
    }
    if let Some(assignee) = &policy.assignee {
        object.insert(
            "odrl:assignee".to_string(),
            serde_json::Value::String(assignee.clone()),
        );
    }
    if !policy.permissions.is_empty() {
        object.insert(
            "permission".to_string(),
            serde_json::Value::Array(policy.permissions.iter().map(rule_to_json).collect()),
        );
    }
    if !policy.prohibitions.is_empty() {
        object.insert(
            "prohibition".to_string(),
            serde_json::Value::Array(policy.prohibitions.iter().map(rule_to_json).collect()),
        );
    }
    if !policy.obligations.is_empty() {
        object.insert(
            "obligation".to_string(),
            serde_json::Value::Array(policy.obligations.iter().map(rule_to_json).collect()),
        );
    }

    value
}

/// Builds one `permission`/`prohibition`/`obligation` entry from a
/// harvested `catalog_core::Rule` - see `policy_to_json`'s doc comment for
/// which keys are required vs. optional on the real side.
fn rule_to_json(rule: &Rule) -> serde_json::Value {
    let mut value = serde_json::json!({ "action": rule.action });
    if !rule.constraints.is_empty() {
        value["constraint"] = serde_json::Value::Array(
            rule.constraints
                .iter()
                .filter_map(|constraint| match constraint {
                    catalog_core::Constraint::Atomic(atomic) => Some(serde_json::json!({
                        "leftOperand": atomic.left_operand,
                        "operator": atomic.operator,
                        "rightOperand": atomic.right_operand,
                    })),
                    catalog_core::Constraint::Logical(_) => None,
                })
                .collect(),
        );
    }
    value
}

/// Reads the optional descriptive properties `crawler::collect_datasets_and_services`
/// wrote into `dataset.properties` (`title`, `description`, `version`,
/// `creatorName`, `thumbnail`, `keywords`) back out and populates the
/// matching wire fields. Every one of them stays properly absent
/// (`None`/`vec![]`) when the source data doesn't have it - nothing here
/// invents a placeholder.
///
/// - `creator`: built only when a `creatorName` property is present. A
///   `Creator` requires both a `name` and a `thumbnail`
///   (`edc_federated_catalog_client::models::dataset::Creator`), but
///   `catalog_core::Dataset.properties` carries only one dataset-level
///   `thumbnail`, not a separate creator-specific one - so the creator's
///   `thumbnail` reuses the dataset's own `thumbnail` property value
///   (empty string when that's also absent, since `Creator::thumbnail` is
///   itself required and there is nothing else to put there). A defensible
///   simplification: real crawled data rarely distinguishes a dataset's
///   thumbnail from its creator's.
/// - `keywords`: the single comma-separated `keywords` property, split on
///   `,` with each entry trimmed; absent or empty -> an empty `Vec`,
///   matching the real struct's own `#[serde(default)]` on that field.
fn dataset_to_offer(dataset: &Dataset) -> CatalogRequestDataset {
    let thumbnail_value = dataset.properties.get("thumbnail").cloned();
    let creator =
        dataset
            .properties
            .get("creatorName")
            .cloned()
            .map(|name| CatalogRequestCreator {
                name,
                thumbnail: CatalogRequestThumbnail {
                    resource: thumbnail_value.clone().unwrap_or_default(),
                },
            });
    let keywords = dataset
        .properties
        .get("keywords")
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    CatalogRequestDataset {
        id: dataset.id.clone(),
        r#type: "Dataset".to_string(),
        has_policy: dataset.policies.iter().map(policy_to_json).collect(),
        name: dataset.id.clone(),
        content_type: dataset
            .distributions
            .first()
            .map(|d| d.format.clone())
            .unwrap_or_default(),
        title: dataset.properties.get("title").cloned(),
        description: dataset.properties.get("description").cloned(),
        version: dataset.properties.get("version").cloned(),
        creator,
        thumbnail: thumbnail_value.map(|resource| CatalogRequestThumbnail { resource }),
        keywords,
    }
}

/// The `QuerySpec`-shaped request body `POST /api/management/v4/catalogs/request`
/// accepts, matching the real client's `ListOfferBody`
/// (`edc-federated-catalog-client::ListOfferBody`) closely enough to parse
/// what it sends - `@context`/`@type` are accepted but ignored (this route
/// has nothing to validate them against), and only `filterExpression` is
/// acted on. Deserialized leniently: a missing, empty, or entirely
/// malformed body all fall back to `Default` (no filter) rather than a 400
/// - see `catalog_request_route`'s doc comment for why.
#[derive(Debug, Deserialize, Default)]
struct CatalogRequestBody {
    #[serde(rename = "filterExpression", default)]
    filter_expression: Vec<CatalogRequestConstraint>,
}

/// One `filterExpression` entry, matching the real client's private
/// `Constraint` shape (`{operandLeft, operator, operandRight}`) closely
/// enough to read it back - this route only ever recognizes one exact
/// shape of it, see `catalog_request_route`.
#[derive(Debug, Deserialize, Default)]
struct CatalogRequestConstraint {
    #[serde(rename = "operandLeft", default)]
    operand_left: String,
    #[serde(default)]
    operator: String,
    #[serde(rename = "operandRight", default)]
    operand_right: String,
}

/// `POST /api/management/v4/catalogs/request` - see this section's module-
/// level comment above for the wire-compatibility contract this route
/// exists to satisfy.
///
/// Response: one offer per catalog currently in `state.cache`
/// (`state.cache.query(CatalogQuery::all())`, the same call `GET /catalog`
/// already uses), built by `catalog_to_offer` - catalogs with no data
/// services are skipped (logged once as a `tracing::warn!` with the
/// skipped count, not per-catalog) rather than erroring or fabricating a
/// service.
///
/// Request body: a `QuerySpec`-shaped JSON body (`CatalogRequestBody`) that
/// may carry a `filterExpression` array. The only constraint shape honored
/// is `operandLeft == "datasets.id"` with `operator == "="` - the exact
/// filter `get_offer_by_dataset_id` sends client-side - which narrows the
/// response to offers containing a dataset with that id. Any other/
/// unrecognized constraint, and a missing, empty, or malformed body
/// entirely, all mean the same thing: the full unfiltered offer list comes
/// back. A real client always sends *some* `QuerySpec` body, so being
/// lenient here matters more than being strict.
///
/// Gated by the same OAuth2 Bearer mechanism as `GET /catalog` and
/// `GET`/`POST /sparql` (`check_oauth2_bearer`) - this is another
/// catalog-listing surface, so gating it the same way is the consistent
/// choice. Unchanged/open when `state.oauth2` is `None`, exactly like
/// those two routes.
///
/// Also applies the same ODRL policy-based dataset-visibility filtering
/// as `GET /catalog` (`filter_catalogs_by_policy`, gap analysis §3.4),
/// *before* the `filterExpression` handling below - a caller not entitled
/// to a dataset under its harvested policy must not be able to retrieve
/// it merely by asking for it by id via `datasets.id`/`=`. An offer left
/// with zero visible datasets after policy filtering is kept, with an
/// empty `dataset` array, not omitted - consistent with this file's
/// existing "empty, not omitted" convention for `hasPolicy` on a
/// policy-free dataset.
async fn catalog_request_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let claims = match check_oauth2_bearer(&state, &headers) {
        Ok(claims) => claims,
        Err(response) => return *response,
    };

    let mut catalogs = match state.cache.query(CatalogQuery::all()).await {
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
    filter_catalogs_by_policy(&mut catalogs, claims.as_ref(), &state);

    let mut skipped = 0usize;
    let mut offers: Vec<CatalogRequestOffer> = Vec::with_capacity(catalogs.len());
    for catalog in &catalogs {
        match catalog_to_offer(catalog) {
            Some(offer) => offers.push(offer),
            None => skipped += 1,
        }
    }
    if skipped > 0 {
        tracing::warn!(
            skipped,
            "skipped {skipped} catalog(s) with no data services in POST \
             /api/management/v4/catalogs/request: a FederatedCatalogOffer's 'service' field is \
             a single required Service, not Option/Vec, so a catalog with zero data services \
             cannot produce a valid offer"
        );
    }

    let filter = serde_json::from_slice::<CatalogRequestBody>(&body).unwrap_or_default();
    let dataset_id_filter = filter.filter_expression.iter().find_map(|constraint| {
        (constraint.operand_left == "datasets.id" && constraint.operator == "=")
            .then(|| constraint.operand_right.clone())
    });
    if let Some(dataset_id) = dataset_id_filter {
        offers.retain(|offer| offer.dataset.iter().any(|dataset| dataset.id == dataset_id));
    }

    Json(offers).into_response()
}

/// `application/sparql-results+json`, the one result media type this
/// endpoint produces (gap analysis §3.3's stated minimum).
const SPARQL_RESULTS_JSON: &str = "application/sparql-results+json";

/// `GET /sparql?query=...` - the SPARQL 1.1 Protocol's URL-encoded GET
/// form. See [`sparql_route`] for the shared handling.
#[derive(Debug, Deserialize)]
struct SparqlGetParams {
    query: Option<String>,
}

async fn sparql_route_get(
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
struct SparqlPostForm {
    query: Option<String>,
}

async fn sparql_route_post(
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
fn accepts_sparql_results_json(headers: &HeaderMap) -> bool {
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
/// - ODRL policy-based query-rewriting filtering (gap analysis §3.4,
///   `sparql_rewrite`) runs next, whenever [`should_filter_by_policy`] says
///   it should: the caller's own per-dataset allow-list is computed via
///   [`visible_dataset_resource_iris`] (the same decision
///   `filter_catalogs_by_policy` already makes for `GET /catalog`/the
///   management API) and `query` is rewritten to restrict every
///   recognized dataset-subject variable to it
///   (`sparql_rewrite::restrict_to_visible_dataset_iris`). A query that
///   cannot be scoped this way (no such variable found anywhere in its own
///   top scope) is handled per
///   `PolicyFilterConfig::unscopeable_sparql_query_action`: `400 Bad
///   Request` under its default ([`odrl_filter::UnscopeableSparqlQueryAction::Reject`]),
///   or run completely unrewritten under the explicit
///   `run_unfiltered` opt-out. When filtering is off entirely (OAuth2
///   disabled and `PolicyFilterConfig::filter_when_oauth2_disabled` set to
///   `false`), `query` reaches evaluation completely unrewritten, exactly
///   as before this feature existed.
/// - Query fails to parse, fails to evaluate, or is a `CONSTRUCT`/
///   `DESCRIBE` (unsupported result shape - see `SparqlError`'s own doc
///   comments): 400 Bad Request with a plain-text explanation - these are
///   all the caller's own query's fault. A query rejected here was either
///   already like this before any rewriting (rewriting passes an unparseable
///   query through unchanged, per `sparql_rewrite`'s own doc comment) or
///   became so only in a way that itself proves the original could never
///   have evaluated either.
/// - Otherwise: 200 with an `application/sparql-results+json` body,
///   computed from the (possibly policy-rewritten) query.
///
/// Checked first, ahead of all of the above: the OAuth2 Bearer gate (see
/// `check_oauth2_bearer`'s doc comment) - `401`/`403` when
/// `AppState::oauth2` is configured and the caller's token doesn't clear
/// it; unchanged behavior (falls straight through to the checks above)
/// when it isn't configured at all.
async fn sparql_route(
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
             (Oxigraph) backend - set CRAWLER_CONFIG_PATH to enable the SPARQL endpoint"
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

    let query = if should_filter_by_policy(&state) {
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
        let visible = visible_dataset_resource_iris(&catalogs, &engine_claims, &state);

        match sparql_rewrite::restrict_to_visible_dataset_iris(&query, &visible) {
            Ok(rewritten) => rewritten,
            Err(sparql_rewrite::UnscopeableQuery) => {
                match state.policy_filter.unscopeable_sparql_query_action {
                    odrl_filter::UnscopeableSparqlQueryAction::Reject => {
                        return (
                            StatusCode::BAD_REQUEST,
                            "this query cannot be scoped to a per-caller allow-list of visible \
                             datasets (no dataset-subject-shaped variable, e.g. '?x a \
                             dcat:Dataset', found anywhere in it) - rejected rather than run \
                             unfiltered against the whole store; see \
                             PolicyFilterConfig::unscopeable_sparql_query_action"
                                .to_string(),
                        )
                            .into_response();
                    }
                    odrl_filter::UnscopeableSparqlQueryAction::RunUnfiltered => query,
                }
            }
        }
    } else {
        query
    };

    match sparql.sparql_query_json(&query) {
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
        Err(err @ SparqlError::Serialize(_)) => {
            tracing::error!(error = %err, "failed to serialize SPARQL results");
            (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use rdf_store::memory::InMemoryCatalogCache;
    use tower::ServiceExt;

    fn test_state() -> AppState {
        AppState::new(Arc::new(InMemoryCatalogCache::new()))
    }

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

    /// Proves `AppState.cache: Arc<dyn CatalogCache>` genuinely works with
    /// the real Oxigraph-backed implementation, not just
    /// `InMemoryCatalogCache` - the backend `main.rs` switches to when
    /// `CRAWLER_CONFIG_PATH` is set (see that function's doc comment).
    /// Exercises `GET /catalog` end to end through the router, not just
    /// the cache trait directly. (Previously exercised the now-removed
    /// `POST /dsp/catalog/request` DSP-serving endpoint - see
    /// `docs/gap-analysis-2026-08-27.md` §1 for why that endpoint is
    /// gone; this test keeps the same "real Oxigraph backend through the
    /// router" coverage against the surface that replaced it.)
    #[tokio::test]
    async fn catalog_endpoint_serves_data_from_the_oxigraph_backend() {
        let cache: Arc<dyn CatalogCache> =
            Arc::new(rdf_store::oxigraph_backend::OxigraphCatalogCache::in_memory().unwrap());
        seed_sample_catalog(&*cache).await.unwrap();
        let state = AppState::new(cache);

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
        let mut ids: Vec<&str> = parsed.catalogs[0]
            .datasets
            .iter()
            .map(|d| d.id.as_str())
            .collect();
        ids.sort_unstable();
        assert_eq!(ids, vec!["CAT0101", "CAT0102"]);
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

    // --- `/sparql` (gap analysis §3.3) --------------------------------------

    /// `AppState` wired the way `main.rs` wires it once
    /// `CRAWLER_CONFIG_PATH` is set: a real Oxigraph-backed cache, with
    /// `AppState::sparql` pointed at that same store so `/sparql` is live.
    fn sparql_test_state() -> AppState {
        let store =
            Arc::new(rdf_store::oxigraph_backend::OxigraphCatalogCache::in_memory().unwrap());
        let cache: Arc<dyn CatalogCache> = store.clone();
        AppState::new(cache).with_sparql(Some(store))
    }

    /// A small but real per-participant catalog - same shape as
    /// `seed_sample_catalog`'s fixture (one dataset, one distribution, one
    /// data service), parameterized by origin node so two distinct
    /// participants' worth of real, differently-shaped data can be seeded
    /// side by side, which is what the SPARQL tests below need to prove a
    /// query genuinely spans more than one harvested participant.
    fn participant_catalog(node_id: &str, catalog_id: &str, dataset_id: &str) -> Catalog {
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

    /// The in-memory backend (no `CRAWLER_CONFIG_PATH`, `AppState::sparql`
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

    // --- OAuth2 Bearer gating (docs/oauth2-bearer-gating-2026-08-28.md) ---
    //
    // Router-level, through the real `build_router` + `oneshot` - not
    // `OAuth2Verifier::verify` called directly (that's already covered,
    // thoroughly, by `oauth2.rs`'s own unit tests). What these prove is
    // the wiring: that `check_oauth2_bearer` actually gates these two
    // routes and only these two, and that the mock JWKS server is reached
    // over a real HTTP fetch (`OAuth2Verifier::fetch`), not a pre-parsed
    // fixture - see `oauth2::test_support::spawn_jwks_server`.

    use crate::oauth2::test_support::{
        base_claims, ec_jwk, generate_key, sign_es256, spawn_jwks_server,
    };
    use crate::oauth2::{OAuth2Config, OAuth2Verifier};

    fn oauth2_config(jwks_uri: String) -> OAuth2Config {
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
    async fn oauth2_catalog_state(
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

    /// Same idea as `oauth2_catalog_state`, but built on `sparql_test_state()`
    /// (a real Oxigraph backend, one seeded participant) so `/sparql` has
    /// something real to answer once a valid token clears the gate.
    async fn oauth2_sparql_state(
        configure: impl FnOnce(&mut OAuth2Config),
    ) -> (AppState, oauth2::test_support::TestKey) {
        let key = generate_key("sparql-key");
        let jwks_uri = spawn_jwks_server(serde_json::json!({"keys": [ec_jwk(&key, None)]})).await;
        let mut config = oauth2_config(jwks_uri);
        configure(&mut config);
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), config)
            .await
            .expect("fetch mock JWKS");

        let state = sparql_test_state();
        state
            .cache
            .upsert(participant_catalog("node-a", "cat-a", "DATASET-A"))
            .await
            .unwrap();
        let state = state.with_oauth2(Some(Arc::new(verifier)));
        (state, key)
    }

    fn bearer(token: &str) -> String {
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
            oauth2_sparql_state(|config| config.required_scope = Some("sparql:read".to_string()))
                .await;
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

    // --- `POST /api/management/v4/catalogs/request` -----------------------
    //
    // Wire-compatibility with the real, already-published
    // `edc-federated-catalog-client` 0.2.5 crate (a *dev*-dependency only -
    // see this crate's own Cargo.toml) is the whole point of this route,
    // so these tests deserialize its real response bodies with that
    // crate's own `FederatedCatalogOffer` type rather than a local
    // stand-in - a genuine round-trip proof, not just "200 and looks like
    // JSON".

    use catalog_core::Constraint;
    use edc_connector_client::types::policy::{
        Constraint as RealConstraint, LeftOperand, Operator, PolicyKind as RealPolicyKind,
    };
    use edc_connector_client::types::properties::PropertyValue;
    use edc_federated_catalog_client::ListOfferBody;
    use edc_federated_catalog_client::models::FederatedCatalogOffer;

    fn catalog_request(body: Body) -> Request<Body> {
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
        let has_policy = &raw[0]["http://www.w3.org/ns/dcat#dataset"][0]["http://www.w3.org/ns/odrl/2/hasPolicy"];
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
            let offers: Vec<FederatedCatalogOffer> =
                serde_json::from_slice(&response_body).unwrap();
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
    //    Fixed to `odrl:use` (`CATALOG_VISIBILITY_ACTION`, defined above
    //    near `get_catalog` and reused here as `TEST_CATALOG_VISIBILITY_ACTION`
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
    //    above for the same "empty, not omitted" convention already used
    //    elsewhere in this file) - a participant a caller has zero
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
    fn eu_resident_claims() -> serde_json::Value {
        let mut claims = base_claims();
        claims["role"] = serde_json::json!("eu-resident");
        claims
    }

    /// One catalog with two datasets: `OPEN-DATASET` (no policies at all,
    /// visible under `NoPolicyVisibility`'s default `Open` regardless of
    /// caller) and `GATED-DATASET` (one policy, [`eu_resident_only_policy`],
    /// visible only to a caller whose claims satisfy it).
    fn catalog_with_open_and_gated_datasets(node_id: &str, catalog_id: &str) -> Catalog {
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
    async fn oauth2_state_with_catalog(
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
    async fn get_catalog_filters_by_policy_even_when_oauth2_is_disabled_matching_the_default_config()
     {
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
    async fn get_catalog_keeps_a_catalog_with_an_empty_datasets_list_when_every_dataset_is_hidden()
    {
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
    async fn catalog_request_route_shows_a_policy_gated_dataset_to_a_caller_with_the_required_claim()
     {
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

    // --- SPARQL ODRL policy-based filtering (gap analysis §3.4)
    // ------------------------------------------------------------------
    //
    // The last of gap analysis §3.4's three serving surfaces: `GET`/
    // `POST /sparql` now calls `odrl_filter::dataset_is_visible` (via
    // `visible_dataset_resource_iris`) and rewrites the caller's query
    // through `sparql_rewrite::restrict_to_visible_dataset_iris` before
    // ever evaluating it - see `sparql_route`'s own doc comment for the
    // exact behavior, and `sparql_rewrite`'s module doc for the design
    // and its documented residual gaps.
    //
    // This surface was genuinely harder than the other two: named graphs
    // in the semantic cache are per-*participant*, not per-*dataset*
    // (`rdf_store::oxigraph_backend`'s own module doc), while ODRL
    // policies are attached per-*dataset* - and an arbitrary caller-
    // supplied SELECT/ASK query may or may not even bind a variable to a
    // dataset's subject IRI at all. The design actually shipped:
    //
    // 1. Compute the allow-list of dataset IRIs currently visible to the
    //    caller by running `odrl_filter::dataset_is_visible` over every
    //    dataset in the cache (`visible_dataset_resource_iris`) - the
    //    same computation `filter_catalogs_by_policy` already does for
    //    `GET /catalog`/the management API, factored into a shared
    //    `engine_claims_from_bearer` helper both paths call rather than
    //    duplicated.
    // 2. Rewrite the incoming query, at the level of its real parsed
    //    SPARQL algebra (not its text - see `sparql_rewrite`'s own module
    //    doc for why that distinction matters), to inject a
    //    `FILTER(!BOUND(?x) || ?x IN (...))` restriction for every
    //    variable that appears as the subject of a `?x a dcat:Dataset`
    //    triple pattern and is still visible at the query's own top
    //    scope.
    // 3. A query with no such bindable variable anywhere in its own top
    //    scope - the store cannot tell what the query is "about" at a
    //    dataset level, so there is nothing to inject the restriction
    //    onto - is handled per
    //    `PolicyFilterConfig::unscopeable_sparql_query_action`'s own
    //    conservative default ([`odrl_filter::UnscopeableSparqlQueryAction::Reject`]):
    //    `400 Bad Request`, not silently run unfiltered.
    //
    // Per this session's own prior-art lesson (silent over-permission is
    // the failure mode that matters, not a loud error), every "hidden"
    // assertion below checks a policy-gated dataset's actual *absence*
    // from the parsed SPARQL JSON results, mirroring the REST-surface
    // negative-test discipline above - not merely that the response still
    // parses.

    /// Same idea as `oauth2_sparql_state`, but seeded with a caller-
    /// supplied catalog (via `sparql_test_state()`'s real Oxigraph
    /// backend) rather than the fixed single-dataset `participant_catalog`
    /// fixture - the SPARQL analogue of `oauth2_state_with_catalog`, which
    /// does the same thing for `GET /catalog`/the management API's
    /// in-memory-backed state.
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

        let state = sparql_test_state();
        state.cache.upsert(catalog).await.unwrap();
        let state = state.with_oauth2(Some(Arc::new(verifier)));
        (state, key)
    }

    /// `SELECT ?dataset WHERE { ?dataset a dcat:Dataset }` - the same
    /// bindable-dataset-IRI query shape `sparql_get_select_finds_datasets_from_both_seeded_participants`
    /// already uses above, run here against a catalog that mixes an open
    /// and a policy-gated dataset (`catalog_with_open_and_gated_datasets`,
    /// from the REST-surface filtering section above).
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
        let state = sparql_test_state();
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

    /// A query with no dataset-subject-shaped variable anywhere in it -
    /// `?s`/`?p`/`?o` here are each unconstrained, no `?x a dcat:Dataset`
    /// triple pattern ties any of them to a dataset's subject position -
    /// so there is no allow-list variable for query-rewriting filtering to
    /// restrict. This query would, if ever run unfiltered, return every
    /// harvested triple in the store including the gated dataset's own -
    /// exactly the silent-over-permission risk
    /// `UnscopeableSparqlQueryAction::Reject`'s default guards against.
    #[tokio::test]
    async fn sparql_rejects_an_unscopeable_query_by_default_rather_than_running_it_unfiltered() {
        let state = sparql_test_state();
        state
            .cache
            .upsert(catalog_with_open_and_gated_datasets("node-a", "cat-a"))
            .await
            .unwrap();
        assert_eq!(
            state.policy_filter.unscopeable_sparql_query_action,
            odrl_filter::UnscopeableSparqlQueryAction::Reject,
            "this test exercises the default; update it if the default ever changes"
        );
        let app = build_router(state);

        let query = "SELECT ?s ?p ?o WHERE { ?s ?p ?o }";
        let uri = format!("/sparql?query={}", urlencoding::encode(query));
        let response = app
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "a query with no bindable dataset-subject variable must be rejected outright per \
             PolicyFilterConfig::unscopeable_sparql_query_action's default (Reject), not \
             silently run unfiltered against the whole store"
        );
    }
}
