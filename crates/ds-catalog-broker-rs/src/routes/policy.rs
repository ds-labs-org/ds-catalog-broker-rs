//! ODRL policy-based visibility filtering shared by the catalog, SPARQL
//! and management routes (gap analysis §3.4).

use std::collections::BTreeSet;

use std::sync::Arc;

use catalog_core::{Catalog, Dataset};
use rdf_store::CatalogQuery;

use super::internal_error;

use crate::{AppState, odrl_filter};

/// The ODRL action `GET /catalog` and the management API check when
/// deciding whether a caller may see a harvested dataset at all (gap
/// analysis §3.4). Fixed to ODRL's own general-purpose "make use of this
/// asset" action rather than a bespoke broker-specific action string no
/// real crawled policy would ever grant/deny - listing/browsing a dataset
/// in this broker's own re-served catalog is the closest fit to that
/// action; actually transferring the underlying data stays entirely the
/// connector's own, separate DSP contract-negotiation concern this broker
/// never participates in.
pub(crate) const CATALOG_VISIBILITY_ACTION: &str = "odrl:use";

/// Whether ODRL policy-based dataset filtering (gap analysis §3.4) should
/// run at all for this request: always once an OAuth2 Bearer gate is
/// configured (`check_oauth2_bearer` already produced a genuine, if
/// possibly claim-sparse, verified identity to evaluate against), and
/// otherwise per `PolicyFilterConfig::filter_when_oauth2_disabled` - see
/// that field's own doc comment for why its default keeps filtering on
/// even then, evaluated against an empty claims map.
pub(super) fn should_filter_by_policy(state: &AppState) -> bool {
    state.oauth2.is_some() || state.policy_filter.filter_when_oauth2_disabled
}

/// `check_oauth2_bearer`'s own verified-claims output (`None` when OAuth2
/// is disabled), converted to `ds-odrl-engine-rs`'s own claims shape and
/// layered with host-synthesized context claims - the one path every
/// caller of `odrl_filter::dataset_is_visible` in this file goes through
/// first, shared by [`filter_catalogs_by_policy`] (`GET /catalog`/the
/// management API) and [`visible_resource_iris`] (`sparql_route`'s
/// own filtering) alike, so the two surfaces can never
/// silently diverge on how a bearer token's claims get mapped.
pub(super) fn engine_claims_from_bearer(claims: Option<&serde_json::Value>) -> engine::Claims {
    odrl_filter::with_context_claims(odrl_filter::jwt_claims_to_engine_claims(
        claims.unwrap_or(&serde_json::Value::Null),
    ))
}

/// Removes, from each of `catalogs`, every dataset
/// `odrl_filter::dataset_is_visible` says the caller identified by
/// `claims` is not entitled to see for [`CATALOG_VISIBILITY_ACTION`], and,
/// per `services`, every data service only those datasets use
/// ([`service_is_visible`]) - the
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
pub(super) fn filter_catalogs_by_policy(
    catalogs: &mut [Catalog],
    claims: Option<&serde_json::Value>,
    state: &AppState,
    services: ServiceFiltering,
) {
    if !should_filter_by_policy(state) {
        return;
    }

    let engine_claims = engine_claims_from_bearer(claims);
    for catalog in catalogs.iter_mut() {
        let used_by_any = services_used_by(catalog.datasets.iter());
        catalog.datasets.retain(|dataset| {
            odrl_filter::dataset_is_visible(
                dataset,
                &engine_claims,
                CATALOG_VISIBILITY_ACTION,
                &state.policy_filter,
            )
        });
        if services == ServiceFiltering::HideGatedOnly {
            let used_by_visible = services_used_by(catalog.datasets.iter());
            catalog
                .data_services
                .retain(|service| service_is_visible(&service.id, &used_by_any, &used_by_visible));
        }
    }
}

/// Whether [`filter_catalogs_by_policy`] also removes data services only
/// hidden datasets use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ServiceFiltering {
    /// `GET /catalog`: hide them, matching `/sparql`.
    HideGatedOnly,
    /// The management API: keep every service. Its offers are built around
    /// a catalog's data service, and a catalog left with zero visible
    /// datasets is deliberately still listed with an empty dataset array
    /// (`catalog_request_route`'s doc comment), which needs the service.
    KeepAll,
}

/// Every data service id a distribution of `datasets` uses.
pub(super) fn services_used_by<'a>(
    datasets: impl Iterator<Item = &'a Dataset>,
) -> BTreeSet<String> {
    datasets
        .flat_map(|dataset| &dataset.distributions)
        .map(|distribution| distribution.access_service.clone())
        .collect()
}

/// A data service is visible when a visible dataset uses it, or when no
/// dataset uses it at all. One only hidden datasets use is hidden with
/// them: its endpoint names the gated partner. Shared by
/// [`filter_catalogs_by_policy`] and [`visible_resource_iris`] so
/// `GET /catalog` and `/sparql` agree (the management API keeps every
/// service - see [`ServiceFiltering::KeepAll`]).
pub(super) fn service_is_visible(
    service_id: &str,
    used_by_any: &BTreeSet<String>,
    used_by_visible: &BTreeSet<String>,
) -> bool {
    used_by_visible.contains(service_id) || !used_by_any.contains(service_id)
}

/// What the caller identified by `engine_claims` may see across every
/// harvested `catalogs`, as resource IRIs spelled exactly as
/// `rdf_store::oxigraph_backend::dataset_resource_iri`/`service_resource_iri`
/// (and therefore a real SPARQL binding) would spell them. Visibility is
/// the same per-dataset decision [`filter_catalogs_by_policy`] already
/// makes for `GET /catalog`/the management API, for
/// [`CATALOG_VISIBILITY_ACTION`].
///
/// Returns the visible datasets plus every data service a visible
/// dataset's distribution uses, or that no dataset uses at all
/// ([`service_is_visible`]): the allow-list
/// `OxigraphCatalogCache::sparql_query_json_policy_filtered` evaluates over.
pub(super) fn visible_resource_iris(
    catalogs: &[Catalog],
    engine_claims: &engine::Claims,
    state: &AppState,
) -> BTreeSet<String> {
    let mut visible_resources = BTreeSet::new();
    for catalog in catalogs {
        let node = &catalog.origin_node;
        let visible: Vec<&Dataset> = catalog
            .datasets
            .iter()
            .filter(|dataset| {
                odrl_filter::dataset_is_visible(
                    dataset,
                    engine_claims,
                    CATALOG_VISIBILITY_ACTION,
                    &state.policy_filter,
                )
            })
            .collect();
        for dataset in &visible {
            visible_resources.insert(rdf_store::oxigraph_backend::dataset_resource_iri(
                node,
                &dataset.id,
            ));
        }
        let used_by_any = services_used_by(catalog.datasets.iter());
        let used_by_visible = services_used_by(visible.into_iter());
        visible_resources.extend(
            catalog
                .data_services
                .iter()
                .filter(|service| service_is_visible(&service.id, &used_by_any, &used_by_visible))
                .map(|service| {
                    rdf_store::oxigraph_backend::service_resource_iri(node, &service.id)
                }),
        );
    }
    visible_resources
}

/// The response `render` builds from the catalogs matching `query`,
/// filtered by policy for the caller whose verified `claims` these are.
/// Decoding, filtering and rendering all run on the blocking pool: each is
/// synchronous and takes a while on a large store, and an async worker
/// held that long would stall every other request it serves, `/health`
/// included.
pub(super) async fn render_visible_catalogs(
    state: AppState,
    query: CatalogQuery,
    claims: Option<serde_json::Value>,
    services: ServiceFiltering,
    render: impl FnOnce(Vec<Catalog>) -> axum::response::Response + Send + 'static,
) -> axum::response::Response {
    // Wait for a decode slot, so a burst of requests queues here instead
    // of filling the blocking pool with full copies of the store.
    let slot = Arc::clone(&state.catalog_slots)
        .acquire_owned()
        .await
        .expect("the catalog decode semaphore is never closed");
    let rendered = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        let mut catalogs = state.cache.catalogs(query)?;
        filter_catalogs_by_policy(&mut catalogs, claims.as_ref(), &state, services);
        Ok::<_, rdf_store::StoreError>(render(catalogs))
    })
    .await;
    match rendered {
        Ok(Ok(response)) => response,
        Ok(Err(err)) => internal_error(err),
        Err(join_error) => {
            tracing::error!(error = %join_error, "serving the catalogs panicked");
            internal_error("serving the catalogs failed")
        }
    }
}
