use std::sync::Arc;

use crawler::HolderConfig;
use dcp_core::HolderIdentity;
use ds_catalog_broker_rs::config::{self, BrokerSettings};
use ds_catalog_broker_rs::oauth2::{OAuth2Config, OAuth2Verifier};
use ds_catalog_broker_rs::odrl_filter::PolicyFilterConfig;
use ds_catalog_broker_rs::{
    AppState, SparqlLimitsConfig, build_router, crawl_limits_from_settings, seed_sample_catalog,
};
use rdf_store::CatalogCache;
use rdf_store::memory::InMemoryCatalogCache;

const DEFAULT_ADDR: &str = "127.0.0.1:8080";

/// Reads the `broker:oauth2*` settings (see
/// `docs/oauth2-bearer-gating-2026-08-28.md`'s config table) and builds an
/// [`OAuth2Config`], the same "presence of the required setting decides
/// opt-in" shape as the crawler (on when `broker:participant` is set).
/// `broker:oauth2JwksUri` unset ->
/// `None`, and gating stays off - byte-identical behavior to before this
/// feature existed. `oauth2Issuer`/`oauth2Audience`/`oauth2RequiredScope`
/// are all optional and independent of each other.
fn load_oauth2_config(settings: &BrokerSettings) -> Option<OAuth2Config> {
    let jwks_uri = settings.get(config::OAUTH2_JWKS_URI)?;
    Some(OAuth2Config {
        jwks_uri,
        issuer: settings.get(config::OAUTH2_ISSUER),
        audience: settings.get(config::OAUTH2_AUDIENCE),
        required_scope: settings.get(config::OAUTH2_REQUIRED_SCOPE),
    })
}

/// Builds this connector's own DCP holder identity, reading its credential
/// from `broker:credentialJwsFile`. An unreadable file panics on boot, like
/// any other bad crawler config.
fn build_holder(holder: &HolderConfig) -> Arc<HolderIdentity> {
    let credential_jws = holder
        .read_credential_jws()
        .unwrap_or_else(|err| panic!("failed to load the holder credential: {err}"));
    Arc::new(HolderIdentity::new(
        holder.own_did_host.clone(),
        holder.insecure_http,
        credential_jws,
        holder.required_scope.clone(),
    ))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let http_client = reqwest::Client::new();

    // The Turtle config (see `ds_catalog_broker_rs::config`'s module doc).
    // An explicit `CONFIG_STORE_PATH` (path or URL) that cannot be read panics on boot,
    // and so does an invalid participant or holder resource in it.
    let settings = BrokerSettings::load(&http_client)
        .await
        .unwrap_or_else(|err| panic!("failed to load the broker configuration: {err}"));

    let addr = settings
        .get(config::HTTP_API_ADDR)
        .unwrap_or_else(|| DEFAULT_ADDR.to_string());

    // broker:oauth2JwksUri unset: `oauth2_verifier` stays `None` and both gated
    // routes are byte-identical to before this feature existed (see
    // `AppState::oauth2`'s doc comment). Set: fetched eagerly, here, before
    // `AppState` is built - a bad/unreachable JWKS panics on boot rather
    // than silently starting unauthenticated, the same failure posture as
    // a bad participant or holder in the config.
    let oauth2_verifier = match load_oauth2_config(&settings) {
        Some(config) => {
            let jwks_uri = config.jwks_uri.clone();
            let verifier = OAuth2Verifier::fetch(&http_client, config)
                .await
                .unwrap_or_else(|err| {
                    panic!("failed to fetch/verify oauth2JwksUri={jwks_uri:?}: {err}")
                });
            Some(Arc::new(verifier))
        }
        None => None,
    };
    tracing::info!(
        oauth2_gating_active = oauth2_verifier.is_some(),
        "oauth2 bearer gating configuration resolved (oauth2JwksUri unset means both /catalog and /sparql stay unauthenticated)"
    );

    // No broker:participant in the config: a plain in-memory HashMap cache,
    // seeded with one placeholder sample catalog, no crawler started.
    //
    // At least one broker:participant: this connector now works the way EDC's own
    // federated catalog does - a periodic, config-driven crawl populates a
    // real RDF (Oxigraph) store, which the DSP catalog endpoint then
    // serves. In-memory only, same as EDC's own federated-catalog cache:
    // there is no on-disk persistence option here either, by design, not
    // as a gap - see `rdf_store::oxigraph_backend`'s module doc for the
    // backend itself and `crates/crawler`'s doc comments for the crawl
    // loop. `InMemoryCatalogCache` (a plain `HashMap`, not backed by RDF
    // at all) stays the default when no participant is configured.
    type CacheHolderSparql = (
        Arc<dyn CatalogCache>,
        Option<Arc<HolderIdentity>>,
        Option<Arc<rdf_store::oxigraph_backend::OxigraphCatalogCache>>,
    );
    let (cache, holder, sparql): CacheHolderSparql = match settings.crawler().cloned() {
        Some(config) => {
            // Kept as a concrete `Arc<OxigraphCatalogCache>` (not just the
            // `Arc<dyn CatalogCache>` coercion below) purely so `AppState`
            // can also wire up `/sparql` against it - see
            // `AppState::sparql`'s own doc comment for why that can't be
            // recovered from the trait object alone.
            let store = Arc::new(
                rdf_store::oxigraph_backend::OxigraphCatalogCache::in_memory()
                    .expect("open in-memory Oxigraph store"),
            );
            let cache: Arc<dyn CatalogCache> = store.clone();
            let holder = config.holder.as_ref().map(build_holder);
            let limits = crawl_limits_from_settings(&settings);
            tracing::info!(
                participants = config.participants.len(),
                interval_secs = config.interval_secs,
                holder_configured = holder.is_some(),
                timeout_ms = limits.participant_timeout.as_millis() as u64,
                concurrency = limits.concurrency,
                max_catalog_age_secs = limits.max_catalog_age.as_secs(),
                "starting scheduled catalog crawler; serving from an in-memory Oxigraph store, with /sparql enabled"
            );
            crawler::spawn_scheduler(
                cache.clone(),
                config,
                http_client.clone(),
                holder.clone(),
                limits,
            );
            (cache, holder, Some(store))
        }
        None => {
            // No crawler configured: the plain in-memory cache, seeded
            // with one sample catalog - this stands in for a real crawl
            // result until a broker:participant is configured. No SPARQL backend
            // either (see `AppState::sparql`'s doc comment): `/sparql`
            // answers 501 until a real Oxigraph-backed crawl is running.
            let cache: Arc<dyn CatalogCache> = Arc::new(InMemoryCatalogCache::new());
            seed_sample_catalog(&*cache)
                .await
                .expect("seeding sample catalog failed");
            (cache, None, None)
        }
    };

    let mut state = AppState::new(cache)
        .with_holder(holder)
        .with_sparql(sparql)
        .with_oauth2(oauth2_verifier)
        .with_policy_filter(PolicyFilterConfig::from_settings(&settings))
        .with_sparql_limits(SparqlLimitsConfig::from_settings(&settings));
    state.http = http_client;
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|err| panic!("failed to bind {addr}: {err}"));
    tracing::info!("ds-catalog-broker-rs listening on {addr}");

    axum::serve(listener, app)
        .await
        .expect("ds-catalog-broker-rs server failed");
}
