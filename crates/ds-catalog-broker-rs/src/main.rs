use std::sync::Arc;

use ds_catalog_broker_rs::config::{self, BrokerSettings};
use ds_catalog_broker_rs::oauth2::{OAuth2Config, OAuth2Verifier};
use ds_catalog_broker_rs::odrl_filter::PolicyFilterConfig;
use ds_catalog_broker_rs::{AppState, SparqlLimitsConfig, build_router, serving};

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

    // One serving mode (see `serving`): an in-memory Oxigraph store backs
    // `GET /catalog`, the management API and `/sparql`; the crawler fills it
    // when the config lists participants. An unreadable holder credential
    // stops the broker on boot, like any other bad crawler config.
    let serving::Serving { cache, holder, .. } = serving::start(
        &settings,
        &http_client,
        tokio_util::sync::CancellationToken::new(),
    )
    .unwrap_or_else(|err| panic!("failed to start serving: {err}"));

    let mut state = AppState::new(cache)
        .with_holder(holder)
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
