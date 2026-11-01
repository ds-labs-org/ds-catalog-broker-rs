use std::sync::Arc;

use ds_catalog_broker_rs::config::{self, BrokerSettings};
use ds_catalog_broker_rs::oauth2::{OAuth2Config, OAuth2Verifier};
use ds_catalog_broker_rs::odrl_filter::PolicyFilterConfig;
use std::future::IntoFuture;

use ds_catalog_broker_rs::{
    AppState, SparqlLimitsConfig, build_router, serving, shutdown_delay_from_settings,
};
use tokio_util::sync::CancellationToken;

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
    let shutdown = CancellationToken::new();
    let draining = CancellationToken::new();
    let serving::Serving {
        cache,
        holder,
        crawler,
    } = serving::start(&settings, &http_client, shutdown.clone())
        .unwrap_or_else(|err| panic!("failed to start serving: {err}"));

    let mut state = AppState::new(cache)
        .with_holder(holder)
        .with_oauth2(oauth2_verifier)
        .with_policy_filter(PolicyFilterConfig::from_settings(&settings))
        .with_sparql_limits(SparqlLimitsConfig::from_settings(&settings))
        .with_crawl_status(crawler.as_ref().map(|c| c.status.clone()))
        .with_shutdown(shutdown.clone())
        .with_draining(draining.clone());
    state.http = http_client;
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|err| panic!("failed to bind {addr}: {err}"));
    tracing::info!("ds-catalog-broker-rs listening on {addr}");

    tokio::spawn(handle_signals(shutdown.clone()));
    // On SIGTERM or SIGINT: /ready starts failing and the crawler stops
    // (interrupting a cycle in flight); after broker:shutdownDelaySecs the
    // listener closes and in-flight requests are drained, with running
    // /sparql evaluations stopped.
    let stop = serving::stop_after(shutdown.clone(), shutdown_delay_from_settings(&settings));
    let server = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            stop.await;
            draining.cancel();
        })
        .into_future();
    let mut server = std::pin::pin!(server);
    match crawler {
        None => server.await.expect("ds-catalog-broker-rs server failed"),
        Some(crawler) => {
            let mut scheduler = crawler.handle;
            tokio::select! {
                served = &mut server => {
                    served.expect("ds-catalog-broker-rs server failed");
                    shutdown.cancel();
                    if let Err(err) = scheduler.await {
                        tracing::error!(error = %err, "the crawl scheduler ended abnormally");
                    }
                }
                ended = &mut scheduler => {
                    if !shutdown.is_cancelled() {
                        // The crawler is gone, so catalogs would go stale
                        // while /ready kept answering: exit, so the
                        // supervisor restarts the broker.
                        tracing::error!(outcome = ?ended, "the crawl scheduler stopped unexpectedly; exiting");
                        std::process::exit(1);
                    }
                    if let Err(err) = ended {
                        tracing::error!(error = %err, "the crawl scheduler ended abnormally");
                    }
                    server.await.expect("ds-catalog-broker-rs server failed");
                }
            }
        }
    }
    tracing::info!("ds-catalog-broker-rs stopped");
}

/// Cancel `shutdown` on the first SIGTERM or SIGINT (Ctrl-C), and exit at
/// once on a second one, for when draining takes too long.
async fn handle_signals(shutdown: CancellationToken) {
    let first = next_signal().await;
    tracing::info!("{first} received; shutting down (send it again to exit at once)");
    shutdown.cancel();
    let second = next_signal().await;
    tracing::warn!("{second} received again; exiting without draining");
    std::process::exit(130);
}

/// Wait for the next SIGINT or SIGTERM and name it.
async fn next_signal() -> &'static str {
    let interrupt = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %err, "cannot listen for SIGINT");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(err) => {
                tracing::error!(error = %err, "cannot listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => "SIGINT",
        () = terminate => "SIGTERM",
    }
}
