use super::*;

use crate::serving;
use tokio_util::sync::CancellationToken;

fn settings(ttl: &str) -> config::BrokerSettings {
    let prefix = "@prefix broker: <https://catalog-broker.ds-labs.org/ontologies/config#> .\n";
    config::BrokerSettings::from_turtle(format!("{prefix}{ttl}").as_bytes(), None, "test").unwrap()
}

/// With no participant, `main` serves an empty Oxigraph store, `/sparql`
/// included, and starts no crawler.
#[tokio::test]
async fn no_participant_serves_an_empty_store_with_sparql() {
    let serving = serving::start(
        &settings("<urn:c> a broker:BrokerConfig .\n"),
        &reqwest::Client::new(),
        CancellationToken::new(),
    )
    .unwrap();
    assert!(serving.crawler.is_none());
    assert!(serving.holder.is_none());
    assert!(
        serving
            .cache
            .query(CatalogQuery::all())
            .await
            .unwrap()
            .is_empty()
    );

    let app = build_router(AppState::new(serving.cache));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/sparql?query=ASK%20%7B%20%3Fs%20%3Fp%20%3Fo%20%7D")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// With a participant, the crawler is started on the same store the
/// routes read.
#[tokio::test]
async fn a_participant_starts_the_crawler() {
    let serving = serving::start(
        &settings(
            "<urn:c> a broker:BrokerConfig ; broker:participant <urn:p> .\n\
             <urn:p> a broker:Participant ; broker:participantId \"p\" ;\n\
               broker:participantName \"P\" ; broker:catalogRequestUrl \"http://127.0.0.1:1/c\" .\n",
        ),
        &reqwest::Client::new(),
        CancellationToken::new(),
    )
    .unwrap();
    let crawler = serving.crawler.expect("a participant starts the crawler");
    crawler.handle.abort();
}

/// Cancelling the shutdown token stops the crawler `start` started.
#[tokio::test]
async fn cancelling_shutdown_stops_the_crawler() {
    let shutdown = CancellationToken::new();
    let serving = serving::start(
        &settings(
            "<urn:c> a broker:BrokerConfig ; broker:participant <urn:p> .\n\
             <urn:p> a broker:Participant ; broker:participantId \"p\" ;\n\
               broker:participantName \"P\" ; broker:catalogRequestUrl \"http://127.0.0.1:1/c\" .\n",
        ),
        &reqwest::Client::new(),
        shutdown.clone(),
    )
    .unwrap();
    shutdown.cancel();
    let stopped =
        tokio::time::timeout(Duration::from_secs(2), serving.crawler.unwrap().handle).await;
    assert!(matches!(stopped, Ok(Ok(()))), "{stopped:?}");
}

/// An unreadable holder credential is an error, not a panic.
#[tokio::test]
async fn an_unreadable_holder_credential_is_an_error() {
    let result = serving::start(
        &settings(
            "<urn:c> a broker:BrokerConfig ; broker:participant <urn:p> ; broker:holder <urn:h> .\n\
             <urn:p> a broker:Participant ; broker:participantId \"p\" ;\n\
               broker:participantName \"P\" ; broker:catalogRequestUrl \"http://127.0.0.1:1/c\" .\n\
             <urn:h> a broker:Holder ; broker:ownDidHost \"h\" ; broker:requiredScope \"s\" ;\n\
               broker:credentialJwsFile \"/nonexistent/holder.jws\" .\n",
        ),
        &reqwest::Client::new(),
        CancellationToken::new(),
    );
    assert!(
        matches!(result, Err(serving::ServingError::Holder(_))),
        "{:?}",
        result.err()
    );
}

/// The graceful-shutdown future waits `delay` after the token is cancelled.
#[tokio::test(start_paused = true)]
async fn stop_after_waits_the_delay_after_shutdown() {
    let shutdown = CancellationToken::new();
    let stop = tokio::spawn(serving::stop_after(
        shutdown.clone(),
        Duration::from_secs(5),
    ));
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert!(!stop.is_finished(), "nothing happens before the signal");
    shutdown.cancel();
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(
        !stop.is_finished(),
        "the listener stays open during the delay"
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(stop.is_finished());
}

#[test]
fn the_shutdown_delay_comes_from_the_config() {
    let unset = config::BrokerSettings::from_values([]).unwrap();
    assert_eq!(crate::shutdown_delay_from_settings(&unset), Duration::ZERO);
    let set =
        config::BrokerSettings::from_values([("shutdownDelaySecs".to_string(), "7".to_string())])
            .unwrap();
    assert_eq!(
        crate::shutdown_delay_from_settings(&set),
        Duration::from_secs(7)
    );
}
