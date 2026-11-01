// --- Full-store reads stay off the async workers (#27) ------------------

use super::*;
use std::time::Instant;

/// A store big enough that decoding all of it takes a noticeable time.
async fn large_state() -> AppState {
    let state = test_state();
    for participant in 0..150 {
        let mut catalog = participant_catalog(
            &format!("node-{participant}"),
            &format!("cat-{participant}"),
            "DATASET-0",
        );
        for dataset in 1..40 {
            let mut extra = catalog.datasets[0].clone();
            extra.id = format!("DATASET-{dataset}");
            catalog.datasets.push(extra);
        }
        state.cache.upsert(catalog).await.unwrap();
    }
    state
}

/// Serve `request` on this single-threaded runtime while a ticker task
/// tries to wake every 5 ms, and return the longest the ticker had to
/// wait. A route that decodes the store on the async worker holds the
/// only thread, so the ticker stalls for the whole decode.
async fn longest_stall_while_serving(state: AppState, request: Request<Body>) -> Duration {
    let app = build_router(state);
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ticker = {
        let stop = Arc::clone(&stop);
        tokio::spawn(async move {
            let mut longest = Duration::ZERO;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let before = Instant::now();
                tokio::time::sleep(Duration::from_millis(5)).await;
                longest = longest.max(before.elapsed());
            }
            longest
        })
    };
    // Let the ticker start its first sleep.
    tokio::task::yield_now().await;
    let response = app.oneshot(request).await.unwrap();
    assert!(response.status().is_success(), "{}", response.status());
    response.into_body().collect().await.unwrap();
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    ticker.await.unwrap()
}

const STALL_LIMIT: Duration = Duration::from_millis(100);

#[tokio::test(flavor = "current_thread")]
async fn policy_filtered_sparql_does_not_stall_the_async_worker() {
    let state = large_state().await;
    let uri = format!("/sparql?query={}", urlencoding::encode("ASK { ?s ?p ?o }"));
    let stall = longest_stall_while_serving(
        state,
        Request::builder().uri(uri).body(Body::empty()).unwrap(),
    )
    .await;
    assert!(
        stall < STALL_LIMIT,
        "the async worker stalled for {stall:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn get_catalog_does_not_stall_the_async_worker() {
    let state = large_state().await;
    let stall = longest_stall_while_serving(
        state,
        Request::builder()
            .uri("/catalog")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert!(
        stall < STALL_LIMIT,
        "the async worker stalled for {stall:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn the_management_catalog_request_does_not_stall_the_async_worker() {
    let state = large_state().await;
    let stall = longest_stall_while_serving(state, catalog_request(Body::from("{}"))).await;
    assert!(
        stall < STALL_LIMIT,
        "the async worker stalled for {stall:?}"
    );
}
