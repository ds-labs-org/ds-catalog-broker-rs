use super::*;

use std::sync::RwLock;
use std::time::SystemTime;

use crawler::{CrawlStatus, ParticipantStatus};

async fn get_ready(state: AppState) -> (StatusCode, serde_json::Value) {
    let response = build_router(state)
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap())
}

/// With no crawler there is nothing to wait for.
#[tokio::test]
async fn ready_without_a_crawler() {
    let (status, body) = get_ready(test_state()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        serde_json::json!({"status": "ready", "crawler": null})
    );
}

/// With a crawler, `/ready` answers 503 until the first cycle has finished.
#[tokio::test]
async fn not_ready_before_the_first_crawl_cycle() {
    let crawl_status = Arc::new(RwLock::new(CrawlStatus::default()));
    let (status, body) = get_ready(test_state().with_crawl_status(Some(crawl_status))).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["status"], "starting");
    assert_eq!(body["crawler"]["cycles_completed"], 0);
}

/// After a cycle, every participant's status is listed.
#[tokio::test]
async fn ready_after_a_cycle_reports_each_participant() {
    let now = SystemTime::now();
    let mut crawl_status = CrawlStatus {
        cycles_completed: 3,
        ..CrawlStatus::default()
    };
    crawl_status.participants.insert(
        "a".to_string(),
        ParticipantStatus {
            last_attempt: Some(now),
            last_success: Some(now - Duration::from_secs(90)),
            last_error: Some("timed out".to_string()),
            cached: true,
        },
    );
    crawl_status.participants.insert(
        "b".to_string(),
        ParticipantStatus {
            last_attempt: Some(now),
            last_success: None,
            last_error: Some("connection refused".to_string()),
            cached: false,
        },
    );
    let state = test_state().with_crawl_status(Some(Arc::new(RwLock::new(crawl_status))));
    let (status, body) = get_ready(state).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ready");
    assert_eq!(body["crawler"]["cycles_completed"], 3);
    let participants = body["crawler"]["participants"].as_array().unwrap();
    assert_eq!(participants.len(), 2);
    let a = &participants[0];
    assert_eq!(a["id"], "a");
    assert_eq!(a["cached"], true);
    assert_eq!(a["last_error"], "timed out");
    assert!(a["last_success"].is_string(), "{a}");
    assert!(a["last_attempt"].is_string(), "{a}");
    let age = a["catalog_age_secs"].as_u64().unwrap();
    assert!((90..100).contains(&age), "{a}");
    let b = &participants[1];
    assert_eq!(b["id"], "b");
    assert_eq!(b["cached"], false);
    assert!(b["last_success"].is_null());
    assert!(
        b["catalog_age_secs"].is_null(),
        "no cached catalog has no age"
    );
}

/// `/health` stays a plain liveness check.
#[tokio::test]
async fn health_stays_a_liveness_check_while_not_ready() {
    let crawl_status = Arc::new(RwLock::new(CrawlStatus::default()));
    let response = build_router(test_state().with_crawl_status(Some(crawl_status)))
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
