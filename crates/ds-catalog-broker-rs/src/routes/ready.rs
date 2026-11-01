//! `GET /ready`: readiness, with the crawler's per-participant status.
//!
//! `/health` answers as soon as the process serves (liveness). `/ready`
//! answers `503` until the crawler has finished its first cycle, so a load
//! balancer does not send traffic to a broker that has not crawled yet.
//! With no crawler configured there is nothing to wait for. Not gated by
//! OAuth2, like `/health`: probes carry no token.

use std::time::{Duration, SystemTime};

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use chrono::{DateTime, SecondsFormat, Utc};
use crawler::CrawlStatus;
use serde::Serialize;

use crate::AppState;

#[derive(Debug, Serialize)]
pub(crate) struct ReadyResponse {
    /// `ready` or `starting`.
    status: &'static str,
    /// `None` when no crawler runs.
    crawler: Option<CrawlerReport>,
}

#[derive(Debug, Serialize)]
struct CrawlerReport {
    cycles_completed: u64,
    participants: Vec<ParticipantReport>,
}

#[derive(Debug, Serialize)]
struct ParticipantReport {
    id: String,
    /// RFC 3339, UTC.
    last_attempt: Option<String>,
    /// RFC 3339, UTC.
    last_success: Option<String>,
    last_error: Option<String>,
    cached: bool,
    /// Seconds since the cached catalog was crawled; `None` when nothing
    /// is cached.
    catalog_age_secs: Option<u64>,
}

pub(super) async fn ready(State(state): State<AppState>) -> impl IntoResponse {
    let Some(shared) = &state.crawl_status else {
        return (
            StatusCode::OK,
            Json(ReadyResponse {
                status: "ready",
                crawler: None,
            }),
        );
    };
    let snapshot = shared
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let (code, status) = if snapshot.cycles_completed == 0 {
        (StatusCode::SERVICE_UNAVAILABLE, "starting")
    } else {
        (StatusCode::OK, "ready")
    };
    (
        code,
        Json(ReadyResponse {
            status,
            crawler: Some(report(&snapshot, SystemTime::now())),
        }),
    )
}

fn report(status: &CrawlStatus, now: SystemTime) -> CrawlerReport {
    CrawlerReport {
        cycles_completed: status.cycles_completed,
        participants: status
            .participants
            .iter()
            .map(|(id, participant)| ParticipantReport {
                id: id.clone(),
                last_attempt: participant.last_attempt.map(rfc3339),
                last_success: participant.last_success.map(rfc3339),
                last_error: participant.last_error.clone(),
                cached: participant.cached,
                catalog_age_secs: participant
                    .last_success
                    .filter(|_| participant.cached)
                    .map(|at| now.duration_since(at).unwrap_or(Duration::ZERO).as_secs()),
            })
            .collect(),
    }
}

fn rfc3339(at: SystemTime) -> String {
    DateTime::<Utc>::from(at).to_rfc3339_opts(SecondsFormat::Secs, true)
}
