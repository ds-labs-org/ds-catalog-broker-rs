//! `GET /ready`: readiness, with the crawler's per-participant status.
//!
//! `/health` answers as soon as the process serves (liveness). `/ready`
//! answers `503 starting` until the crawler has finished its first cycle, so
//! a load balancer does not send traffic to a broker that has not crawled
//! yet, and `503 stopping` once shutdown has begun, so traffic drains away
//! before the listener closes.
//!
//! It does not wait for the first cycle when there is no crawler, or when a
//! holder is configured: a DCP or OID4VP crawl needs the remote side to call
//! back into `/dsp/holder/*` on this broker, which a readiness-gated load
//! balancer would block, failing that very cycle.
//!
//! Probes carry no token, so `/ready` always answers. With OAuth2 on, the
//! per-participant details (ids, upstream error text) are shown only to a
//! caller with a valid token; everyone else gets the status and cycle count.

use std::time::{Duration, SystemTime};

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use chrono::{DateTime, SecondsFormat, Utc};
use crawler::{CrawlStatus, SharedCrawlStatus};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use super::auth::check_oauth2_bearer;
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
    /// Left out for a caller without a valid token when OAuth2 is on.
    #[serde(skip_serializing_if = "Option::is_none")]
    participants: Option<Vec<ParticipantReport>>,
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

pub(super) async fn ready(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let stopping = state
        .shutdown
        .as_ref()
        .is_some_and(CancellationToken::is_cancelled);
    let show_details =
        state.oauth2.is_none() || matches!(check_oauth2_bearer(&state, &headers), Ok(Some(_)));
    let snapshot = state.crawl_status.as_ref().map(SharedCrawlStatus::snapshot);
    let waits_for_first_cycle = state.holder.is_none();
    let (code, status) = match &snapshot {
        _ if stopping => (StatusCode::SERVICE_UNAVAILABLE, "stopping"),
        Some(crawl) if crawl.cycles_completed == 0 && waits_for_first_cycle => {
            (StatusCode::SERVICE_UNAVAILABLE, "starting")
        }
        _ => (StatusCode::OK, "ready"),
    };
    (
        code,
        Json(ReadyResponse {
            status,
            crawler: snapshot.map(|crawl| report(&crawl, SystemTime::now(), show_details)),
        }),
    )
}

fn report(status: &CrawlStatus, now: SystemTime, show_details: bool) -> CrawlerReport {
    CrawlerReport {
        cycles_completed: status.cycles_completed,
        participants: show_details.then(|| {
            status
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
                .collect()
        }),
    }
}

fn rfc3339(at: SystemTime) -> String {
    DateTime::<Utc>::from(at).to_rfc3339_opts(SecondsFormat::Secs, true)
}
