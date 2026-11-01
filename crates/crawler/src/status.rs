//! What the crawler reports about itself: per-participant crawl outcomes,
//! shared with the HTTP layer for readiness and monitoring.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

/// The crawler's state as of its last finished cycle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CrawlStatus {
    /// How many crawl cycles have finished, whatever their outcome. Zero
    /// until the first one ends.
    pub cycles_completed: u64,
    /// Every configured participant, by `broker:participantId`.
    pub participants: BTreeMap<String, ParticipantStatus>,
}

/// One participant's crawl history.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParticipantStatus {
    /// When its last crawl ended, success or failure.
    pub last_attempt: Option<SystemTime>,
    /// When it was last crawled successfully.
    pub last_success: Option<SystemTime>,
    /// Why its last crawl failed; `None` once a crawl succeeds again.
    pub last_error: Option<String>,
    /// Whether a catalog of it is in the cache: true after a success, false
    /// again once the catalog expires (`CrawlLimits::max_catalog_age`).
    pub cached: bool,
}

/// [`CrawlStatus`], shared between the crawler that writes it and the
/// readers that report it. Readers only get [`Self::snapshot`]; only this
/// crate writes.
#[derive(Debug, Clone, Default)]
pub struct SharedCrawlStatus(Arc<RwLock<CrawlStatus>>);

impl SharedCrawlStatus {
    pub fn new(status: CrawlStatus) -> Self {
        Self(Arc::new(RwLock::new(status)))
    }

    /// A copy of the current status.
    pub fn snapshot(&self) -> CrawlStatus {
        // A poisoned lock only means a writer panicked mid-update; the map
        // is still whole, so keep serving it.
        self.0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn update(&self, change: impl FnOnce(&mut CrawlStatus)) {
        change(
            &mut self
                .0
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
    }
}
