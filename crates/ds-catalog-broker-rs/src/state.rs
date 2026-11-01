//! Shared application state and the runtime limits read from the broker
//! config.

use std::sync::Arc;
use std::time::Duration;

use rdf_store::oxigraph_backend::OxigraphCatalogCache;

use crate::oauth2::OAuth2Verifier;
use crate::{HolderIdentity, config, odrl_filter};

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    /// The Oxigraph store every route serves from: `GET /catalog`, the
    /// management API and `/sparql` (through
    /// `OxigraphCatalogCache::sparql_query_json`, which is not on the
    /// `CatalogCache` trait). The crawler writes into the same store; with
    /// no participant configured it simply stays empty.
    pub cache: Arc<OxigraphCatalogCache>,
    /// Shared HTTP client for this connector's own DCP *holder* role's
    /// outbound calls - `reqwest::Client` is cheap to clone (internally
    /// `Arc`-backed) and reuses connection pooling, so one instance lives
    /// on `AppState` rather than being constructed per request.
    pub http: reqwest::Client,
    /// This connector's own DCP *holder* identity - set only when a
    /// `broker:Holder` is configured alongside at least one participant (see `main.rs`).
    /// `None` means this connector presents no credential of its own and
    /// the two `/dsp/holder/*` routes (`routes::holder`) 404.
    pub holder: Option<Arc<HolderIdentity>>,
    /// The OAuth2 Bearer resource-server gate for `GET /catalog` and
    /// `GET`/`POST /sparql` - see `oauth2`'s module doc and
    /// `docs/oauth2-bearer-gating-2026-08-28.md`. `Some` means gating is
    /// active (set only when `broker:oauth2JwksUri` was configured, see
    /// `main.rs`); `None` (the default) leaves both routes exactly as
    /// unauthenticated as before this feature existed. Never gates
    /// `/health` or the two `/dsp/holder/*` routes - those are unaffected
    /// by this field entirely.
    pub oauth2: Option<Arc<OAuth2Verifier>>,
    /// ODRL policy-based dataset-visibility filtering configuration (gap
    /// analysis §3.4) - see `odrl_filter::PolicyFilterConfig`'s own doc
    /// comment for the three conservative-by-default judgment calls it
    /// makes explicit. Defaults to `PolicyFilterConfig::default()`.
    ///
    /// Consulted by `filter_catalogs_by_policy`, called from both
    /// `GET /catalog` and `POST /api/management/v4/catalogs/request` -
    /// see `src/tests/policy.rs` for the behavior this drives.
    pub policy_filter: odrl_filter::PolicyFilterConfig,
    /// Time and size bounds on every `/sparql` evaluation - see
    /// [`SparqlLimitsConfig`]. Defaults to `SparqlLimitsConfig::default()`.
    pub sparql_limits: SparqlLimitsConfig,
    /// One permit per `/sparql` evaluation allowed to run at once
    /// ([`SparqlLimitsConfig::max_concurrent`]); set with `sparql_limits`.
    pub sparql_slots: Arc<tokio::sync::Semaphore>,
    /// What the crawler reports, for `GET /ready`. `None` when no crawler
    /// runs (no `broker:participant`), in which case the broker is ready
    /// as soon as it serves.
    pub crawl_status: Option<crawler::SharedCrawlStatus>,
    /// Cancelled when the broker starts shutting down; from then on
    /// `GET /ready` answers 503 `stopping`. `None` in tests that never stop.
    pub shutdown: Option<tokio_util::sync::CancellationToken>,
}

/// Bounds on one `GET`/`POST /sparql` evaluation, so a caller-supplied
/// query (every query shape is accepted, unauthenticated by default)
/// cannot hold a worker thread or build an unbounded response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparqlLimitsConfig {
    /// How long evaluation may run before it is cancelled and the caller
    /// gets `503 Service Unavailable`. Default: 10 seconds.
    pub timeout: Duration,
    /// The most `SELECT` rows one response may hold; a larger result is
    /// rejected with `400 Bad Request` rather than truncated. Default:
    /// 10,000.
    pub max_rows: usize,
    /// How many evaluations may run at once. A query over the limit gets
    /// `503 Service Unavailable` straight away. An evaluation keeps its
    /// slot until it actually stops, which can be after its timeout:
    /// oxigraph only checks for cancellation when it reads the store, so
    /// in-memory work (a `VALUES` cross product, say) runs to the end.
    /// Default: 4.
    pub max_concurrent: usize,
}

impl Default for SparqlLimitsConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            max_rows: 10_000,
            max_concurrent: 4,
        }
    }
}

impl SparqlLimitsConfig {
    /// Reads `broker:sparqlQueryTimeoutMs`, `broker:sparqlMaxRows` and
    /// `broker:sparqlMaxConcurrent` (positive integers) from the broker config. Unset is the default; any other value was checked
    /// when the config was read.
    pub fn from_settings(settings: &config::BrokerSettings) -> Self {
        let default = Self::default();
        let timeout_ms = settings
            .positive_integer(config::SPARQL_QUERY_TIMEOUT_MS)
            .unwrap_or(default.timeout.as_millis() as usize);
        Self {
            timeout: Duration::from_millis(timeout_ms as u64),
            max_rows: settings
                .positive_integer(config::SPARQL_MAX_ROWS)
                .unwrap_or(default.max_rows),
            max_concurrent: settings
                .positive_integer(config::SPARQL_MAX_CONCURRENT)
                .unwrap_or(default.max_concurrent),
        }
    }
}

/// Reads `broker:crawlTimeoutMs`, `broker:crawlConcurrency` and
/// `broker:catalogMaxAgeSecs` (positive integers) from the broker config into
/// the crawler's [`crawler::CrawlLimits`]. Unset is the default; any other
/// value was checked when the config was read.
pub fn crawl_limits_from_settings(settings: &config::BrokerSettings) -> crawler::CrawlLimits {
    let default = crawler::CrawlLimits::default();
    crawler::CrawlLimits {
        participant_timeout: settings
            .positive_integer(config::CRAWL_TIMEOUT_MS)
            .map_or(default.participant_timeout, |ms| {
                Duration::from_millis(ms as u64)
            }),
        concurrency: settings
            .positive_integer(config::CRAWL_CONCURRENCY)
            .unwrap_or(default.concurrency),
        max_catalog_age: settings
            .positive_integer(config::CATALOG_MAX_AGE_SECS)
            .map_or(default.max_catalog_age, |secs| {
                Duration::from_secs(secs as u64)
            }),
    }
}

/// Reads `broker:shutdownDelaySecs`: how long to keep serving after a
/// shutdown signal, with `/ready` already failing. Unset: no delay.
pub fn shutdown_delay_from_settings(settings: &config::BrokerSettings) -> Duration {
    settings
        .positive_integer(config::SHUTDOWN_DELAY_SECS)
        .map_or(Duration::ZERO, |secs| Duration::from_secs(secs as u64))
}

impl AppState {
    pub fn new(cache: Arc<OxigraphCatalogCache>) -> Self {
        Self {
            cache,
            http: reqwest::Client::new(),
            holder: None,
            oauth2: None,
            policy_filter: odrl_filter::PolicyFilterConfig::default(),
            sparql_slots: Arc::new(tokio::sync::Semaphore::new(
                SparqlLimitsConfig::default().max_concurrent,
            )),
            sparql_limits: SparqlLimitsConfig::default(),
            crawl_status: None,
            shutdown: None,
        }
    }

    /// Builder-style setter for this connector's own DCP holder identity.
    /// See the `holder` field's doc comment.
    pub fn with_holder(mut self, holder: Option<Arc<HolderIdentity>>) -> Self {
        self.holder = holder;
        self
    }

    /// Builder-style setter for the OAuth2 Bearer gate. See the `oauth2`
    /// field's doc comment.
    pub fn with_oauth2(mut self, oauth2: Option<Arc<OAuth2Verifier>>) -> Self {
        self.oauth2 = oauth2;
        self
    }

    /// Builder-style setter for the ODRL policy-filtering config. See the
    /// `policy_filter` field's doc comment.
    pub fn with_policy_filter(mut self, policy_filter: odrl_filter::PolicyFilterConfig) -> Self {
        self.policy_filter = policy_filter;
        self
    }

    /// Builder-style setter for the `/sparql` limits. See the
    /// `sparql_limits` field's doc comment.
    pub fn with_sparql_limits(mut self, sparql_limits: SparqlLimitsConfig) -> Self {
        self.sparql_slots = Arc::new(tokio::sync::Semaphore::new(sparql_limits.max_concurrent));
        self.sparql_limits = sparql_limits;
        self
    }

    /// Builder-style setter for the crawler's status. See the
    /// `crawl_status` field's doc comment.
    pub fn with_crawl_status(mut self, crawl_status: Option<crawler::SharedCrawlStatus>) -> Self {
        self.crawl_status = crawl_status;
        self
    }

    /// Builder-style setter for the shutdown token. See the `shutdown`
    /// field's doc comment.
    pub fn with_shutdown(mut self, shutdown: tokio_util::sync::CancellationToken) -> Self {
        self.shutdown = Some(shutdown);
        self
    }
}
