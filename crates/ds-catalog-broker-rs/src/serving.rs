//! The one serving mode: the store every route reads, and the crawler that
//! fills it when the config lists participants.

use std::sync::Arc;

use dcp_core::HolderIdentity;
use rdf_store::oxigraph_backend::OxigraphCatalogCache;

use crate::config::BrokerSettings;
use crate::crawl_limits_from_settings;

/// What `main` serves from.
pub struct Serving {
    /// The in-memory Oxigraph store behind every route. Empty until a crawl
    /// writes to it, and forever empty with no participant.
    pub cache: Arc<OxigraphCatalogCache>,
    /// The crawler's holder identity, when the config has a `broker:holder`
    /// and at least one participant.
    pub holder: Option<Arc<HolderIdentity>>,
    /// The crawl scheduler, when the config lists at least one participant.
    pub crawler: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Debug, thiserror::Error)]
pub enum ServingError {
    #[error("failed to open the in-memory Oxigraph store: {0}")]
    Store(#[from] rdf_store::StoreError),
    #[error("failed to load the holder credential: {0}")]
    Holder(#[from] crawler::ConfigError),
}

/// Open the store and, when `settings` lists participants, start the crawl
/// scheduler on it. Must be called inside a Tokio runtime.
pub fn start(settings: &BrokerSettings, http: &reqwest::Client) -> Result<Serving, ServingError> {
    let cache = Arc::new(OxigraphCatalogCache::in_memory()?);
    let Some(config) = settings.crawler().cloned() else {
        tracing::info!("no broker:participant configured; the catalog stays empty");
        return Ok(Serving {
            cache,
            holder: None,
            crawler: None,
        });
    };

    let holder = config.holder.as_ref().map(build_holder).transpose()?;
    let limits = crawl_limits_from_settings(settings);
    tracing::info!(
        participants = config.participants.len(),
        interval_secs = config.interval_secs,
        holder_configured = holder.is_some(),
        timeout_ms = limits.participant_timeout.as_millis() as u64,
        concurrency = limits.concurrency,
        max_catalog_age_secs = limits.max_catalog_age.as_secs(),
        "starting scheduled catalog crawler"
    );
    let crawler =
        crawler::spawn_scheduler(cache.clone(), config, http.clone(), holder.clone(), limits);
    Ok(Serving {
        cache,
        holder,
        crawler: Some(crawler),
    })
}

/// This connector's own DCP holder identity, with its credential read from
/// `broker:credentialJwsFile`.
fn build_holder(holder: &crawler::HolderConfig) -> Result<Arc<HolderIdentity>, ServingError> {
    Ok(Arc::new(HolderIdentity::new(
        holder.own_did_host.clone(),
        holder.insecure_http,
        holder.read_credential_jws()?,
        holder.required_scope.clone(),
    )))
}
