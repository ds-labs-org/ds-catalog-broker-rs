//! The one serving mode: the store every route reads, and the crawler that
//! fills it when the config lists participants.

use std::sync::Arc;

use dcp_core::HolderIdentity;
use rdf_store::oxigraph_backend::OxigraphCatalogCache;

use crate::config::BrokerSettings;

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
    let _ = (settings, http);
    todo!()
}
