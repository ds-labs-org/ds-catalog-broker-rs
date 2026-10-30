//! Axum HTTP server skeleton for the federated catalog rewrite.
//!
//! Exposes a health check and a `GET /catalog` endpoint backed by
//! `rdf-store`'s `CatalogCache` trait. The catalog endpoint is
//! intentionally thin - it exists to prove the wiring between
//! `ds-catalog-broker-rs`, `catalog-core` types, and the `rdf-store` cache trait works
//! end to end, not to be a finished Management API. Query parameters,
//! pagination shape, and response JSON-LD framing (EDC's Management API
//! returns `dspace:`/`edc:` JSON-LD) are all deferred to a later
//! iteration.

pub mod config;
pub mod oauth2;
pub mod odrl_filter;
mod routes;
mod sample;
mod state;
#[cfg(test)]
mod tests;

pub use dcp_core::HolderIdentity;
pub use oauth2::{OAuth2Config, OAuth2Verifier, VerifyError};
pub use routes::build_router;
pub use sample::seed_sample_catalog;
pub use state::{AppState, SparqlLimitsConfig, crawl_limits_from_settings};
