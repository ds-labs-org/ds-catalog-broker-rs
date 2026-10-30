//! The sample catalog a server started without a crawler serves.

use catalog_core::{Catalog, DataService, Dataset, Distribution, NodeId};
use rdf_store::{CatalogCache, StoreResult};

/// Seed `cache` with one sample catalog, so a freshly started server (or a
/// test) has something real to serve from `GET /catalog` before any
/// crawler exists to populate it.
///
/// This stands in for the not-yet-built crawler: it upserts exactly the
/// same way a real crawl result would, through the public `CatalogCache`
/// trait, so it exercises the same end-to-end path as production code
/// rather than poking the cache's internals.
///
/// Dataset ids (`CAT0101`, `CAT0102`) are deliberately aligned with
/// `vendor/eclipse-edc-connector`'s own DSP-TCK seed data
/// (`system-tests/tck/tck-extension/.../DataSeed.java`), specifically the
/// `CAT0xxx`-prefixed subset it reserves for the catalog-protocol test
/// group (as opposed to its `ACN0xxx`/`ATP0xxx` ids, used by the
/// contract-negotiation/transfer-process groups this project doesn't
/// implement). This gives the Rust and EDC catalog-request responses the
/// same dataset *count and ids* to compare against
/// (`compliance/benchmark-2026-08-27.md`), even though the two
/// implementations still diverge on everything else about how those
/// datasets are represented on the wire (see that report's fidelity
/// section).
pub async fn seed_sample_catalog(cache: &dyn CatalogCache) -> StoreResult<()> {
    let node = NodeId::new("sample-participant");
    let mut catalog = Catalog::new("sample-catalog", node);
    catalog.participant_id = Some("did:example:sample-participant".to_string());
    for dataset_id in ["CAT0101", "CAT0102"] {
        catalog.datasets.push(Dataset {
            id: dataset_id.to_string(),
            properties: Default::default(),
            distributions: vec![Distribution {
                format: "application/json".to_string(),
                access_service: "sample-data-service".to_string(),
            }],
            policies: Vec::new(),
        });
    }
    catalog.data_services.push(DataService {
        id: "sample-data-service".to_string(),
        endpoint_url: "https://sample.example.org/dsp".to_string(),
        endpoint_description: Some("dataspace-protocol-http:1.0".to_string()),
    });

    cache.upsert(catalog).await
}
