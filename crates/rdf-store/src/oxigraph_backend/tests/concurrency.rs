// --- Concurrent reads during upserts (#26) ----------------------------

use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// A catalog for `node` with `datasets` datasets, each tagged with
/// `generation`, so a read can tell which upsert it saw.
fn generation_catalog(node: &str, generation: &str, datasets: usize) -> Catalog {
    let mut catalog = Catalog::new(format!("cat-{generation}"), NodeId::new(node));
    catalog.participant_id = Some(format!("did:example:{generation}"));
    for index in 0..datasets {
        let mut properties = BTreeMap::new();
        properties.insert("generation".to_string(), generation.to_string());
        catalog.datasets.push(Dataset {
            id: format!("ds-{index}"),
            properties,
            distributions: vec![Distribution {
                format: "application/json".to_string(),
                access_service: "svc".to_string(),
            }],
            policies: Vec::new(),
        });
    }
    catalog.data_services.push(DataService {
        id: "svc".to_string(),
        endpoint_url: "https://example.org/dsp".to_string(),
        endpoint_description: None,
    });
    catalog
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(future)
}

/// Readers running while the same participant is upserted over and over
/// must always see one whole catalog, the old one or the new one: never
/// an error, never a missing catalog, never a mix of the two.
#[test]
fn concurrent_reads_never_see_a_partial_upsert() {
    let cache = Arc::new(cache());
    let old = generation_catalog("node-race", "old", 40);
    let new = generation_catalog("node-race", "new", 40);
    block_on(cache.upsert(old.clone())).unwrap();

    let done = Arc::new(AtomicBool::new(false));
    let readers: Vec<_> = (0..4)
        .map(|_| {
            let cache = Arc::clone(&cache);
            let done = Arc::clone(&done);
            let (old, new) = (old.clone(), new.clone());
            std::thread::spawn(move || {
                let mut reads = 0usize;
                while !done.load(Ordering::Relaxed) {
                    let by_node = block_on(cache.query(CatalogQuery {
                        origin_node: Some(NodeId::new("node-race")),
                        ..CatalogQuery::all()
                    }));
                    let all = block_on(cache.query(CatalogQuery::all()));
                    for result in [by_node, all] {
                        let catalogs = result
                            .unwrap_or_else(|err| panic!("read failed during an upsert: {err}"));
                        assert_eq!(catalogs.len(), 1, "the catalog went missing");
                        assert!(
                            catalogs[0] == old || catalogs[0] == new,
                            "read a catalog that is neither the old nor the new one: {:?}",
                            catalogs[0].id
                        );
                    }
                    reads += 1;
                }
                reads
            })
        })
        .collect();

    for round in 0..300 {
        let next = if round % 2 == 0 { &new } else { &old };
        block_on(cache.upsert(next.clone())).unwrap();
    }
    done.store(true, Ordering::Relaxed);
    let reads: usize = readers.into_iter().map(|r| r.join().unwrap()).sum();
    assert!(reads > 0, "the readers never ran");
}

/// `delete` racing an upsert of the same participant leaves the graph
/// either empty or holding one whole catalog, never orphan quads.
#[test]
fn delete_racing_upsert_leaves_a_whole_catalog_or_none() {
    let catalog = generation_catalog("node-del", "only", 200);
    for _ in 0..30 {
        let cache = Arc::new(cache());
        block_on(cache.upsert(catalog.clone())).unwrap();
        let writer = {
            let cache = Arc::clone(&cache);
            let catalog = catalog.clone();
            std::thread::spawn(move || block_on(cache.upsert(catalog)).unwrap())
        };
        // Delete while the upsert is (most likely) writing.
        std::thread::sleep(std::time::Duration::from_millis(5));
        block_on(cache.delete(&NodeId::new("node-del"))).unwrap();
        writer.join().unwrap();
        let catalogs = block_on(cache.query(CatalogQuery::all())).unwrap();
        let graph = node_iri(&NodeId::new("node-del"));
        let leftover = cache
            .store
            .inner()
            .quads_for_pattern(None, None, None, Some(graph.as_ref().into()))
            .count();
        assert!(
            (catalogs.is_empty() && leftover == 0) || catalogs == vec![catalog.clone()],
            "left {} quads behind with {} catalogs readable",
            leftover,
            catalogs.len()
        );
    }
}
