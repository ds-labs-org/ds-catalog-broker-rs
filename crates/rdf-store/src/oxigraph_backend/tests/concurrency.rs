// --- Concurrent reads during upserts (#26) ----------------------------

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Instant;

/// A catalog for `node` with `datasets` datasets, each tagged with
/// `generation`, so a read can tell which upsert it saw.
fn generation_catalog(node: &str, generation: &str, datasets: usize) -> Catalog {
    let mut catalog = Catalog::new(format!("cat-{node}-{generation}"), NodeId::new(node));
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

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
}

/// Sets the flag when dropped, so reader threads stop even if the
/// writer panics.
struct StopOnDrop(Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Run `readers` threads calling `read` in a loop while `write` runs on
/// this thread. Every reader has finished at least one read before
/// `write` starts, and they all keep reading until it returns.
fn race(readers: usize, read: impl Fn() + Send + Sync + 'static, write: impl FnOnce()) {
    let read = Arc::new(read);
    let done = Arc::new(AtomicBool::new(false));
    let started = Arc::new(Barrier::new(readers + 1));
    let handles: Vec<_> = (0..readers)
        .map(|_| {
            let (read, done, started) =
                (Arc::clone(&read), Arc::clone(&done), Arc::clone(&started));
            std::thread::spawn(move || {
                read();
                started.wait();
                while !done.load(Ordering::Relaxed) {
                    read();
                }
            })
        })
        .collect();
    {
        let _stop = StopOnDrop(Arc::clone(&done));
        started.wait();
        write();
    }
    for handle in handles {
        handle.join().unwrap();
    }
}

/// Readers running while the same participant is upserted over and over
/// must always see one whole catalog, the old one or the new one: never
/// an error, never a missing catalog, never a mix of the two.
#[test]
fn concurrent_reads_never_see_a_partial_upsert() {
    let cache = Arc::new(cache());
    let old = generation_catalog("node-race", "old", 40);
    let new = generation_catalog("node-race", "new", 40);
    let rt = runtime();
    rt.block_on(cache.upsert(old.clone())).unwrap();

    let reader_cache = Arc::clone(&cache);
    let (expected_old, expected_new) = (old.clone(), new.clone());
    race(
        4,
        move || {
            let rt = runtime();
            let by_node =
                rt.block_on(reader_cache.query(CatalogQuery::for_node(NodeId::new("node-race"))));
            let all = rt.block_on(reader_cache.query(CatalogQuery::all()));
            for result in [by_node, all] {
                let catalogs =
                    result.unwrap_or_else(|err| panic!("read failed during an upsert: {err}"));
                assert_eq!(catalogs.len(), 1, "the catalog went missing");
                assert!(
                    catalogs[0] == expected_old || catalogs[0] == expected_new,
                    "read a catalog that is neither the old nor the new one: {:?}",
                    catalogs[0].id
                );
            }
        },
        || {
            for round in 0..300 {
                let next = if round % 2 == 0 { &new } else { &old };
                rt.block_on(cache.upsert(next.clone())).unwrap();
            }
        },
    );
}

/// One `query(CatalogQuery::all())` reads every participant from the
/// same store state. For each generation the writer upserts A, then B,
/// so a consistent read shows A at B's generation or one ahead of it.
/// Large participants that never change make each read slow, so writes
/// land mid-read.
#[test]
fn reading_all_catalogs_sees_one_store_state() {
    let cache = Arc::new(cache());
    let rt = runtime();
    for node in ["node-big-1", "node-big-2", "node-big-3", "node-big-4"] {
        rt.block_on(cache.upsert(generation_catalog(node, "static", 300)))
            .unwrap();
    }
    let generations: Vec<String> = (0..600).map(|g| format!("{g:04}")).collect();
    let catalogs = |g: &str| {
        (
            generation_catalog("node-a", g, 2),
            generation_catalog("node-b", g, 2),
        )
    };
    let (a, b) = catalogs(&generations[0]);
    rt.block_on(cache.upsert(a)).unwrap();
    rt.block_on(cache.upsert(b)).unwrap();

    let reader_cache = Arc::clone(&cache);
    race(
        4,
        move || {
            let all = runtime()
                .block_on(reader_cache.query(CatalogQuery::all()))
                .unwrap();
            let generation = |node: &str| {
                all.iter()
                    .find(|c| c.origin_node == NodeId::new(node))
                    .and_then(|c| c.participant_id.as_deref())
                    .and_then(|id| id.strip_prefix("did:example:"))
                    .and_then(|g| g.parse::<u32>().ok())
                    .unwrap_or_else(|| panic!("{node} went missing"))
            };
            let (a, b) = (generation("node-a"), generation("node-b"));
            assert!(
                a == b || a == b + 1,
                "read node-a at generation {a} and node-b at {b}"
            );
        },
        || {
            for g in &generations[1..] {
                let (a, b) = catalogs(g);
                rt.block_on(cache.upsert(a)).unwrap();
                rt.block_on(cache.upsert(b)).unwrap();
            }
        },
    );
}

/// `delete` racing an upsert of the same participant leaves the graph
/// either empty or holding one whole catalog, never orphan quads.
#[test]
fn delete_racing_upsert_leaves_a_whole_catalog_or_none() {
    let catalog = generation_catalog("node-del", "only", 200);
    let graph = node_iri(&NodeId::new("node-del"));
    let rt = runtime();

    // Spread the deletes across the length of one upsert, so some of them
    // land while it is writing whatever the machine's speed.
    let timing = cache();
    let started = Instant::now();
    rt.block_on(timing.upsert(catalog.clone())).unwrap();
    let upsert_time = started.elapsed();

    for step in 0..40u32 {
        let cache = Arc::new(cache());
        rt.block_on(cache.upsert(catalog.clone())).unwrap();
        let writer = {
            let cache = Arc::clone(&cache);
            let catalog = catalog.clone();
            std::thread::spawn(move || runtime().block_on(cache.upsert(catalog)).unwrap())
        };
        std::thread::sleep(upsert_time * step / 40);
        rt.block_on(cache.delete(&NodeId::new("node-del"))).unwrap();
        writer.join().unwrap();
        let catalogs = rt.block_on(cache.query(CatalogQuery::all())).unwrap();
        let leftover = cache
            .store
            .inner()
            .quads_for_pattern(None, None, None, Some(graph.as_ref().into()))
            .count();
        assert!(
            (catalogs.is_empty() && leftover == 0) || catalogs == vec![catalog.clone()],
            "left {leftover} quads behind with {} catalogs readable",
            catalogs.len()
        );
    }
}
