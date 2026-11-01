// --- Empty and deeply nested logical constraints (#30) ----------------

use super::*;

/// A one-dataset catalog for `node` whose only permission carries
/// `constraint`.
fn catalog_with_constraint(node: &str, constraint: Constraint) -> Catalog {
    let mut catalog = Catalog::new(format!("cat-{node}"), NodeId::new(node));
    catalog.datasets.push(Dataset {
        id: "ds".to_string(),
        properties: BTreeMap::new(),
        distributions: Vec::new(),
        policies: vec![Policy {
            id: None,
            kind: PolicyKind::Offer,
            assigner: None,
            assignee: None,
            permissions: vec![Rule {
                action: "use".to_string(),
                constraints: vec![constraint],
            }],
            prohibitions: Vec::new(),
            obligations: Vec::new(),
        }],
    });
    catalog
}

/// `innermost` wrapped in `levels` nested `odrl:and` groups, so it sits at
/// depth `levels` (a rule's own constraint is at depth 0).
fn nested_and(levels: usize, innermost: Constraint) -> Constraint {
    (0..levels).fold(innermost, |inner, _| Constraint::and(vec![inner]))
}

fn leaf() -> Constraint {
    Constraint::atomic("odrl:spatial", "eq", "https://example.org/place/eu")
}

async fn round_trip(cache: &OxigraphCatalogCache, catalog: &Catalog) -> Catalog {
    cache.upsert(catalog.clone()).await.unwrap();
    let mut read = cache
        .query(CatalogQuery::for_node(catalog.origin_node.clone()))
        .await
        .unwrap();
    assert_eq!(read.len(), 1);
    read.remove(0)
}

/// An empty group is a real ODRL value - an empty `and` holds, an empty
/// `or` never does - so it must come back as written, not be dropped or
/// break the read.
#[tokio::test]
async fn empty_logical_groups_round_trip() {
    let cache = cache();
    let groups = [
        Constraint::and(Vec::new()),
        Constraint::or(Vec::new()),
        Constraint::xone(Vec::new()),
        Constraint::and_sequence(Vec::new()),
        Constraint::and(vec![leaf(), Constraint::or(Vec::new())]),
    ];
    for (index, group) in groups.into_iter().enumerate() {
        let catalog = catalog_with_constraint(&format!("node-empty-{index}"), group);
        assert_eq!(round_trip(&cache, &catalog).await, catalog);
    }
    assert_eq!(cache.query(CatalogQuery::all()).await.unwrap().len(), 5);
}

/// The deepest constraint the crawler keeps (depth 64) round-trips.
#[tokio::test]
async fn a_constraint_at_the_depth_bound_round_trips() {
    let cache = cache();
    let catalog = catalog_with_constraint("node-deep", nested_and(MAX_CONSTRAINT_DEPTH, leaf()));
    assert_eq!(round_trip(&cache, &catalog).await, catalog);
}

/// The ODRL engine evaluates a constraint past the bound as not
/// satisfied, so storing the tree with those children dropped (an empty
/// `and` at the bound, which always holds) would loosen the policy. The
/// upsert is refused instead, writes nothing, and leaves the previous
/// catalog and every other participant readable.
#[tokio::test]
async fn an_upsert_with_a_constraint_past_the_depth_bound_is_refused() {
    let cache = cache();
    cache
        .upsert(catalog_with_constraint("node-ok", leaf()))
        .await
        .unwrap();
    let previous = catalog_with_constraint("node-too-deep", leaf());
    cache.upsert(previous.clone()).await.unwrap();

    let too_deep = catalog_with_constraint(
        "node-too-deep",
        nested_and(MAX_CONSTRAINT_DEPTH + 1, leaf()),
    );
    assert!(cache.upsert(too_deep).await.is_err());

    let read = cache
        .query(CatalogQuery::for_node(NodeId::new("node-too-deep")))
        .await
        .unwrap();
    assert_eq!(read, vec![previous], "the previous catalog stays as it was");
    let deepest_written = cache
        .store
        .inner()
        .quads_for_pattern(None, None, None, None)
        .map(|quad| {
            quad.unwrap()
                .subject
                .to_string()
                .matches("/constraints/")
                .count()
        })
        .max()
        .unwrap();
    assert!(deepest_written <= 1, "the refused tree left quads behind");
    assert_eq!(cache.query(CatalogQuery::all()).await.unwrap().len(), 2);
}

/// Remove every `fcns:logicalOperator` quad, as in a graph written by
/// hand or by another producer.
fn strip_logical_operators(cache: &OxigraphCatalogCache) {
    let store = cache.store.inner();
    let marker = logical_operator_pred();
    let quads: Vec<Quad> = store
        .quads_for_pattern(None, Some(marker.as_ref()), None, None)
        .collect::<Result<_, _>>()
        .unwrap();
    for quad in quads {
        store.remove(&quad).unwrap();
    }
}

/// A group without the marker is read from its link predicates, as plain
/// ODRL would have it.
#[tokio::test]
async fn a_group_without_the_operator_marker_reads_from_its_links() {
    let cache = cache();
    let catalog = catalog_with_constraint(
        "node-plain",
        Constraint::xone(vec![leaf(), Constraint::and(vec![leaf(), leaf()])]),
    );
    cache.upsert(catalog.clone()).await.unwrap();
    strip_logical_operators(&cache);
    let read = cache
        .query(CatalogQuery::for_node(NodeId::new("node-plain")))
        .await
        .unwrap();
    assert_eq!(read, vec![catalog]);
}

/// A marker naming one operator while the children hang off another is
/// contradictory: an error, not a silently emptied group.
#[tokio::test]
async fn a_marker_that_disagrees_with_the_links_is_an_error() {
    let cache = cache();
    let catalog = catalog_with_constraint("node-odd", Constraint::and(vec![leaf()]));
    cache.upsert(catalog).await.unwrap();
    let store = cache.store.inner();
    let marker = logical_operator_pred();
    let quad = store
        .quads_for_pattern(None, Some(marker.as_ref()), None, None)
        .next()
        .unwrap()
        .unwrap();
    store.remove(&quad).unwrap();
    store
        .insert(&Quad::new(
            quad.subject.clone(),
            marker,
            odrl_or_pred(),
            quad.graph_name.clone(),
        ))
        .unwrap();
    assert!(
        cache
            .query(CatalogQuery::for_node(NodeId::new("node-odd")))
            .await
            .is_err()
    );
}

/// One participant's graph that does not decode must not take every
/// other participant down with it in `query(all)`.
#[tokio::test]
async fn an_undecodable_catalog_is_left_out_of_reading_all_catalogs() {
    let cache = cache();
    cache
        .upsert(catalog_with_constraint("node-good", leaf()))
        .await
        .unwrap();
    let broken = catalog_with_constraint("node-broken", Constraint::and(vec![leaf()]));
    cache.upsert(broken).await.unwrap();
    strip_logical_operators(&cache);
    let store = cache.store.inner();
    // Leave the group with neither a marker nor any child link.
    let links: Vec<Quad> = store
        .quads_for_pattern(None, Some(odrl_and_pred().as_ref()), None, None)
        .collect::<Result<_, _>>()
        .unwrap();
    for quad in links {
        store.remove(&quad).unwrap();
    }

    let all = cache.query(CatalogQuery::all()).await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].origin_node, NodeId::new("node-good"));
    assert!(
        cache
            .query(CatalogQuery::for_node(NodeId::new("node-broken")))
            .await
            .is_err(),
        "asking for that participant alone still reports the error"
    );
}
