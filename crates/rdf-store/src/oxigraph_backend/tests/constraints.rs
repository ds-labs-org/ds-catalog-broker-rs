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

/// Children past the bound are dropped the way the crawler drops them -
/// the group at the bound comes back empty - and nothing half-written is
/// left to break reads of this or any other participant.
#[tokio::test]
async fn children_past_the_depth_bound_are_dropped_cleanly() {
    let cache = cache();
    cache
        .upsert(catalog_with_constraint("node-ok", leaf()))
        .await
        .unwrap();
    let too_deep = catalog_with_constraint(
        "node-too-deep",
        nested_and(MAX_CONSTRAINT_DEPTH + 2, leaf()),
    );
    let read = round_trip(&cache, &too_deep).await;
    let expected = catalog_with_constraint(
        "node-too-deep",
        nested_and(MAX_CONSTRAINT_DEPTH, Constraint::and(Vec::new())),
    );
    assert_eq!(read, expected);
    assert_eq!(cache.query(CatalogQuery::all()).await.unwrap().len(), 2);
}
