use super::*;
use catalog_core::LogicalConstraint;

fn sample_catalog(node: &str, id: &str) -> Catalog {
    Catalog::new(id, NodeId::new(node))
}

fn cache() -> OxigraphCatalogCache {
    OxigraphCatalogCache::in_memory().unwrap()
}

/// A catalog exercising every field the domain model has: nested
/// datasets with properties, distributions, and a policy, a data
/// service, a participant id, and catalog-level properties. Used by
/// the round-trip and real-decomposition tests below. A more
/// elaborate, ordering-focused policy fixture lives separately in
/// `policy_catalog` below - kept out of this shared fixture so it
/// doesn't perturb the quad-count/predicate assertions the other
/// tests below make against `rich_catalog`.
fn rich_catalog() -> Catalog {
    let mut catalog = Catalog::new("cat-rich", NodeId::new("node-rich"));
    catalog.participant_id = Some("did:example:rich-participant".to_string());
    catalog.properties.insert(
        "http://www.w3.org/ns/dcat#keyword".to_string(),
        "logistics".to_string(),
    );
    catalog
        .properties
        .insert("internalLabel".to_string(), "demo".to_string());

    let mut ds1_properties = BTreeMap::new();
    ds1_properties.insert("assetType".to_string(), "data.rest".to_string());
    catalog.datasets.push(Dataset {
        id: "ds-1".to_string(),
        properties: ds1_properties,
        distributions: vec![
            Distribution {
                format: "application/json".to_string(),
                access_service: "svc-1".to_string(),
            },
            Distribution {
                format: "application/xml".to_string(),
                access_service: "svc-1".to_string(),
            },
        ],
        policies: vec![Policy {
            id: None,
            kind: PolicyKind::Set,
            assigner: None,
            assignee: None,
            permissions: vec![Rule {
                action: "use".to_string(),
                constraints: Vec::new(),
            }],
            prohibitions: Vec::new(),
            obligations: Vec::new(),
        }],
    });
    catalog.datasets.push(Dataset {
        id: "ds-2".to_string(),
        properties: BTreeMap::new(),
        distributions: vec![Distribution {
            format: "text/csv".to_string(),
            access_service: "svc-2".to_string(),
        }],
        policies: Vec::new(),
    });

    catalog.data_services.push(DataService {
        id: "svc-1".to_string(),
        endpoint_url: "https://example.org/dsp".to_string(),
        endpoint_description: Some("dataspace-protocol-http:1.0".to_string()),
    });
    catalog.data_services.push(DataService {
        id: "svc-2".to_string(),
        endpoint_url: "https://example.org/other-dsp".to_string(),
        endpoint_description: None,
    });

    catalog
}

#[tokio::test]
async fn upsert_then_query_all_returns_it() {
    let cache = cache();
    cache
        .upsert(sample_catalog("node-1", "cat-1"))
        .await
        .unwrap();

    let results = cache.query(CatalogQuery::all()).await.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, "cat-1");
}

#[tokio::test]
async fn upsert_replaces_prior_catalog_for_same_node() {
    let cache = cache();
    cache
        .upsert(sample_catalog("node-1", "cat-1"))
        .await
        .unwrap();
    cache
        .upsert(sample_catalog("node-1", "cat-2"))
        .await
        .unwrap();

    let results = cache.query(CatalogQuery::all()).await.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, "cat-2");
}

#[tokio::test]
async fn query_for_node_filters_by_origin() {
    let cache = cache();
    cache
        .upsert(sample_catalog("node-1", "cat-1"))
        .await
        .unwrap();
    cache
        .upsert(sample_catalog("node-2", "cat-2"))
        .await
        .unwrap();

    let results = cache
        .query(CatalogQuery::for_node(NodeId::new("node-2")))
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, "cat-2");
}

#[tokio::test]
async fn query_respects_offset_and_limit() {
    let cache = cache();
    for i in 0..5 {
        cache
            .upsert(sample_catalog(&format!("node-{i}"), &format!("cat-{i}")))
            .await
            .unwrap();
    }

    let results = cache
        .query(CatalogQuery {
            origin_node: None,
            offset: 2,
            limit: Some(2),
        })
        .await
        .unwrap();
    assert_eq!(
        results.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
        vec!["cat-2", "cat-3"]
    );
}

#[tokio::test]
async fn delete_removes_catalog_and_reports_result() {
    let cache = cache();
    cache
        .upsert(sample_catalog("node-1", "cat-1"))
        .await
        .unwrap();

    let removed = cache.delete(&NodeId::new("node-1")).await.unwrap();
    assert!(removed);

    let results = cache.query(CatalogQuery::all()).await.unwrap();
    assert!(results.is_empty());

    let removed_again = cache.delete(&NodeId::new("node-1")).await.unwrap();
    assert!(!removed_again);
}

/// The correctness bar from gap analysis §3.2 (extended by §3.4):
/// round-tripping a catalog that exercises every field (nested
/// datasets, properties with both an already-IRI key and a plain
/// key, distributions, a harvested policy, data services,
/// participant id) through real triples must reproduce the exact
/// same domain value, order included. `ds-2` deliberately carries
/// no policy at all - regression coverage that a dataset predating
/// this feature (or one whose participant just advertised none)
/// still round-trips its `policies` field to an empty `Vec`, not
/// an error or `None`.
#[tokio::test]
async fn round_trips_a_catalog_exercising_every_field_exactly() {
    let cache = cache();
    let original = rich_catalog();
    cache.upsert(original.clone()).await.unwrap();

    let results = cache
        .query(CatalogQuery::for_node(NodeId::new("node-rich")))
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0], original);
    assert!(
        results[0].datasets[1].policies.is_empty(),
        "ds-2 carries no policy and must round-trip to an empty Vec"
    );
}

/// A more elaborate policy than `rich_catalog`'s: two permissions
/// (proving `Policy.permissions`' `Vec` order survives an unordered
/// triple store, not just its presence), the first with two
/// constraints (same proof for `Rule.constraints`), a prohibition
/// with no constraints, no obligations, an explicit `Offer` kind
/// (not the `Set` default), an id, an assigner, and an assignee -
/// covering every `Policy`/`Rule`/`Constraint` field at least once.
fn policy_catalog() -> Catalog {
    let mut catalog = Catalog::new("cat-policy", NodeId::new("node-policy"));
    catalog.datasets.push(Dataset {
        id: "ds-policy".to_string(),
        properties: BTreeMap::new(),
        distributions: Vec::new(),
        policies: vec![Policy {
            id: Some("policy-1".to_string()),
            kind: PolicyKind::Offer,
            assigner: Some("did:example:assigner".to_string()),
            assignee: Some("did:example:assignee".to_string()),
            permissions: vec![
                Rule {
                    action: "use".to_string(),
                    constraints: vec![
                        Constraint::atomic("dateTime", "lteq", "2027-01-01T00:00:00Z"),
                        Constraint::atomic("count", "lteq", "100"),
                    ],
                },
                Rule {
                    action: "distribute".to_string(),
                    constraints: Vec::new(),
                },
            ],
            prohibitions: vec![Rule {
                action: "modify".to_string(),
                constraints: Vec::new(),
            }],
            obligations: Vec::new(),
        }],
    });
    catalog
}

#[tokio::test]
async fn round_trips_a_dataset_policy_with_full_shape_and_preserves_ordering() {
    let cache = cache();
    let original = policy_catalog();
    cache.upsert(original.clone()).await.unwrap();

    let results = cache
        .query(CatalogQuery::for_node(NodeId::new("node-policy")))
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    // Exhaustive: `Vec`'s `PartialEq` is order-sensitive, so this
    // alone already proves permission/constraint order survived.
    assert_eq!(results[0], original);

    // Spelled out explicitly too, so the ordering claim is legible
    // without cross-referencing `policy_catalog` above.
    let policy = &results[0].datasets[0].policies[0];
    assert_eq!(policy.permissions[0].action, "use");
    let Constraint::Atomic(first) = &policy.permissions[0].constraints[0] else {
        panic!("expected an atomic constraint");
    };
    assert_eq!(first.left_operand, "dateTime");
    let Constraint::Atomic(second) = &policy.permissions[0].constraints[1] else {
        panic!("expected an atomic constraint");
    };
    assert_eq!(second.left_operand, "count");
    assert_eq!(policy.permissions[1].action, "distribute");
    assert!(policy.permissions[1].constraints.is_empty());
    assert_eq!(policy.prohibitions.len(), 1);
    assert!(policy.prohibitions[0].constraints.is_empty());
    assert!(policy.obligations.is_empty());
    assert_eq!(policy.kind, PolicyKind::Offer);
    assert_eq!(policy.id.as_deref(), Some("policy-1"));
    assert_eq!(policy.assigner.as_deref(), Some("did:example:assigner"));
    assert_eq!(policy.assignee.as_deref(), Some("did:example:assignee"));
}

/// RED (gap analysis §3.4): `catalog_core::Constraint` now has a
/// `Logical` variant (`odrl:and`/`odrl:or`/`odrl:xone`/
/// `odrl:andSequence`, nesting arbitrarily - see that type's own
/// doc comment), but this store's `write_constraint`/
/// `load_constraint` still only handle the `Atomic` shape
/// (`write_constraint`'s own doc comment says so explicitly:
/// "This store still only ever writes the `Atomic` shape"). This
/// asserts a policy carrying a *nested* logical constraint - an
/// `odrl:xone` whose second child is itself a nested `odrl:and` of
/// two atomic leaves - survives `upsert` then `query` byte for
/// byte: which combinator was used at each level, and the exact
/// child order at each level, both preserved.
///
/// Expected to fail today: `write_constraint` silently no-ops on
/// `Constraint::Logical` (see its own doc comment for why silent),
/// so no `odrl:leftOperand`/`odrl:operator`/`odrl:rightOperand`
/// triples - nor anything describing the `odrl:xone`/`odrl:and`
/// grouping itself or its children - are ever written for that
/// constraint node. `load_constraint` then unconditionally requires
/// `odrl:leftOperand` on every constraint subject, so reading the
/// policy back errors out (`StoreError::Backend("... is missing
/// odrl:leftOperand")`) instead of returning the original nested
/// structure.
#[tokio::test]
async fn round_trips_a_nested_logical_constraint_preserving_structure_and_order() {
    let cache = cache();
    let mut catalog = Catalog::new("cat-logical", NodeId::new("node-logical"));

    let nested_and = Constraint::and(vec![
        Constraint::atomic("odrl:dateTime", "gteq", "2026-01-01T00:00:00Z"),
        Constraint::atomic("odrl:dateTime", "lteq", "2027-01-01T00:00:00Z"),
    ]);
    let top_level_xone = Constraint::xone(vec![
        Constraint::atomic("odrl:spatial", "eq", "https://example.org/place/eu"),
        nested_and,
    ]);

    catalog.datasets.push(Dataset {
        id: "ds-logical".to_string(),
        properties: BTreeMap::new(),
        distributions: Vec::new(),
        policies: vec![Policy {
            id: Some("policy-logical".to_string()),
            kind: PolicyKind::Offer,
            assigner: None,
            assignee: None,
            permissions: vec![Rule {
                action: "use".to_string(),
                constraints: vec![top_level_xone.clone()],
            }],
            prohibitions: Vec::new(),
            obligations: Vec::new(),
        }],
    });

    cache.upsert(catalog.clone()).await.unwrap();

    let results = cache
        .query(CatalogQuery::for_node(NodeId::new("node-logical")))
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0], catalog,
        "a nested logical constraint must round-trip byte for byte - \
         combinator, nested structure, and child order all included"
    );

    // Spelled out explicitly too, so the nesting/order claim is
    // legible without cross-referencing the fixture above.
    let constraint = &results[0].datasets[0].policies[0].permissions[0].constraints[0];
    let Constraint::Logical(LogicalConstraint::Xone(children)) = constraint else {
        panic!("expected the top-level constraint to round-trip as odrl:xone, got {constraint:?}");
    };
    assert_eq!(children.len(), 2, "xone must keep both children, in order");
    let Constraint::Atomic(first) = &children[0] else {
        panic!(
            "expected xone's first child to stay atomic (spatial eq), got {:?}",
            children[0]
        );
    };
    assert_eq!(first.left_operand, "odrl:spatial");
    let Constraint::Logical(LogicalConstraint::And(nested_children)) = &children[1] else {
        panic!(
            "expected xone's second child to round-trip as a nested odrl:and, got {:?}",
            children[1]
        );
    };
    assert_eq!(
        nested_children.len(),
        2,
        "nested and must keep both children, in order"
    );
    let Constraint::Atomic(nested_first) = &nested_children[0] else {
        panic!("expected the nested and's first child to stay atomic");
    };
    assert_eq!(nested_first.operator, "gteq");
    let Constraint::Atomic(nested_second) = &nested_children[1] else {
        panic!("expected the nested and's second child to stay atomic");
    };
    assert_eq!(nested_second.operator, "lteq");
}

/// Regression coverage for every dataset that predates this
/// feature (or whose participant simply advertised no policy at
/// all): `Dataset.policies` must round-trip to an empty `Vec`, not
/// an error, and no stray `odrl:hasPolicy` triple should exist for
/// it.
#[tokio::test]
async fn dataset_with_no_policies_round_trips_to_an_empty_vec() {
    let cache = cache();
    let mut catalog = Catalog::new("cat-no-policy", NodeId::new("node-no-policy"));
    catalog.datasets.push(Dataset {
        id: "ds-1".to_string(),
        properties: BTreeMap::new(),
        distributions: Vec::new(),
        policies: Vec::new(),
    });
    cache.upsert(catalog.clone()).await.unwrap();

    let results = cache
        .query(CatalogQuery::for_node(NodeId::new("node-no-policy")))
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0], catalog);
    assert!(results[0].datasets[0].policies.is_empty());

    let graph = cache
        .snapshot(&node_iri(&NodeId::new("node-no-policy")))
        .unwrap();
    let policy_links = cache
        .quads(None, Some(&odrl_has_policy_pred()), None, &graph)
        .unwrap();
    assert!(policy_links.is_empty());
}

/// Proves real ODRL decomposition happened, the same way
/// `a_direct_quad_pattern_query_finds_a_distribution_format_by_its_real_dcat_predicate`
/// proves it for DCAT: a direct quad-pattern query using the real
/// `odrl:hasPolicy`/`rdf:type` predicates finds the policy this
/// store wrote, reachable from the dataset by a genuine ODRL link,
/// not just present somewhere in the graph.
#[tokio::test]
async fn a_direct_quad_pattern_query_finds_a_policy_by_its_real_odrl_predicates() {
    let cache = cache();
    cache.upsert(policy_catalog()).await.unwrap();

    let graph = cache
        .snapshot(&node_iri(&NodeId::new("node-policy")))
        .unwrap();
    let dataset_subject = dataset_iri(&node_base(&NodeId::new("node-policy")), "ds-policy");
    let policy_links = cache
        .quads(
            Some(&dataset_subject),
            Some(&odrl_has_policy_pred()),
            None,
            &graph,
        )
        .unwrap();
    assert_eq!(policy_links.len(), 1);

    let policy_subject = match &policy_links[0].object {
        Term::NamedNode(node) => node.clone(),
        other => panic!("expected a named node object, got {other:?}"),
    };
    let type_matches = cache
        .quads(
            Some(&policy_subject),
            Some(&rdf_type()),
            Some(&Term::from(odrl_policy_class(PolicyKind::Offer))),
            &graph,
        )
        .unwrap();
    assert_eq!(
        type_matches.len(),
        1,
        "expected the harvested policy to carry a real odrl:Offer rdf:type"
    );
}

/// Proves real decomposition happened: a direct quad-pattern query
/// against the store, using the real `dct:format` predicate IRI,
/// finds a specific distribution's format. This is impossible
/// against the old JSON-blob representation, where the entire
/// catalog was one opaque literal object and no predicate other
/// than `fcns:catalogJson` ever existed in the store.
#[tokio::test]
async fn a_direct_quad_pattern_query_finds_a_distribution_format_by_its_real_dcat_predicate() {
    let cache = cache();
    cache.upsert(rich_catalog()).await.unwrap();

    let graph = cache
        .snapshot(&node_iri(&NodeId::new("node-rich")))
        .unwrap();
    let matches = cache
        .quads(
            None,
            Some(&dct_format_pred()),
            Some(&Term::from(Literal::from("application/xml".to_string()))),
            &graph,
        )
        .unwrap();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one distribution with this format"
    );

    // And the subject that carries it really is a dcat:Distribution
    // reachable from ds-1 via the real dcat:distribution property -
    // not just a coincidentally-matching literal floating in the
    // graph.
    let distribution_subject = match &matches[0].subject {
        NamedOrBlankNode::NamedNode(n) => n.clone(),
        other => panic!("expected a named node subject, got {other:?}"),
    };
    let type_matches = cache
        .quads(
            Some(&distribution_subject),
            Some(&rdf_type()),
            Some(&Term::from(dcat_distribution_class())),
            &graph,
        )
        .unwrap();
    assert_eq!(type_matches.len(), 1);
}

/// Same proof as above, but via a real SPARQL ASK through
/// `contreforts_kg::QueryEngine` (the "SPARQL ASK" option gap
/// analysis §3.2 calls out), scoped to one named graph.
#[tokio::test]
async fn sparql_ask_finds_a_dataset_via_the_real_dcat_dataset_link() {
    let cache = cache();
    cache.upsert(rich_catalog()).await.unwrap();

    let engine = contreforts_kg::QueryEngine::new(&cache.store);
    let found = engine
        .ask(&format!(
            "PREFIX dcat: <{DCAT_NS}> ASK {{ GRAPH <{}> {{ \
                 ?catalog a dcat:Catalog ; dcat:dataset ?dataset . \
                 ?dataset a dcat:Dataset . \
                 ?dataset dcat:distribution ?distribution . \
                 ?distribution dcat:accessService ?service . \
                 ?service a dcat:DataService \
             }} }}",
            node_iri(&NodeId::new("node-rich")).as_str()
        ))
        .unwrap();
    assert!(
        found,
        "expected the real dcat:dataset/distribution/accessService chain to be queryable"
    );
}

/// A property whose key is already a real vocabulary IRI is stored
/// under that exact predicate, not this project's fallback
/// namespace - proving "reuse the term when one genuinely fits"
/// actually happens, not just documented.
#[tokio::test]
async fn a_property_keyed_by_a_real_vocabulary_iri_is_stored_under_that_predicate() {
    let cache = cache();
    cache.upsert(rich_catalog()).await.unwrap();

    let graph = cache
        .snapshot(&node_iri(&NodeId::new("node-rich")))
        .unwrap();
    let keyword_pred = iri("http://www.w3.org/ns/dcat#keyword");
    let matches = cache
        .quads(None, Some(&keyword_pred), None, &graph)
        .unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(term_as_string(&matches[0].object).unwrap(), "logistics");
}

/// `upsert` replacing a node's graph wholesale must also drop the
/// old catalog's decomposed triples, not just its top-level
/// resource - otherwise a re-crawl with fewer datasets would leak
/// orphaned dataset/distribution triples forever.
#[tokio::test]
async fn upsert_wholesale_replacement_drops_the_prior_catalogs_decomposed_triples() {
    let cache = cache();
    cache.upsert(rich_catalog()).await.unwrap();

    let mut smaller = Catalog::new("cat-smaller", NodeId::new("node-rich"));
    smaller.datasets.push(Dataset {
        id: "only-dataset".to_string(),
        properties: BTreeMap::new(),
        distributions: vec![],
        policies: Vec::new(),
    });
    cache.upsert(smaller.clone()).await.unwrap();

    let results = cache
        .query(CatalogQuery::for_node(NodeId::new("node-rich")))
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0], smaller);

    // No leftover triples from `rich_catalog`'s ds-1/ds-2/svc-1/svc-2.
    let graph = cache
        .snapshot(&node_iri(&NodeId::new("node-rich")))
        .unwrap();
    let all_quads = cache.quads(None, None, None, &graph).unwrap();
    let leaked_old_dataset = all_quads.iter().any(|q| {
        matches!(&q.subject, NamedOrBlankNode::NamedNode(n) if n.as_str().contains("ds-1") || n.as_str().contains("ds-2"))
    });
    assert!(
        !leaked_old_dataset,
        "old catalog's dataset triples must not survive a wholesale upsert"
    );
}

mod concurrency;
mod constraints;
mod listing;
mod sparql;

/// `upsert` hands the encode and commit to the blocking pool, so the
/// calling task is not held while a large catalog is written: its first
/// poll returns `Pending`, and the write still lands.
#[tokio::test]
async fn upsert_does_not_write_on_the_calling_task() {
    use std::future::Future;
    use std::task::{Context, Waker};

    let cache = cache();
    let mut catalog = sample_catalog("node-big", "cat-big");
    for i in 0..2000 {
        catalog.datasets.push(Dataset {
            id: format!("ds-{i}"),
            properties: BTreeMap::new(),
            distributions: Vec::new(),
            policies: Vec::new(),
        });
    }
    let mut upsert = Box::pin(cache.upsert(catalog));
    let first = upsert
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()));
    assert!(
        first.is_pending(),
        "the write ran to completion inside the first poll"
    );
    assert!(matches!(upsert.await, Ok(())));
    let stored = cache.query(CatalogQuery::all()).await.unwrap();
    assert_eq!(stored[0].datasets.len(), 2000);
}
