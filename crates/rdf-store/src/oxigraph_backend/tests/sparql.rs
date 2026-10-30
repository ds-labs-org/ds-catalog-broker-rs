// --- `sparql_query_json` (gap analysis §3.3) --------------------------

use super::*;
use crate::oxigraph_backend::sparql::{SEQUENCE_INDEX_IRI, owning_resource_iri};

/// A plain `SELECT` with no `GRAPH`/`FROM` clause at all must still
/// find data crawled from two *different* origin nodes (two
/// separate named graphs) - proving the "whole store by default"
/// union-graph behavior documented on `sparql_query_json`, not just
/// that the method returns something.
#[tokio::test]
async fn sparql_query_json_select_with_no_graph_clause_searches_every_named_graph() {
    let cache = cache();
    cache
        .upsert(sample_catalog("node-a", "cat-a"))
        .await
        .unwrap();
    cache
        .upsert(sample_catalog("node-b", "cat-b"))
        .await
        .unwrap();

    let bytes = cache
        .sparql_query_json(&format!(
            "PREFIX dcat: <{DCAT_NS}> SELECT ?catalog WHERE {{ ?catalog a dcat:Catalog }}"
        ))
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(parsed["head"]["vars"], serde_json::json!(["catalog"]));
    let bindings = parsed["results"]["bindings"].as_array().unwrap();
    assert_eq!(
        bindings.len(),
        2,
        "expected one dcat:Catalog per origin node, got {parsed}"
    );
    let mut catalog_iris: Vec<&str> = bindings
        .iter()
        .map(|b| b["catalog"]["value"].as_str().unwrap())
        .collect();
    catalog_iris.sort_unstable();
    assert!(catalog_iris[0].contains("node-a") && catalog_iris[0].contains("cat-a"));
    assert!(catalog_iris[1].contains("node-b") && catalog_iris[1].contains("cat-b"));
    // And the JSON Results type/value shape is real, not
    // hand-rolled: a resource binding must come back as a `uri`.
    assert_eq!(bindings[0]["catalog"]["type"], serde_json::json!("uri"));
}

/// The `GRAPH <iri>` clause (the documented stretch-goal way to
/// scope a query to one participant) finds only that participant's
/// data, even though the store as a whole holds two.
#[tokio::test]
async fn sparql_query_json_graph_clause_scopes_to_one_participant() {
    let cache = cache();
    cache
        .upsert(sample_catalog("node-a", "cat-a"))
        .await
        .unwrap();
    cache
        .upsert(sample_catalog("node-b", "cat-b"))
        .await
        .unwrap();

    let scoped_graph = node_iri(&NodeId::new("node-b"));
    let bytes = cache
        .sparql_query_json(&format!(
            "PREFIX dcat: <{DCAT_NS}> SELECT ?catalog WHERE {{ GRAPH <{}> {{ ?catalog a dcat:Catalog }} }}",
            scoped_graph.as_str()
        ))
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let bindings = parsed["results"]["bindings"].as_array().unwrap();
    assert_eq!(bindings.len(), 1);
    assert!(
        bindings[0]["catalog"]["value"]
            .as_str()
            .unwrap()
            .contains("node-b")
    );
}

/// A real `ASK` query, through the same HTTP-facing method,
/// against real harvested-looking data (the "rich" catalog fixture
/// used elsewhere in this module).
#[tokio::test]
async fn sparql_query_json_ask_returns_the_spec_shaped_boolean_result() {
    let cache = cache();
    cache.upsert(rich_catalog()).await.unwrap();

    let bytes = cache
        .sparql_query_json(&format!(
            "PREFIX dcat: <{DCAT_NS}> ASK {{ ?d a dcat:Dataset ; dcat:distribution ?dist . ?dist dcat:accessService ?svc }}"
        ))
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed, serde_json::json!({"head": {}, "boolean": true}));
}

/// A SPARQL **Update** operation (`INSERT DATA`) must never be
/// reachable through this method - proving the "read-only by
/// construction" claim in `sparql_query_json`'s own doc comment,
/// not just documenting it.
#[tokio::test]
async fn sparql_update_operation_is_rejected_not_silently_ignored() {
    let cache = cache();
    cache
        .upsert(sample_catalog("node-1", "cat-1"))
        .await
        .unwrap();

    let attempted_injection = format!(
        "PREFIX dcat: <{DCAT_NS}> INSERT DATA {{ GRAPH <{}> {{ <urn:x> a dcat:Catalog }} }}",
        node_iri(&NodeId::new("node-1")).as_str()
    );
    let outcome = cache.sparql_query_json(&attempted_injection);
    assert!(
        matches!(outcome, Err(SparqlError::Parse(_))),
        "expected an Update operation to fail to parse as a Query, got {outcome:?}"
    );

    // And, just as importantly, nothing was actually inserted -
    // the store is unaffected by the attempt.
    let results = cache.query(CatalogQuery::all()).await.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, "cat-1");
}

/// `CONSTRUCT` is a well-formed Query, just not one this method
/// serializes (see `SparqlError::UnsupportedGraphResult`'s own doc
/// comment) - it must fail cleanly, not panic or silently return
/// an empty/wrong result.
#[tokio::test]
async fn sparql_query_json_rejects_construct_queries_cleanly() {
    let cache = cache();
    cache
        .upsert(sample_catalog("node-1", "cat-1"))
        .await
        .unwrap();

    let outcome = cache.sparql_query_json("CONSTRUCT { ?s ?p ?o } WHERE { ?s ?p ?o }");
    assert!(matches!(outcome, Err(SparqlError::UnsupportedGraphResult)));
}

/// A syntactically invalid query string is a `Parse` error, not a
/// panic and not silently empty results.
#[tokio::test]
async fn sparql_query_json_rejects_malformed_query_syntax() {
    let cache = cache();
    let outcome = cache.sparql_query_json("this is not sparql at all");
    assert!(matches!(outcome, Err(SparqlError::Parse(_))));
}

// --- `sparql_query_json_limited` --------------------------------------

#[tokio::test]
async fn sparql_query_json_limited_stops_once_cancelled() {
    let cache = cache();
    cache
        .upsert(sample_catalog("node-1", "cat-1"))
        .await
        .unwrap();
    let token = CancellationToken::new();
    token.cancel();
    let limits = SparqlLimits {
        cancellation: Some(token),
        max_rows: None,
    };
    let visible = BTreeSet::new();
    for visible in [None, Some(&visible)] {
        let outcome = cache.sparql_query_json_limited(
            "SELECT * WHERE { ?a ?b ?c . ?d ?e ?f }",
            visible,
            &limits,
        );
        assert!(
            matches!(outcome, Err(SparqlError::Cancelled)),
            "got {outcome:?}"
        );
    }
}

#[tokio::test]
async fn sparql_query_json_limited_rejects_more_rows_than_max_rows() {
    let cache = cache();
    cache
        .upsert(sample_catalog("node-a", "cat-a"))
        .await
        .unwrap();
    cache
        .upsert(sample_catalog("node-b", "cat-b"))
        .await
        .unwrap();
    let query =
        format!("PREFIX dcat: <{DCAT_NS}> SELECT ?catalog WHERE {{ ?catalog a dcat:Catalog }}");
    let limited = |max_rows| SparqlLimits {
        cancellation: None,
        max_rows: Some(max_rows),
    };

    let outcome = cache.sparql_query_json_limited(&query, None, &limited(1));
    assert!(
        matches!(outcome, Err(SparqlError::TooManyRows(1))),
        "got {outcome:?}"
    );

    let bytes = cache
        .sparql_query_json_limited(&query, None, &limited(2))
        .expect("exactly max_rows rows is within the limit");
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed["results"]["bindings"].as_array().unwrap().len(), 2);
}

// --- `sparql_query_json_restricted` -----------------------------------

/// Every binding value (IRI or literal) of a `SELECT` result body.
fn binding_values(bytes: &[u8]) -> Vec<String> {
    let parsed: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    parsed["results"]["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|binding| {
            binding
                .as_object()
                .unwrap()
                .values()
                .map(|term| term["value"].as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn owning_resource_iri_maps_every_resource_minted_under_a_dataset_or_service_to_it() {
    let node = NodeId::new("node/a");
    let dataset = dataset_resource_iri(&node, "ds/1");
    let service = service_resource_iri(&node, "svc/1");
    let base = node_base(&node);
    let policy = policy_iri(&base, "ds/1", 0);
    let rule = rule_iri(policy.as_str(), "permissions", 0);
    for iri in [
        dataset.clone(),
        distribution_iri(&base, "ds/1", 0).into_string(),
        policy.as_str().to_string(),
        constraint_iri(rule.as_str(), 0).into_string(),
    ] {
        assert_eq!(owning_resource_iri(&iri), Some(dataset.as_str()), "{iri}");
    }
    assert_eq!(owning_resource_iri(&service), Some(service.as_str()));

    // An empty id is still a resource: `"@id": ""` must be gated
    // like any other dataset or service.
    let empty_dataset = dataset_resource_iri(&node, "");
    assert_eq!(empty_dataset, format!("{base}/datasets/"));
    for iri in [
        empty_dataset.clone(),
        distribution_iri(&base, "", 0).into_string(),
        policy_iri(&base, "", 0).into_string(),
    ] {
        assert_eq!(
            owning_resource_iri(&iri),
            Some(empty_dataset.as_str()),
            "{iri}"
        );
    }
    let empty_service = service_resource_iri(&node, "");
    assert_eq!(
        owning_resource_iri(&empty_service),
        Some(empty_service.as_str())
    );

    // Fails closed: anything else minted under a node belongs to
    // itself, so no allow-list can contain it.
    for iri in [format!("{base}/datasets"), format!("{base}/other/x")] {
        assert_eq!(owning_resource_iri(&iri), Some(iri.as_str()), "{iri}");
    }

    for iri in [
        node_iri(&node).into_string(),
        catalog_iri(&base, "cat/datasets/x").into_string(),
        "http://www.w3.org/ns/dcat#Dataset".to_string(),
    ] {
        assert_eq!(owning_resource_iri(&iri), None, "{iri}");
    }
}

#[test]
fn sequence_index_iri_constant_matches_the_predicate_the_store_writes() {
    assert_eq!(SEQUENCE_INDEX_IRI, sequence_index_pred().as_str());
}

/// A dataset and a service published with `"@id": ""` must be
/// hidden like any other when they are not on the allow-list.
#[tokio::test]
async fn sparql_query_json_restricted_hides_empty_id_resources() {
    let cache = cache();
    let node = NodeId::new("node-e");
    let mut catalog = Catalog::new("cat-e", node.clone());
    let mut properties = BTreeMap::new();
    properties.insert("title".to_string(), "TOP SECRET".to_string());
    catalog.datasets.push(Dataset {
        id: String::new(),
        properties,
        distributions: vec![Distribution {
            format: "application/json".to_string(),
            access_service: String::new(),
        }],
        policies: Vec::new(),
    });
    catalog.datasets.push(Dataset {
        id: "open".to_string(),
        properties: BTreeMap::new(),
        distributions: vec![],
        policies: Vec::new(),
    });
    catalog.data_services.push(DataService {
        id: String::new(),
        endpoint_url: "https://secret-partner.example/dsp".to_string(),
        endpoint_description: None,
    });
    cache.upsert(catalog).await.unwrap();

    let visible = BTreeSet::from([dataset_resource_iri(&node, "open")]);
    let values = binding_values(
        &cache
            .sparql_query_json_restricted("SELECT ?s ?p ?o WHERE { ?s ?p ?o }", &visible)
            .unwrap(),
    );
    assert!(
        !values
            .iter()
            .any(|v| v.contains("TOP SECRET") || v.contains("secret-partner")),
        "an empty-id dataset or service off the allow-list must be hidden. Got: {values:?}"
    );
    assert!(values.contains(&dataset_resource_iri(&node, "open")));
}

/// With every resource on the allow-list, the view must answer
/// exactly like the store for a spread of query shapes.
#[tokio::test]
async fn sparql_query_json_restricted_matches_the_store_when_everything_is_visible() {
    let cache = cache();
    let mut catalog = rich_catalog();
    catalog.datasets[0].policies = policy_catalog().datasets[0].policies.clone();
    cache.upsert(catalog.clone()).await.unwrap();
    cache
        .upsert(sample_catalog("node-a", "cat-a"))
        .await
        .unwrap();
    let node = &catalog.origin_node;
    let visible: BTreeSet<String> = catalog
        .datasets
        .iter()
        .map(|d| dataset_resource_iri(node, &d.id))
        .chain(
            catalog
                .data_services
                .iter()
                .map(|s| service_resource_iri(node, &s.id)),
        )
        .collect();
    let graph = node_iri(node).into_string();

    for query in [
        format!("SELECT ?s ?p ?o WHERE {{ ?s ?p ?o FILTER(?p != <{SEQUENCE_INDEX_IRI}>) }}"),
        format!("SELECT ?g ?s WHERE {{ GRAPH ?g {{ ?s a <{DCAT_NS}Dataset> }} }}"),
        "SELECT ?g WHERE { GRAPH ?g {} }".to_string(),
        format!("SELECT ?s WHERE {{ GRAPH <{graph}> {{ ?s a <{DCAT_NS}Dataset> }} }}"),
        format!("SELECT ?s FROM <{graph}> WHERE {{ ?s a <{DCAT_NS}Distribution> }}"),
        format!("SELECT ?g FROM NAMED <{graph}> WHERE {{ GRAPH ?g {{}} }}"),
        format!(
            "SELECT ?d (COUNT(?x) AS ?n) WHERE {{ ?d a <{DCAT_NS}Dataset> . \
             OPTIONAL {{ ?d <{DCAT_NS}distribution> ?x }} }} GROUP BY ?d"
        ),
        format!("SELECT ?s ?o WHERE {{ ?s <{DCAT_NS}dataset>/<{DCAT_NS}distribution>* ?o }}"),
        format!(
            "SELECT ?s WHERE {{ ?s a <{DCAT_NS}Dataset> \
             MINUS {{ ?s <{DCAT_NS}distribution> ?x }} }}"
        ),
        "ASK { ?s ?p ?o }".to_string(),
    ] {
        let mut expected = binding_rows(&cache.sparql_query_json(&query).unwrap());
        let mut got = binding_rows(
            &cache
                .sparql_query_json_restricted(&query, &visible)
                .unwrap(),
        );
        expected.sort();
        got.sort();
        assert_eq!(got, expected, "{query}");
    }
}

/// Each result row (or the ASK boolean) as one comparable string.
fn binding_rows(bytes: &[u8]) -> Vec<String> {
    let parsed: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    if let Some(boolean) = parsed.get("boolean") {
        return vec![boolean.to_string()];
    }
    parsed["results"]["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row.to_string())
        .collect()
}

/// Everything not on the allow-list is unreachable, even by
/// `?s ?p ?o`, which no query rewrite could scope: a hidden
/// dataset's own triples, every resource minted under it, the
/// catalog's link to it, a data service not on the list, and a
/// dataset harvested after the allow-list was computed. Everything
/// on it stays, including a same-id dataset from another
/// participant.
#[tokio::test]
async fn sparql_query_json_restricted_shows_only_allow_listed_resources() {
    let cache = cache();
    let mut catalog = rich_catalog();
    catalog.datasets.push(Dataset {
        id: "ds-10".to_string(),
        properties: BTreeMap::new(),
        distributions: vec![],
        policies: Vec::new(),
    });
    cache.upsert(catalog).await.unwrap();
    let mut other = Catalog::new("cat-other", NodeId::new("node-other"));
    other.datasets.push(Dataset {
        id: "ds-1".to_string(),
        properties: BTreeMap::new(),
        distributions: vec![],
        policies: Vec::new(),
    });
    cache.upsert(other).await.unwrap();

    let rich = NodeId::new("node-rich");
    let hidden_dataset = dataset_resource_iri(&rich, "ds-1");
    let hidden_service = service_resource_iri(&rich, "svc-1");
    let visible = BTreeSet::from([
        dataset_resource_iri(&rich, "ds-2"),
        dataset_resource_iri(&rich, "ds-10"),
        service_resource_iri(&rich, "svc-2"),
        dataset_resource_iri(&NodeId::new("node-other"), "ds-1"),
    ]);

    // Harvested after `visible` was computed, so not on it.
    let mut late = Catalog::new("cat-late", NodeId::new("node-late"));
    late.datasets.push(Dataset {
        id: "late-ds".to_string(),
        properties: BTreeMap::new(),
        distributions: vec![],
        policies: Vec::new(),
    });
    cache.upsert(late).await.unwrap();

    let bytes = cache
        .sparql_query_json_restricted("SELECT ?s ?p ?o WHERE { ?s ?p ?o }", &visible)
        .unwrap();
    let values = binding_values(&bytes);

    for hidden in [&hidden_dataset, &hidden_service] {
        assert!(
            !values
                .iter()
                .any(|v| v == hidden || v.starts_with(&format!("{hidden}/"))),
            "no triple may mention {hidden} or anything minted under it. Got: {values:?}"
        );
    }
    assert!(
        !values.iter().any(|v| v == "data.rest"),
        "the hidden dataset's own literal properties must not be reachable"
    );
    assert!(
        !values.iter().any(|v| v.contains("late-ds")),
        "a dataset harvested after the allow-list was computed must stay hidden"
    );
    assert!(
        !values.iter().any(|v| v.ends_with("#sequenceIndex")),
        "position numbers must not be exposed"
    );
    for still_visible in &visible {
        assert!(
            values.contains(still_visible),
            "{still_visible} must stay visible. Got: {values:?}"
        );
    }

    let unrestricted = binding_values(
        &cache
            .sparql_query_json("SELECT ?s ?p ?o WHERE { ?s ?p ?o }")
            .unwrap(),
    );
    assert!(
        unrestricted.contains(&hidden_dataset),
        "without restriction, the same query must still see every dataset"
    );
}

/// The view must behave like the store for the query shapes that
/// depend on graph handling and aggregation: `GRAPH ?g`, `FROM`,
/// `ASK` and `COUNT`.
#[tokio::test]
async fn sparql_query_json_restricted_supports_graph_from_ask_and_count() {
    let cache = cache();
    cache.upsert(rich_catalog()).await.unwrap();
    let rich = NodeId::new("node-rich");
    let visible = BTreeSet::from([
        dataset_resource_iri(&rich, "ds-2"),
        service_resource_iri(&rich, "svc-2"),
    ]);
    let graph = node_iri(&rich).into_string();
    let dataset_count = |bytes: &[u8]| -> String {
        let parsed: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        parsed["results"]["bindings"][0]["n"]["value"]
            .as_str()
            .unwrap()
            .to_string()
    };

    let count_query = format!(
        "PREFIX dcat: <{DCAT_NS}> \
         SELECT (COUNT(*) AS ?n) WHERE {{ ?d a dcat:Dataset }}"
    );
    assert_eq!(
        dataset_count(&cache.sparql_query_json(&count_query).unwrap()),
        "2"
    );
    assert_eq!(
        dataset_count(
            &cache
                .sparql_query_json_restricted(&count_query, &visible)
                .unwrap()
        ),
        "1",
        "COUNT must not count hidden datasets"
    );

    let graph_query = format!(
        "PREFIX dcat: <{DCAT_NS}> \
         SELECT (COUNT(*) AS ?n) WHERE {{ GRAPH ?g {{ ?d a dcat:Dataset }} }}"
    );
    assert_eq!(
        dataset_count(
            &cache
                .sparql_query_json_restricted(&graph_query, &visible)
                .unwrap()
        ),
        "1"
    );

    let from_query = format!(
        "PREFIX dcat: <{DCAT_NS}> \
         SELECT (COUNT(*) AS ?n) FROM <{graph}> WHERE {{ ?d a dcat:Dataset }}"
    );
    assert_eq!(
        dataset_count(
            &cache
                .sparql_query_json_restricted(&from_query, &visible)
                .unwrap()
        ),
        "1"
    );

    let hidden = dataset_resource_iri(&rich, "ds-1");
    let ask = |query: &str| -> serde_json::Value {
        let bytes = cache.sparql_query_json_restricted(query, &visible).unwrap();
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["boolean"].clone()
    };
    assert_eq!(ask(&format!("ASK {{ <{hidden}> ?p ?o }}")), false);
    assert_eq!(
        ask(&format!(
            "ASK {{ <{}> ?p ?o }}",
            dataset_resource_iri(&rich, "ds-2")
        )),
        true
    );
}
