//! SPARQL query evaluation over the store, optionally restricted to an
//! allow-list of visible resources.

use super::*;

/// How many times [`OxigraphCatalogCache::sparql_query_json_policy_filtered`]
/// runs a query before giving up because the store keeps changing.
pub const POLICY_FILTERED_ATTEMPTS: usize = 5;

/// Longest a policy-filtered query waits for one in-progress write to
/// commit before returning [`SparqlError::StoreBusy`]. Waiting does not
/// use up an attempt.
const WRITE_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

impl OxigraphCatalogCache {
    /// Evaluate an arbitrary, caller-supplied SPARQL query and return
    /// the result serialized as
    /// [`application/sparql-results+json`](https://www.w3.org/TR/sparql11-results-json/)
    /// bytes - the HTTP surface in `ds-catalog-broker-rs` (gap analysis
    /// §3.3) writes these bytes straight through as the response body.
    ///
    /// ## Why this lives here, not on the `CatalogCache` trait
    ///
    /// SPARQL evaluation is an Oxigraph-specific capability, and the
    /// `CatalogCache` trait is what the crawler writes through, so this is
    /// an inherent method on [`OxigraphCatalogCache`] instead - the HTTP
    /// layer holds the concrete `Arc<OxigraphCatalogCache>`.
    ///
    /// ## Why the whole store, not one named graph, by default
    ///
    /// A crawled catalog's triples live in a per-origin-node named
    /// graph (the "Named graph" mapping in [`super`]'s module doc), not the
    /// default graph - so a plain `SELECT * WHERE { ?s ?p ?o }` with no
    /// `GRAPH` clause would, under SPARQL's normal rules, match only
    /// the (always-empty) default graph and never see any harvested
    /// data at all. That would silently defeat "search everything I've
    /// harvested", the primary use case the gap analysis calls out.
    /// Instead, whenever the query itself does not already specify its
    /// own dataset (no `FROM`/`FROM NAMED`, checked via
    /// `QueryDataset::is_default_dataset`), this method sets the
    /// query's default graph to the union of every named graph in the
    /// store (`QueryDataset::set_default_graph_as_union`) before
    /// executing it - so a plain triple pattern with no `GRAPH` clause
    /// searches every harvested participant's graph at once, which is
    /// what "the whole store" should mean here.
    ///
    /// A caller that wants to scope to one participant still can,
    /// without any bespoke query-param feature, via SPARQL's own
    /// `GRAPH <iri>` clause (the exact graph IRI scheme is documented
    /// in [`super`]'s module doc, under "Resource IRIs") - or via the query's own
    /// `FROM`/`FROM NAMED`, which this method leaves untouched when
    /// present (`is_default_dataset()` is only true when the query
    /// didn't specify one itself). That satisfies the gap analysis's
    /// stretch goal ("via SPARQL's own GRAPH clause... rather than a
    /// bespoke query-param feature") without any extra code here.
    ///
    /// ## Why this is inherently read-only
    ///
    /// This method only ever calls [`SparqlEvaluator::parse_query`],
    /// which parses the SPARQL 1.1 **Query** grammar
    /// (`SELECT`/`ASK`/`CONSTRUCT`/`DESCRIBE`) - never
    /// `SparqlEvaluator::parse_update` or `Store::update`, which is
    /// the only code path in `oxigraph` that can mutate a store via
    /// SPARQL. A SPARQL Update string (`INSERT DATA { ... }`,
    /// `DELETE ...`, `LOAD`, `CLEAR`, ...) simply fails to parse as a
    /// Query - it is not reachable through this method at all, not
    /// merely rejected after being recognized. See
    /// `sparql_update_operation_is_rejected_not_silently_ignored`
    /// in `tests/sparql.rs` for a test proving this.
    ///
    /// ## Result shape
    ///
    /// - `ASK` -> `{"head":{},"boolean":<bool>}`.
    /// - `SELECT` -> `{"head":{"vars":[...]},"results":{"bindings":[...]}}`,
    ///   using `oxigraph`'s own `sparesults`-backed serializer, so IRI
    ///   vs. literal vs. blank node, datatypes, and language tags all
    ///   come out exactly per the W3C JSON Results spec - this method
    ///   never hand-rolls that format.
    /// - `CONSTRUCT`/`DESCRIBE` -> `Err(SparqlError::UnsupportedGraphResult)`,
    ///   see that variant's own doc comment.
    pub fn sparql_query_json(&self, query: &str) -> SparqlQueryResult<Vec<u8>> {
        self.sparql_query_json_limited(query, None, &SparqlLimits::default())
    }

    /// [`Self::sparql_query_json`], evaluated over only the part of the
    /// store a caller may see: every harvested dataset or data service
    /// whose resource IRI ([`dataset_resource_iri`],
    /// [`service_resource_iri`]) is not in `visible_resource_iris` is
    /// treated as absent, along with everything minted under it.
    ///
    /// ## Why hide at the data level, not only in the query
    ///
    /// Rewriting the caller's query can only restrict the variables
    /// it recognizes as a dataset subject: a sibling `UNION`/`OPTIONAL`
    /// branch, or any triple pattern on another variable, can still
    /// read a hidden dataset's triples. Filtering the data the query
    /// runs over is sound for every query shape, because no pattern
    /// can match a triple that is not there.
    ///
    /// ## What is hidden
    ///
    /// A quad is dropped when its subject or object belongs to a
    /// dataset or data service ([`owning_resource_iri`]) that is not in
    /// `visible_resource_iris` - so the catalog's own `dcat:dataset` /
    /// `dcat:service` links to it disappear too. This store never mints
    /// blank nodes, so every such resource is reachable that way.
    ///
    /// - **An allow-list, not a deny-list.** A dataset or service
    ///   harvested after the caller computed its allow-list (a crawl
    ///   landing mid-request) is hidden, not leaked.
    /// - **No position numbers.** Every `internal:sequenceIndex` quad is
    ///   dropped: visible datasets would otherwise keep their original
    ///   positions, and the gaps would show where hidden ones were.
    ///
    /// ## Cost
    ///
    /// Nothing is copied: the query runs through oxigraph's own
    /// evaluator over a [`VisibleDataset`] view of the live store,
    /// which filters each triple-pattern lookup as it happens. A
    /// lookup whose bound subject or object belongs to a hidden
    /// resource returns nothing without reading the store, so its cost
    /// doesn't depend on whether that resource exists. A lookup by a
    /// literal value (e.g. a guessed title) still reads and discards
    /// hidden matches, so its timing can differ slightly when one
    /// exists.
    ///
    /// ## Known differences from [`Self::sparql_query_json`]
    ///
    /// - **Not one snapshot.** Each lookup reads the store as it is at
    ///   that moment (unlike `sparql_query_json`, which reads one
    ///   snapshot per query), and the caller computes
    ///   `visible_resource_iris` before evaluation starts. A crawl
    ///   landing mid-request can therefore show an allow-listed
    ///   dataset's newer triples, including ones whose policy the
    ///   crawl tightened. Use [`Self::sparql_query_json_policy_filtered`],
    ///   which computes the allow-list and evaluates on one store state,
    ///   when the allow-list comes from the catalogs in the store.
    /// - **No numeric canonicalization.** Terms are compared as written:
    ///   `"01"^^xsd:integer` in a query doesn't match a stored `1`. The
    ///   only typed numbers this store writes are the position numbers
    ///   this view drops anyway.
    pub fn sparql_query_json_restricted(
        &self,
        query: &str,
        visible_resource_iris: &BTreeSet<String>,
    ) -> SparqlQueryResult<Vec<u8>> {
        self.sparql_query_json_limited(query, Some(visible_resource_iris), &SparqlLimits::default())
    }

    /// [`Self::sparql_query_json_restricted`] with the allow-list computed
    /// from the store's own catalogs, on the same store state the query
    /// reads.
    ///
    /// `allow_list` receives every catalog ([`Self::catalogs`]) and
    /// returns the resource IRIs the caller may see. Filtered evaluation
    /// reads the store once per lookup (see [`VisibleDataset`]), so a
    /// write landing between the allow-list and the end of evaluation
    /// would mix two states: a join could see an old graph and a new one,
    /// and an allow-list built from old policies would admit new data.
    /// The cache counts writes (`write_sequence`); when a write overlapped
    /// the attempt, its result is discarded and the whole attempt,
    /// allow-list included, runs again. After [`POLICY_FILTERED_ATTEMPTS`]
    /// attempts the call returns [`SparqlError::StoreBusy`].
    ///
    /// Waiting for a write that is still committing does not use up an
    /// attempt; it is bounded by `WRITE_WAIT` and by the caller's
    /// cancellation token. A cancelled token also ends the call before
    /// any further attempt, whatever the last attempt returned: oxigraph
    /// checks the token only when it reads the store, so a query that
    /// never does would otherwise be re-run in full after its caller gave
    /// up.
    ///
    /// Writers are never blocked. A crawl that commits rarely sees one
    /// retry; one that commits continuously can starve a long query,
    /// which then ends in `StoreBusy` (or the caller's time limit).
    /// `allow_list` may therefore run more than once.
    ///
    /// Alternatives considered: a store transaction gives a read view but
    /// takes the in-memory backend's single writer lock for the whole
    /// query, and oxigraph exposes no public snapshot to hand to both the
    /// allow-list and `VisibleDataset`.
    pub fn sparql_query_json_policy_filtered(
        &self,
        query: &str,
        mut allow_list: impl FnMut(&[Catalog]) -> BTreeSet<String>,
        limits: &SparqlLimits,
    ) -> SparqlQueryResult<Vec<u8>> {
        let cancelled = || {
            limits
                .cancellation
                .as_ref()
                .is_some_and(|token| token.is_cancelled())
        };
        for _ in 0..POLICY_FILTERED_ATTEMPTS {
            // A caller that gave up gets no further attempt, even when the
            // last one ended with a result: a query that never reads the
            // store cannot be interrupted, and each re-run would hold the
            // caller's evaluation slot for its full duration.
            if cancelled() {
                return Err(SparqlError::Cancelled);
            }
            // A write is committing: wait it out, bounded by `WRITE_WAIT`,
            // without using up an attempt.
            let waiting_since = std::time::Instant::now();
            let before = loop {
                let sequence = self.write_sequence.load(Ordering::SeqCst);
                if sequence.is_multiple_of(2) {
                    break sequence;
                }
                if cancelled() {
                    return Err(SparqlError::Cancelled);
                }
                if waiting_since.elapsed() >= WRITE_WAIT {
                    return Err(SparqlError::StoreBusy);
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
            };
            let catalogs = self
                .catalogs(CatalogQuery::all())
                .map_err(|err| SparqlError::Store(err.to_string()))?;
            let visible = allow_list(&catalogs);
            drop(catalogs);
            let result = self.sparql_query_json_limited(query, Some(&visible), limits);
            if self.write_sequence.load(Ordering::SeqCst) == before {
                return result;
            }
            if cancelled() {
                return Err(SparqlError::Cancelled);
            }
        }
        Err(SparqlError::StoreBusy)
    }

    /// [`Self::sparql_query_json`] (`visible_resource_iris: None`) or
    /// [`Self::sparql_query_json_restricted`] (`Some`), bounded by
    /// `limits` - see [`SparqlLimits`].
    pub fn sparql_query_json_limited(
        &self,
        query: &str,
        visible_resource_iris: Option<&BTreeSet<String>>,
        limits: &SparqlLimits,
    ) -> SparqlQueryResult<Vec<u8>> {
        let prepared = Self::prepare_sparql(query, limits.cancellation.clone())?;
        let results = match visible_resource_iris {
            None => prepared.on_store(self.store.inner()).execute(),
            Some(visible_resource_iris) => prepared
                .on_queryable_dataset(VisibleDataset {
                    store: self.store.inner(),
                    visible_resource_iris,
                })
                .execute(),
        }
        .map_err(evaluation_error)?;
        serialize_sparql_results(results, limits.max_rows)
    }

    /// Whether `query` parses as a SPARQL query this store would evaluate,
    /// without evaluating it: [`SparqlError::Parse`] when it doesn't. Cheap
    /// enough to run before committing any evaluation resources.
    pub fn check_sparql(query: &str) -> SparqlQueryResult<()> {
        Self::prepare_sparql(query, None).map(|_| ())
    }

    /// Parses `query` (Query grammar only - see "Why this is inherently
    /// read-only" on [`Self::sparql_query_json`]) and defaults its
    /// dataset to the union of every named graph.
    pub(super) fn prepare_sparql(
        query: &str,
        cancellation: Option<CancellationToken>,
    ) -> SparqlQueryResult<PreparedSparqlQuery> {
        let mut evaluator = SparqlEvaluator::new();
        if let Some(token) = cancellation {
            evaluator = evaluator.with_cancellation_token(token);
        }
        let mut prepared = evaluator
            .parse_query(query)
            .map_err(|err| SparqlError::Parse(err.to_string()))?;

        if prepared.dataset().is_default_dataset() {
            prepared.dataset_mut().set_default_graph_as_union();
        }
        Ok(prepared)
    }
}

pub(super) fn evaluation_error(err: QueryEvaluationError) -> SparqlError {
    match err {
        QueryEvaluationError::Cancelled => SparqlError::Cancelled,
        // The evaluator reads the store through a dataset whose only
        // error is a storage failure: a server fault, not a bad query.
        QueryEvaluationError::Dataset(err) => SparqlError::Store(err.to_string()),
        err => SparqlError::Evaluation(err.to_string()),
    }
}

pub(super) fn serialize_sparql_results(
    results: QueryResults<'_>,
    max_rows: Option<usize>,
) -> SparqlQueryResult<Vec<u8>> {
    let serializer = QueryResultsSerializer::from_format(QueryResultsFormat::Json);
    match results {
        QueryResults::Boolean(value) => serializer
            .serialize_boolean_to_writer(Vec::new(), value)
            .map_err(|err| SparqlError::Serialize(err.to_string())),
        QueryResults::Solutions(solutions) => {
            let variables = solutions.variables().to_vec();
            let mut writer = serializer
                .serialize_solutions_to_writer(Vec::new(), variables)
                .map_err(|err| SparqlError::Serialize(err.to_string()))?;
            for (row, solution) in solutions.enumerate() {
                if let Some(max_rows) = max_rows
                    && row >= max_rows
                {
                    return Err(SparqlError::TooManyRows(max_rows));
                }
                let solution = solution.map_err(evaluation_error)?;
                writer
                    .serialize(&solution)
                    .map_err(|err| SparqlError::Serialize(err.to_string()))?;
            }
            writer
                .finish()
                .map_err(|err| SparqlError::Serialize(err.to_string()))
        }
        QueryResults::Graph(_) => Err(SparqlError::UnsupportedGraphResult),
    }
}

/// The harvested resource `iri` belongs to, for allow-list purposes.
/// Fails closed: anything this store minted under a node other than
/// the node IRI itself and its catalogs belongs to *something*, and is
/// visible only when that something is on the allow-list.
///
/// - `None` (never gated): any IRI outside [`NODE_NS`], the node IRI
///   itself, and `{node_base}/catalogs/...`, which `GET /catalog` shows
///   every caller too.
/// - `{node_base}/datasets/{id}` or `{node_base}/services/{id}`, for
///   that IRI or anything minted under it. `id` may be empty: an
///   `"@id": ""` dataset is still that dataset ([`dataset_resource_iri`]
///   with an empty id produces exactly this owner).
/// - `iri` itself, for anything else under a node: nothing is allowed
///   to list it, so it stays hidden.
///
/// Node, dataset and service ids are percent-encoded, so none of them
/// can contain a literal `/`.
pub(super) fn owning_resource_iri(iri: &str) -> Option<&str> {
    let rest = iri.strip_prefix(NODE_NS)?;
    let (node, tail) = rest.split_once('/')?;
    let (kind, after_kind) = tail.split_once('/').unwrap_or((tail, ""));
    match kind {
        "catalogs" => None,
        "datasets" | "services" if tail.len() > kind.len() => {
            let id = after_kind.split('/').next().unwrap_or("");
            Some(&iri[..NODE_NS.len() + node.len() + 1 + kind.len() + 1 + id.len()])
        }
        _ => Some(iri),
    }
}

/// `internal:sequenceIndex`, as a constant string so the per-quad check
/// in [`quad_is_visible`] doesn't rebuild and re-validate the IRI.
pub(super) const SEQUENCE_INDEX_IRI: &str =
    "https://federated-catalog-rs.internal/ns#sequenceIndex";

/// Whether `iri` is outside every resource, or belongs to one on
/// `visible_resource_iris` - see [`owning_resource_iri`].
pub(super) fn iri_is_visible(iri: &str, visible_resource_iris: &BTreeSet<String>) -> bool {
    owning_resource_iri(iri).is_none_or(|owner| visible_resource_iris.contains(owner))
}

/// Whether a caller restricted to `visible_resource_iris` may see
/// `quad` - see [`OxigraphCatalogCache::sparql_query_json_restricted`].
pub(super) fn quad_is_visible(quad: &Quad, visible_resource_iris: &BTreeSet<String>) -> bool {
    if quad.predicate.as_str() == SEQUENCE_INDEX_IRI {
        return false;
    }
    let subject_visible = match &quad.subject {
        NamedOrBlankNode::NamedNode(node) => iri_is_visible(node.as_str(), visible_resource_iris),
        NamedOrBlankNode::BlankNode(_) => true,
    };
    let object_visible = match &quad.object {
        Term::NamedNode(node) => iri_is_visible(node.as_str(), visible_resource_iris),
        Term::BlankNode(_) | Term::Literal(_) => true,
        // A triple term (only with oxigraph's RDF 1.2 support, which this
        // workspace doesn't enable, and never written by this store):
        // hidden rather than inspected.
        #[allow(unreachable_patterns)]
        _ => false,
    };
    subject_visible && object_visible
}

/// Whether `graph` holds a `dcat:Catalog` type quad.
pub(super) fn graph_holds_a_catalog(
    store: &oxigraph::store::Store,
    graph: NamedOrBlankNodeRef<'_>,
) -> Result<bool, StorageError> {
    store
        .quads_for_pattern(
            None,
            Some(rdf_type().as_ref()),
            Some(dcat_catalog_class().as_ref().into()),
            Some(graph.into()),
        )
        .next()
        .transpose()
        .map(|quad| quad.is_some())
}

// Test seam: runs once per triple-pattern lookup of a `VisibleDataset`
// on the evaluating thread. A test installs a closure to write to the
// store in the middle of an evaluation, or to make a lookup fail with a
// storage error.
#[cfg(test)]
thread_local! {
    pub(super) static LOOKUP_HOOK: std::cell::RefCell<Option<Box<dyn FnMut() -> Option<StorageError>>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn lookup_hook() -> Option<StorageError> {
    // Taken out while it runs, so a hook that itself queries the store
    // does not re-enter it.
    let mut hook = LOOKUP_HOOK.with(|hook| hook.borrow_mut().take())?;
    let injected = hook();
    LOOKUP_HOOK.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(hook);
        }
    });
    injected
}

#[cfg(not(test))]
fn lookup_hook() -> Option<StorageError> {
    None
}

/// The live store, minus every quad [`quad_is_visible`] rejects, as a
/// dataset oxigraph's SPARQL evaluator can query directly. Terms are
/// passed through as plain [`Term`]s; `FROM`/`FROM NAMED` and the
/// default-graph-as-union setting are applied by the evaluator on top
/// of this view, exactly as for [`Store`](oxigraph::store::Store).
#[derive(Clone, Copy)]
pub(super) struct VisibleDataset<'a> {
    store: &'a oxigraph::store::Store,
    visible_resource_iris: &'a BTreeSet<String>,
}

impl<'a> QueryableDataset<'a> for VisibleDataset<'a> {
    type InternalTerm = Term;
    type Error = StorageError;

    fn internal_quads_for_pattern(
        &self,
        subject: Option<&Term>,
        predicate: Option<&Term>,
        object: Option<&Term>,
        graph_name: Option<Option<&Term>>,
    ) -> impl Iterator<Item = Result<InternalQuad<Term>, StorageError>> + use<'a> {
        let Self {
            store,
            visible_resource_iris,
        } = *self;

        // A bound term that cannot appear in that position (a literal
        // subject, a non-IRI predicate, a literal graph name) matches
        // nothing.
        let subject = match subject {
            None => Some(None),
            Some(Term::NamedNode(node)) => Some(Some(NamedOrBlankNodeRef::from(node))),
            Some(Term::BlankNode(node)) => Some(Some(NamedOrBlankNodeRef::from(node))),
            Some(_) => None,
        };
        let predicate = match predicate {
            None => Some(None),
            Some(Term::NamedNode(node)) => Some(Some(node.as_ref())),
            Some(_) => None,
        };
        // `None` = any named graph (not the default one), per
        // `QueryableDataset`'s contract.
        let graph = match graph_name {
            None => Some(None),
            Some(None) => Some(Some(GraphNameRef::DefaultGraph)),
            Some(Some(Term::NamedNode(node))) => Some(Some(GraphNameRef::from(node))),
            Some(Some(Term::BlankNode(node))) => Some(Some(GraphNameRef::from(node))),
            Some(Some(_)) => None,
        };
        let named_graphs_only = graph_name.is_none();

        // A bound subject or object owned by a hidden resource can match
        // nothing visible: answer without reading the store, so lookup
        // cost doesn't reveal whether the hidden resource exists.
        let bound_iri_hidden = [
            subject.flatten(),
            object.and_then(|o| match o {
                Term::NamedNode(node) => Some(NamedOrBlankNodeRef::from(node)),
                _ => None,
            }),
        ]
        .into_iter()
        .flatten()
        .any(|term| match term {
            NamedOrBlankNodeRef::NamedNode(node) => {
                !iri_is_visible(node.as_str(), visible_resource_iris)
            }
            NamedOrBlankNodeRef::BlankNode(_) => false,
        });

        let injected = lookup_hook();
        let quads = match (subject, predicate, graph) {
            _ if bound_iri_hidden => None,
            (Some(subject), Some(predicate), Some(graph)) => {
                Some(store.quads_for_pattern(subject, predicate, object.map(Term::as_ref), graph))
            }
            _ => None,
        };

        let quads = injected
            .into_iter()
            .map(Err)
            .chain(quads.into_iter().flatten());
        quads.filter_map(move |quad| {
            let quad = match quad {
                Ok(quad) => quad,
                Err(err) => return Some(Err(err)),
            };
            if named_graphs_only && quad.graph_name.is_default_graph() {
                return None;
            }
            if !quad_is_visible(&quad, visible_resource_iris) {
                return None;
            }
            Some(Ok(InternalQuad {
                subject: quad.subject.into(),
                predicate: quad.predicate.into(),
                object: quad.object,
                graph_name: match quad.graph_name {
                    GraphName::DefaultGraph => None,
                    GraphName::NamedNode(node) => Some(node.into()),
                    GraphName::BlankNode(node) => Some(node.into()),
                },
            }))
        })
    }

    /// Every named graph holding a catalog. Each graph this store
    /// writes holds its `dcat:Catalog` type quad, which is never
    /// hidden, so this lists exactly the graphs with visible content -
    /// straight from the store's graph index rather than the trait's
    /// default full-quad scan, which made `GRAPH ?g {}` cost a scan of
    /// the whole store per evaluation.
    fn internal_named_graphs(&self) -> impl Iterator<Item = Result<Term, StorageError>> + use<'a> {
        let store = self.store;
        store.named_graphs().filter_map(move |graph| match graph {
            Err(err) => Some(Err(err)),
            Ok(graph) => match graph_holds_a_catalog(store, graph.as_ref()) {
                Ok(true) => Some(Ok(graph.into())),
                Ok(false) => None,
                Err(err) => Some(Err(err)),
            },
        })
    }

    fn contains_internal_graph_name(&self, graph_name: &Term) -> Result<bool, StorageError> {
        match graph_name {
            Term::NamedNode(node) => graph_holds_a_catalog(self.store, node.as_ref().into()),
            Term::BlankNode(node) => graph_holds_a_catalog(self.store, node.as_ref().into()),
            _ => Ok(false),
        }
    }

    fn internalize_term(&self, term: Term) -> Result<Term, StorageError> {
        Ok(term)
    }

    fn externalize_term(&self, term: Term) -> Result<Term, StorageError> {
        Ok(term)
    }
}
