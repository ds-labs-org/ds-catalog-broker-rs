//! SPARQL query-rewriting ODRL policy filtering for `GET`/`POST /sparql`
//! (gap analysis §3.4's last remaining serving surface - `GET /catalog`
//! and the management API were already closed by `odrl_filter`'s own
//! `dataset_is_visible`/`filter_catalogs_by_policy`; see that module's own
//! doc comment). SPARQL is the hard one: named graphs in the semantic
//! cache are per-*participant* (`rdf_store::oxigraph_backend`'s own module
//! doc), not per-*dataset*, and ODRL policies are attached per-*dataset*,
//! so there is no coarser `GRAPH <iri>` scope to filter on - the only way
//! to keep a policy-gated dataset's triples out of an arbitrary
//! caller-supplied query's results is to rewrite the query itself.
//!
//! ## Why rewrite the parsed algebra, not the query *text*
//!
//! The obvious-looking shortcut - find `?x a dcat:Dataset` by scanning the
//! query *string* and splice a `VALUES ?x { ... }`/`FILTER(...)` clause
//! into the text near it - is exactly the kind of "reconstruct structure
//! from printed text instead of the real thing" mistake this same
//! organization already hit once, building a similar feature in the
//! sibling `ds-sql-dps-rs` project (`config-graph/src/store.rs`): a name
//! that looks stable in printed form (there, a blank node's label; here, a
//! variable's name) can silently mean something other than what the text
//! suggests once scoping is involved (there, a *query-string-local* blank
//! node identity; here, a variable shadowed by a subquery's own
//! projection). Splicing `VALUES`/`FILTER` text near *a* textual
//! occurrence of `?x` cannot tell whether that occurrence is the same `?x`
//! the outer query result actually exposes, or a same-named but
//! *different*, subquery-scoped variable that never escapes it - the
//! rewritten clause would then silently filter nothing at all for that
//! query, exactly the "unenforceable check that silently permits
//! everything" failure class
//! `docs/spikes/2026-08-27-edc-catalog-metadata-exposure-policy.md`
//! documents.
//!
//! So this module never touches query *text* except to parse it once (via
//! `spargebra::SparqlParser`, the exact same SPARQL algebra parser
//! `oxigraph` itself depends on - see this crate's own `Cargo.toml` for
//! why that dependency is pinned to oxigraph's own exact version) and to
//! print the rewritten result back out (via that same crate's own
//! `Display` impls, proven by its own doc tests to round-trip). Everything
//! in between - finding which variables genuinely denote a harvested
//! dataset's subject IRI *at the query's own top scope*, and inserting a
//! restriction that only touches those - works on the real parsed
//! [`spargebra::algebra::GraphPattern`] tree, where SPARQL's own variable
//! scoping rules (`Project`/`Group`'s `variables` list is the *only* thing
//! that lets a variable escape a subquery boundary) are already
//! unambiguous, structural facts about the tree rather than something this
//! module would otherwise have to reimplement by guessing at brace/scope
//! nesting in a query string.
//!
//! ## What counts as a "dataset-subject-shaped variable"
//!
//! Deliberately narrow: a variable is a candidate only where it is the
//! *subject* of a triple pattern whose predicate is `rdf:type` (either
//! spelled `a` or `rdf:type` in the source text - both parse to the exact
//! same absolute predicate IRI in the algebra tree, so this module never
//! has to special-case the spelling) and whose object is exactly
//! `dcat:Dataset` ([`collect_dataset_subject_variables`]). Nothing else
//! (navigating to a dataset via `dcat:dataset`/`dcat:distribution` without
//! ever typing it, or a `FILTER(?type = dcat:Dataset)` instead of a type
//! triple) is recognized - see this module's own doc comment further down
//! ("Known residual gaps") for what that narrowness costs, and why the
//! conservative direction (treating an unrecognized shape as unscopeable,
//! not as scoped-and-safe) is the one it costs on.
//!
//! ## The restriction itself: `FILTER(!BOUND(?x) || ?x IN (...))`, not `VALUES`
//!
//! A naive `VALUES ?x { <iri> ... }` joined against the query's pattern
//! has a real correctness trap of its own: SPARQL's `Join` semantics bind
//! *any* variable the join partner doesn't already constrain, rather than
//! leaving it alone - so for a solution row where `?x` happens not to be
//! bound at all (e.g. one `UNION` branch that never touches a dataset
//! subject under that name), joining it against `VALUES ?x { ... }` would
//! *manufacture* a spurious `?x` binding for that row rather than passing
//! it through untouched. `FILTER(!BOUND(?x) || ?x IN (...))` instead only
//! ever *tests* `?x`, never binds it: a row where `?x` is unbound passes
//! through completely unchanged (the restriction has nothing to say about
//! it - see "Known residual gaps" below for what that still leaves open),
//! and a row where `?x` *is* bound must have a value in the allow-list.
//! Multiple distinct dataset-subject variables (e.g. one per `UNION`
//! branch, each named differently) each get their own `!BOUND || IN`
//! clause, `AND`ed together ([`combined_restriction`]).
//!
//! ## Known residual gaps (documented, not silently claimed away)
//!
//! This is a real, working query-rewriting filter for the common query
//! shapes this endpoint's own existing test suite already exercises
//! (`SELECT`/`ASK`, `ORDER BY`/`LIMIT`, multi-pattern `WHERE` clauses), but
//! it is not - and cannot be, short of a full query-intent classifier -
//! a sound filter for every SPARQL query shape:
//!
//! - **A dataset-subject variable that never escapes a subquery's own
//!   `SELECT` list is invisible to this module**, by the same
//!   `Project`-boundary logic that makes the rest of it sound (see
//!   [`collect_dataset_subject_variables`]'s own doc comment). Such a
//!   query is rejected as unscopeable per
//!   [`odrl_filter::UnscopeableSparqlQueryAction`]'s default - safe (denies
//!   rather than leaks) but a real availability cost for a legitimate
//!   nested-subquery query this module could not have scoped correctly
//!   anyway.
//! - **A `GROUP BY`/aggregate query only gets a scoped dataset variable
//!   when that variable is itself one of the `GROUP BY` keys** - one used
//!   only *inside* an aggregate expression (e.g. `COUNT(DISTINCT ?dataset)`
//!   grouped by something else) does not escape the `Group` node either,
//!   for the same reason, and is rejected as unscopeable too.
//! - **A query that reveals dataset data through a pattern this module
//!   does not recognize as dataset-typing at all is not protected by the
//!   fact that some *other* part of the same query happens to be
//!   recognized.** For example, a query mixing a recognized
//!   `?x a dcat:Dataset` pattern in one `UNION`/`OPTIONAL` branch with an
//!   unrelated pattern exposing other harvested triples under a
//!   *different* variable in a sibling branch is accepted as "scopeable"
//!   (because `?x` was found), rewritten, and run - but the sibling
//!   branch's own data is not restricted by this filter at all, since
//!   nothing ties it to any dataset-subject variable this module
//!   recognizes. This is the module's most significant residual gap:
//!   soundness here is per-recognized-variable, not per-query. A
//!   deployment with real concerns about this query shape should treat
//!   `GET`/`POST /sparql` as a coarser-grained capability (behind a scope
//!   only trusted internal tooling receives) rather than relying on this
//!   filter alone as a hard per-triple security boundary against
//!   arbitrary caller-supplied queries.
//! - **`CONSTRUCT`/`DESCRIBE` are still rejected outright by
//!   `sparql_query_json`** (`SparqlError::UnsupportedGraphResult`) after
//!   this module runs, same as before this feature existed - this module
//!   rewrites their pattern the same as any other query form (so a
//!   scopeable one is rewritten correctly, in case that restriction is
//!   ever lifted) but the net effect today is unchanged: still a 400.
//! - **Property paths** (`?x a/rdf:type dcat:Dataset`, `^dcat:dataset`,
//!   etc.) are never recognized - `spargebra`'s algebra only routes a
//!   *literal* `a`/`rdf:type` predicate through an ordinary
//!   [`spargebra::term::TriplePattern`] inside a
//!   [`spargebra::algebra::GraphPattern::Bgp`]; anything expressed as an
//!   actual property-path expression parses into
//!   `GraphPattern::Path` instead, which this module does not inspect (see
//!   [`collect_dataset_subject_variables`]'s own `Path` arm). Conservative
//!   in the same direction as the rest of this list: such a query is
//!   simply not found to be scopeable via that occurrence, not silently
//!   treated as safe.

use std::collections::BTreeSet;

use spargebra::algebra::{Expression, GraphPattern, OrderExpression};
use spargebra::term::{NamedNode, NamedNodePattern, TermPattern, TriplePattern, Variable};
use spargebra::{Query, SparqlParser};

/// The absolute `rdf:type` predicate IRI - what both the `a` shorthand and
/// a written-out `rdf:type` (however that prefix happens to be bound, or
/// not bound at all - "rdf:type" is one of the handful of SPARQL keywords
/// usable with no `PREFIX` declaration) resolve to once parsed, per the
/// [SPARQL grammar](https://www.w3.org/TR/sparql11-query/#rVerb).
/// Restated here (`spargebra`'s own resolved value is not part of its
/// public API to depend on by name) rather than depended on, matching this
/// crate's own established precedent for restating a fixed vocabulary
/// term a dependency doesn't expose as a public constant (see
/// `odrl_filter::ODRL_NS`'s own doc comment for the exact same call).
const RDF_TYPE_IRI: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

/// The absolute `dcat:Dataset` class IRI, matching
/// `rdf_store::oxigraph_backend`'s own `DCAT_NS`/`dcat_dataset_class()` -
/// restated for the same reason [`RDF_TYPE_IRI`] is (that module's
/// constants are private to `rdf-store`, not part of its public API).
const DCAT_DATASET_IRI: &str = "http://www.w3.org/ns/dcat#Dataset";

/// No variable anywhere in the query's own top scope (see this module's
/// own doc comment, "What counts as a dataset-subject-shaped variable")
/// denotes a harvested dataset's subject IRI - there is nothing for
/// [`restrict_to_visible_dataset_iris`] to inject a per-caller restriction
/// onto. What the caller (`sparql_route`) does with this is governed by
/// [`odrl_filter::PolicyFilterConfig::unscopeable_sparql_query_action`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnscopeableQuery;

/// Rewrites `query` so that every recognized dataset-subject variable is
/// restricted to `visible_dataset_iris` (see this module's own doc comment
/// for the full design and its documented residual gaps), returning the
/// rewritten query as SPARQL text ready to hand to
/// [`rdf_store::oxigraph_backend::OxigraphCatalogCache::sparql_query_json`].
///
/// - `query` fails to parse as a SPARQL **Query** at all (bad syntax, or a
///   SPARQL **Update** string - a different grammar entirely, the same
///   distinction `sparql_query_json`'s own doc comment relies on for its
///   read-only guarantee): returned unchanged, `Ok(query.to_string())`.
///   This is deliberately *not* an error from this function's own point of
///   view - a query that cannot be parsed can never reach evaluation
///   either (`sparql_query_json` parses with the exact same grammar and
///   will reject it the same way it always has), so passing it through
///   unrewritten costs nothing in safety and preserves this endpoint's
///   existing bad-syntax error message and status code unchanged.
/// - No dataset-subject variable found anywhere in `query`'s own top
///   scope: `Err(UnscopeableQuery)`.
/// - Otherwise: `Ok(rewritten)`, the same query with a
///   `FILTER(!BOUND(?v) || ?v IN (...))` restriction (one clause per
///   recognized variable, `AND`ed together - see this module's own doc
///   comment for why `FILTER`, not `VALUES`) inserted into its own true
///   `WHERE`-clause scope (past any `ORDER BY`/`Project`/`DISTINCT`/
///   `REDUCED`/`LIMIT`/`OFFSET` wrapper - see [`peel_modifiers`]), so the
///   restriction applies to the query's real result rows rather than
///   (invalidly) sitting outside the printed `WHERE { ... }` block once
///   re-serialized.
pub fn restrict_to_visible_dataset_iris(
    query: &str,
    visible_dataset_iris: &BTreeSet<String>,
) -> Result<String, UnscopeableQuery> {
    let Ok(parsed) = SparqlParser::new().parse_query(query) else {
        return Ok(query.to_string());
    };

    // A dataset IRI this store itself minted (`dataset_resource_iri`) is
    // always a valid absolute IRI - `filter_map` here is defense in depth
    // against a future caller of this function passing an arbitrary
    // string in, not a case real callers of this module are expected to
    // hit.
    let allowed: Vec<NamedNode> = visible_dataset_iris
        .iter()
        .filter_map(|iri| NamedNode::new(iri.clone()).ok())
        .collect();

    rewrite_query(parsed, &allowed).map(|query| query.to_string())
}

fn rewrite_query(query: Query, allowed: &[NamedNode]) -> Result<Query, UnscopeableQuery> {
    Ok(match query {
        Query::Select {
            dataset,
            pattern,
            base_iri,
        } => Query::Select {
            dataset,
            pattern: inject_restriction(pattern, allowed)?,
            base_iri,
        },
        Query::Ask {
            dataset,
            pattern,
            base_iri,
        } => Query::Ask {
            dataset,
            pattern: inject_restriction(pattern, allowed)?,
            base_iri,
        },
        Query::Construct {
            template,
            dataset,
            pattern,
            base_iri,
        } => Query::Construct {
            template,
            dataset,
            pattern: inject_restriction(pattern, allowed)?,
            base_iri,
        },
        Query::Describe {
            dataset,
            pattern,
            base_iri,
        } => Query::Describe {
            dataset,
            pattern: inject_restriction(pattern, allowed)?,
            base_iri,
        },
    })
}

fn inject_restriction(
    pattern: GraphPattern,
    allowed: &[NamedNode],
) -> Result<GraphPattern, UnscopeableQuery> {
    let variables = collect_dataset_subject_variables(&pattern);
    if variables.is_empty() {
        return Err(UnscopeableQuery);
    }
    let expr = combined_restriction(&variables, allowed);

    let (modifiers, core) = peel_modifiers(pattern);
    let restricted_core = GraphPattern::Filter {
        expr,
        inner: Box::new(core),
    };
    Ok(rewrap_modifiers(modifiers, restricted_core))
}

/// `tp`'s subject, if `tp` is exactly `?subject a dcat:Dataset` (in either
/// resolved-IRI spelling - see [`RDF_TYPE_IRI`]'s own doc comment).
fn dataset_subject_variable(tp: &TriplePattern) -> Option<Variable> {
    let TermPattern::Variable(subject) = &tp.subject else {
        return None;
    };
    let NamedNodePattern::NamedNode(predicate) = &tp.predicate else {
        return None;
    };
    if predicate.as_str() != RDF_TYPE_IRI {
        return None;
    }
    let TermPattern::NamedNode(object) = &tp.object else {
        return None;
    };
    if object.as_str() != DCAT_DATASET_IRI {
        return None;
    }
    Some(subject.clone())
}

/// Every variable that is both (a) the subject of a `?x a dcat:Dataset`
/// triple pattern *somewhere* in `pattern`, and (b) still visible/bound at
/// `pattern`'s own top scope - i.e. it survives every `Project`/`Group`
/// boundary between where it was found and the top, per each such
/// boundary's own `variables` list (SPARQL's actual variable-scoping rule:
/// a `Project`/`Group` node's output rows carry *only* the variables named
/// in its own `variables` field - see this module's own doc comment,
/// "Why rewrite the parsed algebra, not the query text", for why this
/// structural check is exactly the thing a text-level rewrite cannot do
/// soundly).
///
/// Every other [`GraphPattern`] combinator either passes a variable's
/// visibility straight through unchanged (`Filter`/`Graph`/`Extend`/
/// `OrderBy`/`Distinct`/`Reduced`/`Slice`/`Service`) or unions the two
/// sides' visible variables (`Join`/`LeftJoin`/`Union`/`Lateral` - a
/// variable found on either side is still a real, nameable variable at
/// this level, even if some solutions leave it unbound; see this module's
/// own doc comment for why the restriction this feeds into is a `FILTER`,
/// which handles an unbound occurrence safely, rather than a `VALUES` join,
/// which would not). `Minus`'s right-hand side never contributes new
/// bindings to the result at all (it only ever removes rows), so only its
/// `left` is considered. `Values` and `Path` never establish dataset-type
/// membership on their own (see this module's own doc comment's "Known
/// residual gaps" for `Path`) and contribute nothing.
fn collect_dataset_subject_variables(pattern: &GraphPattern) -> BTreeSet<Variable> {
    match pattern {
        GraphPattern::Bgp { patterns } => patterns
            .iter()
            .filter_map(dataset_subject_variable)
            .collect(),
        GraphPattern::Path { .. } | GraphPattern::Values { .. } => BTreeSet::new(),
        GraphPattern::Join { left, right }
        | GraphPattern::LeftJoin { left, right, .. }
        | GraphPattern::Union { left, right }
        // `Lateral` (SEP-0006, `LATERAL { ... }`) - this crate's own
        // `spargebra` dependency always enables that feature (see this
        // workspace's own root `Cargo.toml`), so the variant always exists
        // here; there is no matching Cargo *feature* of our own crate to
        // gate this arm on (unlike `spargebra`'s own internal
        // `#[cfg(feature = "sep-0006")]` uses, which do gate a variant that
        // may or may not exist in *its* build).
        | GraphPattern::Lateral { left, right } => {
            let mut vars = collect_dataset_subject_variables(left);
            vars.extend(collect_dataset_subject_variables(right));
            vars
        }
        GraphPattern::Minus { left, .. } => collect_dataset_subject_variables(left),
        GraphPattern::Filter { inner, .. }
        | GraphPattern::Graph { inner, .. }
        | GraphPattern::Extend { inner, .. }
        | GraphPattern::OrderBy { inner, .. }
        | GraphPattern::Distinct { inner }
        | GraphPattern::Reduced { inner }
        | GraphPattern::Slice { inner, .. }
        | GraphPattern::Service { inner, .. } => collect_dataset_subject_variables(inner),
        GraphPattern::Project { inner, variables } => {
            let projected: BTreeSet<Variable> = variables.iter().cloned().collect();
            collect_dataset_subject_variables(inner)
                .into_iter()
                .filter(|v| projected.contains(v))
                .collect()
        }
        GraphPattern::Group {
            inner, variables, ..
        } => {
            let grouped: BTreeSet<Variable> = variables.iter().cloned().collect();
            collect_dataset_subject_variables(inner)
                .into_iter()
                .filter(|v| grouped.contains(v))
                .collect()
        }
    }
}

/// One layer of the fixed "SELECT modifier stack"
/// (`ORDER BY`/`Project`(the `SELECT` variable list itself)/`DISTINCT`/
/// `REDUCED`/`LIMIT`+`OFFSET`) [`peel_modifiers`] strips off the top of a
/// query's pattern and [`rewrap_modifiers`] puts back once the restriction
/// is inserted underneath all of them - mirroring exactly the same
/// unwrapping `spargebra`'s own `SparqlGraphRootPattern` `Display` impl
/// does when printing a query back out (peeling this same node sequence
/// off is what recovers a clean `SELECT ... WHERE { ... } ORDER BY ...`
/// surface form rather than nonsensical syntax like a `FILTER` clause
/// appended *after* a `WHERE` block's closing brace).
enum Modifier {
    OrderBy(Vec<OrderExpression>),
    /// Only the *first* (outermost) `Project` layer peeled ever reaches
    /// here - see [`peel_modifiers`]'s own `project_seen` guard, which
    /// mirrors `SparqlGraphRootPattern`'s identical `if project.is_empty()`
    /// guard: a second, *nested* `Project` (a real subquery) is left
    /// alone, as part of the "core" pattern the restriction wraps, not
    /// peeled any further.
    Project(Vec<Variable>),
    Distinct,
    Reduced,
    Slice {
        start: usize,
        length: Option<usize>,
    },
}

/// Strips `pattern`'s own outer modifier-node chain (see [`Modifier`]'s
/// own doc comment), returning the peeled layers (outermost first) and
/// the remaining "core" pattern - the one [`inject_restriction`] actually
/// wraps in a `Filter`.
fn peel_modifiers(pattern: GraphPattern) -> (Vec<Modifier>, GraphPattern) {
    let mut modifiers = Vec::new();
    let mut project_seen = false;
    let mut current = pattern;
    loop {
        current = match current {
            GraphPattern::OrderBy { inner, expression } => {
                modifiers.push(Modifier::OrderBy(expression));
                *inner
            }
            GraphPattern::Project { inner, variables } if !project_seen => {
                project_seen = true;
                modifiers.push(Modifier::Project(variables));
                *inner
            }
            GraphPattern::Distinct { inner } => {
                modifiers.push(Modifier::Distinct);
                *inner
            }
            GraphPattern::Reduced { inner } => {
                modifiers.push(Modifier::Reduced);
                *inner
            }
            GraphPattern::Slice {
                inner,
                start,
                length,
            } => {
                modifiers.push(Modifier::Slice { start, length });
                *inner
            }
            other => return (modifiers, other),
        };
    }
}

/// The exact inverse of [`peel_modifiers`]: re-wraps `core` in `modifiers`,
/// innermost (last-peeled) first, reconstructing the original nesting
/// order around the new, restricted core.
fn rewrap_modifiers(modifiers: Vec<Modifier>, mut core: GraphPattern) -> GraphPattern {
    for modifier in modifiers.into_iter().rev() {
        core = match modifier {
            Modifier::OrderBy(expression) => GraphPattern::OrderBy {
                inner: Box::new(core),
                expression,
            },
            Modifier::Project(variables) => GraphPattern::Project {
                inner: Box::new(core),
                variables,
            },
            Modifier::Distinct => GraphPattern::Distinct {
                inner: Box::new(core),
            },
            Modifier::Reduced => GraphPattern::Reduced {
                inner: Box::new(core),
            },
            Modifier::Slice { start, length } => GraphPattern::Slice {
                inner: Box::new(core),
                start,
                length,
            },
        };
    }
    core
}

/// `!BOUND(?var) || ?var IN (allowed...)` - see this module's own doc
/// comment for why a `FILTER` testing `?var`, rather than a `VALUES` join
/// binding it, is the sound choice here.
fn restriction_expression(var: &Variable, allowed: &[NamedNode]) -> Expression {
    let in_list: Vec<Expression> = allowed
        .iter()
        .map(|iri| Expression::NamedNode(iri.clone()))
        .collect();
    let unbound = Expression::Not(Box::new(Expression::Bound(var.clone())));
    let in_allow_list = Expression::In(Box::new(Expression::Variable(var.clone())), in_list);
    Expression::Or(Box::new(unbound), Box::new(in_allow_list))
}

/// [`restriction_expression`] for every variable in `variables`, `AND`ed
/// together - `variables` is never empty here (its only caller,
/// [`inject_restriction`], already returns [`UnscopeableQuery`] before
/// reaching this function otherwise).
fn combined_restriction(variables: &BTreeSet<Variable>, allowed: &[NamedNode]) -> Expression {
    let mut iter = variables.iter();
    let first = iter
        .next()
        .expect("caller already returned UnscopeableQuery for an empty variable set");
    let mut expr = restriction_expression(first, allowed);
    for var in iter {
        expr = Expression::And(
            Box::new(expr),
            Box::new(restriction_expression(var, allowed)),
        );
    }
    expr
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow_list(iris: &[&str]) -> BTreeSet<String> {
        iris.iter().map(|s| s.to_string()).collect()
    }

    /// Parses back cleanly, and evaluates against a tiny real Oxigraph
    /// store to prove the restriction actually restricts - not just that
    /// the rewritten text looks plausible.
    fn assert_selects_only(query: &str, allowed: &[&str], expect_dataset_iris: &[&str]) {
        let rewritten = restrict_to_visible_dataset_iris(query, &allow_list(allowed))
            .unwrap_or_else(|_| panic!("expected {query:?} to be scopeable"));

        let store = oxigraph::store::Store::new().unwrap();
        let graph = oxigraph::model::NamedNode::new("https://example.org/graph").unwrap();
        for id in ["OPEN-DATASET", "GATED-DATASET"] {
            let subject =
                oxigraph::model::NamedNode::new(format!("https://example.org/datasets/{id}"))
                    .unwrap();
            let predicate = oxigraph::model::NamedNode::new(RDF_TYPE_IRI).unwrap();
            let object = oxigraph::model::NamedNode::new(DCAT_DATASET_IRI).unwrap();
            store
                .insert(&oxigraph::model::Quad::new(
                    subject,
                    predicate,
                    object,
                    graph.clone(),
                ))
                .unwrap();
        }

        let mut prepared = oxigraph::sparql::SparqlEvaluator::new()
            .parse_query(&rewritten)
            .unwrap_or_else(|err| panic!("rewritten query {rewritten:?} failed to parse: {err}"));
        if prepared.dataset().is_default_dataset() {
            prepared.dataset_mut().set_default_graph_as_union();
        }
        let results = prepared.on_store(&store).execute().unwrap();
        let oxigraph::sparql::QueryResults::Solutions(solutions) = results else {
            panic!("expected a SELECT/ASK solutions result");
        };
        let mut got: Vec<String> = solutions
            .map(|solution| {
                let solution = solution.unwrap();
                solution
                    .iter()
                    .map(|(_, term)| term.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .filter(|row| !row.is_empty())
            .collect();
        got.sort();
        let mut expected: Vec<String> = expect_dataset_iris
            .iter()
            .map(|iri| format!("<https://example.org/datasets/{iri}>"))
            .collect();
        expected.sort();
        assert_eq!(
            got, expected,
            "rewritten query: {rewritten}\n(expected only {expect_dataset_iris:?} to survive)"
        );
    }

    #[test]
    fn restricts_a_plain_dataset_select_to_the_allow_list() {
        assert_selects_only(
            "PREFIX dcat: <http://www.w3.org/ns/dcat#> \
             SELECT ?dataset WHERE { ?dataset a dcat:Dataset }",
            &["https://example.org/datasets/OPEN-DATASET"],
            &["OPEN-DATASET"],
        );
    }

    #[test]
    fn empty_allow_list_hides_every_dataset() {
        assert_selects_only(
            "PREFIX dcat: <http://www.w3.org/ns/dcat#> \
             SELECT ?dataset WHERE { ?dataset a dcat:Dataset }",
            &[],
            &[],
        );
    }

    #[test]
    fn recognizes_the_written_out_rdf_type_spelling_too() {
        assert_selects_only(
            "PREFIX dcat: <http://www.w3.org/ns/dcat#> \
             PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> \
             SELECT ?dataset WHERE { ?dataset rdf:type dcat:Dataset }",
            &["https://example.org/datasets/OPEN-DATASET"],
            &["OPEN-DATASET"],
        );
    }

    #[test]
    fn restricts_an_ask_query() {
        let rewritten = restrict_to_visible_dataset_iris(
            "PREFIX dcat: <http://www.w3.org/ns/dcat#> \
             ASK { ?dataset a dcat:Dataset }",
            &allow_list(&["https://example.org/datasets/OPEN-DATASET"]),
        )
        .expect("an ASK query with a dataset-subject variable must be scopeable");
        assert!(
            rewritten.contains("BOUND"),
            "expected the ASK query to be rewritten with the BOUND/IN restriction, got: \
             {rewritten}"
        );
    }

    #[test]
    fn a_query_with_no_dataset_subject_variable_is_unscopeable() {
        let result = restrict_to_visible_dataset_iris(
            "SELECT ?s ?p ?o WHERE { ?s ?p ?o }",
            &allow_list(&["https://example.org/datasets/OPEN-DATASET"]),
        );
        assert_eq!(result, Err(UnscopeableQuery));
    }

    #[test]
    fn a_variable_projected_out_of_a_subquery_is_still_scopeable_at_the_outer_level() {
        assert_selects_only(
            "PREFIX dcat: <http://www.w3.org/ns/dcat#> \
             SELECT ?dataset WHERE { { SELECT ?dataset WHERE { ?dataset a dcat:Dataset } } }",
            &["https://example.org/datasets/OPEN-DATASET"],
            &["OPEN-DATASET"],
        );
    }

    #[test]
    fn a_variable_hidden_inside_a_subqueries_own_projection_is_unscopeable() {
        // The subquery types `?d`, but only ever projects `?title` out of
        // its own SELECT list - `?d` never reaches the outer query's own
        // scope, so there is nothing here this module can soundly restrict
        // (see this module's own doc comment's "Known residual gaps").
        let result = restrict_to_visible_dataset_iris(
            "PREFIX dcat: <http://www.w3.org/ns/dcat#> \
             SELECT ?title WHERE { \
                 { SELECT ?title WHERE { ?d a dcat:Dataset . ?d dcat:title ?title } } \
             }",
            &allow_list(&["https://example.org/datasets/OPEN-DATASET"]),
        );
        assert_eq!(result, Err(UnscopeableQuery));
    }

    #[test]
    fn a_malformed_query_is_passed_through_unchanged() {
        let query = "this is not sparql at all";
        let result = restrict_to_visible_dataset_iris(query, &allow_list(&[]));
        assert_eq!(
            result,
            Ok(query.to_string()),
            "a query this module cannot even parse must be passed through unchanged - it can \
             never reach evaluation either, so `sparql_query_json`'s own parser produces the \
             same error it always has"
        );
    }

    #[test]
    fn a_sparql_update_string_is_passed_through_unchanged() {
        // Update ("INSERT DATA { ... }") is a different grammar entirely -
        // `SparqlParser::parse_query` fails on it the same way it fails on
        // any other malformed Query string, so this hits the same
        // pass-through path as the malformed-query test above. Restated
        // here anyway as its own test since it's the one case
        // `sparql_query_json`'s own doc comment calls out by name as the
        // read-only guarantee's actual mechanism.
        let query = "INSERT DATA { <urn:x> a <urn:Thing> }";
        let result = restrict_to_visible_dataset_iris(query, &allow_list(&[]));
        assert_eq!(result, Ok(query.to_string()));
    }

    #[test]
    fn preserves_order_by_and_limit_around_the_injected_restriction() {
        let rewritten = restrict_to_visible_dataset_iris(
            "PREFIX dcat: <http://www.w3.org/ns/dcat#> \
             SELECT ?dataset WHERE { ?dataset a dcat:Dataset } ORDER BY ?dataset LIMIT 1",
            &allow_list(&["https://example.org/datasets/OPEN-DATASET"]),
        )
        .expect("scopeable");
        assert!(
            rewritten.contains("ORDER BY") && rewritten.contains("LIMIT 1"),
            "ORDER BY/LIMIT must survive the rewrite, got: {rewritten}"
        );
        // And it must still actually parse and restrict correctly with
        // those modifiers in place.
        assert_selects_only(
            "PREFIX dcat: <http://www.w3.org/ns/dcat#> \
             SELECT ?dataset WHERE { ?dataset a dcat:Dataset } ORDER BY ?dataset LIMIT 5",
            &["https://example.org/datasets/OPEN-DATASET"],
            &["OPEN-DATASET"],
        );
    }
}
