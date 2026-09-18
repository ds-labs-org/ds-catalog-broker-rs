//! ODRL policy-based dataset-visibility filtering - closes gap analysis
//! §3.4's "nothing filters on policy content today" by bridging harvested
//! `catalog_core::Policy` data to `ds-odrl-engine-rs`'s evaluation engine
//! (the sibling `ds-odrl-engine-rs` submodule's `engine` crate) to decide
//! which harvested datasets a caller may see, across all three serving
//! surfaces (`GET /catalog`, the management API, and SPARQL via real query
//! rewriting).
//!
//! **Status.** Every function below has its real entitlement/mapping
//! logic (the original RED-phase commit had every one of them `todo!()`,
//! with only the real, final signatures in place - see that commit's own
//! message for the design this fills in). This module's own
//! `#[cfg(test)] mod tests` passes end to end, and `lib.rs` now calls
//! `dataset_is_visible` (via its own `filter_catalogs_by_policy` helper)
//! from both `GET /catalog` and `POST /api/management/v4/catalogs/request`,
//! per that file's "ODRL policy-based dataset visibility filtering" test
//! section. Real query-rewriting filtering for `GET`/`POST /sparql` is
//! still **not wired** - `sparql_route` does not yet call `dataset_is_visible`
//! at all, so today every caller sees every harvested triple regardless of
//! policy content, same as before this file existed. `lib.rs`'s own
//! `tests` module has a "SPARQL ODRL policy-based filtering (gap analysis
//! §3.4) - RED phase" section specifying the intended behavior (a
//! bindable-dataset-IRI query hides a policy-gated dataset's triples from
//! a disallowed caller; an unscopeable query - no dataset-subject-shaped
//! variable anywhere in it - is rejected per
//! [`PolicyFilterConfig::unscopeable_sparql_query_action`]'s default) -
//! those tests fail today, intentionally; wiring them green is separate,
//! later work.
//!
//! ## Design: per-`(policy, action)` evaluation, OR'd across a dataset's
//! own alternative offers
//!
//! `engine::evaluate_request`'s own multi-policy combining rule ANDs
//! (deny-overrides) every policy in one `Request`'s `policies` array
//! together - correct for "all of these policies must hold simultaneously",
//! but wrong here: `catalog_core::Dataset::policies` is a `Vec<Policy>` of
//! *independent alternative offers* a crawled participant advertised for
//! the same dataset (ODRL's own `odrl:hasPolicy` cardinality - a dataset
//! commonly carries several distinct offers, e.g. one for EU-resident
//! callers and one for everyone else), not a conjunction every one of
//! which must hold at once. A caller is visible-if-entitled under *any
//! one* of them. So [`dataset_is_visible`] calls `engine::evaluate_request`
//! once per `(policy, action)` pair - never once with a dataset's whole
//! `Vec<Policy>` flattened into a single `Request` - and ORs the outcomes:
//! the first policy that yields `WireDecision::Allow` makes the dataset
//! visible, independent of what every other alternative offer says.
//!
//! ## The four conservative-by-default judgment calls this config makes
//! explicit
//!
//! See [`PolicyFilterConfig`]'s own doc comment, and each of its fields',
//! for the full reasoning behind [`UnmappableConstraintAction`]'s default
//! ([`UnmappableConstraintAction::HideDataset`]),
//! [`NoPolicyVisibility`]'s default ([`NoPolicyVisibility::Open`]),
//! [`PolicyFilterConfig::filter_when_oauth2_disabled`]'s default (`true`,
//! filtering still runs against an empty claims map), and
//! [`UnscopeableSparqlQueryAction`]'s default
//! ([`UnscopeableSparqlQueryAction::Reject`], for `GET`/`POST /sparql`'s
//! own query-rewriting filtering - see `lib.rs`'s `sparql_route` doc
//! comment for the current status of that surface).

use std::collections::BTreeSet;

use catalog_core::{
    Constraint as CoreConstraint, Dataset, LogicalConstraint, Policy as CorePolicy,
    PolicyKind as CorePolicyKind, Rule as CoreRule,
};
use chrono::Utc;
use engine::wire::WireActionDecl;
use engine::{
    Behaviour, ClaimValue, Claims, ConflictStrategy, Constraint as EngineConstraint, DutyMode,
    MAX_CONSTRAINT_DEPTH, Operator, Request as EngineRequest, RequestConfig, Rule as EngineRule,
    WireDecision, WirePolicy, evaluate_request,
};

// --- Configuration (gap analysis §3.4's "driven by a new, explicit runtime
// config rather than hardcoded") -------------------------------------------

/// What to do when a harvested [`catalog_core::Constraint`]'s `operator`
/// string does not parse into `ds-odrl-engine-rs`'s own closed
/// `engine::Operator` enum (e.g. a future ODRL operator this engine
/// version doesn't yet recognize, or a typo'd/vendor-specific string a
/// crawled participant advertised).
///
/// **Default: [`Self::HideDataset`]** - the most conservative of the
/// three, per this feature's own design instruction. An operator this
/// broker cannot evaluate is exactly the situation where guessing
/// "probably fine" risks the failure class
/// `docs/spikes/2026-08-27-edc-catalog-metadata-exposure-policy.md` (in
/// the main `dataspace` repo) warns about - an unenforceable check that
/// silently permits everything - except here the unenforceable half is
/// one *constraint*, not the whole gate. The conservative direction is
/// therefore to hide the one dataset whose policy this broker cannot
/// fully evaluate, rather than to quietly drop the constraint (possibly
/// granting visibility a fully-evaluated policy would have denied) or to
/// quietly drop just the containing policy (possibly falling through to a
/// *different*, more permissive alternative offer on the same dataset
/// that happens to parse, when the harvested participant's actual intent
/// may have been the opposite). Easily flipped per-deployment via
/// `POLICY_FILTER_UNMAPPABLE_CONSTRAINT_ACTION` - see
/// [`PolicyFilterConfig::from_env`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnmappableConstraintAction {
    /// Drop just the one unmappable constraint (its containing rule is
    /// evaluated as if that constraint were never present), logging a
    /// `tracing::warn!`. The most permissive of the three: a rule that
    /// would otherwise have been further narrowed by the dropped
    /// constraint is now evaluated as less restrictive than the harvested
    /// policy actually said.
    SkipConstraint,
    /// Drop the whole [`catalog_core::Policy`] the unmappable constraint
    /// was found in - as if that one alternative offer were never
    /// advertised - but keep evaluating the dataset's *other* policies
    /// normally.
    DropPolicy,
    /// Hide the whole dataset outright - see this enum's own doc comment
    /// for why this is the default.
    #[default]
    HideDataset,
}

/// Whether a dataset with zero harvested policies at all, or a harvested
/// policy with an empty `permissions` list, is visible by default.
///
/// **Default: [`Self::Open`]** - matching `ds-odrl-engine-rs`'s own
/// documented `Behaviour::Open` rationale (`engine::profile::Behaviour`'s
/// doc comment, in the sibling `ds-odrl-engine-rs` submodule): an
/// `odrl:Offer` with no permissions at all is the *common* harvested-data
/// case, not a denial - most real DSP catalogs advertise plenty of
/// policy-free or empty-permissions datasets, and defaulting this to
/// `Closed` would empty this broker's re-served catalog of most of what
/// it actually harvested. This governs *only* the empty-`permissions`
/// case: an explicit, covering, but unsatisfied permission still denies
/// under either setting, and a matching prohibition still denies under
/// either setting too (see [`dataset_is_visible`]'s own doc comment).
///
/// This is a judgment call, not a law of nature: a deployment whose
/// upstream participants *do* mean "no permissions" as "nobody may use
/// this" should set `POLICY_FILTER_NO_POLICY_VISIBILITY=closed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NoPolicyVisibility {
    #[default]
    Open,
    Closed,
}

/// What `GET`/`POST /sparql`'s query-rewriting filtering should do with a
/// caller-supplied SPARQL query for which no *dataset-subject-shaped*
/// variable can be found - i.e. no variable appears as the subject of a
/// `?x a dcat:Dataset` triple pattern (or another dataset-shaped predicate
/// this store recognizes) anywhere in the query, so there is nothing for
/// the allow-list of visible dataset IRIs (the same computation
/// `GET /catalog`'s own filtering already does per caller, via
/// [`dataset_is_visible`]) to be injected onto - e.g. a `VALUES ?x { ... }`
/// or `FILTER(?x IN (...))` restriction. Named graphs in the semantic
/// cache are per-*participant*, not per-*dataset*, and ODRL policies are
/// attached per-*dataset*, so there is no coarser scope
/// (`GRAPH <participant>`) this filtering can fall back to either.
///
/// **Default: [`Self::Reject`]** - the same conservative-by-default
/// posture as [`UnmappableConstraintAction::HideDataset`] and
/// [`NoPolicyVisibility::Open`]'s own denial-on-the-restrictive-side
/// framing: a query this broker cannot scope to an allow-list is exactly
/// the situation where silently running it unfiltered risks returning a
/// policy-gated dataset's triples to a caller not entitled to them -
/// `docs/spikes/2026-08-27-edc-catalog-metadata-exposure-policy.md`'s own
/// central finding (an unenforceable check that silently permits
/// everything) applies here at the level of "this whole query", not just
/// one constraint or one policy. `sparql_route` returns this rejection as
/// a plain `400 Bad Request` with an explanation, the same status this
/// route already uses for every other caller-query-is-the-problem case
/// (parse/evaluation errors, `CONSTRUCT`/`DESCRIBE`) - see that
/// function's own doc comment.
///
/// A deployment that would rather keep every caller-supplied query
/// answered unfiltered whenever it cannot be scoped (effectively opting
/// that query class out of ODRL enforcement entirely) can set
/// `POLICY_FILTER_UNSCOPEABLE_SPARQL_QUERY_ACTION=run_unfiltered` - a
/// real, if dangerous, escape hatch, not a silently-different production
/// default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnscopeableSparqlQueryAction {
    #[default]
    Reject,
    RunUnfiltered,
}

/// Explicit, env-var-driven runtime configuration for ODRL policy
/// filtering (gap analysis §3.4) - the same "presence/value of an env var
/// decides behavior" shape `OAuth2Config`/`load_oauth2_config` already use
/// in this crate (`src/oauth2.rs`, `src/main.rs`), not a new mechanism.
#[derive(Debug, Clone)]
pub struct PolicyFilterConfig {
    pub unmappable_constraint_action: UnmappableConstraintAction,
    pub no_policy_visibility: NoPolicyVisibility,
    /// Whether dataset filtering runs at all when `AppState::oauth2` is
    /// `None` (no OAuth2 Bearer gate configured, so there is no verified
    /// JWT and therefore no claims to build a caller identity from).
    ///
    /// **Default: `true`** - filtering still runs, evaluated against an
    /// *empty* claims map, rather than being skipped outright whenever
    /// OAuth2 is off. This is a real, visible behavior change the first
    /// time an operator harvests a constrained policy into an otherwise
    /// fully-open, unauthenticated deployment: today, with no filtering at
    /// all, every harvested dataset is listed regardless of policy content;
    /// once this ships with the default left in place, a dataset whose
    /// *every* alternative offer requires some claim (an
    /// `odrl:assignee`-scoped policy, an `eq`/`isAnyOf` constraint against
    /// some claim key, etc.) becomes invisible to an unauthenticated
    /// caller, because an empty claims map cannot satisfy any of those. A
    /// dataset with only unconstrained or no-permission policies is
    /// unaffected either way.
    ///
    /// Chosen anyway, as the safer default, over skipping filtering
    /// entirely when OAuth2 is off: skipping would mean "no verifier
    /// configured" quietly becomes "every harvested policy is unenforced",
    /// which is exactly the unwired-gate-silently-permits-everything
    /// failure class
    /// `docs/spikes/2026-08-27-edc-catalog-metadata-exposure-policy.md`
    /// documents. An operator who deliberately wants a fully-open catalog
    /// with no policy-based filtering at all can still get it by setting
    /// `POLICY_FILTER_RUN_WHEN_OAUTH2_DISABLED=false` explicitly, rather
    /// than that behavior falling out automatically merely from never
    /// having configured `OAUTH2_JWKS_URI`.
    pub filter_when_oauth2_disabled: bool,
    /// What `GET`/`POST /sparql`'s query-rewriting filtering does with a
    /// caller query it cannot scope to a per-caller allow-list of visible
    /// dataset IRIs - see [`UnscopeableSparqlQueryAction`]'s own doc
    /// comment for the full reasoning behind its default
    /// ([`UnscopeableSparqlQueryAction::Reject`]).
    pub unscopeable_sparql_query_action: UnscopeableSparqlQueryAction,
}

impl Default for PolicyFilterConfig {
    fn default() -> Self {
        Self {
            unmappable_constraint_action: UnmappableConstraintAction::default(),
            no_policy_visibility: NoPolicyVisibility::default(),
            filter_when_oauth2_disabled: true,
            unscopeable_sparql_query_action: UnscopeableSparqlQueryAction::default(),
        }
    }
}

impl PolicyFilterConfig {
    /// Reads `POLICY_FILTER_UNMAPPABLE_CONSTRAINT_ACTION` (`skip` |
    /// `drop_policy` | `hide_dataset`), `POLICY_FILTER_NO_POLICY_VISIBILITY`
    /// (`open` | `closed`), `POLICY_FILTER_RUN_WHEN_OAUTH2_DISABLED`
    /// (`false`/`0` disables filtering when OAuth2 is off; anything else,
    /// *including unset*, keeps it enabled - see that field's own doc
    /// comment for why "unset" and "explicitly true" are deliberately the
    /// same value here, unlike the other settings' unset case), and
    /// `POLICY_FILTER_UNSCOPEABLE_SPARQL_QUERY_ACTION` (`reject` |
    /// `run_unfiltered`).
    ///
    /// An unset value for any of the first two (or fourth) settings falls
    /// back to `Default::default()`'s value for that field silently, the
    /// same silent-default posture every other `env::var(...).ok()`-based
    /// config in this crate already has (see `main.rs`'s
    /// `load_oauth2_config`). A *present but unrecognized* value also
    /// falls back to the default, but logs a `tracing::warn!` first - a
    /// typo'd env var should be visible in the logs, not merely silently
    /// ignored the same way an absent one is.
    pub fn from_env() -> Self {
        let default = Self::default();

        let unmappable_constraint_action =
            match std::env::var("POLICY_FILTER_UNMAPPABLE_CONSTRAINT_ACTION")
                .ok()
                .as_deref()
            {
                None => default.unmappable_constraint_action,
                Some("skip") => UnmappableConstraintAction::SkipConstraint,
                Some("drop_policy") => UnmappableConstraintAction::DropPolicy,
                Some("hide_dataset") => UnmappableConstraintAction::HideDataset,
                Some(other) => {
                    tracing::warn!(
                        value = other,
                        "unrecognized POLICY_FILTER_UNMAPPABLE_CONSTRAINT_ACTION (expected 'skip', \
                     'drop_policy', or 'hide_dataset'); falling back to the default \
                     (hide_dataset)"
                    );
                    default.unmappable_constraint_action
                }
            };

        let no_policy_visibility = match std::env::var("POLICY_FILTER_NO_POLICY_VISIBILITY")
            .ok()
            .as_deref()
        {
            None => default.no_policy_visibility,
            Some("open") => NoPolicyVisibility::Open,
            Some("closed") => NoPolicyVisibility::Closed,
            Some(other) => {
                tracing::warn!(
                    value = other,
                    "unrecognized POLICY_FILTER_NO_POLICY_VISIBILITY (expected 'open' or \
                         'closed'); falling back to the default (open)"
                );
                default.no_policy_visibility
            }
        };

        let filter_when_oauth2_disabled = std::env::var("POLICY_FILTER_RUN_WHEN_OAUTH2_DISABLED")
            .ok()
            .map(|value| value != "false" && value != "0")
            .unwrap_or(default.filter_when_oauth2_disabled);

        let unscopeable_sparql_query_action =
            match std::env::var("POLICY_FILTER_UNSCOPEABLE_SPARQL_QUERY_ACTION")
                .ok()
                .as_deref()
            {
                None => default.unscopeable_sparql_query_action,
                Some("reject") => UnscopeableSparqlQueryAction::Reject,
                Some("run_unfiltered") => UnscopeableSparqlQueryAction::RunUnfiltered,
                Some(other) => {
                    tracing::warn!(
                        value = other,
                        "unrecognized POLICY_FILTER_UNSCOPEABLE_SPARQL_QUERY_ACTION (expected \
                         'reject' or 'run_unfiltered'); falling back to the default (reject)"
                    );
                    default.unscopeable_sparql_query_action
                }
            };

        Self {
            unmappable_constraint_action,
            no_policy_visibility,
            filter_when_oauth2_disabled,
            unscopeable_sparql_query_action,
        }
    }
}

// --- JWT claims -> engine::Claims -------------------------------------

/// Converts a verified caller's JWT claims (a `serde_json::Value::Object`,
/// as `OAuth2Verifier::verify` already returns) into `ds-odrl-engine-rs`'s
/// own [`Claims`] map.
///
/// Per top-level key: a bare JSON string becomes [`ClaimValue::Single`]; a
/// JSON array of strings becomes [`ClaimValue::Multi`]; anything else (a
/// number, a bool, a nested object, `null`, or an array containing
/// something other than a string) is dropped silently - not an error,
/// since a claim shape this engine's `Operator`/`ClaimValue` model has no
/// use for is simply not representable here, not a malformed token.
///
/// `scope` is handled first and specially, ahead of the generic rule
/// above: OAuth2's own convention (RFC 6749 §3.3) is a single
/// space-delimited *string* claim, not a JSON array, so it is split on
/// ASCII whitespace into a [`ClaimValue::Multi`] rather than falling
/// through to the generic "bare string -> `Single`" rule, which would
/// otherwise treat the whole space-joined blob as one opaque value an
/// `isAnyOf`/`eq` constraint could never usefully match a single scope
/// out of.
///
/// Callers building a [`engine::RequestConfig`] from this map's output
/// should set `party_identity_claim` to `"sub"` (via
/// `engine::profile::ResolvedConfig::with_party_identity_claim`), so an
/// `odrl:assignee`-scoped policy is actually honored - see
/// [`dataset_is_visible`].
pub fn jwt_claims_to_engine_claims(claims: &serde_json::Value) -> Claims {
    let mut mapped = Claims::new();
    let Some(object) = claims.as_object() else {
        return mapped;
    };

    for (key, value) in object {
        // `scope`, and only when it is actually the OAuth2-conventional
        // bare string - a non-string `scope` (a caller that already sends
        // an array, however unconventional) falls through to the generic
        // rule below via `or_else` rather than being dropped outright.
        let scope_multi = (key == "scope")
            .then(|| value.as_str())
            .flatten()
            .map(|scope| {
                ClaimValue::Multi(scope.split_ascii_whitespace().map(str::to_string).collect())
            });

        let mapped_value = scope_multi.or_else(|| match value {
            serde_json::Value::String(s) => Some(ClaimValue::Single(s.clone())),
            serde_json::Value::Array(items) => items
                .iter()
                .map(|item| item.as_str().map(str::to_string))
                .collect::<Option<Vec<String>>>()
                .map(ClaimValue::Multi),
            // An array containing anything other than strings has no
            // representation in `ClaimValue` - dropped (`None` from the
            // `collect` above), not an error. Numbers, bools, nested
            // objects, and `null` are not auto-flattened either - see this
            // function's own doc comment.
            serde_json::Value::Number(_)
            | serde_json::Value::Bool(_)
            | serde_json::Value::Object(_)
            | serde_json::Value::Null => None,
        });

        if let Some(mapped_value) = mapped_value {
            mapped.insert(key.clone(), mapped_value);
        }
    }

    mapped
}

/// Layers host-synthesized context claims on top of JWT-derived ones -
/// currently just `dateTime`, set to the current wall-clock time
/// (`chrono::Utc::now()`, already a workspace dependency - no exotic clock
/// source needed), mirroring `ds-sql-dps-rs`'s own
/// `dataplane/src/public.rs::get_file` pattern exactly (`claims.insert(
/// "dateTime", ClaimValue::from(Utc::now().to_rfc3339()))`), so a
/// harvested policy's `odrl:dateTime` validity-window constraints are
/// evaluable here the same way they are there.
///
/// Called *after* [`jwt_claims_to_engine_claims`], so a caller-supplied
/// JWT that happens to carry its own (untrustworthy) `dateTime` claim is
/// overwritten by this host-synthesized one rather than the other way
/// around.
pub fn with_context_claims(mut claims: Claims) -> Claims {
    claims.insert(
        "dateTime".to_string(),
        ClaimValue::from(Utc::now().to_rfc3339()),
    );
    claims
}

// --- catalog_core -> engine mapping -------------------------------------

/// An unmappable constraint (its `operator` string does not parse into
/// `engine::Operator`) was found while mapping one [`catalog_core::Rule`]
/// or [`catalog_core::Constraint`], under a
/// [`PolicyFilterConfig::unmappable_constraint_action`] other than
/// [`UnmappableConstraintAction::SkipConstraint`] (that one case is
/// resolved on the spot, by omitting just the failing constraint - see
/// [`catalog_constraint_to_engine_constraint`]'s own doc comment). Which of
/// the two remaining configured actions applies is decided one level up,
/// by [`catalog_policy_to_wire_policy`] - the first caller in the chain
/// that knows what "the whole policy" actually means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnmappableConstraint;

/// [`PolicyFilterConfig::unmappable_constraint_action`] is
/// [`UnmappableConstraintAction::HideDataset`] and an [`UnmappableConstraint`]
/// was found - propagated all the way up to [`dataset_is_visible`], the
/// only caller in a position to act on it by hiding the whole dataset. A
/// distinct type from [`UnmappableConstraint`] (even though both are
/// presently unit structs) purely to document *where in the call chain*
/// each one is meaningful: one names "a rule/constraint could not be
/// mapped", the other names "and the configured response to that is to
/// hide this dataset".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HideDatasetForUnmappableConstraint;

/// Maps one harvested [`catalog_core::Constraint`] - atomic, or an
/// arbitrarily nested `odrl:and`/`odrl:or`/`odrl:xone`/`odrl:andSequence`
/// logical group, per that type's own doc comment - onto
/// `ds-odrl-engine-rs`'s [`EngineConstraint`] (a flat struct with
/// `and`/`or`/`xone`/`and_sequence: Option<Vec<Constraint>>` fields, unlike
/// this crate's own enum shape - see `catalog_core::Constraint`'s doc
/// comment for why the two crates deliberately chose differently).
///
/// An atomic constraint's `leftOperand` is compacted out of the ODRL
/// namespace via [`normalize_left_operand`] (that function's own doc
/// comment has the full rationale: it is vocabulary, meant to line up
/// with this bridge's flat claim-map keys, not data); `rightOperand` is
/// carried through byte for byte, unmodified - it is the value a claim is
/// compared against, never itself a claim-map key.
///
/// `Ok(None)` means "this constraint was dropped" - reachable only when
/// `config.unmappable_constraint_action` is
/// [`UnmappableConstraintAction::SkipConstraint`] and this exact
/// constraint's `operator` string didn't parse into `engine::Operator`
/// (nested recursively: a logical group with one unmappable child under
/// this setting drops just that child and keeps the rest of the group,
/// rather than the whole group). `Err(UnmappableConstraint)` is the other
/// two configured actions' shared signal - see [`UnmappableConstraint`]'s
/// own doc comment for why this function does not itself distinguish
/// between them.
pub fn catalog_constraint_to_engine_constraint(
    constraint: &CoreConstraint,
    config: &PolicyFilterConfig,
) -> Result<Option<EngineConstraint>, UnmappableConstraint> {
    catalog_constraint_to_engine_constraint_at_depth(constraint, config, 0)
}

/// The `operator` wire spellings `ds-odrl-engine-rs::engine::Operator`
/// recognizes (`engine::wire::operator_wire_name`'s own inverse - that
/// function is private to the engine crate, so this restates its fixed set
/// rather than depending on it), with an optional leading `odrl:` stripped
/// first - a crawled participant's harvested operator string is sometimes
/// the bare local name (`"lteq"`) and sometimes the `odrl:`-prefixed form
/// (`"odrl:lteq"`); both mean the same operator, and there is no ambiguity
/// between them worth preserving as a distinct mapping outcome.
fn parse_operator(operator: &str) -> Option<Operator> {
    let bare = operator.strip_prefix("odrl:").unwrap_or(operator);
    match bare {
        "eq" => Some(Operator::Eq),
        "neq" => Some(Operator::Neq),
        "isAnyOf" => Some(Operator::IsAnyOf),
        "isAllOf" => Some(Operator::IsAllOf),
        "isNoneOf" => Some(Operator::IsNoneOf),
        "isPartOf" => Some(Operator::IsPartOf),
        "lt" => Some(Operator::Lt),
        "lteq" => Some(Operator::Lteq),
        "gt" => Some(Operator::Gt),
        "gteq" => Some(Operator::Gteq),
        _ => None,
    }
}

/// The full ODRL 2.2 vocabulary namespace, exactly as
/// `ds-odrl-engine-rs::dsp_odrl_adapter::jsonld::ODRL_NS` defines it (that
/// constant is private to the engine's own crate, so this restates it
/// rather than depending on it) - used only to recognize and strip an
/// unabbreviated `leftOperand` IRI in [`normalize_left_operand`].
const ODRL_NS: &str = "http://www.w3.org/ns/odrl/2/";

/// Compacts a harvested `leftOperand` out of the ODRL namespace, the same
/// convention `dsp_odrl_adapter::ingest`'s own module doc documents and
/// applies when it ingests a real DSP contract's ODRL JSON-LD: "Vocabulary
/// terms are compacted out of the ODRL namespace ... `http://www.w3.org/ns/odrl/2/dateTime`
/// becomes `dateTime` ... That is what makes an ingested policy line up
/// with ... the flat claim-map keys `engine::Claims` is built from." A
/// `leftOperand` is vocabulary, not data - unlike a `rightOperand`,
/// carried byte for byte in [`catalog_constraint_to_engine_constraint_at_depth`]
/// below - so a harvested `"odrl:dateTime"` or a full
/// `"http://www.w3.org/ns/odrl/2/dateTime"` must normalize to the same
/// bare `"dateTime"` this bridge's own claims map
/// ([`jwt_claims_to_engine_claims`]/[`with_context_claims`]) uses as a
/// key, or [`engine::Constraint::evaluate`]'s plain-string
/// `claims.get(&self.left_operand)` lookup silently never matches any
/// claim at all, denying what should be a satisfiable constraint. A
/// `leftOperand` outside the ODRL namespace (a deployment-specific claim
/// key such as `"role"`) is left exactly as written, matching
/// `dsp_odrl_adapter`'s own "an IRI outside the ODRL namespace is left
/// exactly as written" rule.
fn normalize_left_operand(left_operand: &str) -> String {
    left_operand
        .strip_prefix(ODRL_NS)
        .or_else(|| left_operand.strip_prefix("odrl:"))
        .unwrap_or(left_operand)
        .to_string()
}

/// [`catalog_constraint_to_engine_constraint`]'s actual recursion, with an
/// explicit depth counter this crate's own public signature has no room
/// for. Bounded by the same [`MAX_CONSTRAINT_DEPTH`] the crawler's own
/// parsing already bounds itself by (gap analysis \u{a7}3.4's own note on
/// why the two are kept in step) - a harvested `Constraint` reaching this
/// function has already been through that bound once, so this is a
/// defense-in-depth guard against a `Constraint` value built some other
/// way (directly, in a test, or by a future caller), not a bound this
/// function expects to actually hit against real crawled data. A tree that
/// somehow exceeds it is treated exactly like an unmappable operator -
/// this crate has no third notion of "too deep to evaluate" distinct from
/// "cannot evaluate this constraint" - so the configured
/// `unmappable_constraint_action` still governs what happens to it.
/// One of [`EngineConstraint`]'s own `and`/`or`/`xone`/`and_sequence`
/// logical constructors - a plain type alias purely so the `match` in
/// [`catalog_constraint_to_engine_constraint_at_depth`] below doesn't spell
/// this function-pointer type out inline (clippy's own `type_complexity`
/// lint).
type ConstraintCtor = fn(Vec<EngineConstraint>) -> EngineConstraint;

fn catalog_constraint_to_engine_constraint_at_depth(
    constraint: &CoreConstraint,
    config: &PolicyFilterConfig,
    depth: usize,
) -> Result<Option<EngineConstraint>, UnmappableConstraint> {
    if depth > MAX_CONSTRAINT_DEPTH {
        tracing::warn!(
            depth,
            "ODRL constraint nested past MAX_CONSTRAINT_DEPTH while mapping to the ODRL \
             engine's wire shape; treating it the same as an unmappable operator"
        );
        return match config.unmappable_constraint_action {
            UnmappableConstraintAction::SkipConstraint => Ok(None),
            UnmappableConstraintAction::DropPolicy | UnmappableConstraintAction::HideDataset => {
                Err(UnmappableConstraint)
            }
        };
    }

    match constraint {
        CoreConstraint::Atomic(atomic) => match parse_operator(&atomic.operator) {
            Some(operator) => Ok(Some(EngineConstraint::new(
                normalize_left_operand(&atomic.left_operand),
                operator,
                atomic.right_operand.clone(),
            ))),
            None => match config.unmappable_constraint_action {
                UnmappableConstraintAction::SkipConstraint => {
                    tracing::warn!(
                        left_operand = %atomic.left_operand,
                        operator = %atomic.operator,
                        "dropping unmappable ODRL constraint operator \
                         (POLICY_FILTER_UNMAPPABLE_CONSTRAINT_ACTION=skip)"
                    );
                    Ok(None)
                }
                UnmappableConstraintAction::DropPolicy
                | UnmappableConstraintAction::HideDataset => Err(UnmappableConstraint),
            },
        },
        CoreConstraint::Logical(logical) => {
            let (children, build): (&[CoreConstraint], ConstraintCtor) = match logical {
                LogicalConstraint::And(children) => (children.as_slice(), EngineConstraint::and),
                LogicalConstraint::Or(children) => (children.as_slice(), EngineConstraint::or),
                LogicalConstraint::Xone(children) => (children.as_slice(), EngineConstraint::xone),
                LogicalConstraint::AndSequence(children) => {
                    (children.as_slice(), EngineConstraint::and_sequence)
                }
            };
            let mut mapped = Vec::with_capacity(children.len());
            for child in children {
                if let Some(engine_child) =
                    catalog_constraint_to_engine_constraint_at_depth(child, config, depth + 1)?
                {
                    mapped.push(engine_child);
                }
            }
            Ok(Some(build(mapped)))
        }
    }
}

/// Maps one harvested [`catalog_core::Rule`] (a `permission`/`prohibition`/
/// `obligation` entry) onto `ds-odrl-engine-rs`'s [`EngineRule`], via
/// [`catalog_constraint_to_engine_constraint`] for each of its constraints.
///
/// `Ok(None)` means the whole rule was dropped - only reachable the same
/// way [`catalog_constraint_to_engine_constraint`]'s own `Ok(None)` is,
/// propagated up when *every* constraint of this rule turned out to be
/// droppable under [`UnmappableConstraintAction::SkipConstraint`] and
/// nothing else remains to construct a meaningful `EngineRule` from... in
/// fact a rule needs no constraints at all to be meaningful (an
/// unconstrained permission is ordinary ODRL), so in practice this always
/// maps to `Ok(Some(_))` when every constraint mapping itself succeeded
/// with `Ok(_)` - `Ok(None)` is carried at this level purely so the type
/// signature stays uniform with [`catalog_constraint_to_engine_constraint`]
/// rather than because a rule-level "no-op" state is separately
/// meaningful. `Err(UnmappableConstraint)` propagates unchanged from the
/// first constraint mapping call that returns it.
pub fn catalog_rule_to_engine_rule(
    rule: &CoreRule,
    config: &PolicyFilterConfig,
) -> Result<Option<EngineRule>, UnmappableConstraint> {
    let mut constraints = Vec::with_capacity(rule.constraints.len());
    for constraint in &rule.constraints {
        if let Some(engine_constraint) =
            catalog_constraint_to_engine_constraint(constraint, config)?
        {
            constraints.push(engine_constraint);
        }
    }
    Ok(Some(EngineRule::new(rule.action.clone(), constraints)))
}

/// [`catalog_core::PolicyKind`]'s wire spelling on [`WirePolicy::kind`] -
/// a plain label the engine never itself branches on (see that field's
/// own doc comment), so this is a direct, lossless rename rather than a
/// judgment call.
fn policy_kind_wire_name(kind: CorePolicyKind) -> &'static str {
    match kind {
        CorePolicyKind::Set => "Set",
        CorePolicyKind::Offer => "Offer",
        CorePolicyKind::Agreement => "Agreement",
    }
}

/// Maps one harvested [`catalog_core::Policy`] (one of a dataset's
/// alternative offers) onto `ds-odrl-engine-rs`'s [`WirePolicy`], via
/// [`catalog_rule_to_engine_rule`] for each of its permissions/
/// prohibitions/obligations. `fallback_id` is used as the wire policy's
/// `id` when the harvested `Policy::id` is `None` (`WirePolicy::id` is a
/// plain, required `String`, unlike `catalog_core::Policy::id`'s
/// `Option<String>`).
///
/// This is where an [`UnmappableConstraint`] surfaced by
/// [`catalog_rule_to_engine_rule`] is finally resolved into one of the two
/// remaining configured actions (`SkipConstraint` is already fully
/// resolved lower in the chain and never reaches this function as an
/// `Err`):
/// - [`UnmappableConstraintAction::DropPolicy`]: `Ok(None)` - this policy
///   contributes nothing, but [`dataset_is_visible`]'s per-policy loop
///   keeps evaluating the dataset's other alternative offers normally.
/// - [`UnmappableConstraintAction::HideDataset`]:
///   `Err(HideDatasetForUnmappableConstraint)` - propagated to
///   [`dataset_is_visible`], the only caller positioned to act on it by
///   hiding the whole dataset outright, independent of what any other
///   alternative offer might otherwise have granted.
pub fn catalog_policy_to_wire_policy(
    policy: &CorePolicy,
    fallback_id: &str,
    config: &PolicyFilterConfig,
) -> Result<Option<WirePolicy>, HideDatasetForUnmappableConstraint> {
    let map_rules = |rules: &[CoreRule]| -> Result<Vec<EngineRule>, UnmappableConstraint> {
        let mut mapped = Vec::with_capacity(rules.len());
        for rule in rules {
            if let Some(engine_rule) = catalog_rule_to_engine_rule(rule, config)? {
                mapped.push(engine_rule);
            }
        }
        Ok(mapped)
    };

    let mapped = (|| -> Result<WirePolicy, UnmappableConstraint> {
        Ok(WirePolicy {
            id: policy.id.clone().unwrap_or_else(|| fallback_id.to_string()),
            kind: policy_kind_wire_name(policy.kind).to_string(),
            assigner: policy.assigner.clone().unwrap_or_default(),
            assignee: policy.assignee.clone(),
            permissions: map_rules(&policy.permissions)?,
            prohibitions: map_rules(&policy.prohibitions)?,
            obligations: map_rules(&policy.obligations)?,
            conflict: ConflictStrategy::default(),
            inherit_from: None,
        })
    })();

    match mapped {
        Ok(wire_policy) => Ok(Some(wire_policy)),
        Err(UnmappableConstraint) => match config.unmappable_constraint_action {
            UnmappableConstraintAction::DropPolicy => Ok(None),
            UnmappableConstraintAction::HideDataset => Err(HideDatasetForUnmappableConstraint),
            UnmappableConstraintAction::SkipConstraint => {
                // Fully resolved at the constraint level - see
                // `catalog_constraint_to_engine_constraint`'s own doc
                // comment. An `Err` never reaches this match arm under
                // this setting.
                unreachable!(
                    "SkipConstraint drops the offending constraint before an Err can propagate \
                     this far"
                )
            }
        },
    }
}

// --- The entitlement decision -------------------------------------------

/// Builds the single-policy `engine::Request` [`dataset_is_visible`] sends
/// to [`evaluate_request`] for one already-mapped `wire_policy`.
///
/// `config.actions` is every action `wire_policy`'s own rules mention,
/// plus `action` itself - mirroring `ds-odrl-engine-rs::dsp_odrl_adapter`'s
/// own `minimal_config` (a real precedent in the sibling engine repo for
/// exactly this "declare a floor, not a profile" situation: no
/// `odrl:includedIn` taxonomy, since a harvested dataset's policy declares
/// none). `action` itself must always be included even when no rule
/// mentions it at all - `evaluate_request` treats an unrecognized
/// *requested* action as a hard `Decision::Error`, and a dataset with only
/// unrelated permissions (or none at all) must still evaluate to a
/// `Deny`/`Allow`, never an `Error`.
///
/// `party_identity_claim` is fixed to `"sub"` (see
/// [`jwt_claims_to_engine_claims`]'s own doc comment), so a policy naming
/// an `odrl:assignee` is actually scoped to the caller identified by that
/// claim. `behaviour` mirrors `config.no_policy_visibility` - the same
/// judgment call now also governing the engine's own reading of "no
/// permissions" for one already-mapped policy, not only this function's
/// own empty-`Vec<Policy>` short circuit. `duty_mode` is fixed to
/// [`DutyMode::Advise`]: this broker tracks no duty fulfillment of its own
/// (there is no negotiation, no obligation ledger), so an outstanding
/// `odrl:duty`/`odrl:obligation` is surfaced as advisory rather than
/// silently forcing a `Deny` a caller has no way to have resolved.
fn build_request(
    dataset: &Dataset,
    wire_policy: &WirePolicy,
    action: &str,
    claims: &Claims,
    config: &PolicyFilterConfig,
) -> EngineRequest {
    let mut actions: BTreeSet<String> = BTreeSet::new();
    actions.insert(action.to_string());
    for rule in wire_policy
        .permissions
        .iter()
        .chain(&wire_policy.prohibitions)
        .chain(&wire_policy.obligations)
    {
        actions.insert(rule.action.clone());
    }

    let behaviour = match config.no_policy_visibility {
        NoPolicyVisibility::Open => Behaviour::Open,
        NoPolicyVisibility::Closed => Behaviour::Closed,
    };

    let request_config = RequestConfig {
        type_: "odrl:Profile".to_string(),
        id: "urn:ds-catalog-broker-rs:odrl-filter-config".to_string(),
        actions: actions
            .into_iter()
            .map(|id| WireActionDecl {
                id,
                included_in: None,
            })
            .collect(),
        duty_mode: DutyMode::Advise,
        behaviour,
        party_identity_claim: Some("sub".to_string()),
        agreement_assignee_claim: None,
    };

    EngineRequest {
        dataset_id: dataset.id.clone(),
        action: action.to_string(),
        config: request_config,
        policies: vec![wire_policy.clone()],
        claims: claims.clone(),
        asset_collections: Vec::new(),
    }
}

/// Is `dataset` visible to the caller `claims` describes, for `action`,
/// under `config`?
///
/// **The actual per-dataset entitlement decision** - gap analysis §3.4's
/// "filter what it re-serves based on policy", now answered rather than
/// left open. See this module's own doc comment for the full per-
/// `(policy, action)`, OR'd-across-alternative-offers design:
///
/// - `dataset.policies` is empty: visible exactly when
///   `config.no_policy_visibility` is [`NoPolicyVisibility::Open`].
/// - Otherwise, each policy is mapped via [`catalog_policy_to_wire_policy`]
///   and, when that succeeds with a policy to evaluate, wrapped in its own
///   single-policy `engine::Request` (`dataset_id = dataset.id`, `action`,
///   `claims` as given, `party_identity_claim = "sub"`, `behaviour`
///   matching `config.no_policy_visibility`) and passed to
///   `engine::evaluate_request` - once per policy, **never** with the
///   dataset's whole `Vec<Policy>` flattened into one `Request` (that
///   would apply `evaluate_request`'s own deny-overrides-across-policies
///   combining rule, which is correct for "all of these must hold at
///   once" and wrong for "any one of these alternative offers is enough").
///   The dataset is visible as soon as any one policy's evaluation
///   produces `WireDecision::Allow`.
/// - A policy for which `catalog_policy_to_wire_policy` returns
///   `Err(HideDatasetForUnmappableConstraint)` (see that function's own
///   doc comment) hides the *whole* dataset immediately, regardless of
///   what any other alternative offer would otherwise have granted - the
///   most conservative reading of an operator this broker could not fully
///   evaluate.
/// - A policy for which it returns `Ok(None)` (dropped under
///   [`UnmappableConstraintAction::DropPolicy`]) is simply skipped; the
///   dataset's remaining policies are still evaluated normally.
///
/// `claims` should already have gone through
/// [`jwt_claims_to_engine_claims`] and [`with_context_claims`] - this
/// function itself does no JWT decoding or claims synthesis of its own.
pub fn dataset_is_visible(
    dataset: &Dataset,
    claims: &Claims,
    action: &str,
    config: &PolicyFilterConfig,
) -> bool {
    if dataset.policies.is_empty() {
        return config.no_policy_visibility == NoPolicyVisibility::Open;
    }

    for (index, policy) in dataset.policies.iter().enumerate() {
        let fallback_id = format!("{}-policy-{index}", dataset.id);
        match catalog_policy_to_wire_policy(policy, &fallback_id, config) {
            Err(HideDatasetForUnmappableConstraint) => return false,
            Ok(None) => continue,
            Ok(Some(wire_policy)) => {
                let request = build_request(dataset, &wire_policy, action, claims, config);
                let response = evaluate_request(&request);
                if response.decision == WireDecision::Allow {
                    return true;
                }
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use catalog_core::PolicyKind;

    fn dataset_with_policies(policies: Vec<CorePolicy>) -> Dataset {
        Dataset {
            id: "ds-1".to_string(),
            properties: Default::default(),
            distributions: Vec::new(),
            policies,
        }
    }

    fn policy(permissions: Vec<CoreRule>, prohibitions: Vec<CoreRule>) -> CorePolicy {
        CorePolicy {
            id: Some("policy-1".to_string()),
            kind: PolicyKind::Offer,
            assigner: None,
            assignee: None,
            permissions,
            prohibitions,
            obligations: Vec::new(),
        }
    }

    fn unconstrained_rule(action: &str) -> CoreRule {
        CoreRule {
            action: action.to_string(),
            constraints: Vec::new(),
        }
    }

    // --- dataset_is_visible --------------------------------------------

    #[test]
    fn dataset_with_an_allow_granting_policy_is_visible() {
        let dataset =
            dataset_with_policies(vec![policy(vec![unconstrained_rule("use")], Vec::new())]);
        let claims = Claims::new();
        let config = PolicyFilterConfig::default();

        assert!(
            dataset_is_visible(&dataset, &claims, "use", &config),
            "an unconstrained permission for the requested action must grant visibility"
        );
    }

    #[test]
    fn dataset_with_only_a_denying_prohibition_is_not_visible() {
        let dataset =
            dataset_with_policies(vec![policy(Vec::new(), vec![unconstrained_rule("use")])]);
        let claims = Claims::new();
        let config = PolicyFilterConfig::default();

        assert!(
            !dataset_is_visible(&dataset, &claims, "use", &config),
            "a matching, unconstrained prohibition must deny visibility even under the default \
             no_policy_visibility=Open setting - Open only governs the empty-permissions case"
        );
    }

    #[test]
    fn dataset_with_an_empty_permissions_policy_is_visible_under_default_open() {
        let dataset = dataset_with_policies(vec![policy(Vec::new(), Vec::new())]);
        let claims = Claims::new();
        let config = PolicyFilterConfig::default();
        assert_eq!(
            config.no_policy_visibility,
            NoPolicyVisibility::Open,
            "this test exercises the default; update it if the default ever changes"
        );

        assert!(
            dataset_is_visible(&dataset, &claims, "use", &config),
            "a policy with an empty permissions list (and no prohibitions) must be visible \
             under the default no_policy_visibility=Open setting - an empty-permissions Offer \
             is normal harvested data, not a denial"
        );
    }

    #[test]
    fn dataset_with_no_policies_at_all_is_visible_under_default_open() {
        let dataset = dataset_with_policies(Vec::new());
        let claims = Claims::new();
        let config = PolicyFilterConfig::default();

        assert!(
            dataset_is_visible(&dataset, &claims, "use", &config),
            "a dataset with zero harvested policies must be visible under the default \
             no_policy_visibility=Open setting"
        );
    }

    fn dataset_with_unmappable_constraint_policy() -> Dataset {
        dataset_with_policies(vec![policy(
            vec![CoreRule {
                action: "use".to_string(),
                constraints: vec![CoreConstraint::atomic(
                    "odrl:spatial",
                    "definitelyNotARealOdrlOperator",
                    "https://example.org/place/eu",
                )],
            }],
            Vec::new(),
        )])
    }

    #[test]
    fn dataset_with_unmappable_constraint_is_hidden_under_default_hide_dataset_config() {
        let dataset = dataset_with_unmappable_constraint_policy();
        let claims = Claims::new();
        let config = PolicyFilterConfig::default();
        assert_eq!(
            config.unmappable_constraint_action,
            UnmappableConstraintAction::HideDataset,
            "this test exercises the default; update it if the default ever changes"
        );

        assert!(
            !dataset_is_visible(&dataset, &claims, "use", &config),
            "an unmappable operator must hide the whole dataset under the default (most \
             conservative) unmappable_constraint_action"
        );
    }

    #[test]
    fn dataset_with_unmappable_constraint_is_visible_when_configured_to_skip_just_that_constraint()
    {
        let dataset = dataset_with_unmappable_constraint_policy();
        let claims = Claims::new();
        let config = PolicyFilterConfig {
            unmappable_constraint_action: UnmappableConstraintAction::SkipConstraint,
            ..PolicyFilterConfig::default()
        };

        assert!(
            dataset_is_visible(&dataset, &claims, "use", &config),
            "skipping just the unmappable constraint must leave the rule's other (zero, here) \
             constraints to grant an otherwise-unconstrained permission"
        );
    }

    // --- leftOperand normalization (normalize_left_operand) --------------
    //
    // A harvested `leftOperand` is vocabulary, compacted out of the ODRL
    // namespace the same way `dsp_odrl_adapter::ingest` compacts one when
    // it ingests a real DSP contract - see `normalize_left_operand`'s own
    // doc comment. Caught during this feature's own end-to-end
    // verification: a permission constrained by `("odrl:dateTime", "odrl:lteq", ...)`
    // (the compact-IRI form a real crawled participant may well advertise)
    // silently never matched this bridge's own `"dateTime"` claims-map key
    // before this normalization existed - `engine::Constraint::evaluate`'s
    // claim lookup is a plain string match, so an un-normalized
    // `"odrl:dateTime"` looked up nothing and a genuinely satisfiable
    // constraint was denied instead of granted.

    #[test]
    fn an_odrl_prefixed_left_operand_matches_a_bare_claim_key() {
        let dataset = dataset_with_policies(vec![policy(
            vec![CoreRule {
                action: "use".to_string(),
                constraints: vec![CoreConstraint::atomic(
                    "odrl:dateTime",
                    "odrl:lteq",
                    "2027-01-01T00:00:00Z",
                )],
            }],
            Vec::new(),
        )]);
        let claims = with_context_claims(Claims::new());
        let config = PolicyFilterConfig::default();

        assert!(
            dataset_is_visible(&dataset, &claims, "use", &config),
            "an 'odrl:'-prefixed leftOperand must normalize to the same bare key \
             with_context_claims sets ('dateTime'), so a satisfiable dateTime constraint is \
             actually evaluated against it, not silently denied for matching nothing"
        );
    }

    #[test]
    fn a_full_iri_left_operand_matches_a_bare_claim_key() {
        let dataset = dataset_with_policies(vec![policy(
            vec![CoreRule {
                action: "use".to_string(),
                constraints: vec![CoreConstraint::atomic(
                    "http://www.w3.org/ns/odrl/2/dateTime",
                    "lteq",
                    "2027-01-01T00:00:00Z",
                )],
            }],
            Vec::new(),
        )]);
        let claims = with_context_claims(Claims::new());
        let config = PolicyFilterConfig::default();

        assert!(
            dataset_is_visible(&dataset, &claims, "use", &config),
            "an unabbreviated ODRL-namespace leftOperand IRI must normalize the same way the \
             'odrl:'-prefixed compact form does"
        );
    }

    #[test]
    fn a_non_odrl_left_operand_is_left_exactly_as_written() {
        assert_eq!(normalize_left_operand("role"), "role");
        assert_eq!(
            normalize_left_operand("https://example.org/ns#region"),
            "https://example.org/ns#region",
            "a leftOperand outside the ODRL namespace must not be altered"
        );
    }

    // --- jwt_claims_to_engine_claims -------------------------------------

    #[test]
    fn scope_claim_is_space_split_into_a_multi_value_not_json_array_parsed() {
        let jwt = serde_json::json!({ "scope": "catalog:read sparql:read" });

        let claims = jwt_claims_to_engine_claims(&jwt);

        assert_eq!(
            claims.get("scope"),
            Some(&ClaimValue::Multi(vec![
                "catalog:read".to_string(),
                "sparql:read".to_string()
            ])),
            "OAuth2's own space-delimited scope convention must be split into a Multi, not \
             treated as one opaque Single string"
        );
    }

    #[test]
    fn a_bare_string_claim_becomes_a_single_value() {
        let jwt = serde_json::json!({ "sub": "did:example:consumer" });

        let claims = jwt_claims_to_engine_claims(&jwt);

        assert_eq!(
            claims.get("sub"),
            Some(&ClaimValue::Single("did:example:consumer".to_string()))
        );
    }

    #[test]
    fn a_json_array_of_strings_becomes_a_multi_value() {
        let jwt = serde_json::json!({ "groups": ["eu-members", "gold-tier"] });

        let claims = jwt_claims_to_engine_claims(&jwt);

        assert_eq!(
            claims.get("groups"),
            Some(&ClaimValue::Multi(vec![
                "eu-members".to_string(),
                "gold-tier".to_string()
            ]))
        );
    }

    #[test]
    fn numeric_bool_nested_and_null_valued_claims_are_dropped_silently() {
        let jwt = serde_json::json!({
            "sub": "did:example:consumer",
            "age": 42,
            "active": true,
            "verified_claims": {"nested": "object"},
            "nothing": null,
        });

        let claims = jwt_claims_to_engine_claims(&jwt);

        assert_eq!(
            claims.len(),
            1,
            "only the bare-string 'sub' claim should survive filter_map'ing; got {claims:?}"
        );
        assert!(claims.contains_key("sub"));
    }
}
