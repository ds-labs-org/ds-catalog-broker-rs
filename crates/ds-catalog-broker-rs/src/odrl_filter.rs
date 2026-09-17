//! ODRL policy-based dataset-visibility filtering - closes gap analysis
//! §3.4's "nothing filters on policy content today" by bridging harvested
//! `catalog_core::Policy` data to `ds-odrl-engine-rs`'s evaluation engine
//! (the sibling `ds-odrl-engine-rs` submodule's `engine` crate) to decide
//! which harvested datasets a caller may see, across all three serving
//! surfaces (`GET /catalog`, the management API, and SPARQL via real query
//! rewriting).
//!
//! **RED phase.** Every type and function below has its real, final
//! signature - the workspace compiles, and every call site this module
//! will eventually need (in `lib.rs`'s three route handlers) already
//! type-checks against it - but the actual entitlement/mapping *logic* is
//! `todo!()` for now, matching this session's own established TDD posture
//! (see e.g. `crates/rdf-store/src/lib.rs`'s
//! `round_trips_a_nested_logical_constraint_preserving_structure_and_order`
//! red/green history). This module's own `#[cfg(test)] mod tests` therefore
//! fails at assertion/panic time today, not at compile time; a later
//! "green:" commit fills these bodies in.
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
//! ## The three conservative-by-default judgment calls this config makes
//! explicit
//!
//! See [`PolicyFilterConfig`]'s own doc comment, and each of its fields',
//! for the full reasoning behind [`UnmappableConstraintAction`]'s default
//! ([`UnmappableConstraintAction::HideDataset`]),
//! [`NoPolicyVisibility`]'s default ([`NoPolicyVisibility::Open`]), and
//! [`PolicyFilterConfig::filter_when_oauth2_disabled`]'s default (`true`,
//! filtering still runs against an empty claims map).

use catalog_core::{Constraint as CoreConstraint, Dataset, Policy as CorePolicy, Rule as CoreRule};
use chrono::Utc;
use engine::{ClaimValue, Claims, Constraint as EngineConstraint, Rule as EngineRule, WirePolicy};

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
}

impl Default for PolicyFilterConfig {
    fn default() -> Self {
        Self {
            unmappable_constraint_action: UnmappableConstraintAction::default(),
            no_policy_visibility: NoPolicyVisibility::default(),
            filter_when_oauth2_disabled: true,
        }
    }
}

impl PolicyFilterConfig {
    /// Reads `POLICY_FILTER_UNMAPPABLE_CONSTRAINT_ACTION` (`skip` |
    /// `drop_policy` | `hide_dataset`), `POLICY_FILTER_NO_POLICY_VISIBILITY`
    /// (`open` | `closed`), and `POLICY_FILTER_RUN_WHEN_OAUTH2_DISABLED`
    /// (`false`/`0` disables filtering when OAuth2 is off; anything else,
    /// *including unset*, keeps it enabled - see that field's own doc
    /// comment for why "unset" and "explicitly true" are deliberately the
    /// same value here, unlike the other two settings' unset case).
    ///
    /// An unset value for either of the first two settings falls back to
    /// `Default::default()`'s value for that field silently, the same
    /// silent-default posture every other `env::var(...).ok()`-based
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

        Self {
            unmappable_constraint_action,
            no_policy_visibility,
            filter_when_oauth2_disabled,
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
    let _ = claims;
    todo!(
        "RED phase (gap analysis \u{a7}3.4): jwt_claims_to_engine_claims mapping logic is not \
         yet implemented - see odrl_filter's module doc comment"
    )
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
    let _ = (constraint, config);
    todo!(
        "RED phase (gap analysis \u{a7}3.4): recursive Constraint mapping is not yet \
         implemented - see odrl_filter's module doc comment"
    )
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
    let _ = (rule, config);
    todo!(
        "RED phase (gap analysis \u{a7}3.4): Rule mapping is not yet implemented - see \
         odrl_filter's module doc comment"
    )
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
    let _ = (policy, fallback_id, config);
    todo!(
        "RED phase (gap analysis \u{a7}3.4): Policy mapping is not yet implemented - see \
         odrl_filter's module doc comment"
    )
}

// --- The entitlement decision -------------------------------------------

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
    let _ = (dataset, claims, action, config);
    todo!(
        "RED phase (gap analysis \u{a7}3.4): the per-(policy, action) entitlement decision is \
         not yet implemented - see odrl_filter's module doc comment"
    )
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
