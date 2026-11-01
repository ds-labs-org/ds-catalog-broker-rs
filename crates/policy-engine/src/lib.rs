//! Portable attribute-based decision engine for harvested ODRL policies.
//!
//! See the `dataspace` study repo's case study,
//! `docs/case-studies/2026-08-30-attribute-based-odrl-policy-enforcement.md`
//! (<https://labs.deepthought-solutions.net/Deepthought-Solutions/dataspace/src/branch/main/docs/case-studies/2026-08-30-attribute-based-odrl-policy-enforcement.md>),
//! for the full design proposal this crate implements — **PROPOSAL status,
//! not an accepted architecture decision** (see that document's "Status"
//! section). This
//! module implements only the "core evaluation logic" half of the
//! proposal: [`evaluate`] is a plain, portable Rust function with zero
//! WASM/FFI involvement, testable exactly like any other Rust library
//! function. The WASM ABI built on top of it lives in [`ffi`].
//!
//! # Status
//!
//! This crate is a prototype and nothing in the workspace depends on it.
//! It supports the `eq`, `neq` and `isAnyOf` operators and combines all
//! attached policies with deny-overrides. It has no profiles, no duties
//! and no error result. The case study's 2026-09-05 update records that
//! those were built later in the separate `ds-odrl-engine-rs` repository,
//! which is what `ds-catalog-broker-rs` uses for its filtering. See
//! `docs/policy-engine.md` in this repository for the ABI and the build.
//!
//! # Scope boundary
//!
//! This crate does not verify eIDAS2/EUDI Wallet presentations, does not
//! talk to a wallet or a trust list, and does not verify a JWT's
//! signature. It is a pure decision function over two inputs a caller
//! (this workspace's `ds-catalog-broker-rs` crate, eventually, or an EDC
//! extension in the JVM-host prototype) already produced elsewhere: a
//! harvested [`Policy`] and an already-verified flat claims map. See the
//! design doc's "Scope boundary" section for the full statement.
//!
//! # Independence from `catalog-core`
//!
//! [`Policy`]/[`Rule`]/[`Constraint`]/[`PolicyKind`] below deliberately
//! mirror `catalog_core::Policy`/`Rule`/`Constraint`/`PolicyKind`
//! field-for-field (same field names, same default derives, same
//! `PolicyKind` variant spelling) so a caller can serialize one straight
//! into the other with `serde_json::to_value`/`from_value` and no
//! translation layer — but this crate does **not** depend on
//! `catalog-core`. That is a portability requirement, not an oversight:
//! this crate must compile to `wasm32-unknown-unknown` and be invocable
//! from both a Rust host and a JVM host (via Chicory), so it cannot pull
//! in anything host-specific (`catalog-core` itself is dependency-light,
//! but the point is this crate's *own* dependency graph must never grow
//! a `tokio`/`reqwest`/native-only edge just because a type happens to
//! look similar elsewhere in the workspace).
//!
//! # Multiple policies on one dataset — an interpretation this crate had
//! to make explicit
//!
//! The design doc's "Enforcement decision semantics" section states the
//! algorithm as evaluated "once per `(Dataset, Policy, claims)` triple"
//! (singular `Policy`), but the wire request schema carries
//! `policies: Vec<Policy>` (plural — a dataset can have more than one
//! attached ODRL offer) and the response carries exactly one `decision`
//! for the whole request. The doc does not spell out how multiple
//! policies combine into that one decision. This crate resolves the gap
//! by extending the *same* deny-overrides algorithm across the flattened
//! rule lists of every policy in the request, rather than introducing a
//! second, undocumented combining step:
//!
//! 1. Deny if **any** prohibition rule in **any** attached policy
//!    matches.
//! 2. Otherwise allow if **no** attached policy has **any** permission
//!    rule at all (the flattened permission set, across every policy on
//!    the dataset, is empty).
//! 3. Otherwise allow if **any** permission rule in **any** attached
//!    policy matches.
//! 4. Otherwise deny.
//!
//! This is a direct generalization, not a new policy: with exactly one
//! policy in `policies` (the shape of every example in the design doc)
//! it reduces to precisely the four-step algorithm as written there.

// BTreeMap, not std::collections::HashMap, for the claims map: HashMap's
// default RandomState needs an OS randomness source to seed itself, which
// wasm32-unknown-unknown (no WASI, no browser JS shim) does not reliably
// provide - a HashMap constructed inside this guest at runtime risks a
// trap the moment serde_json builds one during deserialization. BTreeMap
// needs only `Ord` on the key (String already has it), serializes to the
// exact same JSON object shape, and has no such platform dependency - the
// safer default for a module whose whole reason to exist is portability.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub mod ffi;

/// Mirrors `catalog_core::PolicyKind` exactly (see that type's doc
/// comment in `crates/catalog-core/src/lib.rs`): `Set`/`Offer`/
/// `Agreement`, serialized as the bare variant name (no rename), matching
/// `catalog-core`'s own `#[derive(Serialize)]` output and its tests'
/// `value["kind"] == "Offer"` assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PolicyKind {
    #[default]
    Set,
    Offer,
    Agreement,
}

/// One atomic ODRL constraint: `left_operand operator right_operand`.
/// Mirrors `catalog_core::Constraint` field-for-field. See the module doc
/// and the design doc's "leftOperand-to-claim mapping and supported
/// operators" section for how `operator` is interpreted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Constraint {
    pub left_operand: String,
    pub operator: String,
    pub right_operand: String,
}

/// One ODRL rule entry (a single permission, prohibition, or obligation).
/// Mirrors `catalog_core::Rule` field-for-field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub action: String,
    #[serde(default)]
    pub constraints: Vec<Constraint>,
}

/// A harvested ODRL policy. Mirrors `catalog_core::Policy`
/// field-for-field, including which fields default when absent from the
/// wire JSON (matching `catalog-core`'s own `#[serde(default)]`
/// placement exactly, so a caller round-tripping a `catalog_core::Policy`
/// through JSON into this type sees identical leniency).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub kind: PolicyKind,
    #[serde(default)]
    pub assigner: Option<String>,
    #[serde(default)]
    pub assignee: Option<String>,
    #[serde(default)]
    pub permissions: Vec<Rule>,
    #[serde(default)]
    pub prohibitions: Vec<Rule>,
    #[serde(default)]
    pub obligations: Vec<Rule>,
}

/// One identity claim's value: either a single string (e.g. `sub`,
/// `nationality`) or an array of strings (e.g. `scope`, a role/group
/// list) — see the design doc's "identity-claims model" section. This is
/// `#[serde(untagged)]` so the wire JSON is exactly a bare JSON string or
/// a bare JSON array of strings, matching the request schema's `claims`
/// example verbatim (no `{"Single": ...}` wrapper).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ClaimValue {
    Single(String),
    List(Vec<String>),
}

impl ClaimValue {
    /// Does this claim value equal (for [`ClaimValue::Single`]) or
    /// contain (for [`ClaimValue::List`]) the given string?
    fn contains(&self, needle: &str) -> bool {
        match self {
            ClaimValue::Single(s) => s == needle,
            ClaimValue::List(values) => values.iter().any(|v| v == needle),
        }
    }

    /// Does this claim value equal/contain *any* of the given candidate
    /// strings? Used by the `isAnyOf` operator.
    fn contains_any(&self, candidates: &[&str]) -> bool {
        match self {
            ClaimValue::Single(s) => candidates.contains(&s.as_str()),
            ClaimValue::List(values) => values.iter().any(|v| candidates.contains(&v.as_str())),
        }
    }
}

/// The request schema, verbatim per the design doc's "Request/response
/// JSON schema" section: one dataset, every ODRL policy attached to it,
/// and the caller's flat claims map.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateRequest {
    pub dataset_id: String,
    #[serde(default)]
    pub policies: Vec<Policy>,
    #[serde(default)]
    pub claims: BTreeMap<String, ClaimValue>,
}

/// `"Allow"` / `"Deny"`, serialized as the bare variant name (matching
/// the design doc's response schema exactly — no rename needed since
/// the variant names already are the literal wire strings).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Allow,
    Deny,
}

/// The response schema, verbatim per the design doc. `reason` is
/// diagnostic text only — see the design doc's explicit note that it has
/// no defined machine-parseable structure in v1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateResponse {
    pub dataset_id: String,
    pub decision: Decision,
    pub reason: String,
}

/// The result of resolving a constraint or a rule against the claims map.
///
/// `Unevaluable` means the engine cannot tell whether the constraint holds:
/// the claim is absent or the operator is not one of `eq`/`neq`/`isAnyOf`.
/// A permission needs a definite `Match` to allow. A prohibition applies on
/// `Match` or `Unevaluable`, so a constraint the engine cannot read never
/// switches a prohibition off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Match,
    Miss,
    Unevaluable,
}

/// Combine the constraints of one rule with AND. A definite `Miss` makes the
/// rule a `Miss` whatever the others say, otherwise any `Unevaluable`
/// constraint makes the rule `Unevaluable`. An empty `constraints` list is
/// an unconditional rule and is a `Match`, for permissions and prohibitions
/// alike.
fn rule_outcome(rule: &Rule, claims: &BTreeMap<String, ClaimValue>) -> Outcome {
    let mut outcome = Outcome::Match;
    for constraint in &rule.constraints {
        match constraint_outcome(constraint, claims) {
            Outcome::Miss => return Outcome::Miss,
            Outcome::Unevaluable => outcome = Outcome::Unevaluable,
            Outcome::Match => {}
        }
    }
    outcome
}

/// Resolve one atomic constraint against the claims map.
///
/// The claim is looked up by exact `left_operand` key. An absent claim is
/// `Unevaluable` for every operator, `neq` included: it is not treated as
/// vacuously satisfied. An operator outside `eq`/`neq`/`isAnyOf` (numeric
/// and date comparisons, `isPartOf`, logical groups, misspellings) is
/// `Unevaluable`. Never a panic or an error.
fn constraint_outcome(constraint: &Constraint, claims: &BTreeMap<String, ClaimValue>) -> Outcome {
    let Some(value) = claims.get(&constraint.left_operand) else {
        return Outcome::Unevaluable;
    };
    let matched = match constraint.operator.as_str() {
        "eq" => value.contains(&constraint.right_operand),
        "neq" => !value.contains(&constraint.right_operand),
        "isAnyOf" => {
            // `right_operand` is a comma-delimited list because
            // `catalog_core::Constraint.right_operand` is a single String.
            // Candidates are trimmed, so "DE, FR" and "DE,FR" behave the
            // same, and empty entries are dropped so an empty operand has
            // no candidates and cannot match an empty-string claim.
            let candidates: Vec<&str> = constraint
                .right_operand
                .split(',')
                .map(str::trim)
                .filter(|candidate| !candidate.is_empty())
                .collect();
            value.contains_any(&candidates)
        }
        _ => return Outcome::Unevaluable,
    };
    if matched {
        Outcome::Match
    } else {
        Outcome::Miss
    }
}

/// `policy.id`, or a stable placeholder when a harvested policy has no
/// `@id` — used only to build a human-readable `reason` string, never to
/// affect the decision itself.
fn policy_label(policy: &Policy) -> &str {
    policy.id.as_deref().unwrap_or("<unnamed>")
}

/// A short, human-readable trace of one rule's constraints, e.g.
/// `"nationality eq DE"` for a single constraint, `"a eq b and c eq d"`
/// for several, or `"unconditional"` for an empty constraint list — used
/// only to build `reason`, never to affect the decision itself.
fn describe_rule(rule: &Rule) -> String {
    if rule.constraints.is_empty() {
        return "unconditional".to_string();
    }
    rule.constraints
        .iter()
        .map(|c| format!("{} {} {}", c.left_operand, c.operator, c.right_operand))
        .collect::<Vec<_>>()
        .join(" and ")
}

/// The core decision function — see the module doc's "Multiple policies
/// on one dataset" section for how the design doc's per-`(Dataset,
/// Policy, claims)` algorithm generalizes to `request.policies`' full
/// list, and the design doc's "Enforcement decision semantics" section
/// for the algorithm's justification against XACML/EDC/ODRL prior art.
///
/// Deny-overrides at the top level:
/// 1. Any matching prohibition, in any attached policy, denies outright.
///    A prohibition with a constraint the engine cannot evaluate (absent
///    claim, unsupported operator) and no definitely failing constraint
///    also denies.
/// 2. No attached policy has any permission rule at all → allow (open by
///    default).
/// 3. Any matching permission, in any attached policy, allows.
/// 4. Permissions exist somewhere but none matched → deny.
pub fn evaluate(request: &EvaluateRequest) -> EvaluateResponse {
    for policy in &request.policies {
        for (idx, rule) in policy.prohibitions.iter().enumerate() {
            let outcome = rule_outcome(rule, &request.claims);
            if outcome != Outcome::Miss {
                let verdict = if outcome == Outcome::Match {
                    "matched"
                } else {
                    "could not be evaluated, failing closed"
                };
                return EvaluateResponse {
                    dataset_id: request.dataset_id.clone(),
                    decision: Decision::Deny,
                    reason: format!(
                        "prohibition[{idx}] of policy '{}' {verdict}: {}",
                        policy_label(policy),
                        describe_rule(rule)
                    ),
                };
            }
        }
    }

    let any_permission_declared = request.policies.iter().any(|p| !p.permissions.is_empty());
    if !any_permission_declared {
        return EvaluateResponse {
            dataset_id: request.dataset_id.clone(),
            decision: Decision::Allow,
            reason: "no permission rules declared on any attached policy; open by default"
                .to_string(),
        };
    }

    for policy in &request.policies {
        for (idx, rule) in policy.permissions.iter().enumerate() {
            if rule_outcome(rule, &request.claims) == Outcome::Match {
                return EvaluateResponse {
                    dataset_id: request.dataset_id.clone(),
                    decision: Decision::Allow,
                    reason: format!(
                        "permission[{idx}] of policy '{}' matched: {}",
                        policy_label(policy),
                        describe_rule(rule)
                    ),
                };
            }
        }
    }

    EvaluateResponse {
        dataset_id: request.dataset_id.clone(),
        decision: Decision::Deny,
        reason: "permission rules exist but none matched the caller's claims".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(pairs: &[(&str, ClaimValue)]) -> BTreeMap<String, ClaimValue> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    fn single(s: &str) -> ClaimValue {
        ClaimValue::Single(s.to_string())
    }

    fn list(values: &[&str]) -> ClaimValue {
        ClaimValue::List(values.iter().map(|s| s.to_string()).collect())
    }

    fn constraint(left: &str, op: &str, right: &str) -> Constraint {
        Constraint {
            left_operand: left.to_string(),
            operator: op.to_string(),
            right_operand: right.to_string(),
        }
    }

    fn rule(action: &str, constraints: Vec<Constraint>) -> Rule {
        Rule {
            action: action.to_string(),
            constraints,
        }
    }

    fn policy(id: &str, permissions: Vec<Rule>, prohibitions: Vec<Rule>) -> Policy {
        Policy {
            id: Some(id.to_string()),
            kind: PolicyKind::Offer,
            assigner: None,
            assignee: None,
            permissions,
            prohibitions,
            obligations: vec![],
        }
    }

    /// Design doc's own worked example, verbatim: a permission whose
    /// single constraint matches allows, and the `reason` string matches
    /// the doc's example exactly (`"permission[0] of policy 'policy-1'
    /// matched: nationality eq DE"`).
    #[test]
    fn matching_permission_allows_with_doc_example_reason() {
        let request = EvaluateRequest {
            dataset_id: "urn:uuid:example-dataset-1".to_string(),
            policies: vec![policy(
                "policy-1",
                vec![rule("use", vec![constraint("nationality", "eq", "DE")])],
                vec![],
            )],
            claims: claims(&[("sub", single("user-42")), ("nationality", single("DE"))]),
        };

        let response = evaluate(&request);

        assert_eq!(response.dataset_id, "urn:uuid:example-dataset-1");
        assert_eq!(response.decision, Decision::Allow);
        assert_eq!(
            response.reason,
            "permission[0] of policy 'policy-1' matched: nationality eq DE"
        );
    }

    /// Deny-overrides: a prohibition whose constraints all match denies
    /// even when a permission on the same policy *also* matches.
    #[test]
    fn matching_prohibition_denies_even_when_permission_also_matches() {
        let request = EvaluateRequest {
            dataset_id: "ds-1".to_string(),
            policies: vec![policy(
                "policy-1",
                vec![rule("use", vec![constraint("nationality", "eq", "DE")])],
                vec![rule("use", vec![constraint("sub", "eq", "user-42")])],
            )],
            claims: claims(&[("sub", single("user-42")), ("nationality", single("DE"))]),
        };

        let response = evaluate(&request);

        assert_eq!(response.decision, Decision::Deny);
        assert!(
            response
                .reason
                .starts_with("prohibition[0] of policy 'policy-1' matched"),
            "reason was: {}",
            response.reason
        );
    }

    /// A permission whose constraint doesn't match because the claim is
    /// entirely missing from the claims map denies (permissions exist,
    /// none matched — step 4, not step 2's open-policy allow).
    #[test]
    fn permission_with_missing_claim_denies() {
        let request = EvaluateRequest {
            dataset_id: "ds-1".to_string(),
            policies: vec![policy(
                "policy-1",
                vec![rule("use", vec![constraint("nationality", "eq", "DE")])],
                vec![],
            )],
            claims: claims(&[("sub", single("user-42"))]),
        };

        let response = evaluate(&request);

        assert_eq!(response.decision, Decision::Deny);
        assert_eq!(
            response.reason,
            "permission rules exist but none matched the caller's claims"
        );
    }

    /// A permission whose constraint doesn't match because the claim is
    /// present but has the wrong value denies.
    #[test]
    fn permission_with_wrong_claim_value_denies() {
        let request = EvaluateRequest {
            dataset_id: "ds-1".to_string(),
            policies: vec![policy(
                "policy-1",
                vec![rule("use", vec![constraint("nationality", "eq", "DE")])],
                vec![],
            )],
            claims: claims(&[("nationality", single("FR"))]),
        };

        let response = evaluate(&request);

        assert_eq!(response.decision, Decision::Deny);
    }

    /// A dataset whose only policy has no permissions and no prohibitions
    /// at all is open — step 2's "no permissions declared -> allow".
    #[test]
    fn no_permissions_or_prohibitions_allows() {
        let request = EvaluateRequest {
            dataset_id: "ds-1".to_string(),
            policies: vec![policy("policy-1", vec![], vec![])],
            claims: claims(&[]),
        };

        let response = evaluate(&request);

        assert_eq!(response.decision, Decision::Allow);
        assert_eq!(
            response.reason,
            "no permission rules declared on any attached policy; open by default"
        );
    }

    /// A dataset with zero attached policies at all is likewise open (the
    /// flattened permission set across zero policies is empty).
    #[test]
    fn no_policies_at_all_allows() {
        let request = EvaluateRequest {
            dataset_id: "ds-1".to_string(),
            policies: vec![],
            claims: claims(&[]),
        };

        assert_eq!(evaluate(&request).decision, Decision::Allow);
    }

    /// An unconditional permission rule (empty `constraints`) counts as
    /// "all match" per the design doc, so it allows regardless of claims.
    #[test]
    fn unconditional_permission_allows() {
        let request = EvaluateRequest {
            dataset_id: "ds-1".to_string(),
            policies: vec![policy("policy-1", vec![rule("use", vec![])], vec![])],
            claims: claims(&[]),
        };

        assert_eq!(evaluate(&request).decision, Decision::Allow);
    }

    /// An unconditional prohibition rule (empty `constraints`) denies
    /// unconditionally, per the design doc's explicit "an empty
    /// `constraints` list on a prohibition rule counts as 'all match'".
    #[test]
    fn unconditional_prohibition_denies() {
        let request = EvaluateRequest {
            dataset_id: "ds-1".to_string(),
            policies: vec![policy(
                "policy-1",
                vec![rule("use", vec![constraint("nationality", "eq", "DE")])],
                vec![rule("use", vec![])],
            )],
            claims: claims(&[("nationality", single("DE"))]),
        };

        assert_eq!(evaluate(&request).decision, Decision::Deny);
    }

    /// An unsupported operator string degrades safely to non-matching
    /// rather than panicking, for both a missing and a present claim.
    #[test]
    fn unsupported_operator_never_panics_and_never_matches() {
        let request = EvaluateRequest {
            dataset_id: "ds-1".to_string(),
            policies: vec![policy(
                "policy-1",
                vec![rule("use", vec![constraint("age_in_years", "gteq", "18")])],
                vec![],
            )],
            claims: claims(&[("age_in_years", single("42"))]),
        };

        // Must not panic, and must resolve to Deny (permission declared,
        // none matched — the unsupported operator can never satisfy).
        let response = evaluate(&request);
        assert_eq!(response.decision, Decision::Deny);
    }

    /// `neq` on a claim that is entirely missing is still a miss (not a
    /// vacuous match) — the "claim absent -> false regardless of
    /// operator" rule applies to `neq` too.
    #[test]
    fn neq_on_missing_claim_does_not_match() {
        let request = EvaluateRequest {
            dataset_id: "ds-1".to_string(),
            policies: vec![policy(
                "policy-1",
                vec![rule("use", vec![constraint("nationality", "neq", "US")])],
                vec![],
            )],
            claims: claims(&[]),
        };

        assert_eq!(evaluate(&request).decision, Decision::Deny);
    }

    /// `neq` on a present claim with a different value matches (allows).
    #[test]
    fn neq_on_present_different_claim_matches() {
        let request = EvaluateRequest {
            dataset_id: "ds-1".to_string(),
            policies: vec![policy(
                "policy-1",
                vec![rule("use", vec![constraint("nationality", "neq", "US")])],
                vec![],
            )],
            claims: claims(&[("nationality", single("DE"))]),
        };

        assert_eq!(evaluate(&request).decision, Decision::Allow);
    }

    /// `eq` against a multi-valued claim (`ClaimValue::List`) matches if
    /// the target value is a member of the list.
    #[test]
    fn eq_matches_multi_valued_claim_membership() {
        let request = EvaluateRequest {
            dataset_id: "ds-1".to_string(),
            policies: vec![policy(
                "policy-1",
                vec![rule("use", vec![constraint("scope", "eq", "sparql:read")])],
                vec![],
            )],
            claims: claims(&[("scope", list(&["catalog:read", "sparql:read"]))]),
        };

        assert_eq!(evaluate(&request).decision, Decision::Allow);
    }

    /// `isAnyOf` against a single-valued claim matches when the claim is
    /// one of the constraint's comma-delimited candidates.
    #[test]
    fn is_any_of_matches_single_valued_claim() {
        let request = EvaluateRequest {
            dataset_id: "ds-1".to_string(),
            policies: vec![policy(
                "policy-1",
                vec![rule(
                    "use",
                    vec![constraint("nationality", "isAnyOf", "DE,FR,NL")],
                )],
                vec![],
            )],
            claims: claims(&[("nationality", single("FR"))]),
        };

        assert_eq!(evaluate(&request).decision, Decision::Allow);
    }

    /// `isAnyOf` against a multi-valued claim matches when *any* element
    /// of the claim's list is among the constraint's candidates.
    #[test]
    fn is_any_of_matches_multi_valued_claim_intersection() {
        let request = EvaluateRequest {
            dataset_id: "ds-1".to_string(),
            policies: vec![policy(
                "policy-1",
                vec![rule(
                    "use",
                    vec![constraint("scope", "isAnyOf", "admin:read, sparql:read")],
                )],
                vec![],
            )],
            claims: claims(&[("scope", list(&["catalog:read", "sparql:read"]))]),
        };

        assert_eq!(evaluate(&request).decision, Decision::Allow);
    }

    /// `isAnyOf` misses when no element of a multi-valued claim is among
    /// the candidates.
    #[test]
    fn is_any_of_misses_when_no_overlap() {
        let request = EvaluateRequest {
            dataset_id: "ds-1".to_string(),
            policies: vec![policy(
                "policy-1",
                vec![rule(
                    "use",
                    vec![constraint("scope", "isAnyOf", "admin:read,write")],
                )],
                vec![],
            )],
            claims: claims(&[("scope", list(&["catalog:read", "sparql:read"]))]),
        };

        assert_eq!(evaluate(&request).decision, Decision::Deny);
    }

    /// Multiple constraints on one rule are AND-ed: both must match.
    #[test]
    fn multiple_constraints_on_one_rule_are_and_ed() {
        let request = EvaluateRequest {
            dataset_id: "ds-1".to_string(),
            policies: vec![policy(
                "policy-1",
                vec![rule(
                    "use",
                    vec![
                        constraint("nationality", "eq", "DE"),
                        constraint("age_over_18", "eq", "true"),
                    ],
                )],
                vec![],
            )],
            claims: claims(&[
                ("nationality", single("DE")),
                ("age_over_18", single("false")),
            ]),
        };

        // Second constraint fails -> the whole rule fails -> no permission
        // matches -> deny.
        assert_eq!(evaluate(&request).decision, Decision::Deny);
    }

    /// Multiple permission rules in one policy are alternatives (OR): if
    /// either matches, the policy allows.
    #[test]
    fn multiple_permission_rules_are_alternatives() {
        let request = EvaluateRequest {
            dataset_id: "ds-1".to_string(),
            policies: vec![policy(
                "policy-1",
                vec![
                    rule("use", vec![constraint("nationality", "eq", "DE")]),
                    rule("use", vec![constraint("nationality", "eq", "FR")]),
                ],
                vec![],
            )],
            claims: claims(&[("nationality", single("FR"))]),
        };

        assert_eq!(evaluate(&request).decision, Decision::Allow);
    }

    /// Multiple policies on one dataset: a prohibition on the *second*
    /// policy still denies, even though the first policy's permission
    /// matches — deny-overrides is applied across the flattened rule
    /// lists of every attached policy, not per-policy independently.
    #[test]
    fn prohibition_on_a_different_policy_still_overrides() {
        let request = EvaluateRequest {
            dataset_id: "ds-1".to_string(),
            policies: vec![
                policy(
                    "policy-open",
                    vec![rule("use", vec![constraint("nationality", "eq", "DE")])],
                    vec![],
                ),
                policy("policy-embargo", vec![], vec![rule("use", vec![])]),
            ],
            claims: claims(&[("nationality", single("DE"))]),
        };

        let response = evaluate(&request);
        assert_eq!(response.decision, Decision::Deny);
        assert!(response.reason.contains("policy-embargo"));
    }

    /// Multiple policies on one dataset: a permission on a *second*
    /// policy allows even though the first policy declares permissions
    /// that don't match the caller.
    #[test]
    fn matching_permission_on_a_different_policy_allows() {
        let request = EvaluateRequest {
            dataset_id: "ds-1".to_string(),
            policies: vec![
                policy(
                    "policy-de-only",
                    vec![rule("use", vec![constraint("nationality", "eq", "DE")])],
                    vec![],
                ),
                policy(
                    "policy-fr-only",
                    vec![rule("use", vec![constraint("nationality", "eq", "FR")])],
                    vec![],
                ),
            ],
            claims: claims(&[("nationality", single("FR"))]),
        };

        let response = evaluate(&request);
        assert_eq!(response.decision, Decision::Allow);
        assert!(response.reason.contains("policy-fr-only"));
    }

    fn prohibition_only_request(
        constraints: Vec<Constraint>,
        claim_pairs: &[(&str, ClaimValue)],
    ) -> EvaluateRequest {
        EvaluateRequest {
            dataset_id: "ds-1".to_string(),
            policies: vec![policy("policy-1", vec![], vec![rule("use", constraints)])],
            claims: claims(claim_pairs),
        }
    }

    /// A prohibition constraint on a claim the caller did not present
    /// cannot be shown to be false, so it denies instead of being skipped.
    #[test]
    fn prohibition_with_missing_claim_denies() {
        let request = prohibition_only_request(vec![constraint("nationality", "neq", "DE")], &[]);
        let response = evaluate(&request);
        assert_eq!(response.decision, Decision::Deny);
        assert!(
            response.reason.contains("could not be evaluated"),
            "reason was: {}",
            response.reason
        );
    }

    /// A prohibition with an operator this engine cannot evaluate denies.
    #[test]
    fn prohibition_with_unsupported_operator_denies() {
        for operator in ["lt", "gt", "isPartOf", "isNoneOf", "egal"] {
            let request = prohibition_only_request(
                vec![constraint("age", operator, "18")],
                &[("age", single("42"))],
            );
            assert_eq!(
                evaluate(&request).decision,
                Decision::Deny,
                "operator {operator}"
            );
        }
    }

    /// A constraint that definitely fails still lets the prohibition's AND
    /// fail, even when another constraint of the same rule is unevaluable.
    #[test]
    fn prohibition_with_a_definite_miss_does_not_apply() {
        let request = prohibition_only_request(
            vec![
                constraint("nationality", "eq", "US"),
                constraint("age", "lt", "18"),
            ],
            &[("nationality", single("DE")), ("age", single("10"))],
        );
        assert_eq!(evaluate(&request).decision, Decision::Allow);
    }

    /// A prohibition that fails closed also overrides a matching permission.
    #[test]
    fn unevaluable_prohibition_overrides_a_matching_permission() {
        let request = EvaluateRequest {
            dataset_id: "ds-1".to_string(),
            policies: vec![policy(
                "policy-1",
                vec![rule("use", vec![])],
                vec![rule("use", vec![constraint("age", "lt", "18")])],
            )],
            claims: claims(&[("age", single("42"))]),
        };
        assert_eq!(evaluate(&request).decision, Decision::Deny);
    }

    /// An unevaluable permission constraint stays a miss.
    #[test]
    fn unevaluable_permission_constraint_stays_a_miss() {
        let request = EvaluateRequest {
            dataset_id: "ds-1".to_string(),
            policies: vec![
                policy(
                    "p1",
                    vec![rule("use", vec![constraint("age", "lt", "18")])],
                    vec![],
                ),
                policy("p2", vec![rule("use", vec![])], vec![]),
            ],
            claims: claims(&[("age", single("42"))]),
        };
        // p2's unconditional permission still allows.
        assert_eq!(evaluate(&request).decision, Decision::Allow);
    }

    /// An empty right operand yields no candidates, so it cannot match an
    /// empty-string claim.
    #[test]
    fn empty_is_any_of_does_not_match_an_empty_claim() {
        for right in ["", " , ,"] {
            let request = EvaluateRequest {
                dataset_id: "ds-1".to_string(),
                policies: vec![policy(
                    "policy-1",
                    vec![rule("use", vec![constraint("scope", "isAnyOf", right)])],
                    vec![],
                )],
                claims: claims(&[("scope", single(""))]),
            };
            assert_eq!(
                evaluate(&request).decision,
                Decision::Deny,
                "right {right:?}"
            );
        }
    }

    /// The request/response types round-trip through JSON in exactly the
    /// shape the design doc's example shows (field names, `kind` variant
    /// spelling, flat claims map).
    #[test]
    fn request_deserializes_from_the_design_docs_example_json() {
        let json = r#"{
          "dataset_id": "urn:uuid:example-dataset-1",
          "policies": [
            {
              "id": "policy-1",
              "kind": "Offer",
              "assigner": "did:web:provider.example",
              "assignee": null,
              "permissions": [
                {
                  "action": "use",
                  "constraints": [
                    { "left_operand": "nationality", "operator": "eq", "right_operand": "DE" }
                  ]
                }
              ],
              "prohibitions": [],
              "obligations": []
            }
          ],
          "claims": {
            "sub": "user-42",
            "nationality": "DE",
            "scope": ["catalog:read", "sparql:read"]
          }
        }"#;

        let request: EvaluateRequest = serde_json::from_str(json).expect("valid per the schema");
        assert_eq!(request.policies[0].kind, PolicyKind::Offer);
        assert_eq!(
            request.claims["scope"],
            list(&["catalog:read", "sparql:read"])
        );

        let response = evaluate(&request);
        let response_json = serde_json::to_value(&response).unwrap();
        assert_eq!(response_json["decision"], "Allow");
    }
}
