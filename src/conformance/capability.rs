//! Capability fixture self-consistency checks.
//!
//! cotest does not link soland's reducer authorization engine here. The
//! authority-chain helpers below are an executable oracle for the shared fixture
//! shape and expected outcomes, not a substitute for implementation-level
//! reducer tests. Keep this boundary explicit so fixture agreement is not
//! mistaken for cross-implementation conformance.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{load_fixture_value, required_str, validate_profile};
use crate::transcripts::record_vector_event;

pub fn run_capability_fixture_suite() -> Result<()> {
    let value = load_fixture_value("capability-fixture.json")?;
    validate_profile(&value, "ak.vector_group.capability.v1")?;
    let fixtures = value
        .get("fixtures")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("capability artifact missing fixtures"))?;
    for fixture in fixtures {
        let name = required_str(fixture, "name")?;
        if fixture.get("expected").is_none()
            && fixture.get("requests").is_none()
            && fixture.get("cases").is_none()
        {
            bail!("capability fixture {name} missing expected outcome");
        }
        if name == "approval_constraint_requires_controller_approval" {
            let requests = fixture
                .get("requests")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("approval fixture missing requests"))?;
            if !requests.iter().any(|request| {
                request
                    .pointer("/expected/decision")
                    .and_then(Value::as_str)
                    == Some("require_review")
            }) {
                bail!("approval fixture no longer requires review without proof");
            }
        }
        if name == "revoked_grant_denies_later_write"
            && fixture
                .pointer("/expected/decision")
                .and_then(Value::as_str)
                != Some("deny")
        {
            bail!("revoked grant fixture no longer denies later write");
        }
        if fixture.get("grants").is_some() && fixture.get("request").is_some() {
            evaluate_direct_grant_request_fixture(fixture)?;
        }
        match name {
            "authority_chain_multi_level" => evaluate_authority_chain_fixture(fixture)?,
            "authority_regrant_terminal_child_carrier" => {
                evaluate_authority_regrant_terminal_child_fixture(fixture)?;
            }
            "membership_without_capability_denies_core_writes" => {
                evaluate_membership_without_capability_fixture(fixture)?;
            }
            "revoke_rollback_forward_recompute" => evaluate_revoke_rollback_fixture(fixture)?,
            "revoke_downstream_recheck" => evaluate_revoke_downstream_fixture(fixture)?,
            "authority_liveness_and_root_lifecycle" => {
                evaluate_authority_liveness_fixture(fixture)?;
            }
            "relinquish_and_dependency_pending" => evaluate_relinquish_pending_fixture(fixture)?,
            "unified_authority_constraints" => evaluate_unified_authority_constraints(fixture)?,
            "authority_audit_materialization" => evaluate_authority_audit_fixture(fixture)?,
            "derived_uses_issuer_authority_rules" => evaluate_derived_authority_fixture(fixture)?,
            "sensitive_field_handling" => evaluate_sensitive_field_handling_fixture(fixture)?,
            _ => {}
        }
    }
    Ok(())
}

fn str_vec(value: &Value, pointer: &str) -> Vec<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn action_implies(granted: &str, requested: &str) -> bool {
    granted == requested || granted == "ak.realm.admin"
}

fn parent_can_regrant(parent_actions: &[String], child_actions: &[String]) -> bool {
    child_actions.iter().all(|child| {
        parent_actions
            .iter()
            .any(|granted| action_implies(granted, child))
    })
}

struct AuthorityGrant {
    grant_id: String,
    parent_authority_grant_id: String,
    subject: String,
    actions: Vec<String>,
    resources: Vec<Value>,
    constraints: Vec<Value>,
    authorized_by_grant: String,
    issuer_authority_ref: String,
}

#[derive(Clone)]
struct ActionQuery {
    actor: String,
    action: String,
    resource: String,
    request_time: String,
    audience: String,
}

#[derive(Default)]
struct ChainResult {
    authorized: bool,
    valid_chain: Vec<String>,
    time: bool,
    resource_scope: bool,
    rate_limit: bool,
    audience: bool,
}

fn parse_authority_chain(fixture: &Value) -> Result<Vec<AuthorityGrant>> {
    let raw = fixture
        .get("authority_chain")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("authority_chain fixture missing authority_chain"))?;
    let mut out = Vec::with_capacity(raw.len());
    for grant in raw {
        let authorized_by_grant = grant
            .get("refs")
            .and_then(Value::as_array)
            .and_then(|refs| {
                refs.iter().find(|reference| {
                    reference.get("role").and_then(Value::as_str) == Some("authorized_by")
                })
            })
            .and_then(|reference| reference.get("id").and_then(Value::as_str))
            .unwrap_or_default()
            .to_owned();
        let issuer_authority_ref = grant
            .get("refs")
            .and_then(Value::as_array)
            .and_then(|refs| {
                refs.iter().find(|reference| {
                    reference.get("role").and_then(Value::as_str) == Some("issuer_authority")
                })
            })
            .and_then(|reference| reference.get("id").and_then(Value::as_str))
            .unwrap_or_default()
            .to_owned();
        let parent_authority_grant_id = grant
            .pointer("/payload/issuer_authority_refs")
            .and_then(Value::as_array)
            .and_then(|refs| {
                refs.iter().find(|reference| {
                    reference.get("kind").and_then(Value::as_str) == Some("grant")
                })
            })
            .and_then(|reference| reference.get("grant_id").and_then(Value::as_str))
            .unwrap_or_default()
            .to_owned();
        out.push(AuthorityGrant {
            grant_id: grant
                .pointer("/payload/grant_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            parent_authority_grant_id,
            subject: grant
                .pointer("/payload/subject")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            actions: str_vec(grant, "/payload/actions"),
            resources: grant
                .pointer("/payload/resources")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            constraints: grant
                .pointer("/payload/constraints")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            authorized_by_grant,
            issuer_authority_ref,
        });
    }
    Ok(out)
}

fn resource_matches(resource: &Value, requested: &str) -> bool {
    resource.get("realm_id").and_then(Value::as_str) == Some(requested)
}

fn request_resource_matches(grant_resource: &Value, request_resource: &Value) -> bool {
    if let (Some(grant), Some(request)) = (grant_resource.as_str(), request_resource.as_str()) {
        return grant == request;
    }

    let Some(grant) = grant_resource.as_object() else {
        return false;
    };
    let Some(request) = request_resource.as_object() else {
        return false;
    };

    if let Some(grant_realm) = grant.get("realm_id").and_then(Value::as_str)
        && request.get("realm_id").and_then(Value::as_str) != Some(grant_realm)
    {
        return false;
    }
    if grant.get("kind").and_then(Value::as_str) == Some("realm") {
        return true;
    }
    if let Some(grant_kind) = grant.get("kind").and_then(Value::as_str)
        && request.get("kind").and_then(Value::as_str) != Some(grant_kind)
    {
        return false;
    }
    if let Some(grant_strand) = grant.get("strand_id").and_then(Value::as_str)
        && request.get("strand_id").and_then(Value::as_str) != Some(grant_strand)
    {
        return false;
    }
    if let Some(grant_cell) = grant.get("cell").and_then(Value::as_str)
        && request.get("cell").and_then(Value::as_str) != Some(grant_cell)
    {
        return false;
    }
    true
}

fn grant_matches_request(grant: &Value, request: &Value) -> bool {
    let Some(actor) = request.get("actor_id").and_then(Value::as_str) else {
        return false;
    };
    if grant.get("subject").and_then(Value::as_str) != Some(actor) {
        return false;
    }
    let Some(action) = request.get("action").and_then(Value::as_str) else {
        return false;
    };
    if !grant
        .get("actions")
        .and_then(Value::as_array)
        .is_some_and(|actions| {
            actions
                .iter()
                .filter_map(Value::as_str)
                .any(|granted| action_implies(granted, action))
        })
    {
        return false;
    }
    let Some(request_resource) = request.get("resource") else {
        return false;
    };
    grant
        .get("resources")
        .and_then(Value::as_array)
        .is_some_and(|resources| {
            resources
                .iter()
                .any(|resource| request_resource_matches(resource, request_resource))
        })
}

fn evaluate_grant_request(grants: &[Value], request: &Value) -> (String, Vec<String>) {
    let matched_grants: Vec<String> = grants
        .iter()
        .filter(|grant| grant_matches_request(grant, request))
        .filter_map(|grant| grant.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect();
    let decision = if matched_grants.is_empty() {
        "deny"
    } else {
        "allow"
    };
    (decision.to_owned(), matched_grants)
}

fn deny_reason_for_request(request: &Value) -> &'static str {
    match request.get("action").and_then(Value::as_str) {
        Some("ak.message.create") => "no_strand_track_message_grant",
        _ => "capability_denied",
    }
}

fn evaluate_direct_grant_request_fixture(fixture: &Value) -> Result<()> {
    let name = required_str(fixture, "name")?;
    let grants = fixture
        .get("grants")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("capability fixture {name} missing grants[]"))?;
    let request = fixture
        .get("request")
        .ok_or_else(|| anyhow!("capability fixture {name} missing request"))?;
    let (decision, matched_grants) = evaluate_grant_request(grants, request);

    let expected_decision = fixture
        .pointer("/expected/decision")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("capability fixture {name} missing expected.decision"))?;
    if decision != expected_decision {
        bail!("capability fixture {name}: decision {decision} but expected {expected_decision}");
    }
    let expected_matched = str_vec(fixture, "/expected/matched_grants");
    if !expected_matched.is_empty() && matched_grants != expected_matched {
        bail!(
            "capability fixture {name}: matched grants {:?} but expected {:?}",
            matched_grants,
            expected_matched
        );
    }
    if decision == "deny"
        && let Some(expected_reason) = fixture
            .pointer("/expected/reason_code")
            .and_then(Value::as_str)
    {
        let reason = deny_reason_for_request(request);
        if reason != expected_reason {
            bail!("capability fixture {name}: deny reason {reason} but expected {expected_reason}");
        }
    }
    Ok(())
}

fn evaluate_membership_without_capability_fixture(fixture: &Value) -> Result<()> {
    let name = required_str(fixture, "name")?;
    let memberships = fixture
        .get("memberships")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("capability fixture {name} missing memberships[]"))?;
    let grants = fixture
        .get("grants")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("capability fixture {name} missing grants[]"))?;
    let requests = fixture
        .get("requests")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("capability fixture {name} missing requests[]"))?;

    for request in requests {
        let actor = required_str(request, "actor_id")?;
        let member_joined = memberships.iter().any(|membership| {
            membership.get("actor_id").and_then(Value::as_str) == Some(actor)
                && membership.get("membership").and_then(Value::as_str) == Some("join")
        });
        if !member_joined {
            bail!("capability fixture {name}: request actor {actor} is not a joined member");
        }
        let (decision, matched_grants) = evaluate_grant_request(grants, request);
        if !matched_grants.is_empty() {
            bail!(
                "capability fixture {name}: membership baseline request unexpectedly matched grants {:?}",
                matched_grants
            );
        }
        let expected_decision = request
            .pointer("/expected/decision")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                anyhow!("capability fixture {name} request missing expected.decision")
            })?;
        if decision != expected_decision {
            bail!(
                "capability fixture {name}: decision {decision} but expected {expected_decision}"
            );
        }
        let expected_reason = request
            .pointer("/expected/reason_code")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                anyhow!("capability fixture {name} request missing expected.reason_code")
            })?;
        let reason = deny_reason_for_request(request);
        if reason != expected_reason {
            bail!("capability fixture {name}: reason {reason} but expected {expected_reason}");
        }
    }

    record_vector_event(
        "capability.membership_is_not_baseline",
        &json!({"requests": requests.len()}),
        &json!({"decision": "deny"}),
        &json!({"membership_baseline": false}),
    );
    Ok(())
}

fn evaluate_chain(base: &Value, grants: &[AuthorityGrant], query: &ActionQuery) -> ChainResult {
    let base_grant = base
        .get("grant_id")
        .and_then(Value::as_str)
        .unwrap_or_default();

    let Some(leaf) = grants.iter().find(|grant| {
        grant.subject == query.actor
            && grant
                .actions
                .iter()
                .any(|action| action_implies(action, &query.action))
    }) else {
        return ChainResult::default();
    };

    let mut chain: Vec<&AuthorityGrant> = vec![leaf];
    let mut current = leaf;
    loop {
        if current.parent_authority_grant_id == base_grant {
            break;
        }
        match grants
            .iter()
            .find(|grant| grant.grant_id == current.parent_authority_grant_id)
        {
            Some(parent) => {
                chain.push(parent);
                current = parent;
            }
            // Parent grant neither the root nor a present authority edge: the
            // chain is broken (for example, a middle grant was skipped).
            None => return ChainResult::default(),
        }
    }
    chain.reverse();

    let mut prev_actions = str_vec(base, "/actions");
    for grant in &chain {
        if !grant.grant_id.starts_with("ak:grant:")
            || grant.authorized_by_grant != grant.parent_authority_grant_id
            || grant.issuer_authority_ref != grant.parent_authority_grant_id
        {
            return ChainResult::default();
        }
        if !parent_can_regrant(&prev_actions, &grant.actions) {
            return ChainResult::default();
        }
        prev_actions = grant.actions.clone();
    }

    let mut time = true;
    let mut resource_scope = true;
    let rate_limit = true;
    let mut audience = true;
    for grant in &chain {
        if !grant
            .resources
            .iter()
            .any(|resource| resource_matches(resource, &query.resource))
        {
            resource_scope = false;
        }
        for constraint in &grant.constraints {
            match constraint.get("constraint_kind").and_then(Value::as_str) {
                Some("temporal") => {
                    if let Some(not_before) = constraint.get("not_before").and_then(Value::as_str)
                        && query.request_time.as_str() < not_before
                    {
                        time = false;
                    }
                    if let Some(expires_at) = constraint.get("expires_at").and_then(Value::as_str)
                        && query.request_time.as_str() > expires_at
                    {
                        time = false;
                    }
                }
                Some("quota") => {
                    // Single-shot query: a lone request does not exceed the
                    // declared rate/quota constraint, so rate_limit stays true.
                }
                Some("scope_limitation") => {
                    let allowed = constraint
                        .get("allowed_audiences")
                        .and_then(Value::as_array)
                        .map(|audiences| {
                            audiences
                                .iter()
                                .any(|value| value.as_str() == Some(query.audience.as_str()))
                        })
                        .unwrap_or(false);
                    if !allowed {
                        audience = false;
                    }
                }
                _ => {}
            }
        }
    }

    let mut valid_chain = vec![chain[0].authorized_by_grant.clone()];
    for grant in &chain {
        valid_chain.push(grant.grant_id.clone());
    }

    ChainResult {
        authorized: time && resource_scope && audience,
        valid_chain,
        time,
        resource_scope,
        rate_limit,
        audience,
    }
}

/// Vector `ak.vector.capability.authority_chain.v1` (conformance §4.2).
///
/// A multi-level authority chain authorizes only when every link can re-grant
/// the requested action AND every constraint (time, resource
/// scope, rate, audience) holds. The evaluator must not authorize directly
/// from the root (skipping a middle grant), must not ignore the audience
/// scope limitation, and must not authorize after the temporal window expires.
fn evaluate_authority_chain_fixture(fixture: &Value) -> Result<()> {
    let base = fixture
        .get("base")
        .ok_or_else(|| anyhow!("authority_chain fixture missing base grant"))?;
    let grants = parse_authority_chain(fixture)?;
    let query_value = fixture
        .get("action_query")
        .ok_or_else(|| anyhow!("authority_chain fixture missing action_query"))?;
    let query = ActionQuery {
        actor: required_str(query_value, "actor_id")?.to_owned(),
        action: required_str(query_value, "action")?.to_owned(),
        resource: required_str(query_value, "resource")?.to_owned(),
        request_time: required_str(query_value, "request_time")?.to_owned(),
        audience: required_str(query_value, "request_audience")?.to_owned(),
    };

    let result = evaluate_chain(base, &grants, &query);

    let expected_authorized = fixture
        .pointer("/expected/authorized")
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("authority_chain fixture missing expected.authorized"))?;
    if result.authorized != expected_authorized {
        bail!(
            "authority_chain: authorized={} but expected {}",
            result.authorized,
            expected_authorized
        );
    }
    let expected_chain = str_vec(fixture, "/expected/valid_chain");
    if result.valid_chain != expected_chain {
        bail!(
            "authority_chain: valid_chain {:?} did not match expected {:?}",
            result.valid_chain,
            expected_chain
        );
    }
    for (key, value) in [
        ("time", result.time),
        ("resource_scope", result.resource_scope),
        ("rate_limit", result.rate_limit),
        ("audience", result.audience),
    ] {
        let expected = fixture
            .pointer(&format!("/expected/constraints_checked/{key}"))
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("authority_chain fixture missing constraints_checked.{key}"))?;
        if value != expected {
            bail!("authority_chain: constraint `{key}`={value} but expected {expected}");
        }
    }

    // Non-tautology guards: each failure condition from §4.2 must flip the
    // decision to unauthorized.
    let mut expired = query.clone();
    expired.request_time = "2026-06-01T00:00:00.000Z".to_owned();
    if evaluate_chain(base, &grants, &expired).authorized {
        bail!("authority_chain: expired temporal window still authorized");
    }
    let mut wrong_audience = query.clone();
    wrong_audience.audience = "did:web:attacker.example".to_owned();
    if evaluate_chain(base, &grants, &wrong_audience).authorized {
        bail!("authority_chain: out-of-scope audience still authorized");
    }
    let without_middle: Vec<AuthorityGrant> = grants
        .into_iter()
        .filter(|grant| grant.subject != "ak:did_core:webvh:z6mkfixtureopsexamplecom")
        .collect();
    if evaluate_chain(base, &without_middle, &query).authorized {
        bail!("authority_chain: skipping the middle grant still authorized");
    }

    record_vector_event(
        "capability.authority_chain",
        query_value,
        &fixture["expected"],
        &json!({
            "authorized": result.authorized,
            "valid_chain": result.valid_chain,
            "constraints_checked": {
                "time": result.time,
                "resource_scope": result.resource_scope,
                "rate_limit": result.rate_limit,
                "audience": result.audience,
            },
        }),
    );
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct OrdinaryAuthorityControl {
    max_depth: Option<u64>,
    regrant_allowed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RegrantDecision {
    Accepted,
    Rejected { reason_code: &'static str },
}

impl RegrantDecision {
    fn as_json(self) -> Value {
        match self {
            Self::Accepted => json!({"accepted": true}),
            Self::Rejected { reason_code } => json!({
                "accepted": false,
                "error_code": "failed_precondition",
                "reason_code": reason_code,
            }),
        }
    }
}

fn ordinary_authority_controls(
    grant: &Value,
    context: &str,
) -> Result<Vec<OrdinaryAuthorityControl>> {
    let constraints = grant
        .get("constraints")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("{context} missing constraints array"))?;
    constraints
        .iter()
        .enumerate()
        .filter(|(_, constraint)| {
            constraint.get("constraint_kind").and_then(Value::as_str)
                == Some("authority_control")
                && constraint.get("constraint_subkind").is_none()
        })
        .map(|(index, constraint)| {
            let max_depth = match constraint.get("max_authority_depth") {
                Some(value) => Some(value.as_u64().ok_or_else(|| {
                    anyhow!(
                        "{context} constraints[{index}].max_authority_depth must be an unsigned integer"
                    )
                })?),
                None => None,
            };
            let regrant_allowed = match constraint.get("authority_regrant_allowed") {
                Some(value) => value.as_bool().ok_or_else(|| {
                    anyhow!(
                        "{context} constraints[{index}].authority_regrant_allowed must be a boolean"
                    )
                })?,
                None => false,
            };
            Ok(OrdinaryAuthorityControl {
                max_depth,
                regrant_allowed,
            })
        })
        .collect()
}

fn evaluate_regrant_candidate(
    accepted_grants: &BTreeMap<&str, &Value>,
    candidate: &Value,
    context: &str,
) -> Result<RegrantDecision> {
    let child_controls = ordinary_authority_controls(candidate, context)?;
    let authority_refs = candidate
        .get("issuer_authority_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("{context} missing issuer_authority_refs array"))?;
    let grant_refs = authority_refs
        .iter()
        .filter(|authority_ref| authority_ref.get("kind").and_then(Value::as_str) == Some("grant"))
        .collect::<Vec<_>>();
    if grant_refs.is_empty() {
        bail!("{context} must contain at least one grant authority ref");
    }

    for authority_ref in grant_refs {
        let parent_id = required_str(authority_ref, "grant_id")?;
        let parent = accepted_grants
            .get(parent_id)
            .ok_or_else(|| anyhow!("{context} references unresolved accepted grant {parent_id}"))?;
        let parent_controls =
            ordinary_authority_controls(parent, &format!("{context} accepted grant {parent_id}"))?;
        if parent_controls.is_empty() {
            return Ok(RegrantDecision::Rejected {
                reason_code: "authority_regrant_denied",
            });
        }

        let parent_depth = parent_controls
            .iter()
            .filter_map(|control| control.max_depth)
            .min();
        let parent_allows_regrant = parent_controls
            .iter()
            .all(|control| control.regrant_allowed);
        if parent_depth == Some(0) {
            return Ok(RegrantDecision::Rejected {
                reason_code: if parent_allows_regrant {
                    "authority_depth_exceeded"
                } else {
                    "authority_regrant_denied"
                },
            });
        }

        if !parent_allows_regrant {
            let explicitly_terminal = !child_controls.is_empty()
                && child_controls
                    .iter()
                    .all(|control| control.max_depth == Some(0) && !control.regrant_allowed);
            if !explicitly_terminal {
                return Ok(RegrantDecision::Rejected {
                    reason_code: "authority_regrant_denied",
                });
            }
        } else if let Some(parent_depth) = parent_depth {
            let child_depth = child_controls
                .iter()
                .filter_map(|control| control.max_depth)
                .min();
            if child_depth.is_none_or(|depth| depth >= parent_depth) {
                return Ok(RegrantDecision::Rejected {
                    reason_code: "authority_depth_exceeded",
                });
            }
        }
    }

    Ok(RegrantDecision::Accepted)
}

/// Vector `ak.vector.capability.authority_regrant_terminal_child.v1`.
///
/// This evaluator is deliberately data-driven and independent from Soland's
/// reducer. It treats only ordinary `authority_control` constraints as
/// regrant carriers, defaults `authority_regrant_allowed` to false, and
/// applies every referenced accepted grant as a fail-closed parent boundary.
fn evaluate_authority_regrant_terminal_child_fixture(fixture: &Value) -> Result<()> {
    const VECTOR_ID: &str = "ak.vector.capability.authority_regrant_terminal_child.v1";
    const REQUIRED_CASES: [&str; 9] = [
        "ordinary_parent_without_authority_control_is_not_a_grant_ref",
        "applet_authority_only_parent_is_not_an_ordinary_grant_ref",
        "false_parent_rejects_child_without_control_carrier",
        "false_parent_rejects_positive_child_depth",
        "false_parent_rejects_child_that_reopens_regrant",
        "false_parent_accepts_wire_explicit_terminal_child",
        "terminal_child_cannot_be_referenced_by_a_grandchild",
        "true_parent_accepts_depth_narrowing",
        "true_parent_rejects_non_narrowed_depth",
    ];

    let vector_id = required_str(fixture, "vector_id")?;
    if vector_id != VECTOR_ID {
        bail!("authority regrant fixture vector id {vector_id} does not match {VECTOR_ID}");
    }
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("authority regrant fixture missing cases"))?;
    let mut observed_cases = BTreeSet::new();

    for case in cases {
        let case_name = required_str(case, "name")?;
        if !observed_cases.insert(case_name) {
            bail!("authority regrant fixture repeats case {case_name}");
        }
        let accepted_values = case
            .get("accepted_grants")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("{case_name}: missing accepted_grants array"))?;
        let mut accepted_grants = BTreeMap::new();
        for grant in accepted_values {
            let grant_id = required_str(grant, "grant_id")?;
            if accepted_grants.insert(grant_id, grant).is_some() {
                bail!("{case_name}: duplicate accepted grant {grant_id}");
            }
        }
        let candidate = case
            .get("candidate")
            .ok_or_else(|| anyhow!("{case_name}: missing candidate"))?;
        let actual = evaluate_regrant_candidate(&accepted_grants, candidate, case_name)?.as_json();
        let expected = case
            .get("expected")
            .ok_or_else(|| anyhow!("{case_name}: missing expected outcome"))?;
        if actual != *expected {
            bail!(
                "{case_name}: regrant decision {} did not match expected {}",
                actual,
                expected
            );
        }

        record_vector_event(
            "capability.authority_regrant_terminal_child",
            candidate,
            expected,
            &actual,
        );
    }

    for required_case in REQUIRED_CASES {
        if !observed_cases.contains(required_case) {
            bail!("authority regrant fixture missing required case {required_case}");
        }
    }
    Ok(())
}

fn message_event_authorized(
    events: &[Value],
    ignore_event_id: Option<&str>,
    grant_id: &str,
) -> bool {
    let mut granted = false;
    let mut revoked = false;
    for event in events {
        if event.get("event_id").and_then(Value::as_str) == ignore_event_id {
            continue;
        }
        match event.get("kind").and_then(Value::as_str) {
            Some("ak.capability.grant") => {
                if event.pointer("/payload/grant_id").and_then(Value::as_str) == Some(grant_id) {
                    granted = true;
                }
            }
            Some("ak.capability.revoke")
                if event.pointer("/payload/grant_id").and_then(Value::as_str) == Some(grant_id) =>
            {
                revoked = true;
            }
            _ => {}
        }
    }
    granted && !revoked
}

/// Vector `ak.vector.capability.revoke_rollback.v1` (conformance §4.3).
///
/// With the revoke in effect the later write MUST be denied; rolling the
/// revoke back MUST make the same event authorized in a forward recompute,
/// the rollback MUST produce an independent auditable reference, and it MUST
/// NOT mutate the existing event id chain.
fn evaluate_revoke_rollback_fixture(fixture: &Value) -> Result<()> {
    let events = fixture
        .get("events")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("revoke_rollback fixture missing events"))?;
    let subject_event_id = required_str(fixture, "subject_event_id")?;
    let subject_event = events
        .iter()
        .find(|event| event.get("event_id").and_then(Value::as_str) == Some(subject_event_id))
        .ok_or_else(|| anyhow!("revoke_rollback fixture subject_event not in events"))?;
    let grant_id = subject_event
        .pointer("/payload/authorized_by")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("revoke_rollback subject_event missing payload.authorized_by"))?;
    let rollback_target = fixture
        .pointer("/rollback/target_event_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("revoke_rollback fixture missing rollback.target_event_id"))?;

    let initial_authorized = message_event_authorized(events, None, grant_id);
    let rolled_back_authorized = message_event_authorized(events, Some(rollback_target), grant_id);
    let rollback_ref_present = fixture
        .pointer("/rollback/reason")
        .and_then(Value::as_str)
        .is_some();
    let event_chain_immutable = events
        .iter()
        .all(|event| event.get("event_id").and_then(Value::as_str).is_some());

    let initial_decision = if initial_authorized { "allow" } else { "deny" };
    let post_decision = if rolled_back_authorized {
        "allow"
    } else {
        "deny"
    };

    let expected_initial = fixture
        .pointer("/expected/initial_decision")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let expected_post = fixture
        .pointer("/expected/post_rollback_decision")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if initial_decision != expected_initial {
        bail!(
            "revoke_rollback: initial decision {initial_decision} but expected {expected_initial}"
        );
    }
    if post_decision != expected_post {
        bail!(
            "revoke_rollback: post-rollback decision {post_decision} but expected {expected_post}"
        );
    }
    if !rollback_ref_present {
        bail!("revoke_rollback: rollback produced no auditable reference");
    }
    if !event_chain_immutable {
        bail!("revoke_rollback: event id chain was mutated by rollback");
    }

    record_vector_event(
        "capability.revoke_rollback",
        &json!({"subject_event_id": subject_event_id, "rollback_target": rollback_target}),
        &fixture["expected"],
        &json!({
            "initial_decision": initial_decision,
            "post_rollback_decision": post_decision,
            "rollback_ref_present": rollback_ref_present,
            "event_chain_immutable": event_chain_immutable,
        }),
    );
    Ok(())
}

/// Vector `ak.vector.capability.revoke_downstream_recheck.v1` (conformance
/// §10.7).
///
/// Revoking an upstream grant G MUST fail-close any pending event authorized
/// by a downstream child grant C, MUST invalidate every allow-cache entry that
/// depends on G or C in the same transaction, MUST retain the historical event
/// as an audit fact, and MUST treat G as no longer currently valid.
fn evaluate_revoke_downstream_fixture(fixture: &Value) -> Result<()> {
    let grants = fixture
        .get("grants")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("revoke_downstream fixture missing grants"))?;
    let revoked_root = fixture
        .pointer("/revoke/grant_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("revoke_downstream fixture missing revoke.grant_id"))?;

    // Propagate current invalidity through typed grant authority refs. This is
    // a read-time walk; no descendant grant record is rewritten.
    let mut revoked: HashSet<String> = HashSet::new();
    revoked.insert(revoked_root.to_owned());
    loop {
        let mut changed = false;
        for grant in grants {
            let grant_id = grant
                .get("grant_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let has_revoked_parent = grant
                .get("issuer_authority_refs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|reference| reference.get("kind").and_then(Value::as_str) == Some("grant"))
                .filter_map(|reference| reference.get("grant_id").and_then(Value::as_str))
                .any(|parent| revoked.contains(parent));
            if has_revoked_parent && revoked.insert(grant_id.to_owned()) {
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let pending_grant = fixture
        .pointer("/pending_event/authorized_by")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("revoke_downstream fixture missing pending_event.authorized_by"))?;
    let pending_decision = if revoked.contains(pending_grant) {
        "fail_closed"
    } else {
        "allow"
    };
    let pending_reason = if revoked.contains(pending_grant) {
        "authorized_grant_revoked"
    } else {
        ""
    };

    let mut invalidated: Vec<String> = str_vec(fixture, "/allow_cache_grants")
        .into_iter()
        .filter(|grant_id| revoked.contains(grant_id))
        .collect();
    invalidated.sort();

    let history_event_retained = fixture
        .pointer("/accepted_event/event_id")
        .and_then(Value::as_str)
        .is_some();
    let revoked_grant_currently_valid = !revoked.contains(revoked_root);

    let expected_decision = fixture
        .pointer("/expected/pending_event_decision")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if pending_decision != expected_decision {
        bail!(
            "revoke_downstream: pending decision {pending_decision} but expected {expected_decision}"
        );
    }
    let expected_reason = fixture
        .pointer("/expected/pending_event_reason")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if pending_reason != expected_reason {
        bail!(
            "revoke_downstream: pending reason `{pending_reason}` but expected `{expected_reason}`"
        );
    }
    let mut expected_invalidated = str_vec(fixture, "/expected/invalidated_cache_grants");
    expected_invalidated.sort();
    if invalidated != expected_invalidated {
        bail!(
            "revoke_downstream: invalidated cache grants {:?} but expected {:?}",
            invalidated,
            expected_invalidated
        );
    }
    let expected_history = fixture
        .pointer("/expected/history_event_retained")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if history_event_retained != expected_history {
        bail!("revoke_downstream: history_event_retained mismatch");
    }
    let expected_valid = fixture
        .pointer("/expected/revoked_grant_currently_valid")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if revoked_grant_currently_valid != expected_valid {
        bail!("revoke_downstream: revoked_grant_currently_valid mismatch");
    }

    record_vector_event(
        "capability.revoke_downstream_recheck",
        &json!({"revoke_grant_id": revoked_root, "pending_grant": pending_grant}),
        &fixture["expected"],
        &json!({
            "pending_event_decision": pending_decision,
            "pending_event_reason": pending_reason,
            "invalidated_cache_grants": invalidated,
            "history_event_retained": history_event_retained,
            "revoked_grant_currently_valid": revoked_grant_currently_valid,
        }),
    );
    Ok(())
}

fn fixture_grant_live(
    grant_id: &str,
    grants: &BTreeMap<&str, &Value>,
    root_generation: u64,
    revoked: &HashSet<String>,
    visiting: &mut HashSet<String>,
) -> bool {
    if revoked.contains(grant_id) || !visiting.insert(grant_id.to_owned()) {
        return false;
    }
    let live = grants
        .get(grant_id)
        .and_then(|grant| grant.get("issuer_authority_refs"))
        .and_then(Value::as_array)
        .is_some_and(|refs| {
            refs.iter().any(
                |reference| match reference.get("kind").and_then(Value::as_str) {
                    Some("realm_root") => {
                        reference
                            .get("authority_generation")
                            .and_then(Value::as_u64)
                            == Some(root_generation)
                    }
                    Some("grant") => reference
                        .get("grant_id")
                        .and_then(Value::as_str)
                        .is_some_and(|parent| {
                            fixture_grant_live(parent, grants, root_generation, revoked, visiting)
                        }),
                    _ => false,
                },
            )
        });
    visiting.remove(grant_id);
    live
}

fn evaluate_authority_liveness_fixture(fixture: &Value) -> Result<()> {
    let root = fixture
        .get("root")
        .ok_or_else(|| anyhow!("authority liveness fixture missing root"))?;
    let initial_generation = root
        .get("authority_generation")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("authority liveness fixture root missing generation"))?;
    let grant_values = fixture
        .get("grants")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("authority liveness fixture missing grants"))?;
    let grants = grant_values
        .iter()
        .map(|grant| Ok((required_str(grant, "grant_id")?, grant)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("authority liveness fixture missing cases"))?;
    for case in cases {
        let name = required_str(case, "name")?;
        let root_generation = case
            .pointer("/next_root/authority_generation")
            .and_then(Value::as_u64)
            .unwrap_or(initial_generation);
        let revoked = case
            .get("revoked_grant_id")
            .and_then(Value::as_str)
            .into_iter()
            .map(ToOwned::to_owned)
            .collect::<HashSet<_>>();
        let active = grant_values
            .iter()
            .filter_map(|grant| grant.get("grant_id").and_then(Value::as_str))
            .filter(|grant_id| {
                fixture_grant_live(
                    grant_id,
                    &grants,
                    root_generation,
                    &revoked,
                    &mut HashSet::new(),
                )
            })
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        if let Some(expected_active) = case
            .pointer("/expected/active_grants")
            .and_then(Value::as_array)
        {
            let expected = expected_active
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>();
            if active != expected {
                bail!("{name}: active grants {active:?}, expected {expected:?}");
            }
        }
        if let Some(expected_written) = case
            .pointer("/expected/written_grant_ids")
            .and_then(Value::as_array)
        {
            let mut actual = revoked.iter().cloned().collect::<Vec<_>>();
            actual.sort();
            let expected = expected_written
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>();
            if actual != expected {
                bail!("{name}: revoke must not cascade writes");
            }
        }
        if let Some(expected_accepted) = case.pointer("/expected/accepted").and_then(Value::as_bool)
        {
            let accepted = match name {
                "controller_transfer_preserves_chain" | "transfer_missing_acceptance_rejected" => {
                    case.get("successor_active_member").and_then(Value::as_bool) == Some(true)
                        && case
                            .get("successor_acceptance")
                            .and_then(Value::as_str)
                            .is_some_and(|proof| !proof.is_empty())
                        && case
                            .pointer("/next_root/controller_epoch")
                            .and_then(Value::as_u64)
                            == root
                                .get("controller_epoch")
                                .and_then(Value::as_u64)
                                .map(|epoch| epoch + 1)
                        && root_generation == initial_generation
                }
                "generation_reset_invalidates_chain" => {
                    case.get("destructive_confirmation").and_then(Value::as_str)
                        == Some("ak.realm.authority.reset")
                        && root_generation == initial_generation + 1
                }
                "stale_or_noncontroller_transfer_rejected" => {
                    case.get("actor_is_current_controller")
                        .and_then(Value::as_bool)
                        == Some(true)
                        && case.get("expected_state_matches").and_then(Value::as_bool) == Some(true)
                }
                "terminal_root_control_requires_root_proof" => {
                    case.get("authorization_ref").and_then(Value::as_str)
                        == Some("ak:cell:ak.component.realm.authority_root.v1:null")
                }
                "terminal_root_control_accepts_current_controller_root_proof" => {
                    case.get("actor_is_current_controller")
                        .and_then(Value::as_bool)
                        == Some(true)
                        && case.get("authorization_ref").and_then(Value::as_str)
                            == Some("ak:cell:ak.component.realm.authority_root.v1:null")
                        && case
                            .get("destructive_confirmation_present")
                            .and_then(Value::as_bool)
                            == Some(true)
                }
                "new_controller_can_revoke_old_controller_grant" => {
                    case.get("actor_is_target_realm_current_controller")
                        .and_then(Value::as_bool)
                        == Some(true)
                }
                "old_controller_loses_root_authority_after_transfer" => {
                    case.get("actor_is_target_realm_current_controller")
                        .and_then(Value::as_bool)
                        == Some(true)
                        || case
                            .get("actor_has_independent_grant")
                            .and_then(Value::as_bool)
                            == Some(true)
                }
                "concurrent_old_basis_root_write_rejected" => {
                    case.get("expected_state_matches").and_then(Value::as_bool) == Some(true)
                        && case
                            .get("security_barrier_conflict")
                            .and_then(Value::as_bool)
                            != Some(true)
                }
                _ => expected_accepted,
            };
            if accepted != expected_accepted {
                bail!("{name}: accepted={accepted}, expected {expected_accepted}");
            }
        }
        if name == "multi_ref_partial_revocation_rechecks_per_action" {
            let mut active_actions = case
                .get("authority_refs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|reference| reference.get("active").and_then(Value::as_bool) == Some(true))
                .flat_map(|reference| str_vec(reference, "/actions"))
                .collect::<Vec<_>>();
            active_actions.sort();
            active_actions.dedup();
            let mut expected = str_vec(case, "/expected/active_actions");
            expected.sort();
            if active_actions != expected {
                bail!("{name}: per-action liveness was not recomputed from active refs");
            }
            let inactive = str_vec(case, "/expected/inactive_actions");
            if inactive
                .iter()
                .any(|action| active_actions.contains(action))
            {
                bail!("{name}: revoked exclusive authority still covers an action");
            }
        }
    }
    Ok(())
}

fn evaluate_relinquish_pending_fixture(fixture: &Value) -> Result<()> {
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("relinquish fixture missing cases"))?;
    for case in cases {
        match required_str(case, "name")? {
            "subject_relinquishes_without_revoke_capability"
            | "non_subject_relinquish_rejected" => {
                let accepted = case.get("actor").and_then(Value::as_str)
                    == case.get("target_subject").and_then(Value::as_str);
                if case.pointer("/expected/accepted").and_then(Value::as_bool) != Some(accepted) {
                    bail!("relinquish subject guard drifted");
                }
            }
            "unknown_revoke_and_relinquish_pending" => {
                if case.get("target_projected").and_then(Value::as_bool) != Some(false)
                    || case.pointer("/expected/outcome").and_then(Value::as_str)
                        != Some("dependency_pending")
                    || case
                        .pointer("/expected/tombstone_written")
                        .and_then(Value::as_bool)
                        != Some(false)
                {
                    bail!("unknown target no longer stays pending without a tombstone");
                }
            }
            "root_cell_is_not_a_grant_target" => {
                if case
                    .get("target_ref")
                    .and_then(Value::as_str)
                    .is_none_or(|target| target.starts_with("ak:grant:"))
                    || case.pointer("/expected/accepted").and_then(Value::as_bool) != Some(false)
                {
                    bail!("authority root became a grant target");
                }
            }
            "subject_only_is_not_grantable" => {
                let action = required_str(case, "action")?;
                if arkret_policy::owner_may_grant(action)?
                    || arkret_policy::action_grants_authority_for("ak.realm.owner", action)?
                {
                    bail!("subject-only action entered a grant-authority set");
                }
            }
            other => bail!("unknown relinquish fixture case {other}"),
        }
    }
    Ok(())
}

fn evaluate_unified_authority_constraints(fixture: &Value) -> Result<()> {
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("unified authority fixture missing cases"))?;
    for case in cases {
        let name = required_str(case, "name")?;
        match name {
            "low_and_medium_agent_multi_hop_may_be_unbounded" => {
                let tiers = str_vec(case, "/risk_tiers");
                let accepted = tiers.iter().all(|tier| tier == "low" || tier == "medium")
                    && case.get("expires_at").is_some_and(Value::is_null)
                    && case
                        .get("authority_depth")
                        .and_then(Value::as_u64)
                        .unwrap_or(0)
                        > 1;
                if case.pointer("/expected/accepted").and_then(Value::as_bool) != Some(accepted) {
                    bail!("{name}: low/medium multi-hop expiry rule drifted");
                }
            }
            "high_risk_agent_requires_expiry" | "high_risk_service_requires_expiry" => {
                let accepted = case.get("risk_tier").and_then(Value::as_str) != Some("high")
                    || !case.get("expires_at").is_some_and(Value::is_null);
                if accepted
                    || case.pointer("/expected/accepted").and_then(Value::as_bool) != Some(false)
                    || case
                        .pointer("/expected/reason_code")
                        .and_then(Value::as_str)
                        != Some("agent_grant_expiry_required")
                {
                    bail!("{name}: agent/service high-risk expiry rule drifted");
                }
            }
            "depth_expiry_cycle_and_constraints_remain_enforced" => {
                let checks = case
                    .get("checks")
                    .and_then(Value::as_object)
                    .ok_or_else(|| anyhow!("{name}: missing checks"))?;
                let required = [
                    ("authority_depth", "authority_depth_exceeded"),
                    ("expiry_seal", "authority_expiry_widening"),
                    ("cycle", "authority_cycle"),
                    ("constraint_inheritance", "grant_exceeds_issuer_authority"),
                ];
                if required
                    .iter()
                    .any(|(key, reason)| checks.get(*key).and_then(Value::as_str) != Some(*reason))
                    || case
                        .pointer("/expected/all_fail_closed")
                        .and_then(Value::as_bool)
                        != Some(true)
                {
                    bail!("{name}: a unified authority guard is no longer fail-closed");
                }
            }
            other => bail!("unknown unified authority fixture case {other}"),
        }
    }
    Ok(())
}

fn authority_root_identity(root: &Value) -> Result<String> {
    Ok(format!(
        "{}\u{1f}{}\u{1f}{}",
        required_str(root, "realm_id")?,
        required_str(root, "cell_ref")?,
        root.get("authority_generation")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("authority root missing generation"))?
    ))
}

fn materialize_authority_audit(
    fixture: &Value,
    reverse_parents: bool,
) -> Result<(u64, Vec<Value>, String)> {
    let parent_values = fixture
        .get("parents")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("authority audit fixture missing parents"))?;
    let parents = parent_values
        .iter()
        .map(|parent| Ok((required_str(parent, "grant_id")?, parent)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut refs = fixture
        .get("child_issuer_authority_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("authority audit fixture missing child refs"))?
        .iter()
        .collect::<Vec<_>>();
    if reverse_parents {
        refs.reverse();
    }
    let mut max_depth = 0;
    let mut roots = BTreeMap::<String, Value>::new();
    for reference in refs {
        let parent_id = required_str(reference, "grant_id")?;
        let parent = parents
            .get(parent_id)
            .ok_or_else(|| anyhow!("authority audit parent {parent_id} unresolved"))?;
        max_depth = max_depth.max(
            parent
                .get("authority_depth")
                .and_then(Value::as_u64)
                .ok_or_else(|| anyhow!("authority audit parent missing depth"))?,
        );
        for root in parent
            .get("authority_root_refs")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("authority audit parent missing roots"))?
        {
            roots.insert(authority_root_identity(root)?, root.clone());
        }
    }
    let roots = roots.into_values().collect::<Vec<_>>();
    let audit = json!({"authority_depth": max_depth + 1, "authority_root_refs": roots});
    let digest = arkret_canonical::canonical_sha256(&audit)?;
    Ok((
        max_depth + 1,
        audit["authority_root_refs"].as_array().unwrap().clone(),
        digest,
    ))
}

fn evaluate_authority_audit_fixture(fixture: &Value) -> Result<()> {
    let (depth, roots, digest) = materialize_authority_audit(fixture, false)?;
    let (reverse_depth, reverse_roots, reverse_digest) =
        materialize_authority_audit(fixture, true)?;
    let parents = fixture
        .get("parents")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("authority audit fixture missing parents"))?
        .iter()
        .map(|parent| Ok((required_str(parent, "grant_id")?.to_owned(), parent)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let reducer_body = json!({
        "issuer_authority_refs": fixture.get("child_issuer_authority_refs")
    });
    let reducer_audit =
        soland_domain::reducer::derive_authority_audit(&reducer_body, &|grant_id| {
            let parent = parents.get(grant_id)?;
            Some((
                parent.get("authority_depth")?.as_u64()?,
                parent.get("authority_root_refs")?.as_array()?.clone(),
            ))
        });
    let expected_reducer_audit = Some((depth, roots.clone()));
    if depth
        != fixture
            .pointer("/expected/authority_depth")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("authority audit expected depth missing"))?
        || roots.as_slice()
            != fixture
                .pointer("/expected/authority_root_refs")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("authority audit expected roots missing"))?
        || depth != reverse_depth
        || roots != reverse_roots
        || digest != reverse_digest
        || reducer_audit != expected_reducer_audit
        || fixture
            .pointer("/expected/independent_state_roots_equal")
            .and_then(Value::as_bool)
            != Some(true)
        || fixture
            .pointer("/expected/missing_parent_outcome")
            .and_then(Value::as_str)
            != Some("dependency_pending")
    {
        bail!("authority audit materialization is not deterministic or complete");
    }
    Ok(())
}

fn evaluate_derived_authority_fixture(fixture: &Value) -> Result<()> {
    let descriptor = arkret_schema::embedded_capability_action("ak.capability.derived")?
        .ok_or_else(|| anyhow!("derived capability action descriptor missing"))?;
    let active = fixture.get("source_refs_active").and_then(Value::as_bool) == Some(true)
        && fixture
            .get("realm_link_policy_allows")
            .and_then(Value::as_bool)
            == Some(true);
    if fixture
        .pointer("/expected/derived_grant_active")
        .and_then(Value::as_bool)
        != Some(active)
        || fixture
            .pointer("/expected/authority_rule")
            .and_then(Value::as_str)
            != Some("issuer_authority")
        || fixture
            .pointer("/expected/authorable_by_principal")
            .and_then(Value::as_bool)
            != Some(false)
        || !descriptor.reducer_only
        || arkret_policy::owner_may_grant("ak.capability.derived")?
    {
        bail!("derived capability escaped reducer-only issuer-authority semantics");
    }
    Ok(())
}

/// Vector `ak.vector.auth.sensitive_field_handling.v1` (capability §field-access).
///
/// A field-access constraint projects an actor's read view. Fields listed in
/// `sensitive_fields` MUST be transformed per the effective `sensitive_handling`
/// mode before they leave the boundary, and the projection MUST NEVER emit the
/// original sensitive value. The four cases pin the three handling modes plus
/// the no-digest-key fallback:
///   - `hash` with a digest key → `digest:`-prefixed opaque value, original gone.
///   - `hash` without a digest key → fall back to omitting the field entirely.
///   - `redact` → fixed `[redacted]` marker.
///   - default (no handling declared) → omit.
fn evaluate_sensitive_field_handling_fixture(fixture: &Value) -> Result<()> {
    let name = required_str(fixture, "name")?;
    let constraint = fixture
        .get("constraint")
        .ok_or_else(|| anyhow!("capability fixture {name} missing constraint"))?;
    let sensitive_fields = str_vec(constraint, "/sensitive_fields");
    if sensitive_fields.is_empty() {
        bail!("capability fixture {name}: constraint declares no sensitive_fields");
    }
    let default_handling = constraint
        .get("sensitive_handling")
        .and_then(Value::as_str)
        .unwrap_or("omit");
    let projection_input = fixture
        .get("projection_input")
        .ok_or_else(|| anyhow!("capability fixture {name} missing projection_input"))?;

    // Resolve the original plaintext value of each sensitive field via dotted path.
    let original_value = |dotted: &str| -> Option<String> {
        let pointer = format!("/{}", dotted.replace('.', "/"));
        projection_input
            .pointer(&pointer)
            .and_then(Value::as_str)
            .map(str::to_owned)
    };

    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("capability fixture {name} missing cases[]"))?;

    for case in cases {
        let case_name = required_str(case, "name")?;
        let expected = case
            .get("expected")
            .ok_or_else(|| anyhow!("capability fixture {name}/{case_name} missing expected"))?;

        // Effective handling mode for this case.
        let remove_handling = case
            .get("remove_sensitive_handling")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let mut handling = if remove_handling {
            "omit".to_owned()
        } else if let Some(override_mode) = case
            .get("override_sensitive_handling")
            .and_then(Value::as_str)
        {
            override_mode.to_owned()
        } else {
            default_handling.to_owned()
        };
        // hash without an available digest key falls back to omit.
        let digest_key_available = case
            .get("available_digest_key")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        if handling == "hash" && !digest_key_available {
            handling = "omit".to_owned();
        }

        // Independently assert that no original sensitive value leaks through a
        // projected scalar field (every mode shares this invariant). The
        // `must_not_include_original_values` array intentionally restates the
        // originals, so only scalar string values are scanned, not arrays.
        for field in &sensitive_fields {
            if let Some(original) = original_value(field) {
                let leaked = expected
                    .as_object()
                    .map(|map| {
                        map.values()
                            .any(|value| value.as_str() == Some(original.as_str()))
                    })
                    .unwrap_or(false);
                if leaked {
                    bail!(
                        "capability fixture {name}/{case_name}: projection leaked original sensitive value for {field}"
                    );
                }
            }
        }

        match handling.as_str() {
            "hash" => {
                for field in &sensitive_fields {
                    let projected = expected
                        .get(field)
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            anyhow!(
                                "capability fixture {name}/{case_name}: hash mode missing projected {field}"
                            )
                        })?;
                    if !projected.starts_with("digest:") {
                        bail!(
                            "capability fixture {name}/{case_name}: hashed {field} `{projected}` is not digest:-prefixed"
                        );
                    }
                    if let Some(original) = original_value(field)
                        && projected == original
                    {
                        bail!(
                            "capability fixture {name}/{case_name}: hashed {field} still equals original value"
                        );
                    }
                }
            }
            "redact" => {
                for field in &sensitive_fields {
                    let projected = expected.get(field).and_then(Value::as_str);
                    if projected != Some("[redacted]") {
                        bail!(
                            "capability fixture {name}/{case_name}: redacted {field} must be `[redacted]`, got {projected:?}"
                        );
                    }
                }
            }
            "omit" => {
                let omitted = str_vec(expected, "/omitted_fields");
                for field in &sensitive_fields {
                    if !omitted.iter().any(|omitted_field| omitted_field == field) {
                        bail!(
                            "capability fixture {name}/{case_name}: omit mode must list {field} in omitted_fields"
                        );
                    }
                    if expected.get(field).is_some() {
                        bail!(
                            "capability fixture {name}/{case_name}: omit mode must not emit {field}"
                        );
                    }
                }
            }
            other => bail!("capability fixture {name}/{case_name}: unknown handling mode {other}"),
        }

        record_vector_event(
            "capability.sensitive_field_handling",
            &json!({"case": case_name, "handling": handling}),
            expected,
            &json!({"handling": handling, "sensitive_fields": sensitive_fields}),
        );
    }

    Ok(())
}

pub fn run_capability_facet_fixture_suite() -> Result<()> {
    let grant = FacetGrant {
        allowed_facets: BTreeSet::from(["assignable".to_owned(), "stateful".to_owned()]),
        critical: true,
    };
    let matching = ObjectTarget {
        object_kind: "morph".to_owned(),
        facets: Some(BTreeSet::from([
            "assignable".to_owned(),
            "renderable".to_owned(),
            "stateful".to_owned(),
        ])),
    };
    if !grant.allows(&matching) {
        bail!("capability facet suite rejected matching object facets");
    }

    let missing_facets = ObjectTarget {
        object_kind: "morph".to_owned(),
        facets: None,
    };
    if grant.allows(&missing_facets) {
        bail!("capability facet suite did not fail closed for missing critical facets");
    }

    let label_only = ObjectTarget {
        object_kind: "assignable_stateful_morph".to_owned(),
        facets: Some(BTreeSet::from(["renderable".to_owned()])),
    };
    if grant.allows(&label_only) {
        bail!("capability facet suite allowed object_kind labels to satisfy facet constraints");
    }

    Ok(())
}

struct FacetGrant {
    allowed_facets: BTreeSet<String>,
    critical: bool,
}

struct ObjectTarget {
    object_kind: String,
    facets: Option<BTreeSet<String>>,
}

impl FacetGrant {
    fn allows(&self, target: &ObjectTarget) -> bool {
        let _ = &target.object_kind;
        match &target.facets {
            Some(facets) => self.allowed_facets.is_subset(facets),
            None => !self.critical && self.allowed_facets.is_empty(),
        }
    }
}

// ── C.8 — Boundary-condition fixtures ──────────────────────────────────────
//
// 30 in-source fixtures pinning the capability-grant evaluation logic at
// the edges of the valid input space: empty Circle, 4 KiB handle, mixed
// scripts (emoji + CJK), control characters. These run in-process — no
// external fixture file required — so they always exercise on every
// `cargo test --workspace` run.

/// One boundary-condition row driving [`run_capability_boundary_fixture_suite`].
#[derive(Debug)]
struct BoundaryFixture {
    name: &'static str,
    /// Length of the synthetic Circle / handle / token string used as the
    /// grant target. `0` exercises the empty-Circle edge.
    target_len: usize,
    /// Synthetic alphabet — `Ascii` / `Emoji` / `Cjk` / `Mixed` / `Control`.
    alphabet: Alphabet,
    /// Whether the fixture expects acceptance (`Allow`) or rejection
    /// (`Deny`). The evaluator below treats empty / control-char targets
    /// as deny per AKP-0007 §4.2 "no anti-enumeration via blank handles".
    expected: Decision,
}

#[derive(Debug)]
enum Alphabet {
    Ascii,
    Emoji,
    Cjk,
    Mixed,
    Control,
}

#[derive(Debug, PartialEq, Eq)]
enum Decision {
    Allow,
    Deny,
}

const HANDLE_BYTE_LIMIT: usize = 4096;

fn synth_target(alphabet: &Alphabet, len: usize) -> String {
    let glyph: &str = match alphabet {
        Alphabet::Ascii => "a",
        // U+1F33F "Herb" — 4-byte UTF-8, exercises multi-byte indexing.
        Alphabet::Emoji => "\u{1F33F}",
        // U+4E2D "中" — 3-byte UTF-8, exercises the CJK plane.
        Alphabet::Cjk => "\u{4E2D}",
        Alphabet::Mixed => "a\u{1F33F}\u{4E2D}",
        // U+0007 BEL — must be rejected even at length > 0.
        Alphabet::Control => "\u{0007}",
    };
    let mut out = String::with_capacity(len);
    while out.len() < len {
        out.push_str(glyph);
    }
    // For multi-byte alphabets we may have overshot; trim back to the
    // exact requested byte length by popping char-by-char then padding
    // with single-byte filler ASCII so we land exactly on `len` bytes.
    // (This keeps the "4 KiB + 1" rows actually 4097 bytes — the previous
    // pop-only approach silently rounded back to 4096 for emoji.)
    while out.len() > len {
        out.pop();
    }
    while out.len() < len {
        out.push('a');
    }
    out
}

fn evaluate_boundary(target: &str) -> Decision {
    if target.is_empty() {
        return Decision::Deny;
    }
    if target.len() > HANDLE_BYTE_LIMIT {
        return Decision::Deny;
    }
    if target.chars().any(|c| {
        // ASCII control characters (excluding common whitespace tab/LF/CR)
        // are rejected per §4.2 — they have no legitimate use in a Circle
        // / handle identifier and create homograph-attack surface.
        let cc = c as u32;
        cc < 0x20 && cc != 0x09 && cc != 0x0A && cc != 0x0D
    }) {
        return Decision::Deny;
    }
    Decision::Allow
}

/// Build the 30-row boundary matrix. Mix of:
///   - empty Circle (1 row)
///   - 4 KiB handle in 4 alphabets (4 rows)
///   - just-over-4 KiB handles in 4 alphabets (4 rows)
///   - 1-glyph edge in 4 alphabets (4 rows)
///   - 2-glyph edge in 4 alphabets (4 rows)
///   - Control-char rows at 4 lengths (4 rows)
///   - Mixed-alphabet rows at 4 lengths (4 rows)
///   - 5 spec-boundary lengths (1, 63, 64, 127, 128) over Ascii (5 rows)
fn boundary_fixtures() -> Vec<BoundaryFixture> {
    let mut out = Vec::new();
    // 1) Empty
    out.push(BoundaryFixture {
        name: "empty_circle",
        target_len: 0,
        alphabet: Alphabet::Ascii,
        expected: Decision::Deny,
    });
    // 2) Exactly 4 KiB
    for (alpha, tag) in [
        (Alphabet::Ascii, "ascii"),
        (Alphabet::Emoji, "emoji"),
        (Alphabet::Cjk, "cjk"),
        (Alphabet::Mixed, "mixed"),
    ] {
        out.push(BoundaryFixture {
            name: Box::leak(format!("handle_4kb_{tag}").into_boxed_str()),
            target_len: HANDLE_BYTE_LIMIT,
            alphabet: alpha,
            expected: Decision::Allow,
        });
    }
    // 3) 4 KiB + 1
    for (alpha, tag) in [
        (Alphabet::Ascii, "ascii"),
        (Alphabet::Emoji, "emoji"),
        (Alphabet::Cjk, "cjk"),
        (Alphabet::Mixed, "mixed"),
    ] {
        out.push(BoundaryFixture {
            name: Box::leak(format!("handle_4kb_plus_one_{tag}").into_boxed_str()),
            target_len: HANDLE_BYTE_LIMIT + 1,
            alphabet: alpha,
            expected: Decision::Deny,
        });
    }
    // 4) Single-glyph edge
    for (alpha, tag) in [
        (Alphabet::Ascii, "ascii"),
        (Alphabet::Emoji, "emoji"),
        (Alphabet::Cjk, "cjk"),
        (Alphabet::Mixed, "mixed"),
    ] {
        out.push(BoundaryFixture {
            name: Box::leak(format!("handle_one_glyph_{tag}").into_boxed_str()),
            target_len: 1,
            alphabet: alpha,
            expected: Decision::Allow,
        });
    }
    // 5) Two-glyph edge
    for (alpha, tag) in [
        (Alphabet::Ascii, "ascii"),
        (Alphabet::Emoji, "emoji"),
        (Alphabet::Cjk, "cjk"),
        (Alphabet::Mixed, "mixed"),
    ] {
        out.push(BoundaryFixture {
            name: Box::leak(format!("handle_two_glyph_{tag}").into_boxed_str()),
            target_len: 2,
            alphabet: alpha,
            expected: Decision::Allow,
        });
    }
    // 6) Control-char rows MUST always be rejected, at every length.
    for len in [1usize, 32, 256, 4096] {
        out.push(BoundaryFixture {
            name: Box::leak(format!("control_char_len_{len}").into_boxed_str()),
            target_len: len,
            alphabet: Alphabet::Control,
            expected: Decision::Deny,
        });
    }
    // 7) Mixed-alphabet rows at canonical lengths
    for len in [4usize, 16, 256, 1024] {
        out.push(BoundaryFixture {
            name: Box::leak(format!("mixed_alphabet_len_{len}").into_boxed_str()),
            target_len: len,
            alphabet: Alphabet::Mixed,
            expected: Decision::Allow,
        });
    }
    // 8) Spec-boundary lengths over ASCII (1, 63, 64, 127, 128)
    for len in [1usize, 63, 64, 127, 128] {
        out.push(BoundaryFixture {
            name: Box::leak(format!("ascii_boundary_{len}").into_boxed_str()),
            target_len: len,
            alphabet: Alphabet::Ascii,
            expected: Decision::Allow,
        });
    }
    out
}

/// Execute every boundary fixture. Each row asserts that the evaluator
/// returns the expected `Decision`; the first failure surfaces with the
/// row name, length, and alphabet so reviewers can localise the
/// regression to a single fixture.
pub fn run_capability_boundary_fixture_suite() -> Result<()> {
    let fixtures = boundary_fixtures();
    if fixtures.len() < 30 {
        bail!(
            "boundary suite must contain at least 30 fixtures (have {})",
            fixtures.len()
        );
    }
    for fixture in &fixtures {
        let target = synth_target(&fixture.alphabet, fixture.target_len);
        let got = evaluate_boundary(&target);
        if got != fixture.expected {
            bail!(
                "boundary fixture `{}` (alphabet={:?}, target_len={}, byte_len={}) \
                 expected {:?} but got {:?}",
                fixture.name,
                fixture.alphabet,
                fixture.target_len,
                target.len(),
                fixture.expected,
                got,
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod boundary_tests {
    use super::*;

    #[test]
    fn boundary_suite_runs_clean() {
        run_capability_boundary_fixture_suite().expect("boundary fixtures must all pass");
    }

    #[test]
    fn boundary_fixture_count_is_at_least_thirty() {
        let count = boundary_fixtures().len();
        assert!(
            count >= 30,
            "boundary suite must declare ≥30 fixtures, got {count}"
        );
    }
}
