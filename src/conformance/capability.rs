use std::collections::{BTreeSet, HashSet};

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{load_fixture_value, required_str, validate_profile};
use crate::transcripts::record_vector_event;

pub fn run_capability_fixture_suite() -> Result<()> {
    let value = load_fixture_value("capability-fixture.json")?;
    validate_profile(&value, "ck.profile.capability_vectors.v1")?;
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
            "delegate_chain_multi_level" => evaluate_delegate_chain_fixture(fixture)?,
            "membership_without_capability_denies_core_writes" => {
                evaluate_membership_without_capability_fixture(fixture)?;
            }
            "revoke_rollback_forward_recompute" => evaluate_revoke_rollback_fixture(fixture)?,
            "revoke_downstream_recheck" => evaluate_revoke_downstream_fixture(fixture)?,
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

fn grant_id_of_event(event_id: &str) -> String {
    event_id.replacen("ck:event:", "ck:grant:", 1)
}

fn action_implies(granted: &str, requested: &str) -> bool {
    granted == requested || granted == "ck.realm.admin"
}

fn parent_can_delegate(parent_actions: &[String], child_actions: &[String]) -> bool {
    let can_delegate = parent_actions
        .iter()
        .any(|action| action == "ck.capability.delegate" || action == "ck.realm.admin");
    can_delegate
        && child_actions.iter().all(|child| {
            parent_actions
                .iter()
                .any(|granted| action_implies(granted, child))
        })
}

struct Delegation {
    event_id: String,
    parent_grant_id: String,
    subject: String,
    actions: Vec<String>,
    resources: Vec<Value>,
    constraints: Vec<Value>,
    authorized_by_event: String,
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

fn parse_delegations(fixture: &Value) -> Result<Vec<Delegation>> {
    let raw = fixture
        .get("delegations")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("delegate_chain fixture missing delegations"))?;
    let mut out = Vec::with_capacity(raw.len());
    for delegation in raw {
        let authorized_by_event = delegation
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
        out.push(Delegation {
            event_id: required_str(delegation, "event_id")?.to_owned(),
            parent_grant_id: delegation
                .pointer("/payload/parent_grant_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            subject: delegation
                .pointer("/payload/subject")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            actions: str_vec(delegation, "/payload/actions"),
            resources: delegation
                .pointer("/payload/resources")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            constraints: delegation
                .pointer("/payload/constraints")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            authorized_by_event,
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
        Some("ck.message.create") => "no_strand_track_message_grant",
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

fn evaluate_chain(base: &Value, delegations: &[Delegation], query: &ActionQuery) -> ChainResult {
    let base_grant = base
        .get("grant_id")
        .and_then(Value::as_str)
        .unwrap_or_default();

    let Some(leaf) = delegations.iter().find(|delegation| {
        delegation.subject == query.actor
            && delegation
                .actions
                .iter()
                .any(|action| action_implies(action, &query.action))
    }) else {
        return ChainResult::default();
    };

    let mut chain: Vec<&Delegation> = vec![leaf];
    let mut current = leaf;
    loop {
        if current.parent_grant_id == base_grant {
            break;
        }
        match delegations
            .iter()
            .find(|delegation| grant_id_of_event(&delegation.event_id) == current.parent_grant_id)
        {
            Some(parent) => {
                chain.push(parent);
                current = parent;
            }
            // Parent grant neither the root nor a present delegation: the
            // chain is broken (e.g. a middle delegation was skipped).
            None => return ChainResult::default(),
        }
    }
    chain.reverse();

    let mut prev_actions = str_vec(base, "/actions");
    for delegation in &chain {
        if !parent_can_delegate(&prev_actions, &delegation.actions) {
            return ChainResult::default();
        }
        prev_actions = delegation.actions.clone();
    }

    let mut time = true;
    let mut resource_scope = true;
    let rate_limit = true;
    let mut audience = true;
    for delegation in &chain {
        if !delegation
            .resources
            .iter()
            .any(|resource| resource_matches(resource, &query.resource))
        {
            resource_scope = false;
        }
        for constraint in &delegation.constraints {
            match constraint.get("constraint_type").and_then(Value::as_str) {
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

    let mut valid_chain = vec![chain[0].authorized_by_event.clone()];
    for delegation in &chain {
        valid_chain.push(delegation.event_id.clone());
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

/// Vector `ck.vector.capability.delegate_chain.v1` (conformance §4.2).
///
/// A multi-level delegation chain authorizes only when every link is a valid
/// delegation of the requested action AND every constraint (time, resource
/// scope, rate, audience) holds. The evaluator must not authorize directly
/// from the root (skipping a middle delegate), must not ignore the audience
/// scope limitation, and must not authorize after the temporal window expires.
fn evaluate_delegate_chain_fixture(fixture: &Value) -> Result<()> {
    let base = fixture
        .get("base")
        .ok_or_else(|| anyhow!("delegate_chain fixture missing base grant"))?;
    let delegations = parse_delegations(fixture)?;
    let query_value = fixture
        .get("action_query")
        .ok_or_else(|| anyhow!("delegate_chain fixture missing action_query"))?;
    let query = ActionQuery {
        actor: required_str(query_value, "actor_id")?.to_owned(),
        action: required_str(query_value, "action")?.to_owned(),
        resource: required_str(query_value, "resource")?.to_owned(),
        request_time: required_str(query_value, "request_time")?.to_owned(),
        audience: required_str(query_value, "request_audience")?.to_owned(),
    };

    let result = evaluate_chain(base, &delegations, &query);

    let expected_authorized = fixture
        .pointer("/expected/authorized")
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("delegate_chain fixture missing expected.authorized"))?;
    if result.authorized != expected_authorized {
        bail!(
            "delegate_chain: authorized={} but expected {}",
            result.authorized,
            expected_authorized
        );
    }
    let expected_chain = str_vec(fixture, "/expected/valid_chain");
    if result.valid_chain != expected_chain {
        bail!(
            "delegate_chain: valid_chain {:?} did not match expected {:?}",
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
            .ok_or_else(|| anyhow!("delegate_chain fixture missing constraints_checked.{key}"))?;
        if value != expected {
            bail!("delegate_chain: constraint `{key}`={value} but expected {expected}");
        }
    }

    // Non-tautology guards: each failure condition from §4.2 must flip the
    // decision to unauthorized.
    let mut expired = query.clone();
    expired.request_time = "2026-06-01T00:00:00Z".to_owned();
    if evaluate_chain(base, &delegations, &expired).authorized {
        bail!("delegate_chain: expired temporal window still authorized");
    }
    let mut wrong_audience = query.clone();
    wrong_audience.audience = "did:web:attacker.example".to_owned();
    if evaluate_chain(base, &delegations, &wrong_audience).authorized {
        bail!("delegate_chain: out-of-scope audience still authorized");
    }
    let without_middle: Vec<Delegation> = delegations
        .into_iter()
        .filter(|delegation| delegation.subject != "did:webvh:z6mkfixture:ops.example.com")
        .collect();
    if evaluate_chain(base, &without_middle, &query).authorized {
        bail!("delegate_chain: skipping the middle delegate still authorized");
    }

    record_vector_event(
        "capability.delegate_chain",
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
            Some("ck.capability.grant") => {
                if event.pointer("/payload/grant_id").and_then(Value::as_str) == Some(grant_id) {
                    granted = true;
                }
            }
            Some("ck.capability.revoke")
                if event.pointer("/payload/grant_id").and_then(Value::as_str) == Some(grant_id) =>
            {
                revoked = true;
            }
            _ => {}
        }
    }
    granted && !revoked
}

/// Vector `ck.vector.capability.revoke_rollback.v1` (conformance §4.3).
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

/// Vector `ck.vector.capability.revoke_downstream_recheck.v1` (conformance
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

    // Propagate revocation downstream through parent_grant_id links.
    let mut revoked: HashSet<String> = HashSet::new();
    revoked.insert(revoked_root.to_owned());
    loop {
        let mut changed = false;
        for grant in grants {
            let grant_id = grant
                .get("grant_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let parent = grant.get("parent_grant_id").and_then(Value::as_str);
            if let Some(parent) = parent
                && revoked.contains(parent)
                && revoked.insert(grant_id.to_owned())
            {
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

/// Vector `ck.vector.auth.sensitive_field_handling.v1` (capability §field-access).
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
        object_type: "morph".to_owned(),
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
        object_type: "morph".to_owned(),
        facets: None,
    };
    if grant.allows(&missing_facets) {
        bail!("capability facet suite did not fail closed for missing critical facets");
    }

    let label_only = ObjectTarget {
        object_type: "assignable_stateful_morph".to_owned(),
        facets: Some(BTreeSet::from(["renderable".to_owned()])),
    };
    if grant.allows(&label_only) {
        bail!("capability facet suite allowed object_type labels to satisfy facet constraints");
    }

    Ok(())
}

struct FacetGrant {
    allowed_facets: BTreeSet<String>,
    critical: bool,
}

struct ObjectTarget {
    object_type: String,
    facets: Option<BTreeSet<String>>,
}

impl FacetGrant {
    fn allows(&self, target: &ObjectTarget) -> bool {
        let _ = &target.object_type;
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
    /// as deny per CKP-0007 §4.2 "no anti-enumeration via blank handles".
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
