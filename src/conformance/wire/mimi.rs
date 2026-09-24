//! MIMI component and read-receipt-policy wire-model conformance vectors.

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{emit_vector, load_local_fixture};
use crate::conformance::{required_str, validate_profile};

/// W8 — MIMI Room Policy Component round-trip matrix.
///
/// Spec extensions/mimi-interop.md §9.1 defines the Arkret typed result family
/// ↔ MIMI policy-component mapping; §9.2 defines the criticality ↔ MIMI
/// unknown-handling mapping. The test cross-references each result family
/// against the active event-kind registry's result_writes, asserts that
/// bidirectional vectors carry both legs, and asserts that
/// `direction = arkret_only` vectors declare the private facade media-type so
/// the facade cannot silently impersonate a standard MIMI component.
pub fn run_mimi_components_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("mimi_components_fixture.json")?;
    validate_profile(&fixture, "ak.profile.mimi_components_vectors.v1")?;

    // §9.2 criticality round-trip
    let crit_section = fixture
        .get("criticality_mapping")
        .ok_or_else(|| anyhow!("mimi_components fixture missing criticality_mapping"))?;
    let crit_vectors = crit_section
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("criticality_mapping missing vectors"))?;
    let expected_pairs = [
        ("required", "must_understand"),
        ("optional", "should_understand"),
        ("ignore", "silently_drop"),
    ];
    if crit_vectors.len() != expected_pairs.len() {
        bail!(
            "criticality mapping must cover required / optional / ignore (got {} entries)",
            crit_vectors.len()
        );
    }
    for (vector, (arkret, mimi)) in crit_vectors.iter().zip(expected_pairs.iter()) {
        let actual_arkret = required_str(vector, "arkret")?;
        let actual_mimi = required_str(vector, "mimi_unknown_handling")?;
        if actual_arkret != *arkret || actual_mimi != *mimi {
            bail!(
                "criticality mapping drift: expected ({arkret} <-> {mimi}), got ({actual_arkret} <-> {actual_mimi})"
            );
        }
        if vector.get("round_trip").and_then(Value::as_bool) != Some(true) {
            bail!(
                "criticality mapping {arkret} must declare round_trip=true (no information loss)"
            );
        }
    }

    // §9.1 typed result family round-trip
    let component_section = fixture
        .get("component_mapping")
        .ok_or_else(|| anyhow!("mimi_components fixture missing component_mapping"))?;
    let component_vectors = component_section
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("component_mapping missing vectors"))?;

    let registry = crate::conformance::load_artifact_json("registry/event-kind-registry.json")?;
    let registered = registry["event_kinds"]
        .as_array()
        .ok_or_else(|| anyhow!("event-kind registry missing event_kinds[]"))?;
    let mut bidirectional = 0usize;
    let mut arkret_only = 0usize;
    for vector in component_vectors {
        let component_type = required_str(vector, "arkret_result_family")?;
        let event_kind = required_str(vector, "arkret_kind")?;
        let descriptor = arkret_wire::EventKind::try_new(event_kind)
            .and_then(|kind| kind.descriptor())
            .ok_or_else(|| {
                anyhow!("mimi component vector references unknown event kind {event_kind}")
            })?;
        let writes_component = descriptor.reducer_input
            && registered.iter().any(|row| {
                row["event_kind"].as_str() == Some(event_kind)
                    && row["status"].as_str() == Some("active")
                    && row["result_writes"].as_array().is_some_and(|writes| {
                        writes
                            .iter()
                            .any(|write| write["result_family"].as_str() == Some(component_type))
                    })
            });
        if !writes_component {
            bail!(
                "mimi event kind {event_kind} does not write registered result family {component_type}"
            );
        }
        let direction = required_str(vector, "direction")?;
        match direction {
            "bidirectional" => {
                let _ = required_str(vector, "mimi_path")?;
                bidirectional += 1;
            }
            "arkret_only" => {
                let media = required_str(vector, "facade_media_type")?;
                if media != "application/vnd.arkret.component+json" {
                    bail!(
                        "arkret_only component {component_type} must use the application/vnd.arkret.component+json media type, got {media}"
                    );
                }
                if vector.get("mimi_path").is_some() {
                    bail!(
                        "arkret_only component {component_type} declared a mimi_path (cannot have a standard MIMI mapping)"
                    );
                }
                arkret_only += 1;
            }
            other => {
                bail!("mimi component vector {component_type} unknown direction {other}");
            }
        }
        emit_vector(
            "mimi_components.mapping",
            vector,
            json!({"component_type": component_type, "direction": direction}),
        );
    }

    if bidirectional < 4 {
        bail!(
            "mimi component fixture must cover at least 4 bidirectional mappings, got {bidirectional}"
        );
    }
    if arkret_only < 5 {
        bail!(
            "mimi component fixture must cover at least 5 Arkret-only components, got {arkret_only}"
        );
    }

    Ok(())
}
/// Read receipt disclosure policy + per-scope preference vectors.
///
/// Spec: `discovery/read-receipts.md` §2.4-§2.5 and
/// `discovery/client-preferences.md` §3.6. Vectors describe the
/// decision rules that compliant clients MUST honor while Sync Service only
/// enforces the signed outer scope.
/// This suite is structural — it walks every vector, replays the
/// decision against the spec rules, and asserts the recorded
/// `expected.decision` / `expected.is_send` / `expected.is_locked`
/// fields match.
pub fn run_read_receipt_policy_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("read_receipt_policy_fixture.json")?;
    validate_profile(&fixture, "ak.profile.read_receipt_policy_vectors.v1")?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("read_receipt_policy fixture missing vectors[]"))?;
    if vectors.is_empty() {
        bail!("read_receipt_policy fixture has no vectors");
    }

    let mut covered_required = false;
    let mut covered_disabled_client_enforcement = false;
    let mut covered_visibility_private_client_filter = false;
    let mut covered_display_false_local_only = false;
    let mut covered_branch_tighten = false;
    let mut covered_branch_loosen_blocked = false;
    let mut covered_strand_overrides_realm = false;
    let mut covered_realm_overrides_default = false;

    for vector in vectors {
        let name = required_str(vector, "name")?;
        let policy = vector
            .get("policy")
            .ok_or_else(|| anyhow!("vector {name} missing policy"))?;
        let scope = required_str(policy, "scope")?;
        let prefs = vector
            .get("preferences")
            .ok_or_else(|| anyhow!("vector {name} missing preferences"))?;
        let expected = vector
            .get("expected")
            .ok_or_else(|| anyhow!("vector {name} missing expected"))?;

        // Compose effective policy.
        let (eff_disclosure, eff_visibility) = match scope {
            "realm" => {
                let disclosure = required_str(policy, "disclosure")?;
                let visibility = required_str(policy, "visibility")?;
                (disclosure.to_owned(), visibility.to_owned())
            }
            "strand" => {
                // Track-level read-receipt overrides are not in the current v1
                // catalog. A discussion timeline that needs a
                // distinct read-receipt policy MUST be upgraded to an
                // independent Strand/Circle scope (Strand.scope_circle_id, AKP-0007)
                // whose own ak.realm.read_receipt_policy composes against the
                // parent Realm policy via the same tighten-only rules.
                let parent = policy
                    .get("parent")
                    .ok_or_else(|| anyhow!("vector {name} strand missing parent"))?;
                // `child_scope` (not `branch`, which is a forbidden Strand-track
                // wire term) is the Strand/Circle scope read-receipt policy that
                // composes against the parent via tighten-only rules.
                let child_scope = policy
                    .get("child_scope")
                    .ok_or_else(|| anyhow!("vector {name} strand missing child_scope"))?;
                let parent_disclosure = required_str(parent, "disclosure")?;
                let branch_disclosure = required_str(child_scope, "disclosure")?;
                let parent_visibility = required_str(parent, "visibility")?;
                let branch_visibility = required_str(child_scope, "visibility")?;
                let overrides_allowed = parent
                    .get("scope_overrides_allowed")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| {
                        anyhow!("vector {name} parent missing scope_overrides_allowed")
                    })?;
                let child_rejection = child_policy_rejection(
                    parent_disclosure,
                    branch_disclosure,
                    parent_visibility,
                    branch_visibility,
                    overrides_allowed,
                )?;
                if let Some(rejection) = child_rejection {
                    let declared = expected
                        .get("reducer_action")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            anyhow!("vector {name} rejected child policy missing reducer_action")
                        })?;
                    if declared != rejection {
                        bail!(
                            "vector {name} reducer_action: expected {declared}, computed {rejection}"
                        );
                    }
                } else if expected.get("reducer_action").is_some() {
                    bail!("vector {name} declared reducer_action but child policy is valid");
                }
                let composed_disclosure = if child_rejection.is_some() {
                    parent_disclosure.to_owned()
                } else {
                    branch_disclosure.to_owned()
                };
                let composed_visibility = if child_rejection.is_some() {
                    parent_visibility.to_owned()
                } else {
                    branch_visibility.to_owned()
                };
                if let Some(declared) = expected.get("composed_disclosure").and_then(Value::as_str)
                    && declared != composed_disclosure
                {
                    bail!(
                        "vector {name} composed_disclosure: expected {declared}, computed {composed_disclosure}"
                    );
                }
                if let Some(declared) = expected.get("composed_visibility").and_then(Value::as_str)
                    && declared != composed_visibility
                {
                    bail!(
                        "vector {name} composed_visibility: expected {declared}, computed {composed_visibility}"
                    );
                }
                (composed_disclosure, composed_visibility)
            }
            other => bail!("vector {name} unknown scope {other}"),
        };

        // Resolve the user preference for the scope_lookup target.
        let pref_send = resolve_pref_send(vector, prefs)?;
        let pref_display = resolve_pref_display(vector, prefs)?;

        // Compute decision per spec §2.4-§2.5 rules.
        let (decision, is_send, is_locked) = match eff_disclosure.as_str() {
            "required" => ("forced_send", true, true),
            "disabled" => ("forced_skip", false, true),
            "optional" => {
                if pref_send {
                    ("send", true, false)
                } else {
                    ("skip", false, false)
                }
            }
            other => bail!("vector {name} unknown disclosure {other}"),
        };

        let expected_decision = required_str(expected, "decision")?;
        if expected_decision != decision {
            bail!("vector {name} decision: expected {expected_decision}, computed {decision}");
        }
        let expected_is_send = expected
            .get("is_send")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("vector {name} expected.is_send missing"))?;
        if expected_is_send != is_send {
            bail!("vector {name} is_send: expected {expected_is_send}, computed {is_send}");
        }
        let expected_is_locked = expected
            .get("is_locked")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("vector {name} expected.is_locked missing"))?;
        if expected_is_locked != is_locked {
            bail!("vector {name} is_locked: expected {expected_is_locked}, computed {is_locked}");
        }
        if let Some(expected_display) = expected.get("is_display").and_then(Value::as_bool)
            && expected_display != pref_display
        {
            bail!("vector {name} is_display: expected {expected_display}, computed {pref_display}");
        }

        // Signal payload kind and event_id remain encrypted. The service may
        // enforce only signed scope fanout; private receipt filtering happens
        // after decryption on the client.
        if eff_visibility == "private"
            && eff_disclosure != "disabled"
            && (expected.get("sync_service_fanout").and_then(Value::as_str)
                != Some("scope_members")
                || expected
                    .get("client_receive_filter")
                    .and_then(Value::as_str)
                    != Some("referenced_event_sender_only"))
        {
            bail!(
                "vector {name} effective visibility=private must record scope-only service fanout and client sender filtering"
            );
        }
        if eff_disclosure == "disabled"
            && (expected.get("client_generation").and_then(Value::as_str) != Some("forbidden")
                || expected
                    .get("client_receive_action")
                    .and_then(Value::as_str)
                    != Some("drop_without_display")
                || expected.get("sync_service_fanout").and_then(Value::as_str)
                    != Some("scope_members"))
        {
            bail!(
                "vector {name} effective disclosure=disabled must record client generation/drop behavior and opaque scope fanout"
            );
        }

        match name {
            "disclosure_required_locks_client_send" => covered_required = true,
            "disclosure_disabled_is_enforced_by_clients" => {
                covered_disabled_client_enforcement = true
            }
            "visibility_private_filters_after_client_decryption" => {
                covered_visibility_private_client_filter = true
            }
            "display_false_hides_local_indicator_only" => {
                covered_display_false_local_only = true;
                if expected.get("is_display").and_then(Value::as_bool) != Some(false) {
                    bail!("vector {name} must record expected.is_display=false");
                }
                if expected.get("sync_service_fanout").and_then(Value::as_str)
                    != Some("scope_members")
                {
                    bail!("vector {name} must keep Sync Service fanout unchanged");
                }
                if expected.get("unread_action").and_then(Value::as_str) != Some("unchanged") {
                    bail!("vector {name} must keep unread accounting unchanged");
                }
            }
            "branch_overrides_tighten_only" => covered_branch_tighten = true,
            "branch_overrides_loosen_rejected_when_not_allowed" => {
                covered_branch_loosen_blocked = true
            }
            "prefs_resolution_strand_overrides_realm" => covered_strand_overrides_realm = true,
            "prefs_resolution_realm_overrides_default" => covered_realm_overrides_default = true,
            _ => {}
        }
        emit_vector(
            "read_receipt_policy.decision",
            vector,
            json!({
                "name": name,
                "decision": decision,
                "is_send": is_send,
                "is_locked": is_locked,
                "effective_disclosure": eff_disclosure,
                "effective_visibility": eff_visibility,
                "is_display": pref_display,
            }),
        );
    }

    if !(covered_required
        && covered_disabled_client_enforcement
        && covered_visibility_private_client_filter
        && covered_display_false_local_only
        && covered_branch_tighten
        && covered_branch_loosen_blocked
        && covered_strand_overrides_realm
        && covered_realm_overrides_default)
    {
        bail!(
            "read_receipt_policy fixture must cover required-lock / disabled-client-enforcement / private-client-filter / display-false-local-only / branch-tighten / branch-loosen-blocked / strand-overrides-realm / realm-overrides-default"
        );
    }

    Ok(())
}
fn child_policy_rejection(
    parent_disclosure: &str,
    child_disclosure: &str,
    parent_visibility: &str,
    child_visibility: &str,
    overrides_allowed: bool,
) -> Result<Option<&'static str>> {
    validate_disclosure(parent_disclosure)?;
    validate_disclosure(child_disclosure)?;
    let parent_visibility_rank = visibility_rank(parent_visibility)?;
    let child_visibility_rank = visibility_rank(child_visibility)?;
    if !overrides_allowed
        && (parent_disclosure != child_disclosure || parent_visibility != child_visibility)
    {
        return Ok(Some("reject_loosening_strand_scope_move"));
    }
    match (parent_disclosure, child_disclosure) {
        ("required", "required")
        | ("optional", "optional")
        | ("optional", "disabled")
        | ("disabled", "disabled") => {}
        ("required", "optional" | "disabled") => {
            return Ok(Some("reject_loosening_strand_scope_move"));
        }
        _ => return Ok(Some("reject_loosening_strand_scope_move")),
    }
    if child_visibility_rank < parent_visibility_rank {
        return Ok(Some("reject_loosening_strand_scope_move"));
    }
    Ok(None)
}

fn validate_disclosure(value: &str) -> Result<()> {
    let valid = ["required", "optional", "disabled"];
    if !valid.contains(&value) {
        bail!("invalid disclosure {value}");
    }
    Ok(())
}

fn visibility_rank(value: &str) -> Result<i32> {
    match value {
        "public" => Ok(0),
        "members" => Ok(1),
        "private" => Ok(2),
        other => bail!("invalid visibility {other}"),
    }
}
fn resolve_pref_send(vector: &Value, prefs: &Value) -> Result<bool> {
    // Resolution order per spec discovery/client-preferences.md §3.8:
    // strand -> realm -> default. Track-level overrides are not in v1.
    let lookup = vector.get("scope_lookup");
    if let Some(lookup) = lookup
        && let Some(strand_id) = lookup.get("strand_id").and_then(Value::as_str)
        && let Some(strands) = prefs.get("strands").and_then(Value::as_object)
        && let Some(entry) = strands.get(strand_id)
        && let Some(send) = entry.get("send").and_then(Value::as_bool)
    {
        return Ok(send);
    }
    if let Some(lookup) = lookup
        && let Some(realm_id) = lookup.get("realm_id").and_then(Value::as_str)
        && let Some(realms) = prefs.get("realms").and_then(Value::as_object)
        && let Some(entry) = realms.get(realm_id)
        && let Some(send) = entry.get("send").and_then(Value::as_bool)
    {
        return Ok(send);
    }
    Ok(prefs
        .pointer("/default/send")
        .and_then(Value::as_bool)
        .unwrap_or(true))
}

fn resolve_pref_display(vector: &Value, prefs: &Value) -> Result<bool> {
    // Resolution order per spec discovery/client-preferences.md Â§3.8:
    // strand -> realm -> default. Display only gates local rendering.
    let lookup = vector.get("scope_lookup");
    if let Some(lookup) = lookup
        && let Some(strand_id) = lookup.get("strand_id").and_then(Value::as_str)
        && let Some(strands) = prefs.get("strands").and_then(Value::as_object)
        && let Some(entry) = strands.get(strand_id)
        && let Some(display) = entry.get("display").and_then(Value::as_bool)
    {
        return Ok(display);
    }
    if let Some(lookup) = lookup
        && let Some(realm_id) = lookup.get("realm_id").and_then(Value::as_str)
        && let Some(realms) = prefs.get("realms").and_then(Value::as_object)
        && let Some(entry) = realms.get(realm_id)
        && let Some(display) = entry.get("display").and_then(Value::as_bool)
    {
        return Ok(display);
    }
    Ok(prefs
        .pointer("/default/display")
        .and_then(Value::as_bool)
        .unwrap_or(true))
}
