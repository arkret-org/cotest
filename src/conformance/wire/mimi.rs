//! MIMI component and read-receipt-policy wire-model conformance vectors.

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{emit_vector, load_local_fixture};
use crate::conformance::{required_str, validate_profile};

/// W8 — MIMI Room Policy Component round-trip matrix.
///
/// Spec extensions/mimi-interop.md §9.1 defines the Cokret `component_type`
/// ↔ MIMI policy-component mapping; §9.2 defines the criticality ↔ MIMI
/// unknown-handling mapping. The cotest test cross-references every Cokret
/// component named in the fixture against the active event-kind registry's
/// component_type set, asserts that bidirectional vectors carry both legs
/// (`cokret_component_type` + `mimi_path`), and asserts that
/// `direction = cokret_only` vectors declare the private facade media-type so
/// the facade cannot silently impersonate a standard MIMI component.
pub fn run_mimi_components_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("mimi_components_fixture.json")?;
    validate_profile(&fixture, "ck.profile.mimi_components_vectors.v1")?;

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
    for (vector, (cokret, mimi)) in crit_vectors.iter().zip(expected_pairs.iter()) {
        let actual_cokret = required_str(vector, "cokret")?;
        let actual_mimi = required_str(vector, "mimi_unknown_handling")?;
        if actual_cokret != *cokret || actual_mimi != *mimi {
            bail!(
                "criticality mapping drift: expected ({cokret} <-> {mimi}), got ({actual_cokret} <-> {actual_mimi})"
            );
        }
        if vector.get("round_trip").and_then(Value::as_bool) != Some(true) {
            bail!(
                "criticality mapping {cokret} must declare round_trip=true (no information loss)"
            );
        }
    }

    // §9.1 component_type round-trip
    let component_section = fixture
        .get("component_mapping")
        .ok_or_else(|| anyhow!("mimi_components fixture missing component_mapping"))?;
    let component_vectors = component_section
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("component_mapping missing vectors"))?;

    // Build the live cell_family set from the spec event-kind registry to
    // catch fixture entries that drift away from the canonical names.
    let event_kind_registry =
        crate::conformance::load_artifact_json("registry/event-kind-registry.json")?;
    let mut registered_components = std::collections::BTreeSet::new();
    for entry in event_kind_registry
        .get("event_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event-kind registry missing event_kinds"))?
    {
        if let Some(cell_family) = entry.get("cell_family").and_then(Value::as_str) {
            registered_components.insert(cell_family.to_owned());
        }
    }

    let mut bidirectional = 0usize;
    let mut cokret_only = 0usize;
    for vector in component_vectors {
        let component_type = required_str(vector, "cokret_component_type")?;
        if !registered_components.contains(component_type) {
            bail!("mimi component vector references unknown component_type {component_type}");
        }
        let direction = required_str(vector, "direction")?;
        match direction {
            "bidirectional" => {
                let _ = required_str(vector, "mimi_path")?;
                bidirectional += 1;
            }
            "cokret_only" => {
                let media = required_str(vector, "facade_media_type")?;
                if media != "application/vnd.cokret.component+json" {
                    bail!(
                        "cokret_only component {component_type} must use the application/vnd.cokret.component+json media type, got {media}"
                    );
                }
                if vector.get("mimi_path").is_some() {
                    bail!(
                        "cokret_only component {component_type} declared a mimi_path (cannot have a standard MIMI mapping)"
                    );
                }
                cokret_only += 1;
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

    if bidirectional < 5 {
        bail!(
            "mimi component fixture must cover at least 5 bidirectional mappings, got {bidirectional}"
        );
    }
    if cokret_only < 5 {
        bail!(
            "mimi component fixture must cover at least 5 Cokret-only components (anchorer, plaintext_visible_services, covered_frontier, ...), got {cokret_only}"
        );
    }

    // Move/Anchor/Lattice rebase (spec 2026-05-08) removed cx.component.space.host*;
    // anchorer cell governs Anchor signing instead. Anchorer-related cell families
    // SHOULD be marked cokret_only (no direct MIMI equivalent for Anchor authority).
    Ok(())
}
/// Read receipt disclosure policy + per-scope preference vectors.
///
/// Spec: `discovery/read-receipts.md` §2.4-§2.5 and
/// `discovery/client-preferences.md` §3.6. Vectors describe the
/// decision rules that compliant clients and Sync Service MUST honor.
/// This suite is structural — it walks every vector, replays the
/// decision against the spec rules, and asserts the recorded
/// `expected.decision` / `expected.is_send` / `expected.is_locked`
/// fields match.
pub fn run_read_receipt_policy_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("read_receipt_policy_fixture.json")?;
    validate_profile(&fixture, "ck.profile.read_receipt_policy_vectors.v1")?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("read_receipt_policy fixture missing vectors[]"))?;
    if vectors.is_empty() {
        bail!("read_receipt_policy fixture has no vectors");
    }

    let mut covered_required = false;
    let mut covered_disabled = false;
    let mut covered_visibility_private = false;
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
                // Per spec 2026-05-08 (removed-event-kinds.json:
                // cx.strand.track.read_receipt_policy), track-level read-receipt
                // overrides are not in v1. A discussion timeline that needs a
                // distinct read-receipt policy MUST be upgraded to an
                // independent Strand/Circle scope (Strand.scope_circle_id, CKP-0007)
                // whose own ck.realm.read_receipt_policy composes against the
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
                let composed_disclosure =
                    tighten_disclosure(parent_disclosure, branch_disclosure, overrides_allowed)?;
                let composed_visibility =
                    tighten_visibility(parent_visibility, branch_visibility, overrides_allowed)?;
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

        // Visibility-private fanout MUST be explicitly recorded so that
        // Sync Service implementations have a vector to check against.
        if eff_visibility == "private"
            && expected.get("sync_service_fanout").and_then(Value::as_str) != Some("sender_only")
        {
            bail!(
                "vector {name} effective visibility=private must record sync_service_fanout=sender_only"
            );
        }
        if eff_disclosure == "disabled"
            && expected.get("sync_service_action").and_then(Value::as_str)
                != Some("drop_with_policy_violation")
        {
            bail!(
                "vector {name} effective disclosure=disabled must record sync_service_action=drop_with_policy_violation"
            );
        }

        match name {
            "disclosure_required_locks_client_send" => covered_required = true,
            "disclosure_disabled_drops_receipt_at_sync_service" => covered_disabled = true,
            "visibility_private_fanout_only_to_sender" => covered_visibility_private = true,
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
            }),
        );
    }

    if !(covered_required
        && covered_disabled
        && covered_visibility_private
        && covered_branch_tighten
        && covered_branch_loosen_blocked
        && covered_strand_overrides_realm
        && covered_realm_overrides_default)
    {
        bail!(
            "read_receipt_policy fixture must cover required-lock / disabled-drop / private-fanout / branch-tighten / branch-loosen-blocked / strand-overrides-realm / realm-overrides-default"
        );
    }

    Ok(())
}
fn tighten_disclosure(parent: &str, branch: &str, overrides_allowed: bool) -> Result<String> {
    let valid = ["required", "optional", "disabled"];
    if !valid.contains(&parent) {
        bail!("invalid parent disclosure {parent}");
    }
    if !valid.contains(&branch) {
        bail!("invalid branch disclosure {branch}");
    }
    let is_tighter = matches!(
        (parent, branch),
        ("optional", "required") | ("optional", "disabled")
    );
    Ok(if is_tighter || overrides_allowed {
        branch.to_owned()
    } else {
        parent.to_owned()
    })
}
fn tighten_visibility(parent: &str, branch: &str, overrides_allowed: bool) -> Result<String> {
    let rank = |v: &str| -> Result<i32> {
        match v {
            "public" => Ok(2),
            "members" => Ok(1),
            "private" => Ok(0),
            other => bail!("invalid visibility {other}"),
        }
    };
    let parent_rank = rank(parent)?;
    let branch_rank = rank(branch)?;
    Ok(if branch_rank <= parent_rank || overrides_allowed {
        branch.to_owned()
    } else {
        parent.to_owned()
    })
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
