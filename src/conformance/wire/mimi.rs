//! MIMI interop, component, and read-receipt-policy wire-model conformance vectors.

use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{emit_vector, load_local_fixture};
use crate::conformance::{load_fixture_value, required_str, validate_profile};

const MIMI_INTEROP_VECTOR_IDS: &[&str] = &[
    "ck.vector.mimi.provider_directory_draft_pinning.v1",
    "ck.vector.mimi.room_binding_projection.v1",
    "ck.vector.mimi.keypackage_claim_lifecycle.v1",
    "ck.vector.mimi.content_roundtrip.v1",
    "ck.vector.mimi.identifier_query_privacy.v1",
    "ck.vector.mimi.consent_isolation.v1",
    "ck.vector.mimi.proxy_download_policy.v1",
    "ck.vector.mimi.unsupported_draft_fail_closed.v1",
];

/// MIMI Provider Facade artifact vectors.
pub fn run_mimi_interop_fixture_suite() -> Result<()> {
    let fixture = load_fixture_value("mimi-interop-fixture.json")?;
    validate_profile(&fixture, "ck.profile.mimi_interop.v1")?;
    if required_str(&fixture, "suite")? != "mimi_interop" {
        bail!("mimi interop fixture suite drifted");
    }
    if required_str(&fixture, "runner")? != "cotest::conformance::mimi_interop" {
        bail!("mimi interop fixture runner drifted");
    }

    let covers = string_set(&fixture, "covers_vectors")?;
    for vector_id in MIMI_INTEROP_VECTOR_IDS {
        if !covers.contains(vector_id) {
            bail!("mimi interop fixture missing covers_vectors entry {vector_id}");
        }
    }

    let drafts = required_field(&fixture, "drafts")?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("mimi interop fixture missing cases[]"))?;
    let mut seen = BTreeSet::new();
    for case in cases {
        let vector_id = required_str(case, "vector_id")?;
        let name = required_str(case, "name")?;
        seen.insert(vector_id.to_owned());
        match vector_id {
            "ck.vector.mimi.provider_directory_draft_pinning.v1" => {
                validate_provider_directory_case(case, drafts)?
            }
            "ck.vector.mimi.room_binding_projection.v1" => validate_room_binding_case(case)?,
            "ck.vector.mimi.keypackage_claim_lifecycle.v1" => {
                validate_keypackage_claim_case(case)?
            }
            "ck.vector.mimi.content_roundtrip.v1" => validate_content_roundtrip_case(case)?,
            "ck.vector.mimi.identifier_query_privacy.v1" => validate_identifier_query_case(case)?,
            "ck.vector.mimi.consent_isolation.v1" => validate_consent_isolation_case(case)?,
            "ck.vector.mimi.proxy_download_policy.v1" => validate_proxy_download_case(case)?,
            "ck.vector.mimi.unsupported_draft_fail_closed.v1" => {
                validate_unsupported_draft_case(case, drafts)?
            }
            other => bail!("unexpected MIMI interop vector id {other}"),
        }
        emit_vector(
            "mimi_interop.case",
            case,
            json!({"vector_id": vector_id, "name": name}),
        );
    }
    for vector_id in MIMI_INTEROP_VECTOR_IDS {
        if !seen.contains(*vector_id) {
            bail!("mimi interop fixture missing asserted case {vector_id}");
        }
    }
    Ok(())
}

fn validate_provider_directory_case(case: &Value, drafts: &Value) -> Result<()> {
    let input = required_field(case, "input")?;
    if required_str(input, "service_type")? != "mimi_provider_facade" {
        bail!("provider directory must advertise mimi_provider_facade service_type");
    }
    let supported = string_set(input, "supported_profiles")?;
    if !supported.contains("ck.profile.mimi_interop.v1") {
        bail!("provider directory must advertise ck.profile.mimi_interop.v1");
    }
    let mimi = required_field(input, "mimi")?;
    for (field, draft_field) in [
        ("protocol", "protocol_draft"),
        ("content", "content_draft"),
        ("room_policy", "room_policy_draft"),
        ("identifier", "identifier_draft"),
    ] {
        if required_str(mimi, draft_field)? != required_str(drafts, field)? {
            bail!("provider directory draft field {draft_field} drifted");
        }
    }
    let features = string_set(mimi, "features")?;
    for required in [
        "key_material",
        "submit_message",
        "group_info",
        "consent",
        "identifier_query",
        "report_abuse",
        "proxy_download",
    ] {
        if !features.contains(required) {
            bail!("provider directory missing feature {required}");
        }
    }
    require_expected(case, "accepted_only_when_profile_and_pinned_drafts_match")
}

fn validate_room_binding_case(case: &Value) -> Result<()> {
    let input = required_field(case, "input")?;
    if required_str(input, "kind")? != "ck.mimi.room_binding" {
        bail!("room binding case must use ck.mimi.room_binding");
    }
    let payload = required_field(input, "payload")?;
    if required_str(payload, "profile")? != "ck.profile.mimi_interop.v1" {
        bail!("room binding profile drifted");
    }
    if required_str(payload, "status")? != "accepted" {
        bail!("room binding vector must pin accepted status");
    }
    if !required_str(payload, "mimi_room_uri")?.starts_with("mimi://") {
        bail!("room binding must use a MIMI room URI");
    }
    let scope = required_field(payload, "binding_scope")?;
    if !required_str(scope, "realm_id")?.starts_with("ck:realm:") {
        bail!("room binding scope must include realm_id");
    }
    require_expected(case, "mimi_room_is_projection_not_canonical_truth")
}

fn validate_keypackage_claim_case(case: &Value) -> Result<()> {
    let input = required_field(case, "input")?;
    if required_str(input, "operation_id")? != "ck.open.mimi.exchange.request_key_material" {
        bail!("keypackage vector operation id drifted");
    }
    let response = required_field(input, "response")?;
    for field in ["claim_id", "keypackage_ref", "device_binding", "expires_at"] {
        let _ = required_str(response, field)?;
    }
    if response.get("single_use").and_then(Value::as_bool) != Some(true) {
        bail!("keypackage response must be single_use");
    }
    let after_welcome = required_field(input, "after_welcome")?;
    if required_str(after_welcome, "claim_state")? != "consumed" {
        bail!("keypackage claim must be consumed after Welcome");
    }
    let failure_shape = required_field(input, "failure_shape")?;
    for field in ["policy_denied", "no_available_device", "target_not_visible"] {
        if required_str(failure_shape, field)? != "not_found_equivalent" {
            bail!("keypackage failure shape {field} must be enumeration-safe");
        }
    }
    require_expected(
        case,
        "single_use_keypackage_claim_consumed_after_welcome_and_failure_shape_is_enumeration_safe",
    )
}

fn validate_content_roundtrip_case(case: &Value) -> Result<()> {
    let input = required_field(case, "input")?;
    if required_str(input, "target_format")? != "ck.message.create" {
        bail!("content roundtrip target format drifted");
    }
    if !required_str(input, "source_format")?.contains("GFM-MIMI") {
        bail!("content roundtrip must pin the MIMI markdown variant");
    }
    let digest = required_str(input, "original_envelope_digest")?;
    if !digest.starts_with("sha256:") || digest.len() != "sha256:".len() + 64 {
        bail!("content roundtrip must carry a sha256 original envelope digest");
    }
    require_expected(case, "mapped_event_preserves_original_envelope_digest_and_mimi_message_id")
}

fn validate_identifier_query_case(case: &Value) -> Result<()> {
    let input = required_field(case, "input")?;
    if required_str(input, "privacy_mode")? != "private_contact_discovery" {
        bail!("identifier query must use private contact discovery");
    }
    require_expected(
        case,
        "returns_psi_match_bits_and_invite_handoff_without_exposing_contact_graph",
    )
}

fn validate_consent_isolation_case(case: &Value) -> Result<()> {
    let input = required_field(case, "input")?;
    if required_str(input, "consent_state")? != "accepted" {
        bail!("consent isolation vector must start from accepted consent");
    }
    require_expected(case, "consent_does_not_grant_space_read_or_write_capability")
}

fn validate_proxy_download_case(case: &Value) -> Result<()> {
    let input = required_field(case, "input")?;
    if required_str(input, "asset_privacy_policy")? != "provider_proxy" {
        bail!("proxy download vector must pin provider_proxy asset policy");
    }
    require_expected(case, "direct_object_store_url_is_not_returned")
}

fn validate_unsupported_draft_case(case: &Value, drafts: &Value) -> Result<()> {
    let input = required_field(case, "input")?;
    if required_str(input, "protocol_draft")? == required_str(drafts, "protocol")? {
        bail!("unsupported draft vector must not use the pinned protocol draft");
    }
    require_expected(case, "reject_or_negotiate_new_profile_without_mutating_reducer_profile")
}

fn require_expected(case: &Value, expected: &str) -> Result<()> {
    let actual = required_str(case, "expected")?;
    if actual != expected {
        bail!("MIMI interop expected outcome drifted: expected {expected}, got {actual}");
    }
    Ok(())
}

fn required_field<'a>(value: &'a Value, field: &str) -> Result<&'a Value> {
    value
        .get(field)
        .ok_or_else(|| anyhow!("missing object field {field}"))
}

fn string_set<'a>(value: &'a Value, field: &str) -> Result<BTreeSet<&'a str>> {
    Ok(value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("missing array field {field}"))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .ok_or_else(|| anyhow!("{field} entry must be string"))
        })
        .collect::<Result<BTreeSet<_>>>()?)
}

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
                let child_rejection = child_policy_rejection(
                    parent_disclosure,
                    branch_disclosure,
                    parent_visibility,
                    branch_visibility,
                    overrides_allowed,
                    parent
                        .get("allow_child_privacy_tightening_against_required")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
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

        // Visibility-private fanout MUST be explicitly recorded so that
        // Sync Service implementations have a vector to check against.
        if eff_visibility == "private"
            && eff_disclosure != "disabled"
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
            "display_false_hides_local_indicator_only" => {
                covered_display_false_local_only = true;
                if expected.get("is_display").and_then(Value::as_bool) != Some(false) {
                    bail!("vector {name} must record expected.is_display=false");
                }
                if expected.get("sync_service_fanout").and_then(Value::as_str) != Some("members") {
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
        && covered_disabled
        && covered_visibility_private
        && covered_display_false_local_only
        && covered_branch_tighten
        && covered_branch_loosen_blocked
        && covered_strand_overrides_realm
        && covered_realm_overrides_default)
    {
        bail!(
            "read_receipt_policy fixture must cover required-lock / disabled-drop / private-fanout / display-false-local-only / branch-tighten / branch-loosen-blocked / strand-overrides-realm / realm-overrides-default"
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
    allow_required_privacy_tightening: bool,
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
        ("required", "optional" | "disabled") if allow_required_privacy_tightening => {}
        ("required", "optional" | "disabled") => {
            return Ok(Some("read_receipt_compliance_floor_violated"));
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
