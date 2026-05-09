//! Move/Anchor/Lattice wire-model conformance vectors.
//!
//! These vectors live in cotest (under `tests/fixtures/`) rather than in the
//! shared spec artifact tree, because they describe Space-level behavior that
//! cotest verifies structurally — without running a real reducer / Anchor
//! applier. Each vector couples a fully-shaped input with the outcome the
//! spec mandates. The validation is a static consistency check.
//!
//! Spec references:
//!   * `authz/event-auth-state-resolution.md` (Move / Anchor / Lattice)
//!   * `identity/consent-model.md` (Holder-private consent on consent cell)
//!
//! Pending (root C10.C M2-M5): move_anchor_lattice + anchorer_cell +
//! lattice_round_trip + conflict_repair fixtures.

use std::path::PathBuf;

use anyhow::{Result, anyhow, bail};
use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{canonical_json, required_str, validate_profile};

fn local_fixture_path(file_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(file_name)
}

fn load_local_fixture(file_name: &str) -> Result<Value> {
    let path = local_fixture_path(file_name);
    let raw = std::fs::read_to_string(&path)
        .map_err(|err| anyhow!("read local fixture {}: {err}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|err| anyhow!("parse local fixture {}: {err}", path.display()))
}

fn expected_outcome<'a>(vector: &'a Value, name: &str) -> Result<&'a str> {
    vector
        .pointer("/expected/outcome")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("vector {name} missing expected.outcome"))
}

fn expected_reason<'a>(vector: &'a Value) -> Option<&'a str> {
    vector.pointer("/expected/reason_code").and_then(Value::as_str)
}

pub fn run_consent_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("consent_fixture.json")?;
    validate_profile(&fixture, "cx.profile.consent_vectors.v1")?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("consent fixture missing vectors"))?;

    let mut covered_grant_accept = false;
    let mut covered_revoke_block = false;
    let mut covered_scope_any = false;
    let mut covered_pseudonym = false;
    let mut covered_require_consent = false;

    for vector in vectors {
        let name = required_str(vector, "name")?;
        let events = vector
            .get("events")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("vector {name} missing events"))?;

        // Track active grants: peer/scope -> active state.
        let mut grant_active: std::collections::HashMap<String, bool> = Default::default();
        let mut holder_scope_any: std::collections::HashMap<String, bool> = Default::default();

        for event in events {
            let kind = required_str(event, "kind")?;
            let outcome = expected_outcome(event, name)?;
            match kind {
                "cx.consent.grant" => {
                    if outcome != "accept" {
                        bail!("vector {name} cx.consent.grant must accept");
                    }
                    let payload = event
                        .get("payload")
                        .ok_or_else(|| anyhow!("vector {name} grant missing payload"))?;
                    let actor = required_str(event, "actor_id")?;
                    let peer = payload
                        .get("peer")
                        .and_then(Value::as_str)
                        .ok_or_else(|| anyhow!("vector {name} grant missing peer"))?;
                    let scopes = payload
                        .get("scope")
                        .and_then(Value::as_array)
                        .ok_or_else(|| anyhow!("vector {name} grant missing scope"))?;
                    for scope in scopes {
                        let s = scope
                            .as_str()
                            .ok_or_else(|| anyhow!("vector {name} scope entry not string"))?;
                        if s == "any" {
                            holder_scope_any.insert(format!("{actor}/{peer}"), true);
                        }
                        grant_active.insert(format!("{actor}/{peer}/{s}"), true);
                    }
                    if peer.starts_with("did:cx:psd-") {
                        covered_pseudonym = true;
                    }
                    if scopes.iter().any(|s| s.as_str() == Some("any")) {
                        covered_scope_any = true;
                    }
                }
                "cx.consent.revoke" => {
                    if outcome != "accept" {
                        bail!("vector {name} cx.consent.revoke must accept");
                    }
                    grant_active.values_mut().for_each(|v| *v = false);
                    holder_scope_any.values_mut().for_each(|v| *v = false);
                    covered_revoke_block = true;
                }
                _ => {
                    let constraints = event
                        .get("profile_constraints")
                        .and_then(Value::as_array)
                        .map(|a| {
                            a.iter()
                                .filter_map(Value::as_str)
                                .collect::<Vec<&str>>()
                        })
                        .unwrap_or_default();
                    let lookup = event
                        .get("consent_lookup")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            anyhow!("vector {name} non-consent event missing consent_lookup")
                        })?;
                    let segments: Vec<&str> = lookup.split('/').collect();
                    if segments.len() != 3 {
                        bail!("vector {name} consent_lookup must be holder/peer/scope");
                    }
                    let holder = segments[0];
                    let peer = segments[1];
                    let scope = segments[2];
                    let direct = grant_active
                        .get(&format!("{holder}/{peer}/{scope}"))
                        .copied()
                        .unwrap_or(false);
                    let any = holder_scope_any
                        .get(&format!("{holder}/{peer}"))
                        .copied()
                        .unwrap_or(false);
                    let active = direct || any;
                    let require_consent = constraints.contains(&"require_consent");
                    match outcome {
                        "accept" => {
                            if require_consent && !active {
                                bail!(
                                    "vector {name} event {kind} accepts but no active consent grant for {lookup}"
                                );
                            }
                            if active && require_consent {
                                covered_grant_accept = true;
                            }
                        }
                        "reject" => {
                            if !require_consent {
                                bail!(
                                    "vector {name} event {kind} rejects without require_consent constraint"
                                );
                            }
                            if active {
                                bail!(
                                    "vector {name} event {kind} rejects despite active grant for {lookup}"
                                );
                            }
                            if expected_reason(event) != Some("consent_required") {
                                bail!(
                                    "vector {name} event {kind} reject must use consent_required"
                                );
                            }
                            covered_require_consent = true;
                        }
                        other => bail!("vector {name} event {kind} unexpected outcome {other}"),
                    }
                }
            }
        }
    }
    if !(covered_grant_accept
        && covered_revoke_block
        && covered_scope_any
        && covered_pseudonym
        && covered_require_consent)
    {
        bail!(
            "consent fixture must cover grant_accept + revoke_block + scope_any + pseudonym + require_consent"
        );
    }
    Ok(())
}

fn b64url_nopad(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn compute_state_subject(components_array: &Value) -> Result<String> {
    let cj = canonical_json(components_array)?;
    let digest = Sha256::digest(cj.as_bytes());
    Ok(b64url_nopad(&digest))
}

/// W11 — composite state subject encoding (B4) round-trip.
///
/// Spec §9.5: `state_subject = base64url_nopad(sha256(canonical_json(components_array)))`.
/// Each vector pins its expected canonical JSON form and expected hash so an
/// encoder change is caught loudly.
pub fn run_composite_state_subject_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("composite_state_subject_fixture.json")?;
    validate_profile(&fixture, "cx.profile.composite_state_subject_vectors.v1")?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("composite_state_subject fixture missing vectors"))?;

    // C18 wire-break (spec 2026-05-08): cx.flow.branch.* event kinds renamed
    // to cx.flow.track.*; spec also removed member/history_visibility/
    // policy_components since tracks no longer carry independent membership/
    // visibility/policy. Composite-subject encoding rule is unchanged — kept
    // here as historical-shape vectors (the hash test validates encoding,
    // independent of whether the kind is currently spec-active).
    let kinds = [
        "cx.flow.track.member",
        "cx.flow.track.history_visibility",
        "cx.flow.track.policy_components",
        "cx.device.authorized",
        "cx.device.revoked",
    ];
    let mut covered: std::collections::BTreeSet<&str> = Default::default();

    for vector in vectors {
        let name = required_str(vector, "name")?;
        let kind = required_str(vector, "kind")?;
        if !kinds.contains(&kind) {
            bail!("vector {name} kind {kind} is not a registered composite-subject kind");
        }
        let components = vector
            .get("components_array")
            .ok_or_else(|| anyhow!("vector {name} missing components_array"))?;
        let expected_cj = required_str(vector, "expected_canonical_json")?;
        let actual_cj = canonical_json(components)?;
        if actual_cj != expected_cj {
            bail!(
                "vector {name} canonical_json drift: expected {expected_cj}, got {actual_cj}"
            );
        }
        let expected_subject = required_str(vector, "expected_state_subject")?;
        let actual_subject = compute_state_subject(components)?;
        if actual_subject != expected_subject {
            bail!(
                "vector {name} state_subject drift: expected {expected_subject}, got {actual_subject}"
            );
        }
        covered.insert(kind);
    }

    for kind in kinds {
        if !covered.contains(kind) {
            bail!("composite state subject fixture missing coverage for {kind}");
        }
    }

    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("composite_state_subject fixture missing negative_vectors"))?;
    let mut saw_reorder = false;
    let mut saw_pipe = false;
    for vector in negatives {
        let name = required_str(vector, "name")?;
        let must_differ = required_str(vector, "must_differ_from")?;
        if let Some(components) = vector.get("components_array") {
            let computed = compute_state_subject(components)?;
            if computed == must_differ {
                bail!(
                    "negative vector {name} produced canonical state_subject (would mask reorder bug)"
                );
            }
            saw_reorder = true;
        } else if let Some(pipe) = vector.get("pipe_form").and_then(Value::as_str) {
            // Hash the literal pipe-separated string; it MUST NOT match the
            // canonical hash form.
            let digest = Sha256::digest(pipe.as_bytes());
            if b64url_nopad(&digest) == must_differ {
                bail!(
                    "negative vector {name} pipe-form hash matches canonical state_subject (encoder is using pipe form)"
                );
            }
            saw_pipe = true;
        } else {
            bail!("negative vector {name} requires components_array or pipe_form");
        }
    }
    if !(saw_reorder && saw_pipe) {
        bail!(
            "composite state subject fixture must include both reorder and pipe-form negative vectors"
        );
    }
    Ok(())
}

/// W8 — MIMI Room Policy Component round-trip matrix.
///
/// Spec extensions/mimi-interop.md §9.1 defines the Contrix `component_type`
/// ↔ MIMI policy-component mapping; §9.2 defines the criticality ↔ MIMI
/// unknown-handling mapping. The cotest test cross-references every Contrix
/// component named in the fixture against the active event-kind registry's
/// component_type set, asserts that bidirectional vectors carry both legs
/// (`contrix_component_type` + `mimi_path`), and asserts that
/// `direction = contrix_only` vectors declare the private facade media-type so
/// the facade cannot silently impersonate a standard MIMI component.
pub fn run_mimi_components_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("mimi_components_fixture.json")?;
    validate_profile(&fixture, "cx.profile.mimi_components_vectors.v1")?;

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
    for (vector, (contrix, mimi)) in crit_vectors.iter().zip(expected_pairs.iter()) {
        let actual_contrix = required_str(vector, "contrix")?;
        let actual_mimi = required_str(vector, "mimi_unknown_handling")?;
        if actual_contrix != *contrix || actual_mimi != *mimi {
            bail!(
                "criticality mapping drift: expected ({contrix} <-> {mimi}), got ({actual_contrix} <-> {actual_mimi})"
            );
        }
        if vector.get("round_trip").and_then(Value::as_bool) != Some(true) {
            bail!(
                "criticality mapping {contrix} must declare round_trip=true (no information loss)"
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
    // catch fixture entries that drift away from the canonical names. The
    // Move/Anchor/Lattice rebase (spec 2026-05-08) renamed the registry's
    // per-kind component descriptor from `component_type` to `cell_family`;
    // older fixtures may still call it `contrix_component_type` but the
    // canonical authority is now `cell_family`.
    let event_kind_registry = super::load_artifact_json("registry/event-kind-registry.json")?;
    let mut registered_components = std::collections::BTreeSet::new();
    for entry in event_kind_registry
        .get("event_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event-kind registry missing event_kinds"))?
    {
        if let Some(cell_family) = entry.get("cell_family").and_then(Value::as_str) {
            registered_components.insert(cell_family.to_owned());
        }
        // Back-compat: accept legacy component_type entries if any remain.
        if let Some(component_type) = entry.get("component_type").and_then(Value::as_str) {
            registered_components.insert(component_type.to_owned());
        }
    }

    let mut bidirectional = 0usize;
    let mut contrix_only = 0usize;
    for vector in component_vectors {
        let component_type = required_str(vector, "contrix_component_type")?;
        if !registered_components.contains(component_type) {
            bail!(
                "mimi component vector references unknown component_type {component_type}"
            );
        }
        let direction = required_str(vector, "direction")?;
        match direction {
            "bidirectional" => {
                let _ = required_str(vector, "mimi_path")?;
                bidirectional += 1;
            }
            "contrix_only" => {
                let media = required_str(vector, "facade_media_type")?;
                if media != "application/vnd.contrix.component+json" {
                    bail!(
                        "contrix_only component {component_type} must use the application/vnd.contrix.component+json media type, got {media}"
                    );
                }
                if vector.get("mimi_path").is_some() {
                    bail!(
                        "contrix_only component {component_type} declared a mimi_path (cannot have a standard MIMI mapping)"
                    );
                }
                contrix_only += 1;
            }
            other => {
                bail!(
                    "mimi component vector {component_type} unknown direction {other}"
                );
            }
        }
    }

    if bidirectional < 5 {
        bail!(
            "mimi component fixture must cover at least 5 bidirectional mappings, got {bidirectional}"
        );
    }
    if contrix_only < 5 {
        bail!(
            "mimi component fixture must cover at least 5 Contrix-only components (anchorer, plaintext_visible_services, covered_frontier, ...), got {contrix_only}"
        );
    }

    // Move/Anchor/Lattice rebase (spec 2026-05-08) removed cx.component.space.host*;
    // anchorer cell governs Anchor signing instead. Anchorer-related cell families
    // SHOULD be marked contrix_only (no direct MIMI equivalent for Anchor authority).
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
    validate_profile(&fixture, "cx.profile.read_receipt_policy_vectors.v1")?;
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
    let mut covered_flow_overrides_space = false;
    let mut covered_space_overrides_default = false;

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
            "space" => {
                let disclosure = required_str(policy, "disclosure")?;
                let visibility = required_str(policy, "visibility")?;
                (disclosure.to_owned(), visibility.to_owned())
            }
            "flow_branch" => {
                let parent = policy
                    .get("parent")
                    .ok_or_else(|| anyhow!("vector {name} flow_branch missing parent"))?;
                let branch = policy
                    .get("branch")
                    .ok_or_else(|| anyhow!("vector {name} flow_branch missing branch"))?;
                let parent_disclosure = required_str(parent, "disclosure")?;
                let branch_disclosure = required_str(branch, "disclosure")?;
                let parent_visibility = required_str(parent, "visibility")?;
                let branch_visibility = required_str(branch, "visibility")?;
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
                if let Some(declared) =
                    expected.get("composed_disclosure").and_then(Value::as_str)
                    && declared != composed_disclosure
                {
                    bail!(
                        "vector {name} composed_disclosure: expected {declared}, computed {composed_disclosure}"
                    );
                }
                if let Some(declared) =
                    expected.get("composed_visibility").and_then(Value::as_str)
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
            bail!(
                "vector {name} is_locked: expected {expected_is_locked}, computed {is_locked}"
            );
        }

        // Visibility-private fanout MUST be explicitly recorded so that
        // Sync Service implementations have a vector to check against.
        if eff_visibility == "private"
            && expected.get("sync_service_fanout").and_then(Value::as_str)
                != Some("sender_only")
        {
            bail!(
                "vector {name} effective visibility=private must record sync_service_fanout=sender_only"
            );
        }
        if eff_disclosure == "disabled"
            && expected
                .get("sync_service_action")
                .and_then(Value::as_str)
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
            "prefs_resolution_flow_overrides_space" => covered_flow_overrides_space = true,
            "prefs_resolution_space_overrides_default" => covered_space_overrides_default = true,
            _ => {}
        }
    }

    if !(covered_required
        && covered_disabled
        && covered_visibility_private
        && covered_branch_tighten
        && covered_branch_loosen_blocked
        && covered_flow_overrides_space
        && covered_space_overrides_default)
    {
        bail!(
            "read_receipt_policy fixture must cover required-lock / disabled-drop / private-fanout / branch-tighten / branch-loosen-blocked / flow-overrides-space / space-overrides-default"
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
    let is_tighter =
        matches!((parent, branch), ("optional", "required") | ("optional", "disabled"));
    Ok(if is_tighter || overrides_allowed { branch.to_owned() } else { parent.to_owned() })
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
    let lookup = vector.get("scope_lookup");
    if let Some(lookup) = lookup
        && let Some(flow_id) = lookup.get("flow_id").and_then(Value::as_str)
        && let Some(flows) = prefs.get("flows").and_then(Value::as_object)
        && let Some(entry) = flows.get(flow_id)
        && let Some(send) = entry.get("send").and_then(Value::as_bool)
    {
        return Ok(send);
    }
    if let Some(lookup) = lookup
        && let Some(space_id) = lookup.get("space_id").and_then(Value::as_str)
        && let Some(spaces) = prefs.get("spaces").and_then(Value::as_object)
        && let Some(entry) = spaces.get(space_id)
        && let Some(send) = entry.get("send").and_then(Value::as_bool)
    {
        return Ok(send);
    }
    Ok(prefs
        .pointer("/default/send")
        .and_then(Value::as_bool)
        .unwrap_or(true))
}
