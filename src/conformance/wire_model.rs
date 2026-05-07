//! Phase 4 / Phase 5 wire-model conformance vectors.
//!
//! These vectors live in cotest (under `tests/fixtures/`) rather than in the
//! shared spec artifact tree, because they describe Space-level behavior that
//! cotest verifies structurally — without running a real reducer. Each vector
//! couples a fully-shaped input (event + Space context) with the reducer
//! outcome the spec mandates. The validation is a static consistency check:
//!
//!   * `accept` outcomes for hub Spaces MUST carry exactly one
//!     `host_endorsement` proof whose `host_did` matches the accepted
//!     `space_host`.
//!   * `reject(proof_missing)` outcomes MUST lack a `host_endorsement` proof.
//!   * `reject(host_mismatch)` outcomes MUST carry an endorsement whose
//!     `host_did` is neither the current accepted `space_host` nor (if an
//!     `activation_frontier` is present and the event depends on it) the
//!     `previous_host`.
//!   * `peer_mesh` Space events MUST NOT carry any `host_endorsement` proof.
//!
//! These checks lock the fixtures to spec semantics so the next time the wire
//! model evolves we get a loud failure.
//!
//! Spec references:
//!   * `event-auth-state-resolution.md` §3.3 (Hub Writer Endorsement)
//!   * `event-auth-state-resolution.md` §13 (Host Transfer Ceremony)
//!   * `identity/consent-model.md` (Holder-private consent)

use std::path::PathBuf;

use anyhow::{Result, anyhow, bail};
use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{canonical_json, required_str, validate_profile};

const HOST_ENDORSEMENT: &str = "host_endorsement";

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

fn iter_proofs(event: &Value) -> impl Iterator<Item = &Value> {
    event
        .get("proofs")
        .and_then(Value::as_array)
        .map(|arr| arr.iter())
        .into_iter()
        .flatten()
}

fn host_endorsements(event: &Value) -> Vec<&Value> {
    iter_proofs(event)
        .filter(|p| p.get("kind").and_then(Value::as_str) == Some(HOST_ENDORSEMENT))
        .collect()
}

fn endorsement_did(proof: &Value) -> Option<&str> {
    proof.get("host_did").and_then(Value::as_str)
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

pub fn run_host_endorsement_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("host_endorsement_fixture.json")?;
    validate_profile(&fixture, "cx.profile.host_endorsement_vectors.v1")?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("host_endorsement fixture missing vectors"))?;

    let mut count = 0usize;
    for vector in vectors {
        let name = required_str(vector, "name")?;
        let outcome = expected_outcome(vector, name)?;
        let writer_model = vector
            .pointer("/space/space_writer_model")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("vector {name} missing space.space_writer_model"))?;
        let space_host = vector
            .pointer("/space/space_host")
            .and_then(Value::as_str);
        let previous_host = vector
            .pointer("/space/previous_host")
            .and_then(Value::as_str);

        // Multi-candidate diagnostic vector: hub fork.
        if let Some(candidates) = vector.get("candidates").and_then(Value::as_array) {
            if outcome != "quarantine_slot" {
                bail!("vector {name} has candidates but outcome is not quarantine_slot");
            }
            let reason = expected_reason(vector)
                .ok_or_else(|| anyhow!("quarantine vector {name} missing reason_code"))?;
            if reason != "host_fork_diagnostic" {
                bail!("hub fork diagnostic vector {name} has unexpected reason {reason}");
            }
            // Both candidates must carry a host_endorsement signed by the
            // accepted space_host (this IS the diagnostic signal — host has
            // forked).
            for candidate in candidates {
                let endorsements = host_endorsements(candidate);
                if endorsements.is_empty() {
                    bail!(
                        "vector {name} candidate has no host_endorsement (cannot trigger fork diagnostic)"
                    );
                }
                for proof in endorsements {
                    if endorsement_did(proof) != space_host {
                        bail!(
                            "vector {name} candidate carries non-accepted host_endorsement (would have been rejected before reaching the fork)"
                        );
                    }
                }
            }
            count += 1;
            continue;
        }

        let event = vector
            .get("event")
            .ok_or_else(|| anyhow!("vector {name} missing event"))?;
        let endorsements = host_endorsements(event);

        match (writer_model, outcome) {
            ("hub", "accept") => {
                if endorsements.len() != 1 {
                    bail!(
                        "vector {name} (hub accept) must carry exactly 1 host_endorsement, found {}",
                        endorsements.len()
                    );
                }
                if endorsement_did(endorsements[0]) != space_host {
                    bail!(
                        "vector {name} (hub accept) endorsement.host_did does not match space_host"
                    );
                }
            }
            ("hub", "reject") => {
                let reason = expected_reason(vector)
                    .ok_or_else(|| anyhow!("vector {name} reject missing reason_code"))?;
                match reason {
                    "proof_missing" => {
                        if !endorsements.is_empty() {
                            bail!(
                                "vector {name} reject(proof_missing) but event carries a host_endorsement"
                            );
                        }
                    }
                    "host_mismatch" => {
                        if endorsements.is_empty() {
                            bail!(
                                "vector {name} reject(host_mismatch) requires a non-matching host_endorsement"
                            );
                        }
                        for proof in endorsements {
                            let did = endorsement_did(proof);
                            if did == space_host {
                                bail!(
                                    "vector {name} reject(host_mismatch) but endorsement.host_did matches space_host"
                                );
                            }
                            // After activation_frontier, old host is also valid
                            // EXCEPT for events that depend on the new
                            // frontier — vectors should describe such events.
                            if let Some(prev) = previous_host {
                                let depends = event
                                    .get("depends_on_frontier")
                                    .and_then(Value::as_str);
                                if did == Some(prev) && depends.is_none() {
                                    bail!(
                                        "vector {name} reject(host_mismatch) targets old host but event does not depend on the activation_frontier"
                                    );
                                }
                            }
                        }
                    }
                    other => bail!("vector {name} hub reject unexpected reason {other}"),
                }
            }
            ("peer_mesh", "reject") => {
                if endorsements.is_empty() {
                    bail!(
                        "vector {name} peer_mesh reject must carry a host_endorsement to model the schema_violation case"
                    );
                }
                if expected_reason(vector) != Some("schema_violation") {
                    bail!(
                        "vector {name} peer_mesh reject must use reason_code=schema_violation"
                    );
                }
            }
            (model, out) => {
                bail!("vector {name} unexpected combination writer_model={model} outcome={out}");
            }
        }
        count += 1;
    }
    if count < 6 {
        bail!("host_endorsement fixture must cover at least 6 vectors, got {count}");
    }
    Ok(())
}

pub fn run_host_transfer_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("host_transfer_fixture.json")?;
    validate_profile(&fixture, "cx.profile.host_transfer_vectors.v1")?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("host_transfer fixture missing vectors"))?;

    let mut covered_smooth_accept = false;
    let mut covered_emergency_reject = false;
    let mut covered_post_activation_reject = false;
    let mut covered_standby_warn = false;

    for vector in vectors {
        let name = required_str(vector, "name")?;
        let outcome = expected_outcome(vector, name)?;
        let space_host = vector
            .pointer("/space/space_host")
            .and_then(Value::as_str);

        if let Some(transfer) = vector.get("transfer") {
            let mode = transfer
                .get("mode")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("vector {name} transfer.mode missing"))?;
            let endorsements = host_endorsements(transfer);
            let endorsement_dids: Vec<Option<&str>> =
                endorsements.iter().map(|p| endorsement_did(p)).collect();
            match (mode, outcome) {
                ("smooth", "accept") => {
                    let new_host = transfer.get("new_host").and_then(Value::as_str);
                    if !endorsement_dids.iter().any(|d| *d == space_host) {
                        bail!(
                            "vector {name} smooth accept missing endorsement from current host"
                        );
                    }
                    if !endorsement_dids.iter().any(|d| *d == new_host) {
                        bail!(
                            "vector {name} smooth accept missing endorsement from incoming host"
                        );
                    }
                    let standby = vector
                        .pointer("/space/standby_hosts")
                        .and_then(Value::as_array)
                        .map(|arr| {
                            arr.iter()
                                .filter_map(Value::as_str)
                                .collect::<Vec<&str>>()
                        })
                        .unwrap_or_default();
                    let on_standby = matches!(new_host, Some(nh) if standby.contains(&nh));
                    if !on_standby {
                        let warnings = vector
                            .pointer("/expected/warnings")
                            .and_then(Value::as_array)
                            .ok_or_else(|| {
                                anyhow!(
                                    "vector {name} smooth accept off-standby new_host requires expected.warnings"
                                )
                            })?;
                        let has_warn = warnings.iter().any(|w| {
                            w.as_str() == Some("new_host_outside_standby_hosts")
                        });
                        if !has_warn {
                            bail!(
                                "vector {name} new_host outside standby must emit new_host_outside_standby_hosts"
                            );
                        }
                        covered_standby_warn = true;
                    } else {
                        covered_smooth_accept = true;
                    }
                }
                ("smooth", "reject") => {
                    if expected_reason(vector) != Some("proof_missing") {
                        bail!(
                            "vector {name} smooth reject must use reason_code=proof_missing"
                        );
                    }
                    let new_host = transfer.get("new_host").and_then(Value::as_str);
                    let has_old = endorsement_dids.iter().any(|d| *d == space_host);
                    let has_new = endorsement_dids.iter().any(|d| *d == new_host);
                    if has_old && has_new {
                        bail!(
                            "vector {name} smooth reject(proof_missing) cannot have both endorsements"
                        );
                    }
                }
                ("emergency", "reject") => {
                    if expected_reason(vector) != Some("insufficient_quorum") {
                        bail!(
                            "vector {name} emergency reject must use reason_code=insufficient_quorum"
                        );
                    }
                    let governance = transfer
                        .get("governance_signatures")
                        .and_then(Value::as_array)
                        .map(|a| a.len())
                        .unwrap_or(0);
                    let owners = vector
                        .pointer("/space/owning_organizations")
                        .and_then(Value::as_array)
                        .map(|a| a.len())
                        .unwrap_or(0);
                    let required = owners.div_ceil(2);
                    if governance >= required {
                        bail!(
                            "vector {name} emergency reject claims insufficient_quorum but {governance}>= ceil({owners}/2)={required}"
                        );
                    }
                    covered_emergency_reject = true;
                }
                (mode, out) => {
                    bail!("vector {name} unexpected transfer mode={mode} outcome={out}");
                }
            }
        }

        if let Some(follow_up) = vector.get("follow_up_event") {
            let endorsements = host_endorsements(follow_up);
            if expected_reason(vector) != Some("host_mismatch") {
                bail!("vector {name} follow_up_event must reject(host_mismatch)");
            }
            let prev = vector
                .pointer("/space/previous_host")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("vector {name} follow_up requires previous_host"))?;
            if !endorsements
                .iter()
                .any(|p| endorsement_did(p) == Some(prev))
            {
                bail!(
                    "vector {name} follow_up_event must carry an endorsement from the old host"
                );
            }
            covered_post_activation_reject = true;
        }
    }

    if !(covered_smooth_accept
        && covered_emergency_reject
        && covered_post_activation_reject
        && covered_standby_warn)
    {
        bail!(
            "host_transfer fixture must cover smooth_accept + emergency_reject + post_activation_reject + standby_warn (have smooth_accept={covered_smooth_accept} emergency_reject={covered_emergency_reject} post_activation_reject={covered_post_activation_reject} standby_warn={covered_standby_warn})"
        );
    }
    Ok(())
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

    let kinds = [
        "cx.flow.branch.member",
        "cx.flow.branch.history_visibility",
        "cx.flow.branch.policy_components",
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

    // Build the live component_type set from the spec event-kind registry to
    // catch fixture entries that drift away from the canonical names.
    let event_kind_registry = super::load_artifact_json("registry/event-kind-registry.json")?;
    let mut registered_components = std::collections::BTreeSet::new();
    for entry in event_kind_registry
        .get("event_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event-kind registry missing event_kinds"))?
    {
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
            "mimi component fixture must cover at least 5 Contrix-only components (host, host.transfer, plaintext_visible_services, ...), got {contrix_only}"
        );
    }

    // Phase 4 hub-writer kinds MUST be marked contrix_only (no MIMI equivalent
    // for hub provider transfer ceremonies).
    for required in [
        "cx.component.space.host.v1",
        "cx.component.space.host.transfer.v1",
    ] {
        let entry = component_vectors
            .iter()
            .find(|v| v.get("contrix_component_type").and_then(Value::as_str) == Some(required))
            .ok_or_else(|| anyhow!("mimi component fixture missing host kind {required}"))?;
        if entry.get("direction").and_then(Value::as_str) != Some("contrix_only") {
            bail!("hub writer component {required} must be direction=contrix_only");
        }
    }
    Ok(())
}
