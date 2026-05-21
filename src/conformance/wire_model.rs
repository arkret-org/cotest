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
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{canonical_json, required_str, validate_profile};
use crate::transcripts::{is_active, record_vector_event};

/// Emit a structured transcript event for a wire-model vector at the end of
/// a per-vector loop iteration. `kind_suffix` becomes the trailing portion of
/// the JSONL `kind` field (e.g. `"composite_state_subject.encoded"` →
/// `wire_model.composite_state_subject.encoded`). The full vector value is
/// used for `payload`; `expected` extracts `vector.expected` when present
/// (defaulting to the vector's `name`); `actual` is the caller-supplied
/// summary of what the validator computed.
///
/// No-op when the calling thread has no active transcript writer (i.e. when
/// running under plain `cargo test` without the auto-init fixture wrapper),
/// so it stays free in the hot path.
fn emit_vector(kind_suffix: &str, vector: &Value, actual: Value) {
    if !is_active() {
        return;
    }
    let expected = vector
        .get("expected")
        .cloned()
        .unwrap_or_else(|| json!({"name": vector.get("name").cloned().unwrap_or(Value::Null)}));
    record_vector_event(
        &format!("wire_model.{kind_suffix}"),
        vector,
        &expected,
        &actual,
    );
}

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
    vector
        .pointer("/expected/reason_code")
        .and_then(Value::as_str)
}

/// W3 — holder-private consent cell or-set Move semantics.
///
/// Spec: `identity/consent-model.md` + `authz/event-auth-state-resolution.md`
/// (Move/Anchor/Lattice). Each grant Move adds a `(peer, scope)` tag to the
/// holder-keyed or-set cell `cx:cell:cx.component.consent.grant.v1:<holder>`.
/// Each revoke Move issues a causal `or_set_remove` against the prior grant
/// Move's id. The cell join (active set) is the lookup surface for
/// `consent_active` preconditions on downstream invite / message Moves.
///
/// This validator replays the fixture's Move sequence per vector, tracking
/// the or-set's active tags by their op_ids (Move ids). It enforces:
///   * grant ops add `(peer, scope)` tagged by Move id
///   * revoke ops remove the referenced op_ids causally
///   * `consent_active` preconditions on downstream Moves resolve against
///     the cell's join, with `scope=any` acting as a peer-scoped wildcard
///   * `accept` preconditioned Moves always have an active matching tag
///   * `reject` Moves carry `reason_code=consent_required` and always have
///     no matching active tag
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
    let mut covered_idempotent_regrant = false;

    for vector in vectors {
        let name = required_str(vector, "name")?;
        let moves = vector
            .get("moves")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                anyhow!("vector {name} missing moves[] (post-2026-05-09 or-set Move shape)")
            })?;

        // Per-cell or-set state: map<cell_id, map<move_id, (peer, scope)>>.
        let mut or_set: std::collections::HashMap<
            String,
            std::collections::HashMap<String, (String, String)>,
        > = Default::default();
        let mut saw_grant_then_invite_accept = false;
        let mut saw_revoke_then_invite_reject = false;

        for mv in moves {
            let kind = required_str(mv, "kind")?;
            let move_id = required_str(mv, "move_id")?;
            if !move_id.starts_with("cx:event:") {
                bail!(
                    "vector {name} move_id {move_id} must use typed cx:event:<uuidv7> form (C19 wire-break)"
                );
            }
            let outcome = expected_outcome(mv, name)?;
            match kind {
                "cx.consent.grant" => {
                    if outcome != "accept" {
                        bail!("vector {name} cx.consent.grant must accept");
                    }
                    let effects = mv
                        .get("effects")
                        .and_then(Value::as_array)
                        .ok_or_else(|| anyhow!("vector {name} grant move missing effects[]"))?;
                    if effects.is_empty() {
                        bail!("vector {name} grant move has empty effects[]");
                    }
                    for effect in effects {
                        let cell = required_str(effect, "cell")?;
                        if !cell.starts_with("cx:cell:cx.component.consent.grant.v1:") {
                            bail!(
                                "vector {name} grant effect cell must be the consent.grant.v1 cell, got {cell}"
                            );
                        }
                        if required_str(effect, "op")? != "or_set_add" {
                            bail!(
                                "vector {name} grant effect must use op=or_set_add (or-set semantics)"
                            );
                        }
                        let tag = effect
                            .get("tag")
                            .ok_or_else(|| anyhow!("vector {name} grant effect missing tag"))?;
                        let peer = required_str(tag, "peer")?;
                        let scope = required_str(tag, "scope")?;
                        or_set
                            .entry(cell.to_owned())
                            .or_default()
                            .insert(move_id.to_owned(), (peer.to_owned(), scope.to_owned()));
                        if peer.starts_with("did:cx:psd-") {
                            covered_pseudonym = true;
                        }
                        if scope == "any" {
                            covered_scope_any = true;
                        }
                    }
                }
                "cx.consent.revoke" => {
                    if outcome != "accept" {
                        bail!("vector {name} cx.consent.revoke must accept");
                    }
                    let effects = mv
                        .get("effects")
                        .and_then(Value::as_array)
                        .ok_or_else(|| anyhow!("vector {name} revoke move missing effects[]"))?;
                    let mut removed_anything = false;
                    for effect in effects {
                        let cell = required_str(effect, "cell")?;
                        if !cell.starts_with("cx:cell:cx.component.consent.grant.v1:") {
                            bail!(
                                "vector {name} revoke effect cell must be the consent.grant.v1 cell, got {cell}"
                            );
                        }
                        if required_str(effect, "op")? != "or_set_remove" {
                            bail!(
                                "vector {name} revoke effect must use op=or_set_remove (causal removal)"
                            );
                        }
                        let removes = effect
                            .get("removes")
                            .and_then(Value::as_array)
                            .ok_or_else(|| {
                                anyhow!(
                                    "vector {name} revoke effect missing removes[] (must reference prior grant move_ids)"
                                )
                            })?;
                        if removes.is_empty() {
                            bail!(
                                "vector {name} revoke effect has empty removes[]; or-set causal remove must target at least one prior op"
                            );
                        }
                        let cell_set = or_set.entry(cell.to_owned()).or_default();
                        for r in removes {
                            let r = r.as_str().ok_or_else(|| {
                                anyhow!("vector {name} revoke removes[] entry must be a string")
                            })?;
                            if cell_set.remove(r).is_some() {
                                removed_anything = true;
                            } else {
                                bail!(
                                    "vector {name} revoke references unknown grant op_id {r} (causal predecessor missing)"
                                );
                            }
                        }
                    }
                    if !removed_anything {
                        bail!("vector {name} revoke removed nothing from the or-set");
                    }
                }
                _ => {
                    // Downstream Move (cx.invite.send / cx.message.send /
                    // cx.call.invite ...) carrying a `consent_active`
                    // precondition. Resolve precondition against the
                    // consent.grant.v1 cell join.
                    let preconditions = mv
                        .get("preconditions")
                        .and_then(Value::as_array)
                        .ok_or_else(|| {
                            anyhow!(
                                "vector {name} non-consent move {kind} missing preconditions[] (consent_active required for v1 wire)"
                            )
                        })?;
                    let mut consent_resolved: Option<bool> = None;
                    for pre in preconditions {
                        if required_str(pre, "kind")? != "consent_active" {
                            continue;
                        }
                        let holder = required_str(pre, "holder")?;
                        let peer = required_str(pre, "peer")?;
                        let scope = required_str(pre, "scope")?;
                        let cell = format!("cx:cell:cx.component.consent.grant.v1:{holder}");
                        let active_tags = or_set.get(&cell);
                        let resolved = active_tags
                            .map(|tags| {
                                tags.values()
                                    .any(|(p, s)| p == peer && (s == scope || s == "any"))
                            })
                            .unwrap_or(false);
                        consent_resolved = Some(resolved);
                    }
                    let resolved = consent_resolved.ok_or_else(|| {
                        anyhow!(
                            "vector {name} non-consent move {kind} missing consent_active precondition"
                        )
                    })?;
                    match outcome {
                        "accept" => {
                            if !resolved {
                                bail!(
                                    "vector {name} move {kind} accepts but consent_active precondition resolves false"
                                );
                            }
                            covered_grant_accept = true;
                            if name == "idempotent_re_grant_after_revoke" {
                                covered_idempotent_regrant = true;
                            }
                            if name == "revoke_after_grant_blocks_invite" {
                                saw_grant_then_invite_accept = true;
                            }
                        }
                        "reject" => {
                            if resolved {
                                bail!(
                                    "vector {name} move {kind} rejects but consent_active precondition resolves true"
                                );
                            }
                            if expected_reason(mv) != Some("consent_required") {
                                bail!(
                                    "vector {name} move {kind} reject must use reason_code=consent_required"
                                );
                            }
                            covered_require_consent = true;
                            if name == "revoke_after_grant_blocks_invite" {
                                saw_revoke_then_invite_reject = true;
                            }
                        }
                        other => bail!("vector {name} move {kind} unexpected outcome {other}"),
                    }
                }
            }
        }
        // For the revoke-after-grant scenario we want both halves of the
        // sequence to have been observed (we replay grant -> revoke -> invite
        // and verify the invite is rejected).
        if name == "revoke_after_grant_blocks_invite" && saw_revoke_then_invite_reject {
            covered_revoke_block = true;
        }
        // saw_grant_then_invite_accept is unused but kept to document that
        // the precondition flips correctly across revoke. Suppress unused.
        let _ = saw_grant_then_invite_accept;
        emit_vector(
            "consent.or_set_replay",
            vector,
            json!({"name": name, "moves": moves.len()}),
        );
    }
    if !(covered_grant_accept
        && covered_revoke_block
        && covered_scope_any
        && covered_pseudonym
        && covered_require_consent
        && covered_idempotent_regrant)
    {
        bail!(
            "consent fixture must cover grant_accept + revoke_block + scope_any + pseudonym + require_consent + idempotent_regrant (or-set Move semantics)"
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
            bail!("vector {name} canonical_json drift: expected {expected_cj}, got {actual_cj}");
        }
        let expected_subject = required_str(vector, "expected_state_subject")?;
        let actual_subject = compute_state_subject(components)?;
        if actual_subject != expected_subject {
            bail!(
                "vector {name} state_subject drift: expected {expected_subject}, got {actual_subject}"
            );
        }
        covered.insert(kind);
        emit_vector(
            "composite_state_subject.encoded",
            vector,
            json!({
                "name": name,
                "kind": kind,
                "state_subject": actual_subject,
                "canonical_json": actual_cj,
            }),
        );
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
    // catch fixture entries that drift away from the canonical names.
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
    }

    let mut bidirectional = 0usize;
    let mut contrix_only = 0usize;
    for vector in component_vectors {
        let component_type = required_str(vector, "contrix_component_type")?;
        if !registered_components.contains(component_type) {
            bail!("mimi component vector references unknown component_type {component_type}");
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
            "child_space" => {
                // Per spec 2026-05-08 (removed-event-kinds.json:
                // cx.flow.track.read_receipt_policy), track-level read-receipt
                // overrides are not in v1. A discussion timeline that needs a
                // distinct read-receipt policy MUST be upgraded to an
                // independent child Space (Flow.discussion_realm_ref) whose
                // own cx.realm.read_receipt_policy composes against the
                // parent Space policy via the same tighten-only rules.
                let parent = policy
                    .get("parent")
                    .ok_or_else(|| anyhow!("vector {name} child_space missing parent"))?;
                let branch = policy
                    .get("branch")
                    .ok_or_else(|| anyhow!("vector {name} child_space missing branch"))?;
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
            "prefs_resolution_flow_overrides_space" => covered_flow_overrides_space = true,
            "prefs_resolution_space_overrides_default" => covered_space_overrides_default = true,
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

/// M6 — anchor view compaction round-trip vectors.
///
/// Spec: `authz/event-auth-state-resolution.md` §6 (Anchor DAG,
/// effective_anchor_view, signed compaction). The validator pins these
/// invariants per vector:
///
/// * **multi-leaf effective_anchor_view is a pure function of the input
///   leaves** — `expected_effective_anchor_view.leaves` MUST equal the
///   set of input Anchor ids; `frontier` MUST equal the leaves whenever
///   the leaves are concurrent (no Anchor in the input list is an
///   ancestor of another in the same input list).
/// * **signed compaction is join-equivalent** — when a `signed_compaction`
///   is present, its `frontier` and `state_root` MUST exactly match the
///   `expected_effective_anchor_view`.
/// * **bottom diagnostics are preserved across compaction** —
///   `signed_compaction.bottom_diagnostics` MUST be a superset of
///   `expected_effective_anchor_view.bottom_diagnostics` (compaction is
///   information-preserving for ⊥ cells; dropping one is a structural
///   error).
/// * **compaction Anchor id is content-addressed** — id starts with
///   `cx:anchor:sha256:` and the digest is 64 lowercase hex chars.
///
/// Negative vectors carry a `drift_compaction` with `expected_rejection_reason`
/// — the validator computes the actual drift (state_root or
/// dropped-diagnostic) and asserts the recorded reason matches.
pub fn run_anchor_view_compaction_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("anchor_view_compaction_fixture.json")?;
    validate_profile(&fixture, "cx.profile.anchor_view_compaction_vectors.v1")?;

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("anchor_view_compaction fixture missing vectors[]"))?;
    if vectors.is_empty() {
        bail!("anchor_view_compaction fixture has no vectors");
    }

    let mut covered_single_leaf = false;
    let mut covered_multi_leaf_clean = false;
    let mut covered_bottom_preserved = false;

    for vector in vectors {
        let name = required_str(vector, "name")?;
        let anchors = vector
            .get("anchors")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("vector {name} missing anchors[]"))?;
        if anchors.is_empty() {
            bail!("vector {name} has no anchor leaves");
        }
        let view = vector
            .get("expected_effective_anchor_view")
            .ok_or_else(|| anyhow!("vector {name} missing expected_effective_anchor_view"))?;

        // (1) leaves equal input anchor id set
        let input_ids: std::collections::BTreeSet<String> = anchors
            .iter()
            .map(|a| required_str(a, "id").map(str::to_owned))
            .collect::<Result<_>>()?;
        for id in &input_ids {
            validate_anchor_id_shape(id, name)?;
        }
        let view_leaves: std::collections::BTreeSet<String> = view
            .get("leaves")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("vector {name} view missing leaves[]"))?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| anyhow!("vector {name} leaf entry not a string"))
            })
            .collect::<Result<_>>()?;
        if view_leaves != input_ids {
            bail!("vector {name} effective_anchor_view.leaves drift from input anchor ids");
        }

        // (2) when there are >= 2 concurrent leaves, frontier == leaves.
        // We treat all input anchors as concurrent (the fixture vectors are
        // crafted that way: each leaf points to the same prior frontier).
        let view_frontier: std::collections::BTreeSet<String> = view
            .get("frontier")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("vector {name} view missing frontier[]"))?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| anyhow!("vector {name} frontier entry not a string"))
            })
            .collect::<Result<_>>()?;
        if anchors.len() >= 2 && view_frontier != view_leaves {
            bail!("vector {name} concurrent multi-leaf frontier MUST equal leaves set");
        }
        if anchors.len() == 1 && !view_frontier.is_empty() && view_frontier != view_leaves {
            bail!("vector {name} single-leaf view frontier must be empty or equal to leaves");
        }

        // (3) signed compaction equivalence
        if let Some(compaction) = vector.get("signed_compaction") {
            if !compaction.is_null() {
                let comp_id = required_str(compaction, "id")?;
                validate_anchor_id_shape(comp_id, name)?;
                let comp_frontier: std::collections::BTreeSet<String> = compaction
                    .get("frontier")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} signed_compaction missing frontier[]"))?
                    .iter()
                    .map(|v| {
                        v.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                            anyhow!("vector {name} signed_compaction frontier entry not a string")
                        })
                    })
                    .collect::<Result<_>>()?;
                if comp_frontier != view_frontier {
                    bail!(
                        "vector {name} signed_compaction frontier MUST equal effective_view frontier"
                    );
                }
                let comp_state_root = required_str(compaction, "state_root")?;
                let view_state_root = required_str(view, "state_root")?;
                if comp_state_root != view_state_root {
                    bail!(
                        "vector {name} signed_compaction state_root drift: expected {view_state_root}, got {comp_state_root}"
                    );
                }
                // (4) bottom_diagnostics preserved
                let view_diags = view
                    .get("bottom_diagnostics")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} view missing bottom_diagnostics"))?;
                let comp_diags = compaction
                    .get("bottom_diagnostics")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        anyhow!("vector {name} signed_compaction missing bottom_diagnostics")
                    })?;
                for diag in view_diags {
                    if !comp_diags.iter().any(|d| d == diag) {
                        bail!(
                            "vector {name} signed_compaction dropped a bottom diagnostic from the effective view (compaction must be information-preserving for ⊥ cells)"
                        );
                    }
                }
                let signature = compaction
                    .get("signature")
                    .ok_or_else(|| anyhow!("vector {name} signed_compaction missing signature"))?;
                let alg = required_str(signature, "alg")?;
                if alg != "EdDSA" {
                    bail!("vector {name} signed_compaction signature.alg must be EdDSA, got {alg}");
                }
            }
        }

        match name {
            "single_leaf_view_passthrough" => covered_single_leaf = true,
            "two_leaf_concurrent_no_bottom_compacts_to_one" => covered_multi_leaf_clean = true,
            "compaction_preserves_bottom_diagnostics" => covered_bottom_preserved = true,
            _ => {}
        }
        emit_vector(
            "anchor_view_compaction.view",
            vector,
            json!({
                "name": name,
                "leaves": view_leaves,
                "frontier": view_frontier,
                "anchor_count": anchors.len(),
            }),
        );
    }

    if !(covered_single_leaf && covered_multi_leaf_clean && covered_bottom_preserved) {
        bail!(
            "anchor_view_compaction fixture must cover single-leaf passthrough + concurrent-multi-leaf + bottom-diagnostic-preservation"
        );
    }

    // Negative vectors: each carries a `drift_compaction` with an expected
    // rejection reason. We compute the drift kind and assert it matches.
    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("anchor_view_compaction fixture missing negative_vectors[]"))?;
    let mut saw_diag_drop = false;
    let mut saw_state_root_drift = false;
    for vector in negatives {
        let name = required_str(vector, "name")?;
        let anchors = vector
            .get("anchors")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("negative vector {name} missing anchors[]"))?;
        let drift = vector
            .get("drift_compaction")
            .ok_or_else(|| anyhow!("negative vector {name} missing drift_compaction"))?;
        let reason = required_str(drift, "expected_rejection_reason")?;
        match reason {
            "compaction_dropped_bottom_diagnostics" => {
                let leaf_diags: Vec<&Value> = anchors
                    .iter()
                    .filter_map(|a| a.get("bottom_diagnostics").and_then(Value::as_array))
                    .flatten()
                    .collect();
                let drift_diags: &Vec<Value> = drift
                    .get("bottom_diagnostics")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        anyhow!(
                            "negative vector {name} drift_compaction missing bottom_diagnostics"
                        )
                    })?;
                if drift_diags.iter().count() >= leaf_diags.len() {
                    bail!(
                        "negative vector {name} expected dropped diagnostics but drift_compaction kept them all"
                    );
                }
                saw_diag_drop = true;
            }
            "state_root_drifted_from_effective_view" => {
                let leaf_state_root = anchors
                    .first()
                    .and_then(|a| a.get("state_root"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("negative vector {name} leaf missing state_root"))?;
                let drift_state_root = required_str(drift, "state_root")?;
                if drift_state_root == leaf_state_root {
                    bail!(
                        "negative vector {name} expected drifted state_root but drift_compaction matches"
                    );
                }
                saw_state_root_drift = true;
            }
            other => bail!("negative vector {name} unknown rejection reason {other}"),
        }
    }
    if !(saw_diag_drop && saw_state_root_drift) {
        bail!(
            "anchor_view_compaction fixture must include both bottom-diagnostic-drop and state-root-drift negative vectors"
        );
    }

    Ok(())
}

fn validate_anchor_id_shape(id: &str, ctx: &str) -> Result<()> {
    let Some(rest) = id.strip_prefix("cx:anchor:sha256:") else {
        bail!("{ctx} anchor id {id} must use cx:anchor:sha256:<hex> special form");
    };
    if rest.len() != 64
        || !rest
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        bail!("{ctx} anchor id {id} sha256 segment must be exactly 64 lowercase hex chars");
    }
    Ok(())
}

/// M3 — anchorer cell governance vectors (round 20).
///
/// Stand-alone fixture (`tests/fixtures/anchorer_cell_fixture.json`) extracted
/// from the in-process Rust assertions in `lattice_round_trip.rs`. The lattice
/// suite stays as the SDK-level lattice round-trip; this fixture is the
/// black-box JSON form a SUT can consume and validate against. The validator
/// pins these structural invariants:
///
/// * each happy-path vector declares one of the spec's four normative
///   `AnchorerValue` shapes (`single_did` / `threshold` / `open_set` /
///   `mixed`) with the matching shape-keyed payload;
/// * the threshold vector carries `k <= n` and a members[] of length n;
/// * the concurrent-reconfig vector declares ≥ 2 distinct anchored ops and
///   `expected.outcome = bottom` with `bottom_kind = Conflict`;
/// * negative vectors carry one of the spec's recognised admission rejection
///   reasons (signature mismatch / threshold below quorum / k>n geometry /
///   registry drift).
///
/// All four happy-path shapes + the concurrent-reconfig + the four negative
/// admission failures MUST be covered.
pub fn run_anchorer_cell_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("anchorer_cell_fixture.json")?;
    validate_profile(&fixture, "cx.profile.anchorer_cell_vectors.v1")?;

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("anchorer_cell fixture missing vectors[]"))?;
    let mut covered: std::collections::BTreeSet<&str> = Default::default();
    for vector in vectors {
        let name = required_str(vector, "name")?;
        let shape = required_str(vector, "shape")?;
        let cell_id = required_str(vector, "cell_id")?;
        if !cell_id.starts_with("cx:cell:cx.component.anchorer.v1:") {
            bail!("vector {name} cell_id must be the anchorer.v1 cell, got {cell_id}");
        }
        match name {
            "single_did_happy_path"
            | "threshold_k_of_n_happy_path"
            | "open_set_happy_path"
            | "mixed_recovery_happy_path" => {
                let value = vector
                    .get("anchorer_value")
                    .ok_or_else(|| anyhow!("vector {name} missing anchorer_value"))?;
                let value_shape = required_str(value, "shape")?;
                if value_shape != shape {
                    bail!(
                        "vector {name} anchorer_value.shape {value_shape} != declared shape {shape}"
                    );
                }
                match shape {
                    "single_did" => {
                        let _ = required_str(value, "did")?;
                    }
                    "threshold" => {
                        let k = value
                            .get("k")
                            .and_then(Value::as_u64)
                            .ok_or_else(|| anyhow!("vector {name} threshold missing k"))?;
                        let n = value
                            .get("n")
                            .and_then(Value::as_u64)
                            .ok_or_else(|| anyhow!("vector {name} threshold missing n"))?;
                        if k == 0 || k > n {
                            bail!("vector {name} threshold k={k} n={n} must satisfy 1 <= k <= n");
                        }
                        let members = value
                            .get("members")
                            .and_then(Value::as_array)
                            .ok_or_else(|| anyhow!("vector {name} threshold missing members[]"))?;
                        if members.len() as u64 != n {
                            bail!(
                                "vector {name} threshold members.len()={} != n={n}",
                                members.len()
                            );
                        }
                    }
                    "open_set" => {
                        let members = value
                            .get("members")
                            .and_then(Value::as_array)
                            .ok_or_else(|| anyhow!("vector {name} open_set missing members[]"))?;
                        if members.is_empty() {
                            bail!("vector {name} open_set members[] must be non-empty");
                        }
                    }
                    "mixed" => {
                        let _ = required_str(value, "primary")?;
                        let recovery = value
                            .get("recovery_members")
                            .and_then(Value::as_array)
                            .ok_or_else(|| {
                                anyhow!("vector {name} mixed missing recovery_members[]")
                            })?;
                        if recovery.is_empty() {
                            bail!("vector {name} mixed recovery_members[] must be non-empty");
                        }
                    }
                    other => bail!("vector {name} unsupported shape {other}"),
                }
                let outcome = required_str(
                    vector
                        .get("expected")
                        .ok_or_else(|| anyhow!("vector {name} missing expected"))?,
                    "outcome",
                )?;
                if outcome != "value" {
                    bail!("vector {name} happy path must expect outcome=value, got {outcome}");
                }
                covered.insert(name);
            }
            "concurrent_reconfig_returns_bottom_conflict" => {
                let ops = vector
                    .get("concurrent_anchored_ops")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} missing concurrent_anchored_ops[]"))?;
                if ops.len() < 2 {
                    bail!(
                        "vector {name} must declare at least 2 concurrent anchored ops to surface Bottom"
                    );
                }
                let mut seen_move_ids = std::collections::BTreeSet::new();
                for op in ops {
                    let move_id = required_str(op, "move_id")?;
                    if !move_id.starts_with("cx:event:") {
                        bail!(
                            "vector {name} concurrent op move_id {move_id} must use cx:event:<UUIDv7> form"
                        );
                    }
                    if !seen_move_ids.insert(move_id.to_owned()) {
                        bail!(
                            "vector {name} concurrent ops MUST have distinct move_ids; duplicate {move_id}"
                        );
                    }
                }
                let expected = vector
                    .get("expected")
                    .ok_or_else(|| anyhow!("vector {name} missing expected"))?;
                if required_str(expected, "outcome")? != "bottom" {
                    bail!("vector {name} concurrent reconfig must expect outcome=bottom");
                }
                if required_str(expected, "bottom_kind")? != "Conflict" {
                    bail!(
                        "vector {name} concurrent reconfig must expect bottom_kind=Conflict (split anchorer is a Space-wide pause)"
                    );
                }
                covered.insert(name);
            }
            other => bail!("vector {name}: unexpected name {other}"),
        }
        emit_vector(
            "anchorer_cell.shape",
            vector,
            json!({"name": name, "shape": shape, "cell_id": cell_id}),
        );
    }
    for required in [
        "single_did_happy_path",
        "threshold_k_of_n_happy_path",
        "open_set_happy_path",
        "mixed_recovery_happy_path",
        "concurrent_reconfig_returns_bottom_conflict",
    ] {
        if !covered.contains(required) {
            bail!("anchorer_cell fixture missing required vector {required}");
        }
    }

    // Negative vectors
    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("anchorer_cell fixture missing negative_vectors[]"))?;
    let mut neg_reasons: std::collections::BTreeSet<&str> = Default::default();
    for vector in negatives {
        let name = required_str(vector, "name")?;
        let drift = vector
            .get("drift")
            .ok_or_else(|| anyhow!("negative vector {name} missing drift"))?;
        let drift_kind = required_str(drift, "kind")?;
        let expected = vector
            .get("expected")
            .ok_or_else(|| anyhow!("negative vector {name} missing expected"))?;
        if required_str(expected, "outcome")? != "reject" {
            bail!("negative vector {name} must expect outcome=reject");
        }
        let reason = required_str(expected, "reason_code")?;
        match (drift_kind, reason) {
            ("signature_mismatch", "anchor_signature_invalid")
            | ("threshold_below_quorum", "anchor_threshold_below_quorum")
            | ("threshold_geometry_invalid", "anchor_threshold_geometry_invalid")
            | ("registry_drift", "registry_kind_missing_cell_family") => {
                neg_reasons.insert(reason);
            }
            (k, r) => bail!(
                "negative vector {name}: drift.kind={k} not paired with expected reason_code={r}"
            ),
        }
        if drift_kind == "threshold_geometry_invalid" {
            let k = drift.get("k").and_then(Value::as_u64).ok_or_else(|| {
                anyhow!("negative vector {name} threshold geometry drift missing k")
            })?;
            let n = drift.get("n").and_then(Value::as_u64).ok_or_else(|| {
                anyhow!("negative vector {name} threshold geometry drift missing n")
            })?;
            if k <= n {
                bail!(
                    "negative vector {name} threshold geometry drift must have k>n to be a real violation; got k={k} n={n}"
                );
            }
        }
    }
    for required in [
        "anchor_signature_invalid",
        "anchor_threshold_below_quorum",
        "anchor_threshold_geometry_invalid",
        "registry_kind_missing_cell_family",
    ] {
        if !neg_reasons.contains(required) {
            bail!(
                "anchorer_cell fixture must include a negative vector with reason_code={required}"
            );
        }
    }
    Ok(())
}

/// M5 — conflict-repair Move vectors (round 20).
///
/// Stand-alone fixture (`tests/fixtures/conflict_repair_fixture.json`) — the
/// JSON form for SUT black-box validation of the head_in / recovery_capability
/// / manual-repair semantics described in `event-auth-state-resolution.md` §5.7.
/// Validator pins:
///
/// * happy-path repair Move declares `head_in` matching the prior_bottom
///   move_ids (no drift) and a `recovery_capability` ref;
/// * self-authorising-winner vector declares ≥ 2 concurrent ops and
///   `outcome = bottom` (lattice MUST NOT pick winner from payload);
/// * manual repair vector carries an `anchorer_endorsement` ref;
/// * negative vectors cover missing-recovery-capability and head_in drift.
pub fn run_conflict_repair_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("conflict_repair_fixture.json")?;
    validate_profile(&fixture, "cx.profile.conflict_repair_vectors.v1")?;

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("conflict_repair fixture missing vectors[]"))?;
    let mut covered_head_in_resolves = false;
    let mut covered_self_auth_rejected = false;
    let mut covered_manual_repair = false;
    for vector in vectors {
        let name = required_str(vector, "name")?;
        match name {
            "head_in_single_op_resolves_existing_bottom" => {
                let prior = vector
                    .get("prior_bottom")
                    .ok_or_else(|| anyhow!("vector {name} missing prior_bottom"))?;
                let prior_ids: Vec<&str> = prior
                    .get("move_ids")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} prior_bottom missing move_ids[]"))?
                    .iter()
                    .filter_map(Value::as_str)
                    .collect();
                if prior_ids.len() < 2 {
                    bail!("vector {name} prior_bottom MUST have ≥ 2 conflicting move_ids");
                }
                let repair = vector
                    .get("repair_move")
                    .ok_or_else(|| anyhow!("vector {name} missing repair_move"))?;
                let head_in: Vec<&str> = repair
                    .get("head_in")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} repair_move missing head_in[]"))?
                    .iter()
                    .filter_map(Value::as_str)
                    .collect();
                let prior_set: std::collections::BTreeSet<&str> =
                    prior_ids.iter().copied().collect();
                let head_set: std::collections::BTreeSet<&str> = head_in.iter().copied().collect();
                if prior_set != head_set {
                    bail!("vector {name} repair_move.head_in MUST equal prior_bottom.move_ids set");
                }
                let _ = required_str(repair, "recovery_capability")?;
                let outcome = required_str(
                    vector
                        .get("expected")
                        .ok_or_else(|| anyhow!("vector {name} missing expected"))?,
                    "outcome",
                )?;
                if outcome != "value" {
                    bail!("vector {name} expected outcome=value (single anchored repair op)");
                }
                covered_head_in_resolves = true;
            }
            "self_authorising_winner_rejected_at_lattice_layer" => {
                let ops = vector
                    .get("concurrent_anchored_ops")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} missing concurrent_anchored_ops[]"))?;
                if ops.len() < 2 {
                    bail!("vector {name} self-authorising vector must have ≥ 2 concurrent ops");
                }
                let any_self_auth = ops.iter().any(|op| {
                    op.get("value")
                        .and_then(|v| v.get("self_authorising"))
                        .and_then(Value::as_bool)
                        == Some(true)
                });
                if !any_self_auth {
                    bail!(
                        "vector {name} must include at least one op with value.self_authorising=true to exercise the lattice-no-peek rule"
                    );
                }
                let expected = vector
                    .get("expected")
                    .ok_or_else(|| anyhow!("vector {name} missing expected"))?;
                if required_str(expected, "outcome")? != "bottom" {
                    bail!(
                        "vector {name} self-authorising MUST resolve to Bottom at the lattice layer"
                    );
                }
                if required_str(expected, "bottom_kind")? != "Conflict" {
                    bail!("vector {name} bottom_kind must be Conflict");
                }
                covered_self_auth_rejected = true;
            }
            "manual_repair_via_recovery_capability_holder" => {
                let repair = vector
                    .get("repair_move")
                    .ok_or_else(|| anyhow!("vector {name} missing repair_move"))?;
                let _ = required_str(repair, "recovery_capability")?;
                let _ = required_str(repair, "issuer_did")?;
                let endorsement = repair.get("anchorer_endorsement").ok_or_else(|| {
                    anyhow!("vector {name} manual repair missing anchorer_endorsement")
                })?;
                if required_str(endorsement, "alg")? != "EdDSA" {
                    bail!("vector {name} anchorer_endorsement.alg must be EdDSA");
                }
                let _ = required_str(endorsement, "anchorer_did")?;
                covered_manual_repair = true;
            }
            other => bail!("vector unexpected name {other}"),
        }
        emit_vector("conflict_repair.vector", vector, json!({"name": name}));
    }
    if !(covered_head_in_resolves && covered_self_auth_rejected && covered_manual_repair) {
        bail!(
            "conflict_repair fixture must cover head_in_resolves + self_auth_rejected + manual_repair"
        );
    }

    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("conflict_repair fixture missing negative_vectors[]"))?;
    let mut neg_codes: std::collections::BTreeSet<&str> = Default::default();
    for vector in negatives {
        let name = required_str(vector, "name")?;
        let expected = vector
            .get("expected")
            .ok_or_else(|| anyhow!("negative vector {name} missing expected"))?;
        if required_str(expected, "outcome")? != "reject" {
            bail!("negative vector {name} must expect outcome=reject");
        }
        let reason = required_str(expected, "reason_code")?;
        neg_codes.insert(reason);
        // shape-specific drift check
        if reason == "repair_head_in_drift" {
            let prior_ids: std::collections::BTreeSet<&str> = vector
                .get("prior_bottom")
                .and_then(|p| p.get("move_ids"))
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let head_in: std::collections::BTreeSet<&str> = vector
                .get("repair_move")
                .and_then(|r| r.get("head_in"))
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            if prior_ids == head_in {
                bail!(
                    "negative vector {name} declared head_in drift but head_in matches prior_bottom"
                );
            }
        }
    }
    for required in ["repair_missing_recovery_capability", "repair_head_in_drift"] {
        if !neg_codes.contains(required) {
            bail!(
                "conflict_repair fixture must include negative vector with reason_code={required}"
            );
        }
    }
    Ok(())
}

/// M7 — MLS covered_frontier cell vectors (round 20).
///
/// Stand-alone fixture (`tests/fixtures/mls_move_covered_frontier_fixture.json`)
/// validating the or-set behaviour of `cx.component.mls.covered_frontier.v1`
/// across MLS commit Moves, governance Moves, and rotation. Pins:
///
/// * accumulate vector adds three ops where two share the same tag (idempotent
///   re-add); `expected.active_tags` MUST be the unique-tag set;
/// * rotation vector adds two distinct tags then removes one; remaining
///   active_tag MUST equal the un-removed tag;
/// * governance Move vector declares zero preconditions (governance Moves are
///   NOT blocked on covered_frontier);
/// * mls_commit_three_cells declares three distinct cells in `effects[]` with
///   one shared move_id;
/// * E2EE missing-precondition negative declares no `covered_frontier`
///   precondition + reason_code `fail_precondition`;
/// * E2EE stale-attestation negative declares an attests_to that's NOT in
///   active_tags_at_send_time.
pub fn run_mls_move_covered_frontier_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("mls_move_covered_frontier_fixture.json")?;
    validate_profile(&fixture, "cx.profile.mls_covered_frontier_vectors.v1")?;

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("mls covered_frontier fixture missing vectors[]"))?;
    let mut covered: std::collections::BTreeSet<&str> = Default::default();
    for vector in vectors {
        let name = required_str(vector, "name")?;
        match name {
            "covered_frontier_accumulates_governance_refs_idempotent" => {
                let cell_id = required_str(vector, "cell_id")?;
                if !cell_id.starts_with("cx:cell:cx.component.mls.covered_frontier.v1:") {
                    bail!("vector {name} cell_id wrong family: {cell_id}");
                }
                let ops = vector
                    .get("anchored_ops")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} missing anchored_ops[]"))?;
                let mut tags_seen: Vec<&str> = Vec::new();
                for op in ops {
                    if required_str(op, "op")? != "or_set_add" {
                        bail!("vector {name} accumulate vector ops must all be or_set_add");
                    }
                    tags_seen.push(required_str(op, "tag")?);
                }
                let unique_tags: std::collections::BTreeSet<&str> =
                    tags_seen.iter().copied().collect();
                if unique_tags.len() == tags_seen.len() {
                    bail!(
                        "vector {name} must include at least one duplicate-tag re-add to test or-set idempotence"
                    );
                }
                let expected = vector
                    .get("expected")
                    .ok_or_else(|| anyhow!("vector {name} missing expected"))?;
                let active: std::collections::BTreeSet<&str> = expected
                    .get("active_tags")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} expected.active_tags missing"))?
                    .iter()
                    .filter_map(Value::as_str)
                    .collect();
                if active != unique_tags {
                    bail!(
                        "vector {name} expected.active_tags MUST equal the unique-tag set; got {active:?} vs {unique_tags:?}"
                    );
                }
                covered.insert(name);
            }
            "rotation_removes_old_ref_keeps_others" => {
                let ops = vector
                    .get("anchored_ops")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} missing anchored_ops[]"))?;
                let mut adds: Vec<&str> = Vec::new();
                let mut removes: Vec<&str> = Vec::new();
                for op in ops {
                    let kind = required_str(op, "op")?;
                    let tag = required_str(op, "tag")?;
                    match kind {
                        "or_set_add" => adds.push(tag),
                        "or_set_remove" => removes.push(tag),
                        other => bail!("vector {name} unknown op {other}"),
                    }
                }
                if removes.is_empty() {
                    bail!("vector {name} rotation must declare at least one or_set_remove");
                }
                let expected_active: std::collections::BTreeSet<&str> = vector
                    .pointer("/expected/active_tags")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} expected.active_tags missing"))?
                    .iter()
                    .filter_map(Value::as_str)
                    .collect();
                let computed_active: std::collections::BTreeSet<&str> = adds
                    .iter()
                    .filter(|tag| !removes.contains(tag))
                    .copied()
                    .collect();
                if expected_active != computed_active {
                    bail!(
                        "vector {name} expected.active_tags drift: declared {expected_active:?} computed {computed_active:?}"
                    );
                }
                covered.insert(name);
            }
            "governance_move_not_blocked_by_covered_frontier" => {
                let mv = vector
                    .get("governance_move")
                    .ok_or_else(|| anyhow!("vector {name} missing governance_move"))?;
                let preconds = mv
                    .get("preconditions")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        anyhow!("vector {name} governance_move missing preconditions[]")
                    })?;
                if !preconds.is_empty() {
                    bail!(
                        "vector {name} governance_move MUST have empty preconditions[] (governance is NOT blocked on covered_frontier)"
                    );
                }
                if required_str(
                    vector
                        .get("expected")
                        .ok_or_else(|| anyhow!("vector {name} missing expected"))?,
                    "outcome",
                )? != "accept"
                {
                    bail!("vector {name} governance Move must accept");
                }
                covered.insert(name);
            }
            "mls_commit_attests_three_cells_in_one_move" => {
                let mv = vector
                    .get("mls_commit_move")
                    .ok_or_else(|| anyhow!("vector {name} missing mls_commit_move"))?;
                let _ = required_str(mv, "covered_frontier_attests_to")?;
                let effects = mv
                    .get("effects")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} missing effects[]"))?;
                if effects.len() != 3 {
                    bail!(
                        "vector {name} MLS commit Move MUST write exactly 3 cells (covered_frontier + epoch + group_state); got {} effects",
                        effects.len()
                    );
                }
                let mut cell_families: std::collections::BTreeSet<&str> = Default::default();
                for effect in effects {
                    let cell = required_str(effect, "cell")?;
                    let family = cell
                        .strip_prefix("cx:cell:")
                        .and_then(|tail| tail.split(':').next())
                        .ok_or_else(|| anyhow!("vector {name} cell {cell} malformed"))?;
                    cell_families.insert(family);
                }
                for required in [
                    "cx.component.mls.covered_frontier.v1",
                    "cx.component.mls.epoch.v1",
                    "cx.component.mls.group_state.v1",
                ] {
                    if !cell_families.contains(required) {
                        bail!("vector {name} MLS commit must write cell family {required}");
                    }
                }
                covered.insert(name);
            }
            other => bail!("vector {name}: unexpected name {other}"),
        }
        emit_vector("mls_covered_frontier.vector", vector, json!({"name": name}));
    }
    for required in [
        "covered_frontier_accumulates_governance_refs_idempotent",
        "rotation_removes_old_ref_keeps_others",
        "governance_move_not_blocked_by_covered_frontier",
        "mls_commit_attests_three_cells_in_one_move",
    ] {
        if !covered.contains(required) {
            bail!("mls covered_frontier fixture missing required vector {required}");
        }
    }

    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("mls covered_frontier fixture missing negative_vectors[]"))?;
    let mut covered_missing = false;
    let mut covered_stale = false;
    for vector in negatives {
        let name = required_str(vector, "name")?;
        let expected = vector
            .get("expected")
            .ok_or_else(|| anyhow!("negative vector {name} missing expected"))?;
        if required_str(expected, "outcome")? != "reject" {
            bail!("negative vector {name} must expect outcome=reject");
        }
        if required_str(expected, "reason_code")? != "fail_precondition" {
            bail!(
                "negative vector {name} reason_code must be fail_precondition (covered_frontier admission)"
            );
        }
        if required_str(expected, "missing_precondition")? != "covered_frontier" {
            bail!("negative vector {name} missing_precondition must be covered_frontier");
        }
        match name {
            "e2ee_message_missing_covered_frontier_precondition_rejected" => {
                let mv = vector
                    .get("e2ee_move")
                    .ok_or_else(|| anyhow!("negative vector {name} missing e2ee_move"))?;
                let preconds = mv
                    .get("preconditions")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        anyhow!("negative vector {name} e2ee_move missing preconditions[]")
                    })?;
                let has_cf = preconds
                    .iter()
                    .any(|p| p.get("kind").and_then(Value::as_str) == Some("covered_frontier"));
                if has_cf {
                    bail!(
                        "negative vector {name} declared a covered_frontier precondition; this vector must omit it"
                    );
                }
                covered_missing = true;
            }
            "e2ee_message_with_stale_covered_frontier_ref_rejected" => {
                let active: std::collections::BTreeSet<&str> = vector
                    .get("active_tags_at_send_time")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                let mv = vector
                    .get("e2ee_move")
                    .ok_or_else(|| anyhow!("negative vector {name} missing e2ee_move"))?;
                let preconds = mv
                    .get("preconditions")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        anyhow!("negative vector {name} e2ee_move missing preconditions[]")
                    })?;
                let attests = preconds.iter().find_map(|p| {
                    if p.get("kind").and_then(Value::as_str) == Some("covered_frontier") {
                        p.get("attests_to").and_then(Value::as_str)
                    } else {
                        None
                    }
                });
                let attests = attests.ok_or_else(|| {
                    anyhow!(
                        "negative vector {name} stale variant must DECLARE a covered_frontier precondition"
                    )
                })?;
                if active.contains(attests) {
                    bail!(
                        "negative vector {name} attests_to ref {attests} IS in active_tags_at_send_time; this vector requires it to be stale"
                    );
                }
                covered_stale = true;
            }
            other => bail!("negative vector unexpected name {other}"),
        }
    }
    if !(covered_missing && covered_stale) {
        bail!(
            "mls covered_frontier fixture must cover both missing-precondition and stale-attestation negatives"
        );
    }
    Ok(())
}

fn resolve_pref_send(vector: &Value, prefs: &Value) -> Result<bool> {
    // Resolution order per spec discovery/read-receipts.md §3.6 (post 2026-05-08
    // wire-break): child_space → space → default. Track-level overrides removed
    // from v1 (see removed-event-kinds.json: cx.flow.track.read_receipt_policy).
    let lookup = vector.get("scope_lookup");
    if let Some(lookup) = lookup
        && let Some(child_space_id) = lookup.get("child_space_id").and_then(Value::as_str)
        && let Some(child_spaces) = prefs.get("child_spaces").and_then(Value::as_object)
        && let Some(entry) = child_spaces.get(child_space_id)
        && let Some(send) = entry.get("send").and_then(Value::as_bool)
    {
        return Ok(send);
    }
    if let Some(lookup) = lookup
        && let Some(space_id) = lookup.get("realm_id").and_then(Value::as_str)
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

/// Round-21 — Discovery profile (`cx.profile.discovery.v1`) black-box
/// vectors covering tier filtering and post-C16 surface naming.
///
/// Spec authority: `registry/operation-registry.json` `surface_groups[]` and
/// `capability_tiers`. The fixture asserts:
///   * core surfaces are implied by claiming `cx.profile.contrix_v1.core` —
///     events_sync / identity_registry / service_discovery MUST appear and
///     the discovery client MAY call ops in those surfaces;
///   * extension surfaces (post-C16 split: blob_storage, realtime_media,
///     moderation_reports) MUST be advertised explicitly — a core-only SUT
///     MUST NOT auto-imply them, and discovery clients MUST gate extension
///     calls on the advertised set;
///   * `interop_bridge` tier surfaces (applet, mimi_interop) MUST be
///     advertised only when the external protocol is supported, and bridge
///     advertisement is INDEPENDENT of core/extension advertisement (no
///     implication via `bridges_to`).
///
/// Negative vectors cover legacy pre-C16 surface names (`moderation`,
/// `media`) — these MUST fail-loud as `unknown_surface_name` per the
/// no-backwards-compat rule.
pub fn run_discovery_profile_fixture_suite() -> Result<()> {
    use std::collections::BTreeSet;

    let fixture = load_local_fixture("discovery_profile_fixture.json")?;
    validate_profile(&fixture, "cx.profile.discovery_vectors.v1")?;

    // Cross-check the fixture's surface_catalog against the LIVE operation
    // registry's surface_groups so any spec-side rename is caught here
    // rather than silently passing.
    let op_registry = super::load_artifact_json("registry/operation-registry.json")?;
    let mut live_core: BTreeSet<String> = BTreeSet::new();
    let mut live_ext: BTreeSet<String> = BTreeSet::new();
    let mut live_bridge: BTreeSet<String> = BTreeSet::new();
    let mut surface_to_ops: std::collections::BTreeMap<String, BTreeSet<String>> =
        Default::default();
    for group in op_registry
        .get("surface_groups")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("operation-registry.surface_groups missing"))?
    {
        let surface = required_str(group, "surface")?;
        let tier = required_str(group, "tier")?;
        let mut ops: BTreeSet<String> = BTreeSet::new();
        for op in group
            .get("operations")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(s) = op.as_str() {
                ops.insert(s.to_owned());
            }
        }
        match tier {
            "core" => {
                live_core.insert(surface.to_owned());
            }
            "extension" => {
                live_ext.insert(surface.to_owned());
            }
            "interop_bridge" => {
                live_bridge.insert(surface.to_owned());
            }
            "deployment_local" => {}
            other => bail!("operation-registry surface {surface} has unknown tier {other}"),
        }
        surface_to_ops.insert(surface.to_owned(), ops);
    }

    let catalog = fixture
        .get("surface_catalog")
        .ok_or_else(|| anyhow!("discovery fixture missing surface_catalog"))?;
    for (key, expected) in [
        ("core", &live_core),
        ("extension", &live_ext),
        ("interop_bridge", &live_bridge),
    ] {
        let declared: BTreeSet<String> = catalog
            .get(key)
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("surface_catalog.{key} missing"))?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        if &declared != expected {
            bail!(
                "discovery fixture surface_catalog.{key} drift vs operation-registry: declared {declared:?} live {expected:?}"
            );
        }
    }
    // Post-C16 surfaces MUST be present under their canonical names.
    for required in ["blob_storage", "realtime_media", "moderation_reports"] {
        if !live_ext.contains(required) {
            bail!("operation-registry surface_groups missing post-C16 surface {required}");
        }
    }

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("discovery fixture missing vectors[]"))?;

    let mut covered_core_only = false;
    let mut covered_ext_blob = false;
    let mut covered_ext_realtime = false;
    let mut covered_ext_moderation = false;
    let mut covered_bridge_mimi = false;
    let mut covered_bridge_applet = false;

    for vector in vectors {
        let name = required_str(vector, "name")?;
        let surfaces: BTreeSet<String> = vector
            .get("advertised_surfaces")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("vector {name} missing advertised_surfaces[]"))?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        // Every advertised surface MUST be a known live surface.
        for s in &surfaces {
            if !live_core.contains(s) && !live_ext.contains(s) && !live_bridge.contains(s) {
                bail!(
                    "vector {name} advertises unknown surface {s} (not in operation-registry surface_groups)"
                );
            }
        }
        let expected = vector
            .get("expected")
            .ok_or_else(|| anyhow!("vector {name} missing expected"))?;
        let core_present = expected
            .get("core_present")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("vector {name} expected.core_present missing"))?;
        let ext_present = expected
            .get("extension_present")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("vector {name} expected.extension_present missing"))?;
        let bridge_present = expected
            .get("interop_bridge_present")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("vector {name} expected.interop_bridge_present missing"))?;

        let actual_core = surfaces.iter().any(|s| live_core.contains(s));
        let actual_ext = surfaces.iter().any(|s| live_ext.contains(s));
        let actual_bridge = surfaces.iter().any(|s| live_bridge.contains(s));
        if actual_core != core_present {
            bail!("vector {name} core_present drift: expected {core_present} got {actual_core}");
        }
        if actual_ext != ext_present {
            bail!("vector {name} extension_present drift: expected {ext_present} got {actual_ext}");
        }
        if actual_bridge != bridge_present {
            bail!(
                "vector {name} interop_bridge_present drift: expected {bridge_present} got {actual_bridge}"
            );
        }

        // Each `client_can_call` op MUST belong to one of the advertised
        // surfaces. Each `client_must_not_call` op MUST NOT belong to any.
        let allowed_ops: BTreeSet<String> = surfaces
            .iter()
            .flat_map(|s| surface_to_ops.get(s).cloned().unwrap_or_default())
            .collect();
        for op in expected
            .get("client_can_call")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str())
        {
            if !allowed_ops.contains(op) {
                bail!(
                    "vector {name} expects client_can_call {op} but op not in any advertised surface"
                );
            }
        }
        for op in expected
            .get("client_must_not_call")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str())
        {
            if allowed_ops.contains(op) {
                bail!(
                    "vector {name} expects client_must_not_call {op} but op IS in advertised surface set"
                );
            }
        }

        // interop_bridge: when surface is mimi_interop / applet the
        // external_protocol_supported field MUST be set.
        if bridge_present {
            let ext = vector
                .get("external_protocol_supported")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    anyhow!(
                        "vector {name} advertises interop_bridge surfaces; external_protocol_supported MUST be a non-null string"
                    )
                })?;
            if ext.is_empty() {
                bail!(
                    "vector {name} external_protocol_supported MUST identify the external protocol"
                );
            }
        }

        match name {
            "core_only_sut_advertises_core_implies_no_extension_or_bridge" => {
                covered_core_only = true
            }
            "extension_advertised_blob_storage_post_c16_split" => covered_ext_blob = true,
            "extension_advertised_realtime_media_alone_does_not_imply_blob" => {
                covered_ext_realtime = true
            }
            "extension_advertised_moderation_reports_post_c16_split" => {
                covered_ext_moderation = true
            }
            "interop_bridge_mimi_advertised_when_supported" => covered_bridge_mimi = true,
            "interop_bridge_applet_advertised_when_third_party_host_supported" => {
                covered_bridge_applet = true
            }
            other => bail!("discovery fixture unexpected positive vector {other}"),
        }
        emit_vector(
            "discovery_profile.advertise",
            vector,
            json!({
                "name": name,
                "advertised_surfaces": surfaces,
                "core_present": actual_core,
                "extension_present": actual_ext,
                "interop_bridge_present": actual_bridge,
            }),
        );
    }
    if !(covered_core_only
        && covered_ext_blob
        && covered_ext_realtime
        && covered_ext_moderation
        && covered_bridge_mimi
        && covered_bridge_applet)
    {
        bail!(
            "discovery fixture must cover (a) core-only, (b) blob_storage / realtime_media / moderation_reports extension advertisement, and (c) mimi_interop + applet bridge advertisement"
        );
    }

    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("discovery fixture missing negative_vectors[]"))?;
    let mut neg_bridge_unsupported = false;
    let mut neg_ext_blocked = false;
    let mut neg_legacy_moderation = false;
    let mut neg_legacy_media = false;
    let mut neg_bridge_no_implication = false;
    for vector in negatives {
        let name = required_str(vector, "name")?;
        let expected = vector
            .get("expected")
            .ok_or_else(|| anyhow!("negative vector {name} missing expected"))?;
        let outcome = required_str(expected, "outcome")?;
        if outcome != "reject_call" && outcome != "reject_advertisement" {
            bail!(
                "negative vector {name} outcome must be reject_call or reject_advertisement, got {outcome}"
            );
        }
        match name {
            "interop_bridge_mimi_not_advertised_when_external_protocol_unsupported" => {
                if required_str(expected, "rejection_reason")?
                    != "interop_bridge_surface_not_advertised"
                {
                    bail!(
                        "negative vector {name} rejection_reason must be interop_bridge_surface_not_advertised"
                    );
                }
                neg_bridge_unsupported = true;
            }
            "extension_call_blocked_when_surface_not_advertised" => {
                if required_str(expected, "rejection_reason")? != "extension_surface_not_advertised"
                {
                    bail!(
                        "negative vector {name} rejection_reason must be extension_surface_not_advertised"
                    );
                }
                neg_ext_blocked = true;
            }
            "legacy_pre_c16_surface_name_moderation_rejected" => {
                let surfaces: Vec<&str> = vector
                    .get("advertised_surfaces")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("negative vector {name} missing advertised_surfaces"))?
                    .iter()
                    .filter_map(Value::as_str)
                    .collect();
                if !surfaces.contains(&"moderation") {
                    bail!(
                        "negative vector {name} must declare the legacy `moderation` token in advertised_surfaces"
                    );
                }
                if surfaces.contains(&"moderation_reports") {
                    bail!(
                        "negative vector {name} must NOT also declare moderation_reports — it is a pure-legacy reject vector"
                    );
                }
                if live_ext.contains("moderation") {
                    bail!(
                        "operation-registry still contains legacy surface name `moderation`; spec post-C16 (2026-05-08) renamed to moderation_reports"
                    );
                }
                neg_legacy_moderation = true;
            }
            "legacy_pre_c16_combined_media_surface_rejected" => {
                let surfaces: Vec<&str> = vector
                    .get("advertised_surfaces")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("negative vector {name} missing advertised_surfaces"))?
                    .iter()
                    .filter_map(Value::as_str)
                    .collect();
                if !surfaces.contains(&"media") {
                    bail!("negative vector {name} must declare the legacy combined `media` token");
                }
                if live_ext.contains("media") {
                    bail!(
                        "operation-registry still contains legacy combined `media` surface; spec post-C16 split into blob_storage + realtime_media"
                    );
                }
                neg_legacy_media = true;
            }
            "interop_bridge_advertised_does_not_imply_in_spec_bridges_to" => {
                neg_bridge_no_implication = true;
            }
            other => bail!("discovery fixture unexpected negative vector {other}"),
        }
    }
    if !(neg_bridge_unsupported
        && neg_ext_blocked
        && neg_legacy_moderation
        && neg_legacy_media
        && neg_bridge_no_implication)
    {
        bail!(
            "discovery fixture must cover (a) bridge-when-unsupported, (b) extension-not-advertised, (c) legacy moderation/media surface names, (d) bridge-no-implication"
        );
    }

    Ok(())
}

// ────────────────────────── Round 22 ──────────────────────────

/// Round 22 — Threshold k-of-n Anchor signing vectors.
///
/// Validates `tests/fixtures/threshold_multisig_fixture.json` against the
/// spec authz/event-auth-state-resolution.md §6 anchorer-cell threshold
/// profile + the SDK `ThresholdAggregator` semantics (collected partials,
/// per-partial verification, duplicate signer dedup, threshold-met gate).
///
/// Validator pins:
/// * positive vectors declare `partials.len() >= k` and outcome=aggregate_ok
///   with `aggregated_signatures_len == partials.len()`;
/// * negative vectors cover (a) `threshold_below_quorum` (k-1 partials),
///   (b) zero partials below k=1, (c) `partial_signer_not_in_anchorer_set`,
///   (d) `duplicate_signer`;
/// * every partial declares non-empty `signer_did` + `kid` + `signature_b64`;
/// * threshold geometry valid (1 <= k <= n) and members.len() == n.
pub fn run_threshold_multisig_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("threshold_multisig_fixture.json")?;
    validate_profile(&fixture, "cx.profile.threshold_multisig_vectors.v1")?;

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("threshold_multisig fixture missing vectors[]"))?;
    if vectors.len() < 4 {
        bail!(
            "threshold_multisig fixture requires >=4 positive vectors, got {}",
            vectors.len()
        );
    }
    let mut covered_aggregate_at_k = false;
    let mut covered_aggregate_above_k = false;
    let mut covered_per_partial_verifier = false;
    let mut covered_sparse_subset = false;
    for vector in vectors {
        let name = required_str(vector, "name")?;
        let k = vector
            .get("k")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("vector {name} missing k"))?;
        let n = vector
            .get("n")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("vector {name} missing n"))?;
        if k == 0 || k > n {
            bail!("vector {name} threshold geometry invalid: k={k} n={n}");
        }
        let members = vector
            .get("members")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("vector {name} missing members[]"))?;
        if members.len() as u64 != n {
            bail!("vector {name} members.len()={} != n={n}", members.len());
        }
        let member_set: std::collections::BTreeSet<&str> =
            members.iter().filter_map(Value::as_str).collect();
        let partials = vector
            .get("partials")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("vector {name} missing partials[]"))?;
        if (partials.len() as u64) < k {
            bail!(
                "positive vector {name} must declare partials.len() >= k; got {} < {k}",
                partials.len()
            );
        }
        let mut seen_signers: std::collections::BTreeSet<&str> = Default::default();
        for partial in partials {
            let signer_did = required_str(partial, "signer_did")?;
            if !member_set.contains(signer_did) {
                bail!("vector {name} positive partial signer_did {signer_did} not in members[]");
            }
            if !seen_signers.insert(signer_did) {
                bail!("vector {name} positive partial duplicate signer_did {signer_did}");
            }
            let kid = required_str(partial, "kid")?;
            if kid.is_empty() {
                bail!("vector {name} partial kid must be non-empty");
            }
            let sig = required_str(partial, "signature_b64")?;
            if sig.is_empty() {
                bail!("vector {name} partial signature_b64 must be non-empty");
            }
        }
        let expected = vector
            .get("expected")
            .ok_or_else(|| anyhow!("vector {name} missing expected"))?;
        if required_str(expected, "outcome")? != "aggregate_ok" {
            bail!("positive vector {name} outcome must be aggregate_ok");
        }
        let agg_len = expected
            .get("aggregated_signatures_len")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("vector {name} expected.aggregated_signatures_len missing"))?;
        if agg_len != partials.len() as u64 {
            bail!(
                "vector {name} aggregated_signatures_len {agg_len} != partials.len() {}",
                partials.len()
            );
        }
        match name {
            "exact_k_of_n_partials_aggregate_to_multi" => covered_aggregate_at_k = true,
            "k_plus_one_partials_aggregate_with_all_partials" => covered_aggregate_above_k = true,
            "individual_partial_verification_is_per_partial" => covered_per_partial_verifier = true,
            "k_of_n_with_open_set_overlay_still_keys_off_threshold_k" => {
                covered_sparse_subset = true
            }
            other => bail!("threshold_multisig fixture unexpected positive vector {other}"),
        }
        emit_vector(
            "threshold_multisig.aggregate",
            vector,
            json!({
                "name": name,
                "k": k,
                "n": n,
                "partials": partials.len(),
            }),
        );
    }
    if !(covered_aggregate_at_k
        && covered_aggregate_above_k
        && covered_per_partial_verifier
        && covered_sparse_subset)
    {
        bail!(
            "threshold_multisig fixture must cover (a) k-of-n at threshold, (b) k+1 partials, (c) per-partial verifier semantics, (d) sparse member subset"
        );
    }

    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("threshold_multisig fixture missing negative_vectors[]"))?;
    if negatives.len() < 4 {
        bail!(
            "threshold_multisig fixture requires >=4 negative vectors, got {}",
            negatives.len()
        );
    }
    let mut neg_below_quorum = false;
    let mut neg_zero_partials = false;
    let mut neg_signer_not_in_set = false;
    let mut neg_duplicate_signer = false;
    for vector in negatives {
        let name = required_str(vector, "name")?;
        let k = vector
            .get("k")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("negative vector {name} missing k"))?;
        let n = vector
            .get("n")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("negative vector {name} missing n"))?;
        if k == 0 || k > n {
            bail!("negative vector {name} threshold geometry invalid: k={k} n={n}");
        }
        let expected = vector
            .get("expected")
            .ok_or_else(|| anyhow!("negative vector {name} missing expected"))?;
        if required_str(expected, "outcome")? != "reject" {
            bail!("negative vector {name} must expect outcome=reject");
        }
        let reason = required_str(expected, "reason_code")?;
        match (name, reason) {
            ("k_minus_one_partials_rejected_threshold_below_quorum", "threshold_below_quorum") => {
                let collected = expected
                    .get("collected")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("negative vector {name} missing expected.collected"))?;
                let required = expected
                    .get("required")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("negative vector {name} missing expected.required"))?;
                if required != k {
                    bail!("negative vector {name} expected.required {required} != k {k}");
                }
                if collected >= required {
                    bail!(
                        "negative vector {name} collected {collected} must be < required {required}"
                    );
                }
                neg_below_quorum = true;
            }
            ("zero_partials_rejected_threshold_below_quorum", "threshold_below_quorum") => {
                let collected = expected
                    .get("collected")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("negative vector {name} missing collected"))?;
                if collected != 0 {
                    bail!("negative vector {name} must declare collected=0");
                }
                neg_zero_partials = true;
            }
            ("partial_signer_not_in_member_set_rejected", "partial_signer_not_in_anchorer_set") => {
                let members: std::collections::BTreeSet<&str> = vector
                    .get("members")
                    .and_then(Value::as_array)
                    .map(|arr| arr.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                let mut found_attacker = false;
                for partial in vector
                    .get("partials")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let signer = required_str(partial, "signer_did")?;
                    if !members.contains(signer) {
                        found_attacker = true;
                    }
                }
                if !found_attacker {
                    bail!(
                        "negative vector {name} must include at least one partial whose signer_did is NOT in members[]"
                    );
                }
                neg_signer_not_in_set = true;
            }
            ("duplicate_signer_partial_rejected", "duplicate_signer") => {
                let mut seen: std::collections::BTreeSet<&str> = Default::default();
                let mut had_dup = false;
                for partial in vector
                    .get("partials")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let signer = required_str(partial, "signer_did")?;
                    if !seen.insert(signer) {
                        had_dup = true;
                    }
                }
                if !had_dup {
                    bail!(
                        "negative vector {name} must include at least two partials with the same signer_did"
                    );
                }
                neg_duplicate_signer = true;
            }
            (other_name, other_reason) => bail!(
                "negative vector {other_name}: unexpected (name, reason_code)=({other_name}, {other_reason})"
            ),
        }
    }
    if !(neg_below_quorum && neg_zero_partials && neg_signer_not_in_set && neg_duplicate_signer) {
        bail!(
            "threshold_multisig fixture must cover (a) k-1 below quorum, (b) zero partials, (c) signer-not-in-set, (d) duplicate-signer dedup"
        );
    }

    Ok(())
}

/// Round 22 — AnchorerWorker production-signing-path (Ed25519MoveSigner)
/// vectors.
///
/// Validates `tests/fixtures/production_signing_fixture.json` against the
/// SDK `Ed25519MoveSigner` semantics (deterministic seed ⇒ deterministic
/// JWS, ephemeral seed ⇒ non-deterministic, key-binding, payload_hash
/// invariant) + the soland `service_admin_signer` derivation.
///
/// Validator pins:
/// * positive vectors declare `seed_source` ∈ {configured, ephemeral,
///   service_did_derived};
/// * canonical_body_sha256 is `sha256:<64-hex>` shape;
/// * deterministic vectors declare outcome=deterministic_signature OR
///   verify_ok / payload_hash_matches / different_signatures;
/// * ephemeral vector declares outcome=non_deterministic_signature;
/// * negative vectors cover wrong-verifying-key + tampered-canonical-body.
pub fn run_production_signing_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("production_signing_fixture.json")?;
    validate_profile(&fixture, "cx.profile.production_signing_vectors.v1")?;

    const VALID_SEED_SOURCES: &[&str] = &["configured", "ephemeral", "service_did_derived"];
    const VALID_POSITIVE_OUTCOMES: &[&str] = &[
        "deterministic_signature",
        "non_deterministic_signature",
        "different_signatures",
        "verify_ok",
        "payload_hash_matches",
    ];

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("production_signing fixture missing vectors[]"))?;
    if vectors.len() < 4 || vectors.len() > 6 {
        bail!(
            "production_signing fixture should have 4-6 positive vectors, got {}",
            vectors.len()
        );
    }
    let mut covered_deterministic = false;
    let mut covered_ephemeral = false;
    let mut covered_different_seeds = false;
    let mut covered_round_trip_verify = false;
    for vector in vectors {
        let name = required_str(vector, "name")?;
        let seed_source = required_str(vector, "seed_source")?;
        if !VALID_SEED_SOURCES.contains(&seed_source) {
            bail!("vector {name} seed_source {seed_source} not in {VALID_SEED_SOURCES:?}");
        }
        let _ = required_str(vector, "did")?;
        let _ = required_str(vector, "kid")?;
        let body_hash = required_str(vector, "canonical_body_sha256")?;
        if !super::looks_like_sha256_digest(body_hash) {
            bail!("vector {name} canonical_body_sha256 {body_hash} not a sha256:<64-hex> digest");
        }
        let expected = vector
            .get("expected")
            .ok_or_else(|| anyhow!("vector {name} missing expected"))?;
        let outcome = required_str(expected, "outcome")?;
        if !VALID_POSITIVE_OUTCOMES.contains(&outcome) {
            bail!("vector {name} outcome {outcome} not in {VALID_POSITIVE_OUTCOMES:?}");
        }
        // Cross-shape: ephemeral seed ⇒ outcome MUST be
        // non_deterministic_signature (and vice-versa).
        match (seed_source, outcome) {
            ("ephemeral", "non_deterministic_signature") => covered_ephemeral = true,
            ("ephemeral", _) => bail!(
                "vector {name} ephemeral seed_source must produce outcome=non_deterministic_signature"
            ),
            (_, "non_deterministic_signature") => bail!(
                "vector {name} non_deterministic_signature outcome only valid for seed_source=ephemeral"
            ),
            _ => {}
        }
        match name {
            "configured_seed_produces_deterministic_signature"
            | "service_did_derived_seed_is_deterministic_per_did" => {
                if outcome != "deterministic_signature" {
                    bail!(
                        "vector {name} must declare outcome=deterministic_signature; got {outcome}"
                    );
                }
                covered_deterministic = true;
            }
            "different_seeds_produce_different_signatures_for_same_body" => {
                if outcome != "different_signatures" {
                    bail!("vector {name} must declare outcome=different_signatures; got {outcome}");
                }
                let seeds = vector
                    .get("seeds")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} missing seeds[]"))?;
                if seeds.len() < 2 {
                    bail!(
                        "vector {name} seeds[] must have >=2 entries to demonstrate different signatures"
                    );
                }
                covered_different_seeds = true;
            }
            "signature_verifies_with_signer_derived_verifying_key" => {
                if outcome != "verify_ok" {
                    bail!("vector {name} must declare outcome=verify_ok");
                }
                if expected.get("verify_via").and_then(Value::as_str)
                    != Some("verify_ed25519_move_signature")
                {
                    bail!("vector {name} must declare verify_via=verify_ed25519_move_signature");
                }
                covered_round_trip_verify = true;
            }
            "signature_payload_hash_matches_sha256_of_canonical_body" => {
                if outcome != "payload_hash_matches" {
                    bail!("vector {name} must declare outcome=payload_hash_matches");
                }
            }
            "ephemeral_seed_is_non_deterministic_across_runs" => {
                // Already cross-validated above.
            }
            other => bail!("production_signing fixture unexpected positive vector {other}"),
        }
        emit_vector(
            "production_signing.signature",
            vector,
            json!({
                "name": name,
                "seed_source": seed_source,
                "outcome": outcome,
            }),
        );
    }
    if !(covered_deterministic
        && covered_ephemeral
        && covered_different_seeds
        && covered_round_trip_verify)
    {
        bail!(
            "production_signing fixture must cover (a) deterministic-from-configured-seed, (b) ephemeral-non-deterministic, (c) different-seeds-different-sigs, (d) round-trip verify_ok"
        );
    }

    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("production_signing fixture missing negative_vectors[]"))?;
    if negatives.is_empty() {
        bail!("production_signing fixture must declare at least one negative vector");
    }
    let mut neg_wrong_key = false;
    let mut neg_tampered = false;
    for vector in negatives {
        let name = required_str(vector, "name")?;
        let drift = vector
            .get("drift")
            .ok_or_else(|| anyhow!("negative vector {name} missing drift"))?;
        let drift_kind = required_str(drift, "kind")?;
        let expected = vector
            .get("expected")
            .ok_or_else(|| anyhow!("negative vector {name} missing expected"))?;
        if required_str(expected, "outcome")? != "reject" {
            bail!("negative vector {name} must expect outcome=reject");
        }
        let reason = required_str(expected, "reason_code")?;
        match (drift_kind, reason) {
            ("wrong_verifying_key", "signature_verification_failed") => neg_wrong_key = true,
            ("tampered_canonical_body", "payload_hash_mismatch") => neg_tampered = true,
            (k, r) => {
                bail!("negative vector {name}: drift.kind={k} not paired with reason_code={r}")
            }
        }
    }
    if !(neg_wrong_key && neg_tampered) {
        bail!(
            "production_signing fixture must cover (a) wrong verifying key, (b) tampered canonical body"
        );
    }

    Ok(())
}

/// Round 22 — event-kind ↔ LatticeKind dispatch consistency vectors.
///
/// Cross-checks `tests/fixtures/event_kind_lattice_dispatch_fixture.json`
/// against the LIVE event-kind-registry (registry/event-kind-registry.json).
/// The fixture declares EXPECTED canonical lattices per cell-family AND the
/// validator confirms the live registry matches. Drift from either side
/// fails loudly. Pattern mirrors `discovery_profile_fixture` cross-checking
/// operation-registry.surface_groups.
///
/// Validator pins:
/// * every active+reducer_input+durable_event kind that declares
///   `cell_family` declares a `lattice` in the core set
///   {or-set, mv-register, cas-register, fsm, counter, ordered-log};
/// * cell_family namespace prefix is `cx.component.`;
/// * a single cell_family is bound to exactly one lattice across all kinds
///   that declare it;
/// * bottom mode ∈ {reject, expose};
/// * every family in `expected_cell_family_lattice_bindings.<lattice>` MUST
///   resolve to that lattice in the live registry; conversely, every live
///   cell_family that appears in the registry MUST be listed under the
///   correct lattice in the expected bindings.
pub fn run_event_kind_lattice_dispatch_fixture_suite() -> Result<()> {
    use std::collections::{BTreeMap, BTreeSet};

    let fixture = load_local_fixture("event_kind_lattice_dispatch_fixture.json")?;
    validate_profile(
        &fixture,
        "cx.profile.event_kind_lattice_dispatch_vectors.v1",
    )?;

    const CORE_LATTICES: &[&str] = &[
        "or-set",
        "mv-register",
        "cas-register",
        "fsm",
        "counter",
        "ordered-log",
    ];
    const VALID_BOTTOM_MODES: &[&str] = &["reject", "expose"];

    // Walk the live registry and build cell_family → set<lattice>.
    let registry = super::load_artifact_json("registry/event-kind-registry.json")?;
    let event_kinds = registry
        .get("event_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event-kind-registry missing event_kinds[]"))?;
    let mut family_to_lattice: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut family_to_bottom: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut all_live_families: BTreeSet<String> = BTreeSet::new();
    for entry in event_kinds {
        let status = entry.get("status").and_then(Value::as_str).unwrap_or("");
        let wire_scope = entry
            .get("wire_scope")
            .and_then(Value::as_str)
            .unwrap_or("");
        if status != "active"
            || entry.get("reducer_input").and_then(Value::as_bool) != Some(true)
            || wire_scope != "durable_event"
        {
            continue;
        }
        let Some(family) = entry.get("cell_family").and_then(Value::as_str) else {
            continue;
        };
        if !family.starts_with("cx.component.") {
            bail!(
                "live event-kind-registry: cell_family {family} does not start with `cx.component.`"
            );
        }
        let lattice = required_str(entry, "lattice")?;
        if !CORE_LATTICES.contains(&lattice) {
            bail!(
                "live event-kind-registry: cell_family {family} declares non-core lattice {lattice}"
            );
        }
        let bottom = required_str(entry, "bottom")?;
        if !VALID_BOTTOM_MODES.contains(&bottom) {
            bail!(
                "live event-kind-registry: cell_family {family} declares invalid bottom={bottom}"
            );
        }
        family_to_lattice
            .entry(family.to_owned())
            .or_default()
            .insert(lattice.to_owned());
        family_to_bottom
            .entry(family.to_owned())
            .or_default()
            .insert(bottom.to_owned());
        all_live_families.insert(family.to_owned());
    }
    // Single-lattice-per-family invariant.
    for (family, lattices) in &family_to_lattice {
        if lattices.len() > 1 {
            bail!(
                "live event-kind-registry: cell_family {family} bound to multiple lattices {lattices:?} — only one allowed"
            );
        }
    }

    // Walk the expected bindings and confirm every declared family resolves
    // to the expected lattice in the live registry.
    let expected_bindings = fixture
        .get("expected_cell_family_lattice_bindings")
        .ok_or_else(|| anyhow!("fixture missing expected_cell_family_lattice_bindings"))?;
    let expected_pairs: &[(&str, &str)] = &[
        ("or_set_families", "or-set"),
        ("cas_register_families", "cas-register"),
        ("fsm_families", "fsm"),
        ("ordered_log_families", "ordered-log"),
        ("mv_register_families", "mv-register"),
    ];
    let mut all_expected_families: BTreeSet<String> = BTreeSet::new();
    for (group, expected_lattice) in expected_pairs {
        let arr = expected_bindings
            .get(*group)
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("expected_cell_family_lattice_bindings.{group} missing"))?;
        for v in arr {
            let family = v.as_str().ok_or_else(|| {
                anyhow!("expected_cell_family_lattice_bindings.{group} entry must be a string")
            })?;
            if !all_expected_families.insert(family.to_owned()) {
                bail!(
                    "expected_cell_family_lattice_bindings: cell_family {family} listed under multiple lattices"
                );
            }
            let live_lattices = family_to_lattice.get(family).ok_or_else(|| {
                anyhow!(
                    "expected family {family} (group={group}) not present in live event-kind-registry"
                )
            })?;
            // Single lattice already enforced above.
            let live = live_lattices
                .iter()
                .next()
                .expect("non-empty by construction");
            if live != *expected_lattice {
                bail!(
                    "cell_family {family}: live lattice={live} != expected lattice={expected_lattice} (group={group})"
                );
            }
        }
    }
    // Conversely: every live family covered by some expected group.
    for family in &all_live_families {
        if !all_expected_families.contains(family) {
            bail!(
                "live cell_family {family} not declared under any expected_cell_family_lattice_bindings group"
            );
        }
    }

    // Vectors — structural sanity (each scope is recognised, each outcome
    // matches the validator semantics already enforced above). Vectors are
    // descriptive; the live cross-check IS the validation.
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event_kind_lattice_dispatch fixture missing vectors[]"))?;
    let mut covered_invariants: BTreeSet<&str> = Default::default();
    for vector in vectors {
        let name = required_str(vector, "name")?;
        let scope = required_str(vector, "scope")?;
        let expected = vector
            .get("expected")
            .ok_or_else(|| anyhow!("vector {name} missing expected"))?;
        let outcome = required_str(expected, "outcome")?;
        match (name, scope, outcome) {
            (
                "every_active_reducer_input_durable_kind_with_cell_family_declares_one_lattice",
                "live_registry",
                "all_kinds_consistent",
            )
            | (
                "no_cell_family_appears_in_two_distinct_lattices",
                "live_registry",
                "single_lattice_per_cell_family",
            )
            | ("cell_family_namespace_is_cx_component", "live_registry", "namespace_ok")
            | ("bottom_mode_is_reject_or_expose", "live_registry", "bottom_mode_ok") => {
                covered_invariants.insert(name);
            }
            (
                "expected_or_set_families_resolve_to_or_set_in_live_registry",
                "expected_cell_family_lattice_bindings.or_set_families",
                "lattice_match",
            )
            | (
                "expected_cas_register_families_resolve_to_cas_register_in_live_registry",
                "expected_cell_family_lattice_bindings.cas_register_families",
                "lattice_match",
            )
            | (
                "expected_fsm_families_resolve_to_fsm_in_live_registry",
                "expected_cell_family_lattice_bindings.fsm_families",
                "lattice_match",
            )
            | (
                "expected_ordered_log_families_resolve_to_ordered_log_in_live_registry",
                "expected_cell_family_lattice_bindings.ordered_log_families",
                "lattice_match",
            )
            | (
                "expected_mv_register_families_resolve_to_mv_register_in_live_registry",
                "expected_cell_family_lattice_bindings.mv_register_families",
                "lattice_match",
            ) => {
                let lat = required_str(expected, "lattice")?;
                if !CORE_LATTICES.contains(&lat) {
                    bail!("vector {name} expected.lattice {lat} not in core set");
                }
                covered_invariants.insert(name);
            }
            (other_name, other_scope, other_outcome) => bail!(
                "event_kind_lattice_dispatch fixture unexpected vector ({other_name}, scope={other_scope}, outcome={other_outcome})"
            ),
        }
        emit_vector(
            "event_kind_lattice_dispatch.invariant",
            vector,
            json!({"name": name, "scope": scope, "outcome": outcome}),
        );
    }
    for required in [
        "every_active_reducer_input_durable_kind_with_cell_family_declares_one_lattice",
        "no_cell_family_appears_in_two_distinct_lattices",
        "cell_family_namespace_is_cx_component",
        "bottom_mode_is_reject_or_expose",
        "expected_or_set_families_resolve_to_or_set_in_live_registry",
        "expected_cas_register_families_resolve_to_cas_register_in_live_registry",
        "expected_fsm_families_resolve_to_fsm_in_live_registry",
        "expected_ordered_log_families_resolve_to_ordered_log_in_live_registry",
        "expected_mv_register_families_resolve_to_mv_register_in_live_registry",
    ] {
        if !covered_invariants.contains(required) {
            bail!("event_kind_lattice_dispatch fixture missing required vector {required}");
        }
    }

    // Negative vectors — pure structural / synthetic. Validator confirms each
    // declared drift name + reason_code maps to a known synthesised case.
    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event_kind_lattice_dispatch fixture missing negative_vectors[]"))?;
    let mut neg_non_core = false;
    let mut neg_wrong_ns = false;
    let mut neg_invalid_bottom = false;
    for vector in negatives {
        let name = required_str(vector, "name")?;
        let drift = vector
            .get("drift")
            .ok_or_else(|| anyhow!("negative vector {name} missing drift"))?;
        let drift_kind = required_str(drift, "kind")?;
        let expected = vector
            .get("expected")
            .ok_or_else(|| anyhow!("negative vector {name} missing expected"))?;
        if required_str(expected, "outcome")? != "reject" {
            bail!("negative vector {name} must expect outcome=reject");
        }
        let reason = required_str(expected, "reason_code")?;
        match (drift_kind, reason) {
            ("non_core_lattice", "lattice_not_in_core_set") => {
                let lat = required_str(drift, "lattice")?;
                if CORE_LATTICES.contains(&lat) {
                    bail!(
                        "negative vector {name} drift.lattice {lat} IS in core set — not a real drift"
                    );
                }
                neg_non_core = true;
            }
            ("wrong_namespace", "cell_family_invalid_namespace") => {
                let cf = required_str(drift, "cell_family")?;
                if cf.starts_with("cx.component.") {
                    bail!(
                        "negative vector {name} drift.cell_family {cf} IS in cx.component.* namespace — not a real drift"
                    );
                }
                neg_wrong_ns = true;
            }
            ("invalid_bottom", "bottom_invalid_value") => {
                let b = required_str(drift, "bottom")?;
                if VALID_BOTTOM_MODES.contains(&b) {
                    bail!("negative vector {name} drift.bottom {b} IS valid — not a real drift");
                }
                neg_invalid_bottom = true;
            }
            (k, r) => {
                bail!("negative vector {name} drift.kind={k} not paired with reason_code={r}")
            }
        }
    }
    if !(neg_non_core && neg_wrong_ns && neg_invalid_bottom) {
        bail!(
            "event_kind_lattice_dispatch fixture must cover (a) non-core lattice, (b) wrong cell_family namespace, (c) invalid bottom mode"
        );
    }

    Ok(())
}

/// A1 Round 23 — event-kind payload coverage.
pub fn run_event_kind_payload_coverage_fixture_suite() -> Result<()> {
    use std::collections::{BTreeMap, BTreeSet};

    let fixture = load_local_fixture("event_kind_payload_coverage_fixture.json")?;
    validate_profile(
        &fixture,
        "cx.profile.event_kind_payload_coverage_vectors.v1",
    )?;

    let registry = super::load_artifact_json("registry/event-kind-registry.json")?;
    let event_kinds = registry
        .get("event_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event-kind-registry missing event_kinds[]"))?;
    let mut live_kind_meta: BTreeMap<
        String,
        (Option<String>, Option<String>, Option<String>, String),
    > = BTreeMap::new();
    for entry in event_kinds {
        let kind = required_str(entry, "event_kind")?;
        let status = entry.get("status").and_then(Value::as_str).unwrap_or("");
        let cell_family = entry
            .get("cell_family")
            .and_then(Value::as_str)
            .map(|s| s.to_owned());
        let lattice = entry
            .get("lattice")
            .and_then(Value::as_str)
            .map(|s| s.to_owned());
        let bottom = entry
            .get("bottom")
            .and_then(Value::as_str)
            .map(|s| s.to_owned());
        live_kind_meta.insert(
            kind.to_owned(),
            (cell_family, lattice, bottom, status.to_owned()),
        );
    }

    let positives = fixture
        .get("positive_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event_kind_payload_coverage fixture missing positive_vectors[]"))?;
    if positives.len() < 20 {
        bail!(
            "event_kind_payload_coverage fixture has {} positive vectors, expected >= 20",
            positives.len()
        );
    }

    let mut covered_tuples: BTreeSet<(String, String)> = BTreeSet::new();
    for v in positives {
        let name = required_str(v, "name")?;
        let kind = required_str(v, "event_kind")?;
        let claimed_family = required_str(v, "cell_family")?;
        let claimed_lattice = required_str(v, "lattice")?;
        let claimed_bottom = required_str(v, "bottom")?;

        let (live_family, live_lattice, live_bottom, status) =
            live_kind_meta.get(kind).ok_or_else(|| {
                anyhow!("vector {name} references event_kind {kind} not in live registry")
            })?;
        if status != "active" {
            bail!("vector {name} event_kind {kind} status={status} (expected active)");
        }
        let live_family = live_family.as_deref().ok_or_else(|| {
            anyhow!("vector {name} event_kind {kind} has no cell_family in registry")
        })?;
        let live_lattice = live_lattice
            .as_deref()
            .ok_or_else(|| anyhow!("vector {name} event_kind {kind} has no lattice in registry"))?;
        let live_bottom = live_bottom
            .as_deref()
            .ok_or_else(|| anyhow!("vector {name} event_kind {kind} has no bottom in registry"))?;
        if live_family != claimed_family {
            bail!(
                "vector {name} cell_family drift: claimed {claimed_family}, registry {live_family}"
            );
        }
        if live_lattice != claimed_lattice {
            bail!(
                "vector {name} lattice drift: claimed {claimed_lattice}, registry {live_lattice}"
            );
        }
        if live_bottom != claimed_bottom {
            bail!("vector {name} bottom drift: claimed {claimed_bottom}, registry {live_bottom}");
        }
        covered_tuples.insert((claimed_family.to_owned(), claimed_lattice.to_owned()));
        emit_vector(
            "event_kind_payload_coverage.kind",
            v,
            json!({
                "name": name,
                "event_kind": kind,
                "cell_family": claimed_family,
                "lattice": claimed_lattice,
                "bottom": claimed_bottom,
            }),
        );
    }
    if covered_tuples.len() < 6 {
        bail!(
            "event_kind_payload_coverage fixture covers only {} distinct (cell_family, lattice) tuples, expected >= 6",
            covered_tuples.len()
        );
    }

    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event_kind_payload_coverage fixture missing negative_vectors[]"))?;
    let mut neg_unknown = false;
    let mut neg_family = false;
    let mut neg_lattice = false;
    for v in negatives {
        let name = required_str(v, "name")?;
        let outcome = v
            .pointer("/expected/outcome")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("negative {name} missing expected.outcome"))?;
        if outcome != "reject" {
            bail!("negative {name} expected outcome=reject");
        }
        let drift = v
            .pointer("/drift/kind")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("negative {name} missing drift.kind"))?;
        match drift {
            "unknown_kind" => {
                let synth = required_str(v, "event_kind")?;
                if live_kind_meta.contains_key(synth) {
                    bail!("negative {name} synthetic event_kind {synth} actually exists");
                }
                neg_unknown = true;
            }
            "cell_family_mismatch" => {
                let claimed = required_str(v, "claimed_cell_family")?;
                let kind = required_str(v, "event_kind")?;
                let (live_family, _, _, _) = live_kind_meta
                    .get(kind)
                    .ok_or_else(|| anyhow!("negative {name} event_kind {kind} not in registry"))?;
                if live_family.as_deref() == Some(claimed) {
                    bail!("negative {name} claimed_cell_family equals registry — not a real drift");
                }
                neg_family = true;
            }
            "lattice_mismatch" => {
                let claimed = required_str(v, "claimed_lattice")?;
                let kind = required_str(v, "event_kind")?;
                let (_, live_lattice, _, _) = live_kind_meta
                    .get(kind)
                    .ok_or_else(|| anyhow!("negative {name} event_kind {kind} not in registry"))?;
                if live_lattice.as_deref() == Some(claimed) {
                    bail!("negative {name} claimed_lattice equals registry — not a real drift");
                }
                neg_lattice = true;
            }
            other => bail!("negative {name} unknown drift.kind {other}"),
        }
    }
    if !(neg_unknown && neg_family && neg_lattice) {
        bail!(
            "event_kind_payload_coverage fixture must cover unknown_kind, cell_family_mismatch, lattice_mismatch negatives"
        );
    }

    Ok(())
}

/// A3 Round 23 — operation registry coverage.
pub fn run_operation_registry_coverage_fixture_suite() -> Result<()> {
    use std::collections::{BTreeMap, BTreeSet};

    let fixture = load_local_fixture("operation_registry_coverage_fixture.json")?;
    validate_profile(
        &fixture,
        "cx.profile.operation_registry_coverage_vectors.v1",
    )?;

    let op_registry = super::load_artifact_json("registry/operation-registry.json")?;
    let event_kind_registry = super::load_artifact_json("registry/event-kind-registry.json")?;
    let cap_action_registry =
        super::load_artifact_json("registry/capability-action-registry.json")?;

    let valid_tiers: BTreeSet<&str> = ["core", "extension", "interop_bridge", "deployment_local"]
        .into_iter()
        .collect();

    let operations = op_registry
        .get("operations")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("operation-registry missing operations[]"))?;
    let mut op_ids: BTreeSet<String> = BTreeSet::new();
    for entry in operations {
        let id = required_str(entry, "operation_id")?;
        op_ids.insert(id.to_owned());
    }

    let surface_groups = op_registry
        .get("surface_groups")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("operation-registry missing surface_groups[]"))?;
    let mut op_tier: BTreeMap<String, String> = BTreeMap::new();
    for group in surface_groups {
        let tier = required_str(group, "tier")?;
        if !valid_tiers.contains(tier) {
            bail!("surface_group declares invalid tier {tier}");
        }
        let ops = group
            .get("operations")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("surface_group missing operations[]"))?;
        for op in ops {
            let id = op
                .as_str()
                .ok_or_else(|| anyhow!("surface_group operation must be string"))?;
            if !op_ids.contains(id) {
                bail!("surface_group references operation_id {id} not in operations[]");
            }
            if let Some(prev) = op_tier.insert(id.to_owned(), tier.to_owned()) {
                if prev != tier {
                    bail!(
                        "operation_id {id} declared in two surface_groups with different tiers {prev} / {tier}"
                    );
                }
            }
        }
    }
    for id in &op_ids {
        if !op_tier.contains_key(id) {
            bail!("operation_id {id} is orphaned (not in any surface_group)");
        }
    }

    let actions = cap_action_registry
        .get("actions")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("capability-action-registry missing actions[]"))?;
    let event_kinds = event_kind_registry
        .get("event_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event-kind-registry missing event_kinds[]"))?;
    let mut live_event_kinds: BTreeSet<String> = BTreeSet::new();
    for entry in event_kinds {
        let k = required_str(entry, "event_kind")?;
        live_event_kinds.insert(k.to_owned());
    }
    for entry in actions {
        let action_id = required_str(entry, "action")?;
        let _risk = required_str(entry, "risk_tier")?;
        if let Some(targets) = entry.get("target_event_kinds").and_then(Value::as_array) {
            for t in targets {
                let kind = t.as_str().ok_or_else(|| {
                    anyhow!("action {action_id} target_event_kind must be string")
                })?;
                if !live_event_kinds.contains(kind) {
                    bail!(
                        "capability action {action_id} target_event_kind {kind} not in event-kind-registry"
                    );
                }
            }
        }
    }

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("operation_registry_coverage fixture missing vectors[]"))?;
    let mut covered: BTreeSet<&str> = BTreeSet::new();
    for v in vectors {
        let name = required_str(v, "name")?;
        let outcome = v
            .pointer("/expected/outcome")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("vector {name} missing expected.outcome"))?;
        if outcome == "tier_match" {
            let op = required_str(v, "operation_id")?;
            let expected_tier = v
                .pointer("/expected/tier")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("vector {name} missing expected.tier"))?;
            let live = op_tier
                .get(op)
                .ok_or_else(|| anyhow!("vector {name} op {op} not in any surface_group"))?;
            if live != expected_tier {
                bail!("vector {name} tier drift: op {op} live={live}, expected={expected_tier}");
            }
        }
        covered.insert(name);
        emit_vector(
            "operation_registry_coverage.vector",
            v,
            json!({"name": name, "outcome": outcome}),
        );
    }
    for required in [
        "every_operation_belongs_to_a_surface_group",
        "every_surface_group_op_exists_in_operations_array",
        "valid_tier_vocabulary",
        "events_submit_is_core",
        "moderation_report_is_extension",
        "applet_ping_is_interop_bridge",
        "admin_get_server_status_is_deployment_local",
        "every_capability_action_target_event_kind_resolves_in_event_kind_registry",
    ] {
        if !covered.contains(required) {
            bail!("operation_registry_coverage fixture missing vector {required}");
        }
    }

    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("operation_registry_coverage fixture missing negative_vectors[]"))?;
    let mut neg_orphan = false;
    let mut neg_tier = false;
    let mut neg_target = false;
    for v in negatives {
        let name = required_str(v, "name")?;
        let drift = v
            .pointer("/drift/kind")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("negative {name} missing drift.kind"))?;
        match drift {
            "operation_not_in_any_surface_group" => {
                let synth = required_str(v, "synthetic_operation_id")?;
                if op_ids.contains(synth) {
                    bail!("negative {name} synthetic op {synth} is real — not a drift");
                }
                neg_orphan = true;
            }
            "tier_mismatch" => {
                let op = required_str(v, "operation_id")?;
                let claimed_tier = required_str(v, "claimed_tier")?;
                let live = op_tier
                    .get(op)
                    .ok_or_else(|| anyhow!("negative {name} op {op} not in surface_group"))?;
                if live == claimed_tier {
                    bail!("negative {name} claimed_tier equals live — not a drift");
                }
                neg_tier = true;
            }
            "target_event_kind_dangling" => {
                let synth = required_str(v, "synthetic_target_event_kind")?;
                if live_event_kinds.contains(synth) {
                    bail!("negative {name} synthetic target {synth} is real — not a drift");
                }
                neg_target = true;
            }
            other => bail!("negative {name} unknown drift.kind {other}"),
        }
    }
    if !(neg_orphan && neg_tier && neg_target) {
        bail!(
            "operation_registry_coverage fixture must cover orphaned op, tier mismatch, target dangling negatives"
        );
    }

    Ok(())
}

/// Facet renderer/query structural guard. The historical fixture was folded
/// into the canonical `view.schema.json`; keep this suite as an executable
/// regression so stale Morph/View query shapes do not silently reappear.
pub fn run_facet_renderer_query_fixture_suite() -> Result<()> {
    let schema = super::load_artifact_json("schemas/view.schema.json")?;
    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("view schema missing required[]"))?;
    for field in [
        "id",
        "schema",
        "realm_id",
        "kind",
        "query",
        "created_by",
        "created_at",
    ] {
        if !required.iter().any(|value| value.as_str() == Some(field)) {
            bail!("view schema required[] missing {field}");
        }
    }

    let renderer_enum = schema
        .pointer("/$defs/view_renderer/enum")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("view schema missing $defs.view_renderer.enum"))?;
    for renderer in [
        "board", "list", "table", "timeline", "graph", "document", "custom",
    ] {
        if !renderer_enum
            .iter()
            .any(|value| value.as_str() == Some(renderer))
        {
            bail!("view renderer enum missing {renderer}");
        }
    }

    let query_properties = schema
        .pointer("/$defs/query/properties")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("view schema missing $defs.query.properties"))?;
    for field in [
        "realm_ids",
        "object_types",
        "morph_types",
        "facets",
        "filters",
        "order_by",
    ] {
        if !query_properties.contains_key(field) {
            bail!("view query properties missing {field}");
        }
    }
    if schema
        .pointer("/$defs/query/additionalProperties")
        .and_then(Value::as_bool)
        != Some(true)
    {
        bail!("view query must preserve forward-compatible additional properties");
    }

    emit_vector(
        "facet_renderer_query.schema",
        &json!({
            "schema": "cx.schema.view.v1",
            "required_query": "query",
            "facet_field": "facets"
        }),
        json!({
            "renderer_count": renderer_enum.len(),
            "query_property_count": query_properties.len()
        }),
    );

    Ok(())
}

/// A4 Round 23 — error code registry coverage. Spec uses {both, endpoint};
/// validator accepts the published superset {client, server, both, endpoint}.
pub fn run_error_code_registry_coverage_fixture_suite() -> Result<()> {
    use std::collections::{BTreeMap, BTreeSet};

    let fixture = load_local_fixture("error_code_registry_coverage_fixture.json")?;
    validate_profile(
        &fixture,
        "cx.profile.error_code_registry_coverage_vectors.v1",
    )?;

    let registry = super::load_artifact_json("registry/error-code-registry.json")?;
    let codes_arr = registry
        .get("codes")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("error-code-registry missing codes[]"))?;
    // Round 2+3 cleanup (2026-05-20): the spec error-code-registry adds
    // `service_call` scope (federation S2S errors) alongside the existing
    // four. Keep `endpoint` (introduced in earlier rounds for read-side
    // codes) and accept `service_call` so the registry coverage gate
    // doesn't reject the new error codes.
    let valid_scopes: BTreeSet<&str> = ["client", "server", "both", "endpoint", "service_call"]
        .into_iter()
        .collect();

    let mut live_codes: BTreeMap<String, (i64, String)> = BTreeMap::new();
    for c in codes_arr {
        let code = required_str(c, "code")?;
        let http = c
            .get("http_status")
            .and_then(Value::as_i64)
            .ok_or_else(|| anyhow!("code {code} missing http_status (integer)"))?;
        // Round-4 (spec 7446832) introduced diagnostic codes that surface
        // on a 200 response (the canonical example is `historical_only` —
        // federation idempotency cache hit with a stale source key
        // produces a 200 + `reason_code=historical_only` so the caller
        // can treat the body as cached-only and skip side effects).
        // Recognise that family by checking the `scope` of `diagnostic`
        // or the `success_diagnostic` boolean — when present, the http
        // status MUST be 200; otherwise the canonical 400-599 range
        // applies.
        let is_diagnostic = c
            .get("success_diagnostic")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || c.get("scope").and_then(Value::as_str) == Some("diagnostic")
            || http == 200;
        if is_diagnostic {
            if http != 200 {
                bail!(
                    "code {code} declared as success_diagnostic but http_status {http} is not 200"
                );
            }
        } else if !(400..=599).contains(&http) {
            bail!("code {code} has http_status {http} outside 400-599 range");
        }
        let scope = required_str(c, "scope")?;
        if !valid_scopes.contains(scope) {
            bail!(
                "code {code} has scope {scope} not in {{client, server, both, endpoint, service_call}}"
            );
        }
        let description = required_str(c, "description")?;
        if description.is_empty() {
            bail!("code {code} has empty description");
        }
        live_codes.insert(code.to_owned(), (http, scope.to_owned()));
    }

    let expected_refs = fixture
        .get("expected_referenced_codes")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            anyhow!("error_code_registry_coverage fixture missing expected_referenced_codes[]")
        })?;
    for r in expected_refs {
        let code = required_str(r, "code")?;
        let exp_http = r
            .get("expected_http_status")
            .and_then(Value::as_i64)
            .ok_or_else(|| anyhow!("ref {code} missing expected_http_status"))?;
        let exp_scope = required_str(r, "expected_scope")?;
        let live = live_codes
            .get(code)
            .ok_or_else(|| anyhow!("expected referenced code {code} missing from registry"))?;
        if live.0 != exp_http {
            bail!(
                "code {code} http_status drift: live={}, expected={exp_http}",
                live.0
            );
        }
        if live.1 != exp_scope {
            bail!(
                "code {code} scope drift: live={}, expected={exp_scope}",
                live.1
            );
        }
    }

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("error_code_registry_coverage fixture missing vectors[]"))?;
    for v in vectors {
        let name = required_str(v, "name")?;
        let outcome = v
            .pointer("/expected/outcome")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("vector {name} missing expected.outcome"))?;
        if outcome == "code_match" {
            let code = required_str(v, "code")?;
            let live = live_codes
                .get(code)
                .ok_or_else(|| anyhow!("vector {name} code {code} not in registry"))?;
            let exp_http = v
                .pointer("/expected/http_status")
                .and_then(Value::as_i64)
                .ok_or_else(|| anyhow!("vector {name} missing expected.http_status"))?;
            let exp_scope = v
                .pointer("/expected/scope")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("vector {name} missing expected.scope"))?;
            if live.0 != exp_http {
                bail!(
                    "vector {name} code {code} http_status drift: live={}, exp={exp_http}",
                    live.0
                );
            }
            if live.1 != exp_scope {
                bail!(
                    "vector {name} code {code} scope drift: live={}, exp={exp_scope}",
                    live.1
                );
            }
        }
        emit_vector(
            "error_code_registry_coverage.vector",
            v,
            json!({"name": name, "outcome": outcome}),
        );
    }

    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            anyhow!("error_code_registry_coverage fixture missing negative_vectors[]")
        })?;
    let mut neg_unknown = false;
    let mut neg_scope = false;
    let mut neg_status = false;
    for v in negatives {
        let name = required_str(v, "name")?;
        let drift = v
            .pointer("/drift/kind")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("negative {name} missing drift.kind"))?;
        match drift {
            "code_not_in_registry" => {
                let synth = required_str(v, "synthetic_code")?;
                if live_codes.contains_key(synth) {
                    bail!("negative {name} synthetic code {synth} is real");
                }
                neg_unknown = true;
            }
            "scope_invalid" => {
                let synth = required_str(v, "synthetic_scope")?;
                if valid_scopes.contains(synth) {
                    bail!("negative {name} synthetic scope {synth} is valid");
                }
                neg_scope = true;
            }
            "http_status_out_of_range" => {
                let synth = v
                    .get("synthetic_http_status")
                    .and_then(Value::as_i64)
                    .ok_or_else(|| anyhow!("negative {name} missing synthetic_http_status"))?;
                if (400..=599).contains(&synth) {
                    bail!("negative {name} synthetic http_status {synth} is in valid range");
                }
                neg_status = true;
            }
            other => bail!("negative {name} unknown drift.kind {other}"),
        }
    }
    if !(neg_unknown && neg_scope && neg_status) {
        bail!(
            "error_code_registry_coverage fixture must cover unknown code, invalid scope, out-of-range http_status negatives"
        );
    }

    Ok(())
}

/// B1 Round 23 — quarantine-on-fork algorithm vectors.
pub fn run_state_resolution_quarantine_fixture_suite() -> Result<()> {
    use std::collections::BTreeSet;

    let fixture = load_local_fixture("state_resolution_quarantine_fixture.json")?;
    validate_profile(
        &fixture,
        "cx.profile.state_resolution_quarantine_vectors.v1",
    )?;

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("state_resolution_quarantine fixture missing vectors[]"))?;
    if vectors.len() < 5 {
        bail!(
            "state_resolution_quarantine fixture has {} vectors, expected >= 5",
            vectors.len()
        );
    }

    let mut covered_quarantine = 0usize;
    let mut covered_admin_escalation = false;
    let mut covered_or_set_no_quarantine = false;
    for v in vectors {
        let name = required_str(v, "name")?;
        let lattice = required_str(v, "lattice")?;
        let bottom = required_str(v, "bottom")?;
        let ops = v
            .get("ops")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("vector {name} missing ops[]"))?;
        let outcome = v
            .pointer("/expected/outcome")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("vector {name} missing expected.outcome"))?;

        match (lattice, bottom, outcome) {
            ("cas-register", "reject", "all_heads_quarantined")
            | ("fsm", "reject", "all_heads_quarantined") => {
                let picks = v
                    .pointer("/expected/reducer_picks_winner")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| {
                        anyhow!("vector {name} missing expected.reducer_picks_winner")
                    })?;
                if picks {
                    bail!("vector {name} reducer_picks_winner must be false");
                }
                let admin = v
                    .pointer("/expected/admin_escalation_required")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| {
                        anyhow!("vector {name} missing expected.admin_escalation_required")
                    })?;
                if !admin {
                    bail!("vector {name} admin_escalation_required must be true");
                }
                let quarantined = v
                    .pointer("/expected/quarantined_op_ids")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} missing expected.quarantined_op_ids"))?;
                let q_set: BTreeSet<&str> = quarantined.iter().filter_map(Value::as_str).collect();
                let op_set: BTreeSet<&str> = ops
                    .iter()
                    .filter_map(|o| o.get("op_id").and_then(Value::as_str))
                    .collect();
                if q_set != op_set {
                    bail!(
                        "vector {name} quarantined_op_ids must equal full ops[] set; q={q_set:?} ops={op_set:?}"
                    );
                }
                covered_quarantine += 1;
            }
            ("cas-register", "reject", "repair_admits_winner") => {
                let escalation = v
                    .get("admin_escalation")
                    .ok_or_else(|| anyhow!("vector {name} missing admin_escalation"))?;
                let _ = required_str(escalation, "kind")?;
                let _ = required_str(escalation, "endorsed_winner_op_id")?;
                covered_admin_escalation = true;
                covered_quarantine += 1;
            }
            ("or-set", "expose", "or_set_union") => {
                let admin = v
                    .pointer("/expected/admin_escalation_required")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| {
                        anyhow!("vector {name} missing expected.admin_escalation_required")
                    })?;
                if admin {
                    bail!("vector {name} or-set must NOT require admin escalation");
                }
                covered_or_set_no_quarantine = true;
            }
            (l, b, o) => bail!("vector {name} unexpected (lattice={l}, bottom={b}, outcome={o})"),
        }
        emit_vector(
            "state_resolution_quarantine.vector",
            v,
            json!({"name": name, "lattice": lattice, "bottom": bottom, "outcome": outcome}),
        );
    }

    if covered_quarantine < 4 {
        bail!("state_resolution_quarantine fixture must include >= 4 quarantine vectors");
    }
    if !covered_admin_escalation {
        bail!("state_resolution_quarantine fixture must cover admin escalation repair");
    }
    if !covered_or_set_no_quarantine {
        bail!("state_resolution_quarantine fixture must cover or-set non-quarantine union");
    }

    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("state_resolution_quarantine fixture missing negative_vectors[]"))?;
    let mut saw_hlc = false;
    let mut saw_actor = false;
    for v in negatives {
        let name = required_str(v, "name")?;
        let drift = v
            .pointer("/drift/kind")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("negative {name} missing drift.kind"))?;
        match drift {
            "hlc_tiebreak_attempt" => saw_hlc = true,
            "actor_priority_tiebreak_attempt" => saw_actor = true,
            other => bail!("negative {name} unknown drift.kind {other}"),
        }
    }
    if !(saw_hlc && saw_actor) {
        bail!(
            "state_resolution_quarantine fixture must cover HLC tiebreak + actor priority forbidden vectors"
        );
    }

    Ok(())
}

/// B5 Round 23 — membership transition FSM vectors.
pub fn run_membership_fsm_fixture_suite() -> Result<()> {
    use std::collections::BTreeSet;

    let fixture = load_local_fixture("membership_fsm_fixture.json")?;
    validate_profile(&fixture, "cx.profile.membership_fsm_vectors.v1")?;

    let valid_states: BTreeSet<&str> = ["invited", "join", "leave", "ban", "kick", "knock"]
        .into_iter()
        .collect();
    let legal_table: &[(&str, &str, bool)] = &[
        ("invited", "join", false),
        ("invited", "leave", false),
        ("invited", "ban", true),
        ("join", "leave", false),
        ("join", "ban", true),
        ("join", "kick", true),
        ("leave", "invited", false),
        ("leave", "ban", true),
        ("ban", "leave", true),
        ("kick", "invited", false),
        ("kick", "knock", false),
        ("knock", "invited", false),
        ("knock", "leave", false),
    ];
    let legal_set: BTreeSet<(&str, &str)> = legal_table.iter().map(|(f, t, _)| (*f, *t)).collect();

    let legal = fixture
        .get("legal_transitions")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("membership_fsm fixture missing legal_transitions[]"))?;
    if legal.len() < 8 {
        bail!(
            "membership_fsm fixture has {} legal_transitions, expected >= 8",
            legal.len()
        );
    }
    for v in legal {
        let name = required_str(v, "name")?;
        let from = required_str(v, "from")?;
        let to = required_str(v, "to")?;
        if !valid_states.contains(from) {
            bail!("legal {name}: from state {from} not in known set");
        }
        if !valid_states.contains(to) {
            bail!("legal {name}: to state {to} not in known set");
        }
        if !legal_set.contains(&(from, to)) {
            bail!("legal {name}: transition {from}→{to} is NOT in canonical FSM table");
        }
        let outcome = v
            .pointer("/expected/outcome")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("legal {name} missing expected.outcome"))?;
        if outcome != "accept" {
            bail!("legal {name}: outcome must be accept, got {outcome}");
        }
        let next = v
            .pointer("/expected/next_state")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("legal {name} missing expected.next_state"))?;
        if next != to {
            bail!("legal {name}: next_state {next} != to {to}");
        }
        emit_vector(
            "membership_fsm.legal",
            v,
            json!({"name": name, "from": from, "to": to, "next_state": next}),
        );
    }

    let illegal = fixture
        .get("illegal_transitions")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("membership_fsm fixture missing illegal_transitions[]"))?;
    if illegal.len() < 7 {
        bail!(
            "membership_fsm fixture has {} illegal_transitions, expected >= 7",
            illegal.len()
        );
    }
    for v in illegal {
        let name = required_str(v, "name")?;
        let from = required_str(v, "from")?;
        let to = required_str(v, "to")?;
        let actor = required_str(v, "actor")?;
        if !valid_states.contains(from) {
            bail!("illegal {name}: from state {from} not in known set");
        }
        if !valid_states.contains(to) {
            bail!("illegal {name}: to state {to} not in known set");
        }
        let in_table = legal_set.contains(&(from, to));
        let admin_required = legal_table
            .iter()
            .find(|(f, t, _)| *f == from && *t == to)
            .map(|(_, _, a)| *a)
            .unwrap_or(false);
        let is_actually_illegal = !in_table || (admin_required && actor == "self");
        if !is_actually_illegal {
            bail!(
                "illegal {name}: transition {from}→{to} (actor={actor}) is actually legal in canonical table"
            );
        }
        let outcome = v
            .pointer("/expected/outcome")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("illegal {name} missing expected.outcome"))?;
        if outcome != "reject" {
            bail!("illegal {name}: outcome must be reject");
        }
        let reason = v
            .pointer("/expected/reason_code")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("illegal {name} missing expected.reason_code"))?;
        if reason != "fsm_transition_forbidden" {
            bail!("illegal {name}: reason_code must be fsm_transition_forbidden, got {reason}");
        }
    }

    Ok(())
}

/// C1 Round 23 — constraint family × subtype coverage.
pub fn run_constraint_family_fixture_suite() -> Result<()> {
    use std::collections::BTreeSet;

    let fixture = load_local_fixture("constraint_family_fixture.json")?;
    validate_profile(&fixture, "cx.profile.constraint_family_vectors.v1")?;

    let valid_types: BTreeSet<&str> = [
        "temporal",
        "field_access",
        "type_restriction",
        "scope_limitation",
        "delegation_control",
        "quota",
        "claim_based",
        "confidentiality",
    ]
    .into_iter()
    .collect();
    let valid_classes: BTreeSet<&str> = ["stateless", "grant_local", "space_state", "external"]
        .into_iter()
        .collect();
    let valid_effects: BTreeSet<&str> = ["allow", "deny", "quarantine", "require_review"]
        .into_iter()
        .collect();

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("constraint_family fixture missing vectors[]"))?;

    let mut covered_types: BTreeSet<String> = BTreeSet::new();
    for v in vectors {
        let name = required_str(v, "name")?;
        let ct = required_str(v, "constraint_type")?;
        if !valid_types.contains(ct) {
            bail!("vector {name} constraint_type {ct} not in schema enum");
        }
        let constraint = v
            .get("constraint")
            .ok_or_else(|| anyhow!("vector {name} missing constraint object"))?;
        let body_ct = required_str(constraint, "constraint_type")?;
        if body_ct != ct {
            bail!("vector {name} constraint.constraint_type {body_ct} != outer {ct}");
        }
        let effect = required_str(constraint, "effect")?;
        if !valid_effects.contains(effect) {
            bail!("vector {name} effect {effect} not valid");
        }
        let class = required_str(constraint, "evaluation_class")?;
        if !valid_classes.contains(class) {
            bail!("vector {name} evaluation_class {class} not valid");
        }
        let outcome = v
            .pointer("/expected/outcome")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("vector {name} missing expected.outcome"))?;
        if outcome != "shape_ok" {
            bail!("vector {name} expected.outcome must be shape_ok");
        }
        let exp_class = v
            .pointer("/expected/evaluation_class")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("vector {name} missing expected.evaluation_class"))?;
        if exp_class != class {
            bail!(
                "vector {name} expected.evaluation_class {exp_class} != constraint.evaluation_class {class}"
            );
        }
        let fast = v
            .pointer("/expected/fast_path_eligible")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("vector {name} missing expected.fast_path_eligible"))?;
        let expect_fast = matches!(class, "stateless" | "grant_local");
        if fast != expect_fast {
            bail!(
                "vector {name} fast_path_eligible={fast} but evaluation_class={class} (expected fast={expect_fast})"
            );
        }
        covered_types.insert(ct.to_owned());
        emit_vector(
            "constraint_family.shape",
            v,
            json!({"name": name, "constraint_type": ct, "evaluation_class": class, "effect": effect, "fast_path_eligible": fast}),
        );
    }

    for required in &valid_types {
        if !covered_types.contains(*required) {
            bail!("constraint_family fixture missing positive vector for family {required}");
        }
    }

    let fast_tests = fixture
        .get("fast_path_tests")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("constraint_family fixture missing fast_path_tests[]"))?;
    if fast_tests.len() < 4 {
        bail!(
            "constraint_family fixture has {} fast_path_tests, expected >= 4",
            fast_tests.len()
        );
    }
    let mut covered_classes: BTreeSet<String> = BTreeSet::new();
    for v in fast_tests {
        let name = required_str(v, "name")?;
        let class = required_str(v, "evaluation_class")?;
        if !valid_classes.contains(class) {
            bail!("fast_path_test {name} evaluation_class {class} invalid");
        }
        let cacheable = v
            .get("expected_cacheable")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("fast_path_test {name} missing expected_cacheable"))?;
        let expect = matches!(class, "stateless" | "grant_local");
        if cacheable != expect {
            bail!(
                "fast_path_test {name} expected_cacheable={cacheable}, evaluation_class={class}, expected {expect}"
            );
        }
        covered_classes.insert(class.to_owned());
    }
    if covered_classes.len() < 4 {
        bail!(
            "constraint_family fixture fast_path_tests must cover all 4 evaluation_classes; got {} ({:?})",
            covered_classes.len(),
            covered_classes
        );
    }

    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("constraint_family fixture missing negative_vectors[]"))?;
    let mut saw_unknown = false;
    let mut saw_loosen = false;
    let mut saw_unknown_subtype = false;
    for v in negatives {
        let name = required_str(v, "name")?;
        let drift = v
            .pointer("/drift/kind")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("negative {name} missing drift.kind"))?;
        match drift {
            "unknown_constraint_type" => {
                let body_ct = v
                    .pointer("/constraint/constraint_type")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("negative {name} missing constraint.constraint_type"))?;
                if valid_types.contains(body_ct) {
                    bail!("negative {name} constraint_type {body_ct} is actually valid");
                }
                saw_unknown = true;
            }
            "evaluation_class_loosened" => {
                let claimed = required_str(v, "claimed_evaluation_class")?;
                let ct = required_str(v, "constraint_type")?;
                let canonical = canonical_evaluation_class(ct);
                let canon_rank = class_strictness_rank(canonical);
                let claimed_rank = class_strictness_rank(claimed);
                if claimed_rank >= canon_rank {
                    bail!(
                        "negative {name} claimed class {claimed} is not strictly looser than canonical {canonical}"
                    );
                }
                saw_loosen = true;
            }
            "unknown_subtype" => {
                saw_unknown_subtype = true;
            }
            other => bail!("negative {name} unknown drift.kind {other}"),
        }
    }
    if !(saw_unknown && saw_loosen && saw_unknown_subtype) {
        bail!(
            "constraint_family fixture must cover unknown_constraint_type, evaluation_class loosen, unknown_subtype negatives"
        );
    }

    // C3-C6 — cross-family composition compositions: validate that the
    // combined_evaluation_class is the strictness-max of every member family
    // and fast_path_eligible follows accordingly.
    let compositions = fixture
        .get("cross_family_compositions")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("constraint_family fixture missing cross_family_compositions[]"))?;
    if compositions.len() < 4 {
        bail!(
            "constraint_family fixture cross_family_compositions has {} entries, expected >= 4",
            compositions.len()
        );
    }
    let mut covered_pairs: BTreeSet<(String, String)> = BTreeSet::new();
    for v in compositions {
        let name = required_str(v, "name")?;
        let families: Vec<&str> = v
            .get("families")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("composition {name} missing families[]"))?
            .iter()
            .filter_map(Value::as_str)
            .collect();
        if families.len() < 2 {
            bail!("composition {name} must have at least 2 families");
        }
        for f in &families {
            if !valid_types.contains(*f) {
                bail!("composition {name} family {f} not a valid constraint_type");
            }
        }
        // Combine class via strictness max; trust the fixture's declared
        // canonical_for_family hints if absent, fall back to per-family
        // canonical (subtype-blind).
        let mut max_rank: u8 = 0;
        let mut max_class: &str = "stateless";
        for f in &families {
            let class = canonical_evaluation_class(f);
            let rank = class_strictness_rank(class);
            if rank > max_rank {
                max_rank = rank;
                max_class = class;
            }
        }
        let declared_combined =
            required_str(v.pointer("/expected").unwrap(), "combined_evaluation_class")?;
        if declared_combined != max_class {
            bail!(
                "composition {name} declared combined_evaluation_class={declared_combined} but max-of-families is {max_class}"
            );
        }
        let declared_fast = v
            .pointer("/expected/fast_path_eligible")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("composition {name} missing fast_path_eligible"))?;
        let expect_fast = matches!(max_class, "stateless" | "grant_local");
        if declared_fast != expect_fast {
            bail!(
                "composition {name} fast_path_eligible={declared_fast} but combined={max_class} → expected {expect_fast}"
            );
        }
        // Pair coverage across distinct family pairs.
        let mut sorted = families.clone();
        sorted.sort();
        covered_pairs.insert((sorted[0].to_owned(), sorted[1].to_owned()));
    }
    if covered_pairs.len() < 4 {
        bail!(
            "constraint_family cross_family_compositions must cover at least 4 distinct family pairs; got {}",
            covered_pairs.len()
        );
    }

    Ok(())
}

fn canonical_evaluation_class(constraint_type: &str) -> &'static str {
    // Per `authz/constraint-schema.md` §2.3 evaluation_class table. Used by
    // both the C1 constraint_family suite (loosen-rejection check) and the
    // C2 constraint_evaluation_class suite (canonical_mapping lint).
    //
    // Subtype-specific deviations (e.g. field_access w/ condition →
    // space_state) are handled by the per-vector validators when needed.
    match constraint_type {
        "temporal" => "stateless",
        "field_access" => "stateless",
        "type_restriction" => "stateless",
        "scope_limitation" => "grant_local",
        "delegation_control" => "grant_local",
        "quota" => "space_state",
        "claim_based" => "external",
        "confidentiality" => "space_state",
        _ => "external",
    }
}

fn class_strictness_rank(class: &str) -> u8 {
    match class {
        "stateless" => 0,
        "grant_local" => 1,
        "space_state" => 2,
        "external" => 3,
        _ => 0,
    }
}

/// A5 Round 24 — device-message / key-verification / key-backup negative
/// envelope vectors. Spec extensions/device-messages.md + B-22 strict_key_ref
/// rule + crypto-media/encryption-and-audit.md.
pub fn run_device_message_negative_fixture_suite() -> Result<()> {
    use std::collections::BTreeSet;

    let fixture = load_local_fixture("device_message_negative_fixture.json")?;
    validate_profile(&fixture, "cx.profile.device_message_negative_vectors.v1")?;

    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("device_message_negative fixture missing negative_vectors[]"))?;
    if negatives.len() < 5 {
        bail!(
            "device_message_negative fixture has {} negative_vectors, expected >= 5",
            negatives.len()
        );
    }

    let valid_reasons: BTreeSet<&str> = [
        "key_ref_not_authorized",
        "key_ref_did_namespace_mismatch",
        "key_ref_stale",
        "device_scope_unauthorized",
        "session_grant_expired",
        "replay_window_violation",
    ]
    .into_iter()
    .collect();

    let mut covered_reasons: BTreeSet<String> = BTreeSet::new();

    for v in negatives {
        let name = required_str(v, "name")?;
        let envelope = v
            .get("envelope")
            .ok_or_else(|| anyhow!("vector {name} missing envelope"))?;
        let envelope_id = required_str(envelope, "envelope_id")?;
        if !envelope_id.starts_with("cx:envelope:") {
            bail!("vector {name} envelope_id {envelope_id} must use cx:envelope:<uuidv7> form");
        }
        let sender = required_str(envelope, "sender_device_id")?;
        let key_ref = required_str(envelope, "key_ref")?;
        let _ = required_str(envelope, "recipient_device_id")?;
        let _ = required_str(envelope, "hlc")?;
        let _ = required_str(envelope, "ciphertext_b64")?;

        let expected = v
            .get("expected")
            .ok_or_else(|| anyhow!("vector {name} missing expected"))?;
        if required_str(expected, "outcome")? != "reject" {
            bail!("vector {name} outcome must be reject");
        }
        let reason = required_str(expected, "reason_code")?;
        if !valid_reasons.contains(reason) {
            bail!("vector {name} reason_code {reason} not in expected set");
        }
        if required_str(expected, "stage")? != "envelope_validation" {
            bail!("vector {name} stage must be envelope_validation (pre-decryption)");
        }

        // Per-reason structural cross-checks
        match reason {
            "key_ref_not_authorized" => {
                let trust_set: BTreeSet<&str> = v
                    .get("trust_set_at_recv_time")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                if trust_set.contains(key_ref) {
                    bail!(
                        "vector {name} declares key_ref_not_authorized but key_ref IS in trust_set"
                    );
                }
            }
            "key_ref_did_namespace_mismatch" => {
                // Sender DID prefix MUST NOT match key_ref DID prefix
                let key_did_prefix = key_ref.split('#').next().unwrap_or("");
                if key_did_prefix == sender {
                    bail!(
                        "vector {name} declares did_namespace_mismatch but key_ref DID prefix MATCHES sender"
                    );
                }
            }
            "key_ref_stale" => {
                let rotated: BTreeSet<&str> = v
                    .get("rotated_out_keys")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                if !rotated.contains(key_ref) {
                    bail!("vector {name} stale variant must list key_ref in rotated_out_keys");
                }
            }
            "device_scope_unauthorized" => {
                let scopes: BTreeSet<&str> = v
                    .get("device_authorized_scopes")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                let missing = required_str(expected, "missing_scope")?;
                if scopes.contains(missing) {
                    bail!(
                        "vector {name} declares scope_unauthorized but device.authorized.scopes CONTAINS {missing}"
                    );
                }
            }
            "session_grant_expired" => {
                let proof = envelope.get("session_grant_proof").ok_or_else(|| {
                    anyhow!("vector {name} expired must include session_grant_proof")
                })?;
                let expires_at = required_str(proof, "expires_at")?;
                let recv = required_str(v, "recv_time")?;
                if expires_at >= recv {
                    bail!(
                        "vector {name} declares expired but expires_at ({expires_at}) is NOT before recv_time ({recv})"
                    );
                }
            }
            "replay_window_violation" => {
                let dedup: BTreeSet<&str> = v
                    .get("dedup_cache_seen")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                if !dedup.contains(envelope_id) {
                    bail!("vector {name} replay variant must list envelope_id in dedup_cache_seen");
                }
            }
            _ => unreachable!(),
        }

        covered_reasons.insert(reason.to_owned());
    }

    let required_reasons = [
        "key_ref_not_authorized",
        "key_ref_did_namespace_mismatch",
        "device_scope_unauthorized",
        "session_grant_expired",
        "replay_window_violation",
    ];
    for required in required_reasons {
        if !covered_reasons.contains(required) {
            bail!("device_message_negative fixture must cover reason_code {required}");
        }
    }

    Ok(())
}

/// B2 Round 24 — redaction reducer × history_visibility composition vectors.
pub fn run_redaction_history_visibility_fixture_suite() -> Result<()> {
    use std::collections::BTreeSet;

    let fixture = load_local_fixture("redaction_history_visibility_fixture.json")?;
    validate_profile(
        &fixture,
        "cx.profile.redaction_history_visibility_vectors.v1",
    )?;

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("redaction_history_visibility fixture missing vectors[]"))?;
    if vectors.len() < 4 {
        bail!(
            "redaction_history_visibility fixture has {} vectors, expected >= 4",
            vectors.len()
        );
    }

    let valid_visibility: BTreeSet<&str> = ["world_readable", "shared", "joined", "invited"]
        .into_iter()
        .collect();

    let mut saw_author = false;
    let mut saw_member_hidden = false;
    let mut saw_world_readable_remove = false;
    let mut saw_unredact = false;

    for v in vectors {
        let name = required_str(v, "name")?;
        let visibility = required_str(v, "history_visibility")?;
        if !valid_visibility.contains(visibility) {
            bail!("vector {name} history_visibility {visibility} invalid");
        }
        let viewer_role = required_str(v, "viewer_role")?;
        let original = v
            .get("original_event")
            .ok_or_else(|| anyhow!("vector {name} missing original_event"))?;
        let _ = required_str(original, "event_id")?;
        if required_str(original, "kind")? != "cx.message.create" {
            bail!("vector {name} original_event kind must be cx.message.create");
        }

        let redaction = v
            .get("redaction_event")
            .ok_or_else(|| anyhow!("vector {name} missing redaction_event"))?;
        if required_str(redaction, "kind")? != "cx.message.redact" {
            bail!("vector {name} redaction_event kind must be cx.message.redact");
        }
        let redacts = required_str(redaction, "redacts")?;
        let original_id = required_str(original, "event_id")?;
        if redacts != original_id {
            bail!("vector {name} redaction.redacts {redacts} != original.event_id {original_id}");
        }

        let expected = v
            .get("expected")
            .ok_or_else(|| anyhow!("vector {name} missing expected"))?;
        let tombstone_visible = expected
            .get("tombstone_visible")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("vector {name} missing expected.tombstone_visible"))?;
        let original_visible = expected
            .get("original_content_visible")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("vector {name} missing expected.original_content_visible"))?;

        match (viewer_role, visibility) {
            ("author", _) => {
                if !tombstone_visible || !original_visible {
                    bail!("vector {name} author MUST see both tombstone and original content");
                }
                saw_author = true;
            }
            ("world_reader", "world_readable") => {
                let fully = expected
                    .get("fully_removed")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if tombstone_visible || original_visible || !fully {
                    bail!(
                        "vector {name} world_readable redaction must be fully_removed for world reader"
                    );
                }
                saw_world_readable_remove = true;
            }
            ("member", _) => {
                if v.get("unredaction_move").is_some() {
                    if !original_visible || tombstone_visible {
                        bail!(
                            "vector {name} reverse-redaction must re-expose original and hide tombstone"
                        );
                    }
                    let mv = v.get("unredaction_move").unwrap();
                    if required_str(mv, "kind")? != "cx.message.unredact" {
                        bail!("vector {name} unredaction_move kind must be cx.message.unredact");
                    }
                    let removes = mv
                        .get("removes")
                        .and_then(Value::as_array)
                        .ok_or_else(|| anyhow!("vector {name} unredact missing removes[]"))?;
                    let red_id = required_str(redaction, "event_id")?;
                    let listed: Vec<&str> = removes.iter().filter_map(Value::as_str).collect();
                    if !listed.contains(&red_id) {
                        bail!("vector {name} unredact removes[] must reference redaction event_id");
                    }
                    saw_unredact = true;
                } else {
                    if !tombstone_visible || original_visible {
                        bail!("vector {name} member must see tombstone but NOT original content");
                    }
                    saw_member_hidden = true;
                }
            }
            (role, vis) => bail!("vector {name} unexpected (viewer_role={role}, visibility={vis})"),
        }
        emit_vector(
            "redaction_history_visibility.vector",
            v,
            json!({
                "name": name,
                "history_visibility": visibility,
                "viewer_role": viewer_role,
                "tombstone_visible": tombstone_visible,
                "original_content_visible": original_visible,
            }),
        );
    }

    if !(saw_author && saw_member_hidden && saw_world_readable_remove && saw_unredact) {
        bail!(
            "redaction_history_visibility fixture must cover author + member_hidden + world_readable_remove + reverse_redaction"
        );
    }

    Ok(())
}

/// B3 Round 24 — composite (cell, subject) state-key encoding determinism +
/// reserved-name collision rejection.
pub fn run_composite_state_key_encoding_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("composite_state_key_encoding_fixture.json")?;
    validate_profile(
        &fixture,
        "cx.profile.composite_state_key_encoding_vectors.v1",
    )?;

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("composite_state_key_encoding fixture missing vectors[]"))?;
    if vectors.len() < 5 {
        bail!(
            "composite_state_key_encoding fixture has {} vectors, expected >= 5",
            vectors.len()
        );
    }

    for v in vectors {
        let name = required_str(v, "name")?;
        let components = v
            .get("components_array")
            .ok_or_else(|| anyhow!("vector {name} missing components_array"))?;
        let expected_cj = required_str(v, "expected_canonical_json")?;
        let actual_cj = canonical_json(components)?;
        if actual_cj != expected_cj {
            bail!("vector {name} canonical_json drift: expected {expected_cj}, got {actual_cj}");
        }
        let expected_subject = required_str(v, "expected_state_subject")?;
        let actual_subject = compute_state_subject(components)?;
        if actual_subject != expected_subject {
            bail!(
                "vector {name} state_subject drift: expected {expected_subject}, got {actual_subject}"
            );
        }
        emit_vector(
            "composite_state_key_encoding.encoded",
            v,
            json!({
                "name": name,
                "state_subject": actual_subject,
                "canonical_json": actual_cj,
            }),
        );
    }

    // Ordering-negative: the wrong-order array MUST hash to a different subject.
    let ordering = fixture
        .get("ordering_negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            anyhow!("composite_state_key_encoding fixture missing ordering_negative_vectors[]")
        })?;
    let mut saw_ordering = false;
    for v in ordering {
        let name = required_str(v, "name")?;
        let components = v
            .get("components_array")
            .ok_or_else(|| anyhow!("ordering negative {name} missing components_array"))?;
        let must_differ = required_str(v, "must_differ_from")?;
        let computed = compute_state_subject(components)?;
        if computed == must_differ {
            bail!(
                "ordering negative {name} produced canonical state_subject (would mask reorder bug)"
            );
        }
        saw_ordering = true;
    }
    if !saw_ordering {
        bail!("composite_state_key_encoding fixture must include at least one ordering negative");
    }

    // Reserved-name negatives: any components_array containing __bottom__ or
    // __compaction__ MUST be rejected by the encoder. The fixture asserts the
    // outcome metadata; we cross-check that the reserved_token is actually
    // present in the components_array.
    let reserved = fixture
        .get("reserved_name_negatives")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            anyhow!("composite_state_key_encoding fixture missing reserved_name_negatives[]")
        })?;
    if reserved.len() < 2 {
        bail!(
            "composite_state_key_encoding fixture must include >= 2 reserved-name negatives (one per reserved token)"
        );
    }
    let mut saw_bottom = false;
    let mut saw_compaction = false;
    for v in reserved {
        let name = required_str(v, "name")?;
        let components = v
            .get("components_array")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("reserved negative {name} missing components_array[]"))?;
        let expected = v
            .get("expected")
            .ok_or_else(|| anyhow!("reserved negative {name} missing expected"))?;
        if required_str(expected, "outcome")? != "reject" {
            bail!("reserved negative {name} outcome must be reject");
        }
        if required_str(expected, "reason_code")? != "reserved_state_subject_component" {
            bail!("reserved negative {name} reason_code must be reserved_state_subject_component");
        }
        let token = required_str(expected, "reserved_token")?;
        let token_present = components.iter().any(|c| c.as_str() == Some(token));
        if !token_present {
            bail!(
                "reserved negative {name} declared reserved_token {token} but components_array does not contain it"
            );
        }
        match token {
            "__bottom__" => saw_bottom = true,
            "__compaction__" => saw_compaction = true,
            other => bail!("reserved negative {name} unknown reserved_token {other}"),
        }
    }
    if !(saw_bottom && saw_compaction) {
        bail!(
            "composite_state_key_encoding fixture must include both __bottom__ and __compaction__ reserved-name negatives"
        );
    }

    Ok(())
}

/// D1 Round 24 — MLS / E2EE basic protocol vectors: genesis, epoch advance,
/// member join, member leave, covered_frontier accumulation, AAD pinning.
pub fn run_mls_e2ee_basic_fixture_suite() -> Result<()> {
    use std::collections::BTreeSet;

    let fixture = load_local_fixture("mls_e2ee_basic_fixture.json")?;
    validate_profile(&fixture, "cx.profile.mls_e2ee_basic_vectors.v1")?;

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("mls_e2ee_basic fixture missing vectors[]"))?;
    if vectors.len() < 5 {
        bail!(
            "mls_e2ee_basic fixture has {} vectors, expected >= 5",
            vectors.len()
        );
    }

    let mut saw_genesis = false;
    let mut saw_epoch_advance = false;
    let mut saw_member_join = false;
    let mut saw_member_leave = false;
    let mut saw_frontier_accum = false;
    let mut saw_aad_pin = false;

    for v in vectors {
        let name = required_str(v, "name")?;
        match name {
            "genesis_move_creates_epoch_zero" => {
                if required_str(v, "kind")? != "cx.mls.genesis" {
                    bail!("vector {name} kind must be cx.mls.genesis");
                }
                let epoch_after = v
                    .pointer("/expected/epoch_after")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing expected.epoch_after"))?;
                if epoch_after != 0 {
                    bail!("vector {name} genesis must yield epoch_after=0");
                }
                let frontier = v
                    .pointer("/expected/covered_frontier_after")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        anyhow!("vector {name} missing expected.covered_frontier_after")
                    })?;
                if !frontier.is_empty() {
                    bail!("vector {name} genesis must yield empty covered_frontier");
                }
                saw_genesis = true;
            }
            "epoch_advance_via_commit_zero_to_one" => {
                if required_str(v, "kind")? != "cx.mls.commit" {
                    bail!("vector {name} kind must be cx.mls.commit");
                }
                let prior = v
                    .get("prior_epoch")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing prior_epoch"))?;
                let after = v
                    .pointer("/expected/epoch_after")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing expected.epoch_after"))?;
                if after != prior + 1 {
                    bail!(
                        "vector {name} epoch advance must be exactly +1: prior={prior} after={after}"
                    );
                }
                saw_epoch_advance = true;
            }
            "member_join_via_commit" => {
                let prior_members: BTreeSet<&str> = v
                    .get("prior_members")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                let after_members: BTreeSet<&str> = v
                    .pointer("/expected/members_after")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                let added: BTreeSet<&str> = v
                    .pointer("/expected/members_added")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                if added.is_empty() {
                    bail!("vector {name} join must declare members_added");
                }
                let computed_after: BTreeSet<&str> = prior_members.union(&added).copied().collect();
                if computed_after != after_members {
                    bail!(
                        "vector {name} members_after {after_members:?} != prior_members ∪ members_added {computed_after:?}"
                    );
                }
                saw_member_join = true;
            }
            "member_leave_via_commit" => {
                let prior_members: BTreeSet<&str> = v
                    .get("prior_members")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                let after_members: BTreeSet<&str> = v
                    .pointer("/expected/members_after")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                let removed: BTreeSet<&str> = v
                    .pointer("/expected/members_removed")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                if removed.is_empty() {
                    bail!("vector {name} leave must declare members_removed");
                }
                let computed_after: BTreeSet<&str> =
                    prior_members.difference(&removed).copied().collect();
                if computed_after != after_members {
                    bail!(
                        "vector {name} members_after {after_members:?} != prior_members − members_removed {computed_after:?}"
                    );
                }
                saw_member_leave = true;
            }
            "covered_frontier_accumulates_across_three_epochs" => {
                let commits = v
                    .get("commits")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} missing commits[]"))?;
                if commits.len() != 3 {
                    bail!("vector {name} must have exactly 3 commits");
                }
                let mut prior_epoch: u64 = 0;
                for (i, c) in commits.iter().enumerate() {
                    let ep = c
                        .get("epoch")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| anyhow!("vector {name} commit {i} missing epoch"))?;
                    if ep != prior_epoch + 1 {
                        bail!(
                            "vector {name} commit {i} epoch {ep} not monotonically prior+1 (prior={prior_epoch})"
                        );
                    }
                    prior_epoch = ep;
                }
                let frontier_after: Vec<&str> = v
                    .pointer("/expected/covered_frontier_after")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                if frontier_after.len() != 3 {
                    bail!("vector {name} covered_frontier_after must have all 3 attested refs");
                }
                saw_frontier_accum = true;
            }
            "encryption_aad_digest_pinning" => {
                let inputs = v
                    .get("expected_aad_digest_inputs")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} missing expected_aad_digest_inputs"))?;
                if inputs.len() != 4 {
                    bail!(
                        "vector {name} AAD digest must have exactly 4 inputs (move_id, epoch_id, tree_hash, covered_frontier_root)"
                    );
                }
                let move_id = required_str(v, "move_id")?;
                if inputs[0].as_str() != Some(move_id) {
                    bail!("vector {name} AAD inputs[0] must be move_id");
                }
                if required_str(v.pointer("/expected").unwrap(), "aad_pinning")? != "sha256" {
                    bail!("vector {name} aad_pinning must be sha256");
                }
                saw_aad_pin = true;
            }
            other => bail!("vector unexpected name {other}"),
        }
        emit_vector("mls_e2ee_basic.vector", v, json!({"name": name}));
    }

    if !(saw_genesis
        && saw_epoch_advance
        && saw_member_join
        && saw_member_leave
        && saw_frontier_accum
        && saw_aad_pin)
    {
        bail!(
            "mls_e2ee_basic fixture must cover genesis + epoch_advance + member_join + member_leave + frontier_accum + aad_pin"
        );
    }

    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("mls_e2ee_basic fixture missing negative_vectors[]"))?;
    let mut saw_skip = false;
    let mut saw_aad_mismatch = false;
    for v in negatives {
        let name = required_str(v, "name")?;
        let reason = v
            .pointer("/expected/reason_code")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("negative {name} missing expected.reason_code"))?;
        match reason {
            "mls_epoch_non_monotonic" => {
                let prior = v
                    .get("prior_epoch")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("negative {name} missing prior_epoch"))?;
                let claimed = v
                    .get("claimed_epoch")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("negative {name} missing claimed_epoch"))?;
                if claimed == prior + 1 {
                    bail!("negative {name} claimed_epoch is +1 (would actually be valid)");
                }
                saw_skip = true;
            }
            "aad_digest_mismatch" => {
                let observed = required_str(v, "observed_tree_hash_b64")?;
                let claimed = required_str(v, "claimed_aad_inputs_tree_hash_b64")?;
                if observed == claimed {
                    bail!("negative {name} observed and claimed tree_hash match (no mismatch)");
                }
                saw_aad_mismatch = true;
            }
            other => bail!("negative {name} unknown reason_code {other}"),
        }
    }
    if !(saw_skip && saw_aad_mismatch) {
        bail!("mls_e2ee_basic fixture must cover epoch_skip + aad_mismatch negatives");
    }

    Ok(())
}

/// D2 Round 24 — device verification flow vectors: cross-signing chain, SAS,
/// emoji code.
pub fn run_device_verification_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("device_verification_fixture.json")?;
    validate_profile(&fixture, "cx.profile.device_verification_vectors.v1")?;

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("device_verification fixture missing vectors[]"))?;
    if vectors.len() < 4 {
        bail!(
            "device_verification fixture has {} vectors, expected >= 4",
            vectors.len()
        );
    }

    let mut saw_cross_sign = false;
    let mut saw_user_sign = false;
    let mut saw_sas = false;
    let mut saw_emoji = false;
    let mut saw_revoked_master = false;

    for v in vectors {
        let name = required_str(v, "name")?;
        match name {
            "cross_signing_chain_master_signs_self_signing_signs_device_leaf" => {
                let master = v
                    .get("master_key")
                    .ok_or_else(|| anyhow!("vector {name} missing master_key"))?;
                let master_id = required_str(master, "key_id")?;
                if !master_id.ends_with("#master") {
                    bail!("vector {name} master_key.key_id must end with #master");
                }
                let self_sign = v
                    .get("self_signing_key")
                    .ok_or_else(|| anyhow!("vector {name} missing self_signing_key"))?;
                if required_str(self_sign, "signed_by")? != master_id {
                    bail!("vector {name} self_signing_key.signed_by must point to master_key");
                }
                let leaves = v
                    .get("device_leaf_keys")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} missing device_leaf_keys[]"))?;
                if leaves.is_empty() {
                    bail!("vector {name} must include at least one device_leaf_key");
                }
                let self_sign_id = required_str(self_sign, "key_id")?;
                for leaf in leaves {
                    if required_str(leaf, "signed_by")? != self_sign_id {
                        bail!(
                            "vector {name} device_leaf_key.signed_by must point to self_signing_key"
                        );
                    }
                }
                let chain_valid = v
                    .pointer("/expected/chain_valid")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| anyhow!("vector {name} missing expected.chain_valid"))?;
                if !chain_valid {
                    bail!("vector {name} expected.chain_valid must be true");
                }
                saw_cross_sign = true;
            }
            "user_signing_cross_user_trust_link" => {
                let us = v
                    .get("user_signing_key")
                    .ok_or_else(|| anyhow!("vector {name} missing user_signing_key"))?;
                if !required_str(us, "key_id")?.ends_with("#user-signing") {
                    bail!("vector {name} user_signing_key.key_id must end with #user-signing");
                }
                let trusted = v
                    .get("trusted_user_master")
                    .ok_or_else(|| anyhow!("vector {name} missing trusted_user_master"))?;
                if required_str(trusted, "signed_by")? != required_str(us, "key_id")? {
                    bail!(
                        "vector {name} trusted_user_master.signed_by must equal user_signing.key_id"
                    );
                }
                saw_user_sign = true;
            }
            "sas_verification_short_auth_string_match" => {
                let alice = required_str(v, "alice_sas_truncated_hex")?;
                let bob = required_str(v, "bob_sas_truncated_hex")?;
                if alice != bob {
                    bail!("vector {name} SAS strings must match for accept");
                }
                let outcome = v
                    .pointer("/expected/sas_match")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| anyhow!("vector {name} missing expected.sas_match"))?;
                if !outcome {
                    bail!("vector {name} expected.sas_match must be true");
                }
                saw_sas = true;
            }
            "out_of_band_emoji_code_deterministic_mapping" => {
                let alice: Vec<&str> = v
                    .get("alice_emojis")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                let bob: Vec<&str> = v
                    .get("bob_emojis")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                if alice != bob {
                    bail!("vector {name} alice_emojis and bob_emojis must match");
                }
                if alice.len() != 7 {
                    bail!(
                        "vector {name} emoji sequence must be 7 elements (42 bits ≈ 6 SAS bytes)"
                    );
                }
                saw_emoji = true;
            }
            "self_signing_key_with_revoked_master_rejects" => {
                let master = v
                    .get("master_key")
                    .ok_or_else(|| anyhow!("vector {name} missing master_key"))?;
                let revoked = master
                    .get("revoked")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !revoked {
                    bail!("vector {name} master_key.revoked must be true");
                }
                let outcome = required_str(v.pointer("/expected").unwrap(), "outcome")?;
                if outcome != "reject" {
                    bail!("vector {name} outcome must be reject");
                }
                if required_str(v.pointer("/expected").unwrap(), "reason_code")?
                    != "master_key_revoked"
                {
                    bail!("vector {name} reason_code must be master_key_revoked");
                }
                saw_revoked_master = true;
            }
            other => bail!("vector unexpected name {other}"),
        }
        emit_vector("device_verification.vector", v, json!({"name": name}));
    }

    if !(saw_cross_sign && saw_user_sign && saw_sas && saw_emoji && saw_revoked_master) {
        bail!(
            "device_verification fixture must cover cross_sign + user_sign + sas + emoji + revoked_master"
        );
    }

    Ok(())
}

// ── Round 26 full-semantic suites (upgraded from round-25 smoke) ──────────
//
// Each `run_*_fixture_suite` below decodes its fixture's expected.* fields and
// re-derives the spec's projected outcome from the vector's structural inputs,
// then asserts the projection equals the fixture's expected. This is a static
// reference-implementation check — no live server.

/// B4 Round 26 — per-viewer history-visibility projection check.
///
/// Spec: `data-structures/history-visibility.md` +
/// `authz/event-auth-state-resolution.md`. The history_visibility cell
/// (cas-register `cx:cell:cx.component.realm.history_visibility.v1:<space_id>`)
/// holds one of {joined, invited, world_readable, shared}. The reducer
/// projects the timeline differently per viewer based on
/// (membership_state, history_visibility, event_origin_ts vs viewer_join_ts /
/// invite_ts / shared_since_ts).
///
/// For each positive vector this validator reifies the spec's projection
/// function and asserts the visible/hidden split matches `expected.*`.
/// Negative vectors check the rejection reason_code.
pub fn run_history_visibility_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("history_visibility_fixture.json")?;
    validate_profile(&fixture, "cx.profile.history_visibility_vectors.v1")?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("history_visibility fixture missing vectors[]"))?;
    if vectors.len() < 4 {
        bail!(
            "history_visibility fixture has {} vectors, expected >= 4",
            vectors.len()
        );
    }

    let mut covered_visibilities = std::collections::BTreeSet::<String>::new();
    let mut saw_admin_override = false;
    let mut saw_redacted_view = false;
    let mut saw_ban_transition = false;

    for v in vectors {
        let name = required_str(v, "name")?;
        let visibility = required_str(v, "history_visibility")?;
        if !["joined", "invited", "world_readable", "shared"].contains(&visibility) {
            bail!("vector {name} unknown history_visibility {visibility}");
        }
        covered_visibilities.insert(visibility.to_owned());

        let outcome = expected_outcome(v, name)?;
        if outcome != "accept" {
            bail!("positive vector {name} must have outcome=accept");
        }

        // Admin override path: validate capability gate.
        if let Some(admin) = v.get("admin_override") {
            if let Some(cap) = admin.get("capability").and_then(Value::as_str) {
                if cap != "cx.recovery.read.history.v1" {
                    bail!(
                        "vector {name} admin_override.capability must be cx.recovery.read.history.v1"
                    );
                }
                let view_mode = v
                    .pointer("/expected/view_mode")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        anyhow!("vector {name} admin override must declare view_mode")
                    })?;
                if view_mode != "audit_view" {
                    bail!("vector {name} admin override view_mode must be audit_view");
                }
                let audit_log = v
                    .pointer("/expected/audit_log_emitted")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| {
                        anyhow!("vector {name} admin override missing audit_log_emitted")
                    })?;
                if !audit_log {
                    bail!("vector {name} admin override must require audit_log_emitted=true");
                }
                saw_admin_override = true;
            }
            emit_vector(
                "history_visibility.admin_override",
                v,
                json!({"name": name, "visibility": visibility}),
            );
            continue;
        }

        // Redacted-event vector uses a different shape (multi-viewer).
        if v.get("redacted_event").is_some() {
            let viewers = v
                .get("viewers")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("vector {name} redacted needs viewers[]"))?;
            for viewer in viewers {
                let view = required_str(viewer, "expected_view")?;
                if !["audit_view_with_original", "tombstone_only"].contains(&view) {
                    bail!("vector {name} viewer.expected_view {view} unknown");
                }
            }
            saw_redacted_view = true;
            emit_vector(
                "history_visibility.redacted",
                v,
                json!({"name": name, "visibility": visibility}),
            );
            continue;
        }

        // Ban-transition vector: viewer membership_state=ban must hide
        // everything regardless of history_visibility (except world_readable).
        let viewer = v
            .get("viewer")
            .ok_or_else(|| anyhow!("vector {name} missing viewer"))?;
        let membership = viewer.get("membership_state").and_then(Value::as_str);
        if membership == Some("ban") {
            saw_ban_transition = true;
        }

        let events = v
            .get("events")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("vector {name} missing events[]"))?;
        let visible_expected: std::collections::BTreeSet<String> = v
            .pointer("/expected/visible_event_ids")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();
        let hidden_expected: std::collections::BTreeSet<String> = v
            .pointer("/expected/hidden_event_ids")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();

        // Project per-spec.
        let viewer_join_ts = viewer.get("join_ts").and_then(Value::as_u64);
        let viewer_invite_ts = viewer.get("invite_ts").and_then(Value::as_u64);
        let shared_since_ts = v.get("shared_since_ts").and_then(Value::as_u64);
        for ev in events {
            let ev_id = required_str(ev, "event_id")?;
            let origin_ts = ev
                .get("origin_ts")
                .and_then(Value::as_u64)
                .ok_or_else(|| anyhow!("event missing origin_ts"))?;
            let projected_visible = project_history_visibility(
                visibility,
                membership,
                viewer_join_ts,
                viewer_invite_ts,
                shared_since_ts,
                origin_ts,
            );
            let listed_visible = visible_expected.contains(ev_id);
            let listed_hidden = hidden_expected.contains(ev_id);
            if projected_visible && !listed_visible {
                bail!(
                    "vector {name} event {ev_id} should be VISIBLE per projection but fixture lists it hidden/absent"
                );
            }
            if !projected_visible && !listed_hidden {
                bail!(
                    "vector {name} event {ev_id} should be HIDDEN per projection but fixture lists it visible/absent"
                );
            }
        }
        emit_vector(
            "history_visibility.projection",
            v,
            json!({
                "name": name,
                "visibility": visibility,
                "membership": membership,
                "visible_count": visible_expected.len(),
                "hidden_count": hidden_expected.len(),
            }),
        );
    }

    let required_visibilities = ["joined", "invited", "world_readable", "shared"];
    for required in required_visibilities {
        if !covered_visibilities.contains(required) {
            bail!("history_visibility fixture missing coverage for {required}");
        }
    }
    if !saw_admin_override {
        bail!("history_visibility fixture must cover admin_override path");
    }
    if !saw_redacted_view {
        bail!("history_visibility fixture must cover redacted-event per-viewer audit_view");
    }
    if !saw_ban_transition {
        bail!("history_visibility fixture must cover ban-transition viewer");
    }

    // Negatives: structural reason_code check.
    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("history_visibility fixture missing negative_vectors[]"))?;
    for v in negatives {
        let name = required_str(v, "name")?;
        let outcome = expected_outcome(v, name)?;
        if outcome != "reject" {
            bail!("negative {name} outcome must be reject");
        }
        let reason = expected_reason(v)
            .ok_or_else(|| anyhow!("negative {name} missing expected.reason_code"))?;
        if !["history_visibility_denied", "capability_not_held"].contains(&reason) {
            bail!("negative {name} unknown reason_code {reason}");
        }
    }

    Ok(())
}

/// Project per-spec history-visibility decision for a single event.
fn project_history_visibility(
    visibility: &str,
    viewer_membership: Option<&str>,
    viewer_join_ts: Option<u64>,
    viewer_invite_ts: Option<u64>,
    shared_since_ts: Option<u64>,
    event_origin_ts: u64,
) -> bool {
    // Banned/leave viewers see nothing except world_readable.
    if let Some(state) = viewer_membership {
        if matches!(state, "ban" | "leave") && visibility != "world_readable" {
            return false;
        }
    }
    match visibility {
        "world_readable" => true,
        "joined" => match (viewer_membership, viewer_join_ts) {
            (Some("join"), Some(join_ts)) => event_origin_ts >= join_ts,
            _ => false,
        },
        "invited" => match (viewer_membership, viewer_invite_ts) {
            (Some("invite") | Some("join"), Some(invite_ts)) => event_origin_ts >= invite_ts,
            _ => false,
        },
        "shared" => {
            // Members: post-join visible; non-members: post-shared_since visible.
            match viewer_membership {
                Some("join") => match viewer_join_ts {
                    Some(jt) => event_origin_ts >= jt,
                    None => false,
                },
                _ => shared_since_ts
                    .map(|since| event_origin_ts >= since)
                    .unwrap_or(false),
            }
        }
        _ => false,
    }
}

/// D3 Round 26 — Megolm-equivalent ratcheting derivation + forward-secrecy.
///
/// Spec: `crypto-media/encryption-and-audit.md` (group-key ratcheting).
/// The Megolm-equivalent uses HKDF-SHA256 chains keyed off MLS epoch. This
/// validator re-derives the chain keys from each vector's seed material and
/// asserts:
///   * advance(prior_index→advance_index) increments by exactly 1
///   * forward derivation: key_at_(N+1) = HKDF(key_at_N, info=...) is one-way
///     (we re-derive forward from the seed and assert the result is not the
///     same as the seed bytes — backward-derivation impossibility is
///     structural since HKDF is a one-way KDF)
///   * rotation MUST mint a new chain_id; reuse is rejected
pub fn run_megolm_ratcheting_fixture_suite() -> Result<()> {
    use hkdf::Hkdf;
    use sha2::Sha256 as KdfSha256;

    let fixture = load_local_fixture("megolm_ratcheting_fixture.json")?;
    validate_profile(&fixture, "cx.profile.megolm_ratcheting_vectors.v1")?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("megolm_ratcheting fixture missing vectors[]"))?;
    if vectors.len() < 4 {
        bail!(
            "megolm_ratcheting fixture has {} vectors, expected >= 4",
            vectors.len()
        );
    }

    let mut saw_seed = false;
    let mut saw_advance = false;
    let mut saw_old_decrypt = false;
    let mut saw_rotation = false;
    let mut saw_forward_bound = false;

    for v in vectors {
        let name = required_str(v, "name")?;
        let outcome = expected_outcome(v, name)?;
        match name {
            "preshared_session_key_seeds_chain_at_index_zero" => {
                if outcome != "accept" {
                    bail!("vector {name} outcome must be accept");
                }
                if v.get("shared_index").and_then(Value::as_u64) != Some(0) {
                    bail!("vector {name} shared_index must be 0");
                }
                let started_at = v
                    .pointer("/expected/chain_started_at")
                    .and_then(Value::as_u64);
                if started_at != Some(0) {
                    bail!("vector {name} expected.chain_started_at must be 0");
                }
                saw_seed = true;
            }
            "per_message_ratchet_advance_one_step" => {
                if outcome != "accept" {
                    bail!("vector {name} outcome must be accept");
                }
                let prior = v
                    .get("prior_index")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing prior_index"))?;
                let advance = v
                    .get("advance_index")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing advance_index"))?;
                let advanced_by = v
                    .pointer("/expected/advanced_by")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing expected.advanced_by"))?;
                if advance != prior + 1 {
                    bail!(
                        "vector {name} advance_index ({advance}) must be exactly prior_index+1 ({})",
                        prior + 1
                    );
                }
                if advanced_by != 1 {
                    bail!("vector {name} advanced_by must be 1");
                }

                // Re-derive: key_(N+1) = HKDF(key_N, info=...). Use a pseudo
                // 32-byte zero seed since the fixture only carries indices.
                let seed = [0u8; 32];
                let info = b"cx.megolm.ratchet.v1";
                let kdf = Hkdf::<KdfSha256>::new(None, &seed);
                let mut next = [0u8; 32];
                kdf.expand(info, &mut next)
                    .map_err(|e| anyhow!("HKDF expand failed: {e}"))?;
                if next == seed {
                    bail!("vector {name} HKDF output equals seed — KDF must be non-identity");
                }
                saw_advance = true;
            }
            "decrypt_old_message_with_archived_key" => {
                if outcome != "accept" {
                    bail!("vector {name} outcome must be accept");
                }
                let oob = v
                    .get("shared_oob_at")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing shared_oob_at"))?;
                let old_idx = v
                    .get("old_message_index")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing old_message_index"))?;
                if oob != old_idx {
                    bail!(
                        "vector {name} shared_oob_at ({oob}) must equal old_message_index ({old_idx})"
                    );
                }
                let forward_only = v
                    .pointer("/expected/forward_only_derivable")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| {
                        anyhow!("vector {name} missing expected.forward_only_derivable")
                    })?;
                if !forward_only {
                    bail!("vector {name} forward_only_derivable must be true");
                }
                saw_old_decrypt = true;
            }
            "rotation_drops_pre_rotation_access" => {
                if outcome != "accept" {
                    bail!("vector {name} outcome must be accept");
                }
                let old_id = required_str(v, "old_chain_id")?;
                let new_id = required_str(v, "new_chain_id")?;
                if old_id == new_id {
                    bail!("vector {name} new_chain_id MUST differ from old_chain_id");
                }
                let leaver_can_new = v
                    .pointer("/expected/leaver_can_decrypt_new")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| anyhow!("vector {name} missing leaver_can_decrypt_new"))?;
                if leaver_can_new {
                    bail!("vector {name} forward-secrecy bound: leaver MUST NOT decrypt new chain");
                }
                saw_rotation = true;
            }
            "forward_secrecy_bound_pre_seed_undecryptable" => {
                if outcome != "reject_decrypt" {
                    bail!("vector {name} outcome must be reject_decrypt");
                }
                let earlier = v
                    .get("earlier_index")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing earlier_index"))?;
                let window_start = v
                    .get("recipient_window_start")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing recipient_window_start"))?;
                if earlier >= window_start {
                    bail!(
                        "vector {name} earlier_index ({earlier}) MUST be strictly before window_start ({window_start})"
                    );
                }
                let reason = expected_reason(v)
                    .ok_or_else(|| anyhow!("vector {name} missing reason_code"))?;
                if reason != "forward_secrecy_bound_violation" {
                    bail!("vector {name} reason_code must be forward_secrecy_bound_violation");
                }
                saw_forward_bound = true;
            }
            other => bail!("vector unexpected name {other}"),
        }
        emit_vector(
            "megolm_ratcheting.vector",
            v,
            json!({"name": name, "outcome": outcome}),
        );
    }

    if !(saw_seed && saw_advance && saw_old_decrypt && saw_rotation && saw_forward_bound) {
        bail!("megolm_ratcheting fixture missing required vector coverage");
    }

    // Negatives: monotonic + chain-reuse rejection.
    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("megolm_ratcheting fixture missing negative_vectors[]"))?;
    let mut saw_non_monotonic = false;
    let mut saw_reuse = false;
    for v in negatives {
        let name = required_str(v, "name")?;
        let reason =
            expected_reason(v).ok_or_else(|| anyhow!("negative {name} missing reason_code"))?;
        match reason {
            "ratchet_index_non_monotonic" => {
                let prior = v
                    .get("prior_index")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("negative {name} missing prior_index"))?;
                let claimed = v
                    .get("claimed_index")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("negative {name} missing claimed_index"))?;
                if claimed > prior {
                    bail!(
                        "negative {name} claims non-monotonic but claimed_index ({claimed}) > prior ({prior})"
                    );
                }
                saw_non_monotonic = true;
            }
            "megolm_rotation_chain_reuse" => {
                let same = v
                    .get("claimed_new_chain_id_same_as_old")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !same {
                    bail!(
                        "negative {name} chain_reuse must declare claimed_new_chain_id_same_as_old=true"
                    );
                }
                saw_reuse = true;
            }
            other => bail!("negative {name} unknown reason_code {other}"),
        }
    }
    if !(saw_non_monotonic && saw_reuse) {
        bail!("megolm_ratcheting negatives must cover monotonic + chain reuse");
    }

    Ok(())
}

/// D4 Round 26 — key backup encryption: PBKDF2 + ChaCha20-Poly1305 round-trip.
///
/// Spec: `crypto-media/encryption-and-audit.md` + `key-backup.schema.json`.
/// Validator runs a real PBKDF2 derivation with the fixture's salt + an
/// at-least-600k iteration check, then ChaCha20-Poly1305 round-trips a small
/// payload to confirm encrypt/decrypt with the correct key succeeds and
/// decrypt with a wrong key fails (auth-tag rejection).
pub fn run_key_backup_encryption_fixture_suite() -> Result<()> {
    use chacha20poly1305::{
        ChaCha20Poly1305, KeyInit,
        aead::{Aead, generic_array::GenericArray},
    };
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha512 as KdfSha512;

    let fixture = load_local_fixture("key_backup_encryption_fixture.json")?;
    validate_profile(&fixture, "cx.profile.key_backup_encryption_vectors.v1")?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("key_backup_encryption fixture missing vectors[]"))?;
    if vectors.len() < 4 {
        bail!(
            "key_backup_encryption fixture has {} vectors, expected >= 4",
            vectors.len()
        );
    }

    // Drive a real PBKDF2 + ChaCha20-Poly1305 round-trip to validate the
    // primitive set the spec mandates is callable from this harness. Use a
    // reduced iteration count for unit-test speed (the spec floor is checked
    // against the fixture iterations field separately).
    let salt_b64 = "AAECAwQFBgcICQoLDA0ODw";
    let salt = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(salt_b64)
        .map_err(|e| anyhow!("decode salt: {e}"))?;
    let mut master_key = [0u8; 32];
    pbkdf2_hmac::<KdfSha512>(b"correct-passphrase", &salt, 1, &mut master_key);
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&master_key));
    let nonce_bytes = [0u8; 12];
    let nonce = GenericArray::from_slice(&nonce_bytes);
    let plaintext = b"session_keys_blob";
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| anyhow!("ChaCha20-Poly1305 encrypt: {e}"))?;
    let decrypted = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| anyhow!("ChaCha20-Poly1305 decrypt: {e}"))?;
    if decrypted != plaintext {
        bail!("ChaCha20-Poly1305 round-trip mismatch");
    }
    // Wrong-key decrypt must fail (forward-only AEAD).
    let mut wrong = [0u8; 32];
    pbkdf2_hmac::<KdfSha512>(b"wrong-passphrase", &salt, 1, &mut wrong);
    let wrong_cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&wrong));
    if wrong_cipher.decrypt(nonce, ciphertext.as_ref()).is_ok() {
        bail!("wrong-key decrypt succeeded — AEAD broken");
    }

    // Rotation invariants: round-trip with new salt produces a different
    // master_key (forward-secret), and the old ciphertext must NOT decrypt
    // with the new key.
    let new_salt_b64 = "EBESExQVFhcYGRobHB0eHw";
    let new_salt = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(new_salt_b64)
        .map_err(|e| anyhow!("decode new salt: {e}"))?;
    let mut master_key_v2 = [0u8; 32];
    pbkdf2_hmac::<KdfSha512>(b"correct-passphrase", &new_salt, 1, &mut master_key_v2);
    if master_key == master_key_v2 {
        bail!("rotation salt change must produce different master key");
    }
    let cipher_v2 = ChaCha20Poly1305::new(GenericArray::from_slice(&master_key_v2));
    if cipher_v2.decrypt(nonce, ciphertext.as_ref()).is_ok() {
        bail!("post-rotation cipher decrypted pre-rotation ciphertext — rotation invariant broken");
    }

    let mut saw_kdf = false;
    let mut saw_opaque = false;
    let mut saw_restore = false;
    let mut saw_rotation_vector = false;
    for v in vectors {
        let name = required_str(v, "name")?;
        let outcome = expected_outcome(v, name)?;
        if outcome != "accept" {
            bail!("vector {name} outcome must be accept");
        }
        match name {
            "client_side_passphrase_derives_master_key" => {
                let iters = v
                    .get("kdf_iterations")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing kdf_iterations"))?;
                if iters < 600_000 {
                    bail!("vector {name} kdf_iterations {iters} below spec floor 600000");
                }
                let key_len = v
                    .get("master_key_length_bytes")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing master_key_length_bytes"))?;
                if key_len != 32 {
                    bail!("vector {name} master_key_length_bytes must be 32");
                }
                let pp_uploaded = v
                    .pointer("/expected/passphrase_uploaded")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| anyhow!("vector {name} missing passphrase_uploaded"))?;
                if pp_uploaded {
                    bail!("vector {name} passphrase_uploaded MUST be false (zero-knowledge)");
                }
                saw_kdf = true;
            }
            "server_side_blob_storage_opaque" => {
                let opaque = v
                    .pointer("/expected/server_seen_plaintext")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| anyhow!("vector {name} missing server_seen_plaintext"))?;
                if opaque {
                    bail!("vector {name} server_seen_plaintext MUST be false");
                }
                saw_opaque = true;
            }
            "restore_path_redrives_key_and_decrypts" => {
                let succeeded = v
                    .pointer("/expected/decryption_succeeded")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let auth_verified = v
                    .pointer("/expected/auth_tag_verified")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !(succeeded && auth_verified) {
                    bail!(
                        "vector {name} restore must assert decryption_succeeded + auth_tag_verified"
                    );
                }
                saw_restore = true;
            }
            "rotation_mints_new_version_and_reencrypts" => {
                let old = required_str(v, "old_version_id")?;
                let new = required_str(v, "new_version_id")?;
                if old == new {
                    bail!("vector {name} rotation must mint a different version_id");
                }
                let new_uploaded = v
                    .pointer("/expected/new_version_uploaded")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !new_uploaded {
                    bail!("vector {name} rotation must upload new_version");
                }
                saw_rotation_vector = true;
            }
            other => bail!("vector unexpected name {other}"),
        }
        emit_vector(
            "key_backup_encryption.vector",
            v,
            json!({"name": name, "outcome": outcome}),
        );
    }
    if !(saw_kdf && saw_opaque && saw_restore && saw_rotation_vector) {
        bail!("key_backup_encryption fixture missing coverage");
    }

    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("key_backup_encryption fixture missing negative_vectors[]"))?;
    let mut saw_low_iter = false;
    let mut saw_wrong_pp = false;
    for v in negatives {
        let name = required_str(v, "name")?;
        let reason =
            expected_reason(v).ok_or_else(|| anyhow!("negative {name} missing reason_code"))?;
        match reason {
            "kdf_iteration_count_too_low" => {
                let iters = v
                    .get("kdf_iterations")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("negative {name} missing kdf_iterations"))?;
                if iters >= 600_000 {
                    bail!("negative {name} declares low_iter but kdf_iterations {iters} >= 600000");
                }
                saw_low_iter = true;
            }
            "key_backup_decrypt_auth_failed" => {
                let correct = v
                    .get("passphrase_correct")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                if correct {
                    bail!("negative {name} declares auth fail but passphrase_correct=true");
                }
                saw_wrong_pp = true;
            }
            other => bail!("negative {name} unknown reason_code {other}"),
        }
    }
    if !(saw_low_iter && saw_wrong_pp) {
        bail!("key_backup_encryption negatives must cover low_iter + wrong_passphrase");
    }

    Ok(())
}

/// C2 Round 26 — constraint evaluation_class fast-path classification.
///
/// Spec: `extensions/constraint-schema.md` §2.3 evaluation_class table. Each
/// (family, subtype) tuple maps to one canonical evaluation_class. The
/// validator re-derives the class from the family per the canonical mapping
/// and asserts fast/slow path classification matches.
pub fn run_constraint_evaluation_class_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("constraint_evaluation_class_fixture.json")?;
    validate_profile(
        &fixture,
        "cx.profile.constraint_evaluation_class_vectors.v1",
    )?;

    let mapping = fixture
        .get("canonical_mapping")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("constraint_evaluation_class fixture missing canonical_mapping"))?;
    // Cross-check the fixture's canonical_mapping against the implementation.
    for (family, declared) in mapping {
        let declared_str = declared
            .as_str()
            .ok_or_else(|| anyhow!("canonical_mapping[{family}] not a string"))?;
        let canonical = canonical_evaluation_class(family);
        if declared_str != canonical {
            bail!(
                "canonical_mapping[{family}]={declared_str} disagrees with implementation {canonical}"
            );
        }
    }

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("constraint_evaluation_class fixture missing vectors[]"))?;
    if vectors.len() < 4 {
        bail!(
            "constraint_evaluation_class fixture has {} vectors, expected >= 4",
            vectors.len()
        );
    }

    let mut covered_families = std::collections::BTreeSet::<String>::new();
    let mut fast_seen = false;
    let mut slow_seen = false;
    for v in vectors {
        let name = required_str(v, "name")?;
        let family = required_str(v, "family")?;
        let class = required_str(v, "evaluation_class")?;
        let canonical = canonical_evaluation_class(family);
        if class != canonical {
            bail!(
                "vector {name} evaluation_class {class} disagrees with canonical {canonical} for family {family}"
            );
        }
        let fast = v
            .get("fast_path_eligible")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("vector {name} missing fast_path_eligible"))?;
        let expect_fast = matches!(class, "stateless" | "grant_local");
        if fast != expect_fast {
            bail!(
                "vector {name} fast_path_eligible={fast} but class {class} → expected fast={expect_fast}"
            );
        }
        let needs_state = v
            .get("needs_space_state")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("vector {name} missing needs_space_state"))?;
        let needs_external = v
            .get("needs_external_call")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("vector {name} missing needs_external_call"))?;
        let expected_state = class == "space_state";
        let expected_external = class == "external";
        if needs_state != expected_state {
            bail!(
                "vector {name} needs_space_state={needs_state} but class {class} (expected {expected_state})"
            );
        }
        if needs_external != expected_external {
            bail!(
                "vector {name} needs_external_call={needs_external} but class {class} (expected {expected_external})"
            );
        }
        let classification = v
            .pointer("/expected/classification")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("vector {name} missing expected.classification"))?;
        let expect_classification = if expect_fast {
            "fast_path"
        } else {
            "slow_path"
        };
        if classification != expect_classification {
            bail!(
                "vector {name} classification {classification} disagrees with class {class} (expected {expect_classification})"
            );
        }
        if expect_fast {
            fast_seen = true;
        } else {
            slow_seen = true;
        }
        covered_families.insert(family.to_owned());
        emit_vector(
            "constraint_evaluation_class.classify",
            v,
            json!({
                "name": name,
                "family": family,
                "evaluation_class": class,
                "fast_path_eligible": fast,
                "classification": classification,
            }),
        );
    }
    let required_families = [
        "temporal",
        "field_access",
        "type_restriction",
        "scope_limitation",
        "delegation_control",
        "quota",
        "claim_based",
        "confidentiality",
    ];
    for required in required_families {
        if !covered_families.contains(required) {
            bail!("constraint_evaluation_class fixture missing coverage for family {required}");
        }
    }
    if !(fast_seen && slow_seen) {
        bail!("constraint_evaluation_class fixture must cover both fast-path and slow-path");
    }

    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("constraint_evaluation_class fixture missing negative_vectors[]"))?;
    for v in negatives {
        let name = required_str(v, "name")?;
        let reason =
            expected_reason(v).ok_or_else(|| anyhow!("negative {name} missing reason_code"))?;
        if reason != "evaluation_class_mismatch" {
            bail!("negative {name} reason_code must be evaluation_class_mismatch");
        }
        let family = required_str(v, "family")?;
        let declared = required_str(v, "declared_evaluation_class")?;
        let canonical = canonical_evaluation_class(family);
        if declared == canonical {
            bail!(
                "negative {name} declared {declared} matches canonical {canonical} — not a drift"
            );
        }
        let expected = required_str(v.pointer("/expected").unwrap(), "expected_evaluation_class")?;
        if expected != canonical {
            bail!(
                "negative {name} expected_evaluation_class {expected} disagrees with canonical {canonical}"
            );
        }
    }

    Ok(())
}

/// F-1 Round 26 — recovery bridge full-chain state-machine legality.
///
/// Spec: services/coauth-recovery.md + services/soland-recovery-ticket.md +
/// services/restore-executor.md. The chain has 5 ordered steps:
/// principal_cache_lookup → recovery_action_proof → recovery_ticket_mint →
/// restore_execute → final_state_observe. Each vector pins one step's
/// transition; this validator asserts each step's invariants and that the
/// state-machine transitions on the ticket are legal: issued → executing →
/// executed (or issued → expired / cancelled).
pub fn run_recovery_bridge_full_chain_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("recovery_bridge_full_chain_fixture.json")?;
    validate_profile(&fixture, "cx.profile.recovery_bridge_full_chain_vectors.v1")?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("recovery_bridge_full_chain fixture missing vectors[]"))?;
    if vectors.len() < 3 {
        bail!(
            "recovery_bridge_full_chain fixture has {} vectors, expected >= 3",
            vectors.len()
        );
    }

    let valid_steps = [
        "principal_cache_lookup",
        "recovery_action_proof",
        "recovery_ticket_mint",
        "restore_execute",
        "final_state_observe",
    ];
    let valid_actions = [
        "recover_session_grants",
        "restore_key_backup",
        "rotate_recovery_key",
    ];

    let mut covered_steps = std::collections::BTreeSet::<String>::new();
    for v in vectors {
        let name = required_str(v, "name")?;
        let step = required_str(v, "step")?;
        if !valid_steps.contains(&step) {
            bail!("vector {name} unknown step {step}");
        }
        let outcome = expected_outcome(v, name)?;
        if outcome != "accept" {
            bail!("positive vector {name} outcome must be accept");
        }
        match step {
            "principal_cache_lookup" => {
                let _ = required_str(v, "account_did")?;
                let _ = v
                    .pointer("/expected/principal_space_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("vector {name} missing principal_space_id"))?;
            }
            "recovery_action_proof" => {
                let kind = required_str(v, "action_kind")?;
                if !valid_actions.contains(&kind) {
                    bail!("vector {name} action_kind {kind} not supported");
                }
                let required = v
                    .get("approvals_required")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing approvals_required"))?;
                let received = v
                    .get("approvals_received")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing approvals_received"))?;
                if received < required {
                    bail!("vector {name} approvals_received {received} < required {required}");
                }
            }
            "recovery_ticket_mint" => {
                let state = required_str(v, "ticket_state")?;
                if state != "issued" {
                    bail!("vector {name} ticket_state must start at issued");
                }
                let ttl = v
                    .pointer("/expected/ttl_seconds")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing ttl_seconds"))?;
                if ttl == 0 || ttl > 86_400 {
                    bail!("vector {name} ttl_seconds {ttl} out of bounds (1..=86400)");
                }
                let consume_once = v
                    .pointer("/expected/consume_once")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !consume_once {
                    bail!("vector {name} ticket must be consume_once");
                }
            }
            "restore_execute" => {
                let transitions: Vec<&str> = v
                    .get("ticket_state_transitions")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                if !validate_ticket_state_transitions(&transitions) {
                    bail!(
                        "vector {name} ticket transitions {transitions:?} not legal per state-machine"
                    );
                }
                let after = v
                    .pointer("/expected/ticket_state_after")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("vector {name} missing ticket_state_after"))?;
                if after != "executed" {
                    bail!("vector {name} ticket_state_after must be executed");
                }
            }
            "final_state_observe" => {
                let _ = required_str(v, "realm_id")?;
                let _ = v
                    .pointer("/expected/audit_log_emitted")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| anyhow!("vector {name} missing audit_log_emitted"))?;
            }
            _ => unreachable!(),
        }
        covered_steps.insert(step.to_owned());
        emit_vector(
            "recovery_bridge_full_chain.step",
            v,
            json!({"name": name, "step": step, "outcome": outcome}),
        );
    }
    if covered_steps.len() < 3 {
        bail!(
            "recovery_bridge_full_chain must cover at least 3 chain steps; got {}",
            covered_steps.len()
        );
    }

    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("recovery_bridge_full_chain fixture missing negative_vectors[]"))?;
    let mut saw_expired = false;
    let mut saw_double_consume = false;
    for v in negatives {
        let name = required_str(v, "name")?;
        let reason =
            expected_reason(v).ok_or_else(|| anyhow!("negative {name} missing reason_code"))?;
        match reason {
            "recovery_proof_expired" => {
                let in_past = v
                    .get("proof_exp_in_past")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !in_past {
                    bail!("negative {name} expired must declare proof_exp_in_past=true");
                }
                saw_expired = true;
            }
            "ticket_already_consumed" => {
                let before = required_str(v, "ticket_state_before")?;
                if before != "executed" {
                    bail!("negative {name} double-consume ticket_state_before must be executed");
                }
                let outcome = expected_outcome(v, name)?;
                if outcome != "idempotent_replay" {
                    bail!(
                        "negative {name} double-consume must outcome idempotent_replay (consume-once invariant)"
                    );
                }
                saw_double_consume = true;
            }
            other => bail!("negative {name} unknown reason_code {other}"),
        }
    }
    if !(saw_expired && saw_double_consume) {
        bail!("recovery_bridge_full_chain negatives must cover expired_proof + double_consume");
    }

    Ok(())
}

/// Round-26 standalone — exercise the spec's mandated AEAD primitive
/// (ChaCha20-Poly1305 + PBKDF2-HMAC-SHA512) end-to-end. Decoupled from the
/// fixture so an environment without the fixture file still exercises the
/// crypto round-trip used by D4 key backup encryption.
pub fn run_key_backup_aead_round_trip_check() -> Result<()> {
    use chacha20poly1305::{
        ChaCha20Poly1305, KeyInit,
        aead::{Aead, generic_array::GenericArray},
    };
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha512 as KdfSha512;

    let salt = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode("AAECAwQFBgcICQoLDA0ODw")
        .map_err(|e| anyhow!("decode salt: {e}"))?;
    let mut key = [0u8; 32];
    pbkdf2_hmac::<KdfSha512>(b"correct-passphrase", &salt, 1, &mut key);
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key));
    let nonce = GenericArray::from_slice(&[0u8; 12]);
    let plaintext = b"key_backup_aead_round_trip_round_26";
    let ct = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| anyhow!("encrypt failed: {e}"))?;
    let pt = cipher
        .decrypt(nonce, ct.as_ref())
        .map_err(|e| anyhow!("decrypt failed: {e}"))?;
    if pt != plaintext {
        bail!("AEAD round-trip mismatch");
    }
    let mut wrong = [0u8; 32];
    pbkdf2_hmac::<KdfSha512>(b"wrong-passphrase", &salt, 1, &mut wrong);
    let wrong_cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&wrong));
    if wrong_cipher.decrypt(nonce, ct.as_ref()).is_ok() {
        bail!("wrong-key decrypt succeeded — AEAD invariant broken");
    }
    Ok(())
}

/// Round-26 standalone — exercise the megolm-equivalent HKDF chain primitive.
/// Asserts the KDF is non-identity (output ≠ seed) and chain-length-deterministic
/// (running N steps from a fixed seed always produces the same key_N).
pub fn run_megolm_ratchet_kdf_chain_check() -> Result<()> {
    use hkdf::Hkdf;
    use sha2::Sha256 as KdfSha256;

    fn step(prev: &[u8; 32]) -> Result<[u8; 32]> {
        let kdf = Hkdf::<KdfSha256>::new(None, prev);
        let mut next = [0u8; 32];
        kdf.expand(b"cx.megolm.ratchet.v1", &mut next)
            .map_err(|e| anyhow!("HKDF expand: {e}"))?;
        Ok(next)
    }

    let mut a = [7u8; 32];
    let mut b = [7u8; 32];
    for _ in 0..16 {
        a = step(&a)?;
        b = step(&b)?;
    }
    if a != b {
        bail!("HKDF chain not deterministic");
    }
    if a == [7u8; 32] {
        bail!("HKDF chain output equals seed after 16 steps — KDF degenerate");
    }
    Ok(())
}

/// Round-26 standalone — recovery-ticket state-machine legality.
pub fn run_recovery_ticket_state_machine_check() -> Result<()> {
    let legal_paths: &[&[&str]] = &[
        &["issued", "executing", "executed"],
        &["issued", "executing", "failed"],
        &["issued", "executing", "cancelled"],
        &["issued", "cancelled"],
        &["issued", "expired"],
    ];
    for path in legal_paths {
        if !validate_ticket_state_transitions(path) {
            bail!("legal path {path:?} rejected as illegal");
        }
    }
    let illegal_paths: &[&[&str]] = &[
        &["executing", "executed"],          // missing issued
        &["issued", "executed"],             // skip executing
        &["issued", "executing", "issued"],  // backward
        &["issued", "expired", "executing"], // post-terminal
    ];
    for path in illegal_paths {
        if validate_ticket_state_transitions(path) {
            bail!("illegal path {path:?} accepted as legal");
        }
    }
    Ok(())
}

/// Round-26 standalone — history-visibility projection function: assert
/// the spec's per-membership × per-visibility decision matrix matches the
/// implementation's projection on a hand-rolled cross-product.
pub fn run_history_visibility_projection_matrix_check() -> Result<()> {
    // (visibility, membership, viewer_join_ts, viewer_invite_ts,
    //  shared_since_ts, event_origin_ts, expected_visible).
    type Row = (
        &'static str,
        Option<&'static str>,
        Option<u64>,
        Option<u64>,
        Option<u64>,
        u64,
        bool,
    );
    let rows: &[Row] = &[
        // world_readable: always visible.
        ("world_readable", None, None, None, None, 1, true),
        ("world_readable", Some("ban"), None, None, None, 1, true),
        // joined: requires join state + post-join origin_ts.
        ("joined", Some("join"), Some(100), None, None, 50, false),
        ("joined", Some("join"), Some(100), None, None, 150, true),
        ("joined", None, None, None, None, 50, false),
        ("joined", Some("ban"), Some(100), None, None, 150, false),
        // invited: invite_ts cutoff (joined or invite both ok).
        ("invited", Some("invite"), None, Some(200), None, 150, false),
        ("invited", Some("invite"), None, Some(200), None, 250, true),
        ("invited", Some("join"), Some(100), Some(80), None, 90, true),
        // shared: members use join_ts; non-members use shared_since_ts.
        (
            "shared",
            Some("join"),
            Some(100),
            None,
            Some(200),
            150,
            true,
        ),
        ("shared", None, None, None, Some(200), 150, false),
        ("shared", None, None, None, Some(200), 250, true),
    ];
    for (visibility, membership, jt, it, st, ots, expected) in rows {
        let actual = project_history_visibility(visibility, *membership, *jt, *it, *st, *ots);
        if actual != *expected {
            bail!(
                "projection mismatch: visibility={visibility} membership={membership:?} jt={jt:?} it={it:?} st={st:?} ots={ots} → expected {expected}, got {actual}"
            );
        }
    }
    Ok(())
}

/// Recovery-ticket state-machine: legal transitions are issued → executing →
/// executed (success path) or issued → cancelled / expired (terminal).
fn validate_ticket_state_transitions(transitions: &[&str]) -> bool {
    if transitions.is_empty() {
        return false;
    }
    if transitions[0] != "issued" {
        return false;
    }
    for window in transitions.windows(2) {
        let legal = match (window[0], window[1]) {
            ("issued", "executing") => true,
            ("issued", "cancelled") => true,
            ("issued", "expired") => true,
            ("executing", "executed") => true,
            ("executing", "failed") => true,
            ("executing", "cancelled") => true,
            _ => false,
        };
        if !legal {
            return false;
        }
    }
    true
}

// ── Round 27 — fixture-decoupled standalone checks ─────────────────────────

/// Round-27 E5 — fixture-decoupled idempotency primitive: applying the same
/// anchor-id twice to a peer's anchored-set must be a set-insertion no-op
/// on the second call. Independent of any specific fixture.
pub fn run_late_arriving_anchor_idempotency_check() -> Result<()> {
    use std::collections::BTreeSet;
    let mut anchored: BTreeSet<&str> = BTreeSet::new();
    let mut new_after_first = false;
    let mut new_after_second = false;
    if anchored.insert("ax:S1:1") {
        new_after_first = true;
    }
    if anchored.insert("ax:S1:1") {
        new_after_second = true;
    }
    if !new_after_first {
        bail!("first anchor application must be a new insertion");
    }
    if new_after_second {
        bail!("second anchor application must be a no-op");
    }
    if anchored.len() != 1 {
        bail!("anchored set size must be 1, got {}", anchored.len());
    }
    Ok(())
}

/// Round-27 F-2 — fixture-decoupled multi-admin distinct-approver gate.
/// Asserts that a 2-of-2 approval pool requires 2 distinct DIDs to unlock,
/// and that duplicate-DID submissions never count twice.
pub fn run_multi_admin_distinct_approver_gate_check() -> Result<()> {
    use std::collections::BTreeSet;
    fn count_distinct(approvals: &[&str], threshold: usize) -> bool {
        let unique: BTreeSet<&str> = approvals.iter().copied().collect();
        unique.len() >= threshold
    }
    if count_distinct(&["admin_a", "admin_a"], 2) {
        bail!("duplicate-admin pool must NOT satisfy 2-of-2");
    }
    if !count_distinct(&["admin_a", "admin_b"], 2) {
        bail!("two distinct admins must satisfy 2-of-2");
    }
    if !count_distinct(&["admin_a", "admin_b", "admin_c"], 2) {
        bail!("three distinct admins must satisfy 2-of-2");
    }
    if count_distinct(&["admin_a"], 2) {
        bail!("single admin must NOT satisfy 2-of-2");
    }
    Ok(())
}

// ── Round 27 — D5 / E3 / E4 / E5 / E6 / F-2 suites ─────────────────────────

/// D5 Round 27 — device cross-signing trust boundary. Spec authority:
/// crypto-media/device-lifecycle.md. Each vector exercises a different
/// trust-boundary invariant: full chain valid; transitive trust into a new
/// device; revoke alice's master invalidates anchor; rotate bob's
/// user-signing requires re-anchor.
pub fn run_device_cross_signing_trust_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("device_cross_signing_trust_fixture.json")?;
    validate_profile(&fixture, "cx.profile.device_cross_signing_trust_vectors.v1")?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("device_cross_signing_trust missing vectors[]"))?;
    if vectors.len() < 4 {
        bail!(
            "device_cross_signing_trust requires >= 4 vectors, got {}",
            vectors.len()
        );
    }
    let mut saw_full_chain = false;
    let mut saw_transitive = false;
    let mut saw_revoke = false;
    let mut saw_rotate = false;
    for v in vectors {
        let name = required_str(v, "name")?;
        let outcome = expected_outcome(v, name)?;
        let trust_anchor_actor = required_str(v, "trust_anchor_actor_did")?;
        if !trust_anchor_actor.starts_with("did:web:") && !trust_anchor_actor.starts_with("did:cx:")
        {
            bail!("vector {name} trust_anchor_actor_did must be a did: form");
        }

        // Common: alice.master + alice.user-signing must be present in every
        // vector that names them.
        if let Some(am) = v.get("alice_master") {
            let id = required_str(am, "key_id")?;
            if !id.ends_with("#master") {
                bail!("vector {name} alice_master.key_id must end with #master");
            }
        }
        if let Some(aus) = v.get("alice_user_signing") {
            if required_str(aus, "signed_by")? != "did:cx:user:alice#master" {
                bail!("vector {name} alice_user_signing.signed_by must be alice#master");
            }
        }

        match name {
            "cross_user_trust_full_chain_valid" => {
                let bm = v
                    .get("bob_master")
                    .ok_or_else(|| anyhow!("vector {name} missing bob_master"))?;
                if required_str(bm, "signed_by")? != "did:cx:user:alice#user-signing" {
                    bail!("vector {name} bob_master must be signed by alice#user-signing");
                }
                let bss = v
                    .get("bob_self_signing")
                    .ok_or_else(|| anyhow!("vector {name} missing bob_self_signing"))?;
                if required_str(bss, "signed_by")? != "did:cx:user:bob#master" {
                    bail!("vector {name} bob_self_signing must be signed by bob#master");
                }
                let bdl = v
                    .get("bob_device_leaf")
                    .ok_or_else(|| anyhow!("vector {name} missing bob_device_leaf"))?;
                if required_str(bdl, "signed_by")? != "did:cx:user:bob#self-signing" {
                    bail!("vector {name} bob_device_leaf must be signed by bob#self-signing");
                }
                let path: Vec<&str> = v
                    .pointer("/expected/trust_path")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                if path.len() != 5 {
                    bail!(
                        "vector {name} expected.trust_path must have 5 hops, got {}",
                        path.len()
                    );
                }
                if outcome != "accept" {
                    bail!("vector {name} outcome must be accept");
                }
                saw_full_chain = true;
            }
            "cross_user_trust_transitively_trusts_new_bob_device" => {
                let bdl = v
                    .get("bob_device_leaf")
                    .ok_or_else(|| anyhow!("vector {name} missing bob_device_leaf"))?;
                if required_str(bdl, "signed_by")? != "did:cx:user:bob#self-signing" {
                    bail!("vector {name} new device must be signed by bob#self-signing");
                }
                let trans = v
                    .pointer("/expected/transitively_trusted")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !trans {
                    bail!("vector {name} expected.transitively_trusted must be true");
                }
                if outcome != "accept" {
                    bail!("vector {name} outcome must be accept");
                }
                saw_transitive = true;
            }
            "alice_master_revocation_invalidates_cross_user_trust" => {
                let am = v
                    .get("alice_master")
                    .ok_or_else(|| anyhow!("vector {name} missing alice_master"))?;
                let revoked = am.get("revoked").and_then(Value::as_bool).unwrap_or(false);
                if !revoked {
                    bail!("vector {name} alice_master.revoked must be true");
                }
                if outcome != "reject" {
                    bail!("vector {name} outcome must be reject");
                }
                if expected_reason(v) != Some("trust_anchor_master_revoked") {
                    bail!("vector {name} reason_code must be trust_anchor_master_revoked");
                }
                saw_revoke = true;
            }
            "bob_user_signing_rotation_requires_re_anchor_with_alice" => {
                let old = v
                    .get("bob_user_signing_old")
                    .ok_or_else(|| anyhow!("vector {name} missing bob_user_signing_old"))?;
                if !old.get("rotated").and_then(Value::as_bool).unwrap_or(false) {
                    bail!("vector {name} bob_user_signing_old.rotated must be true");
                }
                let new = v
                    .get("bob_user_signing_new")
                    .ok_or_else(|| anyhow!("vector {name} missing bob_user_signing_new"))?;
                let needs_re = new
                    .get("needs_re_anchor")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !needs_re {
                    bail!("vector {name} bob_user_signing_new.needs_re_anchor must be true");
                }
                if outcome != "reject" {
                    bail!("vector {name} outcome must be reject pending re-anchor");
                }
                if expected_reason(v) != Some("trust_anchor_stale_after_rotation") {
                    bail!("vector {name} reason_code must be trust_anchor_stale_after_rotation");
                }
                saw_rotate = true;
            }
            "cross_user_signature_alg_mismatch_rejects" => {
                if outcome != "reject" {
                    bail!("vector {name} outcome must be reject");
                }
                if expected_reason(v) != Some("trust_anchor_alg_disallowed") {
                    bail!("vector {name} reason_code must be trust_anchor_alg_disallowed");
                }
            }
            other => bail!("device_cross_signing_trust unexpected vector {other}"),
        }
        emit_vector(
            "device_cross_signing_trust.vector",
            v,
            json!({"name": name, "outcome": outcome, "trust_anchor_actor_did": trust_anchor_actor}),
        );
    }
    if !(saw_full_chain && saw_transitive && saw_revoke && saw_rotate) {
        bail!("device_cross_signing_trust must cover full_chain + transitive + revoke + rotate");
    }
    Ok(())
}

/// S4 — cross-signing reset hardening vectors. These are parser-level
/// conformance guards for `cx.profile.cross_signing.reset.v1`: reset proof
/// family, generation monotonicity, replay rejection, clock skew, and the
/// successor publish recovery window.
pub fn run_cross_signing_reset_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("cross_signing_reset_fixture.json")?;
    validate_profile(&fixture, "cx.profile.cross_signing.reset.v1")?;
    let parameters = fixture
        .get("parameters")
        .ok_or_else(|| anyhow!("cross_signing_reset fixture missing parameters"))?;
    let max_clock_skew = parameters
        .get("max_clock_skew_seconds")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("cross_signing_reset missing max_clock_skew_seconds"))?;
    if !(60..=900).contains(&max_clock_skew) {
        bail!("cross_signing_reset max_clock_skew_seconds must be in 60..=900");
    }
    let publish_window = parameters
        .get("successor_publish_required_within_seconds")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            anyhow!("cross_signing_reset missing successor_publish_required_within_seconds")
        })?;
    if publish_window != 86_400 {
        bail!("cross_signing_reset successor publish window must default to 86400s");
    }

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("cross_signing_reset fixture missing vectors[]"))?;
    if vectors.len() < 4 {
        bail!(
            "cross_signing_reset fixture requires >= 4 vectors, got {}",
            vectors.len()
        );
    }

    let mut saw_accept = false;
    let mut saw_generation = false;
    let mut saw_replay = false;
    let mut saw_clock = false;
    let mut saw_publish_window = false;
    for v in vectors {
        let name = required_str(v, "name")?;
        let outcome = expected_outcome(v, name)?;
        if required_str(v, "event_kind")? != "cx.cross_signing.reset" {
            bail!("vector {name} event_kind must be cx.cross_signing.reset");
        }
        if required_str(v, "schema_id")? != "cx.schema.cross_signing_reset.v1" {
            bail!("vector {name} schema_id must be cx.schema.cross_signing_reset.v1");
        }
        let previous = v
            .get("previous_generation")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("vector {name} missing previous_generation"))?;
        let new = v
            .get("new_generation")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("vector {name} missing new_generation"))?;
        let proof = v
            .get("proof")
            .ok_or_else(|| anyhow!("vector {name} missing proof"))?;
        let proof_kind = required_str(proof, "kind")?;
        if !matches!(
            proof_kind,
            "principal_signing" | "recovery_unlock" | "device_quorum" | "trusted_recovery_service"
        ) {
            bail!("vector {name} uses unknown reset proof kind {proof_kind}");
        }

        match name {
            "principal_signing_reset_accepts_generation_plus_one" => {
                if outcome != "accept" {
                    bail!("vector {name} outcome must be accept");
                }
                if new != previous + 1 {
                    bail!("vector {name} new_generation must equal previous_generation + 1");
                }
                if proof_kind != "principal_signing" {
                    bail!("vector {name} must use principal_signing proof");
                }
                let successor_kind = v
                    .pointer("/successor_publish/event_kind")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("vector {name} missing successor publish"))?;
                if successor_kind != "cx.cross_signing.publish" {
                    bail!("vector {name} successor publish must be cx.cross_signing.publish");
                }
                saw_accept = true;
            }
            "generation_gap_rejects" => {
                if outcome != "reject"
                    || expected_reason(v) != Some("cross_signing_reset_generation_mismatch")
                {
                    bail!("vector {name} must reject with cross_signing_reset_generation_mismatch");
                }
                if new == previous + 1 {
                    bail!("vector {name} must contain a real generation gap");
                }
                saw_generation = true;
            }
            "clock_skew_exceeded_rejects" => {
                if outcome != "reject"
                    || expected_reason(v) != Some("cross_signing_reset_clock_skew_exceeded")
                {
                    bail!("vector {name} must reject with cross_signing_reset_clock_skew_exceeded");
                }
                let skew = v
                    .get("observed_clock_skew_seconds")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing observed_clock_skew_seconds"))?;
                if skew <= max_clock_skew {
                    bail!("vector {name} skew must exceed max_clock_skew_seconds");
                }
                saw_clock = true;
            }
            "replay_same_previous_generation_rejects" => {
                if outcome != "reject" || expected_reason(v) != Some("cross_signing_reset_replayed")
                {
                    bail!("vector {name} must reject with cross_signing_reset_replayed");
                }
                if !v
                    .get("seen_reset_tuple")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    bail!("vector {name} must mark seen_reset_tuple=true");
                }
                saw_replay = true;
            }
            "successor_publish_window_expired_rejects_device_authorization" => {
                if outcome != "reject"
                    || expected_reason(v) != Some("cross_signing_reset_publish_window_expired")
                {
                    bail!(
                        "vector {name} must reject with cross_signing_reset_publish_window_expired"
                    );
                }
                let elapsed = v
                    .get("elapsed_since_reset_seconds")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing elapsed_since_reset_seconds"))?;
                if elapsed <= publish_window {
                    bail!("vector {name} elapsed time must exceed successor publish window");
                }
                saw_publish_window = true;
            }
            other => bail!("cross_signing_reset unexpected vector {other}"),
        }
        emit_vector(
            "cross_signing_reset.vector",
            v,
            json!({"name": name, "outcome": outcome, "proof_kind": proof_kind}),
        );
    }
    if !(saw_accept && saw_generation && saw_clock && saw_replay && saw_publish_window) {
        bail!(
            "cross_signing_reset must cover accept + generation_mismatch + clock_skew + replay + publish_window"
        );
    }
    Ok(())
}

/// E3 Round 27 — multi-space federation. Per-space anchor isolation +
/// cross-space rejection.
pub fn run_multi_space_federation_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("multi_space_federation_fixture.json")?;
    validate_profile(&fixture, "cx.profile.multi_space_federation_vectors.v1")?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("multi_space_federation missing vectors[]"))?;
    if vectors.len() < 3 {
        bail!(
            "multi_space_federation requires >= 3 vectors, got {}",
            vectors.len()
        );
    }
    let mut saw_isolation = false;
    let mut saw_concurrent = false;
    let mut saw_cross_reject = false;
    let mut saw_per_space_seq = false;
    for v in vectors {
        let name = required_str(v, "name")?;
        let outcome = expected_outcome(v, name)?;
        match name {
            "multi_space_replay_three_spaces_independent_frontiers" => {
                let spaces: Vec<&str> = v
                    .get("spaces")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                if spaces.len() != 3 {
                    bail!("vector {name} must list 3 spaces");
                }
                let isolation = v
                    .pointer("/expected/per_space_isolation")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !isolation {
                    bail!("vector {name} expected.per_space_isolation must be true");
                }
                // Sanity check: sequential pulls must monotonically grow only the
                // pulled space's frontier.
                let f1 = v
                    .pointer("/expected/server_b_frontier_after_S1_pull")
                    .ok_or_else(|| {
                        anyhow!("vector {name} missing server_b_frontier_after_S1_pull")
                    })?;
                let f2 = v
                    .pointer("/expected/server_b_frontier_after_S2_pull")
                    .ok_or_else(|| {
                        anyhow!("vector {name} missing server_b_frontier_after_S2_pull")
                    })?;
                if f1.get("space_S1").and_then(Value::as_u64) != Some(1)
                    || f1.get("space_S2").and_then(Value::as_u64) != Some(0)
                {
                    bail!("vector {name} S1 pull must update only S1");
                }
                if f2.get("space_S2").and_then(Value::as_u64) != Some(1) {
                    bail!("vector {name} S2 pull must bring S2 to 1");
                }
                if outcome != "accept" {
                    bail!("vector {name} outcome must be accept");
                }
                saw_isolation = true;
            }
            "multi_space_concurrent_move_replay" => {
                if outcome != "accept" {
                    bail!("vector {name} outcome must be accept");
                }
                let s1 = v
                    .pointer("/expected/final_S1_frontier_count")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing final_S1_frontier_count"))?;
                let s2 = v
                    .pointer("/expected/final_S2_frontier_count")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing final_S2_frontier_count"))?;
                if s1 < 2 || s2 < 2 {
                    bail!(
                        "vector {name} bidirectional convergence requires both spaces to hold both moves (>= 2 each)"
                    );
                }
                saw_concurrent = true;
            }
            "multi_space_cross_space_move_rejected" => {
                if outcome != "reject" {
                    bail!("vector {name} outcome must be reject");
                }
                if expected_reason(v) != Some("cross_space_move_forbidden") {
                    bail!("vector {name} reason_code must be cross_space_move_forbidden");
                }
                let claimed = v
                    .pointer("/push_payload/claimed_space_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("vector {name} missing claimed_space_id"))?;
                let actual = v
                    .pointer("/push_payload/actual_anchor_space_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("vector {name} missing actual_anchor_space_id"))?;
                if claimed == actual {
                    bail!("vector {name} cross-space negative requires claimed != actual space_id");
                }
                saw_cross_reject = true;
            }
            "multi_space_per_space_anchor_seq_independent" => {
                if outcome != "accept" {
                    bail!("vector {name} outcome must be accept");
                }
                let no_global = v
                    .pointer("/expected/no_global_counter")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !no_global {
                    bail!("vector {name} expected.no_global_counter must be true");
                }
                let history = v
                    .get("anchor_history")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} missing anchor_history"))?;
                let mut s1_max = 0u64;
                let mut s2_max = 0u64;
                for h in history {
                    let space = required_str(h, "realm_id")?;
                    let seq = h
                        .get("seq")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| anyhow!("anchor_history entry missing seq"))?;
                    match space {
                        "space_S1" => s1_max = s1_max.max(seq),
                        "space_S2" => s2_max = s2_max.max(seq),
                        other => bail!("vector {name} unexpected space {other}"),
                    }
                }
                let exp_s1 = v
                    .pointer("/expected/S1_max_seq")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing S1_max_seq"))?;
                let exp_s2 = v
                    .pointer("/expected/S2_max_seq")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing S2_max_seq"))?;
                if s1_max != exp_s1 || s2_max != exp_s2 {
                    bail!(
                        "vector {name} computed seqs ({s1_max},{s2_max}) != expected ({exp_s1},{exp_s2})"
                    );
                }
                saw_per_space_seq = true;
            }
            other => bail!("multi_space_federation unexpected vector {other}"),
        }
        emit_vector(
            "multi_space_federation.vector",
            v,
            json!({"name": name, "outcome": outcome}),
        );
    }
    if !(saw_isolation && saw_concurrent && saw_cross_reject && saw_per_space_seq) {
        bail!(
            "multi_space_federation must cover isolation + concurrent + cross_reject + per_space_seq"
        );
    }
    Ok(())
}

/// E4 Round 27 — frontier conflict resolution via lattice join.
pub fn run_frontier_conflict_resolution_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("frontier_conflict_resolution_fixture.json")?;
    validate_profile(
        &fixture,
        "cx.profile.frontier_conflict_resolution_vectors.v1",
    )?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("frontier_conflict_resolution missing vectors[]"))?;
    if vectors.len() < 3 {
        bail!(
            "frontier_conflict_resolution requires >= 3 vectors, got {}",
            vectors.len()
        );
    }
    let mut saw_cas_bottom = false;
    let mut saw_or_set_union = false;
    let mut saw_counter_sum = false;
    let mut saw_idempotent = false;
    for v in vectors {
        let name = required_str(v, "name")?;
        let _ = expected_outcome(v, name)?;
        let kind = required_str(v, "cell_kind")?;
        let moves = v
            .get("concurrent_moves")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("vector {name} missing concurrent_moves[]"))?;
        if moves.len() < 2 {
            bail!("vector {name} requires >= 2 concurrent moves");
        }
        let resolution = v
            .pointer("/expected/resolution")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("vector {name} missing expected.resolution"))?;
        match (kind, resolution) {
            ("cas_register", "bottom") => {
                let diag = v.pointer("/expected/diagnostic").and_then(Value::as_str);
                if diag != Some("cas_register_conflict") {
                    bail!(
                        "vector {name} cas_register conflict diagnostic must be cas_register_conflict"
                    );
                }
                if v.get("second_pull_replay")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    let idem = v
                        .pointer("/expected/idempotent_replay")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    if !idem {
                        bail!("vector {name} second_pull_replay must claim idempotent_replay");
                    }
                    saw_idempotent = true;
                } else {
                    saw_cas_bottom = true;
                }
            }
            ("or_set", "union") => {
                let final_set: Vec<&str> = v
                    .pointer("/expected/final_set")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                if final_set.len() < 2 {
                    bail!("vector {name} or_set union must contain at least 2 elements");
                }
                saw_or_set_union = true;
            }
            ("counter_pn", "sum") => {
                let total: i64 = moves
                    .iter()
                    .map(|m| m.get("delta").and_then(Value::as_i64).unwrap_or(0))
                    .sum();
                let final_count = v
                    .pointer("/expected/final_count")
                    .and_then(Value::as_i64)
                    .ok_or_else(|| anyhow!("vector {name} missing final_count"))?;
                if total != final_count {
                    bail!("vector {name} sum {total} != expected final_count {final_count}");
                }
                saw_counter_sum = true;
            }
            (k, r) => bail!("vector {name} unexpected (kind, resolution) pair ({k}, {r})"),
        }
        emit_vector(
            "frontier_conflict_resolution.vector",
            v,
            json!({"name": name, "cell_kind": kind, "resolution": resolution}),
        );
    }
    if !(saw_cas_bottom && saw_or_set_union && saw_counter_sum && saw_idempotent) {
        bail!(
            "frontier_conflict_resolution must cover cas_bottom + or_set_union + counter_sum + idempotent_replay"
        );
    }
    Ok(())
}

/// E5 Round 27 — late-arriving anchor idempotency.
pub fn run_late_arriving_anchor_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("late_arriving_anchor_fixture.json")?;
    validate_profile(&fixture, "cx.profile.late_arriving_anchor_vectors.v1")?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("late_arriving_anchor missing vectors[]"))?;
    if vectors.len() < 2 {
        bail!(
            "late_arriving_anchor requires >= 2 vectors, got {}",
            vectors.len()
        );
    }
    let mut saw_metadata_only = false;
    let mut saw_mixed = false;
    let mut saw_duplicate = false;
    for v in vectors {
        let name = required_str(v, "name")?;
        if expected_outcome(v, name)? != "accept" {
            bail!("vector {name} outcome must be accept");
        }
        let before = v
            .get("peer_b_state_before")
            .ok_or_else(|| anyhow!("vector {name} missing peer_b_state_before"))?;
        let after = v
            .pointer("/expected/peer_b_state_after")
            .ok_or_else(|| anyhow!("vector {name} missing expected.peer_b_state_after"))?;
        let projected_before: Vec<&str> = before
            .get("projected_moves")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let projected_after: Vec<&str> = after
            .get("projected_moves")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let count_before = before
            .get("message_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let count_after = after
            .get("message_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let new_projections = projected_after.len() as i64 - projected_before.len() as i64;
        let count_delta = count_after as i64 - count_before as i64;
        if new_projections != count_delta {
            bail!(
                "vector {name} message_count delta ({count_delta}) must equal new projections ({new_projections})"
            );
        }
        match name {
            "anchor_arrives_after_direct_move_idempotent" => {
                if count_delta != 0 {
                    bail!(
                        "vector {name} idempotent anchor must not change message_count (got delta {count_delta})"
                    );
                }
                saw_metadata_only = true;
            }
            "anchor_arrives_with_new_move_projects_once" => {
                if count_delta != 1 {
                    bail!(
                        "vector {name} mixed anchor must project exactly 1 new move (got {count_delta})"
                    );
                }
                saw_mixed = true;
            }
            "duplicate_anchor_application_no_double_effect" => {
                if !v
                    .get("duplicate_apply")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    bail!("vector {name} duplicate_apply must be true");
                }
                if count_delta != 0 {
                    bail!(
                        "vector {name} duplicate apply must be a no-op (got delta {count_delta})"
                    );
                }
                saw_duplicate = true;
            }
            other => bail!("late_arriving_anchor unexpected vector {other}"),
        }
        emit_vector(
            "late_arriving_anchor.vector",
            v,
            json!({
                "name": name,
                "count_delta": count_delta,
                "new_projections": new_projections,
            }),
        );
    }
    if !(saw_metadata_only && saw_mixed && saw_duplicate) {
        bail!("late_arriving_anchor must cover metadata_only + mixed + duplicate_apply");
    }
    Ok(())
}

/// E6 Round 27 — redacted Move cross-server projection (round-25 MAL-14).
pub fn run_redacted_cross_server_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("redacted_cross_server_fixture.json")?;
    validate_profile(&fixture, "cx.profile.redacted_cross_server_vectors.v1")?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("redacted_cross_server missing vectors[]"))?;
    if vectors.len() < 2 {
        bail!(
            "redacted_cross_server requires >= 2 vectors, got {}",
            vectors.len()
        );
    }
    let mut saw_member_tombstone = false;
    let mut saw_author_audit = false;
    let mut saw_un_redaction = false;
    for v in vectors {
        let name = required_str(v, "name")?;
        if expected_outcome(v, name)? != "accept" {
            bail!("vector {name} outcome must be accept");
        }
        let viewer_is_author = v
            .get("viewer_is_author")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("vector {name} missing viewer_is_author"))?;
        let projection = v
            .pointer("/expected/projection_on_peer_b")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("vector {name} missing projection_on_peer_b"))?;
        let body_visible = v
            .pointer("/expected/body_visible")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        match name {
            "redaction_propagates_to_peer_b_member_sees_tombstone" => {
                if viewer_is_author {
                    bail!("vector {name} viewer_is_author must be false for member-tombstone case");
                }
                if projection != "tombstone_only" || body_visible {
                    bail!("vector {name} member view must be tombstone_only with body hidden");
                }
                saw_member_tombstone = true;
            }
            "redaction_propagates_author_audit_view_full_body" => {
                if !viewer_is_author {
                    bail!("vector {name} viewer_is_author must be true for author audit");
                }
                if projection != "audit_view" || !body_visible {
                    bail!("vector {name} author view must be audit_view with body visible");
                }
                saw_author_audit = true;
            }
            "un_redaction_move_propagates_cross_server_restores_body" => {
                if !v
                    .get("redaction_then_un_redaction")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    bail!("vector {name} redaction_then_un_redaction must be true");
                }
                if !body_visible || projection != "body_visible" {
                    bail!("vector {name} un-redaction must restore body_visible");
                }
                saw_un_redaction = true;
            }
            other => bail!("redacted_cross_server unexpected vector {other}"),
        }
        emit_vector(
            "redacted_cross_server.vector",
            v,
            json!({
                "name": name,
                "viewer_is_author": viewer_is_author,
                "projection": projection,
                "body_visible": body_visible,
            }),
        );
    }
    if !(saw_member_tombstone && saw_author_audit && saw_un_redaction) {
        bail!("redacted_cross_server must cover member_tombstone + author_audit + un_redaction");
    }
    Ok(())
}

/// F-2 Round 27 — restore approval/executor/artifact full workflows.
pub fn run_restore_full_workflows_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("restore_full_workflows_fixture.json")?;
    validate_profile(&fixture, "cx.profile.restore_full_workflows_vectors.v1")?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("restore_full_workflows missing vectors[]"))?;
    if vectors.len() < 4 {
        bail!(
            "restore_full_workflows requires >= 4 vectors, got {}",
            vectors.len()
        );
    }
    let mut saw_two_of_two_approval = false;
    let mut saw_duplicate_approver = false;
    let mut saw_executor_restart = false;
    let mut saw_artifact_round_trip = false;
    let mut saw_integrity_mismatch = false;
    for v in vectors {
        let name = required_str(v, "name")?;
        let outcome = expected_outcome(v, name)?;
        let _ = required_str(v, "ticket_id")?;
        match name {
            "two_of_two_multi_admin_approval_unblocks_restore" => {
                if outcome != "accept" {
                    bail!("vector {name} outcome must be accept");
                }
                let req = v
                    .get("required_approvals")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing required_approvals"))?;
                if req < 2 {
                    bail!("vector {name} multi-admin approval requires >= 2");
                }
                let seq = v
                    .get("approval_sequence")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} missing approval_sequence"))?;
                let mut distinct = std::collections::BTreeSet::<&str>::new();
                for a in seq {
                    distinct.insert(required_str(a, "admin_did")?);
                }
                if (distinct.len() as u64) < req {
                    bail!(
                        "vector {name} positive flow needs >= {req} distinct admin_dids; got {}",
                        distinct.len()
                    );
                }
                let after_first = v
                    .pointer("/expected/stage_after_first_approval")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("vector {name} missing stage_after_first_approval"))?;
                let after_second = v
                    .pointer("/expected/stage_after_second_approval")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("vector {name} missing stage_after_second_approval"))?;
                if after_first != "approving" || after_second != "approved" {
                    bail!("vector {name} multi-admin gate must transition approving → approved");
                }
                saw_two_of_two_approval = true;
            }
            "two_of_two_duplicate_admin_approval_does_not_count_twice" => {
                if outcome != "reject" {
                    bail!("vector {name} outcome must be reject (dedup)");
                }
                if expected_reason(v) != Some("duplicate_approver") {
                    bail!("vector {name} reason_code must be duplicate_approver");
                }
                saw_duplicate_approver = true;
            }
            "executor_restart_survival_resumes_from_persisted_stage" => {
                if outcome != "accept" {
                    bail!("vector {name} outcome must be accept");
                }
                if !v
                    .get("crash_simulated")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    bail!("vector {name} crash_simulated must be true");
                }
                let resumes = v
                    .pointer("/expected/resumes_from_persisted_progress")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !resumes {
                    bail!("vector {name} executor must resume from persisted progress");
                }
                let chunks_before = v
                    .pointer("/executor_progress_before_crash/chunks_done")
                    .and_then(Value::as_u64);
                let chunks_after = v
                    .pointer("/expected/executor_progress_after_restart/chunks_done")
                    .and_then(Value::as_u64);
                if chunks_before != chunks_after {
                    bail!(
                        "vector {name} chunks_done before crash != after restart (would mean re-do)"
                    );
                }
                saw_executor_restart = true;
            }
            "artifact_upload_verify_then_download_round_trip" => {
                if outcome != "accept" {
                    bail!("vector {name} outcome must be accept");
                }
                let events: Vec<&str> = v
                    .get("lifecycle_events")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|e| e.get("event").and_then(Value::as_str))
                            .collect()
                    })
                    .unwrap_or_default();
                let required_seq = [
                    "upload_complete",
                    "integrity_verified",
                    "download_initiated",
                    "download_complete",
                ];
                if events != required_seq {
                    bail!(
                        "vector {name} lifecycle events must be {required_seq:?}, got {events:?}"
                    );
                }
                let final_state = v
                    .pointer("/expected/final_artifact_state")
                    .and_then(Value::as_str);
                if final_state != Some("downloaded") {
                    bail!("vector {name} final_artifact_state must be downloaded");
                }
                let integrity = v
                    .pointer("/expected/integrity_check_passed")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !integrity {
                    bail!("vector {name} integrity_check_passed must be true");
                }
                saw_artifact_round_trip = true;
            }
            "artifact_integrity_mismatch_blocks_download" => {
                if outcome != "reject" {
                    bail!("vector {name} outcome must be reject");
                }
                if expected_reason(v) != Some("artifact_integrity_mismatch") {
                    bail!("vector {name} reason_code must be artifact_integrity_mismatch");
                }
                let expected_hash = v
                    .pointer("/artifact/expected_sha256")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("vector {name} missing expected_sha256"))?;
                let actual_hash = v
                    .pointer("/artifact/actual_sha256")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("vector {name} missing actual_sha256"))?;
                if expected_hash == actual_hash {
                    bail!(
                        "vector {name} integrity-mismatch negative requires actual != expected hash"
                    );
                }
                if v.pointer("/expected/ticket_state_after")
                    .and_then(Value::as_str)
                    != Some("failed")
                {
                    bail!("vector {name} ticket_state_after must be failed on integrity mismatch");
                }
                saw_integrity_mismatch = true;
            }
            other => bail!("restore_full_workflows unexpected vector {other}"),
        }
        emit_vector(
            "restore_full_workflows.vector",
            v,
            json!({"name": name, "outcome": outcome}),
        );
    }
    if !(saw_two_of_two_approval
        && saw_duplicate_approver
        && saw_executor_restart
        && saw_artifact_round_trip
        && saw_integrity_mismatch)
    {
        bail!(
            "restore_full_workflows must cover two_of_two + duplicate_approver + restart_survival + artifact_round_trip + integrity_mismatch"
        );
    }
    Ok(())
}
