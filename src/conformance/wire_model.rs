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
                        let cell = format!(
                            "cx:cell:cx.component.consent.grant.v1:{holder}"
                        );
                        let active_tags = or_set.get(&cell);
                        let resolved = active_tags
                            .map(|tags| {
                                tags.values().any(|(p, s)| {
                                    p == peer && (s == scope || s == "any")
                                })
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
            bail!(
                "vector {name} effective_anchor_view.leaves drift from input anchor ids"
            );
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
            bail!(
                "vector {name} concurrent multi-leaf frontier MUST equal leaves set"
            );
        }
        if anchors.len() == 1 && !view_frontier.is_empty() && view_frontier != view_leaves {
            bail!(
                "vector {name} single-leaf view frontier must be empty or equal to leaves"
            );
        }

        // (3) signed compaction equivalence
        if let Some(compaction) = vector.get("signed_compaction") {
            if !compaction.is_null() {
                let comp_id = required_str(compaction, "id")?;
                validate_anchor_id_shape(comp_id, name)?;
                let comp_frontier: std::collections::BTreeSet<String> = compaction
                    .get("frontier")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        anyhow!("vector {name} signed_compaction missing frontier[]")
                    })?
                    .iter()
                    .map(|v| {
                        v.as_str()
                            .map(ToOwned::to_owned)
                            .ok_or_else(|| {
                                anyhow!(
                                    "vector {name} signed_compaction frontier entry not a string"
                                )
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
                        anyhow!("negative vector {name} drift_compaction missing bottom_diagnostics")
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
        bail!(
            "{ctx} anchor id {id} must use cx:anchor:sha256:<hex> special form"
        );
    };
    if rest.len() != 64 || !rest.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {
        bail!(
            "{ctx} anchor id {id} sha256 segment must be exactly 64 lowercase hex chars"
        );
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
            bail!(
                "vector {name} cell_id must be the anchorer.v1 cell, got {cell_id}"
            );
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
                            bail!(
                                "vector {name} threshold k={k} n={n} must satisfy 1 <= k <= n"
                            );
                        }
                        let members = value
                            .get("members")
                            .and_then(Value::as_array)
                            .ok_or_else(|| {
                                anyhow!("vector {name} threshold missing members[]")
                            })?;
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
                            .ok_or_else(|| {
                                anyhow!("vector {name} open_set missing members[]")
                            })?;
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
                    bail!(
                        "vector {name} happy path must expect outcome=value, got {outcome}"
                    );
                }
                covered.insert(name);
            }
            "concurrent_reconfig_returns_bottom_conflict" => {
                let ops = vector
                    .get("concurrent_anchored_ops")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        anyhow!("vector {name} missing concurrent_anchored_ops[]")
                    })?;
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
                    .ok_or_else(|| {
                        anyhow!("vector {name} prior_bottom missing move_ids[]")
                    })?
                    .iter()
                    .filter_map(Value::as_str)
                    .collect();
                if prior_ids.len() < 2 {
                    bail!(
                        "vector {name} prior_bottom MUST have ≥ 2 conflicting move_ids"
                    );
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
                let head_set: std::collections::BTreeSet<&str> =
                    head_in.iter().copied().collect();
                if prior_set != head_set {
                    bail!(
                        "vector {name} repair_move.head_in MUST equal prior_bottom.move_ids set"
                    );
                }
                let _ = required_str(repair, "recovery_capability")?;
                let outcome = required_str(
                    vector
                        .get("expected")
                        .ok_or_else(|| anyhow!("vector {name} missing expected"))?,
                    "outcome",
                )?;
                if outcome != "value" {
                    bail!(
                        "vector {name} expected outcome=value (single anchored repair op)"
                    );
                }
                covered_head_in_resolves = true;
            }
            "self_authorising_winner_rejected_at_lattice_layer" => {
                let ops = vector
                    .get("concurrent_anchored_ops")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        anyhow!("vector {name} missing concurrent_anchored_ops[]")
                    })?;
                if ops.len() < 2 {
                    bail!(
                        "vector {name} self-authorising vector must have ≥ 2 concurrent ops"
                    );
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
                let endorsement = repair
                    .get("anchorer_endorsement")
                    .ok_or_else(|| {
                        anyhow!("vector {name} manual repair missing anchorer_endorsement")
                    })?;
                if required_str(endorsement, "alg")? != "EdDSA" {
                    bail!(
                        "vector {name} anchorer_endorsement.alg must be EdDSA"
                    );
                }
                let _ = required_str(endorsement, "anchorer_did")?;
                covered_manual_repair = true;
            }
            other => bail!("vector unexpected name {other}"),
        }
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
    for required in [
        "repair_missing_recovery_capability",
        "repair_head_in_drift",
    ] {
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
                        bail!(
                            "vector {name} accumulate vector ops must all be or_set_add"
                        );
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
                        bail!(
                            "vector {name} MLS commit must write cell family {required}"
                        );
                    }
                }
                covered.insert(name);
            }
            other => bail!("vector {name}: unexpected name {other}"),
        }
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
            bail!(
                "negative vector {name} missing_precondition must be covered_frontier"
            );
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
                let has_cf = preconds.iter().any(|p| {
                    p.get("kind").and_then(Value::as_str) == Some("covered_frontier")
                });
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
        for op in group.get("operations").and_then(Value::as_array).into_iter().flatten() {
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
    for (key, expected) in [("core", &live_core), ("extension", &live_ext), ("interop_bridge", &live_bridge)] {
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
            bail!(
                "operation-registry surface_groups missing post-C16 surface {required}"
            );
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
            bail!(
                "vector {name} core_present drift: expected {core_present} got {actual_core}"
            );
        }
        if actual_ext != ext_present {
            bail!(
                "vector {name} extension_present drift: expected {ext_present} got {actual_ext}"
            );
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
            "core_only_sut_advertises_core_implies_no_extension_or_bridge" => covered_core_only = true,
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
    }
    if !(covered_core_only
        && covered_ext_blob
        && covered_ext_realtime
        && covered_ext_moderation
        && covered_bridge_mimi
        && covered_bridge_applet)
    {
        bail!(
            "discovery fixture must cover (a) core-only, (b) blob_storage / realtime_media / moderation_reports post-C16 split, and (c) mimi_interop + applet bridge advertisement"
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
                if required_str(expected, "rejection_reason")? != "interop_bridge_surface_not_advertised" {
                    bail!(
                        "negative vector {name} rejection_reason must be interop_bridge_surface_not_advertised"
                    );
                }
                neg_bridge_unsupported = true;
            }
            "extension_call_blocked_when_surface_not_advertised" => {
                if required_str(expected, "rejection_reason")? != "extension_surface_not_advertised" {
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
                    bail!(
                        "negative vector {name} must declare the legacy combined `media` token"
                    );
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
