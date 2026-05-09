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
