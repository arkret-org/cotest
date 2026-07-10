//! Device-verification and cross-signing trust / reset wire-model conformance
//! vectors.

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{emit_vector, expected_outcome, expected_reason, load_local_fixture};
use crate::conformance::{required_str, validate_profile};

/// D2 Round 24 — device verification strand vectors: cross-signing chain, SAS,
/// emoji code.
pub fn run_device_verification_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("device_verification_fixture.json")?;
    validate_profile(&fixture, "ak.profile.device_verification_vectors.v1")?;

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
/// D5 Round 27 — device cross-signing trust boundary. Spec authority:
/// crypto-media/device-lifecycle.md. Each vector exercises a different
/// trust-boundary invariant: full chain valid; transitive trust into a new
/// device; revoke alice's master invalidates anchor; rotate bob's
/// user-signing requires re-anchor.
pub fn run_device_cross_signing_trust_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("device_cross_signing_trust_fixture.json")?;
    validate_profile(&fixture, "ak.profile.device_cross_signing_trust_vectors.v1")?;
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
        let trust_anchor_actor = required_str(v, "trust_anchor_actor_id")?;
        if !trust_anchor_actor.starts_with("did:web:") && !trust_anchor_actor.starts_with("did:ak:")
        {
            bail!("vector {name} trust_anchor_actor_id must be a did: form");
        }

        // Common: alice.master + alice.user-signing must be present in every
        // vector that names them.
        if let Some(am) = v.get("alice_master") {
            let id = required_str(am, "key_id")?;
            if !id.ends_with("#master") {
                bail!("vector {name} alice_master.key_id must end with #master");
            }
        }
        if let Some(aus) = v.get("alice_user_signing")
            && required_str(aus, "signed_by")? != "did:ak:user:alice#master"
        {
            bail!("vector {name} alice_user_signing.signed_by must be alice#master");
        }

        match name {
            "cross_user_trust_full_chain_valid" => {
                let bm = v
                    .get("bob_master")
                    .ok_or_else(|| anyhow!("vector {name} missing bob_master"))?;
                if required_str(bm, "signed_by")? != "did:ak:user:alice#user-signing" {
                    bail!("vector {name} bob_master must be signed by alice#user-signing");
                }
                let bss = v
                    .get("bob_self_signing")
                    .ok_or_else(|| anyhow!("vector {name} missing bob_self_signing"))?;
                if required_str(bss, "signed_by")? != "did:ak:user:bob#master" {
                    bail!("vector {name} bob_self_signing must be signed by bob#master");
                }
                let bdl = v
                    .get("bob_device_leaf")
                    .ok_or_else(|| anyhow!("vector {name} missing bob_device_leaf"))?;
                if required_str(bdl, "signed_by")? != "did:ak:user:bob#self-signing" {
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
                if required_str(bdl, "signed_by")? != "did:ak:user:bob#self-signing" {
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
            json!({"name": name, "outcome": outcome, "trust_anchor_actor_id": trust_anchor_actor}),
        );
    }
    if !(saw_full_chain && saw_transitive && saw_revoke && saw_rotate) {
        bail!("device_cross_signing_trust must cover full_chain + transitive + revoke + rotate");
    }
    Ok(())
}
/// S4 — cross-signing reset hardening vectors. These are parser-level
/// conformance guards for `ck.profile.cross_signing.reset.v1`: reset proof
/// family, generation monotonicity, replay rejection, clock skew, and the
/// successor publish recovery window.
pub fn run_cross_signing_reset_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("cross_signing_reset_fixture.json")?;
    validate_profile(&fixture, "ak.profile.cross_signing.reset.v1")?;
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
        if required_str(v, "event_kind")? != "ak.cross_signing.reset" {
            bail!("vector {name} event_kind must be ak.cross_signing.reset");
        }
        if required_str(v, "schema_id")? != "ak.schema.cross_signing_reset.v1" {
            bail!("vector {name} schema_id must be ak.schema.cross_signing_reset.v1");
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
                if successor_kind != "ak.cross_signing.publish" {
                    bail!("vector {name} successor publish must be ak.cross_signing.publish");
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
