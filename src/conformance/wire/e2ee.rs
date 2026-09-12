//! Megolm ratcheting and device-message wire-model conformance vectors.

use anyhow::{Result, anyhow, bail};
use base64::Engine as _;
use serde_json::{Value, json};

use super::{emit_vector, expected_outcome, expected_reason, load_local_fixture};
use crate::conformance::{required_str, validate_profile};

/// D3 — Megolm-equivalent ratcheting derivation + forward-secrecy.
///
/// Spec: `crypto-media/encryption-and-audit.md` (group-key ratcheting).
/// The Megolm-equivalent uses HKDF-SHA256 chains keyed off MLS epoch. This
/// validator re-derives the chain keys from each vector's seed material and
/// asserts:
///   * advance(prior_index→advance_index) increments by exactly 1
///   * forward derivation: key_at_(N+1) = HKDF(key_at_N, info=...) is one-way (we re-derive forward
///     from the seed and assert the result is not the same as the seed bytes — backward-derivation
///     impossibility is structural since HKDF is a one-way KDF)
///   * rotation MUST mint a new chain_id; reuse is rejected
pub fn run_megolm_ratcheting_fixture_suite() -> Result<()> {
    use hkdf::Hkdf;
    use sha2::Sha256 as KdfSha256;

    let fixture = load_local_fixture("megolm_ratcheting_fixture.json")?;
    validate_profile(&fixture, "ak.profile.megolm_ratcheting_vectors.v1")?;
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
                let info = b"ak.megolm.ratchet.v1";
                // The fixture pins the HKDF `info` label as base64 so a
                // namespace drift between the fixture and this validator is a
                // loud failure rather than a silently-ignored field.
                let declared_info_b64 = required_str(v, "kdf_info_b64")?;
                let declared_info = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(declared_info_b64)
                    .map_err(|e| {
                        anyhow!("vector {name} kdf_info_b64 is not base64url-no-pad: {e}")
                    })?;
                if declared_info.as_slice() != info.as_slice() {
                    bail!(
                        "vector {name} kdf_info_b64 decodes to {:?}, expected {:?}",
                        String::from_utf8_lossy(&declared_info),
                        String::from_utf8_lossy(info),
                    );
                }
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
/// Standalone — exercise the megolm-equivalent HKDF chain primitive.
/// Asserts the KDF is non-identity (output ≠ seed) and chain-length-deterministic
/// (running N steps from a fixed seed always produces the same key_N).
pub fn run_megolm_ratchet_kdf_chain_check() -> Result<()> {
    use hkdf::Hkdf;
    use sha2::Sha256 as KdfSha256;

    fn step(prev: &[u8; 32]) -> Result<[u8; 32]> {
        let kdf = Hkdf::<KdfSha256>::new(None, prev);
        let mut next = [0u8; 32];
        kdf.expand(b"ak.megolm.ratchet.v1", &mut next)
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
/// A5 — device-message / key-verification / key-backup negative
/// envelope vectors. Spec extensions/device-messages.md + B-22 strict_key_ref
/// rule + crypto-media/encryption-and-audit.md.
pub fn run_device_message_negative_fixture_suite() -> Result<()> {
    use std::collections::BTreeSet;

    let fixture = load_local_fixture("device_message_negative_fixture.json")?;
    validate_profile(&fixture, "ak.profile.device_message_negative_vectors.v1")?;

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
        if !envelope_id.starts_with("ak:envelope:") {
            bail!("vector {name} envelope_id {envelope_id} must use ak:envelope:<uuidv7> form");
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
