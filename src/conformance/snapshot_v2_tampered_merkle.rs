//! CT-3 — Snapshot v2 tampered Merkle conformance suite.
//!
//! Validates `tests/fixtures/snapshot_v2_tampered_merkle.json`, which
//! exercises the rejection of a snapshot whose chunk content or
//! inclusion-proof branch has been mutated, even when a local Merkle
//! recompute is internally consistent against the mutation.
//!
//! Spec authority:
//!   * `contrix-spec/spec/v1/zh/conformance/snapshot-schema.md` §3 (chunk descriptor.sha256 covers
//!     chunk payload canonical JSON bytes), §4 (state_digest MUST be the canonical Merkle root over
//!     reducer output leaves), §5 (signature covers manifest payload), §6
//!     (event_set_commitment.root + merkle_branch inclusion proofs).
//!
//! The signed manifest pins state_digest, event_set_commitment.root, and
//! each chunk.sha256 — recomputing a local Merkle branch from a mutated
//! chunk does not recover the signed root, so the snapshot MUST be
//! rejected. Spec note: snapshot-schema.md does not currently use the
//! field name `audit_path`; the normative inclusion-proof field name is
//! `merkle_branch` (§6). The canonical errcode is `digest_mismatch` per
//! `error-code-registry.json`.
//!
//! Structural check only; deeper re-execution of snapshot verification
//! belongs in the snapshot-verifier crate when it lands.

use anyhow::{Result, anyhow, bail};
use serde_json::Value;

use super::{load_local_fixture_value, required_str, validate_profile};

const PROFILE_ID: &str = "cx.profile.snapshot_v2_tampered_merkle_vectors.v1";
const EXPECTED_ERRCODE: &str = "digest_mismatch";

pub fn run_snapshot_v2_tampered_merkle_suite() -> Result<()> {
    let fixture = load_local_fixture_value("snapshot_v2_tampered_merkle.json")?;
    validate_profile(&fixture, PROFILE_ID)?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("snapshot_v2_tampered_merkle fixture missing vectors[]"))?;
    if vectors.len() < 3 {
        bail!(
            "snapshot_v2_tampered_merkle requires >= 3 vectors, got {}",
            vectors.len()
        );
    }

    let mut saw_chunk_byte_flip = false;
    let mut saw_branch_byte_flip = false;
    let mut saw_chunk_count = false;

    for vector in vectors {
        let name = required_str(vector, "name")?;
        let outcome = vector
            .pointer("/expected/outcome")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("vector {name} missing expected.outcome"))?;
        if outcome != "reject" {
            bail!("vector {name} expected.outcome must be 'reject' (tamper vectors never accept)");
        }
        let errcode = vector
            .pointer("/expected/errcode")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("vector {name} missing expected.errcode"))?;
        if errcode != EXPECTED_ERRCODE {
            bail!(
                "vector {name} expected.errcode must be '{EXPECTED_ERRCODE}' (got {errcode}); see error-code-registry.json"
            );
        }
        let tamper_kind = vector
            .pointer("/tamper/kind")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("vector {name} missing tamper.kind"))?;

        match name {
            "byte_flip_in_chunk_audit_path_recomputed_still_rejected" => {
                if tamper_kind != "chunk_byte_flip" {
                    bail!(
                        "vector {name} tamper.kind must be 'chunk_byte_flip' (got {tamper_kind})"
                    );
                }
                let recompute = vector
                    .pointer("/tamper/recompute_local_branch")
                    .and_then(Value::as_bool);
                if recompute != Some(true) {
                    bail!(
                        "vector {name} tamper.recompute_local_branch must be true — this vector's whole point is that local recompute does NOT rescue the signed snapshot"
                    );
                }
                let local_root = vector
                    .pointer("/local_recomputed_event_set_commitment_root")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        anyhow!("vector {name} missing local_recomputed_event_set_commitment_root")
                    })?;
                let signed_root = vector
                    .pointer("/manifest_signed_event_set_commitment_root")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        anyhow!("vector {name} missing manifest_signed_event_set_commitment_root")
                    })?;
                if local_root == signed_root {
                    bail!(
                        "vector {name} local recomputed root MUST differ from signed root — that is the digest_mismatch we are asserting"
                    );
                }
                saw_chunk_byte_flip = true;
            }
            "byte_flip_in_audit_path_only" => {
                if tamper_kind != "merkle_branch_byte_flip" {
                    bail!(
                        "vector {name} tamper.kind must be 'merkle_branch_byte_flip' (got {tamper_kind})"
                    );
                }
                let leave_intact = vector
                    .pointer("/tamper/leave_chunk_payload_intact")
                    .and_then(Value::as_bool);
                if leave_intact != Some(true) {
                    bail!(
                        "vector {name} tamper.leave_chunk_payload_intact must be true — this vector flips the proof path, not the chunk"
                    );
                }
                let signed_root = vector
                    .pointer("/manifest_signed_event_set_commitment_root")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        anyhow!("vector {name} missing manifest_signed_event_set_commitment_root")
                    })?;
                let local_root = vector
                    .pointer("/local_recomputed_root_from_tampered_branch")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        anyhow!("vector {name} missing local_recomputed_root_from_tampered_branch")
                    })?;
                if local_root == signed_root {
                    bail!("vector {name} tampered branch must NOT hash up to the signed root");
                }
                saw_branch_byte_flip = true;
            }
            "chunk_count_mismatch" => {
                if tamper_kind != "drop_last_chunk" {
                    bail!(
                        "vector {name} tamper.kind must be 'drop_last_chunk' (got {tamper_kind})"
                    );
                }
                let chunks_present = vector
                    .pointer("/tamper/chunks_present")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing tamper.chunks_present"))?;
                let signed_count = vector
                    .pointer("/tamper/manifest_signed_chunk_count")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| {
                        anyhow!("vector {name} missing tamper.manifest_signed_chunk_count")
                    })?;
                if chunks_present >= signed_count {
                    bail!(
                        "vector {name} chunks_present ({chunks_present}) must be < manifest_signed_chunk_count ({signed_count}) — that's the dropped-chunk invariant"
                    );
                }
                let signed_state = vector
                    .pointer("/manifest_signed_state_digest")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("vector {name} missing manifest_signed_state_digest"))?;
                let local_state = vector
                    .pointer("/local_recomputed_state_digest")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        anyhow!("vector {name} missing local_recomputed_state_digest")
                    })?;
                if signed_state == local_state {
                    bail!(
                        "vector {name} dropped chunk MUST yield a different recomputed state_digest"
                    );
                }
                saw_chunk_count = true;
            }
            other => bail!("snapshot_v2_tampered_merkle unexpected vector: {other}"),
        }
    }

    if !(saw_chunk_byte_flip && saw_branch_byte_flip && saw_chunk_count) {
        bail!(
            "snapshot_v2_tampered_merkle must cover all three vectors \
             (byte_flip_in_chunk_audit_path_recomputed_still_rejected + \
              byte_flip_in_audit_path_only + chunk_count_mismatch)"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_passes_against_local_fixture() -> Result<()> {
        run_snapshot_v2_tampered_merkle_suite()
    }
}
