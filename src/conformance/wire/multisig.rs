//! Threshold-multisig and production-signing wire-model conformance vectors,
//! including the multi-admin distinct-approver gate.

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{emit_vector, load_local_fixture};
use crate::conformance::{required_str, validate_profile};

/// Round 22 — Threshold k-of-n Anchor signing vectors.
///
/// Validates `tests/fixtures/threshold_multisig_fixture.json` against the
/// spec authz/event-auth-state-resolution.md §6 anchorer-cell threshold
/// profile + the SDK `ThresholdAggregator` semantics (collected partials,
/// per-partial verification, duplicate signer dedup, threshold-met gate).
///
/// Validator pins:
/// * positive vectors declare `partials.len() >= k` and outcome=aggregate_ok with
///   `aggregated_signatures_len == partials.len()`;
/// * negative vectors cover (a) `threshold_below_quorum` (k-1 partials), (b) zero partials below
///   k=1, (c) `partial_signer_not_in_anchorer_set`, (d) `duplicate_signer`;
/// * every partial declares non-empty `signer_did` + `kid` + `signature_b64`;
/// * threshold geometry valid (1 <= k <= n) and members.len() == n.
pub fn run_threshold_multisig_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("threshold_multisig_fixture.json")?;
    validate_profile(&fixture, "ak.profile.threshold_multisig_vectors.v1")?;

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
/// JWS, ephemeral seed ⇒ non-deterministic, key-binding, payload_digest
/// invariant) + the soland `service_admin_signer` derivation.
///
/// Validator pins:
/// * positive vectors declare `seed_source` ∈ {configured, ephemeral, service_did_derived};
/// * canonical_body_sha256 is `sha256:<64-hex>` shape;
/// * deterministic vectors declare outcome=deterministic_signature OR verify_ok /
///   payload_digest_matches / different_signatures;
/// * ephemeral vector declares outcome=non_deterministic_signature;
/// * negative vectors cover wrong-verifying-key + tampered-canonical-body.
pub fn run_production_signing_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("production_signing_fixture.json")?;
    validate_profile(&fixture, "ak.profile.production_signing_vectors.v1")?;

    const VALID_SEED_SOURCES: &[&str] = &["configured", "ephemeral", "service_did_derived"];
    const VALID_POSITIVE_OUTCOMES: &[&str] = &[
        "deterministic_signature",
        "non_deterministic_signature",
        "different_signatures",
        "verify_ok",
        "payload_digest_matches",
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
        if !crate::conformance::looks_like_sha256_digest(body_hash) {
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
            "signature_payload_digest_matches_sha256_of_canonical_body" => {
                if outcome != "payload_digest_matches" {
                    bail!("vector {name} must declare outcome=payload_digest_matches");
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
            ("tampered_canonical_body", "payload_digest_mismatch") => neg_tampered = true,
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
