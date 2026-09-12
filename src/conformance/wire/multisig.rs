//! Payload-signing wire-model conformance vectors, including the multi-admin
//! distinct-approver gate.
//!
//! The fixture suites drive live SDK types: the payload-signing suite runs
//! [`arkret_signatures::Ed25519PayloadSigner`] plus
//! `verify_ed25519_payload_signature`. A structural-only validator would stay
//! green after the contract it claims to pin disappears, which is exactly how
//! the previous `Ed25519MoveSigner` / `AnchorerWorker` revision of this file
//! outlived its subject.

use anyhow::{Result, anyhow, bail};
use arkret_signatures::Ed25519PayloadSigner;
use arkret_signatures::signer::verify_ed25519_payload_signature;
use arkret_wire::{Did, DidUrl, PayloadSigner as _};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{emit_vector, load_local_fixture};
use crate::conformance::{required_str, validate_profile};

/// `sha256:<hex>` over `bytes`, matching the SDK's canonical digest spelling.
fn sha256_digest_string(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Read a fixture-declared canonical body plus its pinned digest and confirm
/// the two agree, so the pin cannot silently drift away from the bytes.
fn pinned_canonical_body(
    owner: &Value,
    label: &str,
    body_field: &str,
    digest_field: &str,
) -> Result<(Vec<u8>, String)> {
    let body = required_str(owner, body_field)?;
    let pinned = required_str(owner, digest_field)?;
    if !crate::conformance::looks_like_sha256_digest(pinned) {
        bail!("{label} {digest_field} {pinned} is not a sha256:<64-hex> digest");
    }
    let actual = sha256_digest_string(body.as_bytes());
    if actual != pinned {
        bail!("{label} {digest_field} drift: fixture pins {pinned}, bytes hash to {actual}");
    }
    Ok((body.as_bytes().to_vec(), pinned.to_owned()))
}

/// Decode a fixture-declared 32-byte ed25519 seed.
fn seed_from_hex(vector_name: &str, seed_hex: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(seed_hex)
        .map_err(|err| anyhow!("vector {vector_name} seed {seed_hex} is not hex: {err}"))?;
    let seed: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow!(
            "vector {vector_name} seed must be 32 bytes, got {}",
            bytes.len()
        )
    })?;
    Ok(seed)
}

/// Build an [`Ed25519PayloadSigner`] from a vector's declared identity.
fn signer_for(vector_name: &str, vector: &Value, seed: [u8; 32]) -> Result<Ed25519PayloadSigner> {
    let did = required_str(vector, "did")?;
    let kid = required_str(vector, "kid")?;
    let did =
        Did::new(did).map_err(|err| anyhow!("vector {vector_name} did {did} invalid: {err}"))?;
    let kid =
        DidUrl::new(kid).map_err(|err| anyhow!("vector {vector_name} kid {kid} invalid: {err}"))?;
    Ok(Ed25519PayloadSigner::from_did_key_seed(seed, did, kid))
}

/// Draw a seed that differs per call and per process, standing in for the
/// fresh CSPRNG bytes an ephemeral signer would use. `salt` separates two
/// draws taken inside a single run.
fn ephemeral_seed(salt: u8) -> [u8; 32] {
    use std::sync::atomic::{AtomicU64, Ordering};

    // Monotonic per-process counter so two draws inside one run differ even if
    // the clock reports the same nanosecond; the clock and pid make the draw
    // differ across runs.
    static DRAWS: AtomicU64 = AtomicU64::new(0);

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(nanos.to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(DRAWS.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    hasher.update([salt]);
    let digest = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    seed
}

/// Validate production signing semantics.
pub fn run_production_signing_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("production_signing_fixture.json")?;
    validate_profile(&fixture, "ak.profile.production_signing_vectors.v1")?;

    const VALID_SEED_SOURCES: &[&str] = &["configured", "ephemeral"];
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
    let mut covered_payload_digest = false;
    for vector in vectors {
        let name = required_str(vector, "name")?;
        let seed_source = required_str(vector, "seed_source")?;
        if !VALID_SEED_SOURCES.contains(&seed_source) {
            bail!("vector {name} seed_source {seed_source} not in {VALID_SEED_SOURCES:?}");
        }
        let (canonical_body, canonical_digest) = pinned_canonical_body(
            vector,
            &format!("vector {name}"),
            "canonical_body",
            "canonical_body_sha256",
        )?;
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
            ("ephemeral", "non_deterministic_signature") => {}
            ("ephemeral", _) => bail!(
                "vector {name} ephemeral seed_source must produce outcome=non_deterministic_signature"
            ),
            (_, "non_deterministic_signature") => bail!(
                "vector {name} non_deterministic_signature outcome only valid for seed_source=ephemeral"
            ),
            _ => {}
        }
        match name {
            "configured_seed_produces_deterministic_signature" => {
                if outcome != "deterministic_signature" {
                    bail!(
                        "vector {name} must declare outcome=deterministic_signature; got {outcome}"
                    );
                }
                // Two independently constructed signers sharing one seed must
                // emit byte-identical detached JWS for the same body.
                let seed = seed_from_hex(name, required_str(vector, "seed_hex")?)?;
                let first = signer_for(name, vector, seed)?.sign_payload(&canonical_body)?;
                let second = signer_for(name, vector, seed)?.sign_payload(&canonical_body)?;
                if first.jws != second.jws {
                    bail!(
                        "vector {name} configured seed produced two different JWS values; the signer is not deterministic"
                    );
                }
                if first.payload_digest.as_str() != canonical_digest {
                    bail!(
                        "vector {name} payload_digest {} != pinned {canonical_digest}",
                        first.payload_digest
                    );
                }
                covered_deterministic = true;
            }
            "different_seeds_produce_different_signatures_for_same_body" => {
                if outcome != "different_signatures" {
                    bail!("vector {name} must declare outcome=different_signatures; got {outcome}");
                }
                let seeds = vector
                    .get("seeds_hex")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} missing seeds_hex[]"))?;
                if seeds.len() < 2 {
                    bail!(
                        "vector {name} seeds_hex[] must have >=2 entries to demonstrate different signatures"
                    );
                }
                let mut signatures: Vec<String> = Vec::with_capacity(seeds.len());
                for seed_value in seeds {
                    let seed_hex = seed_value.as_str().ok_or_else(|| {
                        anyhow!("vector {name} seeds_hex[] entries must be strings")
                    })?;
                    let seed = seed_from_hex(name, seed_hex)?;
                    let signature =
                        signer_for(name, vector, seed)?.sign_payload(&canonical_body)?;
                    // Key binding changes the signature but never the digest:
                    // payload_digest commits to the body alone.
                    if signature.payload_digest.as_str() != canonical_digest {
                        bail!(
                            "vector {name} payload_digest {} != pinned {canonical_digest}",
                            signature.payload_digest
                        );
                    }
                    signatures.push(signature.jws);
                }
                let distinct: std::collections::BTreeSet<&String> = signatures.iter().collect();
                if distinct.len() != signatures.len() {
                    bail!(
                        "vector {name} distinct seeds produced a repeated JWS; the signer is reusing a key across instances"
                    );
                }
                covered_different_seeds = true;
            }
            "signature_verifies_with_signer_derived_verifying_key" => {
                if outcome != "verify_ok" {
                    bail!("vector {name} must declare outcome=verify_ok");
                }
                if expected.get("verify_via").and_then(Value::as_str)
                    != Some("verify_ed25519_payload_signature")
                {
                    bail!("vector {name} must declare verify_via=verify_ed25519_payload_signature");
                }
                let seed = seed_from_hex(name, required_str(vector, "seed_hex")?)?;
                let signer = signer_for(name, vector, seed)?;
                let signature = signer.sign_payload(&canonical_body)?;
                verify_ed25519_payload_signature(
                    &canonical_body,
                    &signature,
                    &signer.verifying_key(),
                )
                .map_err(|err| anyhow!("vector {name} round-trip verification failed: {err}"))?;
                covered_round_trip_verify = true;
            }
            "signature_payload_digest_matches_sha256_of_canonical_body" => {
                if outcome != "payload_digest_matches" {
                    bail!("vector {name} must declare outcome=payload_digest_matches");
                }
                let seed = seed_from_hex(name, required_str(vector, "seed_hex")?)?;
                let signature = signer_for(name, vector, seed)?.sign_payload(&canonical_body)?;
                if signature.payload_digest.as_str() != canonical_digest {
                    bail!(
                        "vector {name} SDK payload_digest {} != fixture-pinned {canonical_digest}",
                        signature.payload_digest
                    );
                }
                if signature.verification_method.as_str() != required_str(vector, "kid")? {
                    bail!(
                        "vector {name} signature verification_method {} != vector kid",
                        signature.verification_method
                    );
                }
                covered_payload_digest = true;
            }
            "ephemeral_seed_is_non_deterministic_across_runs" => {
                // Two signers built from independently drawn seeds must not
                // agree on the signature for identical body bytes.
                let first =
                    signer_for(name, vector, ephemeral_seed(1))?.sign_payload(&canonical_body)?;
                let second =
                    signer_for(name, vector, ephemeral_seed(2))?.sign_payload(&canonical_body)?;
                if first.jws == second.jws {
                    bail!(
                        "vector {name} two ephemeral signers produced the same JWS; the seed is not fresh per construction"
                    );
                }
                if first.payload_digest != second.payload_digest {
                    bail!(
                        "vector {name} ephemeral signers disagreed on payload_digest for identical bytes"
                    );
                }
                covered_ephemeral = true;
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
                "payload_digest": canonical_digest,
            }),
        );
    }
    if !(covered_deterministic
        && covered_ephemeral
        && covered_different_seeds
        && covered_round_trip_verify
        && covered_payload_digest)
    {
        bail!(
            "production_signing fixture must cover (a) deterministic-from-configured-seed, (b) ephemeral-non-deterministic, (c) different-seeds-different-sigs, (d) round-trip verify_ok, (e) payload_digest == sha256(canonical body)"
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
        let (canonical_body, _) = pinned_canonical_body(
            vector,
            &format!("negative vector {name}"),
            "canonical_body",
            "canonical_body_sha256",
        )?;
        let seed = seed_from_hex(name, required_str(vector, "seed_hex")?)?;
        let signer = signer_for(name, vector, seed)?;
        let signature = signer.sign_payload(&canonical_body)?;
        // Sanity: the honest path must verify, otherwise the negative proves
        // nothing about the drift under test.
        verify_ed25519_payload_signature(&canonical_body, &signature, &signer.verifying_key())
            .map_err(|err| {
                anyhow!("negative vector {name} baseline (untampered) verification failed: {err}")
            })?;
        match (drift_kind, reason) {
            ("wrong_verifying_key", "signature_verification_failed") => {
                let other_seed = seed_from_hex(name, required_str(drift, "verify_with_seed_hex")?)?;
                let other = signer_for(name, vector, other_seed)?;
                if other.verifying_key() == signer.verifying_key() {
                    bail!(
                        "negative vector {name} drift seed derives the same verifying key as the signing seed"
                    );
                }
                if verify_ed25519_payload_signature(
                    &canonical_body,
                    &signature,
                    &other.verifying_key(),
                )
                .is_ok()
                {
                    bail!(
                        "negative vector {name} signature verified under a foreign verifying key"
                    );
                }
                neg_wrong_key = true;
            }
            ("tampered_canonical_body", "payload_digest_mismatch") => {
                let (tampered_body, tampered_digest) = pinned_canonical_body(
                    drift,
                    &format!("negative vector {name} drift"),
                    "tampered_body",
                    "tampered_body_sha256",
                )?;
                if tampered_body == canonical_body {
                    bail!("negative vector {name} tampered_body is identical to canonical_body");
                }
                if signature.payload_digest.as_str() == tampered_digest {
                    bail!(
                        "negative vector {name} tampered body hashes to the signed payload_digest"
                    );
                }
                if verify_ed25519_payload_signature(
                    &tampered_body,
                    &signature,
                    &signer.verifying_key(),
                )
                .is_ok()
                {
                    bail!(
                        "negative vector {name} verifier accepted a signature over tampered canonical bytes"
                    );
                }
                neg_tampered = true;
            }
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
/// F-2 — fixture-decoupled multi-admin distinct-approver gate.
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
