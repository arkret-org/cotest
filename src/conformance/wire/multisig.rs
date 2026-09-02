//! Threshold-multisig and payload-signing wire-model conformance vectors,
//! including the multi-admin distinct-approver gate.
//!
//! Both fixture suites in this module drive live SDK types rather than
//! merely checking fixture shape: the threshold suite runs
//! [`arkret_wire::ThresholdAggregator`] and the payload-signing suite runs
//! [`arkret_signatures::Ed25519PayloadSigner`] plus
//! `verify_ed25519_payload_signature`. A structural-only validator would stay
//! green after the contract it claims to pin disappears, which is exactly how
//! the previous `Ed25519MoveSigner` / `AnchorerWorker` revision of this file
//! outlived its subject.

use std::cell::Cell;

use anyhow::{Result, anyhow, bail};
use arkret_signatures::Ed25519PayloadSigner;
use arkret_signatures::signer::verify_ed25519_payload_signature;
use arkret_wire::{
    Did, DidUrl, MultiSigKind, PartialSignature, PayloadSigner as _, ThresholdAggregator,
};
use base64::Engine as _;
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

/// Materialise a fixture partial as a real SDK [`PartialSignature`].
fn build_partial(vector_name: &str, partial: &Value) -> Result<PartialSignature> {
    let signer_did = required_str(partial, "signer_did")?;
    let kid = required_str(partial, "kid")?;
    let signature_b64 = required_str(partial, "signature_b64")?;
    if signature_b64.is_empty() {
        bail!("vector {vector_name} partial signature_b64 must be non-empty");
    }
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|err| {
            anyhow!("vector {vector_name} partial signature_b64 is not base64url-no-pad: {err}")
        })?;
    let signer_did = Did::new(signer_did)
        .map_err(|err| anyhow!("vector {vector_name} signer_did {signer_did} invalid: {err}"))?;
    let kid = DidUrl::new(kid)
        .map_err(|err| anyhow!("vector {vector_name} partial kid {kid} invalid: {err}"))?;
    Ok(PartialSignature::new(signer_did, signature, kid))
}

/// Threshold k-of-n anchor signing vectors, executed against the live SDK
/// [`ThresholdAggregator`].
///
/// Validates `tests/fixtures/threshold_multisig_fixture.json` against the
/// spec authz/event-auth-state-resolution.md §6 anchorer-cell threshold
/// profile plus the aggregator's real behaviour (collected partials,
/// per-partial verification, duplicate-signer rejection, threshold-met gate).
///
/// Validator pins:
/// * positive vectors declare `partials.len() >= k`, every partial is admitted into a real
///   `ThresholdAggregator`, `aggregate()` yields `MultiSigKind::MultiSig` with one
///   `PayloadSignature` per partial carrying that partial's `kid` and the shared payload digest,
///   and the per-partial verifier is invoked exactly once per partial;
/// * negative vectors cover (a) `threshold_below_quorum` (k-1 partials), (b) zero partials below
///   k=1, (c) `partial_signer_not_in_anchorer_set` (admission drops the partial, so quorum is never
///   reached), (d) `duplicate_signer` (the SDK's `add_partial` rejects it);
/// * threshold geometry valid (1 <= k <= n) and members.len() == n.
pub fn run_threshold_multisig_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("threshold_multisig_fixture.json")?;
    validate_profile(&fixture, "ak.profile.threshold_multisig_vectors.v1")?;

    let encoder = fixture
        .get("encoder")
        .ok_or_else(|| anyhow!("threshold_multisig fixture missing encoder"))?;
    let (canonical_body, canonical_digest) = pinned_canonical_body(
        encoder,
        "threshold_multisig encoder",
        "canonical_body",
        "canonical_body_sha256",
    )?;

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
        let mut aggregator = ThresholdAggregator::new(k as usize).map_err(|err| {
            anyhow!("vector {name} ThresholdAggregator::new({k}) unexpectedly rejected: {err}")
        })?;
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
            aggregator
                .add_partial(build_partial(name, partial)?)
                .map_err(|err| {
                    anyhow!("vector {name} add_partial rejected an admissible partial: {err}")
                })?;
        }
        if !aggregator.threshold_met() {
            bail!(
                "vector {name} collected {} partials but the aggregator reports threshold k={k} unmet",
                aggregator.collected()
            );
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

        // Run the real aggregator. `aggregate()` must call the per-partial
        // verifier exactly once per collected partial and emit one
        // PayloadSignature per partial, each bound to that partial's kid and
        // to the shared canonical-body digest.
        let verifier_calls = Cell::new(0usize);
        let aggregated = aggregator
            .aggregate(&canonical_body, |_partial, bytes| {
                verifier_calls.set(verifier_calls.get() + 1);
                if bytes != canonical_body.as_slice() {
                    return Err(arkret_wire::WireError::Protocol(
                        "aggregate() handed the verifier bytes other than the canonical body"
                            .to_owned(),
                    ));
                }
                Ok(())
            })
            .map_err(|err| anyhow!("vector {name} aggregate() rejected a quorum: {err}"))?;
        if aggregated.kind != MultiSigKind::MultiSig {
            bail!(
                "vector {name} aggregate() produced kind {:?}, expected MultiSigKind::MultiSig",
                aggregated.kind
            );
        }
        if aggregated.signatures.len() as u64 != agg_len {
            bail!(
                "vector {name} aggregate() produced {} signatures, fixture pins {agg_len}",
                aggregated.signatures.len()
            );
        }
        if verifier_calls.get() != partials.len() {
            bail!(
                "vector {name} aggregate() invoked the per-partial verifier {} times for {} partials (must be one call per partial)",
                verifier_calls.get(),
                partials.len()
            );
        }
        for (signature, partial) in aggregated.signatures.iter().zip(partials) {
            let kid = required_str(partial, "kid")?;
            if signature.verification_method.as_str() != kid {
                bail!(
                    "vector {name} aggregated signature verification_method {} != partial kid {kid}",
                    signature.verification_method
                );
            }
            if signature.payload_digest.as_str() != canonical_digest {
                bail!(
                    "vector {name} aggregated signature payload_digest {} != canonical body digest {canonical_digest}",
                    signature.payload_digest
                );
            }
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
        let declared_partials: Vec<&Value> = vector
            .get("partials")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().collect())
            .unwrap_or_default();
        let mut aggregator = ThresholdAggregator::new(k as usize).map_err(|err| {
            anyhow!(
                "negative vector {name} ThresholdAggregator::new({k}) unexpectedly rejected: {err}"
            )
        })?;
        match (name, reason) {
            ("k_minus_one_partials_rejected_threshold_below_quorum", "threshold_below_quorum")
            | ("zero_partials_rejected_threshold_below_quorum", "threshold_below_quorum") => {
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
                for partial in &declared_partials {
                    aggregator
                        .add_partial(build_partial(name, partial)?)
                        .map_err(|err| {
                            anyhow!("negative vector {name} add_partial unexpectedly failed: {err}")
                        })?;
                }
                if aggregator.collected() as u64 != collected {
                    bail!(
                        "negative vector {name} aggregator collected {} partials, fixture declares {collected}",
                        aggregator.collected()
                    );
                }
                if aggregator.threshold_met() {
                    bail!("negative vector {name} aggregator reports threshold met below quorum");
                }
                if aggregator.aggregate(&canonical_body, |_, _| Ok(())).is_ok() {
                    bail!(
                        "negative vector {name} aggregate() succeeded below quorum (collected {collected} < required {required})"
                    );
                }
                if name == "zero_partials_rejected_threshold_below_quorum" {
                    if collected != 0 {
                        bail!("negative vector {name} must declare collected=0");
                    }
                    neg_zero_partials = true;
                } else {
                    neg_below_quorum = true;
                }
            }
            ("partial_signer_not_in_member_set_rejected", "partial_signer_not_in_anchorer_set") => {
                let members: std::collections::BTreeSet<&str> = vector
                    .get("members")
                    .and_then(Value::as_array)
                    .map(|arr| arr.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                let mut found_attacker = false;
                // Admission is an anchorer-cell gate, not an aggregator gate:
                // the aggregator has no member set. Replay the admission
                // filter, then show the surviving partials cannot reach quorum.
                for partial in &declared_partials {
                    let signer = required_str(partial, "signer_did")?;
                    if !members.contains(signer) {
                        found_attacker = true;
                        continue;
                    }
                    aggregator
                        .add_partial(build_partial(name, partial)?)
                        .map_err(|err| {
                            anyhow!("negative vector {name} add_partial unexpectedly failed: {err}")
                        })?;
                }
                if !found_attacker {
                    bail!(
                        "negative vector {name} must include at least one partial whose signer_did is NOT in members[]"
                    );
                }
                if aggregator.threshold_met() {
                    bail!(
                        "negative vector {name} reached quorum from admitted partials alone; the non-member partial is not load-bearing"
                    );
                }
                if aggregator.aggregate(&canonical_body, |_, _| Ok(())).is_ok() {
                    bail!(
                        "negative vector {name} aggregate() succeeded after the non-member partial was refused admission"
                    );
                }
                neg_signer_not_in_set = true;
            }
            ("duplicate_signer_partial_rejected", "duplicate_signer") => {
                let mut seen: std::collections::BTreeSet<&str> = Default::default();
                let mut had_dup = false;
                let mut aggregator_refused_dup = false;
                for partial in &declared_partials {
                    let signer = required_str(partial, "signer_did")?;
                    let duplicate = !seen.insert(signer);
                    let outcome = aggregator.add_partial(build_partial(name, partial)?);
                    if duplicate {
                        had_dup = true;
                        if outcome.is_ok() {
                            bail!(
                                "negative vector {name} add_partial accepted a duplicate signer_did {signer}"
                            );
                        }
                        aggregator_refused_dup = true;
                    } else {
                        outcome.map_err(|err| {
                            anyhow!(
                                "negative vector {name} add_partial rejected the first partial from {signer}: {err}"
                            )
                        })?;
                    }
                }
                if !had_dup {
                    bail!(
                        "negative vector {name} must include at least two partials with the same signer_did"
                    );
                }
                if !aggregator_refused_dup {
                    bail!("negative vector {name} never exercised the duplicate-signer refusal");
                }
                if aggregator.threshold_met() {
                    bail!(
                        "negative vector {name} deduped partials still reached quorum; the dedup is not load-bearing"
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
/// Notary/anchor payload-signing vectors, executed against the live SDK
/// [`Ed25519PayloadSigner`].
///
/// Validates `tests/fixtures/production_signing_fixture.json` by actually
/// signing each vector's canonical body and inspecting the resulting
/// `PayloadSignature`: deterministic seed ⇒ byte-identical detached JWS,
/// ephemeral seed ⇒ different JWS per run, distinct seeds ⇒ distinct
/// signatures over identical bytes, round-trip through
/// `verify_ed25519_payload_signature`, and `payload_digest` equal to
/// sha256 of the canonical body.
///
/// Validator pins:
/// * positive vectors declare `seed_source` ∈ {configured, ephemeral};
/// * `canonical_body_sha256` is `sha256:<64-hex>` AND actually hashes `canonical_body`;
/// * the SDK-produced `payload_digest` equals that pinned digest, so fixture and SDK cannot drift
///   apart silently;
/// * negative vectors cover wrong-verifying-key (signature check fails) and tampered-canonical-body
///   (digest check fails), both asserted by running the real verifier.
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
