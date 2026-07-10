//! `service_binding_ref.reducer_profile_digest` computation (federation).
//!
//! Spec: `arkret-spec/spec/v1/zh/sync/federation.md` §4.1.1 (normative) — the
//! only machine-readable source for the digest is
//! `spec/v1/artifacts/registry/reducer-profile-registry.json`. Senders MUST
//! resolve the registry row whose `profile_id` equals the Realm's declared
//! reducer profile and hash **only** that row's `digest_input` object:
//!
//! ```text
//! reducer_profile_digest = "sha256:" || lowercase_hex(sha256(canonical_json(digest_input)))
//! ```
//!
//! Registered conformance vector: `ck.vector.federation.reducer_profile_digest.v1`
//! (`federation-fixture.json` cases `reducer_profile_digest_federation_minimal`
//! and `reducer_profile_mismatch`; prose in `zh/conformance/conformance-vectors.md`
//! §15.8). Receivers recompute with the same registry rule and byte-compare;
//! any divergence MUST reject the whole batch with `reducer_profile_mismatch`.

use anyhow::{Result, anyhow, bail};
use serde_json::Value;

use super::{canonical_json, load_artifact_json, sha256_prefixed};

/// Registry path relative to `spec/v1/artifacts/`.
const REDUCER_PROFILE_REGISTRY: &str = "registry/reducer-profile-registry.json";

/// The reducer profile soland declares for its federation surface
/// (`ck.peer.events.query.describe` → `supported_profiles`), and the profile pinned
/// by the registered conformance vector.
pub const FEDERATION_MINIMAL_PROFILE_ID: &str = "ak.profile.federation_minimal.v1";

/// Compute the §4.1.1 `reducer_profile_digest` for `profile_id` from the
/// published registry row. Fails closed when the registry row is missing, the
/// row is not `active`, the canonicalization is unsupported, or the digest
/// suite is not `sha256` — mirroring the receiver-side MUSTs.
pub fn reducer_profile_digest(profile_id: &str) -> Result<String> {
    let registry = load_artifact_json(REDUCER_PROFILE_REGISTRY)?;
    let digest_input = reducer_profile_digest_input(&registry, profile_id)?;
    reducer_profile_digest_for_input(&digest_input)
}

/// Resolve the `digest_input` object for `profile_id`, enforcing the
/// fail-closed preconditions of federation.md §4.1.1.
pub(crate) fn reducer_profile_digest_input(registry: &Value, profile_id: &str) -> Result<Value> {
    let canonicalization = registry
        .get("canonicalization")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if canonicalization != "json_jcs" {
        bail!(
            "reducer-profile-registry canonicalization {canonicalization:?} is unsupported; fail closed"
        );
    }
    let digest_suite = registry
        .get("digest_suite")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if digest_suite != "sha256" {
        bail!(
            "reducer-profile-registry digest_suite {digest_suite:?} is not active sha256; fail closed"
        );
    }
    let row = registry
        .get("profiles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|row| row.get("profile_id").and_then(Value::as_str) == Some(profile_id))
        .ok_or_else(|| {
            anyhow!("reducer profile {profile_id} has no reducer-profile-registry row; fail closed")
        })?;
    if row.get("status").and_then(Value::as_str) != Some("active") {
        bail!("reducer profile {profile_id} registry row is not active; fail closed");
    }
    row.get("digest_input")
        .cloned()
        .ok_or_else(|| anyhow!("reducer profile {profile_id} registry row lacks digest_input"))
}

/// Hash an already-resolved `digest_input` object (used by the fixture-driven
/// conformance case, which carries the canonical input inline).
pub(crate) fn reducer_profile_digest_for_input(digest_input: &Value) -> Result<String> {
    Ok(sha256_prefixed(canonical_json(digest_input)?.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conformance::{FederationFixture, load_fixture, looks_like_sha256_digest};

    /// The computed digest for `ck.profile.federation_minimal.v1` MUST match
    /// the registered conformance vector
    /// `ck.vector.federation.reducer_profile_digest.v1` expected value pinned
    /// in `federation-fixture.json` (case
    /// `reducer_profile_digest_federation_minimal`).
    #[test]
    fn federation_minimal_digest_matches_registered_vector() {
        let computed = reducer_profile_digest(FEDERATION_MINIMAL_PROFILE_ID)
            .expect("registry-derived digest computes");
        assert!(looks_like_sha256_digest(&computed));

        let fixture: FederationFixture =
            load_fixture("federation-fixture.json").expect("federation fixture loads");
        let case = fixture
            .cases
            .iter()
            .find(|case| case.name == "reducer_profile_digest_federation_minimal")
            .expect("vector case registered in federation-fixture.json");
        let expected = case
            .expected_digest
            .as_deref()
            .expect("vector case pins expected_digest");
        assert_eq!(
            computed, expected,
            "reducer_profile_digest drifted from ak.vector.federation.reducer_profile_digest.v1"
        );
    }

    /// Missing registry rows MUST fail closed instead of inventing a digest.
    #[test]
    fn unknown_profile_fails_closed() {
        let error = reducer_profile_digest("ak.profile.does_not_exist.v1")
            .expect_err("unknown profile must fail closed");
        assert!(error.to_string().contains("fail closed"));
    }
}
