//! `ak.vector.snapshot.witness_quorum_attestation.v1` — the typed snapshot
//! witness-attestation family (`conformance/snapshot-schema.md` §5.1,
//! `sync-fixture.json` block `snapshot_witness_quorum`).
//!
//! A witness attestation is its own object family, not a bare proof appended to
//! the manifest. It is signed under `ak.snapshot-witness-attestation-proof-v1`
//! over the signature-free canonical projection, so:
//!
//!  - reusing the manifest's `ak.snapshot-proof-v1` context yields a different transcript digest
//!    and MUST be rejected even when the JWS itself verifies;
//!  - the projection may not contain `signature` or `witness_attestations`, otherwise a witness
//!    would sign a transcript containing its own signature;
//!  - quorum is counted per `witness_id` against the accepted Realm auth/policy state, never
//!    against `verification_hints.witness_quorum`, which is a declared value the receiver only
//!    cross-checks;
//!  - the issuer signature covers the final sorted witness list, so a rewritten list is detectable
//!    and an unsorted list is rejected outright rather than normalized first.
//!
//! Admission is driven in the order a receiver must apply it: the witness-list
//! shape gate, then the issuer signature over the final list, then the quorum
//! admission itself. Every step is the shared `arkret_state::snapshot` entry —
//! `witness_attestation_projection` / `witness_attestation_digest` /
//! `validate_witness_attestation_shape` / `verify_witness_attestations` — so a
//! divergence here is a real divergence and not a test-local reimplementation.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail};
use arkret_state::snapshot::{
    SNAPSHOT_WITNESS_ATTESTATION_PROOF_CONTEXT, SnapshotAuthorityKind, SnapshotManifest,
    SnapshotValidationCode, SnapshotValidationError, SnapshotWitnessAttestation,
    SnapshotWitnessQuorumPolicy,
};
use arkret_wire::{DidCoreId, Hash, ProofContextId};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use super::{load_fixture_value, required_field, value_array, value_field_str};

pub const VECTOR_ID_SNAPSHOT_WITNESS_QUORUM_ATTESTATION: &str =
    "ak.vector.snapshot.witness_quorum_attestation.v1";

/// The fixture case names, pinned so a spec-side rename or deletion is loud
/// rather than silently reducing coverage.
const REQUIRED_CASE_NAMES: &[&str] = &[
    "valid_quorum_accepted",
    "witness_quorum_without_attestations_rejected",
    "duplicate_signer_counts_once",
    "unauthorized_witness_not_counted",
    "revoked_witness_not_counted",
    "below_threshold_rejected",
    "declared_hint_below_policy_threshold_rejected",
    "wrong_context_rejected",
    "wrong_projection_rejected",
    "projection_must_not_contain_signature_fields",
    "witness_list_rewritten_invalidates_issuer_signature",
    "witness_list_reordered_invalidates_issuer_signature",
];

/// Members a witness transcript must never contain. Signing any of them would
/// make a witness commit to its own or a sibling's signature.
const FORBIDDEN_PROJECTION_MEMBERS: &[&str] = &[
    "signature",
    "witness_attestations",
    "proof",
    "proofs",
    "verification_hints",
    "chunks",
    "checked_at",
    "created_by",
];

pub fn run_snapshot_witness_quorum_attestation_vector() -> Result<()> {
    let fixture = load_fixture_value("sync-fixture.json")?;
    let vector = required_field(&fixture, "snapshot_witness_quorum")?;
    if value_field_str(vector, "vector_id")? != VECTOR_ID_SNAPSHOT_WITNESS_QUORUM_ATTESTATION {
        bail!("sync fixture snapshot_witness_quorum block names another vector");
    }
    assert_registered_contexts(vector)?;

    let policy = policy_from_fixture(vector)?;
    let manifest = manifest_from_fixture(vector)?;
    assert_projection_and_digest(vector, &manifest)?;

    let cases = value_array(required_field(vector, "cases")?, "witness quorum cases")?;
    let mut seen = BTreeSet::new();
    for case in cases {
        let name = value_field_str(case, "name")?;
        if !seen.insert(name.to_owned()) {
            bail!("witness quorum fixture repeats case `{name}`");
        }
        run_case(name, case, vector, &manifest, &policy)?;
    }
    for required in REQUIRED_CASE_NAMES {
        if !seen.contains(*required) {
            bail!("witness quorum fixture no longer publishes case `{required}`");
        }
    }
    if seen.len() != REQUIRED_CASE_NAMES.len() {
        bail!(
            "witness quorum fixture publishes {} cases, this runner drives {}",
            seen.len(),
            REQUIRED_CASE_NAMES.len()
        );
    }
    Ok(())
}

/// The witness context is registered, is the one the SDK projection emits, and
/// is not the manifest context.
fn assert_registered_contexts(vector: &Value) -> Result<()> {
    let witness_context = value_field_str(vector, "proof_context")?;
    let manifest_context = value_field_str(vector, "manifest_proof_context")?;
    if witness_context == manifest_context {
        bail!("the witness and manifest proof contexts collapsed into one value");
    }
    if witness_context != ProofContextId::SNAPSHOT_WITNESS_ATTESTATION_PROOF_V1
        || witness_context != SNAPSHOT_WITNESS_ATTESTATION_PROOF_CONTEXT
    {
        bail!(
            "fixture witness context `{witness_context}` is not the registered `{}` the SDK \
             projection signs under",
            ProofContextId::SNAPSHOT_WITNESS_ATTESTATION_PROOF_V1
        );
    }
    if manifest_context != ProofContextId::SNAPSHOT_PROOF_V1 {
        bail!("fixture manifest context `{manifest_context}` is not the registered snapshot proof");
    }
    Ok(())
}

/// The canonical projection is exactly the fixture's `canonical_input`, its
/// digest is the fixture golden, and it carries no signature-bearing member.
fn assert_projection_and_digest(vector: &Value, manifest: &SnapshotManifest) -> Result<()> {
    let canonical_input = required_field(vector, "canonical_input")?;
    let witness_id = DidCoreId::new(value_field_str(canonical_input, "witness_id")?)?;
    let projection = manifest.witness_attestation_projection(&witness_id)?;
    if &projection != canonical_input {
        bail!(
            "the SDK witness projection diverged from the fixture canonical_input: {}",
            serde_json::to_string(&projection)?
        );
    }
    let digest = manifest.witness_attestation_digest(&witness_id)?;
    if digest.as_str() != value_field_str(vector, "expected_digest")? {
        bail!(
            "witness attestation digest golden mismatch: computed {}",
            digest.as_str()
        );
    }
    assert_projection_is_signature_free(&projection, FORBIDDEN_PROJECTION_MEMBERS)
}

fn assert_projection_is_signature_free(projection: &Value, forbidden: &[&str]) -> Result<()> {
    let members = projection
        .as_object()
        .ok_or_else(|| anyhow!("witness projection is not a JSON object"))?;
    for member in forbidden {
        if members.contains_key(*member) {
            bail!("witness attestation projection carries `{member}`");
        }
    }
    Ok(())
}

fn run_case(
    name: &str,
    case: &Value,
    vector: &Value,
    manifest: &SnapshotManifest,
    policy: &SnapshotWitnessQuorumPolicy,
) -> Result<()> {
    match name {
        "projection_must_not_contain_signature_fields" => {
            let witness_id = manifest.authority_binding.witness_attestations[0]
                .witness_id
                .clone();
            let projection = manifest.witness_attestation_projection(&witness_id)?;
            let forbidden = value_array(
                required_field(case, "forbidden_projection_members")?,
                "forbidden projection members",
            )?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| anyhow!("forbidden projection member is not a string"))
            })
            .collect::<Result<Vec<_>>>()?;
            assert_projection_is_signature_free(&projection, &forbidden)
        }

        // The transcript cases: a witness signature produced over another
        // context or another projection carries a digest the manifest's own
        // projection can never reproduce. The issuer legitimately signed the
        // manifest it published, so the list gates pass and the per-row
        // transcript check is what answers.
        "wrong_context_rejected" | "wrong_projection_rejected" => {
            let forged = required_field(case, "canonical_input")?;
            let forged_digest = arkret_canonical::canonical_sha256(forged)?;
            if forged_digest != value_field_str(case, "expected_digest")? {
                bail!("case `{name}` forged transcript digest golden mismatch: {forged_digest}");
            }
            if forged_digest == value_field_str(vector, "expected_digest")? {
                bail!(
                    "case `{name}` forged transcript reproduced the canonical digest; the member \
                     it mutates is not part of the signed bytes"
                );
            }
            let mut candidate = manifest.clone();
            candidate.authority_binding.witness_attestations[0]
                .proof
                .payload_digest = Hash::new(forged_digest)?;
            seal_issuer_signature(&mut candidate)?;
            expect_error(name, case, admit(&candidate, policy))
        }

        // The issuer signature covers the final ordered witness list. A row
        // appended after signing keeps the list sorted and unique, so the shape
        // gate passes and the issuer signature is the gate that detects it.
        "witness_list_rewritten_invalidates_issuer_signature" => {
            let sealed_digest = manifest.signature.payload_digest.clone();
            let mut candidate = manifest.clone();
            let intruder = intruder_attestation(case, vector, &candidate, policy)?;
            candidate
                .authority_binding
                .witness_attestations
                .push(intruder);
            if candidate.expected_signature_digest()? == sealed_digest {
                bail!("appending a witness row did not change the issuer signing transcript");
            }
            assert_signed_and_delivered_ids(case, manifest, &candidate)?;
            candidate.validate_witness_attestation_shape().map_err(|error| {
                anyhow!(
                    "a sorted, unique rewritten list must reach the issuer signature gate, but the \
                     shape gate answered first: {}",
                    error.message
                )
            })?;
            expect_error(name, case, admit(&candidate, policy))
        }

        // Rows MUST be sorted by `witness_id`; a receiver rejects the unsorted
        // list and MUST NOT normalize it first, so the shape gate answers
        // before the issuer signature is ever compared.
        "witness_list_reordered_invalidates_issuer_signature" => {
            let sealed_digest = manifest.signature.payload_digest.clone();
            let mut candidate = manifest.clone();
            candidate.authority_binding.witness_attestations.reverse();
            if candidate.expected_signature_digest()? == sealed_digest {
                bail!("reordering the witness rows did not change the issuer signing transcript");
            }
            assert_signed_and_delivered_ids(case, manifest, &candidate)?;
            expect_error(name, case, admit(&candidate, policy))
        }

        _ => {
            let mut candidate = manifest.clone();
            if case
                .get("witness_attestations_present")
                .and_then(Value::as_bool)
                == Some(false)
            {
                candidate.authority_binding.witness_attestations.clear();
            } else {
                candidate.authority_binding.witness_attestations =
                    attestations_from(case, &candidate)?;
            }
            let hints = candidate.verification_hints.as_mut().ok_or_else(|| {
                anyhow!("case `{name}`: the manifest carries no verification hints")
            })?;
            hints.witness_quorum = case
                .get("declared_witness_quorum")
                .and_then(Value::as_u64)
                .map(u32::try_from)
                .transpose()?;
            // The issuer published this exact list, so the list gates are not
            // what the case is about.
            seal_issuer_signature(&mut candidate)?;
            assert_deduplicated_count(name, case, &candidate, policy)?;

            let observed = admit(&candidate, policy);
            match case.get("expected").and_then(Value::as_str) {
                Some("snapshot_accepted") => observed.map_err(|error| {
                    anyhow!(
                        "case `{name}` must be accepted, got {}: {}",
                        error.code.as_str(),
                        error.message
                    )
                }),
                Some(other) => bail!("case `{name}` has unknown expected outcome `{other}`"),
                None => expect_error(name, case, observed),
            }
        }
    }
}

/// Receiver admission in normative order: the witness-list shape rule, then the
/// issuer signature over the final list, then quorum admission against the
/// accepted auth state.
fn admit(
    manifest: &SnapshotManifest,
    policy: &SnapshotWitnessQuorumPolicy,
) -> std::result::Result<(), SnapshotValidationError> {
    manifest.validate_witness_attestation_shape()?;
    let expected = manifest.expected_signature_digest().map_err(|error| {
        SnapshotValidationError::new(
            SnapshotValidationCode::DigestMismatch,
            format!("snapshot manifest signing transcript could not be computed: {error}"),
        )
    })?;
    if manifest.signature.payload_digest != expected {
        return Err(SnapshotValidationError::new(
            SnapshotValidationCode::SignatureInvalid,
            "snapshot manifest signature does not cover the delivered witness list",
        ));
    }
    manifest.verify_witness_attestations(policy)
}

/// Bind the manifest signature to the current `authority_binding`, i.e. model
/// an issuer that signed exactly the list it published.
fn seal_issuer_signature(manifest: &mut SnapshotManifest) -> Result<()> {
    manifest.signature.payload_digest = manifest.expected_signature_digest()?;
    Ok(())
}

/// The deduplicated per-`witness_id` count the fixture states must be the count
/// the manifest actually presents. Quorum is per witness, never per signature.
fn assert_deduplicated_count(
    name: &str,
    case: &Value,
    manifest: &SnapshotManifest,
    policy: &SnapshotWitnessQuorumPolicy,
) -> Result<()> {
    let Some(expected) = case
        .get("deduplicated_valid_witness_count")
        .and_then(Value::as_u64)
    else {
        return Ok(());
    };
    let observed = manifest
        .authority_binding
        .witness_attestations
        .iter()
        .filter(|attestation| {
            policy
                .authorized_witnesses
                .contains(&attestation.witness_id)
        })
        .map(|attestation| attestation.witness_id.clone())
        .collect::<BTreeSet<_>>()
        .len() as u64;
    if observed != expected {
        bail!(
            "case `{name}` states {expected} deduplicated authorized witnesses, the manifest \
             presents {observed}"
        );
    }
    Ok(())
}

fn assert_signed_and_delivered_ids(
    case: &Value,
    signed: &SnapshotManifest,
    delivered: &SnapshotManifest,
) -> Result<()> {
    for (field, manifest) in [
        ("issuer_signed_witness_ids", signed),
        ("delivered_witness_ids", delivered),
    ] {
        let expected = value_array(required_field(case, field)?, field)?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| anyhow!("{field} entry is not a string"))
            })
            .collect::<Result<Vec<_>>>()?;
        let observed = manifest
            .authority_binding
            .witness_attestations
            .iter()
            .map(|attestation| attestation.witness_id.to_string())
            .collect::<Vec<_>>();
        if observed != expected {
            bail!("{field} drifted: fixture states {expected:?}, this runner built {observed:?}");
        }
    }
    Ok(())
}

fn expect_error(
    name: &str,
    case: &Value,
    observed: std::result::Result<(), SnapshotValidationError>,
) -> Result<()> {
    let expected = value_field_str(case, "expected_error")?;
    match observed {
        Ok(()) => bail!("case `{name}` must be rejected with `{expected}` but was accepted"),
        Err(error) => {
            let code = error.code.as_str();
            if code != expected {
                bail!(
                    "case `{name}` rejected with `{code}` ({}), fixture expects `{expected}`",
                    error.message
                );
            }
            Ok(())
        }
    }
}

/// Build the manifest the fixture describes. Every witness row carries the
/// digest the SDK projection derives for that witness, and the issuer signature
/// is bound to the published list.
fn manifest_from_fixture(vector: &Value) -> Result<SnapshotManifest> {
    let fixture_manifest = required_field(vector, "manifest")?;
    let binding = required_field(fixture_manifest, "authority_binding")?;
    let hints = required_field(fixture_manifest, "verification_hints")?;
    let security_class = value_field_str(fixture_manifest, "security_class")?;
    let created_at = value_field_str(fixture_manifest, "created_at")?;
    let mut manifest: SnapshotManifest = serde_json::from_value(json!({
        "id": value_field_str(fixture_manifest, "snapshot_ref")?,
        "realm_id": value_field_str(fixture_manifest, "realm_id")?,
        "reducer_profile": value_field_str(fixture_manifest, "reducer_profile")?,
        "security_class": security_class,
        "schema_profile_refs": required_field(fixture_manifest, "schema_profile_refs")?,
        "state_digest": value_field_str(fixture_manifest, "state_digest")?,
        "frontier": required_field(fixture_manifest, "frontier")?,
        "event_set_commitment": required_field(fixture_manifest, "event_set_commitment")?,
        "verification_hints": {
            "verification_profile": security_class,
            "witness_quorum": required_field(hints, "witness_quorum")?,
        },
        "chunks": [],
        "created_by": value_field_str(fixture_manifest, "created_by")?,
        "created_at": created_at,
        "authority_binding": {
            "issuer": value_field_str(binding, "issuer")?,
            "authority_kind": value_field_str(binding, "authority_kind")?,
            "auth_state_digest": value_field_str(binding, "auth_state_digest")?,
            "auth_frontier": required_field(binding, "auth_frontier")?,
            "checked_at": value_field_str(binding, "checked_at")?,
            "witness_attestations": [],
        },
        "signature": {
            "kind": "detached_jws",
            "verification_method": "did:webvh:z6mkfixture:issuer.example#snapshot-key",
            "payload_digest": Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            "created_at": created_at,
            "jws": "eyJhbGciOiJFZDI1NTE5In0..c25hcHNob3Rpc3N1ZXI",
        },
    }))?;
    if manifest.authority_binding.authority_kind != SnapshotAuthorityKind::WitnessQuorum {
        bail!("witness quorum fixture manifest is not authority_kind=witness_quorum");
    }
    manifest.authority_binding.witness_attestations = attestations_from(binding, &manifest)?;
    seal_issuer_signature(&mut manifest)?;
    Ok(manifest)
}

/// Rebuild the witness rows a fixture object declares, recomputing every
/// `payload_digest` from the manifest's own projection so a case only ever
/// varies the witness set, never the transcript.
///
/// The projection excludes `witness_attestations` and `verification_hints`, so
/// the digests are stable across every case built from the same manifest.
fn attestations_from(
    source: &Value,
    manifest: &SnapshotManifest,
) -> Result<Vec<SnapshotWitnessAttestation>> {
    let rows = value_array(
        required_field(source, "witness_attestations")?,
        "witness attestations",
    )?;
    let mut attestations = Vec::with_capacity(rows.len());
    for row in rows {
        let witness_id = DidCoreId::new(value_field_str(row, "witness_id")?)?;
        let mut attestation: SnapshotWitnessAttestation = serde_json::from_value(json!({
            "witness_id": witness_id,
            "proof": required_field(row, "proof")?,
        }))?;
        attestation.proof.payload_digest = manifest.witness_attestation_digest(&witness_id)?;
        attestation.proof.jws = detached_jws_placeholder(&witness_id);
        attestations.push(attestation);
    }
    Ok(attestations)
}

/// The row a rewritten list appends: the delivered witness the issuer never
/// signed for, named by the fixture rather than invented here.
fn intruder_attestation(
    case: &Value,
    vector: &Value,
    manifest: &SnapshotManifest,
    policy: &SnapshotWitnessQuorumPolicy,
) -> Result<SnapshotWitnessAttestation> {
    let signed = value_array(
        required_field(case, "issuer_signed_witness_ids")?,
        "issuer signed witness ids",
    )?;
    let intruder = value_array(
        required_field(case, "delivered_witness_ids")?,
        "delivered witness ids",
    )?
    .iter()
    .filter_map(Value::as_str)
    .find(|delivered| {
        !signed
            .iter()
            .any(|value| value.as_str() == Some(*delivered))
    })
    .ok_or_else(|| anyhow!("the rewritten-list case delivers no unsigned witness row"))?;
    let intruder = DidCoreId::new(intruder)?;
    if policy.authorized_witnesses.contains(&intruder) {
        bail!("the rewritten-list intruder is an authorized witness");
    }
    let scid = intruder
        .as_str()
        .rsplit(':')
        .next()
        .ok_or_else(|| anyhow!("intruder witness id has no method-specific segment"))?;
    Ok(serde_json::from_value(json!({
        "witness_id": intruder,
        "proof": {
            "kind": "detached_jws",
            "verification_method": format!("did:webvh:{scid}:witness-d.example#snapshot-witness-1"),
            "payload_digest": manifest.witness_attestation_digest(&intruder)?,
            "created_at": value_field_str(required_field(vector, "manifest")?, "created_at")?,
            "jws": detached_jws_placeholder(&intruder),
        }
    }))?)
}

/// The quorum policy resolved from the accepted Realm auth state: only
/// witnesses authorized and not revoked at the resolution instant count, and a
/// witness the resolver could not confirm is left out so it can never reach
/// quorum.
fn policy_from_fixture(vector: &Value) -> Result<SnapshotWitnessQuorumPolicy> {
    let state = required_field(vector, "accepted_auth_state")?;
    let resolved_at: DateTime<Utc> = value_field_str(state, "resolved_at")?.parse()?;
    let threshold = state
        .get("witness_quorum_threshold")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("accepted auth state has no witness_quorum_threshold"))?;
    let mut authorized = BTreeSet::new();
    let mut revoked = BTreeMap::new();
    for row in value_array(
        required_field(state, "authorized_witnesses")?,
        "authorized witnesses",
    )? {
        let witness_id = DidCoreId::new(value_field_str(row, "witness_id")?)?;
        match row.get("revoked_at").and_then(Value::as_str) {
            Some(revoked_at) => {
                let revoked_at: DateTime<Utc> = revoked_at.parse()?;
                revoked.insert(witness_id.clone(), revoked_at);
                if revoked_at > resolved_at {
                    authorized.insert(witness_id);
                }
            }
            None => {
                authorized.insert(witness_id);
            }
        }
    }
    if revoked.is_empty() {
        bail!("the witness quorum fixture lost its revoked-witness row");
    }
    Ok(SnapshotWitnessQuorumPolicy {
        authorized_witnesses: authorized,
        threshold: u32::try_from(threshold)?,
    })
}

/// Structurally valid detached-JWS placeholder. Cryptographic verification of a
/// witness signature belongs to the caller's DID resolver; this vector drives
/// the transcript, ordering, authorization and threshold gates the SDK owns.
fn detached_jws_placeholder(witness_id: &DidCoreId) -> String {
    format!(
        "eyJhbGciOiJFZDI1NTE5In0..{}",
        witness_id
            .as_str()
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect::<String>()
    )
}
