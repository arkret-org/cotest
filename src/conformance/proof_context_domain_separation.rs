//! Per-object-family proof-context domain separation for MIMI
//! (`extensions/mimi-interop.md` §5.1) request and outcome families.
//!
//! v1 has no `ak.directory_operation_proof.v1` / `ak.mimi_operation_proof.v1`.
//! Every request and outcome family carries its own registered context, so a
//! signature minted for one family can never be replayed onto another. This
//! module drives that closure from three sides:
//!
//! 1. **Registry closure** — the six per-family contexts exist in `registry/proof-context-
//!    registry.json`, are bound to their own `object_family`, are pairwise distinct and are all
//!    reachable through the shared [`ProofContextId`] vocabulary. The two retired over-broad
//!    contexts resolve nowhere.
//! 2. **Owner closure** — each family's SDK binding transcript really emits its own context. The
//!    context string is read back out of the canonical transcript the owning type produced, never
//!    restated here.
//! 3. **Theft matrix** — a proof signed under family A's transcript, re-pointed at family B's body,
//!    MUST be rejected by B. The stolen proof's `payload_digest` is rewritten to B's own body
//!    digest first, so B's digest gate admits it and the rejection can only come from the
//!    domain-separated transcript. A focused `context`-only mutation then shows the context member
//!    alone flips the decision while every other transcript member is byte-identical.
//!
//! `mimi_update_consent_request` carries its proof in the dedicated
//! `signature` member rather than `proofs[]`, and its transcript is produced by
//! [`MimiUpdateConsentRequestBody::signature_binding_bytes`]. It is covered by
//! the registry and owner closures here; its wire producer lives in
//! `src/bin/cotest-wire.rs`.

use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use arkret_models_collaboration::http_bodies::{
    MimiIdentifierQueryOutcome, MimiIdentifierQueryRequestBody, MimiKeyMaterialOutcome,
    MimiKeyMaterialRequestBody, MimiRequestConsentRequestBody,
};
use arkret_signatures::proof::sign_ed25519_detached_jws;
use arkret_signatures::{PublicKeyMaterial, verify_ed25519_detached_jws_payload_proof};
use arkret_wire::{
    Audience, DidUrl, DomainSeparationId, Hash, PayloadProof, ProofContextId, proof_kind,
};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

use super::load_artifact_json;

/// The six MIMI operation families that replaced the retired over-broad
/// `ak.mimi_operation_proof.v1`.
pub const MIMI_PER_FAMILY_PROOF_CONTEXTS: &[(&str, &str)] = &[
    (
        ProofContextId::MIMI_IDENTIFIER_QUERY_OUTCOME_PROOF_V1,
        "mimi_identifier_query_outcome",
    ),
    (
        ProofContextId::MIMI_IDENTIFIER_QUERY_REQUEST_PROOF_V1,
        "mimi_identifier_query_request",
    ),
    (
        ProofContextId::MIMI_KEY_MATERIAL_OUTCOME_PROOF_V1,
        "mimi_key_material_outcome",
    ),
    (
        ProofContextId::MIMI_KEY_MATERIAL_REQUEST_PROOF_V1,
        "mimi_key_material_request",
    ),
    (
        ProofContextId::MIMI_REQUEST_CONSENT_REQUEST_PROOF_V1,
        "mimi_request_consent_request",
    ),
    (
        ProofContextId::MIMI_UPDATE_CONSENT_REQUEST_PROOF_V1,
        "mimi_update_consent_request",
    ),
];

/// Contexts the spec retired when the per-family split landed. They must not
/// resolve through the registry or the shared vocabulary; a receiver that still
/// accepted one would accept a proof minted for any sibling operation.
const RETIRED_OVER_BROAD_CONTEXTS: &[&str] = &[
    "ak.directory_operation_proof.v1",
    "ak.mimi_operation_proof.v1",
];

const MIMI_AUDIENCE: &str = "ak:did_core:web:provider.example";
const MIMI_DOMAIN: &str = "https://provider.example";
const REQUESTER_ID: &str = "ak:did_core:web:alice.example";
const VERIFICATION_METHOD: &str = "did:web:alice.example#requester-key";
const PROOF_CREATED_AT: &str = "2026-08-17T00:00:00.000Z";

/// One object family under test: the transcript its owning SDK type builds and
/// the canonical digest of the body that transcript is bound to.
struct FamilyUnderTest {
    name: &'static str,
    expected_context: &'static str,
    payload_digest: Hash,
    #[allow(clippy::type_complexity)]
    binding_bytes: Box<dyn Fn(&PayloadProof) -> Result<Vec<u8>>>,
}

pub fn run_proof_context_domain_separation_vector() -> Result<()> {
    assert_registry_closure()?;

    let signing_key = SigningKey::from_bytes(&[73; 32]);
    let public_key = PublicKeyMaterial::Ed25519Raw {
        bytes: signing_key.verifying_key().to_bytes().to_vec(),
    };

    let mimi = mimi_families()?;
    assert_owner_closure(&mimi, MIMI_PER_FAMILY_PROOF_CONTEXTS, true)?;
    assert_cross_family_theft_is_rejected(&mimi, &signing_key, &public_key, true)?;
    assert_context_alone_decides(&mimi, &signing_key, &public_key, true)?;
    Ok(())
}

/// Every per-family signing domain is registered, bound to its own
/// `object_family`, distinct from its siblings, and reachable through the shared
/// vocabulary.
///
/// MIMI schemas reach the shared `event-envelope.schema.json#/$defs/proof`
/// leaf and therefore belong in `contexts[]`, never `domain_separations[]`.
fn assert_registry_closure() -> Result<()> {
    let registry = load_artifact_json("registry/proof-context-registry.json")?;
    let contexts = registry
        .get("contexts")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("proof-context registry has no contexts[]"))?;
    let separations = registry
        .get("domain_separations")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("proof-context registry has no domain_separations[]"))?;

    let mut seen = BTreeSet::new();
    for (context, object_family) in MIMI_PER_FAMILY_PROOF_CONTEXTS {
        if !seen.insert(*context) {
            bail!("per-family proof context `{context}` is declared twice");
        }
        let row = contexts
            .iter()
            .find(|row| row.get("context").and_then(Value::as_str) == Some(*context))
            .ok_or_else(|| {
                anyhow!(
                    "proof-context registry does not publish per-family context \
                         `{context}` in contexts[]"
                )
            })?;
        if separations
            .iter()
            .any(|row| row.get("domain").and_then(Value::as_str) == Some(*context))
        {
            bail!(
                "proof context `{context}` is registered in both lists; its anchoring \
                     must be decidable from the schema alone"
            );
        }
        if row.get("object_family").and_then(Value::as_str) != Some(*object_family) {
            bail!(
                "proof context `{context}` is not bound to object family `{object_family}`; a \
                     context shared by two families is exactly the over-broad shape v1 removed"
            );
        }
        if ProofContextId::from_wire(context).is_none() {
            bail!("per-family proof context `{context}` is absent from the shared vocabulary");
        }
    }
    if seen.len() != 6 {
        bail!(
            "expected 6 per-family MIMI proof contexts, found {}",
            seen.len()
        );
    }

    for retired in RETIRED_OVER_BROAD_CONTEXTS {
        let registered = contexts
            .iter()
            .any(|row| row.get("context").and_then(Value::as_str) == Some(*retired))
            || separations
                .iter()
                .any(|row| row.get("domain").and_then(Value::as_str) == Some(*retired));
        if registered {
            bail!("retired over-broad proof context `{retired}` is still registered");
        }
        if ProofContextId::from_wire(retired).is_some()
            || DomainSeparationId::from_wire(retired).is_some()
        {
            bail!("retired over-broad proof context `{retired}` still parses in the SDK");
        }
    }
    Ok(())
}

/// Each family's own SDK transcript really carries its own context, read back
/// out of the canonical bytes rather than restated by this suite.
fn assert_owner_closure(
    families: &[FamilyUnderTest],
    registered: &[(&str, &str)],
    mimi: bool,
) -> Result<()> {
    let mut observed = BTreeSet::new();
    for family in families {
        let proof = unsigned_proof(&family.payload_digest, mimi)?;
        let binding = (family.binding_bytes)(&proof)?;
        let context = transcript_member(&binding, "context")?;
        if context != family.expected_context {
            bail!(
                "family `{}` signs under context `{context}`, expected `{}`",
                family.name,
                family.expected_context
            );
        }
        if !observed.insert(context) {
            bail!(
                "family `{}` reuses a sibling's proof context; per-family separation is gone",
                family.name
            );
        }
    }
    for (context, _) in registered {
        // `mimi_update_consent_request` binds through `signature_binding_bytes`
        // and is exercised by the cotest-wire producer, so it is registered
        // here without a matrix row.
        if !observed.contains(*context)
            && *context != ProofContextId::MIMI_UPDATE_CONSENT_REQUEST_PROOF_V1
        {
            bail!("registered per-family context `{context}` has no owning SDK transcript here");
        }
    }
    Ok(())
}

/// The theft matrix: a proof minted for family A, re-pointed at family B.
///
/// The stolen proof's `payload_digest` is rewritten to B's own body digest, so
/// B's digest gate admits the proof and the rejection can only be the
/// domain-separated transcript.
fn assert_cross_family_theft_is_rejected(
    families: &[FamilyUnderTest],
    signing_key: &SigningKey,
    public_key: &PublicKeyMaterial,
    mimi: bool,
) -> Result<()> {
    for source in families {
        let proof = signed_proof(&source.payload_digest, mimi, signing_key, |proof| {
            (source.binding_bytes)(proof)
        })?;
        verify_ed25519_detached_jws_payload_proof(
            &proof,
            &(source.binding_bytes)(&proof)?,
            public_key,
        )
        .map_err(|error| {
            anyhow!(
                "family `{}` rejected its own freshly minted proof: {error}",
                source.name
            )
        })?;

        for target in families {
            if target.name == source.name {
                continue;
            }
            let mut stolen = proof.clone();
            stolen.payload_digest = target.payload_digest.clone();

            // The digest gate must not be what rejects the theft: the target
            // family has to build its transcript over the stolen proof before
            // the signature is ever compared.
            let target_binding = (target.binding_bytes)(&stolen).map_err(|error| {
                anyhow!(
                    "target family `{}` refused to build a transcript for the stolen `{}` proof \
                     ({error}); the digest gate would then be the reason for rejection instead of \
                     domain separation",
                    target.name,
                    source.name
                )
            })?;
            if transcript_member(&target_binding, "payload_digest")?
                != target.payload_digest.as_str()
            {
                bail!(
                    "target family `{}` did not bind the stolen proof to its own body digest",
                    target.name
                );
            }
            if verify_ed25519_detached_jws_payload_proof(&stolen, &target_binding, public_key)
                .is_ok()
            {
                bail!(
                    "a proof minted under `{}` was accepted by `{}`; the per-family contexts do \
                     not separate the two operations",
                    source.expected_context,
                    target.expected_context
                );
            }
        }
    }
    Ok(())
}

/// Isolate the `context` member: two transcripts identical in every other byte
/// still decide differently.
fn assert_context_alone_decides(
    families: &[FamilyUnderTest],
    signing_key: &SigningKey,
    public_key: &PublicKeyMaterial,
    mimi: bool,
) -> Result<()> {
    let [source, target] = [
        families
            .first()
            .ok_or_else(|| anyhow!("no source family"))?,
        families.get(1).ok_or_else(|| anyhow!("no target family"))?,
    ];

    let proof = unsigned_proof(&target.payload_digest, mimi)?;
    let target_binding = (target.binding_bytes)(&proof)?;
    let mut forged: Value = serde_json::from_slice(&target_binding)?;
    forged
        .as_object_mut()
        .ok_or_else(|| anyhow!("proof binding transcript is not a JSON object"))?
        .insert(
            "context".to_owned(),
            Value::String(source.expected_context.to_owned()),
        );
    let forged_bytes = arkret_canonical::canonical_json_bytes(&forged)?;
    if forged_bytes == target_binding {
        bail!(
            "swapping `{}` for `{}` did not change the transcript; the context member is not part \
             of the signed bytes",
            target.expected_context,
            source.expected_context
        );
    }

    let mut signed = proof;
    signed.jws = sign_ed25519_detached_jws(signing_key, &forged_bytes)
        .map_err(|error| anyhow!("sign forged-context transcript: {error}"))?;
    // Same key, same body digest, same verification_method / created_at /
    // domain / audience: only `context` differs, and only the forged transcript
    // verifies.
    verify_ed25519_detached_jws_payload_proof(&signed, &forged_bytes, public_key)
        .map_err(|error| anyhow!("forged-context transcript did not verify at all: {error}"))?;
    if verify_ed25519_detached_jws_payload_proof(&signed, &target_binding, public_key).is_ok() {
        bail!(
            "`{}` accepted a signature made under `{}` over an otherwise byte-identical transcript",
            target.expected_context,
            source.expected_context
        );
    }
    Ok(())
}

fn transcript_member(binding_bytes: &[u8], member: &str) -> Result<String> {
    let value: Value = serde_json::from_slice(binding_bytes)?;
    value
        .get(member)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("proof binding transcript has no string `{member}` member"))
}

fn unsigned_proof(payload_digest: &Hash, mimi: bool) -> Result<PayloadProof> {
    Ok(PayloadProof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        verification_method: DidUrl::new(VERIFICATION_METHOD).map_err(anyhow::Error::msg)?,
        payload_digest: payload_digest.clone(),
        created_at: PROOF_CREATED_AT.parse()?,
        // The MIMI binding requires the provider domain and audience.
        domain: mimi.then(|| MIMI_DOMAIN.to_owned()),
        audience: Some(Audience::Single(MIMI_AUDIENCE.to_owned())),
        proof_purpose: None,
        // The carrier is overwritten by the real detached JWS a line later,
        // but  now rejects anything that is not
        // compact-JWS shaped, so the placeholder has to be shaped like one.
        jws: "eyJhbGciOiJFZDI1NTE5In0..cGxhY2Vob2xkZXI".to_owned(),
    })
}

fn signed_proof(
    payload_digest: &Hash,
    mimi: bool,
    signing_key: &SigningKey,
    binding_bytes: impl Fn(&PayloadProof) -> Result<Vec<u8>>,
) -> Result<PayloadProof> {
    let mut proof = unsigned_proof(payload_digest, mimi)?;
    let binding = binding_bytes(&proof)?;
    proof.jws = sign_ed25519_detached_jws(signing_key, &binding)
        .map_err(|error| anyhow!("sign per-family proof transcript: {error}"))?;
    Ok(proof)
}

fn mimi_families() -> Result<Vec<FamilyUnderTest>> {
    let identifier_query_outcome: MimiIdentifierQueryOutcome = serde_json::from_value(json!({
        "matches": [{
            "identifier_commitment":
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "matched": true
        }],
        "has_more": false
    }))?;
    let identifier_query_request: MimiIdentifierQueryRequestBody = serde_json::from_value(json!({
        "identifiers": [{
            "kind": "handle",
            "identifier_commitment":
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        }],
        "requester_id": REQUESTER_ID
    }))?;
    let key_material_outcome: MimiKeyMaterialOutcome = serde_json::from_value(json!({}))?;
    let key_material_request: MimiKeyMaterialRequestBody = serde_json::from_value(json!({
        "requester_id": REQUESTER_ID,
        "strand_id": "ak:strand:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
        "device_id": "ak:device:01904100-0000-7000-8000-000000000001"
    }))?;
    // The signed request names both identities in full; the proof issuer is
    // the complete Actor and holder_account_id is a binding field. Ruling
    // `tasks/spec-done/2026-09-05-1240-mimi-consent-correlation-cannot-carry-the-consent-peer.md`.
    let request_consent: MimiRequestConsentRequestBody = serde_json::from_value(json!({
        "requester_actor_id": {
            "kind": "account",
            "account_id": {
                "principal_id": REQUESTER_ID,
                "station_id": "ak:did_core:web:requester-station.example"
            }
        },
        "holder_account_id": {
            "principal_id": "ak:did_core:web:bob.example",
            "station_id": "ak:did_core:web:holder-station.example"
        },
        "purpose": "voice_call",
        "proofs": []
    }))?;

    Ok(vec![
        family(
            "mimi_identifier_query_outcome",
            ProofContextId::MIMI_IDENTIFIER_QUERY_OUTCOME_PROOF_V1,
            identifier_query_outcome.payload_digest()?,
            move |proof| Ok(identifier_query_outcome.proof_binding_bytes(proof)?),
        ),
        family(
            "mimi_identifier_query_request",
            ProofContextId::MIMI_IDENTIFIER_QUERY_REQUEST_PROOF_V1,
            identifier_query_request.payload_digest()?,
            move |proof| Ok(identifier_query_request.proof_binding_bytes(proof)?),
        ),
        family(
            "mimi_key_material_outcome",
            ProofContextId::MIMI_KEY_MATERIAL_OUTCOME_PROOF_V1,
            key_material_outcome.payload_digest()?,
            move |proof| Ok(key_material_outcome.proof_binding_bytes(proof)?),
        ),
        family(
            "mimi_key_material_request",
            ProofContextId::MIMI_KEY_MATERIAL_REQUEST_PROOF_V1,
            key_material_request.payload_digest()?,
            move |proof| Ok(key_material_request.proof_binding_bytes(proof)?),
        ),
        family(
            "mimi_request_consent_request",
            ProofContextId::MIMI_REQUEST_CONSENT_REQUEST_PROOF_V1,
            request_consent.payload_digest()?,
            move |proof| Ok(request_consent.proof_binding_bytes(proof)?),
        ),
    ])
}

fn family(
    name: &'static str,
    expected_context: &'static str,
    payload_digest: Hash,
    binding_bytes: impl Fn(&PayloadProof) -> Result<Vec<u8>> + 'static,
) -> FamilyUnderTest {
    FamilyUnderTest {
        name,
        expected_context,
        payload_digest,
        binding_bytes: Box::new(binding_bytes),
    }
}
