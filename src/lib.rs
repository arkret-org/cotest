//! Complement-style black-box conformance harness for Arkret servers.
//!
//! `cotest` keeps the executable harness and scenario logic in the main crate.
//! Integration test files are intentionally thin entrypoints.
//!
//! The standard Event authoring boundary is also a compile-time contract. A
//! marker cannot accept another kind's payload:
//!
//! ```compile_fail
//! use arkret_event_draft::TypedEventDraft;
//! use arkret_models_collaboration::events_payloads::{ContentBlock, MessageCreatePayload};
//! use arkret_wire::{DidCoreId, RealmId, ScopeRef, StrandId, event_spec};
//!
//! let scope = ScopeRef::Realm {
//!     realm_id: RealmId::new("ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir").unwrap(),
//! };
//! let payload = MessageCreatePayload::with_content(
//!     StrandId::new("ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9").unwrap(),
//!     "main",
//!     ContentBlock::text("wrong family"),
//! );
//! let _ = TypedEventDraft::<event_spec::RealmPolicy>::new(
//!     scope,
//!     DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
//!     DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
//!     payload,
//! );
//! ```
//!
//! The raw standard constructor is not public outside `arkret-wire`:
//!
//! ```compile_fail
//! use arkret_wire::{Did, Event, Hlc, RealmId, ScopeRef};
//!
//! let scope = ScopeRef::Realm {
//!     realm_id: RealmId::new("ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir").unwrap(),
//! };
//! let _ = Event::new(
//!     "ak.message.create",
//!     scope,
//!     Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
//!     1,
//!     Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
//!     serde_json::json!({}),
//! );
//! ```

// Doc-comment formatting in this crate uses heavily indented continuation
// lines, ASCII tables, and free-form bullet structures that pre-date
// clippy's CommonMark-strict lints. The substance is correct; reflowing
// hundreds of comments would create churn without changing behavior.
#![allow(clippy::doc_lazy_continuation, clippy::doc_overindented_list_items)]

pub mod conformance;
pub mod fixtures;
pub mod fuzz;
pub mod harness;
pub mod profile_validator;
pub mod publication;
pub mod scenarios;
pub mod transcripts;

/// Build a structurally valid, deterministic verified HandleClaim fixture.
///
/// The signatures are intentionally opaque fixture bytes; the shared model
/// validator still checks every core/status digest and proof transcript field.
pub fn fixture_verified_handle_claim(
    handle: &str,
    subject_account_id: arkret_wire::AccountId,
    issuer_id: arkret_wire::DidCoreId,
    audience: Option<String>,
    issued_at: chrono::DateTime<chrono::Utc>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> arkret_wire::Result<arkret_models_identity::HandleClaim> {
    use arkret_models_identity::{
        Handle, HandleClaim, HandleClaimCore, HandleClaimStatus, HandleClaimVariant,
        HandleVisibility,
    };
    use arkret_wire::{DidUrl, Hash, PayloadProof, PayloadProofPurpose};

    let verification_method = DidUrl::new(format!(
        "did:{}#handle-claim-fixture",
        issuer_id
            .as_str()
            .strip_prefix("ak:did_core:")
            .unwrap_or(issuer_id.as_str())
    ))
    .map_err(|error| arkret_wire::WireError::Protocol(error.to_owned()))?;
    let placeholder = Hash::new(format!("sha256:{}", "0".repeat(64)))?;
    let proof = |purpose, payload_digest| PayloadProof {
        kind: "detached_jws".to_owned(),
        verification_method: verification_method.clone(),
        payload_digest,
        created_at: issued_at,
        domain: Some(arkret_models_identity::HANDLE_CLAIM_PROOF_DOMAIN.to_owned()),
        audience: None,
        proof_purpose: Some(purpose),
        jws: "eyJhbGciOiJFZERTQSJ9..c2ln".to_owned(),
    };
    let mut core = HandleClaimCore {
        schema: HandleClaimCore::SCHEMA.to_owned(),
        handle: Handle::parse(handle)?,
        handle_aliases: Vec::new(),
        subject_account_id,
        issuer_id: issuer_id.clone(),
        claim: HandleClaimVariant::HandleBinding,
        visibility: if audience.is_some() {
            HandleVisibility::Restricted
        } else {
            HandleVisibility::Public
        },
        audience,
        issued_at,
        expires_at,
        source_refs: Vec::new(),
        proofs: [
            proof(PayloadProofPurpose::IssuerAttestation, placeholder.clone()),
            proof(PayloadProofPurpose::HolderAcceptance, placeholder.clone()),
        ],
    };
    let claim_digest = core.claim_digest()?;
    core.proofs[0].payload_digest = claim_digest.clone();
    core.proofs[1].payload_digest = claim_digest.clone();

    let maximum_fresh_until = issued_at + chrono::Duration::seconds(300);
    let fresh_until = expires_at
        .map(|expires| expires.min(maximum_fresh_until))
        .unwrap_or(maximum_fresh_until);
    let mut claim = HandleClaim {
        schema: HandleClaim::SCHEMA.to_owned(),
        claim: core,
        claim_digest,
        status: HandleClaimStatus::Verified,
        as_of: issued_at,
        verifier_id: issuer_id,
        verified_at: Some(issued_at),
        revocation: None,
        revocation_digest: None,
        fresh_until,
        status_proof: proof(PayloadProofPurpose::StatusAttestation, placeholder),
    };
    claim.status_proof.domain = Some(arkret_models_identity::HANDLE_CLAIM_STATUS_DOMAIN.to_owned());
    claim.status_proof.payload_digest = claim.status_digest()?;
    claim.validate()?;
    Ok(claim)
}

/// Build a deterministic, suite-tagged Event identity for fixtures that refer
/// to an Event but do not carry that Event's envelope.
///
/// Real Event fixtures must derive their identity from `Event::digest_payload`;
/// this helper is only for opaque reference samples and missing-id probes.
pub fn fixture_event_id(label: impl AsRef<[u8]>) -> arkret_wire::EventId {
    use sha2::{Digest, Sha256};

    arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        Sha256::digest(label.as_ref()).into(),
    )
}

/// A fixture verification method as the SDK's `arkret_wire::DidUrl`.
///
/// `zh/identity/did-usage-and-verification.md` §2.2 requires every
/// `verification_method` to be a DID URL with a `#fragment`; a bare DID is a
/// fixture bug, not something the type should be widened to accept. Fixture
/// values are compile-time constants of this harness, so a violation is a
/// programming error and panics here rather than being threaded through every
/// builder's error type.
#[track_caller]
pub fn fixture_did_url(value: impl Into<String>) -> arkret_wire::DidUrl {
    let value = value.into();
    arkret_wire::DidUrl::new(value.clone())
        .unwrap_or_else(|error| panic!("cotest fixture verification method {value:?}: {error}"))
}

/// Build a deterministic frozen Ed25519 notary signer for fixtures.
#[track_caller]
pub fn fixture_notary_signer(
    actor_id: arkret_wire::DidCoreId,
) -> arkret_wire::NotarySignerDescriptor {
    let controller = actor_id
        .as_str()
        .strip_prefix("ak:did_core:")
        .unwrap_or_else(|| panic!("fixture notary actor is not a DID-core id: {actor_id}"))
        .to_owned();
    // A WebVH core intentionally retains only the SCID, so prefix
    // substitution cannot recreate a resolvable DID. Fixtures still need
    // a syntactically complete verification-method controller that projects
    // back to the same core; use a closed test-only method coordinate for it.
    let controller = if controller.starts_with("webvh:") {
        format!("{controller}:cotest.invalid:webvh:notary-fixture")
    } else {
        controller
    };
    fixture_notary_signer_for_method(
        actor_id,
        fixture_did_url(format!("did:{controller}#notary-key-1")),
    )
}

/// Build a deterministic frozen Ed25519 notary signer for an exact fixture
/// verification method.
#[track_caller]
pub fn fixture_notary_signer_for_method(
    actor_id: arkret_wire::DidCoreId,
    verification_method: arkret_wire::DidUrl,
) -> arkret_wire::NotarySignerDescriptor {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha256};

    let public_key: [u8; 32] = Sha256::digest(actor_id.as_str().as_bytes()).into();
    let frozen_public_key_b64u = URL_SAFE_NO_PAD.encode(public_key);
    let frozen_public_key_digest = arkret_wire::Hash::new(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(public_key))
    ))
    .unwrap_or_else(|error| panic!("fixture notary digest is invalid: {error}"));
    arkret_wire::NotarySignerDescriptor {
        actor_id: arkret_wire::ActorId::service(actor_id),
        verification_method,
        key_kind: arkret_wire::NotaryKeyKind::Ed25519Raw32,
        jose_algorithm: arkret_wire::NotaryJoseAlgorithm::Ed25519,
        frozen_public_key_b64u,
        frozen_public_key_digest,
    }
}

#[track_caller]
pub fn fixture_single_signer_notary(actor_id: arkret_wire::DidCoreId) -> arkret_wire::NotaryValue {
    arkret_wire::NotaryValue::single_signer(fixture_notary_signer(actor_id))
}

/// Build a deterministic content-addressed signer-evidence reference pair for
/// Event fixtures that do not carry a Station admission proof.
#[track_caller]
pub fn fixture_signer_evidence_pair(
    label: impl AsRef<[u8]>,
) -> (arkret_wire::SignerEvidenceRef, arkret_wire::Hash) {
    use sha2::{Digest, Sha256};

    let digest_hex = hex::encode(Sha256::digest(label.as_ref()));
    let reference =
        arkret_wire::SignerEvidenceRef::new(format!("ak:signer_evidence:sha256:{digest_hex}"))
            .unwrap_or_else(|error| panic!("fixture signer-evidence ref is invalid: {error}"));
    let digest = arkret_wire::Hash::new(format!("sha256:{digest_hex}"))
        .unwrap_or_else(|error| panic!("fixture signer-evidence digest is invalid: {error}"));
    (reference, digest)
}
