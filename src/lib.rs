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
    fixture_verified_handle_claim_at(
        handle,
        subject_account_id,
        issuer_id,
        audience,
        issued_at,
        expires_at,
        issued_at,
    )
}

/// Build a verified HandleClaim fixture whose signed status view is fresh at
/// `status_as_of`, independently of the immutable core's issuance timestamp.
///
/// Selection and directory vectors intentionally replay old claim cores under
/// a current status attestation. Keeping those clocks separate prevents a
/// weeks-old core from being mistaken for a fresh status view.
pub fn fixture_verified_handle_claim_at(
    handle: &str,
    subject_account_id: arkret_wire::AccountId,
    issuer_id: arkret_wire::DidCoreId,
    audience: Option<String>,
    issued_at: chrono::DateTime<chrono::Utc>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    status_as_of: chrono::DateTime<chrono::Utc>,
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
    let proof = |purpose, payload_digest, created_at| PayloadProof {
        kind: "detached_jws".to_owned(),
        verification_method: verification_method.clone(),
        payload_digest,
        created_at,
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
            proof(
                PayloadProofPurpose::IssuerAttestation,
                placeholder.clone(),
                issued_at,
            ),
            proof(
                PayloadProofPurpose::HolderAcceptance,
                placeholder.clone(),
                issued_at,
            ),
        ],
    };
    let claim_digest = core.claim_digest()?;
    core.proofs[0].payload_digest = claim_digest.clone();
    core.proofs[1].payload_digest = claim_digest.clone();

    let maximum_fresh_until = status_as_of + chrono::Duration::seconds(300);
    let fresh_until = expires_at
        .map(|expires| expires.min(maximum_fresh_until))
        .unwrap_or(maximum_fresh_until);
    let mut claim = HandleClaim {
        schema: HandleClaim::SCHEMA.to_owned(),
        claim: core,
        status: HandleClaimStatus::Verified,
        as_of: status_as_of,
        verifier_id: issuer_id,
        verified_at: Some(status_as_of),
        revocation: None,
        fresh_until,
        status_proof: proof(
            PayloadProofPurpose::StatusAttestation,
            placeholder,
            status_as_of,
        ),
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

/// Build a deterministic content-addressed signer-evidence reference pair for
/// Event fixtures whose sole producer proof needs portable signer evidence.
#[track_caller]
pub fn fixture_signer_evidence_ref(label: impl AsRef<[u8]>) -> arkret_wire::SignerEvidenceRef {
    use sha2::{Digest, Sha256};

    let digest_hex = hex::encode(Sha256::digest(label.as_ref()));
    arkret_wire::SignerEvidenceRef::new(format!("ak:signer_evidence:sha256:{digest_hex}"))
        .unwrap_or_else(|error| panic!("fixture signer-evidence ref is invalid: {error}"))
}
