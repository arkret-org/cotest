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
