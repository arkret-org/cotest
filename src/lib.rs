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
//! use arkret_wire::{DidFullId, RealmId, ScopeRef, StrandId, event_spec};
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
//!     DidFullId::new("did:webvh:z6mkfixture:alice.example").unwrap(),
//!     payload,
//! );
//! ```
//!
//! A typed draft exposes no runtime kind override:
//!
//! ```compile_fail
//! use arkret_event_draft::TypedEventDraft;
//! use arkret_models_collaboration::events_payloads::StatePayload;
//! use arkret_wire::{DidFullId, EventKind, RealmId, ScopeRef, event_spec};
//!
//! let draft = TypedEventDraft::<event_spec::RealmPolicy>::new(
//!     ScopeRef::Realm {
//!         realm_id: RealmId::new("ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir").unwrap(),
//!     },
//!     DidFullId::new("did:webvh:z6mkfixture:alice.example").unwrap(),
//!     StatePayload { value: None, state: Some("active".to_owned()), reason: None },
//! ).unwrap();
//! let _ = draft.with_kind(EventKind::MessageCreate);
//! ```
//!
//! The raw standard constructor is not public outside `arkret-wire`:
//!
//! ```compile_fail
//! use arkret_wire::{DidFullId, Event, Hlc, RealmId, ScopeRef};
//!
//! let scope = ScopeRef::Realm {
//!     realm_id: RealmId::new("ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir").unwrap(),
//! };
//! let _ = Event::new(
//!     "ak.message.create",
//!     scope,
//!     DidFullId::new("did:webvh:z6mkfixture:alice.example").unwrap(),
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

pub const HARNESS_NAME: &str = "cotest";

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
