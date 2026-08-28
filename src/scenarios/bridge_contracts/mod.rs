//! Bridge-contract scenarios — split from the previous 1300-line
//! `bridge_contracts.rs` during the round 28 Q1 refactor.
//!
//! Each submodule is single-responsibility:
//! - [`discovery`] — `/_soland/gate/auth/bridge/describe` smoke check
//!   (`principal_bridge_contracts_are_discoverable`). Push-gateway discovery is canonical
//!   `ServiceDescribe` and is covered by the push conformance suite.
//! - [`session_grant`] — coauth-backed session-grant presentation support
//!   (`session_grant_presentation_uses_configured_coauth_introspection`).
//! - [`external_webvh_provider`] — soland's `did:webvh` provider discovery when an external
//!   provider is configured (`external_webvh_provider_is_discoverable`).
//!
//! Helpers shared by 2+ scenarios live in
//! [`crate::scenarios::_helpers::bridge`].

pub mod discovery;
pub mod external_webvh_provider;
pub mod session_grant;

pub use discovery::principal_bridge_contracts_are_discoverable;
pub use external_webvh_provider::external_webvh_provider_is_discoverable;
pub use session_grant::session_grant_presentation_uses_configured_coauth_introspection;
