//! Bridge-contract scenarios — split from the previous 1300-line
//! `bridge_contracts.rs` during the round 28 Q1 refactor.
//!
//! Each submodule is single-responsibility:
//! - [`discovery`] — `/_soland/gate/auth/bridge/describe` +
//!   `/_soland/edge/push/outbound/bridge/describe` smoke check
//!   (`principal_bridge_contracts_are_discoverable`).
//! - [`session_grant`] — coauth-backed session-grant presentation support
//!   (`session_grant_presentation_uses_configured_coauth_introspection`).
//! - [`starid`] — optional `did:webvh` resolver profile discoverability
//!   (`starid_optional_resolver_profile_is_discoverable`).
//!
//! Helpers shared by 2+ scenarios live in
//! [`crate::scenarios::_helpers::bridge`].

pub mod discovery;
pub mod session_grant;
pub mod starid;

pub use discovery::principal_bridge_contracts_are_discoverable;
pub use session_grant::session_grant_presentation_uses_configured_coauth_introspection;
pub use starid::starid_optional_resolver_profile_is_discoverable;
