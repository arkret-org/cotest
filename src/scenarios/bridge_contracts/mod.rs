//! Bridge-contract scenarios — split from the previous 1300-line
//! `bridge_contracts.rs` during the round 28 Q1 refactor.
//!
//! Each submodule is single-responsibility:
//! - [`discovery`] — `/api/v1/auth/bridge/describe` + `/api/v1/push/outbound/bridge/describe` smoke
//!   check (`principal_bridge_contracts_are_discoverable`).
//! - [`session_grant`] — coauth-backed `/api/v1/auth/session-grant/exchange` flow
//!   (`session_grant_exchange_uses_configured_coauth_introspection`).
//! - [`starid`] — optional `did:webvh` resolver profile discoverability
//!   (`starid_optional_resolver_profile_is_discoverable`).
//!
//! Helpers shared by 2+ scenarios live in
//! [`crate::scenarios::_helpers::bridge`].

pub mod discovery;
pub mod session_grant;
pub mod starid;

pub use discovery::principal_bridge_contracts_are_discoverable;
pub use session_grant::session_grant_exchange_uses_configured_coauth_introspection;
pub use starid::starid_optional_resolver_profile_is_discoverable;
