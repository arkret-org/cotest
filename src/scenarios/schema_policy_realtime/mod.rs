//! Schema / policy / realtime scenarios.
//!
//! Each submodule is single-responsibility:
//! - [`schema`] — `/_arkret/self/schemas` registry lifecycle and visibility.
//! - [`policy`] — `/_soland/self/policies` document shape, decisions, and ownership.
//! - [`typing`] — `/_arkret/self/typing` + `/_arkret/self/push_rules` realtime strand.
//! - [`webrtc`] — `/_arkret/self/rtc/*` media surface and guards.
//!
//! No private helpers are shared between the scenarios in this family.

pub mod policy;
pub mod schema;
pub mod typing;
pub mod webrtc;

pub use policy::policy_documents_shape_decisions_and_ownership_work;
pub use schema::schema_registry_lifecycle_and_visibility_work;
pub use typing::typing_and_push_rules_strand_work;
pub use webrtc::webrtc_session_signal_strand_and_guards_work;
