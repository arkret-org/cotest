//! Schema / policy / realtime scenarios — split from the previous 600-line
//! `schema_policy_realtime.rs` during the round 28 Q1 refactor.
//!
//! Each submodule is single-responsibility:
//! - [`schema`] — `/_cokret/self/schemas` registry lifecycle and visibility.
//! - [`policy`] — `/_cokret/self/policies` document shape, decisions, and ownership.
//! - [`typing`] — `/_cokret/self/typing` + `/_cokret/self/push_rules` realtime strand.
//! - [`webrtc`] — `/_cokret/self/webrtc/*` session signaling strand and guards.
//!
//! No private helpers exist between scenarios in this family — the move is a
//! pure mechanical extraction.

pub mod policy;
pub mod schema;
pub mod typing;
pub mod webrtc;

pub use policy::policy_documents_shape_decisions_and_ownership_work;
pub use schema::schema_registry_lifecycle_and_visibility_work;
pub use typing::typing_and_push_rules_strand_work;
pub use webrtc::webrtc_session_signal_strand_and_guards_work;
