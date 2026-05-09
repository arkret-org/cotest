//! Schema / policy / realtime scenarios — split from the previous 600-line
//! `schema_policy_realtime.rs` during the round 28 Q1 refactor.
//!
//! Each submodule is single-responsibility:
//! - [`schema`] — `/api/v1/schemas` registry lifecycle and visibility.
//! - [`policy`] — `/api/v1/policies` document shape, decisions, and ownership.
//! - [`typing`] — `/api/v1/typing` + `/api/v1/push_rules` realtime flow.
//! - [`webrtc`] — `/api/v1/webrtc/*` session signaling flow and guards.
//!
//! No private helpers exist between scenarios in this family — the move is a
//! pure mechanical extraction.

pub mod policy;
pub mod schema;
pub mod typing;
pub mod webrtc;

pub use policy::policy_documents_shape_decisions_and_ownership_work;
pub use schema::schema_registry_lifecycle_and_visibility_work;
pub use typing::typing_and_push_rules_flow_work;
pub use webrtc::webrtc_session_signal_flow_and_guards_work;
