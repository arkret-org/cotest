//! Identity / directory / index scenarios — split from the previous 834-line
//! `identity_directory_index.rs` during the round 28 Q1 refactor.
//!
//! Each submodule is single-responsibility:
//! - [`identity`] — `/api/v1/identity/*` describe/resolve/document/log/submit/receipts.
//! - [`discovery`] — `/api/v1/discovery/*` profile and demo index projections.
//! - [`contacts`] — contacts/invites listing/export/audit flow.
//! - [`directory`] — directory discoverability + actor-privacy projections.
//!
//! No private helpers exist between scenarios in this family — the move is a
//! pure mechanical extraction.

pub mod contacts;
pub mod directory;
pub mod discovery;
pub mod identity;

pub use contacts::contacts_invites_listing_export_and_audit_work;
pub use directory::directory_discoverability_and_actor_privacy_work;
pub use discovery::discovery_and_index_demo_projection_shapes_work;
pub use identity::identity_surface_and_receipts_work;
