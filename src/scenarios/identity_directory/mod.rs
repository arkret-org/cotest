//! Identity / directory scenarios.
//!
//! Each submodule is single-responsibility:
//! - [`identity`] — `/_cokret/root/identity/*` describe/resolve/document/log/submit/receipts.
//! - [`contacts`] — contacts/invites listing/export/audit flow.
//! - [`directory`] — directory discoverability + actor-privacy projections.
//!
//! No private helpers exist between scenarios in this family.

pub mod contacts;
pub mod directory;
pub mod identity;

pub use contacts::contacts_invites_listing_export_and_audit_work;
pub use directory::directory_discoverability_and_actor_privacy_work;
pub use identity::identity_surface_and_receipts_work;
