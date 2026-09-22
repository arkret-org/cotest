//! Identity / directory scenarios.
//!
//! Each submodule is single-responsibility:
//! - [`identity`] — `/_arkret/root/identity/*` describe/resolve/document/log/submit/receipts.
//! - [`contacts`] — contacts/invites listing/export/audit strand.
//!
//! No private helpers exist between scenarios in this family.

pub mod contacts;
pub mod identity;

pub use contacts::contacts_invites_listing_export_and_audit_work;
pub use identity::identity_surface_and_receipts_work;
