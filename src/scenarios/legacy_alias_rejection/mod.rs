//! P4-D — legacy alias rejection.
//!
//! B-B (head 37ce729) is a candidate-stage breaking pass: every legacy
//! alias listed below MUST be hard-rejected. The SDK's
//! `blind_payload_sanitizer` + the floria push gateway's forbidden-leaf
//! list cover most of the surface; this module is the cotest gate that
//! pins the rejection contract for downstream services.
//!
//! Covered aliases:
//!   - `size` (block-level; renamed to `size_bytes`)
//!   - `body` (Flow top-level; renamed to `content`)
//!   - `created_by_principal` (Realm; renamed to `created_by`)
//!   - `snapshot_ref` (snapshot manifest SELF; renamed to `id`;
//!     external references retain `snapshot_ref`)
//!   - `series_sequence` (key-backup; renamed to `series_seq`)
//!   - `flow_body` / `message_body` / `body_only` (privacy enums;
//!     renamed to `flow_content` / `message_content` / `content_only`)
//!   - `cx.secret_storage.v1` wire envelope (rejected with reason
//!     `legacy_secret_storage_wire_form`)
//!   - legacy `ann_*` directory announce id (fail-closed)

pub mod ann_announce_id;
pub mod legacy_secret_storage_wire;
pub mod renamed_fields;
