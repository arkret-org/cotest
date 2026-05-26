//! P4-C — Key-backup 3-class 409 + first-backup gate + post-reset stale.
//!
//! Spec (B-C, head 37ce729) hardens the user key-backup wire:
//!
//!   - **series_chain_broken** — PUT with a `supersedes_digest` that
//!     does not match the on-server `supersedes` envelope's digest.
//!   - **series_seq_not_monotonic** — out-of-order `series_seq`.
//!   - **series_predecessor_not_found** — PUT references a `supersedes`
//!     envelope id that does not exist on the server.
//!   - **first_backup_gate** — inception key retire is rejected unless
//!     a `backup_class=did_recovery` envelope has been published first.
//!   - **post_reset_stale** — cross-signing reset accepted ↦ existing
//!     `secret_storage` envelopes have 24h to publish a successor, else
//!     recovery flow rejects with `backup_post_reset_stale`.
//!
//! Also: `recovery_policy` + `recovery_receipt` schema id acceptance.
//!
//! Each sub-test is SDK-pure (no live SUT) — pins the error code
//! constants + the lifecycle invariants. Live-server variants will run
//! against soland's PUT path under `tests/key_backup_*.rs`.

pub mod first_backup_gate;
pub mod post_reset_stale;
pub mod recovery_schemas;
pub mod series_chain_broken;
pub mod series_predecessor_not_found;
pub mod series_seq_not_monotonic;
