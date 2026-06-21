//! CT-11 — Key backup restore + MLS history replay (entrypoint).
//!
//! Alice has device-A in an E2EE Realm with 3 messages; uploads an
//! Argon2id + XChaCha20-Poly1305 key backup envelope per
//! `key-management.md` §7.2. Device-A is "lost" (revoked). A new
//! device-B onboards, claims the backup with an SSK proof, recovers
//! `mls_history_backup_key`, and replays the historical
//! `ck.mls.commit` chain to decrypt all 3 pre-loss messages.
//!
//! See `cotest::scenarios::key_backup_restore_mls_replay` for the full
//! walk-through and prerequisite blockers.
//!
//! Run with:
//!
//!   cargo test --test key_backup_restore_mls_replay -- --ignored

use anyhow::Result;
use serial_test::serial;

/// Gating: needs live client-side MLS history replay crypto + soland
/// E2E-KEY-BACKUP-2 (SSK-proof-gated DELETE + recovery attestation surface).
/// `PUT /_cokret/self/keys/backups/{id}` and proof-bearing
/// `POST /_cokret/self/keys/backups/{id}/unlock` already exist.
/// Issue: CT-11 (key backup → MLS history replay)
#[tokio::test]
#[ignore = "needs live client-side MLS history replay crypto + soland E2E-KEY-BACKUP-2 (SSK-proof-gated DELETE + recovery attestation surface); PUT /_cokret/self/keys/backups/{id} and POST /_cokret/self/keys/backups/{id}/unlock ARE implemented today - see CT-11"]
#[serial]
async fn device_b_recovers_pre_loss_mls_history_from_key_backup() -> Result<()> {
    cotest::scenarios::key_backup_restore_mls_replay::key_backup_restore_mls_replay_run().await
}
