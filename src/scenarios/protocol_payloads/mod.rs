//! Protocol-payload scenario — split from the previous 1000-line
//! `protocol_payloads.rs` during the round 33.5 refactor.
//!
//! The original monolith was a single 1000-line `async fn` covering the
//! end-to-end happy path across events / keys / device-messages / key-backups /
//! blob / push / moderation surfaces. Logic decomposition was
//! straightforward because each protocol phase is largely independent: the
//! only state plumbed between phases is `(server, token)`, plus a handful of
//! intra-phase locals (e.g. `blob_ref` consumed by the range GET in the same
//! phase).
//!
//! Submodules — each is a single async helper representing one protocol phase:
//! - [`events_keys_setup`] — `/api/v1/events` plus
//!   `/api/v1/keys/{upload,query,claim}` flow.
//! - [`device_messages`] — `/api/v1/device_messages` send / duplicate / list /
//!   describe + the verification-event side path.
//! - [`key_backups`] — `/api/v1/keys/backups/*` PUT / list / describe / GET.
//! - [`backup_delete`] — terminal `DELETE /api/v1/keys/backups/{id}`.
//! - [`blob`] — `/api/v1/blob/{upload,get}` (sha mismatch + happy-path range).
//! - [`push`] — `/api/v1/push/{register-device,notify}` happy + missing-device
//!   rejection.
//! - [`moderation`] — `/api/v1/moderation/report` queueing.
//!
//! No private cross-phase helpers exist — every phase function takes only
//! `(&ContrixServer, &str)` (or just `&ContrixServer` when no auth is
//! required) so the orchestrator can read top-to-bottom as a sequence of
//! protocol phases.

use anyhow::Result;

use crate::harness::{ContrixServer, dev_login};

mod backup_delete;
mod blob;
mod device_messages;
mod events_keys_setup;
mod key_backups;
mod moderation;
mod push;

pub async fn events_keys_device_blob_push_and_moderation_surfaces_work() -> Result<()> {
    let server = ContrixServer::spawn("protocol-payloads").await?;
    let token = dev_login(&server, "did:web:alice.example", "dev_alice").await?;

    events_keys_setup::run(&server, &token).await?;
    device_messages::run(&server, &token).await?;
    key_backups::run(&server, &token).await?;
    backup_delete::run(&server, &token).await?;
    blob::run(&server, &token).await?;
    push::run(&server, &token).await?;
    moderation::run(&server, &token).await?;

    Ok(())
}
