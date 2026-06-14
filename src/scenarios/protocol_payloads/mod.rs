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
//! - [`events_keys_setup`] — `/_cokret/self/events` plus `/_cokret/self/keys/{upload,query,claim}`
//!   strand.
//! - [`device_messages`] — `/_cokret/self/device_messages` send / duplicate / list / describe + the
//!   verification-event side path.
//! - [`key_backups`] — `/_cokret/self/keys/backups/*` PUT / list / unlock plus the
//!   `/_soland/self/keys/backups/describe` deployment-face descriptor.
//! - [`backup_delete`] — terminal `DELETE /_cokret/self/keys/backups/{id}`.
//! - [`blob`] — `/_cokret/self/blob/{upload,get}` (sha mismatch + happy-path range).
//! - [`push`] — `/_cokret/edge/push/{register-device,notify}` happy + missing-device rejection.
//! - [`moderation`] — `/_cokret/self/moderation/report` queueing.
//!
//! No private cross-phase helpers exist — every phase function takes only
//! `(&CokretServer, &str)` (or just `&CokretServer` when no auth is
//! required) so the orchestrator can read top-to-bottom as a sequence of
//! protocol phases.

use anyhow::Result;

use crate::harness::{CokretServer, dev_login};

mod backup_delete;
mod blob;
mod device_messages;
mod events_keys_setup;
mod key_backups;
mod moderation;
mod push;

pub async fn events_keys_device_blob_push_and_moderation_surfaces_work() -> Result<()> {
    let server = CokretServer::spawn("protocol-payloads").await?;
    let token = dev_login(
        &server,
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-0000000000a1",
    )
    .await?;

    events_keys_setup::run(&server, &token).await?;
    device_messages::run(&server, &token).await?;
    key_backups::run(&server, &token).await?;
    backup_delete::run(&server, &token).await?;
    blob::run(&server, &token).await?;
    push::run(&server, &token).await?;
    moderation::run(&server, &token).await?;

    Ok(())
}
