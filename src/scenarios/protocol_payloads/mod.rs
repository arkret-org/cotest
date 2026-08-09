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
//! - [`events_keys_setup`] — `/_arkret/self/events` plus `/_arkret/self/keys/{upload,query,claim}`
//!   strand.
//! - [`device_messages`] — `/_arkret/self/device_messages` send / duplicate / list / describe + the
//!   verification-event side path.
//! - [`key_backups`] — `/_arkret/self/keys/backups/*` PUT / list / unlock plus `/_arkret/describe`
//!   operation advertisement.
//! - [`backup_delete`] — terminal `DELETE /_arkret/self/keys/backups/{id}`.
//! - [`blob`] — `/_arkret/self/blob/{upload,get}` (sha mismatch + happy-path range).
//! - [`push`] — `/_arkret/edge/push/{register-device,notify}` happy + missing-device rejection.
//! - [`moderation`] — `/_arkret/self/moderation/report` queueing.
//!
//! No private cross-phase helpers exist — every phase function takes only
//! `(&ArkretServer, &str)` (or just `&ArkretServer` when no auth is
//! required) so the orchestrator can read top-to-bottom as a sequence of
//! protocol phases.

use anyhow::Result;

use crate::harness::dev_login;
use crate::scenarios::identity_test_support::{
    actor_did_for_service, spawn_with_harness_account_authority,
};

mod backup_delete;
mod blob;
mod device_messages;
mod events_keys_setup;
mod key_backups;
mod moderation;
mod push;

pub async fn events_keys_device_blob_push_and_moderation_surfaces_work() -> Result<()> {
    let server = spawn_with_harness_account_authority(
        "protocol-payloads",
        &[("SOLAND_DID_RESOLVER_ALLOW_METHODS", "web,webvh,key,uuid")],
    )
    .await?;
    let actor_id = actor_did_for_service(server.service_id(), "protocol-payloads-alice")?;
    let token = dev_login(
        &server,
        &actor_id,
        "ak:device:01904100-0000-7000-8000-0000000000a1",
    )
    .await?;

    let (adapter_realm_id, adapter_message_event_id) =
        events_keys_setup::run(&server, &token, &actor_id).await?;
    device_messages::run(&server, &token, &actor_id).await?;
    key_backups::run(&server, &token, &actor_id).await?;
    backup_delete::run(&server, &token, &actor_id).await?;
    blob::run(&server, &token).await?;
    push::run(&server, &token).await?;
    moderation::run(
        &server,
        &token,
        &actor_id,
        &adapter_realm_id,
        &adapter_message_event_id,
    )
    .await?;

    Ok(())
}
