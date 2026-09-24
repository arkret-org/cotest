//! Protocol-payload scenario.
//!
//! One end-to-end happy path across the events / keys / device-messages /
//! key-backups / blob / push / moderation surfaces. Each protocol phase is
//! largely independent: the only state plumbed between phases is
//! `(server, token)`, plus a handful of intra-phase locals (e.g. `blob_ref`
//! consumed by the range GET in the same phase).
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

use anyhow::{Context, Result};

use crate::scenarios::identity_test_support::{
    actor_did_for_service_did, spawn_with_harness_account_authority,
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
    let actor_id = actor_did_for_service_did(server.service_did(), "protocol-payloads-alice")?;
    let client = server
        .demo_client(&actor_id, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let token = client.expect_dev_bearer().to_owned();

    let (actor, adapter_realm_id, adapter_message_event_id) =
        events_keys_setup::run(&server, &client)
            .await
            .context("protocol payload event/key setup")?;
    device_messages::run(&server, &token, &actor_id)
        .await
        .context("protocol payload device messages")?;
    key_backups::run(
        &server,
        &token,
        &actor_id,
        client
            .principal
            .as_ref()
            .context("client carries its provisioned principal")?,
    )
    .await
    .context("protocol payload key backups")?;
    backup_delete::run(&server, &token, &actor_id)
        .await
        .context("protocol payload backup deletion")?;
    blob::run(&server, &token)
        .await
        .context("protocol payload blob")?;
    push::run(&server, &token)
        .await
        .context("protocol payload push")?;
    moderation::run(
        &server,
        &actor,
        &adapter_realm_id,
        &adapter_message_event_id,
    )
    .await
    .context("protocol payload moderation")?;

    Ok(())
}

pub async fn key_backup_replace_with_authorized_device_works() -> Result<()> {
    let server = spawn_with_harness_account_authority(
        "protocol-key-backup-replace",
        &[("SOLAND_DID_RESOLVER_ALLOW_METHODS", "web,webvh,key,uuid")],
    )
    .await?;
    let actor_id = actor_did_for_service_did(server.service_did(), "key-backup-alice")?;
    let client = server
        .demo_client(&actor_id, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    key_backups::put_backup(
        &server,
        client.expect_dev_bearer(),
        &actor_id,
        client
            .principal
            .as_ref()
            .context("client carries its provisioned principal")?,
    )
    .await
}
