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

use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::bridge_contracts::session_grant::mock_session_grant_jwt;
use crate::scenarios::identity_test_support::{
    HARNESS_INTERNAL_AUTHORITY_SECRET, actor_did_for_service_did,
    spawn_with_harness_account_authority,
};

mod backup_delete;
mod blob;
mod device_messages;
mod events_keys_setup;
mod key_backup_pointer;
mod key_backups;
mod moderation;
mod push;
mod snapshot_head_disclosure;

pub use key_backup_pointer::key_backup_active_pointer_is_committed_and_listed_at_its_pcr_cut;
pub use snapshot_head_disclosure::narrow_snapshot_head_discloses_only_complete_creator_cut;

pub async fn events_keys_device_blob_push_and_moderation_surfaces_work() -> Result<()> {
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let account_authority_origin = coauth.origin();
    let introspection_url = coauth.url();
    let server = spawn_with_harness_account_authority(
        "protocol-payloads",
        &[
            (
                "SOLAND_ACCOUNT_AUTHORITY_URL",
                account_authority_origin.as_str(),
            ),
            ("SOLAND_DID_RESOLVER_ALLOW_METHODS", "web,webvh,key,uuid"),
            (
                "SOLAND_SESSION_GRANT_INTROSPECTION_URL",
                introspection_url.as_str(),
            ),
        ],
    )
    .await?;
    let actor_id = actor_did_for_service_did(server.service_did(), "protocol-payloads-alice")?;
    let client = server
        .demo_client(&actor_id, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let token = client.expect_dev_bearer().to_owned();
    let principal = client
        .principal
        .as_ref()
        .context("client carries its provisioned principal")?;
    let grant = mock_session_grant_jwt(
        principal.core_id.as_str(),
        principal.device_id.as_str(),
        server.service_id().as_str(),
    );
    coauth.bind_founding_device_grant(
        &grant,
        principal.core_id.as_str(),
        principal.device_id.as_str(),
        principal.founding_authorize_event_id.as_str(),
        &principal.device_signing_key.verifying_key(),
    )?;
    let event_client = server.client_with_founding_device_grant(principal, grant)?;

    let (actor, adapter_realm_id, adapter_message_event_id) =
        events_keys_setup::run(&server, &client, &event_client)
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

/// A stored envelope makes the list non-empty; it must still be the closed
/// `KeysBackupsList` over HTTP 200 with a `backup_metadata` row.
pub async fn key_backup_list_serves_stored_backup_as_closed_metadata() -> Result<()> {
    let server = spawn_with_harness_account_authority(
        "protocol-key-backup-list-metadata",
        &[("SOLAND_DID_RESOLVER_ALLOW_METHODS", "web,webvh,key,uuid")],
    )
    .await?;
    let actor_id = actor_did_for_service_did(server.service_did(), "key-backup-list-row-alice")?;
    let client = server
        .demo_client(&actor_id, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let token = client.expect_dev_bearer();
    key_backups::put_backup(
        &server,
        token,
        &actor_id,
        client
            .principal
            .as_ref()
            .context("client carries its provisioned principal")?,
    )
    .await?;
    key_backups::list_backups(&server, token).await
}

pub async fn key_backup_list_absent_at_confirmed_pcr_genesis() -> Result<()> {
    let server = spawn_with_harness_account_authority(
        "protocol-key-backup-list-absent",
        &[("SOLAND_DID_RESOLVER_ALLOW_METHODS", "web,webvh,key,uuid")],
    )
    .await?;
    let actor_id = actor_did_for_service_did(server.service_did(), "key-backup-list-alice")?;
    let client = server
        .demo_client(&actor_id, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let body = crate::harness::expect_json(
        server
            .http()
            .get(server.url("/_arkret/self/keys/backups"))
            .bearer_auth(client.expect_dev_bearer()),
        reqwest::StatusCode::OK,
    )
    .await?;
    let listing: arkret_models_crypto::KeysBackupsList = serde_json::from_value(body)?;
    assert!(listing.backups.is_empty());
    assert!(matches!(
        listing.active_series.secret_storage,
        arkret_models_crypto::BackupActiveSeriesPointer::Absent {}
    ));
    assert_eq!(
        listing.active_series.control_realm_id,
        client.principal.as_ref().unwrap().pcr_realm_id
    );
    assert!(
        !listing
            .active_series
            .authority_commit_id
            .as_str()
            .is_empty()
    );
    assert!(listing.next_cursor.is_none());
    assert!(!listing.has_more);
    Ok(())
}
