//! `ak.key_backup.active_series` over the live self Event surface.
//!
//! The founding device of a signed PCR genesis selects the first
//! secret-storage series. The Station must accept it only through the
//! same-cut PCR pointer unit, and the self KeyBackup list must then report
//! that exact pointer at the RealmCommit that accepted it.

use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::events_payloads::{
    ControllerBackupTrustAnchor, UnsignedKeyBackupActiveSeries,
};
use arkret_models_crypto::{BackupActiveSeriesPointer, BackupKind, KeysBackupsList};
use arkret_wire::{
    AccountId, ActorId, AuthorityCommitStatus, AuthoritySubmitOutcome, BackupSeriesId,
    Base64UrlString, DidCoreId, RealmCommitId,
};
use ed25519_dalek::{Signer, SigningKey};
use reqwest::StatusCode;

use crate::harness::{
    ArkretServer, TestActorClient, event_envelope_with_causal_refs_for_device,
    event_signing_identity_for_device, expect_json, expect_response,
};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::bridge_contracts::session_grant::mock_session_grant_jwt;
use crate::scenarios::identity_test_support::{
    HARNESS_INTERNAL_AUTHORITY_SECRET, actor_did_for_service_did,
    spawn_with_harness_account_authority,
};

async fn listing(client: &TestActorClient, server: &ArkretServer) -> Result<KeysBackupsList> {
    let body = expect_json(
        server
            .http()
            .get(server.url("/_arkret/self/keys/backups"))
            .bearer_auth(client.expect_dev_bearer()),
        StatusCode::OK,
    )
    .await?;
    Ok(serde_json::from_value(body)?)
}

struct PointerSigner {
    actor: String,
    device_id: String,
    station: DidCoreId,
    account: AccountId,
    pcr_realm_id: String,
    seed: [u8; 32],
    method: arkret_wire::DidUrl,
    authorize_event_id: arkret_wire::EventId,
}

impl PointerSigner {
    fn event(
        &self,
        series: &BackupSeriesId,
        version: u64,
        source: &RealmCommitId,
        generation: u64,
    ) -> Result<arkret_wire::Event> {
        let unsigned = UnsignedKeyBackupActiveSeries::new(
            ActorId::account(self.account.clone()),
            BackupKind::SecretStorage,
            series.clone(),
            version,
            Vec::new(),
            source.clone(),
            arkret::canonical::normalize_timestamp_canonical(chrono::Utc::now()),
            self.method.clone(),
            ControllerBackupTrustAnchor {
                authorize_event_id: self.authorize_event_id.clone(),
                generation_ref: generation,
            },
        )?;
        let signature = SigningKey::from_bytes(&self.seed)
            .sign(&unsigned.signing_payload_bytes()?)
            .to_bytes();
        let record = unsigned.attach_signature(
            Base64UrlString::new(arkret::canonical::base64url_encode(signature))
                .map_err(anyhow::Error::msg)?,
        )?;
        Ok(event_envelope_with_causal_refs_for_device(
            &self.actor,
            &self.device_id,
            &self.station,
            &self.pcr_realm_id,
            arkret_wire::EventKind::KeyBackupActiveSeries.as_str(),
            serde_json::to_value(record)?,
            None,
            Vec::new(),
            Vec::new(),
        ))
    }
}

pub async fn key_backup_active_pointer_is_committed_and_listed_at_its_pcr_cut() -> Result<()> {
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let account_authority_origin = coauth.origin();
    let introspection_url = coauth.url();
    let server = spawn_with_harness_account_authority(
        "protocol-key-backup-active-pointer",
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
    let actor_id = actor_did_for_service_did(server.service_did(), "key-backup-pointer-alice")?;
    let client = server
        .demo_client(&actor_id, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let principal = client
        .principal
        .as_ref()
        .context("client carries its provisioned principal")?
        .clone();
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
    let event_client = server.client_with_founding_device_grant(&principal, grant)?;

    let genesis = listing(&client, &server).await?;
    ensure!(matches!(
        genesis.active_series.secret_storage,
        BackupActiveSeriesPointer::Absent {}
    ));
    let (seed, method) =
        event_signing_identity_for_device(&event_client.actor, &event_client.device_id);
    ensure!(
        SigningKey::from_bytes(&seed).verifying_key()
            == principal.device_signing_key.verifying_key(),
        "the Event signer is the founding device key"
    );
    let signer = PointerSigner {
        actor: event_client.actor.clone(),
        device_id: event_client.device_id.clone(),
        station: DidCoreId::new(server.service_id().as_str().to_owned())?,
        account: AccountId::new(principal.core_id.clone(), server.service_id().clone()),
        pcr_realm_id: principal.pcr_realm_id.to_string(),
        seed,
        method,
        authorize_event_id: principal.founding_authorize_event_id.clone(),
    };
    let series = BackupSeriesId::new("ak:backup_series:01964137-1000-7000-8000-0000000000b1")?;
    let submit = |event: &arkret_wire::Event| {
        event_client
            .post("/_arkret/self/events")
            .json(&crate::publication::initial_submission(event.clone(), "").unwrap())
    };

    // A pointer bound to a generation the PCR never reached is refused with
    // no durable write: the list still names the genesis cut and Absent.
    let stale = signer.event(&series, 1, &genesis.active_series.authority_commit_id, 2)?;
    let refused = expect_response(submit(&stale), StatusCode::CONFLICT).await?;
    ensure!(
        refused.text().contains("backup_revision_stale"),
        "stale pointer refused for another reason: {}",
        refused.text()
    );
    let after_refusal = listing(&client, &server).await?;
    ensure!(after_refusal.active_series == genesis.active_series);

    let accepted = signer.event(&series, 1, &genesis.active_series.authority_commit_id, 1)?;
    let body = expect_json(submit(&accepted), StatusCode::OK).await?;
    let AuthoritySubmitOutcome::Accepted { status, commit } = serde_json::from_value(body)? else {
        anyhow::bail!("active-series submission was not accepted");
    };
    ensure!(status == AuthorityCommitStatus::Committed);
    ensure!(commit.event_ref == accepted.event_id);
    ensure!(
        commit.previous_commit_ref.as_ref() == Some(&genesis.active_series.authority_commit_id)
    );

    let active = listing(&client, &server).await?;
    ensure!(active.active_series.authority_commit_id == commit.commit_id);
    ensure!(active.active_series.control_realm_id == principal.pcr_realm_id);
    ensure!(
        active.active_series.secret_storage
            == BackupActiveSeriesPointer::Active {
                active_series_id: series.clone(),
                series_pointer_version: 1,
            }
    );

    // The exact Event replays as a duplicate of the same Commit; a second
    // version-1 selection is a same-version fork and is refused.
    let replay = expect_json(submit(&accepted), StatusCode::OK).await?;
    let AuthoritySubmitOutcome::Accepted {
        status,
        commit: replayed,
    } = serde_json::from_value(replay)?
    else {
        anyhow::bail!("active-series replay was not accepted");
    };
    ensure!(status == AuthorityCommitStatus::Duplicate && replayed == commit);
    let fork_series = BackupSeriesId::new("ak:backup_series:01964137-1000-7000-8000-0000000000b2")?;
    let fork = signer.event(&fork_series, 1, &commit.commit_id, 1)?;
    let fork_refused = expect_response(submit(&fork), StatusCode::CONFLICT).await?;
    ensure!(
        fork_refused
            .text()
            .contains("key_backup_active_series_pointer_version_fork"),
        "same-version fork refused for another reason: {}",
        fork_refused.text()
    );
    ensure!(listing(&client, &server).await?.active_series == active.active_series);
    Ok(())
}
