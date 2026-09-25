//! A complete SecurityRotation of one Account over live HTTP against a fresh
//! Soland binary and PostgreSQL: the Station's durable worker drives
//! `revoke → upload_new_material → switch_authoritative_pointer →
//! erase_old_material`, and the authorizing device then completes the
//! rotation with its client-attested `local_commit`.
//!
//! Device A founds the PCR through the ordinary signed genesis. Devices B and
//! C are approved by A: each A-signed `accepted_device` authorization, with
//! the target device's own possession signature, is admitted by the owning
//! Station's accepted-device unit over the Account Authority private
//! admission channel. The Account Authority's pairing ledger in front of that
//! channel is not part of this scenario. Nothing bypasses the Station: A
//! stores its old backup through the self PUT, selects the first series
//! through the self Event surface, and creates every rotation through
//! `ak.self.security_transaction.command.create.v1`.

use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::events_payloads::{
    ControllerBackupTrustAnchor, DeviceAuthorizationBindingKind, DeviceAuthorizePayload,
    DeviceOrPrincipalRef, SignatureMaterial, UnsignedKeyBackupActiveSeries,
};
use arkret_models_crypto::{
    BackupActiveSeriesPointer, BackupKind, BackupObjectRef, BackupRotationBinding,
    BackupRotationKind, BackupRotationPlan, ClientStepAttestation, ClientStepAttestationArtifact,
    ClientStepAttestationAuthData, KeyBackup, KeyBackupAead, KeyBackupAeadName, KeyBackupAuthData,
    KeyBackupDomainSeparation, KeyBackupEncryption, KeyBackupRecipientMethod,
    KeyBackupSignatureAlgorithm, KeysBackupsList, PreparedEventBatchRequest, PreparedEventUnit,
    SecretStorageContentIndex, SecretStorageItemKind, SecurityRotationLocalCommit,
    SecurityRotationRevokeCommandResult, SecurityRotationTransactionCreateRequest,
    SecurityTransaction, SecurityTransactionContinueRequest, SecurityTransactionCreateRequest,
    SecurityTransactionStep, SecurityTransactionTerminalOutcome,
};
use arkret_wire::{
    AccountId, ActorId, AuthorityCommitStatus, AuthoritySubmitOutcome, BackupId, BackupSeriesId,
    Base64UrlString, DeviceId, DidCoreId, DidUrl, Event, EventId, Hash, NonEmptyString,
    RealmCommit, RealmCommitId, TransactionId,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use reqwest::StatusCode;
use serde::Serialize;

use crate::harness::{
    ArkretServer, ProvisionedTestPrincipal, TestActorClient,
    event_envelope_with_causal_refs_for_device, event_signing_identity_for_device, expect_json,
};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::coauth_bootstrap::spawn_ephemeral_postgres_for;
use crate::scenarios::bridge_contracts::session_grant::mock_session_grant_jwt;
use crate::scenarios::identity_test_support::{
    HARNESS_INTERNAL_AUTHORITY_SECRET, actor_did_for_service_did,
    spawn_with_harness_account_authority_at,
};

const SERVER_NAME: &str = "security-rotation-two-devices";
pub(crate) const DEVICE_A: &str = "ak:device:01904100-0000-7000-8000-0000000000a1";
const DEVICE_B: &str = "ak:device:01904100-0000-7000-8000-0000000000b2";
pub(crate) const DEVICE_C: &str = "ak:device:01904100-0000-7000-8000-0000000000c3";
const DEVICE_B_SEED: [u8; 32] = [0xb2; 32];
pub(crate) const DEVICE_C_SEED: [u8; 32] = [0xc3; 32];
const FORGED_SEED: [u8; 32] = [0x66; 32];
const SERIES_ONE: &str = "ak:backup_series:01904100-0000-7000-8000-0000000000e1";
const OLD_BACKUP: &str = "ak:backup:01904100-0000-7000-8000-0000000000e2";
const OLD_SUCCESSOR: &str = "ak:backup:01904100-0000-7000-8000-0000000000e3";
const INACTIVE_SERIES: &str = "ak:backup_series:01904100-0000-7000-8000-0000000000e4";
const INACTIVE_BACKUP: &str = "ak:backup:01904100-0000-7000-8000-0000000000e5";

/// A's signing identity: the device key signs Events, envelopes and records.
pub(crate) struct RotationAuthor {
    actor: String,
    station: DidCoreId,
    account: AccountId,
    principal: ProvisionedTestPrincipal,
    seed: [u8; 32],
    method: DidUrl,
}

impl RotationAuthor {
    /// One `secret_storage` envelope of `series`, signed with `seed` under
    /// A's device method and current authorization.
    fn backup(
        &self,
        backup_id: &str,
        series: &BackupSeriesId,
        ciphertext: &[u8],
        seed: [u8; 32],
    ) -> Result<KeyBackup> {
        let mut envelope = KeyBackup {
            backup_id: BackupId::new(backup_id.to_owned())?,
            actor_id: ActorId::account(self.account.clone()),
            device_id: Some(self.principal.device_id.clone()),
            backup_kind: BackupKind::SecretStorage,
            mixed_secret_storage: false,
            backup_version: "kb_1".to_owned(),
            created_at: arkret::canonical::normalize_timestamp_canonical(Utc::now()),
            updated_at: None,
            expires_at: None,
            encryption: KeyBackupEncryption {
                recipient_method: KeyBackupRecipientMethod::SecretStorageKey,
                recipient_key_ref: Some("mls_group_secrets_backup_key".to_owned()),
                kdf: None,
                aead: KeyBackupAead {
                    name: KeyBackupAeadName::Xchacha20Poly1305,
                    aead_profile: Some("ak.aead.xchacha20_poly1305.v1".to_owned()),
                    nonce_salt: None,
                    nonce: Some(Base64UrlString::new("nonce").map_err(anyhow::Error::msg)?),
                    enc: None,
                    extra: Default::default(),
                },
                key_commitment: None,
                hpke_suite: None,
                extra: Default::default(),
            },
            domain_separation: KeyBackupDomainSeparation {
                subdomain: "rotation".to_owned(),
                aead_aad_extensions: Default::default(),
            },
            contents: vec![SecretStorageContentIndex {
                item_kind: SecretStorageItemKind::MlsGroupSecretsBackupKey,
                secret_id: "mls_group_secrets_backup_key".to_owned(),
            }],
            ciphertext: Base64UrlString::new(arkret_canonical::base64url_encode(ciphertext))
                .map_err(anyhow::Error::msg)?,
            ciphertext_digest: Hash::new(arkret_canonical::sha256_digest(ciphertext))?,
            plaintext_commitment: None,
            auth_data: KeyBackupAuthData {
                device_id: self.principal.device_id.clone(),
                verification_method: self.method.clone(),
                signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
                signature: Base64UrlString::new("AA").map_err(anyhow::Error::msg)?,
                device_authorize_event_id: self.principal.founding_authorize_event_id.clone(),
            },
            retention: None,
            series_id: series.clone(),
            series_seq: 0,
            supersedes_id: None,
            supersedes_digest: None,
            source_commit_ref: None,
            recovery_policy_ref: None,
            extra: Default::default(),
        };
        let signature = SigningKey::from_bytes(&seed).sign(&envelope.signing_payload_bytes()?);
        envelope.auth_data.signature =
            Base64UrlString::new(arkret_canonical::base64url_encode(signature.to_bytes()))
                .map_err(anyhow::Error::msg)?;
        Ok(envelope)
    }

    /// The next envelope of `previous`'s series, chained by its id and the
    /// digest of its signed payload and signed with `seed`.
    fn successor(
        &self,
        backup_id: &str,
        previous: &KeyBackup,
        ciphertext: &[u8],
        seed: [u8; 32],
    ) -> Result<KeyBackup> {
        let mut envelope = self.backup(backup_id, &previous.series_id, ciphertext, seed)?;
        envelope.series_seq = previous.series_seq + 1;
        envelope.supersedes_id = Some(previous.backup_id.clone());
        envelope.supersedes_digest = Some(Hash::new(arkret_canonical::sha256_digest(
            previous.signing_payload_bytes()?,
        ))?);
        let signature = SigningKey::from_bytes(&seed).sign(&envelope.signing_payload_bytes()?);
        envelope.auth_data.signature =
            Base64UrlString::new(arkret_canonical::base64url_encode(signature.to_bytes()))
                .map_err(anyhow::Error::msg)?;
        Ok(envelope)
    }

    /// A's `ak.key_backup.active_series` Event selecting `series`.
    fn pointer(
        &self,
        series: &BackupSeriesId,
        version: u64,
        previous: Vec<BackupSeriesId>,
        source: &RealmCommitId,
    ) -> Result<Event> {
        let unsigned = UnsignedKeyBackupActiveSeries::new(
            ActorId::account(self.account.clone()),
            BackupKind::SecretStorage,
            series.clone(),
            version,
            previous,
            source.clone(),
            arkret::canonical::normalize_timestamp_canonical(Utc::now()),
            self.method.clone(),
            ControllerBackupTrustAnchor {
                authorize_event_id: self.principal.founding_authorize_event_id.clone(),
                generation_ref: 1,
            },
        )?;
        let signature = SigningKey::from_bytes(&self.seed)
            .sign(&unsigned.signing_payload_bytes()?)
            .to_bytes();
        let record = unsigned.attach_signature(
            Base64UrlString::new(arkret_canonical::base64url_encode(signature))
                .map_err(anyhow::Error::msg)?,
        )?;
        Ok(event_envelope_with_causal_refs_for_device(
            &self.actor,
            DEVICE_A,
            &self.station,
            self.principal.pcr_realm_id.as_str(),
            arkret_wire::EventKind::KeyBackupActiveSeries.as_str(),
            serde_json::to_value(record)?,
            None,
            Vec::new(),
            Vec::new(),
        ))
    }

    /// A's `ak.policy.set` publishing a recovery policy whose only method is
    /// a `device_quorum` of `k` over `members`, the policy signed with `seed`
    /// under `method` and the Event signed by A.
    #[allow(clippy::too_many_arguments)]
    fn recovery_policy(
        &self,
        policy_id: &str,
        version: u64,
        supersedes: Option<&str>,
        k: u32,
        members: &[&str],
        method: &DidUrl,
        seed: [u8; 32],
    ) -> Result<Event> {
        let mut policy: arkret_models_crypto::RecoveryPolicy =
            serde_json::from_value(serde_json::json!({
                "schema": "ak.schema.recovery_policy.v1",
                "policy_id": policy_id,
                "account_id": self.account,
                "version": version,
                "supersedes_id": supersedes,
                "trust_domain": "ak:trust_domain:cotest.example",
                "issued_at": arkret_canonical::format_timestamp_canonical(
                    arkret::canonical::normalize_timestamp_canonical(Utc::now())
                ),
                "auth_data": {
                    "verification_method": method,
                    "signature_algorithm": "Ed25519",
                    "signature": "AA"
                },
                "methods": [{"kind": "device_quorum", "k": k, "member_ids": members}]
            }))?;
        let transcript = arkret_models_crypto::recovery_policy_signature_transcript_bytes(&policy)?;
        policy.auth_data.signature = Base64UrlString::new(arkret_canonical::base64url_encode(
            SigningKey::from_bytes(&seed).sign(&transcript).to_bytes(),
        ))
        .map_err(anyhow::Error::msg)?;
        Ok(event_envelope_with_causal_refs_for_device(
            &self.actor,
            DEVICE_A,
            &self.station,
            self.principal.pcr_realm_id.as_str(),
            arkret_wire::EventKind::PolicySet.as_str(),
            serde_json::json!({"policy_id": policy_id, "value": policy}),
            None,
            Vec::new(),
            Vec::new(),
        ))
    }

    /// A's rotation revoking `target`: one replacement envelope of a fresh
    /// series signed with `backup_seed`, and pointer version 2 over
    /// `SERIES_ONE` anchored at `source`. `revoke_seed` signs the revoke.
    pub(crate) fn rotation(
        &self,
        suffix: &str,
        target: &str,
        revoke_seed: [u8; 32],
        backup_seed: [u8; 32],
        old: &KeyBackup,
        source: &RealmCommitId,
    ) -> Result<(SecurityTransactionCreateRequest, BackupRotationBinding)> {
        self.rotation_until(
            suffix,
            target,
            revoke_seed,
            backup_seed,
            std::slice::from_ref(old),
            source,
            chrono::Duration::hours(1),
        )
    }

    /// [`Self::rotation`] over every envelope in `old`, whose transaction
    /// expires `lifetime` after now.
    #[allow(clippy::too_many_arguments)]
    fn rotation_until(
        &self,
        suffix: &str,
        target: &str,
        revoke_seed: [u8; 32],
        backup_seed: [u8; 32],
        old: &[KeyBackup],
        source: &RealmCommitId,
        lifetime: chrono::Duration,
    ) -> Result<(SecurityTransactionCreateRequest, BackupRotationBinding)> {
        let now = arkret::canonical::normalize_timestamp_canonical(Utc::now());
        let revoke = crate::harness::event_envelope_with_chain_and_signing_identity_and_causal_refs(
            &self.actor,
            self.principal.pcr_realm_id.as_str(),
            arkret_wire::EventKind::DeviceRevoke.as_str(),
            serde_json::json!({
                "device_id": target,
                "revoked_by": DEVICE_A,
                "revoked_at": arkret_canonical::format_timestamp_canonical(now),
                "reason": "security_rotation",
            }),
            None,
            Vec::new(),
            revoke_seed,
            &self.method,
            Some(&self.station),
            Vec::new(),
        );
        let series = BackupSeriesId::new(format!(
            "ak:backup_series:01904100-0000-7000-8000-{suffix}00000001"
        ))?;
        let replacement = self.backup(
            &format!("ak:backup:01904100-0000-7000-8000-{suffix}00000002"),
            &series,
            format!("rotated-{suffix}").as_bytes(),
            backup_seed,
        )?;
        let pointer = self.pointer(&series, 2, vec![BackupSeriesId::new(SERIES_ONE)?], source)?;
        let binding = BackupRotationBinding {
            backup_kind: BackupRotationKind::SecretStorage,
            previous_series_id: BackupSeriesId::new(SERIES_ONE)?,
            new_series_id: series,
            new_backups: vec![BackupObjectRef {
                backup_id: replacement.backup_id.clone(),
                ciphertext_digest: replacement.ciphertext_digest.clone(),
            }],
            active_series_event_id: pointer.event_id.clone(),
            old_backups: old
                .iter()
                .map(|old| BackupObjectRef {
                    backup_id: old.backup_id.clone(),
                    ciphertext_digest: old.ciphertext_digest.clone(),
                })
                .collect(),
        };
        let unit = |event: Event| {
            PreparedEventUnit::new(
                arkret_canonical::DigestSuite::Sha256,
                PreparedEventBatchRequest {
                    events: vec![event],
                },
            )
        };
        let request = SecurityTransactionCreateRequest::SecurityRotation(
            SecurityRotationTransactionCreateRequest::from_prepared_rotations(
                TransactionId::new(format!(
                    "ak:transaction:01904100-0000-7000-8000-{suffix}00000000"
                ))?,
                self.account.clone(),
                self.principal.device_id.clone(),
                now + lifetime,
                unit(revoke)?,
                hash("rotated-secret")?,
                vec![BackupRotationPlan {
                    binding: binding.clone(),
                    new_backup_envelopes: vec![replacement],
                    active_series_unit: unit(pointer)?,
                }],
            )?,
        );
        Ok((request, binding))
    }
}

/// The live two-device fixture every rotation scenario starts from: A founds
/// the PCR, B and C are devices A approved, each with its own session, and
/// A stores its old envelope and selects `SERIES_ONE` (pointer version 1).
struct LiveRotation {
    server: ArkretServer,
    _coauth: MockCoauthIntrospectionServer,
    database: crate::scenarios::_helpers::coauth_bootstrap::EphemeralPg,
    client_a: TestActorClient,
    client_b: TestActorClient,
    client_c: TestActorClient,
    events_a: TestActorClient,
    principal: ProvisionedTestPrincipal,
    signer: RotationAuthor,
    seed_a: [u8; 32],
    old: KeyBackup,
    commit: RealmCommit,
    selected: KeysBackupsList,
}

async fn live_rotation(server_name: &str, extra_env: &[(&str, &str)]) -> Result<LiveRotation> {
    let database = spawn_ephemeral_postgres_for("COTEST_SOLAND_DATABASE_URL")?.context(
        "the rotation scenario needs PostgreSQL; set COTEST_SOLAND_DATABASE_URL or make Docker available",
    )?;
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let env = rotation_station_env(&coauth);
    let env = env
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .chain(extra_env.iter().copied())
        .collect::<Vec<_>>();
    let server =
        spawn_with_harness_account_authority_at(server_name, &database.connect_url, &env).await?;
    let RotationFixture {
        client_a,
        client_b,
        client_c,
        events_a,
        principal,
        signer,
        seed_a,
        old,
        commit,
        selected,
    } = rotation_fixture(&server, &coauth, "rotation-alice").await?;
    Ok(LiveRotation {
        server,
        _coauth: coauth,
        database,
        client_a,
        client_b,
        client_c,
        events_a,
        principal,
        signer,
        seed_a,
        old,
        commit,
        selected,
    })
}

/// The two accepted devices B and C next to A's founding device, on
/// an already running Station whose Account Authority is `coauth`, with A's
/// old envelope stored and `SERIES_ONE` selected.
pub(crate) struct RotationFixture {
    pub(crate) client_a: TestActorClient,
    pub(crate) client_b: TestActorClient,
    pub(crate) client_c: TestActorClient,
    pub(crate) events_a: TestActorClient,
    pub(crate) principal: ProvisionedTestPrincipal,
    pub(crate) signer: RotationAuthor,
    pub(crate) seed_a: [u8; 32],
    pub(crate) old: KeyBackup,
    pub(crate) commit: RealmCommit,
    pub(crate) selected: KeysBackupsList,
}

/// The environment a Station needs so that `rotation_fixture` can run on it:
/// `coauth` is its Account Authority and session-grant introspection.
pub(crate) fn rotation_station_env(
    coauth: &MockCoauthIntrospectionServer,
) -> Vec<(String, String)> {
    vec![
        ("SOLAND_ACCOUNT_AUTHORITY_URL".to_owned(), coauth.origin()),
        (
            "SOLAND_DID_RESOLVER_ALLOW_METHODS".to_owned(),
            "web,webvh,key,uuid".to_owned(),
        ),
        (
            "SOLAND_SESSION_GRANT_INTROSPECTION_URL".to_owned(),
            coauth.url(),
        ),
    ]
}

pub(crate) async fn rotation_fixture(
    server: &ArkretServer,
    coauth: &MockCoauthIntrospectionServer,
    actor_label: &str,
) -> Result<RotationFixture> {
    let actor = actor_did_for_service_did(server.service_did(), actor_label)?;
    let client_a = server.demo_client(&actor, DEVICE_A).await?;
    let principal = client_a
        .principal
        .as_ref()
        .context("device A carries its provisioned principal")?
        .clone();
    let account = AccountId::new(principal.core_id.clone(), server.service_id().clone());

    // B and C are accepted devices A approves under the current generation.
    let session_for = async |device: &str, seed: [u8; 32]| -> Result<TestActorClient> {
        let authorize =
            admit_accepted_device(server, &actor, &principal, &account, device, seed).await?;
        let key = SigningKey::from_bytes(&seed);
        let grant = mock_session_grant_jwt(
            principal.core_id.as_str(),
            device,
            server.service_id().as_str(),
        );
        coauth.bind_founding_device_grant(
            &grant,
            principal.core_id.as_str(),
            device,
            authorize.as_str(),
            &key.verifying_key(),
        )?;
        server.client_with_founding_device_grant(
            &ProvisionedTestPrincipal {
                device_id: DeviceId::new(device.to_owned())?,
                device_signing_key: key,
                founding_authorize_event_id: authorize,
                ..principal.clone()
            },
            grant,
        )
    };
    let client_b = session_for(DEVICE_B, DEVICE_B_SEED).await?;
    let client_c = session_for(DEVICE_C, DEVICE_C_SEED).await?;
    let grant_a = mock_session_grant_jwt(
        principal.core_id.as_str(),
        DEVICE_A,
        server.service_id().as_str(),
    );
    coauth.bind_founding_device_grant(
        &grant_a,
        principal.core_id.as_str(),
        DEVICE_A,
        principal.founding_authorize_event_id.as_str(),
        &principal.device_signing_key.verifying_key(),
    )?;
    let events_a = server.client_with_founding_device_grant(&principal, grant_a)?;
    let (seed_a, method_a) = event_signing_identity_for_device(&actor, DEVICE_A);
    ensure!(
        SigningKey::from_bytes(&seed_a).verifying_key()
            == principal.device_signing_key.verifying_key(),
        "the Event signer is the founding device key"
    );
    let signer = RotationAuthor {
        actor: actor.clone(),
        station: DidCoreId::new(server.service_id().as_str().to_owned())?,
        account: account.clone(),
        principal: principal.clone(),
        seed: seed_a,
        method: method_a,
    };

    // A stores its old envelope and selects SERIES_ONE (pointer version 1).
    let old = signer.backup(
        OLD_BACKUP,
        &BackupSeriesId::new(SERIES_ONE)?,
        b"old-ciphertext",
        seed_a,
    )?;
    let stored = expect_json(
        client_a
            .put(&format!("/_arkret/self/keys/backups/{OLD_BACKUP}"))
            .header("Idempotency-Key", "rotation-old-backup")
            .json(&old),
        StatusCode::OK,
    )
    .await?;
    ensure!(stored["status"] == "accepted", "old backup PUT: {stored}");
    let installed = listing(&client_a).await?;
    let pointer_one = signer.pointer(
        &BackupSeriesId::new(SERIES_ONE)?,
        1,
        Vec::new(),
        &installed.active_series.authority_commit_id,
    )?;
    let AuthoritySubmitOutcome::Accepted { status, commit } = serde_json::from_value(
        expect_json(
            events_a
                .post("/_arkret/self/events")
                .json(&crate::publication::initial_submission(pointer_one, "")?),
            StatusCode::OK,
        )
        .await?,
    )?
    else {
        anyhow::bail!("the first pointer was not accepted");
    };
    ensure!(status == AuthorityCommitStatus::Committed);
    let selected = listing(&client_a).await?;
    ensure!(
        selected.active_series.authority_commit_id == commit.commit_id
            && pointer_is(&selected, SERIES_ONE, 1),
        "the first pointer is not listed at its Commit: {:?}",
        selected.active_series
    );
    ensure!(listing(&client_b).await?.active_series == selected.active_series);

    Ok(RotationFixture {
        client_a,
        client_b,
        client_c,
        events_a,
        principal,
        signer,
        seed_a,
        old,
        commit,
        selected,
    })
}

pub async fn security_rotation_runs_worker_steps_to_local_commit() -> Result<()> {
    let LiveRotation {
        server,
        _coauth,
        database,
        client_a,
        client_b,
        client_c,
        events_a,
        principal,
        signer,
        seed_a,
        old,
        commit,
        selected,
    } = live_rotation(SERVER_NAME, &[]).await?;

    // 0. Ordinary unlock at the selected pointer: A and the accepted device B each release the
    //    active-series envelope with a proof over the Station's single-use challenge; an envelope
    //    outside the active series is refused as `backup_revision_stale`.
    let released = unlock(
        &client_a,
        OLD_BACKUP,
        "cm90YXRpb24tdW5sb2NrLWEtMDAwMQ",
        &signer.method,
        seed_a,
    )
    .await?;
    ensure!(
        released.status() == StatusCode::OK,
        "A could not unlock its active envelope: {} {}",
        released.status(),
        released.text().await.unwrap_or_default()
    );
    ensure!(
        released.json::<KeyBackup>().await? == old,
        "unlock released another envelope"
    );
    let method_b =
        DidUrl::new(format!("{}#{DEVICE_B}", signer.actor)).map_err(anyhow::Error::msg)?;
    let released_b = unlock(
        &client_b,
        OLD_BACKUP,
        "cm90YXRpb24tdW5sb2NrLWItMDAwMQ",
        &method_b,
        DEVICE_B_SEED,
    )
    .await?;
    ensure!(
        released_b.status() == StatusCode::OK,
        "the accepted device B could not unlock: {} {}",
        released_b.status(),
        released_b.text().await.unwrap_or_default()
    );
    let inactive = signer.backup(
        INACTIVE_BACKUP,
        &BackupSeriesId::new(INACTIVE_SERIES)?,
        b"inactive-series",
        seed_a,
    )?;
    let stored = expect_json(
        client_a
            .put(&format!("/_arkret/self/keys/backups/{INACTIVE_BACKUP}"))
            .header("Idempotency-Key", "rotation-inactive-backup")
            .json(&inactive),
        StatusCode::OK,
    )
    .await?;
    ensure!(stored["status"] == "accepted", "inactive PUT: {stored}");
    let stale = unlock(
        &client_a,
        INACTIVE_BACKUP,
        "cm90YXRpb24tdW5sb2NrLWEtMDAwMg",
        &signer.method,
        seed_a,
    )
    .await?;
    let stale_status = stale.status();
    let stale_body: serde_json::Value = stale.json().await?;
    ensure!(
        stale_status == StatusCode::CONFLICT
            && stale_body["type"] == "https://arkret.org/problems/failed_precondition"
            && stale_body["reason_code"] == "backup_revision_stale",
        "an envelope outside the active series was released: {stale_status} {stale_body}"
    );

    // 1. A revoke not signed by A's current key aborts with no proposal, Commit or effect on its
    //    target.
    let (forged, _) = signer.rotation(
        "f001",
        DEVICE_B,
        FORGED_SEED,
        seed_a,
        &old,
        &commit.commit_id,
    )?;
    let aborted = create(&client_a, &forged).await?;
    ensure!(
        aborted.revoke_proposal.is_none()
            && aborted.revoke_command_outcome.is_none()
            && aborted.accepted_steps.is_empty()
            && aborted_with(&aborted, "proof_invalid"),
        "a forged revoke was not aborted before any effect: {aborted:?}"
    );
    ensure!(listing(&client_a).await?.active_series == selected.active_series);
    ensure!(listing(&client_b).await?.active_series == selected.active_series);

    // 2. Replacement material not signed by A: the worker accepts the revoke of C, the upload unit
    //    refuses the envelope, and the rotation stops with its revoke kept and no backup, pointer
    //    or step written.
    let (bad_material, bad_binding) = signer.rotation(
        "f002",
        DEVICE_C,
        seed_a,
        FORGED_SEED,
        &old,
        &commit.commit_id,
    )?;
    let stopped = create(&client_a, &bad_material).await?;
    ensure!(
        stopped.accepted_steps.len() == 1
            && stopped.revoke_command_outcome.as_ref().is_some_and(
                |outcome| outcome.result == SecurityRotationRevokeCommandResult::Accepted
            )
            && aborted_with(&stopped, "proof_invalid"),
        "a forged replacement was not refused after the accepted revoke: {stopped:?}"
    );
    let after_refusal = listing(&client_a).await?;
    ensure!(
        pointer_is(&after_refusal, SERIES_ONE, 1)
            && stopped
                .revoke_command_outcome
                .as_ref()
                .is_some_and(|outcome| after_refusal.active_series.authority_commit_id
                    == outcome.covering_commit_id),
        "a refused upload moved the pointer: {:?}",
        after_refusal.active_series
    );
    ensure!(
        !lists(
            &after_refusal,
            bad_binding.new_backups[0].backup_id.as_str()
        ),
        "a refused upload stored its replacement envelope"
    );
    ensure!(
        refused(&client_c).await?,
        "the accepted revoke of C did not stop its session"
    );
    // The stopped rotation's reserved pointer cannot switch outside it.
    let SecurityTransactionCreateRequest::SecurityRotation(bad_rotation) = &bad_material else {
        unreachable!("rotation request")
    };
    let reserved = events_a
        .post("/_arkret/self/events")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(arkret_canonical::canonical_json_bytes(
            &crate::publication::initial_submission(
                bad_rotation.prepared_plan.backup_rotations[0]
                    .active_series_unit
                    .request
                    .events[0]
                    .clone(),
                "",
            )?,
        )?)
        .send()
        .await?;
    let reserved_status = reserved.status();
    let reserved_body = reserved.text().await.unwrap_or_default();
    ensure!(
        !reserved_status.is_success() && reserved_body.contains("reserved by a SecurityRotation"),
        "a reserved pointer switched outside its rotation: {reserved_status} {reserved_body}"
    );
    ensure!(listing(&client_a).await?.active_series == after_refusal.active_series);

    // 3. The genuine rotation revokes B; the worker uploads the replacement, switches the pointer
    //    and erases the old series in the same create.
    let (request, binding) = signer.rotation(
        "f003",
        DEVICE_B,
        seed_a,
        seed_a,
        &old,
        &after_refusal.active_series.authority_commit_id,
    )?;
    let erased = create(&client_a, &request).await?;
    let outcome = erased
        .revoke_command_outcome
        .clone()
        .context("the worker did not decide the revoke proposal")?;
    ensure!(
        outcome.result == SecurityRotationRevokeCommandResult::Accepted
            && erased.accepted_steps.len() == 4
            && erased.terminal_outcome.is_none(),
        "the worker did not reach the local commit: {erased:?}"
    );
    let SecurityTransactionCreateRequest::SecurityRotation(rotation) = &request else {
        unreachable!("rotation request")
    };
    let after_erase = listing(&client_a).await?;
    ensure!(
        after_erase.active_series.authority_commit_id
            != after_refusal.active_series.authority_commit_id
            && pointer_is(&after_erase, binding.new_series_id.as_str(), 2),
        "the switch Commit is not the listed pointer basis: {:?}",
        after_erase.active_series
    );
    ensure!(
        !lists(&after_erase, OLD_BACKUP)
            && lists(&after_erase, binding.new_backups[0].backup_id.as_str()),
        "the worker erased the wrong envelopes"
    );
    // The replacement envelope of the switched series is released to A.
    let rotated = unlock(
        &client_a,
        binding.new_backups[0].backup_id.as_str(),
        "cm90YXRpb24tdW5sb2NrLWEtMDAwMw",
        &signer.method,
        seed_a,
    )
    .await?;
    ensure!(
        rotated.status() == StatusCode::OK,
        "A could not unlock the switched series: {} {}",
        rotated.status(),
        rotated.text().await.unwrap_or_default()
    );
    ensure!(
        refused(&client_b).await?,
        "the revoked device still authenticates"
    );

    // 4. The worker owns erase; no public self HTTP binding remains.
    let foreign = canonical_post(
        &client_a,
        &format!("/_arkret/self/keys/backup-series/{}", "erase"),
        &serde_json::json!({}),
    )?
    .send()
    .await?;
    let foreign_status = foreign.status();
    let foreign_body = foreign.text().await.unwrap_or_default();
    ensure!(
        foreign_status == StatusCode::NOT_FOUND && foreign_body.contains("unrecognized_endpoint"),
        "the retired erase route was still reachable: {foreign_status} {foreign_body}"
    );
    let unchanged = listing(&client_a).await?;
    ensure!(
        unchanged.active_series == after_erase.active_series
            && !lists(&unchanged, OLD_BACKUP)
            && lists(&unchanged, binding.new_backups[0].backup_id.as_str()),
        "a retired erase request changed the backup listing"
    );

    // 5. local_commit: A attests the terminal step with its authorized device key under its account
    //    DID URL. A forged signature is refused and writes nothing; the genuine one completes the
    //    rotation.
    let local_commit = |seed: [u8; 32]| -> Result<SecurityTransactionContinueRequest> {
        let artifact = SecurityRotationLocalCommit {
            schema: arkret_wire::SchemaId::SECURITY_ROTATION_LOCAL_COMMIT_V1.to_owned(),
            transaction_id: erased.transaction_id.clone(),
            transaction_request_digest: erased.request_digest.clone(),
            prepared_plan_digest: erased.prepared_plan_digest.clone(),
            local_commit_digest: rotation.prepared_plan.local_commit_digest.clone(),
            device_id: principal.device_id.clone(),
            committed_at: arkret::canonical::normalize_timestamp_canonical(Utc::now()),
        };
        let mut attestation = ClientStepAttestation {
            step: SecurityTransactionStep::LocalCommit,
            output_ref: rotation.prepared_plan.local_commit_digest.to_string(),
            transaction_id: erased.transaction_id.clone(),
            transaction_request_digest: erased.request_digest.clone(),
            prepared_plan_digest: erased.prepared_plan_digest.clone(),
            artifact: ClientStepAttestationArtifact::SecurityRotation(artifact),
            auth_data: ClientStepAttestationAuthData {
                verification_method: signer.method.clone(),
                signature_algorithm: "Ed25519".to_owned(),
                signature: Base64UrlString::new("AA").map_err(anyhow::Error::msg)?,
            },
        };
        let signature = SigningKey::from_bytes(&seed).sign(&attestation.signing_bytes()?);
        attestation.auth_data.signature =
            Base64UrlString::new(arkret_canonical::base64url_encode(signature.to_bytes()))
                .map_err(anyhow::Error::msg)?;
        Ok(SecurityTransactionContinueRequest {
            request_digest: erased.request_digest.clone(),
            prepared_plan_digest: erased.prepared_plan_digest.clone(),
            expected_accepted_step_count: 4,
            client_attestation: attestation,
        })
    };
    let continue_path = format!(
        "/_arkret/self/security-transactions/{}/continue",
        erased.transaction_id
    );
    let forged = canonical_post(&client_a, &continue_path, &local_commit(FORGED_SEED)?)?
        .send()
        .await?;
    let forged_status = forged.status();
    let forged_body = forged.text().await.unwrap_or_default();
    ensure!(
        forged_status.is_client_error() && forged_body.contains("failed_precondition"),
        "a forged local commit was not refused: {forged_status} {forged_body}"
    );
    let genuine = local_commit(seed_a)?;
    let completed: SecurityTransaction = serde_json::from_value(
        expect_json(
            canonical_post(&client_a, &continue_path, &genuine)?,
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        completed.accepted_steps.len() == 5
            && completed.accepted_steps[..4] == erased.accepted_steps[..]
            && matches!(
                completed.terminal_outcome,
                Some(SecurityTransactionTerminalOutcome::Completed { .. })
            ),
        "the local commit did not complete the rotation: {completed:?}"
    );
    let replayed: SecurityTransaction = serde_json::from_value(
        expect_json(
            canonical_post(&client_a, &continue_path, &genuine)?,
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        replayed == completed,
        "an exact local commit replay changed the resource"
    );
    let fetched: SecurityTransaction = serde_json::from_value(
        expect_json(
            client_a.get(&format!(
                "/_arkret/self/security-transactions/{}",
                erased.transaction_id
            )),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        fetched == completed,
        "the durable resource is not the completed rotation"
    );
    // An exact create replay reads the durable resource and writes nothing.
    ensure!(
        create(&client_a, &request).await? == fetched,
        "an exact create replay changed the resource"
    );
    let unchanged = listing(&client_a).await?;
    ensure!(
        unchanged.active_series == after_erase.active_series
            && !lists(&unchanged, OLD_BACKUP)
            && lists(&unchanged, binding.new_backups[0].backup_id.as_str()),
        "a refused or replayed request changed the backup listing"
    );
    drop(server);
    drop(database);
    Ok(())
}

/// A revoke proposal whose decision never lands before expiry ends
/// `rejected` (decision 0102): the target device is refused while the
/// proposal is pending and authenticates again once the rotation expired with
/// its rejected result. The development failpoint defers every revoke
/// decision on this dedicated server, standing in for a worker that crashed
/// between the proposal and its terminal write.
pub async fn security_rotation_rejected_revoke_restores_the_target_device() -> Result<()> {
    let LiveRotation {
        server,
        _coauth,
        database,
        client_a,
        client_b,
        signer,
        old,
        selected,
        ..
    } = live_rotation(
        "security-rotation-rejected-revoke",
        &[(
            "SOLAND_FAILPOINTS",
            "security_rotation_revoke_terminal=fail_after_durable_steps:0",
        )],
    )
    .await?;
    ensure!(
        !refused(&client_b).await?,
        "B does not authenticate before the rotation"
    );

    let (request, _) = signer.rotation_until(
        "f004",
        DEVICE_B,
        signer.seed,
        signer.seed,
        std::slice::from_ref(&old),
        &selected.active_series.authority_commit_id,
        chrono::Duration::seconds(3),
    )?;
    let pending = create(&client_a, &request).await?;
    ensure!(
        pending.revoke_proposal.is_some()
            && pending.revoke_command_outcome.is_none()
            && pending.accepted_steps.is_empty()
            && pending.terminal_outcome.is_none(),
        "the revoke proposal is not pending: {pending:?}"
    );
    ensure!(
        refused(&client_b).await?,
        "a device with a pending revoke proposal still authenticates"
    );

    // The worker sweeps every few seconds; after expiry it must write the
    // rejected result with the expired terminal, exactly once.
    let path = format!(
        "/_arkret/self/security-transactions/{}",
        pending.transaction_id
    );
    let mut expired = None;
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let current: SecurityTransaction =
            serde_json::from_value(expect_json(client_a.get(&path), StatusCode::OK).await?)?;
        if current.terminal_outcome.is_some() {
            expired = Some(current);
            break;
        }
    }
    let expired = expired.context("the expired rotation was never terminated by the worker")?;
    ensure!(
        matches!(
            expired.terminal_outcome,
            Some(SecurityTransactionTerminalOutcome::Expired { .. })
        ) && expired.accepted_steps.is_empty()
            && expired
                .revoke_command_outcome
                .as_ref()
                .is_some_and(|outcome| outcome.result
                    == SecurityRotationRevokeCommandResult::Rejected
                    && Some(&outcome.proposal_event_id)
                        == pending
                            .revoke_proposal
                            .as_ref()
                            .map(|proposal| &proposal.proposal_event_id)),
        "the expired rotation did not record its rejected revoke: {expired:?}"
    );

    // The rejected proposal has no effect: B authenticates and lists again,
    // and A's pointer and envelopes are untouched. Only the PCR head moved,
    // to the Commit that covers the immutable proposal Event.
    ensure!(
        !refused(&client_b).await?,
        "the target of a rejected revoke is still refused"
    );
    let after = listing(&client_b).await?;
    ensure!(
        pointer_is(&after, SERIES_ONE, 1)
            && lists(&after, OLD_BACKUP)
            && Some(&after.active_series.authority_commit_id)
                == pending
                    .revoke_proposal
                    .as_ref()
                    .map(|proposal| &proposal.covering_commit_id),
        "a rejected rotation moved the pointer or envelopes: {:?}",
        after.active_series
    );
    drop(server);
    drop(database);
    Ok(())
}

/// A storage failure in the middle of `erase_old_material` leaves the
/// rotation resumable (security-transactions.md §3): the first worker attempt
/// erases one of the two planned old envelopes and records the other as
/// `failed_retryable`, the step stays unaccepted, and a later sweep resumes
/// the same durable request, erases the rest and accepts the step. The
/// development failpoint arms only the first erase attempt of a transaction.
pub async fn security_rotation_erase_resumes_after_a_partial_failure() -> Result<()> {
    let LiveRotation {
        server,
        _coauth,
        database,
        client_a,
        client_b,
        signer,
        seed_a,
        old,
        selected,
        ..
    } = live_rotation(
        "security-rotation-erase-resume",
        &[(
            "SOLAND_FAILPOINTS",
            "backup_series_erase_durable_step=fail_after_durable_steps:1",
        )],
    )
    .await?;

    // A second envelope of SERIES_ONE, so the erase has two durable steps.
    let second = signer.successor(OLD_SUCCESSOR, &old, b"old-successor", seed_a)?;
    let stored = expect_json(
        client_a
            .put(&format!("/_arkret/self/keys/backups/{OLD_SUCCESSOR}"))
            .header("Idempotency-Key", "rotation-old-successor")
            .json(&second),
        StatusCode::OK,
    )
    .await?;
    ensure!(stored["status"] == "accepted", "successor PUT: {stored}");
    let olds = [old, second];
    let (request, binding) = signer.rotation_until(
        "f005",
        DEVICE_B,
        seed_a,
        seed_a,
        &olds,
        &selected.active_series.authority_commit_id,
        chrono::Duration::hours(1),
    )?;
    let partial = create(&client_a, &request).await?;
    ensure!(
        partial.accepted_steps.len() == 3 && partial.terminal_outcome.is_none(),
        "a partial erase must leave the step unaccepted and the rotation live: {partial:?}"
    );
    let after_partial = listing(&client_a).await?;
    let still_listed = olds
        .iter()
        .filter(|old| lists(&after_partial, old.backup_id.as_str()))
        .count();
    ensure!(
        still_listed == 1
            && pointer_is(&after_partial, binding.new_series_id.as_str(), 2)
            && lists(&after_partial, binding.new_backups[0].backup_id.as_str()),
        "the first erase attempt did not stop after exactly one durable step: {:?}",
        after_partial.backups
    );

    // The worker resumes the same durable request on a later sweep.
    let path = format!(
        "/_arkret/self/security-transactions/{}",
        partial.transaction_id
    );
    let mut resumed = None;
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let current: SecurityTransaction =
            serde_json::from_value(expect_json(client_a.get(&path), StatusCode::OK).await?)?;
        if current.accepted_steps.len() == 4 || current.terminal_outcome.is_some() {
            resumed = Some(current);
            break;
        }
    }
    let resumed = resumed.context("the worker never resumed the partial erase")?;
    ensure!(
        resumed.accepted_steps.len() == 4
            && resumed.accepted_steps[..3] == partial.accepted_steps[..]
            && resumed.terminal_outcome.is_none(),
        "the resumed erase did not accept exactly the erase step: {resumed:?}"
    );
    let after_resume = listing(&client_a).await?;
    ensure!(
        olds.iter()
            .all(|old| !lists(&after_resume, old.backup_id.as_str()))
            && lists(&after_resume, binding.new_backups[0].backup_id.as_str())
            && after_resume.active_series.secret_storage
                == after_partial.active_series.secret_storage,
        "the resumed erase left planned envelopes or moved the pointer: {:?}",
        after_resume.backups
    );
    ensure!(
        refused(&client_b).await?,
        "the revoked device still authenticates"
    );
    drop(server);
    drop(database);
    Ok(())
}

/// What happens between the first, partial erase attempt and the worker's
/// resume (security-transactions.md §3; decision 0108 §0931).
enum BetweenAttempts {
    /// A accepts an unrelated PCR Commit: the frozen basis is still current.
    UnrelatedPcrCommit,
    /// A moves the `secret_storage` pointer: the resume must stop.
    SecretStoragePointerChanged,
}

/// Leave a SecurityRotation with exactly one of its two old envelopes erased
/// and the erase step unaccepted, apply `between`, then wait for the worker's
/// next sweep. The worker interval is long enough that the between-attempt
/// write lands before any resume.
async fn erase_resume_across(between: BetweenAttempts, name: &str) -> Result<()> {
    let LiveRotation {
        server,
        _coauth,
        database,
        client_a,
        events_a,
        signer,
        seed_a,
        old,
        selected,
        ..
    } = live_rotation(
        name,
        &[
            (
                "SOLAND_FAILPOINTS",
                "backup_series_erase_durable_step=fail_after_durable_steps:1",
            ),
            ("SOLAND_SECURITY_ROTATION_WORKER_INTERVAL_SECONDS", "30"),
        ],
    )
    .await?;
    let second = signer.successor(OLD_SUCCESSOR, &old, b"old-successor", seed_a)?;
    let stored = expect_json(
        client_a
            .put(&format!("/_arkret/self/keys/backups/{OLD_SUCCESSOR}"))
            .header("Idempotency-Key", "rotation-old-successor")
            .json(&second),
        StatusCode::OK,
    )
    .await?;
    ensure!(stored["status"] == "accepted", "successor PUT: {stored}");
    let olds = [old, second];
    let (request, binding) = signer.rotation_until(
        "f006",
        DEVICE_B,
        seed_a,
        seed_a,
        &olds,
        &selected.active_series.authority_commit_id,
        chrono::Duration::hours(1),
    )?;
    let partial = create(&client_a, &request).await?;
    ensure!(
        partial.accepted_steps.len() == 3 && partial.terminal_outcome.is_none(),
        "a partial erase must leave the step unaccepted and the rotation live: {partial:?}"
    );
    let after_partial = listing(&client_a).await?;
    let survivor = olds
        .iter()
        .find(|old| lists(&after_partial, old.backup_id.as_str()))
        .context("the first erase attempt erased every planned envelope")?
        .backup_id
        .clone();
    ensure!(
        olds.iter()
            .filter(|old| lists(&after_partial, old.backup_id.as_str()))
            .count()
            == 1
            && pointer_is(&after_partial, binding.new_series_id.as_str(), 2),
        "the first erase attempt did not stop after exactly one durable step"
    );

    let path = format!(
        "/_arkret/self/security-transactions/{}",
        partial.transaction_id
    );
    match between {
        BetweenAttempts::UnrelatedPcrCommit => {
            // A recovery policy publication is an ordinary PCR Commit that
            // touches neither the pointer nor the device generation.
            let policy = signer.recovery_policy(
                "ak:policy:01904100-0000-7000-8000-0000000000f6",
                1,
                None,
                2,
                &[DEVICE_A, DEVICE_C],
                &signer.method,
                seed_a,
            )?;
            let published = publish_recovery_policy(&events_a, &policy).await?;
            ensure!(
                published.status() == StatusCode::OK,
                "the unrelated PCR Commit was not accepted: {} {}",
                published.status(),
                published.text().await.unwrap_or_default()
            );
            let moved = listing(&client_a).await?;
            ensure!(
                moved.active_series.authority_commit_id
                    != after_partial.active_series.authority_commit_id
                    && moved.active_series.secret_storage
                        == after_partial.active_series.secret_storage,
                "the PCR head did not move past the frozen cut with the pointer unchanged"
            );
        }
        BetweenAttempts::SecretStoragePointerChanged => {
            let pointer = signer.pointer(
                &BackupSeriesId::new(INACTIVE_SERIES)?,
                3,
                vec![binding.new_series_id.clone()],
                &after_partial.active_series.authority_commit_id,
            )?;
            let AuthoritySubmitOutcome::Accepted { status, .. } = serde_json::from_value(
                expect_json(
                    events_a
                        .post("/_arkret/self/events")
                        .json(&crate::publication::initial_submission(pointer, "")?),
                    StatusCode::OK,
                )
                .await?,
            )?
            else {
                anyhow::bail!("the pointer change was not accepted");
            };
            ensure!(status == AuthorityCommitStatus::Committed);
            ensure!(
                pointer_is(&listing(&client_a).await?, INACTIVE_SERIES, 3),
                "the pointer did not move before the resume"
            );
        }
    }
    let unchanged: SecurityTransaction =
        serde_json::from_value(expect_json(client_a.get(&path), StatusCode::OK).await?)?;
    ensure!(
        unchanged.accepted_steps.len() == 3 && unchanged.terminal_outcome.is_none(),
        "the worker resumed before the between-attempt write: {unchanged:?}"
    );

    let mut settled = None;
    for _ in 0..90 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let current: SecurityTransaction =
            serde_json::from_value(expect_json(client_a.get(&path), StatusCode::OK).await?)?;
        if current.accepted_steps.len() == 4 || current.terminal_outcome.is_some() {
            settled = Some(current);
            break;
        }
    }
    let settled = settled.context("the worker never revisited the partial erase")?;
    let after = listing(&client_a).await?;
    match between {
        BetweenAttempts::UnrelatedPcrCommit => {
            ensure!(
                settled.accepted_steps.len() == 4 && settled.terminal_outcome.is_none(),
                "an unrelated PCR Commit stopped the resume: {settled:?}"
            );
            ensure!(
                olds.iter()
                    .all(|old| !lists(&after, old.backup_id.as_str())),
                "the resumed erase left a planned envelope"
            );
        }
        BetweenAttempts::SecretStoragePointerChanged => {
            ensure!(
                settled.accepted_steps.len() == 3 && aborted_with(&settled, "failed_precondition"),
                "a changed pointer did not stop the resume: {settled:?}"
            );
            ensure!(
                lists(&after, survivor.as_str()),
                "the stopped resume still erased the remaining envelope"
            );
        }
    }
    drop(server);
    drop(database);
    Ok(())
}

/// decision 0108 §0931: an unrelated PCR Commit between attempts does not
/// stale the frozen old-backup manifest; the worker resumes and erases the
/// rest with the first request bytes.
pub async fn security_rotation_erase_resumes_after_an_unrelated_pcr_commit() -> Result<()> {
    erase_resume_across(
        BetweenAttempts::UnrelatedPcrCommit,
        "security-rotation-erase-unrelated-commit",
    )
    .await
}

/// decision 0108 §0931: a `secret_storage` pointer change between attempts
/// stops the resume before any further erasure.
pub async fn security_rotation_erase_resume_stops_after_a_pointer_change() -> Result<()> {
    erase_resume_across(
        BetweenAttempts::SecretStoragePointerChanged,
        "security-rotation-erase-pointer-change",
    )
    .await
}

/// Ordinary current-device unlock of `backup_id` (key-management.md
/// §7.7.1, §7.8.2): take the Station's single-use challenge for this
/// device, sign the closed unlock proof with `seed` under `method`, and
/// submit it. Returns the raw unlock response.
async fn unlock(
    client: &TestActorClient,
    backup_id: &str,
    request_id: &str,
    method: &DidUrl,
    seed: [u8; 32],
) -> Result<reqwest::Response> {
    use arkret_models_crypto::{
        KeyBackupUnlockAuthority, KeyBackupUnlockProof, KeyBackupUnlockProofAuthData,
        KeysBackupsIssueUnlockChallengeRequestBody, KeysBackupsUnlockChallenge,
        KeysBackupsUnlockRequestBody,
    };

    let challenge: KeysBackupsUnlockChallenge = serde_json::from_value(
        expect_json(
            client
                .post(&format!(
                    "/_arkret/self/keys/backups/{backup_id}/unlock-challenge"
                ))
                .json(&KeysBackupsIssueUnlockChallengeRequestBody {
                    request_id: Base64UrlString::new(request_id).map_err(anyhow::Error::msg)?,
                }),
            StatusCode::OK,
        )
        .await?,
    )?;
    let mut proof = KeyBackupUnlockProof {
        schema: KeyBackupUnlockProof::SCHEMA.to_owned(),
        authority: KeyBackupUnlockAuthority::CurrentDevice {
            challenge_id: challenge.challenge_id,
            nonce: challenge.nonce,
        },
        account_id: challenge.account_id,
        requesting_device_id: challenge.requesting_device_id,
        backup_id: challenge.backup_id,
        backup_kind: BackupKind::SecretStorage,
        series_id: challenge.series_id,
        ciphertext_digest: challenge.ciphertext_digest,
        challenge: challenge.challenge,
        service_id: challenge.service_id,
        audience: challenge.audience,
        issued_at: challenge.issued_at,
        expires_at: challenge.expires_at,
        auth_data: KeyBackupUnlockProofAuthData {
            verification_method: method.clone(),
            signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
            signature: Base64UrlString::new("AA").map_err(anyhow::Error::msg)?,
        },
    };
    let signature = SigningKey::from_bytes(&seed).sign(&proof.signing_payload_bytes()?);
    proof.auth_data.signature =
        Base64UrlString::new(arkret_canonical::base64url_encode(signature.to_bytes()))
            .map_err(anyhow::Error::msg)?;
    Ok(canonical_post(
        client,
        &format!("/_arkret/self/keys/backups/{backup_id}/unlock"),
        &KeysBackupsUnlockRequestBody { proof },
    )?
    .send()
    .await?)
}

/// A POST whose body is the exact RFC 8785 bytes the operation requires.
fn canonical_post(
    client: &TestActorClient,
    path: &str,
    body: &impl Serialize,
) -> Result<reqwest::RequestBuilder> {
    Ok(client
        .post(path)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(arkret_canonical::canonical_json_bytes(body)?))
}

pub(crate) async fn create(
    client: &TestActorClient,
    request: &SecurityTransactionCreateRequest,
) -> Result<SecurityTransaction> {
    Ok(serde_json::from_value(
        expect_json(
            client
                .post("/_arkret/self/security-transactions")
                .json(request),
            StatusCode::OK,
        )
        .await?,
    )?)
}

fn aborted_with(transaction: &SecurityTransaction, reason: &str) -> bool {
    matches!(
        &transaction.terminal_outcome,
        Some(SecurityTransactionTerminalOutcome::Aborted { reason_code, .. })
            if reason_code.as_deref() == Some(reason)
    )
}

fn pointer_is(list: &KeysBackupsList, series: &str, version: u64) -> bool {
    matches!(
        &list.active_series.secret_storage,
        BackupActiveSeriesPointer::Active { active_series_id, series_pointer_version }
            if active_series_id.as_str() == series && *series_pointer_version == version
    )
}

fn lists(list: &KeysBackupsList, backup_id: &str) -> bool {
    list.backups
        .iter()
        .any(|row| row.backup_id.as_str() == backup_id)
}

pub(crate) async fn refused(client: &TestActorClient) -> Result<bool> {
    Ok(client
        .get("/_arkret/self/keys/backups")
        .send()
        .await?
        .status()
        == StatusCode::UNAUTHORIZED)
}

async fn listing(client: &TestActorClient) -> Result<KeysBackupsList> {
    let body = expect_json(client.get("/_arkret/self/keys/backups"), StatusCode::OK).await?;
    Ok(serde_json::from_value(body)?)
}

fn hash(label: &str) -> Result<Hash> {
    Ok(Hash::new(arkret_canonical::sha256_digest(
        label.as_bytes(),
    ))?)
}

/// An accepted-device authorization payload with a real possession proof.
fn device_authorization(
    account: &AccountId,
    device: &str,
    seed: [u8; 32],
    at: DateTime<Utc>,
) -> Result<DeviceAuthorizePayload> {
    let key = SigningKey::from_bytes(&seed);
    let public =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(&key.verifying_key().to_bytes());
    let mut hpke = vec![0xec, 0x01];
    hpke.extend([seed[0].wrapping_add(1); 32]);
    let mut payload = DeviceAuthorizePayload {
        device_id: DeviceId::new(device.to_owned())?,
        device_public_key_did: NonEmptyString::new(format!("did:key:{public}"))
            .map_err(anyhow::Error::msg)?,
        hpke_key: NonEmptyString::new(arkret_canonical::encode_multibase_base58btc(hpke))
            .map_err(anyhow::Error::msg)?,
        algorithms: vec![
            NonEmptyString::new("ak.hpke_x25519_aead_chacha20poly1305.v1")
                .map_err(anyhow::Error::msg)?,
        ],
        device_key_algorithm: NonEmptyString::new("Ed25519").map_err(anyhow::Error::msg)?,
        authorized_by: DeviceOrPrincipalRef::DeviceId(DeviceId::new(DEVICE_A.to_owned())?),
        scopes: None,
        not_before: at,
        expires_at: None,
        authorization_binding_kind: DeviceAuthorizationBindingKind::AcceptedDevice,
        authorized_generation_ref: 1,
        device_signature: SignatureMaterial::NonEmptyString(
            NonEmptyString::new("unsigned").map_err(anyhow::Error::msg)?,
        ),
        recovery_session_id: None,
        pairing_challenge_transcript_digest: Some(hash("pairing")?),
        applet_id: None,
    };
    let bytes = payload.device_possession_signature_input(account)?;
    payload.device_signature = SignatureMaterial::NonEmptyString(
        NonEmptyString::new(arkret_canonical::base64url_encode(
            key.sign(&bytes).to_bytes(),
        ))
        .map_err(anyhow::Error::msg)?,
    );
    Ok(payload)
}

/// Admit `device` as an `accepted_device` of A's current generation through
/// the owning Station's registered accepted-device unit, over the Account
/// Authority private admission channel the pairing ledger relays through
/// (device-lifecycle.md §2.1.1 clause 6, §5.4). A signs the complete Event;
/// the target device signs its possession object. Returns the accepted
/// authorization Event id.
async fn admit_accepted_device(
    server: &ArkretServer,
    actor: &str,
    principal: &ProvisionedTestPrincipal,
    account: &AccountId,
    device: &str,
    seed: [u8; 32],
) -> Result<EventId> {
    let station = DidCoreId::new(server.service_id().as_str().to_owned())?;
    let payload = device_authorization(account, device, seed, Utc::now())?;
    let event = event_envelope_with_causal_refs_for_device(
        actor,
        DEVICE_A,
        &station,
        principal.pcr_realm_id.as_str(),
        arkret_wire::EventKind::DeviceAuthorize.as_str(),
        serde_json::to_value(&payload)?,
        None,
        Vec::new(),
        Vec::new(),
    );
    let AuthoritySubmitOutcome::Accepted { status, commit } = serde_json::from_value(
        expect_json(
            server
                .http()
                .post(server.url("/_soland/account-authority/events/admit"))
                .bearer_auth(HARNESS_INTERNAL_AUTHORITY_SECRET)
                .header("idempotency-key", event.event_id.as_str())
                .json(&arkret_wire::EventAdmissionSubmission::new(event.clone())),
            StatusCode::OK,
        )
        .await?,
    )?
    else {
        anyhow::bail!("the accepted-device authorization of {device} was not accepted");
    };
    ensure!(
        status == AuthorityCommitStatus::Committed
            && commit.event_ref == event.event_id
            && commit.realm_id == principal.pcr_realm_id,
        "the accepted-device authorization of {device} was not committed on A's PCR: {commit:?}"
    );
    Ok(event.event_id)
}

/// Publish a recovery policy through the formal publication operation.
async fn publish_recovery_policy(
    client: &TestActorClient,
    event: &Event,
) -> Result<reqwest::Response> {
    Ok(canonical_post(
        client,
        "/_arkret/root/identity/recovery-policy",
        &arkret_wire::EventAdmissionSubmission::new(event.clone()),
    )?
    .send()
    .await?)
}

/// One `device_quorum` delete of `backup_id` signed by `signers`, over a fresh
/// single-use challenge issued to `client`.
async fn quorum_delete(
    client: &TestActorClient,
    actor: &str,
    backup_id: &str,
    request_id: &str,
    signers: &[(&str, [u8; 32])],
) -> Result<reqwest::Response> {
    use arkret_models_crypto::{
        KeyBackupDeleteProof, KeyBackupDeleteQuorumSignature, KeysBackupsDeleteChallenge,
        KeysBackupsDeleteRequestBody, KeysBackupsIssueDeleteChallengeRequestBody,
    };
    use arkret_wire::{AuditReasonText, PayloadProof, PayloadProofPurpose, proof_kind};

    let request_id = Base64UrlString::new(request_id).map_err(anyhow::Error::msg)?;
    let reason = AuditReasonText::new("user_requested").map_err(anyhow::Error::msg)?;
    let challenge: KeysBackupsDeleteChallenge = serde_json::from_value(
        expect_json(
            client
                .post(&format!(
                    "/_arkret/self/keys/backups/{backup_id}/delete-challenge"
                ))
                .json(&KeysBackupsIssueDeleteChallengeRequestBody {
                    request_id: request_id.clone(),
                }),
            StatusCode::OK,
        )
        .await?,
    )?;
    let canonical = arkret_canonical::canonical_json_bytes(
        &challenge.delete_intent_transcript(Some(reason.as_str())),
    )?;
    let digest = challenge.delete_intent_digest(Some(reason.as_str()))?;
    let signatures = signers
        .iter()
        .map(|(device, seed)| -> Result<KeyBackupDeleteQuorumSignature> {
            Ok(KeyBackupDeleteQuorumSignature {
                device_id: DeviceId::new((*device).to_owned())?,
                proof: PayloadProof {
                    kind: proof_kind::DETACHED_JWS.to_owned(),
                    verification_method: DidUrl::new(format!("{actor}#{device}"))
                        .map_err(anyhow::Error::msg)?,
                    payload_digest: digest.clone(),
                    created_at: challenge.issued_at,
                    domain: None,
                    audience: None,
                    proof_purpose: Some(PayloadProofPurpose::IssuerAttestation),
                    jws: arkret_signatures::sign_ed25519_detached_jws(
                        &SigningKey::from_bytes(seed),
                        &canonical,
                    )?,
                },
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let body = KeysBackupsDeleteRequestBody {
        request_id,
        challenge_id: challenge.challenge_id,
        proof: KeyBackupDeleteProof::DeviceQuorum {
            threshold: 2,
            signatures,
        },
        reason: Some(reason),
    };
    Ok(client
        .delete(&format!("/_arkret/self/keys/backups/{backup_id}"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(arkret_canonical::canonical_json_bytes(&body)?)
        .send()
        .await?)
}

/// §7.8.1 `device_quorum` delete end to end: the founding device publishes a
/// recovery policy whose quorum is two of A, B and C; a delete signed by one
/// member is refused and leaves the envelope, and a delete signed by B and C
/// removes it.
pub async fn key_backup_device_quorum_delete_removes_an_envelope() -> Result<()> {
    let LiveRotation {
        server: _server,
        _coauth,
        database: _database,
        client_a,
        client_b,
        events_a,
        signer,
        seed_a,
        ..
    } = live_rotation("key-backup-device-quorum-delete", &[]).await?;

    // B may not sign the genesis policy; only the founding device may.
    let genesis = "ak:policy:01904100-0000-7000-8000-0000000000f1";
    let members = [DEVICE_A, DEVICE_B, DEVICE_C];
    let method_b =
        DidUrl::new(format!("{}#{DEVICE_B}", signer.actor)).map_err(anyhow::Error::msg)?;
    let by_b = signer.recovery_policy(genesis, 1, None, 2, &members, &method_b, DEVICE_B_SEED)?;
    let refused_b = publish_recovery_policy(&events_a, &by_b).await?;
    ensure!(
        refused_b.status().is_client_error(),
        "a genesis policy signed by B was accepted: {}",
        refused_b.status()
    );

    // A publishes v1; an exact retry returns the same acceptance.
    let v1 = signer.recovery_policy(genesis, 1, None, 2, &members, &signer.method, seed_a)?;
    let first = publish_recovery_policy(&events_a, &v1).await?;
    ensure!(
        first.status() == StatusCode::OK,
        "recovery policy publication failed: {} {}",
        first.status(),
        first.text().await.unwrap_or_default()
    );
    let first: arkret_models_crypto::RecoveryPolicyPublishOutcome = first.json().await?;
    ensure!(first.version == 1 && first.policy_id.as_str() == genesis);
    let replay: arkret_models_crypto::RecoveryPolicyPublishOutcome =
        publish_recovery_policy(&events_a, &v1)
            .await?
            .json()
            .await?;
    ensure!(
        replay.acceptance_basis_ref == first.acceptance_basis_ref,
        "an exact retry accepted the policy at another Commit"
    );
    let active: arkret_models_crypto::RecoveryPolicyActiveOutcome = serde_json::from_value(
        expect_json(
            client_b.get("/_arkret/root/identity/recovery-policy"),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        active
            .active_policy
            .as_ref()
            .is_some_and(|policy| policy.policy_id.as_str() == genesis),
        "the accepted policy is not the active one"
    );

    // An envelope outside the active series, deleted by quorum.
    let target = signer.backup(
        INACTIVE_BACKUP,
        &BackupSeriesId::new(INACTIVE_SERIES)?,
        b"quorum-delete",
        seed_a,
    )?;
    let stored = expect_json(
        client_a
            .put(&format!("/_arkret/self/keys/backups/{INACTIVE_BACKUP}"))
            .header("Idempotency-Key", "quorum-delete-target")
            .json(&target),
        StatusCode::OK,
    )
    .await?;
    ensure!(stored["status"] == "accepted", "target PUT: {stored}");

    let alone = quorum_delete(
        &client_a,
        &signer.actor,
        INACTIVE_BACKUP,
        "cXVvcnVtLWRlbGV0ZS1vbmUtMDAwMQ",
        &[(DEVICE_B, DEVICE_B_SEED)],
    )
    .await?;
    ensure!(
        alone.status() == StatusCode::FORBIDDEN,
        "a single quorum signature deleted the envelope: {} {}",
        alone.status(),
        alone.text().await.unwrap_or_default()
    );
    ensure!(lists(&listing(&client_a).await?, INACTIVE_BACKUP));

    let deleted = quorum_delete(
        &client_a,
        &signer.actor,
        INACTIVE_BACKUP,
        "cXVvcnVtLWRlbGV0ZS10d28tMDAwMQ",
        &[(DEVICE_B, DEVICE_B_SEED), (DEVICE_C, DEVICE_C_SEED)],
    )
    .await?;
    ensure!(
        deleted.status() == StatusCode::OK,
        "the B+C quorum could not delete: {} {}",
        deleted.status(),
        deleted.text().await.unwrap_or_default()
    );
    let deleted: arkret_models_crypto::KeysBackupsDeleteOutcome = deleted.json().await?;
    ensure!(deleted.deleted);
    ensure!(
        !lists(&listing(&client_a).await?, INACTIVE_BACKUP),
        "the deleted envelope is still listed"
    );
    Ok(())
}
