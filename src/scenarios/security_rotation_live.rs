//! A complete SecurityRotation of one Account over live HTTP against a fresh
//! Soland binary and PostgreSQL: the Station's durable worker drives
//! `revoke → upload_new_material → switch_authoritative_pointer`, and the
//! transaction-bound `backup-series/erase` then removes the old series.
//!
//! Device A founds the PCR through the ordinary signed genesis. Devices B and
//! C are **labelled fixtures**: Soland has no accepted-device pairing
//! admission unit yet (the pairing finalize step is blocked, see
//! `identity_test_support::authorize_additional_principal_device`), so the
//! scenario writes exactly the rows that unit must produce -- each device's
//! committed `ak.device.authorize` Event, a Station-signed successor
//! RealmCommit, its typed authorization current value, the advanced
//! conflict-index marker and the local device mirror. Nothing else bypasses
//! the Station: A stores its old backup through the self PUT, selects the
//! first series through the self Event surface, and creates every rotation
//! through `ak.self.security_transaction.command.create.v1`.

use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::events_payloads::{
    ControllerBackupTrustAnchor, DeviceAuthorizationBindingKind, DeviceAuthorizePayload,
    DeviceOrPrincipalRef, SignatureMaterial, UnsignedKeyBackupActiveSeries,
};
use arkret_models_crypto::{
    BackupActiveSeriesPointer, BackupKind, BackupObjectRef, BackupRotationBinding,
    BackupRotationKind, BackupRotationPlan, BackupSeriesEraseOutcome,
    BackupSeriesEraseRequestBody, BackupSeriesEraseStatus, KeyBackup, KeyBackupAead,
    KeyBackupAeadName, KeyBackupAuthData, KeyBackupDomainSeparation, KeyBackupEncryption,
    KeyBackupRecipientMethod, KeyBackupSignatureAlgorithm, KeysBackupsList,
    PreparedEventBatchRequest, PreparedEventUnit, SecretStorageContentIndex,
    SecretStorageItemKind, SecurityRotationRevokeCommandResult,
    SecurityRotationTransactionCreateRequest, SecurityTransaction,
    SecurityTransactionCreateRequest, SecurityTransactionTerminalOutcome,
};
use arkret_wire::{
    AccountId, ActorId, AuthorityCommitStatus, AuthoritySubmitOutcome, BackupId,
    BackupSeriesId, Base64UrlString, CanonicalPublicMaterial, CommitStreamRef, DeviceId,
    DidCoreId, DidUrl, Event, EventId, Hash, NonEmptyString, RealmCommit,
    RealmCommitAuthorityRef, RealmCommitId, RealmId, TransactionId,
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
const DEVICE_A: &str = "ak:device:01904100-0000-7000-8000-0000000000a1";
const DEVICE_B: &str = "ak:device:01904100-0000-7000-8000-0000000000b2";
const DEVICE_C: &str = "ak:device:01904100-0000-7000-8000-0000000000c3";
const DEVICE_B_SEED: [u8; 32] = [0xb2; 32];
const DEVICE_C_SEED: [u8; 32] = [0xc3; 32];
const FORGED_SEED: [u8; 32] = [0x66; 32];
const SERIES_ONE: &str = "ak:backup_series:01904100-0000-7000-8000-0000000000e1";
const OLD_BACKUP: &str = "ak:backup:01904100-0000-7000-8000-0000000000e2";

/// A's signing identity: the device key signs Events, envelopes and records.
struct RotationAuthor {
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

    /// A's rotation revoking `target`: one replacement envelope of a fresh
    /// series signed with `backup_seed`, and pointer version 2 over
    /// `SERIES_ONE` anchored at `source`. `revoke_seed` signs the revoke.
    fn rotation(
        &self,
        suffix: &str,
        target: &str,
        revoke_seed: [u8; 32],
        backup_seed: [u8; 32],
        old: &KeyBackup,
        source: &RealmCommitId,
    ) -> Result<(SecurityTransactionCreateRequest, BackupRotationBinding)> {
        let now = arkret::canonical::normalize_timestamp_canonical(Utc::now());
        let revoke =
            crate::harness::event_envelope_with_chain_and_signing_identity_and_causal_refs(
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
        let pointer = self.pointer(
            &series,
            2,
            vec![BackupSeriesId::new(SERIES_ONE)?],
            source,
        )?;
        let binding = BackupRotationBinding {
            backup_kind: BackupRotationKind::SecretStorage,
            previous_series_id: BackupSeriesId::new(SERIES_ONE)?,
            new_series_id: series,
            new_backups: vec![BackupObjectRef {
                backup_id: replacement.backup_id.clone(),
                ciphertext_digest: replacement.ciphertext_digest.clone(),
            }],
            active_series_event_id: pointer.event_id.clone(),
            old_backups: vec![BackupObjectRef {
                backup_id: old.backup_id.clone(),
                ciphertext_digest: old.ciphertext_digest.clone(),
            }],
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
                now + chrono::Duration::hours(1),
                unit(revoke)?,
                hash("rotated-secret")?,
                vec![BackupRotationPlan {
                    binding: binding.clone(),
                    encrypted_backup_material: CanonicalPublicMaterial::canonical_json(
                        serde_json::json!({ "backups": [replacement] }),
                    )?,
                    active_series_unit: unit(pointer)?,
                }],
            )?,
        );
        Ok((request, binding))
    }
}

pub async fn security_rotation_revokes_uploads_switches_and_erases() -> Result<()> {
    let database = spawn_ephemeral_postgres_for("COTEST_SOLAND_DATABASE_URL")?.context(
        "the rotation scenario needs PostgreSQL; set COTEST_SOLAND_DATABASE_URL or make Docker available",
    )?;
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let authority_origin = coauth.origin();
    let introspection_url = coauth.url();
    let server = spawn_with_harness_account_authority_at(
        SERVER_NAME,
        &database.connect_url,
        &[
            ("SOLAND_ACCOUNT_AUTHORITY_URL", authority_origin.as_str()),
            ("SOLAND_DID_RESOLVER_ALLOW_METHODS", "web,webvh,key,uuid"),
            (
                "SOLAND_SESSION_GRANT_INTROSPECTION_URL",
                introspection_url.as_str(),
            ),
        ],
    )
    .await?;
    let actor = actor_did_for_service_did(server.service_did(), "rotation-alice")?;
    let client_a = server.demo_client(&actor, DEVICE_A).await?;
    let principal = client_a
        .principal
        .as_ref()
        .context("device A carries its provisioned principal")?
        .clone();
    let account = AccountId::new(principal.core_id.clone(), server.service_id().clone());

    // Fixtures: B and C are accepted devices of A's current generation.
    let session_for = async |device: &str, seed: [u8; 32]| -> Result<TestActorClient> {
        let authorize = install_accepted_device_fixture(
            &server,
            &database.connect_url,
            &actor,
            &principal,
            &account,
            device,
            seed,
        )
        .await?;
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

    // 1. A revoke not signed by A's current key aborts with no proposal,
    //    Commit or effect on its target.
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

    // 2. Replacement material not signed by A: the worker accepts the revoke
    //    of C, the upload unit refuses the envelope, and the rotation stops
    //    with its revoke kept and no backup, pointer or step written.
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
            && stopped
                .revoke_command_outcome
                .as_ref()
                .is_some_and(|outcome| outcome.result
                    == SecurityRotationRevokeCommandResult::Accepted)
            && aborted_with(&stopped, "proof_invalid"),
        "a forged replacement was not refused after the accepted revoke: {stopped:?}"
    );
    let after_refusal = listing(&client_a).await?;
    ensure!(
        pointer_is(&after_refusal, SERIES_ONE, 1)
            && after_refusal.active_series.authority_commit_id.as_str()
                == stopped.accepted_steps[0].output_ref,
        "a refused upload moved the pointer: {:?}",
        after_refusal.active_series
    );
    ensure!(
        !lists(&after_refusal, bad_binding.new_backups[0].backup_id.as_str()),
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

    // 3. The genuine rotation revokes B; the worker uploads the replacement
    //    and switches the pointer in the same create.
    let (request, binding) = signer.rotation(
        "f003",
        DEVICE_B,
        seed_a,
        seed_a,
        &old,
        &after_refusal.active_series.authority_commit_id,
    )?;
    let switched = create(&client_a, &request).await?;
    let outcome = switched
        .revoke_command_outcome
        .clone()
        .context("the worker did not decide the revoke proposal")?;
    ensure!(
        outcome.result == SecurityRotationRevokeCommandResult::Accepted
            && switched.accepted_steps.len() == 3
            && switched.terminal_outcome.is_none(),
        "the worker did not reach erase: {switched:?}"
    );
    ensure!(switched.accepted_steps[1].output_ref == binding.new_series_id.as_str());
    let after_switch = listing(&client_a).await?;
    ensure!(
        after_switch.active_series.authority_commit_id.as_str()
            == switched.accepted_steps[2].output_ref
            && pointer_is(&after_switch, binding.new_series_id.as_str(), 2),
        "the switch Commit is not the listed pointer basis: {:?}",
        after_switch.active_series
    );
    ensure!(
        lists(&after_switch, binding.new_backups[0].backup_id.as_str())
            && lists(&after_switch, OLD_BACKUP),
        "the replacement or the old envelope is missing before erase"
    );
    ensure!(refused(&client_b).await?, "the revoked device still authenticates");

    // 4. Erase is refused at a basis that is no longer current, and deletes
    //    nothing.
    let erase = |authority_commit_id: RealmCommitId| -> Result<BackupSeriesEraseRequestBody> {
        let SecurityTransactionCreateRequest::SecurityRotation(rotation) = &request else {
            unreachable!("rotation request")
        };
        Ok(BackupSeriesEraseRequestBody {
            transaction_id: switched.transaction_id.clone(),
            transaction_request_digest: switched.request_digest.clone(),
            prepared_plan_digest: switched.prepared_plan_digest.clone(),
            erase_confirmation_digest: rotation.prepared_plan.erase_confirmation_digest.clone(),
            series: vec![binding.clone()],
            authority_commit_id,
        })
    };
    let stale = canonical_post(
        &client_a,
        "/_arkret/self/keys/backup-series/erase",
        &erase(commit.commit_id.clone())?,
    )?
    .send()
    .await?;
    let stale_status = stale.status();
    let stale_body = stale.text().await.unwrap_or_default();
    ensure!(
        stale_status.is_client_error() && stale_body.contains("failed_precondition"),
        "a stale erase basis was not refused: {stale_status} {stale_body}"
    );
    ensure!(lists(&listing(&client_a).await?, OLD_BACKUP));

    // 5. Erase at the switch basis removes exactly the old series and
    //    accepts the erase step; an exact replay reads the same outcome.
    let body = erase(after_switch.active_series.authority_commit_id.clone())?;
    let erased = expect_json(
        canonical_post(&client_a, "/_arkret/self/keys/backup-series/erase", &body)?,
        StatusCode::OK,
    )
    .await?;
    let typed: BackupSeriesEraseOutcome = serde_json::from_value(erased.clone())?;
    ensure!(
        typed.status == BackupSeriesEraseStatus::Complete && typed.confirmation.is_some(),
        "the erase did not complete: {erased}"
    );
    let replay = expect_json(
        canonical_post(&client_a, "/_arkret/self/keys/backup-series/erase", &body)?,
        StatusCode::OK,
    )
    .await?;
    ensure!(replay == erased, "an exact erase replay changed the outcome");
    let after_erase = listing(&client_a).await?;
    ensure!(
        !lists(&after_erase, OLD_BACKUP)
            && lists(&after_erase, binding.new_backups[0].backup_id.as_str())
            && after_erase.active_series == after_switch.active_series,
        "erase removed the wrong envelopes or moved the pointer"
    );
    let fetched: SecurityTransaction = serde_json::from_value(
        expect_json(
            client_a.get(&format!(
                "/_arkret/self/security-transactions/{}",
                switched.transaction_id
            )),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        fetched.accepted_steps.len() == 4
            && fetched.accepted_steps[..3] == switched.accepted_steps[..]
            && fetched.terminal_outcome.is_none(),
        "the durable resource does not end at the local commit: {fetched:?}"
    );
    // An exact create replay reads the durable resource and writes nothing.
    ensure!(
        create(&client_a, &request).await? == fetched,
        "an exact create replay changed the resource"
    );
    ensure!(listing(&client_a).await?.active_series == after_switch.active_series);
    drop(server);
    drop(database);
    Ok(())
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

async fn create(
    client: &TestActorClient,
    request: &SecurityTransactionCreateRequest,
) -> Result<SecurityTransaction> {
    Ok(serde_json::from_value(
        expect_json(
            client.post("/_arkret/self/security-transactions").json(request),
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

async fn refused(client: &TestActorClient) -> Result<bool> {
    Ok(client.get("/_arkret/self/keys/backups").send().await?.status() == StatusCode::UNAUTHORIZED)
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

#[derive(Serialize)]
struct CommitIdentityBody<'a> {
    realm_id: &'a RealmId,
    stream_ref: &'a CommitStreamRef,
    stream_position: u64,
    previous_commit_ref: &'a Option<RealmCommitId>,
    event_ref: &'a EventId,
    governance_generation: u64,
    authority_ref: &'a RealmCommitAuthorityRef,
    committed_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct CommitUnsignedBody<'a> {
    commit_id: &'a RealmCommitId,
    realm_id: &'a RealmId,
    stream_ref: &'a CommitStreamRef,
    stream_position: u64,
    previous_commit_ref: &'a Option<RealmCommitId>,
    event_ref: &'a EventId,
    governance_generation: u64,
    authority_ref: &'a RealmCommitAuthorityRef,
    committed_at: DateTime<Utc>,
}

/// The successor RealmCommit the governing Station would sign for `event`,
/// signed with this harness Station's notary key.
fn station_successor(
    server: &ArkretServer,
    head: &RealmCommit,
    event: &Event,
) -> Result<RealmCommit> {
    let committed_at = arkret::canonical::normalize_timestamp_canonical(Utc::now());
    let previous_commit_ref = Some(head.commit_id.clone());
    let stream_position = head.stream_position + 1;
    let identity = arkret_canonical::canonical_json_bytes(&CommitIdentityBody {
        realm_id: &head.realm_id,
        stream_ref: &head.stream_ref,
        stream_position,
        previous_commit_ref: &previous_commit_ref,
        event_ref: &event.event_id,
        governance_generation: head.governance_generation,
        authority_ref: &head.authority_ref,
        committed_at,
    })?;
    let commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(&identity));
    let (_, seed) = crate::harness::test_service_signing_key(SERVER_NAME);
    let signature = arkret_signatures::detached_object::sign_detached_object(
        &CommitUnsignedBody {
            commit_id: &commit_id,
            realm_id: &head.realm_id,
            stream_ref: &head.stream_ref,
            stream_position,
            previous_commit_ref: &previous_commit_ref,
            event_ref: &event.event_id,
            governance_generation: head.governance_generation,
            authority_ref: &head.authority_ref,
            committed_at,
        },
        arkret_wire::DetachedSignatureContext::RealmCommit,
        DidUrl::new(format!("{}#federation-fanout-key", server.service_did()))
            .map_err(anyhow::Error::msg)?,
        committed_at,
        &SigningKey::from_bytes(&seed),
    )?;
    let commit = RealmCommit {
        commit_id,
        realm_id: head.realm_id.clone(),
        stream_ref: head.stream_ref.clone(),
        stream_position,
        previous_commit_ref,
        event_ref: event.event_id.clone(),
        governance_generation: head.governance_generation,
        authority_ref: head.authority_ref.clone(),
        committed_at,
        signature,
    };
    commit.validate_shape()?;
    Ok(commit)
}

/// Write the rows an accepted-device pairing unit would commit for `device`,
/// at the current PCR head, and return its authorization Event id.
async fn install_accepted_device_fixture(
    server: &ArkretServer,
    database_url: &str,
    actor: &str,
    principal: &ProvisionedTestPrincipal,
    account: &AccountId,
    device: &str,
    seed: [u8; 32],
) -> Result<EventId> {
    let realm = principal.pcr_realm_id.to_string();
    let head_url = database_url.to_owned();
    let head_realm = realm.clone();
    let head_json = tokio::task::spawn_blocking(move || -> Result<String> {
        let mut database = postgres::Client::connect(&head_url, postgres::NoTls)?;
        Ok(database
            .query_one(
                "SELECT commit_json::text FROM realm_commits WHERE realm_id=$1 \
                 ORDER BY stream_position DESC LIMIT 1",
                &[&head_realm],
            )?
            .get(0))
    })
    .await??;
    let head: RealmCommit = serde_json::from_str(&head_json)?;
    let station = DidCoreId::new(server.service_id().as_str().to_owned())?;
    let payload = device_authorization(account, device, seed, Utc::now())?;
    let event = event_envelope_with_causal_refs_for_device(
        actor,
        DEVICE_A,
        &station,
        &realm,
        arkret_wire::EventKind::DeviceAuthorize.as_str(),
        serde_json::to_value(&payload)?,
        None,
        Vec::new(),
        Vec::new(),
    );
    let commit = station_successor(server, &head, &event)?;

    let token = arkret_canonical::base64url_decode(
        event
            .event_id
            .as_str()
            .strip_prefix("ak:event:")
            .context("Event id has its typed prefix")?,
    )?;
    ensure!(
        token.len() == 33,
        "Event id token is not suite byte plus digest"
    );
    let canonical = arkret_canonical::canonical_json_bytes(&event.digest_payload()?)?;
    let envelope = serde_json::to_string(&event)?;
    let scope_ref = serde_json::to_string(&event.scope_ref)?;
    let stream_key = arkret_canonical::canonical_json_string(&commit.stream_ref)?;
    let stream_ref = serde_json::to_string(&commit.stream_ref)?;
    let commit_json = serde_json::to_string(&commit)?;
    let mut value = serde_json::to_value(&payload)?;
    value
        .as_object_mut()
        .context("authorization payload is an object")?
        .remove("device_id");
    value["device_authorize_event_id"] = serde_json::to_value(&event.event_id)?;
    let value = value.to_string();
    let committed_at = arkret_canonical::format_timestamp_canonical(commit.committed_at);
    let actor_id = event.actor_id.to_string();
    let kind = event.kind.as_str().to_owned();
    let event_id = event.event_id.to_string();
    let commit_id = commit.commit_id.to_string();
    let previous = head.commit_id.to_string();
    let position = i64::try_from(commit.stream_position)?;
    let generation = i64::try_from(commit.governance_generation)?;
    let url = database_url.to_owned();
    let device = device.to_owned();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut database = postgres::Client::connect(&url, postgres::NoTls)?;
        let mut tx = database.transaction()?;
        tx.execute(
            "INSERT INTO canonical_events \
             (id,digest_suite,digest,actor_id,realm_id,scope_ref,kind,canonical_bytes,envelope,state,received_at,committed_at) \
             VALUES($1,1,$2,$3,$4,$5::text::jsonb,$6,$7,$8::text::jsonb,'committed',$9::text::timestamptz,$9::text::timestamptz)",
            &[&token, &token[1..].to_vec(), &actor_id, &realm, &scope_ref, &kind, &canonical, &envelope, &committed_at],
        )?;
        tx.execute(
            "INSERT INTO realm_commits \
             (commit_id,realm_id,stream_key,stream_ref,stream_position,previous_commit_ref,event_pk,governance_generation,commit_json,committed_at) \
             SELECT $1,$2,$3,$4::text::jsonb,$5,$6,pk,$7,$8::text::jsonb,$9::text::timestamptz \
             FROM canonical_events WHERE id=$10",
            &[&commit_id, &realm, &stream_key, &stream_ref, &position, &previous, &generation, &commit_json, &committed_at, &token],
        )?;
        tx.execute(
            "INSERT INTO pcr_device_authorization_current_results \
             (realm_id,device_id,current_commit_id,current_stream_position,value,updated_at) \
             VALUES($1,$2,$3,$4,$5::text::jsonb,$6::text::timestamptz)",
            &[&realm, &device, &commit_id, &position, &value, &committed_at],
        )?;
        let advanced = tx.execute(
            "UPDATE pcr_device_conflict_index_cuts SET pcr_head_commit_id=$2,updated_at=$4::text::timestamptz \
             WHERE realm_id=$1 AND pcr_head_commit_id=$3",
            &[&realm, &commit_id, &previous, &committed_at],
        )?;
        ensure!(advanced == 1, "the conflict-index marker was not at the prior head");
        let mirrored = tx.execute(
            "INSERT INTO devices (id,actor_id,device_id,device_key,verification_state,payload) \
             SELECT gen_random_uuid(),actor_id,$2,NULL,'verified', \
                    payload || jsonb_build_object('device_authorize_event_id',$3::text,'authorized_generation_ref',1) \
             FROM devices WHERE device_id=$1",
            &[&DEVICE_A, &device, &event_id],
        )?;
        ensure!(mirrored == 1, "device A has no local mirror row to model the fixture on");
        tx.commit()?;
        Ok(())
    })
    .await??;
    Ok(event.event_id)
}
