//! SecurityRotation `revoke` between two devices of one Account, over live
//! HTTP against a fresh Soland binary and PostgreSQL.
//!
//! Device A founds the PCR through the ordinary signed genesis. Device B is a
//! **labelled fixture**: Soland has no accepted-device pairing admission unit
//! yet (the pairing finalize step is blocked, see
//! `identity_test_support::authorize_additional_principal_device`), so the
//! scenario writes exactly the rows that unit must produce -- B's committed
//! `ak.device.authorize` Event, a Station-signed successor RealmCommit, B's
//! typed authorization current value, the advanced conflict-index marker and
//! the local device mirror. Nothing else in the scenario bypasses the
//! Station: A creates the rotation through `ak.self.security_transaction.
//! command.create.v1` and the Station's durable worker drives the
//! coordinator-owned revoke step through the proposal and terminal units.

use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::events_payloads::{
    DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceOrPrincipalRef, SignatureMaterial,
};
use arkret_models_crypto::{
    BackupObjectRef, BackupRotationBinding, BackupRotationKind, BackupRotationPlan,
    KeysBackupsList, PreparedEventBatchRequest, PreparedEventUnit,
    SecurityRotationRevokeCommandResult, SecurityRotationTransactionCreateRequest,
    SecurityTransaction, SecurityTransactionCreateRequest, SecurityTransactionTerminalOutcome,
};
use arkret_wire::{
    AccountId, BackupId, BackupSeriesId, CanonicalPublicMaterial, CommitStreamRef, DeviceId,
    DidCoreId, DidUrl, Event, EventId, Hash, NonEmptyString, RealmCommit, RealmCommitAuthorityRef,
    RealmCommitId, RealmId, TransactionId,
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

const SERVER_NAME: &str = "security-rotation-revoke-two-devices";
const DEVICE_A: &str = "ak:device:01904100-0000-7000-8000-0000000000a1";
const DEVICE_B: &str = "ak:device:01904100-0000-7000-8000-0000000000b2";
const DEVICE_B_SEED: [u8; 32] = [0xb2; 32];
const FORGED_SEED: [u8; 32] = [0x66; 32];

pub async fn security_rotation_revoke_stops_only_its_target_device() -> Result<()> {
    let database = spawn_ephemeral_postgres_for("COTEST_SOLAND_DATABASE_URL")?.context(
        "two-device revoke needs PostgreSQL; set COTEST_SOLAND_DATABASE_URL or make Docker available",
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
    let actor = actor_did_for_service_did(server.service_did(), "rotation-revoke-alice")?;
    let client_a = server.demo_client(&actor, DEVICE_A).await?;
    let principal = client_a
        .principal
        .as_ref()
        .context("device A carries its provisioned principal")?
        .clone();
    let account = AccountId::new(principal.core_id.clone(), server.service_id().clone());
    let genesis = listing(&client_a).await?;

    // Fixture: B is an accepted device of A's current generation.
    let authorize_b = install_accepted_device_fixture(
        &server,
        &database.connect_url,
        &actor,
        &principal,
        &account,
    )
    .await?;
    let key_b = SigningKey::from_bytes(&DEVICE_B_SEED);
    let grant_b = mock_session_grant_jwt(
        principal.core_id.as_str(),
        DEVICE_B,
        server.service_id().as_str(),
    );
    coauth.bind_founding_device_grant(
        &grant_b,
        principal.core_id.as_str(),
        DEVICE_B,
        authorize_b.as_str(),
        &key_b.verifying_key(),
    )?;
    let client_b = server.client_with_founding_device_grant(
        &ProvisionedTestPrincipal {
            device_id: DeviceId::new(DEVICE_B.to_owned())?,
            device_signing_key: key_b,
            founding_authorize_event_id: authorize_b.clone(),
            ..principal.clone()
        },
        grant_b,
    )?;
    let installed = listing(&client_a).await?;
    ensure!(
        installed.active_series.authority_commit_id != genesis.active_series.authority_commit_id,
        "the fixture authorization did not advance the PCR head"
    );
    let b_before = listing(&client_b).await?;
    ensure!(
        b_before.active_series == installed.active_series,
        "B read another PCR cut than A while both are active"
    );

    // A rotation whose revoke Event is not signed by A's current key is
    // aborted by the worker with no proposal, Commit or effect on B.
    let (seed_a, method_a) = event_signing_identity_for_device(&actor, DEVICE_A);
    let forged = rotation_request(
        &server,
        &actor,
        &principal,
        &account,
        "01904100-0000-7000-8000-00000000f001",
        FORGED_SEED,
        method_a.clone(),
    )?;
    let aborted: SecurityTransaction = serde_json::from_value(
        expect_json(
            client_a
                .post("/_arkret/self/security-transactions")
                .json(&forged),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        aborted.revoke_proposal.is_none()
            && aborted.revoke_command_outcome.is_none()
            && aborted.accepted_steps.is_empty(),
        "a forged revoke produced a proposal or result: {aborted:?}"
    );
    ensure!(
        matches!(
            &aborted.terminal_outcome,
            Some(SecurityTransactionTerminalOutcome::Aborted { reason_code, .. })
                if reason_code.as_deref() == Some("proof_invalid")
        ),
        "a forged revoke did not abort with proof_invalid: {:?}",
        aborted.terminal_outcome
    );
    ensure!(
        listing(&client_a).await?.active_series == installed.active_series,
        "a refused revoke advanced the PCR"
    );
    ensure!(
        listing(&client_b).await?.active_series == installed.active_series,
        "a refused revoke affected its target"
    );

    // The genuine rotation: the worker admits the proposal and accepts it.
    let request = rotation_request(
        &server,
        &actor,
        &principal,
        &account,
        "01904100-0000-7000-8000-00000000f002",
        seed_a,
        method_a,
    )?;
    let created = expect_json(
        client_a
            .post("/_arkret/self/security-transactions")
            .json(&request),
        StatusCode::OK,
    )
    .await?;
    let decided: SecurityTransaction = serde_json::from_value(created.clone())?;
    let proposal = decided
        .revoke_proposal
        .clone()
        .context("the worker did not admit the revoke proposal")?;
    let outcome = decided
        .revoke_command_outcome
        .clone()
        .context("the worker did not decide the revoke proposal")?;
    let SecurityTransactionCreateRequest::SecurityRotation(rotation) = &request else {
        unreachable!("rotation request")
    };
    let revoke_event = &rotation.prepared_plan.revoke_unit.request.events[0];
    ensure!(proposal.proposal_event_id == revoke_event.event_id);
    ensure!(
        outcome.result == SecurityRotationRevokeCommandResult::Accepted
            && outcome.proposal_event_id == proposal.proposal_event_id
            && outcome.covering_commit_id == proposal.covering_commit_id,
        "the terminal result is not bound to its proposal: {outcome:?}"
    );
    ensure!(
        decided.accepted_steps.len() == 1
            && decided.accepted_steps[0].output_ref == proposal.covering_commit_id.as_str()
            && decided.accepted_steps[0].prepared_material_digest
                == rotation.prepared_plan.revoke_unit.request_digest
            && decided.terminal_outcome.is_none(),
        "the accepted revoke step is not the first durable step: {:?}",
        decided.accepted_steps
    );

    // A keeps reading at the covering Commit; B no longer authenticates.
    let after = listing(&client_a).await?;
    ensure!(
        after.active_series.authority_commit_id == proposal.covering_commit_id,
        "A's list does not name the covering revoke Commit"
    );
    let refused = client_b.get("/_arkret/self/keys/backups").send().await?;
    ensure!(
        refused.status() == StatusCode::UNAUTHORIZED,
        "the revoked device still authenticates: {} {}",
        refused.status(),
        refused.text().await.unwrap_or_default()
    );

    // The durable resource and an exact create replay return the same result.
    let fetched = expect_json(
        client_a.get(&format!(
            "/_arkret/self/security-transactions/{}",
            decided.transaction_id
        )),
        StatusCode::OK,
    )
    .await?;
    ensure!(fetched == created, "GET changed the decided resource");
    let replay = expect_json(
        client_a
            .post("/_arkret/self/security-transactions")
            .json(&request),
        StatusCode::OK,
    )
    .await?;
    ensure!(
        replay == created,
        "an exact create replay changed the result"
    );
    ensure!(
        listing(&client_a).await?.active_series == after.active_series,
        "a replay wrote another PCR Commit"
    );
    drop(server);
    drop(database);
    Ok(())
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

/// A's SecurityRotation that revokes B. `revoke_seed` signs the revoke Event
/// under A's method, so a foreign seed yields a proof the Station must refuse.
fn rotation_request(
    server: &ArkretServer,
    actor: &str,
    principal: &ProvisionedTestPrincipal,
    account: &AccountId,
    transaction_suffix: &str,
    revoke_seed: [u8; 32],
    method_a: DidUrl,
) -> Result<SecurityTransactionCreateRequest> {
    let station = DidCoreId::new(server.service_id().as_str().to_owned())?;
    let realm = principal.pcr_realm_id.to_string();
    let now = arkret::canonical::normalize_timestamp_canonical(Utc::now());
    let revoke = crate::harness::event_envelope_with_chain_and_signing_identity_and_causal_refs(
        actor,
        &realm,
        arkret_wire::EventKind::DeviceRevoke.as_str(),
        serde_json::json!({
            "device_id": DEVICE_B,
            "revoked_by": DEVICE_A,
            "revoked_at": arkret_canonical::format_timestamp_canonical(now),
            "reason": "security_rotation",
        }),
        None,
        Vec::new(),
        revoke_seed,
        &method_a,
        Some(&station),
        Vec::new(),
    );
    let pointer = event_envelope_with_causal_refs_for_device(
        actor,
        DEVICE_A,
        &station,
        &realm,
        arkret_wire::EventKind::KeyBackupActiveSeries.as_str(),
        serde_json::json!({ "fixture": "rotation-pointer" }),
        None,
        Vec::new(),
        Vec::new(),
    );
    let series = |suffix: &str| {
        BackupSeriesId::new(format!("ak:backup_series:01904100-0000-7000-8000-{suffix}"))
    };
    let backup = |suffix: &str, label: &str| -> Result<BackupObjectRef> {
        Ok(BackupObjectRef {
            backup_id: BackupId::new(format!("ak:backup:01904100-0000-7000-8000-{suffix}"))?,
            ciphertext_digest: hash(label)?,
        })
    };
    let binding = BackupRotationBinding {
        backup_kind: BackupRotationKind::SecretStorage,
        previous_series_id: series("0000000000c1")?,
        new_series_id: series("0000000000c2")?,
        new_backups: vec![backup("0000000000c3", "rotated-backup")?],
        active_series_event_id: pointer.event_id.clone(),
        old_backups: vec![backup("0000000000c5", "old-backup")?],
    };
    let material = CanonicalPublicMaterial::canonical_json(serde_json::json!({
        "backups": [{
            "actor_id": arkret_wire::ActorId::account(account.clone()),
            "backup_id": binding.new_backups[0].backup_id,
            "backup_kind": "secret_storage",
            "ciphertext_digest": binding.new_backups[0].ciphertext_digest,
            "series_id": binding.new_series_id,
        }]
    }))?;
    let unit = |event: Event| {
        PreparedEventUnit::new(
            arkret_canonical::DigestSuite::Sha256,
            PreparedEventBatchRequest {
                events: vec![event],
            },
        )
    };
    Ok(SecurityTransactionCreateRequest::SecurityRotation(
        SecurityRotationTransactionCreateRequest::from_prepared_rotations(
            TransactionId::new(format!("ak:transaction:{transaction_suffix}"))?,
            account.clone(),
            principal.device_id.clone(),
            now + chrono::Duration::hours(1),
            unit(revoke)?,
            hash("rotated-secret")?,
            vec![BackupRotationPlan {
                binding,
                encrypted_backup_material: material,
                active_series_unit: unit(pointer)?,
            }],
        )?,
    ))
}

/// B's accepted-device authorization payload with a real possession proof.
fn device_b_authorization(
    account: &AccountId,
    at: DateTime<Utc>,
) -> Result<DeviceAuthorizePayload> {
    let key = SigningKey::from_bytes(&DEVICE_B_SEED);
    let public =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(&key.verifying_key().to_bytes());
    let mut hpke = vec![0xec, 0x01];
    hpke.extend([0xb3; 32]);
    let mut payload = DeviceAuthorizePayload {
        device_id: DeviceId::new(DEVICE_B.to_owned())?,
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

/// Write the rows an accepted-device pairing unit would commit for B, at the
/// current PCR head, and return B's authorization Event id.
async fn install_accepted_device_fixture(
    server: &ArkretServer,
    database_url: &str,
    actor: &str,
    principal: &ProvisionedTestPrincipal,
    account: &AccountId,
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
    let payload = device_b_authorization(account, Utc::now())?;
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
            &[&realm, &DEVICE_B, &commit_id, &position, &value, &committed_at],
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
            &[&DEVICE_A, &DEVICE_B, &event_id],
        )?;
        ensure!(mirrored == 1, "device A has no local mirror row to model B on");
        tx.commit()?;
        Ok(())
    })
    .await??;
    Ok(event.event_id)
}
