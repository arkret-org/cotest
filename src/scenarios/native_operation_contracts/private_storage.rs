//! Actual encrypted backup custody and issued cursor revocation through native authorities.
use anyhow::Result;
use arkret_crypto::backup::{
    KeyBackupAuthBinding, build_key_backup_envelope, decrypt_key_backup_envelope, derive_vault_kek,
};
use arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeParameters;
use arkret_models_crypto::*;
use arkret_models_identity::account::{AccountCursorRevokeRequestBody, CursorRevokeScope};
use arkret_wire::{
    ActorId, Base64UrlString, DidUrl, PayloadProof, PayloadProofPurpose, ReasonCode,
};
use ed25519_dalek::Signer as _;

use super::*;
use crate::harness::{CanonicalJsonBody as _, expect_json, expect_response};

const SCOPE: [&str; 6] = [
    "ak.self.keys.backups.command.issue_unlock_challenge.v1",
    "ak.self.keys.backups.command.unlock.v1",
    "ak.self.keys.backups.command.issue_delete_challenge.v1",
    "ak.self.keys.backups.resource.delete.v1",
    "ak.self.account.command.revoke_cursor.v1",
    "ak.self.actor_private_events.command.submit.v1",
];

fn entropy() -> Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).context("obtain private backup entropy")?;
    Ok(bytes)
}

fn encoded(bytes: &[u8]) -> Result<Base64UrlString> {
    Base64UrlString::new(arkret_canonical::base64url_encode(bytes)).map_err(anyhow::Error::msg)
}

async fn delete_footprint(
    database: &str,
    backup: &str,
    challenge: &str,
    replay_key: &str,
) -> Result<Value> {
    let (database, backup, challenge, replay_key) = (
        database.to_owned(),
        backup.to_owned(),
        challenge.to_owned(),
        replay_key.to_owned(),
    );
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut db=postgres::Client::connect(&database,postgres::NoTls)?;
        let raw_id=backup.strip_prefix("ak:backup:").context("backup id prefix")?;
        let backup=db.query("SELECT payload FROM key_backups WHERE id::text=$1",&[&raw_id])?.into_iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>();
        let challenge:Value=db.query_one("SELECT to_jsonb(c) FROM key_backup_delete_challenges c WHERE challenge_id=$1",&[&challenge])?.get(0);
        let receipts=db.query("SELECT to_jsonb(r) FROM idempotency_keys r WHERE operation_id='ak.self.keys.backups.resource.delete' AND idempotency_key=$1",&[&replay_key])?.into_iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>();
        Ok(json!({"backups":backup,"challenge":challenge,"receipts":receipts}))
    }).await?
}

async fn delete_empty(builder: reqwest::RequestBuilder) -> Result<u16> {
    let response = expect_response(builder, reqwest::StatusCode::OK).await?;
    ensure!(
        response.body.is_empty(),
        "registered backup delete returned an entity body"
    );
    Ok(response.status.as_u16())
}

pub(super) async fn run() -> Result<()> {
    let (result, observations) = observe(async {
        let deployment = crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment("native-private-storage").await?;
        let fixture=crate::scenarios::_helpers::canonical_api::CanonicalApiFixture::from_owned(deployment.station,deployment.controller,deployment.http,deployment.endpoints,deployment.oidc_client_id);
        let client=&fixture.client;
        let private_route=super::actor_private::exercise(&fixture.server,client,&deployment.account).await?;
        let principal = client.principal.as_ref().context("accepted Device custody absent")?;
        let backup_id = arkret_identifiers::new_prefixed_uuid7("ak:backup:").parse()?;
        let passphrase = zeroize::Zeroizing::new(arkret_crypto::backup::format_backup_passphrase(&entropy()?));
        let secret = zeroize::Zeroizing::new(entropy()?);
        let secret_wire = encoded(secret.as_ref())?;
        let kek = derive_vault_kek(passphrase.as_bytes())?;
        let method = DidUrl::new(format!("{}#{}", principal.did, principal.device_id)).map_err(anyhow::Error::msg)?;
        let seal = |backup_id| build_key_backup_envelope(backup_id, ActorId::account(deployment.account.clone()), Some(principal.device_id.clone()), BackupKind::SecretStorage, "kb_1", "mls_group_secrets", &kek,
            vec![SecretStorageSecret { item_kind: SecretStorageItemKind::MlsGroupSecretsBackupKey, secret_id:"mls_group_secrets_backup_key".into(), secret_base64url:secret_wire.clone(), secret_generation:None, extra:Default::default() }],
            &KeyBackupAuthBinding { device_id:principal.device_id.clone(), verification_method:method.clone(), signature_algorithm:KeyBackupSignatureAlgorithm::Ed25519, device_authorize_event_id:principal.founding_authorize_event_id.clone() },
            &|bytes| Ok(principal.device_signing_key.sign(bytes).to_bytes().to_vec()));
        let envelope = seal(backup_id)?;
        let deletion_envelope = seal(arkret_identifiers::new_prefixed_uuid7("ak:backup:").parse()?)?;
        envelope.validate()?;
        let base = format!("/_arkret/self/keys/backups/{}", envelope.backup_id);
        let stored = expect_json(client.put(&base).header("Idempotency-Key", arkret_identifiers::new_prefixed_uuid7("ak:request:")).json(&envelope), reqwest::StatusCode::OK).await?;
        ensure!(stored["status"]=="accepted", "real encrypted envelope was not accepted");
        let deletion_base=format!("/_arkret/self/keys/backups/{}",deletion_envelope.backup_id);
        let deletion_stored=expect_json(client.put(&deletion_base).header("Idempotency-Key",arkret_identifiers::new_prefixed_uuid7("ak:request:")).json(&deletion_envelope),reqwest::StatusCode::OK).await?;
        ensure!(deletion_stored["status"]=="accepted","inactive deletion envelope was not accepted");
        let listing=client.sdk().list_key_backups(&KeyBackupsListQuery { series_id:None,backup_kind:None,cursor:None,limit:None }).await?;
        let author=crate::scenarios::security_rotation_live::RotationAuthor::from_client(client)?;
        let pointer=author.pointer(&envelope.series_id,1,Vec::new(),&listing.active_series.authority_commit_id)?;
        crate::scenarios::human_device_producer_live::submit_and_expect_commit(client,&deployment.account,principal.device_id.as_str(),&pointer).await?;
        let accepted_pointer=crate::scenarios::mls_lifecycle_live::accepted_full_view(client,&pointer.event_id).await?;
        let challenge_request = KeysBackupsIssueUnlockChallengeRequestBody { request_id:encoded(&entropy()?)? };
        let challenge: KeysBackupsUnlockChallenge = serde_json::from_value(expect_json(client.post(&format!("{base}/unlock-challenge")).json(&challenge_request), reqwest::StatusCode::OK).await?)?;
        ensure!(challenge.account_id==deployment.account && challenge.backup_id==envelope.backup_id && challenge.requesting_device_id==principal.device_id && challenge.ciphertext_digest==envelope.ciphertext_digest, "unlock challenge changed its accepted target");
        let mut proof = KeyBackupUnlockProof { schema:KeyBackupUnlockProof::SCHEMA.into(), authority:KeyBackupUnlockAuthority::CurrentDevice { challenge_id:challenge.challenge_id.clone(),nonce:challenge.nonce.clone() },
            account_id:challenge.account_id.clone(),requesting_device_id:challenge.requesting_device_id.clone(),backup_id:challenge.backup_id.clone(),backup_kind:envelope.backup_kind,series_id:challenge.series_id.clone(),ciphertext_digest:challenge.ciphertext_digest.clone(),challenge:challenge.challenge.clone(),service_id:challenge.service_id.clone(),audience:challenge.audience.clone(),issued_at:challenge.issued_at,expires_at:challenge.expires_at,
            signature_proof:KeyBackupUnlockSignatureProof { verification_method:method.clone(),signature_algorithm:KeyBackupSignatureAlgorithm::Ed25519,signature:encoded(&[0u8;64])? } };
        proof.signature_proof.signature=encoded(&principal.device_signing_key.sign(&proof.signing_payload_bytes()?).to_bytes())?;
        let request=KeysBackupsUnlockRequestBody { proof };
        let unlocked:KeyBackup=serde_json::from_value(expect_json(client.post(&format!("{base}/unlock")).json(&request),reqwest::StatusCode::OK).await?)?;
        ensure!(serde_json::to_value(&unlocked)?==serde_json::to_value(&envelope)?, "unlock changed the accepted encrypted envelope");
        let plaintext=decrypt_key_backup_envelope(passphrase.as_bytes(), &unlocked)?;
        ensure!(plaintext.items.len()==1 && plaintext.items[0].secret_base64url==encoded(secret.as_ref())?, "real backup could not restore its retained secret");
        let database=fixture.server.owned_database_url().context("failure injection requires the scenario-owned isolated database")?.to_owned();
        let before_database=database.clone();
        let id=envelope.backup_id.to_string();
        let deletion_id=deletion_envelope.backup_id.to_string();
        let before=tokio::task::spawn_blocking(move || -> Result<Value> {
            let mut db=postgres::Client::connect(&before_database,postgres::NoTls)?;
            let raw_id=id.strip_prefix("ak:backup:").context("backup id prefix")?;
            let backup:Value=db.query_one("SELECT to_jsonb(b) FROM key_backups b WHERE id::text=$1",&[&raw_id])?.get(0);
            let raw_delete=deletion_id.strip_prefix("ak:backup:").context("deletion backup id prefix")?;
            let delete_backup:Value=db.query_one("SELECT to_jsonb(b) FROM key_backups b WHERE id::text=$1",&[&raw_delete])?.get(0);
            let authorities=db.query("SELECT to_jsonb(a) FROM key_backup_unlock_authorities a",&[])?.into_iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>();
            let entries=db.query("SELECT to_jsonb(e) FROM key_backup_unlock_entries e WHERE backup_id=$1",&[&id])?.into_iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>();
            Ok(json!({"backup":backup,"delete_backup":delete_backup,"unlock_authorities":authorities,"unlock_entries":entries}))
        }).await??;
        ensure!(before["backup"]["payload"]==serde_json::to_value(&envelope)?, "durable backup differs from its accepted original");
        ensure!(before["delete_backup"]["payload"]==serde_json::to_value(&deletion_envelope)?,"deletion target differs from its durable original");
        let trusted_method=accepted_pointer.commit.signature.verification_method.clone();
        let trusted_service=TrustedRecoveryServiceEntry { service_id:fixture.server.service_id().clone(),audience:fixture.server.base_url().origin().ascii_serialization(),authorization_verification_method:trusted_method.clone() };
        let recovery_authority=crate::scenarios::human_pcr_station_binding::recovery::prepare_recovery_authority_with_trusted_service(client,Some(trusted_service)).await?;
        let policy=crate::scenarios::mls_lifecycle_live::accepted_full_view(client,&recovery_authority.policy_event.event_id).await?;
        let (candidate,_gate,_initial,_handoff)=fixture.recovery_candidate().await?;
        let claims:arkret_models_identity::SignedSessionGrantClaims=serde_json::from_slice(&arkret_canonical::base64url_decode(candidate.session().credential().split('.').nth(1).context("native recovery claims absent")?)?)?;
        claims.validate()?;
        let candidate_author=crate::scenarios::security_rotation_live::RotationAuthor::from_client(&candidate)?;
        let recovery_session=crate::scenarios::security_rotation_live::create_verified_recovery_unlock_session_bound(&candidate,&candidate_author,&recovery_authority.method,recovery_authority.seed,
            candidate.principal.as_ref().context("candidate custody absent")?.device_signing_key.to_bytes(),(claims.grant_id,Base64UrlString::new(claims.session_public_key.thumbprint_sha256()?).map_err(anyhow::Error::msg)?),crate::scenarios::_helpers::coauth_bootstrap::JOINT_TRUST_DOMAIN.parse()?).await?;
        let delete_challenge:KeysBackupsDeleteChallenge=serde_json::from_value(expect_json(client.post(&format!("{deletion_base}/delete-challenge")).json(&KeysBackupsIssueDeleteChallengeRequestBody { request_id:encoded(&entropy()?)? }),reqwest::StatusCode::OK).await?)?;
        let delete_request=KeysBackupsDeleteRequestBody { request_id:delete_challenge.request_id.clone(),challenge_id:delete_challenge.challenge_id.clone(),proof:HighRiskAuthorityProof::RecoveryUnlock(HighRiskRecoveryUnlockProofBody { kind:RecoveryUnlockProofKind::RecoveryUnlock,recovery_session_id:recovery_session.recovery_session_id.clone(),proof:PayloadProof {
            kind:arkret_wire::proof_kind::DETACHED_JWS.into(),verification_method:recovery_authority.method.clone(),payload_digest:delete_challenge.delete_intent_digest(None)?,created_at:delete_challenge.issued_at,domain:None,audience:None,proof_purpose:Some(PayloadProofPurpose::IssuerAttestation),
            jws:arkret_signatures::sign_ed25519_detached_jws(&ed25519_dalek::SigningKey::from_bytes(&recovery_authority.seed),&arkret_canonical::canonical_json_bytes(&delete_challenge.delete_intent_transcript(None))?)? } }),reason:None };
        let replay_key=format!("{}:{}:{}",SCOPE[3],deletion_envelope.backup_id,delete_request.request_id);
        let rollback_before=delete_footprint(&database,deletion_envelope.backup_id.as_str(),delete_challenge.challenge_id.as_str(),&replay_key).await?;
        let fault_database=database.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut db=postgres::Client::connect(&fault_database,postgres::NoTls)?;
            db.batch_execute("CREATE FUNCTION cotest_reject_delete_receipt() RETURNS trigger LANGUAGE plpgsql AS $function$ BEGIN IF NEW.operation_id='ak.self.keys.backups.resource.delete' THEN RAISE EXCEPTION 'native delete receipt failure injection'; END IF; RETURN NEW; END $function$; CREATE TRIGGER cotest_reject_delete_receipt BEFORE INSERT ON idempotency_keys FOR EACH ROW EXECUTE FUNCTION cotest_reject_delete_receipt();")?;
            Ok(())
        }).await??;
        let refused=client.delete(&deletion_base).canonical_json(&delete_request)?.send().await?;
        let refused_status=refused.status();
        let refused_body:Value=refused.json().await?;
        let rollback_after=delete_footprint(&database,deletion_envelope.backup_id.as_str(),delete_challenge.challenge_id.as_str(),&replay_key).await?;
        let fault_database=database.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            postgres::Client::connect(&fault_database,postgres::NoTls)?.batch_execute("DROP TRIGGER cotest_reject_delete_receipt ON idempotency_keys; DROP FUNCTION cotest_reject_delete_receipt();")?;
            Ok(())
        }).await??;
        retain_diagnostic("delete-rollback",&json!({"status":refused_status.as_u16(),"response":refused_body,"before":rollback_before,"after":rollback_after}))?;
        ensure!(refused_status==reqwest::StatusCode::INTERNAL_SERVER_ERROR && rollback_before==rollback_after,"receipt write failure did not roll back deletion and challenge consumption");
        let deleted=delete_empty(client.delete(&deletion_base).json(&delete_request)).await?;
        let delete_replay=delete_empty(client.delete(&deletion_base).json(&delete_request)).await?;
        ensure!(deleted==delete_replay,"delete exact replay lost the atomically accepted outcome");
        client.sdk().delete_key_backup(&deletion_envelope.backup_id,&delete_request).await?;
        let accepted_delete=delete_footprint(&database,deletion_envelope.backup_id.as_str(),delete_challenge.challenge_id.as_str(),&replay_key).await?;
        ensure!(accepted_delete["receipts"].as_array().is_some_and(|rows|rows.len()==1 && rows[0]["response_body"].is_null() && rows[0]["response_status"]==deleted),"delete response differs from its durable receipt");
        let trusted_envelope=seal(arkret_identifiers::new_prefixed_uuid7("ak:backup:").parse()?)?;
        let trusted_base=format!("/_arkret/self/keys/backups/{}",trusted_envelope.backup_id);
        expect_json(client.put(&trusted_base).header("Idempotency-Key",arkret_identifiers::new_prefixed_uuid7("ak:request:")).json(&trusted_envelope),reqwest::StatusCode::OK).await?;
        let trusted_challenge:KeysBackupsDeleteChallenge=serde_json::from_value(expect_json(client.post(&format!("{trusted_base}/delete-challenge")).json(&KeysBackupsIssueDeleteChallengeRequestBody { request_id:encoded(&entropy()?)? }),reqwest::StatusCode::OK).await?)?;
        let trusted_proof=PayloadProof { kind:arkret_wire::proof_kind::DETACHED_JWS.into(),verification_method:trusted_method,payload_digest:trusted_challenge.delete_intent_digest(None)?,created_at:trusted_challenge.issued_at,domain:None,audience:None,proof_purpose:Some(PayloadProofPurpose::IssuerAttestation),
            jws:arkret_signatures::sign_ed25519_detached_jws(&fixture.server.federation_signing_key()?,&arkret_canonical::canonical_json_bytes(&trusted_challenge.delete_intent_transcript(None))?)? };
        let trusted_request=KeysBackupsDeleteRequestBody { request_id:trusted_challenge.request_id.clone(),challenge_id:trusted_challenge.challenge_id.clone(),proof:HighRiskAuthorityProof::TrustedRecoveryService(HighRiskTrustedRecoveryServiceProofBody { kind:TrustedRecoveryServiceProofKind::TrustedRecoveryService,service_id:fixture.server.service_id().clone(),recovery_session_id:recovery_session.recovery_session_id.clone(),proof:trusted_proof }),reason:None };
        let mut wrong_service=trusted_request.clone();
        if let HighRiskAuthorityProof::TrustedRecoveryService(body)=&mut wrong_service.proof { body.service_id=deployment.account.principal_id.clone(); }
        let wrong=client.delete(&trusted_base).canonical_json(&wrong_service)?.send().await?;
        ensure!(wrong.status()==reqwest::StatusCode::FORBIDDEN,"an undelegated service obtained delete authority");
        let trusted_deleted=delete_empty(client.delete(&trusted_base).json(&trusted_request)).await?;
        ensure!(trusted_deleted==200 && delete_empty(client.delete(&trusted_base).json(&trusted_request)).await?==trusted_deleted,"trusted-service delete did not preserve its accepted original");
        let trusted_key=format!("{}:{}:{}",SCOPE[3],trusted_envelope.backup_id,trusted_request.request_id);
        let trusted_original=delete_footprint(&database,trusted_envelope.backup_id.as_str(),trusted_challenge.challenge_id.as_str(),&trusted_key).await?;
        ensure!(accepted_delete["backups"].as_array().is_some_and(Vec::is_empty), "native delete did not remove the accepted envelope");
        let cursor=client.sdk().account_subscribe_batch(&AccountSubscribeParameters { catchup:Some(true),..Default::default() }).await?.cursor;
        let revoke=AccountCursorRevokeRequestBody { cursor:cursor.clone(),reason_code:ReasonCode::from_wire("user_requested"),revoke_scope:CursorRevokeScope::ThisCursor };
        let revoked=expect_json(client.post("/_arkret/self/account/cursor/revoke").json(&revoke),reqwest::StatusCode::OK).await?;
        let replay=expect_json(client.post("/_arkret/self/account/cursor/revoke").json(&revoke),reqwest::StatusCode::OK).await?;
        ensure!(revoked==replay,"cursor revoke replay changed the durable original");
        let error=client.sdk().account_subscribe_batch(&AccountSubscribeParameters { after:Some(cursor.clone()),catchup:Some(true),..Default::default() }).await.expect_err("revoked cursor was accepted");
        ensure!(error.error_code()==Some(arkret_wire::ErrorCode::CursorRevoked),"cursor refusal did not reach its actual revocation fence");
        let id=deletion_envelope.backup_id.to_string();
        let challenge_id=delete_challenge.challenge_id.to_string();
        let after=tokio::task::spawn_blocking(move || -> Result<Value> {
            let mut db=postgres::Client::connect(&database,postgres::NoTls)?;
            let raw_id=id.strip_prefix("ak:backup:").context("backup id prefix")?;
            let remaining:i64=db.query_one("SELECT count(*) FROM key_backups WHERE id::text=$1",&[&raw_id])?.get(0);
            let challenge:Value=db.query_one("SELECT to_jsonb(c) FROM key_backup_delete_challenges c WHERE challenge_id=$1",&[&challenge_id])?.get(0);
            let revocations=db.query("SELECT to_jsonb(r) FROM sync_cursor_revocations r",&[])?.into_iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>();
            Ok(json!({"backup_count":remaining,"delete_challenge":challenge,"cursor_revocations":revocations}))
        }).await??;
        ensure!(after["backup_count"]==0 && after["delete_challenge"]["consumed_at"].is_string() && after["cursor_revocations"].as_array().is_some_and(|rows|rows.len()==1), "native delete or cursor side effect is missing");
        Ok::<_,anyhow::Error>(json!({"private_route":private_route,"envelope":envelope,"deletion_envelope":deletion_envelope,"accepted_pointer":accepted_pointer,"recovery_policy":policy,"recovery_session":recovery_session,"unlocked":unlocked,"unlock_challenge":challenge,"delete_challenge":delete_challenge,"delete_request":delete_request,"deleted":deleted,"trusted_envelope":trusted_envelope,"trusted_request":trusted_request,"trusted_deleted":trusted_deleted,"trusted_original":trusted_original,"delete_replay":delete_replay,"sdk_delete_replay_verified":true,"accepted_delete":accepted_delete,"rollback_probe":{"status":refused_status.as_u16(),"response":refused_body,"before":rollback_before,"after":rollback_after},"cursor":cursor,"revoke_request":revoke,"revoked":revoked,"before":before,"after":after,"processes":[deployment.coauth.server.native_process_identity()?,fixture.server.native_process_identity()?]}))
    }).await;
    retain_attempt("account-private-storage", &observations)?;
    let mut artifact = result?;
    validate_exchange_schemas(&observations, &SCOPE)?;
    super::actor_private::verify(&observations, &artifact["private_route"])?;
    verify_native_pcr_commits(
        &observations,
        &[
            serde_json::from_value(artifact["accepted_pointer"].clone())?,
            serde_json::from_value(artifact["recovery_policy"].clone())?,
        ],
    )?;
    artifact["case"] = json!("account_private_storage");

    artifact["scope"] = json!(SCOPE);
    artifact["observations"] = serde_json::to_value(observations)?;
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("account-private-storage.json"),
            serde_json::to_vec_pretty(&artifact)?,
        )?;
    }
    for operation in SCOPE {
        println!("native operation contract passed: {operation}");
    }
    Ok(())
}
