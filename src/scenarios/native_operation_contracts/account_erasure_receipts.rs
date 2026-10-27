//! Live source custody for Account-private erasure receipts.
use arkret_crypto::backup::{KeyBackupAuthBinding, build_key_backup_envelope, derive_vault_kek};
use arkret_models_collaboration::governance::erasure::*;
use arkret_models_crypto::*;
use arkret_wire::{AccountId, ActorId, Base64UrlString, DidUrl};
use ed25519_dalek::Signer as _;

use super::*;
use crate::harness::{ArkretServer, TestActorClient, expect_json};

fn entropy() -> Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).context("native erasure private entropy")?;
    Ok(bytes)
}
fn encoded(bytes: &[u8]) -> Result<Base64UrlString> {
    Base64UrlString::new(arkret_canonical::base64url_encode(bytes)).map_err(anyhow::Error::msg)
}

pub(super) async fn seed(
    station: &ArkretServer,
    client: &TestActorClient,
    account: &AccountId,
) -> Result<Value> {
    let principal = client
        .principal
        .as_ref()
        .context("native erasure accepted Device")?;
    let route = super::actor_private::exercise(station, client, account).await?;
    let passphrase =
        zeroize::Zeroizing::new(arkret_crypto::backup::format_backup_passphrase(&entropy()?));
    let secret = zeroize::Zeroizing::new(entropy()?);
    let kek = derive_vault_kek(passphrase.as_bytes())?;
    let envelope = build_key_backup_envelope(
        arkret_identifiers::new_prefixed_uuid7("ak:backup:").parse()?,
        ActorId::account(account.clone()),
        Some(principal.device_id.clone()),
        BackupKind::SecretStorage,
        "kb_1",
        "mls_group_secrets",
        &kek,
        vec![SecretStorageSecret {
            item_kind: SecretStorageItemKind::MlsGroupSecretsBackupKey,
            secret_id: "mls_group_secrets_backup_key".into(),
            secret_base64url: encoded(secret.as_ref())?,
            secret_generation: None,
            extra: Default::default(),
        }],
        &KeyBackupAuthBinding {
            device_id: principal.device_id.clone(),
            verification_method: DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
                .map_err(anyhow::Error::msg)?,
            signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
            device_authorize_event_id: principal.founding_authorize_event_id.clone(),
        },
        &|bytes| Ok(principal.device_signing_key.sign(bytes).to_bytes().to_vec()),
    )?;
    let accepted = expect_json(
        client
            .put(&format!(
                "/_arkret/self/keys/backups/{}",
                envelope.backup_id
            ))
            .header(
                "Idempotency-Key",
                arkret_identifiers::new_prefixed_uuid7("ak:request:"),
            )
            .json(&envelope),
        reqwest::StatusCode::OK,
    )
    .await?;
    ensure!(
        accepted["status"] == "accepted",
        "actual encrypted private backup was not accepted"
    );
    let key = arkret_wire::AccountDataKey::PUSH_RULES;
    let encrypted = arkret_crypto::account_data_crypto::seal_account_data_value_with_nonce(
        &entropy()?,
        &ActorId::account(account.clone()),
        key,
        &json!({"enabled":true}),
        {
            let mut nonce = [0u8; 24];
            getrandom::fill(&mut nonce).context("native erasure private nonce")?;
            nonce
        },
    )?;
    let event = client
        .author_event(
            principal.pcr_realm_id.as_str(),
            "ak.account_data.set",
            json!({"key":key,"expected_server_revision":0,"body":encrypted}),
        )
        .await?;
    let request = client.verify_publication(
        arkret_models_identity::account::AccountDataReplaceRequestBody {
            set_event: arkret_wire::EventAdmissionSubmission::new(event),
        },
    )?;
    let cell = client.sdk().account_data_replace(key, &request).await?;
    ensure!(
        cell.revision == 1,
        "native private AccountData did not advance its exact revision"
    );
    let before = footprint(station, account).await?;
    for field in ["data", "backups", "private_events", "routes"] {
        ensure!(
            before[field]
                .as_array()
                .is_some_and(|rows| !rows.is_empty()),
            "native erasure seed has no actual {field}"
        );
    }
    Ok(
        json!({"route":route,"backup":envelope,"backup_accepted":accepted,"data_request":request,"data_accepted":cell,"before":before}),
    )
}

pub(super) async fn footprint(station: &ArkretServer, account: &AccountId) -> Result<Value> {
    let database = station
        .owned_database_url()
        .context("native erasure database")?
        .to_owned();
    let account = account.clone();
    tokio::task::spawn_blocking(move ||->Result<Value>{
        let mut db=postgres::Client::connect(&database,postgres::NoTls)?;
        let owner=json!(account);let actor=ActorId::account(account.clone()).to_string();let key=account.to_string();
        let mut result=json!({});
        for (field,sql,value) in [
            ("data","SELECT to_jsonb(r) FROM account_datas r WHERE actor_id=$1",&actor),
            ("backups","SELECT to_jsonb(r) FROM key_backups r WHERE actor_id=$1",&actor),
            ("routes","SELECT to_jsonb(r) FROM device_push_routes r WHERE account_key=$1",&key),
            ("data_changes","SELECT to_jsonb(r) FROM account_data_changes r WHERE actor_id=$1",&actor),
            ("global_versions","SELECT to_jsonb(r) FROM account_global_versions r WHERE actor_key=$1",&actor),
        ] {result[field]=json!(db.query(sql,&[value])?.into_iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>());}
        result["private_events"]=json!(db.query("SELECT to_jsonb(r) FROM actor_private_events r WHERE owner_account_id=$1",&[&owner])?.into_iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>());
        result["completions"]=json!(db.query("SELECT to_jsonb(r) FROM account_private_erasure_completions r WHERE account_id=$1",&[&owner])?.into_iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>());
        result["canonical_pcr"]=json!(db.query("SELECT e.envelope,c.commit_json FROM principal_resolutions p JOIN canonical_events e ON e.realm_id=p.pcr_realm_id JOIN realm_commits c ON c.event_pk=e.pk WHERE p.principal_id=$1 AND p.station_id=$2 ORDER BY c.stream_position",&[&account.principal_id.as_str(),&account.station_id.as_str()])?.into_iter().map(|r|json!({"event":r.get::<_,Value>(0),"commit":r.get::<_,Value>(1)})).collect::<Vec<_>>());
        Ok(result)
    }).await?
}

pub(super) async fn await_completed(
    station: &ArkretServer,
    account: &AccountId,
    record: &arkret_models_collaboration::account_status::AccountStatusRecord,
    seed: &Value,
) -> Result<Value> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        let after = footprint(station, account).await?;
        if let Some(rows) = after["completions"]
            .as_array()
            .filter(|rows| !rows.is_empty())
        {
            let [completion] = rows.as_slice() else {
                anyhow::bail!("native erasure has multiple completion originals")
            };
            let package: ErasureReceiptPackage =
                serde_json::from_value(completion["package"].clone())?;
            package.validate_bindings()?;
            ensure!(package.receipt.trigger==arkret_models_collaboration::events_payloads::event_wire::ErasureTrigger::AccountStatusRecord{account_status_record_id:record.account_status_record_id.clone()}
                &&package.receipt.outcome==ErasureAttemptOutcome::Completed
                &&package.receipt.issuer_id==*station.service_id()
                &&package.receipt.subject.subject_ref==account.principal_id.as_str()
                &&package.receipt.scope.storage_boundary==ErasureStorageBoundary::AccountPrivateStore,
                "native receipt differs from exact source, terminal trigger or completed private boundary");
            for field in [
                "data",
                "backups",
                "private_events",
                "routes",
                "data_changes",
                "global_versions",
            ] {
                ensure!(
                    after[field].as_array().is_some_and(|rows| rows.is_empty()),
                    "Completed retained private {field}"
                );
            }
            ensure!(
                after["canonical_pcr"] == seed["before"]["canonical_pcr"]
                    && after["canonical_pcr"]
                        .as_array()
                        .is_some_and(|rows| !rows.is_empty()),
                "erasure rewrote its original accepted Human PCR"
            );
            return Ok(json!({"package":package,"after":after}));
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "native worker did not physically complete; pending/refusal earns zero coverage"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

async fn send(receiver: &ArkretServer, request: reqwest::Request) -> Result<Value> {
    let frozen = request
        .try_clone()
        .context("native receipt HTTP original")?;
    let response = receiver.http().execute(request).await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    cotest_test_support::operation_observation::record_response(
        Some(&frozen),
        status.as_u16(),
        &bytes,
    )?;
    ensure!(
        status == reqwest::StatusCode::OK,
        "native receipt transport: {status} {}",
        String::from_utf8_lossy(&bytes)
    );
    Ok(serde_json::from_slice(&bytes)?)
}

pub(super) async fn exercise(
    source: &ArkretServer,
    receiver: &ArkretServer,
    account: &AccountId,
    record: &arkret_models_collaboration::account_status::AccountStatusRecord,
    seed: &Value,
) -> Result<Value> {
    ensure!(
        source.service_id() != receiver.service_id(),
        "receipt transport needs an independent receiver"
    );
    let completion = await_completed(source, account, record, seed).await?;
    let package: ErasureReceiptPackage = serde_json::from_value(completion["package"].clone())?;
    let body = arkret_canonical::canonical_json_bytes(&package)?;
    let key = arkret_identifiers::new_prefixed_uuid7("ak:request:");
    let post = receiver.signed_peer_post_request_with_idempotency_key(
        source,
        "/_arkret/peer/erasure-receipts",
        &body,
        receiver.service_id(),
        Some(&key),
    )?;
    let accepted = send(
        receiver,
        post.try_clone().context("native receipt exact retry")?,
    )
    .await?;
    let replay = send(receiver, post).await?;
    let other_key = arkret_identifiers::new_prefixed_uuid7("ak:request:");
    let duplicate = send(
        receiver,
        receiver.signed_peer_post_request_with_idempotency_key(
            source,
            "/_arkret/peer/erasure-receipts",
            &body,
            receiver.service_id(),
            Some(&other_key),
        )?,
    )
    .await?;
    ensure!(
        accepted == replay && accepted == duplicate,
        "receipt replay/new transport key changed its frozen acceptance"
    );
    let ErasureReceiptSubmitResponseBody::Accepted(acceptance) =
        serde_json::from_value(accepted.clone())?
    else {
        anyhow::bail!("native receiver did not accept the actual package")
    };
    ensure!(
        acceptance.status == ErasureReceiptAcceptanceStatus::Accepted
            && acceptance.receipt_id == package.receipt.receipt_id
            && acceptance.receipt_digest == package.computed_receipt_digest()?
            && acceptance.issuer_id == *source.service_id()
            && acceptance.receiver_id == *receiver.service_id(),
        "native acknowledgement changed its package or receiver"
    );
    let fetched = send(
        receiver,
        receiver.signed_peer_get_request(
            source,
            &format!(
                "/_arkret/peer/erasure-receipts/{}",
                package.receipt.receipt_id
            ),
            receiver.service_id(),
        )?,
    )
    .await?;
    ensure!(
        fetched == json!(package),
        "native GET changed its actual original or retained stub"
    );
    let database = receiver
        .owned_database_url()
        .context("native receiver storage")?
        .to_owned();
    let lookup = format!("erasure-receipt:lookup:{}", package.receipt.receipt_id);
    let source_actor = ActorId::service(source.service_id().clone()).to_string();
    let receiver_originals=tokio::task::spawn_blocking(move ||->Result<Value> {
        let mut db=postgres::Client::connect(&database,postgres::NoTls)?;
        let rows=db.query("SELECT to_jsonb(r) FROM idempotency_keys r WHERE (actor_key=$1 AND idempotency_key IN ($2,$3)) OR idempotency_key=$4 ORDER BY idempotency_key",&[&source_actor,&key,&other_key,&lookup])?
            .into_iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>();
        Ok(json!(rows))
    }).await??;
    ensure!(
        receiver_originals
            .as_array()
            .is_some_and(|rows| rows.len() == 3),
        "receipt response and lookup originals were not durably accepted"
    );
    Ok(
        json!({"seed":seed,"completion":completion,"package":package,"accepted":accepted,"replay":replay,
        "duplicate":duplicate,"fetched":fetched,"receiver_originals":receiver_originals,"source_id":source.service_id(),"receiver_id":receiver.service_id()}),
    )
}

pub(super) fn verify(observations: &NativeOperationObservations, evidence: &Value) -> Result<()> {
    super::actor_private::verify(observations, &evidence["seed"]["route"])?;
    let package: ErasureReceiptPackage = serde_json::from_value(evidence["package"].clone())?;
    package.validate_bindings()?;
    package.receipt.validate_proof_payload_digests()?;
    ensure!(
        !package.receipt.proofs.is_empty(),
        "native worker emitted no actual proof"
    );
    for proof in &package.receipt.proofs {
        let did = arkret_identity::verification_method_did(proof.verification_method.as_str())?;
        ensure!(
            arkret_identifiers::project_did_to_core_id(&did)? == package.receipt.issuer_id,
            "receipt proof substituted its real source"
        );
        let key = native_station_key(
            observations,
            &proof.verification_method,
            package
                .receipt
                .issued_at
                .unwrap_or(package.receipt.completed_at),
        )?;
        arkret_signatures::Ed25519DetachedJwsVerifier::new().verify_detached_jws(
            &proof.signature,
            &package.receipt.canonical_proof_input()?,
            &key,
        )?;
    }
    let ErasureReceiptSubmitResponseBody::Accepted(acceptance) =
        serde_json::from_value(evidence["accepted"].clone())?
    else {
        anyhow::bail!("actual native acknowledgement missing")
    };
    let did =
        arkret_identity::verification_method_did(acceptance.proof.verification_method.as_str())?;
    ensure!(
        arkret_identifiers::project_did_to_core_id(&did)? == acceptance.receiver_id
            && acceptance.proof.created_at == acceptance.accepted_at,
        "acknowledgement lacks its exact native receiver/timestamp"
    );
    let key = native_station_key(
        observations,
        &acceptance.proof.verification_method,
        acceptance.accepted_at,
    )?;
    arkret_signatures::Ed25519DetachedJwsVerifier::new().verify_detached_jws(
        &acceptance.proof.jws,
        &acceptance.signing_input_bytes()?,
        &key,
    )?;
    let mut verified = 0;
    for exchange in &observations.exchanges {
        if exchange
            .operation_id
            .as_str()
            .starts_with("ak.peer.erasure_receipt.")
        {
            verify_native_station_http_request(observations, exchange, &[])?;
            verified += 1;
        }
    }
    ensure!(
        verified >= 4,
        "missing actual native receipt submit/replay/get transports"
    );
    Ok(())
}
