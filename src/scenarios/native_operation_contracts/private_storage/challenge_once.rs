//! Two real Coland processes, one Station/PG/keystore, and a caller that
//! observes zero response bytes before both owners are killed and reopened.
//! The relay boundary is after an actually successful upstream response; it
//! does not claim an instruction-level crash inside a production transaction.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use ed25519_dalek::Signer as _;

use super::*;
use crate::harness::{ArkretServer, ServiceRouteRelay, TestActorClient};

#[path = "../../../conformance/recovery_transaction_faults/native/process.rs"]
#[allow(
    clippy::duplicate_mod,
    reason = "Reuse the actual native response-loss/OS process observer."
)]
mod process;
#[path = "../../../conformance/recovery_transaction_faults/native/sql.rs"]
#[expect(
    dead_code,
    reason = "This native composition reuses only the existing SQL observer subset."
)]
#[allow(
    clippy::duplicate_mod,
    reason = "Reuse the actual owned-database observer, not a reference model."
)]
mod sql;

struct ChallengeLock {
    release: mpsc::Sender<()>,
    worker: Option<thread::JoinHandle<Result<()>>>,
    pid: i32,
}

impl ChallengeLock {
    fn hold(database: &str, query: &'static str, id: &str) -> Result<Self> {
        let (database, id) = (database.to_owned(), id.to_owned());
        let (release, released) = mpsc::channel();
        let (ready, readiness) = mpsc::channel();
        let worker = thread::spawn(move || -> Result<()> {
            let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
            db.batch_execute("SET lock_timeout='5s'; SET statement_timeout='15s'; BEGIN")?;
            db.query_one(query, &[&id])?;
            let pid: i32 = db.query_one("SELECT pg_backend_pid()", &[])?.get(0);
            ready
                .send(pid)
                .context("backup SQL barrier owner disappeared")?;
            let _ = released.recv();
            db.batch_execute("ROLLBACK")?;
            Ok(())
        });
        let pid = match readiness.recv_timeout(Duration::from_secs(20)) {
            Ok(pid) => pid,
            Err(error) => {
                drop(release);
                worker
                    .join()
                    .map_err(|_| anyhow::anyhow!("backup barrier panicked"))??;
                return Err(error.into());
            }
        };
        Ok(Self {
            release,
            worker: Some(worker),
            pid,
        })
    }

    fn release(mut self) -> Result<()> {
        self.release
            .send(())
            .context("release actual backup row lock")?;
        self.worker
            .take()
            .context("backup row-lock owner absent")?
            .join()
            .map_err(|_| anyhow::anyhow!("backup barrier panicked"))?
    }
}

impl Drop for ChallengeLock {
    fn drop(&mut self) {
        let _ = self.release.send(());
        if let Some(worker) = self.worker.take()
            && let Ok(Err(error)) = worker.join()
        {
            eprintln!("owned backup row-lock cleanup: {error:#}");
        }
    }
}

async fn unlock_footprint(database: &str, id: &str, backup: &str) -> Result<Value> {
    let (id, backup) = (id.to_owned(), backup.to_owned());
    sql::query(database, move |db| {
        let authority: Value = db.query_one(
            "SELECT to_jsonb(a) FROM key_backup_unlock_authorities a WHERE authority_id=$1", &[&id],
        )?.get(0);
        let entries = db.query(
            "SELECT to_jsonb(e) FROM key_backup_unlock_entries e WHERE authority_id=$1 ORDER BY backup_id", &[&id],
        )?.into_iter().map(|r| r.get::<_, Value>(0)).collect::<Vec<_>>();
        let raw = backup.strip_prefix("ak:backup:").context("backup prefix")?;
        let payload: Value = db.query_one("SELECT payload FROM key_backups WHERE id::text=$1", &[&raw])?.get(0);
        Ok(json!({"authority":authority,"entries":entries,"backup":payload}))
    }).await
}

fn unlock_request(
    client: &TestActorClient,
    target: &KeyBackup,
    challenge: &KeysBackupsUnlockChallenge,
) -> Result<KeysBackupsUnlockRequestBody> {
    let principal = client
        .principal
        .as_ref()
        .context("actual accepted Device")?;
    ensure!(
        target.actor_id == ActorId::account(challenge.account_id.clone())
            && target.backup_id == challenge.backup_id
            && target.ciphertext_digest == challenge.ciphertext_digest
            && challenge.requesting_device_id == principal.device_id,
        "actual challenge changed Account/Device/encrypted target"
    );
    let mut proof = KeyBackupUnlockProof {
        schema: KeyBackupUnlockProof::SCHEMA.into(),
        subject_actor_id: None,
        custody_authorization_ref: None,
        content_history: None,
        authority: KeyBackupUnlockAuthority::CurrentDevice {
            challenge_id: challenge.challenge_id.clone(),
        },
        account_id: challenge.account_id.clone(),
        requesting_device_id: challenge.requesting_device_id.clone(),
        backup_id: challenge.backup_id.clone(),
        backup_kind: target.backup_kind,
        series_id: challenge.series_id.clone(),
        ciphertext_digest: challenge.ciphertext_digest.clone(),
        challenge: challenge.challenge.clone(),
        service_id: challenge.service_id.clone(),
        audience: challenge.audience.clone(),
        issued_at: challenge.issued_at,
        expires_at: challenge.expires_at,
        signature_proof: KeyBackupUnlockSignatureProof {
            verification_method: DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
                .map_err(anyhow::Error::msg)?,
            signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
            signature: encoded(&[0; 64])?,
        },
    };
    proof.signature_proof.signature = encoded(
        &principal
            .device_signing_key
            .sign(&proof.signing_payload_bytes()?)
            .to_bytes(),
    )?;
    proof.validate_for_challenge(challenge)?;
    Ok(KeysBackupsUnlockRequestBody { proof })
}

fn delete_request(
    template: &KeysBackupsDeleteRequestBody,
    challenge: &KeysBackupsDeleteChallenge,
    signer: &ed25519_dalek::SigningKey,
) -> Result<KeysBackupsDeleteRequestBody> {
    let mut request = template.clone();
    request.request_id = challenge.request_id.clone();
    request.challenge_id = challenge.challenge_id.clone();
    let HighRiskAuthorityProof::RecoveryUnlock(authority) = &mut request.proof else {
        anyhow::bail!("native combination requires the separately verified recovery factor");
    };
    authority.proof.payload_digest = challenge.delete_intent_digest(request.reason.as_deref())?;
    authority.proof.created_at = challenge.issued_at;
    authority.proof.jws = arkret_signatures::sign_ed25519_detached_jws(
        signer,
        &arkret_canonical::canonical_json_bytes(
            &challenge.delete_intent_transcript(request.reason.as_deref()),
        )?,
    )?;
    request.validate()?;
    Ok(request)
}

fn request_evidence(request: &reqwest::Request) -> Result<Value> {
    let body = request
        .body()
        .and_then(reqwest::Body::as_bytes)
        .context("canonical body bytes")?;
    let dpop = request
        .headers()
        .get("dpop")
        .context("fresh outer DPoP absent")?
        .as_bytes();
    let credential = request
        .headers()
        .get(reqwest::header::AUTHORIZATION)
        .context("actual authorized request")?
        .to_str()?
        .strip_prefix("DPoP ")
        .context("actual opaque DPoP credential")?;
    let verified = arkret_signatures::dpop::verify_dpop_proof(
        &arkret_signatures::dpop::DpopVerificationRequest {
            proof_jwt: std::str::from_utf8(dpop)?,
            method: request.method().as_str(),
            htu: request.url().as_str(),
            access_token: Some(credential),
            expected_nonce: None,
            now: chrono::Utc::now(),
            max_age: chrono::Duration::seconds(300),
            max_future_skew: chrono::Duration::seconds(30),
        },
    )?;
    Ok(
        json!({"method":request.method().as_str(),"url":request.url().as_str(),
        "body_sha256":arkret_canonical::sha256_digest(body),"body_bytes":body.len(),
        "dpop_sha256":arkret_canonical::sha256_digest(dpop),
        "dpop_public_jwk":verified.public_jwk,"dpop_jkt":verified.jkt}),
    )
}

/// A row lock is held before either native request. Request zero is observed
/// waiting before the public relay selects process one, so the two requests
/// cannot accidentally route to the same owner or rely on a scheduler sleep.
async fn compete(
    server: &ArkretServer,
    sibling: &ArkretServer,
    relay: &ServiceRouteRelay,
    lock: ChallengeLock,
    database: &str,
    requests: [reqwest::Request; 2],
) -> Result<(Vec<process::HeldResponse>, Vec<Vec<u8>>, Value)> {
    let [first, second] = requests;
    let originals = [
        first
            .try_clone()
            .context("retain actual first request for observation")?,
        second
            .try_clone()
            .context("retain actual second request for observation")?,
    ];
    let request_facts = [request_evidence(&first)?, request_evidence(&second)?];
    ensure!(
        request_facts[0]["method"] == request_facts[1]["method"]
            && request_facts[0]["url"] == request_facts[1]["url"]
            && request_facts[0]["body_sha256"] == request_facts[1]["body_sha256"]
            && request_facts[0]["dpop_sha256"] != request_facts[1]["dpop_sha256"],
        "competing requests must freeze one body and use fresh independent outer DPoP"
    );
    ensure!(
        request_facts[0]["dpop_jkt"] == request_facts[1]["dpop_jkt"],
        "competing requests must use the same actual holder key"
    );
    let path = first.url().path().to_owned();
    let before = [
        relay.forwarded_requests(server, &path)?,
        relay.forwarded_requests(sibling, &path)?,
    ];
    let mut tasks = tokio::task::JoinSet::new();
    relay.select_backend(server)?;
    let http = server.http();
    tasks.spawn(async move { (0, process::HeldResponse::forward(&http, first).await) });
    let first_wait = sql::wait_for_waiters(database, lock.pid, 1).await?;
    relay.select_backend(sibling)?;
    let http = sibling.http();
    tasks.spawn(async move { (1, process::HeldResponse::forward(&http, second).await) });
    let both_wait = sql::wait_for_waiters(database, lock.pid, 2).await?;
    lock.release()?;
    let mut responses = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        let (owner, response) = joined?;
        let (held, status, body) = response?;
        cotest_test_support::operation_observation::record_response(
            Some(&originals[owner]),
            status.as_u16(),
            &body,
        )?;
        ensure!(
            status == reqwest::StatusCode::OK,
            "native once request {owner} returned {status}: {}",
            String::from_utf8_lossy(&body)
        );
        responses.push((owner, held, body));
    }
    responses.sort_by_key(|row| row.0);
    ensure!(
        responses.len() == 2,
        "two actual upstream outcomes required"
    );
    let after = [
        relay.forwarded_requests(server, &path)?,
        relay.forwarded_requests(sibling, &path)?,
    ];
    ensure!(
        after == [before[0] + 1, before[1] + 1],
        "each actual backend must complete exactly one request"
    );
    let mut held = Vec::new();
    let mut bodies = Vec::new();
    for (_, response, body) in responses {
        held.push(response);
        bodies.push(body);
    }
    Ok((
        held,
        bodies,
        json!({"requests":request_facts,"first_wait":first_wait,"both_wait":both_wait,
        "backend_forwarded_before":before,"backend_forwarded_after":after,"statuses":[200,200]}),
    ))
}

async fn reopen_after_loss(
    server: &mut ArkretServer,
    sibling: &mut ArkretServer,
    relay: &ServiceRouteRelay,
    held: Vec<process::HeldResponse>,
    method: &str,
) -> Result<Value> {
    let before = [
        process::process_evidence(server.native_process_identity()?)?,
        process::process_evidence(sibling.native_process_identity()?)?,
    ];
    ensure!(
        before[0]["pid"] != before[1]["pid"],
        "two actual process owners required"
    );
    let config_before = [
        server.service_route_configuration_digest()?,
        sibling.service_route_configuration_digest()?,
    ];
    server.stop_external_process().await?;
    sibling.stop_external_process().await?;
    let mut losses = Vec::new();
    for response in held {
        let mut loss = response.lose_after_kill().await?;
        // The reused Recovery relay executes the supplied actual HTTP method;
        // its old descriptive POST label is not a DELETE observation.
        loss["upstream"] = json!(format!("real TLS Station {method} accepted"));
        losses.push(loss);
    }
    relay.select_backend(server)?;
    server.start_external_process().await?;
    relay.select_backend(sibling)?;
    sibling.start_external_process().await?;
    let after = [
        process::process_evidence(server.native_process_identity()?)?,
        process::process_evidence(sibling.native_process_identity()?)?,
    ];
    let config_after = [
        server.service_route_configuration_digest()?,
        sibling.service_route_configuration_digest()?,
    ];
    ensure!(
        config_before[0] == config_before[1] && config_before == config_after,
        "reopen changed retained authority configuration"
    );
    for i in 0..2 {
        ensure!(
            (before[i]["pid"] != after[i]["pid"]
                || before[i]["os_process"] != after[i]["os_process"])
                && before[i]["sha256"] == after[i]["sha256"]
                && before[i]["origin"] == after[i]["origin"],
            "actual process reopen evidence differs"
        );
    }
    relay.select_backend(server)?;
    Ok(
        json!({"before":before,"after":after,"configuration_before":config_before,
        "configuration_after":config_after,"response_loss":losses,
        "kill_wait_mechanism":"owned Child::kill then Child::wait for both instances before downstream disconnect"}),
    )
}

pub(super) async fn run(
    server: &mut ArkretServer,
    client: &TestActorClient,
    active: &KeyBackup,
    inactive: &KeyBackup,
    delete_template: &KeysBackupsDeleteRequestBody,
    delete_signer: &ed25519_dalek::SigningKey,
) -> Result<Value> {
    let host = client
        .sdk()
        .own_station_result_client()?
        .context("actual accepted host/session source is required")?;
    let accepted_grant_ref = host.session()?.grant_ref().clone();
    let authenticated_actor = ActorId::account(host.session()?.account_id().clone());
    ensure!(
        authenticated_actor == active.actor_id && authenticated_actor == inactive.actor_id,
        "backup targets differ from the actual accepted host Account"
    );
    let database = server
        .owned_database_url()
        .context("scenario-owned backup authority DB")?
        .to_owned();
    let relay = server.install_service_route_relay().await?;
    let mut sibling = server
        .spawn_service_route_sibling(&relay, "native-backup-challenge-sibling")
        .await?;
    let db_identity = sql::database_identity(&database).await?;

    relay.select_backend(server)?;
    let base = format!("/_arkret/self/keys/backups/{}", active.backup_id);
    let issue = KeysBackupsIssueUnlockChallengeRequestBody {
        request_id: encoded(&entropy()?)?,
        subject_actor_id: None,
        custody_authorization_ref: None,
        content_history: None,
    };
    let challenge: KeysBackupsUnlockChallenge = serde_json::from_value(
        expect_json(
            client
                .post(&format!("{base}/unlock-challenge"))
                .canonical_json(&issue)?,
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    challenge.validate_at(chrono::Utc::now())?;
    challenge.validate_for_request(&issue, &active.backup_id)?;
    let unlock = unlock_request(client, active, &challenge)?;
    let unlock_path = format!("{base}/unlock");
    let before = unlock_footprint(
        &database,
        challenge.challenge_id.as_str(),
        active.backup_id.as_str(),
    )
    .await?;
    let body = arkret_canonical::canonical_json_bytes(&unlock)?;
    let lock = ChallengeLock::hold(
        &database,
        "SELECT authority_id FROM key_backup_unlock_authorities WHERE authority_id=$1 FOR UPDATE",
        challenge.challenge_id.as_str(),
    )?;
    let requests = [
        client.post(&unlock_path).canonical_json(&unlock)?.build()?,
        client.post(&unlock_path).canonical_json(&unlock)?.build()?,
    ];
    let (held, bodies, concurrency) =
        compete(server, &sibling, &relay, lock, &database, requests).await?;
    for bytes in &bodies {
        ensure!(
            serde_json::from_slice::<Value>(bytes)? == serde_json::to_value(active)?,
            "unlock did not return the exact encrypted original"
        );
    }
    let accepted = unlock_footprint(
        &database,
        challenge.challenge_id.as_str(),
        active.backup_id.as_str(),
    )
    .await?;
    let entries = accepted["entries"]
        .as_array()
        .context("actual unlock entries")?;
    ensure!(
        entries.len() == 1
            && entries[0]["request_digest"] == arkret_canonical::sha256_digest(&body)
            && entries[0]["consumed_at"].is_string()
            && entries[0]["holder"].as_str().is_some_and(|v| !v.is_empty()),
        "one immutable consumed unlock entry required"
    );
    let expected_jkt = concurrency["requests"][0]["dpop_jkt"]
        .as_str()
        .context("actual verified request holder thumbprint")?
        .to_owned();
    let expected_holder = json!({"session_grant_ref":accepted_grant_ref,"cnf_jkt":expected_jkt});
    let observed_holder: Value = serde_json::from_str(
        entries[0]["holder"]
            .as_str()
            .context("actual ledger holder")?,
    )?;
    ensure!(
        observed_holder == expected_holder,
        "unlock ledger differs from actual accepted fullRef/verified request holder"
    );
    let charge = arkret_canonical::canonical_json_bytes(active)?.len() as u64;
    ensure!(
        before["entries"].as_array().is_some_and(|v| v.len() == 1
            && v[0]["consumed_at"].is_null()
            && v[0]["request_digest"].is_null())
            && before["authority"]["remaining_bytes"].as_u64() == Some(charge)
            && accepted["authority"]["remaining_bytes"].as_u64() == Some(0)
            && entries[0]["charge"].as_u64() == Some(charge),
        "concurrent unlock charged other than once"
    );
    let processes = reopen_after_loss(server, &mut sibling, &relay, held, "POST").await?;
    let mut replay_requests = Vec::new();
    let replay_before = [
        relay.forwarded_requests(server, &unlock_path)?,
        relay.forwarded_requests(&sibling, &unlock_path)?,
    ];
    for owner in [0, 1] {
        relay.select_backend(if owner == 0 { &*server } else { &sibling })?;
        let request = client.post(&unlock_path).canonical_json(&unlock)?.build()?;
        let facts = request_evidence(&request)?;
        ensure!(
            facts["dpop_jkt"] == expected_jkt,
            "unlock replay changed its actual holder key"
        );
        replay_requests.push(facts);
        let original = request.try_clone().context("retain actual unlock replay")?;
        let response = server.http().execute(request).await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        cotest_test_support::operation_observation::record_response(
            Some(&original),
            status.as_u16(),
            &bytes,
        )?;
        ensure!(
            status == reqwest::StatusCode::OK
                && serde_json::from_slice::<Value>(&bytes)? == serde_json::to_value(active)?,
            "reopened unlock lost its exact encrypted outcome/current authority"
        );
    }
    let replayed = unlock_footprint(
        &database,
        challenge.challenge_id.as_str(),
        active.backup_id.as_str(),
    )
    .await?;
    let replay_after = [
        relay.forwarded_requests(server, &unlock_path)?,
        relay.forwarded_requests(&sibling, &unlock_path)?,
    ];
    ensure!(
        replay_after == [replay_before[0] + 1, replay_before[1] + 1],
        "unlock replay must reach each reopened native process"
    );
    ensure!(
        accepted == replayed,
        "unlock replay changed consumption, holder or byte budget"
    );
    let unlock_evidence = json!({"challenge":challenge,"request":unlock,"charge":charge,"before":before,
        "expected_holder":expected_holder,
        "accepted":accepted,"replayed":replayed,"concurrency":concurrency,"processes":processes,"replay_requests":replay_requests,
        "replay_backend_before":replay_before,"replay_backend_after":replay_after,
        "outcome":active,"outcome_digest":arkret_canonical::canonical_sha256(active)?});

    relay.select_backend(server)?;
    let base = format!("/_arkret/self/keys/backups/{}", inactive.backup_id);
    expect_json(
        client
            .put(&base)
            .header(
                "Idempotency-Key",
                arkret_identifiers::new_prefixed_uuid7("ak:request:"),
            )
            .canonical_json(inactive)?,
        reqwest::StatusCode::OK,
    )
    .await?;
    let issue = KeysBackupsIssueDeleteChallengeRequestBody {
        request_id: encoded(&entropy()?)?,
    };
    let challenge: KeysBackupsDeleteChallenge = serde_json::from_value(
        expect_json(
            client
                .post(&format!("{base}/delete-challenge"))
                .canonical_json(&issue)?,
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    challenge.validate_for_request(&issue, &inactive.backup_id)?;
    ensure!(
        inactive.actor_id == ActorId::account(challenge.account_id.clone())
            && challenge.service_id == *server.service_id(),
        "delete challenge changed its independent Account/authority binding"
    );
    let delete = delete_request(delete_template, &challenge, delete_signer)?;
    let key = format!("{}:{}:{}", SCOPE[3], inactive.backup_id, delete.request_id);
    let before = delete_footprint(
        &database,
        inactive.backup_id.as_str(),
        challenge.challenge_id.as_str(),
        &key,
    )
    .await?;
    let lock = ChallengeLock::hold(
        &database,
        "SELECT challenge_id FROM key_backup_delete_challenges WHERE challenge_id=$1 FOR UPDATE",
        challenge.challenge_id.as_str(),
    )?;
    let requests = [
        client.delete(&base).canonical_json(&delete)?.build()?,
        client.delete(&base).canonical_json(&delete)?.build()?,
    ];
    let (held, bodies, concurrency) =
        compete(server, &sibling, &relay, lock, &database, requests).await?;
    ensure!(
        bodies.iter().all(Vec::is_empty),
        "delete's accepted outcome must be empty200"
    );
    ensure!(
        concurrency["requests"]
            .as_array()
            .is_some_and(|rows| rows.iter().all(|row| row["dpop_jkt"] == expected_jkt)),
        "delete competition changed the actual accepted holder key"
    );
    let accepted = delete_footprint(
        &database,
        inactive.backup_id.as_str(),
        challenge.challenge_id.as_str(),
        &key,
    )
    .await?;
    // Exactly the production writer's preimage: canonical full typed DELETE
    // body, not just its delete-intent transcript, signature or request ID.
    let request_hash = arkret_canonical::canonical_sha256(&delete)?;
    let expected_receipt = json!({"authenticated_actor":authenticated_actor,
        "request_hash":request_hash,"operation_id":"ak.self.keys.backups.resource.delete",
        "idempotency_key":key});
    ensure!(
        before["backups"] == json!([inactive])
            && before["challenge"]["consumed_at"].is_null()
            && before["receipts"] == json!([])
            && accepted["backups"] == json!([])
            && accepted["challenge"]["consumed_at"].is_string()
            && accepted["receipts"]
                .as_array()
                .is_some_and(|rows| rows.len() == 1
                    && rows[0]["response_status"] == 200
                    && rows[0]["response_body"].is_null()
                    && rows[0]["request_hash"] == expected_receipt["request_hash"]
                    && rows[0]["authenticated_actor"] == expected_receipt["authenticated_actor"]
                    && rows[0]["operation_id"] == expected_receipt["operation_id"]
                    && rows[0]["idempotency_key"] == expected_receipt["idempotency_key"]),
        "delete lacks one atomic consumed challenge/deletion/terminal receipt"
    );
    let processes = reopen_after_loss(server, &mut sibling, &relay, held, "DELETE").await?;
    let mut replay_requests = Vec::new();
    let replay_before = [
        relay.forwarded_requests(server, &base)?,
        relay.forwarded_requests(&sibling, &base)?,
    ];
    for owner in [0, 1] {
        relay.select_backend(if owner == 0 { &*server } else { &sibling })?;
        let request = client.delete(&base).canonical_json(&delete)?.build()?;
        let facts = request_evidence(&request)?;
        ensure!(
            facts["dpop_jkt"] == expected_jkt,
            "delete replay changed its actual holder key"
        );
        replay_requests.push(facts);
        let original = request.try_clone().context("retain actual delete replay")?;
        let response = server.http().execute(request).await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        cotest_test_support::operation_observation::record_response(
            Some(&original),
            status.as_u16(),
            &bytes,
        )?;
        ensure!(
            status == reqwest::StatusCode::OK && bytes.is_empty(),
            "reopened delete did not return its original empty200 receipt"
        );
    }
    let replayed = delete_footprint(
        &database,
        inactive.backup_id.as_str(),
        challenge.challenge_id.as_str(),
        &key,
    )
    .await?;
    let replay_after = [
        relay.forwarded_requests(server, &base)?,
        relay.forwarded_requests(&sibling, &base)?,
    ];
    ensure!(
        replay_after == [replay_before[0] + 1, replay_before[1] + 1],
        "delete replay must reach each reopened native process"
    );
    ensure!(
        accepted == replayed,
        "delete exact replay repeated or rewrote a side effect"
    );
    ensure!(
        host.session()?.grant_ref() == &accepted_grant_ref
            && ActorId::account(host.session()?.account_id().clone()) == authenticated_actor,
        "the actual host session changed during backup once/reopen checks"
    );
    relay.select_backend(server)?;
    Ok(
        json!({"database":db_identity,"authority":server.service_id(),"origin":server.base_url(),
        "accepted_session_grant_ref":accepted_grant_ref,"authenticated_actor":authenticated_actor,
        "boundary":"actual shared-authority Coland processes and standard HTTPS; real Coauth remains a separate service/database",
        "unlock":unlock_evidence,"delete":{"challenge":challenge,"request":delete,"envelope":inactive,"before":before,
            "expected_receipt":expected_receipt,
            "accepted":accepted,"replayed":replayed,"concurrency":concurrency,"processes":processes,"replay_requests":replay_requests,
            "replay_backend_before":replay_before,"replay_backend_after":replay_after,
            "outcome":{"status":200,"body_bytes":0}}}),
    )
}
