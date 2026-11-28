//! Real H/issuer, one accepted Agent root, a dropped HTTP response and a cold crypto process.
use std::path::Path;

use arkret_models_crypto::*;

use super::*;
use crate::harness::heap_future;

fn persist<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(&arkret_canonical::canonical_json_bytes(value)?)?;
    file.sync_all()?;
    Ok(())
}

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

fn material(
    group: &arkret::ArkretMlsGroup,
    original: &Event,
    backup: &KeyBackup,
) -> Result<EventContentMaterial> {
    let [item] = backup.contents.as_slice() else {
        bail!("expected one root")
    };
    let context = item.root_context.clone().context("root context")?;
    let root = group.export_content_root(&context)?;
    let root_ref = arkret_crypto::content_history::content_root_ref(&root, &context)?;
    ensure!(item.root_ref.as_ref() == Some(&root_ref));
    let content_context = ContentContext {
        root_context: context,
        root_ref: root_ref.clone(),
        purpose: ContentPurpose::EventBody,
        encryption_scheme: arkret::EncryptedPayloadScheme::EpochContentAead,
        encryption_algorithm: ContentEncryptionAlgorithm::Aes128Gcm,
        producer: group.local_content_endpoint()?,
        content_key_salt: arkret_crypto::content_history::fresh_content_key_salt()?,
    };
    let key = arkret_crypto::content_history::derive_content_key(&root, &content_context)?;
    Ok(EventContentMaterial {
        outer_event: EventContentMaterial::outer_event_for(original)?,
        key_commitment: arkret_crypto::content_history::content_key_commitment(
            &content_context,
            &key,
        )?,
        content_context,
        protection: ContentProtection {
            root_refs: vec![root_ref],
            blob_refs: vec![],
            backup_refs: vec![backup.backup_id.clone()],
        },
    })
}

/// Runs in two separate OS processes against the private temporary runtime directory.
pub fn agent_first_crypto_worker() -> Result<()> {
    let dir = std::path::PathBuf::from(
        std::env::var_os("COTEST_FIRST_AGENT_DIR").context("missing private runtime directory")?,
    );
    let mut group = arkret::ArkretMlsGroup::restore_from_state_record(&read(&dir.join("mls"))?)?;
    let backup: KeyBackup = read(&dir.join("root-packet"))?;
    match std::env::var("COTEST_FIRST_AGENT_PHASE")?.as_str() {
        "freeze" => {
            let seed: [u8; 32] = read(&dir.join("signing-seed"))?;
            for name in ["first", "denied"] {
                let mut event: Event = read(&dir.join(format!("{name}-intent")))?;
                let plain = arkret_canonical::canonical_json_bytes(&event.payload["content"])?;
                let m = material(&group, &event, &backup)?;
                let reference = m.content_context.root_context.group_state_ref.clone();
                crate::harness::content::seal_message(
                    &mut group, &mut event, &reference, &plain, m,
                )?;
                crate::harness::refresh_typed_event_proof_with_signing_seed(&mut event, seed)?;
                persist(&dir.join(format!("{name}-signed")), &event)?;
            }
        }
        "reopen" => {
            let expected: Event = read(&dir.join("first-signed"))?;
            let held: arkret_wire::CommittedEventView = read(&dir.join("accepted"))?;
            ensure!(held.reducer_input() == Some(&expected));
            let envelope: arkret::EncryptedEnvelope =
                serde_json::from_value(expected.payload["encrypted_content"].clone())?;
            let context = backup.contents[0].root_context.clone().context("context")?;
            let root = group.export_content_root(&context)?;
            let m = EventContentMaterial::from_original(
                &expected,
                &envelope,
                context,
                group.original_content_endpoint(&expected)?,
            )?;
            ensure!(m.protection.backup_refs == [backup.backup_id]);
            let domain = arkret::mls_basic_credential_identity(expected.actual_signer())?;
            let header = envelope.reconstruct_pre_encryption_header(
                arkret::EncryptedPayloadScheme::EpochContentAead,
                expected.scope_ref.clone(),
                expected.kind.as_str(),
                std::str::from_utf8(&domain)?,
                None,
                m,
            )?;
            let restored =
                arkret_crypto::content_history::open_content(&root, &header, &envelope.ciphertext)?;
            persist(
                &dir.join("restored-digest"),
                &arkret_canonical::sha256_digest(restored),
            )?;
        }
        _ => bail!("unknown cold runtime phase"),
    }
    Ok(())
}

async fn worker(dir: &Path, phase: &str) -> Result<()> {
    let result = tokio::process::Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "agent_first_crypto_worker",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("COTEST_FIRST_AGENT_DIR", dir)
        .env("COTEST_FIRST_AGENT_PHASE", phase)
        .output()
        .await?;
    ensure!(
        result.status.success() && String::from_utf8_lossy(&result.stdout).contains("1 passed"),
        "cold {phase} worker failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}

/// Forward all signed headers and exact body bytes using the real Station's TLS client.
/// Once the Station accepts the request, close the caller's socket before sending a receipt.
async fn lose_receipt(builder: reqwest::RequestBuilder) -> Result<()> {
    use reqwest::header::{CONTENT_LENGTH, HOST, HeaderMap, HeaderName, HeaderValue};
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, BufReader};
    let (upstream, request) = builder.build_split();
    let request = request?;
    let target = request.url().clone();
    ensure!(
        matches!(target.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
            && target.query().is_none()
    );
    let method = request.method().clone();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let local = format!("http://{}{}", listener.local_addr()?, target.path());
    let downstream = reqwest::Client::builder()
        .no_proxy()
        .build()?
        .request(method.clone(), local)
        .headers(request.headers().clone())
        .body(
            request
                .body()
                .and_then(reqwest::Body::as_bytes)
                .context("signed JSON")?
                .to_vec(),
        );
    let relay = async move {
        let (stream, _) = listener.accept().await?;
        let mut incoming = BufReader::new(stream);
        let mut line = String::new();
        incoming.read_line(&mut line).await?;
        ensure!(line.trim_end() == format!("{method} {} HTTP/1.1", target.path()));
        let mut headers = HeaderMap::new();
        loop {
            line.clear();
            ensure!(incoming.read_line(&mut line).await? > 0 && line.len() <= 65536);
            if line == "\r\n" {
                break;
            }
            let (name, value) = line.split_once(':').context("HTTP field")?;
            headers.append(
                HeaderName::from_bytes(name.as_bytes())?,
                HeaderValue::from_str(value.trim())?,
            );
        }
        let length = headers
            .get(CONTENT_LENGTH)
            .context("signed content length")?
            .to_str()?
            .parse::<usize>()?;
        ensure!((1..2 * 1024 * 1024).contains(&length));
        headers.remove(HOST);
        let mut bytes = vec![0; length];
        incoming.read_exact(&mut bytes).await?;
        let response = upstream
            .request(method, target)
            .headers(headers)
            .body(bytes)
            .send()
            .await?;
        let status = response.status();
        if status != StatusCode::OK {
            let problem: arkret_wire::Problem = response.json().await?;
            bail!("H declined fault-injection request: {status} {problem:?}");
        }
        // No response bytes are written to the downstream socket.
        drop(incoming);
        anyhow::Ok(())
    };
    let (forwarded, received) = tokio::time::timeout(Duration::from_secs(40), async {
        tokio::join!(relay, downstream.send())
    })
    .await?;
    forwarded?;
    ensure!(received.is_err(), "runtime received an acknowledgement");
    Ok(())
}

pub(super) async fn join_and_publish(
    deployment: coauth_session_evidence::ActualAgentDeployment,
    controller: Member,
    mut agent: AgentRuntimeSession,
    mut group: arkret::ArkretMlsGroup,
    genesis: Event,
    enrollment: Event,
    strand: arkret_wire::StrandId,
    actions: Vec<&str>,
) -> Result<()> {
    let ScopeRef::Sidecar {
        realm_id,
        sidecar_id,
    } = &genesis.scope_ref
    else {
        bail!("expected Sidecar genesis");
    };
    let subject = super::super::pcr_backup::Subject::from(&agent);
    let series = heap_future(|| select_agent_backup_series(&controller, &subject)).await?;
    let own = agent
        .runtime
        .sdk()
        .own_station_result_client()?
        .context("issued Agent own-Station binding")?;
    let query = SidecarBackupPrepareQuery {
        sidecar_id: sidecar_id.clone(),
    };
    ensure!(
        matches!(
            heap_future(|| own.prepare_sidecar_backup(&query)).await,
            Err(arkret_http_client::Error::Api { status: 403, .. })
        ),
        "pending Agent received the root inputs"
    );
    let (state, receiver) = heap_future(|| {
        private_reply::join_agent_and_consume(&controller, &agent, &mut group, &genesis, None, true)
    })
    .await?;
    let (write, claims) =
        heap_future(|| content_direct_evidence::issue(&deployment, &agent, &actions, realm_id))
            .await?;
    for required in [
        "ak.message.create",
        ServiceOperationId::SELF_KEYS_BACKUPS_READ_LIST_V1,
        ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_REPLACE_V1,
    ] {
        ensure!(
            claims.scopes.iter().any(|scope| scope == required),
            "effective Agent session lacks {required}"
        );
    }
    agent.runtime = write;
    heap_future(move || {
        run(
            deployment, controller, agent, receiver, state, series, enrollment, strand,
        )
    })
    .await
}

async fn reject_other_root_inputs(
    runtime: &TestActorClient,
    agent: &AgentRuntimeSession,
    prepared: &SidecarBackupPrepareResponseBody,
    entry: &ContentRootBackupEntry,
    producer: &ContentEndpoint,
    accepted_shape: &KeyBackup,
) -> Result<()> {
    let own = runtime
        .sdk()
        .own_station_result_client()?
        .context("Agent session")?;
    let seal = |inputs: &SidecarBackupPrepareResponseBody, root: &ContentRootBackupEntry| {
        garth::mls::content_roots::agent_sidecar_publication::seal_agent_sidecar_root(
            inputs,
            root,
            producer,
            &agent.controller_account,
            Utc::now(),
            |bytes| Ok(agent.runtime_key.sign(bytes).to_bytes().to_vec()),
        )
    };
    let mut future = prepared.clone();
    future.root_context.epoch += 1;
    let mut wrong_epoch = entry.clone();
    wrong_epoch.root_context = future.root_context.clone();
    wrong_epoch.root_ref = arkret_crypto::content_history::content_root_ref(
        &wrong_epoch.root_base64url,
        &wrong_epoch.root_context,
    )?;
    wrong_epoch.secret_id = format!(
        "root_{}",
        wrong_epoch.root_ref.as_str().trim_start_matches("sha256:")
    );
    let mnemonic = arkret::identity_root::format_bip39_identity_recovery_mnemonic(&[93; 32])?;
    let alternate =
        arkret::identity_root::derive_identity_recovery_key_material_from_bip39(&mnemonic, "", 0)?;
    let key = &alternate.backup_hpke_public_key_multikey;
    let mut wrong_recipient = prepared.clone();
    wrong_recipient.backup_hpke.public_key_multibase = key.clone();
    wrong_recipient.backup_hpke.key_agreement_ref =
        DidUrl::new(format!("did:key:{key}#{key}")).map_err(anyhow::Error::msg)?;
    ensure!(
        wrong_recipient.backup_hpke.key_agreement_ref != prepared.backup_hpke.key_agreement_ref
    );
    for (label, packet) in [
        ("epoch", seal(&future, &wrong_epoch)?),
        ("recipient", seal(&wrong_recipient, entry)?),
    ] {
        ensure!(
            matches!(
                heap_future(|| own.put_own_key_backup(&packet)).await,
                Err(arkret_http_client::Error::Api { status: 403, .. })
            ),
            "H did not refuse wrong {label}"
        );
    }
    let mut mixed = serde_json::to_value(accepted_shape)?;
    let items = mixed["contents"]
        .as_array_mut()
        .context("signed root index")?;
    items.push(serde_json::to_value(
        &seal(&future, &wrong_epoch)?.contents[0],
    )?);
    let response = runtime
        .put(&format!(
            "/_arkret/self/keys/backups/{}",
            accepted_shape.backup_id
        ))
        .header("idempotency-key", format!("mixed-{}", unique_uuid7()))
        .canonical_json(&mixed)?
        .send()
        .await?;
    let status = response.status();
    let error: arkret_wire::Problem = response.json().await?;
    ensure!(
        matches!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY | StatusCode::BAD_REQUEST | StatusCode::FORBIDDEN
        ) && matches!(
            error.error_code(),
            Some(
                arkret_wire::ErrorCode::SchemaViolation
                    | arkret_wire::ErrorCode::CapabilityDenied
                    | arkret_wire::ErrorCode::ParamInvalid
            )
        ),
        "unexpected mixed-root refusal: {status} {}",
        error.problem_type
    );
    println!(
        "[agent-first] H refused signed wrong epoch and wrong HPKE recipient, and rejected a mixed root index"
    );
    Ok(())
}

async fn run(
    mut deployment: coauth_session_evidence::ActualAgentDeployment,
    controller: Member,
    agent: AgentRuntimeSession,
    receiver: arkret::ArkretMlsGroup,
    state: arkret_wire::CommittedEventFullView,
    series: arkret::BackupSeriesId,
    enrollment: Event,
    strand: arkret_wire::StrandId,
) -> Result<()> {
    let scope = state.event.scope_ref.clone();
    let ScopeRef::Sidecar {
        realm_id: realm,
        sidecar_id: sidecar,
    } = &scope
    else {
        bail!("expected Sidecar");
    };
    let runtime = &agent.runtime;
    let own = runtime
        .sdk()
        .own_station_result_client()?
        .context("issued Agent host binding")?;
    let query = SidecarBackupPrepareQuery {
        sidecar_id: sidecar.clone(),
    };
    let basis = heap_future(|| {
        crate::harness::content::root_context(runtime, &receiver, &state.event.event_id)
    })
    .await?;
    let prepared = heap_future(|| own.prepare_sidecar_backup(&query))
        .await
        .context("effective Agent first root preparation")?;
    let prepared = prepared.value()?;
    ensure!(
        prepared.series_id == series
            && prepared.series_sequence == 0
            && prepared.root_context == basis
            && prepared.supersedes_id.is_none()
    );
    let producer = receiver.local_content_endpoint()?;
    let root = receiver.export_content_root(&basis)?;
    let root_ref = arkret_crypto::content_history::content_root_ref(&root, &basis)?;
    let entry = ContentRootBackupEntry {
        item_kind: ContentRootItemKind::ContentEpochRoot,
        secret_id: format!("root_{}", root_ref.as_str().trim_start_matches("sha256:")),
        root_ref,
        root_context: basis,
        root_base64url: root,
    };
    let packet = garth::mls::content_roots::agent_sidecar_publication::seal_agent_sidecar_root(
        prepared,
        &entry,
        &producer,
        &agent.controller_account,
        Utc::now(),
        |b| Ok(agent.runtime_key.sign(b).to_bytes().to_vec()),
    )?;
    heap_future(|| reject_other_root_inputs(runtime, &agent, prepared, &entry, &producer, &packet))
        .await?;
    // Runtime obtains the provision reference exclusively from its own bound prepare response.
    let dir = tempfile::tempdir()?;
    let dirpath = dir.path();
    persist(&dirpath.join("root-packet"), &packet)?;
    persist(&dirpath.join("mls"), &receiver.export_state_record()?)?;
    persist(&dirpath.join("signing-seed"), &agent.runtime_key.to_bytes())?;
    let idempotency = format!(
        "arkret-key-backup-{}",
        arkret_canonical::canonical_sha256(&packet)?.trim_start_matches("sha256:")
    );
    lose_receipt(
        runtime
            .put(&format!("/_arkret/self/keys/backups/{}", packet.backup_id))
            .header("idempotency-key", idempotency)
            .canonical_json(&packet)?,
    )
    .await?;
    let frozen_packet: KeyBackup = read(&dirpath.join("root-packet"))?;
    let contender = garth::mls::content_roots::agent_sidecar_publication::seal_agent_sidecar_root(
        prepared,
        &entry,
        &producer,
        &agent.controller_account,
        Utc::now(),
        |bytes| Ok(agent.runtime_key.sign(bytes).to_bytes().to_vec()),
    )?;
    ensure!(contender.backup_id != frozen_packet.backup_id && contender.series_sequence == 0);
    let (left, right, conflict) = tokio::join!(
        heap_future(|| own.put_own_key_backup(&frozen_packet)),
        heap_future(|| own.put_own_key_backup(&frozen_packet)),
        heap_future(|| own.put_own_key_backup(&contender)),
    );
    ensure!(
        matches!(conflict, Err(arkret_http_client::Error::Api { status: 409, error })
        if error.extensions.get("reason_code").and_then(|v| v.as_str()) == Some(arkret_wire::ReasonCode::SERIES_SEQ_NOT_MONOTONIC)),
        "a different first packet must lose the series race"
    );
    for ack in [left?, right?] {
        ensure!(
            ack.value()?.backup_id == packet.backup_id
                && ack.value()?.ciphertext_digest == packet.ciphertext_digest
        );
    }
    let after = heap_future(|| own.prepare_sidecar_backup(&query)).await?;
    ensure!(
        after.value()?.series_sequence == 1
            && after.value()?.supersedes_id.as_ref() == Some(&packet.backup_id)
    );
    println!(
        "[agent-first] vacant series, one root PUT, lost HTTP receipt, concurrent exact retries; next sequence 1"
    );
    let text = arkret::ContentBlock::text("First private message of this epoch");
    let plaintext = arkret_canonical::canonical_json_bytes(&text)?;
    for (name, body) in [
        ("first", text),
        (
            "denied",
            arkret::ContentBlock::text("must remain uncommitted"),
        ),
    ] {
        let e = agent.author_scoped_event(
            arkret_wire::EventKind::MessageCreate,
            scope.clone(),
            json!({"strand_id":strand,"track_name":"discussion","content":body}),
            vec![],
        )?;
        persist(&dirpath.join(format!("{name}-intent")), &e)?;
    }
    drop(receiver);
    worker(dirpath, "freeze").await?;
    let first: Event = read(&dirpath.join("first-signed"))?;
    let submit = |e: &Event| {
        runtime
            .post("/_arkret/self/events")
            .canonical_json(&arkret_wire::EventAdmissionSubmission::new(e.clone()))
    };
    lose_receipt(submit(&first)?).await?;
    heap_future(|| deployment.station.restart_external_process()).await?;
    let controller_sdk = controller.client.sdk();
    let recovered = heap_future(|| controller_sdk.committed_event_get(&first.event_id)).await?;
    ensure!(recovered.reducer_input() == Some(&first));
    crate::scenarios::human_device_producer_live::ensure_commit_signed_by(
        recovered.commit(),
        &deployment.station,
    )?;
    persist(&dirpath.join("accepted"), &recovered)?;
    worker(dirpath, "reopen").await?;
    ensure!(
        read::<String>(&dirpath.join("restored-digest"))?
            == arkret_canonical::sha256_digest(&plaintext)
    );
    let retry: Event = read(&dirpath.join("first-signed"))?;
    let receipt: AuthoritySubmitResponseBody =
        serde_json::from_value(expect_json(submit(&retry)?, StatusCode::OK).await?)?;
    let AuthoritySubmitResponseBody::Accepted { commit, .. } = receipt else {
        bail!("first-message replay was not accepted")
    };
    ensure!(
        &commit == recovered.commit(),
        "replay produced a different Commit"
    );
    let mut leave = controller.client.author_event(realm.as_str(),"ak.sidecar.member.state",json!({
        "agent_account_id":agent.agent_account,"membership":"leave","predecessor_event_ref":enrollment.event_id
    })).await?;
    leave.scope_ref = scope.clone();
    crate::harness::refresh_typed_event_proof_with_signing_seed(
        &mut leave,
        controller.key.to_bytes(),
    )?;
    let left = crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        &controller.client,
        &controller.account,
        controller.device.as_str(),
        &leave,
    )
    .await?;
    crate::scenarios::human_device_producer_live::ensure_commit_signed_by(
        &left,
        &deployment.station,
    )?;
    ensure!(matches!(
        own.prepare_sidecar_backup(&query).await,
        Err(arkret_http_client::Error::Api { status: 403, .. })
    ));
    ensure!(
        matches!(
            own.put_own_key_backup(&frozen_packet).await,
            Err(arkret_http_client::Error::Api { status: 403, .. })
        ),
        "revoked runtime recovered a backup receipt through replay"
    );
    let denied: Event = read(&dirpath.join("denied-signed"))?;
    let response = submit(&denied)?.send().await?;
    let status = response.status();
    let problem: arkret_wire::Problem = response.json().await?;
    ensure!(
        status == StatusCode::FORBIDDEN
            || (status == StatusCode::CONFLICT
                && problem
                    .extensions
                    .get("reason_code")
                    .and_then(serde_json::Value::as_str)
                    == Some(arkret_wire::ReasonCode::EPOCH_UPDATE_REQUIRED)),
        "unexpected post-revocation refusal: {status} {}",
        problem.problem_type
    );
    crate::harness::expect_api_error(
        controller.client.get(&format!(
            "/_arkret/self/committed-events/{}",
            denied.event_id
        )),
        StatusCode::NOT_FOUND,
        arkret_wire::ErrorCode::NOT_FOUND,
    )
    .await?;
    let database = deployment
        .station
        .owned_database_url()
        .context("H database")?
        .to_owned();
    let stream = serde_json::to_value(arkret_wire::CommitStreamRef::from_scope(&scope, None)?)?;
    let subject = producer.actor_id.to_string();
    let counts = tokio::task::spawn_blocking(move || -> Result<(i64, i64)> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        let row = db.query_one(
            "SELECT (SELECT count(*) FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk
                       WHERE c.stream_ref=$1 AND e.kind='ak.message.create'),
                    (SELECT count(*) FROM key_backup_identities WHERE actor_id=$2 AND series_id=$3)",
            &[&stream, &subject, &series.as_str()],
        )?;
        Ok((row.get(0), row.get(1)))
    })
    .await??;
    ensure!(
        counts == (1, 1),
        "expected one accepted message and one backup: {counts:?}"
    );
    println!(
        "[agent-first] after cold H and client restart original body recovered; replay returned original {}; revoked send {status}; messages={}, backups={}",
        commit.commit_id, counts.0, counts.1
    );
    let principal = controller.client.principal.as_ref().context("controller")?;
    let mnemonic =
        arkret::identity_root::format_bip39_identity_recovery_mnemonic(&principal.root_key_seed)?;
    let fixture = crate::scenarios::_helpers::canonical_api::CanonicalApiFixture::from_owned(
        deployment.station,
        deployment.controller,
        deployment.http,
        deployment.endpoints,
        deployment.oidc_client_id,
    );
    let sibling = heap_future(|| fixture.pair_sibling()).await?;
    ensure!(sibling.device_id != controller.client.device_id);
    let subject = ActorId::account(agent.agent_account.clone());
    let verifier = agent.runtime_key.verifying_key();
    let opened = heap_future(|| {
        recover_on_new_device(
            &sibling,
            &recovered,
            &mnemonic,
            producer,
            None,
            Some((&subject, &agent.custody_authorization)),
            &verifier,
        )
    })
    .await?;
    ensure!(
        opened == vec![plaintext],
        "authorized new device could not recover first Agent message"
    );
    println!(
        "[agent-first] authorized new device unlocked Agent-signed packet and recovered the exact original plaintext"
    );
    Ok(())
}
