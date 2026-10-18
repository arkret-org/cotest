//! Terminal gates consume the same actually joined and granted MLS endpoint.

use super::*;
use crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores;

pub(super) struct Materials<'a> {
    pub station: &'a ArkretServer,
    pub controller: &'a TestActorClient,
    pub agent: &'a AgentRuntimeSession,
    pub issuer: &'a MockCoauthIntrospectionServer,
    pub database_url: &'a str,
    pub realm: &'a RealmId,
    pub strand: &'a str,
    pub group: &'a mut arkret::ArkretMlsGroup,
    pub claim: &'a KeyPackagesClaimRequestBody,
    pub consume: &'a arkret_models_crypto::KeyPackagesConsumeRequestBody,
    pub state_ref: &'a EventId,
}

fn claim_request(
    material: &Materials<'_>,
    target: &arkret_wire::Hash,
) -> Result<KeyPackagesClaimRequestBody> {
    let mut request = material.claim.clone();
    request.claim_request_id = arkret_wire::Base64UrlString::new(
        URL_SAFE_NO_PAD.encode(&arkret_canonical::sha256_bytes(unique_uuid7().as_bytes())[..16]),
    )
    .map_err(anyhow::Error::msg)?;
    request.target_keypackage_ref = Some(serde_json::from_value(serde_json::to_value(target)?)?);
    let arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Device { signed_at, .. } =
        &mut request.requester_authorization
    else {
        bail!("terminal claim requires the actual controller device");
    };
    *signed_at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let bytes = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
        &request.unsigned_request(),
        &request.service_binding,
        &request.requester_authorization,
    )?;
    let arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Device { signature, .. } =
        &mut request.requester_authorization
    else {
        unreachable!()
    };
    let key = &material
        .controller
        .principal
        .as_ref()
        .context("accepted controller")?
        .device_signing_key;
    signature.sig =
        arkret_wire::Base64UrlString::new(URL_SAFE_NO_PAD.encode(key.sign(&bytes).to_bytes()))
            .map_err(anyhow::Error::msg)?;
    Ok(request)
}

async fn current_key(material: &Materials<'_>) -> Result<arkret::SignerKeysQueryOutcome> {
    let request = arkret::SignerKeysQueryRequestBody {
        request_id: RequestId::new(format!("ak:request:{}", unique_uuid7()))?,
        realm_id: material.realm.clone(),
        recipient_account_id: material.agent.controller_account.clone(),
        queries: vec![arkret::SignerKeyQuerySelector::CurrentAdmission {
            sender: arkret::CurrentSignerKeyQuerySender::Agent {
                actor: ActorId::account(material.agent.agent_account.clone()),
                verification_method: material.agent.verification_method.clone(),
            },
        }],
    };
    let outcome = material
        .controller
        .sdk()
        .signer_keys_query(&request)
        .await?;
    outcome.validate_for_request(&request)?;
    Ok(outcome)
}

async fn refusal<T: serde::Serialize>(
    runtime: &TestActorClient,
    path: &str,
    body: &T,
) -> Result<()> {
    let response = runtime
        .post(path)
        .header("Content-Type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(body)?)
        .send()
        .await?;
    ensure!(
        matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ),
        "terminal request reached a non-authorization result: {}",
        response.status()
    );
    let _: arkret_wire::Problem = response.json().await?;
    Ok(())
}

async fn relay_positions(database_url: &str) -> Result<serde_json::Value> {
    let url = database_url.to_owned();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut database = postgres::Client::connect(&url, postgres::NoTls)?;
        Ok(database.query_one("SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.realm_id), '[]'::jsonb) FROM signal_relay_position r", &[])?.get(0))
    }).await?
}

pub(super) async fn exercise(mut material: Materials<'_>) -> Result<()> {
    material
        .agent
        .transition(
            material.controller,
            &material.agent.controller_account,
            AgentTransition::Resume,
        )
        .await?;
    let authorization = material
        .controller
        .sdk()
        .committed_event_get(&material.agent.key_authorization)
        .await?;
    let payload = AgentKeyAuthorizePayload::try_from(
        authorization
            .reducer_input()
            .context("original key authorization")?,
    )?;
    let grant = crate::scenarios::bridge_contracts::session_grant::mock_session_grant_jwt(
        material.agent.agent_account.principal_id.as_str(),
        material.agent.verification_method.as_str(),
        material.station.service_id().as_str(),
    );
    material.issuer.bind_agent_runtime_grant(
        &grant,
        &material.agent.key_authorization,
        &payload,
        &material.agent.runtime_key.verifying_key(),
    )?;
    let runtime = material.station.client_with_agent_runtime_grant(
        material.agent.agent_did.as_str(),
        "terminal-runtime",
        grant,
        material.agent.runtime_key.clone(),
    )?;
    ensure!(
        runtime
            .get("/_arkret/self/device_messages")
            .send()
            .await?
            .status()
            == StatusCode::OK
    );
    let keys = current_key(&material).await?;
    ensure!(matches!(
        keys.results.as_slice(),
        [arkret::SignerKeyQueryOutcome::CurrentResolved { .. }]
    ));
    let direct =
        direct_evidence::found(material.controller, material.agent, material.station).await?;
    let mut joined_direct = Box::pin(direct_mls_evidence::join(
        material.station,
        material.controller,
        material.agent,
        &runtime,
        direct,
    ))
    .await?;
    let direct_presence = Box::pin(presence_evidence::positive_direct(
        &material,
        &runtime,
        &mut joined_direct,
    ))
    .await?;
    let presence = presence_evidence::unmapped_ordinary(&mut material, &runtime).await?;
    let first = material.group.identity().key_package_record()?;
    let second = material.group.identity().key_package_record()?;
    let private = tempfile::NamedTempFile::new()?;
    std::fs::write(
        private.path(),
        material.group.identity().export_private_state()?,
    )?;
    private.as_file().sync_all()?;
    let identity = ArkretMlsIdentity::restore_from_private_state(
        ActorId::account(material.agent.agent_account.clone()),
        MlsEndpointIdentity::agent_runtime(
            material.agent.agent_account.principal_id.clone(),
            material.agent.verification_method.clone(),
            material.agent.key_authorization.clone(),
        )?,
        &std::fs::read(private.path())?,
    )?;
    let upload = identity.signed_key_packages_upload_request(
        &[first.clone(), second.clone()],
        material.agent.verification_method.as_str(),
    )?;
    let uploaded: KeyPackagesUploadOutcome = serde_json::from_value(
        expect_json(
            runtime
                .post("/_arkret/self/keys/keypackages/upload")
                .header("Content-Type", "application/json")
                .body(arkret_canonical::canonical_json_bytes(&upload)?),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        uploaded.accepted == 2
            && uploaded
                .key_package_refs
                .contains(&second.keypackage_ref.to_string())
    );
    let control_claim = claim_request(&material, &first.keypackage_ref)?;
    let control: arkret_models_crypto::KeyPackagesClaimOutcome = serde_json::from_value(
        expect_json(
            material
                .controller
                .post("/_arkret/self/keys/keypackages/claim")
                .header("idempotency-key", control_claim.claim_request_id.as_str())
                .header("Content-Type", "application/json")
                .body(arkret_canonical::canonical_json_bytes(&control_claim)?),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        control.claims.len() == 1
            && control.claims[0].actor_id == ActorId::account(material.agent.agent_account.clone())
    );
    let header = arkret::EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        "application/vnd.arkret.message+json",
        arkret::EncryptedPayloadScheme::MlsRfc9420,
        ScopeRef::Realm {
            realm_id: material.realm.clone(),
        },
        arkret_wire::EventKind::MessageCreate.as_str(),
        material.group.epoch(),
        material.state_ref.clone(),
        material.group.local_content_sender_domain()?,
        arkret::EventContentRoutingContext::None,
    )?;
    let encrypted = arkret::MessageCrypto::encrypt(
        material.group,
        "terminal-frozen-reply",
        header,
        &arkret_canonical::canonical_json_bytes(&arkret::ContentBlock::text(
            "terminal must refuse this new reply",
        ))?,
    )?;
    let event = material.agent.author_scoped_event(arkret_wire::EventKind::MessageCreate,
        ScopeRef::Realm { realm_id: material.realm.clone() },
        json!({"strand_id":material.strand,"track_name":"discussion","encrypted_content":encrypted.payload.to_envelope()?}), Vec::new())?;
    let durable = tempfile::NamedTempFile::new()?;
    std::fs::write(
        durable.path(),
        serde_json::to_vec(&material.group.export_state_record()?)?,
    )?;
    durable.as_file().sync_all()?;
    let terminal_claim = claim_request(&material, &second.keypackage_ref)?;
    let pending = pairing_expiry_evidence::replacement_material_with_ttl(
        material.station,
        material.controller,
        &material.agent.controller_account,
        material.agent,
        120000,
    )
    .await?;
    let token = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({
        "r":pending.bootstrap.pairing_request_id,"c":pending.bootstrap.pairing_code,
    }))?);
    ensure!(pending.bootstrap.pairing_expires_at > Utc::now() + chrono::Duration::seconds(90));
    let terminal_started = Instant::now();
    repairing_evidence::lifecycle(material.controller, material.agent, "deactivate").await?;
    let deadline = terminal_started + Duration::from_secs(60);
    loop {
        let result = runtime.get("/_arkret/self/device_messages").send().await?;
        if matches!(
            result.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            break;
        }
        ensure!(result.status() == StatusCode::OK && Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let before = acceptance_rows_with_agent_stores(material.database_url, true).await?;
    let relay_before = relay_positions(material.database_url).await?;
    ensure!(
        Utc::now() < presence.expires_at && Utc::now() < direct_presence.expires_at,
        "terminal Signal controls expired before the authorization gate was exercised"
    );
    refusal(&runtime, "/_arkret/self/signal", &presence).await?;
    refusal(&runtime, "/_arkret/self/signal", &direct_presence).await?;
    let response = material
        .station
        .http()
        .post(material.station.url("/_arkret/open/agent-pairing/resolve"))
        .header("Content-Type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(
            &arkret_models_collaboration::agent_operations::AgentPairingResolveRequestBody {
                pairing_token: token,
            },
        )?)
        .send()
        .await?;
    ensure!(
        response.status() == StatusCode::NOT_FOUND
            && Utc::now() < pending.bootstrap.pairing_expires_at,
        "terminal open handle remained resolvable or the test waited for TTL expiry"
    );
    let response = material
        .controller
        .post(&format!(
            "/_arkret/self/agents/{}/renew-pairing",
            material.agent.agent_account.principal_id
        ))
        .header("Content-Type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(
            &arkret_models_collaboration::agent_operations::AgentRenewPairingRequestBody {
                pairing_ttl_ms: Some(120000),
            },
        )?)
        .send()
        .await?;
    ensure!(response.status().is_client_error());
    let problem: arkret_wire::Problem = response.json().await?;
    ensure!(
        problem
            .extensions
            .get("reason_code")
            .and_then(serde_json::Value::as_str)
            == Some(arkret_wire::ReasonCode::AGENT_DEACTIVATED)
    );
    let response = material
        .controller
        .post("/_arkret/gate/account/agent-key-pair")
        .header(
            "Idempotency-Key",
            pending.body.authorize_event.event.event_id.as_str(),
        )
        .header("Content-Type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(&pending.body)?)
        .send()
        .await?;
    ensure!(response.status().is_client_error());
    let problem: arkret_wire::Problem = response.json().await?;
    ensure!(
        problem
            .extensions
            .get("reason_code")
            .and_then(serde_json::Value::as_str)
            == Some(arkret_wire::ReasonCode::AGENT_DEACTIVATED)
    );
    refusal(&runtime, "/_arkret/self/keys/keypackages/upload", &upload).await?;
    refusal(
        &runtime,
        "/_arkret/self/keys/keypackages/consume",
        material.consume,
    )
    .await?;
    refusal(
        &runtime,
        "/_arkret/self/events",
        &arkret_wire::EventAdmissionSubmission::new(event),
    )
    .await?;
    let keys = current_key(&material).await?;
    ensure!(
        matches!(
            keys.results.as_slice(),
            [arkret::SignerKeyQueryOutcome::Unavailable { .. }]
        ),
        "terminal Agent still supplied a current signer"
    );
    let response = material
        .controller
        .post("/_arkret/self/keys/keypackages/claim")
        .header("idempotency-key", terminal_claim.claim_request_id.as_str())
        .header("Content-Type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(&terminal_claim)?)
        .send()
        .await?;
    ensure!(
        response.status().as_u16() == arkret_wire::ErrorCode::ClaimFailed.http_status(),
        "terminal claim did not use the opaque claim_failed status: {}",
        response.status()
    );
    let problem: arkret_wire::Problem = response.json().await?;
    ensure!(
        problem.code() == arkret_wire::ErrorCode::CLAIM_FAILED
            && problem.status == arkret_wire::ErrorCode::ClaimFailed.http_status()
            && problem.extensions.is_empty(),
        "terminal claim disclosed its private target failure: {problem:?}"
    );
    ensure!(
        acceptance_rows_with_agent_stores(material.database_url, true).await? == before,
        "terminal endpoint refusals changed full accepted state"
    );
    ensure!(
        relay_positions(material.database_url).await? == relay_before,
        "terminal Signal advanced its accepting relay position"
    );
    ensure!(
        Instant::now() <= deadline,
        "terminal endpoint matrix exceeded sixty seconds from transition submission"
    );
    println!(
        "[agent-terminal] active_signer_control=1 active_upload_control=1 actual_controller_claim_control=1 durable_runtime_identity=1 live_pairing_handle_control=1 terminal_open_handle_before_ttl=1 terminal_renew=1 terminal_pending_pair=1 terminal_session=1 terminal_upload=1 terminal_consume=1 terminal_new_granted_event=1 terminal_signer_unavailable=1 terminal_controller_claim=1 full_footprint_unchanged=1 canonical_case_completion_claim=0"
    );
    Ok(())
}
