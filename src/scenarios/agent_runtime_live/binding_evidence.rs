//! Real pending runtime binding, platform persistence and controller approval.

use std::path::PathBuf;

use arkret_models_collaboration::agent_operations::{
    AgentRenewPairingOutcome, AgentRenewPairingRequestBody, AgentView,
};
use arkret_models_collaboration::agent_scope::{
    AgentKeyPairRequestBody, AgentRuntimeApprovalRequestBody,
};
use serde_json::Value;

use super::*;
use crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores;

struct NativeBinding {
    worker: PathBuf,
    home: tempfile::TempDir,
    bootstrap_file: PathBuf,
    service: String,
}

impl NativeBinding {
    fn new(bootstrap: &AgentPairingBootstrap, controller: &AccountId) -> Result<Self> {
        let worker = PathBuf::from(
            std::env::var("COTEST_SAVFOX_BINDING_WORKER")
                .context("real Savfox native binding worker required")?,
        );
        ensure!(worker.is_file(), "native binding worker is absent");
        let home = tempfile::tempdir()?;
        let bootstrap_file = home.path().join("owned-bootstrap.json");
        std::fs::write(
            &bootstrap_file,
            arkret_canonical::canonical_json_bytes(
                &json!({"bootstrap":bootstrap,"controller":controller}),
            )?,
        )?;
        Ok(Self {
            worker,
            home,
            bootstrap_file,
            service: format!("cotest-agent-binding-{}", unique_uuid7()),
        })
    }

    fn invoke(&self, operation: &str) -> Result<Value> {
        let result_file = self.home.path().join("owned-worker-result.json");
        let child = std::process::Command::new(&self.worker)
            .args([operation])
            .arg(self.home.path())
            .arg(&self.bootstrap_file)
            .arg(&result_file)
            .arg(&self.service)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        let pid = child.id();
        let result = child.wait_with_output()?;
        ensure!(
            result.status.success(),
            "native {operation} failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        println!("[agent-binding] native_operation={operation} process_id={pid} exit_code=0");
        Ok(serde_json::from_slice(&std::fs::read(result_file)?)?)
    }

    fn request(&self, operation: &str) -> Result<AgentRuntimeApprovalRequestBody> {
        Ok(serde_json::from_value(self.invoke(operation)?)?)
    }
}

impl Drop for NativeBinding {
    fn drop(&mut self) {
        let _ = std::process::Command::new(&self.worker)
            .arg("cleanup")
            .arg(self.home.path())
            .arg(&self.bootstrap_file)
            .arg(self.home.path().join("owned-cleanup.json"))
            .arg(&self.service)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

async fn renew(
    station: &ArkretServer,
    controller: &TestActorClient,
    agent: &AgentRuntimeSession,
) -> Result<AgentPairingBootstrap> {
    let renewed: AgentRenewPairingOutcome = serde_json::from_value(
        expect_json(
            controller
                .post(&format!(
                    "/_arkret/self/agents/{}/renew-pairing",
                    agent.agent_account.principal_id
                ))
                .json(&AgentRenewPairingRequestBody {
                    pairing_ttl_ms: Some(120_000),
                }),
            StatusCode::OK,
        )
        .await?,
    )?;
    let token = URL_SAFE_NO_PAD.encode(serde_json::to_vec(
        &json!({"r":renewed.pairing_request_id,"c":renewed.pairing_code}),
    )?);
    Ok(serde_json::from_value(expect_json(station.http().post(station.url("/_arkret/open/agent-pairing/resolve"))
        .json(&arkret_models_collaboration::agent_operations::AgentPairingResolveRequestBody { pairing_token: token }), StatusCode::OK).await?)?)
}

async fn candidate(
    station: &ArkretServer,
    body: &AgentRuntimeApprovalRequestBody,
) -> Result<AgentRuntimeApprovalOutcome> {
    Ok(serde_json::from_value(
        expect_json(
            station
                .http()
                .post(station.url("/_arkret/open/agent-pairing/runtime-key-requests"))
                .json(body),
            StatusCode::OK,
        )
        .await?,
    )?)
}

async fn notifications(
    controller: &TestActorClient,
    after: Option<&str>,
    approval: &OpaqueLocalId,
) -> Result<(String, String)> {
    let request = controller.get("/_arkret/self/account/subscribe");
    let request = if let Some(cursor) = after {
        request.query(&[("after", cursor), ("catchup", "true")])
    } else {
        request
    };
    let delta = crate::harness::expect_account_subscribe_delta(request, StatusCode::OK).await?;
    let frame: arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame =
        serde_json::from_value(delta.clone())?;
    let items = frame
        .notifications
        .context("actual notification delta")?
        .items;
    let found: Vec<_> = items
        .iter()
        .filter(|item| {
            serde_json::to_value(item)
                .ok()
                .is_some_and(|v| v["data"]["approval_request_id"] == approval.as_str())
        })
        .collect();
    ensure!(
        found.len() == 1,
        "delta lacks exactly one actual pending approval upsert"
    );
    let item = serde_json::to_value(found[0])?;
    ensure!(
        item["action"] == "upsert",
        "same binding emitted a terminal notification"
    );
    for key in [
        "pairing_code",
        "proof_of_possession",
        "runtime_attestation",
        "public_key",
        "requested_scope_disclosure",
        "authorize_event",
    ] {
        ensure!(
            !serde_json::to_string(&item)?.contains(&format!("\"{key}\"")),
            "notification disclosed {key}"
        );
    }
    Ok((
        frame.cursor.context("actual account cursor")?,
        item["id"]
            .as_str()
            .context("notification identity")?
            .to_owned(),
    ))
}

async fn refused_request(
    station: &ArkretServer,
    database: &str,
    value: Value,
    label: &str,
    schema: bool,
) -> Result<()> {
    let before = acceptance_rows_with_agent_stores(database, true).await?;
    let response = station
        .http()
        .post(station.url("/_arkret/open/agent-pairing/runtime-key-requests"))
        .header("Content-Type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(&value)?)
        .send()
        .await?;
    ensure!(
        response.status().is_client_error(),
        "{label} accepted a bad possession request"
    );
    let problem: arkret_wire::Problem = response.json().await?;
    ensure!(
        (problem.code() == arkret_wire::ErrorCode::SCHEMA_VIOLATION) == schema,
        "{label} stopped at the wrong gate: {problem:?}"
    );
    if label == "different_stable_binding" {
        ensure!(
            problem.status == 409
                && problem
                    .extensions
                    .get("reason_code")
                    .and_then(Value::as_str)
                    == Some("agent_runtime_request_conflict"),
            "different binding classification: {problem:?}"
        );
    }
    ensure!(
        acceptance_rows_with_agent_stores(database, true).await? == before,
        "{label} changed complete accepted/Agent state"
    );
    println!(
        "[agent-binding] refused={label} code={} status={} full_business_footprint_unchanged=1",
        problem.code(),
        problem.status
    );
    Ok(())
}

fn author(
    controller: &TestActorClient,
    account: &AccountId,
    agent: &AgentRuntimeSession,
    payload: &AgentKeyAuthorizePayload,
) -> Result<Event> {
    let principal = controller.principal.as_ref().context("controller device")?;
    let method = DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
        .map_err(anyhow::Error::msg)?;
    sign(
        arkret_event_draft::build_agent_key_authorize_intent(
            payload,
            ScopeRef::Realm {
                realm_id: agent.agent_pcr.clone(),
            },
            ActorId::account(agent.agent_account.clone()),
            ActorId::account(account.clone()),
            agent.delegation.clone(),
            Utc::now(),
        )?
        .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
        &method,
        principal.device_signing_key.to_bytes(),
    )
}

async fn approval_body(
    station: &ArkretServer,
    controller: &TestActorClient,
    account: &AccountId,
    agent: &AgentRuntimeSession,
    bootstrap: &AgentPairingBootstrap,
    runtime: &AgentRuntimeApprovalRequestBody,
    approval: &AgentRuntimeApprovalOutcome,
) -> Result<AgentKeyPairRequestBody> {
    let accepted = controller
        .sdk()
        .committed_event_get(&agent.key_authorization)
        .await?;
    let mut payload = AgentKeyAuthorizePayload::try_from(
        accepted.reducer_input().context("original accepted key")?,
    )?;
    payload.supersedes = vec![
        arkret_models_collaboration::events_payloads::agent::AgentKeySupersession {
            key_id: payload.key_id.clone(),
            authorized_event_ref: agent.key_authorization.clone(),
        },
    ];
    payload.key_id =
        NonEmptyString::new(runtime.verification_method.as_str()).map_err(anyhow::Error::msg)?;
    payload.verification_method = runtime.verification_method.clone();
    payload.public_key = runtime.public_key.clone();
    payload.runtime_attestation = runtime.runtime_attestation.clone();
    payload.issued_at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let binding = arkret_models_collaboration::agent_scope::agent_runtime_key_binding_digest(
        &runtime.agent_id,
        &runtime.pairing_request_id,
        &runtime.verification_method,
        &runtime.public_key,
        runtime.runtime_attestation.as_ref(),
    )?;
    ensure!(
        binding == runtime.proof_of_possession.runtime_key_binding_digest,
        "actual runtime binding differs from source bytes"
    );
    let digest = agent_key_pairing_request_binding_digest(
        ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1,
        &account.principal_id,
        &runtime.agent_id,
        &bootstrap.pairing_request_id,
        &approval.approval_request_id,
        bootstrap.pairing_expires_at,
        station.service_id(),
        &binding,
    )?;
    payload.approval_evidence = AgentKeyApprovalEvidence {
        kind: AgentKeyApprovalEvidenceKind::PairingRequest,
        evidence_ref: None,
        request_canonical_digest: Some(digest),
        pairing_request_id: Some(bootstrap.pairing_request_id.clone()),
        approved_by: Some(account.principal_id.clone()),
    };
    let principal = controller.principal.as_ref().context("controller")?;
    let method = DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
        .map_err(anyhow::Error::msg)?;
    Ok(AgentKeyPairRequestBody {
        pairing_request_id: bootstrap.pairing_request_id.clone(),
        approval_request_id: approval.approval_request_id.clone(),
        requested_scope_disclosure: requested_scope_disclosure(
            account,
            (method, principal.device_signing_key.to_bytes()),
            &runtime.agent_id,
            station.service_id(),
            &bootstrap.pairing_request_id,
            &payload.agent_key_scope,
        )?,
        authorize_event: arkret_wire::EventAdmissionSubmission::new(author(
            controller, account, agent, &payload,
        )?),
    })
}

async fn refused_approval(
    controller: &TestActorClient,
    database: &str,
    body: &AgentKeyPairRequestBody,
    label: &str,
    needle: &str,
) -> Result<()> {
    let before = acceptance_rows_with_agent_stores(database, true).await?;
    let response = controller
        .post("/_arkret/gate/account/agent-key-pair")
        .header(
            "Idempotency-Key",
            body.authorize_event.event.event_id.as_str(),
        )
        .header("Content-Type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(body)?)
        .send()
        .await?;
    ensure!(
        response.status().is_client_error(),
        "{label} approved a stale binding"
    );
    let problem: arkret_wire::Problem = response.json().await?;
    ensure!(
        problem.code() != arkret_wire::ErrorCode::SCHEMA_VIOLATION
            && problem.detail.contains(needle),
        "{label} missed approval binding admission: {problem:?}"
    );
    ensure!(
        acceptance_rows_with_agent_stores(database, true).await? == before,
        "{label} changed complete state"
    );
    println!(
        "[agent-binding] refused={label} code={} status={} full_business_footprint_unchanged=1",
        problem.code(),
        problem.status
    );
    Ok(())
}

pub async fn run_agent_runtime_binding_admission()
-> Result<crate::conformance::SuiteExecutionResult> {
    let name = "agent-runtime-binding-production";
    let database = database(name)?.context("real PostgreSQL required")?;
    let issuer = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let group = TestServerGroup::try_multi_external_with_node_envs(
        name,
        &[station_env(&database.connect_url, &issuer)],
    )
    .await?
    .context("actual Station required")?;
    let station = group.server(0);
    let (controller, account) =
        standard_client(station, &issuer, "binding-controller", CONTROLLER_DEVICE).await?;
    let mut agent =
        AgentRuntimeSession::establish(station, &issuer, &controller, &account, "binding-agent")
            .await?;
    let bootstrap = renew(station, &controller, &agent).await?;
    let native = NativeBinding::new(&bootstrap, &account)?;
    let first = native.request("create")?;
    let approval = candidate(station, &first).await?;
    let (cursor, notification) =
        notifications(&controller, None, &approval.approval_request_id).await?;
    let frozen = approval_body(
        station,
        &controller,
        &account,
        &agent,
        &bootstrap,
        &first,
        &approval,
    )
    .await?;
    let restart = native.request("load")?;
    let recreated = native.request("recreate")?;
    ensure!(
        first.public_key == restart.public_key
            && restart.public_key == recreated.public_key
            && first.proof_of_possession.runtime_key_binding_digest
                == recreated.proof_of_possession.runtime_key_binding_digest,
        "platform runtime key changed across process restart/channel recreation"
    );
    ensure!(
        first.proof_of_possession.created_at != recreated.proof_of_possession.created_at,
        "native retry did not refresh the possession proof"
    );
    let retry = candidate(station, &recreated).await?;
    ensure!(
        retry.approval_request_id == approval.approval_request_id,
        "stable proof refresh replaced approval identity"
    );
    let (_, retry_notification) =
        notifications(&controller, Some(&cursor), &retry.approval_request_id).await?;
    ensure!(
        notification == retry_notification,
        "stable proof refresh replaced notification identity"
    );
    let view: AgentView = serde_json::from_value(
        expect_json(
            controller.get(&format!(
                "/_arkret/self/agents/{}",
                agent.agent_account.principal_id
            )),
            StatusCode::OK,
        )
        .await?,
    )?;
    let pending = serde_json::to_value(
        view.key_state
            .context("actual authenticated key state")?
            .pending_runtime_key_request
            .context("authenticated pending projection")?,
    )?;
    for key in [
        "pairing_code",
        "requested_scope_disclosure",
        "authorize_event",
    ] {
        ensure!(
            pending.get(key).is_none(),
            "controller projection exposed {key}"
        );
    }
    ensure!(
        first.public_key.kid.as_str() == first.verification_method.as_str()
            && first.proof_of_possession.verification_method == first.verification_method,
        "runtime method aliases are not byte-identical"
    );
    ensure!(
        first
            .proof_of_possession
            .created_at
            .timestamp_subsec_nanos()
            % 1_000_000
            == 0
            && first
                .proof_of_possession
                .expires_at
                .timestamp_subsec_nanos()
                % 1_000_000
                == 0
            && first.proof_of_possession.expires_at
                <= first.proof_of_possession.created_at + chrono::Duration::seconds(300),
        "producer did not floor/bound actual proof instants"
    );
    let method = first.verification_method.clone();
    let mut other_seed = [0u8; 32];
    getrandom::fill(&mut other_seed).map_err(|e| anyhow::anyhow!("runtime entropy: {e}"))?;
    let other_key = SigningKey::from_bytes(&other_seed);
    let different =
        arkret_signatures::agent::RuntimeKeyRequestBuilder::new_with_verification_method(
            &other_key,
            bootstrap.clone(),
            &method,
        )
        .build_approval_request()?
        .body;
    refused_request(
        station,
        &database.connect_url,
        serde_json::to_value(different)?,
        "different_stable_binding",
        false,
    )
    .await?;
    for (label, field, replacement) in [
        (
            "wrong_secret",
            "/pairing_code",
            Value::String("00000000".into()),
        ),
        (
            "wrong_proof_handle",
            "/proof_of_possession/challenge",
            Value::String(format!("agent_pairing_request:{}", unique_uuid7())),
        ),
        (
            "wrong_service",
            "/proof_of_possession/audience_id",
            serde_json::to_value(&agent.agent_account.principal_id)?,
        ),
        (
            "wrong_binding_digest",
            "/proof_of_possession/runtime_key_binding_digest",
            Value::String(format!("sha256:{}", "0".repeat(64))),
        ),
        (
            "wrong_raw_signature",
            "/proof_of_possession/signature",
            Value::String(URL_SAFE_NO_PAD.encode([0u8; 64])),
        ),
        (
            "wrong_kid",
            "/public_key/kid",
            Value::String(format!("{}#wrong-runtime", agent.agent_did)),
        ),
    ] {
        let mut bad = serde_json::to_value(&recreated)?;
        if label == "wrong_secret" && bad["pairing_code"] == replacement {
            bad["pairing_code"] = Value::String("11111111".into());
        } else {
            *bad.pointer_mut(field).context("SDK negative field")? = replacement;
        }
        refused_request(station, &database.connect_url, bad, label, false).await?;
    }
    let expiry =
        arkret_canonical::format_timestamp_canonical(recreated.proof_of_possession.expires_at);
    for (label, wire) in [
        ("microsecond_wire", expiry.replace('Z', "997Z")),
        ("offset_wire", expiry.replace('Z', "+00:00")),
    ] {
        let mut bad = serde_json::to_value(&recreated)?;
        bad["proof_of_possession"]["expires_at"] = Value::String(wire);
        refused_request(station, &database.connect_url, bad, label, true).await?;
    }
    let mut extra = serde_json::to_value(&recreated)?;
    extra["proof_of_possession"]["extra_field"] = json!(true);
    refused_request(
        station,
        &database.connect_url,
        extra,
        "closed_possession_shape",
        true,
    )
    .await?;
    let mut long = serde_json::to_value(&recreated)?;
    long["proof_of_possession"]["expires_at"] =
        json!(arkret_canonical::format_timestamp_canonical(
            recreated.proof_of_possession.created_at + chrono::Duration::seconds(301)
        ));
    refused_request(
        station,
        &database.connect_url,
        long,
        "possession_window_over_300_seconds",
        false,
    )
    .await?;
    let mut wrong_approval = frozen.clone();
    wrong_approval.approval_request_id =
        OpaqueLocalId::new(format!("agent_runtime_approval:{}", unique_uuid7(),))
            .map_err(anyhow::Error::msg)?;
    refused_approval(
        &controller,
        &database.connect_url,
        &wrong_approval,
        "different_controller_approval_instance",
        "candidate",
    )
    .await?;
    let mut bad = frozen.clone();
    let mut payload = AgentKeyAuthorizePayload::try_from(&bad.authorize_event.event)?;
    payload.approval_evidence.request_canonical_digest = Some(
        arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64))).map_err(anyhow::Error::msg)?,
    );
    bad.authorize_event = arkret_wire::EventAdmissionSubmission::new(author(
        &controller,
        &account,
        &agent,
        &payload,
    )?);
    refused_approval(
        &controller,
        &database.connect_url,
        &bad,
        "persisted_request_binding_recomputed",
        "request_canonical_digest",
    )
    .await?;
    ensure!(
        native.invoke("lose_key")?["bound_key_missing_stopped_request"] == true,
        "lost-key runtime continued"
    );
    let renewed = renew(station, &controller, &agent).await?;
    ensure!(
        renewed.pairing_request_id != bootstrap.pairing_request_id,
        "lost-key recovery reused old handle"
    );
    refused_approval(
        &controller,
        &database.connect_url,
        &frozen,
        "stale_controller_approval",
        "pairing",
    )
    .await?;
    drop(native);
    let new_native = NativeBinding::new(&renewed, &account)?;
    let request = new_native.request("create")?;
    let new_approval = candidate(station, &request).await?;
    let body = approval_body(
        station,
        &controller,
        &account,
        &agent,
        &renewed,
        &request,
        &new_approval,
    )
    .await?;
    let refreshed = new_native.request("load")?;
    let refresh = candidate(station, &refreshed).await?;
    ensure!(
        refresh.approval_request_id == new_approval.approval_request_id,
        "proof refresh invalidated frozen controller approval"
    );
    let paired: AgentKeyPairOutcome = serde_json::from_value(
        expect_json(
            controller
                .post("/_arkret/gate/account/agent-key-pair")
                .header(
                    "Idempotency-Key",
                    body.authorize_event.event.event_id.as_str(),
                )
                .json(&body),
            StatusCode::OK,
        )
        .await?,
    )?;
    wait_for_activation(
        station,
        &renewed,
        &renewed.pairing_code,
        &agent.agent_account.principal_id,
        &paired.authorize_event_ref,
    )
    .await?;
    ensure!(
        paired.authorize_event_ref == body.authorize_event.event.event_id,
        "frozen approval authorized another Event"
    );
    // Exercise nonempty optional attestation bytes on the same real consumer.
    agent.key_authorization = paired.authorize_event_ref.clone();
    let attested_bootstrap = renew(station, &controller, &agent).await?;
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|error| anyhow::anyhow!("attested runtime entropy: {error}"))?;
    let key = SigningKey::from_bytes(&seed);
    let method = attested_bootstrap
        .validated_runtime_identity()
        .map_err(anyhow::Error::msg)?
        .verification_method
        .clone();
    let attested = arkret_signatures::agent::RuntimeKeyRequestBuilder::new_with_verification_method(
        &key, attested_bootstrap, &method)
        .runtime_attestation(arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayloadRuntimeAttestation {
            kind: arkret_models_collaboration::events_payloads::agent::AgentKeyRuntimeAttestationKind::SelfAsserted,
            software: Some(format!("cotest-private-attestation-{}", unique_uuid7())), version: None, attestation_ref: None,
        }).build_approval_request()?.body;
    ensure!(
        attested.runtime_attestation.is_some(),
        "attestation privacy input was empty"
    );
    let attested_approval = candidate(station, &attested).await?;
    notifications(&controller, None, &attested_approval.approval_request_id).await?;
    println!(
        "[agent-binding] actual_native_persistence=1 stable_notification_upsert=1 same_binding_approval_preserved=1 lost_key_stop_and_renew=1 actual_final_binding_admission=1"
    );
    Ok(crate::conformance::SuiteExecutionResult {
        entrypoint: "ak.suite.agent.vectors.v1",
        fixture: "agent-vectors-fixture.json",
        cases: vec![crate::conformance::CaseExecutionResult {
            case_id: "agent_runtime_key_binding".to_owned(),
            assertions: 13,
        }],
    })
}
