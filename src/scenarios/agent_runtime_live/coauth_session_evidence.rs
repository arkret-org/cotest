//! Normal product onboarding against owned Coauth and HTTPS Station processes.

use std::io::{Seek, SeekFrom, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use cotest_test_support::provisioning::{DeploymentEndpoints, MockEmailInbox};
use serde_json::json;

use crate::harness::{ArkretServer, CanonicalClientRequest, ClientSession, reserve_port};
use crate::scenarios::_helpers::coauth_bootstrap::{
    JOINT_TRUST_DOMAIN, prepare_coauth_with_db_required,
};
use crate::scenarios::_helpers::external_binary::{SpawnedExternalProcess, workspace_root};

pub async fn run_agent_session_grant_replay_production()
-> Result<crate::conformance::SuiteExecutionResult> {
    run_agent_issuer_boundary(false).await
}

pub async fn run_agent_longevity_session_boundary() -> Result<()> {
    run_agent_issuer_boundary(true).await?;
    println!(
        "[agent-longevity-session] real_issuer_conjunction=1 canonical_case_completion_claim=0"
    );
    Ok(())
}

pub(super) struct ActualAgentDeployment {
    pub station: ArkretServer,
    pub coauth: crate::scenarios::_helpers::coauth_bootstrap::SpawnedCoauth,
    pub controller: crate::harness::TestActorClient,
    pub account: arkret_wire::AccountId,
    _email: SpawnedExternalProcess,
}

pub(super) async fn actual_agent_deployment(label: &str) -> Result<ActualAgentDeployment> {
    let mut port = reserve_port()?;
    let email_base = format!("http://127.0.0.1:{}", port.port());
    port.release();
    let child = Command::new("node")
        .arg(
            workspace_root()
                .context("workspace root is unavailable")?
                .join("cotest/e2e/mocks/mock-email.mjs"),
        )
        .env("MOCK_EMAIL_PORT", port.port().to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("start the owned email delivery inbox")?;
    let _email =
        SpawnedExternalProcess::from_child(email_base.clone(), "node".into(), child, vec![port]);
    let prepared = prepare_coauth_with_db_required()?;
    let pending_station = reserve_port()?;
    let pending_endpoint = format!("https://127.0.0.1:{}", pending_station.port());
    let secret = "cotest-real-agent-session";
    let registration = "cotest-real-agent-webvh";
    let mut coauth = prepared
        .spawn_for_station(&pending_endpoint, secret, registration, None)
        .await?;
    // Obtain the generated issuer's actual public key before founding a Station.
    // The temporary endpoint serves no business; all business remains gated on trust.
    let cold_http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let discovery: serde_json::Value = cold_http
        .get(format!(
            "{}/.well-known/openid-configuration",
            coauth.base_url()
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let jwks: serde_json::Value = cold_http
        .get(
            discovery["jwks_uri"]
                .as_str()
                .context("Coauth omitted jwks_uri")?,
        )
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let key = jwks["keys"]
        .as_array()
        .context("Coauth keyset is missing")?
        .iter()
        .find(|key| key["kid"] == "coauth-account-authority-v1")
        .context("Coauth issuer key is missing")?;
    ensure!(
        key["kty"] == "OKP" && key["crv"] == "Ed25519",
        "Coauth issuer key is not Ed25519"
    );
    use base64::Engine as _;
    let key_bytes: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(key["x"].as_str().context("Coauth issuer key omitted x")?)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Coauth issuer public key is not 32 bytes"))?;
    let public_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&key_bytes);
    let introspection = format!(
        "{}/_coauth/internal/session-grants/introspect",
        coauth.base_url()
    );
    let station = ArkretServer::spawn_with_env(
        label,
        &[
            ("COLAND_SEED_DEMO_DATA", "0"),
            ("COLAND_TRUST_DOMAIN", JOINT_TRUST_DOMAIN),
            ("COLAND_ACCOUNT_AUTHORITY_URL", coauth.base_url()),
            ("COLAND_ACCOUNT_AUTHORITY_PUBLIC_KEY_MULTIBASE", &public_key),
            ("COLAND_SESSION_GRANT_INTROSPECTION_URL", &introspection),
            ("COLAND_INTERNAL_AUTHORITY_SHARED_SECRET", secret),
            ("COLAND_ACCOUNT_AUTHORITY_TRUST_DOMAIN", JOINT_TRUST_DOMAIN),
            ("COLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER", registration),
        ],
    )
    .await?;
    coauth.bind_station(&station, secret, registration).await?;
    let client_id = "01GFWR28C4KNE04WG3HKXB7C9R";
    coauth.config.as_file_mut().seek(SeekFrom::Start(0))?;
    let mut config: serde_yaml_ng::Value = serde_yaml_ng::from_reader(coauth.config.as_file_mut())?;
    config["clients"] = serde_yaml_ng::to_value(json!([{
        "client_id": client_id,
        "client_auth_method": "none",
        "redirect_uris": ["http://127.0.0.1/auth/callback"]
    }]))?;
    config["account"] = serde_yaml_ng::to_value(json!({
        "password_registration_enabled": true,
        "password_registration_contact_required": true,
        "registration_email_delivery_bypass_allowed": false
    }))?;
    config["email"] = serde_yaml_ng::to_value(json!({
        "from": "Cotest <noreply@example.test>",
        "provider": {
            "type": "http_webhook",
            "url": format!("{email_base}/mock/email/verification/send"),
            "headers": {"X-Cotest-Mock": "mock-email"}
        }
    }))?;
    let file = coauth.config.as_file_mut();
    file.seek(SeekFrom::Start(0))?;
    file.set_len(0)?;
    serde_yaml_ng::to_writer(&mut *file, &config)?;
    file.flush()?;
    let synced = Command::new(&coauth.server.bin_path)
        .args(["config", "sync", "--config"])
        .arg(coauth.config.path())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .context("synchronize the normal OAuth client deployment configuration")?;
    ensure!(synced.success(), "Coauth config sync failed: {synced}");
    coauth.restart_same_config().await?;
    let mut builder = reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(45));
    if let Some(ca) = station.tls_ca_path() {
        builder =
            builder.add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(ca)?)?);
    }
    let http = builder.build()?;
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let readiness = http
            .get(format!("{}/_coauth/self/viewer", coauth.base_url()))
            .send()
            .await?;
        if readiness.status() == reqwest::StatusCode::UNAUTHORIZED
            || readiness.status().is_success()
        {
            break;
        }
        ensure!(
            std::time::Instant::now() < deadline,
            "Coauth owning Station trust did not become ready: {}",
            readiness.status()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let endpoints = DeploymentEndpoints {
        coauth_base_url: coauth.base_url().to_owned(),
        coland_base_url: station.base_url().to_string(),
        mock_email: Some(MockEmailInbox {
            base_url: email_base,
        }),
    };
    let controller = station
        .canonical_client(CanonicalClientRequest {
            http: &http,
            endpoints: &endpoints,
            oidc_client_id: client_id,
            handle: "alice",
            password: "1amTester!",
            device_id: super::CONTROLLER_DEVICE,
            display_name: "Live Agent controller",
        })
        .await
        .context("normal Coauth controller onboarding")?;
    ensure!(
        matches!(controller.session(), ClientSession::Canonical { .. }),
        "controller has no normal issuer grant"
    );
    let principal = controller
        .principal
        .as_ref()
        .context("canonical founding custody was not restored")?;
    let response = controller
        .get("/_arkret/self/account/viewer")
        .send()
        .await?;
    ensure!(
        response.status().is_success(),
        "normal Station grant validation failed: {}",
        response.status()
    );
    let viewer: arkret_models_collaboration::account_operations::AccountView =
        response.json().await?;
    ensure!(
        viewer.principal_id == principal.core_id,
        "viewer names another controller"
    );
    let account =
        arkret_wire::AccountId::new(principal.core_id.clone(), station.service_id().clone());
    Ok(ActualAgentDeployment {
        station,
        coauth,
        controller,
        account,
        _email,
    })
}

async fn run_agent_issuer_boundary(
    longevity: bool,
) -> Result<crate::conformance::SuiteExecutionResult> {
    use base64::Engine as _;
    let deployment = actual_agent_deployment("agent-real-coauth").await?;
    let station = &deployment.station;
    let coauth = &deployment.coauth;
    let controller = &deployment.controller;
    let account = &deployment.account;
    let mut agent = super::AgentRuntimeSession::establish_observed(
        &station,
        super::AgentSessionIssuer::Coauth {
            base: coauth.base_url(),
            database_url: &coauth.pg.connect_url,
        },
        &controller,
        &account,
        "real-coauth-agent",
        super::requested_scope(&super::runtime_operations())?,
        None,
    )
    .await
    .context("real Coauth Agent pairing and session issuance")?;
    let response = agent
        .runtime
        .get("/_arkret/self/device_messages")
        .send()
        .await?;
    ensure!(
        response.status().is_success(),
        "real Agent session was refused: {}",
        response.status()
    );
    if longevity {
        super::longevity_evidence::renew_with_real_issuer(
            &station,
            &coauth,
            &controller,
            &mut agent,
        )
        .await?;
    }
    lifecycle_refusals(&station, &coauth, &controller, &agent).await?;
    let issue_url = format!("{}/_arkret/gate/account/session-grants", coauth.base_url());
    let header = arkret_signatures::dpop::build_dpop_proof(
        &arkret_signatures::dpop::DpopProofRequest::new("POST", &issue_url),
        &agent.runtime_key,
    )?
    .proof_jwt;
    let (protected, _) = header.rsplit_once('.').context("DPoP is not compact JWS")?;
    let corrupted = format!(
        "{protected}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 64])
    );
    expect_issue_refusal(
        &station,
        &coauth.pg.connect_url,
        &issue_url,
        agent
            .issuer_request
            .as_ref()
            .context("actual accepted issuer request")?,
        &agent.runtime_key,
        Some(&corrupted),
        arkret_wire::ErrorCode::SIGNATURE_INVALID,
        Some(arkret_wire::ReasonCode::PROOF_INVALID),
    )
    .await
    .context("bad HTTP DPoP signature")?;
    println!(
        "[agent-session] normal_product_onboarding=1 real_issuer_grant=1 exact_replay=1 actual_station_consumer=1 automatic_pair_reconciliation=1"
    );
    Ok(crate::conformance::SuiteExecutionResult {
        entrypoint: "ak.suite.agent.vectors.v1",
        fixture: "agent-vectors-fixture.json",
        cases: vec![crate::conformance::CaseExecutionResult {
            case_id: "agent_session_grant_replay".to_owned(),
            assertions: 4,
        }],
    })
}

pub(super) async fn wait_for_issuer_authorization(
    database_url: &str,
    event: &arkret_wire::EventId,
) -> Result<()> {
    let url = database_url.to_owned();
    let event = event.to_string();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let url = url.clone();
        let event = event.clone();
        let state: Option<String> = tokio::task::spawn_blocking(move || -> Result<_> {
            let mut db = postgres::Client::connect(&url, postgres::NoTls)?;
            Ok(db.query_opt("SELECT coland_fanout_state FROM agent_key_authorizations WHERE authorized_event_id=$1", &[&event])?.map(|row| row.get(0)))
        }).await??;
        if state.as_deref() == Some("delivered") {
            return Ok(());
        }
        ensure!(
            std::time::Instant::now() < deadline,
            "real Coauth did not automatically reconcile accepted Agent authorization: {state:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn issue_runtime_session(
    station: &crate::harness::ArkretServer,
    base: &str,
    database_url: &str,
    agent: &arkret_wire::DidCoreId,
    authorization: &arkret_wire::EventId,
    method: &arkret_wire::DidUrl,
    key: &ed25519_dalek::SigningKey,
    operations: &[&str],
) -> Result<(
    String,
    arkret_models_collaboration::session_grants::AgentSessionGrantRequest,
)> {
    issue_runtime_session_with_scope(
        station,
        base,
        database_url,
        agent,
        authorization,
        method,
        key,
        operations,
        arkret_models_collaboration::session_grants::SessionGrantAgentScopeRequest {
            realm_ids: Vec::new(),
            strand_ids: Vec::new(),
            track_names: Vec::new(),
        },
    )
    .await
}

pub(super) async fn issue_runtime_session_with_scope(
    station: &crate::harness::ArkretServer,
    base: &str,
    database_url: &str,
    agent: &arkret_wire::DidCoreId,
    authorization: &arkret_wire::EventId,
    method: &arkret_wire::DidUrl,
    key: &ed25519_dalek::SigningKey,
    operations: &[&str],
    scope_request: arkret_models_collaboration::session_grants::SessionGrantAgentScopeRequest,
) -> Result<(
    String,
    arkret_models_collaboration::session_grants::AgentSessionGrantRequest,
)> {
    use arkret_models_collaboration::session_grants::{
        SessionGrantDpopBindingProof, SessionGrantOutcome, SessionGrantRequestBody,
        UnsignedAgentSessionGrantProof, UnsignedAgentSessionGrantRequest,
    };
    use arkret_signatures::dpop::{DpopProofRequest, build_dpop_proof};
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    let url = format!("{base}/_arkret/gate/account/session-grants");
    let binding = build_dpop_proof(&DpopProofRequest::new("POST", &url), key)?;
    let issued_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let unsigned = UnsignedAgentSessionGrantRequest::new(
        agent.clone(),
        operations
            .iter()
            .map(|operation| (*operation).to_owned())
            .collect(),
        authorization.clone(),
        scope_request,
        None,
        SessionGrantDpopBindingProof {
            proof_jwt: binding.proof_jwt,
        },
        UnsignedAgentSessionGrantProof {
            challenge: random_session_challenge()?,
            audience_id: station.service_id().clone(),
            issued_at,
            expires_at: issued_at + chrono::Duration::minutes(5),
            verification_method: method.clone(),
        },
    )?;
    let mut request = unsigned.attach_signature(
        arkret_wire::NonEmptyString::new("pending").map_err(anyhow::Error::msg)?,
    )?;
    let SessionGrantRequestBody::Agent(body) = &mut request else {
        unreachable!()
    };
    body.proof.signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(key.sign(&body.proof.canonical_signing_bytes()?).to_bytes());
    request.validate()?;
    let bytes = arkret_canonical::canonical_json_bytes(&request)?;
    let http_proof = build_dpop_proof(&DpopProofRequest::new("POST", &url), key)?;
    let response = station
        .http()
        .post(&url)
        .header("DPoP", &http_proof.proof_jwt)
        .header("Content-Type", "application/json")
        .body(bytes.clone())
        .send()
        .await?;
    let status = response.status();
    let first = response.bytes().await?;
    ensure!(
        status.is_success(),
        "real Agent issue failed: {status} {}",
        String::from_utf8_lossy(&first)
    );
    let replay_proof = build_dpop_proof(&DpopProofRequest::new("POST", &url), key)?;
    let response = station
        .http()
        .post(&url)
        .header("DPoP", replay_proof.proof_jwt)
        .header("Content-Type", "application/json")
        .body(bytes.clone())
        .send()
        .await?;
    ensure!(
        response.status().is_success(),
        "real Agent exact issue replay failed: {}",
        response.status()
    );
    ensure!(
        response.bytes().await? == first,
        "real issuer replay changed the recorded outcome"
    );
    let outcome: SessionGrantOutcome = serde_json::from_slice(&first)?;
    ensure!(
        outcome.device_id.is_none(),
        "Agent grant incorrectly binds a Human Device"
    );
    let SessionGrantRequestBody::Agent(original) = request else {
        unreachable!()
    };
    expect_issue_refusal(
        station,
        database_url,
        &url,
        &original,
        key,
        Some(&http_proof.proof_jwt),
        arkret_wire::ErrorCode::SIGNATURE_INVALID,
        Some(arkret_wire::ReasonCode::PROOF_INVALID),
    )
    .await?;
    for (negative, expected_code, expected_reason) in [
        (
            "conflicting_intent",
            arkret_wire::ErrorCode::DUPLICATE_CONFLICT,
            None,
        ),
        (
            "bad_signature",
            arkret_wire::ErrorCode::SIGNATURE_INVALID,
            Some(arkret_wire::ReasonCode::PROOF_INVALID),
        ),
        (
            "wrong_audience",
            arkret_wire::ErrorCode::SIGNATURE_INVALID,
            Some(arkret_wire::ReasonCode::PROOF_INVALID),
        ),
        (
            "wrong_principal",
            arkret_wire::ErrorCode::FAILED_PRECONDITION,
            Some(arkret_wire::ReasonCode::VERIFICATION_METHOD_PRINCIPAL_MISMATCH),
        ),
    ] {
        let mut body = original.clone();
        if negative != "conflicting_intent" {
            body.proof.challenge = random_session_challenge()?;
        }
        body.dpop_binding_proof.proof_jwt =
            build_dpop_proof(&DpopProofRequest::new("POST", &url), key)?.proof_jwt;
        match negative {
            "conflicting_intent" => body
                .requested_scope
                .push(arkret_wire::ServiceOperationId::SELF_ACCOUNT_READ_VIEWER_V1.to_owned()),
            "wrong_audience" => body.proof.audience_id = agent.clone(),
            "wrong_principal" => {
                body.proof.verification_method =
                    arkret_wire::DidUrl::new(format!("{}#wrong-runtime", station.service_did()))
                        .map_err(anyhow::Error::msg)?
            }
            _ => {}
        }
        body.proof.request_canonical_digest = body.canonical_request_digest()?;
        body.proof.signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(key.sign(&body.proof.canonical_signing_bytes()?).to_bytes());
        if negative == "bad_signature" {
            body.proof.signature =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 64]);
        }
        expect_issue_refusal(
            station,
            database_url,
            &url,
            &body,
            key,
            None,
            expected_code,
            expected_reason,
        )
        .await
        .with_context(|| format!("real Agent {negative} rejection"))?;
    }
    Ok((outcome.session_grant, original))
}

pub(super) async fn grant_ledger(database_url: &str) -> Result<serde_json::Value> {
    let url = database_url.to_owned();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut db = postgres::Client::connect(&url, postgres::NoTls)?;
        Ok(db.query_one("SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.id),'[]'::jsonb) FROM oauth_session_grants r", &[])?.get(0))
    }).await?
}

async fn lifecycle_refusals(
    station: &ArkretServer,
    coauth: &crate::scenarios::_helpers::coauth_bootstrap::SpawnedCoauth,
    controller: &crate::harness::TestActorClient,
    agent: &super::AgentRuntimeSession,
) -> Result<()> {
    use arkret_models_collaboration::agent_operations::{
        AgentDeactivateRequestBody, AgentPauseRequestBody, AgentResumeRequestBody,
    };
    use arkret_wire::{ActorId, ErrorCode, EventAdmissionSubmission, ReasonCode, ScopeRef};

    use crate::harness::expect_json;
    let principal = controller
        .principal
        .as_ref()
        .context("accepted controller custody")?;
    let method = arkret_wire::DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
        .map_err(anyhow::Error::msg)?;
    let request = agent
        .issuer_request
        .as_ref()
        .context("actual accepted issuer request")?;
    let issue_url = format!("{}/_arkret/gate/account/session-grants", coauth.base_url());
    let paused = super::sign(
        arkret_event_draft::build_agent_pause_intent(
            ActorId::account(agent.agent_account.clone()),
            ActorId::account(agent.controller_account.clone()),
            ScopeRef::Realm {
                realm_id: agent.agent_pcr.clone(),
            },
            agent.delegation.clone(),
            None,
            chrono::Utc::now(),
        )?
        .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
        &method,
        principal.device_signing_key.to_bytes(),
    )?;
    let pause_started = std::time::Instant::now();
    expect_json(
        controller
            .post(&format!(
                "/_arkret/self/agents/{}/pause",
                agent.agent_account.principal_id
            ))
            .json(&AgentPauseRequestBody {
                reason: None,
                lifecycle_event: EventAdmissionSubmission::new(paused),
            }),
        reqwest::StatusCode::OK,
    )
    .await?;
    expect_issue_refusal(
        station,
        &coauth.pg.connect_url,
        &issue_url,
        &fresh_session_request(request, &issue_url, &agent.runtime_key)?,
        &agent.runtime_key,
        None,
        ErrorCode::FAILED_PRECONDITION,
        Some(ReasonCode::AGENT_PAUSED),
    )
    .await
    .context("paused Agent fresh issuance")?;
    wait_runtime_rejected(
        &agent.runtime,
        "paused actual issuer credential",
        pause_started,
    )
    .await?;
    let resumed = super::sign(
        arkret_event_draft::build_agent_resume_intent(
            ActorId::account(agent.agent_account.clone()),
            ActorId::account(agent.controller_account.clone()),
            ScopeRef::Realm {
                realm_id: agent.agent_pcr.clone(),
            },
            agent.delegation.clone(),
            chrono::Utc::now(),
        )?
        .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
        &method,
        principal.device_signing_key.to_bytes(),
    )?;
    expect_json(
        controller
            .post(&format!(
                "/_arkret/self/agents/{}/resume",
                agent.agent_account.principal_id
            ))
            .json(&AgentResumeRequestBody {
                lifecycle_event: EventAdmissionSubmission::new(resumed),
            }),
        reqwest::StatusCode::OK,
    )
    .await?;
    let (resumed_grant, _) = issue_runtime_session(
        station,
        coauth.base_url(),
        &coauth.pg.connect_url,
        &agent.agent_account.principal_id,
        &agent.key_authorization,
        &agent.verification_method,
        &agent.runtime_key,
        &super::runtime_operations(),
    )
    .await
    .context("resumed Agent actual fresh issuer credential")?;
    let resumed_runtime = station.client_with_agent_runtime_grant(
        agent.agent_did.as_str(),
        "actual-resumed-lifecycle",
        resumed_grant,
        agent.runtime_key.clone(),
    )?;
    ensure!(
        resumed_runtime
            .get("/_arkret/self/device_messages")
            .send()
            .await?
            .status()
            .is_success()
    );
    set_accountability(
        controller,
        agent,
        arkret_models_collaboration::governance::accountability::AccountabilityGrantStatus::Revoked,
    )
    .await?;
    expect_issue_refusal(
        station,
        &coauth.pg.connect_url,
        &issue_url,
        &fresh_session_request(request, &issue_url, &agent.runtime_key)?,
        &agent.runtime_key,
        None,
        ErrorCode::FAILED_PRECONDITION,
        Some(ReasonCode::ACCOUNTABILITY_GRANT_MISSING),
    )
    .await
    .context("revoked accountability refuses fresh issuance")?;
    set_accountability(
        controller,
        agent,
        arkret_models_collaboration::governance::accountability::AccountabilityGrantStatus::Active,
    )
    .await?;
    let deactivated = super::sign(
        arkret_event_draft::build_agent_deactivate_intent(
            ActorId::account(agent.agent_account.clone()),
            ActorId::account(agent.controller_account.clone()),
            ScopeRef::Realm {
                realm_id: agent.agent_pcr.clone(),
            },
            agent.delegation.clone(),
            arkret_event_draft::AgentLifecycleState::Active,
            None,
            chrono::Utc::now(),
        )?
        .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
        &method,
        principal.device_signing_key.to_bytes(),
    )?;
    let deactivate_started = std::time::Instant::now();
    expect_json(
        controller
            .post(&format!(
                "/_arkret/self/agents/{}/deactivate",
                agent.agent_account.principal_id
            ))
            .json(&AgentDeactivateRequestBody {
                reason: None,
                lifecycle_event: EventAdmissionSubmission::new(deactivated),
            }),
        reqwest::StatusCode::OK,
    )
    .await?;
    expect_issue_refusal(
        station,
        &coauth.pg.connect_url,
        &issue_url,
        &fresh_session_request(request, &issue_url, &agent.runtime_key)?,
        &agent.runtime_key,
        None,
        ErrorCode::FAILED_PRECONDITION,
        Some(ReasonCode::AGENT_DEACTIVATED),
    )
    .await
    .context("deactivated Agent fresh issuance")?;
    wait_runtime_rejected(
        &resumed_runtime,
        "deactivated actual resumed issuer credential",
        deactivate_started,
    )
    .await?;
    println!(
        "[agent-lifecycle-issuer] actual_paused_fresh_issue_refused=1 actual_issued_session_refused_within_60s=1 actual_resume_fresh_grant_consumer=1 actual_terminal_fresh_issue_refused=1 actual_resumed_grant_terminal_refused_within_60s=1"
    );
    Ok(())
}

pub(super) async fn wait_runtime_rejected(
    runtime: &crate::harness::TestActorClient,
    label: &str,
    start: std::time::Instant,
) -> Result<()> {
    loop {
        let response = runtime.get("/_arkret/self/device_messages").send().await?;
        if matches!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
        ) {
            ensure!(
                start.elapsed() <= Duration::from_secs(60),
                "{label} exceeded the independent freshness window"
            );
            return Ok(());
        }
        ensure!(
            response.status().is_success() && start.elapsed() < Duration::from_secs(60),
            "{label} did not fail closed"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn random_session_challenge() -> Result<String> {
    use base64::Engine as _;
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow::anyhow!("OS Agent challenge generation failed: {error}"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

pub(super) fn fresh_session_request(
    original: &arkret_models_collaboration::session_grants::AgentSessionGrantRequest,
    url: &str,
    key: &ed25519_dalek::SigningKey,
) -> Result<arkret_models_collaboration::session_grants::AgentSessionGrantRequest> {
    use arkret_signatures::dpop::{DpopProofRequest, build_dpop_proof};
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    let mut body = original.clone();
    body.dpop_binding_proof.proof_jwt =
        build_dpop_proof(&DpopProofRequest::new("POST", url), key)?.proof_jwt;
    body.proof.challenge = random_session_challenge()?;
    body.proof.issued_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    body.proof.expires_at = body.proof.issued_at + chrono::Duration::minutes(5);
    body.proof.request_canonical_digest = body.canonical_request_digest()?;
    body.proof.signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(key.sign(&body.proof.canonical_signing_bytes()?).to_bytes());
    body.validate()?;
    Ok(body)
}

async fn set_accountability(
    controller: &crate::harness::TestActorClient,
    agent: &super::AgentRuntimeSession,
    status: arkret_models_collaboration::governance::accountability::AccountabilityGrantStatus,
) -> Result<()> {
    set_accountability_for_agent(
        controller,
        &agent.agent_account.principal_id,
        &agent.controller_account,
        status,
    )
    .await
}

pub(super) async fn set_accountability_for_agent(
    controller: &crate::harness::TestActorClient,
    agent_id: &arkret_wire::DidCoreId,
    controller_account: &arkret_wire::AccountId,
    status: arkret_models_collaboration::governance::accountability::AccountabilityGrantStatus,
) -> Result<()> {
    set_accountability_with_source(controller, agent_id, controller_account, status).await?;
    Ok(())
}

pub(super) async fn set_accountability_with_source(
    controller: &crate::harness::TestActorClient,
    agent_id: &arkret_wire::DidCoreId,
    controller_account: &arkret_wire::AccountId,
    status: arkret_models_collaboration::governance::accountability::AccountabilityGrantStatus,
) -> Result<arkret_wire::CommittedEventView> {
    use arkret_models_collaboration::governance::accountability::{
        AccountabilityGrantPayload, AccountabilityScope, AccountabilityScopeKind,
    };
    use arkret_wire::PayloadSigner as _;
    let principal = controller
        .principal
        .as_ref()
        .context("accepted controller custody")?;
    let method = arkret_wire::DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
        .map_err(anyhow::Error::msg)?;
    let created_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut grant = AccountabilityGrantPayload::new(
        principal.core_id.clone(),
        agent_id.clone(),
        AccountabilityScope::Single(AccountabilityScopeKind::AgentOperator),
        created_at - chrono::Duration::seconds(1),
        None,
        arkret_wire::PayloadProof {
            kind: "detached_jws".to_owned(),
            verification_method: method.clone(),
            payload_digest: arkret_wire::Hash::new(arkret_canonical::sha256_digest(b""))
                .map_err(anyhow::Error::msg)?,
            created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: String::new(),
        },
    );
    grant.grant_status = status;
    grant.proof.payload_digest = grant.payload_digest()?;
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        principal.device_signing_key.to_bytes(),
        principal.did.clone(),
        method.clone(),
    );
    grant.proof.jws = signer
        .sign_payload(&grant.canonical_proof_binding_bytes()?)?
        .jws;
    let event = super::sign(
        arkret_event_draft::accountability_grant_intent(
            &grant,
            arkret_wire::ScopeRef::Realm {
                realm_id: principal.pcr_realm_id.clone(),
            },
            arkret_wire::ActorId::account(controller_account.clone()),
            created_at,
            None,
        )?
        .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
        &method,
        principal.device_signing_key.to_bytes(),
    )?;
    let outcome: arkret_wire::AuthoritySubmitOutcome = serde_json::from_value(
        crate::harness::expect_json(
            controller
                .post("/_arkret/self/events")
                .header("Content-Type", "application/json")
                .body(arkret_canonical::canonical_json_bytes(
                    &arkret_wire::EventAdmissionSubmission::new(event.clone()),
                )?),
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        matches!(
            outcome,
            arkret_wire::AuthoritySubmitOutcome::Accepted { .. }
        ),
        "controller accountability Event was refused"
    );
    let source = controller
        .sdk()
        .committed_event_get(&event.event_id)
        .await?;
    ensure!(source.reducer_input() == Some(&event));
    source.commit().validate_content_address()?;
    Ok(source)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn expect_issue_refusal(
    station: &crate::harness::ArkretServer,
    database_url: &str,
    url: &str,
    body: &arkret_models_collaboration::session_grants::AgentSessionGrantRequest,
    key: &ed25519_dalek::SigningKey,
    retained_http_proof: Option<&str>,
    code: &str,
    reason: Option<&str>,
) -> Result<()> {
    use arkret_signatures::dpop::{DpopProofRequest, build_dpop_proof};
    let before = grant_ledger(database_url).await?;
    let fresh = build_dpop_proof(&DpopProofRequest::new("POST", url), key)?;
    let response = station
        .http()
        .post(url)
        .header("DPoP", retained_http_proof.unwrap_or(&fresh.proof_jwt))
        .header("Content-Type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(body)?)
        .send()
        .await?;
    let status = response.status();
    ensure!(!status.is_success(), "negative Agent issuance was accepted");
    let problem: arkret_wire::Problem = response.json().await?;
    ensure!(
        problem.status == status.as_u16(),
        "Problem status differs from its HTTP status"
    );
    ensure!(
        problem.code() == code,
        "Agent issue returned wrong error: {problem:?}"
    );
    if let Some(reason) = reason {
        ensure!(
            problem
                .extensions
                .get("reason_code")
                .and_then(serde_json::Value::as_str)
                == Some(reason),
            "Agent issue omitted its formal reason {reason}: {problem:?}"
        );
    }
    ensure!(
        grant_ledger(database_url).await? == before,
        "refused Agent request changed the issuer grant ledger"
    );
    println!(
        "[agent-session] refused_code={} reason={reason:?} status={} full_grant_ledger_unchanged=1",
        problem.code(),
        problem.status
    );
    Ok(())
}
