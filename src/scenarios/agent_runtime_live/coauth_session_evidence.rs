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

pub struct ActualAgentDeployment {
    pub(crate) http: reqwest::Client,
    pub(crate) oidc_client_id: String,
    pub station: ArkretServer,
    pub(crate) coauth: crate::scenarios::_helpers::coauth_bootstrap::SpawnedCoauth,
    pub controller: crate::harness::TestActorClient,
    pub account: arkret_wire::AccountId,
    pub(crate) endpoints: DeploymentEndpoints,
    pub(crate) webvh_registration_bearer: String,
    _email: SpawnedExternalProcess,
}

pub fn actual_agent_deployment(
    label: &str,
) -> impl std::future::Future<Output = Result<ActualAgentDeployment>> + '_ {
    crate::harness::heap_future(|| actual_agent_deployment_configured(label))
}

async fn actual_agent_deployment_configured(label: &str) -> Result<ActualAgentDeployment> {
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
    let station = ArkretServer::spawn_with_env(
        label,
        &[
            ("COLAND_SEED_DEMO_DATA", "0"),
            ("COLAND_TRUST_DOMAIN", JOINT_TRUST_DOMAIN),
            ("COLAND_ACCOUNT_AUTHORITY_URL", coauth.base_url()),
            (
                "COLAND_SESSION_GRANT_INTROSPECTION_URL",
                &format!(
                    "{}/_coauth/internal/session-grants/introspect",
                    coauth.base_url().trim_end_matches('/')
                ),
            ),
            (
                "COLAND_AUTH_SESSION_LOGOUT_URL",
                &format!(
                    "{}/_coauth/internal/auth-sessions/logout",
                    coauth.base_url().trim_end_matches('/')
                ),
            ),
            ("COLAND_ACCOUNT_AUTHORITY_PUBLIC_KEY_MULTIBASE", &public_key),
            ("COLAND_INTERNAL_AUTHORITY_SHARED_SECRET", secret),
            ("COLAND_ACCOUNT_AUTHORITY_TRUST_DOMAIN", JOINT_TRUST_DOMAIN),
            ("COLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER", registration),
        ],
    )
    .await?;
    coauth.bind_station(&station, secret, registration).await?;
    let client_id = "01GFWR28C4KNE04WG3HKXB7C9R";
    coauth.config.as_file_mut().seek(SeekFrom::Start(0))?;
    let mut config: serde_json::Value = serde_saphyr::from_reader(coauth.config.as_file_mut())?;
    config["clients"] = serde_json::to_value(json!([{
        "client_id": client_id,
        "client_auth_method": "none",
        "redirect_uris": ["http://127.0.0.1/auth/callback"]
    }]))?;
    config["account"] = serde_json::to_value(json!({
        "password_registration_enabled": true,
        "password_registration_contact_required": true,
        "registration_email_delivery_bypass_allowed": false
    }))?;
    config["email"] = serde_json::to_value(json!({
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
    serde_saphyr::to_io_writer(&mut *file, &config)?;
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
        // Match the harness's explicit run PKI without platform-verifier
        // signature differences; hostname and chain verification stay enabled.
        builder = builder
            .tls_backend_rustls()
            .tls_certs_only(reqwest::Certificate::from_pem_bundle(&std::fs::read(ca)?)?);
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
    wait_for_onboarding_activity(&coauth.pg.connect_url).await?;
    let issuer_binding =
        crate::scenarios::_helpers::native_issuer_binding::capture(&coauth, &station).await?;
    cotest_test_support::operation_observation::record_issuer_binding_observation(issuer_binding);
    Ok(ActualAgentDeployment {
        http,
        oidc_client_id: client_id.to_owned(),
        station,
        coauth,
        controller,
        account,
        endpoints,
        webvh_registration_bearer: registration.to_owned(),
        _email,
    })
}

pub async fn additional_controller(
    deployment: &ActualAgentDeployment,
    handle: &str,
    device_id: &str,
) -> Result<crate::harness::TestActorClient> {
    let mut builder = reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(45));
    if let Some(ca) = deployment.station.tls_ca_path() {
        builder = builder
            .tls_backend_rustls()
            .tls_certs_only(reqwest::Certificate::from_pem_bundle(&std::fs::read(ca)?)?);
    }
    let http = builder.build()?;
    let controller = deployment
        .station
        .canonical_client(CanonicalClientRequest {
            http: &http,
            endpoints: &deployment.endpoints,
            oidc_client_id: "01GFWR28C4KNE04WG3HKXB7C9R",
            handle,
            password: "1amTester!",
            device_id,
            display_name: "Second actual Sidecar controller",
        })
        .await?;
    let principal = controller
        .principal
        .as_ref()
        .context("normal second controller custody")?;
    ensure!(principal.core_id != deployment.account.principal_id);
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    loop {
        let url = deployment.coauth.pg.connect_url.clone();
        let id = principal.core_id.to_string();
        let (sessions, durable): (i64, i64) = tokio::task::spawn_blocking(move || -> Result<_> {
            let mut db = postgres::Client::connect(&url, postgres::NoTls)?;
            let row = db.query_one(
                "SELECT count(*), count(*) FILTER (WHERE s.last_active_at>=h.issued_at) \
                FROM oauth_sessions s JOIN principal_did_owners p ON p.user_id=s.user_id \
                JOIN LATERAL (SELECT max(issued_at) AS issued_at FROM account_handoff_grants \
                    WHERE local_account_id=s.user_id) h ON h.issued_at IS NOT NULL \
                WHERE p.principal_id=$1 AND s.finished_at IS NULL",
                &[&id],
            )?;
            Ok((row.get(0), row.get(1)))
        })
        .await??;
        ensure!(
            sessions == 1,
            "normal second controller must have one exact bound OAuth session"
        );
        if durable == sessions {
            break;
        }
        ensure!(
            std::time::Instant::now() < deadline,
            "second controller activity not durably flushed"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    println!(
        "[agent-second-controller] normal_onboarding=1 distinct_principal=1 exact_prior_activity_flushed=1"
    );
    Ok(controller)
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
        station,
        super::AgentSessionIssuer::Coauth {
            base: coauth.base_url(),
            database_url: &coauth.pg.connect_url,
        },
        controller,
        account,
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
    for partial_signature in [false, true] {
        let mut request = station
            .http()
            .get(station.url(&format!(
                "/_arkret/self/agents/{}",
                agent.agent_account.principal_id
            )))
            .header("Source-Service-ID", station.service_id().as_str())
            .header("Destination-Service-ID", station.service_id().as_str())
            .header("Source-Trust-Domain", JOINT_TRUST_DOMAIN)
            .header("Destination-Trust-Domain", JOINT_TRUST_DOMAIN);
        if partial_signature {
            request = request.header("Signature-Input", "sig1=()");
        }
        let response = request.send().await?;
        ensure!(
            response.status() == reqwest::StatusCode::UNAUTHORIZED,
            "unexpected unsigned or partial service projection refusal: {}",
            response.status()
        );
    }
    if longevity {
        super::longevity_evidence::renew_with_real_issuer(station, coauth, controller, &mut agent)
            .await?;
    }
    lifecycle_refusals(station, coauth, controller, &agent).await?;
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
        station,
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

async fn wait_for_onboarding_activity(database_url: &str) -> Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    loop {
        let url = database_url.to_owned();
        let (sessions, durable): (i64, i64) = tokio::task::spawn_blocking(move || -> Result<_> {
            let mut db = postgres::Client::connect(&url, postgres::NoTls)?;
            let row = db.query_one(
                "SELECT count(*), count(*) FILTER (WHERE s.last_active_at >= h.issued_at) \
                 FROM oauth_sessions s JOIN LATERAL \
                 (SELECT max(issued_at) AS issued_at FROM account_handoff_grants \
                  WHERE local_account_id=s.user_id) h ON h.issued_at IS NOT NULL \
                 WHERE s.finished_at IS NULL",
                &[],
            )?;
            Ok((row.get(0), row.get(1)))
        })
        .await??;
        ensure!(
            sessions == 1,
            "normal controller onboarding must have one bound OAuth session"
        );
        if durable == sessions {
            println!(
                "[agent-issuer-baseline] prior_handoff_activity_durably_flushed=1 complete_session_fields_retained=1 no_database_mutation=1"
            );
            return Ok(());
        }
        ensure!(
            std::time::Instant::now() < deadline,
            "normal handoff activity did not reach the production minute flush"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
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
    arkret_models_collaboration::session_grants::AgentSessionGrantRequestBody,
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
        arkret_models_collaboration::session_grants::RequestedAgentSessionGrantScope {
            realm_ids: Vec::new(),
            strand_ids: Vec::new(),
            track_names: Vec::new(),
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_runtime_session_request(
    station: &crate::harness::ArkretServer,
    base: &str,
    agent: &arkret_wire::DidCoreId,
    authorization: &arkret_wire::EventId,
    method: &arkret_wire::DidUrl,
    key: &ed25519_dalek::SigningKey,
    operations: &[&str],
    scope_request: arkret_models_collaboration::session_grants::RequestedAgentSessionGrantScope,
) -> Result<arkret_models_collaboration::session_grants::AgentSessionGrantRequestBody> {
    use arkret_models_collaboration::session_grants::{
        AgentSessionGrantProofInput, AgentSessionGrantSigningInput, SessionGrantDpopBindingProof,
        SessionGrantRequestBody,
    };
    use arkret_signatures::dpop::{DpopProofRequest, build_dpop_proof};
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    let url = format!("{base}/_arkret/gate/account/session-grants");
    let binding = build_dpop_proof(&DpopProofRequest::new("POST", &url), key)?;
    let issued_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let unsigned = AgentSessionGrantSigningInput::new(
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
        AgentSessionGrantProofInput {
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
    let SessionGrantRequestBody::Agent(body) = request else {
        unreachable!()
    };
    Ok(body)
}

#[expect(
    clippy::too_many_arguments,
    reason = "Session fixture binds the accepted Agent authority, signing key, and requested scope"
)]
pub(super) async fn issue_runtime_session_with_scope(
    station: &crate::harness::ArkretServer,
    base: &str,
    database_url: &str,
    agent: &arkret_wire::DidCoreId,
    authorization: &arkret_wire::EventId,
    method: &arkret_wire::DidUrl,
    key: &ed25519_dalek::SigningKey,
    operations: &[&str],
    scope_request: arkret_models_collaboration::session_grants::RequestedAgentSessionGrantScope,
) -> Result<(
    String,
    arkret_models_collaboration::session_grants::AgentSessionGrantRequestBody,
)> {
    use arkret_models_collaboration::session_grants::{
        SessionGrantRequestBody, SessionGrantResponseBody,
    };
    use arkret_signatures::dpop::{DpopProofRequest, build_dpop_proof};
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    let url = format!("{base}/_arkret/gate/account/session-grants");
    let request = SessionGrantRequestBody::Agent(build_runtime_session_request(
        station,
        base,
        agent,
        authorization,
        method,
        key,
        operations,
        scope_request,
    )?);
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
    let outcome: SessionGrantResponseBody = serde_json::from_slice(&first)?;
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

pub(super) async fn issuer_state(url: &str) -> Result<serde_json::Value> {
    let url = url.to_owned();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut db = postgres::Client::connect(&url, postgres::NoTls)?;
        let mut state = serde_json::Map::new();
        for table in ["oauth_sessions", "oauth_session_grants", "oauth_session_grant_operations", "agent_session_proof_replay"] {
            let query = format!("SELECT coalesce(jsonb_agg(v ORDER BY v::text),'[]'::jsonb) FROM (SELECT to_jsonb(r) v FROM {table} r) rows");
            state.insert(table.to_owned(), db.query_one(&query, &[])?.get(0));
        }
        Ok(serde_json::Value::Object(state))
    }).await?
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
    original: &arkret_models_collaboration::session_grants::AgentSessionGrantRequestBody,
    url: &str,
    key: &ed25519_dalek::SigningKey,
) -> Result<arkret_models_collaboration::session_grants::AgentSessionGrantRequestBody> {
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
    let outcome: arkret_wire::AuthoritySubmitResponseBody = serde_json::from_value(
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
            arkret_wire::AuthoritySubmitResponseBody::Accepted { .. }
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

/// Validate an actual issue reply against its canonical operation binding.
/// This is evidence metadata validation, never an authorization evaluator.
pub(super) fn validate_issue_problem(problem: &arkret_wire::Problem) -> Result<()> {
    static MAPPING: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();
    if MAPPING.get().is_none() {
        let path = crate::conformance::spec_artifacts_root()
            .join("registry/operations-error-mapping.json");
        let value = serde_json::from_slice(&std::fs::read(path)?)?;
        let _ = MAPPING.set(value);
    }
    let mapping = MAPPING.get().context("canonical operation error mapping")?;
    let universal_rule = mapping["rules"]["universal_codes"]
        .as_str()
        .context("canonical universal error rule")?;
    let listed = universal_rule
        .strip_prefix("Every protected operation MAY additionally return any of: ")
        .and_then(|rule| rule.split_once(". These ").map(|(codes, _)| codes))
        .context("review changed universal error rule format")?;
    let universal = listed.split(", ").collect::<Vec<_>>();
    ensure!(
        !universal.is_empty()
            && universal
                .iter()
                .all(|code| arkret_wire::ErrorCode::is_registered(code)),
        "universal error rule must name registered codes"
    );
    let operation = arkret_wire::ServiceOperationId::from_wire(
        "ak.gate.account.command.issue_session_grant.v1",
    )
    .context("canonical issue operation")?;
    let specific = operation.operation_specific_errors();
    let code = arkret_wire::ErrorCode::from_wire(problem.code())
        .context("registered actual error code")?;
    let reason = problem
        .extensions
        .get("reason_code")
        .map(|value| value.as_str().context("reason_code must be a string"))
        .transpose()?;
    if let Some(reason) = reason {
        ensure!(
            arkret_wire::ReasonCode::is_registered(reason),
            "actual reason_code is unregistered"
        );
        if reason == arkret_wire::ReasonCode::HUMAN_APPROVAL_REQUIRED {
            ensure!(
                problem.agent_human_approval_details()?.is_some(),
                "human approval reason requires its exact SDK error parent and closed extensions"
            );
        }
    } else {
        ensure!(
            problem.status
                == code.http_status_in(arkret_wire::ErrorStatusContext::SessionIssuanceOrRefresh),
            "actual reason-free status differs from the registered session error"
        );
    }
    ensure!(
        serde_json::to_value(problem)?["type"] == code.type_uri(),
        "actual error type URI differs from registry"
    );
    ensure!(
        universal.contains(&code.as_str())
            || specific.iter().any(|entry| match entry {
                arkret_wire::OperationSpecificError::Code(allowed) => *allowed == code,
                arkret_wire::OperationSpecificError::Reason(allowed) =>
                    reason == Some(allowed.as_str()),
            }),
        "actual issue reply is outside its operation error binding: {}",
        code.as_str()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn expect_issue_refusal(
    station: &crate::harness::ArkretServer,
    database_url: &str,
    url: &str,
    body: &arkret_models_collaboration::session_grants::AgentSessionGrantRequestBody,
    key: &ed25519_dalek::SigningKey,
    retained_http_proof: Option<&str>,
    code: &str,
    reason: Option<&str>,
) -> Result<()> {
    use arkret_signatures::dpop::{DpopProofRequest, build_dpop_proof};
    let before = issuer_state(database_url).await?;
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
    validate_issue_problem(&problem)?;
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
    let after = issuer_state(database_url).await?;
    if after != before {
        let changed_tables = before
            .as_object()
            .context("issuer state object")?
            .keys()
            .filter(|table| before[*table] != after[*table])
            .cloned()
            .collect::<Vec<_>>();
        if let Some(directory) = std::env::var_os("COTEST_SERVICE_LOG_DIR") {
            let directory = std::path::PathBuf::from(directory);
            std::fs::create_dir_all(&directory)?;
            let path = directory.join(format!("issuer-noop-{}.json", super::unique_uuid7()));
            let mut file = std::fs::File::create(path)?;
            use std::io::Write as _;
            file.write_all(&serde_json::to_vec(
                &json!({"before":before,"after":after}),
            )?)?;
            file.sync_all()?;
        }
        anyhow::bail!(
            "refused Agent request changed issuer session, grant, operation or proof state; tables={changed_tables:?}; private diagnostic retained"
        );
    }
    println!(
        "[agent-session] refused_code={} reason={reason:?} status={} full_issuer_state_unchanged=1",
        problem.code(),
        problem.status
    );
    Ok(())
}

#[cfg(test)]
mod operation_error_tests {
    use super::*;

    fn problem(code: arkret_wire::ErrorCode, reason: Option<&str>) -> Result<arkret_wire::Problem> {
        let mut value = serde_json::json!({"type":code.type_uri(),"title":code.title(),
            "status":code.http_status_in(arkret_wire::ErrorStatusContext::SessionIssuanceOrRefresh),
            "detail":"Operation error binding metadata fixture"});
        if let Some(reason) = reason {
            value["reason_code"] = serde_json::json!(reason);
            if reason == "human_approval_required" {
                value["approval_request_id"] =
                    serde_json::json!("opaque_metadata_contract_request");
            }
        }
        Ok(serde_json::from_value(value)?)
    }

    #[test]
    fn issue_error_binding_rejects_endpoint_errors_and_wrong_status() -> Result<()> {
        use arkret_wire::ErrorCode;
        validate_issue_problem(&problem(ErrorCode::CapabilityDenied, None)?)?;
        validate_issue_problem(&problem(ErrorCode::ServiceUnavailable, None)?)?;
        validate_issue_problem(&problem(
            ErrorCode::ClaimRequired,
            Some("human_approval_required"),
        )?)?;
        ensure!(validate_issue_problem(&problem(ErrorCode::PolicyUnavailable, None)?).is_err());
        ensure!(validate_issue_problem(&problem(ErrorCode::PolicyViolation, None)?).is_err());
        ensure!(
            validate_issue_problem(&problem(
                ErrorCode::PolicyViolation,
                Some("human_approval_required")
            )?)
            .is_err()
        );
        let mut wrong = problem(ErrorCode::CapabilityDenied, None)?;
        wrong.status = 503;
        ensure!(validate_issue_problem(&wrong).is_err());
        Ok(())
    }

    #[test]
    fn actual_session_policy_renderer_uses_registered_operation_errors() -> Result<()> {
        use coauth_backend::handlers::account::agents::AgentAuthRejection;
        for rejection in [
            AgentAuthRejection::PolicyViolation,
            AgentAuthRejection::PolicyUnavailable,
        ] {
            let code = arkret_wire::ErrorCode::from_wire(rejection.code())
                .context("registered renderer code")?;
            let mut reply = problem(code, rejection.reason_code())?;
            reply.status = rejection.http_status().as_u16();
            validate_issue_problem(&reply)?;
        }
        Ok(())
    }
}
