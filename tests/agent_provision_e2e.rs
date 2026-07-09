//! Personal AI Agent provisioning -> pairing -> lifecycle, driven live against
//! a spawned soland in development mode (CKP-0008, spec_section_11 live leg).
//!
//! Exercises the dev-mode server-authored fan-out (architecture option B) end
//! to end through the public agent HTTP surface:
//!   1. `ck.self.agent.command.provision` -> `pending_runtime_key` + pairing.
//!   2. `ck.gate.account.command.pair_agent_key` -> durable `ck.agent.key.authorize`, clears
//!      `effective_after_first_authorized_key`, status -> `active`.
//!   3. grant attach / detach -> durable `ck.capability.grant` / `ck.capability.revoke`.
//!   4. pause / resume / deactivate -> durable lifecycle events flip status.
//!
//! `CokretServer::spawn` builds / locates the sibling `soland` binary and runs
//! it in development mode. The agent endpoints internally author their durable
//! fan-out events, so this test needs no client-side event signing.
//!
//! The second test also drives the cross-service session leg by presenting a
//! DPoP-bound `agent_key_proof` session grant and backing soland with a local
//! introspection service.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{SecondsFormat, Utc};
use cokret_core::{Error as CokretError, EventsSubscribeFrameKind};
use cokret_http_client::{Auth, Client as SdkClient, ClientBuilder, EventsSubscribeOptions};
use cotest::harness::{
    CokretServer, add_member, create_realm, event_envelope, register_account, submit_event,
};
use cotest::scenarios::_helpers::mock_http::{self, MockServer};
use ed25519_dalek::{Signer, SigningKey};
use reqwest::StatusCode;
use salvo::affix_state;
use salvo::prelude::{Depot, Json, Request, Response, Router, handler};
use serde_json::{Value, json};
use serial_test::serial;
use sha2::{Digest, Sha256};

const ALICE_DID: &str = "did:web:cotest-agent-alice.example";
const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-00000000a901";
const AGENT_SESSION_GRANT: &str = "cotest.agent.session.grant";
const INTROSPECTION_BEARER: &str = "cotest-introspection-bearer";

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn agent_provision_pair_lifecycle_e2e() -> Result<()> {
    let server = CokretServer::spawn("agent-provision-e2e").await?;
    let token = register_account(&server, ALICE_DID, "@cotest-agent-alice", ALICE_DEVICE).await?;

    // 1-2. provision -> pending_runtime_key + pairing material -> active.
    let agent_did =
        provision_and_pair_agent(&server, &token, "Summary Assistant", "summary").await?;
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "active");

    // 3. grant attach/detach must materialize into the authz projection.
    let controller = bearer_sdk_client(&server, &token)?;
    let attach = controller
        .agent_grant_attach(
            &agent_did,
            &arkret::AgentGrantAttachRequestBody {
                grant: json!({
                    "actions": ["ck.event.read"]
                }),
            },
        )
        .await?;
    let grant_id = attach.grant_id.to_string();
    let effective_after_attach = effective_grants(&server, &token, &agent_did).await?;
    assert!(
        grant_exists_in(&effective_after_attach, &grant_id),
        "attached grant must appear in effective grants: {effective_after_attach}"
    );

    let grant_id = arkret::GrantId::new(grant_id)?;
    let detach = controller.agent_grant_detach(&agent_did, &grant_id).await?;
    assert!(detach.ok, "grant detach must succeed");
    let effective_after_detach = effective_grants(&server, &token, &agent_did).await?;
    assert!(
        !grant_exists_in(&effective_after_detach, grant_id.as_str()),
        "detached grant must disappear from effective grants: {effective_after_detach}"
    );

    // 4. lifecycle transitions land durable events + flip projected status.
    for (path, expect) in [
        ("pause", "paused"),
        ("resume", "active"),
        ("deactivate", "deactivated"),
    ] {
        let outcome = match path {
            "pause" => {
                controller
                    .agent_pause(&agent_did, &arkret::AgentPauseRequestBody { reason: None })
                    .await?
            }
            "resume" => {
                controller
                    .agent_resume(
                        &agent_did,
                        &arkret::AgentResumeRequestBody {
                            sidecar_exposure_ack: None,
                        },
                    )
                    .await?
            }
            "deactivate" => {
                controller
                    .agent_deactivate(
                        &agent_did,
                        &arkret::AgentDeactivateRequestBody { reason: None },
                    )
                    .await?
            }
            _ => unreachable!(),
        };
        assert!(outcome.ok, "lifecycle {path} must succeed");
        assert_eq!(
            agent_status(&server, &token, &agent_did).await?,
            expect,
            "status after {path}"
        );
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn agent_key_proof_session_reply_and_revoke_live_e2e() -> Result<()> {
    let service_name = "agent-live-e2e";
    let holder = AgentSessionHolder::new();
    let mock = MockIntrospection::spawn(
        format!("did:web:{service_name}.cotest.local"),
        holder.cnf_jkt.clone(),
        holder.public_jwk.to_string(),
    )
    .await?;
    let introspection_url = mock.url();
    let server = CokretServer::spawn_with_env(
        service_name,
        &[
            (
                "SOLAND_SESSION_GRANT_INTROSPECTION_URL",
                introspection_url.as_str(),
            ),
            (
                "SOLAND_SESSION_GRANT_INTROSPECTION_BEARER",
                INTROSPECTION_BEARER,
            ),
        ],
    )
    .await?;
    mock.set_service_did(server.service_did().to_owned());
    let token = register_account(&server, ALICE_DID, "@cotest-agent-alice", ALICE_DEVICE).await?;

    let realm_id = create_realm(&server, &token, ALICE_DID, "Agent reply live e2e").await?;
    let agent_did = provision_and_pair_agent(&server, &token, "Reply Assistant", "reply").await?;
    mock.set_subject(agent_did.clone());
    advance_event_sequence(ALICE_DID, &realm_id, 32);
    add_member(&server, &token, ALICE_DID, &realm_id, &agent_did).await?;

    let controller = bearer_sdk_client(&server, &token)?;
    let participation = controller
        .agent_participation_replace(
            &agent_did,
            &arkret::AgentParticipationReplaceRequestBody {
                scope: arkret::AgentParticipationScope::Realm {
                    realm_id: arkret::RealmId::new(realm_id.clone())?,
                },
                selection: arkret::AgentParticipation {
                    reply: true,
                    accept_third_party_mention: false,
                    act_on_behalf: false,
                },
            },
        )
        .await?;
    assert!(participation.ok, "participation set must succeed");
    assert!(
        participation
            .entries
            .first()
            .is_some_and(|entry| entry.effective.reply),
        "effective reply bit must be enabled"
    );

    // The agent reply targets the realm's default Strand (the message envelope
    // derives `strand_id` from the realm id). soland's agent-reply participation
    // gate resolves the message scope through the projected Strand, so the
    // Strand must exist first — create it as the realm owner.
    let default_strand_id = realm_id.replace("ak:realm:", "ak:strand:");
    let strand = submit_event(
        &server,
        &token,
        ALICE_DID,
        &realm_id,
        "ck.strand.create",
        json!({
            "object": {
                "id": default_strand_id,
                "schema": "ck.schema.strand.v1",
                "realm_id": realm_id,
                "tracks": {"discussion": {"enabled": true, "is_primary": true}},
                "created_by": ALICE_DID,
                "created_at": "2026-05-02T00:00:00Z",
                "metadata": {"title": "Agent reply strand"}
            }
        }),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(strand["status"], "accepted");

    // CKP-0016 §5.2: every agent-originated Event carries an auditable
    // `agent_context` whose `authorization_ref` MUST resolve to an active
    // capability grant for the agent IN THE EVENT'S REALM, with an action
    // covering the operation's canonical kind. Grant the agent `ck.message.create`
    // in the reply Realm so the reply's agent_context references a real grant.
    let agent_grant_id = "ak:grant:01999999-0000-7000-8000-0000000000c1";
    let agent_grant = submit_event(
        &server,
        &token,
        ALICE_DID,
        &realm_id,
        "ck.capability.grant",
        json!({
            "grant_id": agent_grant_id,
            "grant": {
                "id": agent_grant_id,
                "schema": "ck.schema.capability.v1",
                "realm_id": realm_id,
                "issuer": ALICE_DID,
                "subject": agent_did,
                "actions": ["ck.message.create"],
                "resources": [{"kind": "realm", "realm_id": realm_id}],
                "constraints": [],
                "issued_at": "2026-05-02T00:00:00Z",
                "proofs": [{
                    "kind": "detached_jws",
                    "alg": "EdDSA",
                    "verification_method": format!("{ALICE_DID}#cotest"),
                    "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    "created_at": "2026-05-02T00:00:00Z",
                    "jws": "a..b"
                }]
            }
        }),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(agent_grant["status"], "accepted");

    let agent_message = event_envelope(
        &agent_did,
        &realm_id,
        "ck.message.create",
        json!({
            "body": "agent_key_proof live reply",
            "content": {"body": "agent_key_proof live reply"},
            "agent_context": {
                "agent_id": agent_did,
                "operator_or_controller": ALICE_DID,
                "execution_purpose": "reply",
                "authorization_ref": agent_grant_id,
            },
        }),
    );
    let agent_client = agent_session_client(&server, &holder)?;
    let accepted = agent_client
        .events_submit(&event_from_value(&agent_message)?)
        .await?;
    assert_eq!(
        accepted
            .accepted
            .first()
            .map(|event_id| event_id.to_string())
            .as_deref(),
        agent_message["event_id"].as_str(),
        "agent-authored message must be accepted"
    );
    assert!(
        mock.requests() >= 1,
        "agent submit must use the introspection service"
    );

    let agent_event_id = agent_message["event_id"]
        .as_str()
        .expect("agent message event_id")
        .to_owned();
    let scan = agent_client
        .events_query(&realm_id, None, None, None, Some(50))
        .await?;
    assert!(
        scan.events
            .iter()
            .any(|event| event.event_id.to_string() == agent_event_id),
        "DPoP-bound agent scan must include accepted reply event {agent_event_id}: {scan:?}"
    );

    let mut stream = agent_client
        .events_subscribe_frames(
            &EventsSubscribeOptions::new()
                .realm(realm_id.clone())
                .include_history(true)
                .max_duration_ms(150)
                .heartbeat_ms(100),
        )
        .await?;
    let mut stream_frames = Vec::new();
    while let Some(frame) = stream.next_frame().await? {
        stream_frames.push(frame);
    }
    assert!(
        stream_frames
            .iter()
            .any(|frame| frame.kind == EventsSubscribeFrameKind::CatchupComplete),
        "agent stream must emit catchup_complete: {stream_frames:?}"
    );
    assert!(
        stream_frames
            .iter()
            .any(|frame| serde_json::to_string(frame)
                .is_ok_and(|frame_json| frame_json.contains(&agent_event_id))),
        "DPoP-bound agent stream history must include accepted reply event {agent_event_id}: {stream_frames:?}"
    );

    let paused = controller
        .agent_pause(
            &agent_did,
            &arkret::AgentPauseRequestBody {
                reason: Some("cotest live e2e pause".to_owned()),
            },
        )
        .await?;
    assert!(paused.ok, "pause must succeed");
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "paused");

    let after_pause = event_envelope(
        &agent_did,
        &realm_id,
        "ck.message.create",
        json!({
            "body": "agent_key_proof after pause",
            "content": {"body": "agent_key_proof after pause"},
            "agent_context": {
                "agent_id": agent_did,
                "operator_or_controller": ALICE_DID,
                "execution_purpose": "reply",
                "authorization_ref": agent_grant_id,
            },
        }),
    );
    expect_sdk_api_error(
        agent_client
            .events_submit(&event_from_value(&after_pause)?)
            .await,
        StatusCode::PRECONDITION_FAILED,
        "agent_paused",
    )?;

    let deactivated = controller
        .agent_deactivate(
            &agent_did,
            &arkret::AgentDeactivateRequestBody {
                reason: Some("cotest live e2e".to_owned()),
            },
        )
        .await?;
    assert!(deactivated.ok, "deactivate must succeed");
    assert_eq!(
        agent_status(&server, &token, &agent_did).await?,
        "deactivated"
    );

    let after_deactivate = event_envelope(
        &agent_did,
        &realm_id,
        "ck.message.create",
        json!({
            "body": "agent_key_proof after deactivate",
            "content": {"body": "agent_key_proof after deactivate"},
            "agent_context": {
                "agent_id": agent_did,
                "operator_or_controller": ALICE_DID,
                "execution_purpose": "reply",
                "authorization_ref": agent_grant_id,
            },
        }),
    );
    expect_sdk_api_error(
        agent_client
            .events_submit(&event_from_value(&after_deactivate)?)
            .await,
        StatusCode::PRECONDITION_FAILED,
        "agent_deactivated",
    )?;

    mock.set_active(false);
    let after_revoke = event_envelope(
        &agent_did,
        &realm_id,
        "ck.message.create",
        json!({
            "body": "agent_key_proof after revoke",
            "content": {"body": "agent_key_proof after revoke"},
        }),
    );
    expect_sdk_api_error(
        agent_client
            .events_submit(&event_from_value(&after_revoke)?)
            .await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )?;
    assert!(
        mock.requests() >= 2,
        "write after revoke must force fresh introspection"
    );

    Ok(())
}

async fn provision_and_pair_agent(
    server: &CokretServer,
    token: &str,
    display_name: &str,
    agent_slug: &str,
) -> Result<String> {
    let controller = bearer_sdk_client(server, token)?;
    let prov = controller
        .agent_provision(&arkret::AgentProvisionRequestBody {
            display_name: Some(display_name.to_owned()),
            agent_slug: Some(agent_slug.to_owned()),
            requested_scope: None,
            accountability: Value::Null,
            pairing_ttl_ms: None,
        })
        .await?;
    let agent_did = prov.agent_principal_id.to_string();
    assert!(prov.pairing_code.is_some(), "pairing_code present");
    assert_eq!(
        agent_status(server, token, &agent_did).await?,
        "pending_runtime_key"
    );

    let pair = pair_agent_runtime_key(server, token, &prov).await?;
    assert!(
        !pair.authorized_event_ref.as_str().is_empty(),
        "authorized_event_ref present"
    );
    assert_eq!(agent_status(server, token, &agent_did).await?, "active");
    Ok(agent_did)
}

async fn pair_agent_runtime_key(
    server: &CokretServer,
    token: &str,
    provisioned: &arkret::AgentProvisionOutcome,
) -> Result<arkret::AgentKeyPairOutcome> {
    let agent_did = provisioned.agent_principal_id.to_string();
    let pairing_request_id = provisioned.pairing_request_id.as_str();
    let pairing_code = provisioned
        .pairing_code
        .as_deref()
        .ok_or_else(|| anyhow!("pairing_code missing"))?;
    let pairing_expires_at = provisioned
        .expires_at
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    let agent_id = provisioned.agent_principal_id.clone();
    let controller_id = arkret::Did::new(ALICE_DID.to_owned())
        .map_err(|err| anyhow!("alice did invalid: {err}"))?;
    let verification_method = format!("{agent_did}#runtime-key-1");
    let signing_key = SigningKey::from_bytes(&[13_u8; 32]);
    let public_key = json!({
        "kty": "OKP",
        "kid": verification_method,
        "alg": "Ed25519",
        "key": URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
    });
    let runtime_public_key_digest = arkret::agent::agent_runtime_public_key_digest(&public_key)?;
    let request_digest = arkret::agent::agent_key_pair_proof_request_binding_digest(
        pairing_request_id,
        &agent_id,
        &verification_method,
        &public_key,
        None,
    )?;
    let proof_expires_at =
        chrono::DateTime::parse_from_rfc3339("2999-01-01T00:00:00.000Z")?.with_timezone(&Utc);
    let signing_input = arkret::agent::agent_key_pair_proof_signing_input(
        verification_method.clone(),
        pairing_request_id.to_owned(),
        server.service_did().to_owned(),
        proof_expires_at,
        request_digest.clone(),
    );
    let signature = signing_key.sign(&signing_input.canonical_bytes()?);
    let pairing_binding_digest = arkret::agent::agent_key_pairing_request_binding_digest(
        &controller_id,
        &agent_id,
        &verification_method,
        &runtime_public_key_digest,
        pairing_request_id,
        pairing_code,
        &pairing_expires_at,
        server.service_did(),
    )?;
    let body = arkret::models::AgentKeyPairRequestBody {
        pairing_request_id: pairing_request_id.to_owned(),
        agent_principal_id: agent_id,
        verification_method: verification_method.clone(),
        public_key,
        proof_of_possession: json!({
            "challenge": pairing_request_id,
            "audience": server.service_did(),
            "request_canonical_digest": request_digest.as_str(),
            "expires_at": proof_expires_at.to_rfc3339_opts(SecondsFormat::Millis, true),
            "signature": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        }),
        runtime_attestation: None,
        authorize_event: json!({
            "kind": "ck.agent.key.authorize",
            "actor_id": ALICE_DID,
            "payload": {
                "agent_principal_id": agent_did,
                "key_id": "ak:agent_key:01999999000070008000000000000001",
                "verification_method": verification_method,
                "public_key_digest": runtime_public_key_digest.as_str(),
                "accountable_principal_id": ALICE_DID,
                "agent_key_scope": {
                    "actions": [
                        "ck.self.events.stream.subscribe",
                        "ck.self.events.query.scan",
                        "ck.self.events.command.submit",
                        "ck.event.read",
                        "ck.message.create"
                    ],
                    "resources": [{"kind": "realm", "realm_id": "*"}],
                    "constraints": []
                },
                "audience": [server.service_did()],
                "issued_at": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                "expires_at": "2999-01-01T00:00:00Z",
                "approval_evidence": {
                    "kind": "approval_event",
                    "ref": "ak:event:01999999-0000-7000-8000-000000000001",
                    "request_canonical_digest": pairing_binding_digest.as_str(),
                    "approved_by": ALICE_DID
                }
            }
        }),
    };
    // `agent_key_pair` drives `ck.gate.account.command.pair_agent_key`, bound to
    // `POST /_cokret/gate/account/agent-key-pair`: the controller submits the
    // durable `ck.agent.key.authorize` event that clears `pending_runtime_key`.
    Ok(bearer_sdk_client(server, token)?
        .agent_key_pair(&body)
        .await?)
}

async fn agent_status(server: &CokretServer, token: &str, agent_did: &str) -> Result<String> {
    let list = bearer_sdk_client(server, token)?.agent_list().await?;
    let status = list
        .agents
        .iter()
        .find(|agent| agent["agent_principal_id"].as_str() == Some(agent_did))
        .and_then(|agents| agents["status"].as_str())
        .unwrap_or_default()
        .to_owned();
    Ok(status)
}

async fn effective_grants(server: &CokretServer, token: &str, agent_did: &str) -> Result<Value> {
    // The dev-mode agent grant is authored into the controller's
    // principal-control Realm (soland `ensure_self_realm`). soland only lets a
    // caller read a non-self subject's effective grants for a Realm the caller
    // owns (anti-enumeration); a bare `subject` query defaults to realm `*` and
    // is denied. Scope the query to the controller's principal-control Realm,
    // which the controller owns and where the agent grant lives.
    let control_realm = arkret::auth::principal_control_realm_id(
        &arkret::Did::new(ALICE_DID.to_owned()).map_err(|e| anyhow!("alice did invalid: {e}"))?,
    );
    let effective = bearer_sdk_client(server, token)?
        .authz_effective_grants(control_realm.as_str(), agent_did, None)
        .await?;
    Ok(serde_json::to_value(effective)?)
}

fn grant_exists_in(effective: &Value, grant_id: &str) -> bool {
    effective["grants"].as_array().is_some_and(|grants| {
        grants.iter().any(|grant| {
            grant["id"].as_str() == Some(grant_id) || grant["grant_id"].as_str() == Some(grant_id)
        })
    })
}

fn bearer_sdk_client(server: &CokretServer, token: &str) -> Result<SdkClient> {
    Ok(ClientBuilder::new(server.base_url())
        .allow_insecure_localhost()
        .auth(Auth::Bearer(token.to_owned()))
        .build()?)
}

fn agent_session_client(server: &CokretServer, holder: &AgentSessionHolder) -> Result<SdkClient> {
    Ok(ClientBuilder::new(server.base_url())
        .allow_insecure_localhost()
        .auth(Auth::Dpop(garth::session::dpop::access_token_auth(
            AGENT_SESSION_GRANT,
            SigningKey::from_bytes(&holder.signing_key.to_bytes()),
        )))
        .build()?)
}

fn event_from_value(value: &Value) -> Result<arkret::Event> {
    Ok(serde_json::from_value(value.clone())?)
}

fn expect_sdk_api_error<T>(
    result: cokret_core::Result<T>,
    status: StatusCode,
    code: &str,
) -> Result<()> {
    match result {
        Err(CokretError::Api {
            status: actual_status,
            error,
        }) => {
            assert_eq!(
                actual_status,
                status.as_u16(),
                "expected SDK API status {status}, got {actual_status}: {error:?}"
            );
            assert_eq!(
                error.code(),
                code,
                "expected SDK API error code {code}, got {error:?}"
            );
            Ok(())
        }
        Err(error) => Err(anyhow!(
            "expected SDK API error {status}/{code}, got {error}"
        )),
        Ok(_) => Err(anyhow!(
            "expected SDK API error {status}/{code}, got success"
        )),
    }
}

fn advance_event_sequence(actor: &str, realm_id: &str, count: usize) {
    for _ in 0..count {
        let _ = event_envelope(
            actor,
            realm_id,
            "ck.message.create",
            json!({"body": "sequence padding"}),
        );
    }
}

struct AgentSessionHolder {
    signing_key: SigningKey,
    public_jwk: Value,
    cnf_jkt: String,
}

impl AgentSessionHolder {
    fn new() -> Self {
        let secret = [7_u8; 32];
        let signing_key = SigningKey::from_bytes(&secret);
        let public_x = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
        let public_jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": public_x,
        });
        let cnf_jkt =
            jwk_thumbprint_ed25519(public_jwk["x"].as_str().expect("public x must be a string"));
        Self {
            signing_key,
            public_jwk,
            cnf_jkt,
        }
    }
}

fn jwk_thumbprint_ed25519(x: &str) -> String {
    let canonical = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}");
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

#[derive(Clone)]
struct AgentIntrospectionState {
    active: Arc<AtomicBool>,
    request_count: Arc<AtomicUsize>,
    service_did: Arc<Mutex<String>>,
    subject: Arc<Mutex<Option<String>>>,
    cnf_jkt: String,
    session_public_key: String,
}

struct MockIntrospection {
    url: String,
    active: Arc<AtomicBool>,
    request_count: Arc<AtomicUsize>,
    service_did: Arc<Mutex<String>>,
    subject: Arc<Mutex<Option<String>>>,
    _server: MockServer,
}

impl MockIntrospection {
    async fn spawn(
        service_did: String,
        cnf_jkt: String,
        session_public_key: String,
    ) -> Result<Self> {
        let active = Arc::new(AtomicBool::new(true));
        let request_count = Arc::new(AtomicUsize::new(0));
        let service_did = Arc::new(Mutex::new(service_did));
        let subject = Arc::new(Mutex::new(None));
        let state = AgentIntrospectionState {
            active: Arc::clone(&active),
            request_count: Arc::clone(&request_count),
            service_did: Arc::clone(&service_did),
            subject: Arc::clone(&subject),
            cnf_jkt,
            session_public_key,
        };
        let router = Router::with_path("session-grants/introspect")
            .hoop(affix_state::inject(state))
            .post(agent_introspect);
        let server = mock_http::spawn_mock(router).await?;
        let url = format!("http://{}/session-grants/introspect", server.addr());
        Ok(Self {
            url,
            active,
            request_count,
            service_did,
            subject,
            _server: server,
        })
    }

    fn url(&self) -> String {
        self.url.clone()
    }

    fn requests(&self) -> usize {
        self.request_count.load(Ordering::SeqCst)
    }

    fn set_service_did(&self, service_did: String) {
        if let Ok(mut guard) = self.service_did.lock() {
            *guard = service_did;
        }
    }

    fn set_subject(&self, subject: String) {
        if let Ok(mut guard) = self.subject.lock() {
            *guard = Some(subject);
        }
    }

    fn set_active(&self, active: bool) {
        self.active.store(active, Ordering::SeqCst);
    }
}

#[handler]
async fn agent_introspect(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot
        .get_typed::<AgentIntrospectionState>()
        .expect("agent introspection mock state injected")
        .clone();
    state.request_count.fetch_add(1, Ordering::SeqCst);
    let authorized = req
        .headers()
        .get(salvo::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .to_ascii_lowercase()
                .contains(&format!("bearer {INTROSPECTION_BEARER}"))
        });
    if !authorized {
        res.status_code(salvo::http::StatusCode::UNAUTHORIZED);
        res.render(Json(
            json!({"ok": false, "error": {"errcode": "unauthenticated"}}),
        ));
        return;
    }
    let _body: Value = req.parse_json().await.unwrap_or_else(|_| json!({}));

    let service_did = state
        .service_did
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or_else(|_| "did:web:agent-live-e2e.cotest.local".to_owned());
    let subject = state
        .subject
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .unwrap_or_else(|| "did:web:agent-unset.example".to_owned());
    let body = if state.active.load(Ordering::SeqCst) {
        json!({
            "active": true,
            "status": "active",
            "proof_required": false,
            "one_time_use_consumed": false,
            "grant": {
                // `SessionGrantIntrospectGrant.id` is a typed `GrantId`
                // (`ck:grant:<uuidv7>`); a bare label fails SDK deserialization
                // and soland reports the introspection response as invalid (503).
                "id": "ak:grant:01964137-0000-7000-8000-000000000a01",
                "issuer": "did:web:coauth.cotest.local",
                "subject": subject,
                "service_account_id": "agent-live-e2e-account",
                "audience": service_did,
                "scopes": [
                    "ck.self.events.stream.subscribe",
                    "ck.self.events.query.scan",
                    "ck.self.events.command.submit",
                    "ck.event.read",
                    "ck.message.create"
                ],
                "expires_at": "2026-12-31T23:59:59Z",
                "revocation_ref": "ak:session:agent-live-e2e-grant",
                "session_public_key": state.session_public_key,
                "cnf_jkt": state.cnf_jkt,
                "proof_kind": "agent_key_proof",
                "scope_details": {
                    "agent_principal_id": subject,
                    "controller_did": ALICE_DID,
                    "resources": {
                        "realm_refs": ["*"],
                        "strand_refs": []
                    },
                    "constraints": {
                        "allowed_tracks": [],
                        "allowed_data_classes": [],
                        "allowed_endpoints": []
                    },
                    "capability_grant_refs": [],
                    "policy_refs": []
                },
                "freshness_state": "fresh"
            }
        })
    } else {
        json!({
            "active": false,
            "status": "revoked",
            "proof_required": false,
            "one_time_use_consumed": false
        })
    };
    res.render(Json(body));
}
