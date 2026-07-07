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

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{SecondsFormat, Utc};
use cotest::harness::{
    CokretServer, add_member, create_realm, event_envelope, expect_api_error, expect_json,
    register_account, submit_event,
};
use ed25519_dalek::{Signer, SigningKey};
use reqwest::StatusCode;
use serde_json::{Value, json};
use serial_test::serial;
use sha2::{Digest, Sha256};

const ALICE_DID: &str = "did:web:cotest-agent-alice.example";
const ALICE_DEVICE: &str = "ck:device:01904100-0000-7000-8000-00000000a901";
const AGENT_SESSION_GRANT: &str = "cotest.agent.session.grant";
const INTROSPECTION_BEARER: &str = "cotest-introspection-bearer";

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn agent_provision_pair_lifecycle_e2e() -> Result<()> {
    let server = CokretServer::spawn("agent-provision-e2e").await?;
    let token = register_account(&server, ALICE_DID, "@cotest-agent-alice", ALICE_DEVICE).await?;

    // 1. provision -> pending_runtime_key + pairing material.
    let prov = server
        .http()
        .post(server.url("/_cokret/self/agents"))
        .bearer_auth(&token)
        .json(&json!({"display_name": "Summary Assistant", "agent_slug": "summary"}))
        .send()
        .await?;
    assert_eq!(
        prov.status(),
        StatusCode::CREATED,
        "provision must return 201"
    );
    let prov: Value = prov.json().await?;
    let agent_did = prov["agent_principal_id"]
        .as_str()
        .expect("agent_principal_id")
        .to_owned();
    assert!(
        prov["pairing_request_id"].as_str().is_some(),
        "pairing_request_id present"
    );
    assert!(
        prov["pairing_code"].as_str().is_some(),
        "pairing_code present"
    );
    assert_eq!(
        agent_status(&server, &token, &agent_did).await?,
        "pending_runtime_key"
    );

    // 2. pair the runtime key -> durable ck.agent.key.authorize -> active.
    let pair = pair_agent_runtime_key(&server, &token, &prov).await?;
    assert!(
        pair["authorized_event_ref"].as_str().is_some(),
        "authorized_event_ref present"
    );
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "active");

    // 3. grant attach/detach must materialize into the authz projection.
    let attach = server
        .http()
        .post(server.url(&format!(
            "/_cokret/self/agents/{}/grants",
            urlencoding(&agent_did)
        )))
        .bearer_auth(&token)
        .json(&json!({
            "grant": {
                "actions": ["ck.event.read"]
            }
        }))
        .send()
        .await?;
    assert_eq!(
        attach.status(),
        StatusCode::CREATED,
        "grant attach must return 201"
    );
    let attach: Value = attach.json().await?;
    let grant_id = attach["grant_id"].as_str().expect("grant_id").to_owned();
    let effective_after_attach = effective_grants(&server, &token, &agent_did).await?;
    assert!(
        grant_exists_in(&effective_after_attach, &grant_id),
        "attached grant must appear in effective grants: {effective_after_attach}"
    );

    let detach = server
        .http()
        .delete(server.url(&format!(
            "/_cokret/self/agents/{}/grants/{}",
            urlencoding(&agent_did),
            urlencoding(&grant_id)
        )))
        .bearer_auth(&token)
        .send()
        .await?;
    assert_eq!(
        detach.status(),
        StatusCode::OK,
        "grant detach must return 200"
    );
    let effective_after_detach = effective_grants(&server, &token, &agent_did).await?;
    assert!(
        !grant_exists_in(&effective_after_detach, &grant_id),
        "detached grant must disappear from effective grants: {effective_after_detach}"
    );

    // 4. lifecycle transitions land durable events + flip projected status.
    for (path, expect) in [
        ("pause", "paused"),
        ("resume", "active"),
        ("deactivate", "deactivated"),
    ] {
        let res = server
            .http()
            .post(server.url(&format!(
                "/_cokret/self/agents/{}/{path}",
                urlencoding(&agent_did)
            )))
            .bearer_auth(&token)
            .json(&json!({}))
            .send()
            .await?;
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "lifecycle {path} must return 200"
        );
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
    )?;
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

    let participation = expect_json(
        server
            .http()
            .put(server.url(&format!(
                "/_cokret/self/agents/{}/participation",
                urlencoding(&agent_did)
            )))
            .bearer_auth(&token)
            .json(&json!({
                "participation_scope": {
                    "kind": "realm",
                    "realm_id": realm_id,
                },
                "selection": {
                    "reply": true,
                    "accept_third_party_mention": false,
                    "act_on_behalf": false,
                }
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(participation["ok"], true, "participation set must succeed");
    assert_eq!(
        participation["entries"][0]["effective"]["reply"], true,
        "effective reply bit must be enabled"
    );

    // The agent reply targets the realm's default Strand (the message envelope
    // derives `strand_id` from the realm id). soland's agent-reply participation
    // gate resolves the message scope through the projected Strand, so the
    // Strand must exist first — create it as the realm owner.
    let default_strand_id = realm_id.replace("ck:realm:", "ck:strand:");
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
    let agent_grant_id = "ck:grant:01999999-0000-7000-8000-0000000000c1";
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
    let accepted = expect_json(
        agent_session_post(&server, &holder, &agent_message, "reply-before-revoke")?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        accepted["accepted"]
            .as_array()
            .and_then(|events| events.first())
            .and_then(Value::as_str),
        agent_message["event_id"].as_str(),
        "agent-authored message must be accepted"
    );
    assert!(
        mock.requests() >= 1,
        "agent submit must use the introspection service"
    );

    let deactivated = server
        .http()
        .post(server.url(&format!(
            "/_cokret/self/agents/{}/deactivate",
            urlencoding(&agent_did)
        )))
        .bearer_auth(&token)
        .json(&json!({"reason": "cotest live e2e"}))
        .send()
        .await?;
    assert_eq!(
        deactivated.status(),
        StatusCode::OK,
        "deactivate must return 200"
    );
    assert_eq!(
        agent_status(&server, &token, &agent_did).await?,
        "deactivated"
    );

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
    expect_api_error(
        agent_session_post(&server, &holder, &after_revoke, "reply-after-revoke")?,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;
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
    let prov = server
        .http()
        .post(server.url("/_cokret/self/agents"))
        .bearer_auth(token)
        .json(&json!({
            "display_name": display_name,
            "agent_slug": agent_slug,
        }))
        .send()
        .await?;
    assert_eq!(
        prov.status(),
        StatusCode::CREATED,
        "provision must return 201"
    );
    let prov: Value = prov.json().await?;
    let agent_did = prov["agent_principal_id"]
        .as_str()
        .ok_or_else(|| anyhow!("agent_principal_id missing: {prov}"))?
        .to_owned();
    assert!(
        prov["pairing_request_id"].as_str().is_some(),
        "pairing_request_id present"
    );
    assert!(
        prov["pairing_code"].as_str().is_some(),
        "pairing_code present"
    );
    assert_eq!(
        agent_status(server, token, &agent_did).await?,
        "pending_runtime_key"
    );

    let pair = pair_agent_runtime_key(server, token, &prov).await?;
    assert!(
        pair["authorized_event_ref"].as_str().is_some(),
        "authorized_event_ref present"
    );
    assert_eq!(agent_status(server, token, &agent_did).await?, "active");
    Ok(agent_did)
}

async fn pair_agent_runtime_key(
    server: &CokretServer,
    token: &str,
    provisioned: &Value,
) -> Result<Value> {
    let agent_did = provisioned["agent_principal_id"]
        .as_str()
        .ok_or_else(|| anyhow!("agent_principal_id missing: {provisioned}"))?;
    let pairing_request_id = provisioned["pairing_request_id"]
        .as_str()
        .ok_or_else(|| anyhow!("pairing_request_id missing: {provisioned}"))?;
    let pairing_code = provisioned["pairing_code"]
        .as_str()
        .ok_or_else(|| anyhow!("pairing_code missing: {provisioned}"))?;
    let pairing_expires_at = provisioned["expires_at"]
        .as_str()
        .ok_or_else(|| anyhow!("expires_at missing: {provisioned}"))?;
    let agent_id = cokret::Did::new(agent_did.to_owned())
        .map_err(|err| anyhow!("agent_principal_id invalid: {err}"))?;
    let controller_id = cokret::Did::new(ALICE_DID.to_owned())
        .map_err(|err| anyhow!("alice did invalid: {err}"))?;
    let verification_method = format!("{agent_did}#runtime-key-1");
    let signing_key = SigningKey::from_bytes(&[13_u8; 32]);
    let public_key = json!({
        "kty": "OKP",
        "kid": verification_method,
        "alg": "Ed25519",
        "key": URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
    });
    let runtime_public_key_digest = cokret::agent::agent_runtime_public_key_digest(&public_key)?;
    let request_digest = cokret::agent::agent_key_pair_proof_request_binding_digest(
        pairing_request_id,
        &agent_id,
        &verification_method,
        &public_key,
        None,
    )?;
    let proof_expires_at =
        chrono::DateTime::parse_from_rfc3339("2999-01-01T00:00:00.000Z")?.with_timezone(&Utc);
    let signing_input = cokret::agent::agent_key_pair_proof_signing_input(
        verification_method.clone(),
        pairing_request_id.to_owned(),
        server.service_did().to_owned(),
        proof_expires_at,
        request_digest.clone(),
    );
    let signature = signing_key.sign(&signing_input.canonical_bytes()?);
    let pairing_binding_digest = cokret::agent::agent_key_pairing_request_binding_digest(
        &controller_id,
        &agent_id,
        &verification_method,
        &runtime_public_key_digest,
        pairing_request_id,
        pairing_code,
        pairing_expires_at,
        server.service_did(),
    )?;
    let body = cokret::models::AgentKeyPairRequestBody {
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
                "key_id": "ck:agent_key:01999999000070008000000000000001",
                "verification_method": verification_method,
                "public_key_digest": runtime_public_key_digest.as_str(),
                "accountable_principal_id": ALICE_DID,
                "agent_key_scope": {
                    "actions": ["ck.self.events.command.submit"],
                    "resources": [{"kind": "realm", "realm_id": "*"}],
                    "constraints": []
                },
                "audience": [server.service_did()],
                "issued_at": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                "expires_at": "2999-01-01T00:00:00Z",
                "approval_evidence": {
                    "kind": "approval_event",
                    "ref": "ck:event:01999999-0000-7000-8000-000000000001",
                    "request_canonical_digest": pairing_binding_digest.as_str(),
                    "approved_by": ALICE_DID
                }
            }
        }),
    };
    let response = server
        .http()
        .post(server.url("/_cokret/gate/account/agent-key-pair"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await?;
    let status = response.status();
    let body: Value = response.json().await.unwrap_or_else(|_| json!(null));
    assert_eq!(
        status,
        StatusCode::OK,
        "pairing must return 200, got {status}: {body}"
    );
    Ok(body)
}

async fn agent_status(server: &CokretServer, token: &str, agent_did: &str) -> Result<String> {
    let list: Value = server
        .http()
        .get(server.url("/_cokret/self/agents"))
        .bearer_auth(token)
        .send()
        .await?
        .json()
        .await?;
    let status = list["agents"]
        .as_array()
        .and_then(|agents| {
            agents
                .iter()
                .find(|a| a["agent_principal_id"].as_str() == Some(agent_did))
        })
        .and_then(|a| a["status"].as_str())
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
    let control_realm = cokret::auth::principal_control_realm_id(
        &cokret::Did::new(ALICE_DID.to_owned()).map_err(|e| anyhow!("alice did invalid: {e}"))?,
    );
    let effective: Value = server
        .http()
        .get(server.url("/_cokret/self/authz/effective-grants"))
        .bearer_auth(token)
        .query(&[("subject", agent_did), ("realm_id", control_realm.as_str())])
        .send()
        .await?
        .json()
        .await?;
    Ok(effective)
}

fn grant_exists_in(effective: &Value, grant_id: &str) -> bool {
    effective["grants"].as_array().is_some_and(|grants| {
        grants.iter().any(|grant| {
            grant["id"].as_str() == Some(grant_id) || grant["grant_id"].as_str() == Some(grant_id)
        })
    })
}

fn urlencoding(did: &str) -> String {
    did.replace(':', "%3A").replace('/', "%2F")
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

fn agent_session_post(
    server: &CokretServer,
    holder: &AgentSessionHolder,
    event: &Value,
    jti_suffix: &str,
) -> Result<reqwest::RequestBuilder> {
    let url = server.url("/_cokret/self/events");
    let dpop = holder.dpop_proof("POST", &url, jti_suffix)?;
    Ok(server
        .http()
        .post(&url)
        .bearer_auth(AGENT_SESSION_GRANT)
        .header("DPoP", dpop)
        .header("X-Cokret-Session-Grant-Challenge", "cotest-agent-key-proof")
        .header("X-Cokret-Session-Grant-Proof", "cotest-agent-key-proof-jws")
        .json(event))
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

    fn dpop_proof(&self, method: &str, url: &str, jti_suffix: &str) -> Result<String> {
        let header = json!({
            "alg": "EdDSA",
            "typ": "dpop+jwt",
            "jwk": self.public_jwk,
        });
        let ath = URL_SAFE_NO_PAD.encode(Sha256::digest(AGENT_SESSION_GRANT.as_bytes()));
        let payload = json!({
            "htm": method,
            "htu": url,
            "ath": ath,
            "jti": format!(
                "cotest-agent-live-{jti_suffix}-{}",
                Utc::now().timestamp_nanos_opt().unwrap_or_default()
            ),
            "iat": Utc::now().timestamp(),
        });
        let header_b64 = b64_json(&header)?;
        let payload_b64 = b64_json(&payload)?;
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = self.signing_key.sign(signing_input.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        Ok(format!("{signing_input}.{signature_b64}"))
    }
}

fn b64_json(value: &Value) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(value)?))
}

fn jwk_thumbprint_ed25519(x: &str) -> String {
    let canonical = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}");
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

struct MockIntrospection {
    url: String,
    addr: String,
    running: Arc<AtomicBool>,
    active: Arc<AtomicBool>,
    request_count: Arc<AtomicUsize>,
    service_did: Arc<Mutex<String>>,
    subject: Arc<Mutex<Option<String>>>,
    handle: Option<JoinHandle<()>>,
}

impl MockIntrospection {
    fn spawn(service_did: String, cnf_jkt: String, session_public_key: String) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?.to_string();
        let url = format!("http://{addr}/session-grants/introspect");
        let running = Arc::new(AtomicBool::new(true));
        let active = Arc::new(AtomicBool::new(true));
        let request_count = Arc::new(AtomicUsize::new(0));
        let service_did = Arc::new(Mutex::new(service_did));
        let subject = Arc::new(Mutex::new(None));
        let thread_running = Arc::clone(&running);
        let thread_active = Arc::clone(&active);
        let thread_count = Arc::clone(&request_count);
        let thread_service_did = Arc::clone(&service_did);
        let thread_subject = Arc::clone(&subject);
        let handle = thread::spawn(move || {
            while thread_running.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        thread_count.fetch_add(1, Ordering::SeqCst);
                        handle_introspection_connection(
                            stream,
                            thread_active.load(Ordering::SeqCst),
                            &thread_service_did,
                            &cnf_jkt,
                            &session_public_key,
                            &thread_subject,
                        );
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            url,
            addr,
            running,
            active,
            request_count,
            service_did,
            subject,
            handle: Some(handle),
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

impl Drop for MockIntrospection {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        let _ = TcpStream::connect(&self.addr);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn handle_introspection_connection(
    mut stream: TcpStream,
    active: bool,
    service_did: &Arc<Mutex<String>>,
    cnf_jkt: &str,
    session_public_key: &str,
    subject: &Arc<Mutex<Option<String>>>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let request = read_http_request(&mut stream);
    if !request.contains(&format!(
        "authorization: bearer {}",
        INTROSPECTION_BEARER.to_ascii_lowercase()
    )) {
        write_json_response(
            stream,
            "401 Unauthorized",
            json!({"ok": false, "error": {"errcode": "unauthenticated"}}),
        );
        return;
    }

    let service_did = service_did
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or_else(|_| "did:web:agent-live-e2e.cotest.local".to_owned());
    let subject = subject
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .unwrap_or_else(|| "did:web:agent-unset.example".to_owned());
    let body = if active {
        json!({
            "active": true,
            "status": "active",
            "proof_required": false,
            "one_time_use_consumed": false,
            "grant": {
                // `SessionGrantIntrospectGrant.id` is a typed `GrantId`
                // (`ck:grant:<uuidv7>`); a bare label fails SDK deserialization
                // and soland reports the introspection response as invalid (503).
                "id": "ck:grant:01964137-0000-7000-8000-000000000a01",
                "issuer": "did:web:coauth.cotest.local",
                "subject": subject,
                "service_account_id": "agent-live-e2e-account",
                "audience": service_did,
                "scopes": [
                    "ck.agent.action:message.send",
                    "ck.self.events.command.submit"
                ],
                "expires_at": "2026-12-31T23:59:59Z",
                "revocation_ref": "ck:session:agent-live-e2e-grant",
                "session_public_key": session_public_key,
                "cnf_jkt": cnf_jkt,
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
    write_json_response(stream, "200 OK", body);
}

fn read_http_request(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    let mut header_end = None;
    let mut content_length = None;

    loop {
        let bytes_read = match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(bytes_read) => bytes_read,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(_) => break,
        };
        bytes.extend_from_slice(&buffer[..bytes_read]);

        if header_end.is_none()
            && let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n")
        {
            header_end = Some(position + 4);
            let headers = String::from_utf8_lossy(&bytes[..position]);
            content_length = headers.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            });
        }

        if let Some(header_end) = header_end {
            let expected = header_end + content_length.unwrap_or(0);
            if bytes.len() >= expected {
                break;
            }
        }
    }

    String::from_utf8_lossy(&bytes).to_ascii_lowercase()
}

fn write_json_response(mut stream: TcpStream, status: &str, body: Value) {
    let body = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    let header = format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(&body);
}
