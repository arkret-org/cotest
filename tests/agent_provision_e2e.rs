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
use chrono::Utc;
use cotest::harness::{
    CokretServer, add_member, create_realm, event_envelope, expect_api_error, expect_json,
    register_account,
};
use ed25519_dalek::{Signer, SigningKey};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const ALICE_DID: &str = "did:web:cotest-agent-alice.example";
const ALICE_DEVICE: &str = "ck:device:01904100-0000-7000-8000-00000000a901";
const AGENT_SESSION_GRANT: &str = "cotest.agent.session.grant";
const INTROSPECTION_BEARER: &str = "cotest-introspection-bearer";

#[tokio::test(flavor = "multi_thread")]
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
    let pair = server
        .http()
        .post(server.url("/_cokret/gate/account/agent-key-pair"))
        .bearer_auth(&token)
        .json(&json!({
            "pairing_request_id": prov["pairing_request_id"],
            "agent_principal_id": agent_did,
            "verification_method": format!("{agent_did}#runtime-key-1"),
            "public_key": {"key_type": "Ed25519", "public_key_multibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"},
            "proof_of_possession": {
                "challenge": "YWJj",
                "audience": server.url("").trim_end_matches('/'),
                "request_canonical_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "expires_at": "2026-12-31T23:59:59Z",
                "signature": "YQ"
            }
        }))
        .send()
        .await?;
    assert_eq!(pair.status(), StatusCode::OK, "pairing must return 200");
    let pair: Value = pair.json().await?;
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
async fn agent_key_proof_session_reply_and_revoke_live_e2e() -> Result<()> {
    let service_name = "agent-live-e2e";
    let service_did = format!("did:web:{service_name}.cotest.local");
    let holder = AgentSessionHolder::new();
    let mock = MockIntrospection::spawn(
        service_did.clone(),
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

    let agent_message = event_envelope(
        &agent_did,
        &realm_id,
        "ck.message.create",
        json!({
            "body": "agent_key_proof live reply",
            "content": {"body": "agent_key_proof live reply"},
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

    let pair = server
        .http()
        .post(server.url("/_cokret/gate/account/agent-key-pair"))
        .bearer_auth(token)
        .json(&json!({
            "pairing_request_id": prov["pairing_request_id"],
            "agent_principal_id": agent_did,
            "verification_method": format!("{agent_did}#runtime-key-1"),
            "public_key": {"key_type": "Ed25519", "public_key_multibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"},
            "proof_of_possession": {
                "challenge": "YWJj",
                "audience": server.url("").trim_end_matches('/'),
                "request_canonical_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "expires_at": "2026-12-31T23:59:59Z",
                "signature": "YQ"
            }
        }))
        .send()
        .await?;
    assert_eq!(pair.status(), StatusCode::OK, "pairing must return 200");
    let pair: Value = pair.json().await?;
    assert!(
        pair["authorized_event_ref"].as_str().is_some(),
        "authorized_event_ref present"
    );
    assert_eq!(agent_status(server, token, &agent_did).await?, "active");
    Ok(agent_did)
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
    let effective: Value = server
        .http()
        .get(server.url("/_cokret/self/authz/effective-grants"))
        .bearer_auth(token)
        .query(&[("subject", agent_did)])
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
        let subject = Arc::new(Mutex::new(None));
        let thread_running = Arc::clone(&running);
        let thread_active = Arc::clone(&active);
        let thread_count = Arc::clone(&request_count);
        let thread_subject = Arc::clone(&subject);
        let handle = thread::spawn(move || {
            while thread_running.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        thread_count.fetch_add(1, Ordering::SeqCst);
                        handle_introspection_connection(
                            stream,
                            thread_active.load(Ordering::SeqCst),
                            &service_did,
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
    service_did: &str,
    cnf_jkt: &str,
    session_public_key: &str,
    subject: &Arc<Mutex<Option<String>>>,
) {
    let mut buffer = [0_u8; 4096];
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let bytes_read = stream.read(&mut buffer).unwrap_or(0);
    let request = String::from_utf8_lossy(&buffer[..bytes_read]).to_ascii_lowercase();
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
                "scopes": ["ck.agent.action:message.send"],
                "expires_at": "2026-12-31T23:59:59Z",
                "revocation_ref": "ck:session:agent-live-e2e-grant",
                "session_public_key": session_public_key,
                "cnf_jkt": cnf_jkt,
                "proof_kind": "agent_key_proof",
                "scope_details": {
                    "agent_principal_id": subject,
                    "controller_did": ALICE_DID,
                    "resources": {"realm_refs": ["*"]}
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

fn write_json_response(mut stream: TcpStream, status: &str, body: Value) {
    let body = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    let header = format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(&body);
}
