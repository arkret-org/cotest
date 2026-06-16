//! Personal AI Agent provisioning -> pairing -> participation -> reply ->
//! lifecycle, driven live against a spawned soland in development mode
//! (CKP-0008 / CKP-0016, spec_section_11 live leg).
//!
//! Exercises the dev-mode server-authored fan-out (architecture option B):
//!   1. `ck.self.agent.command.provision` -> `pending_runtime_key` + pairing.
//!   2. `ck.gate.account.command.pair_agent_key` -> durable
//!      `ck.agent.key.authorize`, clears `effective_after_first_authorized_key`,
//!      status -> `active`.
//!   3. participation `reply=true` materialises a `ck.message.create` grant;
//!      a native agent without it is denied `agent_reply_not_permitted`.
//!   4. pause / resume / deactivate land durable lifecycle events.
//!
//! Spawns the sibling `soland` binary; `CokretServer::spawn` builds / locates
//! it and runs it in development mode (in-memory-or-default store, no docker).

use anyhow::Result;
use cotest::harness::{
    CokretServer, add_member, create_realm, dev_login, event_envelope, register_account,
    submit_event,
};
use reqwest::StatusCode;
use serde_json::{Value, json};

const ALICE_DID: &str = "did:web:cotest-agent-alice.example";
const ALICE_DEVICE: &str = "ck:device:01904100-0000-7000-8000-00000000a901";
const AGENT_DEVICE: &str = "ck:device:01904100-0000-7000-8000-00000000a9e7";

#[tokio::test(flavor = "multi_thread")]
async fn agent_provision_pair_reply_lifecycle_e2e() -> Result<()> {
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
    assert_eq!(prov.status(), StatusCode::CREATED, "provision must return 201");
    let prov: Value = prov.json().await?;
    let agent_did = prov["agent_principal_id"].as_str().expect("agent_principal_id").to_owned();
    assert!(prov["pairing_request_id"].as_str().is_some(), "pairing_request_id present");
    assert!(prov["pairing_code"].as_str().is_some(), "pairing_code present");

    assert_eq!(agent_status(&server, &token, &agent_did).await?, "pending_runtime_key");

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
    assert!(pair["authorized_event_ref"].as_str().is_some(), "authorized_event_ref present");
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "active");

    // 3. controller realm with the agent as a member, then reply enforcement.
    let realm = create_realm(&server, &token, ALICE_DID, "Agent Realm").await?;
    add_member(&server, &token, ALICE_DID, &realm, &agent_did).await?;
    let agent_token = dev_login(&server, &agent_did, AGENT_DEVICE).await?;

    // Without a participation `reply` selection the native agent MUST be denied
    // (reply gate `agent_reply_not_permitted` / capability fail-closed). Accept
    // any client-error rather than pinning the exact precedence code.
    let blocked = event_envelope(&agent_did, &realm, "ck.message.create", json!({"body": "blocked before participation"}));
    let denied = server
        .http()
        .post(server.url("/_cokret/self/events"))
        .bearer_auth(&agent_token)
        .json(&blocked)
        .send()
        .await?;
    assert!(
        denied.status().is_client_error(),
        "agent reply before participation MUST be denied, got {}",
        denied.status()
    );

    // Grant reply participation for the realm scope (materialises the grant).
    let part = server
        .http()
        .put(server.url(&format!(
            "/_cokret/self/agents/{}/participation",
            urlencoding(&agent_did)
        )))
        .bearer_auth(&token)
        .json(&json!({
            "scope": {"kind": "realm", "realm_id": realm},
            "selection": {"reply": true, "accept_third_party_mention": false, "act_on_behalf": false}
        }))
        .send()
        .await?;
    assert_eq!(part.status(), StatusCode::OK, "participation set must return 200");

    // Now the agent reply is permitted.
    submit_event(
        &server,
        &agent_token,
        &agent_did,
        &realm,
        "ck.message.create",
        json!({"body": "allowed after participation"}),
        StatusCode::OK,
    )
    .await?;

    // 4. lifecycle transitions land durable events + flip projected status.
    for (path, expect) in [("pause", "paused"), ("resume", "active"), ("deactivate", "deactivated")] {
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
        assert_eq!(res.status(), StatusCode::OK, "lifecycle {path} must return 200");
        assert_eq!(agent_status(&server, &token, &agent_did).await?, expect, "status after {path}");
    }

    Ok(())
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

fn urlencoding(did: &str) -> String {
    did.replace(':', "%3A").replace('/', "%2F")
}
