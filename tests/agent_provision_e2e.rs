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
//! NOTE: reply-as-agent enforcement (CKP-0016 §6, the `agent_reply_not_permitted`
//! gate + capability fail-closed) is covered by soland unit tests
//! (`reducer::apply_capability` flag tests + `operations::policy` reply gate);
//! it is intentionally not driven here because the dev fan-out advances the
//! controller's server-side `actor_seq`, which cannot interleave with the
//! harness's independent client-side sequence counter for additional
//! controller-authored events (realm.create / member.state).

use anyhow::Result;
use cotest::harness::{CokretServer, register_account};
use reqwest::StatusCode;
use serde_json::{Value, json};

const ALICE_DID: &str = "did:web:cotest-agent-alice.example";
const ALICE_DEVICE: &str = "ck:device:01904100-0000-7000-8000-00000000a901";

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
