//! COT-STATE-01 — `ak.realm.policy_server` live contract against a real Soland.
//!
//! The fixture suite (`conformance/policy_server.rs`) can only pin the
//! canonical shapes; the observations here come from the running server:
//!
//!   * a declaration becomes a durable Control Move in the canonical Event log, covered by a newly
//!     accepted Seal (the frontier advances past the pre-PUT Seal);
//!   * the `governed_by` organization fallback resolves for a child Realm that has no direct
//!     binding;
//!   * `DELETE` against an inherited-only or never-declared Realm answers `not_found`, appends no
//!     Event and does not advance the Seal frontier;
//!   * with a durable PostgreSQL backend the declaration survives a full process restart.
//!
//! The value-tombstone legs of `policy-server.md` §2.2 are NOT asserted here.
//! They are blocked by
//! `arkret-work/review/spec-open/2026-07-30-cas-register-join-lacks-reachability.md`:
//! `cas_register.join` gets no reachability information, so the second accepted
//! write to the cell joins to `⊥` and every dependent read fails closed. That
//! finding carries the reproduction; once the protocol decides how the join
//! learns reachability, the tombstone / idempotent-repeat / fallback-restored
//! legs belong in this file.

use anyhow::{Result, anyhow};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{ArkretServer, TestActorClient, TestServerGroup, expect_json};
use crate::transcripts::record_vector_event;

fn declaration_body(host: &str) -> Value {
    json!({
        "policy_server_did": format!("did:web:{host}"),
        "policy_server_url": format!("https://{host}/_arkret/self/policy/check"),
        "cache_ttl_seconds": 60,
        "timeout_ms": 1500,
        "on_timeout": "fail_closed",
    })
}

async fn create_policy_realm(
    client: &TestActorClient,
    realm_id: &str,
    title: &str,
) -> Result<String> {
    let created = client
        .create_realm_with(json!({
            "realm_id": realm_id,
            "title": title,
            "summary": title,
            "public": false,
            "plaintext_visible_services": [client.service_id()]
        }))
        .await?;
    client
        .grant_self_realm_actions(realm_id, &["ak.policy.manage"])
        .await?;
    created["realm_id"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("create realm response missing realm_id: {created}"))
}

async fn policy_server_events(client: &TestActorClient, realm_id: &str) -> Result<Vec<Value>> {
    let listed = expect_json(
        client
            .get("/_arkret/self/events")
            .query(&[("realms", realm_id), ("limit", "200")]),
        StatusCode::OK,
    )
    .await?;
    Ok(listed["events"]
        .as_array()
        .ok_or_else(|| anyhow!("events query missing events array: {listed}"))?
        .iter()
        .filter(|event| {
            event["kind"]
                .as_str()
                .or_else(|| event["event_kind"].as_str())
                == Some("ak.realm.policy_server")
        })
        .cloned()
        .collect())
}

async fn accepted_seal_id(client: &TestActorClient, realm_id: &str) -> Result<String> {
    let frontier = expect_json(
        client
            .get("/_arkret/self/events/frontier")
            .query(&[("realm_id", realm_id)]),
        StatusCode::OK,
    )
    .await?;
    let state: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
        serde_json::from_value(frontier.clone())
            .map_err(|error| anyhow!("invalid Realm frontier `{frontier}`: {error}"))?;
    let arkret_models_collaboration::event_sync::EventsFrontierView::RealmSeal(frontier) =
        state.frontier
    else {
        return Err(anyhow!(
            "Realm selector returned the wrong frontier variant"
        ));
    };
    Ok(frontier.seal_id.to_string())
}

async fn get_policy_server(
    client: &TestActorClient,
    realm_id: &str,
) -> Result<(StatusCode, Value)> {
    let response = client
        .get(&format!("/_arkret/self/realms/{realm_id}/policy-server"))
        .send()
        .await?;
    let status = response.status();
    let body = response.json::<Value>().await.unwrap_or(Value::Null);
    Ok((status, body))
}

async fn delete_policy_server(
    client: &TestActorClient,
    realm_id: &str,
) -> Result<(StatusCode, Value)> {
    let response = client
        .delete(&format!("/_arkret/self/realms/{realm_id}/policy-server"))
        .send()
        .await?;
    let status = response.status();
    let body = response.json::<Value>().await.unwrap_or(Value::Null);
    Ok((status, body))
}

async fn put_policy_server(
    client: &TestActorClient,
    realm_id: &str,
    body: &Value,
) -> Result<(StatusCode, Value)> {
    let response = client
        .put(&format!("/_arkret/self/realms/{realm_id}/policy-server"))
        .json(body)
        .send()
        .await?;
    let status = response.status();
    let body = response.json::<Value>().await.unwrap_or(Value::Null);
    Ok((status, body))
}

async fn link_governed_by(client: &TestActorClient, realm_id: &str, target: &str) -> Result<()> {
    let body = expect_json(
        client
            .post(&format!("/_arkret/self/realms/{realm_id}/links"))
            .json(&json!({
                "target_realm_id": target,
                "link_kind": "governed_by",
                "status": "active",
            })),
        StatusCode::OK,
    )
    .await?;
    if body["status"] != "active" {
        return Err(anyhow!("governed_by link did not activate: {body}"));
    }
    Ok(())
}

/// Live declaration → Seal → organization fallback → refused deletes, all
/// observed from the server (Event log + Seal frontier), never echoed from
/// fixture expectations.
pub async fn policy_server_binding_contract_is_live() -> Result<()> {
    let group = TestServerGroup::single("policy-server-live").await?;
    let server = group.server(0);
    let alice = server
        .demo_client(
            "did:web:alice-policy-live.example",
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let child_realm = create_policy_realm(
        &alice,
        "ak:realm:01999999-0000-7000-8000-00000005c001",
        "Policy Server Live Child",
    )
    .await?;
    let org_realm = create_policy_realm(
        &alice,
        "ak:realm:01999999-0000-7000-8000-00000005c002",
        "Policy Server Live Org",
    )
    .await?;
    link_governed_by(&alice, &child_realm, &org_realm).await?;

    // The org declares: durable Control Move + newly accepted Seal.
    let seal_before = accepted_seal_id(&alice, &org_realm).await?;
    let (status, view) =
        put_policy_server(&alice, &org_realm, &declaration_body("org-policy.example")).await?;
    assert_eq!(status, StatusCode::OK, "org PUT: {view}");
    assert_eq!(view["from_org_fallback"], false);
    let declared = policy_server_events(&alice, &org_realm).await?;
    assert_eq!(declared.len(), 1, "declaration events: {declared:?}");
    assert_eq!(
        declared[0]["payload"]["policy_server_did"], "did:web:org-policy.example",
        "declaration event payload: {declared:?}"
    );
    let seal_after_put = accepted_seal_id(&alice, &org_realm).await?;
    assert_ne!(
        seal_before, seal_after_put,
        "declaration Control Move must be covered by a newly accepted Seal"
    );

    // The child resolves the org binding through the governed_by walk.
    let (status, inherited) = get_policy_server(&alice, &child_realm).await?;
    assert_eq!(status, StatusCode::OK, "inherited GET: {inherited}");
    assert_eq!(inherited["policy_server_did"], "did:web:org-policy.example");
    assert_eq!(inherited["from_org_fallback"], true);

    // An inherited binding is not a direct declaration: DELETE answers
    // not_found and must not touch the ancestor.
    let (inherited_status, inherited_body) = delete_policy_server(&alice, &child_realm).await?;
    assert_eq!(
        inherited_status,
        StatusCode::NOT_FOUND,
        "inherited DELETE: {inherited_body}"
    );
    let org_events_after = policy_server_events(&alice, &org_realm).await?;
    assert_eq!(
        org_events_after.len(),
        1,
        "an inherited DELETE must not append to the ancestor: {org_events_after:?}"
    );
    let seal_after_refusal = accepted_seal_id(&alice, &org_realm).await?;
    assert_eq!(
        seal_after_put, seal_after_refusal,
        "a refused DELETE must not advance the accepted Seal frontier"
    );

    // A Realm with neither a direct binding nor a governed_by chain.
    let never_declared = create_policy_realm(
        &alice,
        "ak:realm:01999999-0000-7000-8000-00000005c003",
        "Policy Server Live Never",
    )
    .await?;
    let (missing_status, missing_body) = delete_policy_server(&alice, &never_declared).await?;
    assert_eq!(
        missing_status,
        StatusCode::NOT_FOUND,
        "never-declared DELETE: {missing_body}"
    );

    record_vector_event(
        "policy_server.binding_tombstone",
        &json!({"realm_id": child_realm, "org_realm_id": org_realm}),
        &json!({
            "missing_direct_history_delete": "not_found",
            "delete_inherited_value_mutates_ancestor": false,
            "from_org_fallback": true,
            "declaration_accepted_after_seal": true,
        }),
        &json!({
            "declaration_seal_advanced": seal_before != seal_after_put,
            "declaration_events": declared.len(),
            "inherited_delete": inherited_status.as_u16(),
            "inherited_delete_appended_to_ancestor":
                org_events_after.len() - declared.len(),
            "inherited_delete_seal_advanced": seal_after_put != seal_after_refusal,
            "missing_direct_history_delete": missing_status.as_u16(),
            "fallback_policy_server_did": inherited["policy_server_did"].clone(),
        }),
    );
    Ok(())
}

/// With a durable PostgreSQL backend the declaration must come back after a
/// full process restart.
///
/// Requires the pre-built external Soland binary and
/// `COTEST_POLICY_LIVE_DATABASE_URL`; skips (with a log line) otherwise.
pub async fn policy_server_declaration_survives_restart() -> Result<()> {
    let Ok(database_url) = std::env::var("COTEST_POLICY_LIVE_DATABASE_URL") else {
        eprintln!(
            "skipping policy-server restart scenario: COTEST_POLICY_LIVE_DATABASE_URL is unset"
        );
        return Ok(());
    };
    if crate::scenarios::_helpers::external_binary::locate_external_binary(
        &crate::scenarios::_helpers::external_binary::SOLAND_SPEC,
    )
    .is_none()
    {
        eprintln!(
            "skipping policy-server restart scenario: no pre-built Soland binary (set SOLAND_BIN)"
        );
        return Ok(());
    }
    let mut server =
        ArkretServer::spawn_with_database_url("policy-server-live-restart", &database_url, &[])
            .await?;
    let alice = server
        .demo_client(
            "did:web:alice-policy-restart.example",
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let realm_id = create_policy_realm(
        &alice,
        "ak:realm:01999999-0000-7000-8000-00000005c011",
        "Policy Server Restart",
    )
    .await?;

    let (status, view) = put_policy_server(
        &alice,
        &realm_id,
        &declaration_body("restart-policy.example"),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "PUT before restart: {view}");
    let declared = policy_server_events(&alice, &realm_id).await?;
    assert_eq!(declared.len(), 1, "declaration events: {declared:?}");

    server.restart_external_process().await?;

    let (status, restored) = get_policy_server(&alice, &realm_id).await?;
    assert_eq!(status, StatusCode::OK, "restarted GET: {restored}");
    assert_eq!(
        restored["policy_server_did"], "did:web:restart-policy.example",
        "the declaration must survive restart: {restored}"
    );
    let events = policy_server_events(&alice, &realm_id).await?;
    assert_eq!(
        events.len(),
        1,
        "the durable log must retain the declaration after restart: {events:?}"
    );

    record_vector_event(
        "policy_server.tombstone_federation_replay",
        &json!({"realm_id": realm_id}),
        &json!({"restart_replay_restores_declaration": true}),
        &json!({
            "post_restart_get": status.as_u16(),
            "post_restart_policy_server_did": restored["policy_server_did"].clone(),
            "durable_policy_events": events.len(),
        }),
    );
    Ok(())
}
