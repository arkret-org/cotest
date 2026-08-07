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
use anyhow::{Result, anyhow};
use arkret_models_collaboration::governance::realm_governance::{
    RealmLinkCreateRequestBody, RealmPolicyServerDeleteRequestBody,
    RealmPolicyServerReplaceRequestBody,
};
use arkret_wire::EventInitialSubmission;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    ArkretServer, CanonicalJsonBody, TestActorClient, TestServerGroup, events_query_for_realm,
    expect_json, head_eq_precondition,
};

/// The one cell every `ak.realm.policy_server` write moves.
const POLICY_SERVER_CELL: &str = "ak:cell:ak.component.realm.policy_server.v1:null";
use crate::transcripts::record_vector_event;

/// The declaration the caller signs. It is the durable payload the reducer
/// stores, not a narrower REST projection of it: the request body carries the
/// signed Event and nothing else.
fn declaration_payload(host: &str) -> Value {
    json!({
        "policy_server_did": format!("did:web:{host}"),
        "policy_server_url": format!("https://{host}/_arkret/self/policy/check"),
        "cache_ttl_seconds": 60,
        "timeout_ms": 1500,
        "on_timeout": "fail_closed",
    })
}

async fn create_policy_realm(client: &TestActorClient, title: &str) -> Result<String> {
    let created = client
        .create_realm_with(json!({
            "title": title,
            "summary": title,
            "public": false,
            "plaintext_visible_services": [client.service_id()]
        }))
        .await?;
    // The Realm id is derived from the genesis Event. Granting against anything
    // else addresses a Realm that was never created, which the server answers
    // with `realm not found`.
    let realm_id = created["realm_id"]
        .as_str()
        .ok_or_else(|| anyhow!("create realm response missing realm_id: {created}"))?
        .to_owned();
    client
        .grant_self_realm_actions(&realm_id, &["ak.policy.manage"])
        .await?;
    Ok(realm_id)
}

async fn policy_server_events(client: &TestActorClient, realm_id: &str) -> Result<Vec<Value>> {
    let listed = expect_json(
        client
            .query("/_arkret/self/events")
            .json(&events_query_for_realm(realm_id, 200)?),
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
    let frontier = client.realm_seal_frontier(realm_id).await?;
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
    settled: Option<Value>,
) -> Result<(StatusCode, Value)> {
    // The DELETE carries a body because the removal is a signed Event, and the
    // caller attaches its own `head_eq`: a precondition is inside the bytes it
    // signs, so the service cannot add one for it.
    let preconditions = settled
        .map(|value| vec![head_eq_precondition(POLICY_SERVER_CELL, value)])
        .unwrap_or_default();
    let request = RealmPolicyServerDeleteRequestBody {
        policy_server_event: EventInitialSubmission::online(
            client
                .author_event_with_preconditions(
                    realm_id,
                    arkret_wire::EventKind::REALM_POLICY_SERVER,
                    json!({ "tombstone": true }),
                    preconditions,
                )
                .await?,
        ),
    };
    let response = client
        .delete(&format!("/_arkret/self/realms/{realm_id}/policy-server"))
        .canonical_json(&request)?
        .send()
        .await?;
    let status = response.status();
    let body = response.json::<Value>().await.unwrap_or(Value::Null);
    Ok((status, body))
}

async fn put_policy_server(
    client: &TestActorClient,
    realm_id: &str,
    declaration: Value,
) -> Result<(StatusCode, Value)> {
    let request = RealmPolicyServerReplaceRequestBody {
        policy_server_event: EventInitialSubmission::online(
            client
                .author_event(
                    realm_id,
                    arkret_wire::EventKind::REALM_POLICY_SERVER,
                    declaration,
                )
                .await?,
        ),
    };
    let response = client
        .put(&format!("/_arkret/self/realms/{realm_id}/policy-server"))
        .canonical_json(&request)?
        .send()
        .await?;
    let status = response.status();
    let body = response.json::<Value>().await.unwrap_or(Value::Null);
    Ok((status, body))
}

async fn link_governed_by(client: &TestActorClient, realm_id: &str, target: &str) -> Result<()> {
    let request = RealmLinkCreateRequestBody {
        link_event: EventInitialSubmission::online(
            client
                .author_event(
                    realm_id,
                    arkret_wire::EventKind::REALM_LINK,
                    json!({
                        "target_realm_id": target,
                        "link_kind": "governed_by",
                        "status": "active",
                    }),
                )
                .await?,
        ),
    };
    let body = expect_json(
        client
            .post(&format!("/_arkret/self/realms/{realm_id}/links"))
            .canonical_json(&request)?,
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
    let child_realm = create_policy_realm(&alice, "Policy Server Live Child").await?;
    let org_realm = create_policy_realm(&alice, "Policy Server Live Org").await?;
    link_governed_by(&alice, &child_realm, &org_realm).await?;

    // The org declares: durable Control Move + newly accepted Seal.
    let seal_before = accepted_seal_id(&alice, &org_realm).await?;
    let (status, view) = put_policy_server(
        &alice,
        &org_realm,
        declaration_payload("org-policy.example"),
    )
    .await?;
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
    // No settled direct value to guard: the refusal is `not_found`, before any
    // precondition could apply.
    let (inherited_status, inherited_body) =
        delete_policy_server(&alice, &child_realm, None).await?;
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

    // A settled direct child declaration can be tombstoned. The tombstone
    // restores organization fallback, and repeating DELETE appends nothing.
    let child_declaration = declaration_payload("child-policy.example");
    let (status, direct) =
        put_policy_server(&alice, &child_realm, child_declaration.clone()).await?;
    assert_eq!(status, StatusCode::OK, "child PUT: {direct}");
    let (deleted_status, deleted) =
        delete_policy_server(&alice, &child_realm, Some(child_declaration)).await?;
    assert_eq!(deleted_status, StatusCode::OK, "child DELETE: {deleted}");
    let child_events = policy_server_events(&alice, &child_realm).await?;
    assert_eq!(child_events.len(), 2, "declaration plus tombstone");
    assert_eq!(child_events[1]["payload"]["tombstone"], true);
    let (fallback_status, fallback) = get_policy_server(&alice, &child_realm).await?;
    assert_eq!(
        fallback_status,
        StatusCode::OK,
        "fallback after DELETE: {fallback}"
    );
    assert_eq!(fallback["policy_server_did"], "did:web:org-policy.example");
    assert_eq!(fallback["from_org_fallback"], true);
    // A settled tombstone answers empty-success without admitting the Event, so
    // the repeat needs no guard of its own.
    let (repeat_status, repeat) = delete_policy_server(&alice, &child_realm, None).await?;
    assert_eq!(repeat_status, StatusCode::OK, "repeat DELETE: {repeat}");
    assert_eq!(policy_server_events(&alice, &child_realm).await?.len(), 2);

    // A Realm with neither a direct binding nor a governed_by chain.
    let never_declared = create_policy_realm(&alice, "Policy Server Live Never").await?;
    let (missing_status, missing_body) =
        delete_policy_server(&alice, &never_declared, None).await?;
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
            "settled_delete": deleted_status.as_u16(),
            "repeat_delete": repeat_status.as_u16(),
            "fallback_after_tombstone": fallback["policy_server_did"].clone(),
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
    let realm_id = create_policy_realm(&alice, "Policy Server Restart").await?;

    let restart_declaration = declaration_payload("restart-policy.example");
    let (status, view) = put_policy_server(&alice, &realm_id, restart_declaration.clone()).await?;
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

    let (delete_status, deleted) =
        delete_policy_server(&alice, &realm_id, Some(restart_declaration)).await?;
    assert_eq!(
        delete_status,
        StatusCode::OK,
        "DELETE after restart: {deleted}"
    );
    server.restart_external_process().await?;
    let (tombstone_status, tombstoned) = get_policy_server(&alice, &realm_id).await?;
    assert_eq!(
        tombstone_status,
        StatusCode::NOT_FOUND,
        "tombstone after second restart: {tombstoned}"
    );
    let events = policy_server_events(&alice, &realm_id).await?;
    assert_eq!(events.len(), 2, "declaration and tombstone remain durable");

    record_vector_event(
        "policy_server.tombstone_federation_replay",
        &json!({"realm_id": realm_id}),
        &json!({
            "restart_replay_restores_declaration": true,
            "restart_replay_restores_tombstone": true
        }),
        &json!({
            "post_restart_get": status.as_u16(),
            "post_restart_policy_server_did": restored["policy_server_did"].clone(),
            "post_tombstone_restart_get": tombstone_status.as_u16(),
            "durable_policy_events": events.len(),
        }),
    );
    Ok(())
}
