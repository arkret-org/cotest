//! Personal AI Agent provisioning -> pairing -> lifecycle, driven live against
//! a spawned soland in development mode (AKP-0008, spec_section_11 live leg).
//!
//! Exercises the dev-mode server-authored fan-out (architecture option B) end
//! to end through the public agent HTTP surface:
//!   1. `ak.self.agent.command.provision` -> `pending_runtime_key` + pairing.
//!   2. `ak.gate.account.command.pair_agent_key` -> durable `ak.agent.key.authorize`, clears
//!      `effective_after_first_authorized_key`, status -> `active`.
//!   3. grant attach / detach -> durable `ak.capability.grant` / `ak.capability.revoke`.
//!   4. pause / resume / deactivate -> durable lifecycle events flip status.
//!
//! `ArkretServer::spawn` builds / locates the sibling `soland` binary and runs
//! it in development mode. The agent endpoints internally author their durable
//! fan-out events, so this test needs no client-side event signing.
//!
//! The second test also drives the cross-service session leg by presenting a
//! DPoP-bound `agent_key_proof` session grant and backing soland with a local
//! introspection service.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow};
use arkret_core::{Error as ArkretError, EventsSubscribeFrameKind};
use arkret_http_client::{Auth, Client as SdkClient, ClientBuilder, EventsSubscribeOptions};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{SecondsFormat, Utc};
use cotest::harness::{
    ArkretServer, add_member, create_realm, event_envelope, register_account, submit_event,
};
use cotest::scenarios::_helpers::mock_http::{self, MockServer};
use ed25519_dalek::SigningKey;
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
    let server = ArkretServer::spawn("agent-provision-e2e").await?;
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
                    "actions": ["ak.event.read"]
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

/// `ak.self.agent.command.renew_pairing` (decision 0007): an expired pairing
/// renews IN PLACE on the same agent principal. The renewed handle is fresh
/// and single-use, the dead handle stays permanently unresolvable, and the
/// renewed pairing completes to `active` without provisioning a replacement.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn agent_pairing_renewal_e2e() -> Result<()> {
    let server = ArkretServer::spawn("agent-pairing-renewal-e2e").await?;
    let token = register_account(&server, ALICE_DID, "@cotest-agent-alice", ALICE_DEVICE).await?;
    let controller = bearer_sdk_client(&server, &token)?;

    // Provision with a 1 ms pairing window so the handle is already dead.
    let prov = controller
        .agent_provision(&arkret::AgentProvisionRequestBody {
            display_name: Some("Renewal Assistant".to_owned()),
            slug: "renewal".to_owned(),
            avatar_blob_ref: None,
            requested_scope: None,
            accountability: Value::Null,
            pairing_ttl_ms: Some(1),
        })
        .await?;
    let agent_did = prov.agent_id.to_string();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    // Lazy expiry flips the projected status on first observation.
    assert_eq!(
        agent_status(&server, &token, &agent_did).await?,
        "pairing_expired"
    );

    // Renewal: same principal, fresh handle, status back to pending.
    let renewed = controller
        .agent_renew_pairing(&agent_did, &arkret::AgentRenewPairingRequestBody::default())
        .await?;
    assert_eq!(renewed.agent_id.to_string(), agent_did, "same principal");
    assert_ne!(
        renewed.pairing_request_id, prov.pairing_request_id,
        "renewed pairing_request_id must be fresh"
    );
    assert!(
        renewed.pairing_code.is_some(),
        "renewed pairing_code present"
    );
    assert_ne!(
        renewed.pairing_code, prov.pairing_code,
        "renewed pairing_code must be fresh"
    );
    assert_eq!(
        agent_status(&server, &token, &agent_did).await?,
        "pending_runtime_key"
    );

    // The dead handle must stay unresolvable: pairing with the ORIGINAL
    // provision tuple fails even though the agent is pending again.
    let stale = pair_agent_runtime_key(&server, &token, &prov).await;
    assert!(
        stale.is_err(),
        "pairing with the expired handle must fail after renewal"
    );
    assert_eq!(
        agent_status(&server, &token, &agent_did).await?,
        "pending_runtime_key"
    );

    // The renewed handle completes pairing to active on the same principal.
    let pair = pair_agent_runtime_key(&server, &token, &renewed).await?;
    assert!(
        !pair.authorized_event_ref.as_str().is_empty(),
        "authorized_event_ref present"
    );
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "active");

    // Runtime replacement re-pairing (key-management §3.6.1): renewing an
    // ACTIVE agent is allowed, is NOT a state transition, and never touches
    // existing keys or grants until the new pairing completes.
    let replacement = controller
        .agent_renew_pairing(&agent_did, &arkret::AgentRenewPairingRequestBody::default())
        .await?;
    assert_eq!(
        replacement.agent_id.to_string(),
        agent_did,
        "same principal"
    );
    assert_ne!(
        replacement.pairing_request_id, renewed.pairing_request_id,
        "replacement pairing_request_id must be fresh"
    );
    assert_eq!(
        agent_status(&server, &token, &agent_did).await?,
        "active",
        "replacement re-pairing must not change agent status"
    );

    // A dead handle stays unresolvable and previously-keyed agents never
    // fall back to pairing_expired.
    let stale = pair_agent_runtime_key(&server, &token, &renewed).await;
    assert!(
        stale.is_err(),
        "pairing with the superseded handle must fail"
    );
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "active");

    // Completing the replacement pairing with a DISTINCT runtime key keeps
    // the agent active and supersedes the prior key in the same accepted
    // fan-out (reason=superseded_by_repairing).
    let replaced =
        pair_agent_runtime_key_as(&server, &token, &replacement, "runtime-key-2").await?;
    assert!(
        !replaced.authorized_event_ref.as_str().is_empty(),
        "replacement authorized_event_ref present"
    );
    assert_ne!(
        replaced.authorized_event_ref, pair.authorized_event_ref,
        "replacement authorization is a fresh event"
    );
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "active");

    // Replacement handle expiry has zero side effects: open a 1 ms handle,
    // let it die, and the agent stays active (never pairing_expired).
    let short_lived = controller
        .agent_renew_pairing(
            &agent_did,
            &arkret::AgentRenewPairingRequestBody {
                pairing_ttl_ms: Some(1),
            },
        )
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert_eq!(
        agent_status(&server, &token, &agent_did).await?,
        "active",
        "an expired replacement handle must not touch agent state"
    );
    let expired = pair_agent_runtime_key_as(&server, &token, &short_lived, "runtime-key-3").await;
    assert!(expired.is_err(), "expired replacement handle must be dead");
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "active");
    Ok(())
}

/// AKP-0008 runtime-side approval status poll
/// (`ak.open.agent_pairing.query.runtime_key_request_status`): the runtime
/// learns the controller decision after submitting a runtime key request
/// (cotask 2026-07-10-agent-runtime-approval-status-closure acceptance #5).
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn agent_runtime_key_request_status_poll_e2e() -> Result<()> {
    let server = ArkretServer::spawn("agent-approval-status-e2e").await?;
    let token = register_account(&server, ALICE_DID, "@cotest-agent-alice", ALICE_DEVICE).await?;
    let controller = bearer_sdk_client(&server, &token)?;
    let prov = controller
        .agent_provision(&arkret::AgentProvisionRequestBody {
            display_name: Some("Status Poll Assistant".to_owned()),
            slug: "statuspoll".to_owned(),
            avatar_blob_ref: None,
            requested_scope: None,
            accountability: Value::Null,
            pairing_ttl_ms: None,
        })
        .await?;
    let agent_did = prov.agent_id.to_string();
    let status_body = arkret::models::AgentRuntimeApprovalStatusRequestBody {
        pairing_request_id: prov.pairing_request_id.clone(),
        pairing_code: prov
            .pairing_code
            .clone()
            .ok_or_else(|| anyhow!("pairing_code missing"))?,
        agent_id: prov.agent_id.clone(),
    };

    // 1. Open pairing, nothing submitted yet: pending without an approval_request_id or any
    //    authorized binding.
    let status = controller
        .agent_runtime_approval_status(&status_body)
        .await?;
    assert_eq!(
        status.status,
        arkret::models::AgentStatus::PendingRuntimeKey
    );
    assert!(status.approval_request_id.is_none());
    assert!(status.authorized_event_ref.is_none());
    assert!(status.authorized_public_key_digest.is_none());

    // 2. Runtime submits the open approval request; the poll echoes its id.
    let approval_request = build_runtime_approval_request(&server, &prov)?;
    let submitted = controller
        .agent_runtime_approval_request(&approval_request)
        .await?;
    assert!(submitted.ok);
    let status = controller
        .agent_runtime_approval_status(&status_body)
        .await?;
    assert_eq!(
        status.status,
        arkret::models::AgentStatus::PendingRuntimeKey
    );
    assert_eq!(
        status.approval_request_id.as_deref(),
        Some(submitted.approval_request_id.as_str())
    );

    // 3. Anti-enumeration: a wrong pairing_code is indistinguishable from an unknown
    //    pairing_request_id.
    let wrong_code = arkret::models::AgentRuntimeApprovalStatusRequestBody {
        pairing_code: "00000000".to_owned(),
        ..status_body.clone()
    };
    expect_sdk_api_error(
        controller.agent_runtime_approval_status(&wrong_code).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )?;

    // 4. Controller approves; the poll flips to active and hands the runtime the exact key binding
    //    the controller authorized.
    let pair = pair_agent_runtime_key(&server, &token, &prov).await?;
    let status = controller
        .agent_runtime_approval_status(&status_body)
        .await?;
    assert_eq!(status.status, arkret::models::AgentStatus::Active);
    assert!(status.approval_request_id.is_none());
    assert_eq!(
        status.authorized_event_ref.as_ref().map(|id| id.as_str()),
        Some(pair.authorized_event_ref.as_str())
    );
    let signing_key = runtime_signing_key();
    let builder = runtime_key_request_builder(&server, &prov, &signing_key)?;
    let verification_method = format!("{agent_did}#runtime-key-1");
    assert_eq!(
        status.authorized_verification_method.as_deref(),
        Some(verification_method.as_str())
    );
    let local_digest = builder.public_key_digest()?;
    assert_eq!(
        status.authorized_public_key_digest.as_deref(),
        Some(local_digest.as_str())
    );
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
    let server = ArkretServer::spawn_with_env(
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
    mock.set_service_id(server.service_id().to_owned());
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
        "ak.strand.create",
        json!({
            "object": {
                "id": default_strand_id,
                "schema": "ak.schema.strand.v1",
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

    // AKP-0016 §5.2: every agent-originated Event carries an auditable
    // `agent_context` whose `authorization_ref` MUST resolve to an active
    // capability grant for the agent IN THE EVENT'S REALM, with an action
    // covering the operation's canonical kind. Grant the agent `ak.message.create`
    // in the reply Realm so the reply's agent_context references a real grant.
    let agent_grant_id = "ak:grant:01999999-0000-7000-8000-0000000000c1";
    let agent_grant = submit_event(
        &server,
        &token,
        ALICE_DID,
        &realm_id,
        "ak.capability.grant",
        json!({
            "grant_id": agent_grant_id,
            "grant": {
                "id": agent_grant_id,
                "schema": "ak.schema.capability.v1",
                "realm_id": realm_id,
                "issuer": ALICE_DID,
                "subject": agent_did,
                "actions": ["ak.message.create"],
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
        "ak.message.create",
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

    // Catch-up replay now requires an `after` cursor (the old
    // include-history-from-genesis stream semantics are gone), so cover the
    // agent streaming surface with the live leg instead: subscribe first,
    // submit another agent-authored event, and expect its live frame.
    let mut stream = agent_client
        .events_subscribe_frames(&EventsSubscribeOptions::new().realm(realm_id.clone()))
        .await?;
    let live_message = event_envelope(
        &agent_did,
        &realm_id,
        "ak.message.create",
        json!({
            "body": "agent_key_proof live stream",
            "content": {"body": "agent_key_proof live stream"},
            "agent_context": {
                "agent_id": agent_did,
                "operator_or_controller": ALICE_DID,
                "execution_purpose": "reply",
                "authorization_ref": agent_grant_id,
            },
        }),
    );
    let live_event_id = live_message["event_id"]
        .as_str()
        .expect("live message event_id")
        .to_owned();
    let accepted_live = agent_client
        .events_submit(&event_from_value(&live_message)?)
        .await?;
    assert_eq!(
        accepted_live
            .accepted
            .first()
            .map(|event_id| event_id.to_string())
            .as_deref(),
        Some(live_event_id.as_str()),
        "agent live message must be accepted"
    );
    let mut saw_live_event = false;
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        while let Some(frame) = stream.next_frame().await? {
            if frame.kind == EventsSubscribeFrameKind::Event
                && serde_json::to_string(&frame)
                    .is_ok_and(|frame_json| frame_json.contains(&live_event_id))
            {
                saw_live_event = true;
                break;
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow!("agent stream did not deliver live event {live_event_id} within 15s"))??;
    assert!(
        saw_live_event,
        "DPoP-bound agent stream must deliver the accepted live event {live_event_id}"
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
        "ak.message.create",
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
        "ak.message.create",
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
        "ak.message.create",
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
    server: &ArkretServer,
    token: &str,
    display_name: &str,
    slug: &str,
) -> Result<String> {
    let controller = bearer_sdk_client(server, token)?;
    let prov = controller
        .agent_provision(&arkret::AgentProvisionRequestBody {
            display_name: Some(display_name.to_owned()),
            slug: slug.to_owned(),
            avatar_blob_ref: None,
            requested_scope: None,
            accountability: Value::Null,
            pairing_ttl_ms: None,
        })
        .await?;
    let agent_did = prov.agent_id.to_string();
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

/// Deterministic local runtime key material shared by the pairing and the
/// approval-status tests: verification method, Ed25519 signing key, and the
/// spec-shape OKP public key JWK.
fn runtime_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[13_u8; 32])
}

fn runtime_key_request_builder<'a>(
    server: &ArkretServer,
    provisioned: &arkret::AgentProvisionOutcome,
    signing_key: &'a SigningKey,
) -> Result<arkret::agent::RuntimeKeyRequestBuilder<'a>> {
    let pairing_code = provisioned
        .pairing_code
        .clone()
        .ok_or_else(|| anyhow!("pairing_code missing"))?;
    let service_id = arkret::Did::new(server.service_id().to_owned())?;
    let proof_expires_at =
        chrono::DateTime::parse_from_rfc3339("2999-01-01T00:00:00.000Z")?.with_timezone(&Utc);
    Ok(arkret::agent::RuntimeKeyRequestBuilder::new(
        signing_key,
        arkret::AgentPairingBootstrap {
            arkret_base_url: server.base_url().to_string(),
            service_id,
            agent_id: provisioned.agent_id.clone(),
            pairing_request_id: provisioned.pairing_request_id.clone(),
            pairing_code,
            pairing_expires_at: provisioned.expires_at,
        },
    )
    .proof_expires_at(proof_expires_at))
}

/// Build the open `agent_runtime_approval_request_body` a runtime submits to
/// `POST /_arkret/open/agent-pairing/runtime-key-requests`, from the same key
/// material as [`pair_agent_runtime_key`].
fn build_runtime_approval_request(
    server: &ArkretServer,
    provisioned: &arkret::AgentProvisionOutcome,
) -> Result<arkret::AgentRuntimeApprovalRequestBody> {
    let signing_key = runtime_signing_key();
    Ok(
        runtime_key_request_builder(server, provisioned, &signing_key)?
            .build_approval_request()?
            .body,
    )
}

async fn pair_agent_runtime_key(
    server: &ArkretServer,
    token: &str,
    provisioned: &arkret::AgentProvisionOutcome,
) -> Result<arkret::AgentKeyPairOutcome> {
    pair_agent_runtime_key_as(server, token, provisioned, "runtime-key-1").await
}

/// [`pair_agent_runtime_key`] with an explicit verification-method fragment.
/// Runtime replacement re-pairing uses a distinct fragment so the new key is
/// a distinct key id and the pair completion supersedes the old one.
async fn pair_agent_runtime_key_as(
    server: &ArkretServer,
    token: &str,
    provisioned: &arkret::AgentProvisionOutcome,
    fragment: &str,
) -> Result<arkret::AgentKeyPairOutcome> {
    let agent_did = provisioned.agent_id.to_string();
    let pairing_request_id = provisioned.pairing_request_id.as_str();
    let pairing_code = provisioned
        .pairing_code
        .as_deref()
        .ok_or_else(|| anyhow!("pairing_code missing"))?;
    let pairing_expires_at = provisioned
        .expires_at
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    let agent_id = provisioned.agent_id.clone();
    let controller_id = arkret::Did::new(ALICE_DID.to_owned())
        .map_err(|err| anyhow!("alice did invalid: {err}"))?;
    let signing_key = runtime_signing_key();
    let verification_method = format!("{agent_did}#{fragment}");
    let builder = runtime_key_request_builder(server, provisioned, &signing_key)?
        .verification_method(verification_method.clone());
    let runtime_public_key_digest = builder.public_key_digest()?;
    let pairing_binding_digest = arkret::agent_key_pairing_request_binding_digest(
        &controller_id,
        &agent_id,
        &verification_method,
        &runtime_public_key_digest,
        pairing_request_id,
        pairing_code,
        &pairing_expires_at,
        server.service_id(),
    )?;
    let authorize_event = json!({
        "kind": "ak.agent.key.authorize",
        "actor_id": ALICE_DID,
        "payload": {
            "agent_id": agent_did,
            "key_id": "ak:agent_key:01999999000070008000000000000001",
            "verification_method": verification_method,
            "public_key_digest": runtime_public_key_digest.as_str(),
            "accountable_principal_id": ALICE_DID,
            "agent_key_scope": {
                "actions": [
                    "ak.self.events.stream.subscribe",
                    "ak.self.events.query.scan",
                    "ak.self.events.command.submit",
                    "ak.event.read",
                    "ak.message.create"
                ],
                "resources": [{"kind": "realm", "realm_id": "*"}],
                "constraints": []
            },
            "audience": [server.service_id()],
            "issued_at": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            "expires_at": "2999-01-01T00:00:00Z",
            "approval_evidence": {
                "kind": "approval_event",
                "ref": "ak:event:01999999-0000-7000-8000-000000000001",
                "request_canonical_digest": pairing_binding_digest.as_str(),
                "approved_by": ALICE_DID
            }
        }
    });
    let body = builder.build_key_pair_request(authorize_event)?.body;
    // `agent_key_pair` drives `ak.gate.account.command.pair_agent_key`, bound to
    // `POST /_arkret/gate/account/agent-key-pair`: the controller submits the
    // durable `ak.agent.key.authorize` event that clears `pending_runtime_key`.
    Ok(bearer_sdk_client(server, token)?
        .agent_key_pair(&body)
        .await?)
}

async fn agent_status(server: &ArkretServer, token: &str, agent_did: &str) -> Result<String> {
    let list = bearer_sdk_client(server, token)?.agent_list().await?;
    let status = list
        .agents
        .iter()
        .find(|agent| agent.agent_id.as_str() == agent_did)
        .map(|agent| {
            serde_json::to_value(agent.status)
                .ok()
                .and_then(|value| value.as_str().map(ToOwned::to_owned))
                .unwrap_or_default()
        })
        .unwrap_or_default();
    Ok(status)
}

async fn effective_grants(server: &ArkretServer, token: &str, agent_did: &str) -> Result<Value> {
    // The dev-mode agent grant is authored into the controller's
    // principal-control Realm (soland `ensure_self_realm`). soland only lets a
    // caller read a non-self subject's effective grants for a Realm the caller
    // owns (anti-enumeration); a bare `subject` query defaults to realm `*` and
    // is denied. Scope the query to the controller's principal-control Realm,
    // which the controller owns and where the agent grant lives.
    let control_realm = arkret_core::principal_control_realm_id(
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

fn bearer_sdk_client(server: &ArkretServer, token: &str) -> Result<SdkClient> {
    Ok(ClientBuilder::new(server.base_url())
        .allow_insecure_localhost()
        .auth(Auth::Bearer(token.to_owned()))
        .build()?)
}

fn agent_session_client(server: &ArkretServer, holder: &AgentSessionHolder) -> Result<SdkClient> {
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
    result: arkret_core::Result<T>,
    status: StatusCode,
    code: &str,
) -> Result<()> {
    match result {
        Err(ArkretError::Api {
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
            "ak.message.create",
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
    service_id: Arc<Mutex<String>>,
    subject: Arc<Mutex<Option<String>>>,
    cnf_jkt: String,
    session_public_key: String,
}

struct MockIntrospection {
    url: String,
    active: Arc<AtomicBool>,
    request_count: Arc<AtomicUsize>,
    service_id: Arc<Mutex<String>>,
    subject: Arc<Mutex<Option<String>>>,
    _server: MockServer,
}

impl MockIntrospection {
    async fn spawn(
        service_id: String,
        cnf_jkt: String,
        session_public_key: String,
    ) -> Result<Self> {
        let active = Arc::new(AtomicBool::new(true));
        let request_count = Arc::new(AtomicUsize::new(0));
        let service_id = Arc::new(Mutex::new(service_id));
        let subject = Arc::new(Mutex::new(None));
        let state = AgentIntrospectionState {
            active: Arc::clone(&active),
            request_count: Arc::clone(&request_count),
            service_id: Arc::clone(&service_id),
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
            service_id,
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

    fn set_service_id(&self, service_id: String) {
        if let Ok(mut guard) = self.service_id.lock() {
            *guard = service_id;
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

    let service_id = state
        .service_id
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
                // (`ak:grant:<uuidv7>`); a bare label fails SDK deserialization
                // and soland reports the introspection response as invalid (503).
                "id": "ak:grant:01964137-0000-7000-8000-000000000a01",
                "issuer": "did:web:coauth.cotest.local",
                "subject": subject,
                "service_account_id": "agent-live-e2e-account",
                "audience": service_id,
                "scopes": [
                    "ak.self.events.stream.subscribe",
                    "ak.self.events.query.scan",
                    "ak.self.events.command.submit",
                    "ak.event.read",
                    "ak.message.create"
                ],
                "expires_at": "2026-12-31T23:59:59Z",
                "revocation_ref": "ak:session:agent-live-e2e-grant",
                "session_public_key": state.session_public_key,
                "cnf_jkt": state.cnf_jkt,
                "proof_kind": "agent_key_proof",
                "scope_details": {
                    "agent_id": subject,
                    "controller_id": ALICE_DID,
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
