use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::fixtures::TestScaffold;
use crate::harness::{ArkretServer, actor_core_id, expect_api_error, expect_json};
use crate::scenarios::identity_test_support::{
    actor_did_for_service_did, spawn_with_standard_grant_authority,
};

pub async fn framework_errors_and_invalid_json_use_arkret_envelopes() -> Result<()> {
    // CT-12: scaffold-driven, parallel-safe.
    let scaffold = TestScaffold::fresh("api-errors").await?;
    let server = scaffold.server();

    let missing = expect_api_error(
        server.http().get(server.url("/_arkret/self/missing")),
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
    )
    .await?;
    assert!(missing.instance.is_some());

    expect_api_error(
        server.http().post(server.url("/_arkret/describe")),
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
    )
    .await?;
    expect_api_error(
        server
            .account_registration_request()
            .header("content-type", "application/json")
            .body("{"),
        StatusCode::BAD_REQUEST,
        "param_invalid",
    )
    .await?;

    Ok(())
}

pub async fn account_auth_and_session_edges_are_enforced() -> Result<()> {
    let server = ArkretServer::spawn("account-auth").await?;
    let account_did = arkret_identifiers::Did::new("did:web:alice-auth.example".to_owned())?;
    let account_core_id = arkret_identifiers::project_did_to_core_id(&account_did)?;

    expect_api_error(
        server
            .account_registration_request()
            .json(&crate::harness::NonProtocolTestBody::new(json!({"did": "bad", "handle": "@bad", "device_id": "ak:device:01904100-0000-7000-8000-000000000bad"}))),
        StatusCode::BAD_REQUEST,
        "param_invalid",
    )
    .await?;

    let registration_body = crate::harness::NonProtocolTestBody::new(json!({
        "did": account_did,
        "handle": "@alice-auth",
        "display_name": "alice-auth",
        "device_id": "ak:device:01904100-0000-7000-8000-0000000000a1",
    }));
    let registered = expect_json(
        server
            .account_registration_request()
            .json(&registration_body),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(registered["principal_id"], account_core_id.as_str());

    expect_api_error(
        server
            .account_registration_request()
            .json(&registration_body),
        StatusCode::CONFLICT,
        "duplicate_conflict",
    )
    .await?;

    let login = expect_json(
        server
            .http()
            .post(server.url("/_soland/gate/auth/dev-login"))
            .json(&crate::harness::NonProtocolTestBody::new(json!({
                "actor": account_core_id,
                "device_id": "ak:device:01904100-0000-7000-8000-0000000000a1",
                "display_name": "Alice"
            }))),
        StatusCode::OK,
    )
    .await?;
    let token = login["session_credential"].as_str().unwrap();

    let me = expect_json(
        server
            .http()
            .get(server.url("/_arkret/self/account/viewer"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(me["principal_id"], account_core_id.as_str());

    expect_api_error(
        server
            .http()
            .get(server.url("/_arkret/self/account/viewer")),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;

    // Local development bearers are outside the Account Authority's Standard
    // SessionGrant revoke contract. The Station must not return a false
    // success for this canonical operation.
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/gate/account/session-grants/revoke"))
            .bearer_auth(token),
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
    )
    .await?;

    expect_json(
        server
            .http()
            .get(server.url("/_arkret/self/account/viewer"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;

    Ok(())
}

pub async fn contact_edges_are_rejected() -> Result<()> {
    // Committing a Contact Event is a self Event admission: the holder's
    // device signs it and the Station checks that signer against the
    // session's Standard SessionGrant before the atomic Event/RealmCommit
    // unit (contact-and-direct-conversation.md section 2).
    let station = spawn_with_standard_grant_authority("contact-edges", &[]).await?;
    let server = &station.server;
    let alice_actor = actor_did_for_service_did(server.service_did(), "alice-contact")?;
    let alice = station.standard_grant_client(
        &server
            .demo_client(
                &alice_actor,
                "ak:device:01904100-0000-7000-8000-0000000000a1",
            )
            .await?,
    )?;
    let bob_actor = actor_did_for_service_did(server.service_did(), "bob-contact")?;
    let bob = station.standard_grant_client(
        &server
            .demo_client(&bob_actor, "ak:device:01904100-0000-7000-8000-0000000000b0")
            .await?,
    )?;

    let self_request = alice.contact_request_prepare(&alice.actor)?;
    match alice.sdk().contacts_request(&self_request).await {
        Err(arkret_http_client::Error::Api { status, error }) => {
            assert_eq!(status, StatusCode::BAD_REQUEST.as_u16());
            assert_eq!(error.code(), "param_invalid");
        }
        Err(error) => return Err(error.into()),
        Ok(outcome) => {
            return Err(anyhow::anyhow!(
                "self-targeted Contact request was accepted: {outcome:?}"
            ));
        }
    }

    // Contact prepare/commit records the holder-local request fact. Target
    // resolution and delivery are a later phase, so an offline or currently
    // unresolvable peer is not rejected while authoring that local fact.
    let missing_target = "did:web:missing-contact.example";
    let missing_target_core_id = actor_core_id(missing_target)?;
    let alice_core_id = actor_core_id(&alice.actor)?;
    let bob_core_id = actor_core_id(&bob.actor)?;
    let missing_receipt = alice.request_contact(missing_target).await?;
    assert_eq!(
        missing_receipt
            .core
            .holder
            .contact_actor_id()
            .signing_principal_id()
            .as_str(),
        alice_core_id
    );
    assert_eq!(
        missing_receipt
            .core
            .peer
            .contact_actor_id()
            .signing_principal_id()
            .as_str(),
        missing_target_core_id
    );
    assert_eq!(missing_receipt.core.slot_version, 1);
    assert!(missing_receipt.core.slot_predecessor.is_none());

    let receipt = bob.request_contact(&alice.actor).await?;
    assert_eq!(
        receipt
            .core
            .holder
            .contact_actor_id()
            .signing_principal_id()
            .as_str(),
        bob_core_id
    );
    assert_eq!(
        receipt
            .core
            .peer
            .contact_actor_id()
            .signing_principal_id()
            .as_str(),
        alice_core_id
    );

    // Alice answers Bob's pending request with a normal response. Its absence
    // transcript observes her own (empty) slot plus the consumed request, and
    // the round is accepted in both holders' list projections.
    alice.accept_contact(&bob).await?;
    for (client, peer) in [(&alice, &bob_core_id), (&bob, &alice_core_id)] {
        let row = client
            .sdk()
            .contacts_list()
            .await?
            .contacts
            .into_iter()
            .find(|row| {
                row.peer.contact_actor_id().signing_principal_id().as_str() == peer.as_str()
            })
            .ok_or_else(|| anyhow::anyhow!("the accepted Contact row is missing"))?;
        assert_eq!(row.state, arkret::ContactState::Accepted);
    }

    Ok(())
}

/// Prepare one two-phase Contact command at `path`, sign its exact draft as
/// `kind` and commit it; the committed outcome is returned.
async fn contact_command(
    client: &crate::harness::TestActorClient,
    path: &str,
    prepare: serde_json::Value,
    kind: &str,
) -> Result<arkret::contact_operations::ContactOperationOutcome> {
    use arkret::contact_operations::{
        ContactCommitPhase, ContactCommitRequestBody, ContactOperationOutcome,
        ContactPreparedOutcome,
    };
    let operation_id = arkret::ProtocolOperationId::new(crate::harness::next_typed_id("operation"))
        .map_err(anyhow::Error::msg)?;
    let idempotency_key = arkret::IdempotencyKey::new(crate::harness::next_typed_id("idempotency"))
        .map_err(anyhow::Error::msg)?;
    let mut body = prepare;
    body["phase"] = json!("prepare");
    body["operation_id"] = json!(operation_id);
    body["idempotency_key"] = json!(idempotency_key);
    let prepared: ContactOperationOutcome =
        serde_json::from_value(expect_json(client.post(path).json(&body), StatusCode::OK).await?)?;
    let (reservation_handle, event_draft) = match prepared {
        ContactOperationOutcome::Prepared { outcome } => match outcome {
            ContactPreparedOutcome::Request {
                reservation_handle,
                event_draft,
                ..
            }
            | ContactPreparedOutcome::Response {
                reservation_handle,
                event_draft,
                ..
            }
            | ContactPreparedOutcome::Reject {
                reservation_handle,
                event_draft,
                ..
            }
            | ContactPreparedOutcome::ScopeUpdate {
                reservation_handle,
                event_draft,
                ..
            }
            | ContactPreparedOutcome::Tombstone {
                reservation_handle,
                event_draft,
                ..
            } => (reservation_handle, event_draft),
        },
        other => return Err(anyhow::anyhow!("{path} prepare did not prepare: {other:?}")),
    };
    let commit = ContactCommitRequestBody {
        phase: ContactCommitPhase::Commit,
        operation_id,
        idempotency_key,
        reservation_handle,
        signed_event: client.sign_prepared_contact_event(&event_draft, kind)?,
    };
    Ok(serde_json::from_value(
        expect_json(client.post(path).json(&commit), StatusCode::OK).await?,
    )?)
}

/// The holder's current list row for `peer`.
async fn contact_row(
    client: &crate::harness::TestActorClient,
    peer: &str,
) -> Result<arkret::contact_operations::ContactListRow> {
    let peer = actor_core_id(peer)?;
    client
        .sdk()
        .contacts_list()
        .await?
        .contacts
        .into_iter()
        .find(|row| {
            row.peer
                .contact_actor_id()
                .signing_principal_id()
                .as_str()
                == peer.as_str()
        })
        .ok_or_else(|| anyhow::anyhow!("the Contact row for {peer} is missing"))
}

pub async fn contact_reject_scope_update_and_tombstone_commit_atomically() -> Result<()> {
    use arkret::contact_operations::{ContactAcceptedOutcome, ContactOperationOutcome};
    let station = spawn_with_standard_grant_authority("contact-successors", &[]).await?;
    let server = &station.server;
    let client = |label: &'static str, device: &'static str| {
        let station = &station;
        async move {
            let actor = actor_did_for_service_did(station.server.service_did(), label)?;
            station.standard_grant_client(&station.server.demo_client(&actor, device).await?)
        }
    };
    let carol = client("carol-contact", "ak:device:01904100-0000-7000-8000-0000000000c1").await?;
    let dave = client("dave-contact", "ak:device:01904100-0000-7000-8000-0000000000d1").await?;
    let erin = client("erin-contact", "ak:device:01904100-0000-7000-8000-0000000000e1").await?;
    let _ = server;

    // `ak.contact.rejected`: Carol terminally rejects Dave's pending request.
    dave.request_contact(&carol.actor).await?;
    let pending = contact_row(&carol, &dave.actor).await?;
    let rejected = contact_command(
        &carol,
        "/_arkret/self/contacts/reject",
        json!({
            "peer": pending.peer,
            "request_event_ref": pending.request_event_ref,
            "action": "reject",
        }),
        arkret_wire::event_kind_str::CONTACT_REJECTED,
    )
    .await?;
    assert!(matches!(
        rejected,
        ContactOperationOutcome::Accepted {
            outcome: ContactAcceptedOutcome::Reject { .. }
        }
    ));
    assert_eq!(
        contact_row(&carol, &dave.actor).await?.state,
        arkret::ContactState::Rejected
    );

    // `ak.contact.scope.update`: after a normal round, the requester's first
    // successor walks the founding edge from its own request head, and the
    // responder's first successor follows its accepted head.
    erin.request_contact(&carol.actor).await?;
    carol.accept_contact(&erin).await?;
    for (holder, peer) in [(&erin, &carol), (&carol, &erin)] {
        let row = contact_row(holder, &peer.actor).await?;
        let next = row
            .next_prepare_input
            .ok_or_else(|| anyhow::anyhow!("an accepted row carries its next prepare input"))?;
        assert_eq!(next.version, 2);
        let updated = contact_command(
            holder,
            "/_arkret/self/contacts/scope-update",
            json!({
                "peer": row.peer,
                "contact_round_id": next.contact_round_id,
                "version": next.version,
                "predecessor_event_ref": next.predecessor_event_ref,
                "granted_to_peer_scopes": [],
            }),
            arkret_wire::event_kind_str::CONTACT_SCOPE_UPDATE,
        )
        .await?;
        assert!(matches!(
            updated,
            ContactOperationOutcome::Accepted {
                outcome: ContactAcceptedOutcome::ScopeUpdate { .. }
            }
        ));
        let row = contact_row(holder, &peer.actor).await?;
        assert_eq!(row.state, arkret::ContactState::Accepted);
        assert!(row.granted_to_peer_scopes.is_empty());
        assert_eq!(
            row.next_prepare_input
                .ok_or_else(|| anyhow::anyhow!("an accepted row keeps its next prepare input"))?
                .version,
            3
        );
    }

    // `ak.contact.tombstone`: Carol terminates the round.
    let row = contact_row(&carol, &erin.actor).await?;
    let next = row
        .next_prepare_input
        .ok_or_else(|| anyhow::anyhow!("an accepted row carries its next prepare input"))?;
    let tombstoned = contact_command(
        &carol,
        "/_arkret/self/contacts/tombstone",
        json!({
            "peer": row.peer,
            "contact_round_id": next.contact_round_id,
            "version": next.version,
            "predecessor_event_ref": next.predecessor_event_ref,
            "block_peer": false,
        }),
        arkret_wire::event_kind_str::CONTACT_TOMBSTONE,
    )
    .await?;
    assert!(matches!(
        tombstoned,
        ContactOperationOutcome::Accepted {
            outcome: ContactAcceptedOutcome::Tombstone { .. }
        }
    ));
    for (holder, peer) in [(&carol, &erin), (&erin, &carol)] {
        assert_eq!(
            contact_row(holder, &peer.actor).await?.state,
            arkret::ContactState::Tombstoned
        );
    }
    Ok(())
}
