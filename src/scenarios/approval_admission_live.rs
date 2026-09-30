//! Actual detached WIP approval, governance-only evidence audit and clean replication.
use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::governance::membership_invite::MembershipPayloadState;
use arkret_models_collaboration::governance::realm_join_intake::RealmJoinIntent;
use arkret_wire::{
    ApprovalContext, ApprovalSignature, ApprovalSignatureInput, ApprovalSignatureProof,
    ApprovalSignatureProofKind, ApprovalTarget, CurrentRevision, Did, EventKind, Hash, RealmId,
    SpaceId, StrandId,
};
use serde_json::{Value, json};

use crate::harness::{CanonicalJsonBody, TestActorClient, TestServerGroup};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::live_gate::skip_or_fail;
use crate::scenarios::human_device_producer_live::{
    database, ensure_same_commit, membership_payload, prepare_join, standard_client, station_env,
    submit_and_expect_commit, wait_for_committed,
};
use crate::scenarios::identity_test_support::{
    HARNESS_INTERNAL_AUTHORITY_SECRET, test_principal_root_signing_authority,
};

async fn evidence_rows(url: &str) -> Result<i64> {
    let url = url.to_owned();
    tokio::task::spawn_blocking(move || -> Result<i64> {
        let mut db = postgres::Client::connect(&url, postgres::NoTls)?;
        Ok(db
            .query_one("SELECT COUNT(*) FROM event_approval_private_audit", &[])?
            .get(0))
    })
    .await?
}
async fn submit(
    client: &TestActorClient,
    submission: &arkret_wire::EventAdmissionSubmission,
) -> Result<(reqwest::StatusCode, Value)> {
    let response = client
        .post("/_arkret/self/events")
        .canonical_json(submission)?
        .send()
        .await?;
    let status = response.status();
    Ok((status, response.json().await?))
}

async fn create_object(
    client: &TestActorClient,
    realm: &str,
    kind: EventKind,
    payload: Value,
) -> Result<arkret_wire::Event> {
    ensure!(matches!(
        kind,
        EventKind::SpaceCreate | EventKind::StrandCreate
    ));
    let mut event = client.author_event(realm, kind.as_str(), payload).await?;
    let created_at = serde_json::to_value(&event)?["created_at"].clone();
    event
        .payload
        .get_mut("object")
        .and_then(Value::as_object_mut)
        .context("create payload object")?
        .insert("created_at".to_owned(), created_at);
    let (seed, _) =
        crate::harness::event_signing_identity_for_device(&client.actor, &client.device_id);
    crate::harness::refresh_typed_event_proof_with_signing_seed(&mut event, seed)?;
    Ok(event)
}

pub async fn approval_admission_run() -> Result<()> {
    const GROUP: &str = "approval-admission";
    let Some(governance_db) = database(GROUP)? else {
        return Ok(());
    };
    let Some(member_db) = database(GROUP)? else {
        return Ok(());
    };
    ensure!(
        governance_db.connect_url != member_db.connect_url,
        "approval privacy needs independent databases"
    );
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let Some(group) = TestServerGroup::try_multi_external_with_node_envs(
        GROUP,
        &[
            station_env(&governance_db.connect_url, &coauth),
            station_env(&member_db.connect_url, &coauth),
        ],
    )
    .await?
    else {
        return skip_or_fail(GROUP, "prebuilt Soland unavailable");
    };
    let (alice, alice_account) = standard_client(
        group.server(0),
        &coauth,
        "approval-alice",
        "ak:device:01904100-0000-7000-8000-000000000228",
    )
    .await?;
    let (bob, bob_account) = standard_client(
        group.server(1),
        &coauth,
        "approval-bob",
        "ak:device:01904100-0000-7000-8000-000000001121",
    )
    .await?;
    let created=alice.create_realm_with(json!({"title":"Real WIP review","public":true,"join_rule":"public","plaintext_visible_services":[group.server(0).service_id(),group.server(1).service_id()]})).await?;
    let realm = created["realm_id"].as_str().context("Realm id")?;
    let realm_id = RealmId::new(realm)?;
    prepare_join(
        &bob,
        realm,
        group.server(0),
        "ak:request:019b0000-0000-7000-8000-000000001121",
        RealmJoinIntent::MemberJoin,
    )
    .await?;
    let joined = bob
        .author_event(
            realm,
            EventKind::MemberState.as_str(),
            membership_payload(
                realm,
                bob_account.clone(),
                MembershipPayloadState::Join,
                "WIP approver",
            )?,
        )
        .await?;
    submit_and_expect_commit(&bob, &bob_account, &bob.device_id, &joined).await?;
    let actor = arkret_wire::ActorId::account(alice_account.clone());
    let object = |kind: &str, title: &str, parent: Option<&SpaceId>, fields: Value| {
        let mut value = json!({"schema":"ak.schema.space.v1","realm_id":realm_id,"kind":kind,"title":title,"fields":fields,"created_by":actor,"created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())});
        if let Some(id) = parent {
            value["parent_space_id"] = json!(id);
        }
        json!({"object":value})
    };
    let board = create_object(
        &alice,
        realm,
        EventKind::SpaceCreate,
        object("board", "Review Board", None, json!({})),
    )
    .await?;
    submit_and_expect_commit(&alice, &alice_account, &alice.device_id, &board).await?;
    let board_id = SpaceId::from_event_id(&board.event_id);
    let list = create_object(
        &alice,
        realm,
        EventKind::SpaceCreate,
        object(
            "list",
            "Review",
            Some(&board_id),
            json!({"wip_limit":1,"wip_limit_enforcement":"require_review"}),
        ),
    )
    .await?;
    let list_commit =
        submit_and_expect_commit(&alice, &alice_account, &alice.device_id, &list).await?;
    let list_id = SpaceId::from_event_id(&list.event_id);
    let mut cards = Vec::new();
    for title in ["First", "Second"] {
        let card=create_object(&alice,realm,EventKind::StrandCreate,json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm_id,"tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},"metadata":{"title":title},"state":"active","created_by":actor,"created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())}})).await?;
        submit_and_expect_commit(&alice, &alice_account, &alice.device_id, &card).await?;
        cards.push(StrandId::from_event_id(&card.event_id));
    }
    let first=alice.author_event(realm,EventKind::StrandMove.as_str(),json!({"board_space_id":board_id,"strand_id":cards[0],"target_space_id":list_id,"rank":"a"})).await?;
    submit_and_expect_commit(&alice, &alice_account, &alice.device_id, &first).await?;
    let grant=alice.author_event(realm,EventKind::CapabilityGrant.as_str(),json!({"grant":{"schema":"ak.schema.capability.v1","realm_id":realm_id,"issuer_id":actor,"subject":arkret_wire::ActorId::account(bob_account.clone()),"actions":["ak.space.update"],"resources":[arkret_wire::WireResourceSelector::space(realm_id.clone(),list_id.clone())],"constraints":[{"constraint_kind":"kind_restriction","effect":"allow","allowed_space_kinds":["list"]}],"issuer_authority_refs":[{"kind":"realm_root","realm_id":realm_id,"authority_event_ref":realm_id.event_id(),"authority_generation":0}],"issued_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())}})).await?;
    submit_and_expect_commit(&alice, &alice_account, &alice.device_id, &grant).await?;
    let target=alice.author_event(realm,EventKind::StrandMove.as_str(),json!({"board_space_id":board_id,"strand_id":cards[1],"target_space_id":list_id,"rank":"b"})).await?;
    let bare = arkret_wire::EventAdmissionSubmission::new(target.clone());
    let (status, error) = submit(&alice, &bare).await?;
    ensure!(
        !status.is_success() && error["reason_code"] == "approval_required",
        "missing WIP vote did not require approval: {error}"
    );
    let (method, seed) = test_principal_root_signing_authority(&bob.actor)?;
    let did = Did::new(&bob.actor)?;
    let signer = arkret_signatures::Ed25519DetachedJwsSigner::from_seed(seed, method.as_str());
    let mut vote = ApprovalSignature {
        input: ApprovalSignatureInput {
            approval_context: ApprovalContext::ListWip {
                list_space_id: list_id.clone(),
                list_policy_revision: CurrentRevision {
                    commit_id: list_commit.commit_id.clone(),
                    stream_position: list_commit.stream_position,
                },
            },
            approval_target: ApprovalTarget::Event {
                event_id: target.event_id.clone(),
            },
            request_canonical_digest: Hash::new(arkret_canonical::canonical_sha256(&target)?)?,
            operation: "ak.self.events.command.submit.v1".to_owned(),
            action: arkret_wire::CapabilityActionId::StrandMove,
            realm_id: realm_id.clone(),
            initiating_actor_id: target.actor_id.clone(),
            approver_did: did,
            approved_at: chrono::Utc::now(),
            nonce: "cotest-approval-private-nonce-0228-1121".to_owned(),
        },
        proof: ApprovalSignatureProof {
            kind: ApprovalSignatureProofKind::DetachedJws,
            verification_method: method,
            jws: String::new(),
        },
    };
    vote.proof.jws = signer.sign_detached_jws(
        &arkret_signatures::approval_signature::approval_signature_signing_bytes(&vote)?,
    );
    let submitted = arkret_wire::EventAdmissionSubmission {
        event: target.clone(),
        approval_signatures: Some(vec![vote]),
    };
    let (status, outcome) = submit(&alice, &submitted).await?;
    ensure!(
        status.is_success(),
        "valid historical WIP vote rejected: {outcome}"
    );
    let committed = wait_for_committed(&alice, &target.event_id).await?;
    ensure_same_commit(
        committed.commit(),
        &wait_for_committed(&bob, &target.event_id).await?,
    )?;
    ensure!(
        evidence_rows(&governance_db.connect_url).await? == 1,
        "governance omitted accepted-at audit"
    );
    ensure!(
        evidence_rows(&member_db.connect_url).await? == 0,
        "replication leaked private approval audit"
    );
    let (status, replay) = submit(&alice, &submitted).await?;
    ensure!(
        status.is_success(),
        "exact approval replay rejected: {replay}"
    );
    ensure!(
        evidence_rows(&governance_db.connect_url).await? == 1,
        "exact replay consumed nonce twice"
    );
    eprintln!(
        "1121 WIP historical approval accepted and cleanly replicated: {}",
        committed.commit().event_ref
    );
    Ok(())
}
