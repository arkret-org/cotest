//! Exact parent Realm join generations in a real two-Station Circle flow.

use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::governance::circle::CircleCreateRequestBody;
use arkret_models_collaboration::governance::membership_invite::MembershipPayloadState;
use arkret_models_collaboration::governance::realm_join_intake::RealmJoinIntent;
use arkret_models_collaboration::mls_group_state_material::{
    MlsGroupStateMaterialOutcome, MlsMemberGroupStateMaterialReadRequestBody,
};
use arkret_models_collaboration::mls_roster_authority::{
    MlsMemberRosterAuthorityReadRequestBody, MlsRosterAuthorityReadOutcome, MlsRosterRecord,
    MlsSelfRosterAuthorityReadOutcome,
};
use arkret_wire::{ActorId, CircleId, EventAdmissionSubmission, EventKind, ScopeRef};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{
    CanonicalJsonBody, TestActorClient, TestServerGroup, expect_json, refresh_typed_event_proof,
};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::live_gate::skip_or_fail;
use crate::scenarios::cross_station_mls_welcome::genesis_creator_leaf_authority;
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, database, membership_payload, prepare_join, station_env,
    submit_and_expect_commit, wait_for_committed,
};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;
use crate::scenarios::mls_lifecycle_live::{ACTIVE_SUITE, Member, canonical, upload_public_blob};

const GROUP: &str = "circle-parent-membership-live";
const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002861";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002862";

async fn circle_state(
    client: &TestActorClient,
    account: &arkret_wire::AccountId,
    realm: &str,
    circle: &CircleId,
    state: &str,
    expected: serde_json::Value,
    parent: Option<serde_json::Value>,
) -> Result<arkret_wire::RealmCommit> {
    let actor = ActorId::account(account.clone());
    let mut payload = json!({"circle_id":circle,"member_id":actor,
        "membership":state,"expected_membership":expected});
    if let Some(parent) = parent {
        payload["parent_membership_revision"] = parent;
    }
    let mut event = client
        .author_event(realm, EventKind::CircleMemberState.as_str(), payload)
        .await?;
    event.scope_ref = ScopeRef::Circle {
        realm_id: event.realm_id.clone(),
        circle_id: circle.clone(),
    };
    refresh_typed_event_proof(&mut event)?;
    submit_and_expect_commit(client, account, BOB_DEVICE, &event).await
}

async fn parent_state(
    client: &TestActorClient,
    signer: &arkret_wire::AccountId,
    device: &str,
    realm: &str,
    subject: &arkret_wire::AccountId,
    state: MembershipPayloadState,
) -> Result<arkret_wire::RealmCommit> {
    let event = client
        .author_event(
            realm,
            EventKind::MemberState.as_str(),
            membership_payload(
                realm,
                subject.clone(),
                state,
                "Circle parent revision live matrix",
            )?,
        )
        .await?;
    submit_and_expect_commit(client, signer, device, &event).await
}

async fn canonical_rows(
    database_url: &str,
    circles: &[CircleId],
    actor: &ActorId,
) -> Result<Vec<(String, String, i64)>> {
    let database_url = database_url.to_owned();
    let circles = circles.iter().map(ToString::to_string).collect::<Vec<_>>();
    let member = actor.to_string();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut client=postgres::Client::connect(&database_url,postgres::NoTls)?;
        let mut rows=Vec::new();
        for circle in circles {
            let row=client.query_one(
                "SELECT m.value::text,m.current_commit_id,(SELECT COUNT(*) FROM realm_commits c \
                 WHERE c.realm_id=m.realm_id AND c.stream_ref->>'circle_id'=m.circle_id) \
                 FROM circle_member_state_current_results m WHERE m.circle_id=$1 AND m.member_id=$2",
                &[&circle,&member],
            )?;
            rows.push((row.get(0),row.get(1),row.get(2)));
        }
        Ok(rows)
    }).await?
}

pub(crate) async fn wait_for_membership_current(
    database_url: &str,
    commit: &arkret_wire::RealmCommit,
    actor: &ActorId,
    membership: &str,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        let database_url = database_url.to_owned();
        let commit = commit.clone();
        let member = actor.to_string();
        let membership = membership.to_owned();
        let installed = tokio::task::spawn_blocking(move || -> Result<bool> {
            let mut client = postgres::Client::connect(&database_url, postgres::NoTls)?;
            let realm = commit.realm_id.as_str();
            let row = match &commit.stream_ref {
                arkret_wire::CommitStreamRef::Realm { .. } => client.query_opt(
                    "SELECT current_commit_id,current_stream_position,jsonb_build_object('kind','realm','realm_id',realm_id),membership FROM member_state_current_results WHERE realm_id=$1 AND member_id=$2",
                    &[&realm,&member],
                )?,
                arkret_wire::CommitStreamRef::Circle { circle_id, .. } => client.query_opt(
                    "SELECT current_commit_id,current_stream_position,source_stream_ref,membership FROM circle_member_state_current_results WHERE realm_id=$1 AND member_id=$2 AND circle_id=$3",
                    &[&realm,&member,&circle_id.as_str()],
                )?,
                _ => anyhow::bail!("membership current has an unsupported source stream"),
            };
            Ok(row.is_some_and(|row| {
                row.get::<_, String>(0) == commit.commit_id.as_str()
                    && row.get::<_, i64>(1) as u64 == commit.stream_position
                    && row.get::<_, serde_json::Value>(2) == json!(commit.stream_ref)
                    && row.get::<_, String>(3) == membership
            }))
        }).await??;
        if installed {
            return Ok(());
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "the member Station did not install the exact membership current"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

const SELF_MATERIAL: &str = "/_arkret/self/mls/group-state-material/query";
const PEER_MATERIAL: &str = "/_arkret/peer/mls/group-state-material";

struct CircleMlsMaterial {
    material: MlsMemberGroupStateMaterialReadRequestBody,
    roster: MlsMemberRosterAuthorityReadRequestBody,
    group_info: Vec<u8>,
    tree: Vec<u8>,
}

async fn activate_circle(
    creator: &Member,
    realm: &str,
    circle: &CircleId,
) -> Result<CircleMlsMaterial> {
    let realm_id = arkret_wire::RealmId::new(realm.to_owned())?;
    let scope = ScopeRef::Circle {
        realm_id: realm_id.clone(),
        circle_id: circle.clone(),
    };
    let binding = arkret::MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)?;
    let mut group = creator
        .mls_identity()?
        .create_group_with_governance_binding(&scope, &binding)?;
    let leaf = genesis_creator_leaf_authority(&mut group, creator)?;
    let (group_info, tree) = group.public_group_state_bytes()?;
    let group_info_ref = upload_public_blob(&creator.client, &realm_id, &group_info).await?;
    let tree_ref = upload_public_blob(&creator.client, &realm_id, &tree).await?;
    let mut event = creator
        .client
        .author_event(
            realm,
            EventKind::MlsGenesis.as_str(),
            canonical(
                json!({"cipher_suite":ACTIVE_SUITE,"group_info_ref":group_info_ref,
            "ratchet_tree_ref":tree_ref,"governance_binding":binding,"creator_leaf_authority":leaf,
            "created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())}),
            )?,
        )
        .await?;
    event.scope_ref = scope.clone();
    refresh_typed_event_proof(&mut event)?;
    submit_and_expect_commit(
        &creator.client,
        &creator.account,
        creator.device.as_str(),
        &event,
    )
    .await?;
    wait_for_committed(&creator.client, &event.event_id).await?;
    let material = MlsMemberGroupStateMaterialReadRequestBody {
        realm_id: realm_id.clone(),
        effective_scope: scope.clone(),
        mls_group_id: scope.canonical_mls_group_id()?,
        epoch: Default::default(),
        group_state_event_id: event.event_id.clone(),
        caller_actor_id: creator.actor.clone(),
        target_commit_event_ref: event.event_id.clone(),
        target_epoch: 0,
        group_info_ref: arkret_wire::BlobRef::new(group_info_ref)?,
        ratchet_tree_ref: arkret_wire::BlobRef::new(tree_ref)?,
        max_response_bytes: None,
    };
    let roster = MlsMemberRosterAuthorityReadRequestBody {
        realm_id,
        effective_scope: scope,
        mls_group_id: material.mls_group_id.clone(),
        target_commit_event_ref: event.event_id,
        target_epoch: 0,
        caller_actor_id: creator.actor.clone(),
        cursor: None,
    };
    Ok(CircleMlsMaterial {
        material,
        roster,
        group_info,
        tree,
    })
}

async fn assert_circle_mls_reads(
    material: &CircleMlsMaterial,
    member: &TestActorClient,
    governance: &crate::harness::ArkretServer,
    account_station: &crate::harness::ArkretServer,
    authorized: bool,
) -> Result<()> {
    let expected = if authorized {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    };
    let self_material = expect_json(
        member
            .post(SELF_MATERIAL)
            .canonical_json(&material.material)?,
        expected,
    )
    .await?;
    let self_roster = expect_json(
        member
            .post(arkret_wire::PATH_SELF_MLS_ROSTER_AUTHORITY)
            .canonical_json(&material.roster)?,
        expected,
    )
    .await?;
    let self_result = authorized
        .then(|| serde_json::from_value::<MlsSelfRosterAuthorityReadOutcome>(self_roster.clone()))
        .transpose()?;
    let peer_request = if let Some(result) = &self_result {
        arkret::verify_mls_member_roster_authority_pages(
            std::slice::from_ref(result),
            &material.roster,
        )?
    } else {
        // Keep the original accepted Genesis locator to probe historical-cut
        // denial after leave; an unauthorized self response supplies no keys.
        material
            .roster
            .with_accepted_genesis(material.material.group_state_event_id.clone())
    };
    ensure!(
        peer_request.genesis_event_ref == material.material.group_state_event_id,
        "the own Station derived a different accepted Circle Genesis"
    );
    let (status, peer_material) = governance
        .signed_peer_post(
            account_station,
            PEER_MATERIAL,
            &arkret_canonical::canonical_json_bytes(&material.material.as_peer_request())?,
            governance.service_id(),
        )
        .await?;
    ensure!(
        status == expected,
        "Circle peer material returned {status}: {}",
        String::from_utf8_lossy(&peer_material)
    );
    let (status, peer_roster) = governance
        .signed_peer_post(
            account_station,
            arkret_wire::PATH_PEER_MLS_ROSTER_AUTHORITY,
            &arkret_canonical::canonical_json_bytes(&peer_request)?,
            governance.service_id(),
        )
        .await?;
    ensure!(
        status == expected,
        "Circle peer roster returned {status}: {}",
        String::from_utf8_lossy(&peer_roster)
    );
    if !authorized {
        let peer_material: serde_json::Value = serde_json::from_slice(&peer_material)?;
        let peer_roster: serde_json::Value = serde_json::from_slice(&peer_roster)?;
        ensure!(
            self_material["type"] == peer_material["type"]
                && self_roster["type"] == peer_roster["type"],
            "Circle current or historical-cut denial leaked another error bucket"
        );
        return Ok(());
    }
    for outcome in [
        serde_json::from_value::<MlsGroupStateMaterialOutcome>(self_material)?,
        serde_json::from_slice::<MlsGroupStateMaterialOutcome>(&peer_material)?,
    ] {
        let validated = outcome.validate_for_request(&material.material.as_peer_request())?;
        ensure!(
            validated.group_info_bytes == material.group_info
                && validated.ratchet_tree_bytes == material.tree,
            "Circle material did not preserve accepted Genesis bytes"
        );
    }
    let self_page = self_result
        .context("authorized roster supplies verified own-Station keys")?
        .roster;
    let peer_page: MlsRosterAuthorityReadOutcome = serde_json::from_slice(&peer_roster)?;
    let (_, seed) = crate::harness::test_service_signing_key(&format!("{GROUP}-0"));
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let method = format!("{}#notary-key", governance.service_did());
    for page in [&self_page, &peer_page] {
        page.manifest.validate_for_request(&peer_request)?;
        arkret_signatures::keypackages::verify_keypackage_signing_input(
            &key.verifying_key().to_bytes(),
            &method,
            &page.manifest.signing_bytes()?,
            &page.manifest.signature,
        )?;
        ensure!(
            page.page_index == 0
                && page.next_cursor.is_none()
                && page.manifest.page_count == 1
                && page.manifest.total_records == 1
                && page.records.len() == 1,
            "Circle Genesis roster was partial or invented an Add"
        );
        ensure!(
            page.manifest.records_digest.as_str()
                == arkret_canonical::canonical_sha256(&page.records)?,
            "Circle roster digest differed from signed complete records"
        );
        ensure!(
            matches!(&page.records[0],MlsRosterRecord::Genesis{genesis_event_ref,actor_id,..}
            if genesis_event_ref==&peer_request.genesis_event_ref && actor_id==&peer_request.caller_actor_id),
            "Circle roster did not bind the actual accepted creator"
        );
    }
    ensure!(
        arkret_canonical::canonical_json_bytes(&self_page.records)?
            == arkret_canonical::canonical_json_bytes(&peer_page.records)?,
        "Circle self/peer roster records disagree"
    );
    Ok(())
}

pub async fn grant_circle_actions(
    controller: &Member,
    realm: &str,
    circle: &CircleId,
    subject: &Member,
) -> Result<()> {
    use arkret_models_collaboration::events_payloads::{
        CapabilityGrantCreateBody, CapabilityGrantPayload,
    };
    use arkret_models_collaboration::governance::grant_constraint::CapabilitySubject;
    let realm_id = arkret_wire::RealmId::new(realm.to_owned())?;
    let grant = CapabilityGrantCreateBody {
        schema: "ak.schema.capability.v1".to_owned(),
        realm_id: Some(realm_id.clone()),
        issuer_id: controller.actor.clone(),
        subject: CapabilitySubject::Actor(subject.actor.clone()),
        actions: vec![
            "ak.circle.member.add".to_owned(),
            "ak.mls.genesis".to_owned(),
        ],
        resources: vec![serde_json::from_value(
            json!({"kind":"circle","realm_id":realm_id,"circle_id":circle}),
        )?],
        constraints: Vec::new(),
        issuer_authority_refs: vec![arkret::IssuerAuthorityRef::RealmRoot {
            realm_id: realm_id.clone(),
            authority_event_ref: realm_id.event_id(),
            authority_generation: 0,
        }],
        issued_at: chrono::Utc::now(),
    };
    let event = controller
        .client
        .author_event(
            realm,
            EventKind::CapabilityGrant.as_str(),
            serde_json::to_value(CapabilityGrantPayload { grant })?,
        )
        .await?;
    submit_and_expect_commit(
        &controller.client,
        &controller.account,
        controller.device.as_str(),
        &event,
    )
    .await?;
    wait_for_committed(&subject.client, &event.event_id).await?;
    Ok(())
}

/// Independent Circle positions, both scan directions and the peer's exact
/// replication scope are exercised over accepted, signed MLS Genesis rows.
async fn assert_circle_stream_scan(
    member: &TestActorClient,
    outsider: &TestActorClient,
    governance: &crate::harness::ArkretServer,
    account_station: &crate::harness::ArkretServer,
    realm: &str,
    circle: &CircleId,
) -> Result<()> {
    use arkret_models_collaboration::authority_commit::PeerStreamScanOutcome;
    use arkret_wire::{CommitStreamRef, StreamScanDirection, StreamScanRequest};
    let realm_id = arkret_wire::RealmId::new(realm)?;
    let stream = CommitStreamRef::Circle {
        realm_id: realm_id.clone(),
        circle_id: circle.clone(),
    };
    let (_, seed) = crate::harness::test_service_signing_key(&format!("{GROUP}-0"));
    let public_key = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes()
            .to_vec(),
    };
    let mut forward_positions = Vec::new();
    for direction in [
        StreamScanDirection::After(None),
        StreamScanDirection::Before(None),
    ] {
        let request = StreamScanRequest {
            realm_id: realm_id.clone(),
            stream_ref: stream.clone(),
            direction,
            limit: 50,
        };
        let (status, bytes) = governance
            .signed_peer_post(
                account_station,
                "/_arkret/peer/streams/scan",
                &arkret_canonical::canonical_json_bytes(&request)?,
                governance.service_id(),
            )
            .await?;
        ensure!(
            status == StatusCode::OK,
            "Circle peer scan failed: {}",
            String::from_utf8_lossy(&bytes)
        );
        let peer: PeerStreamScanOutcome = serde_json::from_slice(&bytes)?;
        peer.validate_for_request(&request)?;
        let expected_positions = peer
            .committed_events
            .iter()
            .map(|row| row.commit().stream_position)
            .collect::<Vec<_>>();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
        let page = loop {
            let result = member.sdk().scan_commit_stream(&request).await;
            if let Ok(page) = &result
                && page
                    .committed_events
                    .iter()
                    .map(|row| row.commit().stream_position)
                    .collect::<Vec<_>>()
                    == expected_positions
            {
                break result?;
            }
            ensure!(
                tokio::time::Instant::now() < deadline,
                "Circle replica never installed the accepted peer scan prefix: {result:?}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        };
        page.validate_for_request(&request)?;
        ensure!(
            peer.readable_floor == page.readable_floor && !page.truncated && !peer.truncated,
            "Circle peer and self floors or complete-page boundaries differed"
        );
        let positions = page
            .committed_events
            .iter()
            .map(|row| row.commit().stream_position)
            .collect::<Vec<_>>();
        ensure!(
            positions
                == peer
                    .committed_events
                    .iter()
                    .map(|row| row.commit().stream_position)
                    .collect::<Vec<_>>(),
            "Circle peer and self coordinates differed"
        );
        for row in page
            .committed_events
            .iter()
            .chain(peer.committed_events.iter())
        {
            ensure!(
                row.commit().stream_ref == stream,
                "Circle scan substituted a Realm coordinate"
            );
            let unsigned = arkret_canonical::unsigned_value(row.commit(), &["signature"])?;
            arkret_signatures::detached_object::verify_detached_object_signature(
                &row.commit().signature,
                &unsigned,
                arkret_wire::DetachedSignatureContext::RealmCommit,
                &public_key,
            )?;
        }
        if matches!(request.direction, StreamScanDirection::After(_)) {
            forward_positions = positions;
        } else {
            ensure!(
                positions == forward_positions.iter().rev().copied().collect::<Vec<_>>(),
                "backfill and forward catch-up disagreed within one Circle stream"
            );
        }
    }
    let unknown_circle = CircleId::from_event_id(&realm_id.event_id());
    let mut request = StreamScanRequest {
        realm_id,
        stream_ref: stream,
        direction: StreamScanDirection::After(None),
        limit: 1,
    };
    let hidden = expect_json(
        outsider
            .post("/_arkret/self/streams/scan")
            .canonical_json(&request)?,
        StatusCode::FORBIDDEN,
    )
    .await?;
    ensure!(hidden["type"] == "https://arkret.org/problems/capability_denied");
    request.stream_ref = CommitStreamRef::Circle {
        realm_id: request.realm_id.clone(),
        circle_id: unknown_circle,
    };
    let unknown = expect_json(
        outsider
            .post("/_arkret/self/streams/scan")
            .canonical_json(&request)?,
        StatusCode::FORBIDDEN,
    )
    .await?;
    for field in ["type", "title", "status", "detail"] {
        ensure!(
            hidden[field] == unknown[field],
            "Circle scan disclosed target existence through {field}"
        );
    }
    Ok(())
}

pub async fn run() -> Result<()> {
    let Some(governance_db) = database("circle-parent-governance")? else {
        return Ok(());
    };
    let Some(account_db) = database("circle-parent-account")? else {
        return Ok(());
    };
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let Some(group) = TestServerGroup::try_multi_external_with_node_envs(
        GROUP,
        &[
            station_env(&governance_db.connect_url, &coauth),
            station_env(&account_db.connect_url, &coauth),
        ],
    )
    .await?
    else {
        return skip_or_fail(GROUP, "prebuilt Soland unavailable");
    };
    let governance = group.server(0);
    let account_station = group.server(1);
    let alice_member =
        Member::provision(governance, &coauth, "circle-parent-alice", ALICE_DEVICE).await?;
    let bob_member =
        Member::provision(account_station, &coauth, "circle-parent-bob", BOB_DEVICE).await?;
    let alice = alice_member.client.clone();
    let alice_account = alice_member.account.clone();
    let bob = bob_member.client.clone();
    let bob_account = bob_member.account.clone();
    let actor = ActorId::account(bob_account.clone());
    let realm = create_realm_with_join_rule(
        &alice,
        "Circle parent revision",
        "public",
        &[governance, account_station],
    )
    .await?;
    prepare_join(
        &bob,
        &realm,
        governance,
        "ak:request:01904100-0000-7000-8000-000000002861",
        RealmJoinIntent::MemberJoin,
    )
    .await?;
    let join = parent_state(
        &bob,
        &bob_account,
        BOB_DEVICE,
        &realm,
        &bob_account,
        MembershipPayloadState::Join,
    )
    .await?;
    wait_for_committed(&bob, &join.event_ref).await?;

    // The governing Station signs Snapshot heads; the Account replica cannot.
    let parent = alice.parent_membership_revision(&realm, &actor).await?;
    let mut circles = Vec::new();
    let mut circle_mls = Vec::new();
    for (title, history) in [
        ("Parent bound one", "since_join"),
        ("Parent bound two", "all_history_for_current_members"),
    ] {
        let mut create = alice
            .author_event(
                &realm,
                EventKind::CircleCreate.as_str(),
                json!({"object":{"schema":"ak.schema.circle.v1","realm_id":realm,"title":title,
                "display":{"short_name":title,"color_token":"blue","symbol":{"glyph":"lock"}},
                "directory_visibility":"members","join_rule":"public","history_access":history,
                "state":"active","created_by":ActorId::account(alice_account.clone())}}),
            )
            .await?;
        create
            .payload
            .get_mut("object")
            .context("Circle draft omitted its object")?["created_at"] = json!(
            arkret_canonical::format_timestamp_canonical(create.created_at)
        );
        refresh_typed_event_proof(&mut create)?;
        let circle = CircleId::from_event_id(&create.event_id);
        expect_json(
            alice
                .post("/_arkret/self/circles")
                .json(&CircleCreateRequestBody {
                    create_event: EventAdmissionSubmission::new(create),
                }),
            StatusCode::OK,
        )
        .await?;
        grant_circle_actions(&alice_member, &realm, &circle, &bob_member).await?;
        let joined = circle_state(
            &bob,
            &bob_account,
            &realm,
            &circle,
            "join",
            serde_json::Value::Null,
            Some(serde_json::to_value(&parent)?),
        )
        .await?;
        wait_for_committed(&bob, &joined.event_ref).await?;
        expect_json(
            alice.get(&format!("/_arkret/self/circles/{}", circle.as_str())),
            StatusCode::NOT_FOUND,
        )
        .await?;
        // Governance has the authoritative member cut; the member's own
        // Station installs its anchored replica independently.
        expect_json(
            bob.get(&format!("/_arkret/self/circles/{}", circle.as_str())),
            StatusCode::OK,
        )
        .await?;
        let material = if history == "since_join" {
            let material = activate_circle(&bob_member, &realm, &circle).await?;
            assert_circle_mls_reads(&material, &bob, governance, account_station, true).await?;
            Some(material)
        } else {
            None
        };
        assert_circle_stream_scan(&bob, &alice, governance, account_station, &realm, &circle)
            .await?;
        circle_mls.push(material);
        circles.push(circle);
    }

    for material in circle_mls.iter().flatten() {
        expect_json(
            alice
                .post(SELF_MATERIAL)
                .canonical_json(&material.material)?,
            StatusCode::NOT_FOUND,
        )
        .await?;
        expect_json(
            alice
                .post(arkret_wire::PATH_SELF_MLS_ROSTER_AUTHORITY)
                .canonical_json(&material.roster)?,
            StatusCode::NOT_FOUND,
        )
        .await?;
    }
    // A fresh Circle join under the same exact parent generation may read an
    // earlier target only when the declared history policy permits that cut.
    for (index, circle) in circles.iter().enumerate() {
        let left = circle_state(
            &bob,
            &bob_account,
            &realm,
            circle,
            "leave",
            json!("join"),
            None,
        )
        .await?;
        // Leaving revokes Event reads; inspect the exact durable replica cut.
        wait_for_membership_current(&account_db.connect_url, &left, &actor, "leave").await?;
        let joined = circle_state(
            &bob,
            &bob_account,
            &realm,
            circle,
            "join",
            json!("leave"),
            Some(serde_json::to_value(&parent)?),
        )
        .await?;
        wait_for_committed(&bob, &joined.event_ref).await?;
        if let Some(material) = &circle_mls[index] {
            assert_circle_mls_reads(material, &bob, governance, account_station, false).await?;
        }
    }
    let original_rows = canonical_rows(&governance_db.connect_url, &circles, &actor).await?;
    let left = parent_state(
        &bob,
        &bob_account,
        BOB_DEVICE,
        &realm,
        &bob_account,
        MembershipPayloadState::Leave,
    )
    .await?;
    wait_for_membership_current(&account_db.connect_url, &left, &actor, "leave").await?;
    for circle in &circles {
        expect_json(
            bob.get(&format!("/_arkret/self/circles/{}", circle.as_str())),
            StatusCode::NOT_FOUND,
        )
        .await?;
    }
    for material in circle_mls.iter().flatten() {
        assert_circle_mls_reads(material, &bob, governance, account_station, false).await?;
    }
    ensure!(
        canonical_rows(&governance_db.connect_url, &circles, &actor).await? == original_rows,
        "parent leave changed canonical Circle rows or appended Circle Commits"
    );
    prepare_join(
        &bob,
        &realm,
        governance,
        "ak:request:01904100-0000-7000-8000-000000002862",
        RealmJoinIntent::MemberJoin,
    )
    .await?;
    let rejoin = parent_state(
        &bob,
        &bob_account,
        BOB_DEVICE,
        &realm,
        &bob_account,
        MembershipPayloadState::Join,
    )
    .await?;
    wait_for_committed(&bob, &rejoin.event_ref).await?;
    for material in circle_mls.iter().flatten() {
        assert_circle_mls_reads(material, &bob, governance, account_station, false).await?;
    }
    let next_parent = alice.parent_membership_revision(&realm, &actor).await?;
    ensure!(
        serde_json::to_value(&parent)? != serde_json::to_value(&next_parent)?,
        "parent rejoin reused the old exact revision"
    );
    ensure!(
        canonical_rows(&governance_db.connect_url, &circles, &actor).await? == original_rows,
        "parent rejoin rewrote canonical Circle rows"
    );
    // Rejoin alone never revives either Circle, even with all local bytes.
    for circle in &circles {
        expect_json(
            bob.get(&format!("/_arkret/self/circles/{}", circle.as_str())),
            StatusCode::NOT_FOUND,
        )
        .await?;
        circle_state(
            &bob,
            &bob_account,
            &realm,
            circle,
            "leave",
            json!("join"),
            None,
        )
        .await?;
        let joined = circle_state(
            &bob,
            &bob_account,
            &realm,
            circle,
            "join",
            json!("leave"),
            Some(serde_json::to_value(&next_parent)?),
        )
        .await?;
        wait_for_committed(&bob, &joined.event_ref).await?;
        expect_json(
            bob.get(&format!("/_arkret/self/circles/{}", circle.as_str())),
            StatusCode::OK,
        )
        .await?;
    }
    // New Circle joins with the new parent generation do not authorize the
    // old target cut or expose the previous generation's Genesis via history.
    for material in circle_mls.iter().flatten() {
        assert_circle_mls_reads(material, &bob, governance, account_station, false).await?;
    }
    let restored_rows = canonical_rows(&governance_db.connect_url, &circles, &actor).await?;
    let banned = parent_state(
        &alice,
        &alice_account,
        ALICE_DEVICE,
        &realm,
        &bob_account,
        MembershipPayloadState::Ban,
    )
    .await?;
    wait_for_membership_current(&account_db.connect_url, &banned, &actor, "ban").await?;
    for circle in &circles {
        expect_json(
            bob.get(&format!("/_arkret/self/circles/{}", circle.as_str())),
            StatusCode::NOT_FOUND,
        )
        .await?;
    }
    for material in circle_mls.iter().flatten() {
        assert_circle_mls_reads(material, &bob, governance, account_station, false).await?;
    }
    ensure!(
        canonical_rows(&governance_db.connect_url, &circles, &actor).await? == restored_rows,
        "parent ban changed canonical Circle rows or appended Circle Commits"
    );
    Ok(())
}
