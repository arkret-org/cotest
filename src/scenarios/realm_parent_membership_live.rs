//! Real signed parent-membership admission, including a durable-lock race.
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::governance::membership_invite::MembershipPayloadState;
use arkret_wire::{AccountId, EventAdmissionSubmission, EventKind, RealmId};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    TestActorClient, TestServerGroup, expect_json, ordinary_realm_bootstrap_submission,
    realm_bootstrap_event_batch_for_device, realm_create_payload_for_station,
};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, database, membership_payload, standard_client, station_env,
};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;
use crate::scenarios::peer_semantic_union_live::{
    realm_business_footprint, submit_and_expect_commit,
};

const OWNER: &str = "ak:device:01904100-0000-7000-8000-000000003421";
const MEMBER: &str = "ak:device:01904100-0000-7000-8000-000000003422";
const FOREIGN: &str = "ak:device:01904100-0000-7000-8000-000000003423";

async fn state(
    client: &TestActorClient,
    account: &AccountId,
    realm: &str,
    membership: MembershipPayloadState,
) -> Result<arkret_wire::Event> {
    client
        .author_event(
            realm,
            EventKind::MemberState.as_str(),
            membership_payload(
                realm,
                account.clone(),
                membership,
                "current parent membership admission",
            )?,
        )
        .await
}
async fn reject(client: &TestActorClient, event: arkret_wire::Event) -> Result<()> {
    let response = client
        .post("/_arkret/self/events")
        .header("content-type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(
            &EventAdmissionSubmission::new(event),
        )?)
        .send()
        .await?;
    let status = response.status();
    let problem: Value = response.json().await?;
    ensure!(
        status == StatusCode::FORBIDDEN
            && problem["type"] == "https://arkret.org/problems/capability_denied"
            && problem["reason_code"] == "gate_check_failed",
        "parent cut refusal was {status}: {problem}"
    );
    Ok(())
}
fn next_policy(footprint: &Value, source: &str) -> Result<Value> {
    let current: arkret_models_collaboration::events_payloads::realm::RealmPolicyBundlePayload =
        serde_json::from_value(
            footprint["realm_policy_bundle_current_states"][0]["value"].clone(),
        )?;
    let mut next = current.restate(current.policy_revision + 1);
    next.join_policy = Some(serde_json::from_value(
        json!({"gates":[{"gate_id":"current-parent",
        "kind":"parent_membership","membership_source_realm_ids":[source],"require_min_membership":"join"}],
        "combinator":"all"}),
    )?);
    Ok(serde_json::to_value(next)?)
}
async fn link(
    owner: &TestActorClient,
    account: &AccountId,
    target: &str,
    source: &str,
) -> Result<()> {
    let event = owner
        .author_event(
            target,
            EventKind::RealmLink.as_str(),
            json!({"target_realm_id":source,
        "link_kind":"join_gate_from","status":"active"}),
        )
        .await?;
    submit_and_expect_commit(owner, account, OWNER, &event).await?;
    Ok(())
}

pub async fn run() -> Result<()> {
    let db =
        database("realm-parent-membership-live")?.context("parent gate requires PostgreSQL")?;
    let foreign_db = database("realm-parent-membership-live-foreign")?
        .context("foreign parent requires PostgreSQL")?;
    let authority = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let group = TestServerGroup::try_multi_external_with_node_envs(
        "realm-parent-membership-live",
        &[
            station_env(&db.connect_url, &authority),
            station_env(&foreign_db.connect_url, &authority),
        ],
    )
    .await?
    .context("parent gate requires production Coland")?;
    let station = group.server(0);
    let (owner, owner_account) =
        standard_client(station, &authority, "parent-owner", OWNER).await?;
    let (member, member_account) =
        standard_client(station, &authority, "parent-applicant", MEMBER).await?;
    let (foreign, _) =
        standard_client(group.server(1), &authority, "parent-foreign-owner", FOREIGN).await?;
    // Select only offline genesis salts so target is the first canonical lock.
    // No rejected HTTP bootstrap or retry of a denied admission is hidden here.
    let target_draft = realm_create_payload_for_station(
        owner.service_id(),
        &json!({"title":"Parent-gated target",
        "join_rule":"restricted","join_policy":{"gates":[{"gate_id":"setup","kind":"claim_required",
        "required_claims":["setup"],"trusted_issuer_ids":[station.service_id()]}],"combinator":"all"}}),
    )?;
    let (target, target_events) = realm_bootstrap_event_batch_for_device(
        &owner.actor,
        OWNER,
        station.service_id(),
        target_draft,
    )?;
    let target_id = RealmId::new(target.clone())?;
    let mut source_draft = None;
    for _ in 0..1024 {
        let draft = realm_create_payload_for_station(
            owner.service_id(),
            &json!({"title":"Authoritative parent","join_rule":"public"}),
        )?;
        let (id, events) = realm_bootstrap_event_batch_for_device(
            &owner.actor,
            OWNER,
            station.service_id(),
            draft,
        )?;
        if RealmId::new(id.clone())?.token_bytes() > target_id.token_bytes() {
            source_draft = Some((id, events));
            break;
        }
    }
    let (source, source_events) =
        source_draft.context("select canonical target-first offline bootstrap order")?;
    for (id, events) in [(&target, target_events), (&source, source_events)] {
        let request = ordinary_realm_bootstrap_submission(events)?;
        let result: arkret_models_collaboration::authority_commit::SelfAuthoritySubmitResponseBody =
            serde_json::from_value(
                expect_json(
                    owner
                        .post("/_arkret/self/events")
                        .header("content-type", "application/json")
                        .body(arkret_canonical::canonical_json_bytes(&request)?),
                    StatusCode::OK,
                )
                .await?,
            )?;
        result.validate_for_request(&arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::OrdinaryRealmBootstrap(request))?;
        ensure!(
            matches!(result, arkret_models_collaboration::authority_commit::SelfAuthoritySubmitResponseBody::OrdinaryRealmBootstrap(ref accepted)
                if accepted.status == arkret_models_collaboration::authority_commit::AggregateAcceptanceStatus::Committed),
            "bootstrap was not committed"
        );
        owner.track_controlled_realm(&RealmId::new(id.clone())?);
    }
    // Missing active relationship is refused even for the genuine target owner.
    let before = realm_business_footprint(&db.connect_url, &target).await?;
    let event = owner
        .author_event(
            &target,
            EventKind::RealmPolicyBundle.as_str(),
            next_policy(&before, &source)?,
        )
        .await?;
    reject(&owner, event).await?;
    ensure!(
        realm_business_footprint(&db.connect_url, &target).await? == before,
        "missing link wrote target state"
    );
    link(&owner, &owner_account, &target, &source).await?;
    let before = realm_business_footprint(&db.connect_url, &target).await?;
    let event = owner
        .author_event(
            &target,
            EventKind::RealmPolicyBundle.as_str(),
            next_policy(&before, &source)?,
        )
        .await?;
    submit_and_expect_commit(&owner, &owner_account, OWNER, &event).await?;
    let before = realm_business_footprint(&db.connect_url, &target).await?;
    reject(
        &member,
        state(
            &member,
            &member_account,
            &target,
            MembershipPayloadState::Join,
        )
        .await?,
    )
    .await?;
    ensure!(
        realm_business_footprint(&db.connect_url, &target).await? == before,
        "nonmember parent gate wrote target"
    );
    let joined = state(
        &member,
        &member_account,
        &source,
        MembershipPayloadState::Join,
    )
    .await?;
    submit_and_expect_commit(&member, &member_account, MEMBER, &joined).await?;
    // Hold target's actual authority row. While admission is demonstrably waiting
    // on that lock, accept a genuine source leave, then release the target lock.
    let dsn = db.connect_url.clone();
    let locked_target = target.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let lock = tokio::task::spawn_blocking(move || -> Result<()> {
        let mut db = postgres::Client::connect(&dsn, postgres::NoTls)?;
        let mut tx = db.transaction()?;
        tx.query_one(
            "SELECT generation FROM realm_authorities WHERE realm_id=$1 FOR UPDATE",
            &[&locked_target],
        )?;
        let pid: i32 = tx.query_one("SELECT pg_backend_pid()", &[])?.get(0);
        ready_tx
            .send(pid)
            .map_err(|_| anyhow::anyhow!("lock observer dropped"))?;
        release_rx.recv_timeout(Duration::from_secs(90))?;
        tx.commit()?;
        Ok(())
    });
    let blocker = ready_rx.await?;
    let target_join = state(
        &member,
        &member_account,
        &target,
        MembershipPayloadState::Join,
    )
    .await?;
    let before = realm_business_footprint(&db.connect_url, &target).await?;
    let waiting_client = member.clone();
    let join = tokio::spawn(async move { reject(&waiting_client, target_join).await });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let dsn = db.connect_url.clone();
        let waiting=tokio::task::spawn_blocking(move||->Result<bool>{let mut db=postgres::Client::connect(&dsn,postgres::NoTls)?;
            Ok(db.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",&[&blocker])?.get(0))}).await??;
        if waiting {
            break;
        }
        ensure!(
            !join.is_finished() && tokio::time::Instant::now() < deadline,
            "target did not wait on durable authority lock"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let leave = state(
        &member,
        &member_account,
        &source,
        MembershipPayloadState::Leave,
    )
    .await?;
    submit_and_expect_commit(&member, &member_account, MEMBER, &leave).await?;
    release_tx.send(())?;
    lock.await??;
    join.await??;
    ensure!(
        realm_business_footprint(&db.connect_url, &target).await? == before,
        "lock-raced admission left target durable effects"
    );
    let rejoin = state(
        &member,
        &member_account,
        &source,
        MembershipPayloadState::Join,
    )
    .await?;
    submit_and_expect_commit(&member, &member_account, MEMBER, &rejoin).await?;
    let allowed = state(
        &member,
        &member_account,
        &target,
        MembershipPayloadState::Join,
    )
    .await?;
    submit_and_expect_commit(&member, &member_account, MEMBER, &allowed).await?;
    // An active link is insufficient when current governance services differ.
    let foreign_source = create_realm_with_join_rule(
        &foreign,
        "Foreign current authority",
        "public",
        &[group.server(1)],
    )
    .await?;
    crate::scenarios::human_device_producer_live::prepare_join(
        &owner,
        &foreign_source,
        group.server(1),
        "ak:request:01904100-0000-7000-8000-000000003423",
        arkret_models_collaboration::governance::realm_join_intake::RealmJoinIntent::MemberJoin,
    )
    .await?;
    let foreign_join = state(
        &owner,
        &owner_account,
        &foreign_source,
        MembershipPayloadState::Join,
    )
    .await?;
    submit_and_expect_commit(&owner, &owner_account, OWNER, &foreign_join).await?;
    crate::scenarios::human_device_producer_live::wait_for_committed(
        &owner,
        &foreign_join.event_id,
    )
    .await?;
    link(&owner, &owner_account, &target, &foreign_source).await?;
    let before = realm_business_footprint(&db.connect_url, &target).await?;
    let event = owner
        .author_event(
            &target,
            EventKind::RealmPolicyBundle.as_str(),
            next_policy(&before, &foreign_source)?,
        )
        .await?;
    reject(&owner, event).await?;
    ensure!(
        realm_business_footprint(&db.connect_url, &target).await? == before,
        "foreign current tenure wrote target state"
    );
    Ok(())
}
