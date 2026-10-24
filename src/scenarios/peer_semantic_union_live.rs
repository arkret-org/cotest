//! Real peer HTTP consumption of the closed submission carrier union.
//! This bounded carrier runner does not claim all 86 canonical semantic variants.
use anyhow::{Context, Result, bail, ensure};
use arkret_models_collaboration::authority_commit::{
    CommittedEventReplicationOutcome, PeerAuthoritySubmitResponseBody,
};
use arkret_models_collaboration::governance::membership_invite::MembershipPayloadState;
use arkret_models_collaboration::governance::realm_join_intake::RealmJoinIntent;
use arkret_wire::{
    AccountId, AuthorityCommitStatus, AuthoritySubmitResponseBody, Event, EventAdmissionSubmission,
    EventKind, RealmCommit,
};
use serde_json::{Value, json};

use crate::harness::{TestActorClient, TestServerGroup, expect_json};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::fanout_route_miss_live::replication_body;
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, database, membership_payload, prepare_join, standard_client,
    station_env, wait_for_committed,
};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;

const GROUP: &str = "peer-semantic-union-live";
const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000003401";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000003402";

/// These new production consumers retain the accepted Account/device signer
/// and send the SDK's exact canonical carrier bytes over the real self rail.
pub(crate) async fn submit_and_expect_commit(
    client: &TestActorClient,
    account: &AccountId,
    device: &str,
    event: &Event,
) -> Result<RealmCommit> {
    let producer = event
        .account_device_producer()?
        .context("accepted Account device producer required")?;
    ensure!(
        &producer.account_id == account && producer.device_id.as_str() == device,
        "Event signer does not match the original accepted Account/device"
    );
    let submission = EventAdmissionSubmission::new(event.clone());
    let outcome: AuthoritySubmitResponseBody = serde_json::from_value(
        expect_json(
            client
                .post("/_arkret/self/events")
                .header("content-type", "application/json")
                .body(arkret_canonical::canonical_json_bytes(&submission)?),
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    let AuthoritySubmitResponseBody::Accepted { status, commit } = outcome else {
        bail!("authored Event was not accepted as committed");
    };
    ensure!(
        status == AuthorityCommitStatus::Committed && commit.event_ref == event.event_id,
        "acceptance does not name the original submitted Event"
    );
    commit.validate_shape()?;
    Ok(commit)
}

/// Event/Commit/current rows are compared as bytes/values, not counts alone.
/// The selected tables are durable business effects; delivery retry bookkeeping
/// is excluded because a pre-existing fanout retry can progress independently.
pub(crate) async fn realm_business_footprint(database: &str, realm: &str) -> Result<Value> {
    let database = database.to_owned();
    let realm = realm.to_owned();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        let tables = db.query("SELECT table_name FROM information_schema.columns WHERE table_schema='public' AND column_name='realm_id' AND (table_name IN ('canonical_events','realm_commits','notifications','event_notification_relay','capability_quota_counters','capability_quota_buckets','capability_quota_consumptions') OR right(table_name,16)='_current_states') ORDER BY table_name", &[])?;
        let mut result = serde_json::Map::new();
        for table in tables {
            let name: String = table.get(0);
            // Names originate in PostgreSQL metadata, still quote every identifier.
            let quoted = name.replace('"', "\"\"");
            let sql = format!("SELECT COALESCE(jsonb_agg(business_row ORDER BY business_row::text),'[]'::jsonb) FROM (SELECT to_jsonb(t) AS business_row FROM \"{quoted}\" t WHERE realm_id=$1) rows");
            let rows: Value = db.query_one(&sql, &[&realm])?.get(0);
            result.insert(name, rows);
        }
        // Quota tables deliberately have no realm_id column: anchor them
        // through the target Realm's accepted grant cells instead of omitting them.
        for table in ["capability_quota_counters", "capability_quota_buckets", "capability_quota_consumptions"] {
            let sql = format!("SELECT COALESCE(jsonb_agg(business_row ORDER BY business_row::text),'[]'::jsonb) FROM (SELECT to_jsonb(t) AS business_row FROM {table} t WHERE grant_id IN (SELECT grant_id FROM capability_grant_current_states WHERE realm_id=$1)) rows");
            result.insert(table.to_owned(), db.query_one(&sql, &[&realm])?.get(0));
        }
        ensure!(result.contains_key("canonical_events") && result.contains_key("realm_commits"), "durable effect tables absent");
        Ok(Value::Object(result))
    }).await?
}

pub async fn run() -> Result<()> {
    let account_db = database(GROUP)?
        .ok_or_else(|| anyhow::anyhow!("peer carrier runner requires real PostgreSQL"))?;
    let governance_db = database(GROUP)?
        .ok_or_else(|| anyhow::anyhow!("peer carrier runner requires real PostgreSQL"))?;
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let group = TestServerGroup::try_multi_external_with_node_envs(
        GROUP,
        &[
            station_env(&account_db.connect_url, &coauth),
            station_env(&governance_db.connect_url, &coauth),
        ],
    )
    .await?
    .ok_or_else(|| anyhow::anyhow!("peer carrier runner requires prebuilt production Coland"))?;
    let (alice, _) =
        standard_client(group.server(1), &coauth, "peer-union-owner", ALICE_DEVICE).await?;
    let (bob, bob_account) =
        standard_client(group.server(0), &coauth, "peer-union-member", BOB_DEVICE).await?;
    let realm = create_realm_with_join_rule(
        &alice,
        "Peer semantic carrier consumption",
        "public",
        &[group.server(0), group.server(1)],
    )
    .await?;
    prepare_join(
        &bob,
        &realm,
        group.server(1),
        "ak:request:01904100-0000-7000-8000-000000003401",
        RealmJoinIntent::MemberJoin,
    )
    .await?;
    let join = bob
        .author_event(
            &realm,
            EventKind::MemberState.as_str(),
            membership_payload(
                &realm,
                bob_account.clone(),
                MembershipPayloadState::Join,
                "peer carrier consumer",
            )?,
        )
        .await?;
    let commit = submit_and_expect_commit(&bob, &bob_account, BOB_DEVICE, &join).await?;
    wait_for_committed(&bob, &join.event_id).await?;
    let exact: Value = serde_json::from_slice(&replication_body(&bob, &join, &commit).await?)?;
    let before = realm_business_footprint(&account_db.connect_url, &realm).await?;
    // Exact duplicate is a real authenticated service request, with original source Commit.
    let (status, answer) = group
        .server(0)
        .signed_peer_post(
            group.server(1),
            "/_arkret/peer/events",
            &arkret_canonical::canonical_json_bytes(&exact)?,
            group.server(0).service_id(),
        )
        .await?;
    ensure!(status.is_success(), "exact peer replay failed: {status}");
    let outcome: PeerAuthoritySubmitResponseBody = serde_json::from_slice(&answer)?;
    ensure!(
        matches!(outcome, PeerAuthoritySubmitResponseBody::CommittedReplication(ref value) if matches!(value.replication_outcomes.as_slice(), [CommittedEventReplicationOutcome::Duplicate {}])),
        "peer duplicate created a new acceptance"
    );
    ensure!(
        realm_business_footprint(&account_db.connect_url, &realm).await? == before,
        "duplicate mutated durable business rows"
    );
    // Retired or cross-branch carriers must reach the real router and reject
    // before any Event/current/notification/quota effect.
    for (name, malformed) in [
        ("missing_source_commit", {
            let mut x = exact.clone();
            x["replications"][0]
                .as_object_mut()
                .unwrap()
                .remove("source_commit");
            x
        }),
        ("approval_signatures_on_committed_replication", {
            let mut x = exact.clone();
            x["replications"][0]["event_submission"]["approval_signatures"] = json!([]);
            x
        }),
        ("wire_recipient_witness_rejected", {
            let mut x = exact.clone();
            x["replications"][0]["recipient_witness"] = json!({});
            x
        }),
        ("wire_processing_rejected", {
            let mut x = exact.clone();
            x["replications"][0]["processing"] = json!({});
            x
        }),
        ("mixed_authority_forward_and_replication", {
            let mut x = exact.clone();
            x["event_submission"] = json!({"event":join});
            x
        }),
    ] {
        let (status, answer) = group
            .server(0)
            .signed_peer_post(
                group.server(1),
                "/_arkret/peer/events",
                &arkret_canonical::canonical_json_bytes(&malformed)?,
                group.server(0).service_id(),
            )
            .await?;
        ensure!(
            status == reqwest::StatusCode::BAD_REQUEST
                || status == reqwest::StatusCode::UNPROCESSABLE_ENTITY,
            "{name} reached unexpected decision {status}: {}",
            String::from_utf8_lossy(&answer)
        );
        let problem: Value = serde_json::from_slice(&answer)?;
        ensure!(
            problem["type"]
                .as_str()
                .is_some_and(|kind| kind.ends_with("/schema_violation")),
            "{name} failed before its schema oracle: {problem}"
        );
        ensure!(
            realm_business_footprint(&account_db.connect_url, &realm).await? == before,
            "{name} mutated durable business rows"
        );
    }
    Ok(())
}
