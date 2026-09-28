//! A Realm member cannot read a full CircleView until Circle membership is committed.

use std::collections::BTreeSet;

use anyhow::{Result, ensure};
use arkret_wire::{ActorId, CircleId, EventAdmissionSubmission, EventKind, ScopeRef};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::harness::{TestServerGroup, expect_json};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::live_gate::skip_or_fail;
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, database, standard_client, station_env,
};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;

const GROUP: &str = "circle-full-view";
const DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002849";
const OUTSIDER_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002850";
const ABSENT_CIRCLE: &str = "ak:circle:AVBgYTmzSkzTSd1dlFH4ZADaQRkVcx_iTAvXdxlTfxrg";

pub async fn run() -> Result<()> {
    let Some(database) = database(GROUP)? else {
        return Ok(());
    };
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let Some(group) = TestServerGroup::try_multi_external_with_node_envs(
        GROUP,
        &[station_env(&database.connect_url, &coauth)],
    )
    .await?
    else {
        return skip_or_fail(GROUP, "prebuilt Soland unavailable");
    };
    let station = group.server(0);
    let (alice, account) = standard_client(station, &coauth, "circle-view-alice", DEVICE).await?;
    let realm =
        create_realm_with_join_rule(&alice, "Circle full view", "public", &[station]).await?;
    let actor = ActorId::account(account);

    let mut create = alice
        .author_event(
            &realm,
            EventKind::CircleCreate.as_str(),
            json!({"object": {
                "schema": "ak.schema.circle.v1", "realm_id": realm,
                "title": "Private Circle detail", "summary": "Member-only summary",
                "display": {"short_name": "Private Circle", "color_token": "blue",
                    "symbol": {"glyph": "lock"}},
                "directory_visibility": "realm_members", "join_rule": "public",
                "history_access": "since_join", "state": "active",
                "created_by": actor,
            }}),
        )
        .await?;
    create
        .payload
        .get_mut("object")
        .and_then(Value::as_object_mut)
        .expect("Circle create has an object")
        .insert(
            "created_at".to_owned(),
            json!(arkret_canonical::format_timestamp_canonical(
                create.created_at
            )),
        );
    crate::harness::refresh_typed_event_proof(&mut create)?;
    let circle = CircleId::from_event_id(&create.event_id);
    let created = expect_json(
        alice
            .post("/_arkret/self/circles")
            .json(&json!({"create_event": EventAdmissionSubmission::new(create)})),
        StatusCode::OK,
    )
    .await?;
    ensure!(
        created["circle_id"] == circle.as_str(),
        "unexpected Circle create response: {created}"
    );

    let path = format!("/_arkret/self/circles/{}", circle.as_str());
    assert_preview(&alice, &realm, &circle, &path).await?;
    let (outsider, _) =
        standard_client(station, &coauth, "circle-view-outsider", OUTSIDER_DEVICE).await?;
    let hidden = expect_json(outsider.get(&path), StatusCode::NOT_FOUND).await?;
    let absent = expect_json(
        alice.get(&format!("/_arkret/self/circles/{ABSENT_CIRCLE}")),
        StatusCode::NOT_FOUND,
    )
    .await?;
    let hidden_fields: BTreeSet<&str> = hidden
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("hidden Circle error is not an object: {hidden}"))?
        .keys()
        .map(String::as_str)
        .collect();
    let absent_fields: BTreeSet<&str> = absent
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("absent Circle error is not an object: {absent}"))?
        .keys()
        .map(String::as_str)
        .collect();
    ensure!(
        hidden_fields == absent_fields && hidden["type"] == absent["type"],
        "hidden and absent Circle errors disclose a different shape: {hidden} / {absent}"
    );

    let mut join = alice
        .author_event(
            &realm,
            EventKind::CircleMemberState.as_str(),
            json!({"circle_id":circle,"member_id":actor,"membership":"join",
            "expected_membership":null}),
        )
        .await?;
    join.scope_ref = ScopeRef::Circle {
        realm_id: join.realm_id.clone(),
        circle_id: circle.clone(),
    };
    crate::harness::refresh_typed_event_proof(&mut join)?;
    expect_json(
        alice
            .post(&format!("{path}/members"))
            .json(&json!({"member_event": EventAdmissionSubmission::new(join)})),
        StatusCode::OK,
    )
    .await?;
    let detail = expect_json(alice.get(&path), StatusCode::OK).await?;
    ensure!(
        detail["title"] == "Private Circle detail",
        "joined member lost full view: {detail}"
    );
    let listed = list_views(&alice, &realm).await?;
    ensure!(
        listed
            .iter()
            .any(|view| view["circle_id"] == circle.as_str()),
        "joined member missing from Circle full-view list: {listed:?}"
    );

    let mut leave = alice
        .author_event(
            &realm,
            EventKind::CircleMemberState.as_str(),
            json!({"circle_id":circle,"member_id":actor,"membership":"leave",
                "expected_membership":"join"}),
        )
        .await?;
    leave.scope_ref = ScopeRef::Circle {
        realm_id: leave.realm_id.clone(),
        circle_id: circle.clone(),
    };
    crate::harness::refresh_typed_event_proof(&mut leave)?;
    let actor_path: String =
        url::form_urlencoded::byte_serialize(serde_json::to_string(&actor)?.as_bytes()).collect();
    expect_json(
        alice
            .delete(&format!("{path}/members/{actor_path}"))
            .json(&json!({"member_event": EventAdmissionSubmission::new(leave)})),
        StatusCode::OK,
    )
    .await?;
    assert_preview(&alice, &realm, &circle, &path).await?;

    let mut hidden_create = alice
        .author_event(
            &realm,
            EventKind::CircleCreate.as_str(),
            json!({"object": {
                "schema": "ak.schema.circle.v1", "realm_id": realm,
                "title": "Members-only detail",
                "display": {"short_name": "Members only", "color_token": "blue",
                    "symbol": {"glyph": "lock"}},
                "directory_visibility": "members", "join_rule": "public",
                "history_access": "since_join", "state": "active",
                "created_by": actor,
            }}),
        )
        .await?;
    hidden_create
        .payload
        .get_mut("object")
        .and_then(Value::as_object_mut)
        .expect("Circle create has an object")
        .insert(
            "created_at".to_owned(),
            json!(arkret_canonical::format_timestamp_canonical(
                hidden_create.created_at
            )),
        );
    crate::harness::refresh_typed_event_proof(&mut hidden_create)?;
    let hidden_circle = CircleId::from_event_id(&hidden_create.event_id);
    expect_json(
        alice
            .post("/_arkret/self/circles")
            .json(&json!({"create_event": EventAdmissionSubmission::new(hidden_create)})),
        StatusCode::OK,
    )
    .await?;
    let members_only = expect_json(
        alice.get(&format!("/_arkret/self/circles/{}", hidden_circle.as_str())),
        StatusCode::NOT_FOUND,
    )
    .await?;
    let members_fields: BTreeSet<&str> = members_only
        .as_object()
        .ok_or_else(|| {
            anyhow::anyhow!("hidden members-only error is not an object: {members_only}")
        })?
        .keys()
        .map(String::as_str)
        .collect();
    ensure!(
        members_fields == absent_fields && members_only["type"] == absent["type"],
        "members-only and absent Circle errors differ: {members_only} / {absent}"
    );
    assert_preview(&alice, &realm, &circle, &path).await?;
    Ok(())
}

async fn list_views(alice: &crate::harness::TestActorClient, realm: &str) -> Result<Vec<Value>> {
    let response = expect_json(
        alice.get(&format!("/_arkret/self/circles?realm_id={realm}")),
        StatusCode::OK,
    )
    .await?;
    let views = response
        .get("circles")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("Circle list has no canonical circles array: {response}"))?;
    Ok(views.clone())
}

async fn assert_preview(
    alice: &crate::harness::TestActorClient,
    realm: &str,
    circle: &CircleId,
    path: &str,
) -> Result<()> {
    let preview = expect_json(alice.get(path), StatusCode::OK).await?;
    assert_exact_preview(&preview, realm, circle)?;
    let listed = list_views(alice, realm).await?;
    ensure!(
        listed.len() == 1,
        "Circle preview list has unexpected rows: {listed:?}"
    );
    assert_exact_preview(&listed[0], realm, circle)?;
    Ok(())
}

fn assert_exact_preview(value: &Value, realm: &str, circle: &CircleId) -> Result<()> {
    let fields: BTreeSet<&str> = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("Circle preview is not an object: {value}"))?
        .keys()
        .map(String::as_str)
        .collect();
    ensure!(
        fields
            == BTreeSet::from([
                "circle_id",
                "realm_id",
                "visibility",
                "display",
                "member_count_bucket",
                "join_rule",
                "opaque_commitment"
            ]),
        "Circle preview has noncanonical fields: {value}"
    );
    ensure!(value["circle_id"] == circle.as_str() && value["realm_id"] == realm);
    ensure!(value["visibility"] == "realm_members" && value["join_rule"] == "public");
    ensure!(
        value["member_count_bucket"] == "0",
        "founder/left Circle must have no members: {value}"
    );
    let display_fields: BTreeSet<&str> = value["display"]
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("Circle preview display is not an object: {value}"))?
        .keys()
        .map(String::as_str)
        .collect();
    ensure!(display_fields == BTreeSet::from(["color_token", "symbol"]));
    let commitment = hex::encode(Sha256::digest(
        format!("ak.circle.preview.v1\0{realm}\0{}", circle.as_str()).as_bytes(),
    ));
    ensure!(
        value["opaque_commitment"] == commitment,
        "Circle preview commitment differs: {value}"
    );
    Ok(())
}
