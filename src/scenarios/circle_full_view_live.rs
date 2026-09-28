//! A Realm member cannot read a full CircleView until Circle membership is committed.

use anyhow::{Result, ensure};
use arkret_wire::{ActorId, CircleId, EventAdmissionSubmission, EventKind, ScopeRef};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{TestServerGroup, expect_json};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::live_gate::skip_or_fail;
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, database, standard_client, station_env,
};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;

const GROUP: &str = "circle-full-view";
const DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002849";

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
    assert_full_view_absent(&alice, &realm, &path).await?;

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
    assert_full_view_absent(&alice, &realm, &path).await?;
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
        .or_else(|| response.get("circle_views"))
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("Circle list has no view array: {response}"))?;
    Ok(views.clone())
}

async fn assert_full_view_absent(
    alice: &crate::harness::TestActorClient,
    realm: &str,
    path: &str,
) -> Result<()> {
    let response = alice.get(path).send().await?;
    let status = response.status();
    let value: Value = response.json().await?;
    match status {
        StatusCode::NOT_FOUND => ensure!(
            value["type"] == "https://arkret.org/problems/not_found",
            "Circle read returned an unexpected refusal: {value}"
        ),
        StatusCode::OK => assert_no_private_detail(&value)?,
        other => anyhow::bail!("Circle non-member read returned {other}: {value}"),
    }
    for item in list_views(alice, realm).await? {
        assert_no_private_detail(&item)?;
    }
    Ok(())
}

fn assert_no_private_detail(value: &Value) -> Result<()> {
    for key in ["title", "summary", "created_by", "member_ids"] {
        ensure!(
            value.get(key).is_none(),
            "Circle preview leaked {key}: {value}"
        );
    }
    ensure!(
        value.pointer("/display/short_name").is_none(),
        "Circle preview leaked display.short_name: {value}"
    );
    Ok(())
}
