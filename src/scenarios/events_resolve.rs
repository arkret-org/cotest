//! Live self-events resolve coverage against a spawned soland process.

use anyhow::{Result, anyhow};
use arkret_models_collaboration::event_query::EventsDescribeRequestBody;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{TestServerGroup, expect_json, expect_response};
use crate::scenarios::identity_test_support::actor_did_for_service_did;

pub async fn events_resolve_selector_budget_run() -> Result<()> {
    let group = TestServerGroup::single("events-resolve-selectors").await?;
    let server = group.server(0);
    let alice_did = actor_did_for_service_did(server.service_did(), "events-resolve-alice")?;
    let alice = server
        .register_client(
            &alice_did,
            "@events-resolve-alice",
            "ak:device:01904100-0000-7000-8000-00000000e501",
        )
        .await?;

    let describe = expect_json(
        alice
            .query("/_arkret/self/events/describe")
            .json(&EventsDescribeRequestBody::default()),
        StatusCode::OK,
    )
    .await?;
    let max_resolve = describe
        .pointer("/limits/max_resolve")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("describe missing limits.max_resolve: {describe}"))?
        as usize;
    assert_eq!(max_resolve, arkret_wire::MAX_EVENT_RESOLVE);

    let realm_id = alice.create_realm("events-resolve-seal-selectors").await?;
    let missing_seal = format!("ak:seal:sha256:{}", "1".repeat(64));
    let seal_only = expect_json(
        alice
            .query("/_arkret/self/seals/resolve")
            .json(&serde_json::from_value::<
                arkret_models_collaboration::http_bodies::SelfSealResolveRequestBody,
            >(
                json!({"realm_id": realm_id, "seal_refs": [missing_seal]}),
            )?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(seal_only["missing_seal_refs"], json!([missing_seal]));
    assert_eq!(seal_only["seals"], json!([]));

    let missing_event = "ak:event:Af0YczSWD-8X4lrK2BH5wtPMV43kWXeGhVnctg-7ZeGb";
    let missing_digest = format!("sha256:{}", "2".repeat(64));
    let mixed = expect_json(
        alice
            .query("/_arkret/self/events/resolve")
            .json(&serde_json::from_value::<
                arkret_models_collaboration::http_bodies::EventsResolveRequestBody,
            >(json!({
                "event_ids": [missing_event],
                "event_digests": [missing_digest]
            }))?),
        StatusCode::OK,
    )
    .await?;
    let mixed_missing = mixed["missing"]
        .as_array()
        .ok_or_else(|| anyhow!("mixed resolve missing[] absent: {mixed}"))?;
    assert_eq!(mixed_missing.len(), 2);
    assert!(mixed_missing.iter().any(|value| value == missing_event));
    assert!(
        mixed_missing
            .iter()
            .any(|value| value == &json!(missing_digest))
    );

    let at_budget: Vec<String> = (0..max_resolve)
        .map(|index| crate::fixture_event_id(format!("events-resolve:{index}")).to_string())
        .collect();
    let at_budget_outcome = expect_json(
        alice
            .query("/_arkret/self/events/resolve")
            .json(&serde_json::from_value::<
                arkret_models_collaboration::http_bodies::EventsResolveRequestBody,
            >(json!({"event_ids": at_budget}))?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        at_budget_outcome["missing"].as_array().map(Vec::len),
        Some(max_resolve)
    );

    let over_budget = expect_response(
        alice
            .query("/_arkret/self/events/resolve")
            .json(&serde_json::from_value::<
                arkret_models_collaboration::http_bodies::EventsResolveRequestBody,
            >(json!({
                "event_ids": at_budget,
                "event_digests": [missing_digest]
            }))?),
        StatusCode::PAYLOAD_TOO_LARGE,
    )
    .await?;
    let over_budget_problem: arkret_wire::Problem = serde_json::from_value(over_budget.json()?)?;
    assert_eq!(over_budget_problem.code(), "limit_exceeded");

    Ok(())
}
