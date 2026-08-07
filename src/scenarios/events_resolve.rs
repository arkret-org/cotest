//! Live self-events resolve coverage against a spawned soland process.

use anyhow::{Result, anyhow};
use arkret_models_collaboration::event_query::EventsDescribeRequestBody;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{TestServerGroup, expect_json, expect_response};

pub async fn events_resolve_selector_budget_run() -> Result<()> {
    let group = TestServerGroup::single("events-resolve-selectors").await?;
    let server = group.server(0);
    let alice = server
        .register_client(
            "did:web:events-resolve-alice.example",
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

    let missing_seal = format!("ak:seal:sha256:{}", "1".repeat(64));
    let seal_only = expect_json(
        alice
            .query("/_arkret/self/events/resolve")
            .json(&serde_json::from_value::<
                arkret_models_collaboration::http_bodies::EventsResolveRequestBody,
            >(json!({"seal_refs": [missing_seal]}))?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(seal_only["missing"], json!([missing_seal]));
    assert!(
        seal_only
            .get("unauthorized")
            .is_none_or(|value| value.is_null() || value.as_array().is_some_and(Vec::is_empty))
    );

    let missing_event = "ak:event:Af0YczSWD-8X4lrK2BH5wtPMV43kWXeGhVnctg-7ZeGb";
    let missing_digest = format!("sha256:{}", "2".repeat(64));
    let mixed = expect_json(
        alice
            .query("/_arkret/self/events/resolve")
            .json(&serde_json::from_value::<
                arkret_models_collaboration::http_bodies::EventsResolveRequestBody,
            >(json!({
                "event_ids": [missing_event],
                "event_digests": [missing_digest],
                "seal_refs": [missing_seal]
            }))?),
        StatusCode::OK,
    )
    .await?;
    let mixed_missing = mixed["missing"]
        .as_array()
        .ok_or_else(|| anyhow!("mixed resolve missing[] absent: {mixed}"))?;
    assert_eq!(mixed_missing.len(), 3);
    assert!(mixed_missing.iter().any(|value| value == missing_event));
    assert!(
        mixed_missing
            .iter()
            .any(|value| value == &json!(missing_digest))
    );
    assert!(
        mixed_missing
            .iter()
            .any(|value| value == &json!(missing_seal))
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
                "seal_refs": [missing_seal]
            }))?),
        StatusCode::FORBIDDEN,
    )
    .await?;
    let over_budget_body: Value = over_budget.json()?;
    let code = over_budget_body
        .pointer("/error/code")
        .or_else(|| over_budget_body.pointer("/error/errcode"))
        .and_then(Value::as_str);
    assert_eq!(code, Some("quota_exceeded"));

    Ok(())
}
