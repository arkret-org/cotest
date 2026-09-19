//! Protocol-level conformance for the public Agent draft pending-intent account channel.
//!
//! This lane intentionally uses only the canonical artifacts and the public SDK
//! frame parser. It does not insert Station rows or call the private pending
//! ledger. Product E2E remains a separate gate once the Soland harness builds
//! against the current SDK.

use std::fs;

use anyhow::{Context, Result, anyhow, ensure};
use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeFrame, AgentDraftPendingIntentChange, AgentDraftPendingIntentContainer,
};
use serde_json::{Value, json};

use super::{load_artifact_json, spec_artifacts_root};
use crate::conformance::schema_validation_fixture::{schema_invalid, schema_valid};

const LOCAL_FIXTURE: &str = "agent-draft-pending-intent-account-subscribe.json";
const CANONICAL_FIXTURE: &str = "agent-draft-pending-intent-fixture.json";
const FRAME_SCHEMA: &str = "schemas/account-subscribe-frame.schema.json";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentDraftPendingIntentAccountSubscribeCoverage {
    pub assertions: usize,
    pub protocol_cases: Vec<&'static str>,
}

pub fn run_agent_draft_pending_intent_account_subscribe_conformance()
-> Result<AgentDraftPendingIntentAccountSubscribeCoverage> {
    let fixture = load_local_fixture()?;
    ensure!(
        fixture["canonical_fixture"] == CANONICAL_FIXTURE,
        "local carrier fixture must name the canonical pending-intent fixture"
    );
    ensure!(
        fixture["schema_ref"] == FRAME_SCHEMA,
        "local carrier fixture must validate the complete public frame"
    );
    assert_templates_match_canonical_fixture(&fixture)?;

    let mut assertions = assert_holder_only_contract(&fixture)?;
    assertions += assert_baseline_paging(&fixture)?;
    assertions += assert_delta_upsert_and_remove(&fixture)?;
    assertions += assert_terminal_redaction(&fixture)?;
    assertions += assert_resync_restarts_private_offset(&fixture)?;
    assertions += assert_max_100(&fixture)?;
    assertions += assert_legacy_four_channels_remain_valid(&fixture)?;

    Ok(AgentDraftPendingIntentAccountSubscribeCoverage {
        assertions,
        protocol_cases: vec![
            "holder_only_contract",
            "baseline_private_offset_paging",
            "delta_upsert_remove",
            "live_to_terminal_redaction",
            "resync_restarts_private_offset",
            "combined_max_100",
            "legacy_four_channels_unchanged",
        ],
    })
}

fn load_local_fixture() -> Result<Value> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(LOCAL_FIXTURE);
    serde_json::from_slice(&fs::read(&path).with_context(|| format!("read {}", path.display()))?)
        .with_context(|| format!("parse {}", path.display()))
}

fn assert_templates_match_canonical_fixture(fixture: &Value) -> Result<()> {
    let path = spec_artifacts_root()
        .join("fixtures")
        .join(CANONICAL_FIXTURE);
    let canonical: Value = serde_json::from_slice(
        &fs::read(&path).with_context(|| format!("read {}", path.display()))?,
    )?;
    for (local_name, canonical_name) in [
        ("live", "agent_draft_pending_intent_live_available_valid"),
        (
            "terminal",
            "agent_draft_pending_intent_consumed_redacted_valid",
        ),
    ] {
        let expected = canonical["schema_validation_cases"]
            .as_array()
            .and_then(|cases| {
                cases
                    .iter()
                    .find(|case| case["name"].as_str() == Some(canonical_name))
            })
            .and_then(|case| case.get("instance"))
            .ok_or_else(|| anyhow!("canonical fixture lacks {canonical_name}"))?;
        ensure!(
            &fixture[local_name] == expected,
            "local {local_name} template drifted from {canonical_name}"
        );
    }
    Ok(())
}

fn assert_holder_only_contract(fixture: &Value) -> Result<usize> {
    let registry = load_artifact_json("registry/schema-registry.json")?;
    let row = registry["schemas"]
        .as_array()
        .and_then(|rows| {
            rows.iter().find(|row| {
                row["schema_id"].as_str() == Some("ak.schema.account_subscribe_frame.v1")
            })
        })
        .ok_or_else(|| anyhow!("account subscribe schema registry row absent"))?;
    let expected = &fixture["contract_expectations"];
    ensure!(
        row.pointer("/channel_contract/authorization/allow") == expected.get("authorization_allow"),
        "holder allow rule drifted"
    );
    ensure!(
        row.pointer("/channel_contract/authorization/deny") == expected.get("authorization_deny"),
        "holder deny set drifted"
    );
    ensure!(
        row.pointer("/channel_contract/authorization/recheck")
            .and_then(Value::as_str)
            == Some("on every baseline page and delta before disclosure"),
        "per-page/delta authorization recheck drifted"
    );
    ensure!(
        row.pointer("/sdk_projection/forbidden_field_reuse")
            == row.pointer("/channel_contract/forbidden_carriers"),
        "the fifth channel was aliased onto an older carrier"
    );
    Ok(4)
}

fn assert_baseline_paging(fixture: &Value) -> Result<usize> {
    let live = fixture["live"].clone();
    let first = parse_frame(json!({
        "kind": "delta",
        "cursor": "ak:cursor:pending-page-1",
        "baseline": {
            "snapshot_cursor": "ak:cursor:pending-snapshot-1",
            "channels": ["agent_draft_pending_intents"],
            "completed_channels": []
        },
        "agent_draft_pending_intents": {
            "mode": "baseline",
            "snapshot_cut_position": 7,
            "page_offset": 0,
            "next_page_offset": 1,
            "items": [{"action": "upsert", "value": live}]
        }
    }))?;
    let terminal = parse_frame(json!({
        "kind": "delta",
        "cursor": "ak:cursor:pending-page-2",
        "baseline": {
            "snapshot_cursor": "ak:cursor:pending-snapshot-1",
            "channels": ["agent_draft_pending_intents"],
            "completed_channels": ["agent_draft_pending_intents"]
        },
        "agent_draft_pending_intents": {
            "mode": "baseline",
            "snapshot_cut_position": 7,
            "page_offset": 1,
            "next_page_offset": null,
            "items": []
        }
    }))?;
    let (first_cut, first_offset, first_next) = baseline_positions(&first)?;
    let (last_cut, last_offset, last_next) = baseline_positions(&terminal)?;
    ensure!((first_cut, first_offset, first_next) == (7, 0, Some(1)));
    ensure!((last_cut, last_offset, last_next) == (7, 1, None));
    ensure!(
        first
            .baseline
            .as_ref()
            .is_some_and(|value| value.completed_channels.is_empty()),
        "intermediate page completed the private channel"
    );
    ensure!(
        terminal.baseline.as_ref().is_some_and(|value| {
            serde_json::to_value(&value.completed_channels)
                .is_ok_and(|channels| channels == json!(["agent_draft_pending_intents"]))
        }),
        "terminal page did not complete the private channel"
    );
    Ok(4)
}

fn assert_delta_upsert_and_remove(fixture: &Value) -> Result<usize> {
    let upsert = parse_frame(delta_frame(
        8,
        json!({"action": "upsert", "value": fixture["live"].clone()}),
    ))?;
    let removal = parse_frame(delta_frame(
        9,
        json!({"action": "remove", "value": fixture["removal"].clone()}),
    ))?;
    ensure!(matches!(
        pending_items(&upsert)?.first(),
        Some(AgentDraftPendingIntentChange::Upsert(_))
    ));
    ensure!(matches!(
        pending_items(&removal)?.first(),
        Some(AgentDraftPendingIntentChange::Remove(_))
    ));
    ensure!(delta_position(&upsert)? == 8 && delta_position(&removal)? == 9);
    Ok(3)
}

fn assert_terminal_redaction(fixture: &Value) -> Result<usize> {
    let live = parse_frame(delta_frame(
        8,
        json!({"action": "upsert", "value": fixture["live"].clone()}),
    ))?;
    let terminal = parse_frame(delta_frame(
        9,
        json!({"action": "upsert", "value": fixture["terminal"].clone()}),
    ))?;
    let live_json = serde_json::to_value(&live)?;
    let terminal_json = serde_json::to_value(&terminal)?;
    ensure!(
        live_json
            .pointer("/agent_draft_pending_intents/items/0/value/content_handoff")
            .is_some(),
        "live upsert lost its encrypted handoff"
    );
    ensure!(
        terminal_json
            .pointer("/agent_draft_pending_intents/items/0/value/content_handoff")
            .is_none(),
        "terminal upsert retained content_handoff"
    );
    ensure!(
        !contains_key_recursive(&terminal_json, "ciphertext"),
        "terminal upsert retained ciphertext"
    );
    for field in [
        "controller_account_id",
        "agent_id",
        "draft_id",
        "accepted_event_id",
        "canonical_event_digest",
        "content_digest",
        "expires_at",
    ] {
        ensure!(
            live_json.pointer(&format!(
                "/agent_draft_pending_intents/items/0/value/{field}"
            )) == terminal_json.pointer(&format!(
                "/agent_draft_pending_intents/items/0/value/{field}"
            )),
            "terminal upsert changed stable {field}"
        );
    }
    Ok(10)
}

fn assert_resync_restarts_private_offset(fixture: &Value) -> Result<usize> {
    let resync = parse_frame(json!({"kind": "resync_required"}))?;
    ensure!(
        serde_json::to_value(&resync)?["kind"] == "resync_required",
        "resync control frame drifted"
    );
    let restarted = parse_frame(json!({
        "kind": "delta",
        "cursor": "ak:cursor:pending-restarted",
        "baseline": {
            "snapshot_cursor": "ak:cursor:pending-snapshot-2",
            "channels": ["agent_draft_pending_intents"],
            "completed_channels": []
        },
        "agent_draft_pending_intents": {
            "mode": "baseline",
            "snapshot_cut_position": 10,
            "page_offset": 0,
            "next_page_offset": 1,
            "items": [{"action": "upsert", "value": fixture["live"].clone()}]
        }
    }))?;
    let (cut, offset, _) = baseline_positions(&restarted)?;
    ensure!(
        (cut, offset) == (10, 0),
        "resync reused a stale private offset"
    );
    ensure!(
        restarted.baseline.as_ref().is_some_and(|baseline| {
            baseline.snapshot_cursor.as_str() == "ak:cursor:pending-snapshot-2"
        }),
        "resync did not establish a new frozen snapshot"
    );
    Ok(3)
}

fn assert_max_100(fixture: &Value) -> Result<usize> {
    let expected = fixture["contract_expectations"]["max_items_per_frame"]
        .as_u64()
        .ok_or_else(|| anyhow!("max_items_per_frame must be an integer"))?
        as usize;
    ensure!(expected == 100, "canonical combined item bound drifted");
    let item = json!({"action": "upsert", "value": fixture["live"].clone()});
    let hundred = (0..expected).map(|_| item.clone()).collect::<Vec<_>>();
    parse_frame(delta_frame_with_items(11, hundred))?;
    let hundred_one = (0..=expected).map(|_| item.clone()).collect::<Vec<_>>();
    let value = delta_frame_with_items(12, hundred_one);
    schema_invalid(FRAME_SCHEMA, &value)?;
    let frame: AccountSubscribeFrame = serde_json::from_value(value)?;
    ensure!(
        frame.validate().is_err(),
        "public SDK accepted 101 pending-intent changes"
    );
    Ok(3)
}

fn assert_legacy_four_channels_remain_valid(fixture: &Value) -> Result<usize> {
    let legacy = fixture["contract_expectations"]["legacy_channels"]
        .as_array()
        .ok_or_else(|| anyhow!("legacy_channels must be an array"))?;
    let frame = parse_frame(json!({
        "kind": "delta",
        "cursor": "ak:cursor:legacy-four",
        "baseline": {
            "snapshot_cursor": "ak:cursor:legacy-four-snapshot",
            "channels": legacy,
            "completed_channels": legacy
        }
    }))?;
    let encoded = serde_json::to_value(frame)?;
    ensure!(
        encoded.get("agent_draft_pending_intents").is_none(),
        "legacy four-channel frame grew a synthetic fifth payload"
    );
    ensure!(
        encoded["baseline"]["channels"] == fixture["contract_expectations"]["legacy_channels"],
        "legacy channel identities or order changed"
    );
    Ok(2)
}

fn parse_frame(value: Value) -> Result<AccountSubscribeFrame> {
    schema_valid(FRAME_SCHEMA, &value)?;
    let frame: AccountSubscribeFrame = serde_json::from_value(value)?;
    frame.validate()?;
    Ok(frame)
}

fn delta_frame(position: u64, item: Value) -> Value {
    delta_frame_with_items(position, vec![item])
}

fn delta_frame_with_items(position: u64, items: Vec<Value>) -> Value {
    json!({
        "kind": "delta",
        "cursor": format!("ak:cursor:pending-delta-{position}"),
        "agent_draft_pending_intents": {
            "mode": "delta",
            "projection_position": position,
            "items": items
        }
    })
}

fn baseline_positions(frame: &AccountSubscribeFrame) -> Result<(u64, u64, Option<u64>)> {
    match frame.agent_draft_pending_intents.as_ref() {
        Some(AgentDraftPendingIntentContainer::Baseline {
            snapshot_cut_position,
            page_offset,
            next_page_offset,
            ..
        }) => Ok((*snapshot_cut_position, *page_offset, *next_page_offset)),
        _ => Err(anyhow!("frame did not carry a pending-intent baseline")),
    }
}

fn pending_items(frame: &AccountSubscribeFrame) -> Result<&[AgentDraftPendingIntentChange]> {
    match frame.agent_draft_pending_intents.as_ref() {
        Some(AgentDraftPendingIntentContainer::Delta { items, .. }) => Ok(items),
        _ => Err(anyhow!("frame did not carry a pending-intent delta")),
    }
}

fn delta_position(frame: &AccountSubscribeFrame) -> Result<u64> {
    match frame.agent_draft_pending_intents.as_ref() {
        Some(AgentDraftPendingIntentContainer::Delta {
            projection_position,
            ..
        }) => Ok(*projection_position),
        _ => Err(anyhow!("frame did not carry a pending-intent delta")),
    }
}

fn contains_key_recursive(value: &Value, needle: &str) -> bool {
    match value {
        Value::Object(object) => object
            .iter()
            .any(|(key, value)| key == needle || contains_key_recursive(value, needle)),
        Value::Array(values) => values
            .iter()
            .any(|value| contains_key_recursive(value, needle)),
        _ => false,
    }
}
