//! Poll Message reducer fixture consumer.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, bail};

use super::load_fixture_value;

const FIXTURE: &str = "poll-reducer-fixture.json";
const ENTRYPOINT: &str = "ak.suite.message.poll_reducer.v1";
const VECTOR: &str = "ak.vector.message.poll_reducer.v1";

pub fn run_poll_reducer_fixture_suite() -> Result<()> {
    let fixture = load_fixture_value(FIXTURE)?;
    if fixture["suite"] != "message_poll_reducer"
        || fixture["runner"]["kind"] != "named_suite"
        || fixture["runner"]["entrypoint"] != ENTRYPOINT
        || fixture["covers_vectors"] != serde_json::json!([VECTOR])
    {
        bail!("poll reducer fixture identity drifted");
    }
    let poll = fixture["poll"].as_object().context("poll fixture basis")?;
    let poll_scope = poll["scope_circle_id"]
        .as_str()
        .context("poll scope_circle_id")?;
    let default_max = poll["max_selections"]
        .as_u64()
        .context("poll max_selections")? as usize;
    let answers = poll["answer_ids"]
        .as_array()
        .context("poll answer_ids")?
        .iter()
        .map(|value| value.as_str().context("poll answer id"))
        .collect::<Result<BTreeSet<_>>>()?;
    let cases = fixture["cases"].as_array().context("poll cases")?;
    let names = cases
        .iter()
        .map(|case| case["name"].as_str().context("poll case name"))
        .collect::<Result<BTreeSet<_>>>()?;
    let required = BTreeSet::from([
        "valid_single_selection",
        "valid_multi_selection",
        "unknown_answer_rejected",
        "over_selection_rejected_without_truncation",
        "cross_scope_poll_ref_rejected",
        "causal_successor_replaces_actor_vote",
        "concurrent_digest_order_is_arrival_independent",
    ]);
    if names != required {
        bail!("poll reducer fixture is not the closed seven-case set");
    }

    for case in cases {
        let name = case["name"].as_str().context("poll case name")?;
        match name {
            "causal_successor_replaces_actor_vote" => {
                let current = case["current_event_digest"]
                    .as_str()
                    .context("current digest")?;
                let refs = case["candidate_causal_refs"]
                    .as_array()
                    .context("candidate causal refs")?;
                if !refs.iter().any(|value| value.as_str() == Some(current))
                    || case["expected"] != "candidate"
                {
                    bail!("causal successor vector no longer selects the candidate");
                }
            }
            "concurrent_digest_order_is_arrival_independent" => {
                let left = case["left_event_digest"].as_str().context("left digest")?;
                let right = case["right_event_digest"]
                    .as_str()
                    .context("right digest")?;
                let expected = case["expected_winner_digest"]
                    .as_str()
                    .context("expected winner")?;
                if left.max(right) != expected {
                    bail!("concurrent Poll response winner is not canonical digest max");
                }
            }
            _ => {
                let selections = case["selections"]
                    .as_array()
                    .context("poll selections")?
                    .iter()
                    .map(|value| value.as_str().context("poll selection"))
                    .collect::<Result<Vec<_>>>()?;
                let max = case["max_selections"]
                    .as_u64()
                    .map_or(default_max, |v| v as usize);
                let scope = case["scope_circle_id"].as_str().unwrap_or(poll_scope);
                let derived = if scope != poll_scope {
                    "poll_ref_cross_scope"
                } else if selections
                    .iter()
                    .any(|selection| !answers.contains(selection))
                {
                    "poll_selection_unknown"
                } else if selections.len() > max {
                    "poll_selection_limit_exceeded"
                } else {
                    "accepted"
                };
                if case["expected"].as_str() != Some(derived) {
                    bail!("poll fixture case {name} derives {derived}");
                }
            }
        }
    }
    Ok(())
}
