//! Poll Message reducer fixture consumer.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail};
use arkret_models_collaboration::poll::{
    PollPartition, PollResponseFact, PollResponseSet, validate_poll_selections,
};
use arkret_wire::Hash;
use serde_json::Value;

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
        "empty_selection_rejected",
        "duplicate_selection_rejected",
    ]);
    if names != required {
        bail!("poll reducer fixture is not the closed selection-validation case set");
    }

    for case in cases {
        let name = case["name"].as_str().context("poll case name")?;
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
        let owned_selections: Vec<_> = selections.iter().map(|s| (*s).to_owned()).collect();
        let owned_answers = answers.iter().map(|s| (*s).to_owned()).collect();
        let selection_result = validate_poll_selections(&owned_selections, &owned_answers, max);
        let derived = if scope != poll_scope {
            "poll_ref_cross_scope"
        } else if let Err(error) = &selection_result {
            match error {
                arkret_models_collaboration::poll::PollSelectionError::Empty => {
                    "poll_selection_empty"
                }
                arkret_models_collaboration::poll::PollSelectionError::Duplicate => {
                    "poll_selection_duplicate"
                }
                arkret_models_collaboration::poll::PollSelectionError::Unknown => {
                    "poll_selection_unknown"
                }
                arkret_models_collaboration::poll::PollSelectionError::LimitExceeded => {
                    "poll_selection_limit_exceeded"
                }
            }
        } else {
            "accepted"
        };
        if case["expected"].as_str() != Some(derived) {
            bail!("poll fixture case {name} derives {derived}");
        }
    }
    run_graph_cases(&fixture)?;
    Ok(())
}

fn partition(value: &Value) -> Result<PollPartition> {
    Ok(PollPartition {
        realm_id: serde_json::from_value(value["realm_id"].clone())?,
        scope_circle_id: serde_json::from_value(value["scope_circle_id"].clone())?,
        poll_ref: serde_json::from_value(value["poll_ref"].clone())?,
        actor_id: serde_json::from_value(value["actor_id"].clone())?,
    })
}

fn labels(value: &Value, digests: &BTreeMap<String, Hash>) -> Result<BTreeSet<Hash>> {
    value.as_array().map_or(Ok(BTreeSet::new()), |items| {
        items
            .iter()
            .map(|item| {
                let label = item.as_str().context("digest label")?;
                digests
                    .get(label)
                    .cloned()
                    .with_context(|| format!("unknown digest label {label}"))
            })
            .collect()
    })
}

fn run_graph_cases(fixture: &Value) -> Result<()> {
    let digests: BTreeMap<String, Hash> = serde_json::from_value(fixture["digests"].clone())?;
    let primary = partition(&fixture["poll"])?;
    let cases = fixture["graph_cases"]
        .as_array()
        .context("Poll graph cases")?;
    for case in cases {
        let name = case["name"].as_str().context("graph case name")?;
        let mut shards = Vec::new();
        for input in case["events"].as_array().context("graph events")? {
            let mut coordinates = fixture["poll"].clone();
            for key in ["realm_id", "scope_circle_id", "poll_ref", "actor_id"] {
                if let Some(value) = input.get(key) {
                    coordinates[key] = value.clone();
                }
            }
            let digest = digests[input["label"].as_str().context("response label")?].clone();
            let mut shard = PollResponseSet::default();
            shard.insert(
                digest,
                PollResponseFact {
                    partition: partition(&coordinates)?,
                    selections: serde_json::from_value(input["selections"].clone())?,
                    causal_refs: labels(&input["causal_refs"], &digests)?,
                },
            )?;
            shards.push(shard);
        }
        let mut basis = PollResponseSet::default();
        for digest in labels(&case["known_non_responses"], &digests)? {
            basis.observe_non_response(digest)?;
        }
        let mut whole = basis.clone();
        for shard in &shards {
            whole.merge(shard)?;
        }
        let original_projection = whole.project();
        // Every arrival order includes late predecessors; each intermediate
        // projection executes dependency waiting before final convergence.
        let mut orders = Vec::new();
        permutations(&mut (0..shards.len()).collect::<Vec<_>>(), 0, &mut orders);
        for order in orders {
            let mut replay = basis.clone();
            for index in &order {
                replay.merge(&shards[*index])?;
                let _ = replay.project();
                replay.merge(&shards[*index])?;
            }
            if replay != whole || replay.project() != original_projection {
                bail!("Poll {name}: arrival order / duplicate changed state or tally");
            }
            // All split points compare both operand orders and both association
            // groupings. This uses full facts, including non-winning branches.
            for split in 0..=order.len() {
                let mut left = basis.clone();
                let mut right = PollResponseSet::default();
                for index in &order[..split] {
                    left.merge(&shards[*index])?;
                }
                for index in &order[split..] {
                    right.merge(&shards[*index])?;
                }
                let mut lr = left.clone();
                lr.merge(&right)?;
                let mut rl = right.clone();
                rl.merge(&left)?;
                if lr != whole || rl != whole || lr.project() != original_projection {
                    bail!("Poll {name}: partitioned union failed convergence");
                }
                for third in split..=order.len() {
                    let mut middle = PollResponseSet::default();
                    let mut last = PollResponseSet::default();
                    for index in &order[split..third] {
                        middle.merge(&shards[*index])?;
                    }
                    for index in &order[third..] {
                        last.merge(&shards[*index])?;
                    }
                    let mut ab_c = left.clone();
                    ab_c.merge(&middle)?;
                    ab_c.merge(&last)?;
                    middle.merge(&last)?;
                    let mut a_bc = left.clone();
                    a_bc.merge(&middle)?;
                    if ab_c != a_bc || a_bc.project() != original_projection {
                        bail!("Poll {name}: associativity failed");
                    }
                }
            }
        }
        for digest in labels(&case["remove"], &digests)? {
            whole.remove(&digest);
        }
        let projection = whole.project();
        let empty = Default::default();
        let outcome = projection.get(&primary).unwrap_or(&empty);
        let expected_winner = case["expected_winner"]
            .as_str()
            .map(|label| digests[label].clone());
        let expected_selections: BTreeSet<String> =
            serde_json::from_value(case["expected_selections"].clone())?;
        if outcome.heads != labels(&case["expected_heads"], &digests)?
            || outcome.winner != expected_winner
            || outcome.selections != expected_selections
            || outcome.pending != labels(&case["expected_pending"], &digests)?
            || outcome.invalid != labels(&case["expected_invalid"], &digests)?
        {
            bail!("Poll {name}: actual graph result {outcome:?}");
        }
        // Tally adopts one complete winning response, never the union of heads.
        let tally: BTreeMap<_, usize> = outcome
            .selections
            .iter()
            .map(|answer| (answer, 1))
            .collect();
        let expected_tally: BTreeMap<_, usize> = expected_selections
            .iter()
            .map(|answer| (answer, 1))
            .collect();
        if tally != expected_tally {
            bail!("Poll {name}: tally mismatch");
        }
    }
    Ok(())
}

fn permutations(items: &mut [usize], offset: usize, output: &mut Vec<Vec<usize>>) {
    if offset == items.len() {
        output.push(items.to_vec());
        return;
    }
    for index in offset..items.len() {
        items.swap(offset, index);
        permutations(items, offset + 1, output);
        items.swap(offset, index);
    }
}
