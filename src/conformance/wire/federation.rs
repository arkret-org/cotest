//! Multi-space federation wire-model conformance vectors.

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{emit_vector, expected_outcome, expected_reason, load_local_fixture};
use crate::conformance::{required_str, validate_profile};

/// E3 Round 27 — multi-space federation. Per-space anchor isolation +
/// cross-space rejection.
pub fn run_multi_space_federation_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("multi_space_federation_fixture.json")?;
    validate_profile(&fixture, "cx.profile.multi_space_federation_vectors.v1")?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("multi_space_federation missing vectors[]"))?;
    if vectors.len() < 3 {
        bail!(
            "multi_space_federation requires >= 3 vectors, got {}",
            vectors.len()
        );
    }
    let mut saw_isolation = false;
    let mut saw_concurrent = false;
    let mut saw_cross_reject = false;
    let mut saw_per_space_seq = false;
    for v in vectors {
        let name = required_str(v, "name")?;
        let outcome = expected_outcome(v, name)?;
        match name {
            "multi_space_replay_three_spaces_independent_frontiers" => {
                let spaces: Vec<&str> = v
                    .get("spaces")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                if spaces.len() != 3 {
                    bail!("vector {name} must list 3 spaces");
                }
                let isolation = v
                    .pointer("/expected/per_space_isolation")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !isolation {
                    bail!("vector {name} expected.per_space_isolation must be true");
                }
                // Sanity check: sequential pulls must monotonically grow only the
                // pulled space's frontier.
                let f1 = v
                    .pointer("/expected/server_b_frontier_after_S1_pull")
                    .ok_or_else(|| {
                        anyhow!("vector {name} missing server_b_frontier_after_S1_pull")
                    })?;
                let f2 = v
                    .pointer("/expected/server_b_frontier_after_S2_pull")
                    .ok_or_else(|| {
                        anyhow!("vector {name} missing server_b_frontier_after_S2_pull")
                    })?;
                if f1.get("space_S1").and_then(Value::as_u64) != Some(1)
                    || f1.get("space_S2").and_then(Value::as_u64) != Some(0)
                {
                    bail!("vector {name} S1 pull must update only S1");
                }
                if f2.get("space_S2").and_then(Value::as_u64) != Some(1) {
                    bail!("vector {name} S2 pull must bring S2 to 1");
                }
                if outcome != "accept" {
                    bail!("vector {name} outcome must be accept");
                }
                saw_isolation = true;
            }
            "multi_space_concurrent_move_replay" => {
                if outcome != "accept" {
                    bail!("vector {name} outcome must be accept");
                }
                let s1 = v
                    .pointer("/expected/final_S1_frontier_count")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing final_S1_frontier_count"))?;
                let s2 = v
                    .pointer("/expected/final_S2_frontier_count")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing final_S2_frontier_count"))?;
                if s1 < 2 || s2 < 2 {
                    bail!(
                        "vector {name} bidirectional convergence requires both spaces to hold both moves (>= 2 each)"
                    );
                }
                saw_concurrent = true;
            }
            "multi_space_cross_space_move_rejected" => {
                if outcome != "reject" {
                    bail!("vector {name} outcome must be reject");
                }
                if expected_reason(v) != Some("cross_space_move_forbidden") {
                    bail!("vector {name} reason_code must be cross_space_move_forbidden");
                }
                let claimed = v
                    .pointer("/push_payload/claimed_space_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("vector {name} missing claimed_space_id"))?;
                let actual = v
                    .pointer("/push_payload/actual_anchor_space_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("vector {name} missing actual_anchor_space_id"))?;
                if claimed == actual {
                    bail!("vector {name} cross-space negative requires claimed != actual space_id");
                }
                saw_cross_reject = true;
            }
            "multi_space_per_space_anchor_seq_independent" => {
                if outcome != "accept" {
                    bail!("vector {name} outcome must be accept");
                }
                let no_global = v
                    .pointer("/expected/no_global_counter")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !no_global {
                    bail!("vector {name} expected.no_global_counter must be true");
                }
                let history = v
                    .get("anchor_history")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} missing anchor_history"))?;
                let mut s1_max = 0u64;
                let mut s2_max = 0u64;
                for h in history {
                    let space = required_str(h, "realm_id")?;
                    let seq = h
                        .get("seq")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| anyhow!("anchor_history entry missing seq"))?;
                    match space {
                        "space_S1" => s1_max = s1_max.max(seq),
                        "space_S2" => s2_max = s2_max.max(seq),
                        other => bail!("vector {name} unexpected space {other}"),
                    }
                }
                let exp_s1 = v
                    .pointer("/expected/S1_max_seq")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing S1_max_seq"))?;
                let exp_s2 = v
                    .pointer("/expected/S2_max_seq")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing S2_max_seq"))?;
                if s1_max != exp_s1 || s2_max != exp_s2 {
                    bail!(
                        "vector {name} computed seqs ({s1_max},{s2_max}) != expected ({exp_s1},{exp_s2})"
                    );
                }
                saw_per_space_seq = true;
            }
            other => bail!("multi_space_federation unexpected vector {other}"),
        }
        emit_vector(
            "multi_space_federation.vector",
            v,
            json!({"name": name, "outcome": outcome}),
        );
    }
    if !(saw_isolation && saw_concurrent && saw_cross_reject && saw_per_space_seq) {
        bail!(
            "multi_space_federation must cover isolation + concurrent + cross_reject + per_space_seq"
        );
    }
    Ok(())
}
