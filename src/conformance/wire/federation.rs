//! Multi-Realm federation wire-model conformance vectors.

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{emit_vector, expected_outcome, expected_reason, load_local_fixture};
use crate::conformance::{required_str, validate_profile};

/// E3 Round 27 — Multi-Realm federation. Per-Realm anchor isolation +
/// cross-Realm rejection.
pub fn run_multi_realm_federation_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("multi_realm_federation_fixture.json")?;
    validate_profile(&fixture, "ck.profile.multi_realm_federation_vectors.v1")?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("multi_realm_federation missing vectors[]"))?;
    if vectors.len() < 3 {
        bail!(
            "multi_realm_federation requires >= 3 vectors, got {}",
            vectors.len()
        );
    }
    let mut saw_isolation = false;
    let mut saw_concurrent = false;
    let mut saw_cross_reject = false;
    let mut saw_per_realm_seq = false;
    for v in vectors {
        let name = required_str(v, "name")?;
        let outcome = expected_outcome(v, name)?;
        match name {
            "multi_realm_replay_three_realms_independent_frontiers" => {
                let realms: Vec<&str> = v
                    .get("realms")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                if realms.len() != 3 {
                    bail!("vector {name} must list 3 realms");
                }
                let isolation = v
                    .pointer("/expected/per_realm_isolation")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !isolation {
                    bail!("vector {name} expected.per_realm_isolation must be true");
                }
                // Sanity check: sequential pulls must monotonically grow only the
                // pulled Realm's frontier.
                let f1 = v
                    .pointer("/expected/server_b_frontier_after_R1_pull")
                    .ok_or_else(|| {
                        anyhow!("vector {name} missing server_b_frontier_after_R1_pull")
                    })?;
                let f2 = v
                    .pointer("/expected/server_b_frontier_after_R2_pull")
                    .ok_or_else(|| {
                        anyhow!("vector {name} missing server_b_frontier_after_R2_pull")
                    })?;
                if f1.get("realm_R1").and_then(Value::as_u64) != Some(1)
                    || f1.get("realm_R2").and_then(Value::as_u64) != Some(0)
                {
                    bail!("vector {name} R1 pull must update only R1");
                }
                if f2.get("realm_R2").and_then(Value::as_u64) != Some(1) {
                    bail!("vector {name} R2 pull must bring R2 to 1");
                }
                if outcome != "accept" {
                    bail!("vector {name} outcome must be accept");
                }
                saw_isolation = true;
            }
            "multi_realm_concurrent_move_replay" => {
                if outcome != "accept" {
                    bail!("vector {name} outcome must be accept");
                }
                let r1 = v
                    .pointer("/expected/final_R1_frontier_count")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing final_R1_frontier_count"))?;
                let r2 = v
                    .pointer("/expected/final_R2_frontier_count")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing final_R2_frontier_count"))?;
                if r1 < 2 || r2 < 2 {
                    bail!(
                        "vector {name} bidirectional convergence requires both realms to hold both moves (>= 2 each)"
                    );
                }
                saw_concurrent = true;
            }
            "multi_realm_cross_realm_move_rejected" => {
                if outcome != "reject" {
                    bail!("vector {name} outcome must be reject");
                }
                if expected_reason(v) != Some("cross_realm_move_forbidden") {
                    bail!("vector {name} reason_code must be cross_realm_move_forbidden");
                }
                let claimed = v
                    .pointer("/push_payload/claimed_realm_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("vector {name} missing claimed_realm_id"))?;
                let actual = v
                    .pointer("/push_payload/actual_anchor_realm_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("vector {name} missing actual_anchor_realm_id"))?;
                if claimed == actual {
                    bail!("vector {name} cross-Realm negative requires claimed != actual realm_id");
                }
                saw_cross_reject = true;
            }
            "multi_realm_per_realm_anchor_seq_independent" => {
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
                let mut r1_max = 0u64;
                let mut r2_max = 0u64;
                for h in history {
                    let realm = required_str(h, "realm_id")?;
                    let seq = h
                        .get("seq")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| anyhow!("anchor_history entry missing seq"))?;
                    match realm {
                        "realm_R1" => r1_max = r1_max.max(seq),
                        "realm_R2" => r2_max = r2_max.max(seq),
                        other => bail!("vector {name} unexpected Realm {other}"),
                    }
                }
                let exp_r1 = v
                    .pointer("/expected/R1_max_seq")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing R1_max_seq"))?;
                let exp_r2 = v
                    .pointer("/expected/R2_max_seq")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing R2_max_seq"))?;
                if r1_max != exp_r1 || r2_max != exp_r2 {
                    bail!(
                        "vector {name} computed seqs ({r1_max},{r2_max}) != expected ({exp_r1},{exp_r2})"
                    );
                }
                saw_per_realm_seq = true;
            }
            other => bail!("multi_realm_federation unexpected vector {other}"),
        }
        emit_vector(
            "multi_realm_federation.vector",
            v,
            json!({"name": name, "outcome": outcome}),
        );
    }
    if !(saw_isolation && saw_concurrent && saw_cross_reject && saw_per_realm_seq) {
        bail!(
            "multi_realm_federation must cover isolation + concurrent + cross_reject + per_realm_seq"
        );
    }
    Ok(())
}
