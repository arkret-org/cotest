//! CT-2 — Mixed lattice cell types conformance suite.
//!
//! Validates `tests/fixtures/lattice_mixed_kinds.json`, which exercises
//! Arkret state resolution when a single Space has cells of different
//! lattice types (cas_register + or_set + mv_register) updating
//! concurrently in the same Move batch or across the same Anchor frontier.
//!
//! Spec authority:
//!   * `arkret-spec/spec/v1/zh/models/realm-and-space.md` (lattice cell registry /
//!     `cowrite_policy`)
//!   * `arkret-spec/spec/v1/zh/authz/event-auth-state-resolution.md` §3 (lattice_op kinds) and §5.3
//!     (per-lattice reference impl)
//!
//! Each cell family has its own lattice; a single Move MAY write multiple
//! cells, and concurrent Moves are resolved per-cell by the cell's own
//! lattice. The suite enforces these invariants structurally — it does not
//! drive a live reducer; deeper deterministic re-execution lives in the
//! SDK's lattice crate (root C10.A) and integration tests once a
//! Move/Anchor SUT is wired through cotest's harness.

use anyhow::{Result, anyhow, bail};
use serde_json::Value;

use super::{load_local_fixture_value, required_str, validate_profile};

const PROFILE_ID: &str = "ak.profile.lattice_mixed_kinds_vectors.v1";

pub fn run_lattice_mixed_kinds_suite() -> Result<()> {
    let fixture = load_local_fixture_value("lattice_mixed_kinds.json")?;
    validate_profile(&fixture, PROFILE_ID)?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("lattice_mixed_kinds fixture missing vectors[]"))?;
    if vectors.len() < 3 {
        bail!(
            "lattice_mixed_kinds requires >= 3 vectors, got {}",
            vectors.len()
        );
    }

    let mut saw_cas_or_set_coexist = false;
    let mut saw_mv_concurrent = false;
    let mut saw_all_three = false;

    for vector in vectors {
        let name = required_str(vector, "name")?;
        match name {
            "cas_register_or_set_coexist" => {
                check_cas_or_set_coexist(vector)?;
                saw_cas_or_set_coexist = true;
            }
            "mv_register_concurrent_writers" => {
                check_mv_concurrent(vector)?;
                saw_mv_concurrent = true;
            }
            "cas_or_set_mv_one_anchor" => {
                check_all_three(vector)?;
                saw_all_three = true;
            }
            other => bail!("lattice_mixed_kinds unexpected vector: {other}"),
        }
    }

    if !(saw_cas_or_set_coexist && saw_mv_concurrent && saw_all_three) {
        bail!(
            "lattice_mixed_kinds must cover all three vectors (cas_register_or_set_coexist + \
             mv_register_concurrent_writers + cas_or_set_mv_one_anchor)"
        );
    }
    Ok(())
}

fn check_cas_or_set_coexist(vector: &Value) -> Result<()> {
    let name = required_str(vector, "name")?;
    let effects = vector
        .pointer("/move/effects")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("vector {name} missing move.effects[]"))?;
    if effects.len() < 2 {
        bail!(
            "vector {name} requires >= 2 effects covering distinct lattice kinds (got {})",
            effects.len()
        );
    }
    let mut kinds: std::collections::BTreeSet<&str> = Default::default();
    for effect in effects {
        let op_kind = effect
            .pointer("/op/kind")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("vector {name} effect missing op.kind"))?;
        kinds.insert(op_kind);
    }
    // `set` (cas_register) + `add` (or_set) must both appear.
    if !kinds.contains("set") {
        bail!("vector {name} must include a cas_register `set` effect");
    }
    if !kinds.contains("add") {
        bail!("vector {name} must include an or_set `add` effect");
    }
    let atomicity = vector
        .pointer("/expected/atomicity")
        .and_then(Value::as_str);
    if atomicity != Some("all_effects_or_none") {
        bail!("vector {name} expected.atomicity must be 'all_effects_or_none'");
    }
    let cell_states = vector
        .pointer("/expected/cell_states")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("vector {name} missing expected.cell_states"))?;
    let mut surface_lattices: std::collections::BTreeSet<&str> = Default::default();
    for (_, state) in cell_states {
        let lat = state
            .get("lattice")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("vector {name} cell_state missing lattice"))?;
        surface_lattices.insert(lat);
    }
    if !surface_lattices.contains("cas_register") || !surface_lattices.contains("or_set") {
        bail!("vector {name} cell_states must include cas_register + or_set lattices");
    }
    Ok(())
}

fn check_mv_concurrent(vector: &Value) -> Result<()> {
    let name = required_str(vector, "name")?;
    let lattice_type = vector
        .pointer("/lattice/type")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("vector {name} missing lattice.type"))?;
    if lattice_type != "mv_register" {
        bail!("vector {name} lattice.type must be 'mv_register'");
    }
    let bottom = vector
        .pointer("/lattice/bottom")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("vector {name} missing lattice.bottom"))?;
    if bottom != "expose" {
        bail!("vector {name} lattice.bottom must be 'expose' (mv_register normal case)");
    }
    let moves = vector
        .get("concurrent_moves")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("vector {name} missing concurrent_moves[]"))?;
    if moves.len() < 2 {
        bail!(
            "vector {name} requires >= 2 concurrent moves (got {})",
            moves.len()
        );
    }
    let mut issuers: std::collections::BTreeSet<&str> = Default::default();
    for m in moves {
        let issuer = required_str(m, "issuer_id")?;
        issuers.insert(issuer);
    }
    if issuers.len() < 2 {
        bail!(
            "vector {name} concurrent moves must come from distinct issuers (got {})",
            issuers.len()
        );
    }
    let status = vector
        .pointer("/expected/query/status")
        .and_then(Value::as_str);
    if status != Some("conflict") {
        bail!(
            "vector {name} expected.query.status must be 'conflict' (mv_register exposes heads, not a single winner)"
        );
    }
    let heads = vector
        .pointer("/expected/query/heads")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("vector {name} missing expected.query.heads[]"))?;
    if heads.len() != moves.len() {
        bail!(
            "vector {name} expected.query.heads must have one entry per concurrent move ({} vs {})",
            heads.len(),
            moves.len()
        );
    }
    let lww = vector
        .pointer("/expected/last_write_wins")
        .and_then(Value::as_bool);
    if lww != Some(false) {
        bail!(
            "vector {name} expected.last_write_wins must be false — mv_register does not pick a winner"
        );
    }
    Ok(())
}

fn check_all_three(vector: &Value) -> Result<()> {
    let name = required_str(vector, "name")?;
    let moves = vector
        .get("anchor_frontier_moves")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("vector {name} missing anchor_frontier_moves[]"))?;
    if moves.len() < 3 {
        bail!(
            "vector {name} requires >= 3 moves covering all three lattice kinds (got {})",
            moves.len()
        );
    }
    if vector
        .pointer("/expected/verify_anchor")
        .and_then(Value::as_str)
        != Some("accept")
    {
        bail!("vector {name} expected.verify_anchor must be 'accept'");
    }
    let surface = vector
        .pointer("/expected/state_surface")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("vector {name} missing expected.state_surface"))?;
    let mut lattices: std::collections::BTreeSet<&str> = Default::default();
    for (_, cell_state) in surface {
        let lat = cell_state
            .get("lattice")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("vector {name} state_surface cell missing lattice"))?;
        lattices.insert(lat);
    }
    for required in ["cas_register", "or_set", "mv_register"] {
        if !lattices.contains(required) {
            bail!(
                "vector {name} state_surface must include all three lattice kinds; missing {required}"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_passes_against_local_fixture() -> Result<()> {
        run_lattice_mixed_kinds_suite()
    }
}
