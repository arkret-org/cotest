//! State-root and Strand tracks reducer conformance vectors.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail};
use arkret_identifiers::CellRef;
use arkret_state::lattice::CellState;
use arkret_state::state::{EMPTY_STATE_ROOT, compute_state_root};
use arkret_wire::EventKind;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::transcripts::record_vector_event;

pub const VECTOR_ID_STATE_ROOT_INCREMENTAL: &str = "ak.vector.state_root.incremental.v1";
pub const VECTOR_ID_STRAND_TRACKS_UPDATE_ATOMIC: &str = "ak.vector.strand_tracks_update.atomic.v1";

pub const ALL_STATE_REDUCER_HARDENING_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_STATE_ROOT_INCREMENTAL,
    VECTOR_ID_STRAND_TRACKS_UPDATE_ATOMIC,
];

const STATE_REDUCER_HARDENING_FIXTURE_FILE: &str = "state-reducer-hardening-fixture.json";
const STATE_REDUCER_HARDENING_PROFILE: &str = "ak.vector_group.cba_lattice.v1";
const STRAND_TRACKS_CELL_FAMILY: &str = arkret_wire::CellFamilyId::STRAND_TRACKS_V1;

pub fn run_state_reducer_hardening_fixture_suite() -> Result<()> {
    let fixture = state_reducer_hardening_fixture()?;
    run_state_root_incremental_case(case(&fixture, VECTOR_ID_STATE_ROOT_INCREMENTAL)?)?;
    run_strand_tracks_update_atomic_case(case(&fixture, VECTOR_ID_STRAND_TRACKS_UPDATE_ATOMIC)?)?;
    Ok(())
}

pub fn run_state_root_incremental_vector() -> Result<()> {
    let fixture = state_reducer_hardening_fixture()?;
    run_state_root_incremental_case(case(&fixture, VECTOR_ID_STATE_ROOT_INCREMENTAL)?)
}

pub fn run_strand_tracks_update_atomic_vector() -> Result<()> {
    let fixture = state_reducer_hardening_fixture()?;
    run_strand_tracks_update_atomic_case(case(&fixture, VECTOR_ID_STRAND_TRACKS_UPDATE_ATOMIC)?)
}

fn state_reducer_hardening_fixture() -> Result<Value> {
    let fixture = super::load_fixture_value(STATE_REDUCER_HARDENING_FIXTURE_FILE)?;
    super::validate_profile(&fixture, STATE_REDUCER_HARDENING_PROFILE)?;
    validate_state_reducer_fixture_metadata(&fixture)?;
    Ok(fixture)
}

fn validate_state_reducer_fixture_metadata(fixture: &Value) -> Result<()> {
    if fixture.get("suite").and_then(Value::as_str) != Some("state_reducer_hardening") {
        bail!("state reducer hardening fixture suite drifted");
    }

    let covers = fixture
        .get("covers_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("state reducer hardening fixture missing covers_vectors[]"))?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("state reducer hardening fixture missing cases[]"))?;

    for vector_id in ALL_STATE_REDUCER_HARDENING_VECTOR_IDS {
        if !covers
            .iter()
            .any(|entry| entry.as_str() == Some(*vector_id))
        {
            bail!("state reducer hardening fixture missing covers_vectors entry {vector_id}");
        }
        if !cases.iter().any(|case| {
            case.get("vector_id").and_then(Value::as_str) == Some(*vector_id)
                && case
                    .get("assertions")
                    .and_then(Value::as_array)
                    .is_some_and(|assertions| !assertions.is_empty())
        }) {
            bail!("state reducer hardening fixture missing asserted case {vector_id}");
        }
    }

    Ok(())
}

fn case<'a>(fixture: &'a Value, vector_id: &str) -> Result<&'a Value> {
    fixture
        .get("cases")
        .and_then(Value::as_array)
        .and_then(|cases| {
            cases
                .iter()
                .find(|case| case.get("vector_id").and_then(Value::as_str) == Some(vector_id))
        })
        .ok_or_else(|| anyhow!("state reducer hardening fixture missing case {vector_id}"))
}

fn run_state_root_incremental_case(case: &Value) -> Result<()> {
    let input = case
        .get("input")
        .ok_or_else(|| anyhow!("state_root case missing input"))?;
    let initial_cells = cells_from_array(input, "/initial_cells")?;
    if initial_cells.len() < 8 {
        bail!("state_root incremental vector must start with at least 8 cells");
    }
    let initial_root = compute_root_str(&initial_cells)?;
    if initial_root == EMPTY_STATE_ROOT {
        bail!("non-empty state_root fixture unexpectedly equals empty Merkle root");
    }

    let transitions = pointer_array(input, "/transitions")?;
    let mut seen = BTreeSet::new();
    for transition in transitions {
        let name = required_str(transition, "name")?;
        seen.insert(name.to_owned());
        let delta = pointer_array(transition, "/delta")?;
        let full_cells = apply_delta_full(&initial_cells, delta)?;
        let incremental_cells = apply_delta_incremental(&initial_cells, delta)?;
        let full_root = compute_root_str(&full_cells)?;
        let incremental_root = compute_root_str(&incremental_cells)?;

        if expected_bool(transition, "incremental_equals_full").unwrap_or(false)
            && incremental_root != full_root
        {
            bail!(
                "state_root transition {name} diverged: incremental={incremental_root}, full={full_root}"
            );
        }

        if expected_bool(transition, "non_empty_delta_changes_root").unwrap_or(false) {
            if delta.is_empty() {
                bail!("state_root transition {name} expected a non-empty delta");
            }
            if full_root == initial_root {
                bail!("state_root transition {name} did not change root after non-empty delta");
            }
        }

        if expected_bool(transition, "stale_cache_would_drift").unwrap_or(false)
            && initial_root == full_root
        {
            bail!("state_root transition {name} stale cache did not drift from full root");
        }

        if expected_bool(transition, "delta_order_independent").unwrap_or(false) {
            let mut reversed = delta.to_vec();
            reversed.reverse();
            let reversed_root = compute_root_str(&apply_delta_incremental(
                &initial_cells,
                reversed.as_slice(),
            )?)?;
            if reversed_root != incremental_root {
                bail!(
                    "state_root transition {name} changed under reversed delta order: {reversed_root} != {incremental_root}"
                );
            }
        }

        if expected_bool(transition, "reuses_previous_root").unwrap_or(false) {
            if !delta.is_empty() {
                bail!("state_root transition {name} expected empty delta");
            }
            if incremental_root != initial_root {
                bail!(
                    "state_root transition {name} did not reuse previous root: {incremental_root} != {initial_root}"
                );
            }
        }

        if expected_bool(transition, "must_not_return_empty_merkle_root").unwrap_or(false)
            && incremental_root == EMPTY_STATE_ROOT
        {
            bail!("state_root transition {name} returned empty Merkle root for empty delta");
        }

        if let Some(cell) = expected_str_opt(transition, "new_cell_present")?
            && !full_cells.contains_key(&cell_ref(cell)?)
        {
            bail!("state_root transition {name} did not include new cell {cell}");
        }

        if let Some(cell) = expected_str_opt(transition, "tombstone_cell_remains")? {
            let state = full_cells.get(&cell_ref(cell)?).ok_or_else(|| {
                anyhow!("state_root transition {name} removed tombstone cell {cell}")
            })?;
            if !is_tombstone_state(state) {
                bail!("state_root transition {name} tombstone cell {cell} was not retained");
            }
        }

        if let Some(expected_count) = expected_u64_opt(transition, "final_cell_count")?
            && full_cells.len() as u64 != expected_count
        {
            bail!(
                "state_root transition {name} expected {expected_count} cells, got {}",
                full_cells.len()
            );
        }

        record_vector_event(
            &format!("state_reducer_hardening.state_root.{name}"),
            &json!({
                "vector_id": VECTOR_ID_STATE_ROOT_INCREMENTAL,
                "delta_len": delta.len(),
            }),
            &json!({
                "incremental_equals_full": true,
                "full_root": full_root,
            }),
            &json!({
                "incremental_root": incremental_root,
                "full_root": full_root,
                "cell_count": full_cells.len(),
            }),
        );
    }

    for required in [
        "single_cell_update",
        "half_cell_update",
        "all_cells_update",
        "empty_delta_reuses_previous_root",
        "new_cell_plus_tombstone",
    ] {
        if !seen.contains(required) {
            bail!("state_root incremental vector missing transition {required}");
        }
    }

    Ok(())
}

fn run_strand_tracks_update_atomic_case(case: &Value) -> Result<()> {
    assert_strand_tracks_registry_binding()?;

    let input = case
        .get("input")
        .ok_or_else(|| anyhow!("strand_tracks case missing input"))?;
    let cell_id = required_str(input, "cell_id")?;
    let expected_prefix = format!("ak:cell:{STRAND_TRACKS_CELL_FAMILY}:");
    if !cell_id.starts_with(&expected_prefix) {
        bail!("strand tracks vector cell_id is not bound to {STRAND_TRACKS_CELL_FAMILY}");
    }
    required_str(input, "strand_id")?;

    let initial_tracks = tracks_from_value(
        input
            .get("initial_tracks")
            .ok_or_else(|| anyhow!("strand_tracks case missing initial_tracks"))?,
    )?;
    validate_tracks_invariant(&initial_tracks).map_err(|reason| {
        anyhow!("strand_tracks initial state violates invariant with reason {reason}")
    })?;

    let scenarios = pointer_array(input, "/cases")?;
    let mut seen = BTreeSet::new();
    for scenario in scenarios {
        let name = required_str(scenario, "name")?;
        seen.insert(name.to_owned());
        let expected = scenario
            .get("expected")
            .ok_or_else(|| anyhow!("strand_tracks scenario {name} missing expected"))?;
        let expected_decision = required_str(expected, "decision")?;
        let patches = track_patches_from_value(
            scenario
                .get("patch")
                .ok_or_else(|| anyhow!("strand_tracks scenario {name} missing patch"))?,
        )?;
        let before = initial_tracks.clone();
        let result = apply_tracks_patch_atomic(&initial_tracks, &patches);

        match expected_decision {
            "accept" => {
                let outcome = result.map_err(|reason| {
                    anyhow!("strand_tracks scenario {name} unexpectedly rejected: {reason}")
                })?;
                let expected_cell_writes = expected
                    .get("cell_writes")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| {
                        anyhow!("strand_tracks scenario {name} missing expected.cell_writes")
                    })?;
                if outcome.cell_writes != expected_cell_writes {
                    bail!(
                        "strand_tracks scenario {name} expected {expected_cell_writes} cell writes, got {}",
                        outcome.cell_writes
                    );
                }
                let expected_tracks = expected
                    .get("tracks")
                    .ok_or_else(|| {
                        anyhow!("strand_tracks scenario {name} missing expected.tracks")
                    })?
                    .clone();
                let observed_tracks = serde_json::to_value(&outcome.tracks)?;
                if observed_tracks != expected_tracks {
                    bail!(
                        "strand_tracks scenario {name} final tracks drifted: expected {expected_tracks}, got {observed_tracks}"
                    );
                }
                if expected
                    .get("sequential_first_path_would_violate")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                    && !first_patch_would_violate_sequentially(&initial_tracks, &patches)?
                {
                    bail!(
                        "strand_tracks scenario {name} did not prove intermediate zero-primary state is hidden"
                    );
                }
                record_vector_event(
                    &format!("state_reducer_hardening.strand_tracks.{name}"),
                    &json!({
                        "vector_id": VECTOR_ID_STRAND_TRACKS_UPDATE_ATOMIC,
                        "patch_len": patches.len(),
                    }),
                    &json!({
                        "decision": "accept",
                        "cell_writes": expected_cell_writes,
                        "tracks": expected_tracks,
                    }),
                    &json!({
                        "decision": "accept",
                        "cell_writes": outcome.cell_writes,
                        "tracks": observed_tracks,
                    }),
                );
            }
            "reject" => {
                let expected_reason = required_str(expected, "reason")?;
                let observed_reason = result.err().ok_or_else(|| {
                    anyhow!("strand_tracks scenario {name} unexpectedly accepted")
                })?;
                if observed_reason != expected_reason {
                    bail!(
                        "strand_tracks scenario {name} expected reject reason {expected_reason}, got {observed_reason}"
                    );
                }
                if expected
                    .get("tracks_unchanged")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                    && initial_tracks != before
                {
                    bail!("strand_tracks scenario {name} mutated tracks after rejection");
                }
                record_vector_event(
                    &format!("state_reducer_hardening.strand_tracks.{name}"),
                    &json!({
                        "vector_id": VECTOR_ID_STRAND_TRACKS_UPDATE_ATOMIC,
                        "patch_len": patches.len(),
                    }),
                    &json!({
                        "decision": "reject",
                        "reason": expected_reason,
                    }),
                    &json!({
                        "decision": "reject",
                        "reason": observed_reason,
                        "tracks": serde_json::to_value(&initial_tracks)?,
                    }),
                );
            }
            other => bail!("strand_tracks scenario {name} unknown expected decision {other}"),
        }
    }

    for required in [
        "primary_switch_atomic",
        "disable_and_profile_update_atomic",
        "disabled_primary_rejected",
        "last_enabled_track_rejected",
        "primary_conflict_rejected_all_or_nothing",
        "unregistered_track_name_rejected",
        "selector_segment_rejected",
    ] {
        if !seen.contains(required) {
            bail!("strand_tracks atomic vector missing scenario {required}");
        }
    }

    Ok(())
}

fn assert_strand_tracks_registry_binding() -> Result<()> {
    let registry = super::load_artifact_json("registry/event-kind-registry.json")?;
    let event = registry
        .get("event_kinds")
        .and_then(Value::as_array)
        .and_then(|events| {
            events.iter().find(|event| {
                event.get("event_kind").and_then(Value::as_str)
                    == Some(EventKind::STRAND_TRACKS_UPDATE)
            })
        })
        .ok_or_else(|| {
            anyhow!(
                "event-kind registry missing {eventkind_strand_tracks_update}",
                eventkind_strand_tracks_update = EventKind::STRAND_TRACKS_UPDATE
            )
        })?;

    if event.get("cell_family").and_then(Value::as_str) != Some(STRAND_TRACKS_CELL_FAMILY) {
        bail!(
            "{eventkind_strand_tracks_update} cell family drifted",
            eventkind_strand_tracks_update = EventKind::STRAND_TRACKS_UPDATE
        );
    }
    if event.get("lattice").and_then(Value::as_str) != Some("mv_register") {
        bail!(
            "{eventkind_strand_tracks_update} lattice must remain mv_register",
            eventkind_strand_tracks_update = EventKind::STRAND_TRACKS_UPDATE
        );
    }
    if event.get("bottom").and_then(Value::as_str) != Some("expose") {
        bail!(
            "{eventkind_strand_tracks_update} bottom policy must remain expose",
            eventkind_strand_tracks_update = EventKind::STRAND_TRACKS_UPDATE
        );
    }
    if event.get("reducer_input").and_then(Value::as_bool) != Some(true) {
        bail!(
            "{eventkind_strand_tracks_update} must remain reducer_input",
            eventkind_strand_tracks_update = EventKind::STRAND_TRACKS_UPDATE
        );
    }

    Ok(())
}

fn cells_from_array(value: &Value, pointer: &str) -> Result<BTreeMap<CellRef, CellState>> {
    let mut cells = BTreeMap::new();
    for entry in pointer_array(value, pointer)? {
        let cell_id = required_str(entry, "cell")?;
        let value = entry
            .get("value")
            .ok_or_else(|| anyhow!("cell entry {cell_id} missing value"))?
            .clone();
        let previous = cells.insert(cell_ref(cell_id)?, CellState::Value(value));
        if previous.is_some() {
            bail!("duplicate state_root cell {cell_id}");
        }
    }
    Ok(cells)
}

fn apply_delta_full(
    base: &BTreeMap<CellRef, CellState>,
    delta: &[Value],
) -> Result<BTreeMap<CellRef, CellState>> {
    let mut cells = base.clone();
    apply_delta_entries(&mut cells, delta)?;
    Ok(cells)
}

fn apply_delta_incremental(
    cached: &BTreeMap<CellRef, CellState>,
    delta: &[Value],
) -> Result<BTreeMap<CellRef, CellState>> {
    let mut cells = cached.clone();
    apply_delta_entries(&mut cells, delta)?;
    Ok(cells)
}

fn apply_delta_entries(cells: &mut BTreeMap<CellRef, CellState>, delta: &[Value]) -> Result<()> {
    for entry in delta {
        let cell_id = required_str(entry, "cell")?;
        let op = required_str(entry, "op")?;
        let value = entry
            .get("value")
            .ok_or_else(|| anyhow!("delta entry {cell_id} missing value"))?
            .clone();
        match op {
            "set" | "tombstone" => {
                cells.insert(cell_ref(cell_id)?, CellState::Value(value));
            }
            other => bail!("unsupported state_root delta op {other}"),
        }
    }
    Ok(())
}

fn compute_root_str(cells: &BTreeMap<CellRef, CellState>) -> Result<String> {
    Ok(compute_state_root(cells)
        .map_err(|err| anyhow!("state_root compute failed: {err}"))?
        .as_str()
        .to_owned())
}

fn cell_ref(raw: &str) -> Result<CellRef> {
    CellRef::new(raw.to_owned()).map_err(|err| anyhow!("invalid cell ref {raw}: {err}"))
}

fn is_tombstone_state(state: &CellState) -> bool {
    match state {
        CellState::Value(value) => value
            .get("deleted")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        CellState::Bottom(_) => true,
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Default)]
struct TrackState {
    enabled: bool,
    #[serde(default)]
    is_primary: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct TrackPatch {
    path: String,
    op: String,
    value: Value,
}

struct TrackPatchOutcome {
    tracks: BTreeMap<String, TrackState>,
    cell_writes: u64,
}

fn tracks_from_value(value: &Value) -> Result<BTreeMap<String, TrackState>> {
    let tracks: BTreeMap<String, TrackState> = serde_json::from_value(value.clone())
        .map_err(|err| anyhow!("invalid tracks map: {err}"))?;
    for key in tracks.keys() {
        if !valid_track_key(key) {
            bail!("invalid track key {key}");
        }
    }
    Ok(tracks)
}

fn track_patches_from_value(value: &Value) -> Result<Vec<TrackPatch>> {
    serde_json::from_value(value.clone()).map_err(|err| anyhow!("invalid track patch list: {err}"))
}

fn apply_tracks_patch_atomic(
    initial: &BTreeMap<String, TrackState>,
    patches: &[TrackPatch],
) -> std::result::Result<TrackPatchOutcome, &'static str> {
    let mut merged = initial.clone();
    for patch in patches {
        apply_single_track_patch(&mut merged, patch)?;
    }
    validate_tracks_invariant(&merged)?;
    Ok(TrackPatchOutcome {
        tracks: merged,
        cell_writes: 1,
    })
}

fn first_patch_would_violate_sequentially(
    initial: &BTreeMap<String, TrackState>,
    patches: &[TrackPatch],
) -> Result<bool> {
    let first = patches
        .first()
        .ok_or_else(|| anyhow!("sequential check requires at least one patch"))?;
    let mut partial = initial.clone();
    apply_single_track_patch(&mut partial, first).map_err(|reason| {
        anyhow!("first patch was structurally rejected during sequential check: {reason}")
    })?;
    Ok(validate_tracks_invariant(&partial).is_err())
}

fn apply_single_track_patch(
    tracks: &mut BTreeMap<String, TrackState>,
    patch: &TrackPatch,
) -> std::result::Result<(), &'static str> {
    if patch.path.contains('[') || patch.path.contains(']') {
        return Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
    }
    let parts: Vec<&str> = patch.path.split('.').collect();
    if parts.len() != 3 || parts[0] != "tracks" {
        return Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
    }
    let track_key = parts[1];
    let field = parts[2];
    if !valid_track_key(track_key) || patch.op != "set" {
        return Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
    }

    let track = tracks
        .get_mut(track_key)
        .ok_or(arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
    match field {
        "enabled" => {
            track.enabled = patch
                .value
                .as_bool()
                .ok_or(arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
            Ok(())
        }
        "is_primary" => {
            track.is_primary = patch
                .value
                .as_bool()
                .ok_or(arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
            Ok(())
        }
        "profile" => {
            track.profile = Some(
                patch
                    .value
                    .as_str()
                    .ok_or(arkret_wire::ErrorCode::SCHEMA_VIOLATION)?
                    .to_owned(),
            );
            Ok(())
        }
        _ => Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION),
    }
}

fn validate_tracks_invariant(
    tracks: &BTreeMap<String, TrackState>,
) -> std::result::Result<(), &'static str> {
    if tracks.is_empty() {
        return Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
    }
    let mut primary_count = 0;
    for (key, track) in tracks {
        if !valid_track_key(key) {
            return Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
        }
        if track.is_primary && !track.enabled {
            return Err(arkret_wire::ReasonCode::PRIMARY_TRACK_REQUIRED);
        }
        if track.enabled && track.is_primary {
            primary_count += 1;
        }
    }
    if primary_count != 1 {
        return Err(if primary_count == 0 {
            arkret_wire::ReasonCode::PRIMARY_TRACK_REQUIRED
        } else {
            arkret_wire::ErrorCode::SCHEMA_VIOLATION
        });
    }
    Ok(())
}

fn valid_track_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if key.len() > 64 || !first.is_ascii_lowercase() {
        return false;
    }
    chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
}

fn pointer_array<'a>(value: &'a Value, pointer: &str) -> Result<&'a [Value]> {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| anyhow!("missing array at {pointer}"))
}

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing string field {field}"))
}

fn expected_bool(value: &Value, field: &str) -> Result<bool> {
    value
        .pointer(&format!("/expected/{field}"))
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("missing bool expected.{field}"))
}

fn expected_str_opt<'a>(value: &'a Value, field: &str) -> Result<Option<&'a str>> {
    match value.pointer(&format!("/expected/{field}")) {
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => bail!("expected.{field} must be a string"),
        None => Ok(None),
    }
}

fn expected_u64_opt(value: &Value, field: &str) -> Result<Option<u64>> {
    match value.pointer(&format!("/expected/{field}")) {
        Some(Value::Number(number)) => number
            .as_u64()
            .map(Some)
            .ok_or_else(|| anyhow!("expected.{field} must be u64")),
        Some(_) => bail!("expected.{field} must be u64"),
        None => Ok(None),
    }
}
