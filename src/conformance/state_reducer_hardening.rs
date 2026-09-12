//! State-root and Strand tracks reducer conformance vectors.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail};
use arkret_identifiers::{CellRef, EventId};
use arkret_state::state::{EMPTY_STATE_ROOT, compute_state_root};
use arkret_state::state_model::{ResolvedCellState, SequencedStateValue};
use arkret_wire::{EventCellBottom, EventCellStateModel, EventKind};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{expected_bool, expected_str_opt, expected_u64_opt, required_str};
use crate::transcripts::record_vector_event;

pub const VECTOR_ID_STATE_ROOT_INCREMENTAL: &str = "ak.vector.state_root.incremental.v1";
pub const VECTOR_ID_STRAND_TRACKS_UPDATE_ATOMIC: &str = "ak.vector.strand_tracks_update.atomic.v1";
pub const VECTOR_ID_PATCH_REDACTABLE_CONTENT_SLOT_UNSET_BAN: &str =
    "ak.vector.patch.redactable_content_slot_unset_ban.v1";

pub const ALL_STATE_REDUCER_HARDENING_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_STATE_ROOT_INCREMENTAL,
    VECTOR_ID_STRAND_TRACKS_UPDATE_ATOMIC,
    VECTOR_ID_PATCH_REDACTABLE_CONTENT_SLOT_UNSET_BAN,
];

const STATE_REDUCER_HARDENING_FIXTURE_FILE: &str = "state-reducer-hardening-fixture.json";
const STATE_REDUCER_HARDENING_PROFILE: &str = "ak.vector_group.cbs_lattice.v1";
const STATE_REDUCER_HARDENING_SUITE_ENTRYPOINT: &str = "ak.suite.reducer.hardening.v1";
const STRAND_OBJECT_CELL_FAMILY: &str = arkret_wire::CellFamilyId::STRAND_OBJECT_V1;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateReducerHardeningFixture {
    profile: String,
    version: String,
    suite: String,
    runner: Value,
    covers_vectors: Vec<String>,
    cases: Vec<Value>,
}

pub fn run_state_reducer_hardening_fixture_suite() -> Result<()> {
    let fixture = state_reducer_hardening_fixture()?;
    run_state_root_incremental_case(case(&fixture, VECTOR_ID_STATE_ROOT_INCREMENTAL)?)?;
    run_strand_tracks_update_atomic_case(case(&fixture, VECTOR_ID_STRAND_TRACKS_UPDATE_ATOMIC)?)?;
    run_redactable_content_slot_unset_ban_case(case(
        &fixture,
        VECTOR_ID_PATCH_REDACTABLE_CONTENT_SLOT_UNSET_BAN,
    )?)?;
    Ok(())
}

pub fn run_patch_redactable_content_slot_unset_ban_vector() -> Result<()> {
    let fixture = state_reducer_hardening_fixture()?;
    run_redactable_content_slot_unset_ban_case(case(
        &fixture,
        VECTOR_ID_PATCH_REDACTABLE_CONTENT_SLOT_UNSET_BAN,
    )?)
}

pub fn run_state_root_incremental_vector() -> Result<()> {
    let fixture = state_reducer_hardening_fixture()?;
    run_state_root_incremental_case(case(&fixture, VECTOR_ID_STATE_ROOT_INCREMENTAL)?)
}

pub fn run_strand_tracks_update_atomic_vector() -> Result<()> {
    let fixture = state_reducer_hardening_fixture()?;
    run_strand_tracks_update_atomic_case(case(&fixture, VECTOR_ID_STRAND_TRACKS_UPDATE_ATOMIC)?)
}

fn state_reducer_hardening_fixture() -> Result<StateReducerHardeningFixture> {
    let fixture: StateReducerHardeningFixture = serde_json::from_value(super::load_fixture_value(
        STATE_REDUCER_HARDENING_FIXTURE_FILE,
    )?)?;
    validate_state_reducer_fixture_metadata(&fixture)?;
    Ok(fixture)
}

fn validate_state_reducer_fixture_metadata(fixture: &StateReducerHardeningFixture) -> Result<()> {
    if fixture.profile != STATE_REDUCER_HARDENING_PROFILE
        || fixture.suite != "state_reducer_hardening"
        || fixture.version.trim().is_empty()
    {
        bail!("state reducer hardening fixture suite drifted");
    }
    if fixture
        .runner
        .pointer("/entrypoint")
        .and_then(Value::as_str)
        != Some(STATE_REDUCER_HARDENING_SUITE_ENTRYPOINT)
    {
        bail!(
            "state reducer hardening fixture runner entrypoint is not \
             {STATE_REDUCER_HARDENING_SUITE_ENTRYPOINT}"
        );
    }

    let covers = &fixture.covers_vectors;
    let cases = &fixture.cases;

    for vector_id in ALL_STATE_REDUCER_HARDENING_VECTOR_IDS {
        if !covers.iter().any(|entry| entry == vector_id) {
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

fn case<'a>(fixture: &'a StateReducerHardeningFixture, vector_id: &str) -> Result<&'a Value> {
    fixture
        .cases
        .iter()
        .find(|case| case.get("vector_id").and_then(Value::as_str) == Some(vector_id))
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
    let expected_prefix = format!("ak:cell:{STRAND_OBJECT_CELL_FAMILY}:");
    if !cell_id.starts_with(&expected_prefix) {
        bail!("strand tracks vector cell_id is not bound to {STRAND_OBJECT_CELL_FAMILY}");
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
    let descriptor = EventKind::try_new(arkret_wire::event_kind_str::STRAND_TRACKS_UPDATE)
        .and_then(|kind| kind.descriptor())
        .ok_or_else(|| {
            anyhow!(
                "SDK missing {}",
                arkret_wire::event_kind_str::STRAND_TRACKS_UPDATE
            )
        })?;
    let write = descriptor
        .cell_writes
        .iter()
        .find(|write| {
            write.cell_family.map(|family| family.as_str()) == Some(STRAND_OBJECT_CELL_FAMILY)
        })
        .ok_or_else(|| {
            anyhow!(
                "{} has no SDK-declared {} write",
                arkret_wire::event_kind_str::STRAND_TRACKS_UPDATE,
                STRAND_OBJECT_CELL_FAMILY
            )
        })?;

    if write.cell_family.map(|family| family.as_str()) != Some(STRAND_OBJECT_CELL_FAMILY) {
        bail!(
            "{eventkind_strand_tracks_update} cell family drifted",
            eventkind_strand_tracks_update = arkret_wire::event_kind_str::STRAND_TRACKS_UPDATE
        );
    }
    if write.state_model != Some(EventCellStateModel::CausalRegister) {
        bail!(
            "{eventkind_strand_tracks_update} state model must remain causal_register",
            eventkind_strand_tracks_update = arkret_wire::event_kind_str::STRAND_TRACKS_UPDATE
        );
    }
    if write.bottom != Some(EventCellBottom::Expose) {
        bail!(
            "{eventkind_strand_tracks_update} bottom policy must remain expose",
            eventkind_strand_tracks_update = arkret_wire::event_kind_str::STRAND_TRACKS_UPDATE
        );
    }
    if !descriptor.reducer_input {
        bail!(
            "{eventkind_strand_tracks_update} must remain reducer_input",
            eventkind_strand_tracks_update = arkret_wire::event_kind_str::STRAND_TRACKS_UPDATE
        );
    }

    Ok(())
}

fn cells_from_array(value: &Value, pointer: &str) -> Result<BTreeMap<CellRef, ResolvedCellState>> {
    let mut cells = BTreeMap::new();
    for entry in pointer_array(value, pointer)? {
        let cell_id = required_str(entry, "cell")?;
        let value = entry
            .get("value")
            .ok_or_else(|| anyhow!("cell entry {cell_id} missing value"))?
            .clone();
        let previous = cells.insert(
            cell_ref(cell_id)?,
            ResolvedCellState::Sequenced(SequencedStateValue {
                revision_event_id: revision_event_id(entry)?,
                value,
            }),
        );
        if previous.is_some() {
            bail!("duplicate state_root cell {cell_id}");
        }
    }
    Ok(cells)
}

fn apply_delta_full(
    base: &BTreeMap<CellRef, ResolvedCellState>,
    delta: &[Value],
) -> Result<BTreeMap<CellRef, ResolvedCellState>> {
    let mut cells = base.clone();
    apply_delta_entries(&mut cells, delta)?;
    Ok(cells)
}

fn apply_delta_incremental(
    cached: &BTreeMap<CellRef, ResolvedCellState>,
    delta: &[Value],
) -> Result<BTreeMap<CellRef, ResolvedCellState>> {
    let mut cells = cached.clone();
    apply_delta_entries(&mut cells, delta)?;
    Ok(cells)
}

fn apply_delta_entries(
    cells: &mut BTreeMap<CellRef, ResolvedCellState>,
    delta: &[Value],
) -> Result<()> {
    for entry in delta {
        let cell_id = required_str(entry, "cell")?;
        let op = required_str(entry, "op")?;
        let value = entry
            .get("value")
            .ok_or_else(|| anyhow!("delta entry {cell_id} missing value"))?
            .clone();
        match op {
            "set" | "tombstone" => {
                cells.insert(
                    cell_ref(cell_id)?,
                    ResolvedCellState::Sequenced(SequencedStateValue {
                        revision_event_id: revision_event_id(entry)?,
                        value,
                    }),
                );
            }
            other => bail!("unsupported state_root delta op {other}"),
        }
    }
    Ok(())
}

/// Compute the Seal security root from sequenced state, including the
/// Event-derived revision identity retained for each fixture write.
fn compute_root_str(cells: &BTreeMap<CellRef, ResolvedCellState>) -> Result<String> {
    Ok(compute_state_root(
        arkret_state::GovernanceView::new(cells),
        arkret_canonical::DigestSuite::Sha256,
    )
    .map_err(|err| anyhow!("state_root compute failed: {err}"))?
    .as_str()
    .to_owned())
}

fn cell_ref(raw: &str) -> Result<CellRef> {
    CellRef::new(raw.to_owned()).map_err(|err| anyhow!("invalid cell ref {raw}: {err}"))
}

fn revision_event_id(entry: &Value) -> Result<EventId> {
    let digest = arkret_canonical::canonical_sha256(entry)?;
    EventId::from_event_digest(&arkret_wire::Hash::new(digest)?)
        .map_err(|error| anyhow!("fixture revision does not derive an Event id: {error}"))
}

fn is_tombstone_state(state: &ResolvedCellState) -> bool {
    match state {
        ResolvedCellState::Sequenced(state) => state
            .value
            .get("deleted")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        _ => false,
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

// ── `ak.vector.patch.redactable_content_slot_unset_ban.v1` ─────────────────
//
// `event-and-patch.md` §4.2.4 is a slot-existence rule, not a capability
// boundary: absence of a content slot on a materialized object is reserved for
// "never authored" and "cleared by redaction", so an ordinary update MUST NOT
// remove it. The normative path set is the machine-readable
// `registry/redactable-field-registry.json`, which is why this vector reads the
// registry instead of restating a list, and why `metadata.title` /
// `metadata.summary` / `metadata.fields.*` — which are ordinary optional
// members — must keep accepting `$op="unset"` or an optional field would become
// write-once.

const REDACTABLE_FIELD_REGISTRY_REF: &str = "registry/redactable-field-registry.json";
const REDACTABLE_PATH_SOURCE: &str = "registry/redactable-field-registry.json#/redactable_fields";

/// Typed object refs for each registered content-carrier update surface.
const TYPED_UPDATE_TARGET_REFS: &[(&str, &str)] = &[
    (
        "message",
        "ak:message:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2",
    ),
    (
        "morph",
        "ak:morph:ASc_XP_IqOBAY6GgbPMLFCeZmi0uBNaWvHazHgmn-B8K",
    ),
    (
        "strand",
        "ak:strand:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
    ),
];

fn run_redactable_content_slot_unset_ban_case(case: &Value) -> Result<()> {
    let input = case
        .get("input")
        .ok_or_else(|| anyhow!("redactable slot case missing input"))?;
    if required_str(input, "path_source")? != REDACTABLE_PATH_SOURCE {
        bail!(
            "redactable slot vector no longer derives its path set from \
             {REDACTABLE_PATH_SOURCE}; a hand-maintained list would drift from the registry"
        );
    }
    let registry = super::load_artifact_json(REDACTABLE_FIELD_REGISTRY_REF)?;
    let registered = registered_redactable_slots(&registry)?;
    let cases = pointer_array(input, "/cases")?;

    let mut covered_slots = BTreeSet::new();
    let mut saw_empty_body_set = false;
    let mut metadata_accepts = BTreeSet::new();
    for entry in cases {
        let name = required_str(entry, "name")?;
        let object_kind = required_str(entry, "object_kind")?;
        let event_kind = required_str(entry, "event_kind")?;
        if !registered.iter().any(|(kind, _)| kind == object_kind) {
            bail!(
                "redactable slot case `{name}` names an unregistered object kind `{object_kind}`"
            );
        }
        let patch: arkret_wire::patch::Patch =
            serde_json::from_value(entry.get("patch").cloned().ok_or_else(|| {
                anyhow!("redactable slot case `{name}` carries no ak.schema.patch.v1 body")
            })?)?;
        let paths = patch.iter().map(|(path, _)| path).collect::<Vec<_>>();
        let [path] = paths.as_slice() else {
            bail!("redactable slot case `{name}` must address exactly one path");
        };
        let path = (*path).to_owned();

        let prestate = redactable_prestate(object_kind, &path);
        let observed = patch.apply(&prestate);
        // The fixture supplies a registry-checked object kind, not an untrusted
        // prestate id. Exercise the same semantic guard used by the reducer;
        // payload constructors additionally cover each event kind's wire shape.
        let semantic = arkret_wire::patch::validate_patch_semantic_safety(
            &patch,
            arkret_wire::patch::PatchTargetKind::Verified(object_kind),
        );
        let target_ref = typed_update_target_ref(object_kind)?;
        let payload: Result<Value> = match (object_kind, event_kind) {
            ("strand", "ak.strand.update") => {
                arkret_models_collaboration::events_payloads::StrandPatchPayload::for_strand(
                    arkret_wire::StrandId::new(target_ref)?,
                    patch.clone(),
                )
                .and_then(|payload| {
                    let value = payload.to_value()?;
                    let decoded: arkret_models_collaboration::events_payloads::StrandPatchPayload =
                        serde_json::from_value(value.clone()).map_err(|error| {
                            arkret_wire::WireError::Protocol(format!(
                                "strand update DTO round trip failed: {error}"
                            ))
                        })?;
                    arkret_wire::patch::validate_patch_semantic_safety(
                        &decoded.patch,
                        arkret_wire::patch::PatchTargetKind::Verified("strand"),
                    )?;
                    Ok(value)
                })
                .map_err(Into::into)
            }
            ("morph", "ak.morph.update") => {
                arkret_models_collaboration::events_payloads::MorphUpdatePayload::for_morph(
                    arkret_wire::MorphId::new(target_ref)?,
                    patch.clone(),
                )
                .and_then(|payload| {
                    let value = payload.to_value()?;
                    let decoded: arkret_models_collaboration::events_payloads::MorphUpdatePayload =
                        serde_json::from_value(value.clone()).map_err(|error| {
                            arkret_wire::WireError::Protocol(format!(
                                "morph update DTO round trip failed: {error}"
                            ))
                        })?;
                    arkret_wire::patch::validate_patch_semantic_safety(
                        &decoded.patch,
                        arkret_wire::patch::PatchTargetKind::Verified("morph"),
                    )?;
                    Ok(value)
                })
                .map_err(Into::into)
            }
            ("message", "ak.message.revise") => {
                // Message revision is a replacement-content surface, not a
                // generic patch surface. Its real closed DTO must reject a
                // patch carrier; Patch::apply above separately proves the
                // exact redactable-slot unset prohibition and reason code.
                serde_json::from_value::<
                    arkret_models_collaboration::events_payloads::MessageRevisePayload,
                >(serde_json::json!({
                    "message_id": arkret_wire::MessageId::new(target_ref)?,
                    "patch": patch,
                }))
                .and_then(serde_json::to_value)
                .map_err(Into::into)
            }
            _ => bail!("redactable slot case `{name}` does not name its registered update surface"),
        };

        let decision = entry
            .pointer("/expected/decision")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("redactable slot case `{name}` has no expected.decision"))?;
        match decision {
            "reject" => {
                let reason_code = entry
                    .pointer("/expected/reason_code")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        anyhow!("redactable slot rejection `{name}` names no reason_code")
                    })?;
                if reason_code != arkret_wire::ReasonCode::PATCH_UNSET_REDACTABLE_FIELD {
                    bail!(
                        "redactable slot rejection `{name}` names `{reason_code}`, the registered \
                         reason is `{}`",
                        arkret_wire::ReasonCode::PATCH_UNSET_REDACTABLE_FIELD
                    );
                }
                if entry.pointer("/expected/reason").and_then(Value::as_str)
                    != Some(arkret_wire::ErrorCode::SCHEMA_VIOLATION)
                {
                    bail!("redactable slot rejection `{name}` is not a schema_violation");
                }
                let error = observed.err().ok_or_else(|| {
                    anyhow!(
                        "`$op=\"unset\"` on registered content slot `{path}` was applied; the \
                         cleared slot is now indistinguishable from a redacted one"
                    )
                })?;
                if !error.to_string().contains(reason_code) {
                    bail!("redactable slot rejection `{name}` reported `{error}`");
                }
                let semantic_error = semantic.err().ok_or_else(|| {
                    anyhow!("the patch semantic guard accepted `{path}` unset for `{name}`")
                })?;
                if !semantic_error.to_string().contains(reason_code) {
                    bail!(
                        "redactable slot rejection `{name}` reported `{semantic_error}` from the \
                         semantic guard instead of `{reason_code}`"
                    );
                }
                let payload_error = payload.err().ok_or_else(|| {
                    anyhow!(
                        "the typed update admission accepted `{path}` unset for `{name}`; the \
                         typed and container gates disagree"
                    )
                })?;
                if object_kind != "message" && !payload_error.to_string().contains(reason_code) {
                    bail!(
                        "redactable slot rejection `{name}` reported `{payload_error}` after \
                         typed DTO round trip instead of `{reason_code}`"
                    );
                }
                if entry
                    .pointer("/expected/object_unchanged")
                    .and_then(Value::as_bool)
                    != Some(true)
                {
                    bail!("redactable slot rejection `{name}` does not assert object_unchanged");
                }
                assert_ordinary_update_is_not_the_redaction_event(
                    &registry,
                    object_kind,
                    &path,
                    event_kind,
                )?;
                covered_slots.insert((object_kind.to_owned(), path.clone()));
            }
            "accept" => {
                let post = observed.map_err(|error| {
                    anyhow!("redactable slot case `{name}` must be accepted, got `{error}`")
                })?;
                semantic.map_err(|error| {
                    anyhow!(
                        "redactable slot case `{name}` was refused by the patch semantic guard: \
                         `{error}`"
                    )
                })?;
                payload.map_err(|error| {
                    anyhow!(
                        "redactable slot case `{name}` was refused by the typed update admission: \
                         `{error}`"
                    )
                })?;
                if let Some(state) = entry
                    .pointer("/expected/state_unchanged")
                    .and_then(Value::as_str)
                    && post.get("state").and_then(Value::as_str) != Some(state)
                {
                    bail!("redactable slot case `{name}` moved the object out of `{state}`");
                }
                if entry
                    .pointer("/expected/content_slot_present")
                    .and_then(Value::as_bool)
                    == Some(true)
                {
                    if post.get(path.as_str()).is_none() {
                        bail!(
                            "redactable slot case `{name}` cleared `{path}` through `$op=\"set\"`; \
                             the non-terminal clear must keep the slot present"
                        );
                    }
                    saw_empty_body_set = true;
                }
                if path.starts_with("metadata") {
                    if post
                        .pointer(&format!("/{}", path.replace('.', "/")))
                        .is_some()
                    {
                        bail!(
                            "redactable slot case `{name}` left `{path}` in place; `$op=\"unset\"` \
                             is the only non-terminal clear path for an ordinary optional member"
                        );
                    }
                    metadata_accepts.insert(path.clone());
                }
            }
            other => bail!("redactable slot case `{name}` has unknown decision `{other}`"),
        }
    }

    for slot in &registered {
        if !covered_slots.contains(slot) {
            bail!(
                "registered redactable slot `{}.{}` has no `$op=\"unset\"` rejection case",
                slot.0,
                slot.1
            );
        }
    }
    if covered_slots.len() != registered.len() {
        bail!(
            "the redactable slot vector drives {} slots, the registry publishes {}",
            covered_slots.len(),
            registered.len()
        );
    }
    if !saw_empty_body_set {
        bail!(
            "the redactable slot vector lost its `$op=\"set\"` empty-body case; without it nothing \
             proves the rule is slot existence rather than a capability boundary"
        );
    }
    if metadata_accepts.len() < 2 {
        bail!(
            "the redactable slot vector must accept `$op=\"unset\"` on metadata.summary and on a \
             metadata.fields.* member; it covers {:?}",
            metadata_accepts
        );
    }
    Ok(())
}

/// Valid object id used only to exercise the registered event-specific DTO.
fn typed_update_target_ref(object_kind: &str) -> Result<&'static str> {
    TYPED_UPDATE_TARGET_REFS
        .iter()
        .find_map(|(kind, target)| (*kind == object_kind).then_some(*target))
        .ok_or_else(|| anyhow!("no typed update target fixture for `{object_kind}`"))
}

/// `(object_kind, path)` rows of the redactable-field registry.
fn registered_redactable_slots(registry: &Value) -> Result<BTreeSet<(String, String)>> {
    let rows = registry
        .get("redactable_fields")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("redactable-field registry has no redactable_fields[]"))?;
    let mut slots = BTreeSet::new();
    for row in rows {
        slots.insert((
            required_str(row, "object_kind")?.to_owned(),
            required_str(row, "path")?.to_owned(),
        ));
    }
    if slots.is_empty() {
        bail!("redactable-field registry publishes no content-carrier slots");
    }
    Ok(slots)
}

/// The rejected patch is an *ordinary* update, not the terminal redaction the
/// registry reserves for the same slot. Without this the vector would pass even
/// if the fixture quietly moved to the redaction event kind.
fn assert_ordinary_update_is_not_the_redaction_event(
    registry: &Value,
    object_kind: &str,
    path: &str,
    event_kind: &str,
) -> Result<()> {
    let row = registry
        .get("redactable_fields")
        .and_then(Value::as_array)
        .and_then(|rows| {
            rows.iter().find(|row| {
                row.get("object_kind").and_then(Value::as_str) == Some(object_kind)
                    && row.get("path").and_then(Value::as_str) == Some(path)
            })
        })
        .ok_or_else(|| anyhow!("`{object_kind}.{path}` is not a registered redactable slot"))?;
    if required_str(row, "non_terminal_clear_op")? != "set" {
        bail!("`{object_kind}.{path}` no longer declares `set` as its non-terminal clear op");
    }
    let terminal = row
        .get("terminal_clear_event_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("`{object_kind}.{path}` declares no terminal clear event kinds"))?;
    if terminal
        .iter()
        .any(|kind| kind.as_str() == Some(event_kind))
    {
        bail!(
            "`{object_kind}.{path}` unset case uses the terminal redaction kind `{event_kind}`; \
             the vector must reject an ordinary update"
        );
    }
    if EventKind::try_new(event_kind).is_none() {
        bail!("redactable slot case names an unregistered event kind `{event_kind}`");
    }
    Ok(())
}

/// A materialized object carrying the addressed slot plus the ordinary optional
/// metadata members, so an accepted `unset` really removes something.
fn redactable_prestate(object_kind: &str, path: &str) -> Value {
    let mut object = json!({
        "kind": object_kind,
        "state": "active",
        "metadata": {
            "title": "authored title",
            "summary": "authored summary",
            "fields": { "dropped_field": "authored value" }
        }
    });
    let slot = path.split('.').next().unwrap_or(path);
    if slot == "encrypted_content" {
        object["encrypted_content"] = json!({
            "algorithm": "mls_application_v1",
            "ciphertext": "Y2lwaGVydGV4dA"
        });
    } else {
        object["content"] = json!({ "kind": "ak.content.text", "body": "authored body" });
    }
    object
}

fn pointer_array<'a>(value: &'a Value, pointer: &str) -> Result<&'a [Value]> {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| anyhow!("missing array at {pointer}"))
}
