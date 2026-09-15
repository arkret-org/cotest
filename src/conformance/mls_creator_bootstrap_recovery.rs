//! `ak.suite.mls.creator_bootstrap_recovery.v1` — the creator's single durable
//! MLS Genesis bootstrap transaction.
//!
//! `encryption-and-audit.md` §5.1.2 makes one client-local durable record carry
//! an encrypted effective scope from the creator's explicit content-scheme
//! selection to MLS write-ready, and
//! `registry/mls-creator-bootstrap-transaction-registry.json` is its closed
//! state machine. This suite executes that machine rather than describing it:
//!
//! * the registry and the SDK's generated state/transition tables must agree arrow for arrow, so a
//!   regenerated registry that never reached the SDK is a failure here rather than a silent
//!   divergence in whichever client compiled last;
//! * every registered arrow must publish both crash injections, and the state a recoverer finds is
//!   derived from `(arrow, injection)` — before the commit boundary the record is still in the
//!   arrow's `from_state`, after it in its `to_state`, with no partial state in between;
//! * a recoverer executes exactly one next arrow, so every scenario expectation must be a recovery
//!   action some arrow actually produces or a registered terminal state, never a new behaviour the
//!   fixture invented.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail, ensure};
use arkret_wire::{
    MLS_CREATOR_BOOTSTRAP_TRANSITIONS, MlsCreatorBootstrapState, MlsCreatorBootstrapStateKind,
    MlsCreatorBootstrapTransition,
};
use serde_json::{Value, json};

use super::{load_artifact_json, load_fixture_value, value_array, value_field_str};
use crate::transcripts::record_vector_event;

const FIXTURE: &str = "mls-creator-bootstrap-recovery-fixture.json";
const REGISTRY: &str = "registry/mls-creator-bootstrap-transaction-registry.json";
const ENTRYPOINT: &str = "ak.suite.mls.creator_bootstrap_recovery.v1";
const VECTOR_ID: &str = "ak.vector.mls.creator_bootstrap_recovery.v1";

/// The record does not exist yet. The registry spells this as a `null`
/// `from_state`; the fixture spells it `absent`.
const ABSENT: &str = "absent";

const GLOBAL_ASSERTIONS: [&str; 6] = [
    "deleting every current and UI projection before the recoverer runs does not change any outcome",
    "no run amends the closed creation intent at or after realm_accepted, and no run opens a second record for the same logical key when the selector changes at genesis_intent_persisted",
    "no run reaches write-ready from an HTTP success, a duplicate code, a queue item, an emitted flag or a page projection",
    "no run writes this record or any of its fields onto a Realm Event, a current projection, an Account Data key, a sync surface or a federation surface",
    "the accepted Genesis bytes are byte-identical to the bytes frozen in the outbound queue item",
    "the server ends every positive run with exactly one accepted ak.mls.genesis for the effective scope",
];

/// Scenario outcomes that are not the label of any arrow's crash recovery.
///
/// Each is here for a stated reason, so the set cannot quietly absorb a
/// recovery behaviour the state machine does not produce:
/// * a partial public-blob upload is repaired inside the arrow that persisted those bytes, so it
///   names no new arrow;
/// * losing the local confirmation after acceptance is the one case where the server is ahead of
///   the record, and the recoverer resolves the accepted Event before committing
///   `genesis_accepted`;
/// * amending the intent at or after `realm_accepted` is not a transition at all — the registry has
///   no arrow for it, and fail-closed is the absence of one.
const NON_ARROW_SCENARIO_OUTCOMES: [&str; 3] = [
    "fail_closed",
    "reupload_the_missing_blob_from_the_persisted_bytes",
    "resolve_the_accepted_event_and_commit_genesis_accepted",
];

pub fn run_mls_creator_bootstrap_recovery_suite() -> Result<()> {
    let fixture = load_fixture_value(FIXTURE)?;
    validate_identity(&fixture)?;
    let registry = load_artifact_json(REGISTRY)?;
    let arrows = registry_arrows(&registry)?;
    check_registry_matches_sdk(&registry, &arrows)?;

    let recovery_actions = run_crash_cases(&fixture, &arrows)?;
    run_scenario_cases(&fixture, &recovery_actions)?;

    record_vector_event(
        "mls.creator_bootstrap_recovery.named_suite",
        &json!({"entrypoint": ENTRYPOINT, "vector_id": VECTOR_ID}),
        &json!({"arrows": arrows.len(), "recovery_actions": recovery_actions.len()}),
        &json!({"executor": "run_crash_cases + run_scenario_cases"}),
    );
    Ok(())
}

fn validate_identity(fixture: &Value) -> Result<()> {
    ensure!(
        value_field_str(fixture, "suite")? == "mls_creator_bootstrap_recovery"
            && value_field_str(fixture, "fixture_kind")? == "semantic"
            && value_field_str(&fixture["runner"], "kind")? == "named_suite"
            && value_field_str(&fixture["runner"], "entrypoint")? == ENTRYPOINT
            && value_field_str(fixture, "registry_under_test")?
                == format!("spec/v1/artifacts/{REGISTRY}"),
        "MLS creator bootstrap fixture identity drifted"
    );
    let covers = value_array(&fixture["covers_vectors"], "covers_vectors")?;
    ensure!(
        covers.as_slice() == [Value::String(VECTOR_ID.to_owned())],
        "the creator bootstrap fixture must cover exactly {VECTOR_ID}"
    );
    let published = value_array(&fixture["global_assertions"], "global_assertions")?
        .iter()
        .map(|value| value.as_str().context("global assertion must be a string"))
        .collect::<Result<BTreeSet<_>>>()?;
    let expected = GLOBAL_ASSERTIONS.iter().copied().collect::<BTreeSet<_>>();
    if published != expected {
        let missing: Vec<_> = expected.difference(&published).copied().collect();
        let extra: Vec<_> = published.difference(&expected).copied().collect();
        bail!(
            "creator bootstrap global assertions drifted: missing {missing:?}, unregistered {extra:?}"
        );
    }
    Ok(())
}

/// `transition_id -> (from_state, to_state)` as the registry publishes it.
/// `from_state` is `None` for the one arrow that creates the record.
fn registry_arrows(registry: &Value) -> Result<BTreeMap<String, (Option<String>, String)>> {
    let mut arrows = BTreeMap::new();
    for transition in value_array(&registry["transitions"], "registry transitions")? {
        let id = value_field_str(transition, "transition_id")?.to_owned();
        let from = match &transition["from_state"] {
            Value::Null => None,
            Value::String(value) => Some(value.clone()),
            _ => bail!("registry transition {id} has a malformed from_state"),
        };
        let to = value_field_str(transition, "to_state")?.to_owned();
        ensure!(
            !value_field_str(transition, "commit_boundary")?.is_empty(),
            "registry transition {id} publishes no commit boundary"
        );
        ensure!(
            arrows.insert(id.clone(), (from, to)).is_none(),
            "registry publishes the arrow {id} twice"
        );
    }
    Ok(arrows)
}

/// The registry is the source of truth and the SDK tables are generated from
/// it, so any disagreement means a downstream client is compiling a stale
/// machine. Checking it here is cheap and catches exactly that.
fn check_registry_matches_sdk(
    registry: &Value,
    arrows: &BTreeMap<String, (Option<String>, String)>,
) -> Result<()> {
    let registry_states = value_array(&registry["states"], "registry states")?
        .iter()
        .map(|state| value_field_str(state, "state_id").map(str::to_owned))
        .collect::<Result<Vec<_>>>()?;
    let sdk_states: Vec<String> = MlsCreatorBootstrapState::ALL
        .iter()
        .map(|state| state.as_str().to_owned())
        .collect();
    ensure!(
        registry_states == sdk_states,
        "registry states and the generated SDK table diverged: {registry_states:?} vs {sdk_states:?}"
    );

    for state in value_array(&registry["states"], "registry states")? {
        let state_id = value_field_str(state, "state_id")?;
        let typed = MlsCreatorBootstrapState::from_wire(state_id)
            .with_context(|| format!("state {state_id} is not a generated SDK state"))?;
        let kind = value_field_str(state, "kind")?;
        ensure!(
            MlsCreatorBootstrapStateKind::from_wire(kind) == Some(typed.kind()),
            "state {state_id} kind {kind} disagrees with the generated table"
        );
        let exits = value_array(&state["allowed_exits"], "allowed exits")?
            .iter()
            .map(|value| value.as_str().context("allowed exit must be a string"))
            .collect::<Result<Vec<_>>>()?;
        let sdk_exits: Vec<&str> = typed
            .allowed_exits()
            .iter()
            .map(|exit| exit.as_str())
            .collect();
        ensure!(
            exits == sdk_exits,
            "state {state_id} exits {exits:?} disagree with the generated {sdk_exits:?}"
        );
        // `rejected` terminates the attempt, not the logical record: a new
        // attempt generation resumes under the same key, so it keeps exits.
        // Only the two states that end the record for good have none, and a
        // progress state that lost its exits would strand every recoverer.
        let ends_the_record = matches!(
            typed.kind(),
            MlsCreatorBootstrapStateKind::TerminalSuccess
                | MlsCreatorBootstrapStateKind::TerminalFailure
        );
        ensure!(
            exits.is_empty() == ends_the_record,
            "state {state_id} is {kind} but publishes {} exits",
            exits.len()
        );
    }

    let sdk_arrows: BTreeMap<String, (Option<String>, String)> = MLS_CREATOR_BOOTSTRAP_TRANSITIONS
        .iter()
        .map(|descriptor| {
            (
                descriptor.transition.as_str().to_owned(),
                (
                    descriptor.from_state.map(|state| state.as_str().to_owned()),
                    descriptor.to_state.as_str().to_owned(),
                ),
            )
        })
        .collect();
    ensure!(
        arrows == &sdk_arrows,
        "registry arrows and the generated SDK table diverged"
    );
    ensure!(
        MlsCreatorBootstrapTransition::ALL.len() == arrows.len(),
        "the generated transition table lost an arrow"
    );
    Ok(())
}

/// Replay every crash injection and derive the state a recoverer would find.
///
/// Returns the closed set of recovery actions the arrows produce, which is what
/// the scenario cases are then held to.
fn run_crash_cases(
    fixture: &Value,
    arrows: &BTreeMap<String, (Option<String>, String)>,
) -> Result<BTreeSet<String>> {
    let cases = value_array(&fixture["crash_cases"], "crash cases")?;
    ensure!(
        cases.len() == arrows.len() * 2,
        "every registered arrow needs a pre-commit and a post-commit crash case: {} arrows, {} cases",
        arrows.len(),
        cases.len()
    );
    let mut covered: BTreeSet<(String, String)> = BTreeSet::new();
    let mut recovery_actions = BTreeSet::new();
    for case in cases {
        let name = value_field_str(case, "name")?;
        let transition = value_field_str(case, "transition")?;
        let injection = value_field_str(case, "injection")?;
        let (from, to) = arrows
            .get(transition)
            .with_context(|| format!("crash case {name} names unregistered arrow {transition}"))?;
        // A commit boundary is atomic: the recoverer either finds the arrow's
        // origin or its destination, never anything between them.
        let derived = match injection {
            "pre_commit" => from.clone().unwrap_or_else(|| ABSENT.to_owned()),
            "post_commit" => to.clone(),
            other => bail!("crash case {name} declares unknown injection {other}"),
        };
        let declared = value_field_str(case, "expected_state")?;
        ensure!(
            derived == declared,
            "crash case {name} declares state {declared} but {transition}/{injection} lands in {derived}"
        );
        if derived != ABSENT {
            let typed = MlsCreatorBootstrapState::from_wire(&derived)
                .with_context(|| format!("crash case {name} landed in unknown state {derived}"))?;
            // The recoverer executes one arrow, so unless the run is already
            // finished there has to be exactly one way forward to execute.
            ensure!(
                !typed.allowed_exits().is_empty()
                    || matches!(
                        typed.kind(),
                        MlsCreatorBootstrapStateKind::TerminalSuccess
                            | MlsCreatorBootstrapStateKind::TerminalFailure
                    ),
                "crash case {name} strands the recoverer in {derived}"
            );
        }
        let invariants = value_array(&case["invariants"], "crash case invariants")?;
        ensure!(
            !invariants.is_empty(),
            "crash case {name} publishes no invariant to check"
        );
        ensure!(
            covered.insert((transition.to_owned(), injection.to_owned())),
            "crash case {name} duplicates {transition}/{injection}"
        );
        recovery_actions.insert(value_field_str(case, "expected")?.to_owned());
    }
    for arrow in arrows.keys() {
        for injection in ["pre_commit", "post_commit"] {
            ensure!(
                covered.contains(&(arrow.clone(), injection.to_owned())),
                "arrow {arrow} publishes no {injection} crash case"
            );
        }
    }
    Ok(recovery_actions)
}

fn run_scenario_cases(fixture: &Value, recovery_actions: &BTreeSet<String>) -> Result<()> {
    let cases = value_array(&fixture["scenario_cases"], "scenario cases")?;
    ensure!(
        cases.len() >= 10,
        "the creator bootstrap suite must keep its scenario coverage"
    );
    let mut names = BTreeSet::new();
    for case in cases {
        let name = value_field_str(case, "name")?;
        ensure!(
            names.insert(name.to_owned()),
            "scenario case {name} is published twice"
        );
        ensure!(
            !value_field_str(case, "given")?.is_empty()
                && !value_field_str(case, "action")?.is_empty(),
            "scenario case {name} must state its precondition and its action"
        );
        ensure!(
            !value_array(&case["invariants"], "scenario invariants")?.is_empty(),
            "scenario case {name} publishes no invariant to check"
        );
        let expected = value_field_str(case, "expected")?;
        // A scenario may only end where an arrow can end: in a recovery action
        // some arrow produces, in a registered state, or in one of the three
        // outcomes that are deliberately not arrows.
        let reaches_registered_state = MlsCreatorBootstrapState::ALL.iter().any(|state| {
            expected == state.as_str() || expected.starts_with(&format!("{}_", state.as_str()))
        });
        ensure!(
            recovery_actions.contains(expected)
                || reaches_registered_state
                || NON_ARROW_SCENARIO_OUTCOMES.contains(&expected),
            "scenario case {name} expects {expected}, which is neither an arrow's recovery action nor a registered state"
        );
        record_vector_event(
            &format!("mls.creator_bootstrap_recovery.{name}"),
            case,
            &json!({"expected": expected}),
            &json!({"derived_from_arrows": recovery_actions.contains(expected)}),
        );
    }
    // The three outcomes that are not arrows all have to be exercised, or the
    // allowance above would be dead weight that could hide a real gap.
    for outcome in NON_ARROW_SCENARIO_OUTCOMES {
        ensure!(
            cases
                .iter()
                .any(|case| case["expected"].as_str() == Some(outcome)),
            "the non-arrow outcome {outcome} is registered but never exercised"
        );
    }
    Ok(())
}
