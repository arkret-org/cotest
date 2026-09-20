//! Executable push-rule core fixture runner.
//!
//! The fixture is consumed through the production shared watch-level evaluator.
//! Visible notifications and blind wakeups are recorded only after an allow
//! decision; filtered cases prove that neither delivery sink changes.

use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use arkret_models_integration::PushRule;
use arkret_push_policy::push_rule_core::{
    EventContext, ShouldNotify, WatchLevel, evaluate_watch_level,
};
use arkret_wire::ProfileId;
use serde::Deserialize;
use serde_json::json;

pub const PUSH_RULE_CORE_ENTRYPOINT: &str = "ak.suite.push.rule_core.v1";
pub const FIXTURE: &str = "push-rule-core-fixture.json";

const VECTOR_IDS: &[&str] = &[
    "ak.vector.push.broadcast_mention_controls.v1",
    "ak.vector.push.strand_engaged_mention.v1",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    version: String,
    runner: Runner,
    suite: String,
    profile: String,
    description: String,
    covers_vectors: Vec<String>,
    cases: Vec<VectorCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Runner {
    kind: String,
    entrypoint: String,
}

#[derive(Debug, Deserialize)]
struct VectorCase {
    name: String,
    #[serde(default)]
    vector_id: Option<String>,
    #[serde(default)]
    assertions: Vec<String>,
    watch_level: String,
    #[serde(default)]
    event: EventVector,
    #[serde(default)]
    client_projection: ClientProjectionInput,
    expected: ExpectedVector,
}

#[derive(Debug, Default, Deserialize)]
struct EventVector {
    #[serde(default)]
    mentions_actor: bool,
    #[serde(default)]
    assigned_to_actor: bool,
    #[serde(default)]
    reply_to_self: bool,
    #[serde(default)]
    participating_thread_update: bool,
    #[serde(default)]
    is_e2ee: bool,
    #[serde(default)]
    local_decrypted: bool,
}

#[derive(Debug, Deserialize)]
struct ClientProjectionInput {
    #[serde(default = "default_mentions_actor_known")]
    mentions_actor_known: bool,
    #[serde(default)]
    client_side_mentions_rule: bool,
}

impl Default for ClientProjectionInput {
    fn default() -> Self {
        Self {
            mentions_actor_known: true,
            client_side_mentions_rule: false,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ExpectedVector {
    deliver: bool,
    blind_wakeup: bool,
    reason_code: String,
    client_projection: ExpectedClientProjection,
}

#[derive(Debug, Deserialize)]
struct ExpectedClientProjection {
    should_notify: bool,
    watch_suppressed: bool,
    muted_short_circuit: bool,
    blind_wakeup_required: bool,
    unresolved_client_evaluation: bool,
}

fn default_mentions_actor_known() -> bool {
    true
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct DeliveryState {
    visible_notifications: Vec<String>,
    blind_wakeups: Vec<String>,
    admitted_client_rules: Vec<String>,
}

struct PushConsumer {
    state: DeliveryState,
}

impl PushConsumer {
    fn new() -> Self {
        Self {
            state: DeliveryState::default(),
        }
    }

    fn admit_rule_carrier(&mut self) -> Result<()> {
        let client: PushRule = serde_json::from_value(json!({
            "rule_id": "ak.rule.cotest.client-only",
            "kind": "underride",
            "evaluation_locus": "client",
            "actions": []
        }))?;
        ensure!(client.evaluation_locus == "client");
        self.state
            .admitted_client_rules
            .push(client.rule_id.to_string());
        let accepted = self.state.clone();

        let server = serde_json::from_value::<PushRule>(json!({
            "rule_id": "ak.rule.cotest.server",
            "kind": "underride",
            "evaluation_locus": "server",
            "actions": []
        }));
        ensure!(
            server.is_err(),
            "PushRule accepted server evaluation authority"
        );
        ensure!(
            self.state == accepted,
            "rejected PushRule changed consumer state"
        );
        Ok(())
    }

    fn evaluate(&mut self, case: &VectorCase) -> Result<CaseExecutionResult> {
        let before = self.state.clone();
        let level = WatchLevel::from_wire(&case.watch_level)
            .with_context(|| format!("invalid watch_level {}", case.watch_level))?;
        let context = EventContext {
            mentions_actor: case.event.mentions_actor,
            assigned_to_actor: case.event.assigned_to_actor,
            reply_to_self: case.event.reply_to_self,
            participating_thread_update: case.event.participating_thread_update,
            is_e2ee: case.event.is_e2ee,
            local_decrypted: case.event.local_decrypted,
        };
        let (decision, reason_code) = evaluate_watch_level(level, &context);
        let expected = &case.expected;

        ensure!(
            decision.delivers() == expected.deliver,
            "deliver decision drifted"
        );
        ensure!(
            matches!(decision, ShouldNotify::BlindWakeup) == expected.blind_wakeup,
            "blind-wakeup decision drifted"
        );
        ensure!(reason_code == expected.reason_code, "reason code drifted");
        ensure!(
            decision.visible() == expected.client_projection.should_notify,
            "visible client projection drifted"
        );
        ensure!(
            matches!(decision, ShouldNotify::DontNotify)
                == expected.client_projection.watch_suppressed,
            "watch-suppressed projection drifted"
        );
        ensure!(
            (level == WatchLevel::Muted) == expected.client_projection.muted_short_circuit,
            "muted short-circuit projection drifted"
        );
        ensure!(
            matches!(decision, ShouldNotify::BlindWakeup)
                == expected.client_projection.blind_wakeup_required,
            "blind-wakeup-required projection drifted"
        );
        let unresolved = matches!(decision, ShouldNotify::BlindWakeup)
            && (!case.client_projection.mentions_actor_known
                || case.client_projection.client_side_mentions_rule);
        ensure!(
            unresolved == expected.client_projection.unresolved_client_evaluation,
            "unresolved client projection drifted"
        );

        match decision {
            ShouldNotify::Notify => self.state.visible_notifications.push(case.name.clone()),
            ShouldNotify::BlindWakeup => self.state.blind_wakeups.push(case.name.clone()),
            ShouldNotify::DontNotify => {}
        }
        let delivery_effects = self.state.visible_notifications.len()
            + self.state.blind_wakeups.len()
            - before.visible_notifications.len()
            - before.blind_wakeups.len();
        ensure!(delivery_effects == usize::from(expected.deliver));
        let rejected_state_unchanged = expected.deliver || self.state == before;
        ensure!(
            rejected_state_unchanged,
            "filtered event changed delivery state"
        );

        Ok(CaseExecutionResult {
            case_id: case.name.clone(),
            assertions: 10,
            delivery_effects,
            decision: match decision {
                ShouldNotify::Notify => "notify",
                ShouldNotify::DontNotify => "dont_notify",
                ShouldNotify::BlindWakeup => "blind_wakeup",
            },
            rejected_state_unchanged,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseExecutionResult {
    pub case_id: String,
    pub assertions: usize,
    pub delivery_effects: usize,
    pub decision: &'static str,
    pub rejected_state_unchanged: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PushRuleCoreExecution {
    pub entrypoint: &'static str,
    pub fixture: &'static str,
    pub cases: Vec<CaseExecutionResult>,
    pub visible_notifications: usize,
    pub blind_wakeups: usize,
    pub admitted_client_rules: usize,
}

fn spec_artifacts_root() -> PathBuf {
    if let Some(root) = std::env::var_os("COTEST_SPEC_ARTIFACTS_ROOT") {
        return PathBuf::from(root);
    }
    if let Some(root) = std::env::var_os("COTEST_SPEC_ROOT") {
        let root = PathBuf::from(root);
        for candidate in [root.clone(), root.join("spec").join("v1").join("artifacts")] {
            if candidate.join("fixtures").is_dir() {
                return candidate;
            }
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("arkret-spec")
        .join("spec")
        .join("v1")
        .join("artifacts")
}

fn load_fixture() -> Result<Fixture> {
    let path = spec_artifacts_root().join("fixtures").join(FIXTURE);
    serde_json::from_slice(&std::fs::read(&path)?)
        .with_context(|| format!("parse fixture {}", path.display()))
}

pub fn run_push_rule_core_suite() -> Result<PushRuleCoreExecution> {
    let fixture = load_fixture()?;
    ensure!(fixture.runner.kind == "named_suite");
    ensure!(fixture.runner.entrypoint == PUSH_RULE_CORE_ENTRYPOINT);
    ensure!(fixture.suite == "push_rule_core_consistency");
    ensure!(fixture.profile == ProfileId::PUSH_GATEWAY_BLIND_WAKEUP_V1);
    ensure!(!fixture.version.trim().is_empty());
    ensure!(!fixture.description.trim().is_empty());
    for vector_id in VECTOR_IDS {
        ensure!(
            fixture
                .covers_vectors
                .iter()
                .any(|value| value == vector_id)
        );
        ensure!(fixture.cases.iter().any(|case| {
            case.vector_id.as_deref() == Some(*vector_id) && !case.assertions.is_empty()
        }));
    }

    let mut consumer = PushConsumer::new();
    consumer.admit_rule_carrier()?;
    let mut results = Vec::with_capacity(fixture.cases.len());
    for case in &fixture.cases {
        results.push(consumer.evaluate(case)?);
    }
    ensure!(results.len() == fixture.cases.len());
    for (case, result) in fixture.cases.iter().zip(&results) {
        ensure!(case.name == result.case_id);
        ensure!(result.assertions > 0);
        ensure!(result.rejected_state_unchanged);
    }
    ensure!(consumer.state.visible_notifications.len() == 5);
    ensure!(consumer.state.blind_wakeups.len() == 3);
    ensure!(consumer.state.admitted_client_rules.len() == 1);

    Ok(PushRuleCoreExecution {
        entrypoint: PUSH_RULE_CORE_ENTRYPOINT,
        fixture: FIXTURE,
        cases: results,
        visible_notifications: consumer.state.visible_notifications.len(),
        blind_wakeups: consumer.state.blind_wakeups.len(),
        admitted_client_rules: consumer.state.admitted_client_rules.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_thirteen_cases_execute_the_production_core() -> Result<()> {
        let execution = run_push_rule_core_suite()?;
        assert_eq!(execution.cases.len(), 13);
        assert_eq!(execution.visible_notifications, 5);
        assert_eq!(execution.blind_wakeups, 3);
        assert_eq!(execution.admitted_client_rules, 1);
        assert_eq!(
            execution
                .cases
                .iter()
                .filter(|case| case.delivery_effects == 0)
                .count(),
            5
        );
        Ok(())
    }

    #[test]
    fn filtered_cases_never_mutate_delivery_sinks() -> Result<()> {
        let execution = run_push_rule_core_suite()?;
        assert!(
            execution
                .cases
                .iter()
                .filter(|case| case.decision == "dont_notify")
                .all(|case| case.delivery_effects == 0 && case.rejected_state_unchanged)
        );
        Ok(())
    }
}
