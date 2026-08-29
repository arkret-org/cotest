use anyhow::{Context, Result, anyhow, bail};
use arkret::push_rule_core::{self, EventContext, ShouldNotify, WatchLevel};
use arkret_models_integration::PushRule;
use arkret_wire::ProfileId;
use serde::Deserialize;
use serde_json::Value;

const PUSH_RULE_CORE_FIXTURE_FILE: &str = "push-rule-core-fixture.json";
const PUSH_RULE_CORE_VECTOR_IDS: &[&str] = &[
    "ak.vector.push.broadcast_mention_controls.v1",
    "ak.vector.push.strand_engaged_mention.v1",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    runner: Value,
    suite: String,
    profile: String,
    description: String,
    #[serde(default)]
    covers_vectors: Vec<String>,
    cases: Vec<VectorCase>,
}

#[derive(Debug, Deserialize)]
struct VectorCase {
    name: String,
    #[serde(default)]
    vector_id: Option<String>,
    #[serde(default)]
    assertions: Vec<String>,
    #[serde(default)]
    watch_level: Option<String>,
    #[serde(default)]
    event: EventVector,
    #[serde(default)]
    client_projection: ClientProjectionInput,
    #[serde(default)]
    expected: Option<ExpectedVector>,
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

#[derive(Debug, Default, Deserialize)]
struct ClientProjectionInput {
    #[serde(default = "default_mentions_actor_known")]
    mentions_actor_known: bool,
    #[serde(default)]
    client_side_mentions_rule: bool,
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

pub fn run_push_rule_core_fixture_suite() -> Result<()> {
    let fixture_value = super::load_fixture_value(PUSH_RULE_CORE_FIXTURE_FILE)?;
    let fixture: Fixture = super::parse_fixture_value(PUSH_RULE_CORE_FIXTURE_FILE, fixture_value)?;
    if fixture.suite != "push_rule_core_consistency"
        || fixture.profile != ProfileId::PUSH_GATEWAY_BLIND_WAKEUP_V1
        || fixture.description.trim().is_empty()
        || fixture.runner.is_null()
    {
        bail!(
            "unexpected push rule fixture suite {}, expected push_rule_core_consistency",
            fixture.suite
        );
    }
    for vector_id in PUSH_RULE_CORE_VECTOR_IDS {
        if !fixture
            .covers_vectors
            .iter()
            .any(|entry| entry == vector_id)
        {
            bail!("push rule fixture missing covers_vectors entry {vector_id}");
        }
        if !fixture.cases.iter().any(|case| {
            case.vector_id.as_deref() == Some(*vector_id) && !case.assertions.is_empty()
        }) {
            bail!("push rule fixture missing asserted case {vector_id}");
        }
    }

    for case in &fixture.cases {
        assert_shared_core(case).with_context(|| format!("shared core vector {}", case.name))?;
    }
    run_push_rule_client_only_vector()?;

    Ok(())
}

/// v1 push rules are evaluated by the client.  Decode through the SDK wire
/// type so cotest cannot accidentally grow a second, more permissive parser.
pub fn run_push_rule_client_only_vector() -> Result<()> {
    let client: PushRule = serde_json::from_value(serde_json::json!({
        "rule_id": "ak.rule.cotest.client-only",
        "kind": "underride",
        "evaluation_locus": "client",
        "actions": []
    }))?;
    if client.evaluation_locus != "client" {
        bail!("v1 push rule did not preserve evaluation_locus=client");
    }

    let server = serde_json::from_value::<PushRule>(serde_json::json!({
        "rule_id": "ak.rule.cotest.server",
        "kind": "underride",
        "evaluation_locus": "server",
        "actions": []
    }));
    if server.is_ok() {
        bail!("v1 push rule accepted forbidden evaluation_locus=server");
    }
    Ok(())
}

fn assert_shared_core(case: &VectorCase) -> Result<()> {
    let watch_level = case
        .watch_level
        .as_deref()
        .ok_or_else(|| anyhow!("shared core vector missing watch_level"))?;
    let level = parse_watch_level(watch_level)?;
    let ctx = EventContext {
        mentions_actor: case.event.mentions_actor,
        assigned_to_actor: case.event.assigned_to_actor,
        reply_to_self: case.event.reply_to_self,
        participating_thread_update: case.event.participating_thread_update,
        is_e2ee: case.event.is_e2ee,
        local_decrypted: case.event.local_decrypted,
    };
    let (decision, reason_code) = push_rule_core::evaluate_watch_level(level, &ctx);

    let expected = case
        .expected
        .as_ref()
        .ok_or_else(|| anyhow!("shared core vector missing expected"))?;
    if decision.delivers() != expected.deliver {
        bail!(
            "deliver mismatch: expected {}, got {}",
            expected.deliver,
            decision.delivers()
        );
    }
    let blind_wakeup = matches!(decision, ShouldNotify::BlindWakeup);
    if blind_wakeup != expected.blind_wakeup {
        bail!(
            "blind_wakeup mismatch: expected {}, got {}",
            expected.blind_wakeup,
            blind_wakeup
        );
    }
    if reason_code != expected.reason_code {
        bail!(
            "reason_code mismatch: expected {}, got {}",
            expected.reason_code,
            reason_code
        );
    }
    let projection = &expected.client_projection;
    if decision.visible() != projection.should_notify {
        bail!(
            "client_projection.should_notify mismatch: expected {}, got {}",
            projection.should_notify,
            decision.visible()
        );
    }
    if blind_wakeup != projection.blind_wakeup_required {
        bail!(
            "client_projection.blind_wakeup_required mismatch: expected {}, got {}",
            projection.blind_wakeup_required,
            blind_wakeup
        );
    }
    let watch_suppressed = matches!(decision, ShouldNotify::DontNotify);
    if watch_suppressed != projection.watch_suppressed {
        bail!(
            "client_projection.watch_suppressed mismatch: expected {}, got {}",
            projection.watch_suppressed,
            watch_suppressed
        );
    }
    let muted_short_circuit = level == WatchLevel::Muted;
    if muted_short_circuit != projection.muted_short_circuit {
        bail!(
            "client_projection.muted_short_circuit mismatch: expected {}, got {}",
            projection.muted_short_circuit,
            muted_short_circuit
        );
    }
    let unresolved_client_evaluation = blind_wakeup
        && (!case.client_projection.mentions_actor_known
            || case.client_projection.client_side_mentions_rule);
    if unresolved_client_evaluation != projection.unresolved_client_evaluation {
        bail!(
            "client_projection.unresolved_client_evaluation mismatch: expected {}, got {}",
            projection.unresolved_client_evaluation,
            unresolved_client_evaluation
        );
    }
    Ok(())
}

fn parse_watch_level(value: &str) -> Result<WatchLevel> {
    WatchLevel::from_wire(value).ok_or_else(|| anyhow!("invalid watch_level {value}"))
}
