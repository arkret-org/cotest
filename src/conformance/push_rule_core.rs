use anyhow::{Context, Result, anyhow, bail};
use cokret::push_rule_core::{self, EventContext, ShouldNotify, WatchLevel};
use serde::Deserialize;
use serde_json::Value;

const PUSH_RULE_CORE_FIXTURE_FILE: &str = "push-rule-core-fixture.json";
const PUSH_RULE_CORE_PROFILE: &str = "ck.profile.push_gateway.blind_wakeup.v1";
const PUSH_RULE_CORE_VECTOR_IDS: &[&str] = &[
    "ck.vector.push.broadcast_mention_controls.v1",
    "ck.vector.push.strand_engaged_mention.v1",
];

#[derive(Debug, Deserialize)]
struct Fixture {
    suite: String,
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
    super::validate_profile(&fixture_value, PUSH_RULE_CORE_PROFILE)?;
    validate_push_rule_core_fixture_metadata(&fixture_value)?;
    let fixture: Fixture = super::parse_fixture_value(PUSH_RULE_CORE_FIXTURE_FILE, fixture_value)?;
    if fixture.suite != "push_rule_core_consistency" {
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

    Ok(())
}

fn validate_push_rule_core_fixture_metadata(fixture: &Value) -> Result<()> {
    let covers = fixture
        .get("covers_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("push rule fixture missing covers_vectors[]"))?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("push rule fixture missing cases[]"))?;
    for vector_id in PUSH_RULE_CORE_VECTOR_IDS {
        if !covers
            .iter()
            .any(|entry| entry.as_str() == Some(*vector_id))
        {
            bail!("push rule fixture missing covers_vectors entry {vector_id}");
        }
        if !cases.iter().any(|case| {
            case.get("vector_id").and_then(Value::as_str) == Some(*vector_id)
                && case
                    .get("assertions")
                    .and_then(Value::as_array)
                    .is_some_and(|assertions| !assertions.is_empty())
        }) {
            bail!("push rule fixture missing asserted case {vector_id}");
        }
    }
    Ok(())
}

fn assert_shared_core(case: &VectorCase) -> Result<()> {
    let level = parse_watch_level(&case.watch_level)?;
    let ctx = EventContext {
        mentions_actor: case.event.mentions_actor,
        assigned_to_actor: case.event.assigned_to_actor,
        reply_to_self: case.event.reply_to_self,
        participating_thread_update: case.event.participating_thread_update,
        is_e2ee: case.event.is_e2ee,
        local_decrypted: case.event.local_decrypted,
    };
    let (decision, reason_code) = push_rule_core::evaluate_watch_level(level, &ctx);

    if decision.delivers() != case.expected.deliver {
        bail!(
            "deliver mismatch: expected {}, got {}",
            case.expected.deliver,
            decision.delivers()
        );
    }
    let blind_wakeup = matches!(decision, ShouldNotify::BlindWakeup);
    if blind_wakeup != case.expected.blind_wakeup {
        bail!(
            "blind_wakeup mismatch: expected {}, got {}",
            case.expected.blind_wakeup,
            blind_wakeup
        );
    }
    if reason_code != case.expected.reason_code {
        bail!(
            "reason_code mismatch: expected {}, got {}",
            case.expected.reason_code,
            reason_code
        );
    }
    let projection = &case.expected.client_projection;
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
