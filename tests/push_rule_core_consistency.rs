use anyhow::{Context, Result, anyhow, bail};
use cokret::push_rule_core::{self, EventContext, ShouldNotify, WatchLevel};
use serde::Deserialize;

const FIXTURE: &str = include_str!("fixtures/push_rule_core_vectors.json");

#[derive(Debug, Deserialize)]
struct Fixture {
    suite: String,
    cases: Vec<VectorCase>,
}

#[derive(Debug, Deserialize)]
struct VectorCase {
    name: String,
    watch_level: String,
    #[serde(default)]
    event: EventVector,
    #[serde(default, rename = "yougen")]
    _yougen: YougenOverrides,
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

#[allow(dead_code)]
#[derive(Debug, Default, Deserialize)]
struct YougenOverrides {
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
    #[serde(default, rename = "yougen")]
    _yougen: Option<ExpectedYougen>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ExpectedYougen {
    should_notify: bool,
    watch_suppressed: bool,
    muted_short_circuit: bool,
    blind_wakeup_required: bool,
    unresolved_client_evaluation: bool,
}

fn default_mentions_actor_known() -> bool {
    true
}

#[test]
fn push_rule_core_consistency_vectors_match_all_implementations() -> Result<()> {
    let fixture: Fixture = serde_json::from_str(FIXTURE).context("parse push rule fixture")?;
    if fixture.suite != "push_rule_core_consistency" {
        bail!(
            "unexpected push rule fixture suite {}, expected push_rule_core_consistency",
            fixture.suite
        );
    }

    for case in &fixture.cases {
        assert_shared_core(case).with_context(|| format!("shared core vector {}", case.name))?;
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
    Ok(())
}

fn parse_watch_level(value: &str) -> Result<WatchLevel> {
    WatchLevel::from_wire(value).ok_or_else(|| anyhow!("invalid watch_level {value}"))
}
