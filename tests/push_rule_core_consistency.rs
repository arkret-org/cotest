#![allow(dead_code)]

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;

#[path = "../../chime/src/push_rule_core.rs"]
mod chime_push_rule_core;
#[path = "../../soland/src/push_rule_core.rs"]
mod soland_push_rule_core;
#[path = "../../yougen/src/notification_rules.rs"]
mod yougen_notification_rules;

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
    #[serde(default)]
    yougen: YougenOverrides,
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
    yougen: ExpectedYougen,
}

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
        assert_soland(case).with_context(|| format!("soland vector {}", case.name))?;
        assert_chime(case).with_context(|| format!("chime vector {}", case.name))?;
        assert_yougen(case).with_context(|| format!("yougen vector {}", case.name))?;
    }

    Ok(())
}

fn assert_soland(case: &VectorCase) -> Result<()> {
    let level = parse_soland_watch_level(&case.watch_level)?;
    let ctx = soland_push_rule_core::EventContext {
        mentions_actor: case.event.mentions_actor,
        assigned_to_actor: case.event.assigned_to_actor,
        reply_to_self: case.event.reply_to_self,
        participating_thread_update: case.event.participating_thread_update,
        is_e2ee: case.event.is_e2ee,
        local_decrypted: case.event.local_decrypted,
    };
    let decision = soland_push_rule_core::evaluate_push_rule(level, &ctx);

    if decision.deliver != case.expected.deliver {
        bail!(
            "deliver mismatch: expected {}, got {}",
            case.expected.deliver,
            decision.deliver
        );
    }
    if decision.blind_wakeup != case.expected.blind_wakeup {
        bail!(
            "blind_wakeup mismatch: expected {}, got {}",
            case.expected.blind_wakeup,
            decision.blind_wakeup
        );
    }
    if decision.reason_code != case.expected.reason_code {
        bail!(
            "reason_code mismatch: expected {}, got {}",
            case.expected.reason_code,
            decision.reason_code
        );
    }
    Ok(())
}

fn assert_chime(case: &VectorCase) -> Result<()> {
    let level = parse_chime_watch_level(&case.watch_level)?;
    let ctx = chime_push_rule_core::EventContext {
        mentions_actor: case.event.mentions_actor,
        assigned_to_actor: case.event.assigned_to_actor,
        reply_to_self: case.event.reply_to_self,
        participating_thread_update: case.event.participating_thread_update,
        is_e2ee: case.event.is_e2ee,
        local_decrypted: case.event.local_decrypted,
    };
    let (decision, reason_code) = chime_push_rule_core::evaluate_watch_level(level, &ctx);
    let expected_decision =
        expected_chime_decision(case.expected.deliver, case.expected.blind_wakeup);

    if decision != expected_decision {
        bail!(
            "decision mismatch: expected {:?}, got {:?}",
            expected_decision,
            decision
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

fn assert_yougen(case: &VectorCase) -> Result<()> {
    let level = parse_yougen_watch_level(&case.watch_level)?;
    let ctx = yougen_notification_rules::NotificationEvalContext {
        event_kind: "cx.message.create".to_owned(),
        notification_type: "message".to_owned(),
        space_id: "cx:space:t4_4".to_owned(),
        flow_id: Some("cx:flow:t4_4".to_owned()),
        flow_track: Some("discussion".to_owned()),
        is_e2ee: case.event.is_e2ee,
        local_decrypted: case.event.local_decrypted,
        mentions_actor: if case.yougen.mentions_actor_known {
            Some(case.event.mentions_actor)
        } else {
            None
        },
        assigned_to_actor: case.event.assigned_to_actor,
        reply_to_self: case.event.reply_to_self,
        participating_thread_update: case.event.participating_thread_update,
        watch_level: Some(level),
        ..Default::default()
    };
    let rules = case
        .yougen
        .client_side_mentions_rule
        .then(client_side_mentions_rule);
    let decision = yougen_notification_rules::evaluate_notification(rules.as_ref(), None, &ctx);
    let projected_reason = projected_yougen_reason_code(level, &decision);

    if projected_reason != case.expected.reason_code {
        bail!(
            "projected reason_code mismatch: expected {}, got {}",
            case.expected.reason_code,
            projected_reason
        );
    }
    if decision.should_notify != case.expected.yougen.should_notify {
        bail!(
            "should_notify mismatch: expected {}, got {}",
            case.expected.yougen.should_notify,
            decision.should_notify
        );
    }
    if decision.watch_suppressed != case.expected.yougen.watch_suppressed {
        bail!(
            "watch_suppressed mismatch: expected {}, got {}",
            case.expected.yougen.watch_suppressed,
            decision.watch_suppressed
        );
    }
    if decision.muted_short_circuit != case.expected.yougen.muted_short_circuit {
        bail!(
            "muted_short_circuit mismatch: expected {}, got {}",
            case.expected.yougen.muted_short_circuit,
            decision.muted_short_circuit
        );
    }
    if decision.blind_wakeup_required != case.expected.yougen.blind_wakeup_required {
        bail!(
            "blind_wakeup_required mismatch: expected {}, got {}",
            case.expected.yougen.blind_wakeup_required,
            decision.blind_wakeup_required
        );
    }
    if decision.unresolved_client_evaluation != case.expected.yougen.unresolved_client_evaluation {
        bail!(
            "unresolved_client_evaluation mismatch: expected {}, got {}",
            case.expected.yougen.unresolved_client_evaluation,
            decision.unresolved_client_evaluation
        );
    }

    Ok(())
}

fn parse_soland_watch_level(value: &str) -> Result<soland_push_rule_core::WatchLevel> {
    soland_push_rule_core::WatchLevel::from_wire(value)
        .ok_or_else(|| anyhow!("invalid soland watch_level {value}"))
}

fn parse_chime_watch_level(value: &str) -> Result<chime_push_rule_core::WatchLevel> {
    chime_push_rule_core::WatchLevel::from_wire(value)
        .ok_or_else(|| anyhow!("invalid chime watch_level {value}"))
}

fn parse_yougen_watch_level(value: &str) -> Result<yougen_notification_rules::WatchLevel> {
    yougen_notification_rules::WatchLevel::from_wire(value)
        .ok_or_else(|| anyhow!("invalid yougen watch_level {value}"))
}

fn expected_chime_decision(
    deliver: bool,
    blind_wakeup: bool,
) -> chime_push_rule_core::ShouldNotify {
    match (deliver, blind_wakeup) {
        (_, true) => chime_push_rule_core::ShouldNotify::BlindWakeup,
        (true, false) => chime_push_rule_core::ShouldNotify::Notify,
        (false, false) => chime_push_rule_core::ShouldNotify::DontNotify,
    }
}

fn projected_yougen_reason_code(
    level: yougen_notification_rules::WatchLevel,
    decision: &yougen_notification_rules::NotificationDecision,
) -> &'static str {
    if decision.muted_short_circuit {
        return soland_push_rule_core::reason_code::MUTED;
    }
    if decision.blind_wakeup_required {
        return soland_push_rule_core::reason_code::BLIND_WAKEUP_REQUIRED;
    }
    if decision.watch_suppressed {
        return match level {
            yougen_notification_rules::WatchLevel::MentionsOnly => {
                soland_push_rule_core::reason_code::NOT_MENTIONED
            }
            yougen_notification_rules::WatchLevel::Participating => {
                soland_push_rule_core::reason_code::NOT_PARTICIPATING
            }
            yougen_notification_rules::WatchLevel::Muted => {
                soland_push_rule_core::reason_code::MUTED
            }
            yougen_notification_rules::WatchLevel::All => {
                soland_push_rule_core::reason_code::WATCH_ALLOWS
            }
        };
    }
    if decision.should_notify {
        soland_push_rule_core::reason_code::WATCH_ALLOWS
    } else {
        "no_push_rule_matched"
    }
}

fn client_side_mentions_rule() -> yougen_notification_rules::PushRulesConfig {
    yougen_notification_rules::PushRulesConfig {
        rules: vec![yougen_notification_rules::PushRule {
            rule_id: "t4_4.client_mentions".to_owned(),
            kind: "underride".to_owned(),
            enabled: true,
            evaluation_locus: "client".to_owned(),
            conditions: vec![yougen_notification_rules::PushCondition {
                kind: "mentions_actor".to_owned(),
                field: None,
                pattern: None,
                op: None,
                value: None,
            }],
            actions: vec!["notify".to_owned(), "highlight".to_owned()],
        }],
    }
}
