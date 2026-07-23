use anyhow::{Context, Result, anyhow, bail};
use arkret::push_rule_core::{self, EventContext, ShouldNotify, WatchLevel};
use arkret_models_integration::{
    HARDENED_MENTION_ROUTING_PROFILES, MentionRoutingHint, effective_mention_routing_hint,
};
use arkret_wire::PROFILE_E2EE_CLIENT;
use serde::Deserialize;
use serde_json::Value;

const PUSH_RULE_CORE_FIXTURE_FILE: &str = "push-rule-core-fixture.json";
const PUSH_RULE_CORE_PROFILE: &str = "ak.profile.push_gateway.blind_wakeup.v1";
pub const VECTOR_ID_HARDENED_MENTION_ROUTING_HINT: &str =
    "ak.vector.push.mention_routing_hint_disabled_on_hardened_realm.v1";
const PUSH_RULE_CORE_VECTOR_IDS: &[&str] = &[
    "ak.vector.push.broadcast_mention_controls.v1",
    "ak.vector.push.strand_engaged_mention.v1",
    VECTOR_ID_HARDENED_MENTION_ROUTING_HINT,
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
    #[serde(default)]
    watch_level: Option<String>,
    #[serde(default)]
    event: EventVector,
    #[serde(default)]
    client_projection: ClientProjectionInput,
    #[serde(default)]
    expected: Option<ExpectedVector>,
}

#[derive(Debug, Deserialize)]
struct HardenedMentionRoutingCase {
    runner: String,
    variants: Vec<MentionRoutingVariant>,
    expected_hardened_behavior: ExpectedHardenedBehavior,
}

#[derive(Debug, Deserialize)]
struct MentionRoutingVariant {
    realm_profiles: Vec<String>,
    declared_mention_routing_hint: String,
    expected_effective_hint: String,
}

#[derive(Debug, Deserialize)]
struct ExpectedHardenedBehavior {
    register_sidecar_token: bool,
    compare_sidecar_token: bool,
    persist_sidecar_token: bool,
    fallback: String,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct InstrumentedMentionRoutingSidecar {
    register_calls: usize,
    compare_calls: usize,
    persist_calls: usize,
    fallback_calls: usize,
}

impl InstrumentedMentionRoutingSidecar {
    fn apply(&mut self, effective_hint: MentionRoutingHint) -> &'static str {
        match effective_hint {
            MentionRoutingHint::Disabled => {
                self.fallback_calls += 1;
                "blind_or_batch_wakeup"
            }
            MentionRoutingHint::RecipientRegisteredToken => {
                self.register_calls += 1;
                self.compare_calls += 1;
                self.persist_calls += 1;
                "recipient_registered_token"
            }
        }
    }
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
        if case.vector_id.as_deref() == Some(VECTOR_ID_HARDENED_MENTION_ROUTING_HINT) {
            continue;
        }
        assert_shared_core(case).with_context(|| format!("shared core vector {}", case.name))?;
    }
    run_hardened_mention_routing_hint_vector()?;

    Ok(())
}

pub fn run_hardened_mention_routing_hint_vector() -> Result<()> {
    let fixture = super::load_fixture_value(PUSH_RULE_CORE_FIXTURE_FILE)?;
    let case_value = fixture
        .get("cases")
        .and_then(Value::as_array)
        .and_then(|cases| {
            cases.iter().find(|case| {
                case.get("vector_id").and_then(Value::as_str)
                    == Some(VECTOR_ID_HARDENED_MENTION_ROUTING_HINT)
            })
        })
        .ok_or_else(|| anyhow!("hardened mention-routing vector case missing"))?;
    let case: HardenedMentionRoutingCase = serde_json::from_value(case_value.clone())
        .context("decode hardened mention-routing vector case")?;
    if case.runner
        != "cotest::conformance::push_rule_core::run_hardened_mention_routing_hint_vector"
    {
        bail!("hardened mention-routing fixture runner is not resolvable");
    }
    if case.variants.len() != 5 {
        bail!(
            "hardened mention-routing vector must contain 5 variants, got {}",
            case.variants.len()
        );
    }
    if case.expected_hardened_behavior.register_sidecar_token
        || case.expected_hardened_behavior.compare_sidecar_token
        || case.expected_hardened_behavior.persist_sidecar_token
        || case.expected_hardened_behavior.fallback != "blind_or_batch_wakeup"
    {
        bail!("hardened mention-routing behavior expectations drifted");
    }

    let mut disabled_recipient_variants = 0usize;
    let mut disabled_unknown_variants = 0usize;
    let mut enabled_positive_controls = 0usize;
    for variant in &case.variants {
        let has_hardened_profile = variant.realm_profiles.iter().any(|profile| {
            HARDENED_MENTION_ROUTING_PROFILES
                .iter()
                .any(|hardened| profile == hardened)
        });
        let has_ordinary_e2ee_profile = variant
            .realm_profiles
            .iter()
            .any(|profile| profile == PROFILE_E2EE_CLIENT);
        let declared = MentionRoutingHint::parse_wire(&variant.declared_mention_routing_hint);
        let effective = effective_mention_routing_hint(
            &variant.realm_profiles,
            Some(&variant.declared_mention_routing_hint),
        );
        if effective.as_str() != variant.expected_effective_hint {
            bail!(
                "mention-routing effective hint mismatch for profiles {:?}: expected {}, got {}",
                variant.realm_profiles,
                variant.expected_effective_hint,
                effective.as_str()
            );
        }

        let mut sidecar = InstrumentedMentionRoutingSidecar::default();
        let route = sidecar.apply(effective);
        match effective {
            MentionRoutingHint::Disabled => {
                if sidecar.register_calls != 0
                    || sidecar.compare_calls != 0
                    || sidecar.persist_calls != 0
                    || sidecar.fallback_calls != 1
                    || route != case.expected_hardened_behavior.fallback
                {
                    bail!(
                        "disabled mention routing touched sidecar token state: {sidecar:?}, route={route}"
                    );
                }
                if declared == Some(MentionRoutingHint::RecipientRegisteredToken) {
                    if !has_hardened_profile {
                        bail!("recipient token was disabled without a hardened Realm profile");
                    }
                    disabled_recipient_variants += 1;
                } else if declared.is_none() {
                    if !has_hardened_profile {
                        bail!("unknown hint control must execute under a hardened Realm profile");
                    }
                    disabled_unknown_variants += 1;
                } else {
                    bail!("fixture introduced an unexpected disabled canonical hint");
                }
            }
            MentionRoutingHint::RecipientRegisteredToken => {
                if sidecar.register_calls != 1
                    || sidecar.compare_calls != 1
                    || sidecar.persist_calls != 1
                    || sidecar.fallback_calls != 0
                    || route != MentionRoutingHint::RecipientRegisteredToken.as_str()
                {
                    bail!("positive mention-routing control did not use the sidecar: {sidecar:?}");
                }
                if declared != Some(MentionRoutingHint::RecipientRegisteredToken)
                    || !has_ordinary_e2ee_profile
                    || has_hardened_profile
                {
                    bail!("positive mention-routing control is not explicit ordinary-E2EE opt-in");
                }
                enabled_positive_controls += 1;
            }
        }
    }

    if disabled_recipient_variants != 3
        || disabled_unknown_variants != 1
        || enabled_positive_controls != 1
    {
        bail!(
            "unexpected mention-routing variant split: hardened={disabled_recipient_variants}, unknown={disabled_unknown_variants}, positive={enabled_positive_controls}"
        );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardened_mention_routing_vector_runs_clean() {
        run_hardened_mention_routing_hint_vector().unwrap();
    }
}
