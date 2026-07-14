//! Agent participation policy conformance vectors.
//!
//! Covers controller-scoped agent selector mentions and AKP-0010 participation
//! policy semantics by exercising the SDK wire DTOs and reducer-pure helpers.

use anyhow::{Result, anyhow, bail};
use arkret_core::{
    AGENT_SELECTOR_CLAIM_SCHEMA, AgentParticipation, AgentParticipationEntry,
    AgentParticipationError, AgentParticipationOutcome, AgentParticipationScope,
    AgentSelectorClaim, Audience, Did, DirectoryAgentSelectorResolutionOutcome, Handle,
    HandleBindingState, HandleVisibility, Hash, Mention, MentionNode, Proof, RealmId,
    effective_participation, fold_ceiling_chain, validate_agent_participation_tightens,
    validate_selection_within_ceiling,
};
use chrono::{TimeZone, Utc};
use serde_json::Value;

use super::schema_validation_fixture::SchemaEnv;

pub const VECTOR_ID_AGENT_MENTION_SELECTOR: &str = "ak.vector.agent.mention_selector.v1";
pub const VECTOR_ID_AGENT_PARTICIPATION_CEILING_TIGHTEN: &str =
    "ak.vector.agent.participation.ceiling_tighten.v1";
pub const VECTOR_ID_AGENT_PARTICIPATION_EFFECTIVE_INTERSECTION: &str =
    "ak.vector.agent.participation.effective_intersection.v1";
pub const VECTOR_ID_AGENT_PARTICIPATION_SELECTION_WITHIN_CEILING: &str =
    "ak.vector.agent.participation.selection_within_ceiling.v1";
pub const VECTOR_ID_AGENT_PARTICIPATION_SESSION_OVERLAY: &str =
    "ak.vector.agent.participation.session_overlay.v1";
pub const VECTOR_ID_AGENT_PARTICIPATION_THIRD_PARTY_MENTION_GATE: &str =
    "ak.vector.agent.participation.third_party_mention_gate.v1";

pub const ALL_AGENT_PARTICIPATION_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_AGENT_MENTION_SELECTOR,
    VECTOR_ID_AGENT_PARTICIPATION_CEILING_TIGHTEN,
    VECTOR_ID_AGENT_PARTICIPATION_EFFECTIVE_INTERSECTION,
    VECTOR_ID_AGENT_PARTICIPATION_SELECTION_WITHIN_CEILING,
    VECTOR_ID_AGENT_PARTICIPATION_SESSION_OVERLAY,
    VECTOR_ID_AGENT_PARTICIPATION_THIRD_PARTY_MENTION_GATE,
];

const AGENT_PARTICIPATION_FIXTURE_FILE: &str = "agent-participation-fixture.json";
const AGENT_PARTICIPATION_PROFILE: &str = "ak.profile.agent_participation_policy.v1";
const AGENT_PARTICIPATION_ENTRY_SCHEMA: &str =
    "schemas/agent-operations.schema.json#/$defs/agent_participation_entry";
const GRANT_MESSAGE_CREATE: &str = "ak.message.create";
const GRANT_REACTION_ADD: &str = "ak.reaction.add";
const GRANT_EVENT_READ: &str = "ak.event.read";
const GRANT_ACT_ON_BEHALF: &str = "ak.agent.act_on_behalf";

fn participation_fixture() -> Result<Value> {
    let fixture = super::load_fixture_value(AGENT_PARTICIPATION_FIXTURE_FILE)?;
    super::validate_profile(&fixture, AGENT_PARTICIPATION_PROFILE)?;
    validate_agent_participation_fixture_metadata(&fixture)?;
    Ok(fixture)
}

fn validate_agent_participation_fixture_metadata(fixture: &Value) -> Result<()> {
    if fixture.get("suite").and_then(Value::as_str) != Some("agent_participation") {
        bail!("agent participation fixture suite drifted");
    }

    let covers = fixture
        .get("covers_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("agent participation fixture missing covers_vectors[]"))?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("agent participation fixture missing cases[]"))?;

    for vector_id in ALL_AGENT_PARTICIPATION_VECTOR_IDS {
        if !covers
            .iter()
            .any(|entry| entry.as_str() == Some(*vector_id))
        {
            bail!("agent participation fixture missing covers_vectors entry {vector_id}");
        }
        if !cases.iter().any(|case| {
            case.get("vector_id").and_then(Value::as_str) == Some(*vector_id)
                && case
                    .get("assertions")
                    .and_then(Value::as_array)
                    .is_some_and(|assertions| !assertions.is_empty())
        }) {
            bail!("agent participation fixture missing asserted case {vector_id}");
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
        .ok_or_else(|| anyhow!("agent participation fixture missing case {vector_id}"))
}

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("case missing string field {field}"))
}

fn expected_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .pointer(&format!("/expected/{field}"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("case missing expected.{field}"))
}

fn participation_field(value: &Value, field: &str) -> Result<AgentParticipation> {
    serde_json::from_value(
        value
            .get(field)
            .cloned()
            .ok_or_else(|| anyhow!("case missing participation field {field}"))?,
    )
    .map_err(|err| anyhow!("invalid participation field {field}: {err}"))
}

fn participation_pointer(value: &Value, pointer: &str) -> Result<AgentParticipation> {
    serde_json::from_value(
        value
            .pointer(pointer)
            .cloned()
            .ok_or_else(|| anyhow!("case missing participation pointer {pointer}"))?,
    )
    .map_err(|err| anyhow!("invalid participation pointer {pointer}: {err}"))
}

fn scope_field(value: &Value, field: &str) -> Result<AgentParticipationScope> {
    serde_json::from_value(
        value
            .get(field)
            .cloned()
            .ok_or_else(|| anyhow!("case missing scope field {field}"))?,
    )
    .map_err(|err| anyhow!("invalid scope field {field}: {err}"))
}

fn did_field(value: &Value, field: &str) -> Result<Did> {
    Did::new(required_str(value, field)?.to_owned()).map_err(Into::into)
}

fn participation_reason(error: AgentParticipationError) -> String {
    let message = error.to_string();
    message
        .strip_prefix("reason=")
        .and_then(|suffix| suffix.split(':').next())
        .unwrap_or(&message)
        .to_owned()
}

fn expect_reason(error: AgentParticipationError, expected: &str) -> Result<()> {
    let actual = participation_reason(error);
    if actual != expected {
        bail!("expected reason {expected}, got {actual}");
    }
    Ok(())
}

fn selector_claim(case: &Value, agent_field: &str, slug_field: &str) -> Result<AgentSelectorClaim> {
    Ok(AgentSelectorClaim {
        schema: AGENT_SELECTOR_CLAIM_SCHEMA.to_owned(),
        controller_subject: did_field(case, "controller_subject")?,
        agent_slug: required_str(case, slug_field)?.to_owned(),
        subject: did_field(case, agent_field)?,
        issuer: Did::new("did:web:directory.acme.example".to_owned())?,
        issuer_service_id: Some(Did::new("did:web:directory.acme.example".to_owned())?),
        binding_state: HandleBindingState::Verified,
        visibility: HandleVisibility::Restricted,
        audience: Some("ak:realm:0196419b-0000-7000-8000-000000000000".to_owned()),
        claim_scope: Default::default(),
        expires_at: None,
        created_at: Utc.with_ymd_and_hms(2026, 6, 19, 0, 0, 0).unwrap(),
        verified_at: Some(Utc.with_ymd_and_hms(2026, 6, 19, 0, 1, 0).unwrap()),
        source_refs: vec!["ak:event:0196419b-0000-7000-8000-000000000001".to_owned()],
        proofs: vec![Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:web:directory.acme.example#key-1".to_owned(),
            event_digest: Hash::new(
                "sha256:0000000000000000000000000000000000000000000000000000000000000001",
            )?,
            created_at: Utc.with_ymd_and_hms(2026, 6, 19, 0, 0, 0).unwrap(),
            domain: None,
            audience: Some(Audience::Single(
                "ak:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
            )),
            jws: "fixture.signature.value".to_owned(),
        }],
    })
}

fn selector_outcome(claim: AgentSelectorClaim) -> Result<DirectoryAgentSelectorResolutionOutcome> {
    let outcome = DirectoryAgentSelectorResolutionOutcome {
        controller_subject: claim.controller_subject.clone(),
        subject: claim.subject.clone(),
        agent_slug: claim.agent_slug.clone(),
        verified: true,
        selector_claim: claim,
        source_refs: vec!["ak:event:0196419b-0000-7000-8000-000000000001".to_owned()],
        expires_at: None,
    };
    outcome.validate()?;
    Ok(outcome)
}

fn resolve_selector(
    candidates: &[DirectoryAgentSelectorResolutionOutcome],
) -> Option<&DirectoryAgentSelectorResolutionOutcome> {
    let [candidate] = candidates else {
        return None;
    };
    candidate.validate().ok()?;
    Some(candidate)
}

pub fn run_agent_mention_selector_vector() -> Result<()> {
    let fixture = participation_fixture()?;
    let vector = case(&fixture, VECTOR_ID_AGENT_MENTION_SELECTOR)?;
    let claim = selector_claim(vector, "agent_subject", "agent_slug_at_time")?;
    claim.validate()?;
    let outcome = selector_outcome(claim.clone())?;

    let mention = Mention::new(outcome.subject.clone())
        .with_agent_selector_metadata(
            outcome.controller_subject.clone(),
            Handle::parse(required_str(vector, "controller_handle")?)?,
            outcome.agent_slug.clone(),
        )
        .with_mention_text_original(required_str(vector, "mention_text_original")?)
        .with_resolved_at(Utc.with_ymd_and_hms(2026, 6, 19, 0, 2, 0).unwrap());
    let node = MentionNode::mention(mention.clone());

    let expected_subject = did_field(vector, "agent_subject")?;
    if mention.subject_id != expected_subject || node.target_id() != expected_subject.as_str() {
        bail!("agent selector mention did not persist agent DID as authoritative subject_id");
    }
    if mention.controller_subject_id.as_ref() != Some(&claim.controller_subject) {
        bail!("agent selector mention lost controller audit metadata");
    }
    if mention.agent_slug_at_time.as_deref() != Some(required_str(vector, "agent_slug_at_time")?) {
        bail!("agent selector mention lost agent slug snapshot");
    }
    if mention.mention_text_original.as_deref()
        != Some(required_str(vector, "mention_text_original")?)
    {
        bail!("agent selector mention lost original text snapshot");
    }

    let changed = selector_outcome(selector_claim(
        vector,
        "changed_agent_subject",
        "changed_agent_slug",
    )?)?;
    if changed.subject == mention.subject_id {
        bail!("changed selector control must target a different agent DID");
    }
    if mention.subject_id.as_str() != expected_str(vector, "historical_target_after_slug_change")? {
        bail!("historical mention target was rewritten after slug change");
    }

    if resolve_selector(&[outcome.clone(), changed]).is_some() {
        bail!("ambiguous agent selector resolution did not fail closed");
    }
    if resolve_selector(&[]).is_some() {
        bail!("unavailable agent selector resolution did not fail closed");
    }
    Ok(())
}

pub fn run_agent_participation_ceiling_tighten_vector() -> Result<()> {
    let fixture = participation_fixture()?;
    let vector = case(&fixture, VECTOR_ID_AGENT_PARTICIPATION_CEILING_TIGHTEN)?;
    let parent = participation_field(vector, "parent_ceiling")?;
    let child = participation_field(vector, "accepted_child_ceiling")?;
    let widening = participation_field(vector, "widening_child_ceiling")?;
    let strand_widening = participation_field(vector, "strand_widening_ceiling")?;

    validate_agent_participation_tightens(parent, child)?;
    validate_agent_participation_tightens(child, child)?;
    expect_reason(
        validate_agent_participation_tightens(parent, widening).unwrap_err(),
        expected_str(vector, "widen_reason")?,
    )?;
    expect_reason(
        validate_agent_participation_tightens(child, strand_widening).unwrap_err(),
        expected_str(vector, "widen_reason")?,
    )?;

    let folded = fold_ceiling_chain([parent, child]);
    if folded != child {
        bail!("ceiling chain did not fold to the tighter child ceiling");
    }
    Ok(())
}

fn materialized_grants(effective: AgentParticipation) -> Vec<&'static str> {
    let mut grants = Vec::new();
    if effective.reply {
        grants.push(GRANT_MESSAGE_CREATE);
        grants.push(GRANT_REACTION_ADD);
    }
    if effective.act_on_behalf {
        grants.push(GRANT_ACT_ON_BEHALF);
    }
    grants
}

fn provision_ceiling_from_requested_scope(scope: &Value) -> Result<AgentParticipation> {
    let actions = scope
        .get("actions")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("requested_scope.actions[] is required"))?
        .iter()
        .map(|action| {
            action
                .as_str()
                .ok_or_else(|| anyhow!("requested_scope action must be a string"))
        })
        .collect::<Result<Vec<_>>>()?;
    let message_create = actions.contains(&GRANT_MESSAGE_CREATE);
    let controller_constraint = scope
        .get("constraints")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|constraint| {
            if constraint.get("constraint_type").and_then(Value::as_str) != Some("claim_based") {
                return false;
            }
            let controller_requirement = match constraint.get("subtype").and_then(Value::as_str) {
                Some("approval") => {
                    constraint.get("approval_required").and_then(Value::as_bool) == Some(true)
                        && (constraint.get("approval_relation").and_then(Value::as_str)
                            == Some("controller")
                            || constraint
                                .get("controller_approval_required")
                                .and_then(Value::as_bool)
                                == Some(true))
                }
                Some("accountability") => {
                    constraint
                        .get("accountability_required")
                        .and_then(Value::as_bool)
                        == Some(true)
                        && constraint.get("approval_relation").and_then(Value::as_str)
                            == Some("controller")
                }
                _ => false,
            };
            let applies = constraint
                .get("applies_to_actions")
                .and_then(Value::as_array)
                .is_none_or(|applicable| {
                    applicable
                        .iter()
                        .any(|action| action.as_str() == Some(GRANT_MESSAGE_CREATE))
                });
            controller_requirement && applies
        });
    Ok(AgentParticipation {
        reply: message_create && actions.contains(&GRANT_REACTION_ADD),
        accept_third_party_mention: actions.contains(&GRANT_EVENT_READ),
        act_on_behalf: message_create && controller_constraint,
    })
}

pub fn run_agent_participation_effective_intersection_vector() -> Result<()> {
    let fixture = participation_fixture()?;
    let vector = case(
        &fixture,
        VECTOR_ID_AGENT_PARTICIPATION_EFFECTIVE_INTERSECTION,
    )?;
    let provision_ceiling = provision_ceiling_from_requested_scope(
        vector
            .get("requested_scope")
            .ok_or_else(|| anyhow!("effective vector missing requested_scope"))?,
    )?;
    let governance_ceiling = participation_field(vector, "governance_ceiling")?;
    let ceiling = fold_ceiling_chain([provision_ceiling, governance_ceiling]);
    let selection = participation_field(vector, "selection")?;
    let expected = participation_pointer(vector, "/expected/effective")?;

    validate_selection_within_ceiling(ceiling, expected)?;
    let effective = effective_participation(ceiling, selection);
    if effective != expected {
        bail!("effective participation drifted: expected {expected:?}, got {effective:?}");
    }

    let grants = materialized_grants(effective);
    for expected_grant in super::string_array_field(&vector["expected"], "materialized_grants")? {
        if !grants.contains(&expected_grant) {
            bail!("effective participation did not materialize grant {expected_grant}");
        }
    }
    for forbidden_grant in super::string_array_field(&vector["expected"], "forbidden_grants")? {
        if grants.contains(&forbidden_grant) {
            bail!("effective participation materialized forbidden grant {forbidden_grant}");
        }
    }

    let tightened = AgentParticipation {
        reply: false,
        ..ceiling
    };
    let after_tighten = effective_participation(tightened, selection);
    if after_tighten != participation_pointer(vector, "/expected/after_reply_tighten")? {
        bail!("tightened ceiling did not revoke reply grant");
    }
    if materialized_grants(after_tighten).contains(&GRANT_MESSAGE_CREATE) {
        bail!("reply grant survived ceiling tighten");
    }

    let unknown_source_effective = AgentParticipation::NONE;
    if unknown_source_effective
        != participation_pointer(vector, "/expected/unknown_source_effective")?
    {
        bail!("unknown ceiling source did not fail closed to no participation");
    }
    for variant in vector
        .get("derivation_variants")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("effective vector missing derivation_variants[]"))?
    {
        let actual = provision_ceiling_from_requested_scope(
            variant
                .get("requested_scope")
                .ok_or_else(|| anyhow!("derivation variant missing requested_scope"))?,
        )?;
        let expected: AgentParticipation = serde_json::from_value(
            variant
                .get("expected")
                .cloned()
                .ok_or_else(|| anyhow!("derivation variant missing expected"))?,
        )?;
        if actual != expected {
            bail!(
                "requested_scope derivation variant {} drifted: expected {expected:?}, got {actual:?}",
                variant
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("unnamed")
            );
        }
    }
    Ok(())
}

pub fn run_agent_participation_selection_within_ceiling_vector() -> Result<()> {
    let fixture = participation_fixture()?;
    let vector = case(
        &fixture,
        VECTOR_ID_AGENT_PARTICIPATION_SELECTION_WITHIN_CEILING,
    )?;
    let provision_ceiling = provision_ceiling_from_requested_scope(
        vector
            .get("requested_scope")
            .ok_or_else(|| anyhow!("selection vector missing requested_scope"))?,
    )?;
    let governance_ceiling = participation_field(vector, "governance_ceiling")?;
    let ceiling = fold_ceiling_chain([provision_ceiling, governance_ceiling]);
    let selection = participation_field(vector, "selection")?;
    expect_reason(
        validate_selection_within_ceiling(ceiling, selection).unwrap_err(),
        expected_str(vector, "reason")?,
    )?;
    let capped_bits = super::string_array_field(&vector["expected"], "capped_bits")?;
    if capped_bits != ["accept_third_party_mention"] {
        bail!("selection-within-ceiling capped bits drifted: {capped_bits:?}");
    }
    let materialized = vector
        .pointer("/expected/materialized_grants")
        .and_then(Value::as_array);
    if materialized.is_none_or(|grants| !grants.is_empty()) {
        bail!("rejected participation selection must not materialize grants");
    }
    Ok(())
}

pub fn run_agent_participation_session_overlay_vector() -> Result<()> {
    let fixture = participation_fixture()?;
    let vector = case(&fixture, VECTOR_ID_AGENT_PARTICIPATION_SESSION_OVERLAY)?;
    let scope = scope_field(vector, "participation_scope")?;
    let selection = participation_field(vector, "selection")?;
    let ceiling = participation_field(vector, "ceiling")?;
    let effective = effective_participation(ceiling, selection);
    if effective != participation_pointer(vector, "/expected/effective")? {
        bail!("session overlay effective participation drifted");
    }

    let entry = AgentParticipationEntry {
        scope: scope.clone(),
        selection,
        ceiling,
        effective,
    };
    let outcome = AgentParticipationOutcome {
        ok: true,
        agent_id: "did:web:agents.acme.example:alice-summary".to_owned(),
        entries: vec![entry.clone()],
    };
    if !outcome.ok || outcome.entries.len() != 1 {
        bail!("agent participation outcome shape drifted");
    }

    let schema_ref = expected_str(vector, "schema_ref")?;
    if schema_ref != AGENT_PARTICIPATION_ENTRY_SCHEMA {
        bail!("agent participation entry schema ref drifted: {schema_ref}");
    }
    let schema_env = SchemaEnv::load()?;
    let validator = schema_env.compile(schema_ref)?;
    let value = serde_json::to_value(&entry)?;
    if !validator.is_valid(&value) {
        let errors = validator
            .iter_errors(&value)
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        bail!("valid agent participation entry failed schema validation: {errors}");
    }

    let mut malformed = value.clone();
    malformed
        .as_object_mut()
        .ok_or_else(|| anyhow!("serialized participation entry was not an object"))?
        .remove("participation_scope");
    if validator.is_valid(&malformed) {
        bail!("agent participation entry without participation_scope passed schema validation");
    }

    let no_grant_runtime = "failed_precondition";
    if no_grant_runtime != expected_str(vector, "runtime_without_grant")? {
        bail!("session overlay runtime boundary drifted");
    }

    let realm_id = match scope {
        AgentParticipationScope::Realm { realm_id } => realm_id,
        other => bail!("session overlay vector expected Realm scope, got {other:?}"),
    };
    if realm_id != RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000000".to_owned())? {
        bail!("session overlay Realm scope drifted");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DeliveryArtifacts {
    mention_notification: bool,
    inbox_entry: bool,
    push: bool,
    subscribe_projection: bool,
}

impl DeliveryArtifacts {
    const NONE: Self = Self {
        mention_notification: false,
        inbox_entry: false,
        push: false,
        subscribe_projection: false,
    };
    const ALL: Self = Self {
        mention_notification: true,
        inbox_entry: true,
        push: true,
        subscribe_projection: true,
    };
}

fn artifacts_from_expected(value: &Value, pointer: &str) -> Result<DeliveryArtifacts> {
    let object = value
        .pointer(pointer)
        .ok_or_else(|| anyhow!("case missing delivery expectation {pointer}"))?;
    Ok(DeliveryArtifacts {
        mention_notification: object
            .get("mention_notification")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("{pointer}.mention_notification must be bool"))?,
        inbox_entry: object
            .get("inbox_entry")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("{pointer}.inbox_entry must be bool"))?,
        push: object
            .get("push")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("{pointer}.push must be bool"))?,
        subscribe_projection: object
            .get("subscribe_projection")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("{pointer}.subscribe_projection must be bool"))?,
    })
}

fn mention_delivery(
    author: &Did,
    controller: &Did,
    effective: AgentParticipation,
) -> DeliveryArtifacts {
    if author == controller || effective.accept_third_party_mention {
        DeliveryArtifacts::ALL
    } else {
        DeliveryArtifacts::NONE
    }
}

pub fn run_agent_participation_third_party_mention_gate_vector() -> Result<()> {
    let fixture = participation_fixture()?;
    let vector = case(
        &fixture,
        VECTOR_ID_AGENT_PARTICIPATION_THIRD_PARTY_MENTION_GATE,
    )?;
    let controller = did_field(vector, "controller_subject")?;
    let third_party = did_field(vector, "third_party_subject")?;
    let before = participation_field(vector, "effective_before")?;
    let after = participation_field(vector, "effective_after")?;

    let third_party_before = mention_delivery(&third_party, &controller, before);
    if third_party_before != artifacts_from_expected(vector, "/expected/third_party_before")? {
        bail!("third-party mention delivered while accept_third_party_mention=false");
    }
    let controller_before = mention_delivery(&controller, &controller, before);
    if controller_before != artifacts_from_expected(vector, "/expected/controller_before")? {
        bail!("controller mention did not deliver while third-party mentions are gated");
    }

    let historical_after_flip = third_party_before;
    if historical_after_flip
        != artifacts_from_expected(vector, "/expected/third_party_before_after_flip")?
    {
        bail!("third-party mention gate was applied retroactively after a later enable");
    }

    let third_party_after = mention_delivery(&third_party, &controller, after);
    if third_party_after != artifacts_from_expected(vector, "/expected/third_party_after")? {
        bail!("third-party mention did not deliver after effective bit became true");
    }
    Ok(())
}

pub fn run_agent_participation_fixture_suite() -> Result<()> {
    validate_agent_participation_fixture_metadata(&participation_fixture()?)?;
    if ALL_AGENT_PARTICIPATION_VECTOR_IDS.len() != 6 {
        bail!(
            "expected 6 agent participation vector ids, got {}",
            ALL_AGENT_PARTICIPATION_VECTOR_IDS.len()
        );
    }

    run_agent_mention_selector_vector()?;
    run_agent_participation_ceiling_tighten_vector()?;
    run_agent_participation_effective_intersection_vector()?;
    run_agent_participation_selection_within_ceiling_vector()?;
    run_agent_participation_session_overlay_vector()?;
    run_agent_participation_third_party_mention_gate_vector()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_participation_vectors_run_clean() {
        run_agent_participation_fixture_suite().unwrap();
    }
}
