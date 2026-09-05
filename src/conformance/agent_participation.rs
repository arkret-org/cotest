//! Agent participation policy conformance vectors.
//!
//! Covers controller-scoped agent selector mentions and AKP-0010 participation
//! policy semantics by exercising the SDK wire DTOs and reducer-pure helpers.

use anyhow::{Result, anyhow, bail};
use arkret_identifiers::{DidCoreId, Hash, RealmId};
use arkret_models_collaboration::events_payloads::mention::{Mention, MentionNode, MentionTarget};
use arkret_models_collaboration::governance::agent_participation::{
    AgentParticipationEntry, AgentParticipationError, AgentParticipationOutcome, ParticipationBits,
    ParticipationNextReplaceInput, ParticipationScope, effective_participation, fold_ceiling_chain,
    validate_agent_participation_tightens,
};
use arkret_models_discovery::DirectoryAgentSelectorResolutionOutcome;
use arkret_models_identity::claim_presentation::AgentSelectorClaim;
use arkret_models_identity::handle::{Handle, HandleBindingState, HandleVisibility};
use arkret_wire::{
    AccountId, ActorId, Audience, PayloadProof, PayloadProofPurpose, ProfileId, SchemaId,
};
use chrono::{TimeZone, Utc};
use serde::Deserialize;
use serde_json::Value;

use super::schema_validation_fixture::SchemaEnv;
use super::{expected_bool, expected_str, required_str, required_u64};

pub const VECTOR_ID_AGENT_MENTION_SELECTOR: &str = "ak.vector.agent.mention_selector.v1";
pub const VECTOR_ID_AGENT_PARTICIPATION_CEILING_TIGHTEN: &str =
    "ak.vector.agent.participation.ceiling_tighten.v1";
pub const VECTOR_ID_AGENT_PARTICIPATION_EFFECTIVE_INTERSECTION: &str =
    "ak.vector.agent.participation.effective_intersection.v1";
pub const VECTOR_ID_AGENT_PARTICIPATION_SELECTION_CAS: &str =
    "ak.vector.agent.participation.selection_cas.v1";
pub const VECTOR_ID_AGENT_PARTICIPATION_SESSION_OVERLAY: &str =
    "ak.vector.agent.participation.session_overlay.v1";
pub const VECTOR_ID_AGENT_PARTICIPATION_THIRD_PARTY_MENTION_GATE: &str =
    "ak.vector.agent.participation.third_party_mention_gate.v1";

pub const ALL_AGENT_PARTICIPATION_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_AGENT_MENTION_SELECTOR,
    VECTOR_ID_AGENT_PARTICIPATION_CEILING_TIGHTEN,
    VECTOR_ID_AGENT_PARTICIPATION_EFFECTIVE_INTERSECTION,
    VECTOR_ID_AGENT_PARTICIPATION_SELECTION_CAS,
    VECTOR_ID_AGENT_PARTICIPATION_SESSION_OVERLAY,
    VECTOR_ID_AGENT_PARTICIPATION_THIRD_PARTY_MENTION_GATE,
];

const AGENT_PARTICIPATION_FIXTURE_FILE: &str = "agent-participation-fixture.json";
const AGENT_PARTICIPATION_ENTRY_SCHEMA: &str =
    "schemas/agent-operations.schema.json#/$defs/agent_participation_entry";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentParticipationFixture {
    profile: String,
    version: String,
    suite: String,
    runner: Value,
    covers_vectors: Vec<String>,
    cases: Vec<Value>,
}

fn participation_fixture() -> Result<AgentParticipationFixture> {
    let fixture: AgentParticipationFixture =
        serde_json::from_value(super::load_fixture_value(AGENT_PARTICIPATION_FIXTURE_FILE)?)?;
    validate_agent_participation_fixture_metadata(&fixture)?;
    Ok(fixture)
}

fn validate_agent_participation_fixture_metadata(
    fixture: &AgentParticipationFixture,
) -> Result<()> {
    if fixture.profile != ProfileId::AGENT_PARTICIPATION_POLICY_V1
        || fixture.suite != "agent_participation"
        || fixture.version.trim().is_empty()
        || fixture.runner.is_null()
    {
        bail!("agent participation fixture suite drifted");
    }

    let covers = &fixture.covers_vectors;
    let cases = &fixture.cases;

    for vector_id in ALL_AGENT_PARTICIPATION_VECTOR_IDS {
        if !covers.iter().any(|entry| entry == vector_id) {
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

fn case<'a>(fixture: &'a AgentParticipationFixture, vector_id: &str) -> Result<&'a Value> {
    fixture
        .cases
        .iter()
        .find(|case| case.get("vector_id").and_then(Value::as_str) == Some(vector_id))
        .ok_or_else(|| anyhow!("agent participation fixture missing case {vector_id}"))
}

fn participation_field(value: &Value, field: &str) -> Result<ParticipationBits> {
    serde_json::from_value(
        value
            .get(field)
            .cloned()
            .ok_or_else(|| anyhow!("case missing participation field {field}"))?,
    )
    .map_err(|err| anyhow!("invalid participation field {field}: {err}"))
}

fn participation_pointer(value: &Value, pointer: &str) -> Result<ParticipationBits> {
    serde_json::from_value(
        value
            .pointer(pointer)
            .cloned()
            .ok_or_else(|| anyhow!("case missing participation pointer {pointer}"))?,
    )
    .map_err(|err| anyhow!("invalid participation pointer {pointer}: {err}"))
}

fn scope_field(value: &Value, field: &str) -> Result<ParticipationScope> {
    serde_json::from_value(
        value
            .get(field)
            .cloned()
            .ok_or_else(|| anyhow!("case missing scope field {field}"))?,
    )
    .map_err(|err| anyhow!("invalid scope field {field}: {err}"))
}

fn did_field(value: &Value, field: &str) -> Result<DidCoreId> {
    DidCoreId::new(required_str(value, field)?).map_err(Into::into)
}

/// Read a complete `AccountId` from the fixture. Mention subjects are never
/// carried as a bare principal string, so the fixture side is typed too.
fn account_pointer(value: &Value, pointer: &str) -> Result<AccountId> {
    let raw = value
        .pointer(pointer)
        .cloned()
        .ok_or_else(|| anyhow!("case missing account pointer {pointer}"))?;
    let account: AccountId = serde_json::from_value(raw)
        .map_err(|err| anyhow!("invalid account at {pointer}: {err}"))?;
    account.validate()?;
    Ok(account)
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

fn selector_claim(
    case: &Value,
    subject_account_id: AccountId,
    slug_field: &str,
) -> Result<AgentSelectorClaim> {
    Ok(AgentSelectorClaim {
        schema: SchemaId::AGENT_SELECTOR_CLAIM_V1.to_owned(),
        controller_subject_id: did_field(case, "controller_subject")?,
        agent_slug: required_str(case, slug_field)?.to_owned(),
        subject_account_id,
        issuer_id: DidCoreId::new("ak:did_core:web:directory.acme.example")?,
        vouching_id: Some(DidCoreId::new("ak:did_core:web:directory.acme.example")?),
        binding_state: HandleBindingState::Verified,
        visibility: HandleVisibility::Restricted,
        audience: Some("ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1".to_owned()),
        claim_scope: Default::default(),
        expires_at: None,
        created_at: Utc.with_ymd_and_hms(2026, 6, 19, 0, 0, 0).unwrap(),
        verified_at: Some(Utc.with_ymd_and_hms(2026, 6, 19, 0, 1, 0).unwrap()),
        source_refs: vec!["ak:event:AR4I3pqI_AE1Vxb4LEKq2azQxWXhHobgzwnTJmhVKJT-".to_owned()],
        proofs: vec![PayloadProof {
            kind: "detached_jws".to_owned(),
            verification_method: crate::fixture_did_url("did:web:directory.acme.example#key-1"),
            payload_digest: Hash::new(
                "sha256:0000000000000000000000000000000000000000000000000000000000000001",
            )?,
            created_at: Utc.with_ymd_and_hms(2026, 6, 19, 0, 0, 0).unwrap(),
            domain: None,
            audience: Some(Audience::Single(
                "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1".to_owned(),
            )),
            proof_purpose: Some(PayloadProofPurpose::IssuerAttestation),
            jws: "fixture.signature.value".to_owned(),
        }],
    })
}

fn selector_outcome(claim: AgentSelectorClaim) -> Result<DirectoryAgentSelectorResolutionOutcome> {
    let outcome = DirectoryAgentSelectorResolutionOutcome {
        controller_subject_id: claim.controller_subject_id.clone(),
        subject_account_id: claim.subject_account_id.clone(),
        agent_slug: claim.agent_slug.clone(),
        selector_claim: claim,
        source_refs: vec![arkret_wire::EventId::new(
            "ak:event:AR4I3pqI_AE1Vxb4LEKq2azQxWXhHobgzwnTJmhVKJT-".to_owned(),
        )?],
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

/// The `identity-handles.md` §3.8.2 step-1 join: keep the MemberIdentity
/// candidates whose `subject_actor_id` is the `account` branch, then compare
/// that account with the mention subject over both components. The `service`
/// branch never participates.
fn member_identity_join<'a>(
    candidates: &'a [ActorId],
    subject_account_id: &AccountId,
) -> Vec<&'a ActorId> {
    candidates
        .iter()
        .filter(|candidate| candidate.as_account_id() == Some(subject_account_id))
        .collect()
}

pub fn run_agent_mention_selector_vector() -> Result<()> {
    let fixture = participation_fixture()?;
    let vector = case(&fixture, VECTOR_ID_AGENT_MENTION_SELECTOR)?;
    // The signed claim names one complete AccountId and the mention copies it
    // verbatim; the Station is no longer supplied by the consumer. Ruling
    // `review/spec-done/2026-09-05-1310`.
    let expected_subject = account_pointer(vector, "/persisted_mention/subject_account_id")?;
    let expected_controller =
        account_pointer(vector, "/persisted_mention/controller_subject_account_id")?;
    let claim = selector_claim(vector, expected_subject.clone(), "agent_slug_at_time")?;
    claim.validate()?;
    let outcome = selector_outcome(claim.clone())?;

    if outcome.subject_account_id != expected_subject
        || outcome.controller_subject_id != expected_controller.principal_id
    {
        bail!("fixture selector outcome and persisted mention name different targets");
    }

    // A Directory that keeps the agent principal and swaps the Station is a
    // different target, not the same one: the outcome must equal the claim.
    let mut retargeted = outcome.clone();
    retargeted.subject_account_id = AccountId::new(
        expected_subject.principal_id.clone(),
        DidCoreId::new("ak:did_core:web:other.example")?,
    );
    if retargeted.validate().is_ok() {
        bail!("a selector outcome that retargets the Station must not validate");
    }
    let mention = Mention::new(expected_subject.clone())
        .with_agent_selector_metadata(
            expected_controller.clone(),
            Handle::parse(required_str(vector, "controller_handle")?)?,
            outcome.agent_slug.clone(),
        )
        .with_mention_text_original(required_str(vector, "mention_text_original")?)
        .with_resolved_at(Utc.with_ymd_and_hms(2026, 6, 19, 0, 2, 0).unwrap());
    let node = MentionNode::mention(mention.clone());

    if mention.subject_account_id != expected_subject
        || node.target() != MentionTarget::Subject(&expected_subject)
    {
        bail!(
            "agent selector mention did not persist the agent's complete AccountId as authoritative subject_account_id"
        );
    }
    if mention.controller_subject_account_id.as_ref() != Some(&expected_controller) {
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

    let changed_subject = AccountId::new(
        did_field(vector, "changed_agent_subject")?,
        expected_subject.station_id.clone(),
    );
    let changed = selector_outcome(selector_claim(
        vector,
        changed_subject,
        "changed_agent_slug",
    )?)?;
    if changed.subject_account_id == mention.subject_account_id {
        bail!("changed selector control must target a different agent account");
    }
    if mention.subject_account_id
        != account_pointer(vector, "/expected/historical_target_after_slug_change")?
    {
        bail!("historical mention target was rewritten after slug change");
    }

    if resolve_selector(&[outcome.clone(), changed]).is_some() {
        bail!("ambiguous agent selector resolution did not fail closed");
    }
    if resolve_selector(&[]).is_some() {
        bail!("unavailable agent selector resolution did not fail closed");
    }

    // Step 6 (negative, normative) — a Realm member sharing the agent's
    // principal but hosted by another Station MUST NOT match this mention:
    // no notification target, no authorization hit, and no §3.8.2
    // MemberIdentity join hit.
    let other_station = account_pointer(vector, "/expected/same_principal_other_station_account")?;
    if expected_bool(vector, "same_principal_other_station_matches")? {
        bail!("fixture must assert that a same-principal other-Station account does not match");
    }
    if other_station.principal_id != expected_subject.principal_id
        || other_station.station_id == expected_subject.station_id
    {
        bail!("fixture negative account must share the principal and differ in Station");
    }
    if other_station == mention.subject_account_id
        || MentionTarget::Subject(&other_station) == node.target()
    {
        bail!("mention target equality MUST cover principal_id and station_id");
    }
    let roster = vec![
        ActorId::account(expected_subject.clone()),
        ActorId::account(other_station.clone()),
        ActorId::service(DidCoreId::new("ak:did_core:web:station.acme.example")?),
    ];
    let joined = member_identity_join(&roster, &mention.subject_account_id);
    if joined != vec![&roster[0]] {
        bail!("§3.8.2 MemberIdentity join MUST select only the addressed account; got {joined:?}");
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

pub fn run_agent_participation_effective_intersection_vector() -> Result<()> {
    let fixture = participation_fixture()?;
    let vector = case(
        &fixture,
        VECTOR_ID_AGENT_PARTICIPATION_EFFECTIVE_INTERSECTION,
    )?;
    let ceiling = participation_field(vector, "governance_ceiling")?;
    let selection = participation_field(vector, "selection")?;
    let expected = participation_pointer(vector, "/expected/effective")?;

    if !expected.is_subset_of(ceiling) {
        bail!("expected effective participation exceeds its governance ceiling");
    }
    let effective = effective_participation(ceiling, selection);
    if effective != expected {
        bail!("effective participation drifted: expected {expected:?}, got {effective:?}");
    }

    let tightened = ParticipationBits {
        reply_message: false,
        reaction_add: false,
        reaction_remove: false,
        ..ceiling
    };
    let after_tighten = effective_participation(tightened, selection);
    if after_tighten != participation_pointer(vector, "/expected/after_reply_tighten")? {
        bail!("tightened ceiling did not disable the reply action gate");
    }

    let unknown_source_effective = ParticipationBits::NONE;
    if unknown_source_effective
        != participation_pointer(vector, "/expected/unknown_source_effective")?
    {
        bail!("unknown ceiling source did not fail closed to no participation");
    }
    Ok(())
}

pub fn run_agent_participation_selection_cas_vector() -> Result<()> {
    let fixture = participation_fixture()?;
    let vector = case(&fixture, VECTOR_ID_AGENT_PARTICIPATION_SELECTION_CAS)?;
    if required_u64(vector, "initial_expected_version")? != 0 {
        bail!("first participation selection write must use expected_version=0");
    }
    let ceiling = participation_field(vector, "governance_ceiling")?;
    let selection = participation_field(vector, "selection")?;
    let effective = effective_participation(ceiling, selection);
    if effective != participation_pointer(vector, "/expected/effective")? {
        bail!("selection action-time intersection drifted");
    }
    let capped_bits = super::string_array_field(&vector["expected"], "capped_bits")?;
    if capped_bits != ["accept_third_party_mention"] {
        bail!("selection CAS capped bits drifted: {capped_bits:?}");
    }
    if vector
        .pointer("/expected/stored_version")
        .and_then(Value::as_u64)
        != Some(1)
    {
        bail!("accepted first participation write must store version=1");
    }
    Ok(())
}

pub fn run_agent_participation_session_overlay_vector() -> Result<()> {
    let fixture = participation_fixture()?;
    let vector = case(&fixture, VECTOR_ID_AGENT_PARTICIPATION_SESSION_OVERLAY)?;
    let scope = scope_field(vector, "target_scope")?;
    let selection = participation_field(vector, "selection")?;
    let version = required_u64(vector, "version")?;

    let entry = AgentParticipationEntry {
        scope: scope.clone(),
        selection,
        version,
        next_replace_input: ParticipationNextReplaceInput {
            expected_version: version,
        },
    };
    let outcome = AgentParticipationOutcome {
        agent_id: "ak:did_core:web:agents.acme.example:alice-summary".to_owned(),
        agent_participation_entries: vec![entry.clone()],
    };
    if outcome.agent_participation_entries.len() != 1 {
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
        .remove("target_scope");
    if validator.is_valid(&malformed) {
        bail!("agent participation entry without target_scope passed schema validation");
    }
    let mut missing_echo = value.clone();
    missing_echo
        .as_object_mut()
        .ok_or_else(|| anyhow!("serialized participation entry was not an object"))?
        .remove("next_replace_input");
    if validator.is_valid(&missing_echo) {
        bail!("agent participation entry without next_replace_input passed schema validation");
    }

    let no_grant_runtime = "failed_precondition";
    if no_grant_runtime != expected_str(vector, "runtime_without_grant")? {
        bail!("session overlay runtime boundary drifted");
    }

    let realm_id = match scope {
        ParticipationScope::Realm { realm_id } => realm_id,
        other => bail!("session overlay vector expected Realm scope, got {other:?}"),
    };
    if realm_id != RealmId::new("ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5".to_owned())?
    {
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
    author: &DidCoreId,
    controller: &DidCoreId,
    effective: ParticipationBits,
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
    run_agent_participation_selection_cas_vector()?;
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

    #[test]
    fn renamed_top_level_fixture_key_is_reported() {
        let mut value = super::super::load_fixture_value(AGENT_PARTICIPATION_FIXTURE_FILE).unwrap();
        let cases = value.as_object_mut().unwrap().remove("cases").unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("renamed_cases".to_owned(), cases);

        let error = serde_json::from_value::<AgentParticipationFixture>(value).unwrap_err();
        assert!(
            error.to_string().contains("renamed_cases"),
            "strict fixture root did not name the changed key: {error}"
        );
    }
}
