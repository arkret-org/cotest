//! Agent participation policy conformance vectors.
//!
//! Covers known-Agent picker label verification and AKP-0010 participation
//! policy semantics by exercising the SDK wire DTOs and reducer-pure helpers.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail, ensure};
use arkret_identifiers::{DidCoreId, RealmId};
use arkret_models_collaboration::events_payloads::mention::{Mention, MentionNode, MentionTarget};
use arkret_models_collaboration::governance::agent_participation::{
    AgentParticipationEntry, AgentParticipationError, AgentParticipationOutcome, ParticipationBits,
    ParticipationNextReplaceInput, ParticipationScope, effective_participation, fold_ceiling_chain,
    validate_agent_participation_tightens,
};
use arkret_models_collaboration::mention_composer::{
    AgentMentionComposerScope, AgentMentionLabels, AgentMentionRoute, MentionDraftBinding,
    agent_mention_route_with_modes,
};
use arkret_models_identity::claim_presentation::AgentSelectorClaimValue;
use arkret_models_identity::handle::HandleVisibility;
use arkret_wire::{AccountId, ActorId, ProfileId};
use serde::Deserialize;
use serde_json::Value;

use super::schema_validation_fixture::SchemaEnv;
use super::{expected_bool, expected_str, required_str, required_u64};

pub const VECTOR_ID_AGENT_SELECTOR_LABEL_KNOWN_ACCOUNT: &str =
    "ak.vector.agent.selector_label_known_account.v1";
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

pub const VECTOR_ID_AGENT_INTERACTION_MODE: &str = "ak.vector.agent.interaction_mode.v1";

pub const ALL_AGENT_PARTICIPATION_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_AGENT_INTERACTION_MODE,
    VECTOR_ID_AGENT_SELECTOR_LABEL_KNOWN_ACCOUNT,
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
    interaction_contract: Value,
    runtime_access_cases: Vec<Value>,
    reply_configuration_contract: Value,
    owned_agent_authority_contract: Value,
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
        if *vector_id == VECTOR_ID_AGENT_INTERACTION_MODE {
            if fixture.interaction_contract["vector_id"] != *vector_id {
                bail!("interaction contract missing");
            }
            continue;
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

fn fixture_all(row: &Value, keys: &[&str]) -> bool {
    keys.iter().all(|key| row[*key] == true)
}

// These are reference fixture decisions, matching the normative artifact-lint
// models. They do not establish a live Station's authorization or reply readiness.
fn reply_configuration_decision(table: &str, row: &Value) -> Value {
    let all = |keys: &[&str]| fixture_all(row, keys);
    let result = match table {
        "authorization_cases" => {
            return serde_json::json!(
                all(&[
                    "exact_account_scope_binding",
                    "joined",
                    "other_action_gates"
                ]) && (row["actor_root_authority"] == true
                    || row["effective_message_grant"] == true)
            );
        }
        "setup_cases" => match row["intent"].as_str() {
            Some("preference_only" | "mode_only") => "no_grant",
            Some("shared_reply") => {
                if !all(&["exact_account_scope_binding", "global_scope_allows"]) {
                    "blocked"
                } else {
                    match row["grant_state"].as_str() {
                        Some("unknown") => "pending",
                        Some("accepted") => "reuse_grant",
                        Some("refused") => "refused",
                        Some("missing") => {
                            if row["confirmation_is_explicit"] != true {
                                "needs_confirmation"
                            } else if row["verified_owned_source"] == true {
                                if all(&["current_controller_authority", "management_allows"]) {
                                    "publish_grant"
                                } else {
                                    "blocked"
                                }
                            } else if row["issuer_can_grant"] == true {
                                "publish_grant"
                            } else {
                                "requires_issuer"
                            }
                        }
                        _ => "invalid",
                    }
                }
            }
            _ => "invalid",
        },
        "readiness_cases" => {
            let gates = [
                "actor_binding",
                "public_mode",
                "message_authority",
                "content_service_scope",
                "membership_lifecycle",
                "participation_ceiling",
                "runtime_session_key",
                "scope_mls",
            ];
            if row["configuration_accepted"] != true {
                if row["configuration_accepted"].is_null() {
                    "pending"
                } else {
                    "not_configured"
                }
            } else if gates.iter().any(|key| row[*key] == false) {
                "blocked"
            } else if !all(&gates) {
                "pending"
            } else {
                "ready"
            }
        }
        "recovery_cases" => match row["kind"].as_str() {
            Some("unknown_submission") => "retain_exact_pending_submission",
            Some("refused_submission") => "new_request_after_authority_repair",
            kind => {
                if kind == Some("reset")
                    || !all(&["same_account_scope_binding", "active_message_grant"])
                {
                    "needs_new_confirmation"
                } else {
                    match kind {
                        Some("restart") => "reuse_grant",
                        Some("endpoint_replacement") => "reuse_grant_restore_endpoint",
                        _ => "invalid",
                    }
                }
            }
        },
        _ => "invalid",
    };
    serde_json::json!(result)
}

fn owned_agent_reference_decision<'a>(row: &'a Value, registry: &Value) -> Result<&'a str> {
    if row["accepted_identity"] == true {
        return Ok("reuse_accepted");
    }
    if !fixture_all(row, &["signing_eligible", "exact_account_binding"]) {
        return Ok("deny");
    }
    let operation = required_str(row, "operation")?;
    if operation == "revoke" {
        return Ok(
            if fixture_all(
                row,
                &[
                    "owned_source",
                    "original_issuer",
                    "target_present",
                    "exact_revision",
                ],
            ) {
                "allow"
            } else {
                "deny"
            },
        );
    }
    if !fixture_all(row, &["current_evidence", "management_evidence"]) {
        return Ok("pending");
    }
    if operation == "authorize"
        && (!registry["supported_actions"]
            .as_array()
            .is_some_and(|actions| actions.contains(&row["action"]))
            || !fixture_all(row, &["explicit_confirmation", "terminal_source"])
            || row["controller_is_agent"] == true)
    {
        return Ok("deny");
    }
    let rules = row["management_rules"]
        .as_array()
        .ok_or_else(|| anyhow!("management rule cases missing"))?;
    let mut effects = BTreeSet::new();
    for rule in rules {
        if !rule["operations"]
            .as_array()
            .is_some_and(|operations| operations.contains(&row["operation"]))
        {
            continue;
        }
        let target = &rule["target"];
        if (target["kind"] == "controller" && target["account_id"] != row["controller_account_id"])
            || (target["kind"] == "agent" && target["account_id"] != row["agent_account_id"])
            || rule["actions"]
                .as_array()
                .is_some_and(|actions| !actions.is_empty() && !actions.contains(&row["action"]))
        {
            continue;
        }
        effects.insert(required_str(rule, "effect")?);
    }
    for effect in ["deny", "quarantine", "require_review"] {
        if effects.contains(effect) {
            return Ok(effect);
        }
    }
    if operation == "join" {
        return Ok(
            if fixture_all(
                row,
                &[
                    "controller_join_active",
                    "agent_binding_valid",
                    "agent_action_gates",
                ],
            ) {
                "allow"
            } else {
                "deny"
            },
        );
    }
    Ok(
        if fixture_all(
            row,
            &[
                "controller_join_active",
                "agent_binding_valid",
                "controller_permission",
                "whole_allow_path",
                "identity_conditions_preserved",
                "scope_within_confirmation",
                "global_key_ceiling",
                "agent_action_gates",
                "parent_quota_available",
            ],
        ) && row["matched_global_deny"] != true
            && row["grant_terminal"] != true
        {
            "allow"
        } else {
            "deny"
        },
    )
}

fn validate_case_names(rows: &[Value], count: usize) -> Result<BTreeSet<&str>> {
    let names = rows
        .iter()
        .map(|row| required_str(row, "name"))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        rows.len() == count && names.len() == count,
        "case ledger omitted or duplicated a boundary"
    );
    Ok(names)
}

fn validate_extended_contracts(fixture: &AgentParticipationFixture) -> Result<()> {
    validate_case_names(&fixture.runtime_access_cases, 11)?;
    for row in &fixture.runtime_access_cases {
        let allow = row["role"] == "target"
            && row["selection_source"] == "authenticated_owner_current"
            && fixture_all(
                row,
                &[
                    "same_station",
                    "current_selection",
                    "complete_governance_cut",
                    "exact_binding",
                    "selection_bit",
                    "ceiling_bit",
                ],
            );
        ensure!(
            row["expected"] == if allow { "allow" } else { "deny" },
            "runtime participation case {} drifted",
            row["name"]
        );
    }
    let reply = &fixture.reply_configuration_contract;
    ensure!(
        reply["registry_ref"]
            == "registry/contract-registry.json#/did_evidence_boundary_registry/agent_participation_runtime_contract/product_configuration"
            && reply["vector_id"] == VECTOR_ID_AGENT_INTERACTION_MODE,
        "reply configuration contract binding drifted"
    );
    for (table, count) in [
        ("authorization_cases", 9),
        ("setup_cases", 12),
        ("readiness_cases", 19),
        ("recovery_cases", 7),
    ] {
        let rows = reply[table]
            .as_array()
            .ok_or_else(|| anyhow!("reply {table} missing"))?;
        validate_case_names(rows, count)?;
        for row in rows {
            ensure!(
                row["expected"] == reply_configuration_decision(table, row),
                "reply {table} case {} drifted",
                row["name"]
            );
        }
    }
    let owned = &fixture.owned_agent_authority_contract;
    ensure!(
        owned["registry_ref"] == "registry/owned-agent-authority-registry.json"
            && owned["vector_id"] == VECTOR_ID_AGENT_INTERACTION_MODE,
        "owned Agent registry binding drifted"
    );
    let registry = super::load_artifact_json("registry/owned-agent-authority-registry.json")?;
    ensure!(
        registry["fixture_ref"]
            == "fixtures/agent-participation-fixture.json#/owned_agent_authority_contract"
    );
    let rows = owned["cases"]
        .as_array()
        .ok_or_else(|| anyhow!("owned Agent cases missing"))?;
    let names = validate_case_names(rows, 63)?;
    let required = owned["required_case_names"]
        .as_array()
        .ok_or_else(|| anyhow!("owned Agent required cases missing"))?;
    let required = required
        .iter()
        .map(|name| {
            name.as_str()
                .ok_or_else(|| anyhow!("invalid required case name"))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        names == required,
        "owned Agent required case ledger drifted"
    );
    for row in rows {
        ensure!(
            row["expected"] == owned_agent_reference_decision(row, &registry)?,
            "owned Agent case {} drifted",
            row["name"]
        );
    }
    let schema_env = SchemaEnv::load()?;
    let schema_cases = owned["schema_cases"]
        .as_array()
        .ok_or_else(|| anyhow!("owned Agent schema cases missing"))?;
    validate_case_names(schema_cases, 19)?;
    for row in schema_cases {
        let schema_ref = format!(
            "{}{}",
            required_str(row, "schema_file")?,
            required_str(row, "fragment")?
        );
        let instance: Value = serde_json::from_str(required_str(row, "canonical_json")?)?;
        ensure!(
            Some(schema_env.compile(&schema_ref)?.is_valid(&instance)) == row["valid"].as_bool(),
            "owned Agent schema case {} drifted",
            row["name"]
        );
    }
    let quota = &owned["quota_sequence"];
    let limit = required_u64(quota, "limit")?;
    let mut counts = BTreeMap::<(String, String, u64), u64>::new();
    let mut identities = BTreeSet::new();
    let mut verdicts = Vec::new();
    for request in quota["requests"]
        .as_array()
        .ok_or_else(|| anyhow!("quota requests missing"))?
    {
        let key = (
            required_str(request, "parent_grant")?.to_owned(),
            required_str(request, "controller_account")?.to_owned(),
            required_u64(request, "window")?,
        );
        let identity = required_str(request, "event_id")?;
        let count = counts.entry(key).or_default();
        verdicts.push(if identities.contains(identity) {
            "reuse_accepted"
        } else if *count >= limit {
            "deny"
        } else {
            identities.insert(identity);
            *count += 1;
            "allow"
        });
    }
    ensure!(
        counts.len() == 1 && serde_json::to_value(verdicts)? == quota["expected"],
        "parent quota sharing or accepted retry identity drifted"
    );
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

fn selector_value(subject_account_id: AccountId) -> AgentSelectorClaimValue {
    AgentSelectorClaimValue {
        subject_account_id,
        visibility: HandleVisibility::Restricted,
        audience: Some("ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1".to_owned()),
    }
}

/// Label verification for a known-Agent picker. The mention target is always
/// the exact full Agent AccountId an authorized source already supplied; the
/// provision-written selector value can only verify the label shown for that
/// target. It verifies only when exactly one current value is visible and its
/// `subject_account_id` equals the known target over both components.
#[derive(Debug, Eq, PartialEq)]
enum SelectorLabel {
    Verified,
    Unverified,
}

fn verify_selector_label(known: &AccountId, visible: &[AgentSelectorClaimValue]) -> SelectorLabel {
    if arkret_models_identity::claim_presentation::agent_selector_matches_known_account(
        known, visible,
    ) {
        SelectorLabel::Verified
    } else {
        SelectorLabel::Unverified
    }
}

fn run_mention_composer_contract(vector: &Value, known: &AccountId) -> Result<()> {
    let contract = vector
        .get("composer_contract")
        .ok_or_else(|| anyhow!("composer contract missing"))?;
    let token = required_str(contract, "selected_input")?;
    let draft = format!("ask {token}");
    let mut binding =
        MentionDraftBinding::new(known.clone(), 4, draft.len(), token.to_owned(), &draft)
            .ok_or_else(|| anyhow!("selected token did not bind"))?;
    if binding.subject_account_id != *known
        || required_str(contract, "selected_target_source")? != "known_authorized_agent_account_id"
    {
        bail!("selected token retargeted the known AccountId");
    }
    let edited = format!("ask {token}-extra then {token}");
    if binding.rebase(&draft, &edited) || required_u64(contract, "edited_token_binding_count")? != 0
    {
        bail!("edited token retained or revived its binding");
    }
    let raw =
        serde_json::json!({"kind":"text", "text": required_str(contract, "unselected_input")?});
    if !arkret_models_collaboration::events_payloads::mention::collect_mention_nodes(&raw)
        .map_err(|error| anyhow!("{error:?}"))?
        .is_empty()
        || required_u64(contract, "unselected_target_count")? != 0
    {
        bail!("unselected input created a mention");
    }
    let private_holder = required_str(contract, "private_holder_label")?;
    let shared_holder = required_str(contract, "shared_holder_label")?;
    let labels = AgentMentionLabels::new(shared_holder, Some(private_holder), false, "summary");
    if labels.shared != format!("{shared_holder}/summary") || labels.shared.contains(private_holder)
    {
        bail!("private holder label leaked into shared output");
    }
    let routes = contract
        .get("routing_cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("routing cases missing"))?;
    validate_case_names(routes, 15)?;
    for row in routes {
        let scope = match required_str(row, "scope")? {
            "realm" => AgentMentionComposerScope::Realm,
            "circle" => AgentMentionComposerScope::Circle,
            "direct" => AgentMentionComposerScope::Direct,
            "sidecar" => AgentMentionComposerScope::Sidecar,
            other => bail!("unknown composer scope {other}"),
        };
        let mode = match required_str(row, "interaction_mode")? {
            "public" => {
                Some(arkret_models_collaboration::agent_interaction::AgentInteractionMode::Public)
            }
            "private" => {
                Some(arkret_models_collaboration::agent_interaction::AgentInteractionMode::Private)
            }
            "unknown" => None,
            other => bail!("unknown interaction mode {other}"),
        };
        let boolean = |key: &str| {
            row.get(key)
                .and_then(Value::as_bool)
                .ok_or_else(|| anyhow!("routing boolean missing {key}"))
        };
        // Only a currently bound owned token supplies an Agent mode. Previous
        // sidecar sessions and restored history cannot supply a removed token.
        let modes = if boolean("owned")? && row["token_bound"] != false {
            vec![mode]
        } else {
            Vec::new()
        };
        let actual =
            agent_mention_route_with_modes(scope, &modes, boolean("other")?, boolean("audience")?);
        let expected = match required_str(row, "expected")? {
            "shared" => AgentMentionRoute::Shared,
            "direct" => AgentMentionRoute::Direct,
            "sidecar" => AgentMentionRoute::Sidecar,
            "blocked" => AgentMentionRoute::BlockedMixedPrivateTargets,
            other => bail!("unknown composer expected route {other}"),
        };
        if actual != expected {
            bail!("composer route mismatch: {row}");
        }
    }
    Ok(())
}

/// Persist a known-Agent mention. The target is the known AccountId whatever
/// the label verdict; a verified label only adds audit metadata.
fn known_agent_mention(
    known: &AccountId,
    label: &SelectorLabel,
    controller: &AccountId,
    slug: &str,
) -> Mention {
    let mut mention = Mention::new(known.clone());
    if *label == SelectorLabel::Verified {
        mention.controller_subject_account_id = Some(controller.clone());
        mention.agent_slug_at_time = Some(slug.to_owned());
    }
    mention
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

pub fn run_agent_selector_label_known_account_vector() -> Result<()> {
    let fixture = participation_fixture()?;
    let vector = case(&fixture, VECTOR_ID_AGENT_SELECTOR_LABEL_KNOWN_ACCOUNT)?;
    if expected_str(vector, "mention_target_source")? != "known_authorized_agent_account_id" {
        bail!("mention target source drifted from the known authorized Agent AccountId");
    }
    let known = account_pointer(vector, "/known_authorized_agent_account_id")?;
    let expected_subject = account_pointer(vector, "/persisted_mention/subject_account_id")?;
    let expected_controller =
        account_pointer(vector, "/persisted_mention/controller_subject_account_id")?;
    if expected_subject != known {
        bail!("persisted mention target is not the known authorized Agent AccountId");
    }

    // The Agent Station is derived from the accepted provision reconciled with
    // the Agent PCR genesis actor account, never asserted by the consumer.
    let genesis_account = account_pointer(
        vector,
        "/agent_provision/agent_pcr_genesis_actor_account_id",
    )?;
    let provision_agent = DidCoreId::new(
        vector
            .pointer("/agent_provision/payload_agent_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("agent_provision.payload_agent_id missing"))?,
    )?;
    if genesis_account.principal_id != provision_agent || genesis_account != known {
        bail!("known Agent AccountId is not the provision reconciled with its PCR genesis");
    }

    // Exactly one current selector value that names the known target verifies
    // the label.
    let claim_subject = account_pointer(vector, "/selector_claim/subject_account_id")?;
    let claim = selector_value(claim_subject);
    let label = verify_selector_label(&known, std::slice::from_ref(&claim));
    let disclosure_matches = vector
        .pointer("/selector_claim_disclosure/target_matches_known_account")
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("selector_claim_disclosure.target_matches_known_account missing"))?;
    if (label == SelectorLabel::Verified) != disclosure_matches {
        bail!("selector label verdict disagrees with the fixture disclosure");
    }
    let slug = required_str(vector, "agent_slug_at_time")?;
    let mention = known_agent_mention(&known, &label, &expected_controller, slug);
    let node = MentionNode::mention(mention.clone());
    if mention.subject_account_id != expected_subject
        || node.target() != MentionTarget::Subject(&expected_subject)
        || mention.controller_subject_account_id.as_ref() != Some(&expected_controller)
        || mention.agent_slug_at_time.as_deref() != Some(slug)
        || mention.mention_text_original.is_some()
    {
        bail!("verified known-Agent mention drifted from the persisted fixture mention");
    }

    // A value naming the same principal on another Station never verifies the
    // label for the known target; the mention target does not move.
    let retargeted = selector_value(AccountId::new(
        known.principal_id.clone(),
        DidCoreId::new("ak:did_core:web:other.example")?,
    ));
    if expected_str(vector, "claim_not_equal_to_known_account")? != "reject_label"
        || verify_selector_label(&known, std::slice::from_ref(&retargeted))
            != SelectorLabel::Unverified
    {
        bail!("a claim naming another account verified the known-Agent label");
    }

    // Two current claims for the same principal on two Stations are never
    // deduplicated: the label stays unverified and no target is selected.
    if expected_str(vector, "two_current_claims_same_principal_two_stations")?
        != "unverified_label_no_target_selection"
        || verify_selector_label(&known, &[claim.clone(), retargeted.clone()])
            != SelectorLabel::Unverified
    {
        bail!("ambiguous selector claims verified a label");
    }
    let changed_subject = AccountId::new(
        did_field(vector, "changed_agent_subject")?,
        known.station_id.clone(),
    );
    let changed = selector_value(changed_subject);
    let ambiguous = verify_selector_label(&known, &[claim.clone(), changed.clone()]);
    if expected_str(vector, "ambiguous_label")? != "unverified_label_without_retargeting"
        || ambiguous != SelectorLabel::Unverified
        || known_agent_mention(&known, &ambiguous, &expected_controller, slug).subject_account_id
            != known
    {
        bail!("ambiguous label verified or retargeted the known-Agent mention");
    }
    let unavailable = verify_selector_label(&known, &[]);
    let unlabelled = known_agent_mention(&known, &unavailable, &expected_controller, slug);
    if expected_str(vector, "unavailable_label")? != "ordinary_known_account_mention_unaffected"
        || unavailable != SelectorLabel::Unverified
        || unlabelled != Mention::new(known.clone())
    {
        bail!("an unavailable label changed the ordinary known-account mention");
    }

    // Slug changes do not rewrite the historical target.
    if changed.subject_account_id == mention.subject_account_id
        || mention.subject_account_id
            != account_pointer(vector, "/expected/historical_target_after_slug_change")?
    {
        bail!("historical mention target was rewritten after slug change");
    }

    // Free-text composite input is plain text: no mention node is produced.
    let free_text = required_str(vector, "unsupported_free_text_input")?;
    if expected_str(vector, "free_text_composite_input")?
        != "plain_text_no_mention_no_directed_notification"
    {
        bail!("free-text composite input semantics drifted");
    }
    let plain_body = serde_json::json!({
        "kind": "paragraph",
        "children": [{ "kind": "text", "text": free_text }]
    });
    if !arkret_models_collaboration::events_payloads::mention::collect_mention_nodes(&plain_body)
        .map_err(|error| anyhow!("{error:?}"))?
        .is_empty()
    {
        bail!("free-text composite selector produced a mention node");
    }

    // A same-principal account on another Station never matches the mention.
    let other_station = account_pointer(vector, "/expected/same_principal_other_station_account")?;
    if expected_bool(vector, "same_principal_other_station_matches")? {
        bail!("fixture must assert that a same-principal other-Station account does not match");
    }
    if other_station.principal_id != known.principal_id
        || other_station.station_id == known.station_id
        || other_station == mention.subject_account_id
        || MentionTarget::Subject(&other_station) == node.target()
    {
        bail!("mention target equality MUST cover principal_id and station_id");
    }
    let roster = vec![
        ActorId::account(known.clone()),
        ActorId::account(other_station.clone()),
        ActorId::service(DidCoreId::new("ak:did_core:web:station.acme.example")?),
    ];
    let joined = member_identity_join(&roster, &mention.subject_account_id);
    if joined != vec![&roster[0]] {
        bail!("§3.8.2 MemberIdentity join MUST select only the addressed account; got {joined:?}");
    }
    run_mention_composer_contract(vector, &known)?;
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

pub fn run_agent_interaction_mode_vector() -> Result<()> {
    use arkret_models_collaboration::agent_interaction::agent_interaction_from_verified_exact_read;
    use arkret_models_collaboration::exact_current_results::{
        ExactCurrentResultSelector, ExactCurrentResultsReadOutcome,
        ExactCurrentResultsReadRequestBody,
    };
    let participation = participation_fixture()?;
    let contract = &participation.interaction_contract;
    if required_str(contract, "vector_id")? != "ak.vector.agent.interaction_mode.v1"
        || !participation
            .covers_vectors
            .iter()
            .any(|id| id == "ak.vector.agent.interaction_mode.v1")
    {
        bail!("mode vector metadata missing");
    }
    let exact = super::load_fixture_value("exact-current-results-read-fixture.json")?;
    let cases = exact["schema_validation_cases"]
        .as_array()
        .ok_or_else(|| anyhow!("exact cases missing"))?;
    let instance = |name: &str| -> Result<Value> {
        Ok(cases
            .iter()
            .find(|c| c["name"] == name)
            .ok_or_else(|| anyhow!("missing {name}"))?["instance"]
            .clone())
    };
    let request: ExactCurrentResultsReadRequestBody =
        serde_json::from_value(instance("agent_mode_exact_request")?)?;
    let ExactCurrentResultSelector::AgentInteraction(selector) = &request.selector else {
        bail!("wrong mode selector");
    };
    let base = instance("agent_mode_present")?;
    let controller: AccountId =
        serde_json::from_value(base["entry"]["value"]["controller_account_id"].clone())?;
    let rows = contract["mode_cases"]
        .as_array()
        .ok_or_else(|| anyhow!("mode cases missing"))?;
    if rows.len() != 6 {
        bail!("incomplete mode cases");
    }
    for row in rows {
        let status = required_str(row, "status")?;
        let actual = if status == "missing" {
            "unknown".to_owned()
        } else {
            let mut value = if status == "never_written" {
                instance("agent_mode_never_written")?
            } else {
                base.clone()
            };
            if status == "present" {
                value["entry"]["value"]["interaction_mode"] = row["mode"].clone();
            }
            let outcome: ExactCurrentResultsReadOutcome = serde_json::from_value(value)?;
            let owner = if row["binding_valid"] == false {
                &selector.agent_account_id
            } else {
                &controller
            };
            match agent_interaction_from_verified_exact_read(
                &outcome,
                &request.realm_id,
                &selector.agent_account_id,
                owner,
                if status == "stale" { 5 } else { 4 },
            ) {
                Ok((
                    arkret_models_collaboration::agent_interaction::AgentInteractionMode::Public,
                    _,
                )) => "public".to_owned(),
                Ok(_) => "private".to_owned(),
                Err(_) => "unknown".to_owned(),
            }
        };
        if actual != required_str(row, "expected")? {
            bail!("mode observation mismatch: {row}");
        }
    }
    Ok(())
}

pub fn run_agent_participation_fixture_suite() -> Result<()> {
    validate_extended_contracts(&participation_fixture()?)?;
    if ALL_AGENT_PARTICIPATION_VECTOR_IDS.len() != 7 {
        bail!(
            "expected 7 agent participation vector ids, got {}",
            ALL_AGENT_PARTICIPATION_VECTOR_IDS.len()
        );
    }

    run_agent_interaction_mode_vector()?;
    run_agent_selector_label_known_account_vector()?;
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
    fn extended_contracts_reject_changed_verdicts_and_schema_expectations() {
        for pointer in [
            "/runtime_access_cases/0/expected",
            "/reply_configuration_contract/authorization_cases/0/expected",
            "/reply_configuration_contract/readiness_cases/0/expected",
            "/owned_agent_authority_contract/cases/0/expected",
            "/owned_agent_authority_contract/schema_cases/0/valid",
            "/owned_agent_authority_contract/quota_sequence/expected/0",
        ] {
            let mut value =
                super::super::load_fixture_value(AGENT_PARTICIPATION_FIXTURE_FILE).unwrap();
            let expected = value.pointer_mut(pointer).unwrap();
            *expected = match expected.as_bool() {
                Some(value) => Value::Bool(!value),
                None => Value::String("incorrect_verdict".to_owned()),
            };
            let fixture: AgentParticipationFixture = serde_json::from_value(value).unwrap();
            assert!(
                validate_extended_contracts(&fixture).is_err(),
                "ignored {pointer}"
            );
        }
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
