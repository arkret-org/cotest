//! Cotest-local privacy and direct-conversation contract vectors.
//!
//! These are fixture-driven, schema-adjacent checks for behavior that is
//! currently specified in prose/artifacts but not yet backed by a live
//! cross-service e2e harness.

use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use arkret_identifiers::{EventId, RealmId, StrandId};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{load_artifact_json, load_local_fixture_value};
use crate::transcripts::record_vector_event;

const FIXTURE_FILE: &str = "private_chat_privacy_contracts.json";
const REALM_REMARK_KEY_PREFIX: &str = "ak.contacts.realm.";

#[derive(Debug, Deserialize)]
struct PrivateChatPrivacyFixture {
    suite: String,
    version: u32,
    account_data_cases: AccountDataCases,
    privacy_payload_vectors: Vec<PrivacyPayloadVector>,
    direct_conversation_vectors: DirectConversationVectors,
}

#[derive(Debug, Deserialize)]
struct AccountDataCases {
    positive: AccountDataCase,
    negative: AccountDataCase,
}

#[derive(Debug, Deserialize)]
struct AccountDataCase {
    name: String,
    key: String,
    payload: Value,
    expect_valid: bool,
    #[serde(default)]
    expected_error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PrivacyPayloadVector {
    name: String,
    surface: String,
    payload: Value,
    forbidden_fields: Vec<String>,
    forbidden_literals: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DirectConversationVectors {
    trust_domain: String,
    resolve_request: Value,
    resolve_creation_required_response: Value,
    resolve_response: Value,
    binding_event_ref: String,
    binding_payload: Value,
    contact_list_row: Value,
    derived_strand_selection: DerivedStrandSelection,
    pending_contact_negative: PendingContactNegative,
}

#[derive(Debug, Deserialize)]
struct DerivedStrandSelection {
    realm_id: String,
    binding_main_strand_id: String,
    default_strand_id_for_realm: String,
    selected_main_strand_id: String,
}

#[derive(Debug, Deserialize)]
struct PendingContactNegative {
    name: String,
    contact_row: Value,
    resolve_request: Value,
    expected_error: ExpectedError,
    observed_response: Value,
}

#[derive(Debug, Deserialize)]
struct ExpectedError {
    error_code: String,
    reason_code: String,
}

pub fn run_private_chat_privacy_contract_suite() -> Result<()> {
    validate_realm_remark_registry()?;
    validate_direct_conversation_artifacts()?;
    validate_direct_conversation_founder_derivation()?;

    let value = load_local_fixture_value(FIXTURE_FILE)?;
    let fixture: PrivateChatPrivacyFixture = serde_json::from_value(value)
        .map_err(|err| anyhow!("failed to parse {FIXTURE_FILE}: {err}"))?;

    if fixture.suite != "private_chat_privacy_contracts" {
        bail!("unexpected fixture suite `{}`", fixture.suite);
    }
    if fixture.version != 1 {
        bail!("unexpected fixture version `{}`", fixture.version);
    }

    validate_account_data_case(&fixture.account_data_cases.positive)?;
    validate_account_data_case(&fixture.account_data_cases.negative)?;
    validate_privacy_payload_vectors(&fixture.privacy_payload_vectors)?;
    validate_direct_conversation_vectors(&fixture.direct_conversation_vectors)?;

    Ok(())
}

fn validate_realm_remark_registry() -> Result<()> {
    let registry = load_artifact_json("registry/account-data-key-registry.json")?;
    let entry = registry
        .get("account_data_key_patterns")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|entry| {
            entry.get("key_pattern").and_then(Value::as_str) == Some("ak.contacts.realm.<realm_id>")
        })
        .ok_or_else(|| anyhow!("account-data registry missing ak.contacts.realm.<realm_id>"))?;

    if entry.get("storage").and_then(Value::as_str) != Some("encrypted_account_data") {
        bail!("ak.contacts.realm.<realm_id> must stay encrypted account data");
    }
    if entry.get("scope").and_then(Value::as_str) != Some("realm_private_preference") {
        bail!("ak.contacts.realm.<realm_id> scope drifted from realm_private_preference");
    }
    let writers = entry
        .get("write_event_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("ak.contacts.realm.<realm_id> missing write_event_kinds"))?;
    if !writers
        .iter()
        .any(|writer| writer.as_str() == Some("ak.account_data.set"))
    {
        bail!("ak.contacts.realm.<realm_id> must be written by ak.account_data.set");
    }

    record_vector_event(
        "private_chat_privacy.realm_remark_registry",
        &json!({"key_pattern": "ak.contacts.realm.<realm_id>"}),
        &json!({
            "storage": "encrypted_account_data",
            "scope": "realm_private_preference",
            "writer": "ak.account_data.set",
        }),
        &json!({
            "storage": entry.get("storage").cloned(),
            "scope": entry.get("scope").cloned(),
            "write_event_kinds": entry.get("write_event_kinds").cloned(),
        }),
    );
    Ok(())
}

/// Founder derivation is the whole reason the cross-server creation race disappears, so it is
/// checked as a conformance property rather than only in SDK unit tests.
///
/// The normal branch resolves to the **responder**, not the request issuer. That is normative: the
/// basis is lit up by the responder's acceptance receipt, which proves the responder was online
/// when it came into existence, while the requester may have gone offline days earlier. Base v1
/// defines no fallback, so naming the possibly-absent party would leave the pair unable to ever
/// create.
fn validate_direct_conversation_founder_derivation() -> Result<()> {
    use arkret_models_collaboration::objects::direct_conversation::{
        DirectConversationFounderBasis, direct_conversation_founder, direct_conversation_may_found,
    };

    let alice = arkret_identifiers::Did::new("did:webvh:z6mkcotest:alice.example".to_owned())?;
    let bob = arkret_identifiers::Did::new("did:webvh:z6mkcotest:bob.example".to_owned())?;
    let carol = arkret_identifiers::Did::new("did:webvh:z6mkcotest:carol.example".to_owned())?;

    // A requests, B accepts -> B founds.
    let normal = DirectConversationFounderBasis::Normal {
        request_issuer: alice.clone(),
    };
    let founder = direct_conversation_founder([alice.clone(), bob.clone()], &normal)?;
    if founder != bob {
        bail!("normal basis founder must be the responder, not the request issuer");
    }
    // Argument order must not matter: both sides compute the same answer independently.
    if direct_conversation_founder([bob.clone(), alice.clone()], &normal)? != bob {
        bail!("founder derivation is not order independent");
    }
    // The non-founder may never author the founding unit, no matter how long it waits.
    if direct_conversation_may_found(&alice, [alice.clone(), bob.clone()], &normal)? {
        bail!("the request issuer must not be able to found the conversation");
    }

    // Glare: no responder exists, so the requests[0] issuer founds.
    let glare = DirectConversationFounderBasis::Glare {
        first_request_issuer: alice.clone(),
    };
    if direct_conversation_founder([alice.clone(), bob.clone()], &glare)? != alice {
        bail!("glare basis founder must be the requests[0] issuer");
    }

    // controller-to-own-Agent is fixed to the controller regardless of DID ordering, so an Agent
    // runtime key never needs Direct Conversation founding scope.
    let agent = DirectConversationFounderBasis::ControllerOwnedAgent {
        controller_id: alice.clone(),
    };
    if direct_conversation_founder([bob.clone(), alice.clone()], &agent)? != alice {
        bail!("controller-owned-Agent founder must be the controller");
    }

    // Malformed inputs fail closed instead of guessing the complement.
    if direct_conversation_founder(
        [alice.clone(), bob.clone()],
        &DirectConversationFounderBasis::Normal {
            request_issuer: carol,
        },
    )
    .is_ok()
    {
        bail!("a request issuer outside the pair must not derive a founder");
    }
    if direct_conversation_founder(
        [alice.clone(), alice.clone()],
        &DirectConversationFounderBasis::Normal {
            request_issuer: alice,
        },
    )
    .is_ok()
    {
        bail!("a degenerate pair must not derive a founder");
    }

    record_vector_event(
        "private_chat_privacy.direct_conversation_founder_derivation",
        &json!({
            "normal": {"request_issuer": "alice", "participants": ["alice", "bob"]},
            "glare": {"first_request_issuer": "alice"},
            "controller_owned_agent": {"controller": "alice"}
        }),
        &json!({
            "normal_founder": "responder",
            "glare_founder": "requests[0]_issuer",
            "controller_owned_agent_founder": "controller",
            "non_founder_may_found": false,
            "timeout_grants_create_authority": false,
            "issuer_outside_pair": "rejected",
            "degenerate_pair": "rejected"
        }),
        &json!({
            "normal_founder": "bob",
            "glare_founder": "alice",
            "controller_owned_agent_founder": "alice"
        }),
    );
    Ok(())
}

fn validate_direct_conversation_artifacts() -> Result<()> {
    let operation = arkret_wire::ServiceOperationId::from_wire(
        arkret_wire::ServiceOperationId::SELF_DIRECT_CONVERSATION_QUERY_RESOLVE,
    )
    .ok_or_else(|| anyhow!("SDK missing direct conversation resolve operation"))?
    .descriptor();
    if operation.http_method != "POST"
        || operation.http_path != "/_arkret/self/direct-conversations/resolve"
    {
        bail!("direct conversation resolver HTTP binding drifted");
    }
    if operation.request_schema_ref
        != Some(
            "schemas/direct-conversation-operations.schema.json#/$defs/direct_conversation_resolve_request",
        )
    {
        bail!("direct conversation request schema ref drifted");
    }
    if operation.response_schema_ref
        != Some(
            "schemas/direct-conversation-operations.schema.json#/$defs/direct_conversation_resolve_outcome",
        )
    {
        bail!("direct conversation response schema ref drifted");
    }

    record_vector_event(
        "private_chat_privacy.direct_conversation_artifacts",
        &json!({"operation_id": "ak.self.direct_conversation.query.resolve"}),
        &json!({
            "http": "POST /_arkret/self/direct-conversations/resolve",
            "request_field": "peer",
            "response_field": "state",
            "binding_field": "binding_event_ref",
            "main_strand_id_from_binding": true,
        }),
        &json!({
            "http": format!("{} {}", operation.http_method, operation.http_path),
            "request_schema_ref": operation.request_schema_ref,
            "response_schema_ref": operation.response_schema_ref,
        }),
    );
    Ok(())
}

fn validate_account_data_case(case: &AccountDataCase) -> Result<()> {
    let outcome = validate_realm_remark_entry(&case.key, &case.payload);
    let actual_valid = outcome.is_ok();
    record_vector_event(
        &format!("private_chat_privacy.account_data.{}", case.name),
        &json!({"key": &case.key, "payload": &case.payload}),
        &json!({
            "valid": case.expect_valid,
            "expected_error": &case.expected_error,
        }),
        &json!({
            "valid": actual_valid,
            "error": outcome.as_ref().err().map(|err| err.to_string()),
        }),
    );

    match (case.expect_valid, outcome) {
        (true, Ok(())) | (false, Err(_)) => Ok(()),
        (true, Err(err)) => bail!("account-data case `{}` rejected: {err}", case.name),
        (false, Ok(())) => bail!(
            "account-data negative case `{}` was accepted; expected {:?}",
            case.name,
            case.expected_error
        ),
    }
}

fn validate_realm_remark_entry(key: &str, payload: &Value) -> Result<()> {
    let realm_id = key
        .strip_prefix(REALM_REMARK_KEY_PREFIX)
        .ok_or_else(|| anyhow!("realm_remark_key_namespace_mismatch"))?;
    RealmId::new(realm_id).map_err(|_| anyhow!("realm_remark_key_invalid_realm_id"))?;

    let subject = payload
        .get("subject")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("realm_remark_subject_missing"))?;
    if subject.get("kind").and_then(Value::as_str) != Some("realm") {
        bail!("realm_remark_subject_kind_mismatch");
    }
    let subject_id = subject
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("realm_remark_subject_id_missing"))?;
    if subject_id != realm_id {
        bail!("realm_remark_subject_mismatch");
    }
    if !matches!(payload.get("pinned"), Some(Value::Bool(_))) {
        bail!("realm_remark_pinned_must_be_bool");
    }
    Ok(())
}

fn validate_privacy_payload_vectors(vectors: &[PrivacyPayloadVector]) -> Result<()> {
    if vectors.is_empty() {
        bail!("privacy payload vectors must not be empty");
    }
    for vector in vectors {
        if !matches!(
            vector.surface.as_str(),
            "directory_projection" | "bridge_payload" | "push_payload"
        ) {
            bail!(
                "privacy vector `{}` uses unknown surface `{}`",
                vector.name,
                vector.surface
            );
        }
        for field in &vector.forbidden_fields {
            if contains_key_recursive(&vector.payload, field) {
                bail!(
                    "privacy vector `{}` leaked forbidden field `{field}`",
                    vector.name
                );
            }
        }
        for literal in &vector.forbidden_literals {
            if contains_literal_recursive(&vector.payload, literal) {
                bail!(
                    "privacy vector `{}` leaked forbidden literal `{literal}`",
                    vector.name
                );
            }
        }
        record_vector_event(
            &format!("private_chat_privacy.payload.{}", vector.name),
            &json!({"surface": &vector.surface, "payload": &vector.payload}),
            &json!({
                "forbidden_fields_absent": true,
                "forbidden_literals_absent": true,
            }),
            &json!({
                "surface": &vector.surface,
                "forbidden_fields": &vector.forbidden_fields,
                "forbidden_literals": &vector.forbidden_literals,
            }),
        );
    }
    Ok(())
}

fn validate_direct_conversation_vectors(vectors: &DirectConversationVectors) -> Result<()> {
    validate_resolve_request_shape(&vectors.resolve_request)?;
    validate_resolve_response_shape(&vectors.resolve_creation_required_response)?;
    validate_resolve_response_shape(&vectors.resolve_response)?;
    validate_binding_payload(
        &vectors.trust_domain,
        &vectors.binding_event_ref,
        &vectors.binding_payload,
    )?;
    validate_resolver_uses_binding_main_strand(vectors)?;
    validate_contact_list_row(vectors)?;
    validate_pending_contact_negative(&vectors.pending_contact_negative)?;
    validate_schema_negative_shapes(&vectors.resolve_request, &vectors.resolve_response)?;

    record_vector_event(
        "private_chat_privacy.direct_conversation_vectors",
        &json!({
            "request": &vectors.resolve_request,
            "creation_required_response": &vectors.resolve_creation_required_response,
            "response": &vectors.resolve_response,
            "binding_event_ref": &vectors.binding_event_ref,
        }),
        &json!({
            "request_peer_field": true,
            "response_state_field": true,
            "binding_main_strand_used": true,
            "pending_contact_no_realm_created": true,
        }),
        &json!({
            "response_state": vectors.resolve_response.get("state").cloned(),
            "response_main_strand_id": vectors.resolve_response.pointer("/coordinates/main_strand_id").cloned(),
            "binding_main_strand_id": vectors.binding_payload.get("main_strand_id").cloned(),
        }),
    );
    Ok(())
}

fn validate_resolve_request_shape(value: &Value) -> Result<()> {
    let env = crate::conformance::schema_validation_fixture::SchemaEnv::load()?;
    let validator = env.compile(
        "schemas/direct-conversation-operations.schema.json#/$defs/direct_conversation_resolve_request",
    )?;
    if !validator.is_valid(value) {
        let detail = validator
            .iter_errors(value)
            .map(|error| format!("{}: {error}", error.instance_path()))
            .collect::<Vec<_>>()
            .join("; ");
        bail!(
            "direct conversation request does not match the canonical operation schema: {detail}"
        );
    }
    serde_json::from_value::<
        arkret_models_collaboration::direct_conversation_ops::DirectConversationResolveRequestBody,
    >(value.clone())?;
    Ok(())
}

fn validate_resolve_response_shape(value: &Value) -> Result<()> {
    let env = crate::conformance::schema_validation_fixture::SchemaEnv::load()?;
    let validator = env.compile(
        "schemas/direct-conversation-operations.schema.json#/$defs/direct_conversation_resolve_outcome",
    )?;
    if !validator.is_valid(value) {
        let detail = validator
            .iter_errors(value)
            .map(|error| format!("{}: {error}", error.instance_path()))
            .collect::<Vec<_>>()
            .join("; ");
        bail!(
            "direct conversation response does not match the canonical operation schema: {detail}"
        );
    }
    serde_json::from_value::<
        arkret_models_collaboration::direct_conversation_ops::DirectConversationResolveOutcome,
    >(value.clone())?;
    Ok(())
}

fn validate_binding_payload(
    trust_domain: &str,
    binding_event_ref: &str,
    payload: &Value,
) -> Result<()> {
    validate_event_id(binding_event_ref)?;
    let binding = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::device_identity::DirectConversationBoundPayload,
    >(payload.clone())?;
    let trust_domain = arkret::TypedTrustDomainId::new(trust_domain.to_owned())
        .map_err(|err| anyhow!("invalid trust domain: {err}"))?;
    binding.validate_pair_key(trust_domain)?;
    Ok(())
}

fn validate_resolver_uses_binding_main_strand(vectors: &DirectConversationVectors) -> Result<()> {
    let response_coordinates = vectors
        .resolve_response
        .get("coordinates")
        .ok_or_else(|| anyhow!("found response missing coordinates"))?;
    let response_realm_id = required_str(response_coordinates, "realm_id")?;
    let response_main_strand_id = required_str(response_coordinates, "main_strand_id")?;
    let response_binding_ref = required_str(response_coordinates, "binding_event_ref")?;
    let binding_realm_id = required_str(&vectors.binding_payload, "realm_id")?;
    let binding_main_strand_id = required_str(&vectors.binding_payload, "main_strand_id")?;

    if response_realm_id != binding_realm_id {
        bail!("resolver response realm_id must come from direct conversation binding");
    }
    if response_main_strand_id != binding_main_strand_id {
        bail!("resolver response main_strand_id must come from direct conversation binding");
    }
    if response_binding_ref != vectors.binding_event_ref {
        bail!("resolver response binding_event_ref must identify the binding event");
    }

    let selection = &vectors.derived_strand_selection;
    validate_realm_id(&selection.realm_id)?;
    validate_strand_id(&selection.binding_main_strand_id)?;
    validate_strand_id(&selection.default_strand_id_for_realm)?;
    validate_strand_id(&selection.selected_main_strand_id)?;
    if selection.realm_id != response_realm_id {
        bail!("derived strand selection realm_id must match resolver response");
    }
    if selection.binding_main_strand_id != binding_main_strand_id {
        bail!("derived strand selection binding_main_strand_id must match binding");
    }
    if selection.selected_main_strand_id != selection.binding_main_strand_id {
        bail!("direct conversation selection must use binding_main_strand_id");
    }
    if selection.selected_main_strand_id == selection.default_strand_id_for_realm {
        bail!("direct conversation selection must not fall back to default_strand_id_for_realm");
    }
    Ok(())
}

fn validate_contact_list_row(vectors: &DirectConversationVectors) -> Result<()> {
    let row = &vectors.contact_list_row;
    if required_str(row, "state")? != "accepted" {
        bail!("contact row with direct_conversation summary must be accepted");
    }
    for field in ["granted_by_me", "granted_to_me", "bidirectional_scopes"] {
        let scopes = value_array(required_field(row, field)?)?;
        if scopes.is_empty() {
            bail!("contact row {field} must keep directional scopes");
        }
    }
    if let Some(effective) = row.get("effective_scopes") {
        let effective = string_set(effective)?;
        let bidirectional = string_set(required_field(row, "bidirectional_scopes")?)?;
        if effective != bidirectional {
            bail!("effective_scopes must equal bidirectional_scopes when present");
        }
    }

    let summary = required_field(row, "direct_conversation")?;
    if required_str(summary, "state")? != "active" {
        bail!("accepted contact fixture must point at active direct conversation summary");
    }
    let coordinates = vectors
        .resolve_response
        .get("coordinates")
        .ok_or_else(|| anyhow!("found response missing coordinates"))?;
    if required_str(summary, "realm_id")? != required_str(coordinates, "realm_id")? {
        bail!("contact direct_conversation realm_id must match resolver response");
    }
    if required_str(summary, "main_strand_id")? != required_str(coordinates, "main_strand_id")? {
        bail!("contact direct_conversation main_strand_id must match resolver response");
    }
    Ok(())
}

fn validate_pending_contact_negative(case: &PendingContactNegative) -> Result<()> {
    validate_resolve_request_shape(&case.resolve_request)?;
    let contact_state = required_str(&case.contact_row, "state")?;
    if !matches!(contact_state, "pending_incoming" | "pending_outgoing") {
        bail!(
            "pending negative `{}` must use a pending contact state",
            case.name
        );
    }
    if case.contact_row.get("direct_conversation").is_some() {
        bail!("pending contact must not carry a direct_conversation summary");
    }
    if case.expected_error.error_code != "failed_precondition"
        || case.expected_error.reason_code != "direct_conversation_unavailable"
    {
        bail!("pending contact negative must fail with direct_conversation_unavailable");
    }
    for forbidden in ["realm_id", "main_strand_id", "binding_event_ref"] {
        if case.observed_response.get(forbidden).is_some() {
            bail!("pending contact negative must not create or return `{forbidden}`");
        }
    }
    validate_resolve_response_shape(&case.observed_response)?;
    Ok(())
}

fn validate_schema_negative_shapes(valid_request: &Value, valid_response: &Value) -> Result<()> {
    let mut request_with_retired_target = valid_request.clone();
    request_with_retired_target
        .as_object_mut()
        .ok_or_else(|| anyhow!("valid request is not an object"))?
        .insert("target".to_owned(), json!("did:web:bob.example"));
    if validate_resolve_request_shape(&request_with_retired_target).is_ok() {
        bail!("direct conversation request accepted an injected target field");
    }

    let mut response_without_coordinates = valid_response.clone();
    response_without_coordinates
        .as_object_mut()
        .ok_or_else(|| anyhow!("valid response is not an object"))?
        .remove("coordinates");
    if validate_resolve_response_shape(&response_without_coordinates).is_ok() {
        bail!("direct conversation found response accepted missing coordinates");
    }
    Ok(())
}

fn required_field<'a>(value: &'a Value, field: &str) -> Result<&'a Value> {
    value
        .get(field)
        .ok_or_else(|| anyhow!("missing field `{field}`"))
}

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    required_field(value, field)?
        .as_str()
        .ok_or_else(|| anyhow!("field `{field}` must be a string"))
}

fn value_array(value: &Value) -> Result<&Vec<Value>> {
    value.as_array().ok_or_else(|| anyhow!("expected array"))
}

fn string_set(value: &Value) -> Result<BTreeSet<String>> {
    value_array(value)?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("expected string array item"))
        })
        .collect::<Result<BTreeSet<_>>>()
}

fn validate_realm_id(value: &str) -> Result<()> {
    RealmId::new(value)
        .map(|_| ())
        .map_err(|err| anyhow!("{err}"))
}

fn validate_strand_id(value: &str) -> Result<()> {
    StrandId::new(value)
        .map(|_| ())
        .map_err(|err| anyhow!("{err}"))
}

fn validate_event_id(value: &str) -> Result<()> {
    EventId::new(value)
        .map(|_| ())
        .map_err(|err| anyhow!("{err}"))
}

fn contains_key_recursive(value: &Value, needle: &str) -> bool {
    match value {
        Value::Object(map) => map
            .iter()
            .any(|(key, value)| key == needle || contains_key_recursive(value, needle)),
        Value::Array(items) => items
            .iter()
            .any(|item| contains_key_recursive(item, needle)),
        _ => false,
    }
}

fn contains_literal_recursive(value: &Value, needle: &str) -> bool {
    match value {
        Value::Object(map) => map
            .iter()
            .any(|(key, value)| key.contains(needle) || contains_literal_recursive(value, needle)),
        Value::Array(items) => items
            .iter()
            .any(|item| contains_literal_recursive(item, needle)),
        Value::String(raw) => raw.contains(needle),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_chat_privacy_contract_fixture_runs() {
        run_private_chat_privacy_contract_suite().expect("private chat privacy contract suite");
    }
}
