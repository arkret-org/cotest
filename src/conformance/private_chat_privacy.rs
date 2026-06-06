//! Cotest-local privacy and direct-conversation contract vectors.
//!
//! These are fixture-driven, schema-adjacent checks for behavior that is
//! currently specified in prose/artifacts but not yet backed by a live
//! cross-service e2e harness.

use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use cokret_core::{Did, EventId, FlowId, RealmId};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{load_artifact_json, load_local_fixture_value};
use crate::transcripts::record_vector_event;

const FIXTURE_FILE: &str = "private_chat_privacy_contracts.json";
const REALM_REMARK_KEY_PREFIX: &str = "ck.contacts.realm.";

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
    resolve_request: Value,
    resolve_response: Value,
    binding_event_ref: String,
    binding_payload: Value,
    contact_list_row: Value,
    derived_flow_selection: DerivedFlowSelection,
    pending_contact_negative: PendingContactNegative,
    schema_negative_shapes: Vec<SchemaNegativeShape>,
}

#[derive(Debug, Deserialize)]
struct DerivedFlowSelection {
    realm_id: String,
    binding_main_flow_id: String,
    default_flow_id_for_realm: String,
    selected_main_flow_id: String,
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

#[derive(Debug, Deserialize)]
struct SchemaNegativeShape {
    name: String,
    kind: String,
    body: Value,
}

pub fn run_private_chat_privacy_contract_suite() -> Result<()> {
    validate_realm_remark_registry()?;
    validate_direct_conversation_artifacts()?;

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
    let registry = load_artifact_json("registry/account-data-type-registry.json")?;
    let entry = registry
        .get("account_data_types")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|entry| {
            entry.get("key_pattern").and_then(Value::as_str) == Some("ck.contacts.realm.<realm_id>")
        })
        .ok_or_else(|| anyhow!("account-data registry missing ck.contacts.realm.<realm_id>"))?;

    if entry.get("storage").and_then(Value::as_str) != Some("encrypted_account_data") {
        bail!("ck.contacts.realm.<realm_id> must stay encrypted account data");
    }
    if entry.get("scope").and_then(Value::as_str) != Some("realm_private_preference") {
        bail!("ck.contacts.realm.<realm_id> scope drifted from realm_private_preference");
    }
    let writers = entry
        .get("write_event_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("ck.contacts.realm.<realm_id> missing write_event_kinds"))?;
    if !writers
        .iter()
        .any(|writer| writer.as_str() == Some("ck.account_data.set"))
    {
        bail!("ck.contacts.realm.<realm_id> must be written by ck.account_data.set");
    }

    record_vector_event(
        "private_chat_privacy.realm_remark_registry",
        &json!({"key_pattern": "ck.contacts.realm.<realm_id>"}),
        &json!({
            "storage": "encrypted_account_data",
            "scope": "realm_private_preference",
            "writer": "ck.account_data.set",
        }),
        &json!({
            "storage": entry.get("storage").cloned(),
            "scope": entry.get("scope").cloned(),
            "write_event_kinds": entry.get("write_event_kinds").cloned(),
        }),
    );
    Ok(())
}

fn validate_direct_conversation_artifacts() -> Result<()> {
    let operation_registry = load_artifact_json("registry/operation-registry.json")?;
    let operation = operation_registry
        .get("operations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|operation| {
            operation.get("operation_id").and_then(Value::as_str)
                == Some("ck.self.direct_conversation.resolve")
        })
        .ok_or_else(|| anyhow!("operation registry missing ck.self.direct_conversation.resolve"))?;
    if operation.get("http").and_then(Value::as_str)
        != Some("POST /_cokret/self/direct-conversations/resolve")
    {
        bail!("direct conversation resolver HTTP binding drifted");
    }
    if operation.get("request_schema_ref").and_then(Value::as_str)
        != Some("schemas/contact-operations.schema.json#/$defs/direct_conversation_resolve_request")
    {
        bail!("direct conversation request schema ref drifted");
    }
    if operation.get("response_schema_ref").and_then(Value::as_str)
        != Some(
            "schemas/contact-operations.schema.json#/$defs/direct_conversation_resolve_response",
        )
    {
        bail!("direct conversation response schema ref drifted");
    }

    let contact_schema = load_artifact_json("schemas/contact-operations.schema.json")?;
    let request_def = contact_schema
        .pointer("/$defs/direct_conversation_resolve_request")
        .ok_or_else(|| anyhow!("missing direct_conversation_resolve_request schema"))?;
    assert_schema_contract(
        "direct_conversation_resolve_request",
        request_def,
        &["peer"],
        &["peer", "create", "idempotency_key"],
        &["target", "realm_id", "main_flow_id"],
    )?;

    let response_def = contact_schema
        .pointer("/$defs/direct_conversation_resolve_response")
        .ok_or_else(|| anyhow!("missing direct_conversation_resolve_response schema"))?;
    assert_schema_contract(
        "direct_conversation_resolve_response",
        response_def,
        &["state"],
        &[
            "state",
            "realm_id",
            "main_flow_id",
            "binding_event_ref",
            "created",
        ],
        &["status", "binding_ref", "default_flow_id"],
    )?;

    let event_payload_schema = load_artifact_json("schemas/event-payload.schema.json")?;
    let binding_def = event_payload_schema
        .pointer("/$defs/direct_conversation_bound_payload")
        .ok_or_else(|| anyhow!("missing direct_conversation_bound_payload schema"))?;
    assert_schema_contract(
        "direct_conversation_bound_payload",
        binding_def,
        &[
            "pair_key",
            "participants_unordered",
            "realm_id",
            "main_flow_id",
            "contact_refs",
            "member_event_refs",
            "main_flow_create_ref",
            "created_at",
        ],
        &[
            "pair_key",
            "participants_unordered",
            "realm_id",
            "main_flow_id",
            "contact_refs",
            "member_event_refs",
            "main_flow_create_ref",
            "created_at",
            "binding_state",
            "supersedes_binding_ref",
        ],
        &["default_flow_id", "status", "binding_ref"],
    )?;

    record_vector_event(
        "private_chat_privacy.direct_conversation_artifacts",
        &json!({"operation_id": "ck.self.direct_conversation.resolve"}),
        &json!({
            "http": "POST /_cokret/self/direct-conversations/resolve",
            "request_field": "peer",
            "response_field": "state",
            "binding_field": "binding_event_ref",
            "main_flow_id_from_binding": true,
        }),
        &json!({
            "http": operation.get("http").cloned(),
            "request_schema_ref": operation.get("request_schema_ref").cloned(),
            "response_schema_ref": operation.get("response_schema_ref").cloned(),
        }),
    );
    Ok(())
}

fn assert_schema_contract(
    label: &str,
    schema: &Value,
    required_fields: &[&str],
    allowed_properties: &[&str],
    forbidden_properties: &[&str],
) -> Result<()> {
    if schema.get("additionalProperties").and_then(Value::as_bool) != Some(false) {
        bail!("{label} must be a closed DTO with additionalProperties=false");
    }
    let required = string_set(schema.get("required").unwrap_or(&Value::Null))?;
    for field in required_fields {
        if !required.contains(*field) {
            bail!("{label} missing required field `{field}`");
        }
    }
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("{label} missing properties"))?;
    for property in allowed_properties {
        if !properties.contains_key(*property) {
            bail!("{label} missing property `{property}`");
        }
    }
    for property in forbidden_properties {
        if properties.contains_key(*property) {
            bail!("{label} must not expose retired property `{property}`");
        }
    }
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
    validate_resolve_response_shape(&vectors.resolve_response)?;
    validate_binding_payload(&vectors.binding_event_ref, &vectors.binding_payload)?;
    validate_resolver_uses_binding_main_flow(vectors)?;
    validate_contact_list_row(vectors)?;
    validate_pending_contact_negative(&vectors.pending_contact_negative)?;
    validate_schema_negative_shapes(&vectors.schema_negative_shapes)?;

    record_vector_event(
        "private_chat_privacy.direct_conversation_vectors",
        &json!({
            "request": &vectors.resolve_request,
            "response": &vectors.resolve_response,
            "binding_event_ref": &vectors.binding_event_ref,
        }),
        &json!({
            "request_peer_field": true,
            "response_state_field": true,
            "binding_main_flow_used": true,
            "pending_contact_no_realm_created": true,
        }),
        &json!({
            "response_state": vectors.resolve_response.get("state").cloned(),
            "response_main_flow_id": vectors.resolve_response.get("main_flow_id").cloned(),
            "binding_main_flow_id": vectors.binding_payload.get("main_flow_id").cloned(),
        }),
    );
    Ok(())
}

fn validate_resolve_request_shape(value: &Value) -> Result<()> {
    assert_allowed_object_fields(
        "direct conversation resolve request",
        value,
        &["peer", "create", "idempotency_key"],
    )?;
    let peer = required_str(value, "peer")?;
    Did::new(peer.to_owned()).map_err(|err| anyhow!("invalid request peer DID: {err}"))?;
    if let Some(create) = value.get("create")
        && !create.is_boolean()
    {
        bail!("direct conversation resolve request create must be bool");
    }
    Ok(())
}

fn validate_resolve_response_shape(value: &Value) -> Result<()> {
    assert_allowed_object_fields(
        "direct conversation resolve response",
        value,
        &[
            "state",
            "realm_id",
            "main_flow_id",
            "binding_event_ref",
            "created",
        ],
    )?;
    let state = required_str(value, "state")?;
    if !matches!(
        state,
        "found" | "created" | "not_found" | "retired" | "non_canonical"
    ) {
        bail!("unknown direct conversation resolver state `{state}`");
    }
    if matches!(state, "found" | "created") {
        validate_realm_id(required_str(value, "realm_id")?)?;
        validate_flow_id(required_str(value, "main_flow_id")?)?;
        validate_event_id(required_str(value, "binding_event_ref")?)?;
    }
    Ok(())
}

fn validate_binding_payload(binding_event_ref: &str, payload: &Value) -> Result<()> {
    validate_event_id(binding_event_ref)?;
    assert_allowed_object_fields(
        "direct conversation binding payload",
        payload,
        &[
            "pair_key",
            "participants_unordered",
            "realm_id",
            "main_flow_id",
            "contact_refs",
            "member_event_refs",
            "main_flow_create_ref",
            "created_at",
            "binding_state",
            "supersedes_binding_ref",
        ],
    )?;
    let pair_key = required_str(payload, "pair_key")?;
    if pair_key.contains('@') || pair_key.starts_with('@') {
        bail!("direct conversation pair_key must not be a handle string");
    }
    validate_realm_id(required_str(payload, "realm_id")?)?;
    validate_flow_id(required_str(payload, "main_flow_id")?)?;
    validate_event_id(required_str(payload, "main_flow_create_ref")?)?;

    let participants = value_array(required_field(payload, "participants_unordered")?)?;
    if participants.len() != 2 {
        bail!("direct conversation binding must have exactly two participants");
    }
    let mut seen = BTreeSet::new();
    for participant in participants {
        let did = participant
            .as_str()
            .ok_or_else(|| anyhow!("participant must be a DID string"))?;
        Did::new(did.to_owned()).map_err(|err| anyhow!("invalid participant DID: {err}"))?;
        if !seen.insert(did) {
            bail!("direct conversation participants must be unique");
        }
    }

    validate_event_ref_array(payload, "contact_refs", 2)?;
    validate_event_ref_array(payload, "member_event_refs", 2)?;
    if let Some(state) = payload.get("binding_state").and_then(Value::as_str)
        && !matches!(state, "active" | "retired" | "duplicate" | "non_canonical")
    {
        bail!("unknown direct conversation binding_state `{state}`");
    }
    Ok(())
}

fn validate_resolver_uses_binding_main_flow(vectors: &DirectConversationVectors) -> Result<()> {
    let response_realm_id = required_str(&vectors.resolve_response, "realm_id")?;
    let response_main_flow_id = required_str(&vectors.resolve_response, "main_flow_id")?;
    let response_binding_ref = required_str(&vectors.resolve_response, "binding_event_ref")?;
    let binding_realm_id = required_str(&vectors.binding_payload, "realm_id")?;
    let binding_main_flow_id = required_str(&vectors.binding_payload, "main_flow_id")?;

    if response_realm_id != binding_realm_id {
        bail!("resolver response realm_id must come from direct conversation binding");
    }
    if response_main_flow_id != binding_main_flow_id {
        bail!("resolver response main_flow_id must come from direct conversation binding");
    }
    if response_binding_ref != vectors.binding_event_ref {
        bail!("resolver response binding_event_ref must identify the binding event");
    }

    let selection = &vectors.derived_flow_selection;
    validate_realm_id(&selection.realm_id)?;
    validate_flow_id(&selection.binding_main_flow_id)?;
    validate_flow_id(&selection.default_flow_id_for_realm)?;
    validate_flow_id(&selection.selected_main_flow_id)?;
    if selection.realm_id != response_realm_id {
        bail!("derived flow selection realm_id must match resolver response");
    }
    if selection.binding_main_flow_id != binding_main_flow_id {
        bail!("derived flow selection binding_main_flow_id must match binding");
    }
    if selection.selected_main_flow_id != selection.binding_main_flow_id {
        bail!("direct conversation selection must use binding_main_flow_id");
    }
    if selection.selected_main_flow_id == selection.default_flow_id_for_realm {
        bail!("direct conversation selection must not fall back to default_flow_id_for_realm");
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
    if required_str(summary, "realm_id")? != required_str(&vectors.resolve_response, "realm_id")? {
        bail!("contact direct_conversation realm_id must match resolver response");
    }
    if required_str(summary, "main_flow_id")?
        != required_str(&vectors.resolve_response, "main_flow_id")?
    {
        bail!("contact direct_conversation main_flow_id must match resolver response");
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
        || case.expected_error.reason_code != "contact_not_accepted"
    {
        bail!("pending contact negative must fail with contact_not_accepted");
    }
    for forbidden in ["realm_id", "main_flow_id", "binding_event_ref"] {
        if case.observed_response.get(forbidden).is_some() {
            bail!("pending contact negative must not create or return `{forbidden}`");
        }
    }
    if case
        .observed_response
        .get("created")
        .and_then(Value::as_bool)
        == Some(true)
    {
        bail!("pending contact negative must not mark created=true");
    }
    Ok(())
}

fn validate_schema_negative_shapes(cases: &[SchemaNegativeShape]) -> Result<()> {
    if cases.is_empty() {
        bail!("direct conversation schema negative shapes must not be empty");
    }
    for case in cases {
        let accepted = match case.kind.as_str() {
            "request" => validate_resolve_request_shape(&case.body).is_ok(),
            "response" => validate_resolve_response_shape(&case.body).is_ok(),
            other => bail!("schema negative `{}` has unknown kind `{other}`", case.name),
        };
        if accepted {
            bail!("schema negative `{}` was accepted", case.name);
        }
    }
    Ok(())
}

fn assert_allowed_object_fields(label: &str, value: &Value, allowed: &[&str]) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("{label} must be an object"))?;
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            bail!("{label} contains forbidden field `{key}`");
        }
    }
    Ok(())
}

fn validate_event_ref_array(value: &Value, field: &str, min_items: usize) -> Result<()> {
    let refs = value_array(required_field(value, field)?)?;
    if refs.len() < min_items {
        bail!("{field} must contain at least {min_items} refs");
    }
    for event_ref in refs {
        let event_ref = event_ref
            .as_str()
            .ok_or_else(|| anyhow!("{field} entries must be event ids"))?;
        validate_event_id(event_ref)?;
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

fn value_array<'a>(value: &'a Value) -> Result<&'a Vec<Value>> {
    value.as_array().ok_or_else(|| anyhow!("expected array"))
}

fn string_set(value: &Value) -> Result<BTreeSet<String>> {
    Ok(value_array(value)?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("expected string array item"))
        })
        .collect::<Result<BTreeSet<_>>>()?)
}

fn validate_realm_id(value: &str) -> Result<()> {
    RealmId::new(value)
        .map(|_| ())
        .map_err(|err| anyhow!("{err}"))
}

fn validate_flow_id(value: &str) -> Result<()> {
    FlowId::new(value)
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
