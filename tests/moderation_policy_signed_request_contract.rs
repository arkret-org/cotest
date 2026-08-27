use std::path::PathBuf;

use serde_json::{Value, json};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cotest is under the Arkret workspace")
        .to_path_buf()
}

fn read(relative: &str) -> String {
    let path = workspace_root().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

#[test]
fn moderation_policy_registry_and_request_schema_require_one_signed_event() {
    let registry: Value = serde_json::from_str(&read(
        "arkret-spec/spec/v1/artifacts/registry/operation-registry.json",
    ))
    .expect("operation registry is JSON");
    let operation = registry["operations"]
        .as_array()
        .expect("operations array")
        .iter()
        .find(|row| row["operation_id"] == "ak.self.realm.moderation_policy.resource.replace.v1")
        .expect("Realm moderation-policy replace operation");
    assert_eq!(
        operation["request_schema_ref"],
        "schemas/realm-read-operations.schema.json#/$defs/realm_moderation_policy_replace_request_body"
    );
    assert_eq!(
        operation["durable_effect"]["event_kinds"],
        json!(["ak.realm.moderation_policy"])
    );
    assert!(
        operation["notes"]
            .as_str()
            .is_some_and(|notes| notes.contains("caller-signed"))
    );

    let request_schema: Value = serde_json::from_str(&read(
        "arkret-spec/spec/v1/artifacts/schemas/realm-read-operations.schema.json",
    ))
    .expect("Realm operation schema is JSON");
    let request = &request_schema["$defs"]["realm_moderation_policy_replace_request_body"];
    assert_eq!(request["required"], json!(["moderation_policy_event"]));
    assert_eq!(request["additionalProperties"], false);
    let submission = &request_schema["$defs"]["realm_moderation_policy_event_submission"];
    assert_eq!(
        submission["allOf"][1]["properties"]["event"]["properties"]["kind"]["const"],
        "ak.realm.moderation_policy"
    );

    let payload_schema: Value = serde_json::from_str(&read(
        "arkret-spec/spec/v1/artifacts/schemas/event-payload.schema.json",
    ))
    .expect("Event payload schema is JSON");
    let payload = &payload_schema["$defs"]["realm_moderation_policy_state_payload"];
    assert_eq!(payload["required"], json!(["value"]));
    assert_eq!(payload["properties"]["value"]["type"], "object");
    assert_eq!(payload["additionalProperties"], false);
}

#[test]
fn sdk_model_and_client_keep_the_signed_body_closed_and_canonical() {
    let model =
        read("arkret-rust-sdk/crates/models-collaboration/src/governance/realm_governance.rs");
    assert!(model.contains("pub moderation_policy_event: EventInitialSubmission"));
    assert!(model.contains("impl RealmModerationPolicyReplaceRequestBody"));
    assert!(model.contains("pub fn validate("));
    assert!(model.contains("realm_id: &RealmId"));
    assert!(model.contains("digest_suite: arkret_canonical::DigestSuite"));
    assert!(model.contains("EventKind::RealmModerationPolicy"));
    assert!(model.contains("REALM_MODERATION_POLICY_CELL_REF"));
    assert!(model.contains("requires exactly one signed head_eq precondition"));
    let request_body = model
        .split("pub struct RealmModerationPolicyReplaceRequestBody")
        .nth(1)
        .and_then(|tail| {
            tail.split("impl RealmModerationPolicyReplaceRequestBody")
                .next()
        })
        .expect("closed moderation-policy request body source");
    assert!(!request_body.contains("pub policy:"));

    let client = read("arkret-rust-sdk/crates/http-client/src/endpoints/moderation.rs");
    assert!(client.contains("request: &RealmModerationPolicyReplaceRequestBody"));
    assert!(client.contains("request.validate(realm_id, digest_suite)?"));
    assert!(client.contains("/_arkret/self/realms/{realm_id}/moderation-policy"));
    assert!(client.contains("self.put("));

    let request_transport = read("arkret-rust-sdk/crates/http-client/src/request.rs");
    assert!(request_transport.contains("self.canonical_json_body(self.request(Method::PUT"));
}

#[test]
fn soland_validates_and_forwards_the_exact_event_without_authoring_one() {
    let handler = read("soland/crates/http/src/routing/spaces/space.rs");
    assert!(handler.contains("body: JsonBody<RealmModerationPolicyReplaceRequestBody>"));
    assert!(handler.contains("moderation_policy_event"));
    assert!(handler.contains("submit_initial_event_submission"));
    assert!(!handler.contains("body.into_inner().policy"));
    assert!(!handler.contains("persist_realm_moderation_policy"));
    assert!(!handler.contains("arkret_signatures::sign_event"));
}
