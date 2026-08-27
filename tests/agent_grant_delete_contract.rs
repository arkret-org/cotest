use std::path::PathBuf;

use serde_json::Value;

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
fn agent_grant_delete_is_a_typed_caller_signed_event_surface() {
    let registry: Value = serde_json::from_str(&read(
        "arkret-spec/spec/v1/artifacts/registry/operation-registry.json",
    ))
    .expect("operation registry is JSON");
    let operation = registry["operations"]
        .as_array()
        .expect("operations array")
        .iter()
        .find(|row| row["operation_id"] == "ak.self.agent.grant.resource.delete.v1")
        .expect("agent grant delete operation");
    assert_eq!(
        operation["request_schema_ref"],
        "schemas/agent-operations.schema.json#/$defs/agent_grant_detach_request_body"
    );
    assert_eq!(
        operation["durable_effect"]["event_kinds"][0],
        "ak.capability.revoke"
    );

    let schema: Value = serde_json::from_str(&read(
        "arkret-spec/spec/v1/artifacts/schemas/agent-operations.schema.json",
    ))
    .expect("agent operations schema is JSON");
    let request = &schema["$defs"]["agent_grant_detach_request_body"];
    assert_eq!(request["required"], serde_json::json!(["revoke_event"]));
    let event = &request["properties"]["revoke_event"]["allOf"][1]["properties"]["event"];
    assert_eq!(event["properties"]["kind"]["const"], "ak.capability.revoke");
    assert_eq!(event["properties"]["preconditions"]["minItems"], 1);
    assert_eq!(event["properties"]["preconditions"]["maxItems"], 1);

    let client = read("arkret-rust-sdk/crates/http-client/src/endpoints/agent.rs");
    assert!(client.contains("request: &AgentGrantDetachRequestBody"));
    assert!(client.contains("self.request(Method::DELETE, &path)?"));
    assert!(client.contains("self.canonical_json_body"));

    let handler = read("Soland/crates/http/src/routing/identity/agents/lifecycle.rs");
    assert!(handler.contains("body: JsonBody<AgentGrantDetachRequestBody>"));
    assert!(handler.contains("submit_signed_agent_event(state, &session, body.revoke_event)"));
    assert!(!handler.contains("agent_grant_fanout_unavailable"));
}
