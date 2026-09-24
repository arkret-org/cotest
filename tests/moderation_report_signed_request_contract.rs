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

fn source_between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split(start)
        .nth(1)
        .and_then(|tail| tail.split(end).next())
        .unwrap_or_else(|| panic!("source section {start} .. {end}"))
}

#[test]
fn registry_and_schema_pin_the_exact_signed_report_event() {
    let registry: Value = serde_json::from_str(&read(
        "arkret-spec/spec/v1/artifacts/registry/operation-registry.json",
    ))
    .expect("operation registry is JSON");
    let operation = registry["operations"]
        .as_array()
        .expect("operations array")
        .iter()
        .find(|row| row["operation_id"] == "ak.self.moderation.command.report.v1")
        .expect("moderation report operation");
    assert_eq!(
        operation["idempotency_object_path"],
        "/report_event/event/event_id"
    );
    assert_eq!(
        operation["durable_effect"]["event_kinds"],
        json!(["ak.self.moderation.report"])
    );

    let schema: Value = serde_json::from_str(&read(
        "arkret-spec/spec/v1/artifacts/schemas/moderation-report.schema.json",
    ))
    .expect("moderation report schema is JSON");
    let request = &schema["$defs"]["moderation_report_request_body"];
    assert_eq!(request["required"], json!(["report_event"]));
    assert_eq!(request["additionalProperties"], false);
    let event =
        &schema["$defs"]["moderation_report_event_submission"]["allOf"][1]["properties"]["event"];
    assert_eq!(
        event["properties"]["kind"]["const"],
        "ak.self.moderation.report"
    );
    // Mirrors `moderation-report.schema.json`: a direct-holder signed Event
    // whose current authorization and scope the governance Station resolves,
    // so the submission carries no caller-selected authorization basis.
    assert_eq!(
        event["required"],
        json!(["kind", "realm_id", "scope_ref", "actor_id", "payload"])
    );
    assert_eq!(
        event["not"],
        json!({"anyOf": [
            {"required": ["executed_by"]},
            {"required": ["authorization_ref"]},
            {"required": ["applet_id"]},
            {"required": ["preconditions"]}
        ]})
    );
}

#[test]
fn sdk_and_cotest_keep_full_proof_urls_and_core_reporter_ids() {
    let model = read("arkret-rust-sdk/crates/models-collaboration/src/governance/moderation.rs");
    let body = source_between(
        &model,
        "pub struct ModerationReportRequestBody",
        "pub struct ModerationReportAcceptedTargetBasis",
    );
    assert!(body.contains("pub report_event: EventAdmissionSubmission"));
    assert!(!body.contains("pub target_ref:"));
    assert!(!body.contains("pub reporter:"));
    assert!(model.contains("impl ModerationReportRequestBody"));
    assert!(model.contains("pub fn validate(&self) -> Result<()>"));
    assert!(model.contains("pub fn validate_authoring_context("));
    assert!(model.contains("ReportId::from_event_id"));
    let status = source_between(
        &model,
        "pub enum ModerationReportStatus",
        "pub enum ModerationAction",
    );
    assert!(status.contains("Submitted"));
    assert!(!status.contains("Resolved"));

    let client = read("arkret-rust-sdk/crates/http-client/src/endpoints/moderation.rs");
    let method = client
        .split("pub async fn moderation_report(")
        .nth(1)
        .expect("moderation report client method");
    assert!(method.contains("request.validate()?"));
    assert!(method.contains("request.report_id()?"));
    assert!(method.contains(".post("));
    assert!(method.contains("\"/_arkret/self/moderation/report\""));
    assert!(method.contains("request)"));
    let transport = read("arkret-rust-sdk/crates/http-client/src/request.rs");
    assert!(transport.contains("self.canonical_json_body(self.request(Method::POST"));

    let builder = read("cotest/src/harness/event_builder.rs");
    let helper = source_between(
        &builder,
        "pub async fn moderation_report_request(",
        "pub async fn create_realm_with_signing_seed(",
    );
    assert!(helper.contains("project_did_to_core_id"));
    assert!(helper.contains("EventAdmissionSubmission::new"));
    assert!(helper.contains("author_event("));
    assert!(helper.contains("validate_authoring_context"));
    assert!(!helper.contains("verification_method"));
}

#[test]
fn service_must_validate_and_forward_instead_of_authoring_a_report_event() {
    let service = read("soland/crates/http/src/routing/interop/moderation.rs");
    let handler = source_between(
        &service,
        "async fn moderation_report(",
        "pub(crate) async fn moderation_queue_for_session(",
    );
    assert!(handler.contains("report_event"));
    assert!(handler.contains("submit_initial_event_submission"));
    assert!(!handler.contains("persist_canonical_moderation_report_event"));
    assert!(!handler.contains("sign_event"));
    assert!(!handler.contains("report_fields.insert"));
}
