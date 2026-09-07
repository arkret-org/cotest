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
fn account_profile_registry_and_schema_require_one_signed_create_or_update_event() {
    let registry: Value = serde_json::from_str(&read(
        "arkret-spec/spec/v1/artifacts/registry/contract-registry.json",
    ))
    .expect("contract registry is JSON");
    let operation = registry["operation_registry"]["operations"]
        .as_array()
        .expect("operation registry array")
        .iter()
        .find(|row| row["operation_id"] == "ak.self.account.command.update_profile.v1")
        .expect("account profile update operation");
    assert_eq!(
        operation["idempotency_object_path"],
        "/profile_event/event/event_id"
    );
    assert_eq!(
        operation["durable_effect"]["event_kinds"],
        json!(["ak.profile.create", "ak.profile.update"])
    );
    assert!(
        operation["notes"]
            .as_str()
            .is_some_and(|notes| notes.contains("holder-signed")
                && notes.contains("Direct holder proof is required"))
    );

    let event_schema: Value = serde_json::from_str(&read(
        "arkret-spec/spec/v1/artifacts/schemas/event-envelope.schema.json",
    ))
    .expect("Event envelope schema is JSON");
    let event_required = event_schema["required"]
        .as_array()
        .expect("Event required fields");
    assert!(event_required.iter().any(|field| field == "actor_id"));
    assert!(!event_required.iter().any(|field| field == "station_id"));
    assert!(event_schema["properties"].get("station_id").is_none());
    assert_eq!(
        event_schema["properties"]["actor_id"]["$ref"],
        "./common-ids.schema.json#/$defs/actor_id"
    );
    let identities: Value = serde_json::from_str(&read(
        "arkret-spec/spec/v1/artifacts/schemas/common-ids.schema.json",
    ))
    .expect("identity schema is JSON");
    assert_eq!(
        identities["$defs"]["account_id"]["required"],
        json!(["principal_id", "station_id"])
    );
    assert_eq!(
        identities["$defs"]["account_id"]["additionalProperties"],
        false
    );

    let schema: Value = serde_json::from_str(&read(
        "arkret-spec/spec/v1/artifacts/schemas/account-operations.schema.json",
    ))
    .expect("account operation schema is JSON");
    let request = &schema["$defs"]["account_update_profile_request_body"];
    assert_eq!(request["required"], json!(["profile_event"]));
    assert_eq!(request["additionalProperties"], false);
    let submission = &schema["$defs"]["account_profile_event_submission"];
    let branches = submission["allOf"][2]["oneOf"]
        .as_array()
        .expect("create-or-update branches");
    assert_eq!(
        branches[0]["properties"]["event"]["properties"]["kind"]["const"],
        "ak.profile.create"
    );
    assert_eq!(
        branches[1]["properties"]["event"]["properties"]["kind"]["const"],
        "ak.profile.update"
    );
    assert_eq!(
        schema["$defs"]["account_materialized_profile"]["allOf"][1]["required"],
        json!(["id", "realm_id"])
    );
}

#[test]
fn sdk_keeps_profile_event_closed_and_separates_wire_from_accepted_basis() {
    let model = read("arkret-rust-sdk/crates/models-collaboration/src/account_lifecycle.rs");
    let body = source_between(
        &model,
        "pub struct AccountUpdateProfileRequestBody",
        "pub struct AccountProfileAcceptedBasis",
    );
    assert!(body.contains("pub profile_event: EventInitialSubmission"));
    assert!(!body.contains("pub patch:"));
    assert!(!body.contains("accepted_basis"));
    assert!(model.contains("pub fn validate(&self) -> Result<()>"));
    assert!(model.contains("pub fn validate_authoring_context("));
    assert!(model.contains("EventKind::ProfileCreate"));
    assert!(model.contains("EventKind::ProfileUpdate"));
    assert!(model.contains("ActorProfileId::from_event_id"));
    assert!(model.contains("pub profile: Option<AccountMaterializedProfile>"));
    assert!(model.contains("ak.profile.update target_ref does not match"));
    assert!(model.contains("direct holder-authored Event"));

    let materialized = read("arkret-rust-sdk/crates/models-identity/src/actor_profile.rs");
    assert!(materialized.contains("pub struct AccountMaterializedProfile"));
    assert!(materialized.contains("materialized account profile requires id and realm_id"));

    let payload =
        read("arkret-rust-sdk/crates/models-collaboration/src/events_payloads/actor_profile.rs");
    assert!(payload.contains("pub struct ActorProfileUpdatePayload"));
    assert!(payload.contains("validate_for_account_self_service"));
    assert!(payload.contains("profile_fields."));

    let client = read("arkret-rust-sdk/crates/http-client/src/endpoints/account.rs");
    let method = source_between(
        &client,
        "pub async fn account_update_profile(",
        "pub async fn account_device_pair(",
    );
    assert!(method.contains("request: &AccountUpdateProfileRequestBody"));
    assert!(method.contains("digest_suite: arkret_canonical::DigestSuite"));
    assert!(method.contains("request.validate(digest_suite)?"));
    assert!(method.contains("self.post(\"/_arkret/self/account/profile\", request)"));

    let transport = read("arkret-rust-sdk/crates/http-client/src/request.rs");
    assert!(transport.contains("self.canonical_json_body(self.request(Method::POST"));
}

#[test]
fn service_and_product_do_not_keep_the_unsigned_patch_wrapper() {
    let service = read("soland/crates/http/src/routing/identity/account.rs");
    let handler = source_between(
        &service,
        "async fn update_profile(",
        "struct AcceptedAccountProfile",
    );
    assert!(handler.contains("profile_event"));
    assert!(handler.contains("submit_initial_event_submission"));
    assert!(handler.contains("seal_covering_event"));
    assert!(!handler.contains("let patch = body.patch"));
    assert!(!handler.contains("save_account(current.clone())"));
    assert!(!handler.contains("append_audit_log"));
    assert!(!handler.contains("arkret_signatures::sign_event"));

    let product = read("inkson/src/transport/account.rs");
    let authoring = source_between(
        &product,
        "pub async fn update_profile(",
        "pub async fn respond_contact(",
    );
    assert!(authoring.contains("AccountProfileAcceptedBasis"));
    assert!(authoring.contains("RecoveryMaterialEvidence"));
    assert!(authoring.contains("profile_event"));
    assert!(authoring.contains("validate_authoring_context"));
    // The single finalize boundary: the write is authored (actor frontier,
    // HLC, CBS) and signed in one step; nothing prepares an already-identified
    // Event any more.
    assert!(authoring.contains("author_for_direct_submission"));
    assert!(!authoring.contains("AccountUpdateProfileRequestBody { patch }"));
}
