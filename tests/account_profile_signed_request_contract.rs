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
fn sdk_keeps_profile_event_closed_and_returns_the_covering_commit() {
    let model = read("arkret-rust-sdk/crates/models-collaboration/src/account_operations.rs");
    let body = source_between(
        &model,
        "pub struct AccountUpdateProfileRequestBody",
        "impl AccountUpdateProfileRequestBody",
    );
    assert!(body.contains("pub profile_event: EventAdmissionSubmission"));
    assert!(!body.contains("pub patch:"));
    let validate = source_between(
        &model,
        "impl AccountUpdateProfileRequestBody",
        "event.validate_for_submit_structural()",
    );
    assert!(validate.contains("direct holder-authored Event"));
    assert!(validate.contains("EventKind::ProfileCreate"));
    assert!(validate.contains("EventKind::ProfileUpdate"));
    assert!(validate.contains("validate_for_account_self_service"));
    assert!(validate.contains("object.principal_id != account.principal_id"));

    // The create author region is the closed actor_profile_definition, not the
    // materialized object: schema, realm, times and id are reducer outputs.
    let identity = read("arkret-rust-sdk/crates/models-identity/src/actor_profile.rs");
    let definition = source_between(
        &identity,
        "pub struct ActorProfileDefinition",
        "impl ActorProfileDefinition",
    );
    for reducer_member in ["pub schema", "pub realm_id", "pub created_at", "pub id:"] {
        assert!(!definition.contains(reducer_member), "{reducer_member}");
    }
    assert!(identity.contains("pub struct AccountMaterializedProfile"));
    assert!(identity.contains("materialized account profile requires id and realm_id"));
    assert!(!identity.contains("pub status: Option<ActorStatus>"));

    let payload =
        read("arkret-rust-sdk/crates/models-collaboration/src/events_payloads/actor_profile.rs");
    assert!(payload.contains("pub object: ActorProfileDefinition"));
    assert!(payload.contains("pub struct ActorProfileUpdatePayload"));
    assert!(payload.contains("validate_for_account_self_service"));
    assert!(payload.contains("profile_fields."));

    let outcome = read("arkret-rust-sdk/crates/models-identity/src/account.rs");
    let outcome = source_between(
        &outcome,
        "pub struct AccountUpdateProfileOutcome",
        "pub enum CursorRevokeScope",
    );
    assert!(outcome.contains("AccountMaterializedProfile"));
    assert!(outcome.contains("pub commit: arkret_wire::RealmCommit"));

    let client = read("arkret-rust-sdk/crates/http-client/src/endpoints/account.rs");
    let method = source_between(
        &client,
        "pub async fn account_update_profile(",
        "pub async fn account_device_pair(",
    );
    assert!(method.contains("request: &AccountUpdateProfileRequestBody"));
    assert!(method.contains("request.validate()?"));
    assert!(method.contains("self.post(\"/_arkret/self/account/profile\", request)"));

    let transport = read("arkret-rust-sdk/crates/http-client/src/request.rs");
    assert!(transport.contains("self.canonical_json_body(self.request(Method::POST"));
}

#[test]
fn actor_profile_resolve_carries_the_event_without_a_seal_and_one_failure_value() {
    let schema: Value = serde_json::from_str(&read(
        "arkret-spec/spec/v1/artifacts/schemas/actor-profile-operations.schema.json",
    ))
    .expect("actor profile operation schema is JSON");
    let row = &schema["$defs"]["resolved_actor_profile"];
    assert_eq!(
        row["required"],
        json!([
            "actor_id",
            "actor_profile",
            "profile_event",
            "profile_commit"
        ]),
        "the row is the projection, its exact Event and that Event's covering RealmCommit"
    );
    assert_eq!(row["additionalProperties"], false);
    assert_eq!(
        schema["$defs"]["profile_event"]["allOf"][1]["properties"]["kind"]["enum"],
        json!(["ak.profile.create", "ak.profile.update"])
    );
    assert_eq!(
        schema["$defs"]["resolve_failure"]["properties"]["reason"]["enum"],
        json!(["profile_unavailable"]),
        "unknown actor, missing profile, non-member actor and unauthorized caller are one value"
    );

    let mapping: Value = serde_json::from_str(&read(
        "arkret-spec/spec/v1/artifacts/registry/operations-error-mapping.json",
    ))
    .expect("operation error mapping is JSON");
    let entry = mapping["operations"]
        .as_array()
        .expect("error mapping operation rows")
        .iter()
        .find(|row| row["operation_id"] == "ak.self.actor_profile.read.resolve.v1")
        .expect("resolve operation error mapping");
    assert_eq!(entry["operation_specific"], json!([]));
    assert!(
        entry["description"]
            .as_str()
            .is_some_and(|notes| notes.contains("not_found for the whole request")),
        "a caller without membership in the selector Realm gets one not_found"
    );

    // The shared consumer rule, so no host re-derives what a row proves.
    let row_type = read("arkret-rust-sdk/crates/models-identity/src/actor_profile_operations.rs");
    assert!(row_type.contains("pub profile_commit: RealmCommit"));
    assert!(row_type.contains("pub account_status: Option<AccountStatusProjection>"));
    let sdk = read("arkret-rust-sdk/crates/models-collaboration/src/actor_profile_resolution.rs");
    assert!(sdk.contains("pub fn validate_resolved_actor_profile("));
    assert!(sdk.contains("commit.event_ref != event.event_id"));
    assert!(sdk.contains("pub fn validate_actor_profile_resolve_outcome("));
    assert!(sdk.contains("pub fn classify_confirmed_display_name("));
    assert!(sdk.contains("pub fn contact_accept_may_initialize_confirmation("));
    assert!(
        !sdk.contains("accepted_seal"),
        "ordinary profile state has no covering Seal for a consumer to check"
    );

    let client = read("arkret-rust-sdk/crates/http-client/src/endpoints/identity.rs");
    let method = source_between(
        &client,
        "pub async fn actor_profile_resolve(",
        "/// Fetch the current public principal resolution projection",
    );
    assert!(method.contains("request.validate()?"));
    assert!(method.contains("/_arkret/self/actor-profiles/query"));
    // The client enforces the batch invariant only. Row binding is per-actor, so
    // checking it here would turn one self-inconsistent row into a failure for
    // the whole request and lose the rows that were fine.
    assert!(method.contains("outcome.validate_covers(&request.actor_ids)?"));
    assert!(!method.contains("validate_resolved_actor_profile"));

    // garth owns the freshness verdict, so a rename claim cannot be made from a
    // stale cache and an unvalidated row is recorded as unavailable.
    let engine = read("garth/src/actor_profile_directory.rs");
    assert!(engine.contains("pub enum ActorProfileView"));
    assert!(engine.contains("ActorProfileUnavailableCause::EvidenceRejected"));
    assert!(engine.contains("pub fn confirmed_display_name_state("));
    assert!(engine.contains("pub fn forget_realm("));

    // The service refuses the request instead of answering per actor.
    let service = read("coland/crates/http/src/routing/identity/account.rs");
    let handler = source_between(
        &service,
        "async fn resolve_actor_profiles(",
        "async fn read_principal_resolution_audit(",
    );
    assert!(handler.contains("if !caller_joined {"));
    assert!(handler.contains("AppError::not_found(\"actor profiles unavailable\")"));
    assert!(handler.contains("ActorProfileResolveFailureReason::ProfileUnavailable"));
    assert!(handler.contains("validate_covers"));
}

#[test]
fn service_admits_the_signed_event_through_the_pcr_unit_and_product_authors_the_definition() {
    let service = read("coland/crates/http/src/routing/identity/account.rs");
    let handler = source_between(
        &service,
        "async fn update_profile(",
        "fn validate_profile_request(",
    );
    assert!(handler.contains("profile_event"));
    assert!(handler.contains("prepare_self_event_transaction"));
    assert!(handler.contains("admit_actor_profile"));
    assert!(handler.contains("commit: record.commit"));
    assert!(!handler.contains("TemporarilyUnavailable"));
    assert!(!handler.contains("let patch = body.patch"));
    assert!(!handler.contains("save_account("));
    assert!(!handler.contains("arkret_signatures::sign_event"));
    let reads = source_between(
        &service,
        "pub(crate) async fn accepted_account_profile(",
        "async fn resolve_actor_profiles(",
    );
    assert!(reads.contains("current_actor_profile"));
    assert!(reads.contains("profile_commit: record.commit"));
    assert!(!reads.contains("current provider is unavailable"));

    // The accountability decision is taken at the accepting Commit inside the
    // PCR unit, against committed identity_accountability rows.
    let unit = read("coland/crates/storage-postgres/src/actor_profiles.rs");
    assert!(unit.contains("accountability_holds_in_connection"));
    assert!(unit.contains("commit.committed_at"));
    assert!(unit.contains("FOR SHARE"));
    let schema = read("coland/crates/storage-postgres/migrations/00000000000000_initial/up.sql");
    assert!(schema.contains("CREATE TABLE actor_profile_current_results ("));
    assert!(schema.contains("CREATE TABLE identity_accountability_current_results ("));

    let product = read("inkson/src/transport/account.rs");
    let authoring = source_between(
        &product,
        "pub async fn update_profile(",
        "pub async fn respond_contact(",
    );
    assert!(authoring.contains("RecoveryMaterialEvidence"));
    assert!(authoring.contains("profile_event"));
    assert!(authoring.contains("ActorProfileDefinition"));
    assert!(authoring.contains("author_for_direct_submission"));
    assert!(!authoring.contains("AccountUpdateProfileRequestBody { patch }"));
    assert!(!authoring.contains("created_at: crate::clock::now_utc()"));
}
