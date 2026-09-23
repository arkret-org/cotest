use anyhow::{Result, anyhow};
use arkret_models_collaboration::governance::third_party_invite::ThirdPartyInvitePresentRequestBody;
use arkret_schema::ProtocolSchemaRegistry;
use arkret_schema_conformance::{default_spec_artifacts_dir, schema_registry_from_spec_artifacts};
use serde_json::{Value, json};

#[test]
fn spec_business_flows_cover_operation_registry_surfaces() -> Result<()> {
    cotest::conformance::run_spec_business_flow_coverage_suite()
}

fn validate_present_request_schema(value: &Value) -> Result<()> {
    let artifacts = default_spec_artifacts_dir()
        .ok_or_else(|| anyhow!("arkret-spec artifacts directory is unavailable"))?;
    let mut registry: ProtocolSchemaRegistry = schema_registry_from_spec_artifacts(&artifacts)?;
    let schema: Value = serde_json::from_slice(&std::fs::read(
        artifacts.join("schemas/invite.schema.json"),
    )?)?;
    registry.register_reference_document(schema.clone())?;
    registry.register_fragment(
        "test:third_party_invite_present".to_owned(),
        schema,
        "#/$defs/third_party_invite_present_request_body",
    )?;
    registry.validate_value("test:third_party_invite_present", value)?;
    Ok(())
}

#[test]
fn third_party_invite_present_body_matches_canonical_schema() -> Result<()> {
    let body = json!({
        "invite_token": "Abcd_1234",
        "realm_id": "ak:realm:ARn9Y97Ha81FH12YY8HLiDixId_wA5Wx2c25p82mJcJ5",
        "subject_account_id": {
            "principal_id": "ak:did_core:web:alice.example",
            "station_id": "ak:did_core:web:station.example"
        },
        "subject_did": "did:web:alice.example",
        "claim_nonce": "0123456789abcdef"
    });
    validate_present_request_schema(&body)?;
    let request: ThirdPartyInvitePresentRequestBody = serde_json::from_value(body.clone())?;
    request.validate_minimal()?;
    assert_eq!(serde_json::to_value(request)?, body);

    let mut invalid_token = body.clone();
    invalid_token["invite_token"] = json!("token/in/path");
    assert!(validate_present_request_schema(&invalid_token).is_err());
    let parsed: ThirdPartyInvitePresentRequestBody = serde_json::from_value(invalid_token)?;
    assert!(parsed.validate_minimal().is_err());

    let mut mismatched_subject = body.clone();
    mismatched_subject["subject_account_id"]["principal_id"] = json!("ak:did_core:web:bob.example");
    let parsed: ThirdPartyInvitePresentRequestBody = serde_json::from_value(mismatched_subject)?;
    assert!(parsed.validate_minimal().is_err());

    let mut extra_field = body;
    extra_field["token_in_query"] = json!(true);
    assert!(validate_present_request_schema(&extra_field).is_err());
    assert!(serde_json::from_value::<ThirdPartyInvitePresentRequestBody>(extra_field).is_err());
    Ok(())
}
