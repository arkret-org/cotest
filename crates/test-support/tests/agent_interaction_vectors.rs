//! SDK conformance against the formal v1 Agent mode payload vectors.
use arkret_models_collaboration::agent_interaction::AgentInteractionSetPayload;

#[test]
fn agent_interaction_payload_vectors_match_the_closed_sdk_type() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../arkret-spec/spec/v1/artifacts/fixtures/event-kind-payload-coverage-fixture.json"
    )).unwrap();
    let mut checked = 0;
    for case in vectors["schema_validation_cases"].as_array().unwrap() {
        if case["schema_ref"]
            != "schemas/event-payload.schema.json#/$defs/agent_interaction_set_payload"
        {
            continue;
        }
        checked += 1;
        let actual =
            serde_json::from_value::<AgentInteractionSetPayload>(case["instance"].clone()).is_ok();
        assert_eq!(
            actual,
            case["expect_valid"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
    assert!(checked >= 7, "formal Agent mode cases must not disappear");
}

#[test]
fn agent_interaction_exact_vectors_and_identity_fences_match_sdk() {
    use arkret_models_collaboration::agent_interaction::{
        AgentInteractionMode, agent_interaction_from_verified_exact_read,
    };
    use arkret_models_collaboration::exact_current_results::{
        ExactCurrentResultsReadOutcome, ExactCurrentResultsReadRequestBody,
    };
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../arkret-spec/spec/v1/artifacts/fixtures/exact-current-results-read-fixture.json"
    ))
    .unwrap();
    let cases = fixture["schema_validation_cases"].as_array().unwrap();
    let request: ExactCurrentResultsReadRequestBody = serde_json::from_value(
        cases
            .iter()
            .find(|c| c["name"] == "agent_mode_exact_request")
            .unwrap()["instance"]
            .clone(),
    )
    .unwrap();
    let agent = match &request.selector {
        arkret_models_collaboration::exact_current_results::ExactCurrentResultSelector::AgentInteraction(selector) => selector.agent_account_id.clone(),
        _ => panic!("Agent vector changed family"),
    };
    let present_json = cases
        .iter()
        .find(|c| c["name"] == "agent_mode_present")
        .unwrap()["instance"]
        .clone();
    let controller: arkret_wire::AccountId =
        serde_json::from_value(present_json["entry"]["value"]["controller_account_id"].clone())
            .unwrap();
    let mut checked = 0;
    for case in cases {
        let schema = case["schema_ref"].as_str().unwrap();
        let valid = if schema.ends_with("exact_current_results_read_request") {
            serde_json::from_value::<ExactCurrentResultsReadRequestBody>(case["instance"].clone())
                .is_ok()
        } else {
            serde_json::from_value::<ExactCurrentResultsReadOutcome>(case["instance"].clone())
                .is_ok()
        };
        assert_eq!(
            valid,
            case["expect_valid"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
        checked += 1;
    }
    assert!(checked >= 7);
    for (name, expected) in [
        ("agent_mode_present", AgentInteractionMode::Public),
        ("agent_mode_never_written", AgentInteractionMode::Private),
    ] {
        let outcome: ExactCurrentResultsReadOutcome = serde_json::from_value(
            cases.iter().find(|c| c["name"] == name).unwrap()["instance"].clone(),
        )
        .unwrap();
        assert_eq!(
            agent_interaction_from_verified_exact_read(
                &outcome,
                &request.realm_id,
                &agent,
                &controller,
                4
            )
            .unwrap()
            .0,
            expected
        );
        assert!(
            agent_interaction_from_verified_exact_read(
                &outcome,
                &request.realm_id,
                &agent,
                &controller,
                5
            )
            .is_err()
        );
        let other_agent = arkret_wire::AccountId::new(
            agent.principal_id.clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        );
        assert!(
            agent_interaction_from_verified_exact_read(
                &outcome,
                &request.realm_id,
                &other_agent,
                &controller,
                4
            )
            .is_err()
        );
    }
    let present: ExactCurrentResultsReadOutcome = serde_json::from_value(present_json).unwrap();
    assert!(
        agent_interaction_from_verified_exact_read(&present, &request.realm_id, &agent, &agent, 4)
            .is_err()
    );
}
