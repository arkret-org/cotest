//! Canonical Agent evidence must come from the real admission consumer.

#[test]
fn agent_genesis_cases_cross_real_http_admission_and_preserve_rejected_state() -> anyhow::Result<()>
{
    let execution = cotest::conformance::run_agent_vectors_production_suite()?;
    println!("{execution:#?}");
    let fixture = cotest::conformance::load_fixture_value("agent-vectors-fixture.json")?;
    let mut cases = fixture["schema_validation_cases"]
        .as_array()
        .unwrap()
        .clone();
    cases.extend_from_slice(fixture["cases"].as_array().unwrap());
    cases.extend_from_slice(
        fixture["session_content_authority_contract"]["cases"]
            .as_array()
            .unwrap(),
    );
    let reviewed = cotest::conformance::reviewed_agent_production_case_ids();
    assert_eq!(
        cases.len(),
        96,
        "review the complete canonical Agent inventory"
    );
    assert_eq!(reviewed.len(), cases.len());
    assert!(
        cases
            .iter()
            .all(|case| reviewed.contains(&case["name"].as_str().unwrap()))
    );
    let missing = execution.missing_against_cases(&cases)?;
    assert_eq!(execution.cases.len(), cases.len());
    assert!(missing.is_empty());
    assert!(
        execution
            .cases
            .iter()
            .any(|case| case.case_id == "agent_human_approval_required" && case.assertions == 5)
    );
    assert!(
        execution
            .cases
            .iter()
            .any(|case| case.case_id == "agent_act_on_behalf" && case.assertions == 4)
    );
    assert!(
        execution
            .cases
            .iter()
            .any(|case| case.case_id == "agent_longevity_no_expiry" && case.assertions == 8)
    );
    assert!(
        execution
            .cases
            .iter()
            .any(|case| case.case_id == "agent_controller_lifecycle" && case.assertions == 8)
    );
    assert!(
        !missing
            .iter()
            .any(|case| case == "agent_controller_lifecycle")
    );
    assert!(
        execution
            .cases
            .iter()
            .any(|case| case.case_id == "agent_provision" && case.assertions == 20)
    );
    assert!(!missing.iter().any(|case| case == "agent_provision"));
    assert!(
        execution
            .cases
            .iter()
            .any(|case| case.case_id == "agent_runtime_key_binding" && case.assertions == 13)
    );
    assert!(
        !missing
            .iter()
            .any(|case| case == "agent_runtime_key_binding")
    );
    assert!(
        execution
            .cases
            .iter()
            .any(|case| case.case_id == "agent_pcr_separation" && case.assertions == 8)
    );
    assert!(!missing.iter().any(|case| case == "agent_pcr_separation"));
    assert!(
        execution
            .cases
            .iter()
            .any(|case| case.case_id == "agent_requested_scope_privacy" && case.assertions == 4)
    );
    assert!(
        !missing
            .iter()
            .any(|case| case == "agent_requested_scope_privacy")
    );
    assert!(
        execution
            .cases
            .iter()
            .any(|case| case.case_id == "agent_repairing_supersede" && case.assertions == 8)
    );
    assert!(
        !missing
            .iter()
            .any(|case| case == "agent_repairing_supersede")
    );
    assert!(
        execution
            .cases
            .iter()
            .any(|case| case.case_id == "agent_session_grant_replay" && case.assertions == 4)
    );
    assert!(
        !missing
            .iter()
            .any(|case| case == "agent_session_grant_replay")
    );
    assert!(
        execution
            .cases
            .iter()
            .any(|case| case.case_id == "agent_presence_requires_expiry_and_refresh")
    );
    assert!(
        execution
            .cases
            .iter()
            .any(|case| case.case_id == "two_provisions_declaring_one_realm_id_rejected")
    );
    assert!(
        !missing
            .iter()
            .any(|case| case == "two_provisions_declaring_one_realm_id_rejected")
    );
    assert!(
        execution
            .cases
            .iter()
            .any(|case| case.case_id == "agent_pairing_expiry" && case.assertions == 9)
    );
    assert!(!missing.iter().any(|case| case == "agent_pairing_expiry"));
    assert!(execution.cases.iter().all(|case| case.assertions > 0));
    assert!(execution.cases.iter().any(|case| case.case_id
        == "agent_pcr_genesis_same_batch_rejected"
        && case.assertions == 3));
    assert!(
        !missing
            .iter()
            .any(|case| case == "agent_pcr_genesis_same_batch_rejected")
    );
    Ok(())
}
