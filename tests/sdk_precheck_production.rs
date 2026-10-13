#[test]
fn sdk_precheck_crosses_real_reducer_storage_retry_restart_and_backfill() -> anyhow::Result<()> {
    let execution = cotest::conformance::run_sdk_precheck_suite()?;
    let (fixture, _) = cotest_sdk_precheck_runner::load_fixture_and_base_event()?;
    execution.assert_complete_against(&fixture)?;
    let material = cotest::conformance::run_test_material_rejection_suite()?;
    let material_fixture = cotest::conformance::load_fixture_value(material.fixture)?;
    material.assert_complete_against(&material_fixture)?;
    let profiles = cotest::conformance::load_artifact_json("profiles/conformance-profiles.json")?;
    let mut fixtures = std::collections::BTreeMap::new();
    for entry in std::fs::read_dir(cotest::conformance::spec_artifacts_root().join("fixtures"))? {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        fixtures.insert(
            format!("fixtures/{}", path.file_name().unwrap().to_string_lossy()),
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(path)?)?,
        );
    }
    let executed = [&execution, &material]
        .into_iter()
        .flat_map(|suite| {
            suite
                .cases
                .iter()
                .map(|case| cotest_suite_evidence::CaseRef {
                    fixture_ref: format!("fixtures/{}", suite.fixture),
                    case_id: case.case_id.clone(),
                })
        })
        .collect();
    let vectors: std::collections::BTreeSet<_> = [&fixture, &material_fixture]
        .into_iter()
        .flat_map(|fixture| {
            fixture["covers_vectors"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
        })
        .collect();
    let mut owned_points = std::collections::BTreeSet::new();
    for clause in profiles["sdk_conformance_contract"]["clauses"]
        .as_array()
        .unwrap()
    {
        if let Some(points) = clause
            .pointer("/vector_evidence/decision_points")
            .and_then(serde_json::Value::as_array)
        {
            for point in points {
                if point["vectors"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|v| vectors.contains(v.as_str().unwrap()))
                {
                    owned_points.insert(format!(
                        "{}/{}",
                        clause["clause_id"].as_str().unwrap(),
                        point["id"].as_str().unwrap()
                    ));
                }
            }
        }
    }
    anyhow::ensure!(
        !owned_points.is_empty(),
        "canonical owner decision-point set is empty"
    );
    let gaps: Vec<_> =
        cotest_suite_evidence::audit_decision_points(&profiles, &fixtures, &executed)?
            .into_iter()
            .filter(|gap| owned_points.contains(&gap.decision_point))
            .collect();
    anyhow::ensure!(
        gaps.is_empty(),
        "0038b production decision-point gaps: {gaps:?}"
    );
    println!("{execution:#?}");
    println!("{material:#?}");
    println!("canonical production decision points: {owned_points:#?}");
    Ok(())
}
