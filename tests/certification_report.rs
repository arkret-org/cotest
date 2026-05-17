use anyhow::Result;

#[test]
fn offline_live_stack_report_marks_unconfigured_services_explicitly() -> Result<()> {
    let report = cotest::scenarios::certification_report::offline_live_stack_certification_report();
    let services = report
        .services
        .iter()
        .map(|entry| entry.service.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    for service in ["soland", "floria", "teabay", "starid", "coauth"] {
        assert!(services.contains(service), "missing {service}");
    }
    assert!(
        report
            .services
            .iter()
            .all(|entry| entry.status == "skipped" && entry.reason.is_some())
    );

    let json =
        cotest::scenarios::certification_report::render_stack_certification_report_json(&report)?;
    assert!(json.contains("cx.cotest.live_stack_certification_report.v1"));
    let markdown =
        cotest::scenarios::certification_report::render_stack_certification_report_markdown(
            &report,
        );
    assert!(markdown.contains("| soland | skipped |"));
    Ok(())
}
