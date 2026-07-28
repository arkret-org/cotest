use anyhow::{Result, anyhow, bail};
use chrono::{DateTime, Utc};
use serde_json::Value;

use super::load_fixture_value;

pub fn run_control_proposal_bounded_decision_suite() -> Result<()> {
    let fixture = load_fixture_value("seal-submit-fixture.json")?;
    let cases = fixture
        .get("schema_validation_cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("seal-submit fixture has no schema_validation_cases[]"))?;
    let case = |name: &str| {
        cases
            .iter()
            .find(|case| case.get("name").and_then(Value::as_str) == Some(name))
            .ok_or_else(|| anyhow!("seal-submit fixture is missing {name}"))
    };

    let receipt = case("proposal_receipt_commits_initial_and_absolute_deadlines")?;
    let receipt_instance = &receipt["instance"];
    let received_at = timestamp(receipt_instance, "received_at")?;
    let decision_due_at = timestamp(receipt_instance, "decision_due_at")?;
    let absolute_due_at = timestamp(receipt_instance, "absolute_due_at")?;
    if decision_due_at - received_at != chrono::Duration::seconds(30)
        || absolute_due_at - received_at != chrono::Duration::seconds(90)
        || receipt_instance["defer_count"].as_u64() != Some(0)
    {
        bail!("proposal receipt does not pin the 30s initial / 90s absolute window");
    }

    let second = &case("second_defer_at_immutable_absolute_deadline")?["instance"];
    if second["kind"].as_str() != Some("signed_defer")
        || second["defer_count"].as_u64() != Some(2)
        || timestamp(second, "decision_due_at")? != absolute_due_at
        || timestamp(second, "absolute_due_at")? != absolute_due_at
    {
        bail!("second defer must end exactly at the immutable absolute deadline");
    }

    let third = case("third_defer_is_schema_rejected")?;
    if third["expect_valid"].as_bool() != Some(false)
        || third["instance"]["defer_count"].as_u64() != Some(3)
    {
        bail!("third defer must be a schema rejection at defer_count=3");
    }

    let late = case("late_valid_seal_remains_accepted_and_fault_is_retained")?;
    let late_instance = &late["instance"];
    if late["semantic_outcome"].as_str() != Some("accept")
        || late["receiver_state"]["seal_acceptance"].as_str() != Some("accepted")
        || late["receiver_state"]["governance_fault_retained"].as_bool() != Some(true)
        || late_instance["kind"].as_str() != Some("signed_defer")
        || timestamp(late_instance, "decided_at")? <= decision_due_at
        || timestamp(late_instance, "absolute_due_at")? != absolute_due_at
    {
        bail!(
            "late decision vector must retain the fault while accepting the later valid Seal, without a terminal signed-reject contradiction"
        );
    }
    Ok(())
}

fn timestamp(value: &Value, field: &str) -> Result<DateTime<Utc>> {
    value[field]
        .as_str()
        .ok_or_else(|| anyhow!("{field} is missing"))?
        .parse()
        .map_err(|error| anyhow!("{field} is not an RFC3339 timestamp: {error}"))
}
