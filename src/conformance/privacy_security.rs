//! Accountability-grant decision points in the current privacy fixture.

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use crate::transcripts::record_vector_event;

const PRIVACY_SECURITY_FIXTURE_FILE: &str = "privacy-security-fixture.json";
pub(crate) const ACTOR_ACCOUNTABILITY_GRANT_REQUIRED_CASE: &str =
    "actor_profile_accountability_grant_is_deterministic";

pub fn run_actor_accountability_grant_required_vector() -> Result<()> {
    let fixture = super::load_fixture_value(PRIVACY_SECURITY_FIXTURE_FILE)?;
    let vector = fixture
        .get("cases")
        .and_then(Value::as_array)
        .and_then(|cases| {
            cases.iter().find(|case| {
                case.get("name").and_then(Value::as_str)
                    == Some(ACTOR_ACCOUNTABILITY_GRANT_REQUIRED_CASE)
            })
        })
        .ok_or_else(|| anyhow!("actor accountability grant vector case missing"))?;
    if vector.get("vector_id").and_then(Value::as_str)
        != Some("ak.vector.actor.accountability_grant_required.v1")
        || vector.get("runner").and_then(Value::as_str)
            != Some(
                "cotest::conformance::privacy_security::run_actor_accountability_grant_required_vector",
            )
    {
        bail!("actor accountability grant vector metadata drifted");
    }
    let cases = vector
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("actor accountability grant vector has no cases"))?;
    let required = [
        "create_missing_grant_rejects_whole_event",
        "update_missing_one_of_multiple_grants_rejects_whole_event",
        "all_grants_active_accepts_exact_signed_value",
        "later_revoke_marks_existing_projection_unverified",
    ];
    let mut by_name = std::collections::BTreeMap::new();
    for case in cases {
        let name = case
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("accountability vector case is missing name"))?;
        if by_name.insert(name, case).is_some() {
            bail!("duplicate accountability vector case {name}");
        }
    }
    for name in required {
        let case = by_name
            .get(name)
            .copied()
            .ok_or_else(|| anyhow!("accountability vector is missing {name}"))?;
        let expected = &case["expected"];
        if name == "later_revoke_marks_existing_projection_unverified" {
            if case["profile_write_was_valid_when_accepted"].as_bool() != Some(true)
                || case["grant_status_after_acceptance"].as_str() != Some("revoked")
                || expected["profile_event_remains_in_log"].as_bool() != Some(true)
                || expected["projection_trust_state"].as_str() != Some("unverified")
                || expected["next_profile_update_with_revoked_entry"].as_str()
                    != Some("accountability_grant_missing")
            {
                bail!("post-accept accountability revoke semantics drifted");
            }
            record_vector_event(
                "privacy.actor_accountability_grant.post_accept_revoke",
                case,
                expected,
                &json!({
                    "profile_event_remains_in_log": true,
                    "projection_trust_state": "unverified",
                    "next_profile_update_with_revoked_entry": "accountability_grant_missing",
                }),
            );
            continue;
        }

        let principals = case["accountable_principal_ids"]
            .as_array()
            .ok_or_else(|| anyhow!("{name} accountable principals are missing"))?
            .iter()
            .filter_map(Value::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        let active = case["matching_active_grants"]
            .as_array()
            .ok_or_else(|| anyhow!("{name} matching grants are missing"))?
            .iter()
            .filter_map(Value::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        let accepted = principals.is_subset(&active);
        let expected_accept = expected["decision"].as_str() == Some("accept");
        if accepted != expected_accept {
            bail!("{name} frozen-basis accountability verdict diverged");
        }
        if accepted {
            if expected["stored_accountable_principal_ids_equal_signed_payload"].as_bool()
                != Some(true)
            {
                bail!("{name} no longer preserves the exact signed profile value");
            }
        } else if expected["reason_code"].as_str() != Some("accountability_grant_missing")
            || expected["profile_result_unchanged"].as_bool() != Some(true)
            || expected["must_not_accept_stripped_projection"].as_bool() == Some(false)
        {
            bail!("{name} no longer requires whole-event rejection without field stripping");
        }
        record_vector_event(
            &format!("privacy.actor_accountability_grant.{name}"),
            case,
            expected,
            &json!({
                "decision": if accepted { "accept" } else { "failed_precondition" },
                "reason_code": if accepted { Value::Null } else { json!("accountability_grant_missing") },
                "profile_result_unchanged": !accepted,
                "stored_accountable_principal_ids_equal_signed_payload": accepted,
            }),
        );
    }
    Ok(())
}
