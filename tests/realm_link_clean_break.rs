use std::collections::BTreeSet;
use std::fs;

use cotest::conformance::spec_artifacts_root;
use serde_json::Value;

fn artifact(relative: &str) -> Value {
    let path = spec_artifacts_root().join(relative);
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

fn string_set(value: &Value) -> BTreeSet<&str> {
    value
        .as_array()
        .expect("expected string array")
        .iter()
        .map(|item| item.as_str().expect("expected string member"))
        .collect()
}

#[test]
fn parent_membership_contract_is_co_governed_and_caller_proof_free() {
    let payload_schema = artifact("schemas/event-payload.schema.json");
    let defs = &payload_schema["$defs"];
    let parent_branch = defs["join_policy_gate"]["oneOf"]
        .as_array()
        .expect("join_policy_gate oneOf")
        .iter()
        .find(|branch| branch["allOf"][1]["properties"]["kind"]["const"] == "parent_membership")
        .expect("parent_membership gate branch");

    let description = parent_branch["allOf"][1]["properties"]["kind"]["description"]
        .as_str()
        .expect("parent_membership description");
    for required in [
        "same verified current authority-tenure service_id",
        "active join_gate_from link",
        "authoritative current member_state rows",
        "accepting transaction",
        "Cross-Station",
        "fails closed",
    ] {
        assert!(
            description.contains(required),
            "parent_membership machine contract lost `{required}`"
        );
    }

    assert_eq!(
        parent_branch["allOf"][1]["properties"]["require_min_membership"]["const"],
        "join"
    );
    let proof_kinds = string_set(&defs["join_gate_proof"]["properties"]["kind"]["enum"]);
    assert_eq!(
        proof_kinds,
        BTreeSet::from(["challenge_response", "claim_required"]),
        "parent_membership must never accept caller-supplied membership proof"
    );

    let link_kinds = string_set(&defs["realm_link_payload"]["properties"]["link_kind"]["enum"]);
    assert!(link_kinds.contains("join_gate_from"));
    assert!(link_kinds.contains("governed_by"));

    let event_registry = artifact("registry/event-kind-registry.json");
    let member_state = event_registry["event_kinds"]
        .as_array()
        .expect("event_kinds array")
        .iter()
        .find(|row| row["event_kind"] == "ak.member.state")
        .expect("ak.member.state registry row");
    let admission = member_state["payload"]
        .as_str()
        .expect("member payload note");
    for required in [
        "co-governance",
        "active join_gate_from links",
        "source authoritative current member_state rows",
        "accepting transaction",
    ] {
        assert!(
            admission.contains(required),
            "member admission contract lost `{required}`"
        );
    }
}
