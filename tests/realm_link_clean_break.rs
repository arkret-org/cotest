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
fn rejects_automatic_realm_inheritance_without_current_v1_carrier() {
    let event_registry = artifact("registry/event-kind-registry.json");
    let event_kinds: BTreeSet<_> = event_registry["event_kinds"]
        .as_array()
        .expect("event_kinds array")
        .iter()
        .filter_map(|row| row["event_kind"].as_str())
        .collect();
    for retired in ["ak.realm.inheritance_policy", "ak.capability.derived"] {
        assert!(
            !event_kinds.contains(retired),
            "retired automatic-inheritance Event kind {retired} is registered"
        );
    }

    let operation_registry = artifact("registry/operation-registry.json");
    assert!(
        operation_registry["operations"]
            .as_array()
            .expect("operations array")
            .iter()
            .all(|row| row["operation_id"] != "ak.self.realm_link.read.effective_policy.v1"),
        "retired automatic effective-policy read operation is registered"
    );

    let current_registry = artifact("registry/current-result-registry.json");
    assert!(
        current_registry["result_kinds"]
            .as_array()
            .expect("result_kinds array")
            .iter()
            .all(|row| row["result_kind"] != "realm_inheritance_policy"),
        "retired inheritance typed-current family is registered"
    );

    let payload_schema = artifact("schemas/event-payload.schema.json");
    let defs = payload_schema["$defs"].as_object().expect("payload $defs");
    for retired in [
        "capability_derived_payload",
        "inheritance_policy_status",
        "realm_inheritance_policy_payload",
    ] {
        assert!(
            !defs.contains_key(retired),
            "retired automatic-inheritance schema {retired} remains reachable"
        );
    }

    let link_kinds = string_set(&defs["realm_link_payload"]["properties"]["link_kind"]["enum"]);
    assert!(link_kinds.contains("governed_by"));
    assert!(link_kinds.contains("join_gate_from"));
    assert!(!link_kinds.contains("inherits_policy_from"));

    let link_properties = defs["realm_link_payload"]["properties"]
        .as_object()
        .expect("realm_link_payload properties");
    for forbidden in [
        "inherits",
        "policy_rules",
        "capability_bundles",
        "notification_defaults",
    ] {
        assert!(
            !link_properties.contains_key(forbidden),
            "Realm link regained automatic {forbidden} propagation"
        );
    }

    let link_operation_schema = artifact("schemas/realm-link-operations.schema.json");
    assert!(
        link_operation_schema["$defs"]
            .as_object()
            .expect("realm-link operation $defs")
            .get("realm_effective_policy_outcome")
            .is_none(),
        "retired effective-policy response schema is still exposed"
    );
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
