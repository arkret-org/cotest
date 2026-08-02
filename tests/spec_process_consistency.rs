use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

#[test]
fn invite_membership_target_transitions_are_exact_and_atomic() {
    let catalog = read_json(
        &spec_artifacts_root()
            .join("registry")
            .join("contract-registry.json"),
    );
    let contracts = &catalog["event_kind_registry"]["cell_contracts"];
    for (kind, to) in [
        ("ak.invite.create", "invite"),
        ("ak.invite.accept", "join"),
        ("ak.invite.cancel", "leave"),
        ("ak.invite.revoke", "leave"),
    ] {
        let writes = contracts[kind]["cell_writes"]
            .as_array()
            .unwrap_or_else(|| panic!("{kind} must declare cell_writes"));
        assert_eq!(writes.len(), 2, "{kind} must atomically write two cells");
        let member = writes
            .iter()
            .find(|write| write["cell_family"].as_str() == Some("ak.component.member.state.v1"))
            .unwrap_or_else(|| panic!("{kind} must write member.state"));
        assert_eq!(
            member
                .pointer("/effect_projection/kind")
                .and_then(Value::as_str),
            Some("transition_to")
        );
        assert_eq!(
            member
                .pointer("/effect_projection/to/const")
                .and_then(Value::as_str),
            Some(to)
        );
    }
    assert_vector_variants(
        "protocol-edge-cases-fixture.json",
        "ak.vector.invite.membership_transition_atomicity.v1",
        &[
            "create_then_accept_walks_leave_invite_join",
            "accept_without_invite_prestate_is_invalid_membership_transition",
            "directed_terminal_move_missing_invitee_is_reducer_projection_failed",
            "bare_member_state_ban_from_invite_prestate_is_rejected",
        ],
    );
}

#[test]
fn join_policy_hard_gates_cover_every_entry_path() {
    assert_vector_variants(
        "protocol-edge-cases-fixture.json",
        "ak.vector.join_policy.gate_axis_orthogonality.v1",
        &[
            "invite_path_hits_principal_denylist",
            "public_realm_cooldown_still_evaluated",
            "closed_realm_applicant_self_join_rejected",
            "closed_realm_admin_write_accepted",
            "dm_bootstrap_batch_reaches_two_members",
            "dm_third_member_add_rejected",
        ],
    );
}

fn assert_vector_variants(fixture: &str, vector_id: &str, required: &[&str]) {
    let fixture = read_json(&spec_artifacts_root().join("fixtures").join(fixture));
    let vector = find_vector(&fixture, vector_id);
    let variants = vector["variants"]
        .as_array()
        .expect("vector variants must be an array");
    for required_variant in required {
        assert!(
            variants
                .iter()
                .any(|variant| variant.as_str() == Some(required_variant)),
            "{vector_id} must cover {required_variant}"
        );
    }
}

fn find_vector<'a>(fixture: &'a Value, vector_id: &str) -> &'a Value {
    fixture
        .get("cases")
        .or_else(|| fixture.get("vectors"))
        .unwrap_or_else(|| panic!("fixture containing {vector_id} must declare cases or vectors"))
        .as_array()
        .expect("fixture vector collection must be an array")
        .iter()
        .find(|case| case["vector_id"].as_str() == Some(vector_id))
        .unwrap_or_else(|| panic!("fixture must contain {vector_id}"))
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(
        &fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn spec_artifacts_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cotest has a workspace parent")
        .join("arkret-spec")
        .join("spec")
        .join("v1")
        .join("artifacts")
}
