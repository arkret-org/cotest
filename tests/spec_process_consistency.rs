use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

#[test]
fn invite_lifecycle_and_acceptance_membership_writes_are_exact() {
    let catalog = read_json(
        &spec_artifacts_root()
            .join("registry")
            .join("contract-registry.json"),
    );
    let contracts = &catalog["event_kind_registry"]["cell_contracts"];
    for (kind, expected_families) in [
        (
            "ak.invite.create",
            &["ak.component.invite.lifecycle.v1"][..],
        ),
        (
            "ak.invite.accept",
            &[
                "ak.component.invite.lifecycle.v1",
                "ak.component.member.state.v1",
            ][..],
        ),
        (
            "ak.invite.cancel",
            &["ak.component.invite.lifecycle.v1"][..],
        ),
        (
            "ak.invite.revoke",
            &["ak.component.invite.lifecycle.v1"][..],
        ),
    ] {
        let writes = contracts[kind]["cell_writes"]
            .as_array()
            .unwrap_or_else(|| panic!("{kind} must declare cell_writes"));
        let families = writes
            .iter()
            .map(|write| {
                write["cell_family"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{kind} write must name cell_family"))
            })
            .collect::<Vec<_>>();
        assert_eq!(families, expected_families, "{kind} write set drifted");
    }

    let accept_member = contracts["ak.invite.accept"]["cell_writes"]
        .as_array()
        .expect("ak.invite.accept cell_writes must be an array")
        .iter()
        .find(|write| write["cell_family"].as_str() == Some("ak.component.member.state.v1"))
        .expect("ak.invite.accept must write member.state");
    assert_eq!(
        accept_member
            .pointer("/effect_projection/to/const")
            .and_then(Value::as_str),
        Some("join")
    );

    let membership_fsm = &catalog["event_kind_registry"]["fsm_templates"]["ak.fsm.membership.v1"];
    let states = membership_fsm["states"]
        .as_array()
        .expect("membership states must be an array");
    assert!(
        states.iter().all(|state| state.as_str() != Some("invite")),
        "Realm membership FSM must not invent an invite state"
    );
    let transitions = membership_fsm["allowed_transitions"]
        .as_array()
        .expect("membership transitions must be an array");
    assert!(
        transitions.iter().any(|transition| {
            transition.as_array().is_some_and(|edge| {
                edge.first().and_then(Value::as_str) == Some("leave")
                    && edge.get(1).and_then(Value::as_str) == Some("join")
            })
        }),
        "exact invite acceptance requires the registered leave-to-join edge"
    );
    assert_vector_variants(
        "protocol-edge-cases-fixture.json",
        "ak.vector.invite.membership_transition_atomicity.v1",
        &[
            "create_keeps_member_leave_then_accept_joins",
            "accept_without_pending_or_claimed_invite_prestate_is_rejected",
            "cancel_rejected_leaves_member_cell_unchanged",
            "direct_inviter_cancel_missing_or_mismatched_invitee_is_reducer_projection_failed",
            "bare_member_state_ban_from_leave_uses_membership_fsm",
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
