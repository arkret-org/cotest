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
    let fixture =
        read_json(&spec_artifacts_root().join("fixtures/protocol-edge-cases-fixture.json"));
    let vector = find_vector(
        &fixture,
        "ak.vector.invite.membership_transition_atomicity.v1",
    );
    assert_eq!(
        vector["expected"]["accepted_member_state_path"],
        serde_json::json!(["leave", "join"])
    );
    assert_eq!(
        catalog["event_kind_registry"]["fsm_templates"]["ak.fsm.membership.v1"]["states"],
        serde_json::json!(["join", "knock", "leave", "ban"])
    );
    for kind in [
        "ak.invite.create",
        "ak.invite.accept",
        "ak.invite.cancel",
        "ak.invite.revoke",
    ] {
        let writes = contracts[kind]["cell_writes"]
            .as_array()
            .unwrap_or_else(|| panic!("{kind} must declare cell_writes"));
        // governance-objects.md section 5.3: every directed invite Move also
        // touches the Realm live-target slot, which is the sole truth source
        // for "one live directed invite per invitee". accept keeps the slot
        // release last so the member join stays adjacent to the lifecycle
        // write it is atomic with.
        let expected_families: &[&str] = if kind == "ak.invite.accept" {
            &[
                "ak.component.invite.lifecycle.v1",
                "ak.component.member.state.v1",
                "ak.component.invite.live_target.v1",
            ]
        } else {
            &[
                "ak.component.invite.lifecycle.v1",
                "ak.component.invite.live_target.v1",
            ]
        };
        let actual_families: Vec<_> = writes
            .iter()
            .map(|write| {
                write["cell_family"]
                    .as_str()
                    .expect("registered cell family")
            })
            .collect();
        assert_eq!(
            actual_families, expected_families,
            "{kind} exact registered write set"
        );
        // The write count is branch-dependent, not per kind: accept and revoke
        // derive the slot write only when the payload carries
        // `invitee_account_id`, so the fixture records the maximal branch under
        // its own key rather than one number per kind.
        let counted_branch = match kind {
            "ak.invite.accept" => "ak.invite.accept.directed",
            "ak.invite.revoke" => "ak.invite.revoke.directed_terminal",
            other => other,
        };
        assert_eq!(
            vector["expected"]["registered_write_counts"][counted_branch],
            serde_json::json!(writes.len()),
            "{kind} maximal registered write count"
        );
        assert_eq!(contracts[kind]["plane"], "control");
        assert_eq!(contracts[kind]["sealed"], true);
        if kind != "ak.invite.accept" {
            continue;
        }
        assert_eq!(
            writes[0]
                .pointer("/effect_projection/to/const")
                .and_then(Value::as_str),
            Some("accepted")
        );
        let member = &writes[1];
        assert_eq!(
            member
                .pointer("/cell_subject/components/0/field")
                .and_then(Value::as_str),
            Some("envelope.actor_id")
        );
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
            Some("join")
        );
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
            "revoke_with_expired_reason_leaves_member_cell_unchanged",
            "third_party_create_and_revoke_write_no_member_state",
            "bare_member_state_ban_from_leave_uses_membership_fsm",
            "direct_inviter_cancel_revoked_is_accepted",
            "direct_inviter_cancel_missing_or_mismatched_invitee_is_reducer_projection_failed",
            "token_invite_cancel_revoked_is_invite_kind_requires_revoke",
            "token_invite_revoke_revoked_is_accepted",
            "claimed_invite_accept_is_accepted",
            "direct_create_and_accept_release_the_live_target_slot",
            "send_failed_revoke_keeps_the_live_target_slot_claimed",
        ],
    );
}

/// `ak.vector.invite.live_target_uniqueness.v1` (`conformance-vectors.md`
/// section 23.4.1).
///
/// Every claim in the vector is checked against the registry, the schemas and
/// the SDK's own projection rather than restated: the fixture names the
/// variants, and this test proves the artifacts they describe actually say what
/// they claim. The one that matters most is the prefix: the slot value is the
/// literal `ak:event:` create id, so a release Move that spells its `head_eq`
/// as `ak:invite:` can never match and would strand the account forever.
#[test]
fn invite_live_target_uniqueness_is_carried_by_the_registered_slot() {
    const FAMILY: &str = "ak.component.invite.live_target.v1";
    let catalog = read_json(
        &spec_artifacts_root()
            .join("registry")
            .join("contract-registry.json"),
    );
    let contracts = &catalog["event_kind_registry"]["cell_contracts"];

    // The claim write stores `envelope.event_id` verbatim and the subject is a
    // single-component canonical_json composite over the invitee account.
    // encoding.md section 4.1 forbids `realm_id` in a subject: the cell is
    // already located by the envelope's Realm.
    let claim = live_target_write(&contracts["ak.invite.create"], FAMILY);
    assert_eq!(claim["lattice"].as_str(), Some("cas_register"));
    assert_eq!(claim["bottom"].as_str(), Some("reject"));
    assert_eq!(claim["initial_value"].as_str(), Some("__unset__"));
    assert_eq!(
        claim
            .pointer("/effect_projection/value/envelope_field")
            .and_then(Value::as_str),
        Some("event_id"),
        "the slot value is the create Event id, not a retyped invite_id"
    );
    let components = claim
        .pointer("/cell_subject/components")
        .and_then(Value::as_array)
        .expect("single-component composite subject");
    assert_eq!(components.len(), 1);
    assert_eq!(
        components[0]["field"].as_str(),
        Some("payload.invitee_account_id")
    );
    assert_eq!(components[0]["kind"].as_str(), Some("canonical_json"));
    assert!(
        !serde_json::to_string(&claim["cell_subject"])
            .expect("subject serializes")
            .contains("realm_id"),
        "encoding.md section 4.1 forbids realm_id inside a cell subject"
    );

    // Release writes: cancel is unconditional (its account is required),
    // accept and revoke are gated on the optional account being present, and
    // every one of them sets the registered free value back.
    for (kind, condition_field) in [
        ("ak.invite.accept", Some("payload.invitee_account_id")),
        ("ak.invite.cancel", None),
        ("ak.invite.revoke", Some("payload.invitee_account_id")),
    ] {
        let release = live_target_write(&contracts[kind], FAMILY);
        assert_eq!(
            release
                .pointer("/effect_projection/value/const")
                .and_then(Value::as_str),
            Some("__unset__"),
            "{kind} releases the slot by setting the registered free value"
        );
        assert_eq!(
            release.pointer("/condition/field").and_then(Value::as_str),
            condition_field,
            "{kind} release condition"
        );
    }

    // A third-party create never claims the slot, which is what keeps 3PID
    // invites out of the directed uniqueness rule entirely.
    assert!(
        contracts["ak.invite.third_party"]["cell_writes"]
            .as_array()
            .expect("third_party cell_writes")
            .iter()
            .all(|write| write["cell_family"].as_str() != Some(FAMILY)),
        "a third-party invite MUST NOT claim the directed live-target slot"
    );

    // Both directions of the forgery/leak guard are the same predicate.
    for kind in ["ak.invite.accept", "ak.invite.revoke"] {
        let requirements = contracts[kind]["pre_state_requirements"]
            .as_array()
            .unwrap_or_else(|| panic!("{kind} must declare pre_state_requirements"));
        assert!(
            requirements.iter().all(|requirement| {
                requirement
                    .pointer("/predicate/kind")
                    .and_then(Value::as_str)
                    == Some("stored_field_matches_payload")
            }),
            "{kind} binds its optional invitee to the persisted pre-state"
        );
    }
    // `send_failed` keeps the invite live, so the schema forbids the field that
    // would derive a release write at all.
    let revoke_payload = read_json(
        &spec_artifacts_root()
            .join("schemas")
            .join("event-payload.schema.json"),
    );
    let guard = revoke_payload
        .pointer("/$defs/invite_revoke_payload/allOf")
        .and_then(Value::as_array)
        .expect("invite_revoke_payload declares its send_failed guard");
    assert!(
        guard.iter().any(|clause| {
            clause
                .pointer("/if/properties/target_state/const")
                .and_then(Value::as_str)
                == Some("send_failed")
                && clause
                    .pointer("/then/not/required")
                    .and_then(Value::as_array)
                    .is_some_and(|required| {
                        required
                            .iter()
                            .any(|field| field.as_str() == Some("invitee_account_id"))
                    })
        }),
        "send_failed MUST NOT carry invitee_account_id"
    );

    // The rejection is closed and never bypassed into cas_conflict.
    let fixture =
        read_json(&spec_artifacts_root().join("fixtures/protocol-edge-cases-fixture.json"));
    let vector = find_vector(&fixture, "ak.vector.invite.live_target_uniqueness.v1");
    assert_eq!(
        vector["expected"]["occupied_error"]["code"].as_str(),
        Some("failed_precondition")
    );
    assert_eq!(
        vector["expected"]["occupied_error"]["reason_code"].as_str(),
        Some(arkret_wire::ReasonCode::INVITE_LIVE_TARGET_OCCUPIED)
    );
    assert_eq!(
        vector["expected"]["live_states"],
        serde_json::json!(["pending", "send_failed"]),
        "claimed is unreachable for a directed invite"
    );
    let dtos = read_json(
        &spec_artifacts_root()
            .join("schemas")
            .join("service-operation-dtos.schema.json"),
    );
    let problem = &dtos["$defs"]["InviteLiveTargetOccupiedProblem"];
    assert_eq!(
        problem["required"],
        serde_json::json!(["reason_code", "invite_id", "create_event_id"])
    );
    assert_eq!(problem["additionalProperties"], serde_json::json!(false));

    // The SDK DTO derives one member from the other, so the pair cannot
    // disagree, and the head_eq value is always the `ak:event:` spelling.
    let create_event_id =
        arkret_identifiers::EventId::new("ak:event:AUf4Nwr-Lqj1RlqDi4awPbskicm37buT2CswWBfZbgLe")
            .expect("fixture create Event id");
    let details = arkret_wire::InviteLiveTargetOccupiedProblem::new(create_event_id.clone());
    assert_eq!(
        details.invite_id().as_str(),
        "ak:invite:AUf4Nwr-Lqj1RlqDi4awPbskicm37buT2CswWBfZbgLe"
    );
    let slot = arkret_schema::InviteLiveTargetSlot::held_by_invite(details.invite_id());
    assert_eq!(
        slot.head_eq_value().expect("registered contract"),
        serde_json::json!(create_event_id.as_str()),
        "a release head_eq spelled as invite_id would never match the slot"
    );
    assert_eq!(
        arkret_schema::invite_live_target_unset_value().expect("registered contract"),
        serde_json::json!("__unset__")
    );

    assert_vector_variants(
        "protocol-edge-cases-fixture.json",
        "ak.vector.invite.live_target_uniqueness.v1",
        &[
            "second_directed_create_for_the_same_account_is_rejected_with_zero_writes",
            "concurrent_directed_creates_resolve_to_one_slot_holder",
            "terminal_release_then_reinvite_is_accepted",
            "expired_at_wall_clock_alone_does_not_release_the_slot",
            "send_failed_holder_requires_revoke_before_a_new_create",
            "third_party_revoke_forging_invitee_account_id_is_reducer_projection_failed",
            "directed_revoke_omitting_invitee_account_id_is_reducer_projection_failed",
            "release_head_eq_spelled_as_invite_id_is_failed_precondition",
        ],
    );
}

fn live_target_write<'a>(contract: &'a Value, family: &str) -> &'a Value {
    contract["cell_writes"]
        .as_array()
        .expect("registered cell_writes")
        .iter()
        .find(|write| write["cell_family"].as_str() == Some(family))
        .unwrap_or_else(|| panic!("contract must declare a {family} write"))
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
