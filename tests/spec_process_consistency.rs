//! Current Invite result-write and error-shape consistency checks.

use std::path::PathBuf;

use serde_json::Value;

fn artifacts() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cotest has a workspace parent")
        .join("arkret-spec/spec/v1/artifacts")
}

fn read_json(path: &str) -> Value {
    serde_json::from_slice(&std::fs::read(artifacts().join(path)).expect(path))
        .expect("valid spec JSON")
}

fn event_kind<'a>(registry: &'a Value, kind: &str) -> &'a Value {
    registry["event_kind_registry"]["event_kinds"]
        .as_array()
        .expect("event kind registry")
        .iter()
        .find(|row| row["event_kind"] == kind)
        .expect("registered Invite kind")
}

#[test]
fn invite_create_claims_one_typed_live_target_slot() {
    let registry = read_json("registry/contract-registry.json");
    let create = event_kind(&registry, "ak.invite.create");
    let families = create["result_writes"]
        .as_array()
        .expect("typed result writes")
        .iter()
        .map(|write| write["result_family"].as_str().expect("result family"))
        .collect::<Vec<_>>();
    assert_eq!(
        families,
        [
            "invite_lifecycle",
            "invite_directed_invitee",
            "invite_live_target"
        ]
    );
    let slot = &create["result_writes"][2];
    assert_eq!(
        slot["result_selector"]["components"][0]["field"],
        "payload.invitee_account_id"
    );
    assert_eq!(
        slot["result_projection"]["value_projection"]["members"][0]["envelope_field"],
        "event_id"
    );

    let event_id =
        arkret_identifiers::EventId::new("ak:event:AUf4Nwr-Lqj1RlqDi4awPbskicm37buT2CswWBfZbgLe")
            .expect("fixture create Event id");
    let details = arkret_wire::InviteLiveTargetOccupiedProblem::new(event_id.clone());
    assert_eq!(details.create_event_id(), &event_id);
    assert_eq!(
        details.invite_id().as_str(),
        "ak:invite:AUf4Nwr-Lqj1RlqDi4awPbskicm37buT2CswWBfZbgLe"
    );
}

#[test]
fn directed_invite_terminal_events_release_the_typed_slot() {
    let registry = read_json("registry/contract-registry.json");
    for kind in ["ak.invite.accept", "ak.invite.cancel", "ak.invite.revoke"] {
        let row = event_kind(&registry, kind);
        assert!(
            row["result_writes"]
                .as_array()
                .expect("typed result writes")
                .iter()
                .any(|write| write["result_family"] == "invite_live_target"),
            "{kind} omits live-target release"
        );
    }
    let vector = read_json("registry/vector-registry.json");
    assert!(
        vector["vectors"]
            .as_array()
            .expect("vector registry")
            .iter()
            .any(
                |row| row["vector_id"] == "ak.vector.invite.live_target_uniqueness.v1"
                    && row["status"] == "active"
            )
    );
}
