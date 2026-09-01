use arkret_schema::agent_runtime_scope::{AgentRuntimeScopeLayer, assess_agent_runtime_scopes};

const INTERACTIVE: &[&str] = &[
    "ak.self.events.stream.subscribe.v1",
    "ak.self.events.read.scan.v1",
    "ak.self.events.read.frontier.v1",
    "ak.self.seals.read.frontier.v1",
    "ak.self.events.command.submit.v1",
];
const KEYPACKAGE_UPLOAD: &str = "ak.self.keys.keypackages.upload.create.v1";
const KEYPACKAGE_CONSUME: &str = "ak.self.keys.keypackages.command.consume.v1";

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn complete_runtime_scope() -> Vec<String> {
    let mut scope = strings(INTERACTIVE);
    scope.push(KEYPACKAGE_UPLOAD.to_owned());
    scope.push(KEYPACKAGE_CONSUME.to_owned());
    scope
}

#[test]
fn provision_key_session_deficiencies_keep_highest_layer_priority() {
    let complete = complete_runtime_scope();

    let provision = complete
        .iter()
        .filter(|operation| operation.as_str() != "ak.self.seals.read.frontier.v1")
        .cloned()
        .collect::<Vec<_>>();
    let deficiency = assess_agent_runtime_scopes(&provision, &complete, &complete)
        .unwrap()
        .unwrap();
    assert_eq!(deficiency.layer, AgentRuntimeScopeLayer::Provision);
    assert_eq!(
        deficiency.reason,
        arkret_wire::ReasonCode::AgentProvisionScopeMigrationRequired
    );

    let key = complete
        .iter()
        .filter(|operation| operation.as_str() != "ak.self.seals.read.frontier.v1")
        .cloned()
        .collect::<Vec<_>>();
    let deficiency = assess_agent_runtime_scopes(&complete, &key, &complete)
        .unwrap()
        .unwrap();
    assert_eq!(deficiency.layer, AgentRuntimeScopeLayer::KeyAuthorization);
    assert_eq!(
        deficiency.reason,
        arkret_wire::ReasonCode::AgentKeyScopeReauthorizationRequired
    );

    let session = complete
        .iter()
        .filter(|operation| operation.as_str() != "ak.self.seals.read.frontier.v1")
        .cloned()
        .collect::<Vec<_>>();
    let deficiency = assess_agent_runtime_scopes(&complete, &complete, &session)
        .unwrap()
        .unwrap();
    assert_eq!(deficiency.layer, AgentRuntimeScopeLayer::Session);
    assert_eq!(
        deficiency.reason,
        arkret_wire::ReasonCode::AgentSessionScopeRefreshRequired
    );
}

#[test]
fn event_and_seal_frontiers_are_not_substitutable() {
    for (omitted, expected_missing) in [
        (
            "ak.self.events.read.frontier.v1",
            "ak.self.events.read.frontier.v1",
        ),
        (
            "ak.self.seals.read.frontier.v1",
            "ak.self.seals.read.frontier.v1",
        ),
    ] {
        let scope = INTERACTIVE
            .iter()
            .copied()
            .filter(|operation| *operation != omitted)
            .collect::<Vec<_>>();
        let deficiency = assess_agent_runtime_scopes(&scope, INTERACTIVE, INTERACTIVE)
            .unwrap()
            .unwrap();
        assert_eq!(deficiency.layer, AgentRuntimeScopeLayer::Provision);
        assert_eq!(deficiency.missing_operations, [expected_missing]);
    }
}

#[test]
fn e2ee_activation_without_keypackage_upload_fails_at_provision() {
    let activation_only = [KEYPACKAGE_CONSUME];
    let deficiency = assess_agent_runtime_scopes(
        activation_only,
        [KEYPACKAGE_CONSUME, KEYPACKAGE_UPLOAD],
        [KEYPACKAGE_CONSUME, KEYPACKAGE_UPLOAD],
    )
    .unwrap()
    .unwrap();
    assert_eq!(deficiency.layer, AgentRuntimeScopeLayer::Provision);
    assert_eq!(deficiency.missing_operations, [KEYPACKAGE_UPLOAD]);
}

#[test]
fn assessment_never_mutates_or_widens_any_ceiling_bytes() {
    let provision = complete_runtime_scope();
    let key = complete_runtime_scope();
    let session = complete_runtime_scope();
    let before = serde_json::to_vec(&(&provision, &key, &session)).unwrap();

    assert!(
        assess_agent_runtime_scopes(&provision, &key, &session)
            .unwrap()
            .is_none()
    );

    let after = serde_json::to_vec(&(&provision, &key, &session)).unwrap();
    assert_eq!(after, before);
}

#[test]
fn lower_layers_cannot_select_interactive_or_e2ee_for_restricted_agent() {
    let provision = ["ak.event.read"];
    let lower = complete_runtime_scope();
    assert!(
        assess_agent_runtime_scopes(provision, &lower, &lower)
            .unwrap()
            .is_none()
    );
}
