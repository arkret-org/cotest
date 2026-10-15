//! The current join floor also bounds an Agent's own accepted Message.
use super::content_grant_evidence::GrantFixture;
use super::*;
use crate::harness::expect_api_error;

pub const REVIEWED_HISTORY_CONTENT_CASES: [&str; 1] = ["history_not_visible"];

pub async fn run_agent_content_history_production()
-> Result<crate::conformance::SuiteExecutionResult> {
    let fixture = crate::conformance::load_fixture_value("agent-vectors-fixture.json")?;
    let contract = &fixture["session_content_authority_contract"];
    ensure!(
        arkret_canonical::sha256_hex(arkret_canonical::canonical_json_bytes(
            &contract["defaults"]
        )?) == "49fad7028393f37d28ca1a4ee06c376d6b16be0a16e4bfa35b77826a53130665",
        "review changed history baseline"
    );
    let rows = contract["cases"]
        .as_array()
        .context("canonical history cases")?
        .iter()
        .filter(|row| row["name"] == "history_not_visible")
        .collect::<Vec<_>>();
    ensure!(
        rows.len() == 1
            && rows[0]["input"] == json!({"phase":"payload","history_visible":false})
            && rows[0]["expected"] == "deny",
        "review changed history payload obligation"
    );
    let scene = GrantFixture::establish().await?;
    let controller = &scene.deployment.controller;
    let grant = scene.grant(&scene.a, &["ak.message.create"]).await?;
    let (runtime, _) = scene.issue().await?;
    let original = scene
        .commit_message(
            &runtime,
            &scene.a,
            &grant,
            "Own Message in the original join interval",
        )
        .await?;
    ensure!(
        runtime
            .sdk()
            .committed_event_get(&original.event_id)
            .await?
            .reducer_input()
            == Some(&original)
    );
    let original_view = controller
        .sdk()
        .committed_event_get(&original.event_id)
        .await?;
    let before = controller
        .sdk()
        .scan_commit_stream_to_head(
            scene.realm.clone(),
            arkret_wire::CommitStreamRef::Realm {
                realm_id: scene.realm.clone(),
            },
            None,
            100,
        )
        .await?;
    let owner_joins = before
        .committed_events
        .iter()
        .filter_map(arkret::CommittedEventView::reducer_input)
        .filter(|event| {
            event.kind == arkret_wire::EventKind::MemberState
                && event.payload["member_id"]
                    == json!(ActorId::account(scene.deployment.account.clone()))
                && event.payload["membership"] == "join"
        })
        .collect::<Vec<_>>();
    ensure!(
        owner_joins.len() == 1,
        "fixture controller join must be unique and unchanged"
    );
    let generation = owner_joins[0].event_id.clone();
    let leave = controller
        .author_event(
            scene.realm.as_str(),
            "ak.member.state",
            json!({
        "member_id":ActorId::account(scene.agent.agent_account.clone()),"membership":"leave"}),
        )
        .await?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        controller,
        &scene.deployment.account,
        &controller.device_id,
        &leave,
    )
    .await?;
    let mut payload = MembershipPayload::join(
        scene.realm.clone(),
        ActorId::account(scene.agent.agent_account.clone()),
        "New current join interval",
    );
    payload.agent_controller_binding = Some(AgentControllerMembershipBinding {
        controller_account_id: scene.deployment.account.clone(),
        controller_membership_generation_ref: generation,
        controller_terminal_event_ref: None,
    });
    let rejoin = controller
        .author_event(scene.realm.as_str(), "ak.member.state", payload.to_value()?)
        .await?;
    let joined = crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        controller,
        &scene.deployment.account,
        &controller.device_id,
        &rejoin,
    )
    .await?;
    ensure!(
        joined.event_ref == rejoin.event_id
            && joined.stream_ref == original_view.commit().stream_ref
            && original_view.commit().stream_position < joined.stream_position
    );
    joined.validate_content_address()?;
    let new_message = controller
        .author_event(
            scene.realm.as_str(),
            "ak.message.create",
            serde_json::to_value(
                arkret_models_collaboration::events_payloads::MessageCreatePayload::with_content(
                    scene.a.clone(),
                    "discussion",
                    arkret_models_collaboration::events_payloads::ContentBlock::text(
                        "Current post-rejoin payload",
                    ),
                ),
            )?,
        )
        .await?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        controller,
        &scene.deployment.account,
        &controller.device_id,
        &new_message,
    )
    .await?;
    let actions = scene
        .operations
        .iter()
        .map(String::as_str)
        .filter(|action| *action != "ak.message.create")
        .collect::<Vec<_>>();
    let (fresh, claims) = scene.issue_for(&actions, scene.selectors()).await?;
    ensure!(claims.scopes.iter().any(|action| action == "ak.event.read"));
    let current = fresh
        .sdk()
        .committed_event_get(&new_message.event_id)
        .await?;
    ensure!(
        current.reducer_input() == Some(&new_message)
            && current.commit().stream_position > joined.stream_position
    );
    expect_api_error(
        fresh.get(&format!(
            "/_arkret/self/committed-events/{}",
            scene.message.event_id
        )),
        StatusCode::NOT_FOUND,
        arkret_wire::ErrorCode::NOT_FOUND,
    )
    .await?;
    println!(
        "[agent-history-controls] actual_rejoin_new_interval=1 same_agent_key_and_current_controller=1 post_rejoin_payload_full=1 prior_other_author_hidden=1"
    );
    expect_api_error(
        fresh.get(&format!(
            "/_arkret/self/committed-events/{}",
            original.event_id
        )),
        StatusCode::FORBIDDEN,
        arkret_wire::ErrorCode::CAPABILITY_DENIED,
    )
    .await?;
    ensure!(
        controller
            .sdk()
            .committed_event_get(&original.event_id)
            .await?
            .reducer_input()
            == Some(&original)
    );
    println!(
        "[agent-history] current_read_positive=1 original_join_not_restored=1 prior_self_author_hidden=1 controller_original_retained=1"
    );
    Ok(crate::conformance::SuiteExecutionResult {
        entrypoint: "ak.suite.agent.vectors.v1",
        fixture: "agent-vectors-fixture.json",
        cases: vec![crate::conformance::CaseExecutionResult {
            case_id: "history_not_visible".to_owned(),
            assertions: 1,
        }],
    })
}
