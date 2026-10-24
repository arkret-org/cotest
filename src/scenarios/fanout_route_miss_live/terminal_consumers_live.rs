//! Shared governing cut, terminal child writes and durable live navigation.

use super::terminal_restart_live::{
    ensure_ordinary_refusal_rows, hold_outbox_progress, qualified_ordinary_candidate,
    release_outbox_progress, tombstone,
};
use super::*;
use crate::harness::CanonicalJsonBody;
use crate::scenarios::_helpers::acceptance_footprint::acceptance_rows;
use crate::scenarios::circle_poll_scope_live::{circle_create, circle_event, join_circle};

pub async fn run() -> Result<()> {
    use arkret_wire::{
        ApprovalContext, ApprovalSignature, ApprovalSignatureInput, ApprovalSignatureProof,
        ApprovalSignatureProofKind, ApprovalTarget,
    };
    let Some(mut fixture) = current_origin_fixture("terminal-child-consumers").await? else {
        return Ok(());
    };
    let (_, control_commit, _) = qualified_ordinary_candidate(&fixture).await?;
    let source = fixture._governance_database.connect_url.clone();
    let receiver = fixture._member_database.connect_url.clone();
    let qualified = acceptance_rows(&source).await?;
    let forward_evidence: arkret_models_identity::ForwardAccountDeviceSignerEvidence =
        serde_json::from_value(
            qualified["forwarded_producer_device_evidence"]
                .as_array()
                .context("retained forward witnesses")?
                .iter()
                .find(|row| row["commit_id"] == control_commit.commit_id.as_str())
                .context("accepted ordinary peer producer witness")?["evidence_json"]
                .clone(),
        )?;
    // A controller and an already admitted ordinary remote writer reach the same v1
    // destructive-confirmation refusal, including a correctly signed ordinary vote.
    let source_outbox = hold_outbox_progress(&source).await?;
    for (client, approved) in [
        (&fixture.alice, false),
        (&fixture.bob, false),
        (&fixture.bob, true),
    ] {
        let event = client.author_event(&fixture.realm, EventKind::RealmDestroy.as_str(),
            json!({"reason":if approved { "ordinary approval cannot open destroy" } else { "no destructive carrier" }})).await?;
        let mut submission = EventAdmissionSubmission::new(event.clone());
        if approved {
            let (method, seed) =
                crate::scenarios::identity_test_support::test_principal_root_signing_authority(
                    &fixture.alice.actor,
                )?;
            let signer =
                arkret_signatures::Ed25519DetachedJwsSigner::from_seed(seed, method.as_str());
            let mut vote = ApprovalSignature {
                input: ApprovalSignatureInput {
                    approval_context: ApprovalContext::RealmGovernance {},
                    approval_target: ApprovalTarget::Event {
                        event_id: event.event_id.clone(),
                    },
                    request_canonical_digest: arkret_wire::Hash::new(
                        arkret_canonical::canonical_sha256(&event)?,
                    )?,
                    operation: "ak.self.events.command.submit.v1".into(),
                    action: arkret_wire::CapabilityActionId::RealmDestroy,
                    realm_id: event.realm_id.clone(),
                    initiating_actor_id: event.actor_id.clone(),
                    approver_did: arkret_wire::Did::new(&fixture.alice.actor)?,
                    approved_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
                    nonce: "cotest-terminal-destroy-ordinary-approval".into(),
                },
                proof: ApprovalSignatureProof {
                    kind: ApprovalSignatureProofKind::DetachedJws,
                    verification_method: method,
                    jws: String::new(),
                },
            };
            vote.proof.jws = signer.sign_detached_jws(
                &arkret_signatures::approval_signature::approval_signature_signing_bytes(&vote)?,
            );
            vote.validate()?;
            submission.approval_signatures = Some(vec![vote]);
        }
        let before = acceptance_rows(&source).await?;
        let response = client
            .post("/_arkret/self/events")
            .canonical_json(&submission)?
            .send()
            .await?;
        let status = response.status();
        let problem: arkret_wire::Problem = response.json().await?;
        ensure!(
            status == StatusCode::CONFLICT
                && problem.problem_type.ends_with("failed_precondition")
                && (problem.detail.contains("destructive confirmation carrier")
                    || problem
                        .detail
                        .contains("replica cannot create live effects")),
            "destroy did not reach the common gate: {status} {problem:?}"
        );
        ensure!(
            problem
                .extensions
                .get("reason_code")
                .and_then(Value::as_str)
                != Some("realm_terminal_state")
        );
        ensure_ordinary_refusal_rows(&before, acceptance_rows(&source).await?, client)?;
        if client.actor == fixture.bob.actor {
            use arkret_models_collaboration::authority_commit::{
                AuthorityForwardBranch, PeerAuthorityForwardEventRequestBody,
            };
            let mut peer_request = PeerAuthoritySubmitRequestBody::AuthorityForwardEvent(
                PeerAuthorityForwardEventRequestBody {
                    branch: AuthorityForwardBranch::AuthorityForward,
                    event_submission: submission,
                    producer_device_evidence: Some(forward_evidence.clone()),
                    producer_agent_evidence: None,
                    mls_genesis_material: None,
                },
            );
            let body_digest =
                arkret_models_collaboration::authority_commit::authority_forward_body_digest(
                    &peer_request,
                )?;
            if let PeerAuthoritySubmitRequestBody::AuthorityForwardEvent(request) =
                &mut peer_request
            {
                let evidence = request
                    .producer_device_evidence
                    .as_mut()
                    .context("fresh forward witness")?;
                let mut core = evidence.device_projection_attestation.attestation.clone();
                // The accepted ordinary control proved this immutable PCR source.
                // The real fixture Origin signs a new exact Event/body wrapper;
                // an old statement cannot authorize a different request.
                core.event_authorization.event_id = request.event_submission.event.event_id.clone();
                core.event_authorization.forward_body_digest = body_digest;
                core.attested_at =
                    arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
                core.expires_at = core.attested_at + chrono::Duration::seconds(30);
                evidence.device_projection_attestation = arkret_signatures::device_projection::sign_forward_device_projection_attestation(
                    core, evidence.device_projection_attestation.proof.verification_method.clone(),
                    &fixture.group.server(1).federation_signing_key()?)?;
            }
            peer_request.validate()?;
            let (status, body) = fixture
                .group
                .server(0)
                .signed_peer_post(
                    fixture.group.server(1),
                    PEER_EVENTS,
                    &arkret_canonical::canonical_json_bytes(&peer_request)?,
                    fixture.group.server(0).service_id(),
                )
                .await?;
            let problem: arkret_wire::Problem = serde_json::from_slice(&body)?;
            ensure!(
                status == StatusCode::CONFLICT
                    && problem.problem_type.ends_with("failed_precondition")
                    && problem.detail.contains("destructive confirmation carrier"),
                "signed peer destroy did not reach the governing cut: {status} {problem:?}"
            );
            ensure_ordinary_refusal_rows(&before, acceptance_rows(&source).await?, client)?;
        }
    }
    release_outbox_progress(source_outbox).await?;
    let actor = ActorId::account(fixture.alice_account.clone());
    let mut spaces = Vec::new();
    for kind in ["board", "list"] {
        let mut event = fixture.alice.author_event(&fixture.realm, EventKind::SpaceCreate.as_str(),
            json!({"object":{"schema":"ak.schema.space.v1","realm_id":fixture.realm,
                "kind":kind,"title":kind,"created_by":actor,"created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())}})).await?;
        event.payload.get_mut("object").context("Space object")?["created_at"] = json!(
            arkret_canonical::format_timestamp_canonical(event.created_at)
        );
        crate::harness::refresh_typed_event_proof(&mut event)?;
        submit_and_expect_commit(&fixture.alice, &fixture.alice_account, ALICE_DEVICE, &event)
            .await?;
        spaces.push(arkret_wire::SpaceId::from_event_id(&event.event_id));
    }
    let parent = fixture.alice.author_event(&fixture.realm, EventKind::SpaceParent.as_str(),
        json!({"space_id":spaces[1],"parent_space_id":spaces[0],"expected_parent_space_id":null})).await?;
    submit_and_expect_commit(
        &fixture.alice,
        &fixture.alice_account,
        ALICE_DEVICE,
        &parent,
    )
    .await?;
    let strand = fixture.alice.default_strand_id(&fixture.realm)?;
    let placement = fixture.alice.author_event(&fixture.realm, EventKind::StrandMove.as_str(),
        json!({"board_space_id":spaces[0],"strand_id":strand,"target_space_id":spaces[1],"rank":"a"})).await?;
    submit_and_expect_commit(
        &fixture.alice,
        &fixture.alice_account,
        ALICE_DEVICE,
        &placement,
    )
    .await?;
    let circle = circle_create(
        &fixture.alice,
        &fixture.realm,
        &actor,
        "Terminal retained Circle",
        "Terminal",
    )
    .await?;
    join_circle(&fixture.alice, &fixture.realm, &circle, &actor).await?;
    let live: Value = fixture
        .alice
        .get(&format!("/_arkret/self/circles/{circle}"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    ensure!(live["state"] == "active");
    let canonical = acceptance_rows(&source).await?;
    let (_, terminal) = tombstone(&fixture).await?;
    super::frozen_authority_live::settled(&source, &terminal, "delivered").await?;
    let source_outbox = hold_outbox_progress(&source).await?;
    let receiver_outbox = hold_outbox_progress(&receiver).await?;
    for (client, rows) in [(&fixture.alice, &source), (&fixture.bob, &receiver)] {
        for suffix in ["spaces", "strands"] {
            let result: Value = client
                .get(&format!(
                    "/_arkret/self/realms/{}/{suffix}?include_terminal=true",
                    fixture.realm
                ))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            ensure!(
                result[suffix]
                    .as_array()
                    .context("navigation list")?
                    .is_empty()
            );
        }
        let event = client
            .author_event(
                &fixture.realm,
                EventKind::MessageCreate.as_str(),
                message_create_text_payload(&strand, "post terminal ordinary writer")?,
            )
            .await?;
        let before = acceptance_rows(rows).await?;
        let response = client
            .post("/_arkret/self/events")
            .canonical_json(&EventAdmissionSubmission::new(event))?
            .send()
            .await?;
        ensure!(response.status() == StatusCode::CONFLICT);
        let problem: arkret_wire::Problem = response.json().await?;
        ensure!(problem.problem_type.ends_with("failed_precondition"));
        ensure_ordinary_refusal_rows(&before, acceptance_rows(rows).await?, client)?;
    }
    release_outbox_progress(receiver_outbox).await?;
    release_outbox_progress(source_outbox).await?;
    let after = acceptance_rows(&source).await?;
    for table in [
        "circle_current_states",
        "circle_member_state_current_states",
        "space_current_states",
        "space_parent_current_states",
        "strand_position_current_states",
    ] {
        ensure!(
            canonical[table] == after[table],
            "terminal rewrote canonical child {table}"
        );
    }
    fixture
        .group
        .server_mut(0)
        .restart_external_process()
        .await?;
    let response = fixture
        .alice
        .get(&format!("/_arkret/self/circles/{circle}"))
        .send()
        .await?;
    ensure!(response.status() == StatusCode::NOT_FOUND);
    let restore = fixture
        .alice
        .author_event(
            &fixture.realm,
            EventKind::CircleRestore.as_str(),
            json!({"target_ref":circle}),
        )
        .await?;
    let source_outbox = hold_outbox_progress(&source).await?;
    let stable = acceptance_rows(&source).await?;
    let response = fixture
        .alice
        .post("/_arkret/self/events")
        .canonical_json(&EventAdmissionSubmission::new(restore))?
        .send()
        .await?;
    let status = response.status();
    let problem: arkret_wire::Problem = response.json().await?;
    ensure!(
        status == StatusCode::CONFLICT && problem.problem_type.ends_with("failed_precondition"),
        "terminal must precede unsupported Circle restore: {status} {problem:?}"
    );
    ensure_ordinary_refusal_rows(&stable, acceptance_rows(&source).await?, &fixture.alice)?;
    let event = circle_event(&fixture.alice, &fixture.realm, &circle, EventKind::CircleMemberState,
        json!({"circle_id":circle,"member_id":actor,"membership":"leave","expected_membership":"join"})).await?;
    let stable = acceptance_rows(&source).await?;
    let response = fixture
        .alice
        .post("/_arkret/self/events")
        .canonical_json(&EventAdmissionSubmission::new(event))?
        .send()
        .await?;
    ensure!(response.status() == StatusCode::CONFLICT);
    let problem: arkret_wire::Problem = response.json().await?;
    ensure!(problem.problem_type.ends_with("failed_precondition"));
    ensure_ordinary_refusal_rows(&stable, acceptance_rows(&source).await?, &fixture.alice)?;
    release_outbox_progress(source_outbox).await?;
    println!(
        "[terminal-consumers] controller_destroy_denied=1 signed_peer_destroy_denied=2 ordinary_vote_not_destructive_carrier=1 actual_space_placement=1 effective_circle_closed=1 canonical_children_unchanged=1 cold_restart_navigation_closed=1 ordinary_self_peer_denied=2"
    );
    Ok(())
}
