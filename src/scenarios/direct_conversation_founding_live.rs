//! A Direct Conversation founded from a Contact round that production Contact
//! admission produced (`contact-and-direct-conversation.md` sections 2, 5.2,
//! 5.5 and 6.1).
//!
//! Bob requests Alice and Alice answers with a normal response, both through
//! the self Contact operations on one Station, so the pair's Contact row is
//! the one the atomic Contact admission wrote. The normal round's founder is
//! the responder: Alice authors the four-Event founding unit, names the round
//! by its `direct_conversation_contact_round` ref and submits it through the
//! self events union. The unit commits as four consecutive RealmCommits and an
//! exact retry replays them. A Message into the Direct Conversation is then
//! judged by the profile admission table; its participant evaluator needs the
//! Direct Conversation's MLS group current (task 2145), so the Message stops at
//! the registered participant refusal.

use anyhow::{Context as _, Result, anyhow, ensure};
use arkret_models_collaboration::authority_commit::{
    AggregateAcceptanceStatus, DirectConversationFoundingAcceptanceOutcome,
    DirectConversationFoundingUnitKind, DirectConversationFoundingUnitSubmission,
};
use arkret_models_collaboration::objects::direct_conversation::{
    direct_conversation_main_strand_create_payload, direct_conversation_member_join_payload,
    direct_conversation_peer_membership_bootstrap, direct_conversation_realm_create_payload,
};
use arkret_wire::{
    AccountId, ActorId, AuthoritySubmitOutcome, Did, DidCoreId, Event, EventAdmissionSubmission,
    EventId, GenesisSalt, RealmId, ScopeRef, SemanticRef, StrandId,
};
use reqwest::StatusCode;

use crate::harness::{
    TestActorClient, event_signing_identity_for_device, expect_json,
    message_create_text_payload_for_strand,
};
use crate::scenarios::identity_test_support::{
    actor_did_for_service_did, spawn_with_standard_grant_authority,
};

const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002401";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002402";
const CONTACT_ROUND_ROLE: &str = "direct_conversation_contact_round";

fn account_of(client: &TestActorClient) -> Result<AccountId> {
    Ok(AccountId::new(
        arkret_wire::project_did_to_core_id(&Did::new(client.actor.clone())?)?,
        DidCoreId::new(client.service_id().to_owned())?,
    ))
}

/// A fresh UUIDv7 idempotency key for one founding unit.
fn founding_idempotency_key() -> Result<arkret_wire::UuidV7> {
    let millis = u64::try_from(chrono::Utc::now().timestamp_millis())?;
    let key = format!(
        "{:08x}-{:04x}-7000-8000-{:012x}",
        millis >> 16,
        millis & 0xffff,
        millis
    );
    Ok(arkret_wire::UuidV7::new(key.parse()?)?)
}

/// One Event authored and signed by `client`'s device at `at`.
fn authored(
    client: &TestActorClient,
    kind: &str,
    scope_ref: ScopeRef,
    payload: serde_json::Value,
    semantic_refs: Vec<SemanticRef>,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<Event> {
    let account = account_of(client)?;
    let mut event = arkret_wire::test_support::raw_event_at(
        kind,
        scope_ref,
        account.principal_id,
        account.station_id,
        payload,
        at,
    )?;
    event.semantic_refs = semantic_refs;
    let (seed, method) = event_signing_identity_for_device(&client.actor, &client.device_id);
    let signer =
        arkret_test_kit::seeded_signer_for_seed(seed, Did::new(client.actor.clone())?, method);
    Ok(arkret_test_kit::sign_verifiable_event(
        event,
        &signer,
        arkret::canonical::DigestSuite::Sha256,
    )?
    .expect_verifiable())
}

/// The accepted normal round `holder` sees with `peer`.
async fn accepted_round(holder: &TestActorClient, peer: &AccountId) -> Result<arkret_wire::Hash> {
    let peer = ActorId::account(peer.clone());
    let row = holder
        .sdk()
        .contacts_list()
        .await?
        .contacts
        .into_iter()
        .find(|row| row.peer.contact_actor_id() == peer)
        .context("the accepted Contact row is listed")?;
    ensure!(
        row.state == arkret::ContactState::Accepted,
        "the pair's Contact round is not accepted: {:?}",
        row.state
    );
    Ok(row
        .next_prepare_input
        .context("an accepted row carries its next prepare input")?
        .contact_round_id)
}

pub async fn contact_round_founds_direct_conversation() -> Result<()> {
    let station = spawn_with_standard_grant_authority("contact-dc-founding", &[]).await?;
    let server = &station.server;
    let alice = station.standard_grant_client(
        &server
            .demo_client(
                &actor_did_for_service_did(server.service_did(), "dc-alice")?,
                ALICE_DEVICE,
            )
            .await?,
    )?;
    let bob = station.standard_grant_client(
        &server
            .demo_client(
                &actor_did_for_service_did(server.service_did(), "dc-bob")?,
                BOB_DEVICE,
            )
            .await?,
    )?;
    let alice_account = account_of(&alice)?;
    let bob_account = account_of(&bob)?;

    // Bob requests; Alice, the responder, accepts. Both directions grant
    // `direct_message`.
    bob.request_contact(&alice.actor).await?;
    alice.accept_contact(&bob).await?;
    let contact_round_id = accepted_round(&alice, &bob_account).await?;
    ensure!(
        accepted_round(&bob, &alice_account).await? == contact_round_id,
        "both holders must list the same accepted round"
    );

    // Section 5.5: Alice authors the four-Event unit and signs every Event.
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let genesis = direct_conversation_realm_create_payload(
        GenesisSalt::generate()?,
        server.trust_domain().clone(),
        server.service_id().clone(),
        at,
    )?;
    let create = authored(
        &alice,
        arkret_wire::event_kind_str::REALM_CREATE,
        ScopeRef::RealmGenesis,
        serde_json::to_value(genesis)?,
        vec![SemanticRef::new(
            contact_round_id.to_string(),
            CONTACT_ROUND_ROLE,
        )],
        at,
    )?;
    let realm_id = RealmId::from_event_id(&create.event_id);
    let realm_scope = ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let founder_join = authored(
        &alice,
        arkret_wire::event_kind_str::MEMBER_STATE,
        realm_scope.clone(),
        serde_json::to_value(direct_conversation_member_join_payload(
            realm_id.clone(),
            alice_account.clone(),
        ))?,
        Vec::new(),
        at,
    )?;
    let peer_join = authored(
        &alice,
        arkret_wire::event_kind_str::MEMBER_STATE,
        realm_scope.clone(),
        serde_json::to_value(direct_conversation_peer_membership_bootstrap(
            realm_id.clone(),
            &alice_account,
            [alice_account.clone(), bob_account.clone()],
        )?)?,
        Vec::new(),
        at,
    )?;
    let strand = authored(
        &alice,
        arkret_wire::event_kind_str::STRAND_CREATE,
        realm_scope.clone(),
        serde_json::to_value(direct_conversation_main_strand_create_payload(
            realm_id.clone(),
            ActorId::account(alice_account.clone()),
            at,
        ))?,
        Vec::new(),
        at,
    )?;
    let strand_id = StrandId::from_event_id(&strand.event_id);
    let unit = DirectConversationFoundingUnitSubmission {
        unit_kind: DirectConversationFoundingUnitKind::DirectConversationFounding,
        idempotency_key: founding_idempotency_key()?,
        events: [create, founder_join, peer_join, strand].map(EventAdmissionSubmission::new),
    };
    unit.validate()?;
    let founded: DirectConversationFoundingAcceptanceOutcome = serde_json::from_value(
        expect_json(
            alice.post("/_arkret/self/events").json(&unit),
            StatusCode::OK,
        )
        .await?,
    )
    .context("the founding response is the closed founding outcome")?;
    founded.validate()?;
    ensure!(
        founded.status == AggregateAcceptanceStatus::Committed,
        "the first founding unit must commit"
    );
    let unit_event_ids: Vec<EventId> = unit
        .events
        .iter()
        .map(|submission| submission.event.event_id.clone())
        .collect();
    for (position, commit) in founded.commits.iter().enumerate() {
        ensure!(
            commit.stream_position == position as u64
                && commit.event_ref == unit_event_ids[position]
                && commit.realm_id == realm_id,
            "founding Commit {position} does not cover its unit Event"
        );
    }

    // Section 5.5: an exact retry replays the same four source Commits.
    let replayed: DirectConversationFoundingAcceptanceOutcome = serde_json::from_value(
        expect_json(
            alice.post("/_arkret/self/events").json(&unit),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        replayed.status == AggregateAcceptanceStatus::Duplicate
            && replayed.commits == founded.commits,
        "an exact founding retry must replay the committed unit"
    );

    // Section 8.4: the Message is judged by the profile admission table. Its
    // participant evaluator reads the Direct Conversation's MLS group current,
    // which task 2145 owns; until then it refuses as a closed Event outcome.
    let message = authored(
        &bob,
        arkret_wire::event_kind_str::MESSAGE_CREATE,
        realm_scope,
        message_create_text_payload_for_strand(strand_id, "hello, Alice")?,
        Vec::new(),
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    )?;
    let outcome: AuthoritySubmitOutcome = serde_json::from_value(
        expect_json(
            bob.post("/_arkret/self/events")
                .json(&EventAdmissionSubmission::new(message)),
            StatusCode::OK,
        )
        .await?,
    )?;
    match outcome {
        AuthoritySubmitOutcome::Rejected { reason_code, .. }
            if reason_code == "direct_conversation_participant_authority_denied" =>
        {
            Ok(())
        }
        other => Err(anyhow!(
            "the Direct Conversation Message must stop at the participant evaluator: {other:?}"
        )),
    }
}
