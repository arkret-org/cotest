//! Executable current Poll reducer vector over accepted RealmCommit positions.
//!
//! The vector registry names the normative rules in content-types.md §4.9;
//! it does not publish a JSON fixture. These cases use the production reducer.

use std::collections::BTreeSet;

use anyhow::{Result, ensure};
use arkret_canonical::DigestSuite;
use arkret_models_collaboration::events_payloads::message::PollResponseHead;
use arkret_models_collaboration::poll::{
    PollError, PollPartition, PollResponseSet, VerifiedPollResponse, validate_poll_selections,
};
use arkret_wire::{
    AccountId, ActorId, CommitStreamRef, CommittedEventRef, DidCoreId, EventId, MessageId,
    RealmCommitId, RealmId,
};

fn event(byte: u8) -> EventId {
    EventId::from_digest(DigestSuite::Sha256, [byte; 32])
}

fn partition() -> PollPartition {
    let realm_id = RealmId::new("ak:realm:ASZ1iAvlGxgLC_-P6WHoR9vfijpaxbI5hoSwBx8zWTcT").unwrap();
    PollPartition {
        stream_ref: CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        realm_id,
        poll_ref: MessageId::from_event_id(&event(1)),
        poll_event_ref: event(1),
        actor_id: ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )),
    }
}

fn response(
    part: &PollPartition,
    byte: u8,
    position: u64,
    selections: &[&str],
    heads: Vec<PollResponseHead>,
) -> Result<VerifiedPollResponse, PollError> {
    let answers = ["a", "b", "c"].into_iter().map(str::to_owned).collect();
    VerifiedPollResponse::new(
        part.clone(),
        CommittedEventRef {
            event_id: event(byte),
            commit_id: RealmCommitId::from_digest([byte; 32]),
            stream_ref: part.stream_ref.clone(),
            stream_position: position,
        },
        &selections
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<Vec<_>>(),
        &answers,
        2,
        heads,
        |event_id| {
            Some((
                part.clone(),
                CommittedEventRef {
                    event_id: event_id.clone(),
                    commit_id: RealmCommitId::from_digest([2; 32]),
                    stream_ref: part.stream_ref.clone(),
                    stream_position: 4,
                },
            ))
        },
    )
}

pub fn run_poll_reducer_fixture_suite() -> Result<()> {
    let part = partition();
    let answers: BTreeSet<String> = ["a", "b", "c"].into_iter().map(str::to_owned).collect();
    let cases = [
        (vec![], PollError::EmptySelection),
        (vec!["a", "a"], PollError::DuplicateSelection),
        (vec!["x"], PollError::UnknownAnswer),
        (vec!["a", "b", "c"], PollError::SelectionLimitExceeded),
    ];
    for (values, expected) in cases {
        let values = values.into_iter().map(str::to_owned).collect::<Vec<_>>();
        ensure!(
            validate_poll_selections(&values, &answers, 2) == Err(expected),
            "poll selection validation diverged for {values:?}"
        );
    }
    ensure!(
        validate_poll_selections(&["a".to_owned(), "b".to_owned()], &answers, 2)?
            == BTreeSet::from(["a".to_owned(), "b".to_owned()])
    );

    let first = response(&part, 2, 4, &["a"], vec![])?;
    let last = response(
        &part,
        3,
        9,
        &["b", "c"],
        vec![PollResponseHead {
            poll_event_ref: part.poll_event_ref.clone(),
            response_event_ref: first.accepted_ref.event_id.clone(),
        }],
    )?;
    let middle = response(&part, 4, 6, &["c"], vec![])?;
    let wrong_head = PollResponseHead {
        poll_event_ref: event(8),
        response_event_ref: first.accepted_ref.event_id.clone(),
    };
    ensure!(
        response(&part, 5, 10, &["a"], vec![wrong_head]) == Err(PollError::InvalidHead),
        "cross-poll replacement declaration was accepted"
    );
    let cross_actor_head = PollResponseHead {
        poll_event_ref: part.poll_event_ref.clone(),
        response_event_ref: first.accepted_ref.event_id.clone(),
    };
    let mut other_actor = part.clone();
    other_actor.actor_id = ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:bob.example")?,
        DidCoreId::new("ak:did_core:web:station.example")?,
    ));
    let cross_actor_ref = CommittedEventRef {
        event_id: first.accepted_ref.event_id.clone(),
        commit_id: first.accepted_ref.commit_id.clone(),
        stream_ref: part.stream_ref.clone(),
        stream_position: first.accepted_ref.stream_position,
    };
    ensure!(
        VerifiedPollResponse::new(
            part.clone(),
            CommittedEventRef {
                event_id: event(5),
                commit_id: RealmCommitId::from_digest([5; 32]),
                stream_ref: part.stream_ref.clone(),
                stream_position: 10,
            },
            &["a".to_owned()],
            &answers,
            2,
            vec![cross_actor_head],
            |_| Some((other_actor.clone(), cross_actor_ref.clone())),
        ) == Err(PollError::InvalidHead),
        "cross-Actor replacement declaration was accepted"
    );
    let mut wrong_stream = part.clone();
    wrong_stream.stream_ref = CommitStreamRef::Realm {
        realm_id: RealmId::new("ak:realm:AYcmQBZ6x7FCwln_vbdWIyV2tJ4pOJ4rmbd6v_0Y7N9_")?,
    };
    ensure!(
        response(&wrong_stream, 5, 10, &["a"], vec![]) == Err(PollError::InvalidScope),
        "cross-Realm response was accepted"
    );

    // Receiving a later vote first cannot make a lower position the winner.
    for order in [
        [first.clone(), middle.clone(), last.clone()],
        [last.clone(), first.clone(), middle.clone()],
        [middle.clone(), last.clone(), first.clone()],
    ] {
        let mut whole = PollResponseSet::default();
        for row in order {
            whole.insert(row)?;
        }
        ensure!(
            whole.insert(response(&part, 6, 9, &["a"], vec![])?)
                == Err(PollError::CommitPositionConflict),
            "two responses at one Commit position were accepted"
        );
        let projection = whole.project(true);
        let current = &projection[&part];
        ensure!(
            current.winner.as_ref() == Some(&last.accepted_ref)
                && current.selections == BTreeSet::from(["b".to_owned(), "c".to_owned()])
                && !current.provisional,
            "poll winner followed arrival order or replacement declaration"
        );
        ensure!(
            whole.project(false)[&part].provisional,
            "a gapped Commit prefix was reported as converged"
        );
        let mut shard_a = PollResponseSet::default();
        shard_a.insert(first.clone())?;
        shard_a.insert(last.clone())?;
        let mut shard_b = PollResponseSet::default();
        shard_b.insert(middle.clone())?;
        let mut ab = shard_a.clone();
        ab.merge(&shard_b)?;
        let mut ba = shard_b.clone();
        ba.merge(&shard_a)?;
        ensure!(
            ab == whole && ba == whole,
            "replica union was not commutative"
        );
        ab.merge(&ab.clone())?;
        ensure!(ab == whole, "replica union was not idempotent");
        ab.remove(&part, &last.accepted_ref.event_id);
        ensure!(
            ab.project(true)[&part].winner.as_ref() == Some(&middle.accepted_ref),
            "validity-baseline rebuild did not reveal the preceding vote"
        );
    }
    Ok(())
}
