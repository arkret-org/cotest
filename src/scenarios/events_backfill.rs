//! The registered stream scan backfills one Realm by stream position.

use anyhow::{Result, ensure};
use arkret_wire::{
    CommitStreamRef, CommittedEventView, RealmId, StreamScanDirection, StreamScanOutcome,
    StreamScanRequest,
};

use crate::harness::{TestActorClient, TestServerGroup, submitted_event_id};
use crate::scenarios::identity_test_support::actor_did_for_service_did;

async fn fixture(label: &str) -> Result<(TestServerGroup, TestActorClient, RealmId, Vec<String>)> {
    let group = TestServerGroup::single(label).await?;
    let server = group.server(0);
    let did = actor_did_for_service_did(server.service_did(), label)?;
    let alice = server
        .standard_client(&did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let realm = RealmId::new(alice.create_realm(label).await?)?;
    let strand = alice.default_strand_id(realm.as_str())?;
    let mut ids = Vec::new();
    for index in 0..6 {
        let accepted = alice
            .send_message(realm.as_str(), &strand, &format!("backfill {index}"))
            .await?;
        ids.push(submitted_event_id(&accepted)?.to_string());
    }
    Ok((group, alice, realm, ids))
}

async fn scan(
    client: &TestActorClient,
    realm: &RealmId,
    direction: StreamScanDirection,
    limit: u16,
) -> Result<StreamScanOutcome> {
    let request = StreamScanRequest {
        realm_id: realm.clone(),
        stream_ref: CommitStreamRef::Realm {
            realm_id: realm.clone(),
        },
        direction,
        limit,
    };
    let page = client.sdk().scan_commit_stream(&request).await?;
    page.validate_for_request(&request)?;
    Ok(page)
}

fn message_ids(items: &[CommittedEventView]) -> Vec<String> {
    items
        .iter()
        .filter_map(CommittedEventView::reducer_input)
        .filter(|event| event.kind.as_str() == "ak.message.create")
        .map(|event| event.event_id.to_string())
        .collect()
}

fn check_chain(items: &[CommittedEventView]) -> Result<()> {
    for pair in items.windows(2) {
        let newer = pair[0].commit();
        let older = pair[1].commit();
        ensure!(newer.stream_position == older.stream_position + 1);
        ensure!(newer.previous_commit_ref.as_ref() == Some(&older.commit_id));
    }
    Ok(())
}

pub async fn backfill_pages_recover_messages() -> Result<()> {
    let (_group, alice, realm, expected) = fixture("event-backfill").await?;
    let mut before = None;
    let mut all = Vec::new();
    let mut ended = false;
    for _ in 0..256 {
        let page = scan(&alice, &realm, StreamScanDirection::Before(before), 1).await?;
        ensure!(
            !page.committed_events.is_empty(),
            "truncated page was empty"
        );
        before = page
            .committed_events
            .last()
            .map(|item| item.commit().stream_position);
        all.extend(page.committed_events);
        if !page.truncated {
            ensure!(
                page.readable_floor.is_some(),
                "bottom page omitted readable floor"
            );
            ended = true;
            break;
        }
    }
    ensure!(ended, "backfill exceeded 256-page bound");
    check_chain(&all)?;
    ensure!(
        message_ids(&all) == expected.into_iter().rev().collect::<Vec<_>>(),
        "backfill missed a committed Message"
    );
    Ok(())
}

pub async fn backfill_is_stable_during_new_writes() -> Result<()> {
    let (_group, alice, realm, expected) = fixture("backfill-during-writes").await?;
    let first = scan(&alice, &realm, StreamScanDirection::Before(None), 2).await?;
    ensure!(first.truncated && first.committed_events.len() == 2);
    let newest = first.committed_events[0].commit().stream_position;
    let mut before = first.committed_events[1].commit().stream_position;
    let strand = alice.default_strand_id(realm.as_str())?;
    let mut fresh = Vec::new();
    for index in 0..2 {
        let accepted = alice
            .send_message(realm.as_str(), &strand, &format!("new {index}"))
            .await?;
        fresh.push(submitted_event_id(&accepted)?.to_string());
    }
    let mut old = first.committed_events;
    let mut ended = false;
    for _ in 0..256 {
        let page = scan(&alice, &realm, StreamScanDirection::Before(Some(before)), 2).await?;
        if let Some(last) = page.committed_events.last() {
            before = last.commit().stream_position;
        }
        old.extend(page.committed_events);
        if !page.truncated {
            ended = true;
            break;
        }
    }
    ensure!(ended, "backfill exceeded 256-page bound");
    check_chain(&old)?;
    ensure!(
        message_ids(&old) == expected.into_iter().rev().collect::<Vec<_>>(),
        "new writes changed the old-page boundary"
    );
    let forward = scan(&alice, &realm, StreamScanDirection::After(Some(newest)), 10).await?;
    ensure!(message_ids(&forward.committed_events) == fresh);
    Ok(())
}

pub async fn page_size_change_replays_the_same_position() -> Result<()> {
    let (_group, alice, realm, _) = fixture("position-page-size").await?;
    let first = scan(&alice, &realm, StreamScanDirection::Before(None), 1).await?;
    let before = first.committed_events[0].commit().stream_position;
    let second = scan(&alice, &realm, StreamScanDirection::Before(Some(before)), 3).await?;
    let replay = scan(&alice, &realm, StreamScanDirection::Before(Some(before)), 3).await?;
    ensure!(
        second == replay,
        "positional continuation was not repeatable"
    );
    ensure!(second.committed_events.len() == 3);
    ensure!(second.committed_events[0].commit().stream_position + 1 == before);
    Ok(())
}
