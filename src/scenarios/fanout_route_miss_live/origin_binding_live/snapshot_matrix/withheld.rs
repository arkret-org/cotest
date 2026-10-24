//! Real signed peer pages retain withdrawn content slots across a tenure change.

use coland_storage::{RetentionTombstoneRecord, RetentionTombstoneStore};
use coland_storage_postgres::PgRetentionTombstoneStore;

use super::*;

pub(super) async fn run(fixture: &CurrentOriginFixture, successor_url: &str) -> Result<()> {
    let strand = fixture.alice.default_strand_id(&fixture.realm)?;
    let mut messages = Vec::new();
    for title in [
        "retention withdrawn",
        "redaction withdrawn",
        "still disclosed",
    ] {
        messages.push(
            alice_message(
                &fixture.alice,
                &fixture.alice_account,
                &fixture.realm,
                &strand,
                title,
            )
            .await?,
        );
    }
    let redaction = fixture
        .alice
        .author_event(
            &fixture.realm,
            EventKind::MessageRedact.as_str(),
            crate::harness::message_redact_payload(
                messages[1].0.event_id.as_str(),
                Some("actual withdrawal"),
            )?,
        )
        .await?;
    let redaction_commit = submit_and_expect_commit(
        &fixture.alice,
        &fixture.alice_account,
        ALICE_DEVICE,
        &redaction,
    )
    .await?;
    let expired_at = messages[0].1.committed_at + chrono::Duration::seconds(1);
    while chrono::Utc::now() < expired_at {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let record = RetentionTombstoneRecord {
        event_id: messages[0].0.event_id.to_string(),
        realm_id: fixture.realm.clone(),
        reason: "retention_policy.ttl".into(),
        policy_ttl_seconds: 1,
        expired_at,
        tombstoned_at: chrono::Utc::now(),
        sealed: true,
    };
    // Each serving replica applies its local retention decision. Exercise
    // both read surfaces after real withdrawal, not a background TTL worker.
    for url in [
        fixture._governance_database.connect_url.as_str(),
        successor_url,
    ] {
        let db = Db::connect(Some(url), PoolTuning::default()).await?;
        let tombstones = PgRetentionTombstoneStore {
            pool: db.pool.context("serving replica retention pool")?,
        };
        tombstones.put(&record).await?;
        ensure!(tombstones.get(&record.event_id).await?.is_some());
    }
    let realm = RealmId::new(fixture.realm.clone())?;
    let stream = CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    for peer in [false, true] {
        let mut forward = Vec::new();
        for backwards in [false, true] {
            let mut cursor = None;
            let mut rows = Vec::new();
            loop {
                let request = StreamScanRequestBody {
                    realm_id: realm.clone(),
                    stream_ref: stream.clone(),
                    limit: 2,
                    direction: if backwards {
                        StreamScanDirection::Before(cursor)
                    } else {
                        StreamScanDirection::After(cursor)
                    },
                };
                let (page, truncated) = if peer {
                    let (status, bytes) = fixture
                        .group
                        .server(2)
                        .signed_peer_post(
                            fixture.group.server(1),
                            "/_arkret/peer/streams/scan",
                            &arkret_canonical::canonical_json_bytes(&request)?,
                            fixture.group.server(2).service_id(),
                        )
                        .await?;
                    ensure!(
                        status == StatusCode::OK,
                        "actual peer scan {status}: {}",
                        String::from_utf8_lossy(&bytes)
                    );
                    let page: arkret_models_collaboration::authority_commit::PeerStreamScanResponseBody =
                        serde_json::from_slice(&bytes)?;
                    page.validate_for_request(&request)?;
                    (page.committed_events, page.truncated)
                } else {
                    let page = fixture.alice.sdk().scan_commit_stream(&request).await?;
                    page.validate_for_request(&request)?;
                    (page.committed_events, page.truncated)
                };
                cursor = page.last().map(|row| row.commit().stream_position);
                rows.extend(page);
                if !truncated {
                    break;
                }
                ensure!(cursor.is_some(), "truncated page made no progress");
                ensure!(rows.len() < 200, "scan failed to terminate");
            }
            let mut ascending = rows.clone();
            if backwards {
                ascending.reverse();
            }
            for pair in ascending.windows(2) {
                ensure!(
                    pair[1].commit().stream_position == pair[0].commit().stream_position + 1
                        && pair[1].commit().previous_commit_ref.as_ref()
                            == Some(&pair[0].commit().commit_id),
                    "self/peer Commit chain broke between physical pages"
                );
            }
            for (index, (event, commit)) in messages.iter().enumerate() {
                let row = rows
                    .iter()
                    .find(|row| row.commit() == commit)
                    .context("accepted Message lost its Commit slot")?;
                if index < 2 {
                    ensure!(
                        matches!(row, arkret_wire::CommittedEventView::Withheld(_))
                            && row.reducer_input().is_none(),
                        "withdrawn original became a reducer input: {}",
                        event.event_id
                    );
                } else {
                    ensure!(
                        row.reducer_input() == Some(event),
                        "unrelated Message was withheld"
                    );
                }
            }
            ensure!(
                rows.iter().any(|row| row.commit() == &redaction_commit
                    && row.reducer_input() == Some(&redaction))
            );
            let ids = rows
                .iter()
                .map(|row| row.commit().commit_id.clone())
                .collect::<Vec<_>>();
            if backwards {
                ensure!(
                    ids == forward.iter().rev().cloned().collect::<Vec<_>>(),
                    "reverse scan differs from forward cut"
                );
            } else {
                forward = ids;
            }
        }
    }
    println!(
        "[2133-scan] actual_successor_station=1 signed_peer_tls=1 self_and_peer=1 both_directions=1 limit=2 cross_page_chain=1 retention_withheld=1 redaction_withheld=1 withheld_not_reducer=1 exact_facts_validated=1"
    );
    Ok(())
}
