use anyhow::{Context, Result, ensure};
use cotest::scenarios::protocol_payloads::snapshot_head_disclosure::*;
use reqwest::StatusCode;
use serde_json::json;

use crate::conformance::account_blocklist_projection::native_account_session;
use crate::harness::expect_json;

fn ensure_paired_calendar_source(entries: &[arkret_wire::TypedCurrentRow]) -> Result<()> {
    use arkret_wire::{CurrentSelector, TypedCurrentRow};
    let strands = entries
        .iter()
        .filter_map(|row| match row {
            TypedCurrentRow::Value {
                selector: CurrentSelector::Strand { strand_id },
                source_stream_ref,
                revision,
                ..
            } => Some((strand_id, source_stream_ref, revision)),
            _ => None,
        })
        .collect::<Vec<_>>();
    let sources = entries
        .iter()
        .filter_map(|row| match row {
            TypedCurrentRow::Value {
                selector: CurrentSelector::CalendarScheduleSource { strand_id },
                source_stream_ref,
                revision,
                value,
            } => Some((strand_id, source_stream_ref, revision, value)),
            _ => None,
        })
        .collect::<Vec<_>>();
    ensure!(
        strands.len() == 1 && sources.len() == 1,
        "the founder Strand must have exactly one paired calendar source"
    );
    let (strand, stream, revision) = strands[0];
    let (source_strand, source_stream, source_revision, value) = sources[0];
    ensure!(
        source_strand == strand && source_stream == stream && source_revision == revision,
        "calendar source differs from its paired Strand cut"
    );
    let source: arkret_wire::CalendarScheduleSourceValue = serde_json::from_value(value.clone())?;
    source.validate_for_current(stream.realm_id(), stream, revision)?;
    ensure!(
        source.source.is_none() && source.metadata_context.is_none(),
        "discussion Strand calendar source must retain its empty schedule intent"
    );
    Ok(())
}

async fn account_detail_frames(
    client: &crate::harness::TestActorClient,
    filter: &serde_json::Value,
    after: Option<&str>,
) -> Result<Vec<arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame>>
{
    let filter = String::from_utf8(arkret_canonical::canonical_json_bytes(filter)?)?;
    let mut query = vec![("filter", filter.as_str())];
    if let Some(after) = after {
        query.push(("after", after));
    }
    let response = client
        .get("/_arkret/self/account/subscribe")
        .query(&query)
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;
    ensure!(
        status == StatusCode::OK,
        "account subscribe {status}: {body}"
    );
    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let frame: arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame =
                serde_json::from_str(line).with_context(|| format!("closed Account frame: {line}"))?;
            frame
                .validate()
                .map_err(|error| anyhow::anyhow!("Account frame contract: {error}: {line}"))?;
            Ok(frame)
        })
        .collect()
}

pub async fn preview_account_window_backfills_without_failing_its_sibling_realm() -> Result<()> {
    let SnapshotAuthor {
        _coauth,
        server: _server,
        author,
    } = snapshot_author("account-window-preview-backfill", "window-frank").await?;
    let native = native_account_session(&author).await?;
    let bootstrap = |title: &str| {
        json!({
            "title": title,
            "summary": title,
            "public": false,
            "plaintext_visible_services": []
        })
    };
    let preview_id = author
        .create_realm_bootstrap_with(bootstrap("Preview backfill"))
        .await?["realm_id"]
        .as_str()
        .context("preview realm_id")?
        .to_owned();
    author.create_default_strand(&preview_id).await?;
    let sibling_id = author
        .create_realm_bootstrap_with(bootstrap("Verified sibling"))
        .await?["realm_id"]
        .as_str()
        .context("sibling realm_id")?
        .to_owned();

    // Soland answers one Realm detail per subscribe turn; continue on the
    // returned cursor until both details arrived, as one projected batch.
    let filter = json!({"realm_ids": [preview_id, sibling_id], "window_limit": 8});
    let mut batch = Vec::new();
    let mut after: Option<String> = None;
    for _ in 0..4 {
        for frame in account_detail_frames(&author, &filter, after.as_deref()).await? {
            after = frame.cursor.clone().or(after);
            batch.push(frame);
        }
        let seen = |realm: &str| {
            batch.iter().any(|frame| {
                frame
                    .realms
                    .as_ref()
                    .is_some_and(|realms| realms.entries.contains_key(realm))
            })
        };
        if seen(&preview_id) && seen(&sibling_id) {
            break;
        }
    }
    let frame_of = |realm: &str| {
        batch
            .iter()
            .find(|frame| {
                frame
                    .realms
                    .as_ref()
                    .is_some_and(|realms| realms.entries.contains_key(realm))
            })
            .with_context(|| format!("the Account batch carries the {realm} detail"))
    };
    let preview_frame = frame_of(&preview_id)?;
    let sibling_frame = frame_of(&sibling_id)?;
    let preview = realm_detail(preview_frame, &preview_id)?;
    let preview_window = &preview
        .streams
        .as_deref()
        .with_context(|| format!("preview window: {preview:?}"))?[0];
    ensure!(
        preview_window.limited
            && preview_window.preview_only == Some(true)
            && preview_window.window_start_basis.is_none()
            && window_positions(&preview) == (1..=8).collect::<Vec<_>>()
            && preview.current.is_some(),
        "a limited window without an issued anchor is preview only: {preview_window:?}"
    );
    let sibling = realm_detail(sibling_frame, &sibling_id)?;
    let sibling_window = &sibling
        .streams
        .as_deref()
        .with_context(|| format!("sibling window: {sibling:?}"))?[0];
    ensure!(
        !sibling_window.limited
            && sibling_window.preview_only.is_none()
            && window_positions(&sibling) == (0..=6).collect::<Vec<_>>(),
        "the seven-Commit sibling fits its window: {sibling_window:?}"
    );

    let http = native.client();
    // Inkson verifies every frame of the batch before projecting any; a
    // preview frame must not reject the batch.
    let mut verified = Vec::new();
    for frame in &batch {
        verified.push(
            inkson::realm_events_engine::verify_account_frame_commits(&http, frame)
                .await
                .context("a preview window must not fail the Account batch")?,
        );
    }
    let proof_of = |target: &arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame| {
        batch
            .iter()
            .position(|frame| std::ptr::eq(frame, target))
            .map(|index| &verified[index])
            .context("verified frame")
    };
    let sibling_proof = proof_of(sibling_frame)?;
    let verified = proof_of(preview_frame)?;
    let preview_stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: arkret_wire::RealmId::new(preview_id.clone())?,
    };
    let sibling_stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: arkret_wire::RealmId::new(sibling_id.clone())?,
    };
    ensure!(
        verified.preview_streams().is_empty()
            && verified.resolved_preview_streams()
                == &std::collections::BTreeSet::from([preview_stream.clone()]),
        "the creator's genesis replay settles the preview stream as exact"
    );
    let positions = |stream: &arkret_wire::CommitStreamRef| -> Result<Vec<u64>> {
        Ok(inkson::conformance::own_station_account_pages(verified)?
            .iter()
            .chain(inkson::conformance::own_station_account_pages(
                sibling_proof,
            )?)
            .map(|page| page.rows())
            .collect::<garth::Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .filter(|row| &row.commit().stream_ref == stream)
            .map(|row| row.commit().stream_position)
            .collect::<Vec<_>>())
    };
    ensure!(
        positions(&preview_stream)? == (0..=8).collect::<Vec<_>>()
            && positions(&sibling_stream)? == (0..=6).collect::<Vec<_>>(),
        "both streams are verified from genesis through their window heads"
    );
    ensure!(
        sibling_proof.preview_streams().is_empty()
            && sibling_proof.resolved_preview_streams().is_empty(),
        "the full-history sibling has no preview stream"
    );
    ensure!(
        realm_detail(&verified.product_frame(preview_frame), &preview_id)?.current
            == preview.current
            && realm_detail(&sibling_proof.product_frame(sibling_frame), &sibling_id)?.current
                == sibling.current,
        "a backfilled preview stream keeps its same-cut current"
    );

    let mut forged = preview_frame.clone();
    let rows = forged
        .realms
        .as_mut()
        .and_then(|realms| realms.entries.get_mut(&preview_id))
        .and_then(|entry| entry.committed_events.as_mut())
        .context("preview rows")?;
    let arkret_wire::CommittedEventView::Full(row) = &mut rows[0] else {
        anyhow::bail!("the creator reads full preview rows");
    };
    row.commit.commit_id = arkret_wire::RealmCommitId::from_digest([0x5d; 32]);
    let Err(error) =
        inkson::realm_events_engine::verify_account_frame_commits(&http, &forged).await
    else {
        anyhow::bail!("a forged preview row must fail closed");
    };
    ensure!(
        error
            .to_string()
            .contains("differs from verified stream row"),
        "forged preview row failed for another reason: {error}"
    );
    Ok(())
}

pub async fn limited_window_strand_tail_verifies_with_same_cut_current_through_inkson() -> Result<()>
{
    let SnapshotAuthor {
        _coauth,
        server: _server,
        author,
    } = snapshot_author("account-window-strand-tail", "window-grace").await?;
    let native = native_account_session(&author).await?;
    let bootstrap = author
        .create_realm_bootstrap_with(json!({
            "title": "Strand tail",
            "summary": "Strand tail",
            "public": false,
            "plaintext_visible_services": []
        }))
        .await?;
    let realm_id = bootstrap["realm_id"]
        .as_str()
        .context("realm_id")?
        .to_owned();
    let issued: arkret_wire::RealmStateSnapshot = serde_json::from_value(
        expect_json(
            author
                .get("/_arkret/self/realm-state-snapshot/head")
                .query(&[("realm_id", realm_id.as_str())]),
            StatusCode::OK,
        )
        .await?,
    )
    .context("issued head must be a closed signed snapshot")?;
    ensure!(
        issued.visible_stream_heads.len() == 1
            && issued.visible_stream_heads[0].stream_position == 6,
        "bootstrap head is position 6"
    );
    let strand_id = author.create_default_strand(&realm_id).await?;

    let frame =
        account_detail_frame(&author, json!({"realm_ids": [realm_id], "window_limit": 2})).await?;
    let entry = realm_detail(&frame, &realm_id)?;
    let [window] = entry.streams.as_deref().context("stream windows")? else {
        anyhow::bail!("a single-member Realm has exactly its Realm stream window");
    };
    ensure!(
        window.preview_only.is_none()
            && window.window_start_basis.as_ref().is_some_and(|basis| {
                basis.anchor_position == 6 && basis.snapshot_ref == issued.snapshot_id
            })
            && window_positions(&entry) == vec![7, 8],
        "the window must name the issued anchor and carry the Strand tail: {window:?}"
    );
    let current = entry.current.as_ref().context("same-cut current")?;

    let http = native.client();
    let verified = inkson::realm_events_engine::verify_account_frame_commits(&http, &frame)
        .await
        .context("a StrandCreate/default-Strand tail must verify, not fail the frame")?;
    let typed_realm = arkret_wire::RealmId::new(realm_id.clone())?;
    let stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: typed_realm.clone(),
    };
    ensure!(
        verified.preview_streams().is_empty(),
        "the snapshot window settles as exact"
    );
    ensure!(
        inkson::conformance::own_station_account_pages(&verified)?
            .iter()
            .map(|page| page.rows())
            .collect::<garth::Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .filter(|row| row.commit().stream_ref == stream)
            .map(|row| row.commit().stream_position)
            .collect::<Vec<_>>()
            == vec![7, 8],
        "the verified tail is exactly the two Commits after the issued head"
    );
    let product_frame = verified.product_frame(&frame);
    let product_entry = realm_detail(&product_frame, &realm_id)?;
    let folded = product_entry
        .current
        .as_ref()
        .context("the verified floor and tail admit an exact current")?
        .entries
        .as_slice();
    ensure!(
        folded.len() == 11 && folded == current.entries.as_slice(),
        "the installed current must be the Station's same-cut current: {folded:?}"
    );
    ensure_paired_calendar_source(folded)?;
    let strand = arkret_wire::StrandId::new(strand_id)?;
    ensure!(
        folded.iter().any(|row| matches!(
            row,
            arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::RealmSetDefaultStrand,
                value,
                ..
            } if value == &json!({"default_strand_id": strand})
        )) && folded.iter().any(|row| matches!(
            row,
            arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::Strand { strand_id },
                ..
            } if strand_id == &strand
        )),
        "the fold must carry the new Strand and the default pointer"
    );
    let at_head: arkret_wire::RealmStateSnapshot = serde_json::from_value(
        expect_json(
            author
                .get("/_arkret/self/realm-state-snapshot/head")
                .query(&[("realm_id", realm_id.as_str())]),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        at_head.current_state_entries.len() == folded.len()
            && folded
                .iter()
                .all(|row| at_head.current_state_entries.contains(row)),
        "the fold must equal the signed head current at the window head"
    );
    ensure!(
        realm_detail(&verified.product_frame(&frame), &realm_id)?.current == entry.current,
        "the exact window keeps its same-cut current"
    );

    // The client does not fold typed current (client-sync §5.1); it binds the
    // Station's current to the verified cut. A row sourced from a stream the
    // frame never settled fails the whole frame closed.
    let mut forged = frame.clone();
    let forged_entries = &mut forged
        .realms
        .as_mut()
        .and_then(|realms| realms.entries.get_mut(&realm_id))
        .and_then(|entry| entry.current.as_mut())
        .context("forged current")?
        .entries;
    if let Some(arkret_wire::TypedCurrentRow::Value {
        source_stream_ref, ..
    }) = forged_entries.first_mut()
    {
        *source_stream_ref = arkret_wire::CommitStreamRef::Circle {
            realm_id: typed_realm.clone(),
            circle_id: arkret_wire::CircleId::from_event_id(&arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0x6f; 32],
            )),
        };
    }
    let Err(error) =
        inkson::realm_events_engine::verify_account_frame_commits(&http, &forged).await
    else {
        anyhow::bail!("a current row outside the verified cut must fail closed");
    };
    ensure!(
        error
            .to_string()
            .contains("Account current row differs from its exact own Station snapshot"),
        "forged current failed for another reason: {error}"
    );
    Ok(())
}

pub async fn message_tail_window_beyond_twenty_commits_verifies_through_inkson() -> Result<()> {
    let SnapshotAuthor {
        _coauth,
        server,
        author,
    } = snapshot_author("account-window-message-tail", "window-heidi").await?;
    let native = native_account_session(&author).await?;
    // Plain-text messages need this Station in the plaintext-services facet;
    // the helper also creates the default Strand (positions 8 and 9).
    let created = author
        .create_realm_with(json!({
            "title": "Message tail",
            "summary": "Message tail",
            "public": false,
            "plaintext_visible_services": [server.service_id()]
        }))
        .await?;
    let realm_id = created["realm_id"].as_str().context("realm_id")?.to_owned();
    let strand_id = author.default_strand_id(&realm_id)?;
    let anchor: arkret_models_collaboration::authority_commit::SelfAuthoritySubmitOutcome =
        serde_json::from_value(author.send_message(&realm_id, &strand_id, "anchor").await?)?;
    anchor.validate()?;
    let arkret_models_collaboration::authority_commit::SelfAuthoritySubmitOutcome::Ordinary(
        arkret_wire::AuthoritySubmitOutcome::Accepted {
            commit: anchor_commit,
            ..
        },
    ) = anchor
    else {
        anyhow::bail!("the anchor message must be an accepted ordinary Event");
    };
    let issued: arkret_wire::RealmStateSnapshot = serde_json::from_value(
        expect_json(
            author
                .get("/_arkret/self/realm-state-snapshot/head")
                .query(&[("realm_id", realm_id.as_str())]),
            StatusCode::OK,
        )
        .await?,
    )
    .context("issued head must be a closed signed snapshot")?;
    ensure!(
        issued.visible_stream_heads[0].stream_position == 10
            && issued.visible_stream_heads[0].stream_position == anchor_commit.stream_position
            && issued.visible_stream_heads[0].commit_id == anchor_commit.commit_id
            && issued.current_state_entries.len() == 13,
        "the anchor snapshot is the message cut at position 10: {issued:?}"
    );
    ensure_paired_calendar_source(&issued.current_state_entries)?;
    for index in 0..20 {
        author
            .send_message(&realm_id, &strand_id, &format!("tail {index}"))
            .await?;
    }

    let frame = account_detail_frame(&author, json!({"realm_ids": [realm_id]})).await?;
    let entry = realm_detail(&frame, &realm_id)?;
    let [window] = entry.streams.as_deref().context("stream windows")? else {
        anyhow::bail!("a founder Realm has exactly its Realm stream window");
    };
    ensure!(
        window.limited
            && window.complete
            && window.preview_only.is_none()
            && window.next_position == 31
            && window.window_start_basis.as_ref().is_some_and(|basis| {
                basis.anchor_position == 10 && basis.snapshot_ref == issued.snapshot_id
            })
            && window_positions(&entry) == (11..=30).collect::<Vec<_>>(),
        "the default window must carry the twenty-message tail on the issued anchor: {window:?}"
    );
    let current = entry.current.as_ref().context("same-cut current")?;
    ensure!(
        current.entries.len() == 33
            && current
                .entries
                .iter()
                .filter(|row| matches!(
                    row,
                    arkret_wire::TypedCurrentRow::Value {
                        selector: arkret_wire::CurrentSelector::MessageRevision { .. },
                        ..
                    }
                ))
                .count()
                == 21,
        "the same-cut current carries every message revision: {current:?}"
    );
    ensure_paired_calendar_source(&current.entries)?;

    let http = native.client();
    let verified = inkson::realm_events_engine::verify_account_frame_commits(&http, &frame)
        .await
        .context("a message tail on a message-bearing floor must verify")?;
    ensure!(
        verified.preview_streams().is_empty(),
        "the anchored window settles as exact"
    );
    let product_frame = verified.product_frame(&frame);
    ensure!(
        realm_detail(&product_frame, &realm_id)?.current == entry.current,
        "the verified window keeps the Station's same-cut current"
    );
    let at_head: arkret_wire::RealmStateSnapshot = serde_json::from_value(
        expect_json(
            author
                .get("/_arkret/self/realm-state-snapshot/head")
                .query(&[("realm_id", realm_id.as_str())]),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        at_head.visible_stream_heads[0].stream_position == 30
            && at_head.current_state_entries == current.entries,
        "the signed head at the window head equals the same-cut current"
    );

    // Live delta: two more messages continue the delivered window. The next
    // frame on the same cursor carries exactly those two Commits on an exact
    // snapshot at the delivered head 30, and still verifies through Inkson.
    let delivered_head = window.head_commit_ref.clone();
    for index in 0..2 {
        author
            .send_message(&realm_id, &strand_id, &format!("live {index}"))
            .await?;
    }
    let cursor = frame
        .cursor
        .clone()
        .context("the window frame names its cursor")?;
    let delta_frame = account_detail_frames(
        &author,
        &json!({"realm_ids": [realm_id]}),
        Some(cursor.as_str()),
    )
    .await?
    .into_iter()
    .find(|frame| {
        frame
            .realms
            .as_ref()
            .is_some_and(|realms| realms.entries.contains_key(&realm_id))
    })
    .context("the continued subscribe delivers the Realm delta")?;
    let delta = realm_detail(&delta_frame, &realm_id)?;
    let [delta_window] = delta.streams.as_deref().context("delta stream windows")? else {
        anyhow::bail!("a founder Realm delta has exactly its Realm stream window");
    };
    ensure!(
        delta_window.preview_only.is_none()
            && delta_window.next_position == 33
            && delta_window
                .window_start_basis
                .as_ref()
                .is_some_and(|basis| {
                    basis.anchor_position == 30 && basis.anchor_commit_ref == delivered_head
                })
            && window_positions(&delta) == vec![31, 32],
        "the live delta must continue after the delivered head: {delta_window:?}"
    );
    let verified_delta =
        inkson::realm_events_engine::verify_account_frame_commits(&http, &delta_frame)
            .await
            .context("a live delta on the auto-issued head snapshot must verify")?;
    ensure!(
        verified_delta.preview_streams().is_empty(),
        "the live delta settles as exact"
    );
    Ok(())
}

pub async fn restricted_join_policy_floor_verifies_through_inkson() -> Result<()> {
    let SnapshotAuthor {
        _coauth,
        server,
        author,
    } = snapshot_author("snapshot-join-policy", "join-policy-ivy").await?;
    let native = native_account_session(&author).await?;
    let issuer = server.service_id().to_string();
    let bootstrap = author
        .create_realm_bootstrap_with(json!({
            "title": "Restricted floor",
            "join_rule": "restricted",
            "plaintext_visible_services": [],
            "join_policy": {
                "gates": [{
                    "gate_id": "employee",
                    "kind": "claim_required",
                    "required_claims": ["employee"],
                    "trusted_issuer_ids": [issuer]
                }],
                "combinator": "all"
            }
        }))
        .await?;
    let realm_id = bootstrap["realm_id"]
        .as_str()
        .context("realm_id")?
        .to_owned();
    let issued: arkret_wire::RealmStateSnapshot = serde_json::from_value(
        expect_json(
            author
                .get("/_arkret/self/realm-state-snapshot/head")
                .query(&[("realm_id", realm_id.as_str())]),
            StatusCode::OK,
        )
        .await?,
    )
    .context("a restricted founder cut must be a signed snapshot")?;
    ensure!(
        issued.visible_stream_heads[0].stream_position == 6
            && issued.current_state_entries.iter().any(|row| matches!(
                row,
                arkret_wire::TypedCurrentRow::Value {
                    selector: arkret_wire::CurrentSelector::RealmPolicyBundle,
                    value,
                    ..
                } if value.get("join_policy").is_some()
            ))
            && issued.current_state_entries.iter().any(|row| matches!(
                row,
                arkret_wire::TypedCurrentRow::Value {
                    selector: arkret_wire::CurrentSelector::RealmJoinRule,
                    value,
                    ..
                } if value == "restricted"
            )),
        "the signed cut must carry the join policy and restricted rule: {issued:?}"
    );
    author.create_default_strand(&realm_id).await?;
    let frame =
        account_detail_frame(&author, json!({"realm_ids": [realm_id], "window_limit": 2})).await?;
    let entry = realm_detail(&frame, &realm_id)?;
    let [window] = entry.streams.as_deref().context("stream windows")? else {
        anyhow::bail!("a founder Realm has exactly its Realm stream window");
    };
    ensure!(
        window.preview_only.is_none()
            && window.window_start_basis.as_ref().is_some_and(|basis| {
                basis.anchor_position == 6 && basis.snapshot_ref == issued.snapshot_id
            })
            && window_positions(&entry) == vec![7, 8],
        "the window must name the restricted cut as its basis: {window:?}"
    );
    let verified =
        inkson::realm_events_engine::verify_account_frame_commits(&native.client(), &frame)
            .await
            .context("a signed join policy floor must verify")?;
    ensure!(
        verified.preview_streams().is_empty(),
        "the restricted floor window settles as exact"
    );
    Ok(())
}
