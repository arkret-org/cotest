//! Canonical account subscription replay, privacy, filter binding and long-poll.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountFilter, AccountSubscribeFrame, AccountSubscribeFrameKind, SyncRequestBody,
};
use arkret_wire::RealmId;
use serde_json::{Value, json};

use crate::harness::TestActorClient;

pub(crate) async fn frames(
    client: &TestActorClient,
    after: Option<String>,
    filter: Option<AccountFilter>,
    catchup: bool,
) -> Result<Vec<AccountSubscribeFrame>> {
    tokio::time::timeout(Duration::from_secs(40), async {
        let mut stream = client
            .sdk()
            .account_subscribe_frames(&SyncRequestBody {
                after,
                filter,
                catchup: Some(catchup),
                ..Default::default()
            })
            .await?;
        let mut result = Vec::new();
        while let Some(frame) = stream.next_frame().await? {
            let stop = if catchup {
                frame.kind == AccountSubscribeFrameKind::CatchupComplete
            } else {
                matches!(
                    frame.kind,
                    AccountSubscribeFrameKind::Delta | AccountSubscribeFrameKind::Checkpoint
                )
            };
            result.push(frame);
            if stop {
                break;
            }
        }
        ensure!(!result.is_empty(), "subscription returned no frames");
        if catchup {
            ensure!(
                result.last().unwrap().kind == AccountSubscribeFrameKind::CatchupComplete,
                "missing explicit catchup completion"
            );
        }
        ensure!(
            result.iter().all(|f| !matches!(
                f.kind,
                AccountSubscribeFrameKind::Dropped
                    | AccountSubscribeFrameKind::ResyncRequired
                    | AccountSubscribeFrameKind::Unauthorized
            )),
            "subscription lost its authorized cut"
        );
        Ok(result)
    })
    .await
    .context("account subscription exceeded its server bound")?
}

fn cursor(frames: &[AccountSubscribeFrame]) -> Result<String> {
    frames
        .iter()
        .rev()
        .find_map(|f| f.cursor.clone())
        .context("account subscription omitted cursor")
}

fn buckets(frames: &[AccountSubscribeFrame]) -> Result<Vec<(String, Value)>> {
    let mut result = Vec::new();
    for frame in frames
        .iter()
        .filter(|f| f.kind == AccountSubscribeFrameKind::Delta)
    {
        if let Some(realms) = &frame.realms {
            for (id, bucket) in serde_json::to_value(realms)?
                .as_object()
                .context("Realm buckets")?
            {
                result.push((id.clone(), bucket.clone()));
            }
        }
    }
    Ok(result)
}

fn messages(frames: &[AccountSubscribeFrame], realm: &str) -> Result<Vec<String>> {
    let mut result = Vec::new();
    for (_, bucket) in buckets(frames)?.into_iter().filter(|(id, _)| id == realm) {
        if let Some(items) = bucket["committed_events"].as_array() {
            for item in items {
                if item["event"]["kind"] == "ak.message.create" {
                    result.push(
                        item["event"]["event_id"]
                            .as_str()
                            .context("Message Event id")?
                            .to_owned(),
                    );
                }
            }
        }
    }
    result.sort();
    Ok(result)
}

fn filter(realms: &[String], limit: u32) -> Result<AccountFilter> {
    Ok(AccountFilter {
        realm_ids: Some(
            realms
                .iter()
                .map(|r| RealmId::new(r.clone()))
                .collect::<std::result::Result<_, _>>()?,
        ),
        window_limit: Some(limit),
        ..Default::default()
    })
}

async fn collect_messages(
    client: &TestActorClient,
    after: Option<String>,
    filter: AccountFilter,
    realm: &str,
    expected: &[String],
) -> Result<Vec<AccountSubscribeFrame>> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut expected = expected.to_vec();
    expected.sort();
    loop {
        let mut result = Vec::new();
        let mut next = after.clone();
        for _ in 0..=filter.realm_ids.as_ref().map_or(0, Vec::len) {
            let batch = frames(client, next.clone(), Some(filter.clone()), true).await?;
            let advanced = cursor(&batch)?;
            result.extend(batch);
            let observed = messages(&result, realm)?;
            // An initial multi-Realm read may serve one detail per cursor.
            // Save the baseline only after every selected Realm was consumed.
            let delivered = buckets(&result)?
                .into_iter()
                .map(|(id, _)| id)
                .collect::<std::collections::BTreeSet<_>>();
            let initial_details_complete = after.is_some()
                || filter.realm_ids.as_ref().is_none_or(|selected| {
                    selected.iter().all(|id| delivered.contains(id.as_str()))
                });
            if observed == expected && initial_details_complete {
                return Ok(result);
            }
            if next.as_ref() == Some(&advanced) {
                break;
            }
            next = Some(advanced);
        }
        ensure!(
            Instant::now() < deadline,
            "account replay did not converge to the exact accepted Message set: expected={expected:?}, observed={:?}, initial={}",
            messages(&result, realm)?,
            after.is_none()
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn send(client: &TestActorClient, realm: &str, strand: &str, label: &str) -> Result<String> {
    let outcome = client.send_message(realm, strand, label).await?;
    Ok(crate::harness::submitted_event_id(&outcome)?.to_string())
}

pub async fn canonical_account_stream_api_migration() -> Result<()> {
    let owner = super::_helpers::canonical_api::fixture("account-stream").await?;
    let outsider = super::_helpers::canonical_api::fixture("account-outsider").await?;
    let client = &owner.client;
    let first = client
        .create_realm_with(json!({"title":"account replay"}))
        .await?;
    let realm = first["realm_id"]
        .as_str()
        .context("first Realm")?
        .to_owned();
    let strand = first["default_strand_id"]
        .as_str()
        .context("first Strand")?;
    let selected = filter(std::slice::from_ref(&realm), 100)?;
    let old = send(client, &realm, strand, "before saved cursor").await?;
    let baseline = collect_messages(client, None, selected.clone(), &realm, &[old]).await?;
    let saved = cursor(&baseline)?;
    let mut expected = Vec::new();
    for index in 0..3 {
        expected.push(send(client, &realm, strand, &format!("offline {index}")).await?);
    }
    let resumed = collect_messages(
        client,
        Some(saved.clone()),
        selected.clone(),
        &realm,
        &expected,
    )
    .await?;
    collect_messages(client, Some(saved), selected.clone(), &realm, &expected).await?;
    let sentinel = send(client, &realm, strand, "persisted cursor sentinel").await?;
    collect_messages(
        client,
        Some(cursor(&resumed)?),
        selected.clone(),
        &realm,
        &[sentinel],
    )
    .await?;

    let second = client
        .create_realm_with(json!({"title":"excluded account Realm"}))
        .await?;
    let other_realm = second["realm_id"]
        .as_str()
        .context("second Realm")?
        .to_owned();
    let other_strand = second["default_strand_id"]
        .as_str()
        .context("second Strand")?;
    let excluded = send(
        client,
        &other_realm,
        other_strand,
        "excluded private Message",
    )
    .await?;
    let ordered = filter(&[other_realm.clone(), realm.clone()], 100)?;
    let combined = collect_messages(
        client,
        None,
        ordered,
        &other_realm,
        std::slice::from_ref(&excluded),
    )
    .await?;
    let reordered = filter(&[realm.clone(), other_realm.clone()], 100)?;
    let sentinel = send(client, &realm, strand, "set-order cursor sentinel").await?;
    collect_messages(
        client,
        Some(cursor(&combined)?),
        reordered,
        &realm,
        &[sentinel],
    )
    .await?;
    let restricted = frames(client, None, Some(selected.clone()), true).await?;
    ensure!(
        buckets(&restricted)?.iter().all(|(id, _)| id == &realm),
        "filter disclosed another Realm"
    );
    let foreign = frames(&outsider.client, None, None, true).await?;
    ensure!(
        !serde_json::to_string(&foreign)?.contains(&excluded)
            && buckets(&foreign)?
                .iter()
                .all(|(id, _)| id != &realm && id != &other_realm),
        "outsider saw a private account cut"
    );

    let complete = frames(client, None, Some(selected.clone()), true).await?;
    let complete_ids = messages(&complete, &realm)?;
    let limited = frames(
        client,
        None,
        Some(filter(std::slice::from_ref(&realm), 2)?),
        true,
    )
    .await?;
    let mut visible = Vec::new();
    let mut declared_limited = false;
    for (_, bucket) in buckets(&limited)?
        .into_iter()
        .filter(|(id, _)| id == &realm)
    {
        let items = bucket["committed_events"]
            .as_array()
            .context("limited committed Events")?;
        ensure!(items.len() <= 2, "window_limit exceeded");
        for item in items {
            visible.push(serde_json::to_string(&item["commit"]["event_ref"])?);
        }
        if let Some(streams) = bucket["streams"].as_array() {
            for stream in streams.iter().filter(|s| s["limited"] == true) {
                declared_limited = true;
                ensure!(
                    !bucket["state_at_window_start"].is_null()
                        || stream["preview_only"] == true
                        || !stream["window_start_basis"].is_null(),
                    "truncated stream omitted its state boundary"
                );
            }
        }
    }
    let limited_ids = messages(&limited, &realm)?;
    ensure!(
        !limited_ids.is_empty() && limited_ids.iter().all(|id| complete_ids.contains(id)),
        "initial window omitted the accepted Message set"
    );
    ensure!(
        limited_ids.len() == complete_ids.len() || declared_limited,
        "omitted history was not declared limited"
    );
    ensure!(
        visible
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == visible.len(),
        "initial window duplicated Events"
    );

    for query in [
        "filter.window_limit=invalid",
        "filter.window_limit=-1",
        "filter.window_limit=1&filter.window_limit=2",
        "filter.realms=invalid",
        "filter.event_kinds=ak.message.create",
        "filter.not_event_kinds=ak.message.create",
        "filter.strand_ids=ak:strand:retired",
        "filter.lazy_load_members=invalid",
        "filter.realm_ids=invalid",
        "filter=%7B%22realm_ids%22%3A%5B%22ak%3Arealm%3Aduplicate%22%2C%22ak%3Arealm%3Aduplicate%22%5D%7D",
    ] {
        crate::harness::expect_api_error(
            client.get(&format!(
                "/_arkret/self/account/subscribe?catchup=true&{query}"
            )),
            reqwest::StatusCode::BAD_REQUEST,
            "param_invalid",
        )
        .await?;
    }
    frames(client, None, None, true).await?;
    for cross_account in [true, false] {
        let baseline = frames(client, None, Some(selected.clone()), true).await?;
        let after = cursor(&baseline)?;
        let wrong = if cross_account {
            &outsider.client
        } else {
            client
        };
        let wrong_filter = if cross_account {
            selected.clone()
        } else {
            filter(std::slice::from_ref(&realm), 99)?
        };
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("catchup", "true")
            .append_pair("after", &after)
            .append_pair("filter", &serde_json::to_string(&wrong_filter)?)
            .finish();
        crate::harness::expect_api_error(
            wrong.get(&format!("/_arkret/self/account/subscribe?{query}")),
            reqwest::StatusCode::BAD_REQUEST,
            "cursor_integrity_invalid",
        )
        .await?;
        let event = send(client, &realm, strand, "negative probe preserved cursor").await?;
        collect_messages(client, Some(after), selected.clone(), &realm, &[event]).await?;
    }

    let baseline = frames(client, None, Some(selected.clone()), true).await?;
    let mut after = cursor(&baseline)?;
    let mut quiet = None;
    for _ in 0..3 {
        let start = Instant::now();
        let batch = frames(client, Some(after), Some(selected.clone()), false).await?;
        after = cursor(&batch)?;
        if batch[0].kind == AccountSubscribeFrameKind::Checkpoint {
            ensure!(
                (Duration::from_secs(28)..Duration::from_secs(40)).contains(&start.elapsed()),
                "quiet poll did not honor its 30s bound"
            );
            quiet = Some(after.clone());
            break;
        }
    }
    let after = quiet.context("account subscription never became quiet")?;
    let start = Instant::now();
    let poll = frames(client, Some(after), Some(selected), false);
    let write = async {
        tokio::time::sleep(Duration::from_millis(150)).await;
        send(client, &realm, strand, "wake open account poll").await
    };
    let (woke, _) = tokio::try_join!(poll, write)?;
    ensure!(
        start.elapsed() < Duration::from_secs(5)
            && woke
                .iter()
                .any(|f| f.kind == AccountSubscribeFrameKind::Delta),
        "accepted Message did not wake the account poll"
    );
    println!(
        "account_stream: exact replay, exclusive cursor, Realm privacy, limited boundary, filter binding, malformed filters, quiet bound and wake latency verified"
    );
    Ok(())
}
