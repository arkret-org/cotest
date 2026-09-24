//! Phase 10 — `/_arkret/self/moderation/report` submission.

use anyhow::{Context as _, Result};
use arkret_models_collaboration::governance::moderation_queue::ModerationQueueItem;
use arkret_wire::ScopeRef;
use reqwest::StatusCode;

use crate::harness::{
    ArkretServer, TestActorClient, expect_api_error, expect_json, moderation_report_request,
};

pub async fn run(
    server: &ArkretServer,
    actor: &TestActorClient,
    target_realm_id: &str,
    target_event_id: &str,
) -> Result<()> {
    let realm_id = arkret_identifiers::RealmId::new(target_realm_id.to_owned())?;
    let request = moderation_report_request(
        actor,
        target_realm_id,
        target_event_id,
        ScopeRef::Realm { realm_id },
    )
    .await?;
    let report = expect_json(
        actor
            .authorize(
                server
                    .http()
                    .post(server.url("/_arkret/self/moderation/report")),
            )
            .json(&request),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(report["status"], "submitted");

    // Exact replay of the accepted report Event returns the stored outcome.
    let replay = expect_json(
        actor
            .authorize(
                server
                    .http()
                    .post(server.url("/_arkret/self/moderation/report")),
            )
            .json(&request),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(replay, report);

    // The moderation queue is a same-cut View over the accepted
    // `moderation_report` family: the Realm root controller sees exactly one
    // item whose id is the report Event token retyped to
    // `moderation_queue_item` and whose report is the signed payload.
    let queue_item_id = report["report_id"]
        .as_str()
        .context("report outcome carries report_id")?
        .replacen("ak:report:", "ak:moderation_queue_item:", 1);
    // The Realm root controller reads it over its standard DPoP session: the
    // admin gate authenticates the request and consumes its proof once.
    let queue = expect_json(
        actor.authorize(
            server
                .http()
                .get(server.url("/_soland/admin/moderation/queue")),
        ),
        StatusCode::OK,
    )
    .await?;
    let items = queue["items"]
        .as_array()
        .context("moderation queue carries items")?
        .iter()
        .filter(|item| item["id"] == queue_item_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(items.len(), 1, "{queue}");
    let item: ModerationQueueItem = serde_json::from_value(items[0].clone())
        .context("queue item is a closed moderation-queue-item")?;
    assert_eq!(item.id.as_str(), queue_item_id);
    assert_eq!(
        serde_json::to_value(&item.report)?,
        serde_json::to_value(&request.report_event.event.payload)?
    );
    assert_eq!(items[0]["status"], "submitted");

    // An absent target is the single anti-oracle not_found with zero writes.
    let absent = arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(b"protocol-payloads-absent-report-target"),
    );
    let absent_request = moderation_report_request(
        actor,
        target_realm_id,
        absent.as_str(),
        ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(target_realm_id.to_owned())?,
        },
    )
    .await?;
    expect_api_error(
        actor
            .authorize(
                server
                    .http()
                    .post(server.url("/_arkret/self/moderation/report")),
            )
            .json(&absent_request),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;
    Ok(())
}
