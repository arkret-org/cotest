//! API-only consumers of the existing real accepted-device/MLS lifecycle.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use arkret::{ArkretMlsGroup, CommitStreamRef, EventId, RealmId, ScopeRef, StreamScanOutcome};
use serde_json::json;

use super::_helpers::bridge::MockCoauthIntrospectionServer;
use super::mls_lifecycle_live::Member;
use crate::harness::{ArkretServer, TestActorClient};

mod discussion;
mod receipts;

#[derive(Clone, Copy)]
pub enum MlsApiCase {
    AuditedReport,
    MarkerPrivacy,
    CircleMarkers,
    Discussion,
    ReceiptSignals,
}

pub(super) struct MlsApiContext<'a> {
    source: &'a Member,
    holder: &'a Member,
    station: &'a ArkretServer,
    issuer: &'a MockCoauthIntrospectionServer,
    realm: &'a RealmId,
    strand: &'a str,
    state: &'a EventId,
    source_group: &'a mut ArkretMlsGroup,
    holder_group: &'a mut ArkretMlsGroup,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn exercise(
    case: MlsApiCase,
    source: &Member,
    holder: &Member,
    station: &ArkretServer,
    issuer: &MockCoauthIntrospectionServer,
    realm: &RealmId,
    strand: &str,
    state: &EventId,
    source_group: &mut ArkretMlsGroup,
    holder_group: &mut ArkretMlsGroup,
) -> Result<()> {
    let mut ctx = MlsApiContext {
        source,
        holder,
        station,
        issuer,
        realm,
        strand,
        state,
        source_group,
        holder_group,
    };
    match case {
        MlsApiCase::AuditedReport => audited_report(&mut ctx).await,
        MlsApiCase::MarkerPrivacy => marker_privacy(&mut ctx).await,
        MlsApiCase::CircleMarkers => discussion::markers(&ctx).await,
        MlsApiCase::Discussion => discussion::run(&mut ctx).await,
        MlsApiCase::ReceiptSignals => receipts::run(&mut ctx).await,
    }
}

pub(crate) async fn scan(client: &TestActorClient, scope: &ScopeRef) -> Result<StreamScanOutcome> {
    let stream = match scope {
        ScopeRef::Realm { realm_id } => CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        ScopeRef::Circle {
            realm_id,
            circle_id,
        } => CommitStreamRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: circle_id.clone(),
        },
        _ => anyhow::bail!("API migration requires a Realm or Circle stream"),
    };
    let scan = client
        .sdk()
        .scan_commit_stream_to_head(scope.realm_id().clone(), stream, None, 1000)
        .await?;
    ensure!(
        !scan.truncated,
        "API migration cannot assert over a partial stream"
    );
    for item in &scan.committed_events {
        item.validate_shape()?;
    }
    Ok(scan)
}

async fn audited_report(ctx: &mut MlsApiContext<'_>) -> Result<()> {
    let message = super::message_mls_cross_station_live::submit_and_open(
        ctx.source,
        ctx.holder,
        ctx.source_group,
        ctx.holder_group,
        ctx.realm,
        ctx.strand,
        ctx.state,
        "ordinary report encrypted target",
    )
    .await?;
    let scope = ScopeRef::Realm {
        realm_id: ctx.realm.clone(),
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    let before = loop {
        let current = scan(&ctx.source.client, &scope).await?;
        if current
            .committed_events
            .iter()
            .filter_map(arkret::CommittedEventView::reducer_input)
            .any(|event| {
                event.kind == arkret::EventKind::ModerationFrankingProof
                    && event.payload["event_id"] == message.event_ref.as_str()
            })
        {
            break current;
        }
        ensure!(
            Instant::now() < deadline,
            "receiving Station did not publish the franking carrier before the report baseline"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    // The reporting member is not the Realm owner or the message author.
    let request = crate::harness::moderation_report_request(
        &ctx.holder.client,
        ctx.realm.as_str(),
        message.event_ref.as_str(),
        scope.clone(),
    )
    .await?;
    let report = ctx
        .holder
        .client
        .sdk()
        .moderation_report(&ctx.holder.client.verify_publication(request)?)
        .await?;
    let report = serde_json::to_value(report)?;
    ensure!(
        report["status"] == "submitted" && report.get("routed_to").is_none(),
        "ordinary report escaped its scoped workflow"
    );
    let after = scan(&ctx.source.client, &scope).await?;
    let prefix = &after.committed_events[..before
        .committed_events
        .len()
        .min(after.committed_events.len())];
    ensure!(
        arkret_canonical::canonical_json_bytes(prefix)?
            == arkret_canonical::canonical_json_bytes(&before.committed_events)?,
        "report mutated the complete pre-report Commit prefix"
    );
    let suffix = &after.committed_events[before.committed_events.len()..];
    ensure!(
        suffix.len() == 1,
        "ordinary report committed more than its own single Event"
    );
    let event = suffix[0]
        .reducer_input()
        .context("report Event withheld from its creator Realm")?;
    let expected =
        report["report_id"]
            .as_str()
            .context("report id")?
            .replacen("ak:report:", "ak:event:", 1);
    ensure!(
        event.event_id.as_str() == expected
            && event.kind.as_str() == "ak.self.moderation.report"
            && event.payload["target_ref"] == message.event_ref.as_str()
            && event.payload["reporter_id"] == ctx.holder.account.principal_id.as_str(),
        "ordinary report changed its signed target, reporter or identity"
    );
    ensure!(
        after
            .committed_events
            .iter()
            .filter_map(arkret::CommittedEventView::reducer_input)
            .all(|event| event.kind.as_str() != "ak.audit.accessed"),
        "ordinary report created an audit release"
    );
    println!(
        "audited_e2ee: real MLS target and non-owner reporter; franking baseline; byte-identical prefix; exactly one report Commit; zero audit-release Events"
    );
    Ok(())
}

async fn marker_privacy(ctx: &mut MlsApiContext<'_>) -> Result<()> {
    super::human_device_producer_live::grant_realm_actions(
        &ctx.source.client,
        ctx.station,
        ctx.realm.as_str(),
        &ctx.holder.account,
        &["ak.message.create"],
    )
    .await?;
    let secret = "R03-ENCRYPTED-MENTION-CANARY";
    let content: arkret::ContentBlock = serde_json::from_value(
        json!({"kind":"ak.content.text","body":secret,"format":"plain",
        "mentions":[{"kind":"mention","subject_account_id":ctx.source.account}]}),
    )?;
    let message = super::message_mls_cross_station_live::submit_and_open_content(
        ctx.holder,
        ctx.source,
        ctx.holder_group,
        ctx.source_group,
        ctx.realm,
        ctx.strand,
        ctx.state,
        content,
        ScopeRef::Realm {
            realm_id: ctx.realm.clone(),
        },
    )
    .await?;
    let frames = super::account_stream_api::frames(&ctx.source.client, None, None, true).await?;
    for frame in frames {
        if let Some(notifications) = frame.notifications {
            let body = serde_json::to_value(notifications)?;
            let items = body["items"]
                .as_array()
                .context("closed approval notification items")?;
            ensure!(
                items.iter().all(|item| item["type"] == "agent"),
                "ordinary message entered the Agent approval notification stream"
            );
            let serialized = serde_json::to_string(&body)?;
            ensure!(
                !serialized.contains(secret) && !serialized.contains(message.event_ref.as_str()),
                "approval notifications leaked an encrypted mention"
            );
        }
    }
    println!(
        "private_marker: real MLS mention never enters the closed account approval notification stream"
    );
    Ok(())
}
