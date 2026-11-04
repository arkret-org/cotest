//! API-only consumers of the existing real accepted-device/MLS lifecycle.

use anyhow::{Context, Result, ensure};
use arkret::{ArkretMlsGroup, CommitStreamRef, EventId, RealmId, ScopeRef, StreamScanResponseBody};
use serde_json::json;

use super::_helpers::native_account::NativeAccountProvisioner;
use super::mls_lifecycle_live::Member;
use crate::harness::{ArkretServer, TestActorClient};

mod discussion;
mod receipts;

#[derive(Clone, Copy)]
pub enum MlsApiCase {
    MarkerPrivacy,
    CircleMarkers,
    Discussion,
    ReceiptSignals,
}

pub(super) struct MlsApiContext<'a> {
    source: &'a Member,
    holder: &'a Member,
    station: &'a ArkretServer,
    issuer: &'a NativeAccountProvisioner,
    realm: &'a RealmId,
    strand: &'a str,
    state: &'a EventId,
    source_group: &'a mut ArkretMlsGroup,
    holder_group: &'a mut ArkretMlsGroup,
    receipt_policy_probe: Option<receipts::ScopePolicyRestartProbe>,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn exercise(
    case: MlsApiCase,
    source: &Member,
    holder: &Member,
    station: &ArkretServer,
    issuer: &NativeAccountProvisioner,
    realm: &RealmId,
    strand: &str,
    state: &EventId,
    source_group: &mut ArkretMlsGroup,
    holder_group: &mut ArkretMlsGroup,
) -> Result<Option<receipts::ScopePolicyRestartProbe>> {
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
        receipt_policy_probe: None,
    };
    match case {
        MlsApiCase::MarkerPrivacy => marker_privacy(&mut ctx).await,
        MlsApiCase::CircleMarkers => discussion::markers(&ctx).await,
        MlsApiCase::Discussion => discussion::run(&mut ctx).await,
        MlsApiCase::ReceiptSignals => receipts::run(&mut ctx).await,
    }?;
    Ok(ctx.receipt_policy_probe)
}

pub(crate) async fn scan(
    client: &TestActorClient,
    scope: &ScopeRef,
) -> Result<StreamScanResponseBody> {
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
