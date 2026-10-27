//! Provider hints must reach an authorized real consumer without minting Events.
use arkret_models_collaboration::mimi_operations::{MimiNotifyRequestBody, MimiNotifyResponseBody};
use arkret_models_collaboration::objects::mimi::{MimiNotification, MimiNotificationRouting};
use arkret_models_collaboration::sync_frames::committed_event_subscribe::CommittedEventSubscribeFrameKind;

use super::*;
use crate::harness::ArkretServer;
use crate::scenarios::mls_lifecycle_live::Member;

async fn canonical_originals(database: &str, realm: &arkret_wire::RealmId) -> Result<Vec<Value>> {
    let database = database.to_owned();
    let realm = realm.to_string();
    tokio::task::spawn_blocking(move || -> Result<Vec<Value>> {
        let mut database = postgres::Client::connect(&database, postgres::NoTls)?;
        Ok(database.query(
            "SELECT jsonb_build_object('event',e.envelope,'commit',c.commit_json) FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.realm_id=$1 AND e.state='committed' ORDER BY c.stream_ref::text,c.stream_position",
            &[&realm],
        )?.into_iter().map(|row| row.get(0)).collect())
    }).await?
}

async fn consumed(station: &ArkretServer) -> Result<f64> {
    let base = station
        .metrics_base_url()
        .context("native notification consumer metrics are required")?;
    let body = station
        .http()
        .get(format!("{base}/metrics"))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    Ok(
        crate::scenarios::_helpers::service_metrics::MetricsSnapshot::parse(&body).sum(
            "coland_mimi_notify_refresh_consumed_total",
            &[("transport", "committed_events")],
        ),
    )
}

pub(super) async fn exercise(
    station: &ArkretServer,
    recipient: &Member,
    realm: &arkret_wire::RealmId,
    binding: &arkret_wire::CommittedEventFullView,
    message: &Value,
) -> Result<Value> {
    let database = station
        .owned_database_url()
        .context("native notification database")?;
    let before = canonical_originals(database, realm).await?;
    ensure!(
        !before.is_empty(),
        "notification has no actual canonical originals"
    );
    let options = arkret_http_client::CommittedEventSubscribeOptions::new().realm(realm.clone());
    let mut subscription = recipient
        .client
        .sdk()
        .committed_event_subscribe_frames(&options)
        .await?;
    let first = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        subscription.next_frame(),
    )
    .await
    .context("native subscriber did not enter its actual stream")??
    .context("native subscriber closed before checkpoint")?;
    ensure!(
        first.kind == CommittedEventSubscribeFrameKind::Checkpoint,
        "native notification consumer did not establish its authorized current cut"
    );
    let baseline = consumed(station).await?;
    let room = binding
        .event
        .payload
        .get("mimi_room_uri")
        .and_then(Value::as_str)
        .context("actual room URI")?;
    let strand = binding.event.payload["binding_scope"]["strand_id"]
        .as_str()
        .context("actual accepted binding Strand")?;
    let provider = message["directory"]["mimi"]["provider_id"]
        .as_str()
        .context("native provider")?;
    let request = MimiNotifyRequestBody {
        notification: MimiNotification {
            kind: arkret_wire::NonEmptyString::new("room_updated").map_err(anyhow::Error::msg)?,
            fanout_ref: Some(
                arkret_wire::NonEmptyString::new(
                    message["committed"]["event"]["event_id"]
                        .as_str()
                        .context("actual mapped message")?,
                )
                .map_err(anyhow::Error::msg)?,
            ),
            delivery_hint: Some(
                arkret_wire::NonEmptyString::new("refresh").map_err(anyhow::Error::msg)?,
            ),
        },
        origin_provider_id: Some(station.service_id().clone()),
        routing: Some(MimiNotificationRouting {
            mimi_room_uri: Some(
                arkret_wire::MimiRoomUri::new(room.to_owned()).map_err(anyhow::Error::msg)?,
            ),
            target_provider_ids: Some(vec![station.service_id().clone()]),
        }),
    };
    let (status, accepted) = crate::scenarios::mimi_facade_live::signed_post_inner(
        station,
        &format!("/_arkret/open/mimi/strands/{strand}/notify"),
        Some(room),
        provider,
        &json!(request),
        None,
    )
    .await?;
    ensure!(
        status == reqwest::StatusCode::OK,
        "native notification refused: {status} {accepted}"
    );
    let response: MimiNotifyResponseBody = serde_json::from_value(accepted.clone())?;
    ensure!(
        response.accepted && response.retry_after_ms.is_none(),
        "native hint was not queued"
    );
    let refreshed =
        tokio::time::timeout(std::time::Duration::from_secs(5), subscription.next_frame())
            .await
            .context("the exact authorized subscriber did not handle the hint")??
            .context("the exact subscriber closed before refresh")?;
    ensure!(
        refreshed.kind == CommittedEventSubscribeFrameKind::Checkpoint
            && refreshed.cursor == first.cursor
            && refreshed.payload.is_none(),
        "the hint did not preserve the exact subscriber's unchanged canonical cut"
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let final_count = loop {
        let value = consumed(station).await?;
        if value >= baseline + 1.0 {
            break value;
        }
        ensure!(
            std::time::Instant::now() < deadline,
            "the authorized native consumer never handled the hint; ACK alone is not delivery"
        );
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    };
    let after = canonical_originals(database, realm).await?;
    ensure!(
        before == after,
        "notification minted or changed canonical originals"
    );
    drop(subscription);
    Ok(
        json!({"request":request,"accepted":accepted,"consumer_checkpoint":first,
        "recipient_account":recipient.account,"realm_id":realm,"binding":binding,
        "consumer_count_before":baseline,"consumer_count_after":final_count,"refresh_checkpoint":refreshed,
        "canonical_before":before,"canonical_after":after}),
    )
}

pub(super) fn verify(
    observations: &NativeOperationObservations,
    evidence: &Value,
    message: &Value,
) -> Result<()> {
    let exchange = original_exchange(observations, "ak.open.mimi.command.notify.v1")?;
    let input = verify_native_station_http_request(
        observations,
        exchange,
        &[
            arkret_signatures::http_signature::Component::Header("provider-id".into()),
            arkret_signatures::http_signature::Component::Header("mimi-room-uri".into()),
        ],
    )?;
    let source = message["directory"]["service_id"]
        .as_str()
        .context("native provider service")?;
    let headers = &exchange.explicit_request_headers;
    ensure!(
        input.expires >= input.created
            && input.expires - input.created <= 300
            && exchange.request_body == evidence["request"]
            && exchange.response_body == evidence["accepted"]
            && headers.get("source-service-id").map(String::as_str) == Some(source)
            && headers.get("destination-service-id").map(String::as_str) == Some(source)
            && headers.get("provider-id").map(String::as_str)
                == message["directory"]["mimi"]["provider_id"].as_str()
            && headers.get("mimi-room-uri").map(String::as_str)
                == evidence["request"]["routing"]["mimi_room_uri"].as_str(),
        "notification did not retain its exact signed native source, room and exchange"
    );
    ensure!(
        evidence["accepted"]["accepted"] == true
            && evidence["consumer_checkpoint"]["kind"] == "checkpoint"
            && evidence["refresh_checkpoint"]["kind"] == "checkpoint"
            && evidence["refresh_checkpoint"]["cursor"]
                == evidence["consumer_checkpoint"]["cursor"]
            && evidence["refresh_checkpoint"]["cursor"].is_string()
            && evidence["refresh_checkpoint"]["payload"].is_null()
            && evidence["consumer_count_after"]
                .as_f64()
                .context("native consumer count")?
                >= evidence["consumer_count_before"]
                    .as_f64()
                    .context("original consumer count")?
                    + 1.0
            && evidence["canonical_before"] == evidence["canonical_after"]
            && evidence["canonical_before"]
                .as_array()
                .is_some_and(|rows| !rows.is_empty())
            && evidence["request"]["notification"]["fanout_ref"]
                == message["committed"]["event"]["event_id"],
        "native notification has no actual authorized consumer or changed its canonical originals"
    );
    Ok(())
}
