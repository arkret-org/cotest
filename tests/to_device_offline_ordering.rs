//! CT-10 — To-device queue offline ordering (entrypoint).
//!
//! Real test against the in-process coland harness. Verifies that
//! `/_arkret/self/device_messages` preserves send order across a poll /
//! disconnect / reconnect cycle and that `to_device_position` is
//! monotonic per-(actor, device).
//!
//! See `cotest::scenarios::to_device_offline_ordering` for the 10-step
//! probe.

use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn to_device_queue_preserves_order_across_disconnect() -> Result<()> {
    cotest::scenarios::to_device_offline_ordering::to_device_offline_ordering_run().await
}

#[tokio::test]
#[serial]
async fn device_message_pagination_is_read_only_and_ack_is_cumulative() -> Result<()> {
    cotest::scenarios::to_device_offline_ordering::device_message_pagination_is_read_only_and_ack_is_cumulative().await
}

#[tokio::test]
#[serial]
async fn device_ack_rejects_another_device_of_the_same_account() -> Result<()> {
    cotest::scenarios::to_device_offline_ordering::device_ack_rejects_cross_binding_without_pruning(
        true,
    )
    .await
}

#[tokio::test]
#[serial]
async fn device_ack_rejects_another_account() -> Result<()> {
    cotest::scenarios::to_device_offline_ordering::device_ack_rejects_cross_binding_without_pruning(
        false,
    )
    .await
}

#[tokio::test]
#[serial]
async fn concurrent_device_message_retries_enqueue_once() -> Result<()> {
    cotest::scenarios::to_device_offline_ordering::concurrent_device_message_retries_enqueue_once()
        .await
}

#[tokio::test]
#[serial]
async fn device_message_id_conflict_cannot_redirect_delivery() -> Result<()> {
    cotest::scenarios::to_device_offline_ordering::device_message_id_conflict_cannot_redirect_delivery().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn device_message_survives_station_restart() -> Result<()> {
    cotest::scenarios::to_device_offline_ordering::device_message_survives_station_restart().await
}
