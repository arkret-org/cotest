//! CT-10 — To-device queue offline ordering (entrypoint).
//!
//! Real test against the in-process soland harness. Verifies that
//! `/api/v1/device_messages` preserves send order across a poll /
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
