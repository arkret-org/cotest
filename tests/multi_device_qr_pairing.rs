//! CT-9 — Multi-device QR pairing + cross-signing + MLS Remove on
//! revoke (entrypoint).
//!
//! Alice owns device-A; pairs device-B via QR (synthesized API call);
//! `ck.cross_signing.publish` + `cx.device.cross_signing_binding` +
//! `ck.device.authorize` are submitted; both devices appear in the
//! device list. Alice from device-A revokes device-B; the test asserts
//! device-A still works, device-B's bearer is 401, a
//! `ck.device.list_update` event lists device-B in `left[]`, and the
//! E2EE space's timeline gains a `ck.mls.commit` with a Remove
//! proposal targeting device-B.
//!
//! See `cotest::scenarios::multi_device_qr_pairing` for the full
//! walk-through and prerequisite blockers.
//!
//! Run with:
//!
//!   cargo test --test multi_device_qr_pairing -- --ignored

use anyhow::Result;
use serial_test::serial;

/// Gating: needs soland E2E-MULTI-DEV-1: `GET /_cokret/self/devices` list
/// endpoint + `cross_signing_binding` validation + MLS state machine
/// (`ck.mls.commit` reducer) + `ck.device.list_update` emission +
/// Remove-proposal fanout on device revoke.
/// Issue: CT-9 (multi-device QR pairing)
#[tokio::test]
#[ignore = "needs soland E2E-MULTI-DEV-1: `GET /_cokret/self/devices` list endpoint + `cross_signing_binding` validation + MLS state machine (ck.mls.commit reducer) + ck.device.list_update emission + Remove-proposal fanout on device revoke — see CT-9"]
#[serial]
async fn multi_device_qr_pairing_and_revoke_cascades_mls_remove() -> Result<()> {
    cotest::scenarios::multi_device_qr_pairing::multi_device_qr_pairing_run().await
}
