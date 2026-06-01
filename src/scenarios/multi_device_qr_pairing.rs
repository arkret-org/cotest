//! CT-9 — Multi-device QR pairing + cross-signing + MLS Remove on revoke.
//!
//! Spec references:
//!   - `contrix-spec/spec/v1/zh/crypto-media/device-lifecycle.md` §2.1 "配对流程 (无密码登录)" — QR
//!     pairing handshake:
//!       * new device generates local Ed25519 device key + displays QR containing public key +
//!         challenge nonce.
//!       * primary device scans QR, verifies pairing challenge, and issues a `cx.device.authorize`
//!         event that binds the new device's `verify_key` to the principal via the SSK
//!         (`cross_signing_binding`).
//!   - §5.2 "Device Trust Chain" — every `cx.device.authorize` event MUST carry a
//!     `cross_signing_binding` field signed by the SSK over the canonical `(principal_id,
//!     device_id, device_public_key, ssk_generation)` tuple. Devices without a valid binding MUST
//!     be reported as `unverified`.
//!   - §6 "Device List Sync" — any device add / revoke / signature update MUST produce a
//!     `cx.device.list_update` event in the principal control stream. Clients MUST expose the
//!     device list delta via sync.
//!   - §9 / `key-management.md` §5.2 "设备吊销" — revocation:
//!       * publish `cx.device.revoke` (or call `POST /api/v1/devices/ {device_id}/revoke` which
//!         mints the event).
//!       * for every MLS group the revoked device participated in, issue an MLS `Remove` proposal +
//!         commit so the device's epoch keys no longer decrypt new content.
//!
//! ──────────────────────────────────────────────────────────────────────────
//! ## Scenario walk-through
//!
//! 1. Create alice on a single soland with device-A. (The `TestActorBuilder` from CT-13 would make
//!    this DRY across the three new scenarios; until it lands we use the existing
//!    `ContrixServer::register_client` helper.)
//!
//! 2. Generate a fresh `cx:device:<uuidv7>` for device-B and a dedicated Ed25519 keypair for it.
//!    The QR payload itself is a yougen-side UI concern (`verify-device` flow); cotest synthesizes
//!    the equivalent API calls without driving the QR code itself — this matches the spec note that
//!    "QR is the transport, not the trust primitive".
//!
//! 3. From device-A, generate the cross-signing key (SSK) if alice hasn't published one already,
//!    then submit: a. `cx.cross_signing.publish` (if needed) — binds PSK → SSK. b.
//!    `cx.device.cross_signing_binding` — the SSK signature over device-B's `verify_key`, packaged
//!    per §5.1 canonical input. c. `cx.device.authorize` for device-B with the
//!    `cross_signing_binding` field carrying the §5.2 signature.
//!
//!     Today soland accepts these via `POST /api/v1/devices/authorize-
//!     pairing` (current `device::device_authorize_pairing`); the
//!     cross-signing field is NOT yet validated end-to-end.
//!
//! 4. Assert `GET /api/v1/devices` returns both device-A and device-B with
//!    `verification_state="verified"` (or `"cross_signed"` once soland exposes the §5.2 trust state
//!    distinction). NB: soland does not currently surface a `GET /api/v1/devices` route — the
//!    existing inventory is only readable via the per-device admin surfaces. This is one of the
//!    prerequisite gaps.
//!
//! 5. Wrap alice + a second principal (`bob`) into an E2EE space `S` so that "MLS Remove fanout"
//!    has a non-trivial member set. device-B joins `S` via a Welcome → Commit roundtrip (today this
//!    is also stubbed out in soland; MLS group state is not durable server-side per the `mls` grep
//!    showing no `cx.mls.*` handlers).
//!
//! 6. From device-A, revoke device-B: `POST /api/v1/devices/{device-B}/revoke` Assert: a. response
//!    200 with `revoked_device_id == device-B` and a `revoked_at` timestamp. b. device-A still
//!    works (its session is unaffected). c. device-B's bearer token returns 401 on `GET /api/v1/
//!    account/me` (the post-round-23 `cannot_self_revoke` + revoke surface; verified via the
//!    existing `device::device_revoke` handler). d. For the E2EE space `S` that alice + device-B
//!    were in: a `cx.mls.commit` event with a `Remove` proposal MUST appear in the space timeline
//!    within a bounded delay (per §9 + §6 device list sync). Alice's sync should observe both:
//!             * `cx.device.list_update` with device-B in `left[]`,
//!             * `cx.mls.commit` with `proposals[].type == "remove"`.
//!
//! ──────────────────────────────────────────────────────────────────────────
//! ## Status — `#[ignore]`'d
//!
//! Prerequisite blockers (soland-side):
//!   * **`GET /api/v1/devices`** — soland has `POST /devices/pairing- challenge`, `POST
//!     /devices/authorize-pairing`, and `POST /devices/{device_id}/revoke` but no list/index
//!     endpoint. Step 4 blocks here.
//!   * **`cross_signing_binding` validation** — `device::device_ authorize_pairing` stores the
//!     pairing record but does NOT verify the §5.2 SSK signature, the PSK → SSK chain, or the
//!     canonical signing input. Step 3c can be SUBMITTED today but is not yet enforced as a
//!     `cross_signed` vs. `unverified` distinction.
//!   * **MLS state machine** — `grep mls` in soland turns up only
//!     `routing/federation/move_anchor.rs` (anchor frontier) and `routing/interop/mimi.rs` (interop
//!     shim). There is no server-side `cx.mls.commit` reducer, no MLS group state, and no
//!     Remove-proposal fanout on device revoke. Step 6d is fully unimplemented soland-side.
//!   * **E2E-MULTI-DEV-1** (soland `_todos.md`) is the umbrella task that, when completed, unblocks
//!     this scenario end-to-end.
//!
//! Track: `_claude_todos.md` row CT-9 + soland `_todos.md` E2E-MULTI-DEV-1.

use anyhow::Result;

use crate::harness::TestServerGroup;

/// CT-9 — QR pairing + cross-signing + MLS Remove cascade probe.
///
/// See module docs for the walk-through and prerequisite blockers.
pub async fn multi_device_qr_pairing_run() -> Result<()> {
    // ── Step 1: boot soland + register alice with device-A ──────────────
    //
    // Use a 1-server group (vs. 3-server in CT-1) — multi-device pairing
    // is a single-principal flow that does not require federation.
    let _group = TestServerGroup::single("ct9-qr-pairing").await?;
    // let server = group.server(0);
    //
    //   let device_a = new_prefixed_uuid7("cx:device:");
    //   let alice = server.register_client(
    //       "did:web:alice.ct9.cotest.local",
    //       "@alice-ct9",
    //       &device_a,
    //   ).await?;

    // ── Step 2: synthesize device-B's keypair + QR payload ──────────────
    //
    //   let device_b = new_prefixed_uuid7("cx:device:");
    //   let device_b_signing_key = ed25519_dalek::SigningKey::generate(
    //       &mut rand::rngs::OsRng);
    //   let device_b_verify_key = device_b_signing_key.verifying_key();
    //   // QR payload (yougen-side):
    //   //   { "device_id": device_b,
    //   //     "verify_key": base64url(device_b_verify_key),
    //   //     "pairing_challenge_nonce": ... }
    //   // cotest bypasses the visual QR roundtrip and calls the pairing-
    //   // challenge / authorize-pairing API directly.

    // ── Step 3: cross-signing binding from device-A ─────────────────────
    //
    //   // 3a. mint the SSK if alice hasn't already; publish §5.1
    //   //     envelope:
    //   alice.post("/api/v1/events").json(&event_envelope(
    //       &alice.actor,
    //       <principal_control_space_id>,
    //       "cx.cross_signing.publish",
    //       json!({
    //           "principal_signing_key": { "kid": <PSK kid>, "alg": "EdDSA",
    //                                       "public_key": <PSK pub> },
    //           "self_signing_key": {
    //               "kid": <SSK kid>, "alg": "EdDSA",
    //               "public_key": <SSK pub>,
    //               "binding": {
    //                   "verification_method": <PSK verification method>,
    //                   "alg": "EdDSA",
    //                   "signature": <PSK sig over §5.1 canonical input>,
    //               }
    //           },
    //           "user_signing_key": { ... },
    //           "generation": 1,
    //       }),
    //   )).send().await?;
    //
    //   // 3b + 3c. pairing-challenge → authorize-pairing with
    //   //          cross_signing_binding:
    //   let challenge: Value = alice.post("/api/v1/devices/pairing-challenge")
    //       .json(&json!({"device_id": device_b}))
    //       .send().await?.json().await?;
    //
    //   let canonical = format!(
    //       "cx-device-trust-bind-v1\n{}",
    //       canonical_json(json!({
    //           "principal_id": alice.actor,
    //           "device_id": device_b,
    //           "device_public_key": base64url(device_b_verify_key),
    //           "ssk_generation": 1,
    //       }))
    //   );
    //   let ssk_sig = ssk_signing_key.sign(canonical.as_bytes());
    //
    //   expect_json(
    //       alice.post("/api/v1/devices/authorize-pairing")
    //           .json(&json!({
    //               "device_id": device_b,
    //               "challenge_id": challenge["challenge_id"],
    //               "display_name": "Alice iPad",
    //               "verify_key": base64url(device_b_verify_key),
    //               "cross_signing_binding": {
    //                   "verification_method": <SSK verification method>,
    //                   "alg": "EdDSA",
    //                   "ssk_generation": 1,
    //                   "signature": base64url(ssk_sig),
    //               },
    //               "proof": {"alg": "dev-none"},
    //           })),
    //       StatusCode::OK,
    //   ).await?;

    // ── Step 4: assert both devices visible + verified ──────────────────
    //
    //   let devices = expect_json(
    //       alice.get("/api/v1/devices"),
    //       StatusCode::OK,
    //   ).await?;
    //   let entries = devices["devices"].as_array().unwrap();
    //   assert_eq!(entries.len(), 2);
    //   let by_id: HashMap<_, _> = entries.iter()
    //       .map(|d| (d["device_id"].as_str().unwrap(), d)).collect();
    //   assert_eq!(by_id[&device_a.as_str()]["verification_state"],
    //              "cross_signed");
    //   assert_eq!(by_id[&device_b.as_str()]["verification_state"],
    //              "cross_signed");
    //
    // NB: today this endpoint does not exist — see "blockers" above.

    // ── Step 5: create E2EE space + add both devices to MLS group ───────
    //
    //   let bob = server.register_client(
    //       "did:web:bob.ct9.cotest.local", "@bob-ct9",
    //       &new_prefixed_uuid7("cx:device:")).await?;
    //   let space_id = alice.create_space_with(json!({
    //       "title": "ct9-e2ee",
    //       "encryption_profile": "mls_rfc9420",
    //       "invitees": [bob.actor],
    //       "plaintext_visible_services": [],
    //   })).await?["realm_id"].as_str().unwrap().to_owned();
    //
    //   // Welcome device-B into the MLS group on `space_id`:
    //   alice.post(&format!("/api/v1/spaces/{space_id}/mls/welcomes"))
    //        .json(&json!({"recipient_device_id": device_b, ... }))
    //        .send().await?;
    //
    //   // (Today no soland route accepts MLS welcomes; this is stubbed.)

    // ── Step 6: revoke device-B from device-A; assert cascade ───────────
    //
    //   // 6a. revoke
    //   let revoke = expect_json(
    //       alice.post(&format!("/api/v1/devices/{device_b}/revoke")),
    //       StatusCode::OK,
    //   ).await?;
    //   assert_eq!(revoke["revoked_device_id"], device_b);
    //   assert!(revoke["revoked_at"].is_string());
    //
    //   // 6b. device-A still works:
    //   expect_status(alice.get("/api/v1/account/me"), StatusCode::OK).await?;
    //
    //   // 6c. device-B's bearer is now 401:
    //   //   (need a separate bearer issued to device-B — today only
    //   //   `dev_login` mints bearers, so we'd need a parallel
    //   //   dev-login under device_b's id BEFORE the revoke).
    //   let device_b_token = dev_login(&server, &alice.actor, &device_b).await?;
    //   expect_status(
    //       server.http()
    //             .get(server.url("/api/v1/account/me"))
    //             .bearer_auth(&device_b_token),
    //       StatusCode::UNAUTHORIZED,
    //   ).await?;
    //
    //   // 6d. MLS Remove fanout: alice's sync on `space_id` MUST emit
    //   //     `cx.mls.commit` with proposals[].type == "remove" within
    //   //     a bounded delay.
    //   eventually(|| async {
    //       let sync = alice.sync().await?;
    //       let commits = sync["spaces"][&space_id]["timeline"]["events"]
    //           .as_array()
    //           .unwrap_or(&vec![])
    //           .iter()
    //           .filter(|e| e["kind"] == "cx.mls.commit")
    //           .collect::<Vec<_>>();
    //       assert!(commits.iter().any(|c| c["content"]["proposals"]
    //                  .as_array()
    //                  .map(|p| p.iter().any(|prop| prop["type"] == "remove"))
    //                  .unwrap_or(false)),
    //               "expected at least one Remove proposal in cx.mls.commit");
    //       // device_b appears in cx.device.list_update.left[]:
    //       let list_updates = sync["spaces"]
    //           [<principal_control_space_id>]
    //           ["timeline"]["events"]
    //           .as_array()
    //           .unwrap_or(&vec![])
    //           .iter()
    //           .filter(|e| e["kind"] == "cx.device.list_update")
    //           .collect::<Vec<_>>();
    //       assert!(list_updates.iter().any(|u| u["payload"]["left"]
    //                  .as_array()
    //                  .map(|l| l.iter().any(|d| d == &device_b))
    //                  .unwrap_or(false)),
    //               "expected device_b in cx.device.list_update.left[]");
    //       Ok(())
    //   }, Duration::from_secs(5)).await?;

    unimplemented!(
        "CT-9 multi-device QR pairing + MLS Remove — blocked on soland \
         E2E-MULTI-DEV-1: needs (a) `GET /api/v1/devices` list endpoint, \
         (b) `cross_signing_binding` validation in `device::device_\
         authorize_pairing`, (c) full MLS state machine + \
         `cx.mls.commit` reducer with Remove-proposal fanout on \
         `device::device_revoke`, and (d) `cx.device.list_update` \
         emission per spec §6. The scaffolded test body above documents \
         every assertion in the implementer's terms. See module docs + \
         soland/_todos.md E2E-MULTI-DEV-1 + spec device-lifecycle.md \
         §2.1 / §5.2 / §6 / §9."
    )
}
