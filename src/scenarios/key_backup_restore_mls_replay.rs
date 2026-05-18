//! CT-11 — Key backup restore + MLS history replay.
//!
//! Spec references:
//!   - `contrix-spec/spec/v1/zh/identity/key-management.md` §7.1
//!     "备份内容" — three backup domains MUST be isolated:
//!       * `did_recovery` — DID control / recovery key shares.
//!       * `secret_storage` — `self_signing_key`, `user_signing_key`,
//!         recovery secret, MLS group secrets backup key.
//!       * `mls_history` — historical MLS group state, epoch key
//!         material, pending Welcome.
//!     Cross-domain key reuse is FORBIDDEN; each domain has its own
//!     salt + HKDF info + AEAD AAD.
//!   - §7.2 "Backup Envelope" — `cx.schema.key_backup.v1`:
//!       * `encryption.kdf = argon2id` (memory_kib≥65536, iterations≥3,
//!         parallelism≥1 per soland `_todos.md` E2E-KEY-BACKUP-1).
//!       * `encryption.aead = xchacha20_poly1305`.
//!       * `key_commitment` MUST be present so clients can verify the
//!         passphrase locally before downloading ciphertext.
//!       * Service-side MUST NOT store passphrase / derived key / KDF
//!         output.
//!   - §7.3 "恢复流程" — restore steps:
//!       1. new device generates fresh device key.
//!       2. user enters passphrase / collects recovery shares.
//!       3. client decrypts backup envelope.
//!       4. client verifies key commitment.
//!       5. client publishes `recover` or `cx.device.authorized`.
//!       6. for E2EE spaces: pull MLS state, replay historical
//!          `cx.mls.commit` events with the recovered
//!          `mls_history_backup_key` to decrypt pre-loss epoch content.
//!   - §7.4 "所有权证明与解密证明" — SSK proof binding fields:
//!       `challenge / audience / origin / service_did / principal_did
//!        / key_id / expires_at / nonce`.
//!
//! ──────────────────────────────────────────────────────────────────────────
//! ## Scenario walk-through
//!
//! 1.  Boot soland; register alice with device-A.
//! 2.  Create an E2EE space `S` containing alice (+ optionally bob, to
//!     give Commit events non-trivial proposals); send N=3 messages.
//!     Each message triggers a `cx.mls.commit` envelope on the
//!     timeline; encrypted body is opaque to the server.
//! 3.  Mint a key backup envelope client-side:
//!       * derive `kdf_key = argon2id(passphrase, salt, params)`.
//!       * derive `commitment_key = HKDF(kdf_key,
//!                                       info="contrix-key-backup-
//!                                       commitment-v1")`.
//!       * compute `key_commitment = sha256(commitment_key)`.
//!       * pack `secret_storage` plaintext = `{self_signing_key,
//!         user_signing_key}`; pack `mls_history` plaintext =
//!         `{mls_history_backup_key, epoch_key_material[*]}`.
//!       * encrypt each domain's plaintext under its own subdomain key
//!         (HKDF info = `"contrix-key-backup/<class>/<sub>/v1"`) with
//!         XChaCha20-Poly1305; AAD covers `actor_id, device_id,
//!         backup_class, backup_version, item_type, created_at,
//!         schema_id`.
//!       * upload via
//!         `PUT /api/v1/keys/backups/{backup_id}`
//!         (current soland surface; see
//!         `routing/identity/key_backup.rs`).
//!     Validate the response is 200 with `ok=true`.
//! 4.  "Lose" device-A: revoke it via
//!         `POST /api/v1/devices/{device-A}/revoke`
//!     issued from a sibling device (per CT-9
//!     `cannot_self_revoke` invariant). Today we'd need a second
//!     authorized device to drive the revoke; the scaffold uses an
//!     alternative `cx.device.revoked` direct-event submission as a
//!     stand-in.
//! 5.  Onboard new device-B:
//!       * generate a fresh `cx:device:<uuidv7>` and Ed25519 keypair.
//!       * dev-login (or full recovery via SSK proof — see §7.4) to
//!         get a bearer.
//!       * `GET /api/v1/keys/backups/{backup_id}` returns the full
//!         envelope (per soland E2E-KEY-BACKUP-2; today this is
//!         implemented).
//!       * derive the passphrase keys; verify `key_commitment`;
//!         decrypt the two domains.
//!       * mint a SSK proof per §7.4 canonical fields and POST it back
//!         (recovery confirmation); today no soland endpoint binds
//!         this — the SSK proof is consumed only by the §7.4 attest-
//!         ownership flow which is not yet wired.
//! 6.  device-B replays MLS history:
//!       * `GET /api/v1/spaces/{S}/timeline?since=...` pulls all
//!         `cx.mls.commit` events.
//!       * with the recovered `mls_history_backup_key`, device-B
//!         derives the pre-loss epoch secret and decrypts each
//!         message's ciphertext.
//!     Assert: device-B reconstructs all 3 plaintexts that device-A
//!     originally sent.
//!
//! ──────────────────────────────────────────────────────────────────────────
//! ## Status — `#[ignore]`'d
//!
//! Prerequisite status (soland-side):
//!   * **`PUT /api/v1/keys/backups/{backup_id}`** — IMPLEMENTED today
//!     (see `routing/identity/key_backup.rs::put_key_backup`). Validates
//!     `REQUIRED_KEY_BACKUP_FIELDS` and stores opaque ciphertext.
//!     Steps 3 and 5b work today.
//!   * **`GET /api/v1/keys/backups/{backup_id}`** — IMPLEMENTED
//!     (same module, `get_key_backup`).
//!   * **`DELETE /api/v1/keys/backups/{backup_id}` with SSK proof** —
//!     soland `_todos.md` E2E-KEY-BACKUP-2 status is "needs SSK
//!     `payload=delete:backup_id:nonce` signature"; today only session-
//!     token DELETE is enforced. Step 5e is partially blocked.
//!   * **`mls_history_backup_key` semantics + `cx.mls.commit` reducer**
//!     — soland has NO MLS state machine. The `grep mls` in src returns
//!     only anchor/interop modules; there is no `cx.mls.commit`
//!     reducer, no epoch tracking, and no historical commit chain a
//!     replayer could walk. Step 2 (send 3 messages via MLS) and
//!     step 6 (replay) are blocked end-to-end.
//!   * **SSK proof endpoint per §7.4** — soland does not yet expose a
//!     recovery-attestation surface (E2E-KEY-BACKUP-2 still open). The
//!     `recovery_attestation` field flagged in E2E-KEY-BACKUP-3 is
//!     scoped to threshold recovery, not single-passphrase restore.
//!   * **Argon2id + XChaCha20 client crypto** — cotest's `Cargo.toml`
//!     already pulls `chacha20poly1305`, `pbkdf2`, `hkdf`, `sha2`, but
//!     NOT `argon2`. Adding argon2 is a one-line dep bump (kept out of
//!     this PR to avoid lockfile churn; the scaffold uses pbkdf2 as a
//!     placeholder so the build stays clean).
//!
//! Track: `_claude_todos.md` row CT-11 + soland `_todos.md`
//! E2E-KEY-BACKUP-1/2/3 (E2E-KEY-BACKUP-1 closed, -2 + -3 open).

use anyhow::Result;

use crate::harness::TestServerGroup;

/// CT-11 — key backup restore + MLS history replay probe.
///
/// See module docs for the walk-through and prerequisite blockers.
pub async fn key_backup_restore_mls_replay_run() -> Result<()> {
    // ── Step 1: boot soland + register alice with device-A ──────────────
    let _group = TestServerGroup::single("ct11-key-backup-replay").await?;
    // let server = group.server(0);
    //
    //   let device_a = new_prefixed_uuid7("cx:device:");
    //   let alice = server.register_client(
    //       "did:web:alice.ct11.cotest.local",
    //       "@alice-ct11",
    //       &device_a,
    //   ).await?;

    // ── Step 2: alice creates E2EE space + sends 3 messages ─────────────
    //
    //   let space_id = alice.create_space_with(json!({
    //       "title": "ct11-e2ee-history",
    //       "encryption_profile": "mls_rfc9420",
    //       "plaintext_visible_services": [],
    //   })).await?["space_id"].as_str().unwrap().to_owned();
    //
    //   // Each message is wrapped in a cx.mls.commit envelope.
    //   // Today soland has no MLS reducer; treat this as `cx.message.
    //   // create` with `encrypted=true` content for the scaffold:
    //   let plaintexts = ["pre-loss msg 1", "pre-loss msg 2", "pre-loss msg 3"];
    //   for (i, body) in plaintexts.iter().enumerate() {
    //       let epoch_key = derive_epoch_key(&mls_history_backup_key,
    //                                         /*epoch=*/ i as u64);
    //       let ciphertext = xchacha20_seal(&epoch_key, body.as_bytes(),
    //                                       /*aad=*/ b"ct11-e2ee-history");
    //       alice.post("/api/v1/events").json(&event_envelope(
    //           &alice.actor, &space_id, "cx.mls.commit",
    //           json!({
    //               "epoch": i,
    //               "ciphertext": base64url(ciphertext),
    //               "proposals": [],
    //           }),
    //       )).send().await?;
    //   }

    // ── Step 3: mint + upload the key backup envelope ───────────────────
    //
    //   let passphrase = "correct horse battery staple ct11";
    //   let salt = random_32_bytes();
    //   // Argon2id params per spec §7.2 lower-bound.
    //   let kdf_params = Argon2Params {
    //       memory_kib: 65_536, iterations: 3, parallelism: 1,
    //   };
    //   let kdf_key = argon2id(passphrase.as_bytes(), &salt, &kdf_params);
    //   let commitment_key = hkdf::<Sha256>(
    //       &kdf_key, b"contrix-key-backup-commitment-v1", 32);
    //   let key_commitment = sha256(&commitment_key);
    //
    //   // Per-domain subkeys (§7.1 isolation rule).
    //   let secret_storage_key = hkdf::<Sha256>(
    //       &kdf_key, b"contrix-key-backup/secret_storage/v1/v1", 32);
    //   let mls_history_key = hkdf::<Sha256>(
    //       &kdf_key, b"contrix-key-backup/mls_history/v1/v1", 32);
    //
    //   let ssk_plaintext = serde_json::to_vec(&json!({
    //       "self_signing_key": alice.ssk_secret(),
    //       "user_signing_key": alice.usk_secret(),
    //   }))?;
    //   let mls_plaintext = serde_json::to_vec(&json!({
    //       "mls_history_backup_key": base64url(&mls_history_backup_key),
    //       "epoch_key_material": (0..3).map(|i| json!({
    //           "epoch": i,
    //           "key": base64url(derive_epoch_key(&mls_history_backup_key, i)),
    //       })).collect::<Vec<_>>(),
    //   }))?;
    //
    //   let backup_id = new_prefixed_uuid7("cx:backup:");
    //   let aad = canonical_json(json!({
    //       "actor_id": alice.actor,
    //       "device_id": device_a,
    //       "backup_class": "secret_storage", // and "mls_history" for the other
    //       "backup_version": "kb_1",
    //       "schema_id": "cx.schema.key_backup.v1",
    //   }));
    //   let (nonce_ss, ct_ss) = xchacha20_seal_with_aad(
    //       &secret_storage_key, &ssk_plaintext, aad.as_bytes());
    //   // (and the same for mls_history domain; split into two backup
    //   //  envelopes per the §7.1 default `MUST 分离`.)
    //
    //   expect_json(
    //       alice.put(&format!("/api/v1/keys/backups/{backup_id}"))
    //            .json(&json!({
    //                "backup_id": backup_id,
    //                "actor_id": alice.actor,
    //                "device_id": device_a,
    //                "backup_class": "secret_storage",
    //                "backup_version": "kb_1",
    //                "created_at": now_iso(),
    //                "encryption": {
    //                    "recipient_method": "passphrase_kdf",
    //                    "kdf": { "name": "argon2id", "salt": base64url(&salt),
    //                             "params": kdf_params.to_json() },
    //                    "aead": { "name": "xchacha20_poly1305",
    //                              "nonce": base64url(&nonce_ss) },
    //                    "key_commitment": format!("sha256:{}",
    //                                              hex(&key_commitment)),
    //                },
    //                "contents": [
    //                    {"item_type": "self_signing_key",
    //                     "secret_id": "self_signing_key"},
    //                    {"item_type": "user_signing_key",
    //                     "secret_id": "user_signing_key"},
    //                ],
    //                "ciphertext": base64url(&ct_ss),
    //                "ciphertext_digest": format!("sha256:{}",
    //                                              hex(&sha256(&ct_ss))),
    //                "auth_data": {
    //                    "device_id": device_a,
    //                    "signature": base64url(&device_a_sig_over_envelope),
    //                },
    //            })),
    //       StatusCode::OK,
    //   ).await?;
    //
    //   // Repeat for the mls_history-class envelope.

    // ── Step 4: "lose" device-A by revoking it ──────────────────────────
    //
    //   // §5.2 cannot-self-revoke means we need a sibling device. The
    //   // scaffold uses a synthetic sibling (`device_pair`) authorized
    //   // out-of-band purely so the revoke can fire from someone
    //   // OTHER than device-A:
    //   let device_pair = new_prefixed_uuid7("cx:device:");
    //   let pair_token = ... pair via CT-9 flow ...;
    //   expect_json(
    //       server.http()
    //             .post(server.url(&format!(
    //                 "/api/v1/devices/{device_a}/revoke")))
    //             .bearer_auth(&pair_token),
    //       StatusCode::OK,
    //   ).await?;

    // ── Step 5: onboard new device-B + claim the backup ─────────────────
    //
    //   let device_b = new_prefixed_uuid7("cx:device:");
    //   // 5a. dev-login under device-B (in production this is gated by
    //   //     SSK proof per §7.4; soland's dev-login bypass is enough
    //   //     for the harness).
    //   let device_b_token = dev_login(&server, &alice.actor, &device_b)
    //                             .await?;
    //
    //   // 5b. fetch the backup envelope:
    //   let envelope: Value = expect_json(
    //       server.http()
    //             .get(server.url(&format!(
    //                 "/api/v1/keys/backups/{backup_id}")))
    //             .bearer_auth(&device_b_token),
    //       StatusCode::OK,
    //   ).await?;
    //
    //   // 5c. derive keys from passphrase, verify commitment:
    //   let kdf_key_2 = argon2id(passphrase.as_bytes(),
    //       &base64url_decode(envelope["encryption"]["kdf"]["salt"]
    //                              .as_str().unwrap())?,
    //       &Argon2Params::from_json(&envelope["encryption"]["kdf"]
    //                                       ["params"])?);
    //   let commitment_key_2 = hkdf::<Sha256>(
    //       &kdf_key_2, b"contrix-key-backup-commitment-v1", 32);
    //   let computed_commitment = format!("sha256:{}",
    //                                hex(&sha256(&commitment_key_2)));
    //   assert_eq!(envelope["encryption"]["key_commitment"]
    //                       .as_str().unwrap(),
    //              &computed_commitment,
    //              "key_commitment MUST match — wrong passphrase or \
    //               envelope tampering");
    //
    //   // 5d. derive subdomain keys + decrypt:
    //   let ss_key = hkdf::<Sha256>(
    //       &kdf_key_2, b"contrix-key-backup/secret_storage/v1/v1", 32);
    //   let ss_plain = xchacha20_open_with_aad(&ss_key, &nonce,
    //                       &ct_from_envelope, aad.as_bytes())?;
    //   // ... same for mls_history envelope to recover
    //   //     mls_history_backup_key + epoch_key_material.

    // ── Step 6: replay MLS history + decrypt 3 pre-loss messages ────────
    //
    //   let timeline = expect_json(
    //       server.http()
    //             .get(server.url(&format!(
    //                 "/api/v1/spaces/{space_id}/timeline")))
    //             .bearer_auth(&device_b_token),
    //       StatusCode::OK,
    //   ).await?;
    //   let commits = timeline["events"].as_array().unwrap()
    //       .iter()
    //       .filter(|e| e["kind"] == "cx.mls.commit")
    //       .collect::<Vec<_>>();
    //   assert_eq!(commits.len(), 3);
    //
    //   for (i, commit) in commits.iter().enumerate() {
    //       let epoch_key = derive_epoch_key(
    //           &recovered_mls_history_backup_key, i as u64);
    //       let plaintext = xchacha20_open_with_aad(
    //           &epoch_key,
    //           &base64url_decode(commit["content"]["nonce"]
    //                                  .as_str().unwrap())?,
    //           &base64url_decode(commit["content"]["ciphertext"]
    //                                  .as_str().unwrap())?,
    //           b"ct11-e2ee-history")?;
    //       assert_eq!(String::from_utf8(plaintext)?,
    //                  plaintexts[i],
    //                  "device-B MUST recover pre-loss message {i}");
    //   }

    unimplemented!(
        "CT-11 key backup restore + MLS history replay — blocked on \
         soland-side E2E-KEY-BACKUP-2 (SSK-proof-gated DELETE + recovery \
         attestation surface) AND, more critically, the absence of a \
         server-side MLS state machine: no `cx.mls.commit` reducer, no \
         epoch tracking, no historical commit chain to replay. \
         `PUT/GET /api/v1/keys/backups/{{id}}` ARE implemented today \
         (key_backup.rs) so steps 3 + 5b work; steps 2 + 6 await the \
         MLS reducer. cotest also needs an `argon2` dep added for the \
         §7.2 Argon2id KDF (pbkdf2 is already a transitive dep but \
         spec-compliant Argon2id MUST be the default). See module docs \
         + soland/_todos.md E2E-KEY-BACKUP-2/3 + spec key-management.md \
         §7.2 / §7.3."
    )
}
