// MLS group encryption (E2EE Realm lifecycle)
// Contract: e2e/scenarios/encryption/mls-group.md
// Spec refs:
//   - crypto-media/encryption-and-audit.md §2 (MLS architecture)
//   - §2.2 Welcome/Commit, §2.3 application envelope, §2.4 sync+epoch
//   - §2.5 Governance Binding, §2.6 KeyPackage
//   - models/realm-and-space.md §2.2 encryption_profile, §3.7.2 E2EE Realm

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  authHeaders,
  b64url,
  canonicalTimestamp,
  addRealmMemberApi,
  createRealmApi,
  singleDidNotary,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  type JointUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

// Build an encrypted Realm via a direct ck.realm.create envelope. The shared
// createRealmApi helper puts `plaintext_visible_services` at the payload root,
// which the current soland realm_create schema rejects (additionalProperties);
// this inline shape mirrors the accepted envelope used elsewhere in this file.
async function createEncryptedRealm(
  request: import("@playwright/test").APIRequestContext,
  token: string,
  ownerDid: string,
  title: string,
): Promise<string> {
  const realmId = typedId("realm");
  const createdAt = canonicalTimestamp();
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: ownerDid,
      realmId,
      kind: "ck.realm.create",
      createdAt,
      payload: {
        object: {
          id: realmId,
          schema: "ck.schema.realm.v1",
          title,
          created_by: ownerDid,
          trust_domain: "ck:trust_domain:soland.local",
          schema_refs: ["ck.schema.realm.v1"],
          default_discoverability: "listed",
          default_join_rule: "invite",
          history_visibility: "joined",
          encryption_profile: "mls_rfc9420",
          security_class: "standard",
          federation_policy: "restricted",
          notary_profile: "single_did",
          digest_algorithm: "sha256",
          notary: singleDidNotary(ownerDid),
          created_at: createdAt,
        },
      },
    }),
    { context: `create encrypted realm ${title}` },
  );
  return realmId;
}

async function sendEncryptedTimelineMessage(
  userPage: JointUserPage,
  realmId: string,
  body: string,
): Promise<string> {
  await userPage.gotoTimelineRealm(realmId);

  const encryptToggle = userPage.page.getByTestId("encrypt-local-button");
  await expect(encryptToggle).toBeVisible({ timeout: 30_000 });
  const toggleChecked = async () =>
    encryptToggle.evaluate((element) => {
      const input = element as HTMLInputElement;
      return (
        input.checked === true ||
        element.getAttribute("aria-checked") === "true" ||
        element.getAttribute("data-state") === "checked"
      );
    });
  if (!(await toggleChecked())) {
    await encryptToggle.click();
  }
  await expect.poll(toggleChecked, { timeout: 5_000 }).toBe(true);

  const messageSubmit = userPage.page.waitForResponse(
    (response) => {
      const request = response.request();
      const postData = request.postData() ?? "";
      return (
        request.method() === "POST" &&
        response.url().includes("/_cokret/self/events") &&
        postData.includes("ck.message.create")
      );
    },
    { timeout: 60_000 },
  );

  await userPage.page.getByTestId("chat-input").fill(body);
  await userPage.page.getByTestId("send-chat-button").click();

  const response = await messageSubmit;
  const postData = response.request().postData() ?? "";
  expect(
    [200, 201],
    `encrypted ck.message.create submit returned ${response.status()}: ${await response.text()}`,
  ).toContain(response.status());
  expect(postData).toContain("encrypted_content");
  expect(postData).toContain("mls-rfc9420");
  expect(postData).not.toContain(body);
  await expect(userPage.page.getByTestId("chat-status")).toContainText(
    /Encrypted message sent/i,
    { timeout: 30_000 },
  );
  return postData;
}

test.describe("MLS group encryption", () => {
  test("E2EE Realm surfaces MLS admin controls and rejects non-members from raw events", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const alice = uniqueUser("s11-alice");
    const mallory = uniqueUser("s11-mallory");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, mallory),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const malloryToken = await issueDevSession(request, mallory);
    const alicePage = await openUserPage(browser, alice, {
      sessionCredential: aliceToken,
    });

    try {
      const realmId = await alicePage.createRealm({
        title: `S11 E2EE ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyVisibility: "joined",
        encryptionProfile: "mls_rfc9420",
      });

      await alicePage.gotoRealmAdminSection(realmId, "security");
      await expect(alicePage.page.getByTestId("mls-rotation")).toBeVisible({
        timeout: 30_000,
      });

      // Non-member access to raw events MUST be rejected.
      const eventsResp = await request.get(
        `${solandBaseUrl()}/_cokret/self/events?realms=${encodeURIComponent(realmId)}&limit=20`,
        { headers: { authorization: `Bearer ${malloryToken}` } },
      );
      expect([401, 403, 404, 405]).toContain(eventsResp.status());
      await stepShot(alicePage.page, testInfo, "non-member-blocked");
    } finally {
      await alicePage.close();
    }
  });

  test("alice creates space with encryption_profile=mls_rfc9420 at create time; world_readable policy is rejected", async ({
    request,
  }) => {
    // Smoke for the create-time encryption profile path. Full ck.mls.genesis
    // materialization remains pinned below in the richer lifecycle cases.
    const stamp = Date.now();
    const alice = uniqueUser("s11-create-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `S11 MLS create-time ${stamp}`,
      discoverability: "listed",
      history_visibility: "joined",
      encryption_profile: "mls_rfc9420",
    });

    const exportResp = await request.get(
      `${solandBaseUrl()}/_cokret/self/realms/${encodeURIComponent(realmId)}/export`,
      { headers: authHeaders(aliceToken) },
    );
    expect(exportResp.ok()).toBeTruthy();
    expect(JSON.stringify(await exportResp.json())).toContain(
      '"encryption_profile":"mls_rfc9420"',
    );

    const incompatibleRealmId = typedId("realm");
    const incompatibleCreatedAt = canonicalTimestamp();
    const incompatible = await request.post(
      `${solandBaseUrl()}/_cokret/self/events`,
      {
        headers: authHeaders(aliceToken),
        data: signedEventEnvelope({
          actorDid: alice.did,
          realmId: incompatibleRealmId,
          kind: "ck.realm.create",
          createdAt: incompatibleCreatedAt,
          payload: {
            object: {
              id: incompatibleRealmId,
              schema: "ck.schema.realm.v1",
              title: `S11 MLS incompatible ${stamp}`,
              created_by: alice.did,
              trust_domain: "ck:trust_domain:soland.local",
              schema_refs: ["ck.schema.realm.v1"],
              default_discoverability: "listed",
              default_join_rule: "invite",
              history_visibility: "world_readable",
              encryption_profile: "mls_rfc9420",
              security_class: "standard",
              federation_policy: "restricted",
              notary_profile: "single_did",
              digest_algorithm: "sha256",
              notary: singleDidNotary(alice.did),
              created_at: incompatibleCreatedAt,
            },
          },
        }),
      },
    );
    expect([400, 422]).toContain(incompatible.status());
    expect(wireErrCode(await incompatible.json())).toBe(
      "incompatible_history_with_encryption",
    );
  });

  test("alice claims bob's KeyPackage; Welcome queue endpoint and commit epoch smoke stay live", async ({
    request,
  }) => {
    // API-first smoke for the G3.S1 subset: MLS group genesis,
    // KeyPackage publish/claim CAS, durable Welcome delivery, and
    // monotonic commit epoch. Full client derivation of epoch secrets
    // remains a later yougen+MLS concern.
    const stamp = Date.now();
    const alice = uniqueUser("s11-claim-alice");
    const bob = uniqueUser("s11-claim-bob");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);

    const keypackageId = typedId("mls_keypackage");
    const groupId = typedId("mls_group");
    const nowSeconds = Math.floor(Date.now() / 1000);
    const digest = (nibble: string) => `sha256:${nibble.repeat(64)}`;

    const publish = await request.post(
      `${solandBaseUrl()}/_cokret/self/keys/keypackages/upload`,
      {
        headers: authHeaders(bobToken),
        data: {
          keypackage_id: keypackageId,
          actor_id: bob.did,
          device_id: bob.deviceId,
          lifetime: {
            not_before: nowSeconds - 60,
            not_after: nowSeconds + 3600,
          },
          key_package_bytes_b64: b64url(`opaque-keypackage-${stamp}`),
        },
      },
    );
    expect(publish.ok()).toBeTruthy();
    const publishBody = await publish.json();
    expect(publishBody.keypackage_id).toBe(keypackageId);
    expect(publishBody.actor_id).toBe(bob.did);
    expect(publishBody.device_id).toBe(bob.deviceId);
    expect(publishBody.claimed).toBe(false);

    const pendingBefore = await request.get(
      `${solandBaseUrl()}/_cokret/self/keys/keypackages/welcomes/pending`,
      {
        headers: authHeaders(bobToken),
      },
    );
    expect(pendingBefore.ok()).toBeTruthy();
    expect((await pendingBefore.json()).welcomes).toEqual([]);

    const claim = await request.post(
      `${solandBaseUrl()}/_cokret/self/keys/keypackages/claim`,
      {
        headers: authHeaders(aliceToken),
        data: { keypackage_id: keypackageId, group_id: groupId },
      },
    );
    expect(claim.ok()).toBeTruthy();
    const claimBody = await claim.json();
    expect(claimBody.keypackage_id).toBe(keypackageId);
    expect(claimBody.group_id).toBe(groupId);
    expect(claimBody.claimed_at).toBeTruthy();

    const claimAgain = await request.post(
      `${solandBaseUrl()}/_cokret/self/keys/keypackages/claim`,
      {
        headers: authHeaders(aliceToken),
        data: { keypackage_id: keypackageId, group_id: typedId("mls_group") },
      },
    );
    expect(claimAgain.status()).toBe(409);
    expect(wireErrCode(await claimAgain.json())).toBe(
      "mls_keypackage_already_claimed",
    );

    const realmId = await createRealmApi(request, aliceToken, {
      title: `MLS lifecycle ${stamp}`,
      ownerDid: alice.did,
      history_visibility: "joined",
      encryption_profile: "mls_rfc9420",
    });

    const genesisEventId = typedId("event");
    const commitEventId = typedId("event");
    const frontierEventRef = genesisEventId;
    const genesisBinding = {
      binding_version: 1,
      encoding_profile: "cbor-deterministic-rfc8949-v1",
      realm_id: realmId,
      mls_group_id: groupId,
      previous_epoch: 0,
      next_epoch: 0,
      membership_frontier: [frontierEventRef],
      policy_root: digest("2"),
    };
    const genesisBody = await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ck.mls.genesis",
        eventId: genesisEventId,
        payload: {
          mls_group_id: groupId,
          realm_key_scope: {
            realm_id: realmId,
            policy_digest: digest("2"),
          },
          epoch: 0,
          creator_principal_id: alice.did,
          creator_device_id: alice.deviceId,
          cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
          group_info_digest: digest("3"),
          ratchet_tree_digest: digest("4"),
          governance_binding: genesisBinding,
          created_at: canonicalTimestamp(),
        },
      }),
      {
        context: "submit MLS genesis",
      },
    );
    expect(genesisBody.event_id).toBe(genesisEventId);

    const welcomeId = typedId("mls_welcome");
    const keypackageDigest = digest("5");
    const welcomeBody = await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ck.mls.welcome",
        payload: {
          welcome_id: welcomeId,
          mls_group_id: groupId,
          epoch: 1,
          recipient_principal_id: bob.did,
          recipient_device_id: bob.deviceId,
          key_package_id: keypackageId,
          keypackage_ref: keypackageDigest,
          keypackage_digest: keypackageDigest,
          claim_id: `claim-${stamp}`,
          claim_ref: {
            claim_id: `claim-${stamp}`,
            keypackage_ref: keypackageDigest,
            keypackage_digest: keypackageDigest,
            capabilities_digest: digest("6"),
            ssk_generation: 1,
          },
          ciphertext: `opaque-mls-welcome-${stamp}`,
          expires_at: canonicalTimestamp(new Date(Date.now() + 60 * 60 * 1000)),
          commit_ref: commitEventId,
          governance_binding: genesisBinding,
        },
      }),
      {
        context: "submit MLS welcome",
      },
    );
    expect(welcomeBody.event_id).toMatch(/^ck:event:/);

    const commitPayload = (label: string, nextEpoch = 1) => ({
      group_id: groupId,
      expected_prev_epoch: 0,
      leader_actor_id: alice.did,
      commit_bytes_b64: b64url(label),
      mls_group_id: groupId,
      base_epoch: 0,
      base_epoch_ref: frontierEventRef,
      proposal_refs: [],
      next_epoch: nextEpoch,
      commit_digest: digest("7"),
      governance_binding: {
        binding_version: 1,
        encoding_profile: "cbor-deterministic-rfc8949-v1",
        realm_id: realmId,
        mls_group_id: groupId,
        previous_epoch: 0,
        next_epoch: nextEpoch,
        membership_frontier: [frontierEventRef],
        policy_root: digest("2"),
        threshold: {
          k: 2,
          n: 3,
          signers: [alice.did, bob.did, "did:web:mls-auditor.example"],
        },
        signatures: [
          { signer_did: alice.did, signature_b64: b64url(`alice-${stamp}`) },
          { signer_did: bob.did, signature_b64: b64url(`bob-${stamp}`) },
        ],
      },
    });
    const commitEnvelope = signedEventEnvelope({
      actorDid: alice.did,
      realmId,
      kind: "ck.mls.commit",
      eventId: commitEventId,
      payload: commitPayload(`opaque-commit-${stamp}`),
    });
    const commitBody = await submitSignedEventApi(
      request,
      aliceToken,
      commitEnvelope,
      {
        context: "submit MLS commit",
      },
    );
    expect(commitBody.event_id).toMatch(/^ck:event:/);

    const pendingAfterWelcome = await request.get(
      `${solandBaseUrl()}/_cokret/self/keys/keypackages/welcomes/pending`,
      {
        headers: authHeaders(bobToken),
      },
    );
    expect(pendingAfterWelcome.ok()).toBeTruthy();
    const pendingAfterWelcomeBody = await pendingAfterWelcome.json();
    expect(pendingAfterWelcomeBody.welcomes).toHaveLength(1);
    expect(pendingAfterWelcomeBody.welcomes[0]).toMatchObject({
      welcome_id: welcomeId,
      group_id: groupId,
      key_package_id: keypackageId,
    });
    expect(pendingAfterWelcomeBody.welcomes[0].delivered_at).toBeTruthy();

    const pendingAfterDrain = await request.get(
      `${solandBaseUrl()}/_cokret/self/keys/keypackages/welcomes/pending`,
      {
        headers: authHeaders(bobToken),
      },
    );
    expect(pendingAfterDrain.ok()).toBeTruthy();
    expect((await pendingAfterDrain.json()).welcomes).toEqual([]);

    const staleCommit = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
      headers: authHeaders(aliceToken),
      data: signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ck.mls.commit",
        payload: commitPayload(`opaque-stale-commit-${stamp}`),
      }),
    });
    expect([409, 412, 422]).toContain(staleCommit.status());
    expect(wireErrCode(await staleCommit.json())).toBe("mls_epoch_skew");
  });

  test("joined member decrypts E2EE timeline messages; raw event payload stays ciphertext only", async ({
    browser,
    request,
  }, testInfo) => {
    // Regression for the join→decrypt boundary: accepting a Realm invite must
    // leave the new member with usable MLS state for messages sent after join.
    // Spec: encryption-and-audit.md §2.2-§2.4, §2.3.1-§2.3.3.
    const stamp = Date.now();
    const alice = uniqueUser("s11-decrypt-alice");
    const bob = uniqueUser("s11-decrypt-bob");
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);
    const [alicePage, bobPage] = await Promise.all([
      openUserPage(browser, alice, { sessionCredential: aliceToken }),
      openUserPage(browser, bob, { sessionCredential: bobToken }),
    ]);

    try {
      const realmId = await alicePage.createRealm({
        title: `S11 joined decrypt ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyVisibility: "joined",
        encryptionProfile: "mls_rfc9420",
        seedMembers: [bob.did],
      });
      await bobPage.acceptInvite(realmId);

      // Route-context bootstrap is where Bob applies pending MLS Welcome state.
      await bobPage.gotoTimelineRealm(realmId);

      const plaintext = `joined member decrypts post-join ciphertext ${stamp}`;
      const submittedWire = await sendEncryptedTimelineMessage(alicePage, realmId, plaintext);
      expect(submittedWire).not.toContain(plaintext);

      await expect(alicePage.timelineEvent(plaintext)).toBeVisible({ timeout: 30_000 });

      await bobPage.page.reload({ waitUntil: "domcontentloaded" });
      await expect(bobPage.page.getByTestId("message-list")).toBeVisible({ timeout: 120_000 });
      const bobMessage = bobPage.timelineEvent(plaintext);
      await expect(bobMessage).toBeVisible({ timeout: 60_000 });
      await expect(bobMessage.getByTestId("event-body")).toContainText(plaintext);

      const rawEvents = await request.get(
        `${solandBaseUrl()}/_cokret/self/events?realms=${encodeURIComponent(realmId)}&limit=100`,
        { headers: authHeaders(bobToken) },
      );
      expect(rawEvents.status()).toBe(200);
      const rawWire = JSON.stringify(await rawEvents.json());
      expect(rawWire).toContain("encrypted_content");
      expect(rawWire).toContain("mls-rfc9420");
      expect(rawWire).not.toContain(plaintext);

      await stepShot(bobPage.page, testInfo, "joined-member-decrypted-e2ee-message");
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });

  test.fixme(// @blocking-on: soland#encryption-mls-group-gap
  // @user-promise: e2e/scenarios/encryption/mls-group.md
  // @expected-live-by: 2026Q3
  "carol added in epoch 1 → ck.mls.commit advances to epoch 2; carol cannot decrypt pre-join messages (history_visibility=joined)", async () => {
    // spec: encryption-and-audit.md §2.4.1, models/realm-and-space.md §3.4
  });

  test("alice bans bob → membership_frontier advances; client enters epoch_update_required state for up to max_mls_commit_delay_ms", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const alice = uniqueUser("s11-ban-alice");
    const bob = uniqueUser("s11-ban-bob");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `S11 MLS ban ${stamp}`,
      ownerDid: alice.did,
      history_visibility: "joined",
      encryption_profile: "mls_rfc9420",
    });
    await addRealmMemberApi(request, aliceToken, realmId, bob.did);

    const alicePage = await openUserPage(browser, alice, {
      sessionCredential: aliceToken,
    });

    try {
      await alicePage.gotoRealmAdminSection(realmId, "members");
      const refresh = alicePage.page.getByTestId("refresh-members-button");
      await expect(refresh).toBeVisible({ timeout: 120_000 });
      const bobRow = alicePage.page.getByTestId("member-row").filter({
        has: alicePage.page.locator(`[title="${bob.did}"]`),
      });
      await expect
        .poll(
          async () => {
            await refresh.click();
            return await bobRow.count();
          },
          {
            timeout: 120_000,
            intervals: [1_000, 2_000, 5_000],
            message: "Bob joined member row should appear in synced admin projection",
          },
        )
        .toBeGreaterThan(0);

      await bobRow.first().getByTestId("ban-member-button").click();
      await expect(alicePage.page.getByTestId("realm-admin-panel")).toContainText(
        "epoch_update_required",
        { timeout: 30_000 },
      );

      await alicePage.gotoTimelineRealm(realmId);
      const epochBanner = alicePage.page.getByTestId(
        "epoch-update-required-banner",
      );
      await expect(epochBanner).toBeVisible({ timeout: 30_000 });
      await expect(epochBanner).toContainText("epoch_update_required");
      await expect(alicePage.page.getByTestId("send-chat-button")).toBeDisabled();
      await stepShot(alicePage.page, testInfo, "epoch-update-required-after-ban");
    } finally {
      await alicePage.close();
    }
  });

  test.fixme(// @blocking-on: soland#encryption-mls-group-gap
  // @user-promise: e2e/scenarios/encryption/mls-group.md
  // @expected-live-by: 2026Q3
  "E11.1 concurrent MLS commits produce ⊥ in covered_frontier_cell; subsequent messages marked decryption_pending until later commit resolves", async () => {
    // spec: encryption-and-audit.md §2.5.2
  });

  test.fixme(// @blocking-on: soland#encryption-mls-group-gap
  // @user-promise: e2e/scenarios/encryption/mls-group.md
  // @expected-live-by: 2026Q3
  "E11.2 governance_binding.realm_policy_digest mismatch causes federation push to reject with governance_binding_mismatch", async () => {
    // spec: encryption-and-audit.md §2.5.1
  });

  // encryption_profile is a create-locked Realm field (spec
  // realm-and-space.md §2.3). soland enforces this in operations.rs
  // (operation_touches_encryption_profile → realm_encryption_profile_create_locked)
  // but no soland unit test or cotest case exercises it. This pins the wire
  // rejection so a regression that lets the profile be patched after creation
  // — silently downgrading an Encrypted Realm to plaintext — is caught.
  test("ck.realm.update that patches encryption_profile is rejected (create-locked)", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser("mls-lock-realm-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const realmId = await createEncryptedRealm(
      request,
      aliceToken,
      alice.did,
      `MLS create-lock realm ${stamp}`,
    );

    const resp = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
      headers: authHeaders(aliceToken),
      data: signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ck.realm.update",
        payload: {
          target_ref: realmId,
          patch: { encryption_profile: { $op: "set", value: "none" } },
        },
      }),
    });

    const body = await resp.json();
    expect([400, 409, 412, 422], JSON.stringify(body)).toContain(resp.status());
    expect(wireErrCode(body)).toBe("realm_encryption_profile_create_locked");
  });

  // Circle counterpart of the realm create-lock.
  //
  // CONFIRMED GAP (parked pending fix): unlike ck.realm.update, soland's
  // submit path does NOT enforce the circle create-lock synchronously. The
  // check exists (operations.rs validate_content_encryption_floor CX_CIRCLE_UPDATE
  // branch + reducer.rs apply), but `operation_schema_for_kind` has no arm for
  // ck.circle.create / ck.circle.update, so projection_operation_from_event
  // returns None and event_log.rs skips ALL submit-time operation validation
  // for circle events. The create-lock is only caught at the async projection
  // (reducer) layer — so state stays safe (profile is not actually changed),
  // but the submit returns a misleading 200 instead of 4xx. Fix = add circle
  // operation schemas (needs full circle-path regression: it would newly run
  // validate_operation_policy + policy_gate on circle events at submit).
  test("ck.circle.update that patches encryption_profile is rejected (create-locked)", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser("mls-lock-circle-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const realmId = await createEncryptedRealm(
      request,
      aliceToken,
      alice.did,
      `MLS create-lock circle realm ${stamp}`,
    );

    const circleId = typedId("circle");
    await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ck.circle.create",
        payload: {
          object: {
            id: circleId,
            schema: "ck.schema.circle.v1",
            realm_id: realmId,
            title: `lock circle ${stamp}`,
            display: {
              short_name: "LC",
              color_token: "indigo",
              symbol: { glyph: "shield" },
            },
            directory_visibility: "members",
            join_rule: "invite",
            history_visibility: "joined",
            encryption_profile: "mls_rfc9420",
            state: "active",
            created_by: alice.did,
            created_at: canonicalTimestamp(),
          },
        },
      }),
      { context: `create circle ${circleId}` },
    );

    const resp = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
      headers: authHeaders(aliceToken),
      data: signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ck.circle.update",
        payload: {
          target_ref: circleId,
          patch: { encryption_profile: { $op: "set", value: "none" } },
        },
      }),
    });

    const body = await resp.json();
    expect([400, 409, 412, 422], JSON.stringify(body)).toContain(resp.status());
    expect(wireErrCode(body)).toBe("circle_encryption_profile_create_locked");
  });

  // Not-ready guard: a fresh device of the SAME account that has NOT received
  // an MLS Welcome and has NOT restored its account secret must NOT silently
  // downgrade an encrypted private write to plaintext. The client should
  // surface a recoverable "MLS state not ready" affordance and refuse to
  // submit; it must never POST a plaintext ck.strand.update that the server
  // accepts (or bounces with content_encryption_floor_violation).
  //
  // Parked as fixme: deterministically reaching the "fresh device, no
  // backup, no welcome" state requires a second-device rig (sameActorFreshDevice
  // + openUserPage), and the exact not-ready UX surface (mls-unlock-banner vs
  // board_status text) must be confirmed against a live stack before the
  // assertions can be pinned without flake. Promote to an active test once the
  // first stack run confirms the surfaced affordance.
  test.fixme(
    // @blocking-on: yougen#mls-not-ready-write-guard
    // @user-promise: e2e/scenarios/encryption/mls-group.md
    // @expected-live-by: 2026Q3
    "fresh device without MLS welcome/restore refuses encrypted private writes instead of silently downgrading to plaintext",
    async () => {
      // 1) deviceA: createRealm(encryption_profile=mls_rfc9420) + board + list + card.
      // 2) deviceB = sameActorFreshDevice(alice): fresh session, NO passphrase
      //    vault set up, NO welcome applied.
      // 3) deviceB opens the board, opens the card (title is plaintext metadata),
      //    tries to add a description.
      // 4) Assert: NO /_cokret/self/events POST carrying a plaintext private `body`
      //    is accepted (and none is bounced with content_encryption_floor_violation),
      //    AND a not-ready affordance (mls-unlock-banner / "MLS state is not
      //    ready" board status) is shown.
    },
  );
});

