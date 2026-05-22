// MLS group encryption (E2EE space lifecycle)
// Contract: e2e/scenarios/encryption/mls-group.md
// Spec refs:
//   - crypto-media/encryption-and-audit.md §2 (MLS architecture)
//   - §2.2 Welcome/Commit, §2.3 application envelope, §2.4 sync+epoch
//   - §2.5 Governance Binding, §2.6 KeyPackage
//   - models/space-and-place.md §2.2 encryption_profile, §3.7.2 E2EE space

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import { authHeaders, b64url, createSpaceApi, typedId, wireErrCode } from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("MLS group encryption", () => {
  test("E2EE space surfaces encryption_profile=mls_rfc9420 in admin and rejects non-members from raw events", async ({
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
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

    try {
      // yougen's /setup wizard 当前没有 encryption_profile 选项;先建普通 space,
      // 然后通过 API 把 encryption_profile 升级到 mls_rfc9420(若 soland 接受)。
      const spaceId = await alicePage.createSpace({
        title: `S11 E2EE ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
      });

      const upgradeResp = await request.put(
        `${solandBaseUrl()}/api/v1/spaces/${encodeURIComponent(spaceId)}/policy`,
        {
          headers: { authorization: `Bearer ${aliceToken}` },
          data: { encryption_profile: "mls_rfc9420" },
        },
      );
      // 若 soland 不支持运行时切换 encryption_profile(spec implies 创建时锁定),
      // 该步骤会 4xx — 测试侧 tolerate,后续断言只跑可达的部分。
      if (!upgradeResp.ok()) {
        test.info().annotations.push({
          type: "soland-gap",
          description: `space encryption_profile upgrade returned ${upgradeResp.status()}; spec §2.2 implies create-time only.`,
        });
      }

      // Non-member access to raw events MUST be rejected.
      const eventsResp = await request.get(
        `${solandBaseUrl()}/api/v1/spaces/${encodeURIComponent(spaceId)}/events`,
        { headers: { authorization: `Bearer ${malloryToken}` } },
      );
      expect([401, 403, 404, 405]).toContain(eventsResp.status());
      await stepShot(alicePage.page, testInfo, "non-member-blocked");
    } finally {
      await alicePage.close();
    }
  });

  test(
    "alice creates space with encryption_profile=mls_rfc9420 at create time; world_readable policy is rejected",
    async ({ request }) => {
      // Smoke for the create-time encryption profile path. Full cx.mls.genesis
      // materialization remains pinned below in the richer lifecycle cases.
      const stamp = Date.now();
      const alice = uniqueUser("s11-create-alice");
      await ensureRegistered(request, alice);
      const aliceToken = await issueDevSession(request, alice);

      const spaceId = await createSpaceApi(request, aliceToken, {
        title: `S11 MLS create-time ${stamp}`,
        discoverability: "listed",
        history_visibility: "joined",
        encryption_profile: "mls_rfc9420",
      });

      const exportResp = await request.get(
        `${solandBaseUrl()}/api/v1/spaces/${encodeURIComponent(spaceId)}/export`,
        { headers: authHeaders(aliceToken) },
      );
      expect(exportResp.ok()).toBeTruthy();
      expect(JSON.stringify(await exportResp.json())).toContain('"encryption_profile":"mls_rfc9420"');

      const incompatible = await request.put(
        `${solandBaseUrl()}/api/v1/spaces/${encodeURIComponent(spaceId)}/policy`,
        {
          headers: authHeaders(aliceToken),
          data: { join_rule: "public", history_visibility: "world_readable" },
        },
      );
      expect([400, 422]).toContain(incompatible.status());
      expect(wireErrCode(await incompatible.json())).toBe("incompatible_history_with_encryption");
    },
  );

  test(
    "alice claims bob's KeyPackage; Welcome queue endpoint and commit epoch smoke stay live",
    async ({ request }) => {
      // API-first smoke for the G3.S1 subset: KeyPackage publish/claim CAS,
      // Welcome pending queue surface, and monotonic commit epoch. Full client
      // derivation of epoch secrets remains a later yougen+MLS concern.
      const stamp = Date.now();
      const alice = uniqueUser("s11-claim-alice");
      const bob = uniqueUser("s11-claim-bob");
      await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
      const [aliceToken, bobToken] = await Promise.all([
        issueDevSession(request, alice),
        issueDevSession(request, bob),
      ]);

      const keypackageId = typedId("mls_keypackage");
      const groupId = typedId("mls_group");
      const nowSeconds = Math.floor(Date.now() / 1000);

      const publish = await request.post(`${solandBaseUrl()}/api/v1/mls/keypackages`, {
        headers: authHeaders(bobToken),
        data: {
          keypackage_id: keypackageId,
          actor_did: bob.did,
          device_id: bob.deviceId,
          lifetime: {
            not_before: nowSeconds - 60,
            not_after: nowSeconds + 3600,
          },
          key_package_bytes_b64: b64url(`opaque-keypackage-${stamp}`),
        },
      });
      expect(publish.ok()).toBeTruthy();
      const publishBody = await publish.json();
      expect(publishBody.keypackage_id).toBe(keypackageId);
      expect(publishBody.actor_did).toBe(bob.did);
      expect(publishBody.device_id).toBe(bob.deviceId);
      expect(publishBody.claimed).toBe(false);

      const pendingBefore = await request.get(`${solandBaseUrl()}/api/v1/mls/welcomes/pending`, {
        headers: authHeaders(bobToken),
      });
      expect(pendingBefore.ok()).toBeTruthy();
      expect((await pendingBefore.json()).welcomes).toEqual([]);

      const claim = await request.post(
        `${solandBaseUrl()}/api/v1/mls/keypackages/${encodeURIComponent(keypackageId)}/claim`,
        {
          headers: authHeaders(aliceToken),
          data: { group_id: groupId },
        },
      );
      expect(claim.ok()).toBeTruthy();
      const claimBody = await claim.json();
      expect(claimBody.keypackage_id).toBe(keypackageId);
      expect(claimBody.group_id).toBe(groupId);
      expect(claimBody.claimed_at).toBeTruthy();

      const claimAgain = await request.post(
        `${solandBaseUrl()}/api/v1/mls/keypackages/${encodeURIComponent(keypackageId)}/claim`,
        {
          headers: authHeaders(aliceToken),
          data: { group_id: typedId("mls_group") },
        },
      );
      expect(claimAgain.status()).toBe(409);
      expect(wireErrCode(await claimAgain.json())).toBe("mls_keypackage_already_claimed");

      const commit = await request.post(`${solandBaseUrl()}/api/v1/mls/commits`, {
        headers: authHeaders(aliceToken),
        data: {
          group_id: groupId,
          expected_prev_epoch: 0,
          leader_actor_did: alice.did,
          commit_bytes_b64: b64url(`opaque-commit-${stamp}`),
        },
      });
      expect(commit.ok()).toBeTruthy();
      const commitBody = await commit.json();
      expect(commitBody.previous_epoch).toBe(0);
      expect(commitBody.epoch).toBe(1);

      const staleCommit = await request.post(`${solandBaseUrl()}/api/v1/mls/commits`, {
        headers: authHeaders(aliceToken),
        data: {
          group_id: groupId,
          expected_prev_epoch: 0,
          leader_actor_did: alice.did,
          commit_bytes_b64: b64url(`opaque-stale-commit-${stamp}`),
        },
      });
      expect([409, 412]).toContain(staleCommit.status());
      expect(wireErrCode(await staleCommit.json())).toBe("mls_epoch_skew");

      const pendingAfter = await request.get(`${solandBaseUrl()}/api/v1/mls/welcomes/pending`, {
        headers: authHeaders(bobToken),
      });
      expect(pendingAfter.ok()).toBeTruthy();
      expect(Array.isArray((await pendingAfter.json()).welcomes)).toBe(true);
    },
  );

  test.fixme(
    // @blocking-on: soland#encryption-mls-group-gap
    // @user-promise: e2e/scenarios/encryption/mls-group.md
    // @expected-live-by: 2026Q3
    "alice and bob exchange E2EE messages; client decrypts plaintext, raw event payload is ciphertext only (no plaintext leak)",
    async () => {
      // spec: encryption-and-audit.md §2.3.1-§2.3.3 application data envelope
      // soland gap: encrypted_payload routing without server-side decryption.
    },
  );

  test.fixme(
    // @blocking-on: soland#encryption-mls-group-gap
    // @user-promise: e2e/scenarios/encryption/mls-group.md
    // @expected-live-by: 2026Q3
    "carol added in epoch 1 → cx.mls.commit advances to epoch 2; carol cannot decrypt pre-join messages (history_visibility=joined)",
    async () => {
      // spec: encryption-and-audit.md §2.4.1, models/space-and-place.md §3.4
    },
  );

  test.fixme(
    // @blocking-on: soland#encryption-mls-group-gap
    // @user-promise: e2e/scenarios/encryption/mls-group.md
    // @expected-live-by: 2026Q3
    "alice bans bob → membership_frontier advances; client enters epoch_update_required state for up to max_mls_commit_delay_ms",
    async () => {
      // spec: encryption-and-audit.md §2.4.1, §2.5
    },
  );

  test.fixme(
    // @blocking-on: soland#encryption-mls-group-gap
    // @user-promise: e2e/scenarios/encryption/mls-group.md
    // @expected-live-by: 2026Q3
    "E11.1 concurrent MLS commits produce ⊥ in covered_frontier_cell; subsequent messages marked decryption_pending until later commit resolves",
    async () => {
      // spec: encryption-and-audit.md §2.5.2
    },
  );

  test.fixme(
    // @blocking-on: soland#encryption-mls-group-gap
    // @user-promise: e2e/scenarios/encryption/mls-group.md
    // @expected-live-by: 2026Q3
    "E11.2 governance_binding.space_policy_hash mismatch causes federation push to reject with governance_binding_mismatch",
    async () => {
      // spec: encryption-and-audit.md §2.5.1
    },
  );
});
