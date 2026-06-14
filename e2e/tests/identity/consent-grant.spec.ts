// Consent grant strand
// Contract: e2e/scenarios/identity/consent-grant.md
// Spec: identity/consent-model.md §2-§4

import { expect, test, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  authHeaders,
  createRealmApi,
  expectJsonOk,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";
import { selectDxcOption } from "../../helpers/dxc-select";

test.describe.configure({ mode: "serial" });

async function requestContact(
  actor: Awaited<ReturnType<typeof openUserPage>>,
  targetDid: string,
  scope: "invite" | "message" | "call",
) {
  // "Add contact" is a popup modal opened from the contacts list, not a
  // standalone /contacts/new page.
  await actor.page.goto("/contacts", { waitUntil: "domcontentloaded" });
  await actor.page.getByTestId("add-contact-button").click();
  await expect(actor.page.getByTestId("contact-request-panel")).toBeVisible({
    timeout: 120_000,
  });
  await actor.page.getByTestId("contact-target-input").fill(targetDid);
  // Scope is selected via checkboxes (direct_message + invite default to
  // checked). Leave only the requested scope checked.
  const wantInvite = scope === "invite";
  const wantDm = scope === "message";
  const dm = actor.page.getByTestId("contact-scope-direct_message");
  const inv = actor.page.getByTestId("contact-scope-invite");
  if ((await dm.isChecked()) !== wantDm) await dm.click();
  if ((await inv.isChecked()) !== wantInvite) await inv.click();
  await actor.page.getByTestId("send-contact-request-button").click();
  return actor.page.getByTestId("contact-request-status");
}

async function gotoConsentSettings(actor: Awaited<ReturnType<typeof openUserPage>>) {
  await actor.page.goto("/settings/consent", { waitUntil: "domcontentloaded" });
  await expect(actor.page.getByTestId("consent-settings-panel")).toBeVisible({
    timeout: 120_000,
  });
}

async function expectConsentCell(
  request: APIRequestContext,
  token: string,
  holderDid: string,
  peerDid: string,
  scope: string,
  expectedState: "granted" | "revoked" | "expired" | "pending",
) {
  const cell = await request.get(
    `${solandBaseUrl()}/_cokret/self/consent/cells/${encodeURIComponent(holderDid)}` +
      `?peer=${encodeURIComponent(peerDid)}&scope=${encodeURIComponent(scope)}`,
    { headers: { authorization: `Bearer ${token}` } },
  );
  expect(cell.status()).toBe(200);
  const body = await cell.json();
  expect(JSON.stringify(body)).toContain(peerDid);
  expect(JSON.stringify(body)).toContain(scope);
  expect(JSON.stringify(body)).toContain(expectedState);
  return body as Record<string, unknown>;
}

async function requestContactApi(
  request: APIRequestContext,
  token: string,
  targetDid: string,
  scope: "invite" | "message" | "call",
) {
  const response = await request.post(`${solandBaseUrl()}/_soland/self/contacts/request`, {
    headers: authHeaders(token),
    data: { target: targetDid, scope },
  });
  return await expectJsonOk<Record<string, unknown>>(response, `request contact ${scope}`);
}

test.describe("consent grant", () => {
  test("consent settings surface exposes the local grant form controls", async ({
    browser,
    request,
  }, testInfo) => {
    // Live G2.T5 UI smoke: the settings page exists and its direct grant form
    // is mounted; the live grant/revoke strand is covered below.
    const alice = uniqueUser("g2t5-consent-ui-alice");
    const bob = uniqueUser("g2t5-consent-ui-bob");
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const aliceToken = await issueDevSession(request, alice);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

    try {
      await gotoConsentSettings(alicePage);
      await expect(alicePage.page.getByTestId("consent-grant-empty")).toBeVisible({
        timeout: 30_000,
      });

      await alicePage.page.getByTestId("consent-new-grant-button").click();
      await selectDxcOption(
        alicePage.page.getByTestId("consent-new-grant-scope-input"),
        "message",
      );
      await alicePage.page.getByTestId("consent-new-grant-grantee-input").fill(bob.did);
      await alicePage.page.getByTestId("consent-new-grant-ttl-input").fill("30d");
      await expect(alicePage.page.getByTestId("consent-new-grant-submit-button")).toBeEnabled();
      await stepShot(alicePage.page, testInfo, "A-consent-local-grant-form-ready");

      await alicePage.page.getByTestId("consent-new-grant-button").click();
      await expect(alicePage.page.getByTestId("consent-new-grant-scope-input")).toHaveCount(0);
      await expect(alicePage.page.getByTestId("consent-grant-empty")).toBeVisible();
    } finally {
      await alicePage.close();
    }
  });

  test("consent settings can open an outbound consent request", async ({
    browser,
    request,
  }, testInfo) => {
    // alice asks bob (the holder) to grant her `message` consent via the
    // `ck.consent.request` entry point; the resulting pending cell surfaces as
    // an outgoing-request row on alice's settings page.
    const alice = uniqueUser("consent-request-alice");
    const bob = uniqueUser("consent-request-bob");
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const aliceToken = await issueDevSession(request, alice);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

    try {
      await gotoConsentSettings(alicePage);

      await alicePage.page.getByTestId("consent-request-button").click();
      await selectDxcOption(
        alicePage.page.getByTestId("consent-request-scope-input"),
        "message",
      );
      await alicePage.page.getByTestId("consent-request-holder-input").fill(bob.did);
      await expect(alicePage.page.getByTestId("consent-request-submit-button")).toBeEnabled();
      await alicePage.page.getByTestId("consent-request-submit-button").click();

      await expect(alicePage.page.getByTestId("write-status")).toContainText(/requested/i, {
        timeout: 30_000,
      });
      // Cell is holder=bob / peer=alice / pending; alice (the peer) may read it.
      await expectConsentCell(request, aliceToken, bob.did, alice.did, "message", "pending");
      await expect(
        alicePage.page.getByTestId("consent-outgoing-request-row").filter({ hasText: bob.did }),
      ).toBeVisible({ timeout: 30_000 });
      await stepShot(alicePage.page, testInfo, "consent-outbound-request");
    } finally {
      await alicePage.close();
    }
  });

  test("contacts new page submits scoped consent request", async ({
    browser,
    request,
  }) => {
    const alice = uniqueUser("p1-022-contact-new-alice");
    const bob = uniqueUser("p1-022-contact-new-bob");
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);
    const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });

    try {
      const status = await requestContact(bobPage, alice.did, "message");
      await expect(status).toContainText(/pending/i, { timeout: 30_000 });
      await expectConsentCell(request, aliceToken, alice.did, bob.did, "message", "pending");
    } finally {
      await bobPage.close();
    }
  });

  test("consent API smoke: MIMI request/update returns holder-private receipts", async ({
    request,
  }) => {
    // Live G2.T5 API smoke: soland has a consent-adjacent MIMI surface today.
    // The general ck.consent.* cell reducer is still not implemented, so the
    // full identity consent lifecycle remains fixme below.
    const alice = uniqueUser("g2t5-consent-api-alice");
    const bob = uniqueUser("g2t5-consent-api-bob");
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);

    const open = await request.post(`${solandBaseUrl()}/_cokret/open/mimi/consent/request`, {
      data: {
        holder_did: alice.did,
        grantee_did: bob.did,
        scope: "message",
        purpose: "G2.T5 consent API smoke",
      },
    });
    expect(open.status()).toBe(200);
    const openBody = await open.json();
    expect(openBody.ok).toBe(true);
    expect(openBody.state).toBe("requested");
    expect(openBody.consent_id).toMatch(/^ck:mimi_consent:/);
    expect(openBody.receipt?.operation_id).toBe("ck.open.mimi.command.request_consent");
    expect(openBody.receipt?.extra?.privacy_state).toBe("holder_private");
    expect(openBody.receipt?.extra?.consent_grants_space_capability).toBe(false);

    const update = await request.post(`${solandBaseUrl()}/_cokret/open/mimi/consent/update`, {
      data: {
        consent_id: openBody.consent_id,
        state: "accepted",
        holder_did: alice.did,
        grantee_did: bob.did,
      },
    });
    expect(update.status()).toBe(200);
    const updateBody = await update.json();
    expect(updateBody.ok).toBe(true);
    expect(updateBody.consent_id).toBe(openBody.consent_id);
    expect(updateBody.state).toBe("accepted");
    expect(updateBody.receipt?.operation_id).toBe("ck.open.mimi.command.update_consent");
    expect(updateBody.receipt?.extra?.membership_still_required).toBe(true);
  });

  test("ck.consent.grant event projects consent cell and contact gate", async ({
    request,
  }) => {
    const alice = uniqueUser("p1-020-consent-event-alice");
    const bob = uniqueUser("p1-020-consent-event-bob");
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `P1-020 consent reducer ${Date.now()}`,
      ownerDid: alice.did,
    });

    const pending = await requestContactApi(request, bobToken, alice.did, "message");
    expect(pending.status).toBe("pending");

    const consentId = typedId("operation").replace("ck:operation:", "ck:consent:");
    const grantEnvelope = signedEventEnvelope({
      actorDid: alice.did,
      realmId,
      kind: "ck.consent.grant",
      payload: {
        consent_id: consentId,
        peer: bob.did,
        consent_scope: "direct_message",
        expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      },
    });
    await submitSignedEventApi(request, aliceToken, grantEnvelope, {
      context: "submit ck.consent.grant",
    });
    const grantDot = `${String(grantEnvelope.event_id)}:${Number(grantEnvelope.actor_seq)}`;

    const granted = await expectConsentCell(
      request,
      aliceToken,
      alice.did,
      bob.did,
      "message",
      "granted",
    );
    expect(granted.cell_id).toBe(`ck:cell:ck.component.consent.grant.v1:${consentId}`);
    expect(granted.grant_dots).toContain(grantDot);
    const accepted = await requestContactApi(request, bobToken, alice.did, "message");
    expect(accepted.status).toBe("accepted");

    const revokeEnvelope = signedEventEnvelope({
      actorDid: alice.did,
      realmId,
      kind: "ck.consent.revoke",
      payload: {
        consent_id: consentId,
        observed_dots: [grantDot],
        revoked_at: new Date(Date.now() + 1000).toISOString(),
      },
    });
    await submitSignedEventApi(request, aliceToken, revokeEnvelope, {
      context: "submit ck.consent.revoke",
    });

    const revoked = await expectConsentCell(
      request,
      aliceToken,
      alice.did,
      bob.did,
      "message",
      "revoked",
    );
    expect(revoked.revoked_dots).toContain(grantDot);
    const blocked = await requestContactApi(request, bobToken, alice.did, "message");
    expect(blocked.status).toBe("pending");
  });

  test("consent settings grants and revokes a pending request", async ({
    browser,
    request,
  }) => {
    const alice = uniqueUser("p1-023-settings-consent-alice");
    const bob = uniqueUser("p1-023-settings-consent-bob");
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);
    await requestContactApi(request, bobToken, alice.did, "message");
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

    try {
      await gotoConsentSettings(alicePage);
      const pendingRow = alicePage.page.getByTestId("consent-pending-row").filter({
        hasText: bob.did,
      });
      await expect(pendingRow).toBeVisible({ timeout: 30_000 });
      await pendingRow.getByTestId("consent-detail-button").click();
      const detail = alicePage.page.getByTestId("consent-pending-detail");
      await expect(detail).toContainText(bob.did);
      await selectDxcOption(detail.getByTestId("consent-scope-select"), "message");
      await detail.getByTestId("consent-valid-until-input").fill(
        new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
      );
      await detail.getByTestId("grant-consent-button").click();
      await expect(alicePage.page.getByTestId("write-status")).toContainText(/granted/i, {
        timeout: 30_000,
      });
      await expect(
        alicePage.page.getByTestId("consent-granted-row").filter({ hasText: bob.did }),
      ).toBeVisible({ timeout: 30_000 });
      await expectConsentCell(request, aliceToken, alice.did, bob.did, "message", "granted");

      await alicePage.page
        .getByTestId("consent-granted-row")
        .filter({ hasText: bob.did })
        .getByTestId("revoke-consent-button")
        .click();
      await expect(alicePage.page.getByTestId("write-status")).toContainText(/revoked/i, {
        timeout: 30_000,
      });
      await expectConsentCell(request, aliceToken, alice.did, bob.did, "message", "revoked");
    } finally {
      await alicePage.close();
    }
  });

  test.fixme(
    // @blocking-on: soland#identity-consent-grant-gap
    // @user-promise: e2e/scenarios/identity/consent-grant.md
    // @expected-live-by: 2026Q3
    "alice grants consent and bob can establish contact (full lifecycle)",
    async ({ browser, request }, testInfo) => {
      // spec: identity/consent-model.md §2-§4.
      // soland gap: ck.consent.* reducer/projection 未实现.
      // yougen gap: /contacts/new and /settings/consent consent UI 未实现.
      const stamp = Date.now();
      const alice = uniqueUser("consent-alice");
      const bob = uniqueUser("consent-bob");
      await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
      const [aliceToken, bobToken] = await Promise.all([
        issueDevSession(request, alice),
        issueDevSession(request, bob),
      ]);
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
      const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });

      try {
        await alicePage.gotoHome();
        await bobPage.gotoHome();

        const pendingStatus = await requestContact(bobPage, alice.did, "invite");
        await expect(pendingStatus).toContainText(/pending/i, { timeout: 30_000 });
        await expectConsentCell(request, aliceToken, alice.did, bob.did, "invite", "pending");
        await stepShot(bobPage.page, testInfo, "A-bob-pending-consent");

        await gotoConsentSettings(alicePage);
        const pendingRow = alicePage.page.getByTestId("consent-pending-row").filter({
          hasText: bob.did,
        });
        await expect(pendingRow).toBeVisible({ timeout: 30_000 });
        await pendingRow.getByTestId("consent-detail-button").click();
        const detail = alicePage.page.getByTestId("consent-pending-detail");
        await expect(detail).toContainText(bob.did);
        await selectDxcOption(detail.getByTestId("consent-scope-select"), "invite");
        await detail.getByTestId("consent-valid-until-input").fill(
          new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
        );
        await detail.getByTestId("grant-consent-button").click();
        await expect(alicePage.page.getByTestId("write-status")).toContainText(/granted/i, {
          timeout: 30_000,
        });
        await expectConsentCell(request, aliceToken, alice.did, bob.did, "invite", "granted");
        await stepShot(alicePage.page, testInfo, "B-alice-granted-consent");

        await bobPage.page.reload({ waitUntil: "domcontentloaded" });
        await expect(bobPage.page.getByTestId("contact-request-status")).toContainText(
          /accepted|granted/i,
          { timeout: 30_000 },
        );

        const retryStatus = await requestContact(bobPage, alice.did, "invite");
        await expect(retryStatus).toContainText(/accepted|already connected/i, {
          timeout: 30_000,
        });
        await alicePage.page.goto("/contacts", { waitUntil: "domcontentloaded" });
        await expect(alicePage.page.getByTestId("contact-row").filter({ hasText: bob.did })).toBeVisible({
          timeout: 30_000,
        });
        await stepShot(alicePage.page, testInfo, "C-contact-established");
      } finally {
        await Promise.allSettled([bobPage.close(), alicePage.close()]);
      }
    },
  );

  test(
    "E1.1 time-windowed consent expires after valid_until elapses",
    async ({ browser, request }, testInfo) => {
      // spec: identity/consent-model.md §2 time window.
      const alice = uniqueUser("consent-window-alice");
      const bob = uniqueUser("consent-window-bob");
      await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
      const [aliceToken, bobToken] = await Promise.all([
        issueDevSession(request, alice),
        issueDevSession(request, bob),
      ]);
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
      const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });

      try {
        await requestContact(bobPage, alice.did, "invite");
        await gotoConsentSettings(alicePage);
        const pendingRow = alicePage.page.getByTestId("consent-pending-row").filter({
          hasText: bob.did,
        });
        await pendingRow.getByTestId("consent-detail-button").click();
        const detail = alicePage.page.getByTestId("consent-pending-detail");
        await detail.getByTestId("consent-valid-until-input").fill(
          new Date(Date.now() + 5_000).toISOString(),
        );
        await detail.getByTestId("grant-consent-button").click();
        await expect(alicePage.page.getByTestId("write-status")).toContainText(/granted/i);
        await expectConsentCell(request, aliceToken, alice.did, bob.did, "invite", "granted");

        await expect(await requestContact(bobPage, alice.did, "invite")).toContainText(
          /accepted|already connected/i,
          { timeout: 30_000 },
        );
        await bobPage.page.waitForTimeout(6_000);
        const expiredStatus = await requestContact(bobPage, alice.did, "invite");
        await expect(expiredStatus).toContainText(/pending|expired/i, { timeout: 30_000 });
        await expectConsentCell(request, aliceToken, alice.did, bob.did, "invite", "expired");
        await stepShot(bobPage.page, testInfo, "time-window-expired");
      } finally {
        await Promise.allSettled([bobPage.close(), alicePage.close()]);
      }
    },
  );

  test("E1.2 revoke then re-grant lifecycle", async ({ browser, request }, testInfo) => {
    // spec: identity/consent-model.md §3 add-after-remove lifecycle.
    const alice = uniqueUser("consent-regrant-alice");
    const bob = uniqueUser("consent-regrant-bob");
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
    const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });

    try {
      await requestContact(bobPage, alice.did, "message");
      await gotoConsentSettings(alicePage);
      let pendingRow = alicePage.page.getByTestId("consent-pending-row").filter({
        hasText: bob.did,
      });
      await pendingRow.getByTestId("consent-detail-button").click();
      await alicePage.page.getByTestId("consent-pending-detail").getByTestId("grant-consent-button").click();
      await expectConsentCell(request, aliceToken, alice.did, bob.did, "message", "granted");

      const grantedRow = alicePage.page.getByTestId("consent-granted-row").filter({
        hasText: bob.did,
      });
      await expect(grantedRow).toBeVisible({ timeout: 30_000 });
      await grantedRow.getByTestId("revoke-consent-button").click();
      await expect(alicePage.page.getByTestId("write-status")).toContainText(/revoked/i, {
        timeout: 30_000,
      });
      await expectConsentCell(request, aliceToken, alice.did, bob.did, "message", "revoked");

      await expect(await requestContact(bobPage, alice.did, "message")).toContainText(/pending/i, {
        timeout: 30_000,
      });
      await alicePage.page.reload({ waitUntil: "domcontentloaded" });
      pendingRow = alicePage.page.getByTestId("consent-pending-row").filter({
        hasText: bob.did,
      });
      await pendingRow.getByTestId("consent-detail-button").click();
      await alicePage.page.getByTestId("consent-pending-detail").getByTestId("grant-consent-button").click();
      await expectConsentCell(request, aliceToken, alice.did, bob.did, "message", "granted");
      await expect(await requestContact(bobPage, alice.did, "message")).toContainText(
        /accepted|already connected/i,
        { timeout: 30_000 },
      );
      await stepShot(alicePage.page, testInfo, "revoke-then-regrant");
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });

  test(
    "E1.3 scope-granularity: invite-scope consent does not allow call",
    async ({ browser, request }, testInfo) => {
      // spec: identity/consent-model.md §2 scope granularity.
      const alice = uniqueUser("consent-scope-alice");
      const bob = uniqueUser("consent-scope-bob");
      await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
      const [aliceToken, bobToken] = await Promise.all([
        issueDevSession(request, alice),
        issueDevSession(request, bob),
      ]);
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
      const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });

      try {
        await requestContact(bobPage, alice.did, "invite");
        await gotoConsentSettings(alicePage);
        const inviteRow = alicePage.page.getByTestId("consent-pending-row").filter({
          hasText: bob.did,
        });
        await inviteRow.getByTestId("consent-detail-button").click();
        const detail = alicePage.page.getByTestId("consent-pending-detail");
        await selectDxcOption(detail.getByTestId("consent-scope-select"), "invite");
        await detail.getByTestId("grant-consent-button").click();
        await expectConsentCell(request, aliceToken, alice.did, bob.did, "invite", "granted");

        await expect(await requestContact(bobPage, alice.did, "invite")).toContainText(
          /accepted|already connected/i,
          { timeout: 30_000 },
        );
        await expect(await requestContact(bobPage, alice.did, "call")).toContainText(/pending/i, {
          timeout: 30_000,
        });
        await expectConsentCell(request, aliceToken, alice.did, bob.did, "call", "pending");
        await stepShot(bobPage.page, testInfo, "scope-granularity-call-pending");
      } finally {
        await Promise.allSettled([bobPage.close(), alicePage.close()]);
      }
    },
  );

  test(
    "E1.4 pairwise DID consent isolates contact channels",
    async ({ browser, request }, testInfo) => {
      // spec: identity/consent-model.md §4 pairwise DID isolation.
      const alice = uniqueUser("consent-pairwise-alice");
      const bob = uniqueUser("consent-pairwise-bob");
      const bobPairwise = {
        ...bob,
        did: `did:peer:${Date.now()}bob-consent-pairwise`,
        handle: `${bob.handle}-pairwise`,
      };
      await Promise.all([
        ensureRegistered(request, alice),
        ensureRegistered(request, bob),
        ensureRegistered(request, bobPairwise),
      ]);
      const [aliceToken, pairwiseToken, rootToken] = await Promise.all([
        issueDevSession(request, alice),
        issueDevSession(request, bobPairwise),
        issueDevSession(request, bob),
      ]);
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
      const pairwisePage = await openUserPage(browser, bobPairwise, { sessionToken: pairwiseToken });
      const rootPage = await openUserPage(browser, bob, { sessionToken: rootToken });

      try {
        await requestContact(pairwisePage, alice.did, "message");
        await gotoConsentSettings(alicePage);
        const pairwiseRow = alicePage.page.getByTestId("consent-pending-row").filter({
          hasText: bobPairwise.did,
        });
        await pairwiseRow.getByTestId("consent-detail-button").click();
        await alicePage.page.getByTestId("consent-pending-detail").getByTestId("grant-consent-button").click();
        await expectConsentCell(
          request,
          aliceToken,
          alice.did,
          bobPairwise.did,
          "message",
          "granted",
        );

        await expect(await requestContact(pairwisePage, alice.did, "message")).toContainText(
          /accepted|already connected/i,
          { timeout: 30_000 },
        );
        await expect(await requestContact(rootPage, alice.did, "message")).toContainText(
          /pending|needs consent/i,
          { timeout: 30_000 },
        );
        await expectConsentCell(request, aliceToken, alice.did, bob.did, "message", "pending");
        await stepShot(alicePage.page, testInfo, "pairwise-isolated");
      } finally {
        await Promise.allSettled([
          rootPage.close(),
          pairwisePage.close(),
          alicePage.close(),
        ]);
      }
    },
  );
});
