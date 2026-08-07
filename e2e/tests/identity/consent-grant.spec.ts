// Consent grant strand
// Contract: e2e/scenarios/identity/consent-grant.md
// Spec: identity/consent-model.md §2-§4

import { expect, test, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  authHeaders,
  canonicalTimestamp,
  createRealmApi,
  expectJsonOk,
  signedEventEnvelope,
  sdkMimiConsentProof,
  submitSignedEventApi,
  typedId,
} from "../../helpers/soland-api";
import {
  assertJointStackNotRequired,
  ensureRegistered,
  issueDevSession,
  openDpopUserPage,
  openUserPage,
  selfPathHeadersForDpopSession,
  uniqueUser,
} from "../../helpers/users";
import { selectDxcOption } from "../../helpers/dxc-select";

test.describe.configure({ mode: "serial" });

type ConsentCellBody = {
  holder_did: string;
  peer_did: string;
  consent_scope: string;
  state: "active" | "revoked" | "expired" | "pending";
} & Record<string, unknown>;

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
  const status = actor.page.getByTestId("contact-request-status");
  const pendingRow = actor.page.locator(
    `[data-testid="contact-row"][data-peer="${targetDid}"]`,
  );
  await expect
    .poll(
      async () => {
        const statusText = await status.textContent().catch(() => null);
        if (statusText && /Request sent|请求已发送/.test(statusText)) {
          return "submitted";
        }
        const state = await pendingRow.getAttribute("data-state").catch(() => null);
        return state === "pending_outgoing" || state === "accepted"
          ? "submitted"
          : state ?? statusText;
      },
      {
        timeout: 60_000,
        message:
          "contact request should either report success or appear in the refreshed contact projection",
      },
    )
    .toBe("submitted");
}

async function expectContactState(
  actor: Awaited<ReturnType<typeof openUserPage>>,
  targetDid: string,
  states: string[],
) {
  const row = actor.page.locator(
    `[data-testid="contact-row"][data-peer="${targetDid}"]`,
  );
  await expect(row).toBeVisible({ timeout: 30_000 });
  await expect(row).toHaveAttribute(
    "data-state",
    new RegExp(`^(?:${states.join("|")})$`),
    { timeout: 30_000 },
  );
  return row;
}

async function gotoConsentSettings(
  actor: Awaited<ReturnType<typeof openUserPage>>,
) {
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
  expectedState: "active" | "revoked" | "expired" | "pending",
) {
  const cell = await request.get(
    `${solandBaseUrl()}/_arkret/self/consent/cells/${encodeURIComponent(holderDid)}` +
      `?peer=${encodeURIComponent(peerDid)}&scope=${encodeURIComponent(scope)}`,
    { headers: { authorization: `Bearer ${token}` } },
  );
  expect(cell.status()).toBe(200);
  const body = (await cell.json()) as Partial<ConsentCellBody>;
  expect(body.holder_did).toBe(holderDid);
  expect(body.peer_did).toBe(peerDid);
  expect(body.consent_scope).toBe(consentWireScope(scope));
  expect(body.state).toBe(expectedState);
  return body as ConsentCellBody;
}

function consentWireScope(scope: string): string {
  return scope === "message"
    ? "direct_message"
    : scope === "call"
      ? "voice_call"
      : scope;
}

async function requestContactApi(
  request: APIRequestContext,
  token: string,
  targetDid: string,
  scope: "invite" | "message" | "call",
) {
  const wireScope =
    scope === "message"
      ? "direct_message"
      : scope === "call"
        ? "voice_call"
        : scope;
  const response = await request.post(
    `${solandBaseUrl()}/_arkret/self/contacts/request`,
    {
      headers: authHeaders(token),
      data: { target: targetDid, requested_scopes: [wireScope] },
    },
  );
  return await expectJsonOk<Record<string, unknown>>(
    response,
    `request contact ${scope}`,
  );
}

test.describe("consent grant", () => {
  test("consent settings surface exposes the local grant form controls", async ({
    browser,
    request,
  }, testInfo) => {
    // Live G2.T5 UI smoke: the settings page exists and its direct grant form
    // is mounted; the live grant/revoke strand is covered below.
    const bob = uniqueUser("g2t5-consent-ui-bob");
    await ensureRegistered(request, bob);
    const aliceFlow = await openDpopUserPage(
      browser,
      request,
      "g2t5-consent-ui-alice",
      { prepareMlsDevice: false },
    );
    if (!aliceFlow) {
      assertJointStackNotRequired("consent settings browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alicePage = aliceFlow.page;

    try {
      await gotoConsentSettings(alicePage);
      await expect(
        alicePage.page.getByTestId("consent-grant-empty"),
      ).toBeVisible({
        timeout: 30_000,
      });

      await alicePage.clickWithPassivePromptRetry(
        alicePage.page.getByTestId("consent-new-grant-button"),
      );
      await selectDxcOption(
        alicePage.page.getByTestId("consent-new-grant-scope-input"),
        "message",
      );
      await alicePage.page
        .getByTestId("consent-new-grant-grantee-input")
        .fill(bob.did);
      await alicePage.page
        .getByTestId("consent-new-grant-ttl-input")
        .fill("30d");
      await expect(
        alicePage.page.getByTestId("consent-new-grant-submit-button"),
      ).toBeEnabled();
      await stepShot(
        alicePage.page,
        testInfo,
        "A-consent-local-grant-form-ready",
      );

      await alicePage.clickWithPassivePromptRetry(
        alicePage.page.getByTestId("consent-new-grant-button"),
      );
      await expect(
        alicePage.page.getByTestId("consent-new-grant-scope-input"),
      ).toHaveCount(0);
      await expect(
        alicePage.page.getByTestId("consent-grant-empty"),
      ).toBeVisible();
    } finally {
      await alicePage.close();
    }
  });

  test("consent settings can open an outbound consent request", async ({
    browser,
    request,
  }, testInfo) => {
    // alice asks bob (the holder) to grant her `message` consent via the
    // `ak.consent.request` entry point; the resulting pending cell surfaces as
    // an outgoing-request row on alice's settings page.
    const bob = uniqueUser("consent-request-bob");
    await ensureRegistered(request, bob);
    const aliceFlow = await openDpopUserPage(
      browser,
      request,
      "consent-request-alice",
      { prepareMlsDevice: false },
    );
    if (!aliceFlow) {
      assertJointStackNotRequired("consent request browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alice = aliceFlow.user;
    const aliceToken = await issueDevSession(request, alice);
    const alicePage = aliceFlow.page;

    try {
      await gotoConsentSettings(alicePage);

      await alicePage.page.getByTestId("consent-request-button").click();
      await selectDxcOption(
        alicePage.page.getByTestId("consent-request-scope-input"),
        "message",
      );
      await alicePage.page
        .getByTestId("consent-request-holder-input")
        .fill(bob.did);
      await expect(
        alicePage.page.getByTestId("consent-request-submit-button"),
      ).toBeEnabled();
      await alicePage.page.getByTestId("consent-request-submit-button").click();

      await expect(alicePage.page.getByTestId("write-status")).toContainText(
        /requested/i,
        {
          timeout: 30_000,
        },
      );
      // Consent cells are holder-private. Alice can observe her own outgoing
      // request projection, but MUST NOT read Bob's underlying consent cell.
      const holderCellUrl =
        `${solandBaseUrl()}/_arkret/self/consent/cells/${encodeURIComponent(bob.did)}` +
        `?peer=${encodeURIComponent(alice.did)}&scope=message`;
      const peerRead = await request.get(holderCellUrl, {
        headers: authHeaders(aliceToken),
      });
      expect(peerRead.status()).toBe(403);
      await expect(
        alicePage.page
          .getByTestId("consent-outgoing-request-row")
          .filter({ hasText: bob.did }),
      ).toBeVisible({ timeout: 30_000 });
      await stepShot(alicePage.page, testInfo, "consent-outbound-request");
    } finally {
      await alicePage.close();
    }
  });

  test("contacts modal submits scoped consent request", async ({
    browser,
    request,
  }) => {
    const [aliceFlow, bobFlow] = await Promise.all([
      openDpopUserPage(browser, request, "p1-022-contact-new-alice", {
        prepareMlsDevice: false,
      }),
      openDpopUserPage(browser, request, "p1-022-contact-new-bob", {
        prepareMlsDevice: false,
      }),
    ]);
    if (!aliceFlow || !bobFlow) {
      assertJointStackNotRequired("contacts consent DPoP login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alice = aliceFlow.user;
    const bob = bobFlow.user;
    const bobPage = bobFlow.page;

    try {
      await requestContact(bobPage, alice.did, "message");
      const escapedDid = alice.did.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
      const pendingRow = bobPage.page
        .getByTestId("contact-row")
        .filter({ has: bobPage.page.locator(`[title="${escapedDid}"]`) });
      await expect(pendingRow).toBeVisible({ timeout: 30_000 });
      await expect(pendingRow).toHaveAttribute("data-state", /pending/);
      const cellUrl =
        `${solandBaseUrl()}/_arkret/self/consent/cells/${encodeURIComponent(alice.did)}` +
        `?peer=${encodeURIComponent(bob.did)}&scope=message`;
      const cell = await request.get(cellUrl, {
        headers: selfPathHeadersForDpopSession(
          aliceFlow.session,
          "GET",
          cellUrl,
        ),
      });
      expect(cell.status()).toBe(200);
      expect(await cell.json()).toMatchObject({
        holder_did: alice.did,
        peer_did: bob.did,
        consent_scope: "direct_message",
        state: "pending",
      });
    } finally {
      await Promise.allSettled([bobPage.close(), aliceFlow.page.close()]);
    }
  });

  test("consent API smoke: MIMI request/update returns holder-private receipts", async ({
    request,
  }) => {
    // Live G2.T5 API smoke: soland has a consent-adjacent MIMI surface today.
    // The general ak.consent.* cell reducer is still not implemented, so the
    // full identity consent lifecycle remains fixme below.
    const alice = uniqueUser("g2t5-consent-api-alice");
    const bob = uniqueUser("g2t5-consent-api-bob");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);
    const describe = await expectJsonOk<{
      service_id: string;
      trust_domain: string;
    }>(
      await request.get(`${solandBaseUrl()}/_arkret/describe`),
      "MIMI consent destination describe",
    );

    const open = await request.post(
      `${solandBaseUrl()}/_arkret/open/mimi/consent/request`,
      {
        headers: authHeaders(bobToken),
        data: {
          requester_id: bob.did,
          target: { kind: "did", id: alice.did },
          purpose: "direct_message",
        },
      },
    );
    expect(open.status()).toBe(200);
    const openBody = await open.json();
    expect(openBody.status).toBe("requested");
    expect(openBody.consent_id).toMatch(/^ak:consent:/);

    const updateUrl = `${solandBaseUrl()}/_arkret/open/mimi/consent/update`;
    const unsignedUpdate = {
      consent_id: openBody.consent_id,
      decision: "accept",
      actor_id: alice.did,
    };
    const signature = sdkMimiConsentProof({
      request: unsignedUpdate,
      verificationMethod: `${alice.did}#mimi-consent`,
      createdAt: canonicalTimestamp(),
      domain: describe.trust_domain,
      audience: describe.service_id,
    });

    const eventProofShape: Record<string, unknown> = {
      ...signature,
      event_digest: signature.payload_digest,
    };
    delete eventProofShape.payload_digest;
    const wrongFamily = await request.post(updateUrl, {
      headers: authHeaders(aliceToken),
      data: { ...unsignedUpdate, signature: eventProofShape },
    });
    expect(wrongFamily.status()).toBe(422);

    const tampered = await request.post(updateUrl, {
      headers: authHeaders(aliceToken),
      data: {
        ...unsignedUpdate,
        decision: "revoke",
        signature,
      },
    });
    expect(tampered.status()).toBe(400);
    const tamperedBody = await tampered.json();
    expect(tamperedBody.error?.code ?? tamperedBody.code).toBe("invalid_proof");

    const signedUpdate = { ...unsignedUpdate, signature };
    const update = await request.post(updateUrl, {
      headers: authHeaders(aliceToken),
      data: signedUpdate,
    });
    expect(update.status()).toBe(200);
    const updateBody = await update.json();
    expect(updateBody.status).toBe("accepted");
    expect(typeof updateBody.updated_at).toBe("string");
    expect(updateBody.event_ref).toMatch(/^ak:event:/);

    const replay = await request.post(updateUrl, {
      headers: authHeaders(aliceToken),
      data: signedUpdate,
    });
    expect(replay.status()).toBe(409);
    const replayBody = await replay.json();
    expect(replayBody.error?.code ?? replayBody.code).toBe(
      "duplicate_conflict",
    );
  });

  test("ak.consent.grant event projects consent cell and contact gate", async ({
    request,
  }) => {
    const alice = uniqueUser("p1-020-consent-event-alice");
    const bob = uniqueUser("p1-020-consent-event-bob");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `P1-020 consent reducer ${Date.now()}`,
      ownerDid: alice.did,
    });

    const pending = await requestContactApi(
      request,
      bobToken,
      alice.did,
      "message",
    );
    expect(pending.state).toBe("pending_outgoing");

    const consentId = typedId("operation").replace(
      "ak:operation:",
      "ak:consent:",
    );
    const grantEnvelope = signedEventEnvelope({
      actorDid: alice.did,
      realmId,
      kind: "ak.consent.grant",
      payload: {
        consent_id: consentId,
        peer: bob.did,
        consent_scope: "direct_message",
        expires_at: canonicalTimestamp(
          new Date(Date.now() + 24 * 60 * 60 * 1000),
        ),
      },
    });
    await submitSignedEventApi(request, aliceToken, grantEnvelope, {
      context: "submit ak.consent.grant",
    });
    const grantDot = `${String(grantEnvelope.event_id)}:${Number(grantEnvelope.actor_seq)}`;

    const granted = await expectConsentCell(
      request,
      aliceToken,
      alice.did,
      bob.did,
      "direct_message",
      "active",
    );
    expect(granted.cell_id).toBe(
      `ak:cell:ak.component.consent.grant.v1:${consentId}`,
    );
    expect(granted.grant_dots).toContain(grantDot);
    const stillPending = await requestContactApi(
      request,
      bobToken,
      alice.did,
      "message",
    );
    expect(stillPending.state).toBe("pending_outgoing");

    const revokeEnvelope = signedEventEnvelope({
      actorDid: alice.did,
      realmId,
      kind: "ak.consent.revoke",
      payload: {
        consent_id: consentId,
        observed_dots: [grantDot],
        revoked_at: canonicalTimestamp(new Date(Date.now() + 1000)),
      },
    });
    await submitSignedEventApi(request, aliceToken, revokeEnvelope, {
      context: "submit ak.consent.revoke",
    });

    const revoked = await expectConsentCell(
      request,
      aliceToken,
      alice.did,
      bob.did,
      "direct_message",
      "revoked",
    );
    expect(revoked.revoked_dots).toContain(grantDot);
    const stillPendingAfterRevoke = await requestContactApi(
      request,
      bobToken,
      alice.did,
      "message",
    );
    expect(stillPendingAfterRevoke.state).toBe("pending_outgoing");
  });

  test("consent settings grants and revokes a pending request", async ({
    browser,
    request,
  }) => {
    const aliceFlow = await openDpopUserPage(
      browser,
      request,
      "p1-023-settings-consent-alice",
      { prepareMlsDevice: false },
    );
    if (!aliceFlow) {
      assertJointStackNotRequired("consent settings DPoP login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alice = aliceFlow.user;
    const bob = uniqueUser("p1-023-settings-consent-bob");
    await ensureRegistered(request, bob);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);
    await requestContactApi(request, bobToken, alice.did, "message");
    const alicePage = aliceFlow.page;

    try {
      await gotoConsentSettings(alicePage);
      const pendingRow = alicePage.page
        .getByTestId("consent-pending-row")
        .filter({
          hasText: bob.did,
        });
      await expect(pendingRow).toBeVisible({ timeout: 30_000 });
      await pendingRow.getByTestId("consent-detail-button").click();
      const detail = alicePage.page.getByTestId("consent-pending-detail");
      await expect(detail).toContainText(bob.did);
      await selectDxcOption(
        detail.getByTestId("consent-scope-select"),
        "message",
      );
      await detail
        .getByTestId("consent-valid-until-input")
        .fill(new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString());
      await detail.getByTestId("grant-consent-button").click();
      await expect(alicePage.page.getByTestId("write-status")).toContainText(
        /granted/i,
        {
          timeout: 30_000,
        },
      );
      await expect(
        alicePage.page
          .getByTestId("consent-granted-row")
          .filter({ hasText: bob.did }),
      ).toBeVisible({ timeout: 30_000 });
      // Effective consent state is spec `active` (consent-model.md §2.2 /
      // SDK `ConsentState::Active`); the legacy `granted` term was renamed.
      await expectConsentCell(
        request,
        aliceToken,
        alice.did,
        bob.did,
        "message",
        "active",
      );

      await alicePage.page
        .getByTestId("consent-granted-row")
        .filter({ hasText: bob.did })
        .getByTestId("revoke-consent-button")
        .click();
      await expect(alicePage.page.getByTestId("write-status")).toContainText(
        /revoked/i,
        {
          timeout: 30_000,
        },
      );
      await expectConsentCell(
        request,
        aliceToken,
        alice.did,
        bob.did,
        "message",
        "revoked",
      );
    } finally {
      await alicePage.close();
    }
  });

  test("alice grants consent and bob can establish contact (full lifecycle)", async ({
    browser,
    request,
  }, testInfo) => {
    // spec: identity/consent-model.md §2-§4.
    const [aliceFlow, bobFlow] = await Promise.all([
      openDpopUserPage(browser, request, "consent-alice", {
        prepareMlsDevice: false,
      }),
      openDpopUserPage(browser, request, "consent-bob", {
        prepareMlsDevice: false,
      }),
    ]);
    if (!aliceFlow || !bobFlow) {
      await Promise.allSettled([
        aliceFlow?.page.close(),
        bobFlow?.page.close(),
      ]);
      assertJointStackNotRequired("consent lifecycle DPoP login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alice = aliceFlow.user;
    const bob = bobFlow.user;
    const aliceToken = await issueDevSession(request, alice);
    const alicePage = aliceFlow.page;
    const bobPage = bobFlow.page;

    try {
      await alicePage.gotoHome();
      await bobPage.gotoHome();

      await requestContact(bobPage, alice.did, "invite");
      await expectContactState(bobPage, alice.did, [
        "pending",
        "pending_outgoing",
      ]);
      await expectConsentCell(
        request,
        aliceToken,
        alice.did,
        bob.did,
        "invite",
        "pending",
      );
      await stepShot(bobPage.page, testInfo, "A-bob-pending-consent");

      await gotoConsentSettings(alicePage);
      const pendingRow = alicePage.page
        .getByTestId("consent-pending-row")
        .filter({
          hasText: bob.did,
        });
      await expect(pendingRow).toBeVisible({ timeout: 30_000 });
      await pendingRow.getByTestId("consent-detail-button").click();
      const detail = alicePage.page.getByTestId("consent-pending-detail");
      await expect(detail).toContainText(bob.did);
      await selectDxcOption(
        detail.getByTestId("consent-scope-select"),
        "invite",
      );
      await detail
        .getByTestId("consent-valid-until-input")
        .fill(new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString());
      await detail.getByTestId("grant-consent-button").click();
      await expect(alicePage.page.getByTestId("write-status")).toContainText(
        /granted/i,
        {
          timeout: 30_000,
        },
      );
      // Spec `active` (consent-model.md §2.2 / SDK `ConsentState::Active`).
      await expectConsentCell(
        request,
        aliceToken,
        alice.did,
        bob.did,
        "invite",
        "active",
      );
      await stepShot(alicePage.page, testInfo, "B-alice-granted-consent");

      await bobPage.page.reload({ waitUntil: "domcontentloaded" });
      await expectContactState(bobPage, alice.did, [
        "pending",
        "pending_outgoing",
      ]);

      await alicePage.page.goto("/contacts", { waitUntil: "domcontentloaded" });
      await expectContactState(alicePage, bob.did, [
        "pending",
        "pending_incoming",
      ]);
      await alicePage.page.getByTestId(`contact-accept-${bob.did}`).click();
      await expectContactState(alicePage, bob.did, ["accepted"]);

      await expect
        .poll(
          async () => {
            await bobPage.page.reload({ waitUntil: "domcontentloaded" });
            const row = bobPage.page.locator(
              `[data-testid="contact-row"][data-peer="${alice.did}"]`,
            );
            return await row.getAttribute("data-state");
          },
          { timeout: 30_000 },
        )
        .toBe("accepted");
      await stepShot(alicePage.page, testInfo, "C-contact-established");
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });

  test("E1.1 time-windowed consent expires after valid_until elapses", async ({
    browser,
    request,
  }, testInfo) => {
    test.setTimeout(300_000);
    // spec: identity/consent-model.md §2 time window.
    const [aliceFlow, bobFlow] = await Promise.all([
      openDpopUserPage(browser, request, "consent-window-alice", {
        prepareMlsDevice: false,
      }),
      openDpopUserPage(browser, request, "consent-window-bob", {
        prepareMlsDevice: false,
      }),
    ]);
    if (!aliceFlow || !bobFlow) {
      await Promise.allSettled([
        aliceFlow?.page.close(),
        bobFlow?.page.close(),
      ]);
      assertJointStackNotRequired("time-window consent DPoP login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alice = aliceFlow.user;
    const bob = bobFlow.user;
    const aliceToken = await issueDevSession(request, alice);
    const alicePage = aliceFlow.page;
    const bobPage = bobFlow.page;

    try {
      await requestContact(bobPage, alice.did, "invite");
      await gotoConsentSettings(alicePage);
      const pendingRow = alicePage.page
        .getByTestId("consent-pending-row")
        .filter({
          hasText: bob.did,
        });
      await expect(pendingRow).toBeVisible({ timeout: 30_000 });
      await pendingRow.getByTestId("consent-detail-button").click();
      const detail = alicePage.page.getByTestId("consent-pending-detail");
      await detail
        .getByTestId("consent-valid-until-input")
        .fill(new Date(Date.now() + 5_000).toISOString());
      await detail.getByTestId("grant-consent-button").click();
      await expect(alicePage.page.getByTestId("write-status")).toContainText(
        /granted/i,
      );
      await expectConsentCell(
        request,
        aliceToken,
        alice.did,
        bob.did,
        "invite",
        "active",
      );

      // Consent is an independent authorization cell; it does not accept the
      // pending contact request on Alice's behalf.
      await expectContactState(bobPage, alice.did, [
        "pending",
        "pending_outgoing",
      ]);
      // The consent window above was set to Date.now()+5_000. Instead of
      // sleeping for a fixed margin, poll the authoritative consent cell until
      // the window lapses and the cell falls back to spec `pending` (implicit
      // revoke, consent-model.md §3.2 — there is no distinct `expired` wire
      // state). `expect.poll` bounds the wait and re-queries observable truth.
      await expect
        .poll(
          async () => {
            const cell = await request.get(
              `${solandBaseUrl()}/_arkret/self/consent/cells/${encodeURIComponent(alice.did)}` +
                `?peer=${encodeURIComponent(bob.did)}&scope=invite`,
              { headers: { authorization: `Bearer ${aliceToken}` } },
            );
            if (cell.status() !== 200) {
              return cell.status();
            }
            return JSON.stringify(await cell.json());
          },
          { timeout: 30_000, intervals: [250, 500, 1_000] },
        )
        .toContain("pending");
      await expectContactState(bobPage, alice.did, [
        "pending",
        "pending_outgoing",
      ]);
      await expectConsentCell(
        request,
        aliceToken,
        alice.did,
        bob.did,
        "invite",
        "pending",
      );
      await stepShot(bobPage.page, testInfo, "time-window-expired");
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });

  test("E1.2 revoke then re-grant lifecycle", async ({
    browser,
    request,
  }, testInfo) => {
    // spec: identity/consent-model.md §3 add-after-remove lifecycle.
    const [aliceFlow, bobFlow] = await Promise.all([
      openDpopUserPage(browser, request, "consent-regrant-alice", {
        prepareMlsDevice: false,
      }),
      openDpopUserPage(browser, request, "consent-regrant-bob", {
        prepareMlsDevice: false,
      }),
    ]);
    if (!aliceFlow || !bobFlow) {
      await Promise.allSettled([
        aliceFlow?.page.close(),
        bobFlow?.page.close(),
      ]);
      assertJointStackNotRequired("re-grant consent DPoP login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alice = aliceFlow.user;
    const bob = bobFlow.user;
    const aliceToken = await issueDevSession(request, alice);
    const alicePage = aliceFlow.page;
    const bobPage = bobFlow.page;

    try {
      await requestContact(bobPage, alice.did, "message");
      await gotoConsentSettings(alicePage);
      let pendingRow = alicePage.page
        .getByTestId("consent-pending-row")
        .filter({
          hasText: bob.did,
        });
      await pendingRow.getByTestId("consent-detail-button").click();
      await alicePage.page
        .getByTestId("consent-pending-detail")
        .getByTestId("grant-consent-button")
        .click();
      await expect(alicePage.page.getByTestId("write-status")).toContainText(
        /granted/i,
        { timeout: 30_000 },
      );
      await expectConsentCell(
        request,
        aliceToken,
        alice.did,
        bob.did,
        "message",
        "active",
      );

      const grantedRow = alicePage.page
        .getByTestId("consent-granted-row")
        .filter({
          hasText: bob.did,
        });
      await expect(grantedRow).toBeVisible({ timeout: 30_000 });
      await grantedRow.getByTestId("revoke-consent-button").click();
      await expect(alicePage.page.getByTestId("write-status")).toContainText(
        /revoked/i,
        {
          timeout: 30_000,
        },
      );
      await expectConsentCell(
        request,
        aliceToken,
        alice.did,
        bob.did,
        "message",
        "revoked",
      );

      await requestContact(bobPage, alice.did, "message");
      await expectContactState(bobPage, alice.did, [
        "pending",
        "pending_outgoing",
      ]);
      await alicePage.page.reload({ waitUntil: "domcontentloaded" });
      pendingRow = alicePage.page.getByTestId("consent-pending-row").filter({
        hasText: bob.did,
      });
      await pendingRow.getByTestId("consent-detail-button").click();
      await alicePage.page
        .getByTestId("consent-pending-detail")
        .getByTestId("grant-consent-button")
        .click();
      await expect(alicePage.page.getByTestId("write-status")).toContainText(
        /granted/i,
        { timeout: 30_000 },
      );
      await expectConsentCell(
        request,
        aliceToken,
        alice.did,
        bob.did,
        "message",
        "active",
      );
      await expectContactState(bobPage, alice.did, [
        "pending",
        "pending_outgoing",
      ]);
      await stepShot(alicePage.page, testInfo, "revoke-then-regrant");
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });

  test("E1.3 scope-granularity: invite-scope consent does not allow call", async ({
    browser,
    request,
  }, testInfo) => {
    // spec: identity/consent-model.md §2 scope granularity.
    const [aliceFlow, bobFlow] = await Promise.all([
      openDpopUserPage(browser, request, "consent-scope-alice", {
        prepareMlsDevice: false,
      }),
      openDpopUserPage(browser, request, "consent-scope-bob", {
        prepareMlsDevice: false,
      }),
    ]);
    if (!aliceFlow || !bobFlow) {
      await Promise.allSettled([
        aliceFlow?.page.close(),
        bobFlow?.page.close(),
      ]);
      assertJointStackNotRequired("scope consent DPoP login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alice = aliceFlow.user;
    const bob = bobFlow.user;
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);
    const alicePage = aliceFlow.page;
    const bobPage = bobFlow.page;

    try {
      await requestContact(bobPage, alice.did, "invite");
      await gotoConsentSettings(alicePage);
      const inviteRow = alicePage.page
        .getByTestId("consent-pending-row")
        .filter({
          hasText: bob.did,
        });
      await inviteRow.getByTestId("consent-detail-button").click();
      const detail = alicePage.page.getByTestId("consent-pending-detail");
      await selectDxcOption(
        detail.getByTestId("consent-scope-select"),
        "invite",
      );
      await detail.getByTestId("grant-consent-button").click();
      await expect(alicePage.page.getByTestId("write-status")).toContainText(
        /granted/i,
        { timeout: 30_000 },
      );
      await expectConsentCell(
        request,
        aliceToken,
        alice.did,
        bob.did,
        "invite",
        "active",
      );

      await expectContactState(bobPage, alice.did, [
        "pending",
        "pending_outgoing",
      ]);
      // The contacts UI currently exposes invite/direct-message scopes only.
      // Exercise the independent voice-call consent cell through the same
      // signed contact API used by non-UI clients.
      await requestContactApi(request, bobToken, alice.did, "call");
      await bobPage.page.reload({ waitUntil: "domcontentloaded" });
      await expectContactState(bobPage, alice.did, [
        "pending",
        "pending_outgoing",
      ]);
      await expectConsentCell(
        request,
        aliceToken,
        alice.did,
        bob.did,
        "call",
        "pending",
      );
      await stepShot(bobPage.page, testInfo, "scope-granularity-call-pending");
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });

  test("E1.4 pairwise DID consent isolates contact channels", async ({
    browser,
    request,
  }, testInfo) => {
    // spec: identity/consent-model.md §3.2 and §8.1 pairwise DID isolation.
    const aliceFlow = await openDpopUserPage(
      browser,
      request,
      "consent-pairwise-alice",
      { prepareMlsDevice: false },
    );
    if (!aliceFlow) {
      assertJointStackNotRequired("pairwise consent DPoP login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alice = aliceFlow.user;
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
    const alicePage = aliceFlow.page;

    try {
      const pairwisePending = await requestContactApi(
        request,
        pairwiseToken,
        alice.did,
        "message",
      );
      expect(pairwisePending.state).toBe("pending_outgoing");
      await gotoConsentSettings(alicePage);
      const pairwiseRow = alicePage.page
        .getByTestId("consent-pending-row")
        .filter({
          hasText: bobPairwise.did,
        });
      await pairwiseRow.getByTestId("consent-detail-button").click();
      await alicePage.page
        .getByTestId("consent-pending-detail")
        .getByTestId("grant-consent-button")
        .click();
      await expect(alicePage.page.getByTestId("write-status")).toContainText(
        /granted/i,
        { timeout: 30_000 },
      );
      await expectConsentCell(
        request,
        aliceToken,
        alice.did,
        bobPairwise.did,
        "message",
        "active",
      );

      const pairwiseStillPending = await requestContactApi(
        request,
        pairwiseToken,
        alice.did,
        "message",
      );
      expect(pairwiseStillPending.state).toBe("pending_outgoing");
      const rootPending = await requestContactApi(
        request,
        rootToken,
        alice.did,
        "message",
      );
      expect(rootPending.state).toBe("pending_outgoing");
      await expectConsentCell(
        request,
        aliceToken,
        alice.did,
        bob.did,
        "message",
        "pending",
      );
      await stepShot(alicePage.page, testInfo, "pairwise-isolated");
    } finally {
      await alicePage.close();
    }
  });
});
