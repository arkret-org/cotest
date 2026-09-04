// Consent grant strand
// Contract: e2e/scenarios/identity/consent-grant.md
// Spec: identity/consent-model.md §2-§4

import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import { solandBaseUrl, solandServiceId } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  accountActorId,
  authHeaders,
  canonicalJson,
  canonicalTimestamp,
  createRealmApi,
  expectJsonOk,
  prepareSignedEventSubmissionApi,
  principalControlRealmForId,
  registeredEventSigningSeedB64url,
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
import {
  contactRow,
  requestContactArkret,
} from "../../helpers/contact-api";

test.describe.configure({ mode: "serial" });

type ConsentCellBody = {
  peer: {
    kind: "actor";
    actor_id: {
      kind: "account";
      account_id: { principal_id: string; station_id: string };
    };
  };
  consent_scope: string;
  state: "active" | "no_consent";
} & Record<string, unknown>;

async function requestContact(
  actor: Awaited<ReturnType<typeof openUserPage>>,
  targetId: string,
  scope: "invite" | "message" | "call",
) {
  // "Add contact" is a popup modal opened from the contacts list, not a
  // standalone /contacts/new page.
  await actor.gotoAppPanel("/contacts", "contacts-panel");
  await actor.clickWithPassivePromptRetry(
    actor.page.getByTestId("add-contact-button"),
  );
  await expect(actor.page.getByTestId("contact-request-panel")).toBeVisible({
    timeout: 120_000,
  });
  await actor.fillWithPassivePromptRetry(
    actor.page.getByTestId("contact-target-input"),
    targetId,
  );
  // Scope is selected via checkboxes (direct_message + invite default to
  // checked). Leave only the requested scope checked.
  const wantInvite = scope === "invite";
  const wantDm = scope === "message";
  const dm = actor.page.getByTestId("contact-scope-direct_message");
  const inv = actor.page.getByTestId("contact-scope-invite");
  if ((await dm.isChecked()) !== wantDm)
    await actor.clickWithPassivePromptRetry(dm);
  if ((await inv.isChecked()) !== wantInvite)
    await actor.clickWithPassivePromptRetry(inv);
  await actor.clickWithPassivePromptRetry(
    actor.page.getByTestId("send-contact-request-button"),
  );
  const status = actor.page.getByTestId("contact-request-status");
  const targetActor = canonicalJson(accountActorId(targetId));
  const escapedTarget = targetActor
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"');
  const pendingRow = actor.page
    .getByTestId("contact-row")
    .filter({ has: actor.page.locator(`[title="${escapedTarget}"]`) });
  await expect
    .poll(
      async () => {
        const statusText = await status.textContent().catch(() => null);
        if (statusText && /Request sent|请求已发送/.test(statusText)) {
          return "submitted";
        }
        const state = await pendingRow
          .getAttribute("data-state")
          .catch(() => null);
        return state === "pending_outgoing" || state === "accepted"
          ? "submitted"
          : (state ?? statusText);
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
  targetId: string,
  states: string[],
) {
  const targetActor = canonicalJson(accountActorId(targetId));
  const escapedTarget = targetActor
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"');
  const row = actor.page
    .getByTestId("contact-row")
    .filter({ has: actor.page.locator(`[title="${escapedTarget}"]`) });
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
  await actor.gotoAppPanel("/settings/consent", "consent-settings-panel");
}

async function grantConsentDirect(
  actor: Awaited<ReturnType<typeof openUserPage>>,
  peerId: string,
  scope: "invite" | "message" | "call",
  ttl = "30d",
) {
  await actor.clickWithPassivePromptRetry(
    actor.page.getByTestId("consent-new-grant-button"),
  );
  await selectDxcOption(
    actor.page.getByTestId("consent-new-grant-scope-input"),
    scope,
  );
  await actor.page
    .getByTestId("consent-new-grant-grantee-input")
    .fill(peerId);
  await actor.page.getByTestId("consent-new-grant-ttl-input").fill(ttl);
  await expect(
    actor.page.getByTestId("consent-new-grant-submit-button"),
  ).toBeEnabled();
  await actor.clickWithPassivePromptRetry(
    actor.page.getByTestId("consent-new-grant-submit-button"),
  );
  await expect(actor.page.getByTestId("write-status")).toContainText(
    /granted/i,
    { timeout: 30_000 },
  );
}

async function expectConsentCell(
  request: APIRequestContext,
  token: string,
  holderId: string,
  peerId: string,
  scope: string,
  expectedState: "active" | "no_consent",
) {
  const peer = {
    kind: "actor",
    actor_id: {
      kind: "account",
      account_id: { principal_id: peerId, station_id: solandServiceId() },
    },
  } as const;
  const wireScope = consentWireScope(scope);
  const cell = await request.get(
    `${solandBaseUrl()}/_arkret/self/consent/cell` +
      `?peer=${encodeURIComponent(JSON.stringify(peer))}&consent_scope=${encodeURIComponent(wireScope)}`,
    { headers: { authorization: `Bearer ${token}` } },
  );
  expect(cell.status()).toBe(200);
  const body = (await cell.json()) as Partial<ConsentCellBody>;
  expect(holderId).not.toBe(peerId);
  expect(body.peer).toEqual(peer);
  expect(body.consent_scope).toBe(wireScope);
  expect(body.state).toBe(expectedState);
  return body as ConsentCellBody;
}

async function expectConsentCellMissing(
  request: APIRequestContext,
  token: string,
  peerId: string,
  scope: string,
) {
  const peer = {
    kind: "actor",
    actor_id: {
      kind: "account",
      account_id: { principal_id: peerId, station_id: solandServiceId() },
    },
  } as const;
  const response = await request.get(
    `${solandBaseUrl()}/_arkret/self/consent/cell` +
      `?peer=${encodeURIComponent(JSON.stringify(peer))}&consent_scope=${encodeURIComponent(consentWireScope(scope))}`,
    { headers: { authorization: `Bearer ${token}` } },
  );
  expect(response.status()).toBe(404);
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
  targetId: string,
  scope: "invite" | "message",
) {
  const { outcome } = await requestContactArkret(request, token, targetId, {
    requestedScopes: [consentWireScope(scope)],
  });
  return outcome;
}

async function requestConsentApi(
  request: APIRequestContext,
  token: string,
  holderId: string,
  scope: "invite" | "message" | "call",
) {
  const response = await request.post(
    `${solandBaseUrl()}/_arkret/self/consent/request`,
    {
      headers: { ...authHeaders(token), "content-type": "application/json" },
      data: canonicalJson({
        consent_scope: consentWireScope(scope),
        holder_account_id: {
          principal_id: holderId,
          station_id: solandServiceId(),
        },
      }),
    },
  );
  const outcome = await expectJsonOk<{ accepted_for_processing: true }>(
    response,
    `request consent ${scope}`,
  );
  expect(outcome).toEqual({ accepted_for_processing: true });
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
        .fill(bob.id);
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
        .fill(bob.id);
      await expect(
        alicePage.page.getByTestId("consent-request-submit-button"),
      ).toBeEnabled();
      await alicePage.page.getByTestId("consent-request-submit-button").click();

      await expect(alicePage.page.getByTestId("write-status")).toContainText(
        /accepted for processing/i,
        {
          timeout: 30_000,
        },
      );
      // Peer submission is deliberately opaque: it only enters the holder's
      // quarantine/anti-abuse path and creates no consent cell, pending state,
      // contact fact, or requester-visible outgoing projection.
      const holderCellUrl =
        `${solandBaseUrl()}/_arkret/self/consent/cell` +
        `?peer=${encodeURIComponent(JSON.stringify({ kind: "actor", actor_id: { kind: "account", account_id: { principal_id: bob.id, station_id: solandServiceId() } } }))}&consent_scope=direct_message`;
      const peerRead = await request.get(holderCellUrl, {
        headers: authHeaders(aliceToken),
      });
      expect(peerRead.status()).toBe(404);
      await expect(
        alicePage.page.getByTestId("consent-outgoing-request-row"),
      ).toHaveCount(0);
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
      await requestContact(bobPage, alice.id, "message");
      const escapedId = canonicalJson(accountActorId(alice.id))
        .replace(/\\/g, "\\\\")
        .replace(/"/g, '\\"');
      const pendingRow = bobPage.page
        .getByTestId("contact-row")
        .filter({ has: bobPage.page.locator(`[title="${escapedId}"]`) });
      await expect(pendingRow).toBeVisible({ timeout: 30_000 });
      await expect(pendingRow).toHaveAttribute("data-state", /pending/);
      const cellUrl =
        `${solandBaseUrl()}/_arkret/self/consent/cell` +
        `?peer=${encodeURIComponent(JSON.stringify({ kind: "actor", actor_id: { kind: "account", account_id: { principal_id: bob.id, station_id: solandServiceId() } } }))}&consent_scope=direct_message`;
      const cell = await request.get(cellUrl, {
        headers: selfPathHeadersForDpopSession(
          aliceFlow.session,
          "GET",
          cellUrl,
        ),
      });
      expect(cell.status()).toBe(404);
    } finally {
      await Promise.allSettled([bobPage.close(), aliceFlow.page.close()]);
    }
  });

  test("MIMI consent update admits exact Events, rejects conflicts, and hides correlations", async ({
    request,
  }) => {
    const alice = uniqueUser("g2t5-consent-api-alice");
    const bob = uniqueUser("g2t5-consent-api-bob");
    const charlie = uniqueUser("g2t5-consent-api-charlie");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
      ensureRegistered(request, charlie),
    ]);
    const [aliceToken, bobToken, charlieToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
      issueDevSession(request, charlie),
    ]);
    const aliceSigningSeed = registeredEventSigningSeedB64url(alice.id);
    const charlieSigningSeed = registeredEventSigningSeedB64url(charlie.id);
    if (!aliceSigningSeed || !charlieSigningSeed) {
      throw new Error("canonical provisioning omitted a MIMI consent device signer");
    }
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
        headers: {
          ...authHeaders(bobToken),
          "content-type": "application/json",
        },
        data: canonicalJson({
          requester_id: bob.id,
          target: { kind: "did", id: alice.id },
          purpose: "direct_message",
        }),
      },
    );
    const openText = await open.text();
    expect(open.status(), openText).toBe(200);
    const openBody = JSON.parse(openText) as Record<string, unknown>;
    expect(openBody.status).toBe("requested");
    expect(openBody.consent_id).toMatch(/^ak:consent:/);

    const updateUrl = `${solandBaseUrl()}/_arkret/open/mimi/consent/update`;
    const grantEvent = signedEventEnvelope({
      actorId: alice.id,
      realmId: principalControlRealmForId(alice.id),
      kind: "ak.consent.grant",
      payload: {
        consent_id: openBody.consent_id,
        peer: { kind: "actor", actor_id: accountActorId(bob.id) },
        consent_scope: "direct_message",
      },
    });
    const consentEvent = await prepareSignedEventSubmissionApi(
      request,
      aliceToken,
      grantEvent,
      { context: "prepare MIMI consent grant" },
    );
    const unsignedUpdate = {
      consent_id: openBody.consent_id,
      decision: "accept",
      actor_id: accountActorId(alice.id),
      consent_event: consentEvent,
    };
    const signature = sdkMimiConsentProof({
      request: unsignedUpdate,
      verificationMethod: `${alice.did}#${alice.deviceId}`,
      createdAt: canonicalTimestamp(),
      domain: describe.trust_domain,
      audience: describe.service_id,
      signingSeedB64url: aliceSigningSeed,
    });

    const signedUpdate = { ...unsignedUpdate, signature };
    const update = await request.post(updateUrl, {
      headers: {
        ...authHeaders(aliceToken),
        "content-type": "application/json",
      },
      data: canonicalJson(signedUpdate),
    });
    const updateText = await update.text();
    expect(update.status(), updateText).toBe(200);
    const updateBody = JSON.parse(updateText);
    expect(updateBody.status).toBe("accepted");
    expect(updateBody.event_ref).toBe(grantEvent.event_id);

    const replay = await request.post(updateUrl, {
      headers: {
        ...authHeaders(aliceToken),
        "content-type": "application/json",
      },
      data: canonicalJson(signedUpdate),
    });
    expect(replay.status()).toBe(200);
    const replayBody = await replay.json();
    expect(replayBody).toEqual(updateBody);

    const conflictingEvent = signedEventEnvelope({
      actorId: alice.id,
      realmId: principalControlRealmForId(alice.id),
      eventId: String(grantEvent.event_id),
      kind: "ak.consent.grant",
      payload: {
        consent_id: openBody.consent_id,
        peer: { kind: "actor", actor_id: accountActorId(bob.id) },
        consent_scope: "direct_message",
      },
    });
    conflictingEvent.seal_basis = structuredClone(grantEvent.seal_basis);
    delete conflictingEvent.seal_ref;
    delete conflictingEvent.auth_context;
    const conflictingUnsigned = {
      ...unsignedUpdate,
      consent_event: { ...consentEvent, event: conflictingEvent },
    };
    const conflictingBody = {
      ...conflictingUnsigned,
      signature: sdkMimiConsentProof({
        request: conflictingUnsigned,
        verificationMethod: `${alice.did}#${alice.deviceId}`,
        createdAt: canonicalTimestamp(),
        domain: describe.trust_domain,
        audience: describe.service_id,
        signingSeedB64url: aliceSigningSeed,
      }),
    };
    const conflicting = await request.post(updateUrl, {
      headers: {
        ...authHeaders(aliceToken),
        "content-type": "application/json",
      },
      data: canonicalJson(conflictingBody),
    });
    expect(conflicting.status()).toBe(422);
    const conflictingOutcome = await conflicting.json();
    expect(conflictingOutcome.type).toBe(
      "https://arkret.org/problems/schema_violation",
    );
    expect(conflictingOutcome.reason_code).toBe("event_id_digest_mismatch");

    const invisibleUnsigned = structuredClone(unsignedUpdate);
    invisibleUnsigned.actor_id = accountActorId(charlie.id);
    const invisibleSubmission = invisibleUnsigned.consent_event as Record<
      string,
      unknown
    >;
    const invisibleEvent = invisibleSubmission.event as Record<string, unknown>;
    invisibleEvent.actor_id = accountActorId(charlie.id);
    const invisibleBody = {
      ...invisibleUnsigned,
      signature: sdkMimiConsentProof({
        request: invisibleUnsigned,
        verificationMethod: `${charlie.did}#${charlie.deviceId}`,
        createdAt: canonicalTimestamp(),
        domain: describe.trust_domain,
        audience: describe.service_id,
        signingSeedB64url: charlieSigningSeed,
      }),
    };
    const invisible = await request.post(updateUrl, {
      headers: {
        ...authHeaders(charlieToken),
        "content-type": "application/json",
      },
      data: canonicalJson(invisibleBody),
    });

    const unknownConsentId = typedId("operation").replace(
      "ak:operation:",
      "ak:consent:",
    );
    const unknownUnsigned = structuredClone(invisibleUnsigned);
    unknownUnsigned.consent_id = unknownConsentId;
    const unknownSubmission = unknownUnsigned.consent_event as Record<
      string,
      unknown
    >;
    const unknownEvent = unknownSubmission.event as Record<string, unknown>;
    const unknownPayload = unknownEvent.payload as Record<string, unknown>;
    unknownPayload.consent_id = unknownConsentId;
    const unknownBody = {
      ...unknownUnsigned,
      signature: sdkMimiConsentProof({
        request: unknownUnsigned,
        verificationMethod: `${charlie.did}#${charlie.deviceId}`,
        createdAt: canonicalTimestamp(),
        domain: describe.trust_domain,
        audience: describe.service_id,
        signingSeedB64url: charlieSigningSeed,
      }),
    };
    const unknown = await request.post(updateUrl, {
      headers: {
        ...authHeaders(charlieToken),
        "content-type": "application/json",
      },
      data: canonicalJson(unknownBody),
    });
    expect(unknown.status()).toBe(invisible.status());
    const invisibleOutcome = await invisible.json();
    const unknownOutcome = await unknown.json();
    delete invisibleOutcome.request_id;
    delete unknownOutcome.request_id;
    delete invisibleOutcome.instance;
    delete unknownOutcome.instance;
    expect(unknownOutcome).toEqual(invisibleOutcome);
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
      ownerId: alice.id,
    });

    const pending = await requestContactApi(
      request,
      bobToken,
      alice.id,
      "message",
    );
    expect(pending.state).toBe("pending_outgoing");

    const consentId = typedId("operation").replace(
      "ak:operation:",
      "ak:consent:",
    );
    const grantEnvelope = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.consent.grant",
      payload: {
        consent_id: consentId,
        peer: { kind: "actor", actor_id: accountActorId(bob.id) },
        consent_scope: "direct_message",
        expires_at: canonicalTimestamp(
          new Date(Date.now() + 24 * 60 * 60 * 1000),
        ),
      },
    });
    await submitSignedEventApi(request, aliceToken, grantEnvelope, {
      context: "submit ak.consent.grant",
    });
    const grantDot = `${String(grantEnvelope.event_id)}:0`;

    const granted = await expectConsentCell(
      request,
      aliceToken,
      alice.id,
      bob.id,
      "direct_message",
      "active",
    );
    expect(granted.cell_id).toBe(
      `ak:cell:ak.component.consent.grant.v1:${consentId}`,
    );
    expect(granted.grant_dots).toContain(grantDot);
    const stillPending = await contactRow(request, bobToken, alice.id);
    expect(stillPending?.state).toBe("pending_outgoing");

    const revokeEnvelope = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.consent.revoke",
      payload: {
        consent_id: consentId,
        observed_dot_ids: [grantDot],
        revoked_at: canonicalTimestamp(new Date(Date.now() + 1000)),
      },
    });
    await submitSignedEventApi(request, aliceToken, revokeEnvelope, {
      context: "submit ak.consent.revoke",
    });

    const revoked = await expectConsentCell(
      request,
      aliceToken,
      alice.id,
      bob.id,
      "direct_message",
      "no_consent",
    );
    expect(revoked.revoked_dots).toContain(grantDot);
    const stillPendingAfterRevoke = await contactRow(
      request,
      bobToken,
      alice.id,
    );
    expect(stillPendingAfterRevoke?.state).toBe("pending_outgoing");
  });

  test("consent settings grants and revokes a pending request", async ({
    browser,
    request,
  }) => {
    test.skip(
      true,
      "spec-open 2026-09-04-1301: the quarantine carrier cannot represent contact/direct_message requests",
    );
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
    await requestContactApi(request, bobToken, alice.id, "message");
    const alicePage = aliceFlow.page;

    try {
      await gotoConsentSettings(alicePage);
      const pendingRow = alicePage.page
        .getByTestId("consent-pending-row")
        .filter({
          hasText: bob.id,
        });
      await expect(pendingRow).toBeVisible({ timeout: 30_000 });
      await pendingRow.getByTestId("consent-detail-button").click();
      const detail = alicePage.page.getByTestId("consent-pending-detail");
      await expect(detail).toContainText(bob.id);
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
          .filter({ hasText: bob.id }),
      ).toBeVisible({ timeout: 30_000 });
      // Effective consent state is spec `active` (consent-model.md §2.2 /
      // SDK `ConsentState::Active`).
      await expectConsentCell(
        request,
        aliceToken,
        alice.id,
        bob.id,
        "message",
        "active",
      );

      await alicePage.page
        .getByTestId("consent-granted-row")
        .filter({ hasText: bob.id })
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
        alice.id,
        bob.id,
        "message",
        "no_consent",
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

      await requestContact(bobPage, alice.id, "invite");
      await expectContactState(bobPage, alice.id, [
        "pending",
        "pending_outgoing",
      ]);
      await expectConsentCellMissing(
        request,
        aliceToken,
        bob.id,
        "invite",
      );
      await stepShot(bobPage.page, testInfo, "A-bob-pending-consent");

      await gotoConsentSettings(alicePage);
      // Contact and consent are independent authority roots. Until
      // spec-open/2026-09-04-1301 closes the quarantine carrier, exercise the
      // fully specified holder-authored grant path instead of inventing a
      // pending entry shape.
      await grantConsentDirect(alicePage, bob.id, "invite");
      // Spec `active` (consent-model.md §2.2 / SDK `ConsentState::Active`).
      await expectConsentCell(
        request,
        aliceToken,
        alice.id,
        bob.id,
        "invite",
        "active",
      );
      await stepShot(alicePage.page, testInfo, "B-alice-granted-consent");

      await bobPage.page.reload({ waitUntil: "domcontentloaded" });
      await expectContactState(bobPage, alice.id, [
        "pending",
        "pending_outgoing",
      ]);

      await alicePage.page.goto("/contacts", { waitUntil: "domcontentloaded" });
      const incomingRow = await expectContactState(alicePage, bob.id, [
        "pending",
        "pending_incoming",
      ]);
      await incomingRow
        .getByRole("button", { name: /accept|接受/i })
        .click();
      await expectContactState(alicePage, bob.id, ["accepted"]);

      const aliceActor = canonicalJson(accountActorId(alice.id));
      const escapedAliceActor = aliceActor
        .replace(/\\/g, "\\\\")
        .replace(/"/g, '\\"');
      await expect
        .poll(
          async () => {
            await bobPage.page.reload({ waitUntil: "domcontentloaded" });
            const row = bobPage.page
              .getByTestId("contact-row")
              .filter({
                has: bobPage.page.locator(
                  `[title="${escapedAliceActor}"]`,
                ),
              });
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
      await requestContact(bobPage, alice.id, "invite");
      await gotoConsentSettings(alicePage);
      await grantConsentDirect(alicePage, bob.id, "invite", "5s");
      await expectConsentCell(
        request,
        aliceToken,
        alice.id,
        bob.id,
        "invite",
        "active",
      );

      // Consent is an independent authorization cell; it does not accept the
      // pending contact request on Alice's behalf.
      await expectContactState(bobPage, alice.id, [
        "pending",
        "pending_outgoing",
      ]);
      // The consent window above was set to Date.now()+5_000. Instead of
      // sleeping for a fixed margin, poll the authoritative consent cell until
      // the window lapses and the cell falls back to spec `no_consent` (implicit
      // revoke, consent-model.md §3.2 — there is no distinct `expired` wire
      // state). `expect.poll` bounds the wait and re-queries observable truth.
      await expect
        .poll(
          async () => {
            const cell = await request.get(
              `${solandBaseUrl()}/_arkret/self/consent/cell` +
                `?peer=${encodeURIComponent(JSON.stringify({ kind: "actor", actor_id: { kind: "account", account_id: { principal_id: bob.id, station_id: solandServiceId() } } }))}&consent_scope=invite`,
              { headers: { authorization: `Bearer ${aliceToken}` } },
            );
            if (cell.status() !== 200) {
              return cell.status();
            }
            return JSON.stringify(await cell.json());
          },
          { timeout: 30_000, intervals: [250, 500, 1_000] },
        )
        .toContain("no_consent");
      await expectContactState(bobPage, alice.id, [
        "pending",
        "pending_outgoing",
      ]);
      await expectConsentCell(
        request,
        aliceToken,
        alice.id,
        bob.id,
        "invite",
        "no_consent",
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
      await requestContact(bobPage, alice.id, "message");
      await gotoConsentSettings(alicePage);
      await grantConsentDirect(alicePage, bob.id, "message");
      await expectConsentCell(
        request,
        aliceToken,
        alice.id,
        bob.id,
        "message",
        "active",
      );

      const grantedRow = alicePage.page
        .getByTestId("consent-granted-row")
        .filter({
          hasText: bob.id,
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
        alice.id,
        bob.id,
        "message",
        "no_consent",
      );

      await expectContactState(bobPage, alice.id, [
        "pending",
        "pending_outgoing",
      ]);
      await grantConsentDirect(alicePage, bob.id, "message");
      await expectConsentCell(
        request,
        aliceToken,
        alice.id,
        bob.id,
        "message",
        "active",
      );
      await expectContactState(bobPage, alice.id, [
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
      await requestContact(bobPage, alice.id, "invite");
      await gotoConsentSettings(alicePage);
      await grantConsentDirect(alicePage, bob.id, "invite");
      await expectConsentCell(
        request,
        aliceToken,
        alice.id,
        bob.id,
        "invite",
        "active",
      );

      await expectContactState(bobPage, alice.id, [
        "pending",
        "pending_outgoing",
      ]);
      // Contact scope and consent scope are independent. Voice call is not a
      // Contact request scope, so exercise the spec's opaque consent-request
      // surface and verify it does not create a holder consent cell.
      await requestConsentApi(request, bobToken, alice.id, "call");
      await bobPage.page.reload({ waitUntil: "domcontentloaded" });
      await expectContactState(bobPage, alice.id, [
        "pending",
        "pending_outgoing",
      ]);
      await expectConsentCellMissing(
        request,
        aliceToken,
        bob.id,
        "call",
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
    test.skip(
      true,
      "spec-open 2026-09-04-1351: consent pairwise peer lacks a verifiable Realm-local binding carrier",
    );
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
        alice.id,
        "message",
      );
      expect(pairwisePending.state).toBe("pending_outgoing");
      await gotoConsentSettings(alicePage);
      await grantConsentDirect(alicePage, bobPairwise.did, "message");
      await expectConsentCell(
        request,
        aliceToken,
        alice.id,
        bobPairwise.did,
        "message",
        "active",
      );

      const pairwiseStillPending = await requestContactApi(
        request,
        pairwiseToken,
        alice.id,
        "message",
      );
      expect(pairwiseStillPending.state).toBe("pending_outgoing");
      const rootPending = await requestContactApi(
        request,
        rootToken,
        alice.id,
        "message",
      );
      expect(rootPending.state).toBe("pending_outgoing");
      await expectConsentCellMissing(
        request,
        aliceToken,
        bob.id,
        "message",
      );
      await stepShot(alicePage.page, testInfo, "pairwise-isolated");
    } finally {
      await alicePage.close();
    }
  });
});
