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
  expectJsonOk,
  prepareSignedEventSubmissionApi,
  principalControlRealmForId,
  principalControlRootAuthorizationRefForId,
  registeredEventSigningSeedB64url,
  registeredEventVerificationMethod,
  signedEventEnvelope,
  sdkMimiConsentProof,
  sdkMimiRequestConsentProof,
  submitSignedEventApi,
  typedId,
} from "../../helpers/soland-api";
import {
  assertJointStackNotRequired,
  ensureRegistered,
  issueUserSession,
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
import {
  createMimiProvider,
  postSignedMimiProviderRequest,
} from "../../helpers/mimi-provider";

test.describe.configure({ mode: "serial" });

type ConsentPeer = {
  kind: "actor";
  actor_id: {
    kind: "account";
    account_id: { principal_id: string; station_id: string };
  };
};

// `consent-operations.schema.json#/$defs/consent_view`.
type ConsentView = {
  consent_id: string;
  peer: ConsentPeer;
  consent_scope: string;
  state: "active" | "revoked";
  expires_at?: string;
  updated_at: string;
  revision: { commit_id: string; stream_position: number };
};

function consentPeer(peerId: string): ConsentPeer {
  return {
    kind: "actor",
    actor_id: {
      kind: "account",
      account_id: { principal_id: peerId, station_id: solandServiceId() },
    },
  };
}

function consentResultUrl(peerId: string, scope: string): string {
  return (
    `${solandBaseUrl()}/_arkret/self/consent/result` +
    `?peer=${encodeURIComponent(canonicalJson(consentPeer(peerId)))}` +
    `&consent_scope=${encodeURIComponent(scope)}`
  );
}

async function requestContact(
  actor: Awaited<ReturnType<typeof openUserPage>>,
  targetId: string,
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
  // A contact target typed as a DID is an explicit address, which must be
  // the complete account (handles still resolve through the directory).
  await actor.fillWithPassivePromptRetry(
    actor.page.getByTestId("contact-target-input"),
    canonicalJson(accountActorId(targetId)),
  );
  // Ordinary contacts allow all scopes; per-contact restrictions live in
  // Settings after acceptance, not in the add-contact form.
  await expect(actor.page.getByTestId("contact-scope-direct_message")).toHaveCount(0);
  await expect(actor.page.getByTestId("contact-scope-invite")).toHaveCount(0);
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
  scope: "invite" | "voice_call" | "presence",
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
  // The grantee is a remote account: its Station is part of the identity and
  // Inkson no longer completes a bare principal with its own Station.
  await actor.page
    .getByTestId("consent-new-grant-grantee-station-input")
    .fill(solandServiceId());
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

// `ak.self.consent.read.list.v1`: every holder-private Consent current result
// with its stable consent_id and exact revision. A revoked Consent stays a
// revoked row; a later grant is a new consent_id.
async function listConsentResults(
  request: APIRequestContext,
  token: string,
): Promise<ConsentView[]> {
  const response = await request.get(
    `${solandBaseUrl()}/_arkret/self/consent/results`,
    { headers: authHeaders(token, "GET", `${solandBaseUrl()}/_arkret/self/consent/results`) },
  );
  const body = await expectJsonOk<{ consents: ConsentView[] }>(
    response,
    "list consent results",
  );
  return body.consents;
}

async function expectConsentResult(
  request: APIRequestContext,
  token: string,
  holderId: string,
  peerId: string,
  scope: string,
  expectedState: ConsentView["state"],
): Promise<ConsentView> {
  expect(holderId).not.toBe(peerId);
  const peer = canonicalJson(consentPeer(peerId));
  let matched: ConsentView | undefined;
  await expect
    .poll(
      async () => {
        matched = (await listConsentResults(request, token)).find(
          (row) =>
            canonicalJson(row.peer) === peer &&
            row.consent_scope === scope &&
            row.state === expectedState,
        );
        return matched !== undefined;
      },
      {
        timeout: 30_000,
        intervals: [250, 500, 1_000],
        message: `${scope} Consent toward ${peerId} must reach ${expectedState}`,
      },
    )
    .toBe(true);
  return matched!;
}

// `ak.self.consent.resource.get.v1`: an absent Consent is not represented by
// a placeholder row.
async function expectConsentResultMissing(
  request: APIRequestContext,
  token: string,
  peerId: string,
  scope: string,
) {
  const response = await request.get(consentResultUrl(peerId, scope), {
    headers: authHeaders(token, "GET", consentResultUrl(peerId, scope)),
  });
  expect(response.status()).toBe(404);
}

async function requestContactApi(
  request: APIRequestContext,
  token: string,
  targetId: string,
  scope: "invite" | "direct_message",
) {
  const { outcome } = await requestContactArkret(request, token, targetId, {
    requestedScopes: [scope],
  });
  return outcome;
}

async function requestConsentApi(
  request: APIRequestContext,
  token: string,
  holderId: string,
  scope: "voice_call" | "video_call" | "presence" | "any",
) {
  const response = await request.post(
    `${solandBaseUrl()}/_arkret/self/consent/request`,
    {
      headers: { ...authHeaders(token, "POST", `${solandBaseUrl()}/_arkret/self/consent/request`), "content-type": "application/json" },
      data: canonicalJson({
        consent_scope: scope,
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
        "voice_call",
      );
      await alicePage.page
        .getByTestId("consent-new-grant-grantee-input")
        .fill(bob.id);
      await alicePage.page
        .getByTestId("consent-new-grant-grantee-station-input")
        .fill(solandServiceId());
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
    // alice asks bob (the holder) to grant her `voice_call` consent via the
    // `ak.consent.request` entry point. The request is opaque to her: it
    // yields no Consent result and no outgoing-request row.
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
    const aliceToken = await issueUserSession(request, alice);
    const alicePage = aliceFlow.page;

    try {
      await gotoConsentSettings(alicePage);

      await alicePage.page.getByTestId("consent-request-button").click();
      await selectDxcOption(
        alicePage.page.getByTestId("consent-request-scope-input"),
        "voice_call",
      );
      await alicePage.page
        .getByTestId("consent-request-holder-input")
        .fill(bob.id);
      await alicePage.page
        .getByTestId("consent-request-holder-station-input")
        .fill(solandServiceId());
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
      // quarantine/anti-abuse path and creates no Consent result, pending state,
      // contact fact, or requester-visible outgoing projection.
      const peerRead = await request.get(consentResultUrl(bob.id, "voice_call"), {
        headers: authHeaders(aliceToken, "GET", consentResultUrl(bob.id, "voice_call")),
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

  test("contacts modal submits Contact without creating Consent", async ({
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
      await requestContact(bobPage, alice.id);
      const escapedId = canonicalJson(accountActorId(alice.id))
        .replace(/\\/g, "\\\\")
        .replace(/"/g, '\\"');
      const pendingRow = bobPage.page
        .getByTestId("contact-row")
        .filter({ has: bobPage.page.locator(`[title="${escapedId}"]`) });
      await expect(pendingRow).toBeVisible({ timeout: 30_000 });
      await expect(pendingRow).toHaveAttribute("data-state", /pending/);
      const resultUrl = consentResultUrl(bob.id, "voice_call");
      const result = await request.get(resultUrl, {
        headers: selfPathHeadersForDpopSession(
          aliceFlow.session,
          "GET",
          resultUrl,
        ),
      });
      expect(result.status()).toBe(404);
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
    // Each principal's canonical session provisions its device signer; only
    // alice's session is used, to prepare her own consent Event.
    const [aliceToken] = await Promise.all([
      issueUserSession(request, alice),
      issueUserSession(request, bob),
      issueUserSession(request, charlie),
    ]);
    const aliceSigningSeed = registeredEventSigningSeedB64url(alice.id);
    const bobSigningSeed = registeredEventSigningSeedB64url(bob.id);
    const charlieSigningSeed = registeredEventSigningSeedB64url(charlie.id);
    if (!aliceSigningSeed || !bobSigningSeed || !charlieSigningSeed) {
      throw new Error("canonical provisioning omitted a MIMI consent device signer");
    }
    const describe = await expectJsonOk<{
      service_id: string;
      trust_domain: string;
    }>(
      await request.get(`${solandBaseUrl()}/_arkret/describe`),
      "MIMI consent destination describe",
    );

    // `mimi_request_consent_request_body` names the requester by complete
    // ActorId and the holder by complete AccountId — consent-model.md §6.1
    // forbids falling back to a bare principal — and requires the requester
    // operation proof over `ak.mimi_request_consent_request_proof.v1`.
    const openUnsigned = {
      requester_actor_id: accountActorId(bob.id),
      holder_account_id: accountActorId(alice.id).account_id,
      purpose: "voice_call",
    };
    const bobVerificationMethod = registeredEventVerificationMethod(bob.id);
    if (!bobVerificationMethod) {
      throw new Error("canonical provisioning omitted bob's device verification method");
    }
    const openProof = sdkMimiRequestConsentProof({
      request: openUnsigned,
      verificationMethod: bobVerificationMethod,
      createdAt: canonicalTimestamp(),
      domain: describe.trust_domain,
      audience: describe.service_id,
      signingSeedB64url: bobSigningSeed,
    });
    // mimi-interop.md section 5: both consent operations are provider-to-
    // provider and MUST carry the RFC 9421 provider-source signature. One
    // provider opens the correlation and answers it, because the correlation
    // is bound to the authenticated source service.
    const provider = createMimiProvider("g2t5-consent");
    const open = await postSignedMimiProviderRequest(
      request,
      provider,
      describe.service_id,
      `${solandBaseUrl()}/_arkret/open/mimi/consent/request`,
      { ...openUnsigned, proofs: [openProof] },
    );
    const openText = await open.text();
    expect(open.status(), openText).toBe(200);
    const openBody = JSON.parse(openText) as Record<string, unknown>;
    // `mimi_request_consent_outcome` is closed over `consent_id` and an
    // optional `challenge`; it carries no status member.
    expect(Object.keys(openBody).filter((key) => key !== "challenge")).toEqual(["consent_id"]);
    expect(openBody.consent_id).toMatch(/^ak:consent:/);

    const updateUrl = `${solandBaseUrl()}/_arkret/open/mimi/consent/update`;
    const grantEvent = signedEventEnvelope({
      actorId: alice.id,
      realmId: principalControlRealmForId(alice.id),
      authorizationRef: principalControlRootAuthorizationRefForId(alice.id),
      kind: "ak.consent.grant",
      payload: {
        consent_id: openBody.consent_id,
        peer: { kind: "actor", actor_id: accountActorId(bob.id) },
        consent_scope: "voice_call",
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
    const update = await postSignedMimiProviderRequest(
      request,
      provider,
      describe.service_id,
      updateUrl,
      signedUpdate,
    );
    const updateText = await update.text();
    expect(update.status(), updateText).toBe(200);
    const updateBody = JSON.parse(updateText);
    // `mimi_update_consent_outcome` reports the decision it admitted.
    expect(updateBody.decision).toBe("accept");
    expect(updateBody.consent_id).toBe(openBody.consent_id);
    expect(updateBody.event_ref).toBe(grantEvent.event_id);

    const replay = await postSignedMimiProviderRequest(
      request,
      provider,
      describe.service_id,
      updateUrl,
      signedUpdate,
    );
    expect(replay.status()).toBe(200);
    const replayBody = await replay.json();
    expect(replayBody).toEqual(updateBody);

    const conflictingEvent = signedEventEnvelope({
      actorId: alice.id,
      realmId: principalControlRealmForId(alice.id),
      eventId: String(grantEvent.event_id),
      authorizationRef: principalControlRootAuthorizationRefForId(alice.id),
      kind: "ak.consent.grant",
      payload: {
        consent_id: openBody.consent_id,
        peer: { kind: "actor", actor_id: accountActorId(bob.id) },
        consent_scope: "voice_call",
      },
    });
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
    const conflicting = await postSignedMimiProviderRequest(
      request,
      provider,
      describe.service_id,
      updateUrl,
      conflictingBody,
    );
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
    const invisible = await postSignedMimiProviderRequest(
      request,
      provider,
      describe.service_id,
      updateUrl,
      invisibleBody,
    );

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
    const unknown = await postSignedMimiProviderRequest(
      request,
      provider,
      describe.service_id,
      updateUrl,
      unknownBody,
    );
    expect(unknown.status()).toBe(invisible.status());
    const invisibleOutcome = await invisible.json();
    const unknownOutcome = await unknown.json();
    delete invisibleOutcome.request_id;
    delete unknownOutcome.request_id;
    delete invisibleOutcome.instance;
    delete unknownOutcome.instance;
    expect(unknownOutcome).toEqual(invisibleOutcome);
  });

  test("ak.consent.grant updates only consent and leaves Contact pending", async ({
    request,
  }) => {
    const alice = uniqueUser("p1-020-consent-event-alice");
    const bob = uniqueUser("p1-020-consent-event-bob");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const [aliceToken, bobToken] = await Promise.all([
      issueUserSession(request, alice),
      issueUserSession(request, bob),
    ]);
    // consent-model.md section 3.3: Consent Events are authored in the
    // holder's Principal Control Realm.
    const realmId = principalControlRealmForId(alice.id);

    const pending = await requestContactApi(
      request,
      bobToken,
      alice.id,
      "direct_message",
    );
    expect(pending.state).toBe("pending_outgoing");

    const consentId = typedId("operation").replace(
      "ak:operation:",
      "ak:consent:",
    );
    const grantEnvelope = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      authorizationRef: principalControlRootAuthorizationRefForId(alice.id),
      kind: "ak.consent.grant",
      payload: {
        consent_id: consentId,
        peer: { kind: "actor", actor_id: accountActorId(bob.id) },
        consent_scope: "voice_call",
        expires_at: canonicalTimestamp(
          new Date(Date.now() + 24 * 60 * 60 * 1000),
        ),
      },
    });
    await submitSignedEventApi(request, aliceToken, grantEnvelope, {
      context: "submit ak.consent.grant",
    });

    const granted = await expectConsentResult(
      request,
      aliceToken,
      alice.id,
      bob.id,
      "voice_call",
      "active",
    );
    expect(granted.consent_id).toBe(consentId);
    const stillPending = await contactRow(request, bobToken, alice.id);
    expect(stillPending?.state).toBe("pending_outgoing");

    const revokeEnvelope = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      authorizationRef: principalControlRootAuthorizationRefForId(alice.id),
      kind: "ak.consent.revoke",
      payload: {
        consent_id: consentId,
        expected_revision: granted.revision,
        revoked_at: canonicalTimestamp(new Date(Date.now() + 1000)),
      },
    });
    await submitSignedEventApi(request, aliceToken, revokeEnvelope, {
      context: "submit ak.consent.revoke",
    });

    const revoked = await expectConsentResult(
      request,
      aliceToken,
      alice.id,
      bob.id,
      "voice_call",
      "revoked",
    );
    expect(revoked.consent_id).toBe(consentId);
    expect(revoked.revision).not.toEqual(granted.revision);
    const stillPendingAfterRevoke = await contactRow(
      request,
      bobToken,
      alice.id,
    );
    expect(stillPendingAfterRevoke?.state).toBe("pending_outgoing");
  });

  test("consent grant and Contact acceptance use independent authority", async ({
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
    const aliceToken = await issueUserSession(request, alice);
    const alicePage = aliceFlow.page;
    const bobPage = bobFlow.page;

    try {
      await alicePage.gotoHome();
      await bobPage.gotoHome();

      await requestContact(bobPage, alice.id);
      await expectContactState(bobPage, alice.id, [
        "pending",
        "pending_outgoing",
      ]);
      await expectConsentResultMissing(
        request,
        aliceToken,
        bob.id,
        "invite",
      );
      await stepShot(bobPage.page, testInfo, "A-bob-pending-consent");

      await gotoConsentSettings(alicePage);
      // A Contact request creates no Consent authority. Exercise an explicit
      // holder grant and verify that Contact still needs its own acceptance.
      await grantConsentDirect(alicePage, bob.id, "invite");
      // Spec `active` (consent-model.md §2.2 / SDK `ConsentState::Active`).
      await expectConsentResult(
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

      await alicePage.gotoAppPanel("/contacts", "contacts-panel");
      const incomingRow = await expectContactState(alicePage, bob.id, [
        "pending",
        "pending_incoming",
      ]);
      await alicePage.clickWithPassivePromptRetry(
        incomingRow.getByRole("button", { name: /accept|接受/i }),
      );
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

  test("E1.1 time-windowed consent lapses by its window without a materialized expiry", async ({
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
    const aliceToken = await issueUserSession(request, alice);
    const alicePage = aliceFlow.page;
    const bobPage = bobFlow.page;

    try {
      await requestContact(bobPage, alice.id);
      await gotoConsentSettings(alicePage);
      await grantConsentDirect(alicePage, bob.id, "invite", "5s");
      const granted = await expectConsentResult(
        request,
        aliceToken,
        alice.id,
        bob.id,
        "invite",
        "active",
      );
      expect(granted.expires_at, "the TTL is the Consent window").toBeTruthy();

      // Consent is an independent authorization result; it does not accept
      // the pending contact request on Alice's behalf.
      await expectContactState(bobPage, alice.id, [
        "pending",
        "pending_outgoing",
      ]);
      // consent-model.md section 2: `expired` is not a materialized state.
      // The window is evaluated at read/admission time, so after it lapses
      // the typed current result keeps its `active` reducer state and the
      // exact revision of the grant; nothing is written for expiry.
      const expiresAt = Date.parse(granted.expires_at!);
      await expect
        .poll(() => Date.now() > expiresAt, {
          timeout: 30_000,
          intervals: [250, 500, 1_000],
        })
        .toBe(true);
      await expectContactState(bobPage, alice.id, [
        "pending",
        "pending_outgoing",
      ]);
      const afterWindow = await expectConsentResult(
        request,
        aliceToken,
        alice.id,
        bob.id,
        "invite",
        "active",
      );
      expect(afterWindow.consent_id).toBe(granted.consent_id);
      expect(afterWindow.revision).toEqual(granted.revision);
      expect(afterWindow.expires_at).toBe(granted.expires_at);
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
    const aliceToken = await issueUserSession(request, alice);
    const alicePage = aliceFlow.page;
    const bobPage = bobFlow.page;

    try {
      await requestContact(bobPage, alice.id);
      await gotoConsentSettings(alicePage);
      await grantConsentDirect(alicePage, bob.id, "voice_call");
      const firstGrant = await expectConsentResult(
        request,
        aliceToken,
        alice.id,
        bob.id,
        "voice_call",
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
      await expectConsentResult(
        request,
        aliceToken,
        alice.id,
        bob.id,
        "voice_call",
        "revoked",
      );

      await expectContactState(bobPage, alice.id, [
        "pending",
        "pending_outgoing",
      ]);
      await grantConsentDirect(alicePage, bob.id, "voice_call");
      const secondGrant = await expectConsentResult(
        request,
        aliceToken,
        alice.id,
        bob.id,
        "voice_call",
        "active",
      );
      expect(secondGrant.consent_id).not.toBe(firstGrant.consent_id);
      const rows = await listConsentResults(request, aliceToken);
      expect(rows.find((row) => row.consent_id === firstGrant.consent_id)?.state)
        .toBe("revoked");
      // Multiple stable records cannot be collapsed into one peer/scope result.
      const ambiguous = await request.get(consentResultUrl(bob.id, "voice_call"), {
        headers: authHeaders(aliceToken, "GET", consentResultUrl(bob.id, "voice_call")),
      });
      expect(ambiguous.status()).toBe(409);
      const regrantedRow = alicePage.page.locator(
        `[data-testid="consent-granted-row"][data-consent-id="${secondGrant.consent_id}"]`,
      );
      await regrantedRow.getByTestId("revoke-consent-button").click();
      await expect(alicePage.page.getByTestId("write-status"))
        .toContainText(/revoked/i, { timeout: 30_000 });
      const finalRows = await listConsentResults(request, aliceToken);
      expect(finalRows.find((row) => row.consent_id === firstGrant.consent_id)?.state)
        .toBe("revoked");
      expect(finalRows.find((row) => row.consent_id === secondGrant.consent_id)?.state)
        .toBe("revoked");
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
      issueUserSession(request, alice),
      issueUserSession(request, bob),
    ]);
    const alicePage = aliceFlow.page;
    const bobPage = bobFlow.page;

    try {
      await requestContact(bobPage, alice.id);
      await gotoConsentSettings(alicePage);
      await grantConsentDirect(alicePage, bob.id, "invite");
      await expectConsentResult(
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
      // surface and verify it does not create a holder Consent result.
      await requestConsentApi(request, bobToken, alice.id, "voice_call");
      await bobPage.page.reload({ waitUntil: "domcontentloaded" });
      await expectContactState(bobPage, alice.id, [
        "pending",
        "pending_outgoing",
      ]);
      await expectConsentResultMissing(
        request,
        aliceToken,
        bob.id,
        "voice_call",
      );
      await stepShot(bobPage.page, testInfo, "scope-granularity-call-pending");
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });

  // E1.4 (pairwise consent isolation) is a Rust live scenario, not a browser
  // test: it needs a real Realm-local ephemeral pairwise actor, which only
  // exists as an accepted MLS LeafNode inside a
  // `ak.profile.mls.minimal_metadata_realm.v1` Realm and has no account, no
  // Principal Control Realm and no session to drive a browser with. See
  // `cotest/tests/consent_pairwise_isolation_live.rs`.
});
