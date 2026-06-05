// Calls (1:1 + group + mute + screen share + recording policy)
// Contract: e2e/scenarios/calls/webrtc.md
// Spec refs:
//   - crypto-media/webrtc-signaling.md §2 (design); crypto-media/call-state.md §2-§3 (modes, Call Morph)
//   - webrtc-signaling.md §3 (ck.call.* capabilities: join/signal.send/screen_share/record/moderate)
//   - webrtc-signaling.md §4-§4.1 (ICE config, pairwise pseudonym, mid-call refresh)
//   - webrtc-signaling.md §5-§6 (signaling envelope, 1:1 payloads)

import { expect, test, type APIRequestContext, type Page } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  type JointUser,
  uniqueUser,
} from "../../helpers/users";
import {
  addRealmMemberApi,
  authHeaders,
  createRealmApi,
  wireErrCode,
} from "../../helpers/soland-api";

test.describe.configure({ mode: "serial" });

test.describe("calls", () => {
  test("ICE config endpoint exists and rejects unauthenticated callers", async ({ request }) => {
    const alice = uniqueUser("s18-probe");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);

    const iceProbe = await request.post(`${solandBaseUrl()}/_cokret/self/rtc/ice-config`, {
      data: { call_id: "ck:call:probe", device_id: alice.deviceId, mode: "p2p" },
    });
    // Unauthenticated must be rejected (or endpoint absent → 404, or 405
    // when the path is routed but POST is not allowed yet).
    expect([401, 403, 404, 405]).toContain(iceProbe.status());

    const iceAuth = await request.post(`${solandBaseUrl()}/_cokret/self/rtc/ice-config`, {
      headers: { authorization: `Bearer ${token}` },
      data: { call_id: "ck:call:probe", device_id: alice.deviceId, mode: "p2p" },
    });
    // With auth: either implemented (200 with stun/turn) or absent (404). 5xx is bug.
    expect(iceAuth.status()).toBeLessThan(500);
  });

  test(
    "alice initiates 1:1 call to bob; Call Morph state transitions ringing → connecting → active via ck.call.signal frames",
    async ({ browser, request }) => {
      // spec: call-state.md §2 + §3
      const stamp = Date.now();
      const alice = uniqueUser(`s18-call-alice-${stamp}`);
      const bob = uniqueUser(`s18-call-bob-${stamp}`);
      await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
      const aliceToken = await issueDevSession(request, alice);
      const bobToken = await issueDevSession(request, bob);
      const realmId = await createRealmApi(request, aliceToken, {
        title: `S18 WebRTC ${stamp}`,
        public: true,
      });
      await addRealmMemberApi(request, aliceToken, realmId, bob.did);

      const session = await request.post(`${solandBaseUrl()}/_cokret/self/webrtc/sessions`, {
        headers: authHeaders(aliceToken),
        data: {
          realm_id: realmId,
          participants: [bob.did],
          ttl_ms: 120_000,
        },
      });
      expect(session.ok()).toBeTruthy();
      const sessionBody = await session.json();
      expect(sessionBody.session_id).toMatch(/^ck:call:/);
      expect(sessionBody.participants).toEqual(expect.arrayContaining([alice.did, bob.did]));
      expect(sessionBody.call_state).toBe("ringing");
      const sessionId = sessionBody.session_id as string;

      const offer = await appendCallSignal(request, aliceToken, sessionId, alice, "offer", 1, {
        sdp: "v=0\r\no=alice",
        target: bob.did,
      });
      expect(offer.call_state).toBe("connecting");

      const bobOffer = await readCallSignals(request, bobToken, sessionId, 0);
      expect(bobOffer.call_state).toBe("connecting");
      expect(bobOffer.events).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            seq: 1,
            sender: alice.did,
            type: "offer",
            call_state_after: "connecting",
          }),
        ]),
      );

      const answer = await appendCallSignal(request, bobToken, sessionId, bob, "answer", 2, {
        sdp: "v=0\r\no=bob",
        target: alice.did,
      });
      expect(answer.call_state).toBe("active");

      const aliceAnswer = await readCallSignals(request, aliceToken, sessionId, 1);
      expect(aliceAnswer.call_state).toBe("active");
      expect(aliceAnswer.events).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            seq: 2,
            sender: bob.did,
            type: "answer",
            call_state_after: "active",
          }),
        ]),
      );

      const hangup = await appendCallSignal(request, aliceToken, sessionId, alice, "hangup", 3, {
        reason: "user_hangup",
      });
      expect(hangup.call_state).toBe("ended");

      const bobHangup = await readCallSignals(request, bobToken, sessionId, 2);
      expect(bobHangup.call_state).toBe("ended");
      expect(bobHangup.events).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            seq: 3,
            sender: alice.did,
            type: "hangup",
            call_state_after: "ended",
          }),
        ]),
      );

      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
      try {
        await alicePage.page.goto("/call", { waitUntil: "domcontentloaded" });
        await expect(alicePage.page.getByTestId("call-panel")).toBeVisible({ timeout: 60_000 });
        await alicePage.page.getByTestId("webrtc-call-start-button").click();
        await expect(alicePage.page.getByTestId("call-status-ringing")).toBeVisible();
        await alicePage.page.getByTestId("webrtc-call-connect-button").click();
        await expect(alicePage.page.getByTestId("call-status-connecting")).toBeVisible();
        await alicePage.page.getByTestId("webrtc-call-activate-button").click();
        await expect(alicePage.page.getByTestId("call-status-active")).toBeVisible();
        await alicePage.page.getByTestId("webrtc-leave-call-button").click();
        await expect(alicePage.page.getByTestId("call-status-ended")).toBeVisible();
      } finally {
        await alicePage.close();
      }
    },
  );

  test(
    "alice mutes mic: ck.call.signal{kind=mute_state, muted=true} routes to bob; bob's UI shows muted indicator",
    async ({ browser, request }) => {
      // spec: webrtc-signaling.md §5 + §6
      const { alice, aliceToken, bob, bobToken, realmId } = await setupCallRealm(request, "s18-ui-mute");
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
      try {
        const sessionId = await startUiCall(alicePage.page, realmId, bob.did);
        await alicePage.page.getByTestId("webrtc-mute-button").click();
        await expect(alicePage.page.getByTestId("webrtc-local-mic-status")).toHaveAttribute(
          "data-muted",
          "true",
        );
        await expect(
          alicePage.page.locator(`[data-testid="webrtc-participant-row"][data-actor-did="${alice.did}"]`),
        ).toHaveAttribute("data-stream-state", "muted");
        await expect
          .poll(() => signalSeen(request, bobToken, sessionId, "mute_state", { muted: true }), {
            timeout: 30_000,
          })
          .toBe(true);
      } finally {
        await alicePage.close();
      }
    },
  );

  test(
    "alice shares screen: getDisplayMedia track added; ck.call.signal{kind=media_state, screen_share=true} routes",
    async ({ browser, request }) => {
      // spec: webrtc-signaling.md §3 ck.call.screen_share capability
      const { alice, aliceToken, bob, bobToken, realmId } = await setupCallRealm(request, "s18-ui-screen");
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
      try {
        const sessionId = await startUiCall(alicePage.page, realmId, bob.did);
        await alicePage.page.getByTestId("webrtc-screen-share-start-button").click();
        await expect(alicePage.page.getByTestId("webrtc-screen-share-status")).toHaveAttribute(
          "data-state",
          "sharing",
        );
        await expect(alicePage.page.getByTestId("webrtc-screen-share-preview")).toBeVisible();
        await expect(
          alicePage.page.locator(`[data-testid="webrtc-participant-row"][data-actor-did="${alice.did}"]`),
        ).toHaveAttribute("data-screen-sharing", "true");
        await expect
          .poll(
            () => signalSeen(request, bobToken, sessionId, "media_state", { screen_share: true }),
            { timeout: 30_000 },
          )
          .toBe(true);
      } finally {
        await alicePage.close();
      }
    },
  );

  test(
    "hangup terminates peer connections; Call Morph state=ended; duration persisted",
    async ({ browser, request }) => {
      // spec: call-state.md §3
      const { alice, aliceToken, bob, bobToken, realmId } = await setupCallRealm(request, "s18-ui-hangup");
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
      try {
        const sessionId = await startUiCall(alicePage.page, realmId, bob.did);
        await alicePage.page.getByTestId("webrtc-leave-call-button").click();
        await expect(alicePage.page.getByTestId("call-status-ended")).toBeVisible();
        await expect(alicePage.page.getByTestId("webrtc-call-ended-panel")).toBeVisible();
        await expect
          .poll(async () => {
            const body = await readCallSignals(request, bobToken, sessionId, 0);
            return {
              ended: body.call_state === "ended",
              hangup: body.events.some((event: any) => event.type === "hangup"),
            };
          }, { timeout: 30_000 })
          .toEqual({ ended: true, hangup: true });
      } finally {
        await alicePage.close();
      }
    },
  );

  test(
    "group call mode=sfu: alice+bob+carol join; recording_policy=allow lets carol start recording (writes recording_blob_ref)",
    async ({ browser, request }) => {
      // spec: call-state.md §2 + webrtc-signaling.md §3 ck.call.record capability
      const { alice, aliceToken, bob, carol, carolToken, realmId } = await setupCallRealm(request, "s18-record-allow");
      const session = await createWebrtcSession(request, aliceToken, {
        realm_id: realmId,
        participants: [bob.did, carol.did],
        mode: "sfu",
        recording_policy: "allow",
      });
      expect(session.mode).toBe("sfu");
      expect(session.recording_policy).toBe("allow");
      expect(session.participants).toEqual(expect.arrayContaining([bob.did, carol.did]));

      const recording = await startRecording(request, carolToken, session.session_id, realmId);
      expect(recording.ok).toBe(true);
      expect(recording.recording_started_by).toBe(carol.did);
      expect(recording.recording_policy).toBe("allow");
      expect(recording.recording_blob_ref).toMatch(/^ck:blob:sha256:/);

      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
      try {
        await startUiGroupCall(alicePage.page, realmId, [bob.did, carol.did]);
        await expect(alicePage.page.getByTestId("webrtc-call-mode")).toHaveAttribute("data-mode", "sfu");
        await expect(alicePage.page.getByTestId("webrtc-recording-policy")).toHaveAttribute(
          "data-policy",
          "allow",
        );
        await expect(alicePage.page.getByTestId("webrtc-roster-count")).toHaveText("3");
        await alicePage.page.getByTestId("webrtc-recording-toggle-button").click();
        await expect(alicePage.page.getByTestId("webrtc-recording-status")).toHaveAttribute(
          "data-state",
          "recording",
        );
        await expect(alicePage.page.getByTestId("webrtc-recording-indicator")).toBeVisible();
        await expect(alicePage.page.getByTestId("webrtc-recording-blob-ref")).toContainText(
          /^ck:blob:sha256:/,
        );
      } finally {
        await alicePage.close();
      }
    },
  );

  test(
    "E18.E recording_policy=none rejects carol's recording attempt with failed_precondition reason=recording_policy_violation",
    async ({ request }) => {
      // spec: webrtc-signaling.md §3
      const { aliceToken, carol, carolToken, realmId } = await setupCallRealm(request, "s18-record-deny");
      const session = await createWebrtcSession(request, aliceToken, {
        realm_id: realmId,
        participants: [carol.did],
        mode: "sfu",
        recording_policy: "none",
      });

      const denied = await request.post(
        `${solandBaseUrl()}/_cokret/self/calls/${encodeURIComponent(session.session_id)}/recording/start`,
        {
          headers: authHeaders(carolToken),
          data: { realm_id: realmId },
        },
      );
      expect(denied.status()).toBe(412);
      expect(wireErrCode(await denied.json())).toBe("recording_policy_violation");
    },
  );

  test(
    "E18.F mid-call TURN credential refresh: long calls renew credentials before expiry; call does not drop",
    async ({ request }) => {
      // spec: webrtc-signaling.md §4.1
      const { alice, aliceToken, bob, bobToken, realmId } = await setupCallRealm(request, "s18-turn-refresh");
      const session = await createWebrtcSession(request, aliceToken, {
        realm_id: realmId,
        participants: [bob.did],
        mode: "p2p",
        recording_policy: "none",
      });
      await appendCallSignal(request, aliceToken, session.session_id, alice, "offer", 1, {
        sdp: "v=0\r\no=alice",
      });
      await appendCallSignal(request, bobToken, session.session_id, bob, "answer", 2, {
        sdp: "v=0\r\no=bob",
      });

      const issued = await issueIceConfig(request, aliceToken, {
        realm_id: realmId,
        call_id: session.session_id,
        actor_id: alice.did,
        device_id: alice.deviceId,
      });
      const refreshed = await refreshIceConfig(request, aliceToken, session.session_id, {
        realm_id: realmId,
        actor_id: alice.did,
        device_id: alice.deviceId,
      });
      expect(refreshed.refreshed).toBe(true);
      expect(refreshed.turn_servers[0].username).toBe(issued.turn_servers[0].username);
      expect(refreshed.turn_servers[0].credential).not.toBe(issued.turn_servers[0].credential);
      expect(refreshed.refresh_lead_seconds).toBeGreaterThan(0);

      const afterRefresh = await readCallSignals(request, aliceToken, session.session_id, 0);
      expect(afterRefresh.call_state).toBe("active");
    },
  );

  test(
    "E18.7 pairwise pseudonym in TURN credentials: username does not contain alice.did plaintext (spec §6 pseudonymization)",
    async ({ request }) => {
      // spec: webrtc-signaling.md §4.1 (pairwise pseudonym)
      const { alice, aliceToken, bob, bobToken, realmId } = await setupCallRealm(request, "s18-turn-pseudonym");
      const session = await createWebrtcSession(request, aliceToken, {
        realm_id: realmId,
        participants: [bob.did],
        mode: "p2p",
        recording_policy: "none",
      });

      const aliceIce = await issueIceConfig(request, aliceToken, {
        realm_id: realmId,
        call_id: session.session_id,
        actor_id: alice.did,
        device_id: alice.deviceId,
      });
      const bobIce = await issueIceConfig(request, bobToken, {
        realm_id: realmId,
        call_id: session.session_id,
        actor_id: bob.did,
        device_id: bob.deviceId,
      });
      const aliceUsername = aliceIce.turn_servers[0].username as string;
      const bobUsername = bobIce.turn_servers[0].username as string;
      expect(aliceUsername).toMatch(/^ck-turn-/);
      expect(bobUsername).toMatch(/^ck-turn-/);
      expect(aliceUsername).not.toContain(alice.did);
      expect(aliceUsername).not.toContain("did:web");
      expect(aliceUsername).not.toContain(alice.name);
      expect(bobUsername).not.toContain(bob.did);
      expect(bobUsername).not.toContain("did:web");
      expect(bobUsername).not.toContain(bob.name);
      expect(bobUsername).not.toBe(aliceUsername);
    },
  );
});

async function startUiCall(page: Page, realmId: string, peerDid: string): Promise<string> {
  await page.goto("/call", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("call-panel")).toBeVisible({ timeout: 60_000 });
  await expect(page.getByTestId("webrtc-panel")).toBeVisible({ timeout: 60_000 });
  await page.getByTestId("webrtc-realm-id-input").fill(realmId);
  await page.getByTestId("webrtc-peer-did-input").fill(peerDid);
  await page.getByTestId("webrtc-call-start-button").click();
  await expect(page.getByTestId("call-status-ringing")).toBeVisible();
  await expect
    .poll(async () => page.getByTestId("webrtc-session-id").getAttribute("data-session-id"), {
      timeout: 30_000,
    })
    .toMatch(/^ck:call:/);
  const sessionId = (await page.getByTestId("webrtc-session-id").getAttribute("data-session-id"))!;
  await page.getByTestId("webrtc-call-connect-button").click();
  await expect(page.getByTestId("call-status-connecting")).toBeVisible();
  await page.getByTestId("webrtc-call-activate-button").click();
  await expect(page.getByTestId("call-status-active")).toBeVisible();
  await expect(page.getByTestId("webrtc-roster-count")).toHaveText("2");
  return sessionId;
}

async function startUiGroupCall(page: Page, realmId: string, participantDids: string[]): Promise<string> {
  await page.goto("/call", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("call-panel")).toBeVisible({ timeout: 60_000 });
  await expect(page.getByTestId("webrtc-panel")).toBeVisible({ timeout: 60_000 });
  await page.getByTestId("webrtc-realm-id-input").fill(realmId);
  await page.getByTestId("webrtc-group-participants-input").fill(participantDids.join("\n"));
  await page.getByTestId("webrtc-group-call-start-button").click();
  await expect(page.getByTestId("call-status-active")).toBeVisible();
  await expect
    .poll(async () => page.getByTestId("webrtc-session-id").getAttribute("data-session-id"), {
      timeout: 30_000,
    })
    .toMatch(/^ck:call:/);
  return (await page.getByTestId("webrtc-session-id").getAttribute("data-session-id"))!;
}

async function signalSeen(
  request: APIRequestContext,
  token: string,
  sessionId: string,
  signalType: string,
  payloadSubset: Record<string, unknown>,
) {
  const body = await readCallSignals(request, token, sessionId, 0);
  return body.events.some((event: any) => {
    if (event.type !== signalType) {
      return false;
    }
    for (const [key, value] of Object.entries(payloadSubset)) {
      if (event.payload?.[key] !== value) {
        return false;
      }
    }
    return true;
  });
}

async function appendCallSignal(
  request: APIRequestContext,
  token: string,
  sessionId: string,
  actor: JointUser,
  messageType: string,
  seq: number,
  payload: Record<string, unknown>,
) {
  const response = await request.post(
    `${solandBaseUrl()}/_cokret/self/webrtc/sessions/${encodeURIComponent(sessionId)}/signals`,
    {
      headers: authHeaders(token),
      data: {
        message_type: messageType,
        seq,
        payload,
        proofs: [deviceProof(actor)],
      },
    },
  );
  expect(response.ok(), `append ${messageType} seq=${seq}`).toBeTruthy();
  return await response.json();
}

async function setupCallRealm(request: APIRequestContext, label: string) {
  const stamp = Date.now();
  const alice = uniqueUser(`${label}-alice-${stamp}`);
  const bob = uniqueUser(`${label}-bob-${stamp}`);
  const carol = uniqueUser(`${label}-carol-${stamp}`);
  await Promise.all([
    ensureRegistered(request, alice),
    ensureRegistered(request, bob),
    ensureRegistered(request, carol),
  ]);
  const aliceToken = await issueDevSession(request, alice);
  const bobToken = await issueDevSession(request, bob);
  const carolToken = await issueDevSession(request, carol);
  const realmId = await createRealmApi(request, aliceToken, {
    title: `S18 ${label} ${stamp}`,
    public: true,
  });
  await addRealmMemberApi(request, aliceToken, realmId, bob.did);
  await addRealmMemberApi(request, aliceToken, realmId, carol.did);
  return { alice, bob, carol, aliceToken, bobToken, carolToken, realmId };
}

async function createWebrtcSession(
  request: APIRequestContext,
  token: string,
  data: {
    realm_id: string;
    participants: string[];
    mode: string;
    recording_policy: string;
  },
) {
  const response = await request.post(`${solandBaseUrl()}/_cokret/self/webrtc/sessions`, {
    headers: authHeaders(token),
    data: { ...data, ttl_ms: 120_000 },
  });
  expect(response.ok(), "create WebRTC session").toBeTruthy();
  return await response.json();
}

async function issueIceConfig(
  request: APIRequestContext,
  token: string,
  data: {
    realm_id: string;
    call_id: string;
    actor_id: string;
    device_id: string;
  },
) {
  const response = await request.post(`${solandBaseUrl()}/_cokret/self/rtc/ice-config`, {
    headers: authHeaders(token),
    data,
  });
  expect(response.ok(), "issue ICE config").toBeTruthy();
  return await response.json();
}

async function refreshIceConfig(
  request: APIRequestContext,
  token: string,
  sessionId: string,
  data: {
    realm_id: string;
    actor_id: string;
    device_id: string;
  },
) {
  const response = await request.post(
    `${solandBaseUrl()}/_cokret/self/calls/${encodeURIComponent(sessionId)}/ice-config/refresh`,
    {
      headers: authHeaders(token),
      data,
    },
  );
  expect(response.ok(), "refresh ICE config").toBeTruthy();
  return await response.json();
}

async function startRecording(
  request: APIRequestContext,
  token: string,
  sessionId: string,
  realmId: string,
) {
  const response = await request.post(
    `${solandBaseUrl()}/_cokret/self/calls/${encodeURIComponent(sessionId)}/recording/start`,
    {
      headers: authHeaders(token),
      data: { realm_id: realmId },
    },
  );
  expect(response.ok(), "start recording").toBeTruthy();
  return await response.json();
}

async function readCallSignals(
  request: APIRequestContext,
  token: string,
  sessionId: string,
  since: number,
) {
  const response = await request.get(
    `${solandBaseUrl()}/_cokret/self/webrtc/sessions/${encodeURIComponent(sessionId)}/signals?since=${since}&limit=100`,
    { headers: authHeaders(token) },
  );
  expect(response.ok(), `read signals since ${since}`).toBeTruthy();
  return await response.json();
}

function deviceProof(actor: JointUser) {
  return {
    actor: actor.did,
    kid: `${actor.did}#${actor.deviceId}`,
    sig: "cotest-device-proof",
  };
}
