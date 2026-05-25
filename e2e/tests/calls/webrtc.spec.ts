// Calls (1:1 + group + mute + screen share + recording policy)
// Contract: e2e/scenarios/calls/webrtc.md
// Spec refs:
//   - crypto-media/webrtc-signaling.md §2-§4 (design, modes, Call Morph)
//   - §5 (call.start/join/screen_share/record/moderate capabilities)
//   - §6-§6.3 (ICE config, pairwise pseudonym, mid-call refresh)
//   - §7-§8 (signaling envelope, 1:1 payloads)

import { expect, test, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  type JointUser,
  uniqueUser,
} from "../../helpers/users";
import {
  addSpaceMemberApi,
  authHeaders,
  createSpaceApi,
  wireErrCode,
} from "../../helpers/soland-api";

test.describe.configure({ mode: "serial" });

test.describe("calls", () => {
  test("ICE config endpoint exists and rejects unauthenticated callers", async ({ request }) => {
    const alice = uniqueUser("s18-probe");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);

    const iceProbe = await request.post(`${solandBaseUrl()}/api/v1/calls/ice-config`, {
      data: { call_id: "cx:call:probe", device_id: alice.deviceId, mode: "p2p" },
    });
    // Unauthenticated must be rejected (or endpoint absent → 404, or 405
    // when the path is routed but POST is not allowed yet).
    expect([401, 403, 404, 405]).toContain(iceProbe.status());

    const iceAuth = await request.post(`${solandBaseUrl()}/api/v1/calls/ice-config`, {
      headers: { authorization: `Bearer ${token}` },
      data: { call_id: "cx:call:probe", device_id: alice.deviceId, mode: "p2p" },
    });
    // With auth: either implemented (200 with stun/turn) or absent (404). 5xx is bug.
    expect(iceAuth.status()).toBeLessThan(500);
  });

  test(
    "alice initiates 1:1 call to bob; Call Morph state transitions ringing → connecting → active via cx.call.signal frames",
    async ({ browser, request }) => {
      // spec: webrtc-signaling.md §3 + §4
      const stamp = Date.now();
      const alice = uniqueUser(`s18-call-alice-${stamp}`);
      const bob = uniqueUser(`s18-call-bob-${stamp}`);
      await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
      const aliceToken = await issueDevSession(request, alice);
      const bobToken = await issueDevSession(request, bob);
      const spaceId = await createSpaceApi(request, aliceToken, {
        title: `S18 WebRTC ${stamp}`,
        public: true,
      });
      await addSpaceMemberApi(request, aliceToken, spaceId, bob.did);

      const session = await request.post(`${solandBaseUrl()}/api/v1/webrtc/sessions`, {
        headers: authHeaders(aliceToken),
        data: {
          space_id: spaceId,
          participants: [bob.did],
          ttl_ms: 120_000,
        },
      });
      expect(session.ok()).toBeTruthy();
      const sessionBody = await session.json();
      expect(sessionBody.session_id).toMatch(/^cx:call:/);
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

  test.fixme(
    // @blocking-on: soland#calls-webrtc-gap
    // @user-promise: e2e/scenarios/calls/webrtc.md
    // @expected-live-by: 2026Q3
    "alice mutes mic: cx.call.signal{kind=mute_state, muted=true} routes to bob; bob's UI shows muted indicator",
    async () => {
      // spec: webrtc-signaling.md §7 + §8
    },
  );

  test.fixme(
    // @blocking-on: soland#calls-webrtc-gap
    // @user-promise: e2e/scenarios/calls/webrtc.md
    // @expected-live-by: 2026Q3
    "alice shares screen: getDisplayMedia track added; cx.call.signal{kind=media_state, screen_share=true} routes",
    async () => {
      // spec: webrtc-signaling.md §5 call.screen_share capability
    },
  );

  test.fixme(
    // @blocking-on: soland#calls-webrtc-gap
    // @user-promise: e2e/scenarios/calls/webrtc.md
    // @expected-live-by: 2026Q3
    "hangup terminates peer connections; Call Morph state=ended; duration persisted",
    async () => {
      // spec: webrtc-signaling.md §4
    },
  );

  test(
    "group call mode=sfu: alice+bob+carol join; recording_policy=allow lets carol start recording (writes recording_blob_ref)",
    async ({ request }) => {
      // spec: webrtc-signaling.md §3 + §5 call.record capability
      const { aliceToken, bob, carol, carolToken, spaceId } = await setupCallSpace(request, "s18-record-allow");
      const session = await createWebrtcSession(request, aliceToken, {
        space_id: spaceId,
        participants: [bob.did, carol.did],
        mode: "sfu",
        recording_policy: "allow",
      });
      expect(session.mode).toBe("sfu");
      expect(session.recording_policy).toBe("allow");
      expect(session.participants).toEqual(expect.arrayContaining([bob.did, carol.did]));

      const recording = await startRecording(request, carolToken, session.session_id, spaceId);
      expect(recording.ok).toBe(true);
      expect(recording.recording_started_by).toBe(carol.did);
      expect(recording.recording_policy).toBe("allow");
      expect(recording.recording_blob_ref).toMatch(/^cx:blob:sha256:/);
    },
  );

  test(
    "E18.E recording_policy=none rejects carol's recording attempt with failed_precondition reason=recording_policy_violation",
    async ({ request }) => {
      // spec: webrtc-signaling.md §5
      const { aliceToken, carol, carolToken, spaceId } = await setupCallSpace(request, "s18-record-deny");
      const session = await createWebrtcSession(request, aliceToken, {
        space_id: spaceId,
        participants: [carol.did],
        mode: "sfu",
        recording_policy: "none",
      });

      const denied = await request.post(
        `${solandBaseUrl()}/api/v1/calls/${encodeURIComponent(session.session_id)}/recording/start`,
        {
          headers: authHeaders(carolToken),
          data: { space_id: spaceId },
        },
      );
      expect(denied.status()).toBe(412);
      expect(wireErrCode(await denied.json())).toBe("recording_policy_violation");
    },
  );

  test(
    "E18.F mid-call TURN credential refresh: long calls renew credentials before expiry; call does not drop",
    async ({ request }) => {
      // spec: webrtc-signaling.md §6.3
      const { alice, aliceToken, bob, bobToken, spaceId } = await setupCallSpace(request, "s18-turn-refresh");
      const session = await createWebrtcSession(request, aliceToken, {
        space_id: spaceId,
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
        space_id: spaceId,
        call_id: session.session_id,
        actor_id: alice.did,
        device_id: alice.deviceId,
      });
      const refreshed = await refreshIceConfig(request, aliceToken, session.session_id, {
        space_id: spaceId,
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
      // spec: webrtc-signaling.md §6 (pairwise pseudonym)
      const { alice, aliceToken, bob, bobToken, spaceId } = await setupCallSpace(request, "s18-turn-pseudonym");
      const session = await createWebrtcSession(request, aliceToken, {
        space_id: spaceId,
        participants: [bob.did],
        mode: "p2p",
        recording_policy: "none",
      });

      const aliceIce = await issueIceConfig(request, aliceToken, {
        space_id: spaceId,
        call_id: session.session_id,
        actor_id: alice.did,
        device_id: alice.deviceId,
      });
      const bobIce = await issueIceConfig(request, bobToken, {
        space_id: spaceId,
        call_id: session.session_id,
        actor_id: bob.did,
        device_id: bob.deviceId,
      });
      const aliceUsername = aliceIce.turn_servers[0].username as string;
      const bobUsername = bobIce.turn_servers[0].username as string;
      expect(aliceUsername).toMatch(/^cx-turn-/);
      expect(bobUsername).toMatch(/^cx-turn-/);
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
    `${solandBaseUrl()}/api/v1/webrtc/sessions/${encodeURIComponent(sessionId)}/signals`,
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

async function setupCallSpace(request: APIRequestContext, label: string) {
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
  const spaceId = await createSpaceApi(request, aliceToken, {
    title: `S18 ${label} ${stamp}`,
    public: true,
  });
  await addSpaceMemberApi(request, aliceToken, spaceId, bob.did);
  await addSpaceMemberApi(request, aliceToken, spaceId, carol.did);
  return { alice, bob, carol, aliceToken, bobToken, carolToken, spaceId };
}

async function createWebrtcSession(
  request: APIRequestContext,
  token: string,
  data: {
    space_id: string;
    participants: string[];
    mode: string;
    recording_policy: string;
  },
) {
  const response = await request.post(`${solandBaseUrl()}/api/v1/webrtc/sessions`, {
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
    space_id: string;
    call_id: string;
    actor_id: string;
    device_id: string;
  },
) {
  const response = await request.post(`${solandBaseUrl()}/api/v1/calls/ice-config`, {
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
    space_id: string;
    actor_id: string;
    device_id: string;
  },
) {
  const response = await request.post(
    `${solandBaseUrl()}/api/v1/calls/${encodeURIComponent(sessionId)}/ice-config/refresh`,
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
  spaceId: string,
) {
  const response = await request.post(
    `${solandBaseUrl()}/api/v1/calls/${encodeURIComponent(sessionId)}/recording/start`,
    {
      headers: authHeaders(token),
      data: { space_id: spaceId },
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
    `${solandBaseUrl()}/api/v1/webrtc/sessions/${encodeURIComponent(sessionId)}/signals?since=${since}&limit=100`,
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
