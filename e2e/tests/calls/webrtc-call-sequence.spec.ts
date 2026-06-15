// 1:1 signaling sequence (invite/answer/candidate/hangup, monotonic seq) plus
// multi-party focus_join migration.
// Contract: e2e/scenarios/calls/webrtc-call-sequence.md
// Spec refs:
//   - crypto-media/webrtc-signaling.md §5-§6 (signaling envelope, 1:1 payloads)
//   - crypto-media/call-state.md §4.2 (Call Morph transitions)
//   - crypto-media/media-service-binding.md §5 (focus_join migration on upgrade)

import { expect, test, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  addRealmMemberApi,
  authHeaders,
  createRealmApi,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
  type JointUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("1:1 + multi-party signaling sequence", () => {
  test(
    "invite -> answer -> candidate -> hangup keeps a strictly monotonic seq and drives Call Morph",
    async ({ request }) => {
      const { alice, aliceToken, bob, bobToken, realmId } =
        await setupCallRealm(request, "seq-1to1");
      const callId = await createSession(request, aliceToken, realmId, [
        bob.did,
      ]);

      const invite = await appendSignal(
        request,
        aliceToken,
        callId,
        alice,
        "invite",
        { sdp: "v=0\r\no=alice", target: bob.did },
      );
      expect(invite.seq).toBe(1);
      expect(invite.call_state).toBe("connecting");

      const answer = await appendSignal(request, bobToken, callId, bob, "answer", {
        sdp: "v=0\r\no=bob",
        target: alice.did,
      });
      expect(answer.seq).toBe(2);
      expect(answer.call_state).toBe("active");

      const candidate = await appendSignal(
        request,
        aliceToken,
        callId,
        alice,
        "candidate",
        { candidate: "candidate:1 1 UDP 2130706431 10.0.0.1 5000 typ host" },
      );
      expect(candidate.seq).toBe(3);
      // Ephemeral status signals do not regress the lifecycle.
      expect(candidate.call_state).toBe("active");

      const hangup = await appendSignal(
        request,
        aliceToken,
        callId,
        alice,
        "hangup",
        { reason: "user_hangup" },
      );
      expect(hangup.seq).toBe(4);
      expect(hangup.call_state).toBe("ended");

      // Full log read-back: seq is dense + monotonic, senders attributed.
      const events = await readSignals(request, bobToken, callId);
      expect(events.map((event) => event.seq)).toEqual([1, 2, 3, 4]);
      expect(events.map((event) => event.type)).toEqual([
        "invite",
        "answer",
        "candidate",
        "hangup",
      ]);
      expect(events[0].sender).toBe(alice.did);
      expect(events[1].sender).toBe(bob.did);
    },
  );

  test(
    "multi-party focus_join: three participants migrate onto a shared focus in seq order",
    async ({ request }) => {
      const { alice, aliceToken, bob, bobToken, realmId } =
        await setupCallRealm(request, "seq-focus");
      const carol = uniqueUser(`seq-focus-carol-${Date.now()}`);
      await ensureRegistered(request, carol);
      const carolToken = await issueDevSession(request, carol);
      await addRealmMemberApi(request, aliceToken, realmId, carol.did);

      const callId = await createSession(request, aliceToken, realmId, [
        bob.did,
        carol.did,
      ]);
      const focusId = "ck:focus:livekit-lhr";

      const aliceJoin = await appendSignal(
        request,
        aliceToken,
        callId,
        alice,
        "focus_join",
        { focus_id: focusId, foci_preferred: [focusId] },
      );
      expect(aliceJoin.seq).toBe(1);

      const bobJoin = await appendSignal(
        request,
        bobToken,
        callId,
        bob,
        "focus_join",
        { focus_id: focusId },
      );
      expect(bobJoin.seq).toBe(2);

      const carolJoin = await appendSignal(
        request,
        carolToken,
        callId,
        carol,
        "focus_join",
        { focus_id: focusId },
      );
      expect(carolJoin.seq).toBe(3);

      const events = await readSignals(request, aliceToken, callId);
      const joiners = events
        .filter((event) => event.type === "focus_join")
        .map((event) => event.sender);
      expect(joiners).toEqual([alice.did, bob.did, carol.did]);
      for (const event of events) {
        expect((event.payload as Record<string, unknown>).focus_id).toBe(
          focusId,
        );
      }
    },
  );
});

async function setupCallRealm(request: APIRequestContext, label: string) {
  const stamp = Date.now();
  const alice = uniqueUser(`${label}-alice-${stamp}`);
  const bob = uniqueUser(`${label}-bob-${stamp}`);
  await Promise.all([
    ensureRegistered(request, alice),
    ensureRegistered(request, bob),
  ]);
  const aliceToken = await issueDevSession(request, alice);
  const bobToken = await issueDevSession(request, bob);
  const realmId = await createRealmApi(request, aliceToken, {
    title: `${label} ${stamp}`,
    public: true,
  });
  await addRealmMemberApi(request, aliceToken, realmId, bob.did);
  return { alice, aliceToken, bob, bobToken, realmId };
}

async function createSession(
  request: APIRequestContext,
  token: string,
  realmId: string,
  participants: string[],
): Promise<string> {
  const response = await request.post(
    `${solandBaseUrl()}/_soland/self/webrtc/sessions`,
    {
      headers: authHeaders(token),
      data: { realm_id: realmId, participants, ttl_ms: 120_000 },
    },
  );
  expect(response.status(), await response.text()).toBe(200);
  return (await response.json()).session_id as string;
}

async function appendSignal(
  request: APIRequestContext,
  token: string,
  callId: string,
  actor: JointUser,
  messageType: string,
  payload: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const response = await request.post(
    `${solandBaseUrl()}/_soland/self/webrtc/sessions/${encodeURIComponent(callId)}/signals`,
    {
      headers: authHeaders(token),
      data: {
        message_type: messageType,
        payload,
        proofs: [
          {
            actor: actor.did,
            kid: `${actor.did}#${actor.deviceId}`,
            sig: "cotest-device-proof",
          },
        ],
      },
    },
  );
  expect(response.status(), `append ${messageType}`).toBe(200);
  return (await response.json()) as Record<string, unknown>;
}

async function readSignals(
  request: APIRequestContext,
  token: string,
  callId: string,
): Promise<Array<Record<string, unknown>>> {
  const response = await request.get(
    `${solandBaseUrl()}/_soland/self/webrtc/sessions/${encodeURIComponent(callId)}/signals?since=0&limit=100`,
    { headers: authHeaders(token) },
  );
  expect(response.status()).toBe(200);
  return (await response.json()).events as Array<Record<string, unknown>>;
}
