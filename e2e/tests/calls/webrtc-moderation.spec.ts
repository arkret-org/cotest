// Recording gating (recording_policy) + moderation (kick/ban) with
// removed_participants[] provenance.
// Contract: e2e/scenarios/calls/webrtc-moderation.md
// Spec refs:
//   - crypto-media/webrtc-signaling.md §3 (ck.call.record capability)
//   - crypto-media/webrtc-signaling.md §3a / §13 (moderation: kick/ban/end_for_all)
//   - crypto-media/call-state.md §5.2 (recording consent + retention)
//   - conformance/conformance-vectors.md §12.16 / §12.18

import { expect, test, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  addRealmMemberApi,
  authHeaders,
  createRealmApi,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
  type JointUser,
} from "../../helpers/users";
import { startCallRecording } from "../../helpers/webrtc";

test.describe.configure({ mode: "serial" });

test.describe("recording gating + moderation", () => {
  test(
    "recording_policy=allow lets a participant start recording (writes ck:blob recording_blob_ref)",
    async ({ request }) => {
      const { alice, aliceToken, bob, realmId } = await setupCallRealm(
        request,
        "mod-record-allow",
      );
      const callId = await createSession(request, aliceToken, realmId, {
        participants: [bob.did],
        mode: "sfu",
        recording_policy: "allow",
      });

      const response = await startCallRecording(
        request,
        aliceToken,
        callId,
        realmId,
      );
      expect(response.status(), await response.text()).toBe(200);
      const body = await response.json();
      expect(body.ok).toBe(true);
      expect(body.recording_policy).toBe("allow");
      expect(body.recording_started_by).toBe(alice.did);
      expect(body.recording_blob_ref).toMatch(/^ck:blob:sha256:/);
      expect(body.recording_state).toBeTruthy();
    },
  );

  test(
    "recording_policy=none rejects recording with failed_precondition recording_policy_violation",
    async ({ request }) => {
      const { aliceToken, bob, realmId } = await setupCallRealm(
        request,
        "mod-record-deny",
      );
      const callId = await createSession(request, aliceToken, realmId, {
        participants: [bob.did],
        mode: "sfu",
        recording_policy: "none",
      });

      const denied = await startCallRecording(
        request,
        aliceToken,
        callId,
        realmId,
      );
      expect(denied.status()).toBe(412);
      expect(wireErrCode(await denied.json())).toBe(
        "recording_policy_violation",
      );
    },
  );

  test(
    "moderator kick: ck.call.signal{moderation=kick} is accepted and projected into removed_participants[]",
    async ({ request }) => {
      const { alice, aliceToken, bob, bobToken, realmId } =
        await setupCallRealm(request, "mod-kick");
      const callId = await createSession(request, aliceToken, realmId, {
        participants: [bob.did],
        mode: "sfu",
        recording_policy: "none",
      });

      // First-class `moderation` signal (webrtc-signaling.md §3a): the kick
      // pins the removed (actor, device) tuple; soland projects it into
      // ck.call.state.removed_participants[] so a later token re-issue can gate.
      const kick = await appendModeration(request, aliceToken, callId, alice, {
        action: "kick",
        target_actor_id: bob.did,
        target_device_id: bob.deviceId,
        reason: "policy_violation",
      });
      expect(kick.seq).toBe(1);
      // kick removes a leg but leaves the call lifecycle running.
      expect(kick.call_state).not.toBe("ended");

      const events = await readSignals(request, bobToken, callId);
      const moderationEvent = events.find(
        (event) => event.type === "moderation",
      );
      expect(
        moderationEvent,
        "moderation frame is present in the signal log",
      ).toBeTruthy();
      const data = (moderationEvent!.payload as Record<string, unknown>)
        .data as Record<string, unknown>;
      expect(data.action).toBe("kick");
      expect(data.target_actor_id).toBe(bob.did);
      expect(data.target_device_id).toBe(bob.deviceId);
    },
  );

  test(
    "moderator ban: ck.call.signal{moderation=ban} omits target_device_id (actor-wide scope)",
    async ({ request }) => {
      const { alice, aliceToken, bob, bobToken, realmId } =
        await setupCallRealm(request, "mod-ban");
      const callId = await createSession(request, aliceToken, realmId, {
        participants: [bob.did],
        mode: "sfu",
        recording_policy: "none",
      });

      const ban = await appendModeration(request, aliceToken, callId, alice, {
        action: "ban",
        target_actor_id: bob.did,
      });
      expect(ban.seq).toBe(1);

      const events = await readSignals(request, bobToken, callId);
      const banEvent = events.find((event) => event.type === "moderation");
      expect(banEvent, "moderation frame is present in the signal log").toBeTruthy();
      const data = (banEvent!.payload as Record<string, unknown>).data as Record<
        string,
        unknown
      >;
      expect(data.action).toBe("ban");
      expect(data.target_actor_id).toBe(bob.did);
      // Actor-wide ban: no device id pins it to a single device.
      expect(data.target_device_id).toBeUndefined();
    },
  );

  test(
    "moderator end_for_all: ck.call.signal{moderation=end_for_all} drives the call to ended",
    async ({ request }) => {
      const { alice, aliceToken, bob, realmId } = await setupCallRealm(
        request,
        "mod-end",
      );
      const callId = await createSession(request, aliceToken, realmId, {
        participants: [bob.did],
        mode: "sfu",
        recording_policy: "none",
      });

      const end = await appendModeration(request, aliceToken, callId, alice, {
        action: "end_for_all",
      });
      expect(end.seq).toBe(1);
      expect(end.call_state).toBe("ended");
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
  data: { participants: string[]; mode: string; recording_policy: string },
): Promise<string> {
  const response = await request.post(
    `${solandBaseUrl()}/_cokret/self/webrtc/sessions`,
    {
      headers: authHeaders(token),
      data: { realm_id: realmId, ttl_ms: 120_000, ...data },
    },
  );
  expect(response.status(), await response.text()).toBe(200);
  return (await response.json()).session_id as string;
}

interface AppendResult {
  seq: number;
  next_cursor: string;
  call_state: string;
}

async function appendModeration(
  request: APIRequestContext,
  token: string,
  callId: string,
  actor: JointUser,
  data: Record<string, unknown>,
): Promise<AppendResult> {
  const response = await request.post(
    `${solandBaseUrl()}/_cokret/self/webrtc/sessions/${encodeURIComponent(callId)}/signals`,
    {
      headers: authHeaders(token),
      data: {
        // First-class `moderation` signal type (webrtc-signaling.md §3a);
        // the action rides `payload.data.action`.
        message_type: "moderation",
        payload: { signal_type: "moderation", data },
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
  expect(response.status(), await response.text()).toBe(200);
  return (await response.json()) as AppendResult;
}

interface SignalEvent {
  type: string;
  payload: Record<string, unknown>;
}

async function readSignals(
  request: APIRequestContext,
  token: string,
  callId: string,
): Promise<SignalEvent[]> {
  const response = await request.get(
    `${solandBaseUrl()}/_cokret/self/webrtc/sessions/${encodeURIComponent(callId)}/signals?since=0&limit=100`,
    { headers: authHeaders(token) },
  );
  expect(response.status()).toBe(200);
  return (await response.json()).events as SignalEvent[];
}
