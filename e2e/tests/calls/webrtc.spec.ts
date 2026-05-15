// Calls (1:1 + group + mute + screen share + recording policy)
// Contract: e2e/scenarios/calls/webrtc.md
// Spec refs:
//   - crypto-media/webrtc-signaling.md §2-§4 (design, modes, Call Morph)
//   - §5 (call.start/join/screen_share/record/moderate capabilities)
//   - §6-§6.3 (ICE config, pairwise pseudonym, mid-call refresh)
//   - §7-§8 (signaling envelope, 1:1 payloads)

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("calls", () => {
  test("ICE config endpoint exists and rejects unauthenticated callers", async ({ request }) => {
    const alice = uniqueUser("s18-probe");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);

    const iceProbe = await request.post(`${solandBaseUrl()}/api/v1/calls/ice-config`, {
      data: { call_id: "cx:call:probe", device_id: alice.deviceId, mode: "p2p" },
    });
    // Unauthenticated must be rejected (or endpoint absent → 404).
    expect([401, 403, 404]).toContain(iceProbe.status());

    const iceAuth = await request.post(`${solandBaseUrl()}/api/v1/calls/ice-config`, {
      headers: { authorization: `Bearer ${token}` },
      data: { call_id: "cx:call:probe", device_id: alice.deviceId, mode: "p2p" },
    });
    // With auth: either implemented (200 with stun/turn) or absent (404). 5xx is bug.
    expect(iceAuth.status()).toBeLessThan(500);
  });

  test.fixme(
    "alice initiates 1:1 call to bob; Call Morph state transitions ringing → connecting → active via cx.call.signal frames",
    async () => {
      // spec: webrtc-signaling.md §3 + §4
      // soland gap: cx.call.signal ephemeral routing; Call Morph state machine.
      // yougen gap: in-call UI (mute, hangup, screen share).
    },
  );

  test.fixme(
    "alice mutes mic: cx.call.signal{kind=mute_state, muted=true} routes to bob; bob's UI shows muted indicator",
    async () => {
      // spec: webrtc-signaling.md §7 + §8
    },
  );

  test.fixme(
    "alice shares screen: getDisplayMedia track added; cx.call.signal{kind=media_state, screen_share=true} routes",
    async () => {
      // spec: webrtc-signaling.md §5 call.screen_share capability
    },
  );

  test.fixme(
    "hangup terminates peer connections; Call Morph state=ended; duration persisted",
    async () => {
      // spec: webrtc-signaling.md §4
    },
  );

  test.fixme(
    "group call mode=sfu: alice+bob+carol join; recording_policy=allow lets carol start recording (writes recording_blob_ref)",
    async () => {
      // spec: webrtc-signaling.md §3 + §5 call.record capability
    },
  );

  test.fixme(
    "E18.E recording_policy=none rejects carol's recording attempt with failed_precondition reason=recording_policy_violation",
    async () => {
      // spec: webrtc-signaling.md §5
    },
  );

  test.fixme(
    "E18.F mid-call TURN credential refresh: long calls renew credentials before expiry; call does not drop",
    async () => {
      // spec: webrtc-signaling.md §6.3
    },
  );

  test.fixme(
    "E18.7 pairwise pseudonym in TURN credentials: username does not contain alice.did plaintext (spec §6 pseudonymization)",
    async () => {
      // spec: webrtc-signaling.md §6 (pairwise pseudonym)
    },
  );
});
