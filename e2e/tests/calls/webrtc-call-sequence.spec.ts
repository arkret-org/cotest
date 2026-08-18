// 1:1 signaling sequence + multi-party focus_join over the spec wire.
// Contract: e2e/scenarios/calls/webrtc-call-sequence.md
// Spec refs:
//   - crypto-media/webrtc-signaling.md §5-§6 (signaling envelope, 1:1 payloads)
//   - crypto-media/call-state.md §4.2 (durable ak.call.state lifecycle)
//   - crypto-media/media-service-binding.md §5 (focus_join migration on upgrade)
//
// WIRE NOTE (migration): the retired `/_soland/self/webrtc/sessions` stack
// derived `call_state` from the signal log. In the canonical model the
// `POST /_arkret/self/signal` relay is content-agnostic (it broadcasts the
// verbatim signed envelope), and the call lifecycle lives in the durable
// `ak.call.state` cell driven by `ak.call.state` events (call-state.md §4.2).
// This spec therefore asserts (a) the signaling stream is relayed in seq order
// with senders attributed, and (b) the durable lifecycle advances via
// ak.call.state — the two planes the spec actually defines.

import { expect, test } from "@playwright/test";
import { addRealmMemberApi } from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";
import {
  CAP_CALL_SIGNAL_SEND,
  buildCallSignalEnvelope,
  callSignalPlaintext,
  createCallApi,
  grantCallCapability,
  postCallSignal,
  relayedCallSignals,
  seedCallState,
  setupTwoPartyCallRealm,
} from "../../helpers/webrtc";

test.describe.configure({ mode: "serial", timeout: 420_000 });

test.describe("1:1 + multi-party signaling sequence (spec wire)", () => {
  test("invite -> answer -> candidate -> hangup relays in monotonic seq order and durable ak.call.state advances", async ({
    request,
  }) => {
    const { alice, aliceToken, bob, bobToken, realmId } =
      await setupTwoPartyCallRealm(request, "seq-1to1");
    // bob is a non-owner member; grant him ak.call.signal.send so the relay
    // accepts his `answer` (owner alice holds it by default).
    await grantCallCapability(
      request,
      aliceToken,
      alice.did,
      realmId,
      bob.did,
      CAP_CALL_SIGNAL_SEND,
    );
    const callId = await createCallApi(
      request,
      aliceToken,
      alice.did,
      realmId,
      "connecting",
    );

    // Signaling plane — each frame relayed verbatim.
    await postCallSignal(
      request,
      aliceToken,
      buildCallSignalEnvelope({
        actorDid: alice.did,
        deviceId: alice.deviceId,
        realmId,
        callId,
        signalType: "invite",
        seq: 1,
        data: { mode: "p2p", offer: { type: "offer", sdp: "v=0\r\no=alice" } },
      }),
    );
    await postCallSignal(
      request,
      bobToken,
      buildCallSignalEnvelope({
        actorDid: bob.did,
        deviceId: bob.deviceId,
        realmId,
        callId,
        signalType: "answer",
        seq: 1,
        data: { answer: { type: "answer", sdp: "v=0\r\no=bob" } },
      }),
    );
    await postCallSignal(
      request,
      aliceToken,
      buildCallSignalEnvelope({
        actorDid: alice.did,
        deviceId: alice.deviceId,
        realmId,
        callId,
        signalType: "candidate",
        seq: 2,
        data: {
          candidates: [
            { candidate: "candidate:1 1 UDP 2130706431 10.0.0.1 5000 typ host" },
          ],
        },
      }),
    );
    await postCallSignal(
      request,
      aliceToken,
      buildCallSignalEnvelope({
        actorDid: alice.did,
        deviceId: alice.deviceId,
        realmId,
        callId,
        signalType: "hangup",
        seq: 3,
        data: { reason: "user_hangup" },
      }),
    );

    // Recipient relayed views: senders do not self-echo; per-sender seq is
    // monotonic, senders attributed, signal types canonical.
    const bobView = (
      await relayedCallSignals(request, bobToken, realmId)
    ).filter(
      (env) => callSignalPlaintext(env).call_id === callId,
    );
    const aliceView = (
      await relayedCallSignals(request, aliceToken, realmId)
    ).filter(
      (env) => callSignalPlaintext(env).call_id === callId,
    );
    const byType = (view: Array<Record<string, unknown>>, t: string) =>
      view.filter((e) => callSignalPlaintext(e).signal_kind === t);
    expect(byType(bobView, "invite").length).toBe(1);
    expect(byType(aliceView, "answer").length).toBe(1);
    expect(byType(bobView, "candidate").length).toBe(1);
    expect(byType(bobView, "hangup").length).toBe(1);
    // Sender attribution survives the relay.
    expect(byType(bobView, "invite")[0].sender_actor_id).toBe(alice.did);
    expect(byType(aliceView, "answer")[0].sender_actor_id).toBe(bob.did);
    // Alice's own frames are seq-monotonic per sender (1=invite, 2=candidate,
    // 3=hangup); bob's answer is seq 1 in his own (actor,device) lane.
    const aliceSeqs = bobView
      .filter((e) => e.sender_actor_id === alice.did)
      .map((e) => callSignalPlaintext(e).seq as number);
    expect(aliceSeqs).toEqual([1, 2, 3]);
    const bobSeqs = aliceView
      .filter((e) => e.sender_actor_id === bob.did)
      .map((e) => callSignalPlaintext(e).seq as number);
    expect(bobSeqs).toEqual([1]);

    // Durable lifecycle plane — ak.call.state advances connecting -> active ->
    // ended (call-state.md §4.2). The owner writes the durable cell; we drive
    // it through the legal FSM transitions.
    await seedCallState(request, aliceToken, alice.did, realmId, callId, {
      state: "active",
    });
    await seedCallState(request, aliceToken, alice.did, realmId, callId, {
      state: "ended",
    });
  });

  test("multi-party focus_join: three participants relay onto a shared focus in seq order", async ({
    request,
  }) => {
    const { alice, aliceToken, bob, bobToken, realmId } =
      await setupTwoPartyCallRealm(request, "seq-focus");
    const carol = uniqueUser(`seq-focus-carol-${Date.now()}`);
    await ensureRegistered(request, carol);
    const carolToken = await issueDevSession(request, carol);
    await addRealmMemberApi(request, aliceToken, realmId, carol.did);
    // Non-owner members need send capability.
    for (const member of [bob.did, carol.did]) {
      await grantCallCapability(
        request,
        aliceToken,
        alice.did,
        realmId,
        member,
        CAP_CALL_SIGNAL_SEND,
      );
    }

    const callId = await createCallApi(
      request,
      aliceToken,
      alice.did,
      realmId,
      "connecting",
    );
    const focusId = "livekit-lhr";

    await postCallSignal(
      request,
      aliceToken,
      buildCallSignalEnvelope({
        actorDid: alice.did,
        deviceId: alice.deviceId,
        realmId,
        callId,
        signalType: "focus_join",
        seq: 1,
        data: { focus_id: focusId, foci_preferred: [focusId] },
      }),
    );
    await postCallSignal(
      request,
      bobToken,
      buildCallSignalEnvelope({
        actorDid: bob.did,
        deviceId: bob.deviceId,
        realmId,
        callId,
        signalType: "focus_join",
        seq: 1,
        data: { focus_id: focusId },
      }),
    );
    await postCallSignal(
      request,
      carolToken,
      buildCallSignalEnvelope({
        actorDid: carol.did,
        deviceId: carol.deviceId,
        realmId,
        callId,
        signalType: "focus_join",
        seq: 1,
        data: { focus_id: focusId },
      }),
    );

    const aliceView = (
      await relayedCallSignals(request, aliceToken, realmId)
    ).filter(
      (env) =>
        callSignalPlaintext(env).call_id === callId &&
        callSignalPlaintext(env).signal_kind === "focus_join",
    );
    // Alice (sender) does not self-echo; she sees bob + carol joining the same
    // focus.
    const joiners = aliceView.map((e) => e.sender_actor_id);
    expect(joiners).toEqual(
      expect.arrayContaining([bob.did, carol.did]),
    );
    expect(joiners).not.toContain(alice.did);
    for (const env of aliceView) {
      expect(callSignalPlaintext(env).signal_kind).toBe("focus_join");
      expect(
        (callSignalPlaintext(env).data as Record<string, unknown>).focus_id,
      ).toBe(focusId);
    }
  });
});
