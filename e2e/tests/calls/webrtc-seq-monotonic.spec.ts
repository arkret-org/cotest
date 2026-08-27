// WebRTC seq monotonicity over the spec wire.
// Contract: e2e/scenarios/calls/webrtc-seq-monotonic.md
// Spec refs:
//   - crypto-media/webrtc-signaling.md §5.1 (seq monotonic per
//     (realm_id, call_id, actor_id, device_id); receiver MUST reject rollback)
//
// WIRE NOTE (migration): the retired `/_soland/self/webrtc/sessions` stack
// assigned + enforced `seq` server-side. The canonical
// `POST /_arkret/self/signal` relay is content-agnostic: it broadcasts the
// verbatim signed envelope and the *receiver* enforces seq monotonicity (§5.1
// assigns rollback rejection to the receiver, not the relay — see
// `arkret_sdk::validate_signal_seq` / `CallSignalState`). So the relay delivers
// every frame (including a rollback) verbatim with its `seq` intact, and the
// receiver-side rollback rejection is pinned by the Rust conformance vector
// `ak.vector.call_signal.seq_monotonic.v1` (src/conformance/call_signal.rs).

import { expect, test } from "../../helpers/arkret-test";
import {
  buildCallSignalEnvelope,
  callSignalPlaintext,
  newCallId,
  postCallSignal,
  relayedCallSignals,
  setupTwoPartyCallRealm,
} from "../../helpers/webrtc";

test.describe.configure({ mode: "serial" });

test.describe("ak.call.signal seq monotonicity (spec wire)", () => {
  test("relay preserves each frame's seq verbatim so the receiver can enforce monotonicity", async ({
    request,
  }) => {
    const { alice, aliceToken, bobToken, realmId } = await setupTwoPartyCallRealm(
      request,
      "seq-mono",
    );
    const callId = newCallId();

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
        data: { sdp: "v=0" },
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
        data: { sdp: "v=0" },
      }),
    );

    // A rollback frame (seq=1 after seq=2) is *relayed* verbatim — the receiver,
    // not the relay, rejects it. Assert the relay accepted it AND that the
    // verbatim seq=1 is what lands, so a receiver running validate_signal_seq
    // observes the rollback and can drop it.
    await postCallSignal(
      request,
      aliceToken,
      buildCallSignalEnvelope({
        actorDid: alice.did,
        deviceId: alice.deviceId,
        realmId,
        callId,
        signalType: "candidate",
        seq: 1,
        data: { candidate: "rollback" },
      }),
    );

    const received = (
      await relayedCallSignals(request, bobToken, realmId)
    ).filter(
      (env) => callSignalPlaintext(env).call_id === callId,
    );
    // All three frames are delivered verbatim; the receiver sees the seq
    // sequence [1, 2, 1] and its monotonicity guard rejects the trailing 1.
    const seqs = received.map(
      (env) => callSignalPlaintext(env).seq as number,
    );
    expect(seqs).toEqual([1, 2, 1]);
    expect(applyReceiverSeqGuard(seqs)).toEqual({
      accepted: [1, 2],
      rejected: [1],
    });
  });

  test("monotonic ascending seq is fully accepted by the receiver guard", async ({
    request,
  }) => {
    const { alice, aliceToken, bobToken, realmId } = await setupTwoPartyCallRealm(
      request,
      "seq-asc",
    );
    const callId = newCallId();

    for (let seq = 1; seq <= 4; seq += 1) {
      await postCallSignal(
        request,
        aliceToken,
        buildCallSignalEnvelope({
          actorDid: alice.did,
          deviceId: alice.deviceId,
          realmId,
          callId,
          signalType: seq === 1 ? "invite" : "renegotiate",
          seq,
          data: { sdp: "v=0" },
        }),
      );
    }

    const received = (
      await relayedCallSignals(request, bobToken, realmId)
    ).filter(
      (env) => callSignalPlaintext(env).call_id === callId,
    );
    const seqs = received.map(
      (env) => callSignalPlaintext(env).seq as number,
    );
    expect(seqs).toEqual([1, 2, 3, 4]);
    expect(applyReceiverSeqGuard(seqs)).toEqual({
      accepted: [1, 2, 3, 4],
      rejected: [],
    });
  });
});

// Receiver-side seq monotonicity guard, mirroring
// `arkret_sdk::validate_signal_seq`: `prev = None` accepts any `next`; a
// `next <= prev` is a rollback the receiver MUST drop. This is the same rule
// the Rust conformance vector pins; here it documents how a real receiver
// processes the relayed (verbatim) stream.
function applyReceiverSeqGuard(seqs: number[]): {
  accepted: number[];
  rejected: number[];
} {
  let prev: number | undefined;
  const accepted: number[] = [];
  const rejected: number[] = [];
  for (const seq of seqs) {
    if (prev === undefined || seq > prev) {
      accepted.push(seq);
      prev = seq;
    } else {
      rejected.push(seq);
    }
  }
  return { accepted, rejected };
}
