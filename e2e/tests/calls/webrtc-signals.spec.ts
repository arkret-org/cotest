// WebRTC signal-type coverage over the spec wire.
// Contract: e2e/scenarios/calls/webrtc-signals.md
// Spec refs:
//   - crypto-media/webrtc-signaling.md §5 / §5.1 (ephemeral envelope + proof,
//     canonical 14-value signal_kind enum)
//   - service-http-binding.md §162 (ak.call.signal.send capability on
//     POST /_arkret/self/signal)
//
// Migrated off the retired `/_soland/self/webrtc/sessions` stack: every signal
// is submitted as a real `ak.call.signal` ephemeral envelope (real ed25519
// detached-JWS proof) to `POST /_arkret/self/signal` and read back verbatim
// from `GET /_arkret/self/signal/subscribe`.

import { expect, test } from "../../helpers/arkret-test";
import {
  CALL_SIGNAL_TYPES,
  buildCallSignalEnvelope,
  callSignalPlaintext,
  newCallId,
  postCallSignal,
  relayedCallSignals,
  setupTwoPartyCallRealm,
} from "../../helpers/webrtc";

test.describe.configure({ mode: "serial" });

test.describe("ak.call.signal canonical signal catalog", () => {
  // The 14-value spec enum — `offer` / `ice` / `device_change` are NOT spec
  // signal types and MUST NOT appear here.
  test("CALL_SIGNAL_TYPES is exactly the spec 14-value enum", () => {
    expect([...CALL_SIGNAL_TYPES].sort()).toEqual(
      [
        "ack",
        "answer",
        "candidate",
        "error",
        "focus_join",
        "focus_leave",
        "hangup",
        "invite",
        "media_state",
        "moderation",
        "mute_state",
        "reject",
        "renegotiate",
        "speaking",
      ].sort(),
    );
    // Retired non-spec types must be absent.
    for (const retired of ["offer", "ice", "device_change"]) {
      expect(CALL_SIGNAL_TYPES as readonly string[]).not.toContain(retired);
    }
  });

  for (const signalType of CALL_SIGNAL_TYPES) {
    test(`${signalType} relays with canonical type + monotonic seq + valid proof`, async ({
      request,
    }) => {
      const { alice, aliceToken, bobToken, realmId } =
        await setupTwoPartyCallRealm(request, `sig-${signalType}`);
      const callId = newCallId();

      const envelope = buildCallSignalEnvelope({
        actorDid: alice.did,
        deviceId: alice.deviceId,
        realmId,
        callId,
        signalType,
        seq: 1,
        data: { fixture: "cotest-signal-catalog" },
      });

      const outcome = await postCallSignal(request, aliceToken, envelope);
      // The relay broadcasts to other realm members (bob), not the sender.
      expect(outcome.dispatched_recipient_count).toBe(1);

      // Bob receives the verbatim signed envelope (proof intact).
      const received = await relayedCallSignals(request, bobToken, realmId);
      const mine = received.filter(
        (env) => callSignalPlaintext(env).call_id === callId,
      );
      expect(mine.length, `bob receives the ${signalType} signal`).toBe(1);
      const env = mine[0];
      expect(env.sender_actor_id).toBe(alice.did);
      const payload = callSignalPlaintext(env);
      expect(payload.kind).toBe("ak.call.signal");
      // Canonical signal_kind + monotonic seq survive the relay verbatim.
      expect(CALL_SIGNAL_TYPES as readonly string[]).toContain(
        payload.signal_kind,
      );
      expect(payload.signal_kind).toBe(signalType);
      expect(payload.seq).toBe(1);
      // Proof is present and spec-shaped (§5.1 detached-JWS).
      const proof = env.proof as Record<string, unknown>;
      expect(proof, "relayed envelope carries proof verbatim").toBeTruthy();
      expect(proof.kind).toBe("detached_jws");
      expect(proof.alg).toBeUndefined();
      expect(proof.verification_method).toBe(
        `${alice.fullDid}#${alice.deviceId}`,
      );
      expect(typeof proof.envelope_digest).toBe("string");
      expect(proof.envelope_digest as string).toMatch(
        /^sha256:[0-9a-f]{64}$/,
      );
      // Detached JWS = `<protected>..<signature>` (empty payload segment).
      const jws = proof.jws as string;
      const parts = jws.split(".");
      expect(parts.length, "detached JWS header..signature").toBe(3);
      expect(parts[1], "detached JWS payload segment is empty").toBe("");
      expect(parts[0].length).toBeGreaterThan(0);
      expect(parts[2].length).toBeGreaterThan(0);

      // bob (recipient) is the only one notified; alice does not self-echo.
      const aliceEcho = (
        await relayedCallSignals(request, aliceToken, realmId)
      ).filter(
        (e) => callSignalPlaintext(e).call_id === callId,
      );
      expect(aliceEcho.length, "sender does not self-echo").toBe(0);
    });
  }
});
