// WebRTC renegotiation + ICE restart over the spec wire.
// Contract: e2e/scenarios/calls/webrtc-renegotiate.md
// Spec refs:
//   - crypto-media/webrtc-signaling.md §4.1 (ICE config endpoint + signature,
//     domain label ck.media.ice_config.v1)
//   - crypto-media/webrtc-signaling.md §6.1 (renegotiate{reason:ice_restart};
//     a device switch rides a renegotiate frame, NOT the retired
//     `device_change` signal type)
//
// Migrated off `/_soland/self/webrtc/sessions` + the non-spec `device_change`
// signal type. The ICE config is fetched from `POST /_arkret/self/rtc/ice-config`
// (no prior session needed); renegotiation rides `ck.call.signal{renegotiate}`.

import { expect, test } from "@playwright/test";
import {
  buildCallSignalEnvelope,
  fetchIceConfig,
  newCallId,
  postCallSignal,
  relayedCallSignals,
  setupTwoPartyCallRealm,
} from "../../helpers/webrtc";

test.describe.configure({ mode: "serial" });

test.describe("ak.call.signal renegotiation + ICE restart", () => {
  test("signed ICE config carries the ck.media.ice_config.v1 domain label", async ({
    request,
  }) => {
    const { alice, aliceToken, realmId } = await setupTwoPartyCallRealm(
      request,
      "ice-config",
    );
    const callId = newCallId();

    const ice = await fetchIceConfig(request, aliceToken, {
      realm_id: realmId,
      call_id: callId,
      actor_id: alice.did,
      device_id: alice.deviceId,
      mode: "p2p",
    });
    expect(ice.status(), await ice.text()).toBe(200);
    const body = await ice.json();

    // §4.1 — the response echoes the request tuple (anti-cross-replay) and is
    // signed by the media service with the distinct ICE-config domain label.
    expect(body.realm_id).toBe(realmId);
    expect(body.call_id).toBe(callId);
    expect(body.actor_id).toBe(alice.did);
    expect(body.device_id).toBe(alice.deviceId);
    expect(Array.isArray(body.ice_servers)).toBe(true);
    expect(body.ice_servers.length).toBeGreaterThan(0);
    expect(typeof body.refresh_lead_seconds).toBe("number");
    expect(typeof body.ttl_seconds).toBe("number");
    // §4.1 — refresh_lead_seconds MUST be strictly less than ttl_seconds.
    expect(body.refresh_lead_seconds).toBeLessThan(body.ttl_seconds);
    expect(body.bucket_seconds).toBe(300);

    const signature = body.signature as Record<string, unknown>;
    expect(signature, "ICE config MUST be signed").toBeTruthy();
    expect(signature.alg).toBe("EdDSA");
    // The signing_input is prefixed by the spec domain label — distinct from
    // ck.media.participant_binding.v1 (media-service-binding.md §3.1).
    expect(signature.signature_input).toBe("ak.media.ice_config.v1");
    expect(signature.signature_input).not.toBe(
      "ak.media.participant_binding.v1",
    );
    expect(signature.payload_digest as string).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(typeof signature.sig).toBe("string");
    expect((signature.sig as string).length).toBeGreaterThan(0);
  });

  test("ICE restart rides renegotiate{reason:ice_restart} in seq order (no device_change)", async ({
    request,
  }) => {
    const { alice, aliceToken, bobToken, realmId } = await setupTwoPartyCallRealm(
      request,
      "ice-restart",
    );
    const callId = newCallId();

    // Establish the call leg with an invite, then a renegotiate carrying the
    // ICE restart. A device switch is expressed as a renegotiate frame; the
    // retired `device_change` signal type is no longer in the spec enum.
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
      aliceToken,
      buildCallSignalEnvelope({
        actorDid: alice.did,
        deviceId: alice.deviceId,
        realmId,
        callId,
        signalType: "renegotiate",
        seq: 2,
        data: {
          reason: "ice_restart",
          ice_restart: true,
          offer: { type: "offer", sdp: "v=0\r\no=alice-restart" },
        },
      }),
    );

    const received = (
      await relayedCallSignals(request, bobToken, realmId)
    ).filter(
      (env) => (env.payload as Record<string, unknown>)?.call_id === callId,
    );
    expect(received.map((e) => (e.payload as Record<string, unknown>).seq)).toEqual([
      1, 2,
    ]);
    const last = received[1].payload as Record<string, unknown>;
    expect(last.signal_type).toBe("renegotiate");
    expect((last.data as Record<string, unknown>).reason).toBe("ice_restart");
    // Proof intact on the relayed renegotiate frame.
    const proof = received[1].proof as Record<string, unknown>;
    expect(proof.kind).toBe("detached_jws");
    expect(proof.verification_method).toBe(`${alice.did}#${alice.deviceId}`);
  });
});
