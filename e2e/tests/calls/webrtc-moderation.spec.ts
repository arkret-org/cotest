// Call moderation (kick / ban / end_for_all) over the spec wire.
// Contract: e2e/scenarios/calls/webrtc-moderation.md
// Spec refs:
//   - crypto-media/webrtc-signaling.md §3a (moderation signal + removed_participants[])
//   - crypto-media/webrtc-signaling.md §5.1 (ephemeral relay, ck.call.signal.send gate)
//   - crypto-media/media-service-binding.md §3 (banned actor token re-issue gate)
//
// WIRE NOTE (migration): the retired `/_soland/self/webrtc/sessions` +
// `/_soland/self/calls/.../recording/start` stack is gone. Moderation now rides
// `ck.call.signal{moderation}` on `POST /_cokret/self/ephemeral`, and the
// kick/ban provenance lives in the durable `ck.call.state.removed_participants[]`
// cell. The relay is content-agnostic and gates on `ck.call.signal.send` (§162);
// the `ck.call.moderate` authorization for a moderation frame is a RECEIVER /
// reducer check (§3a: receiver and reducer MUST reject), pinned as a real
// conformance vector (`run_moderator_kick_ban_vector`, step 1 →
// call_moderation_unauthorised). The HTTP-observable moderation consequence is
// the durable ban gate: a banned actor's media-token re-exchange is refused
// with `call_participant_removed`.

import { expect, test } from "@playwright/test";
import { wireErrCode } from "../../helpers/soland-api";
import {
  CAP_CALL_JOIN,
  CAP_CALL_SIGNAL_SEND,
  buildCallSignalEnvelope,
  configureMediaService,
  exchangeMediaToken,
  grantCallCapability,
  newCallId,
  postCallSignal,
  postCallSignalRaw,
  relayedCallSignals,
  seedCallState,
  setupTwoPartyCallRealm,
  type MediaFocusConfig,
} from "../../helpers/webrtc";

const SERVICE_DID = "did:web:media.example";
const ISSUER_KID = `${SERVICE_DID}#media-token`;
const LIVEKIT_FOCUS: MediaFocusConfig = {
  focus_id: "ck:focus:livekit-lhr",
  type: "livekit",
  issuer_kid: ISSUER_KID,
  connect_url: "wss://livekit.media.example",
  ttl_seconds: 300,
  e2ee_key_source: "mls-exporter",
};

test.describe.configure({ mode: "serial" });

test.describe("call moderation (spec wire)", () => {
  test("moderator kick relays ck.call.signal{moderation=kick} with the pinned (actor, device) target", async ({
    request,
  }) => {
    const { alice, aliceToken, bob, bobToken, realmId } =
      await setupTwoPartyCallRealm(request, "mod-kick");
    const callId = newCallId();

    const moderation = buildCallSignalEnvelope({
      actorDid: alice.did,
      deviceId: alice.deviceId,
      realmId,
      callId,
      signalType: "moderation",
      seq: 1,
      data: {
        action: "kick",
        target_actor_id: bob.did,
        target_device_id: bob.deviceId,
        reason: "policy_violation",
      },
    });
    await postCallSignal(request, aliceToken, moderation);

    const received = (
      await relayedCallSignals(request, bobToken, realmId)
    ).filter(
      (env) => (env.payload as Record<string, unknown>)?.call_id === callId,
    );
    const frame = received.find(
      (e) =>
        (e.payload as Record<string, unknown>).signal_type === "moderation",
    );
    expect(frame, "moderation frame relayed to target member").toBeTruthy();
    const data = (frame!.payload as Record<string, unknown>).data as Record<
      string,
      unknown
    >;
    expect(data.action).toBe("kick");
    expect(data.target_actor_id).toBe(bob.did);
    expect(data.target_device_id).toBe(bob.deviceId);
    // The moderation frame MUST carry a verifiable proof (§3a — signed by the
    // moderator).
    const proof = frame!.proof as Record<string, unknown>;
    expect(proof.kind).toBe("detached_jws");
    expect(proof.verification_method).toBe(`${alice.did}#${alice.deviceId}`);
  });

  test("moderator ban: ck.call.signal{moderation=ban} omits target_device_id (actor-wide scope)", async ({
    request,
  }) => {
    const { alice, aliceToken, bob, bobToken, realmId } =
      await setupTwoPartyCallRealm(request, "mod-ban");
    const callId = newCallId();

    await postCallSignal(
      request,
      aliceToken,
      buildCallSignalEnvelope({
        actorDid: alice.did,
        deviceId: alice.deviceId,
        realmId,
        callId,
        signalType: "moderation",
        seq: 1,
        data: { action: "ban", target_actor_id: bob.did },
      }),
    );

    const received = (
      await relayedCallSignals(request, bobToken, realmId)
    ).filter(
      (env) => (env.payload as Record<string, unknown>)?.call_id === callId,
    );
    const frame = received.find(
      (e) =>
        (e.payload as Record<string, unknown>).signal_type === "moderation",
    );
    expect(frame).toBeTruthy();
    const data = (frame!.payload as Record<string, unknown>).data as Record<
      string,
      unknown
    >;
    expect(data.action).toBe("ban");
    expect(data.target_actor_id).toBe(bob.did);
    expect(data.target_device_id).toBeUndefined();
  });

  test("call_moderation_unauthorised: a member lacking ck.call.signal.send cannot relay a moderation frame", async ({
    request,
  }) => {
    // The relay gates moderation (like every ck.call.signal) on
    // ck.call.signal.send (§162). A non-owner member who was NOT granted it is
    // refused at the relay — they can never get a moderation frame onto the
    // wire. (The pure ck.call.moderate receiver-side authz that yields the
    // `call_moderation_unauthorised` reason for a *relayed* frame is pinned by
    // the Rust conformance vector `run_moderator_kick_ban_vector` step 1.)
    const { alice, aliceToken, bob, bobToken, realmId } =
      await setupTwoPartyCallRealm(request, "mod-unauth");
    const callId = newCallId();

    // bob is a member but holds NO call capability.
    const moderation = buildCallSignalEnvelope({
      actorDid: bob.did,
      deviceId: bob.deviceId,
      realmId,
      callId,
      signalType: "moderation",
      seq: 1,
      data: {
        action: "kick",
        target_actor_id: alice.did,
        target_device_id: alice.deviceId,
      },
    });
    const denied = await postCallSignalRaw(request, bobToken, moderation);
    expect(denied.status(), await denied.text()).toBe(403);
    expect(wireErrCode(await denied.json())).toBe("capability_denied");

    // Control: alice (owner) CAN relay a moderation frame — proving the gate is
    // capability-scoped, not a blanket moderation block.
    await postCallSignal(
      request,
      aliceToken,
      buildCallSignalEnvelope({
        actorDid: alice.did,
        deviceId: alice.deviceId,
        realmId,
        callId,
        signalType: "moderation",
        seq: 1,
        data: { action: "kick", target_actor_id: bob.did, target_device_id: bob.deviceId },
      }),
    );
    const received = (
      await relayedCallSignals(request, bobToken, realmId)
    ).filter(
      (env) =>
        (env.payload as Record<string, unknown>)?.call_id === callId &&
        (env.payload as Record<string, unknown>)?.signal_type === "moderation",
    );
    expect(received.length).toBe(1);
  });

  test("durable ban gate: a banned actor's media-token re-exchange is refused call_participant_removed", async ({
    request,
  }) => {
    // §3a / media-service-binding §3 — once a ban row lands in the durable
    // ck.call.state.removed_participants[], the media token issuer MUST refuse
    // that actor's re-exchange. This is the HTTP-observable moderation
    // enforcement (the kick/ban signal itself is ephemeral).
    const { alice, aliceToken, bob, bobToken, realmId } =
      await setupTwoPartyCallRealm(request, "mod-ban-gate");
    await configureMediaService(
      request,
      aliceToken,
      realmId,
      alice.did,
      SERVICE_DID,
      [LIVEKIT_FOCUS],
    );
    // bob needs ck.call.join to exchange a token before the ban.
    await grantCallCapability(
      request,
      aliceToken,
      alice.did,
      realmId,
      bob.did,
      CAP_CALL_JOIN,
    );
    const callId = newCallId();

    // Pre-ban: bob can exchange a media token (no committed focus yet).
    const preBan = await exchangeMediaToken(request, bobToken, {
      realm_id: realmId,
      call_id: callId,
      actor_id: bob.did,
      device_id: bob.deviceId,
      focus_id: LIVEKIT_FOCUS.focus_id,
    });
    expect(preBan.status(), await preBan.text()).toBe(200);

    // Open the durable call state with a legal initial state before recording
    // the actor-wide ban. call-state.md §4.2 forbids a first state of `active`.
    await seedCallState(request, aliceToken, alice.did, realmId, callId, {
      state: "ringing",
    });

    // A moderator actor-wide-bans bob: the durable removed_participants[] row
    // carries a `ban` with no device_id (§3a).
    await seedCallState(request, aliceToken, alice.did, realmId, callId, {
      state: "active",
      removedParticipants: [{ actor_id: bob.did, action: "ban" }],
    });

    // Post-ban: once the reducer projection has made the durable ban row
    // visible to the token issuer, bob's re-exchange is refused.
    let postBanBody: unknown;
    await expect
      .poll(
        async () => {
          const response = await exchangeMediaToken(request, bobToken, {
            realm_id: realmId,
            call_id: callId,
            actor_id: bob.did,
            device_id: bob.deviceId,
            focus_id: LIVEKIT_FOCUS.focus_id,
          });
          postBanBody = await response.json();
          return response.status();
        },
        { timeout: 5_000, intervals: [100, 250, 500, 1_000] },
      )
      .toBe(403);
    expect(wireErrCode(postBanBody)).toBe("call_participant_removed");
  });
});
