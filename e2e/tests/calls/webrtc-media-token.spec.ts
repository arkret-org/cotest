// Media-service binding (AKP-0010): ak.realm.media_service foci -> media token
// exchange issues a LiveKit-shaped backend_token + participant_binding.
// Contract: e2e/scenarios/calls/webrtc-media-token.md
// Spec refs:
//   - crypto-media/media-service-binding.md §5 (oldest-membership focus election)
//   - crypto-media/media-service-binding.md §8.1 (e2ee key source, exporter labels)
//   - bindings/livekit.md §2/§5 (LiveKit JWT video grant claims)
//   - conformance/conformance-vectors.md §12.16-12.19

import { expect, test, type APIRequestContext } from "@playwright/test";
import {
  addRealmMemberApi,
  createRealmApi,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
  type JointUser,
} from "../../helpers/users";
import {
  CAP_CALL_JOIN,
  PARTICIPANT_BINDING_SCHEME,
  configureMediaService,
  decodeLiveKitToken,
  exchangeMediaToken,
  expectedLiveKitRoom,
  grantCallCapability,
  newCallId,
  type MediaFocusConfig,
} from "../../helpers/webrtc";

const SERVICE_ID = "did:web:media.example";
const ISSUER_KID = `${SERVICE_ID}#media-token`;
const LIVEKIT_FOCUS: MediaFocusConfig = {
  focus_id: "ak:focus:livekit-lhr",
  type: "livekit",
  issuer_kid: ISSUER_KID,
  connect_url: "wss://livekit.media.example",
  ttl_seconds: 300,
  e2ee_key_source: "mls-exporter",
};

test.describe.configure({ mode: "serial" });

test.describe("media token exchange", () => {
  test("ak.realm.media_service foci -> exchangeMediaToken issues a LiveKit JWT backend_token + participant_binding", async ({
    request,
  }) => {
    const { alice, aliceToken, realmId, callId } =
      await setupMediaCall(request);
    const response = await exchangeMediaToken(request, aliceToken, {
      realm_id: realmId,
      call_id: callId,
      actor_id: alice.did,
      device_id: alice.deviceId,
      focus_id: LIVEKIT_FOCUS.focus_id,
      desired_media: { audio: true, video: true, screen: false },
    });
    expect(response.status(), await response.text()).toBe(200);
    const body = await response.json();

    // Outcome shape (CallMediaTokenExchangeOutcome). The backend kind is
    // The canonical CallMediaTokenExchangeOutcome field is `backend_kind`.
    expect(body.focus_id).toBe(LIVEKIT_FOCUS.focus_id);
    expect(body.backend_kind).toBe("livekit");
    expect(body.connect_url).toBe(LIVEKIT_FOCUS.connect_url);
    expect(typeof body.backend_token).toBe("string");
    // participant_identity is a fresh `ak:rtc_participant:<uuidv7>` handle.
    expect(body.participant_identity).toMatch(
      /^ak:rtc_participant:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );

    // participant_binding pins the spec scheme + the bound tuple, and carries
    // both `issued_at` and `expires_at` (media-service-binding.md §3).
    const binding = body.participant_binding as Record<string, unknown>;
    expect(binding.scheme).toBe(PARTICIPANT_BINDING_SCHEME);
    expect(binding.issuer_kid).toBe(ISSUER_KID);
    expect(binding.realm_id).toBe(realmId);
    expect(binding.call_id).toBe(callId);
    expect(binding.focus_id).toBe(LIVEKIT_FOCUS.focus_id);
    expect(binding.actor_id).toBe(alice.did);
    expect(binding.device_id).toBe(alice.deviceId);
    expect(binding.participant_identity).toBe(body.participant_identity);
    expect(typeof binding.issued_at).toBe("string");
    expect(typeof binding.expires_at).toBe("string");
    expect(new Date(binding.expires_at as string).getTime()).toBeGreaterThan(
      new Date(binding.issued_at as string).getTime(),
    );
    expect(typeof binding.sig).toBe("string");
    expect((binding.sig as string).length).toBeGreaterThan(0);

    // service_signature is a typed { kid, sig } object: kid is the realm
    // media-service anchor (`did:...#...`), sig is the detached signature.
    const serviceSignature = body.service_signature as Record<string, unknown>;
    expect(serviceSignature.kid).toBe(ISSUER_KID);
    expect(serviceSignature.kid).toMatch(/^did:[^#]+#.+$/);
    expect(typeof serviceSignature.sig).toBe("string");
    expect((serviceSignature.sig as string).length).toBeGreaterThan(0);

    // LiveKit JWT claim shape (bindings/livekit.md §2/§5).
    const claims = decodeLiveKitToken(body.backend_token as string);
    // iss = LiveKit API Key; soland requires it to equal the realm focus
    // issuer_kid, so it equals ISSUER_KID here.
    expect(claims.iss).toBe(ISSUER_KID);
    expect(claims.sub).toBe(body.participant_identity);
    // exp/iat are NumericDate (Unix epoch seconds); exp MUST be within 600s
    // of iat (media-service-binding.md §3 TTL ceiling).
    expect(typeof claims.exp).toBe("number");
    expect((claims.exp as number) - (claims.iat as number)).toBeLessThanOrEqual(
      600,
    );
    const video = claims.video as Record<string, unknown>;
    const expectedRoom = expectedLiveKitRoom(
      realmId,
      callId,
      LIVEKIT_FOCUS.focus_id,
    );
    expect(video.room).toBe(expectedRoom);
    // LiveKit room name MUST NOT leak raw protocol identifiers.
    expect(video.room).not.toContain(callId);
    expect(video.room).not.toContain(realmId);
    expect(video.room).not.toContain(LIVEKIT_FOCUS.focus_id);
    expect(video.roomJoin).toBe(true);
    expect(video.canPublish).toBe(true);
    expect(video.canSubscribe).toBe(true);
    expect(video.canPublishSources).toEqual(
      expect.arrayContaining(["microphone", "camera"]),
    );
    // Screen share is gated: without capability_refs it must not be granted.
    expect(video.canPublishSources).not.toContain("screen_share");
  });

  test("unknown focus token request fails closed with focus_mismatch", async ({
    request,
  }) => {
    const { alice, aliceToken, realmId, callId } =
      await setupMediaCall(request);
    const denied = await exchangeMediaToken(request, aliceToken, {
      realm_id: realmId,
      call_id: callId,
      actor_id: alice.did,
      device_id: alice.deviceId,
      focus_id: "ak:focus:unknown-focus",
    });
    expect(denied.status()).toBe(409);
    expect(wireErrCode(await denied.json())).toBe("focus_mismatch");
  });

  test("token exchange requires ak.call.join: a realm member lacking it is refused, granting it admits them", async ({
    request,
  }) => {
    // WIRE NOTE (migration): the retired stack gated token exchange on a
    // pre-existing signaling session + participant row. The canonical issuer
    // (media-service-binding.md §6 / call-state.md §4.1) gates on realm
    // membership + the `ak.call.join` capability + the durable ban set — NOT
    // a prior participant row. So a member WITHOUT ak.call.join is refused
    // (capability_denied), and granting it admits them.
    const { alice, aliceToken, realmId, callId } =
      await setupMediaCall(request);
    const member = uniqueUser(`media-member-${Date.now()}`);
    await ensureRegistered(request, member);
    const memberToken = await issueDevSession(request, member);
    await addRealmMemberApi(request, aliceToken, realmId, member.did);

    // Member, but no ak.call.join → refused.
    const denied = await exchangeMediaToken(request, memberToken, {
      realm_id: realmId,
      call_id: callId,
      actor_id: member.did,
      device_id: member.deviceId,
      focus_id: LIVEKIT_FOCUS.focus_id,
    });
    expect(denied.status()).toBe(403);
    expect(wireErrCode(await denied.json())).toBe("capability_denied");

    // Grant ak.call.join → admitted (token issued). alice is the realm owner.
    await grantCallCapability(
      request,
      aliceToken,
      alice.did,
      realmId,
      member.did,
      CAP_CALL_JOIN,
    );
    const admitted = await exchangeMediaToken(request, memberToken, {
      realm_id: realmId,
      call_id: callId,
      actor_id: member.did,
      device_id: member.deviceId,
      focus_id: LIVEKIT_FOCUS.focus_id,
    });
    expect(admitted.status(), await admitted.text()).toBe(200);
    const body = await admitted.json();
    expect(body.participant_binding.actor_id).toBe(member.did);
  });
});

async function setupMediaCall(request: APIRequestContext): Promise<{
  alice: JointUser;
  aliceToken: string;
  realmId: string;
  callId: string;
}> {
  const stamp = Date.now();
  const alice = uniqueUser(`media-alice-${stamp}`);
  await ensureRegistered(request, alice);
  const aliceToken = await issueDevSession(request, alice);
  const realmId = await createRealmApi(request, aliceToken, {
    title: `media-service ${stamp}`,
    public: true,
  });
  await configureMediaService(
    request,
    aliceToken,
    realmId,
    alice.did,
    SERVICE_ID,
    [LIVEKIT_FOCUS],
  );

  // Token exchange is decoupled from any prior signaling session
  // (media-service-binding.md settlement ordering): a brand-new call has no ak.call.state
  // cell yet, and authorization is realm membership + ak.call.join. alice owns
  // the realm (holds all caps), so no explicit grant is needed for her.
  const callId = newCallId();
  return { alice, aliceToken, realmId, callId };
}
