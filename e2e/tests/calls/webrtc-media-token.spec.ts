// Media-service binding (AKP-0010): ak.realm.media_service foci -> media token
// exchange issues a LiveKit-shaped backend_token + participant_binding.
// Contract: e2e/scenarios/calls/webrtc-media-token.md
// Spec refs:
//   - crypto-media/media-service-binding.md §5 (oldest-membership focus election)
//   - crypto-media/media-service-binding.md §8.1 (e2ee key source, exporter labels)
//   - bindings/livekit.md §2/§5 (LiveKit JWT video grant claims)
//   - conformance/conformance-vectors.md §12.16-12.19

import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import {
  solandBaseUrl,
  solandServiceDid,
  solandServiceId,
} from "../../helpers/env";
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
  decodeArkretNativeToken,
  decodeLiveKitToken,
  exchangeMediaToken,
  expectedLiveKitRoom,
  grantCallCapability,
  newCallId,
  type MediaFocusConfig,
} from "../../helpers/webrtc";

// The media service the Realm epoch names is this deployment itself:
// media-service-binding.md §3 anchors every issued issuer_kid /
// participant_binding.issuer_kid on the cell's service_id, and the joint runner leaves
// SOLAND_MEDIA_ISSUER_KID unset, so the deployment default signing key is
// `<service DID>#media-1`. The LiveKit JWT `iss` is instead the
// runner-configured SOLAND_LIVEKIT_API_KEY, a backend credential that never
// enters the Realm cell.
// These stay lazy functions: the joint preflight lists Playwright tests with
// no services up, so env reads must not run at module load.
const serviceId = (): string => solandServiceId();
const issuerKid = (): string => `${solandServiceDid()}#media-1`;
const LIVEKIT_API_KEY = "did:web:media.example#media-token";
// token_endpoint origin must equal the deployment's public base URL —
// soland refuses to mint for a focus whose token endpoint names another
// service (media-service-binding.md §2.1 trust root).
const mediaTokenEndpoint = (): string =>
  `${solandBaseUrl()}/_arkret/self/rtc/token`;
const livekitFocus = (): MediaFocusConfig => ({
  focus_id: "livekit-lhr",
  focus_kind: "livekit",
  token_endpoint: mediaTokenEndpoint(),
  connect_url: "wss://livekit.media.example",
});
const arkretNativeFocus = (): MediaFocusConfig => ({
  focus_id: "arkret-native-reference",
  focus_kind: "arkret_native",
  token_endpoint: mediaTokenEndpoint(),
  connect_url: "wss://native.media.example",
});

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
      focus_id: livekitFocus().focus_id,
      desired_media: { audio: true, video: true, screen: false },
    });
    expect(response.status(), await response.text()).toBe(200);
    const body = await response.json();

    // Outcome shape (CallMediaTokenExchangeOutcome). The backend kind is
    // The canonical CallMediaTokenExchangeOutcome field is `backend_kind`.
    expect(body.focus_id).toBe(livekitFocus().focus_id);
    expect(body.backend_kind).toBe("livekit");
    expect(body.connect_url).toBe(livekitFocus().connect_url);
    expect(typeof body.backend_token).toBe("string");
    // participant_identity is a fresh `ak:rtc_participant:<uuidv7>` handle.
    expect(body.participant_identity).toMatch(
      /^ak:rtc_participant:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );

    // participant_binding pins the spec scheme + the bound tuple, and carries
    // both `issued_at` and `expires_at` (media-service-binding.md §3).
    const binding = body.participant_binding as Record<string, unknown>;
    expect(binding.scheme).toBe(PARTICIPANT_BINDING_SCHEME);
    expect(binding.issuer_kid).toBe(issuerKid());
    expect(binding.realm_id).toBe(realmId);
    expect(binding.call_id).toBe(callId);
    expect(binding.focus_id).toBe(livekitFocus().focus_id);
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

    // participant_binding.sig is the single issuer assertion. The closed
    // outcome deliberately has no redundant service_signature.
    expect(body.service_signature).toBeUndefined();

    // LiveKit JWT claim shape (bindings/livekit.md §2/§5).
    const claims = decodeLiveKitToken(body.backend_token as string);
    // iss = LiveKit API Key (SOLAND_LIVEKIT_API_KEY in the joint runner) —
    // deployment configuration, deliberately distinct from the Realm-anchored
    // issuerKid() that signs the participant_binding.
    expect(claims.iss).toBe(LIVEKIT_API_KEY);
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
      livekitFocus().focus_id,
    );
    expect(video.room).toBe(expectedRoom);
    // LiveKit room name MUST NOT leak raw protocol identifiers.
    expect(video.room).not.toContain(callId);
    expect(video.room).not.toContain(realmId);
    expect(video.room).not.toContain(livekitFocus().focus_id);
    expect(video.roomJoin).toBe(true);
    expect(video.canPublish).toBe(true);
    expect(video.canSubscribe).toBe(true);
    expect(video.canPublishSources).toEqual(
      expect.arrayContaining(["microphone", "camera"]),
    );
    // Screen share is gated: without capability_refs it must not be granted.
    expect(video.canPublishSources).not.toContain("screen_share");
  });

  test("arkret-native backend_token parses as the closed signed token object", async ({
    request,
  }) => {
    const { alice, aliceToken, realmId, callId } =
      await setupMediaCall(request);
    const response = await exchangeMediaToken(request, aliceToken, {
      realm_id: realmId,
      call_id: callId,
      actor_id: alice.did,
      device_id: alice.deviceId,
      focus_id: arkretNativeFocus().focus_id,
      desired_media: { audio: true, video: true, screen: false },
    });
    expect(response.status(), await response.text()).toBe(200);
    const body = await response.json();
    expect(body.backend_kind).toBe("arkret_native");
    expect(body.connect_url).toBe(arkretNativeFocus().connect_url);

    const token = decodeArkretNativeToken(body.backend_token);
    expect(token.kid).toBe(issuerKid());
    expect(token.sig.length).toBeGreaterThan(0);
    expect(token.payload.call_id).toBe(callId);
    expect(token.payload.focus_id).toBe(arkretNativeFocus().focus_id);
    expect(token.payload.participant_identity).toBe(body.participant_identity);
    expect(token.payload.media).toEqual({
      audio: true,
      video: true,
      screen: false,
    });
    expect(
      new Date(token.payload.expires_at).getTime() -
        new Date(token.payload.issued_at).getTime(),
    ).toBeLessThanOrEqual(600_000);
    for (const forbidden of ["actor_id", "device_id", "realm_id"]) {
      expect(token.payload).not.toHaveProperty(forbidden);
    }
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
      focus_id: "unknown-focus",
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
      focus_id: livekitFocus().focus_id,
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
      focus_id: livekitFocus().focus_id,
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
    serviceId(),
    [livekitFocus(), arkretNativeFocus()],
  );

  // Token exchange is decoupled from any prior signaling session
  // (media-service-binding.md settlement ordering): a brand-new call has no ak.call.state
  // cell yet, and authorization is realm membership + ak.call.join. alice owns
  // the realm (holds all caps), so no explicit grant is needed for her.
  const callId = newCallId();
  return { alice, aliceToken, realmId, callId };
}
