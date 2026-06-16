// Media-service binding (CKP-0010): ck.realm.media_service foci -> media token
// exchange issues a LiveKit-shaped backend_token + participant_binding.
// Contract: e2e/scenarios/calls/webrtc-media-token.md
// Spec refs:
//   - crypto-media/media-service-binding.md §5 (oldest-membership focus election)
//   - crypto-media/media-service-binding.md §8.1 (e2ee key source, exporter labels)
//   - bindings/livekit.md §2/§5 (LiveKit JWT video grant claims)
//   - conformance/conformance-vectors.md §12.16-12.19

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
import {
  PARTICIPANT_BINDING_SCHEME,
  configureMediaService,
  decodeLiveKitToken,
  exchangeMediaToken,
  expectedLiveKitRoom,
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

test.describe("media token exchange", () => {
  test(
    "ck.realm.media_service foci -> exchangeMediaToken issues a LiveKit JWT backend_token + participant_binding",
    async ({ request }) => {
      const { alice, aliceToken, callId } = await setupMediaCall(request);
      const response = await exchangeMediaToken(request, aliceToken, {
        realm_id: callRealm.id,
        call_id: callId,
        actor_id: alice.did,
        device_id: alice.deviceId,
        focus_id: LIVEKIT_FOCUS.focus_id,
        desired_media: { audio: true, video: true, screen: false },
      });
      expect(response.status(), await response.text()).toBe(200);
      const body = await response.json();

      // Outcome shape (CallMediaTokenExchangeOutcome). The backend kind is
      // surfaced on the wire as `type` (serde rename of `backend_type`).
      expect(body.focus_id).toBe(LIVEKIT_FOCUS.focus_id);
      expect(body.type).toBe("livekit");
      expect(body.connect_url).toBe(LIVEKIT_FOCUS.connect_url);
      expect(typeof body.backend_token).toBe("string");
      // participant_identity is a fresh `ck:rtc_participant:<uuidv7>` handle.
      expect(body.participant_identity).toMatch(
        /^ck:rtc_participant:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      );

      // participant_binding pins the spec scheme + the bound tuple, and carries
      // both `issued_at` and `expires_at` (media-service-binding.md §3).
      const binding = body.participant_binding as Record<string, unknown>;
      expect(binding.scheme).toBe(PARTICIPANT_BINDING_SCHEME);
      expect(binding.issuer_kid).toBe(ISSUER_KID);
      expect(binding.realm_id).toBe(callRealm.id);
      expect(binding.call_id).toBe(callId);
      expect(binding.focus_id).toBe(LIVEKIT_FOCUS.focus_id);
      expect(binding.actor_id).toBe(alice.did);
      expect(binding.device_id).toBe(alice.deviceId);
      expect(binding.participant_identity).toBe(body.participant_identity);
      expect(typeof binding.issued_at).toBe("string");
      expect(typeof binding.expires_at).toBe("string");
      expect(
        new Date(binding.expires_at as string).getTime(),
      ).toBeGreaterThan(new Date(binding.issued_at as string).getTime());
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
      expect(
        (claims.exp as number) - (claims.iat as number),
      ).toBeLessThanOrEqual(600);
      const video = claims.video as Record<string, unknown>;
      const expectedRoom = expectedLiveKitRoom(
        callRealm.id,
        callId,
        LIVEKIT_FOCUS.focus_id,
      );
      expect(video.room).toBe(expectedRoom);
      // LiveKit room name MUST NOT leak raw protocol identifiers.
      expect(video.room).not.toContain(callId);
      expect(video.room).not.toContain(callRealm.id);
      expect(video.room).not.toContain(LIVEKIT_FOCUS.focus_id);
      expect(video.roomJoin).toBe(true);
      expect(video.canPublish).toBe(true);
      expect(video.canSubscribe).toBe(true);
      expect(video.canPublishSources).toEqual(
        expect.arrayContaining(["microphone", "camera"]),
      );
      // Screen share is gated: without capability_refs it must not be granted.
      expect(video.canPublishSources).not.toContain("screen_share");
    },
  );

  test(
    "off-focus token request fails closed with focus_mismatch (oldest-membership election)",
    async ({ request }) => {
      const { alice, aliceToken, callId } = await setupMediaCall(request);
      const denied = await exchangeMediaToken(request, aliceToken, {
        realm_id: callRealm.id,
        call_id: callId,
        actor_id: alice.did,
        device_id: alice.deviceId,
        focus_id: "ck:focus:unknown-focus",
      });
      expect(denied.status()).toBe(400);
      expect(wireErrCode(await denied.json())).toBe("focus_mismatch");
    },
  );

  test(
    "token exchange requires the actor to be a call participant (participant_identity_unrecognised)",
    async ({ request }) => {
      const { aliceToken, callId } = await setupMediaCall(request);
      const outsider = uniqueUser(`media-outsider-${Date.now()}`);
      await ensureRegistered(request, outsider);
      const outsiderToken = await issueDevSession(request, outsider);
      await addRealmMemberApi(request, aliceToken, callRealm.id, outsider.did);

      const denied = await exchangeMediaToken(request, outsiderToken, {
        realm_id: callRealm.id,
        call_id: callId,
        actor_id: outsider.did,
        device_id: outsider.deviceId,
        focus_id: LIVEKIT_FOCUS.focus_id,
      });
      expect(denied.status()).toBe(403);
      expect(wireErrCode(await denied.json())).toBe(
        "participant_identity_unrecognised",
      );
    },
  );
});

const callRealm: { id: string } = { id: "" };

async function setupMediaCall(
  request: APIRequestContext,
): Promise<{ alice: JointUser; aliceToken: string; callId: string }> {
  const stamp = Date.now();
  const alice = uniqueUser(`media-alice-${stamp}`);
  await ensureRegistered(request, alice);
  const aliceToken = await issueDevSession(request, alice);
  const realmId = await createRealmApi(request, aliceToken, {
    title: `media-service ${stamp}`,
    public: true,
  });
  callRealm.id = realmId;
  await configureMediaService(
    request,
    aliceToken,
    realmId,
    alice.did,
    SERVICE_DID,
    [LIVEKIT_FOCUS],
  );

  const session = await request.post(
    `${solandBaseUrl()}/_soland/self/webrtc/sessions`,
    {
      headers: authHeaders(aliceToken),
      data: { realm_id: realmId, participants: [], ttl_ms: 120_000 },
    },
  );
  expect(session.status(), await session.text()).toBe(200);
  const callId = (await session.json()).session_id as string;
  return { alice, aliceToken, callId };
}
