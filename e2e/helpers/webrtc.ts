import {
  expect,
  type APIRequestContext,
  type APIResponse,
} from "@playwright/test";
import { createHash } from "node:crypto";
import { solandBaseUrl } from "./env";
import {
  createRealmApi,
  signedEventEnvelope,
  submitSignedEventApi,
  wireErrCode,
} from "./soland-api";

export let DEMO_REALM_ID = "ck:realm:0196419b-0000-7000-8000-000000000000";
export const DEMO_ALICE_DID = "did:web:alice.example";
export const DEMO_ALICE_DEVICE_ID =
  "ck:device:01904100-0000-7000-8000-a11ce0000001";

export const CALL_SIGNAL_TYPES = [
  "offer",
  "answer",
  "ice",
  "hangup",
  "reject",
  "mute_state",
  "media_state",
  "speaking",
  "focus_join",
  "focus_leave",
  "moderation",
  "error",
  "device_change",
  "renegotiate",
] as const;

export type CallSignalType = (typeof CALL_SIGNAL_TYPES)[number];

export async function demoAliceToken(
  request: APIRequestContext,
): Promise<string> {
  const response = await request.post(
    `${solandBaseUrl()}/_soland/gate/auth/dev-login`,
    {
      data: {
        actor: DEMO_ALICE_DID,
        device_id: DEMO_ALICE_DEVICE_ID,
        display_name: "Alice Desktop",
      },
    },
  );
  expect(response.status(), "demo alice dev-login").toBe(200);
  const body = await response.json();
  expect(body.access_token).toBeTruthy();
  return body.access_token as string;
}

export async function createCallSession(
  request: APIRequestContext,
  token: string,
): Promise<string> {
  DEMO_REALM_ID = await createRealmApi(request, token, {
    title: `cotest webrtc ${Date.now()}`,
    history_visibility: "joined",
    ownerDid: DEMO_ALICE_DID,
  });
  const response = await request.post(
    `${solandBaseUrl()}/_soland/self/webrtc/sessions`,
    {
      headers: authHeaders(token),
      data: {
        realm_id: DEMO_REALM_ID,
        participants: [],
        ttl_ms: 90_000,
      },
    },
  );
  expect(response.status(), "create WebRTC session").toBe(200);
  const body = await response.json();
  expect(body.session_id).toMatch(/^ck:call:/);
  expect(body.participants).toContain(DEMO_ALICE_DID);
  return body.session_id as string;
}

export async function closeCallSession(
  request: APIRequestContext,
  token: string,
  sessionId: string,
) {
  const response = await request.delete(
    `${solandBaseUrl()}/_soland/self/webrtc/sessions/${encodeURIComponent(sessionId)}`,
    {
      headers: authHeaders(token),
    },
  );
  expect(response.status(), "close WebRTC session").toBe(200);
}

export async function postCallSignal(
  request: APIRequestContext,
  token: string,
  sessionId: string,
  messageType: CallSignalType | string,
  seq: number,
  payload: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const response = await request.post(
    `${solandBaseUrl()}/_soland/self/webrtc/sessions/${encodeURIComponent(sessionId)}/signals`,
    {
      headers: authHeaders(token),
      data: {
        message_type: messageType,
        seq,
        payload,
        proofs: [deviceProof()],
      },
    },
  );
  expect(response.status(), `append ${messageType} seq=${seq}`).toBe(200);
  return await response.json();
}

export async function getCallSignals(
  request: APIRequestContext,
  token: string,
  sessionId: string,
  since = 0,
): Promise<Array<Record<string, unknown>>> {
  const response = await request.get(
    `${solandBaseUrl()}/_soland/self/webrtc/sessions/${encodeURIComponent(sessionId)}/signals?since=${since}&limit=100`,
    { headers: authHeaders(token) },
  );
  expect(response.status(), `get signals since ${since}`).toBe(200);
  const body = await response.json();
  expect(Array.isArray(body.events)).toBe(true);
  return body.events as Array<Record<string, unknown>>;
}

export async function expectCallSignalError(
  response: APIResponse,
  status: number,
  code: string,
) {
  expect(response.status()).toBe(status);
  const body = await response.json();
  expect(body.ok).toBe(false);
  expect(body.error?.code ?? body.error?.errcode).toBe(code);
}

export function authHeaders(token: string) {
  return { authorization: `Bearer ${token}` };
}

export function deviceProof() {
  return {
    actor: DEMO_ALICE_DID,
    kid: `${DEMO_ALICE_DID}#${DEMO_ALICE_DEVICE_ID}`,
    sig: "cotest-device-proof",
  };
}

// ── Media-service binding (CKP-0010) — token exchange helpers ────────────────
//
// These back the `ck.realm.media_service` foci configuration and the
// `POST /_cokret/self/rtc/token` media token exchange. The foci selection
// follows the spec oldest-membership-wins rule (media-service-binding.md §5);
// the issued LiveKit token is a standard 3-segment JWT so the harness can
// decode the LiveKit `video` grant claims without a live SFU.

export const PARTICIPANT_BINDING_SCHEME = "ck.media.participant_binding.v1";
export const MEDIA_TOKEN_TTL_MAX_SECS = 600;

export interface MediaFocusConfig {
  focus_id: string;
  type: string;
  issuer_kid: string;
  connect_url: string;
  ttl_seconds?: number;
  e2ee_key_source?: string;
}

/**
 * Project a `ck.realm.media_service` epoch onto the realm so the token issuer
 * can resolve `service_id`, `issuer_kids`, and `foci[]`. The `service_id` is
 * derived from each focus `issuer_kid` (`<service_id>#<key>`).
 */
export async function configureMediaService(
  request: APIRequestContext,
  token: string,
  realmId: string,
  ownerDid: string,
  serviceDid: string,
  foci: MediaFocusConfig[],
): Promise<void> {
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: ownerDid,
      realmId,
      kind: "ck.realm.media_service",
      payload: {
        media_service: {
          service_id: serviceDid,
          foci,
        },
      },
    }),
    { context: `configure media_service for ${realmId}` },
  );
}

export interface MediaParticipantBinding {
  scheme: string;
  sig: string;
  issuer_kid: string;
  realm_id: string;
  call_id: string;
  focus_id: string;
  actor_id: string;
  device_id: string;
  participant_identity: string;
  issued_at: string;
  expires_at: string;
}

export interface MediaServiceSignature {
  kid: string;
  sig: string;
}

export interface MediaTokenExchangeResult {
  focus_id: string;
  type: string;
  connect_url: string;
  backend_token: string;
  participant_identity: string;
  participant_binding: MediaParticipantBinding;
  expires_at: string;
  service_signature: MediaServiceSignature;
}

export async function exchangeMediaToken(
  request: APIRequestContext,
  token: string,
  body: {
    realm_id: string;
    call_id: string;
    actor_id: string;
    device_id: string;
    focus_id: string;
    desired_media?: { audio?: boolean; video?: boolean; screen?: boolean };
    capability_refs?: string[];
  },
): Promise<APIResponse> {
  return await request.post(`${solandBaseUrl()}/_cokret/self/rtc/token`, {
    headers: authHeaders(token),
    data: body,
  });
}

/**
 * Derive the opaque backend room id specified by bindings/livekit.md.
 */
export function expectedLiveKitRoom(
  realmId: string,
  callId: string,
  focusId: string,
): string {
  const digest = createHash("sha256")
    .update(`${realmId}\0${callId}\0${focusId}`, "utf8")
    .digest("hex");
  return `ck_call_${digest.slice(0, 16)}`;
}

/**
 * Decode the standard LiveKit JWT backend token and return its claim object.
 * The payload is canonical-JSON base64url (no padding).
 */
export function decodeLiveKitToken(
  backendToken: string,
): Record<string, unknown> {
  const segments = backendToken.split(".");
  expect(segments.length, "livekit token is a standard 3-segment JWT").toBe(3);
  // bindings/livekit.md §2: backend_token is a real LiveKit JWT
  // (base64url(header).base64url(payload).base64url(HS256 sig)) — no legacy
  // `livekit.` envelope prefix. Header MUST be {alg:HS256, typ:JWT}.
  const header = JSON.parse(
    Buffer.from(segments[0], "base64url").toString("utf8"),
  ) as Record<string, unknown>;
  expect(header.alg, "livekit JWT alg").toBe("HS256");
  expect(header.typ, "livekit JWT typ").toBe("JWT");
  const payloadJson = Buffer.from(segments[1], "base64url").toString("utf8");
  return JSON.parse(payloadJson) as Record<string, unknown>;
}

// ── Recording control + moderation helpers ──────────────────────────────────

export async function startCallRecording(
  request: APIRequestContext,
  token: string,
  sessionId: string,
  realmId: string,
): Promise<APIResponse> {
  return await request.post(
    `${solandBaseUrl()}/_soland/self/calls/${encodeURIComponent(sessionId)}/recording/start`,
    {
      headers: authHeaders(token),
      data: { realm_id: realmId },
    },
  );
}

export { wireErrCode };
