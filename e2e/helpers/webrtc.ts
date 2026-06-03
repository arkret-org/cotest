import {
  expect,
  type APIRequestContext,
  type APIResponse,
} from "@playwright/test";
import { solandBaseUrl } from "./env";
import { createSpaceApi } from "./soland-api";

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
  "error",
  "device_change",
  "renegotiate",
] as const;

export type CallSignalType = (typeof CALL_SIGNAL_TYPES)[number];

export async function demoAliceToken(
  request: APIRequestContext,
): Promise<string> {
  const response = await request.post(
    `${solandBaseUrl()}/api/v1/auth/dev-login`,
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
  DEMO_REALM_ID = await createSpaceApi(request, token, {
    title: `cotest webrtc ${Date.now()}`,
    history_visibility: "joined",
    ownerDid: DEMO_ALICE_DID,
  });
  const response = await request.post(
    `${solandBaseUrl()}/api/v1/webrtc/sessions`,
    {
      headers: authHeaders(token),
      data: {
        space_id: DEMO_REALM_ID,
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
    `${solandBaseUrl()}/api/v1/webrtc/sessions/${encodeURIComponent(sessionId)}`,
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
    `${solandBaseUrl()}/api/v1/webrtc/sessions/${encodeURIComponent(sessionId)}/signals`,
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
    `${solandBaseUrl()}/api/v1/webrtc/sessions/${encodeURIComponent(sessionId)}/signals?since=${since}&limit=100`,
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
