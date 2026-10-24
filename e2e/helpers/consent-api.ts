// Exact-peer complete Consent editing. List summaries are display-only.
import { randomBytes } from "node:crypto";
import { expect, type APIRequestContext } from "@playwright/test";
import { colandBaseUrl, colandServiceDid, colandServiceId, colandServiceResolution, type ColandKey } from "./env";
import {
  accountActorId, authHeaders, canonicalJson, cotestWire, expectJsonOk,
  principalControlRealmForId, principalControlRootAuthorizationRefForId,
  sha256CanonicalJson, signedEventEnvelope,
} from "./coland-api";
import type {
  ConsentCurrentReadResponseBody, ConsentCurrentReadRequestBody, ConsentPeer,
  ConsentPermission, ConsentReplacePayload, ConsentView,
} from "./generated/spec-wire-objects";

export type { ConsentPeer, ConsentPermission, ConsentReplacePayload, ConsentView };

export function consentPermissions(current: ConsentCurrentReadResponseBody): ConsentPermission[] {
  return current.current.state === "present"
    ? structuredClone(current.current.result.value.permissions) : [];
}

export function consentExpectedCurrent(current: ConsentCurrentReadResponseBody): ConsentReplacePayload["expected_current"] {
  return current.current.state === "present"
    ? { state: "present", revision: structuredClone(current.current.result.revision) }
    : { state: "never_written" };
}

export async function readConsentCurrentApi(
  request: APIRequestContext, token: string, holderId: string, peer: ConsentPeer,
  opts: { server?: ColandKey } = {},
): Promise<ConsentCurrentReadResponseBody> {
  const input: ConsentCurrentReadRequestBody = {
    holder_account_id: accountActorId(holderId, opts.server).account_id,
    peer,
    audience_actor_id: { kind: "service", service_id: colandServiceId(opts.server) },
    nonce: randomBytes(32).toString("base64url"),
  };
  const url = `${colandBaseUrl(opts.server)}/_arkret/self/consent/current`;
  const current = await expectJsonOk<ConsentCurrentReadResponseBody>(await request.post(url, {
    headers: { ...authHeaders(token, "POST", url), "content-type": "application/json" },
    data: canonicalJson(input),
  }), "complete exact-peer Consent current");
  expect(current.request_digest).toBe(`sha256:${sha256CanonicalJson(input)}`);
  expect(current.realm_id).toBe(principalControlRealmForId(holderId));
  expect(current.effective_stream_head.stream_ref).toEqual({ kind: "realm", realm_id: current.realm_id });
  expect(Date.parse(current.evaluated_at)).toBeLessThanOrEqual(Date.now());
  expect(Date.parse(current.expires_at)).toBeGreaterThan(Date.now());
  expect(Date.parse(current.expires_at) - Date.parse(current.evaluated_at)).toBeLessThanOrEqual(30_000);
  if (current.current.state === "present") {
    expect(current.current.result.selector).toEqual({ kind: "consent", peer_id: peer.actor_id });
    expect(current.current.result.source_stream_ref).toEqual(current.effective_stream_head.stream_ref);
    expect(current.current.result.revision.stream_position).toBeLessThanOrEqual(current.effective_stream_head.stream_position);
  }
  // These fixture accounts are initial Human PCRs and never change governance.
  // Generation zero and the hosting Station key are independent of the reply.
  const resolution = await expectJsonOk<Record<string, unknown>>(
    await request.get(colandServiceResolution(opts.server).resolution_url),
    "independent holder Station authenticated method history",
  );
  expect(cotestWire<{ verified: boolean }>("verify-consent-current", {
    request: input, outcome: current,
    expected_realm_id: principalControlRealmForId(holderId), expected_generation: 0,
    expected_verification_method: `${colandServiceDid(opts.server)}#federation-fanout-key`,
    authority: {
      kind: "service_resolution", trusted_service_id: colandServiceId(opts.server),
      service_resolution: resolution,
    },
  }).verified, "SDK must verify the complete read and independent native authority history").toBe(true);
  return current;
}

export function consentReplacementEvent(holderId: string, payload: ConsentReplacePayload, server?: ColandKey) {
  return signedEventEnvelope({
    actorId: holderId, server, realmId: principalControlRealmForId(holderId),
    authorizationRef: principalControlRootAuthorizationRefForId(holderId),
    kind: "ak.consent.replace", payload,
  });
}

export async function replaceConsentApi(
  request: APIRequestContext, token: string, holderId: string,
  payload: ConsentReplacePayload, opts: { server?: ColandKey } = {},
) {
  const event = consentReplacementEvent(holderId, payload, opts.server);
  // Keep the complete signed request as the caller's exact retry unit.
  const submission = canonicalJson({ consent_event: { event } });
  const url = `${colandBaseUrl(opts.server)}/_arkret/self/consent/results/replace`;
  const submit = () => request.post(url, {
    headers: { ...authHeaders(token, "POST", url), "content-type": "application/json" },
    data: submission,
  });
  const view = await expectJsonOk<ConsentView>(await submit(), "complete Consent replacement");
  expect(view.peer).toEqual(payload.peer);
  expect(view.permission_scopes).toEqual(payload.permissions.map((p) => p.consent_scope));
  return { view, event, submission, submit };
}

export async function replaceConsentScopeApi(
  request: APIRequestContext, token: string, holderId: string, peer: ConsentPeer,
  scope: ConsentPermission["consent_scope"], permission: ConsentPermission | undefined,
  opts: { server?: ColandKey } = {},
) {
  const current = await readConsentCurrentApi(request, token, holderId, peer, opts);
  const permissions = consentPermissions(current).filter((p) => p.consent_scope !== scope);
  if (permission) {
    expect(permission.consent_scope).toBe(scope);
    permissions.push(structuredClone(permission));
  }
  const order = ["invite", "voice_call", "video_call", "presence"];
  permissions.sort((a, b) => order.indexOf(a.consent_scope) - order.indexOf(b.consent_scope));
  return replaceConsentApi(request, token, holderId, {
    peer, expected_current: consentExpectedCurrent(current), permissions,
  }, opts);
}
