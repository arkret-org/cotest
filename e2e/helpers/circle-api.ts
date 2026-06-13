// Circle administration HTTP helpers (`/_cokret/self/circles/*`).
//
// Face note: Circle administration is now a NORMATIVE Cokret protocol surface.
// The `ck.self.circle.*` operations (list/create/get/members/scope-rotate/
// archive/tombstone) are published in the cokret-spec OpenAPI artifact
// (`/_cokret/self/circles*`), the operation registry, and the contract catalog,
// so soland mounts them under the `/_cokret` tree. (Previously these were
// CKP-0014 §5 implementation-local DRAFT candidates served under
// `/_soland/self/circles`; they have since been accepted into the normative
// catalog, and the legacy `/_soland` mirror was retired.)
//
// The `ck.circle.*` data model itself is spec-canonical (CKP-0007); this HTTP
// surface is the convenience wrapper that builds the canonical operations and
// routes them through the same reducer pipeline as wire events (so reducer
// invariants like `circle_member_must_be_realm_member` fire identically).
//
// Wire shapes mirror soland src/routing/circles.rs (CreateCircleRequestBody /
// CircleMemberRequestBody / CircleOutcome / CircleMembershipOutcome).

import type { APIRequestContext, APIResponse } from "@playwright/test";
import { type SolandKey, solandBaseUrl } from "./env";
import { authHeaders, expectJsonOk } from "./soland-api";

export type CircleOutcome = {
  circle_id: string;
  realm_id: string;
  title: string;
  summary?: string;
  directory_visibility: string;
  join_rule: string;
  history_visibility: string;
  encryption_profile: string;
  mls_group_ref?: string;
  state: string;
  members: string[];
  created_by: string;
  created_at: string;
  updated_by?: string;
  updated_at?: string;
};

export type CircleMembershipOutcome = {
  circle_id: string;
  actor_id: string;
  state: string;
};

// Create a Circle bound to `realmId`. Defaults `join_rule` to "invite" (the
// soland default) so admin-only one-way adds are the membership path.
export async function createCircleCokret(
  request: APIRequestContext,
  token: string,
  args: {
    realmId: string;
    title: string;
    joinRule?: string;
    summary?: string;
    server?: SolandKey;
  },
): Promise<CircleOutcome> {
  const response = await request.post(
    `${solandBaseUrl(args.server)}/_cokret/self/circles`,
    {
      headers: authHeaders(token),
      data: {
        realm_id: args.realmId,
        title: args.title,
        ...(args.joinRule !== undefined ? { join_rule: args.joinRule } : {}),
        ...(args.summary !== undefined ? { summary: args.summary } : {}),
      },
    },
  );
  return await expectJsonOk<CircleOutcome>(
    response,
    `create circle ${args.title}`,
  );
}

export async function getCircleCokret(
  request: APIRequestContext,
  token: string,
  circleId: string,
  opts: { server?: SolandKey } = {},
): Promise<CircleOutcome> {
  const response = await request.get(
    `${solandBaseUrl(opts.server)}/_cokret/self/circles/${encodeURIComponent(circleId)}`,
    { headers: authHeaders(token) },
  );
  return await expectJsonOk<CircleOutcome>(response, `get circle ${circleId}`);
}

// Add (or change) a Circle member. Returns the raw APIResponse so negative
// scenarios can assert status + wire `code` without throwing.
export async function addCircleMemberRaw(
  request: APIRequestContext,
  token: string,
  circleId: string,
  args: { actorId: string; state?: string; server?: SolandKey },
): Promise<APIResponse> {
  return await request.post(
    `${solandBaseUrl(args.server)}/_cokret/self/circles/${encodeURIComponent(circleId)}/members`,
    {
      headers: authHeaders(token),
      data: {
        actor_id: args.actorId,
        ...(args.state !== undefined ? { state: args.state } : {}),
      },
    },
  );
}

// Positive-path member add: asserts 2xx and returns the membership outcome.
export async function addCircleMemberCokret(
  request: APIRequestContext,
  token: string,
  circleId: string,
  args: { actorId: string; state?: string; server?: SolandKey },
): Promise<CircleMembershipOutcome> {
  const response = await addCircleMemberRaw(request, token, circleId, args);
  return await expectJsonOk<CircleMembershipOutcome>(
    response,
    `add circle member ${args.actorId} -> ${circleId}`,
  );
}

export async function removeCircleMemberCokret(
  request: APIRequestContext,
  token: string,
  circleId: string,
  actorId: string,
  opts: { server?: SolandKey } = {},
): Promise<CircleMembershipOutcome> {
  const response = await request.delete(
    `${solandBaseUrl(opts.server)}/_cokret/self/circles/${encodeURIComponent(circleId)}/members/${encodeURIComponent(actorId)}`,
    { headers: authHeaders(token) },
  );
  return await expectJsonOk<CircleMembershipOutcome>(
    response,
    `remove circle member ${actorId} <- ${circleId}`,
  );
}

// Read the canonical wire `code` off a soland error envelope. soland renders
// errors as `{ ok:false, error:{ code, message }, request_id }`
// (cokret_sdk::ErrorEnvelope), so the canonical code lives at `error.code`.
export async function errorWireCode(
  response: APIResponse,
): Promise<string | undefined> {
  try {
    const body = (await response.json()) as {
      code?: string;
      error?: { code?: string };
    };
    return body.error?.code ?? body.code;
  } catch {
    return undefined;
  }
}
