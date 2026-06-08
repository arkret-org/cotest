// Circle administration HTTP helpers (`/_soland/self/circles/*`).
//
// Face note (verified against the live soland binary AND cokret-spec, NOT the
// task brief): Circle administration is an IMPLEMENTATION-LOCAL surface mounted
// under `/_soland/self/circles`. soland routing/mod.rs mounts
// `circles::router()` inside `soland_local_router()`, which the app root pushes
// under `Router::with_path("_soland")` (mod.rs:137/147/241) — it is NOT part of
// `api_v1_router()` (the `/_cokret` tree). cokret-spec CKP-0014 §5 lists
// `POST/GET /_cokret/self/circles` as DRAFT candidates only, and CKP-0014's
// normative rule (line 18) is: "Until an item is accepted into the normative
// operation catalog and OpenAPI artifacts, implementations MUST NOT mount it
// under `/_cokret`. Private deployment endpoints MUST use `/_soland/*`." So
// `/_soland/self/circles` is the spec-correct face today; a hit on
// `/_cokret/self/circles` returns 404 unrecognized_endpoint on a live soland.
// (The circles.rs file-header comment claiming `/_cokret/self/circles` is
// stale/aspirational and contradicts both the live mount and the spec.)
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
    `${solandBaseUrl(args.server)}/_soland/self/circles`,
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
    `${solandBaseUrl(opts.server)}/_soland/self/circles/${encodeURIComponent(circleId)}`,
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
    `${solandBaseUrl(args.server)}/_soland/self/circles/${encodeURIComponent(circleId)}/members`,
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
    `${solandBaseUrl(opts.server)}/_soland/self/circles/${encodeURIComponent(circleId)}/members/${encodeURIComponent(actorId)}`,
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
