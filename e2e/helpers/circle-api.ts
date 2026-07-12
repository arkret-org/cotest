// Circle administration HTTP helpers (`/_arkret/self/circles/*`).
//
// Face note: Circle administration is now a NORMATIVE Arkret protocol surface.
// The `ak.self.circle.*` operations (list/create/get/members/scope-rotate/
// archive/restore/tombstone) are published in the arkret-spec OpenAPI artifact
// (`/_arkret/self/circles*`), the operation registry, and the contract catalog,
// so soland mounts them under the `/_arkret` tree. (Previously these were
// AKP-0014 §5 implementation-local DRAFT candidates served under
// `/_soland/self/circles`; they have since been accepted into the normative
// catalog, and the legacy `/_soland` mirror was retired.)
//
// The `ak.circle.*` data model itself is spec-canonical (AKP-0007); this HTTP
// surface is the convenience wrapper that builds the canonical operations and
// routes them through the same reducer pipeline as wire events (so reducer
// invariants like `circle_member_must_be_realm_member` fire identically).
//
// Wire shapes mirror soland src/routing/circles.rs (CreateCircleRequestBody /
// CircleMemberRequestBody / CircleOutcome / CircleMembershipOutcome).

import type { APIRequestContext, APIResponse } from "@playwright/test";
import { type SolandKey, solandBaseUrl } from "./env";
import {
  authHeaders,
  buildDetachedJwsProof,
  canonicalTimestamp,
  expectJsonOk,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
} from "./soland-api";

export type CircleOutcome = {
  circle_id: string;
  realm_id: string;
  profile_ref?: string;
  title: string;
  summary?: string;
  display: {
    short_name: string;
    color_token: string;
    symbol: { glyph: string } | { emoji: string };
  };
  directory_visibility: string;
  join_rule: string;
  history_visibility: string;
  encryption_profile: string;
  mls_group_ref?: string;
  state: string;
  members: string[];
  member_count?: number;
  viewer_membership?: CircleMembership;
  created_by: string;
  created_at: string;
  updated_by?: string;
  updated_at?: string;
};

export type CircleMembershipOutcome = {
  circle_id: string;
  actor_id: string;
  membership: CircleMembership;
};

export type CircleMembership = "join" | "invite" | "knock" | "leave" | "ban";

export async function grantCircleMemberManageCapability(
  request: APIRequestContext,
  ownerToken: string,
  args: {
    ownerDid: string;
    realmId: string;
    subjectDid: string;
    circleId: string;
    server?: SolandKey;
  },
): Promise<string> {
  const grantId = typedId("grant");
  const issuedAt = canonicalTimestamp();
  const unsignedGrant: Record<string, unknown> = {
    id: grantId,
    grant_id: grantId,
    schema: "ak.schema.capability.v1",
    realm_id: args.realmId,
    issuer: args.ownerDid,
    subject: args.subjectDid,
    actions: ["ak.circle.member.manage"],
    resources: [
      { kind: "circle", realm_id: args.realmId, circle_id: args.circleId },
    ],
    constraints: [
      {
        constraint_type: "scope_limitation",
        effect: "allow",
        allowed_circle_ids: [args.circleId],
      },
    ],
    issued_at: issuedAt,
  };
  await submitSignedEventApi(
    request,
    ownerToken,
    signedEventEnvelope({
      actorDid: args.ownerDid,
      realmId: args.realmId,
      kind: "ak.capability.grant",
      payload: {
        grant_id: grantId,
        grant: {
          ...unsignedGrant,
          proofs: [
            buildDetachedJwsProof({
              issuerDid: args.ownerDid,
              payload: unsignedGrant,
              createdAt: issuedAt,
            }),
          ],
        },
      },
      createdAt: issuedAt,
    }),
    {
      server: args.server,
      context: `grant ak.circle.member.manage for ${args.circleId} to ${args.subjectDid}`,
    },
  );
  return grantId;
}

export async function grantCircleManageCapability(
  request: APIRequestContext,
  ownerToken: string,
  args: {
    ownerDid: string;
    realmId: string;
    subjectDid: string;
    circleId: string;
    server?: SolandKey;
  },
): Promise<string> {
  const grantId = typedId("grant");
  const issuedAt = canonicalTimestamp();
  const unsignedGrant: Record<string, unknown> = {
    id: grantId,
    grant_id: grantId,
    schema: "ak.schema.capability.v1",
    realm_id: args.realmId,
    issuer: args.ownerDid,
    subject: args.subjectDid,
    actions: ["ak.circle.manage"],
    resources: [
      { kind: "circle", realm_id: args.realmId, circle_id: args.circleId },
    ],
    constraints: [
      {
        constraint_type: "scope_limitation",
        effect: "allow",
        allowed_circle_ids: [args.circleId],
      },
    ],
    issued_at: issuedAt,
  };
  await submitSignedEventApi(
    request,
    ownerToken,
    signedEventEnvelope({
      actorDid: args.ownerDid,
      realmId: args.realmId,
      kind: "ak.capability.grant",
      payload: {
        grant_id: grantId,
        grant: {
          ...unsignedGrant,
          proofs: [
            buildDetachedJwsProof({
              issuerDid: args.ownerDid,
              payload: unsignedGrant,
              createdAt: issuedAt,
            }),
          ],
        },
      },
      createdAt: issuedAt,
    }),
    {
      server: args.server,
      context: `grant ak.circle.manage for ${args.circleId} to ${args.subjectDid}`,
    },
  );
  return grantId;
}

// Create a Circle bound to `realmId`. Defaults `join_rule` to "invite" (the
// soland default) so admin-only one-way adds are the membership path.
export async function createCircleArkret(
  request: APIRequestContext,
  token: string,
  args: {
    realmId: string;
    title: string;
    joinRule?: string;
    directoryVisibility?: string;
    summary?: string;
    server?: SolandKey;
  },
): Promise<CircleOutcome> {
  const response = await request.post(
    `${solandBaseUrl(args.server)}/_arkret/self/circles`,
    {
      headers: authHeaders(token),
      data: {
        realm_id: args.realmId,
        title: args.title,
        ...(args.joinRule !== undefined ? { join_rule: args.joinRule } : {}),
        ...(args.directoryVisibility !== undefined
          ? { directory_visibility: args.directoryVisibility }
          : {}),
        ...(args.summary !== undefined ? { summary: args.summary } : {}),
      },
    },
  );
  return await expectJsonOk<CircleOutcome>(
    response,
    `create circle ${args.title}`,
  );
}

export async function getCircleArkret(
  request: APIRequestContext,
  token: string,
  circleId: string,
  opts: { server?: SolandKey } = {},
): Promise<CircleOutcome> {
  const response = await request.get(
    `${solandBaseUrl(opts.server)}/_arkret/self/circles/${encodeURIComponent(circleId)}`,
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
  args: { actorId: string; membership?: CircleMembership; server?: SolandKey },
): Promise<APIResponse> {
  return await request.post(
    `${solandBaseUrl(args.server)}/_arkret/self/circles/${encodeURIComponent(circleId)}/members`,
    {
      headers: authHeaders(token),
      data: {
        actor_id: args.actorId,
        ...(args.membership !== undefined
          ? { membership: args.membership }
          : {}),
      },
    },
  );
}

// Positive-path member add: asserts 2xx and returns the membership outcome.
export async function addCircleMemberArkret(
  request: APIRequestContext,
  token: string,
  circleId: string,
  args: { actorId: string; membership?: CircleMembership; server?: SolandKey },
): Promise<CircleMembershipOutcome> {
  const response = await addCircleMemberRaw(request, token, circleId, args);
  return await expectJsonOk<CircleMembershipOutcome>(
    response,
    `add circle member ${args.actorId} -> ${circleId}`,
  );
}

export async function removeCircleMemberArkret(
  request: APIRequestContext,
  token: string,
  circleId: string,
  actorId: string,
  opts: { server?: SolandKey } = {},
): Promise<CircleMembershipOutcome> {
  const response = await request.delete(
    `${solandBaseUrl(opts.server)}/_arkret/self/circles/${encodeURIComponent(circleId)}/members/${encodeURIComponent(actorId)}`,
    { headers: authHeaders(token) },
  );
  return await expectJsonOk<CircleMembershipOutcome>(
    response,
    `remove circle member ${actorId} <- ${circleId}`,
  );
}

async function submitCircleLifecycleArkret(
  request: APIRequestContext,
  token: string,
  circleId: string,
  action: "archive" | "restore" | "tombstone",
  opts: { reasonCode?: string; server?: SolandKey } = {},
): Promise<CircleOutcome> {
  const response = await request.post(
    `${solandBaseUrl(opts.server)}/_arkret/self/circles/${encodeURIComponent(circleId)}/${action}`,
    {
      headers: authHeaders(token),
      data:
        opts.reasonCode !== undefined
          ? { reason_code: opts.reasonCode }
          : {},
    },
  );
  return await expectJsonOk<CircleOutcome>(
    response,
    `${action} circle ${circleId}`,
  );
}

export async function archiveCircleArkret(
  request: APIRequestContext,
  token: string,
  circleId: string,
  opts: { reasonCode?: string; server?: SolandKey } = {},
): Promise<CircleOutcome> {
  return await submitCircleLifecycleArkret(
    request,
    token,
    circleId,
    "archive",
    opts,
  );
}

export async function restoreCircleArkret(
  request: APIRequestContext,
  token: string,
  circleId: string,
  opts: { reasonCode?: string; server?: SolandKey } = {},
): Promise<CircleOutcome> {
  return await submitCircleLifecycleArkret(
    request,
    token,
    circleId,
    "restore",
    opts,
  );
}

export async function tombstoneCircleArkret(
  request: APIRequestContext,
  token: string,
  circleId: string,
  opts: { reasonCode?: string; server?: SolandKey } = {},
): Promise<CircleOutcome> {
  return await submitCircleLifecycleArkret(
    request,
    token,
    circleId,
    "tombstone",
    opts,
  );
}

// Read the canonical wire `code` off a soland error envelope. soland renders
// errors as `{ ok:false, error:{ code, message }, request_id }`
// (arkret_sdk::ErrorEnvelope), so the canonical code lives at `error.code`.
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
