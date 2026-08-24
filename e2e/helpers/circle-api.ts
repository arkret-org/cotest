// Circle administration HTTP helpers (`/_arkret/self/circles/*`).
//
// Face note: Circle administration is now a NORMATIVE Arkret protocol surface.
// The `ak.self.circle.*` operations (list/create/get/members/scope-rotate/
// archive/restore/tombstone) are published in the arkret-spec OpenAPI artifact
// (`/_arkret/self/circles*`), the operation registry, and the contract catalog,
// so soland mounts them under the `/_arkret` tree. `/_soland/self/circles` is
// not a mounted surface.
//
// The `ak.circle.*` data model itself is spec-canonical (AKP-0007); this HTTP
// surface is the convenience wrapper that builds the canonical operations and
// routes them through the same reducer pipeline as wire events (so reducer
// invariants like `circle_member_must_be_realm_member` fire identically).
//
// Wire shapes mirror soland src/routing/circles.rs (CircleCreateRequestBody /
// CircleMemberRequestBody / CircleView / CircleMembershipOutcome).
//
// Every write body now carries the caller-signed `ak.circle.*` Event and nothing
// else: the operations declare a durable `event_log` effect, and the spec
// forbids the service from producing that signature for the caller
// (`capabilities.md` §118/§361, `key-management.md` §411). That is also why the
// helpers take an `actorDid` — a bearer token says who is calling, but only a
// DID can be the `actor_id` of a signed Event.

import type { APIRequestContext, APIResponse } from "@playwright/test";
import { type SolandKey, solandBaseUrl, solandServiceId } from "./env";
import type { RealmObject } from "./generated/spec-wire-objects";
import {
  authHeaders,
  canonicalJson,
  canonicalTimestamp,
  expectJsonOk,
  prepareSignedEventSubmissionApi,
  signedEventEnvelope,
  sdkCapabilityActionRegistryDigest,
  submitSignedEventApi,
  retypeEventDerivedId,
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
  history_access: RealmObject["history_access"];
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
  const issuedAt = canonicalTimestamp();
  const unsignedGrant: Record<string, unknown> = {
    schema: "ak.schema.capability.v1",
    realm_id: args.realmId,
    issuer: args.ownerDid,
    subject: args.subjectDid,
    subject_principal_server_id: solandServiceId(args.server),
    actions: ["ak.circle.member.manage"],
    capability_action_registry_digest: sdkCapabilityActionRegistryDigest(),
    resources: [
      { kind: "circle", realm_id: args.realmId, circle_id: args.circleId },
    ],
    constraints: [
      {
        constraint_kind: "scope_limitation",
        effect: "allow",
        allowed_circle_ids: [args.circleId],
      },
    ],
    issued_at: issuedAt,
    issuer_authority_refs: [
      {
        kind: "realm_root",
        realm_id: args.realmId,
        cell_ref: "ak:cell:ak.component.realm.authority_root.v1:null",
        controller_epoch_at_issuance: 0,
        authority_generation: 0,
      },
    ],
  };
  const envelope = signedEventEnvelope({
    actorDid: args.ownerDid,
    realmId: args.realmId,
    kind: "ak.capability.grant",
    payload: { grant: unsignedGrant },
    createdAt: issuedAt,
  });
  await submitSignedEventApi(
    request,
    ownerToken,
    envelope,
    {
      server: args.server,
      context: `grant ak.circle.member.manage for ${args.circleId} to ${args.subjectDid}`,
    },
  );
  return retypeEventDerivedId(String(envelope.event_id), "grant");
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
  const issuedAt = canonicalTimestamp();
  const unsignedGrant: Record<string, unknown> = {
    schema: "ak.schema.capability.v1",
    realm_id: args.realmId,
    issuer: args.ownerDid,
    subject: args.subjectDid,
    subject_principal_server_id: solandServiceId(args.server),
    actions: ["ak.circle.manage"],
    capability_action_registry_digest: sdkCapabilityActionRegistryDigest(),
    resources: [
      { kind: "circle", realm_id: args.realmId, circle_id: args.circleId },
    ],
    constraints: [
      {
        constraint_kind: "scope_limitation",
        effect: "allow",
        allowed_circle_ids: [args.circleId],
      },
    ],
    issued_at: issuedAt,
    issuer_authority_refs: [
      {
        kind: "realm_root",
        realm_id: args.realmId,
        cell_ref: "ak:cell:ak.component.realm.authority_root.v1:null",
        controller_epoch_at_issuance: 0,
        authority_generation: 0,
      },
    ],
  };
  const envelope = signedEventEnvelope({
    actorDid: args.ownerDid,
    realmId: args.realmId,
    kind: "ak.capability.grant",
    payload: { grant: unsignedGrant },
    createdAt: issuedAt,
  });
  await submitSignedEventApi(
    request,
    ownerToken,
    envelope,
    {
      server: args.server,
      context: `grant ak.circle.manage for ${args.circleId} to ${args.subjectDid}`,
    },
  );
  return retypeEventDerivedId(String(envelope.event_id), "grant");
}

// `display.short_name` derived from a Circle title, mirroring inkson's
// `ak_ops::circle_display_from_title`. It is a presentation default with no
// reducer meaning, so it belongs wherever the create payload is authored — which
// is the caller now that the service no longer builds that payload.
export function circleDisplayFromTitle(
  title: string,
): CircleOutcome["display"] {
  let shortName = Array.from(title)
    .filter((ch) => /[A-Za-z0-9 _-]/.test(ch))
    .join("")
    .trim();
  if (shortName.length === 0) {
    shortName = "Circle";
  }
  const first = shortName[0]!;
  if (/[a-z]/.test(first)) {
    shortName = first.toUpperCase() + shortName.slice(1);
  } else if (!/[A-Z]/.test(first)) {
    shortName = `C ${shortName}`;
  }
  return {
    short_name: shortName.slice(0, 24).trimEnd(),
    color_token: "slate",
    symbol: { glyph: "ring" },
  };
}

// The Circle object the caller signs into `ak.circle.create`.
//
// `id` and `mls_group_ref` are absent by construction, and the service rejects
// either one: the Circle id is `retype(create_event.event_id)` and the group ref
// is reducer-derived. Everything else is the actor's to choose, which is why the
// whole object lives inside the signed Event rather than in REST fields.
function circleCreateObject(args: {
  actorDid: string;
  realmId: string;
  title: string;
  summary?: string;
  joinRule?: string;
  directoryVisibility?: string;
  historyAccess?: "since_join" | "all_history_for_current_members";
  encryptionProfile?: string;
  createdAt: string;
}): Record<string, unknown> {
  const encryptionProfile = args.encryptionProfile ?? "mls_rfc9420";
  return {
    schema: "ak.schema.circle.v1",
    realm_id: args.realmId,
    title: args.title,
    ...(args.summary !== undefined ? { summary: args.summary } : {}),
    display: circleDisplayFromTitle(args.title),
    directory_visibility: args.directoryVisibility ?? "members",
    join_rule: args.joinRule ?? "invite",
    history_access: args.historyAccess ?? "since_join",
    encryption_profile: encryptionProfile,
    ...(encryptionProfile === "mls_rfc9420"
      ? { content_scheme: "mls_rfc9420" }
      : {}),
    state: "active",
    created_by: args.actorDid,
    created_at: args.createdAt,
  };
}

// Create a Circle bound to `realmId`. Defaults mirror the values the service
// used to fill in before the request body became the caller-signed Event
// (`members` / `invite` / `since_join` / `mls_rfc9420`), so admin-only one-way adds
// stay the membership path.
export async function createCircleArkret(
  request: APIRequestContext,
  token: string,
  args: {
    actorDid: string;
    realmId: string;
    title: string;
    joinRule?: string;
    directoryVisibility?: string;
    historyAccess?: RealmObject["history_access"];
    encryptionProfile?: string;
    summary?: string;
    server?: SolandKey;
  },
): Promise<CircleOutcome> {
  const createdAt = canonicalTimestamp();
  const createEvent = await prepareSignedEventSubmissionApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: args.actorDid,
      realmId: args.realmId,
      kind: "ak.circle.create",
      payload: { object: circleCreateObject({ ...args, createdAt }) },
      createdAt,
    }),
    { server: args.server, context: `prepare circle ${args.title}` },
  );
  const response = await request.post(
    `${solandBaseUrl(args.server)}/_arkret/self/circles`,
    {
      headers: { ...authHeaders(token), "content-type": "application/json" },
      data: canonicalJson({
        create_event: {
          ...createEvent,
        },
      }),
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
//
// `actorDid` is the caller who signs the Event — not `actorId`, the actor whose
// membership moves. The two differ on every admin pull, which is exactly the
// scenario this surface exists for: the puller signs, the pulled actor does
// nothing.
export async function addCircleMemberRaw(
  request: APIRequestContext,
  token: string,
  circleId: string,
  args: {
    actorDid: string;
    realmId: string;
    actorId: string;
    membership?: CircleMembership;
    server?: SolandKey;
  },
): Promise<APIResponse> {
  const memberEvent = await prepareSignedEventSubmissionApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: args.actorDid,
      realmId: args.realmId,
      kind: "ak.circle.member.state",
      payload: {
        circle_id: circleId,
        actor_id: args.actorId,
        membership: args.membership ?? "join",
      },
    }),
    { server: args.server, context: `prepare circle member ${args.actorId}` },
  );
  return await request.post(
    `${solandBaseUrl(args.server)}/_arkret/self/circles/${encodeURIComponent(circleId)}/members`,
    {
      headers: { ...authHeaders(token), "content-type": "application/json" },
      data: canonicalJson({
        member_event: {
          ...memberEvent,
        },
      }),
    },
  );
}

// Positive-path member add: asserts 2xx and returns the membership outcome.
export async function addCircleMemberArkret(
  request: APIRequestContext,
  token: string,
  circleId: string,
  args: {
    actorDid: string;
    realmId: string;
    actorId: string;
    membership?: CircleMembership;
    server?: SolandKey;
  },
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
  args: {
    actorDid: string;
    realmId: string;
    server?: SolandKey;
  },
): Promise<CircleMembershipOutcome> {
  const memberEvent = await prepareSignedEventSubmissionApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: args.actorDid,
      realmId: args.realmId,
      kind: "ak.circle.member.state",
      payload: {
        circle_id: circleId,
        actor_id: actorId,
        membership: "leave",
        expected_membership: "join",
      },
    }),
    { server: args.server, context: `prepare remove circle member ${actorId}` },
  );
  const response = await request.delete(
    `${solandBaseUrl(args.server)}/_arkret/self/circles/${encodeURIComponent(circleId)}/members/${encodeURIComponent(actorId)}`,
    {
      headers: { ...authHeaders(token), "content-type": "application/json" },
      data: canonicalJson({
        member_event: {
          ...memberEvent,
        },
      }),
    },
  );
  return await expectJsonOk<CircleMembershipOutcome>(
    response,
    `remove circle member ${actorId} <- ${circleId}`,
  );
}

// The three lifecycle endpoints share `object_lifecycle_payload`, which
// single-sources the target Circle by `target_ref`; the service checks it
// against the path. `reason` is free text on that payload — it is not a wire
// reason code, which is why the argument lost the `Code` suffix.
type CircleLifecycleArgs = {
  actorDid: string;
  realmId: string;
  reason?: string;
  server?: SolandKey;
};

async function submitCircleLifecycleArkret(
  request: APIRequestContext,
  token: string,
  circleId: string,
  action: "archive" | "restore" | "tombstone",
  args: CircleLifecycleArgs,
): Promise<CircleOutcome> {
  const lifecycleEvent = await prepareSignedEventSubmissionApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: args.actorDid,
      realmId: args.realmId,
      kind: `ak.circle.${action}`,
      payload: {
        target_ref: circleId,
        ...(args.reason !== undefined ? { reason: args.reason } : {}),
      },
    }),
    { server: args.server, context: `prepare ${action} circle ${circleId}` },
  );
  const response = await request.post(
    `${solandBaseUrl(args.server)}/_arkret/self/circles/${encodeURIComponent(circleId)}/${action}`,
    {
      headers: { ...authHeaders(token), "content-type": "application/json" },
      data: canonicalJson({
        lifecycle_event: {
          ...lifecycleEvent,
        },
      }),
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
  args: CircleLifecycleArgs,
): Promise<CircleOutcome> {
  return await submitCircleLifecycleArkret(
    request,
    token,
    circleId,
    "archive",
    args,
  );
}

export async function restoreCircleArkret(
  request: APIRequestContext,
  token: string,
  circleId: string,
  args: CircleLifecycleArgs,
): Promise<CircleOutcome> {
  return await submitCircleLifecycleArkret(
    request,
    token,
    circleId,
    "restore",
    args,
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
