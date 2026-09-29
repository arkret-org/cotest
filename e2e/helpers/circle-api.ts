// Circle administration HTTP helpers (`/_arkret/self/circles/*`).
//
// Face note: Circle administration is now a NORMATIVE Arkret protocol surface.
// The `ak.self.circle.*` operations (list/create/get/members/scope-rotate) are
// published in the arkret-spec OpenAPI artifact
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
// helpers take an `actorId` — a bearer token says who is calling, but only a
// DID can be the `actor_id` of a signed Event.

import type { APIRequestContext, APIResponse } from "@playwright/test";
import { type SolandKey, solandBaseUrl, solandServiceId } from "./env";
import type { RealmObject, CircleView, CircleMembershipOutcome } from "./generated/spec-wire-objects";
import {
  accountActorId,
  authHeaders,
  canonicalJson,
  canonicalTimestamp,
  expectJsonOk,
  prepareSignedEventSubmissionApi,
  realmAuthorityRootRef,
  signedEventEnvelope,
  submitSignedEventApi,
  retypeEventDerivedId,
  wireErrCode,
} from "./soland-api";

export type CircleOutcome = CircleView;
export type { CircleMembershipOutcome } from "./generated/spec-wire-objects";
export type CircleMembership = CircleMembershipOutcome["membership"];

// capability-grant.schema.json: a Realm-root issuer authority is the typed
// reference to the accepted Realm genesis Event at its authority generation.
function circleGrantRealmRootRef(realmId: string, server?: SolandKey) {
  const authorityEventRef = realmAuthorityRootRef(server, realmId);
  if (!authorityEventRef) {
    throw new Error(`Circle grant in ${realmId} has no accepted Realm genesis reference`);
  }
  return {
    kind: "realm_root",
    realm_id: realmId,
    authority_event_ref: authorityEventRef,
    authority_generation: 0,
  };
}

type CircleGrantArgs = {
  ownerId: string;
  realmId: string;
  subjectId: string;
  circleId: string;
  server?: SolandKey;
};

// A Circle-narrowed capability grant (capabilities.md: every Circle action
// MUST be narrowed by `allowed_circle_ids` or a `kind="circle"` resource).
async function grantCircleActionCapability(
  request: APIRequestContext,
  ownerToken: string,
  action: "ak.circle.manage" | "ak.circle.member.manage" | "ak.circle.member.add",
  args: CircleGrantArgs,
): Promise<string> {
  const issuedAt = canonicalTimestamp();
  const unsignedGrant: Record<string, unknown> = {
    schema: "ak.schema.capability.v1",
    realm_id: args.realmId,
    issuer_id: accountActorId(args.ownerId, args.server),
    subject: accountActorId(args.subjectId, args.server),
    actions: [action],
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
    issuer_authority_refs: [circleGrantRealmRootRef(args.realmId, args.server)],
  };
  const envelope = signedEventEnvelope({
    actorId: args.ownerId,
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
      context: `grant ${action} for ${args.circleId} to ${args.subjectId}`,
    },
  );
  return retypeEventDerivedId(String(envelope.event_id), "grant");
}

export async function grantCircleMemberManageCapability(
  request: APIRequestContext,
  ownerToken: string,
  args: CircleGrantArgs,
): Promise<string> {
  return await grantCircleActionCapability(request, ownerToken, "ak.circle.member.manage", args);
}

export async function grantCircleManageCapability(
  request: APIRequestContext,
  ownerToken: string,
  args: CircleGrantArgs,
): Promise<string> {
  return await grantCircleActionCapability(request, ownerToken, "ak.circle.manage", args);
}

// circle.md section 8: `ak.circle.member.add` is the self-service action for
// the subject's own membership (`payload.member_id == envelope.actor_id`),
// e.g. joining a `join_rule=public` Circle; parent Realm membership alone is
// only the enclosing scope floor, not this authorization.
export async function grantCircleMemberAddCapability(
  request: APIRequestContext,
  ownerToken: string,
  args: CircleGrantArgs,
): Promise<string> {
  return await grantCircleActionCapability(request, ownerToken, "ak.circle.member.add", args);
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
  actorId: string;
  server?: SolandKey;
  realmId: string;
  title: string;
  summary?: string;
  joinRule?: string;
  directoryVisibility?: string;
  historyAccess?: "since_join" | "all_history_for_current_members";
  createdAt: string;
}): Record<string, unknown> {
  return {
    schema: "ak.schema.circle.v1",
    realm_id: args.realmId,
    title: args.title,
    ...(args.summary !== undefined ? { summary: args.summary } : {}),
    display: circleDisplayFromTitle(args.title),
    directory_visibility: args.directoryVisibility ?? "members",
    join_rule: args.joinRule ?? "invite",
    history_access: args.historyAccess ?? "since_join",
    state: "active",
    created_by: accountActorId(args.actorId, args.server),
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
    actorId: string;
    realmId: string;
    title: string;
    joinRule?: string;
    directoryVisibility?: string;
    historyAccess?: RealmObject["history_access"];
    summary?: string;
    server?: SolandKey;
  },
): Promise<CircleOutcome> {
  const createdAt = canonicalTimestamp();
  const createEvent = await prepareSignedEventSubmissionApi(
    request,
    token,
    signedEventEnvelope({
      actorId: args.actorId,
      realmId: args.realmId,
      kind: "ak.circle.create",
      server: args.server,
      payload: { object: circleCreateObject({ ...args, createdAt }) },
      createdAt,
    }),
    { server: args.server, context: `prepare circle ${args.title}` },
  );
  const response = await request.post(
    `${solandBaseUrl(args.server)}/_arkret/self/circles`,
    {
      headers: { ...authHeaders(token, "POST", `${solandBaseUrl(args.server)}/_arkret/self/circles`), "content-type": "application/json" },
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
    { headers: authHeaders(token, "GET", `${solandBaseUrl(opts.server)}/_arkret/self/circles/${encodeURIComponent(circleId)}`) },
  );
  return await expectJsonOk<CircleOutcome>(response, `get circle ${circleId}`);
}

// The exact typed revision of `memberId`'s current parent Realm `member_state`
// (typed-current-result.schema.json `member_state_result.revision`), read from
// the caller-visible Realm state snapshot. circle.md section 9.1 item 1: a
// Circle `join` signs this `{commit_id, stream_position}` as
// `parent_membership_revision`; it is taken from a typed current any parent
// Realm member can read, never derived by the service.
export async function readParentMembershipRevisionApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  memberId: string,
  server?: SolandKey,
): Promise<{ commit_id: string; stream_position: number }> {
  const url = new URL(`${solandBaseUrl(server)}/_arkret/self/realm-state-snapshot/head`);
  url.searchParams.set("realm_id", realmId);
  const snapshot = await expectJsonOk<{
    current_state_entries?: Array<{
      selector?: { kind?: unknown; actor_id?: unknown };
      source_stream_ref?: { kind?: unknown; realm_id?: unknown };
      revision?: { commit_id: string; stream_position: number };
      value?: { membership?: unknown };
    }>;
  }>(
    await request.get(url.toString(), {
      headers: authHeaders(token, "GET", url.toString()),
    }),
    `read Realm state snapshot for ${realmId}`,
  );
  const memberKey = canonicalJson(accountActorId(memberId, server));
  const entries = (snapshot.current_state_entries ?? []).filter(
    (entry) =>
      entry.selector?.kind === "member_state" &&
      canonicalJson(entry.selector.actor_id) === memberKey &&
      entry.source_stream_ref?.kind === "realm" &&
      entry.source_stream_ref.realm_id === realmId,
  );
  if (entries.length !== 1 || entries[0]!.value?.membership !== "join" || !entries[0]!.revision) {
    throw new Error(
      `${memberId} has no single current parent Realm join in ${realmId}: ${JSON.stringify(entries)}`,
    );
  }
  return entries[0]!.revision;
}

// Write a Circle membership transition. Returns the raw APIResponse so negative
// scenarios can assert status + wire `code` without throwing.
//
// `signerId` is the caller who signs the Event, `actorId` the actor whose
// membership moves. common-fields.md section 4.5 fixes who may write each
// edge: `leave -> join` only by the target itself (or its exact invite
// acceptance), `knock -> join`, removal and ban by an authorized manager.
// circle.md section 9.1: the Event is committed on the Circle's own stream, so
// it signs `scope_ref={kind:"circle"}`, and a `join` carries the signed
// `parent_membership_revision` of the member's current parent Realm join.
export async function addCircleMemberRaw(
  request: APIRequestContext,
  token: string,
  circleId: string,
  args: {
    signerId: string;
    realmId: string;
    actorId: string;
    membership?: CircleMembership;
    server?: SolandKey;
  },
): Promise<APIResponse> {
  const membership = args.membership ?? "join";
  const parentMembershipRevision =
    membership === "join"
      ? await readParentMembershipRevisionApi(
          request,
          token,
          args.realmId,
          args.actorId,
          args.server,
        )
      : undefined;
  const memberEvent = await prepareSignedEventSubmissionApi(
    request,
    token,
    signedEventEnvelope({
      actorId: args.signerId,
      realmId: args.realmId,
      kind: "ak.circle.member.state",
      server: args.server,
      scopeRef: { kind: "circle", realm_id: args.realmId, circle_id: circleId },
      payload: {
        circle_id: circleId,
        member_id: accountActorId(args.actorId, args.server),
        membership,
        ...(parentMembershipRevision
          ? { parent_membership_revision: parentMembershipRevision }
          : {}),
      },
    }),
    { server: args.server, context: `prepare circle member ${args.actorId}` },
  );
  return await request.post(
    `${solandBaseUrl(args.server)}/_arkret/self/circles/${encodeURIComponent(circleId)}/members`,
    {
      headers: { ...authHeaders(token, "POST", `${solandBaseUrl(args.server)}/_arkret/self/circles/${encodeURIComponent(circleId)}/members`), "content-type": "application/json" },
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
    signerId: string;
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
    actorId: string;
    realmId: string;
    server?: SolandKey;
  },
): Promise<CircleMembershipOutcome> {
  const memberEvent = await prepareSignedEventSubmissionApi(
    request,
    token,
    signedEventEnvelope({
      actorId: args.actorId,
      realmId: args.realmId,
      kind: "ak.circle.member.state",
      server: args.server,
      scopeRef: { kind: "circle", realm_id: args.realmId, circle_id: circleId },
      payload: {
        circle_id: circleId,
        member_id: accountActorId(actorId, args.server),
        membership: "leave",
        expected_membership: "join",
      },
    }),
    { server: args.server, context: `prepare remove circle member ${actorId}` },
  );
  const response = await request.delete(
    `${solandBaseUrl(args.server)}/_arkret/self/circles/${encodeURIComponent(circleId)}/members/${encodeURIComponent(canonicalJson(accountActorId(actorId, args.server)))}`,
    {
      headers: { ...authHeaders(token, "DELETE", `${solandBaseUrl(args.server)}/_arkret/self/circles/${encodeURIComponent(circleId)}/members/${encodeURIComponent(canonicalJson(accountActorId(actorId, args.server)))}`), "content-type": "application/json" },
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

// The lifecycle helpers share `object_lifecycle_payload`, which single-sources
// the target Circle by `target_ref`. Lifecycle writes use the
// canonical Event submission surface directly; `reason` is free text on that
// payload, not a wire reason code.
type CircleLifecycleArgs = {
  actorId: string;
  realmId: string;
  reason?: string;
  server?: SolandKey;
};

async function submitCircleLifecycleArkret(
  request: APIRequestContext,
  token: string,
  circleId: string,
  action: "archive" | "restore",
  args: CircleLifecycleArgs,
): Promise<CircleOutcome> {
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorId: args.actorId,
      realmId: args.realmId,
      kind: `ak.circle.${action}`,
      payload: {
        target_ref: circleId,
        ...(args.reason !== undefined ? { reason: args.reason } : {}),
      },
    }),
    { server: args.server, context: `${action} circle ${circleId}` },
  );
  return await getCircleArkret(request, token, circleId, {
    server: args.server,
  });
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

// Read the sole canonical machine discriminator from RFC 9457 Problem Details.
export async function errorWireCode(
  response: APIResponse,
): Promise<string | undefined> {
  try {
    return wireErrCode(await response.json());
  } catch {
    return undefined;
  }
}
