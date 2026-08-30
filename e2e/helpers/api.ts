import { expect, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl, type SolandKey } from "./env";
import {
  authHeaders,
  acceptInviteApi,
  canonicalJson,
  createRealmApi,
  grantCapabilityEventApi,
  resolveDefaultStrandId,
  signedEventEnvelope,
  submitSignedEventApi,
} from "./soland-api";
import type { RealmObject } from "./generated/spec-wire-objects";
import type { JointUser } from "./users";

export { authHeaders };

export type ApiRealmOpts = {
  title: string;
  summary?: string;
  // Closed `realm.schema.json` enums, mirrored from the spec artifacts.
  discoverability?: RealmObject["default_discoverability"];
  historyAccess?: RealmObject["history_access"];
  encryptionProfile?: RealmObject["encryption_profile"];
  plaintextVisibleServices?: string[];
  invitees?: string[];
  ownerId?: string;
  server?: SolandKey;
};

export type ApiMessage = {
  event_id: string;
  operation_id?: string;
  realm_id: string;
  actor_id?: string;
  sync_token?: string;
};

export type ReadMarker = {
  realm_id: string;
  actor_id: string;
  device_id: string;
  read_scope: {
    kind: string;
    ref?: string;
    track_name?: string;
  };
  position: {
    event_id: string;
    hlc: string;
  };
  updated_at: string;
};

// Thin wrapper over `createRealmApi` so tests share one canonical
// realm-creation strand while preserving the public discoverability default.
export async function createRealmViaApi(
  request: APIRequestContext,
  token: string,
  opts: ApiRealmOpts,
): Promise<string> {
  expect(
    opts.ownerId,
    "createRealmViaApi requires opts.ownerId for canonical events",
  ).toBeTruthy();
  return await createRealmApi(
    request,
    token,
    {
      title: opts.title,
      summary: opts.summary,
      discoverability: opts.discoverability ?? "public",
      history_access: opts.historyAccess,
      encryption_profile: opts.encryptionProfile,
      plaintext_visible_services: opts.plaintextVisibleServices,
      invitees: opts.invitees,
      ownerId: opts.ownerId,
    },
    { server: opts.server },
  );
}

export async function acceptInviteViaApi(
  request: APIRequestContext,
  token: string,
  actorId: string,
  realmId: string,
  opts: { server?: SolandKey } = {},
) {
  const base = solandBaseUrl(opts.server);
  const listUrl = new URL("/_arkret/self/authz/invites", base);
  listUrl.searchParams.set("subject", actorId);
  listUrl.searchParams.set("realm_id", realmId);
  const list = await request.get(listUrl.toString(), {
    headers: {
      ...authHeaders(token, "GET", listUrl.toString()),
      "Arkret-Operation": "ak.self.authz.invites.read.list.v1",
    },
  });
  expect(list.status()).toBe(200);
  const body = (await list.json()) as {
    invites?: Array<{ id: string; realm_id: string; invitee_id?: string }>;
  };
  const invite = (body.invites ?? []).find(
    (candidate) =>
      candidate.realm_id === realmId && candidate.invitee_id === actorId,
  );
  expect(invite, `pending invite for ${actorId} in ${realmId}`).toBeTruthy();

  await acceptInviteApi(request, token, actorId, realmId, invite!.id, opts);
}

export async function createSharedRealmViaApi(
  request: APIRequestContext,
  owner: JointUser,
  ownerToken: string,
  member: JointUser,
  opts: Omit<ApiRealmOpts, "invitees">,
): Promise<string> {
  const realmId = await createRealmViaApi(request, ownerToken, {
    ...opts,
    ownerId: owner.id,
  });
  // A normal Realm has no implicit discussion Strand. This fixture promises a
  // shared messaging Realm, so establish the explicit Strand + default pointer
  // while the root controller is still the author.
  await resolveDefaultStrandId(request, ownerToken, realmId);
  await submitSignedEventApi(
    request,
    ownerToken,
    signedEventEnvelope({
      actorId: owner.id,
      realmId,
      kind: "ak.member.state",
      payload: {
        realm_id: realmId,
        actor_id: member.id,
        membership: "join",
        delivery_status: "unroutable",
      },
    }),
    { server: opts.server, context: `join ${member.id}` },
  );
  // Membership is not an authorization source. This fixture promises only
  // that both participants can author messages; tests exercising reactions,
  // revisions, or moderation must grant those independent actions explicitly.
  await grantCapabilityEventApi(request, ownerToken, {
    ownerId: owner.id,
    realmId,
    subjectId: member.id,
    actions: ["ak.message.create"],
    server: opts.server,
  });
  return realmId;
}

// NOT a thin wrapper over `sendMessageApi` (soland-api.ts): `sendMessageApi`
// derives the signing actor from `GET /account/me` (the token's own account)
// and exposes no parameter for an explicit signer, whereas this helper signs
// with the caller-supplied `opts.actorId` (asserted required). Multi-actor
// specs depend on sending as a DID that is not the token's `/account/me`, so
// delegating would change the signer and add a network round-trip. Since
// `sendMessageApi`'s exported signature must not change, the strand is kept here
// and shares the same primitives (signedEventEnvelope/submitSignedEventApi/
// resolveDefaultStrandId) to prevent canonical drift.
export async function sendPlaintextMessageViaApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  body: string,
  opts: { actorId?: string; server?: SolandKey; strandId?: string } = {},
): Promise<ApiMessage> {
  expect(
    opts.actorId,
    "sendPlaintextMessageViaApi requires opts.actorId for canonical events",
  ).toBeTruthy();
  const strandId =
    opts.strandId ??
    (await resolveDefaultStrandId(request, token, realmId, {
      server: opts.server,
    }));
  const envelope = signedEventEnvelope({
    actorId: opts.actorId!,
    realmId,
    kind: "ak.message.create",
    payload: {
      strand_id: strandId,
      track_name: "discussion",
      content: {
        kind: "ak.content.text",
        body,
      },
    },
  });
  await submitSignedEventApi(request, token, envelope, {
    server: opts.server,
    context: `send message ${body}`,
  });
  return {
    event_id: String(envelope.event_id),
    realm_id: realmId,
    actor_id: opts.actorId,
  };
}

export async function listRealmEventsViaApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  opts: { limit?: number; server?: SolandKey } = {},
): Promise<Array<Record<string, unknown>>> {
  const url = `${solandBaseUrl(opts.server)}/_arkret/self/events`;
  const response = await request.fetch(url, {
    method: "QUERY",
    data: canonicalJson({ realm_ids: [realmId], limit: opts.limit ?? 50 }),
    headers: {
      ...authHeaders(token, "QUERY", url),
      "content-type": "application/json",
    },
  });
  const responseText = await response.text();
  expect(
    response.status(),
    `list Realm events returned ${response.status()}: ${responseText}`,
  ).toBe(200);
  const body = JSON.parse(responseText);
  expect(Array.isArray(body.events)).toBe(true);
  return body.events;
}

export async function listReadMarkersViaApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  opts: { server?: SolandKey } = {},
): Promise<ReadMarker[]> {
  const events = await listRealmEventsViaApi(request, token, realmId, {
    server: opts.server,
    limit: 100,
  });
  return events
    .filter((event) => {
      return (
        event.kind === "ak.read_cursor.advance" ||
        event.event_kind === "ak.read_cursor.advance"
      );
    })
    .map((event) => (event.payload ?? event) as ReadMarker);
}
