import { expect, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl, type SolandKey } from "./env";
import {
  createRealmApi,
  flowIdFromRealmId,
  signedEventEnvelope,
  submitSignedEventApi,
} from "./soland-api";
import type { JointUser } from "./users";

export function authHeaders(token: string) {
  return { authorization: `Bearer ${token}` };
}

export type ApiRealmOpts = {
  title: string;
  summary?: string;
  discoverability?: string;
  historyVisibility?: string;
  encryptionProfile?: string;
  plaintextVisibleServices?: string[];
  invitees?: string[];
  ownerDid?: string;
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
    track_scope?: "all";
  };
  position: {
    event_id: string;
    hlc: string;
  };
  updated_at: string;
};

// Thin wrapper over `createRealmApi` so tests share one canonical
// realm-creation flow while preserving the public discoverability default.
export async function createRealmViaApi(
  request: APIRequestContext,
  token: string,
  opts: ApiRealmOpts,
): Promise<string> {
  expect(opts.ownerDid, "createRealmViaApi requires opts.ownerDid for canonical events").toBeTruthy();
  return await createRealmApi(
    request,
    token,
    {
      title: opts.title,
      summary: opts.summary,
      discoverability: opts.discoverability ?? "public",
      history_visibility: opts.historyVisibility,
      encryption_profile: opts.encryptionProfile,
      plaintext_visible_services: opts.plaintextVisibleServices,
      invitees: opts.invitees,
      ownerDid: opts.ownerDid,
    },
    { server: opts.server },
  );
}

export async function acceptInviteViaApi(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  realmId: string,
  opts: { server?: SolandKey } = {},
) {
  const base = solandBaseUrl(opts.server);
  const list = await request.get(`${base}/_cokret/self/authz/invites`, {
    headers: authHeaders(token),
  });
  expect(list.status()).toBe(200);
  const body = (await list.json()) as {
    invites?: Array<{ invite_id: string; realm_id: string; invitee?: string }>;
  };
  const invite = (body.invites ?? []).find(
    (candidate) => candidate.realm_id === realmId && candidate.invitee === actorDid,
  );
  expect(invite, `pending invite for ${actorDid} in ${realmId}`).toBeTruthy();

  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid,
      realmId,
      kind: "ck.member.state",
      payload: {
        actor_id: actorDid,
        membership: "join",
        reason: "invite_accept",
        invite_ref: invite!.invite_id,
        delivery_status: "unroutable",
      },
    }),
    { server: opts.server, context: `accept invite ${invite!.invite_id}` },
  );
}

export async function createSharedRealmViaApi(
  request: APIRequestContext,
  owner: JointUser,
  ownerToken: string,
  member: JointUser,
  memberToken: string,
  opts: Omit<ApiRealmOpts, "invitees">,
): Promise<string> {
  const realmId = await createRealmViaApi(request, ownerToken, {
    ...opts,
    ownerDid: owner.did,
  });
  await submitSignedEventApi(
    request,
    ownerToken,
    signedEventEnvelope({
      actorDid: owner.did,
      realmId,
      kind: "ck.member.state",
      payload: {
        actor_id: member.did,
        member: member.did,
        membership: "join",
        delivery_status: "unroutable",
      },
    }),
    { server: opts.server, context: `join ${member.did}` },
  );
  void memberToken;
  return realmId;
}

export async function allowPlaintextMessagesViaApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  opts: { server?: SolandKey } = {},
) {
  void request;
  void token;
  void realmId;
  void opts;
}

// NOT a thin wrapper over `sendMessageApi` (soland-api.ts): `sendMessageApi`
// derives the signing actor from `GET /account/me` (the token's own account)
// and exposes no parameter for an explicit signer, whereas this helper signs
// with the caller-supplied `opts.actorDid` (asserted required). Multi-actor
// specs depend on sending as a DID that is not the token's `/account/me`, so
// delegating would change the signer and add a network round-trip. Since
// `sendMessageApi`'s exported signature must not change, the flow is kept here
// and shares the same primitives (signedEventEnvelope/submitSignedEventApi/
// flowIdFromRealmId) to prevent canonical drift.
export async function sendPlaintextMessageViaApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  body: string,
  opts: { actorDid?: string; server?: SolandKey } = {},
): Promise<ApiMessage> {
  expect(opts.actorDid, "sendPlaintextMessageViaApi requires opts.actorDid for canonical events").toBeTruthy();
  const envelope = signedEventEnvelope({
    actorDid: opts.actorDid!,
    realmId,
    kind: "ck.message.create",
    payload: {
      flow_id: flowIdFromRealmId(realmId),
      track_name: "discussion",
      content: {
        kind: "ck.content.text",
        body,
      },
      encrypted: false,
    },
  });
  await submitSignedEventApi(request, token, envelope, {
    server: opts.server,
    context: `send message ${body}`,
  });
  return {
    event_id: String(envelope.event_id),
    realm_id: realmId,
    actor_id: opts.actorDid,
  };
}

export async function listRealmEventsViaApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  opts: { limit?: number; server?: SolandKey } = {},
): Promise<Array<Record<string, unknown>>> {
  const response = await request.get(
    `${solandBaseUrl(opts.server)}/_cokret/self/events?realms=${encodeURIComponent(realmId)}&limit=${
      opts.limit ?? 50
    }`,
    { headers: authHeaders(token) },
  );
  expect(response.status()).toBe(200);
  const body = await response.json();
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
      return event.kind === "ck.read_cursor.advance" || event.event_kind === "ck.read_cursor.advance";
    })
    .map((event) => (event.payload ?? event) as ReadMarker);
}
