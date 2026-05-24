import { expect, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl, solandServiceDid, type SolandKey } from "./env";
import {
  canonicalTimestamp,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
} from "./soland-api";
import type { JointUser } from "./users";

export function authHeaders(token: string) {
  return { authorization: `Bearer ${token}` };
}

export type ApiSpaceOpts = {
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
  space_id: string;
  sender?: string;
  sync_token?: string;
};

export type ReadMarker = {
  realm_id: string;
  actor_id: string;
  device_id: string;
  read_scope: {
    kind: string;
    ref?: string;
    track?: string;
  };
  position: {
    event_id: string;
    hlc: string;
  };
  updated_at: string;
};

export async function createSpaceViaApi(
  request: APIRequestContext,
  token: string,
  opts: ApiSpaceOpts,
): Promise<string> {
  expect(opts.ownerDid, "createSpaceViaApi requires opts.ownerDid for canonical events").toBeTruthy();
  const realmId = typedId("realm");
  const createdAt = canonicalTimestamp();
  const plaintextVisibleServices =
    opts.plaintextVisibleServices ??
    Array.from(new Set([solandServiceDid(opts.server), "did:web:soland.local"]));
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: opts.ownerDid!,
      realmId,
      kind: "cx.realm.create",
      createdAt,
      payload: {
        plaintext_visible_services: plaintextVisibleServices,
        object: {
          id: realmId,
          schema: "cx.schema.realm.v1",
          title: opts.title,
          summary: opts.summary,
          created_by_principal: opts.ownerDid!,
          trust_domain: "cx:trust_domain:soland.local",
          schema_refs: ["cx.schema.realm.v1"],
          default_discoverability: "public",
          default_join_rule: "invite",
          history_visibility: opts.historyVisibility ?? "shared",
          encryption_profile: opts.encryptionProfile ?? "none",
          plaintext_visible_services: plaintextVisibleServices,
          security_class: "standard",
          federation_policy: "restricted",
          anchor_profile: "single_did",
          digest_algorithm: "sha256",
          anchorer: {
            type: "single_did",
            did: opts.ownerDid!,
          },
          created_at: createdAt,
        },
      },
    }),
    { server: opts.server, context: `create realm ${opts.title}` },
  );

  for (const invitee of opts.invitees ?? []) {
    await submitSignedEventApi(
      request,
      token,
      signedEventEnvelope({
        actorDid: opts.ownerDid!,
        realmId,
        kind: "cx.member.state",
        payload: {
          actor_id: invitee,
          member: invitee,
          membership: "invite",
        },
      }),
      { server: opts.server, context: `invite ${invitee}` },
    );
  }

  return realmId;
}

export async function acceptInviteViaApi(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  spaceId: string,
  opts: { server?: SolandKey } = {},
) {
  const base = solandBaseUrl(opts.server);
  const list = await request.get(`${base}/api/v1/authz/invites`, {
    headers: authHeaders(token),
  });
  expect(list.status()).toBe(200);
  const body = (await list.json()) as {
    invites?: Array<{ invite_id: string; space_id: string; invitee?: string }>;
  };
  const invite = (body.invites ?? []).find(
    (candidate) => candidate.space_id === spaceId && candidate.invitee === actorDid,
  );
  expect(invite, `pending invite for ${actorDid} in ${spaceId}`).toBeTruthy();

  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid,
      realmId: spaceId,
      kind: "cx.member.state",
      payload: {
        actor_id: actorDid,
        membership: "join",
        reason: "invite_accept",
        invite_id: invite!.invite_id,
        delivery_status: "unroutable",
      },
    }),
    { server: opts.server, context: `accept invite ${invite!.invite_id}` },
  );
}

export async function createSharedSpaceViaApi(
  request: APIRequestContext,
  owner: JointUser,
  ownerToken: string,
  member: JointUser,
  memberToken: string,
  opts: Omit<ApiSpaceOpts, "invitees">,
): Promise<string> {
  const spaceId = await createSpaceViaApi(request, ownerToken, {
    ...opts,
    ownerDid: owner.did,
  });
  await submitSignedEventApi(
    request,
    ownerToken,
    signedEventEnvelope({
      actorDid: owner.did,
      realmId: spaceId,
      kind: "cx.member.state",
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
  return spaceId;
}

export async function allowPlaintextMessagesViaApi(
  request: APIRequestContext,
  token: string,
  spaceId: string,
  opts: { server?: SolandKey } = {},
) {
  void request;
  void token;
  void spaceId;
  void opts;
}

export async function sendPlaintextMessageViaApi(
  request: APIRequestContext,
  token: string,
  spaceId: string,
  body: string,
  opts: { actorDid?: string; server?: SolandKey } = {},
): Promise<ApiMessage> {
  expect(opts.actorDid, "sendPlaintextMessageViaApi requires opts.actorDid for canonical events").toBeTruthy();
  const envelope = signedEventEnvelope({
    actorDid: opts.actorDid!,
    realmId: spaceId,
    kind: "cx.message.create",
    payload: {
      flow_id: `cx:flow:${spaceId.replace(/^cx:(realm|space):/, "")}`,
      track: "discussion",
      content: {
        kind: "cx.content.text",
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
    space_id: spaceId,
    sender: opts.actorDid,
  };
}

export async function listSpaceEventsViaApi(
  request: APIRequestContext,
  token: string,
  spaceId: string,
  opts: { limit?: number; server?: SolandKey } = {},
): Promise<Array<Record<string, unknown>>> {
  const response = await request.get(
    `${solandBaseUrl(opts.server)}/api/v1/events?realms=${encodeURIComponent(spaceId)}&limit=${
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
  spaceId: string,
  opts: { server?: SolandKey } = {},
): Promise<ReadMarker[]> {
  const response = await request.get(
    `${solandBaseUrl(opts.server)}/api/v1/read-cursors?realm_id=${encodeURIComponent(spaceId)}`,
    { headers: authHeaders(token) },
  );
  expect(response.status()).toBe(200);
  const body = await response.json();
  expect(Array.isArray(body.markers)).toBe(true);
  return body.markers as ReadMarker[];
}
