import { expect, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl, solandServiceDid, type SolandKey } from "./env";
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
  space_id: string;
  actor: string;
  scope_id: string;
  event_id: string;
  read_at: string;
};

export async function createSpaceViaApi(
  request: APIRequestContext,
  token: string,
  opts: ApiSpaceOpts,
): Promise<string> {
  const response = await request.post(`${solandBaseUrl(opts.server)}/api/v1/spaces`, {
    headers: authHeaders(token),
    data: {
      title: opts.title,
      summary: opts.summary,
      discoverability: opts.discoverability,
      history_visibility: opts.historyVisibility,
      encryption_profile: opts.encryptionProfile,
      plaintext_visible_services: opts.plaintextVisibleServices ?? [],
      invitees: opts.invitees ?? [],
    },
  });
  expect(response.status()).toBe(201);
  const body = await response.json();
  const spaceId = body.space_id ?? body.id;
  expect(spaceId).toMatch(/^cx:space:/);
  return spaceId;
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

  const accept = await request.post(`${base}/api/v1/spaces/${encodeURIComponent(spaceId)}/invite/accept`, {
    headers: authHeaders(token),
    data: { invite_id: invite!.invite_id },
  });
  expect(accept.status()).toBe(200);
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
    invitees: [member.did],
  });
  await acceptInviteViaApi(request, memberToken, member.did, spaceId, { server: opts.server });
  return spaceId;
}

export async function allowPlaintextMessagesViaApi(
  request: APIRequestContext,
  token: string,
  spaceId: string,
  opts: { server?: SolandKey } = {},
) {
  const response = await request.patch(
    `${solandBaseUrl(opts.server)}/api/v1/spaces/${encodeURIComponent(spaceId)}`,
    {
      headers: authHeaders(token),
      data: {
        plaintext_visible_services: [solandServiceDid(opts.server)],
      },
    },
  );
  expect(response.status()).toBe(200);
}

export async function sendPlaintextMessageViaApi(
  request: APIRequestContext,
  token: string,
  spaceId: string,
  body: string,
  opts: { server?: SolandKey } = {},
): Promise<ApiMessage> {
  const response = await request.post(`${solandBaseUrl(opts.server)}/api/v1/messages/send`, {
    headers: authHeaders(token),
    data: {
      space_id: spaceId,
      encrypted: false,
      content: {
        kind: "cx.content.text",
        body,
      },
    },
  });
  expect(response.status()).toBe(200);
  const payload = (await response.json()) as ApiMessage;
  expect(payload.event_id).toMatch(/^cx:event:/);
  expect(payload.space_id).toBe(spaceId);
  return payload;
}

export async function listSpaceEventsViaApi(
  request: APIRequestContext,
  token: string,
  spaceId: string,
  opts: { limit?: number; server?: SolandKey } = {},
): Promise<Array<Record<string, unknown>>> {
  const response = await request.get(
    `${solandBaseUrl(opts.server)}/api/v1/events?space_id=${encodeURIComponent(spaceId)}&limit=${
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
    `${solandBaseUrl(opts.server)}/api/v1/read-markers?space_id=${encodeURIComponent(spaceId)}`,
    { headers: authHeaders(token) },
  );
  expect(response.status()).toBe(200);
  const body = await response.json();
  expect(Array.isArray(body.markers)).toBe(true);
  return body.markers as ReadMarker[];
}
