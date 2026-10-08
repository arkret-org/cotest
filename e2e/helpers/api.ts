import { expect, test, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl, solandServiceId, type SolandKey } from "./env";
import {
  accountActorId,
  authHeaders,
  acceptInviteApi,
  acceptPreparedInviteApi,
  waitForInviteDeliveryApi,
  canonicalJson,
  createRealmApi,
  grantCapabilityEventApi,
  resolveDefaultStrandId,
  scanRealmStreamApi,
  signedEventEnvelope,
  submitSignedEventApi,
} from "./soland-api";
import { addRealmMlsMemberApi } from "./soland-api/mls";
import type { InviteObject, RealmObject } from "./generated/spec-wire-objects";
import { allowExplicitInviteNotifications, issueUserSession, type JointUser } from "./users";

export { authHeaders };

export type ApiRealmOpts = {
  title: string;
  summary?: string;
  // Closed `realm.schema.json` enums, mirrored from the spec artifacts.
  discoverability?: RealmObject["default_discoverability"];
  historyAccess?: RealmObject["history_access"];
  /// Accept an `ak.mls.genesis` for the new Realm's scope
  /// (`createRealmApi` `mls_activated`).
  mlsActivated?: boolean;
  plaintextVisibleServices?: string[];
  invitees?: string[];
  inviteeStationIds?: Record<string, string>;
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
      mls_activated: opts.mlsActivated,
      plaintext_visible_services: opts.plaintextVisibleServices,
      invitees: opts.invitees,
      invitee_ids: opts.inviteeStationIds,
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
  listUrl.searchParams.set("subject_station_id", solandServiceId(opts.server));
  listUrl.searchParams.set("realm_id", realmId);
  let invite: InviteObject | undefined;
  await expect
    .poll(
      async () => {
        const list = await request.get(listUrl.toString(), {
          headers: {
            ...authHeaders(token, "GET", listUrl.toString()),
            "Arkret-Operation": "ak.self.authz.invites.read.list.v1",
          },
        });
        expect(list.status()).toBe(200);
        const body = (await list.json()) as {
          invites?: InviteObject[];
        };
        invite = (body.invites ?? []).find(
          (candidate) =>
            candidate.realm_id === realmId &&
            canonicalJson(candidate.invitee_account_id ?? null) ===
              canonicalJson(accountActorId(actorId, opts.server).account_id),
        );
        return Boolean(invite);
      },
      {
        message: `pending invite for ${actorId} in ${realmId}`,
        timeout: 60_000,
        intervals: [250, 500, 1_000, 2_000, 5_000],
      },
    )
    .toBe(true);

  await acceptInviteApi(request, token, actorId, realmId, invite!.id, opts);
}

export async function createSharedRealmViaApi(
  request: APIRequestContext,
  owner: JointUser,
  ownerToken: string,
  member: JointUser,
  opts: Omit<ApiRealmOpts, "invitees">,
): Promise<string> {
  const memberToken = await issueUserSession(request, member, { server: opts.server });
  await allowExplicitInviteNotifications(request, memberToken, opts.server);
  const realmId = await createRealmViaApi(request, ownerToken, {
    ...opts,
    ownerId: owner.id,
    invitees: [member.id],
    inviteeStationIds: { [member.id]: solandServiceId(opts.server) },
  });
  // A normal Realm has no implicit discussion Strand. This fixture promises a
  // shared messaging Realm, so establish the explicit Strand + default pointer
  // while the root controller is still the author.
  await test.step("shared Realm: establish explicit default Strand", () =>
    resolveDefaultStrandId(request, ownerToken, realmId));
  // The applicant consumes its private delivery and prepares through its own
  // Station before authoring the exact join, including on a colocated Station.
  const invitation = await test.step("shared Realm: own invitation delivery", () =>
    waitForInviteDeliveryApi(request, memberToken, member.id, realmId, opts.server ?? "server1"));
  await test.step("shared Realm: prepared invite accept and exact replay", () =>
    acceptPreparedInviteApi(request, memberToken, member.id, realmId, invitation.id, { server: opts.server }));
  if (opts.mlsActivated) {
    // The join advanced the scope's key-access revision; ciphertext is
    // admitted again only once an Add Commit covers it
    // (encryption-and-audit.md §2.4.1, §2.5.2).
    await addRealmMlsMemberApi(
      request,
      realmId,
      { id: member.id, deviceId: member.deviceId, token: memberToken, server: opts.server },
      { server: opts.server },
    );
  }
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
    server: opts.server,
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
  opts: { limit?: number; server?: SolandKey; order?: "ascending" | "descending" } = {},
): Promise<Array<Record<string, unknown>>> {
  const scan = await scanRealmStreamApi(request, token, realmId, {
    server: opts.server,
    limit: opts.limit ?? 50,
  });
  // service-http-binding.md: a `CommittedEventView` is either `{commit,event}`
  // or the closed withheld branch `{commit,event_disclosure}`; a withheld slot
  // discloses no Event, so the Event list carries only the full branch.
  const events = scan.events.filter(
    (event): event is Record<string, unknown> =>
      event !== undefined && event !== null,
  );
  return opts.order === "descending" ? [...events].reverse() : events;
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
