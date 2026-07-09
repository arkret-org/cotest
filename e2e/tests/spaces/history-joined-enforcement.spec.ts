// history_visibility=joined hides pre-join history on read paths.
// Contract: e2e/scenarios/spaces/history-joined-enforcement.md
// @blocking-on: soland#history-visibility-read-path

import { expect, test, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl, solandServiceDid } from "../../helpers/env";
import {
  authHeaders,
  accountSubscribeFramesApi,
  canonicalTimestamp,
  plaintextVisibleServiceDeclarations,
  resolveDefaultStrandId,
  singleDidNotary,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
  type JointUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("history_visibility=joined read enforcement @fully-implemented", () => {
  test("late member events query hides five pre-join messages and includes post-join messages", async ({
    request,
  }) => {
    const fixture = await createHistoryFixture(request, {
      historyVisibility: "joined",
      preCount: 5,
      postCount: 2,
      label: "joined-query-hide",
    });

    const bobBodies = await listMessageBodies(
      request,
      fixture.bobToken,
      fixture.realmId,
    );
    expect(bobBodies).toEqual(fixture.postBodies);
    expect(bobBodies).not.toEqual(expect.arrayContaining(fixture.preBodies));
  });

  test("late member events query keeps post-join message order stable", async ({
    request,
  }) => {
    const fixture = await createHistoryFixture(request, {
      historyVisibility: "joined",
      preCount: 2,
      postCount: 4,
      label: "joined-query-order",
    });

    await expect
      .poll(
        async () =>
          await listMessageBodies(request, fixture.bobToken, fixture.realmId),
        {
          timeout: 10_000,
        },
      )
      .toEqual(fixture.postBodies);
  });

  test("owner events query still sees the full joined-history timeline", async ({
    request,
  }) => {
    const fixture = await createHistoryFixture(request, {
      historyVisibility: "joined",
      preCount: 5,
      postCount: 2,
      label: "joined-owner-full",
    });

    const aliceBodies = await listMessageBodies(
      request,
      fixture.aliceToken,
      fixture.realmId,
    );
    expect(aliceBodies).toEqual([...fixture.preBodies, ...fixture.postBodies]);
  });

  test("shared visibility control allows a late member to read pre-join messages", async ({
    request,
  }) => {
    const fixture = await createHistoryFixture(request, {
      historyVisibility: "shared",
      preCount: 3,
      postCount: 2,
      label: "shared-control",
    });

    const bobBodies = await listMessageBodies(
      request,
      fixture.bobToken,
      fixture.realmId,
    );
    expect(bobBodies).toEqual([...fixture.preBodies, ...fixture.postBodies]);
  });

  test("streaming read paths also filter pre-join history for joined realms", async ({
    request,
  }) => {
    const fixture = await createHistoryFixture(request, {
      historyVisibility: "joined",
      preCount: 4,
      postCount: 1,
      label: "joined-streams",
    });

    const accountBodies = await accountSubscribeBodies(
      request,
      fixture.bobToken,
      fixture.realmId,
    );
    expect(accountBodies).toEqual(fixture.postBodies);

    const eventStreamBodies = await eventsSubscribeBodies(
      request,
      fixture.bobToken,
      fixture.realmId,
    );
    expect(eventStreamBodies).toEqual(fixture.postBodies);
  });
});

type HistoryFixture = {
  realmId: string;
  alice: JointUser;
  bob: JointUser;
  aliceToken: string;
  bobToken: string;
  preBodies: string[];
  postBodies: string[];
};

async function createHistoryFixture(
  request: APIRequestContext,
  opts: {
    historyVisibility: "joined" | "shared";
    preCount: number;
    postCount: number;
    label: string;
  },
): Promise<HistoryFixture> {
  const alice = uniqueUser(`${opts.label}-alice`);
  const bob = uniqueUser(`${opts.label}-bob`);
  await Promise.all([
    ensureRegistered(request, alice),
    ensureRegistered(request, bob),
  ]);
  const [aliceToken, bobToken] = await Promise.all([
    issueDevSession(request, alice),
    issueDevSession(request, bob),
  ]);

  const realmId = typedId("realm");
  const baseMs = Date.now();
  await createRealm(
    request,
    aliceToken,
    alice,
    realmId,
    opts.historyVisibility,
    createdAt(baseMs - 90_000),
  );

  const preBodies: string[] = [];
  for (let i = 0; i < opts.preCount; i += 1) {
    const body = `${opts.label} pre ${i + 1}`;
    preBodies.push(body);
    await createMessage(
      request,
      aliceToken,
      alice,
      realmId,
      body,
      createdAt(baseMs - 60_000 + i * 1_000),
    );
  }

  await joinMember(request, aliceToken, alice, bob, realmId, createdAt(baseMs));

  const postBodies: string[] = [];
  for (let i = 0; i < opts.postCount; i += 1) {
    const body = `${opts.label} post ${i + 1}`;
    postBodies.push(body);
    await createMessage(
      request,
      aliceToken,
      alice,
      realmId,
      body,
      createdAt(baseMs + 60_000 + i * 1_000),
    );
  }

  return { realmId, alice, bob, aliceToken, bobToken, preBodies, postBodies };
}

async function createRealm(
  request: APIRequestContext,
  token: string,
  actor: JointUser,
  realmId: string,
  historyVisibility: "joined" | "shared",
  createdAtValue: string,
) {
  const plaintextVisibleServices = plaintextVisibleServiceDeclarations([
    solandServiceDid(),
    "did:web:soland.local",
  ]);
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: actor.did,
      realmId,
      kind: "ak.realm.create",
      createdAt: createdAtValue,
      payload: {
        // realm_create_payload root is additionalProperties:false; the field
        // lives on the realm object (additionalProperties:true) below.
        object: {
          id: realmId,
          schema: "ak.schema.realm.v1",
          title: `history ${historyVisibility} ${Date.now()}`,
          summary: "cotest joined-history enforcement fixture",
          created_by: actor.did,
          trust_domain: "ak:trust_domain:soland.local",
          schema_refs: ["ak.schema.realm.v1"],
          default_discoverability: "public",
          default_join_rule: "invite",
          history_visibility: historyVisibility,
          encryption_profile: "none",
          plaintext_visible_services: plaintextVisibleServices,
          security_class: "standard",
          federation_policy: "restricted",
          notary_profile: "single_did",
          digest_algorithm: "sha256",
          notary: singleDidNotary(actor.did),
          created_at: createdAtValue,
        },
      },
    }),
    { context: `create ${historyVisibility} realm` },
  );
}

async function createMessage(
  request: APIRequestContext,
  token: string,
  actor: JointUser,
  realmId: string,
  body: string,
  createdAtValue: string,
) {
  const strandId = await resolveDefaultStrandId(request, token, realmId);
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: actor.did,
      realmId,
      kind: "ak.message.create",
      createdAt: createdAtValue,
      payload: {
        strand_id: strandId,
        track_name: "discussion",
        content: {
          kind: "ak.content.text",
          body,
        },
      },
    }),
    { context: `create message ${body}` },
  );
}

async function joinMember(
  request: APIRequestContext,
  token: string,
  actor: JointUser,
  member: JointUser,
  realmId: string,
  createdAtValue: string,
) {
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: actor.did,
      realmId,
      kind: "ak.member.state",
      createdAt: createdAtValue,
      payload: {
        // membership_payload requires realm_id (event-payload.schema.json);
        // soland's registry-backed validator rejects the op without it.
        realm_id: realmId,
        actor_id: member.did,
        membership: "join",
        delivery_status: "unroutable",
      },
    }),
    { context: `join ${member.did}` },
  );
}

async function listMessageBodies(
  request: APIRequestContext,
  token: string,
  realmId: string,
): Promise<string[]> {
  const response = await request.get(
    `${solandBaseUrl()}/_arkret/self/events?realms=${encodeURIComponent(realmId)}&limit=100`,
    { headers: authHeaders(token) },
  );
  const text = await response.text();
  expect(response.status(), `query ${realmId}: ${text}`).toBe(200);
  const body = JSON.parse(text) as { events?: Array<Record<string, unknown>> };
  return (body.events ?? [])
    .filter(isMessageEvent)
    .map(messageBody)
    .filter(isString);
}

async function accountSubscribeBodies(
  request: APIRequestContext,
  token: string,
  realmId: string,
): Promise<string[]> {
  const frames = await accountSubscribeFramesApi(request, token, {
    filter: { spaces: [realmId] },
  });
  const delta = frames.find((frame) => frame.kind === "delta") as
    | {
        realms?: Record<
          string,
          { timeline?: { events?: Array<Record<string, unknown>> } }
        >;
      }
    | undefined;
  const events = delta?.realms?.[realmId]?.timeline?.events ?? [];
  return events.map(messageBody).filter(isString);
}

async function eventsSubscribeBodies(
  request: APIRequestContext,
  token: string,
  realmId: string,
): Promise<string[]> {
  const response = await request.get(
    `${solandBaseUrl()}/_arkret/self/events/subscribe?realms=${encodeURIComponent(
      realmId,
    )}&limit=100&max_duration_ms=100&heartbeat_ms=100`,
    { headers: authHeaders(token) },
  );
  const text = await response.text();
  expect(response.status(), `events subscribe ${realmId}: ${text}`).toBe(200);
  return parseNdjson(text)
    .filter((frame) => frame.kind === "event")
    .map((frame) => messageBody(frame.payload))
    .filter(isString);
}

function isMessageEvent(event: Record<string, unknown>): boolean {
  return (
    event.event_kind === "ak.message.create" ||
    event.kind === "ak.message.create"
  );
}

function messageBody(event: unknown): string | undefined {
  if (!event || typeof event !== "object") {
    return undefined;
  }
  const record = event as Record<string, unknown>;
  const payload =
    record.payload && typeof record.payload === "object"
      ? (record.payload as Record<string, unknown>)
      : record;
  const content =
    payload.content && typeof payload.content === "object"
      ? (payload.content as Record<string, unknown>)
      : undefined;
  return isString(payload.body)
    ? payload.body
    : isString(content?.body)
      ? content.body
      : undefined;
}

function parseNdjson(text: string): Array<Record<string, unknown>> {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

function createdAt(ms: number): string {
  return canonicalTimestamp(new Date(ms));
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}
