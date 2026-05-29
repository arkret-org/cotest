// T-P0-05 joint harness smoke.
// Contract: true yougen UI + true soland process create a realm and render messages.

import { createHash, randomBytes } from "node:crypto";
import type { APIRequestContext } from "@playwright/test";
import { test, expect } from "../../helpers/joint-fixture";
import { listInvitesApi } from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("joint-yougen smoke @fully-implemented", () => {
  test("creates a public realm and renders a soland message in yougen", async ({
    jointRealm,
    request,
  }) => {
    const stamp = Date.now();
    const aliceMessage = `joint smoke from Alice ${stamp}`;

    await submitMessageEvent(
      request,
      jointRealm.aliceToken,
      jointRealm.alice.did,
      jointRealm.alicePage.serverUrl,
      jointRealm.spaceId,
      aliceMessage,
    );
    await jointRealm.alicePage.gotoTimelineSpace(jointRealm.spaceId);
    await expect(jointRealm.alicePage.timelineEvent(aliceMessage)).toBeVisible({
      timeout: 30_000,
    });
  });

  test("admin invite remains visible to invitee without poisoning account subscribe cursor", async ({
    browser,
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser("joint-invite-alice");
    const bob = uniqueUser("joint-invite-bob");
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
    const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });
    const subscribeFailures: string[] = [];

    alicePage.page.on("response", async (response) => {
      if (!response.url().includes("/api/v1/account/subscribe") || response.status() < 400) {
        return;
      }
      const body = await response.text().catch(() => "");
      subscribeFailures.push(`${response.status()} ${response.url()} ${body}`);
    });

    try {
      const spaceId = await alicePage.createSpace({
        title: `joint invite ${stamp}`,
        summary: "regression for write sync_token cursor poisoning",
        discoverability: "listed",
        joinRule: "invite",
        historyVisibility: "joined",
        encryptionProfile: "none",
      });
      await alicePage.inviteFromAdmin(spaceId, bob.did);

      await expect
        .poll(async () => {
          const invites = await listInvitesApi(request, bobToken);
          return invites.some(
            (invite) => invite.space_id === spaceId && invite.invitee === bob.did,
          );
        }, { timeout: 30_000 })
        .toBe(true);

      await bobPage.page.goto("/notifications", { waitUntil: "domcontentloaded" });
      await expect(
        bobPage.page.getByTestId("notification-item").filter({ hasText: spaceId }),
      ).toBeVisible({ timeout: 30_000 });

      await bobPage.acceptInvite(spaceId);
      await alicePage.page.waitForTimeout(6_500);

      expect(
        subscribeFailures.filter((failure) =>
          failure.includes("cursor_integrity_invalid") ||
          failure.includes("cursor principal does not match request actor"),
        ),
        subscribeFailures.join("\n"),
      ).toEqual([]);
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });
});

async function submitMessageEvent(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  serverUrl: string,
  spaceId: string,
  body: string,
) {
  const eventId = `cx:event:${uuidV7()}`;
  const createdAt = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const payload = {
    flow_id: flowIdFromSpaceId(spaceId),
    track: "discussion",
    content: {
      kind: "cx.content.text",
      body,
    },
    encrypted: false,
  };
  const envelope = {
    event_id: eventId,
    kind: "cx.message.create",
    realm_id: spaceId,
    actor_id: actorDid,
    actor_seq: 9_000_000_000_000_000,
    created_at: createdAt,
    prev_refs: [],
    refs: [],
    requirements: {
      schema: ["cx.schema.event.v1"],
      features: [],
      critical_extensions: [],
    },
    payload,
    proofs: [
      {
        type: "dev-proof",
        verification_method: `${actorDid}#device`,
        payload_digest: `sha256:${sha256CanonicalJson(payload)}`,
      },
    ],
  };

  const response = await request.post(`${serverUrl}/api/v1/events`, {
    headers: { authorization: `Bearer ${token}` },
    data: envelope,
  });
  const text = await response.text();
  expect([200, 201], `submit cx.message.create: ${text}`).toContain(response.status());
}

function flowIdFromSpaceId(spaceId: string): string {
  const suffix = spaceId.replace(/^cx:(realm|space):/, "");
  return `cx:flow:${suffix}`;
}

function sha256CanonicalJson(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

function uuidV7(): string {
  const time = Date.now().toString(16).padStart(12, "0").slice(-12);
  const random = randomBytes(9).toString("hex");
  const variant = (8 + (randomBytes(1)[0] & 0x03)).toString(16);
  return [
    time.slice(0, 8),
    time.slice(8, 12),
    `7${random.slice(0, 3)}`,
    `${variant}${random.slice(3, 6)}`,
    random.slice(6, 18),
  ].join("-");
}
