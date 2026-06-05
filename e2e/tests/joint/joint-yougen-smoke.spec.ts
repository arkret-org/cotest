// T-P0-05 joint harness smoke.
// Contract: true yougen UI + true soland process create a realm and render messages.

import { randomBytes } from "node:crypto";
import type { APIRequestContext } from "@playwright/test";
import { test, expect } from "../../helpers/joint-fixture";
import { eventProof, listInvitesApi } from "../../helpers/soland-api";
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
    await jointRealm.alicePage.gotoTimelineRealm(jointRealm.spaceId);
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

    for (const observedPage of [alicePage.page, bobPage.page]) {
      observedPage.on("response", async (response) => {
        if (!response.url().includes("/_cokret/self/account/subscribe") || response.status() < 400) {
          return;
        }
        const body = await response.text().catch(() => "");
        subscribeFailures.push(`${response.status()} ${response.url()} ${body}`);
      });
    }

    try {
      const spaceId = await alicePage.createRealm({
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
            (invite) => invite.realm_id === spaceId && invite.invitee === bob.did,
          );
        }, { timeout: 30_000 })
        .toBe(true);

      await bobPage.page.goto("/notifications", { waitUntil: "domcontentloaded" });
      const inviteCard = bobPage.page.getByTestId("notification-item").filter({
        has: bobPage.page.locator(`[title="${spaceId}"]`),
      });
      await expect(inviteCard).toHaveCount(1, { timeout: 30_000 });
      await expect(inviteCard).toContainText("Realm invite");
      await expect(inviteCard).toContainText("You were invited to join");
      await inviteCard.getByTestId("notification-action").click();

      await expect(bobPage.page.getByTestId("notifications-status")).toContainText(
        /Joined Realm/,
        { timeout: 30_000 },
      );
      await expect(inviteCard).toHaveCount(0, { timeout: 30_000 });
      await expect(bobPage.page.getByTestId("space-list")).toContainText(
        `joint invite ${stamp}`,
        { timeout: 30_000 },
      );
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
  const eventId = `ck:event:${uuidV7()}`;
  const createdAt = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const payload = {
    flow_id: flowIdFromSpaceId(spaceId),
    track_name: "discussion",
    content: {
      kind: "ck.content.text",
      body,
    },
    encrypted: false,
  };
  const envelope = {
    event_id: eventId,
    kind: "ck.message.create",
    realm_id: spaceId,
    actor_id: actorDid,
    actor_seq: 9_000_000_000_000_000,
    created_at: createdAt,
    prev_refs: [],
    refs: [],
    requirements: {
      schema: ["ck.schema.event.v1"],
      features: [],
      critical_extensions: [],
    },
    payload,
    proofs: [eventProof({ actorDid, payload })],
  };

  const response = await request.post(`${serverUrl}/_cokret/self/events`, {
    headers: { authorization: `Bearer ${token}` },
    data: envelope,
  });
  const text = await response.text();
  expect([200, 201], `submit ck.message.create: ${text}`).toContain(response.status());
}

function flowIdFromSpaceId(spaceId: string): string {
  const suffix = spaceId.replace(/^ck:(realm|space):/, "");
  return `ck:flow:${suffix}`;
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
