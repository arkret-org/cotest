// T-P0-05 joint harness smoke.
// Contract: true yougen UI + true soland process create a realm and render messages.

import { createHash, randomBytes } from "node:crypto";
import type { APIRequestContext } from "@playwright/test";
import { test, expect } from "../../helpers/joint-fixture";

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
