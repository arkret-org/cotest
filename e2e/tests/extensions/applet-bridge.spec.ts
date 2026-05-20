// Applet bridge (bot actor + ghost actor + portal realm)
// Contract: e2e/scenarios/extensions/applet-bridge.md
// Spec: extensions/applet-integration.md §3-§5, extensions/applet-schema.md
//
// soland gap: applet manifest verifier + bot/ghost DID provisioning + portal realm routing 未实现
// — the full chain (applet register → bot_actor_did issuance → ghost actor
// provisioning → portal-realm message routing → accountability trace) lives in
// the v1 spec but soland has no `/api/v1/extensions/applets/*` surface yet.
// Until that lands, the main flow and E4.x sub-tests are pinned as fixme so
// the spec contract stays visible in the suite.

import { test } from "@playwright/test";
import { optionalEnv } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

function mockAppletRegistryBaseUrl(): string | undefined {
  const port = optionalEnv("MOCK_APPLET_REGISTRY_PORT");
  return port ? `http://127.0.0.1:${port}` : undefined;
}

test.describe("applet bridge", () => {
  test.fixme(
    "applet registers, bot joins space, ghost actor relays external messages with accountability chain",
    async ({ browser, request }) => {
      // soland gap: applet manifest verifier + bot/ghost DID provisioning + portal realm routing 未实现
      //
      // Reference flow (see scenarios/extensions/applet-bridge.md):
      //   Phase A — applet_service signs manifest via mock-applet-registry;
      //             alice POSTs /api/v1/extensions/applets/register and gets
      //             { applet_id, bot_actor_did, portal_realm_id }.
      //   Phase B — alice creates space S, invites bot_actor_did via the
      //             admin Members section, mock-applet-registry accepts on
      //             bot's behalf, alice confirms bot is in member list.
      //   Phase C — mock POST /external-event provisions ghost_actor_did
      //             (DID Document accountability → bot + registry) and writes
      //             a portal-realm message routed onto space S.
      //   Phase D — alice timeline shows ghost message with ghost badge;
      //             GET /api/v1/identity/${ghost}/did-document exposes the
      //             two-level accountability chain.
      //   Phase E — alice revokes applet; subsequent /external-event calls
      //             see 403/409 with `applet_revoked`; historic DID docs
      //             remain readable but flagged `status: revoked`.
      const stamp = Date.now();
      const alice = uniqueUser(`applet-alice-${stamp}`);
      await ensureRegistered(request, alice);
      const aliceToken = await issueDevSession(request, alice);
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

      const registryBase = mockAppletRegistryBaseUrl();
      if (!registryBase) {
        throw new Error(
          "MOCK_APPLET_REGISTRY_PORT not set — start mock-applet-registry harness first",
        );
      }

      try {
        // Phase A — sign manifest + register applet (soland gap)
        // const signed = await request.post(`${registryBase}/sign-manifest`, {
        //   data: {
        //     manifest_id: `applet:bridge:demo-${stamp}`,
        //     namespace: "bridge.demo",
        //     display_name: "Demo Bridge Applet",
        //     capabilities: ["realm:portal", "message:write", "actor:provision-ghost"],
        //   },
        // });
        // const { manifest, signature } = await signed.json();
        // const reg = await request.post(
        //   `${solandBaseUrl()}/api/v1/extensions/applets/register`,
        //   {
        //     headers: { authorization: `Bearer ${aliceToken}` },
        //     data: { manifest, signature },
        //   },
        // );
        // const { applet_id, bot_actor_did, portal_realm_id } = await reg.json();

        // Phase B — alice creates space + invites bot
        // const spaceId = await alicePage.createSpace({
        //   title: `applet-bridge Demo Space ${stamp}`,
        //   discoverability: "listed",
        //   joinRule: "invite",
        //   historyVisibility: "joined",
        // });
        // await alicePage.inviteFromAdmin(spaceId, bot_actor_did);
        // await request.post(`${registryBase}/bot/${applet_id}/accept-invite`, {
        //   data: { space_id: spaceId },
        // });

        // Phase C — external event → ghost actor → portal-realm message
        // const evt = await request.post(`${registryBase}/external-event`, {
        //   data: {
        //     applet_id,
        //     space_id: spaceId,
        //     external_user: { id: "ext-user-X", display_name: "External X" },
        //     payload: { kind: "message", text: `hi from outside ${stamp}` },
        //   },
        // });
        // const { ghost_actor_did } = await evt.json();

        // Phase D — alice sees ghost message + accountability chain
        // await alicePage.gotoTimelineSpace(spaceId);
        // await expect(alicePage.page.getByTestId("timeline")).toContainText(
        //   `hi from outside ${stamp}`,
        //   { timeout: 30_000 },
        // );
        // const didDoc = await request.get(
        //   `${solandBaseUrl()}/api/v1/identity/${encodeURIComponent(ghost_actor_did)}/did-document`,
        //   { headers: { authorization: `Bearer ${aliceToken}` } },
        // );
        // const doc = await didDoc.json();
        // expect(doc.accountability).toEqual(
        //   expect.arrayContaining([
        //     expect.objectContaining({ kind: "bot_actor", did: bot_actor_did }),
        //     expect.objectContaining({ kind: "applet_registry" }),
        //   ]),
        // );

        // Phase E — revoke applet; subsequent ghost messages rejected
        // const revoke = await request.post(
        //   `${solandBaseUrl()}/api/v1/extensions/applets/${applet_id}/revoke`,
        //   { headers: { authorization: `Bearer ${aliceToken}` }, data: {} },
        // );
        // expect(revoke.status()).toBe(200);
        // const afterRevoke = await request.post(`${registryBase}/external-event`, {
        //   data: {
        //     applet_id,
        //     space_id: spaceId,
        //     external_user: { id: "ext-user-X", display_name: "External X" },
        //     payload: { kind: "message", text: `after revoke ${stamp}` },
        //   },
        // });
        // expect([403, 409]).toContain(afterRevoke.status());
        void alicePage;
      } finally {
        await alicePage.close();
      }
    },
  );

  test.fixme(
    "E4.1 namespace conflict: second applet claiming same namespace is rejected with 409 applet_namespace_conflict",
    async () => {
      // soland gap: applet manifest verifier + bot/ghost DID provisioning + portal realm routing 未实现
      //
      // After Phase A succeeds with namespace = "bridge.demo", a second
      // signed manifest with a fresh manifest_id but the same namespace must
      // be rejected by soland (409 + `applet_namespace_conflict`). The first
      // applet's bot_actor_did / portal_realm_id stay live and uninvited.
    },
  );

  test.fixme(
    "E4.2 capability revoke: after applet revoke, bot_actor's own message writes are also rejected (not just ghost path)",
    async () => {
      // soland gap: applet manifest verifier + bot/ghost DID provisioning + portal realm routing 未实现
      //
      // Revoke is a capability-layer action — the bot_actor_did still
      // resolves (GET /did-document returns 200 with status=revoked) but
      // POST /api/v1/spaces/${spaceId}/messages with bot's token returns
      // 403 + `bot_actor_revoked`. Confirms revoke isn't only a ghost-path
      // filter.
    },
  );

  test.fixme(
    "E4.3 idempotency: re-registering same manifest_id with same Idempotency-Key returns the original {applet_id, bot_actor_did}; different key + same manifest_id is 409 applet_already_registered",
    async () => {
      // soland gap: applet manifest verifier + bot/ghost DID provisioning + portal realm routing 未实现
      //
      // Two register calls with the same manifest_id:
      //   - same `Idempotency-Key` header → second call returns 200 with
      //     identical { applet_id, bot_actor_did } to the first.
      //   - different `Idempotency-Key` header → second call returns 409 +
      //     `applet_already_registered`.
    },
  );
});
