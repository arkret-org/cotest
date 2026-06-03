// Applet bridge (bot actor + ghost actor + portal realm)
// Contract: e2e/scenarios/extensions/applet-bridge.md
// Spec: extensions/applet-integration.md §3-§5, extensions/applet-schema.md

import { expect, test, type APIRequestContext } from "@playwright/test";
import { mockAppletRegistryBaseUrl, solandBaseUrl } from "../../helpers/env";
import {
  addSpaceMemberApi,
  authHeaders,
  createSpaceApi,
  querySpaceEventsApi,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

type SignedManifest = {
  manifest: Record<string, unknown>;
  signature: string;
  manifest_signature?: string;
  signing_did: string;
};

type AppletRegistration = {
  applet_id: string;
  bot_actor_did: string;
  portal_realm_id: string;
  namespace: string;
  status: string;
};

test.describe("applet bridge", () => {
  test("applet registers, bot joins space, ghost actor relays external messages with accountability chain", async ({
    browser,
    request,
  }) => {
    const registryBase = requireMockAppletRegistry();
    const stamp = Date.now();
    const alice = uniqueUser(`applet-alice-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

    try {
      const signed = await signManifest(request, registryBase, {
        manifest_id: `applet:bridge:demo-${stamp}`,
        namespace: `bridge.demo.${stamp}`,
        display_name: "Demo Bridge Applet",
        capabilities: ["realm:portal", "message:write", "actor:provision-ghost"],
      });
      const registration = await registerApplet(request, aliceToken, signed, `register-${stamp}`);
      expect(registration.status).toBe("registered");
      expect(registration.bot_actor_did).toMatch(/^did:web:bot-bridge-demo-/);
      expect(registration.portal_realm_id).toMatch(/^ck:realm:portal:bridge-demo-/);

      const spaceId = await createSpaceApi(request, aliceToken, {
        title: `applet-bridge Demo Space ${stamp}`,
        discoverability: "listed",
        history_visibility: "joined",
      });
      await addSpaceMemberApi(request, aliceToken, spaceId, registration.bot_actor_did);
      const accept = await request.post(
        `${registryBase}/bot/${encodeURIComponent(registration.applet_id)}/accept-invite`,
        { data: { space_id: spaceId } },
      );
      expect(accept.status()).toBe(200);
      expect((await accept.json()).status).toBe("joined");

      const text = `hi from outside ${stamp}`;
      const external = await request.post(`${registryBase}/external-event`, {
        headers: authHeaders(aliceToken),
        data: {
          soland_base_url: solandBaseUrl(),
          applet_id: registration.applet_id,
          space_id: spaceId,
          external_user: { id: "ext-user-X", display_name: "External X" },
          payload: { kind: "message", text },
        },
      });
      expect(external.status()).toBe(200);
      const externalBody = await external.json();
      const ghostActorDid = String(externalBody.ghost_actor_did);
      expect(ghostActorDid).toMatch(/^did:web:ghost-ext-user-x-/);
      expect(String(externalBody.message_id)).toMatch(/^ck:message:/);

      const events = await querySpaceEventsApi(request, aliceToken, spaceId);
      expect(JSON.stringify(events)).toContain(text);
      await alicePage.gotoTimelineSpace(spaceId);
      await expect(alicePage.page.getByTestId("timeline")).toContainText(text, {
        timeout: 30_000,
      });

      const ghostDoc = await didDocument(request, aliceToken, ghostActorDid);
      expect(ghostDoc.status).toBe("active");
      expect(ghostDoc.accountability).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ kind: "bot_actor", did: registration.bot_actor_did }),
          expect.objectContaining({ kind: "applet_registry", did: signed.signing_did }),
        ]),
      );

      const revoke = await request.post(
        `${solandBaseUrl()}/api/v1/extensions/applets/${encodeURIComponent(
          registration.applet_id,
        )}/revoke`,
        { headers: authHeaders(aliceToken), data: {} },
      );
      expect(revoke.status()).toBe(200);
      expect((await revoke.json()).status).toBe("revoked");

      const afterRevokeText = `after revoke ${stamp}`;
      const afterRevoke = await request.post(`${registryBase}/external-event`, {
        headers: authHeaders(aliceToken),
        data: {
          soland_base_url: solandBaseUrl(),
          applet_id: registration.applet_id,
          space_id: spaceId,
          external_user: { id: "ext-user-X", display_name: "External X" },
          payload: { kind: "message", text: afterRevokeText },
        },
      });
      expect([403, 409]).toContain(afterRevoke.status());
      expect(wireErrCode(await afterRevoke.json())).toBe("applet_revoked");
      expect(JSON.stringify(await querySpaceEventsApi(request, aliceToken, spaceId))).not.toContain(
        afterRevokeText,
      );

      const botDoc = await didDocument(request, aliceToken, registration.bot_actor_did);
      const revokedGhostDoc = await didDocument(request, aliceToken, ghostActorDid);
      expect(botDoc.status).toBe("revoked");
      expect(revokedGhostDoc.status).toBe("revoked");
    } finally {
      await alicePage.close();
    }
  });

  test("E4.1 namespace conflict: second applet claiming same namespace is rejected with 409 applet_namespace_conflict", async ({
    request,
  }) => {
    const registryBase = requireMockAppletRegistry();
    const stamp = Date.now();
    const alice = uniqueUser(`applet-conflict-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const namespace = `bridge.conflict.${stamp}`;

    const first = await signManifest(request, registryBase, {
      manifest_id: `applet:bridge:conflict-a-${stamp}`,
      namespace,
    });
    await registerApplet(request, aliceToken, first, `conflict-first-${stamp}`);

    const second = await signManifest(request, registryBase, {
      manifest_id: `applet:bridge:conflict-b-${stamp}`,
      namespace,
    });
    const denied = await rawRegisterApplet(request, aliceToken, second, `conflict-second-${stamp}`);
    expect(denied.status()).toBe(409);
    expect(wireErrCode(await denied.json())).toBe("applet_namespace_conflict");
  });

  test("E4.2 capability revoke: after applet revoke, bot_actor's own message writes are also rejected", async ({
    request,
  }) => {
    const registryBase = requireMockAppletRegistry();
    const stamp = Date.now();
    const alice = uniqueUser(`applet-revoke-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const signed = await signManifest(request, registryBase, {
      manifest_id: `applet:bridge:revoke-${stamp}`,
      namespace: `bridge.revoke.${stamp}`,
    });
    const registration = await registerApplet(request, aliceToken, signed, `revoke-${stamp}`);
    const spaceId = await createSpaceApi(request, aliceToken, {
      title: `applet revoke ${stamp}`,
      discoverability: "listed",
      history_visibility: "joined",
    });
    await addSpaceMemberApi(request, aliceToken, spaceId, registration.bot_actor_did);

    const revoke = await request.post(
      `${solandBaseUrl()}/api/v1/extensions/applets/${encodeURIComponent(
        registration.applet_id,
      )}/revoke`,
      { headers: authHeaders(aliceToken), data: {} },
    );
    expect(revoke.status()).toBe(200);

    const botWrite = await request.post(
      `${solandBaseUrl()}/api/v1/extensions/applets/${encodeURIComponent(
        registration.applet_id,
      )}/bot/messages`,
      {
        headers: authHeaders(aliceToken),
        data: {
          space_id: spaceId,
          payload: { kind: "message", text: `bot after revoke ${stamp}` },
        },
      },
    );
    expect(botWrite.status()).toBe(403);
    expect(wireErrCode(await botWrite.json())).toBe("bot_actor_revoked");

    const botDoc = await didDocument(request, aliceToken, registration.bot_actor_did);
    expect(botDoc.status).toBe("revoked");
  });

  test("E4.3 idempotency: same manifest_id + same Idempotency-Key returns original registration; different key conflicts", async ({
    request,
  }) => {
    const registryBase = requireMockAppletRegistry();
    const stamp = Date.now();
    const alice = uniqueUser(`applet-idem-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const signed = await signManifest(request, registryBase, {
      manifest_id: `applet:bridge:idem-${stamp}`,
      namespace: `bridge.idem.${stamp}`,
    });

    const firstResponse = await rawRegisterApplet(request, aliceToken, signed, `idem-${stamp}`);
    expect(firstResponse.status()).toBe(201);
    const first = (await firstResponse.json()) as AppletRegistration;

    const secondResponse = await rawRegisterApplet(request, aliceToken, signed, `idem-${stamp}`);
    expect(secondResponse.status()).toBe(200);
    const second = (await secondResponse.json()) as AppletRegistration;
    expect(second.applet_id).toBe(first.applet_id);
    expect(second.bot_actor_did).toBe(first.bot_actor_did);

    const conflict = await rawRegisterApplet(request, aliceToken, signed, `idem-other-${stamp}`);
    expect(conflict.status()).toBe(409);
    expect(wireErrCode(await conflict.json())).toBe("applet_already_registered");
  });
});

function requireMockAppletRegistry(): string {
  const registryBase = mockAppletRegistryBaseUrl();
  test.skip(!registryBase, "mock-applet-registry not started for this run");
  if (!registryBase) {
    throw new Error("mock-applet-registry not started");
  }
  return registryBase;
}

async function signManifest(
  request: APIRequestContext,
  registryBase: string,
  data: Record<string, unknown>,
): Promise<SignedManifest> {
  const response = await request.post(`${registryBase}/sign-manifest`, { data });
  expect(response.status()).toBe(200);
  return (await response.json()) as SignedManifest;
}

async function registerApplet(
  request: APIRequestContext,
  token: string,
  signed: SignedManifest,
  idempotencyKey: string,
): Promise<AppletRegistration> {
  const response = await rawRegisterApplet(request, token, signed, idempotencyKey);
  expect(response.status()).toBe(201);
  return (await response.json()) as AppletRegistration;
}

async function rawRegisterApplet(
  request: APIRequestContext,
  token: string,
  signed: SignedManifest,
  idempotencyKey: string,
) {
  return await request.post(`${solandBaseUrl()}/api/v1/extensions/applets/register`, {
    headers: {
      ...authHeaders(token),
      "Idempotency-Key": idempotencyKey,
    },
    data: {
      manifest: signed.manifest,
      signature: signed.signature ?? signed.manifest_signature,
      trusted_registry_did: signed.signing_did,
    },
  });
}

async function didDocument(
  request: APIRequestContext,
  token: string,
  did: string,
): Promise<Record<string, unknown>> {
  const response = await request.get(
    `${solandBaseUrl()}/api/v1/identity/${encodeURIComponent(did)}/did-document`,
    { headers: authHeaders(token) },
  );
  expect(response.status()).toBe(200);
  return (await response.json()) as Record<string, unknown>;
}
