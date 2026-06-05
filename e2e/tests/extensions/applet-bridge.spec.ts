// Applet bridge (bot actor + ghost actor + portal realm)
// Contract: e2e/scenarios/extensions/applet-bridge.md
// Spec: extensions/applet-integration.md §3-§5, extensions/applet-schema.md

import { expect, test, type APIRequestContext } from "@playwright/test";
import { mockAppletRegistryBaseUrl, solandBaseUrl } from "../../helpers/env";
import {
  addRealmMemberApi,
  authHeaders,
  createRealmApi,
  queryRealmEventsApi,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

type SignedPackage = {
  applet_package: Record<string, unknown> & {
    applet_id: string;
    bot_actor_id: string;
    namespaces?: {
      handles?: Array<{ pattern: string }>;
    };
    registration_epoch: string;
    requested_scopes: string[];
  };
  package_digest: string;
  signing_did: string;
};

type AppletRegistration = {
  applet_id: string;
  bot_actor_did: string;
  portal_realm_id: string;
  namespace: string;
  status: string;
  registration_epoch: string;
};

test.describe("applet bridge", () => {
  test("applet package installs, bot joins space, ghost actor relays external messages with accountability chain", async ({
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
      const spaceId = await createRealmApi(request, aliceToken, {
        title: `applet-bridge Demo Space ${stamp}`,
        discoverability: "listed",
        history_visibility: "joined",
      });
      const signed = await signPackage(request, registryBase, {
        package_id: `package:bridge:demo-${stamp}`,
        namespace: `bridge.demo.${stamp}`,
        display_name: "Demo Bridge Applet",
        capabilities: ["realm:portal", "message:write", "actor:provision-ghost"],
      });
      const registration = await installApplet(
        request,
        aliceToken,
        signed,
        spaceId,
        `register-${stamp}`,
      );
      expect(registration.status).toBe("installed");
      expect(registration.bot_actor_did).toMatch(/^did:web:bot-bridge-demo-/);
      expect(registration.portal_realm_id).toBe(spaceId);

      await addRealmMemberApi(request, aliceToken, spaceId, registration.bot_actor_did);
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

      const events = await queryRealmEventsApi(request, aliceToken, spaceId);
      expect(JSON.stringify(events)).toContain(text);
      await alicePage.gotoTimelineRealm(spaceId);
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
        `${solandBaseUrl()}/_cokret/self/applets/${encodeURIComponent(
          registration.applet_id,
        )}/revoke`,
        {
          headers: authHeaders(aliceToken),
          data: {
            effective_scope: { kind: "realm", realm_id: spaceId },
            registration_epoch: registration.registration_epoch,
          },
        },
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
      expect(JSON.stringify(await queryRealmEventsApi(request, aliceToken, spaceId))).not.toContain(
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

    const spaceId = await createRealmApi(request, aliceToken, {
      title: `applet conflict ${stamp}`,
      discoverability: "listed",
      history_visibility: "joined",
    });

    const first = await signPackage(request, registryBase, {
      package_id: `package:bridge:conflict-a-${stamp}`,
      namespace,
    });
    await installApplet(request, aliceToken, first, spaceId, `conflict-first-${stamp}`);

    const second = await signPackage(request, registryBase, {
      package_id: `package:bridge:conflict-b-${stamp}`,
      namespace,
    });
    const denied = await rawInstallApplet(
      request,
      aliceToken,
      second,
      spaceId,
      `conflict-second-${stamp}`,
    );
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
    const spaceId = await createRealmApi(request, aliceToken, {
      title: `applet revoke ${stamp}`,
      discoverability: "listed",
      history_visibility: "joined",
    });
    const signed = await signPackage(request, registryBase, {
      package_id: `package:bridge:revoke-${stamp}`,
      namespace: `bridge.revoke.${stamp}`,
    });
    const registration = await installApplet(request, aliceToken, signed, spaceId, `revoke-${stamp}`);
    await addRealmMemberApi(request, aliceToken, spaceId, registration.bot_actor_did);

    const revoke = await request.post(
      `${solandBaseUrl()}/_cokret/self/applets/${encodeURIComponent(
        registration.applet_id,
      )}/revoke`,
      {
        headers: authHeaders(aliceToken),
        data: {
          effective_scope: { kind: "realm", realm_id: spaceId },
          registration_epoch: registration.registration_epoch,
        },
      },
    );
    expect(revoke.status()).toBe(200);

    const botWrite = await request.post(
      `${solandBaseUrl()}/_cokret/edge/applet/transactions`,
      {
        headers: authHeaders(aliceToken),
        data: {
          applet_id: registration.applet_id,
          realm_id: spaceId,
          payload: { kind: "message", text: `bot after revoke ${stamp}` },
        },
      },
    );
    expect(botWrite.status()).toBe(403);
    expect(wireErrCode(await botWrite.json())).toBe("bot_actor_revoked");

    const botDoc = await didDocument(request, aliceToken, registration.bot_actor_did);
    expect(botDoc.status).toBe("revoked");
  });

  test("E4.3 idempotency: same applet package + same Idempotency-Key returns original registration; different key conflicts", async ({
    request,
  }) => {
    const registryBase = requireMockAppletRegistry();
    const stamp = Date.now();
    const alice = uniqueUser(`applet-idem-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const spaceId = await createRealmApi(request, aliceToken, {
      title: `applet idem ${stamp}`,
      discoverability: "listed",
      history_visibility: "joined",
    });
    const signed = await signPackage(request, registryBase, {
      package_id: `package:bridge:idem-${stamp}`,
      namespace: `bridge.idem.${stamp}`,
    });

    const firstResponse = await rawInstallApplet(
      request,
      aliceToken,
      signed,
      spaceId,
      `idem-${stamp}`,
    );
    expect(firstResponse.status()).toBe(201);
    const first = installRegistrationFromResponse(signed, spaceId, await firstResponse.json());

    const secondResponse = await rawInstallApplet(
      request,
      aliceToken,
      signed,
      spaceId,
      `idem-${stamp}`,
    );
    expect(secondResponse.status()).toBe(200);
    const second = installRegistrationFromResponse(signed, spaceId, await secondResponse.json());
    expect(second.applet_id).toBe(first.applet_id);
    expect(second.bot_actor_did).toBe(first.bot_actor_did);

    const conflict = await rawInstallApplet(
      request,
      aliceToken,
      signed,
      spaceId,
      `idem-other-${stamp}`,
    );
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

async function signPackage(
  request: APIRequestContext,
  registryBase: string,
  data: Record<string, unknown>,
): Promise<SignedPackage> {
  const response = await request.post(`${registryBase}/sign-package`, { data });
  expect(response.status()).toBe(200);
  return (await response.json()) as SignedPackage;
}

async function installApplet(
  request: APIRequestContext,
  token: string,
  signed: SignedPackage,
  realmId: string,
  idempotencyKey: string,
): Promise<AppletRegistration> {
  const response = await rawInstallApplet(request, token, signed, realmId, idempotencyKey);
  expect(response.status()).toBe(201);
  return installRegistrationFromResponse(signed, realmId, await response.json());
}

async function rawInstallApplet(
  request: APIRequestContext,
  token: string,
  signed: SignedPackage,
  realmId: string,
  idempotencyKey: string,
) {
  const effectiveScope = { kind: "realm", realm_id: realmId };
  const preview = await request.post(
    `${solandBaseUrl()}/_cokret/self/applets/install/preview`,
    {
      headers: authHeaders(token),
      data: {
        applet_package: signed.applet_package,
        effective_scope: effectiveScope,
        approval_request: {
          approve_actions: signed.applet_package.requested_scopes,
          allow_ghost_actors: true,
          allow_delegated_native_actors: false,
          allow_e2ee_join: false,
          allow_widget: false,
        },
      },
    },
  );
  if (!preview.ok()) {
    return preview;
  }
  const plan = await preview.json();
  return await request.post(`${solandBaseUrl()}/_cokret/self/applets/install`, {
    headers: {
      ...authHeaders(token),
      "Idempotency-Key": idempotencyKey,
    },
    data: {
      plan_digest: plan.plan_digest,
      applet_package: signed.applet_package,
      effective_scope: effectiveScope,
      approved_scopes: plan.approved_scopes,
      actor_policy: {
        bot_membership: "join",
        ghost_actor_mode: "policy_declared",
      },
      e2ee_policy: { allow_mls_join: false },
      widget_policy: { allow_widget: false },
    },
  });
}

function installRegistrationFromResponse(
  signed: SignedPackage,
  realmId: string,
  response: Record<string, unknown>,
): AppletRegistration {
  return {
    applet_id: String(response.applet_id),
    bot_actor_did: String(response.bot_actor_id),
    portal_realm_id: realmId,
    namespace:
      signed.applet_package.namespaces?.handles?.[0]?.pattern ??
      signed.applet_package.applet_id,
    status: String(response.effective_status),
    registration_epoch: String(response.registration_epoch),
  };
}

async function didDocument(
  request: APIRequestContext,
  token: string,
  did: string,
): Promise<Record<string, unknown>> {
  const response = await request.get(
    `${solandBaseUrl()}/_cokret/root/identity/document?did=${encodeURIComponent(did)}`,
    { headers: authHeaders(token) },
  );
  expect(response.status()).toBe(200);
  return (await response.json()) as Record<string, unknown>;
}
