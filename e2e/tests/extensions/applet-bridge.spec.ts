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
    requested_scopes: string[];
  };
  package_digest: string;
  signing_did: string;
};

type AppletRegistration = {
  applet_id: string;
  bot_actor_id: string;
  portal_realm_id: string;
  namespace: string;
  status: string;
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
      const realmId = await createRealmApi(request, aliceToken, {
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
        realmId,
        `register-${stamp}`,
      );
      expect(registration.status).toBe("installed");
      expect(registration.bot_actor_id).toMatch(/^did:web:bot-bridge-demo-/);
      expect(registration.portal_realm_id).toBe(realmId);

      await addRealmMemberApi(request, aliceToken, realmId, registration.bot_actor_id);
      const accept = await request.post(
        `${registryBase}/bot/${encodeURIComponent(registration.applet_id)}/accept-invite`,
        { data: { realm_id: realmId } },
      );
      expect(accept.status()).toBe(200);
      expect((await accept.json()).status).toBe("joined");

      const text = `hi from outside ${stamp}`;
      const external = await request.post(`${registryBase}/external-event`, {
        headers: authHeaders(aliceToken),
        data: {
          soland_base_url: solandBaseUrl(),
          applet_id: registration.applet_id,
          realm_id: realmId,
          external_user: { id: "ext-user-X", display_name: "External X" },
          payload: { kind: "message", text },
        },
      });
      expect(external.status()).toBe(200);
      const externalBody = await external.json();
      const ghostActorDid = String(externalBody.ghost_actor_id);
      expect(ghostActorDid).toMatch(/^did:web:ghost-ext-user-x-/);
      expect(String(externalBody.message_id)).toMatch(/^ck:message:/);

      const events = await queryRealmEventsApi(request, aliceToken, realmId);
      expect(JSON.stringify(events)).toContain(text);
      await alicePage.gotoTimelineRealm(realmId);
      await expect(alicePage.page.getByTestId("timeline")).toContainText(text, {
        timeout: 30_000,
      });

      const ghostDoc = await didDocument(request, aliceToken, ghostActorDid);
      expect(ghostDoc.status).toBe("active");
      expect(ghostDoc.accountability).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ kind: "bot_actor", did: registration.bot_actor_id }),
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
            effective_scope: { kind: "realm", realm_id: realmId },
            reason_code: "revoke_test",
            revoke_mode: "revoke_all",
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
          realm_id: realmId,
          external_user: { id: "ext-user-X", display_name: "External X" },
          payload: { kind: "message", text: afterRevokeText },
        },
      });
      expect([403, 409]).toContain(afterRevoke.status());
      expect(wireErrCode(await afterRevoke.json())).toBe("applet_revoked");
      expect(JSON.stringify(await queryRealmEventsApi(request, aliceToken, realmId))).not.toContain(
        afterRevokeText,
      );

      const botDoc = await didDocument(request, aliceToken, registration.bot_actor_id);
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

    const realmId = await createRealmApi(request, aliceToken, {
      title: `applet conflict ${stamp}`,
      discoverability: "listed",
      history_visibility: "joined",
    });

    const first = await signPackage(request, registryBase, {
      package_id: `package:bridge:conflict-a-${stamp}`,
      namespace,
    });
    await installApplet(request, aliceToken, first, realmId, `conflict-first-${stamp}`);

    const second = await signPackage(request, registryBase, {
      package_id: `package:bridge:conflict-b-${stamp}`,
      namespace,
    });
    const denied = await rawInstallApplet(
      request,
      aliceToken,
      second,
      realmId,
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
    const realmId = await createRealmApi(request, aliceToken, {
      title: `applet revoke ${stamp}`,
      discoverability: "listed",
      history_visibility: "joined",
    });
    const signed = await signPackage(request, registryBase, {
      package_id: `package:bridge:revoke-${stamp}`,
      namespace: `bridge.revoke.${stamp}`,
    });
    const registration = await installApplet(request, aliceToken, signed, realmId, `revoke-${stamp}`);
    await addRealmMemberApi(request, aliceToken, realmId, registration.bot_actor_id);

    const revoke = await request.post(
      `${solandBaseUrl()}/_cokret/self/applets/${encodeURIComponent(
        registration.applet_id,
      )}/revoke`,
      {
        headers: authHeaders(aliceToken),
        data: {
          effective_scope: { kind: "realm", realm_id: realmId },
          reason_code: "revoke_test",
          revoke_mode: "revoke_all",
        },
      },
    );
    expect(revoke.status()).toBe(200);

    const botWrite = await request.post(
      `${solandBaseUrl()}/_soland/self/applets/${encodeURIComponent(
        registration.applet_id,
      )}/bot/messages`,
      {
        headers: authHeaders(aliceToken),
        data: {
          realm_id: realmId,
          payload: { kind: "message", text: `bot after revoke ${stamp}` },
        },
      },
    );
    expect(botWrite.status()).toBe(403);
    expect(wireErrCode(await botWrite.json())).toBe("bot_actor_revoked");

    const botDoc = await didDocument(request, aliceToken, registration.bot_actor_id);
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
    const realmId = await createRealmApi(request, aliceToken, {
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
      realmId,
      `idem-${stamp}`,
    );
    expect(firstResponse.status()).toBe(201);
    const first = installRegistrationFromResponse(signed, realmId, await firstResponse.json());

    const secondResponse = await rawInstallApplet(
      request,
      aliceToken,
      signed,
      realmId,
      `idem-${stamp}`,
    );
    expect(secondResponse.status()).toBe(200);
    const second = installRegistrationFromResponse(signed, realmId, await secondResponse.json());
    expect(second.applet_id).toBe(first.applet_id);
    expect(second.bot_actor_id).toBe(first.bot_actor_id);

    const conflict = await rawInstallApplet(
      request,
      aliceToken,
      signed,
      realmId,
      `idem-other-${stamp}`,
    );
    expect(conflict.status()).toBe(409);
    expect(wireErrCode(await conflict.json())).toBe("applet_already_registered");
  });
});

// COT-03-003 — inbound transaction-push per-delivery source signature negatives.
// Spec: extensions/applet-integration.md §7.3.1 (双向对称 normative). The inbound
// direction app/bridge → cokret edge (`POST /_cokret/edge/applet/transactions`)
// MUST verify an RFC 9421 HTTP Message Signature per delivery BEFORE processing any
// event / side-effect; a transaction push carrying only `Authorization: Bearer`
// (no `Signature`) MUST be rejected. These are pure negatives — they assert the
// receiver fails closed with the spec failure codes, so a soland that skips inbound
// source-signature verification (letting any bearer holder ghost-write under the
// "external applet delivery" identity) turns these into red, instead of being masked
// by the green happy path. The matching positive path (registry-private-key RFC 9421
// signature over @method/@target-uri/content-digest + Source-Service-DID) is driven
// by the bridge happy-path test once soland implements verification.
test.describe("applet inbound transaction push — per-delivery source signature negatives", () => {
  const TRANSACTIONS_PATH = "/_cokret/edge/applet/transactions";

  // Minimal well-formed transaction-push body. Source DID / events are realistic
  // enough that the request reaches the signature gate rather than failing on shape.
  function transactionPushBody(stamp: number) {
    return {
      source_service_did: "did:web:applet-bridge.joint-e2e.local",
      events: [
        {
          external_event_id: `ext-evt-${stamp}`,
          kind: "message",
          external_ref: { source_network: "demo-bridge", external_user_id: "ext-user-X" },
          payload: { kind: "message", text: `inbound push ${stamp}` },
        },
      ],
    };
  }

  // §7.3.1 failure codes carry the discriminating `reason`; `error.code` is the
  // generic `unauthorized`. Read the reason directly (NOT via wireErrCode, which
  // would surface `code` first).
  function signatureReason(body: unknown): string | undefined {
    if (!body || typeof body !== "object") {
      return undefined;
    }
    const record = body as Record<string, unknown>;
    const nested =
      record.error && typeof record.error === "object"
        ? (record.error as Record<string, unknown>)
        : undefined;
    const direct = record.reason;
    const inner = nested?.reason;
    if (typeof direct === "string") {
      return direct;
    }
    if (typeof inner === "string") {
      return inner;
    }
    return undefined;
  }

  async function setupBearer(request: APIRequestContext): Promise<string> {
    const stamp = Date.now();
    const alice = uniqueUser(`applet-inbound-${stamp}`);
    await ensureRegistered(request, alice);
    return issueDevSession(request, alice);
  }

  test("missing Signature (bearer-only) inbound transaction push → 401 http_signature_required", async ({
    request,
  }) => {
    const token = await setupBearer(request);
    const stamp = Date.now();
    // Only Authorization: Bearer, NO Signature / Signature-Input. §7.3.1: MUST reject.
    const resp = await request.post(`${solandBaseUrl()}${TRANSACTIONS_PATH}`, {
      headers: {
        ...authHeaders(token),
        "Source-Service-DID": "did:web:applet-bridge.joint-e2e.local",
        "Idempotency-Key": `inbound-nosig-${stamp}`,
      },
      data: transactionPushBody(stamp),
    });
    expect(resp.status()).toBe(401);
    expect(signatureReason(await resp.json())).toBe("http_signature_required");
  });

  test("invalid/forged Signature inbound transaction push → 401 http_signature_invalid", async ({
    request,
  }) => {
    const token = await setupBearer(request);
    const stamp = Date.now();
    // Structurally present but cryptographically bogus signature — cannot verify
    // against any registration service DID verification method. §7.3.1: reject.
    const resp = await request.post(`${solandBaseUrl()}${TRANSACTIONS_PATH}`, {
      headers: {
        ...authHeaders(token),
        "Source-Service-DID": "did:web:applet-bridge.joint-e2e.local",
        "Idempotency-Key": `inbound-badsig-${stamp}`,
        "Content-Digest": "sha-256=:b3JCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:",
        "Signature-Input":
          'sig1=("@method" "@target-uri" "@authority" "content-digest" "source-service-did" "destination-service-did" "idempotency-key");created=1700000000;expires=1700000200;keyid="did:web:applet-bridge.joint-e2e.local#key-1";alg="ed25519"',
        Signature: "sig1=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:",
      },
      data: transactionPushBody(stamp),
    });
    expect(resp.status()).toBe(401);
    expect(signatureReason(await resp.json())).toBe("http_signature_invalid");
  });

  test("expired signature window inbound transaction push → 401 signature_window_invalid", async ({
    request,
  }) => {
    const token = await setupBearer(request);
    const stamp = Date.now();
    // created/expires far in the past → outside the §7.3.1 freshness window
    // (expires-created ≤ 300s, created within ±30s skew, expires not past). Even
    // a byte-identical replay after replay-cache eviction MUST be rejected on the
    // created/expires check alone.
    const expired = await request.post(`${solandBaseUrl()}${TRANSACTIONS_PATH}`, {
      headers: {
        ...authHeaders(token),
        "Source-Service-DID": "did:web:applet-bridge.joint-e2e.local",
        "Idempotency-Key": `inbound-expired-${stamp}`,
        "Content-Digest": "sha-256=:b3JCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:",
        "Signature-Input":
          'sig1=("@method" "@target-uri" "@authority" "content-digest" "source-service-did" "destination-service-did" "idempotency-key");created=1000000000;expires=1000000200;keyid="did:web:applet-bridge.joint-e2e.local#key-1";alg="ed25519"',
        Signature: "sig1=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:",
      },
      data: transactionPushBody(stamp),
    });
    expect(expired.status()).toBe(401);
    expect(signatureReason(await expired.json())).toBe("signature_window_invalid");
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
    bot_actor_id: String(response.bot_actor_id),
    portal_realm_id: realmId,
    namespace:
      signed.applet_package.namespaces?.handles?.[0]?.pattern ??
      signed.applet_package.applet_id,
    status: String(response.effective_status),
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
