// Applet bridge (bot actor + ghost actor + portal realm)
// Contract: e2e/scenarios/extensions/applet-bridge.md
// Spec: extensions/applet-integration.md §3-§5, extensions/applet-schema.md

import { createHash, createPrivateKey, sign } from "node:crypto";
import { expect, test, type APIRequestContext } from "@playwright/test";
import { mockAppletRegistryBaseUrl, solandBaseUrl, solandServiceDid } from "../../helpers/env";
import {
  addRealmMemberApi,
  authHeaders,
  canonicalTimestamp,
  canonicalJson,
  createRealmApi,
  queryRealmEventsApi,
  resolveDefaultStrandId,
  typedId,
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
    service_did: string;
    namespaces?: {
      handles?: Array<{ pattern: string }>;
    };
    requested_scopes: string[];
  };
  package_digest: string;
  signing_did: string;
  service_did_document?: Record<string, unknown>;
};

type AppletRegistration = {
  applet_id: string;
  bot_actor_id: string;
  portal_realm_id: string;
  namespace: string;
  status: string;
  capability_grant_refs: string[];
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
    const alicePage = await openUserPage(browser, alice, { sessionCredential: aliceToken });

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
      const externalText = await external.text();
      expect(external.status(), externalText).toBe(200);
      const externalBody = JSON.parse(externalText);
      const ghostActorDid = String(externalBody.ghost_actor_id);
      expect(ghostActorDid).toMatch(/^did:web:ghost-ext-user-x-/);
      expect(String(externalBody.message_id)).toMatch(/^ak:message:/);

      const events = await queryRealmEventsApi(request, aliceToken, realmId);
      expect(JSON.stringify(events)).toContain(text);
      await alicePage.gotoTimelineRealm(realmId);
      await expect(alicePage.page.getByTestId("message-list")).toContainText(text, {
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
        `${solandBaseUrl()}/_arkret/self/applets/${encodeURIComponent(
          registration.applet_id,
        )}/revoke`,
        {
          headers: authHeaders(aliceToken),
          data: {
            effective_scope: { kind: "realm", realm_id: realmId },
            reason_code: "revoke_test",
            revoke_mode: "revoke_runtime_only",
          },
        },
      );
      const revokeText = await revoke.text();
      expect(revoke.status(), revokeText).toBe(200);
      expect(JSON.parse(revokeText).ok).toBe(true);

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
      `${solandBaseUrl()}/_arkret/self/applets/${encodeURIComponent(
        registration.applet_id,
      )}/revoke`,
      {
        headers: authHeaders(aliceToken),
        data: {
          effective_scope: { kind: "realm", realm_id: realmId },
          reason_code: "revoke_test",
          revoke_mode: "revoke_runtime_only",
        },
      },
    );
    const revokeText = await revoke.text();
    expect(revoke.status(), revokeText).toBe(200);
    expect(JSON.parse(revokeText).ok).toBe(true);

    const botWrite = await request.post(
      `${solandBaseUrl()}/_soland/edge/applets/${encodeURIComponent(
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

  // COTEST-SEC-02: production-mode controller-signed package signature negative
  // tests. Spec: extensions/applet-integration.md §4.1 — `controller_did` MUST
  // sign the registration; `proof` MUST be a controller DID detached proof
  // covering the canonical registration object (excluding `proof` itself), and
  // a package whose proof does not cover its body MUST be rejected. soland's
  // canonical install validator (validate_applet_package) recomputes
  // `package_digest` over the bare body and recomputes the proof
  // `event_digest`; a package mutated after signing therefore fails closed at
  // the preview/commit gate. These run for real against soland in dev-mode —
  // no live deployment required — mirroring the runnable positive install case
  // above and the RFC 9421 inbound-signature negative cases below.

  test("E4.4 tampered package body: post-signing mutation breaks package_digest and is rejected with schema_violation", async ({
    request,
  }) => {
    const registryBase = requireMockAppletRegistry();
    const stamp = Date.now();
    const alice = uniqueUser(`applet-tamper-body-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `applet tamper body ${stamp}`,
      discoverability: "listed",
      history_visibility: "joined",
    });
    const signed = await signPackage(request, registryBase, {
      package_id: `package:bridge:tamper-body-${stamp}`,
      namespace: `bridge.tamper.body.${stamp}`,
    });

    // Mutate the signed package body WITHOUT re-signing: the sealed
    // `package_digest` and the controller proof now cover a different byte
    // sequence than what is submitted. soland recomputes the digest over the
    // bare body and MUST reject the mismatch.
    const tampered = tamperSignedPackage(signed, (pkg) => {
      pkg.requested_scopes = [...pkg.requested_scopes, "ak.applet.smuggled.scope"];
    });

    const denied = await rawInstallApplet(
      request,
      aliceToken,
      tampered,
      realmId,
      `tamper-body-${stamp}`,
    );
    expect([400, 409]).toContain(denied.status());
    expect(wireErrCode(await denied.json())).toBe("schema_violation");
  });

  test("E4.5 tampered proof: proof that no longer covers the package body is rejected with proof_invalid", async ({
    request,
  }) => {
    const registryBase = requireMockAppletRegistry();
    const stamp = Date.now();
    const alice = uniqueUser(`applet-tamper-proof-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `applet tamper proof ${stamp}`,
      discoverability: "listed",
      history_visibility: "joined",
    });
    const signed = await signPackage(request, registryBase, {
      package_id: `package:bridge:tamper-proof-${stamp}`,
      namespace: `bridge.tamper.proof.${stamp}`,
    });

    // Keep `package_digest` consistent with the body, but corrupt the proof's
    // `event_digest` so the controller proof no longer covers the canonical
    // registration object. §4.1: the proof MUST cover the body; soland
    // recomputes the payload digest and MUST reject the mismatch.
    const tampered = tamperSignedPackage(signed, (pkg) => {
      const proof = pkg.proof as Record<string, unknown> | undefined;
      if (!proof) {
        throw new Error("signed package is missing controller proof");
      }
      proof.event_digest = `sha256:${"0".repeat(64)}`;
    });

    const denied = await rawInstallApplet(
      request,
      aliceToken,
      tampered,
      realmId,
      `tamper-proof-${stamp}`,
    );
    expect([400, 409]).toContain(denied.status());
    expect(wireErrCode(await denied.json())).toBe("proof_invalid");
  });
});

// Spec: extensions/applet-integration.md §7.3.1. The inbound direction
// app/bridge → arkret edge (`POST /_arkret/edge/applet/transactions`) MUST
// verify an RFC 9421 HTTP Message Signature per delivery before processing any
// event or side effect.
test.describe("applet inbound transaction push — per-delivery source signature", () => {
  const TRANSACTIONS_PATH = "/_arkret/edge/applet/transactions";

  function transactionPushBody(args: {
    stamp: number;
    sourceServiceDid?: string;
    realmId?: string;
    actorDid?: string;
    appletId?: string;
    authorizationRef?: string;
    strandId?: string;
  }) {
    const sourceServiceDid = args.sourceServiceDid ?? "did:web:applet-bridge.joint-e2e.local";
    const realmId = args.realmId ?? typedId("realm");
    const actorDid = args.actorDid ?? `did:web:bot-applet-${args.stamp}.joint-e2e.local`;
    const event = {
      event_id: typedId("event"),
      kind: "ak.message.create",
      realm_id: realmId,
      actor_id: actorDid,
      actor_seq: 1,
      created_at: canonicalTimestamp(),
      hlc: hlcForStamp(args.stamp),
      prev_refs: [],
      refs: [],
      requirements: {
        schema: ["ak.schema.message.v1"],
      },
      payload: {
        strand_id: args.strandId ?? typedId("strand"),
        track_name: "discussion",
        content: { kind: "ak.content.text", body: `inbound push ${args.stamp}` },
      },
      executed_by: sourceServiceDid,
      authorization_ref: args.authorizationRef ?? typedId("grant"),
      applet_id: args.appletId ?? typedAppletId(),
      external_ref: {
        protocol: "demo-bridge",
        external_id: `ext-evt-${args.stamp}`,
        external_user_id: "ext-user-X",
      },
    };
    return {
      source_service_did: sourceServiceDid,
      events: [
        {
          ...event,
          proofs: [appletEventProof(sourceServiceDid, event)],
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

  test("valid applet service signature inbound transaction push → 200 accepted", async ({
    request,
  }) => {
    const registryBase = requireMockAppletRegistry();
    const stamp = Date.now();
    const alice = uniqueUser(`applet-inbound-ok-${stamp}`);
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);
    const realmId = await createRealmApi(request, token, {
      title: `applet inbound signed ${stamp}`,
      discoverability: "listed",
      history_visibility: "joined",
    });
    const sourceServiceDid =
      `did:webvh:z6mkfixture:applet-inbound-${stamp}.joint-e2e.local`;
    const signed = await signPackage(request, registryBase, {
      package_id: `package:bridge:inbound-${stamp}`,
      namespace: `bridge.inbound.${stamp}`,
      service_did: sourceServiceDid,
      capabilities: ["message:write"],
      webhook_auth: {
        type: "http_message_signature",
        key_ref: `${sourceServiceDid}#applet-service-key`,
        accepted_algs: ["EdDSA"],
      },
    });
    const registration = await installApplet(request, token, signed, realmId, `inbound-install-${stamp}`);
    await addRealmMemberApi(request, token, realmId, registration.bot_actor_id);

    const idempotencyKey = `inbound-ok-${stamp}`;
    const body = transactionPushBody({
      stamp,
      sourceServiceDid,
      realmId,
      actorDid: registration.bot_actor_id,
      appletId: registration.applet_id,
      authorizationRef: registration.capability_grant_refs[0],
      strandId: await resolveDefaultStrandId(request, token, realmId),
    });
    const targetUri = `${solandBaseUrl()}${TRANSACTIONS_PATH}`;
    const resp = await request.post(targetUri, {
      headers: {
        ...authHeaders(token),
        ...signedAppletTransactionHeaders({
          body,
          targetUri,
          sourceServiceDid,
          destinationServiceDid: solandServiceDid(),
          idempotencyKey,
        }),
      },
      data: body,
    });
    const responseText = await resp.text();
    expect(resp.status(), responseText).toBe(200);
    const outcome = JSON.parse(responseText) as { ok?: boolean; rejected?: unknown[] };
    expect(outcome.ok).toBe(true);
    expect(outcome.rejected ?? []).toEqual([]);
  });

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
      data: transactionPushBody({ stamp }),
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
      data: transactionPushBody({ stamp }),
    });
    expect(resp.status()).toBe(401);
    expect(signatureReason(await resp.json())).toBe("http_signature_invalid");
  });

  test("expired signature window inbound transaction push → 401 signature_window_invalid", async ({
    request,
  }) => {
    const token = await setupBearer(request);
    const stamp = Date.now();
    const sourceServiceDid = "did:web:applet-bridge.joint-e2e.local";
    const idempotencyKey = `inbound-expired-${stamp}`;
    const body = transactionPushBody({ stamp, sourceServiceDid });
    const targetUri = `${solandBaseUrl()}${TRANSACTIONS_PATH}`;
    // created/expires far in the past → outside the §7.3.1 freshness window
    // (expires-created ≤ 300s, created within ±30s skew, expires not past). Even
    // a byte-identical replay after replay-cache eviction MUST be rejected on the
    // created/expires check alone.
    const expired = await request.post(targetUri, {
      headers: {
        ...authHeaders(token),
        ...signedAppletTransactionHeaders({
          body,
          targetUri,
          sourceServiceDid,
          destinationServiceDid: solandServiceDid(),
          idempotencyKey,
          created: 1_000_000_000,
          expires: 1_000_000_200,
        }),
      },
      data: body,
    });
    expect(expired.status()).toBe(401);
    expect(signatureReason(await expired.json())).toBe("signature_window_invalid");
  });
});

function signedAppletTransactionHeaders(args: {
  body: Record<string, unknown>;
  targetUri: string;
  sourceServiceDid: string;
  destinationServiceDid: string;
  idempotencyKey: string;
  created?: number;
  expires?: number;
}): Record<string, string> {
  const canonicalBody = Buffer.from(canonicalJson(args.body), "utf8");
  const contentDigest = `sha-256=:${createHash("sha256").update(canonicalBody).digest("base64")}:`;
  const created = args.created ?? Math.floor(Date.now() / 1000);
  const expires = args.expires ?? created + 300;
  const keyid = `${args.sourceServiceDid}#applet-service-key`;
  const signatureParams =
    `("@method" "@target-uri" "@authority" "content-digest" ` +
    `"source-service-did" "destination-service-did" "idempotency-key");` +
    `created=${created};expires=${expires};keyid="${keyid}";alg="ed25519"`;
  const signatureBase = [
    `"@method": POST`,
    `"@target-uri": ${args.targetUri}`,
    `"@authority": ${new URL(args.targetUri).host}`,
    `"content-digest": ${contentDigest}`,
    `"source-service-did": ${args.sourceServiceDid}`,
    `"destination-service-did": ${args.destinationServiceDid}`,
    `"idempotency-key": ${args.idempotencyKey}`,
    `"@signature-params": ${signatureParams}`,
  ].join("\n");
  const signature = sign(
    null,
    Buffer.from(signatureBase, "utf8"),
    developmentAppletPrivateKey(keyid),
  );
  return {
    "content-digest": contentDigest,
    "source-service-did": args.sourceServiceDid,
    "destination-service-did": args.destinationServiceDid,
    "idempotency-key": args.idempotencyKey,
    "signature-input": `sig1=${signatureParams}`,
    signature: `sig1=:${signature.toString("base64")}:`,
  };
}

function developmentAppletPrivateKey(verificationMethod: string) {
  const seed = createHash("sha256")
    .update("soland:applet-service-key:")
    .update(verificationMethod)
    .digest();
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return createPrivateKey({
    key: Buffer.concat([pkcs8Prefix, seed]),
    format: "der",
    type: "pkcs8",
  });
}

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

// Deep-clone a controller-signed package and mutate its `applet_package` body
// WITHOUT re-sealing or re-signing, so the submitted bytes diverge from what the
// sealed `package_digest` / controller proof cover. Used by the COTEST-SEC-02
// production-mode signature negative tests.
function tamperSignedPackage(
  signed: SignedPackage,
  mutate: (appletPackage: SignedPackage["applet_package"]) => void,
): SignedPackage {
  const cloned = structuredClone(signed);
  mutate(cloned.applet_package);
  return cloned;
}

async function installApplet(
  request: APIRequestContext,
  token: string,
  signed: SignedPackage,
  realmId: string,
  idempotencyKey: string,
): Promise<AppletRegistration> {
  const response = await rawInstallApplet(request, token, signed, realmId, idempotencyKey);
  const responseText = await response.text();
  expect(response.status(), responseText).toBe(201);
  return installRegistrationFromResponse(signed, realmId, JSON.parse(responseText));
}

async function rawInstallApplet(
  request: APIRequestContext,
  token: string,
  signed: SignedPackage,
  realmId: string,
  idempotencyKey: string,
) {
  await publishAppletServiceDidDocument(request, signed);
  const effectiveScope = { kind: "realm", realm_id: realmId };
  const preview = await request.post(
    `${solandBaseUrl()}/_arkret/self/applets/install/preview`,
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
  return await request.post(`${solandBaseUrl()}/_arkret/self/applets/install`, {
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

async function publishAppletServiceDidDocument(
  request: APIRequestContext,
  signed: SignedPackage,
): Promise<void> {
  if (!signed.service_did_document) {
    return;
  }
  const response = await request.post(
    `${solandBaseUrl()}/_arkret/root/identity/submit-did-operation`,
    {
      data: {
        did: signed.applet_package.service_did,
        did_method: didMethod(signed.applet_package.service_did),
        operation: {
          type: "replace",
          state: signed.service_did_document,
        },
        proofs: [],
      },
    },
  );
  const responseText = await response.text();
  expect(response.status(), responseText).toBe(200);
}

function didMethod(did: string): string {
  const match = /^did:([^:]+):/.exec(did);
  if (!match) {
    throw new Error(`invalid DID: ${did}`);
  }
  return `did:${match[1]}`;
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
    capability_grant_refs: Array.isArray(response.capability_grant_refs)
      ? response.capability_grant_refs.map(String)
      : [],
  };
}

function typedAppletId(): string {
  return typedId("operation").replace("ak:operation:", "ak:applet:");
}

function appletEventProof(
  sourceServiceDid: string,
  event: Record<string, unknown>,
): Record<string, unknown> {
  const eventDigest = `sha256:${createHash("sha256").update(canonicalJson(event)).digest("hex")}`;
  return {
    kind: "detached_jws",
    alg: "EdDSA",
    verification_method: `${sourceServiceDid}#applet-service-key`,
    event_digest: eventDigest,
    created_at: canonicalTimestamp(),
    jws: Buffer.from(`${eventDigest}:joint-e2e`).toString("base64url"),
  };
}

function hlcForStamp(stamp: number): string {
  const physical = Math.max(Date.now(), stamp).toString(16).padStart(12, "0").slice(-12);
  const node = createHash("sha256").update(String(stamp)).digest("hex").slice(0, 8);
  return `${physical}-0000-${node}`;
}

async function didDocument(
  request: APIRequestContext,
  token: string,
  did: string,
): Promise<Record<string, unknown>> {
  const response = await request.get(
    `${solandBaseUrl()}/_arkret/root/identity/document?did=${encodeURIComponent(did)}`,
    { headers: authHeaders(token) },
  );
  const responseText = await response.text();
  expect(response.status(), responseText).toBe(200);
  const body = JSON.parse(responseText) as Record<string, unknown>;
  const didDocument = body.did_document;
  if (
    didDocument &&
    typeof didDocument === "object" &&
    "document" in didDocument &&
    (didDocument as Record<string, unknown>).document &&
    typeof (didDocument as Record<string, unknown>).document === "object"
  ) {
    return (didDocument as Record<string, unknown>).document as Record<string, unknown>;
  }
  return body;
}
