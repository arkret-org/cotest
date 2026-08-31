// Applet bridge (bot actor + ghost actor + portal realm)
// Contract: e2e/scenarios/extensions/applet-bridge.md
// Spec: extensions/applet-integration.md §3-§5, extensions/applet-schema.md

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";
import {
  expect,
  operationSelector,
  test,
  type APIRequestContext,
  type APIResponse,
} from "../../helpers/arkret-test";
import {
  mockAppletRegistryBaseUrl,
  solandBaseUrl,
  solandServiceDid,
  solandServiceId,
} from "../../helpers/env";
import {
  accountActorId,
  addRealmMemberApi,
  advanceEnvelopeToActorFrontier,
  authHeaders,
  canonicalEventTimestamp,
  requireDidCoreId,
  canonicalTimestamp,
  canonicalJson,
  sdkEventDerivedIds,
  sdkEventEnvelopeProof,
  createRealmApi,
  currentActorIdApi,
  grantCapabilityEventApi,
  issueAuthorizationLeasesApi,
  authorizationLeasesFromIssueOutcome,
  queryRealmEventsApi,
  registerEventSigner,
  plaintextVisibleServiceDeclarations,
  prepareSignedEventBatchSubmissionsApi,
  projectDidToCoreId,
  readRealmSealBasis,
  retypeEventDerivedId,
  resolveDefaultStrandId,
  signedEventEnvelope,
  signedRealmGenesisEnvelope,
  singleSignerNotaryFromDid,
  submitSignedEventApi,
  rawPushFederationEvents,
  typedId,
  serviceActorId,
  waitForRealmControlIdleApi,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  assertJointStackNotRequired,
  ensureRegistered,
  issueDevSession,
  openDpopUserPage,
  uniqueUser,
} from "../../helpers/users";
import {
  buildWebvhGenesisEntry,
  generateWebvhKey,
  submitPrincipalGenesisEntry,
  type BuiltWebvhGenesis,
} from "../../helpers/webvh-api";

test.describe.configure({ mode: "serial" });

type SignedPackage = {
  applet_package: Record<string, unknown> & {
    applet_id: string;
    bot_actor_id: string;
    service_id: string;
    namespaces?: {
      handles?: Array<{ pattern: string }>;
    };
    requested_scopes: string[];
    registration_epoch: string;
  };
  package_digest: string;
  signing_did: string;
  service_id_document?: Record<string, unknown>;
  service_id_operation?: BuiltWebvhGenesis;
  bot_actor_operation?: BuiltWebvhGenesis;
  ghost_namespace_token?: string;
  service_signing_private_key?: KeyObject;
  bot_signing_private_key?: KeyObject;
};

type AppletRegistration = {
  applet_id: string;
  bot_actor_id: string;
  portal_realm_id: string;
  namespace: string;
  status: string;
  registration_event_ref: string;
  capability_grants: Array<{
    grant_ref: string;
    actions: string[];
  }>;
};

async function createAppletInstallRealm(
  request: APIRequestContext,
  token: string,
  data: Parameters<typeof createRealmApi>[2],
): Promise<string> {
  const realmId = await createRealmApi(request, token, data);
  const ownerId = await currentActorIdApi(request, token);
  await grantCapabilityEventApi(request, token, {
    ownerId,
    realmId,
    subjectId: ownerId,
    actions: ["ak.realm.admin"],
  });
  return realmId;
}

async function configureAppletPlaintextServices(
  request: APIRequestContext,
  token: string,
  actorId: string,
  realmId: string,
  serviceIds: string[],
): Promise<void> {
  const cell = "ak:cell:ak.component.realm.plaintext_visible_services.v1:null";
  const timeline = await queryRealmEventsApi(request, token, realmId);
  const accepted = Array.isArray(timeline.events)
    ? (timeline.events as Array<Record<string, unknown>>)
    : [];
  const currentValue = [...accepted]
    .reverse()
    .find(
      (event) => event.kind === "ak.realm.plaintext_visible_services",
    )?.payload;
  const envelope = signedEventEnvelope({
    actorId,
    realmId,
    kind: "ak.realm.plaintext_visible_services",
    authorizationRef: "ak:cell:ak.component.realm.authority_root.v1:null",
    sealBasis: await readRealmSealBasis(request, token, realmId),
    preconditions: [
      {
        cell_id: cell,
        predicate: {
          op: "head_eq",
          value:
            currentValue && typeof currentValue === "object"
              ? currentValue
              : null,
        },
      },
    ],
    payload: {
      services: plaintextVisibleServiceDeclarations(serviceIds),
    },
  });
  await advanceEnvelopeToActorFrontier(request, token, envelope);
  await submitSignedEventApi(request, token, envelope, {
    context: "configure Applet plaintext-visible services",
  });
  await waitForRealmControlIdleApi(request, token, realmId);
}

async function revokeAppletRuntime(
  request: APIRequestContext,
  token: string,
  actorId: string,
  appletId: string,
  realmId: string,
  idempotencyKey: string,
): Promise<Record<string, unknown>> {
  const effectiveScope = { kind: "realm", realm_id: realmId };
  const reasonCode = "requested_by_admin";
  const revokeMode = "revoke_runtime_only";
  const base = `${solandBaseUrl()}/_arkret/self/applets/${encodeURIComponent(appletId)}/revoke`;
  const previewUrl = `${base}/preview`;
  const preview = await request.post(previewUrl, {
    headers: {
      ...authHeaders(token, "POST", previewUrl),
      "content-type": "application/json",
    },
    data: canonicalJson({
      effective_scope: effectiveScope,
      reason_code: reasonCode,
      revoke_mode: revokeMode,
    }),
  });
  const previewText = await preview.text();
  expect(preview.status(), previewText).toBe(200);
  const plan = JSON.parse(previewText) as {
    revoke_plan_digest: string;
    revoke_plan: {
      registration_epoch: string;
      capability_revocations?: Array<{
        grant_id: string;
        reason_code: string;
      }>;
      membership_removals?: unknown[];
    };
  };
  expect(plan.revoke_plan.membership_removals ?? []).toEqual([]);
  const sealBasis = await readRealmSealBasis(request, token, realmId);
  const revokeEvents = (plan.revoke_plan.capability_revocations ?? []).map(
    (intent) =>
      signedEventEnvelope({
        actorId,
        realmId,
        kind: "ak.capability.revoke",
        scopeRef: effectiveScope,
        sealBasis,
        authorizationRef: "ak:cell:ak.component.realm.authority_root.v1:null",
        payload: {
          grant_id: intent.grant_id,
          reason: intent.reason_code,
        },
      }),
  );
  const capabilityRevokeEvents = await prepareSignedEventBatchSubmissionsApi(
    request,
    token,
    revokeEvents,
    {
      context: `prepare Applet revoke ${appletId}`,
    },
  );
  const response = await request.post(base, {
    headers: {
      ...authHeaders(token, "POST", base),
      "content-type": "application/json",
      "Idempotency-Key": idempotencyKey,
    },
    data: canonicalJson({
      revoke_plan_digest: plan.revoke_plan_digest,
      effective_scope: effectiveScope,
      reason_code: reasonCode,
      revoke_mode: revokeMode,
      capability_revoke_events: capabilityRevokeEvents,
      membership_state_events: [],
    }),
  });
  const responseText = await response.text();
  expect(response.status(), responseText).toBe(200);
  return JSON.parse(responseText) as Record<string, unknown>;
}

function capabilityGrantRefForAction(
  registration: AppletRegistration,
  action: string,
): string {
  const grantRef = registration.capability_grants.find((grant) =>
    grant.actions.includes(action),
  )?.grant_ref;
  expect(grantRef, `capability grant for ${action}`).toMatch(/^ak:grant:/);
  return grantRef!;
}

test.describe("applet bridge", () => {
  test("applet package installs, bot joins space, ghost actor relays external messages with accountability chain", async ({
    browser,
    request,
  }) => {
    test.setTimeout(300_000);
    const registryBase = requireMockAppletRegistry();
    const stamp = Date.now();
    const aliceFlow = await openDpopUserPage(
      browser,
      request,
      `applet-alice-${stamp}`,
      { prepareMlsDevice: false },
    );
    if (!aliceFlow) {
      assertJointStackNotRequired("applet bridge UI setup");
      test.skip(true, "joint stack is not available");
      return;
    }
    const { page: alicePage, user: alice } = aliceFlow;
    const aliceToken = await issueDevSession(request, alice);

    try {
      const signed = await signPackage(request, registryBase, {
        package_id: `package:bridge:demo-${stamp}`,
        namespace: `bridge.demo.${stamp}`,
        display_name: "Demo Bridge Applet",
        capabilities: ["ak.message.create", "ak.applet.ghost.provision"],
      });
      expect(signed.applet_package.claimed_profiles).toEqual([
        "ak.profile.applet_bridge.v1",
        "ak.profile.applet_service.v1",
      ]);
      const realmId = await alicePage.createRealm({
        title: `applet-bridge Demo Space ${stamp}`,
        discoverability: "listed",
        historyAccess: "since_join",
        encryptionProfile: "none",
      });
      await grantCapabilityEventApi(request, aliceToken, {
        ownerId: alice.id,
        realmId,
        subjectId: alice.id,
        actions: ["ak.realm.admin", "ak.strand.create"],
      });
      await configureAppletPlaintextServices(
        request,
        aliceToken,
        alice.id,
        realmId,
        [
          solandServiceId(),
          signed.applet_package.service_id,
        ],
      );
      await publishAppletServiceIdDocument(request, signed);
      const botVerificationMethod = `${signed.bot_actor_operation?.did}#bot-event-key`;
      const botSigningJwk = signed.bot_signing_private_key?.export({
        format: "jwk",
      });
      if (!botSigningJwk?.d || !signed.bot_actor_operation) {
        throw new Error(
          "Applet Bot is missing its durable runtime signing custody",
        );
      }
      registerEventSigner({
        actorId: signed.applet_package.bot_actor_id,
        deviceId: "bot-event-key",
        verificationMethod: botVerificationMethod,
        signingSeedB64url: botSigningJwk.d,
      });
      const botToken = await issueDevSession(request, {
        ...uniqueUser(`applet-bot-${stamp}`),
        id: signed.applet_package.bot_actor_id,
      });
      const preInstallMembership = signedEventEnvelope({
        actorId: signed.applet_package.bot_actor_id,
        realmId,
        kind: "ak.member.state",
        appletId: signed.applet_package.applet_id,
        proofVerificationMethod: botVerificationMethod,
        payload: {
          realm_id: realmId,
          member_id: accountActorId(signed.applet_package.bot_actor_id),
          membership: "join",
        },
      });
      const preInstallLease = await issueAuthorizationLeasesApi(
        request,
        botToken,
        [preInstallMembership],
      );
      expect(preInstallLease.status()).not.toBe(200);
      expect(wireErrCode(await preInstallLease.json())).toBe(
        "applet_registration_unauthorized",
      );
      const registration = await installApplet(
        request,
        aliceToken,
        signed,
        realmId,
        `register-${stamp}`,
      );
      expect(registration.status).toBe("installed");
      expect(registration.bot_actor_id).toMatch(
        /^ak:did_core:web:bot-bridge-demo-/,
      );
      expect(registration.portal_realm_id).toBe(realmId);
      const messageGrantRef = capabilityGrantRefForAction(
        registration,
        "ak.message.create",
      );
      const provisionGrantRef = capabilityGrantRefForAction(
        registration,
        "ak.applet.ghost.provision",
      );
      const appletServiceToken = await issueDevSession(request, {
        ...uniqueUser(`applet-service-${stamp}`),
        id: signed.applet_package.service_id,
      });
      const botMembershipEvent = signedEventEnvelope({
        actorId: registration.bot_actor_id,
        realmId,
        kind: "ak.member.state",
        appletId: registration.applet_id,
        proofVerificationMethod: botVerificationMethod,
        payload: {
          realm_id: realmId,
          member_id: accountActorId(registration.bot_actor_id),
          membership: "join",
        },
      });
      await submitSignedEventApi(request, botToken, botMembershipEvent, {
        context: "post-install Applet Bot ordinary self-join admission",
      });
      const federatedMembershipReplay = await rawPushFederationEvents(
        request,
        [botMembershipEvent],
        {
          origin: solandServiceId(),
          destination: solandServiceId(),
          realmId,
          idempotencyKey: `applet-bot-membership-peer-replay-${stamp}`,
        },
      );
      const federatedMembershipOutcome =
        (await federatedMembershipReplay.json()) as {
          accepted?: string[];
          duplicate?: string[];
        };
      expect(federatedMembershipReplay.status()).toBe(200);
      expect([
        ...(federatedMembershipOutcome.accepted ?? []),
        ...(federatedMembershipOutcome.duplicate ?? []),
      ]).toContain(String(botMembershipEvent.event_id));
      const membershipTimeline = await queryRealmEventsApi(
        request,
        aliceToken,
        realmId,
      );
      expect(
        (
          (membershipTimeline.events ?? []) as Array<Record<string, unknown>>
        ).some(
          (event) =>
            event.kind === "ak.member.state" &&
            event.actor_id === registration.bot_actor_id &&
            event.applet_id === registration.applet_id &&
            (event.payload as Record<string, unknown>)?.actor_id ===
              registration.bot_actor_id &&
            (event.payload as Record<string, unknown>)?.membership === "join" &&
            (event.proofs as Array<Record<string, unknown>>)?.[0]
              ?.verification_method === botVerificationMethod,
        ),
      ).toBe(true);

      const externalUser = { id: "ext-user-X", display_name: "External X" };
      if (!signed.ghost_namespace_token) {
        throw new Error(
          "signed Applet package is missing its Ghost namespace token",
        );
      }
      const ghostBuilt = buildWebvhGenesisEntry({
        baseUrl: solandBaseUrl(),
        localId: `ghost-${signed.ghost_namespace_token}/${externalUser.id.toLowerCase()}`,
        rootKey: generateWebvhKey(),
        nextRootKey: generateWebvhKey(),
        versionTime: canonicalTimestamp(),
        document: (did) => ({
          "@context": ["https://www.w3.org/ns/did/v1"],
          id: did,
          updated: canonicalTimestamp(),
        }),
      });
      await submitPrincipalGenesisEntry(request, solandBaseUrl(), ghostBuilt);
      const preGhostTimeline = await queryRealmEventsApi(
        request,
        aliceToken,
        realmId,
      );
      const serviceEvents = (
        Array.isArray(preGhostTimeline.events) ? preGhostTimeline.events : []
      ) as Array<Record<string, unknown>>;
      const serviceHead = serviceEvents
        .filter((event) => event.actor_id === signed.applet_package.service_id)
        .sort(
          (left, right) => Number(right.actor_seq) - Number(left.actor_seq),
        )[0];
      const ghostCreation = buildGhostManagedActorCreation({
        signed,
        registration,
        realmId,
        ghostBuilt,
        externalUser,
        appletAuthorityRef: provisionGrantRef,
        createdAt: canonicalTimestamp(),
        serviceActorSeq: Number(serviceHead?.actor_seq ?? -1) + 1,
        servicePrevRef:
          typeof serviceHead?.event_id === "string"
            ? serviceHead.event_id
            : undefined,
      });
      const leaseResponse = await issueAuthorizationLeasesApi(
        request,
        aliceToken,
        [ghostCreation.pcr_genesis_event],
      );
      const leaseText = await leaseResponse.text();
      expect([200, 201], leaseText).toContain(leaseResponse.status());
      const [pcrLease] = authorizationLeasesFromIssueOutcome(
        leaseText,
        1,
        "ordinary Applet PCR injection negative",
      );
      const ordinaryEventsUrl = `${solandBaseUrl()}/_arkret/self/events`;
      const ordinaryPcrInjection = await request.post(ordinaryEventsUrl, {
        headers: {
          ...authHeaders(aliceToken, "POST", ordinaryEventsUrl),
          "content-type": "application/json",
        },
        data: canonicalJson({
          event: ghostCreation.pcr_genesis_event,
          authorization_lease: pcrLease,
        }),
      });
      const ordinaryPcrBody = await ordinaryPcrInjection.json();
      expect(ordinaryPcrInjection.status()).toBe(403);
      expect(wireErrCode(ordinaryPcrBody)).toBe(
        "applet_managed_pcr_genesis_requires_closed_aggregate",
      );

      const peerPcrInjection = await rawPushFederationEvents(
        request,
        [ghostCreation.pcr_genesis_event],
        {
          origin: solandServiceId(),
          destination: solandServiceId(),
          realmId: String(ghostCreation.pcr_genesis_event.realm_id),
          idempotencyKey: `applet-pcr-peer-negative-${stamp}`,
        },
      );
      const peerPcrBody = await peerPcrInjection.json();
      expect(peerPcrInjection.status()).toBe(403);
      expect(wireErrCode(peerPcrBody)).toBe(
        "applet_managed_pcr_genesis_requires_closed_aggregate",
      );
      const provision = await request.post(`${registryBase}/external-event`, {
        headers: authHeaders(aliceToken),
        data: {
          soland_base_url: solandBaseUrl(),
          destination_id: solandServiceId(),
          applet_id: registration.applet_id,
          realm_id: realmId,
          authorization_ref: messageGrantRef,
          provision_authorization_ref: provisionGrantRef,
          external_user: externalUser,
          ghost_creation: ghostCreation,
          payload: { kind: "provision" },
        },
      });
      const provisionText = await provision.text();
      expect(provision.status(), provisionText).toBe(200);
      const provisionBody = JSON.parse(provisionText);
      const ghostActorId = String(provisionBody.ghost_actor_id);
      expect(ghostActorId).toMatch(/^ak:did_core:web:ghost-/);
      await addRealmMemberApi(request, aliceToken, realmId, ghostActorId);
      await waitForRealmControlIdleApi(request, aliceToken, realmId);
      const portalStrandId = await resolveDefaultStrandId(
        request,
        aliceToken,
        realmId,
      );

      const text = `hi from outside ${stamp}`;
      const external = await request.post(`${registryBase}/external-event`, {
        headers: authHeaders(aliceToken),
        data: {
          soland_base_url: solandBaseUrl(),
          destination_id: solandServiceId(),
          applet_id: registration.applet_id,
          realm_id: realmId,
          strand_id: portalStrandId,
          authorization_ref: messageGrantRef,
          provision_authorization_ref: provisionGrantRef,
          external_user: externalUser,
          payload: { kind: "message", text },
        },
      });
      const externalText = await external.text();
      expect(external.status(), externalText).toBe(200);
      const externalBody = JSON.parse(externalText);
      expect(String(externalBody.ghost_actor_id)).toBe(ghostActorId);
      expect(String(externalBody.message_id)).toMatch(/^ak:message:/);

      const events = await queryRealmEventsApi(request, aliceToken, realmId);
      expect(JSON.stringify(events)).toContain(text);
      const acceptedEvents = Array.isArray(events.events)
        ? (events.events as Array<Record<string, unknown>>)
        : [];
      const ghostProfile = acceptedEvents.find(
        (event) =>
          event.kind === "ak.profile.create" &&
          event.actor_id === ghostActorId,
      );
      expect(ghostProfile, "accepted Ghost profile Event").toBeDefined();
      expect(
        (ghostProfile?.payload as Record<string, unknown> | undefined)?.object,
      ).toEqual(
        expect.objectContaining({
          principal_id: ghostActorId,
          actor_kind: "integration",
          accountable_principal_ids: [signed.applet_package.service_id],
        }),
      );
      const accountabilityGrant = acceptedEvents.find(
        (event) =>
          event.kind === "ak.identity.accountability_grant" &&
          (event.payload as Record<string, unknown> | undefined)?.subject_id ===
            ghostActorId,
      );
      expect(
        accountabilityGrant,
        "accepted Ghost accountability grant",
      ).toEqual(
        expect.objectContaining({
          actor_id: signed.applet_package.service_id,
          authorization_ref: provisionGrantRef,
        }),
      );
      expect(accountabilityGrant?.payload).toEqual(
        expect.objectContaining({
          issuer_id: signed.applet_package.service_id,
          subject_id: ghostActorId,
          grant_status: "active",
        }),
      );
      const acceptedGhostHead = acceptedEvents
        .filter((event) => event.actor_id === ghostActorId)
        .sort(
          (left, right) => Number(right.actor_seq) - Number(left.actor_seq),
        )[0];
      expect(acceptedGhostHead, "accepted Ghost actor head").toBeDefined();
      const unsignedDirectWrite = structuredClone(acceptedGhostHead);
      delete unsignedDirectWrite.event_id;
      delete unsignedDirectWrite.proofs;
      unsignedDirectWrite.actor_seq = Number(acceptedGhostHead.actor_seq) + 1;
      unsignedDirectWrite.created_at = canonicalTimestamp();
      unsignedDirectWrite.hlc = hlcForStamp(stamp + 101);
      unsignedDirectWrite.prev_refs = [String(acceptedGhostHead.event_id)];
      const directPayload = structuredClone(
        unsignedDirectWrite.payload as Record<string, unknown>,
      );
      const directContent = structuredClone(
        directPayload.content as Record<string, unknown>,
      );
      directContent.body = `direct self write after revoke ${stamp}`;
      directPayload.content = directContent;
      unsignedDirectWrite.payload = directPayload;
      const directWrite: Record<string, unknown> = {
        ...unsignedDirectWrite,
        event_id: sdkEventDerivedIds(unsignedDirectWrite).event_id,
      };
      directWrite.proofs = [
        appletEventProof(
          signed.applet_package.service_id,
          directWrite,
          signed.service_signing_private_key,
        ),
      ];
      const directLeaseResponse = await issueAuthorizationLeasesApi(
        request,
        appletServiceToken,
        [directWrite],
      );
      const directLeaseText = await directLeaseResponse.text();
      expect([200, 201], directLeaseText).toContain(
        directLeaseResponse.status(),
      );
      const [directWriteLease] = authorizationLeasesFromIssueOutcome(
        directLeaseText,
        1,
        "revoked Applet direct self-write negative",
      );
      await alicePage.gotoTimelineRealm(realmId);
      await expect(alicePage.page.getByTestId("message-list")).toContainText(
        text,
        {
          timeout: 30_000,
        },
      );

      const revoke = await revokeAppletRuntime(
        request,
        aliceToken,
        alice.id,
        registration.applet_id,
        realmId,
        `revoke-${stamp}`,
      );
      expect(revoke.ok).toBe(true);
      expect(revoke.status).toBe("complete");
      expect(revoke.revoked_refs).toEqual(
        expect.arrayContaining([registration.bot_actor_id, ghostActorId]),
      );

      const afterRevokeText = `after revoke ${stamp}`;
      const afterRevoke = await request.post(`${registryBase}/external-event`, {
        headers: authHeaders(aliceToken),
        data: {
          soland_base_url: solandBaseUrl(),
          destination_id: solandServiceId(),
          applet_id: registration.applet_id,
          realm_id: realmId,
          strand_id: portalStrandId,
          authorization_ref: messageGrantRef,
          provision_authorization_ref: provisionGrantRef,
          external_user: externalUser,
          payload: { kind: "message", text: afterRevokeText },
        },
      });
      expect([403, 409]).toContain(afterRevoke.status());
      expect(wireErrCode(await afterRevoke.json())).toBe(
        "applet_registration_unauthorized",
      );
      expect(
        JSON.stringify(await queryRealmEventsApi(request, aliceToken, realmId)),
      ).not.toContain(afterRevokeText);

      const directEventsUrl = `${solandBaseUrl()}/_arkret/self/events`;
      const directAfterRevoke = await request.post(directEventsUrl, {
        headers: {
          ...authHeaders(appletServiceToken, "POST", directEventsUrl),
          "content-type": "application/json",
        },
        data: canonicalJson({
          event: directWrite,
          authorization_lease: directWriteLease,
        }),
      });
      const directAfterRevokeBody = await directAfterRevoke.json();
      expect(directAfterRevoke.status()).toBe(403);
      expect(wireErrCode(directAfterRevokeBody)).toBe("applet_revoked");

      const pcrRealmId = String(provisionBody.principal_control_realm_id);
      const combinedFrontierUrl = `${solandBaseUrl()}/_arkret/self/events/frontier`;
      const revokedAuthoringFrontier = await request.fetch(
        combinedFrontierUrl,
        {
          method: "QUERY",
          headers: {
            ...authHeaders(appletServiceToken, "QUERY", combinedFrontierUrl),
            "content-type": "application/json",
          },
          data: canonicalJson({
            actor_id: ghostActorId,
            realm_id: pcrRealmId,
          }),
        },
      );
      expect(revokedAuthoringFrontier.status()).toBe(404);

      const aggregateFrontierUrl = `${solandBaseUrl()}/_arkret/self/events/frontier`;
      const historicalFrontier = await request.fetch(aggregateFrontierUrl, {
        method: "QUERY",
        headers: {
          ...authHeaders(appletServiceToken, "QUERY", aggregateFrontierUrl),
          "content-type": "application/json",
        },
        data: canonicalJson({ actor_id: ghostActorId }),
      });
      const historicalFrontierText = await historicalFrontier.text();
      expect(historicalFrontier.status(), historicalFrontierText).toBe(200);
      expect(historicalFrontierText).toContain(pcrRealmId);
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

    const realmId = await createAppletInstallRealm(request, aliceToken, {
      title: `applet conflict ${stamp}`,
      discoverability: "listed",
      history_access: "since_join",
    });

    const first = await signPackage(request, registryBase, {
      package_id: `package:bridge:conflict-a-${stamp}`,
      namespace,
    });
    await installApplet(
      request,
      aliceToken,
      first,
      realmId,
      `conflict-first-${stamp}`,
    );

    const second = await signPackage(request, registryBase, {
      package_id: `package:bridge:conflict-b-${stamp}`,
      namespace,
    });
    const { response: denied } = await rawInstallApplet(
      request,
      aliceToken,
      second,
      realmId,
      `conflict-second-${stamp}`,
    );
    expect(denied.status()).toBe(409);
    expect(wireErrCode(await denied.json())).toBe("applet_namespace_conflict");
  });

  test("E4.2 capability revoke preserves Bot creation history and removes the legacy private write route", async ({
    request,
  }) => {
    const registryBase = requireMockAppletRegistry();
    const stamp = Date.now();
    const alice = uniqueUser(`applet-revoke-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const realmId = await createAppletInstallRealm(request, aliceToken, {
      title: `applet revoke ${stamp}`,
      discoverability: "listed",
      history_access: "since_join",
    });
    const signed = await signPackage(request, registryBase, {
      package_id: `package:bridge:revoke-${stamp}`,
      namespace: `bridge.revoke.${stamp}`,
    });
    const registration = await installApplet(
      request,
      aliceToken,
      signed,
      realmId,
      `revoke-${stamp}`,
    );
    await addRealmMemberApi(
      request,
      aliceToken,
      realmId,
      registration.bot_actor_id,
    );

    const revoke = await revokeAppletRuntime(
      request,
      aliceToken,
      alice.id,
      registration.applet_id,
      realmId,
      `revoke-bot-${stamp}`,
    );
    expect(revoke.ok).toBe(true);
    expect(revoke.status).toBe("complete");
    expect(revoke.revoked_refs).toEqual(
      expect.arrayContaining([registration.bot_actor_id]),
    );

    const history = await queryRealmEventsApi(request, aliceToken, realmId);
    expect(JSON.stringify(history)).toContain("ak.applet.registration");
    expect(JSON.stringify(history)).toContain(registration.bot_actor_id);

    const removedLegacyRoute = await request.post(
      `${solandBaseUrl()}/_soland/edge/applets/${encodeURIComponent(registration.applet_id)}/bot/messages`,
      {
        headers: {
          ...authHeaders(aliceToken),
          "content-type": "application/json",
        },
        data: canonicalJson({ text: `must-not-route-${stamp}` }),
      },
    );
    expect(removedLegacyRoute.status()).toBe(404);
  });

  test("E4.3 idempotency: same applet package + same Idempotency-Key returns original registration; different key conflicts", async ({
    request,
  }) => {
    const registryBase = requireMockAppletRegistry();
    const stamp = Date.now();
    const alice = uniqueUser(`applet-idem-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const realmId = await createAppletInstallRealm(request, aliceToken, {
      title: `applet idem ${stamp}`,
      discoverability: "listed",
      history_access: "since_join",
    });
    const signed = await signPackage(request, registryBase, {
      package_id: `package:bridge:idem-${stamp}`,
      namespace: `bridge.idem.${stamp}`,
    });

    const firstResult = await rawInstallApplet(
      request,
      aliceToken,
      signed,
      realmId,
      `idem-${stamp}`,
    );
    const firstResponse = firstResult.response;
    expect(firstResponse.status()).toBe(201);
    const first = installRegistrationFromResponse(
      signed,
      realmId,
      await firstResponse.json(),
      firstResult.grantActionsById,
    );

    const secondResult = await rawInstallApplet(
      request,
      aliceToken,
      signed,
      realmId,
      `idem-${stamp}`,
      firstResult.prepared,
    );
    const secondResponse = secondResult.response;
    expect(secondResponse.status()).toBe(200);
    const second = installRegistrationFromResponse(
      signed,
      realmId,
      await secondResponse.json(),
      secondResult.grantActionsById,
    );
    expect(second.applet_id).toBe(first.applet_id);
    expect(second.bot_actor_id).toBe(first.bot_actor_id);

    const { response: conflict } = await rawInstallApplet(
      request,
      aliceToken,
      signed,
      realmId,
      `idem-other-${stamp}`,
      firstResult.prepared,
    );
    expect(conflict.status()).toBe(409);
    expect(wireErrCode(await conflict.json())).toBe(
      "applet_already_registered",
    );
  });

  // COTEST-SEC-02: production-mode controller-signed package signature negative
  // tests. Spec: extensions/applet-integration.md §4.1 — `controller_id` MUST
  // sign the registration; `proof` MUST be a controller DID detached proof
  // covering the canonical registration object (excluding `proof` itself), and
  // a package whose proof does not cover its body MUST be rejected. soland's
  // canonical install validator (validate_applet_package) recomputes
  // `package_digest` over the bare body and recomputes the proof
  // `payload_digest`; a package mutated after signing therefore fails closed at
  // the preview/commit gate. These run for real against soland in dev-mode —
  // no live deployment required — mirroring the runnable positive install case
  // above and the RFC 9421 inbound-signature negative cases below.

  test("E4.4 install evidence has one carrier in the caller-signed registration manifest", async ({
    request,
  }) => {
    const registryBase = requireMockAppletRegistry();
    const stamp = Date.now();
    const alice = uniqueUser(`applet-evidence-carrier-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const realmId = await createAppletInstallRealm(request, aliceToken, {
      title: `applet evidence carrier ${stamp}`,
      discoverability: "listed",
      history_access: "since_join",
    });
    const signed = await signPackage(request, registryBase, {
      package_id: `package:bridge:evidence-carrier-${stamp}`,
      namespace: `bridge.evidence.carrier.${stamp}`,
    });
    const previewUrl = `${solandBaseUrl()}/_arkret/self/applets/install/preview`;
    await publishAppletServiceIdDocument(request, signed);
    const prepared = await prepareAppletInstallAuthoringBasis(
      request,
      aliceToken,
      signed,
      realmId,
      { kind: "realm", realm_id: realmId },
    );
    const canonicalManifest = registrationManifestFromBasis(prepared.basis);
    const registrationEvidence = structuredClone(
      canonicalManifest.registration_epoch_evidence as Record<string, unknown>,
    );
    const missingBasis = structuredClone(prepared.basis);
    const missingManifest = (
      (missingBasis.registration_event as Record<string, unknown>)
        .payload as Record<string, unknown>
    ).manifest as Record<string, unknown>;
    delete missingManifest.registration_epoch_evidence;

    const missingEvidence = await request.fetch(previewUrl, {
      method: "POST",
      headers: {
        ...authHeaders(aliceToken),
        "content-type": "application/json",
      },
      data: canonicalJson({
        applet_package: signed.applet_package,
        authoring_request_basis: missingBasis,
      }),
    });
    expect(missingEvidence.status()).toBe(400);

    const duplicateSibling = await request.fetch(previewUrl, {
      method: "POST",
      headers: {
        ...authHeaders(aliceToken),
        "content-type": "application/json",
      },
      data: canonicalJson({
        applet_package: signed.applet_package,
        authoring_request_basis: prepared.basis,
        // Negative-only closed-shape probe: the canonical carrier is nested in
        // `authoring_request_basis.registration_event.payload.manifest`.
        registration_epoch_evidence: registrationEvidence, // stale-literal-allow
      }),
    });
    expect(duplicateSibling.status()).toBe(400);

    const misplacedPackage = {
      ...signed.applet_package,
      // Negative-only package probe; no positive helper carries this sibling.
      registration_epoch_evidence: registrationEvidence, // stale-literal-allow
    };
    const misplaced = await request.fetch(previewUrl, {
      method: "POST",
      headers: {
        ...authHeaders(aliceToken),
        "content-type": "application/json",
      },
      data: canonicalJson({
        applet_package: misplacedPackage,
        authoring_request_basis: prepared.basis,
      }),
    });
    expect(misplaced.status()).toBe(400);

    const expectNestedEvidenceRejected = async (
      label: string,
      evidence: Record<string, unknown>,
    ) => {
      const candidate = await prepareAppletInstallAuthoringBasis(
        request,
        aliceToken,
        signed,
        realmId,
        { kind: "realm", realm_id: realmId },
        (manifest) => {
          manifest.registration_epoch_evidence = evidence;
        },
      );
      const denied = await request.fetch(previewUrl, {
        method: "POST",
        headers: {
          ...authHeaders(aliceToken),
          "content-type": "application/json",
        },
        data: canonicalJson({
          applet_package: signed.applet_package,
          authoring_request_basis: candidate.basis,
        }),
      });
      expect(denied.status(), label).toBe(400);
      expect(wireErrCode(await denied.json()), label).toBe(
        "applet_registration_epoch_evidence_mismatch",
      );
    };

    const emptyKeys = structuredClone(registrationEvidence);
    emptyKeys.accepted_signing_keys = [];
    await expectNestedEvidenceRejected("empty accepted key set", emptyKeys);

    const swappedService = structuredClone(registrationEvidence);
    swappedService.did = "did:web:swapped-applet.example";
    await expectNestedEvidenceRejected("swapped service DID", swappedService);

    const rotatedSnapshot = structuredClone(registrationEvidence);
    rotatedSnapshot.document_digest = `sha256:${"44".repeat(32)}`;
    const rotatedKeys = rotatedSnapshot.accepted_signing_keys;
    if (!Array.isArray(rotatedKeys) || rotatedKeys.length === 0) {
      throw new Error(
        "fixture registration evidence has no accepted signing key",
      );
    }
    (rotatedKeys[0] as Record<string, unknown>).public_key_digest =
      `sha256:${"55".repeat(32)}`;
    await expectNestedEvidenceRejected(
      "rotated DID snapshot under the sealed epoch",
      rotatedSnapshot,
    );
  });

  test("E4.5 tampered package body: post-signing mutation breaks package_digest and is rejected with schema_violation", async ({
    request,
  }) => {
    const registryBase = requireMockAppletRegistry();
    const stamp = Date.now();
    const alice = uniqueUser(`applet-tamper-body-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const realmId = await createAppletInstallRealm(request, aliceToken, {
      title: `applet tamper body ${stamp}`,
      discoverability: "listed",
      history_access: "since_join",
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
      pkg.requested_scopes = [
        ...pkg.requested_scopes,
        "ak.applet.smuggled.scope",
      ];
    });

    const { response: denied } = await rawInstallApplet(
      request,
      aliceToken,
      tampered,
      realmId,
      `tamper-body-${stamp}`,
    );
    expect([400, 409]).toContain(denied.status());
    expect(wireErrCode(await denied.json())).toBe("schema_violation");
  });

  test("E4.6 tampered proof: proof that no longer covers the package body is rejected with proof_invalid", async ({
    request,
  }) => {
    const registryBase = requireMockAppletRegistry();
    const stamp = Date.now();
    const alice = uniqueUser(`applet-tamper-proof-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const realmId = await createAppletInstallRealm(request, aliceToken, {
      title: `applet tamper proof ${stamp}`,
      discoverability: "listed",
      history_access: "since_join",
    });
    const signed = await signPackage(request, registryBase, {
      package_id: `package:bridge:tamper-proof-${stamp}`,
      namespace: `bridge.tamper.proof.${stamp}`,
    });

    // Keep `package_digest` consistent with the body, but corrupt the proof's
    // `payload_digest` so the controller proof no longer covers the canonical
    // registration object. §4.1: the proof MUST cover the body; soland
    // recomputes the payload digest and MUST reject the mismatch.
    const tampered = tamperSignedPackage(signed, (pkg) => {
      const proof = pkg.proof as Record<string, unknown> | undefined;
      if (!proof) {
        throw new Error("signed package is missing controller proof");
      }
      proof.payload_digest = `sha256:${"0".repeat(64)}`;
    });

    const { response: denied } = await rawInstallApplet(
      request,
      aliceToken,
      tampered,
      realmId,
      `tamper-proof-${stamp}`,
    );
    expect([400, 409]).toContain(denied.status());
    expect(wireErrCode(await denied.json())).toBe("proof_invalid");
  });

  test("E4.7 an exact successful install replay remains byte-stable", async ({
    request,
  }) => {
    test.setTimeout(120_000);
    const registryBase = requireMockAppletRegistry();
    const stamp = Date.now();
    const alice = uniqueUser(`applet-commit-expiry-${stamp}`);
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);
    const realmId = await createAppletInstallRealm(request, token, {
      title: `applet commit expiry ${stamp}`,
      discoverability: "listed",
      history_access: "since_join",
    });

    const succeedsBeforeExpiry = await signPackage(request, registryBase, {
      package_id: `package:bridge:replay-expired-${stamp}`,
      namespace: `bridge.replay.expired.${stamp}`,
    });
    const idempotencyKey = `success-then-expired-${stamp}`;
    const first = await rawInstallApplet(
      request,
      token,
      succeedsBeforeExpiry,
      realmId,
      idempotencyKey,
      undefined,
      { exerciseAuthoringKats: false },
    );
    expect([200, 201]).toContain(first.response.status());
    const firstOutcome = await first.response.json();
    if (!first.prepared) {
      throw new Error(
        "successful install omitted its exact prepared commit bytes",
      );
    }
    const replay = await rawInstallApplet(
      request,
      token,
      succeedsBeforeExpiry,
      realmId,
      idempotencyKey,
      first.prepared,
      { exerciseAuthoringKats: false },
    );
    expect(replay.response.status()).toBe(200);
    expect(canonicalJson(await replay.response.json())).toBe(
      canonicalJson(firstOutcome),
    );
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
    sourceServiceId?: string;
    realmId?: string;
    actorId?: string;
    appletId?: string;
    authorizationRef?: string;
    strandId?: string;
    sealRef?: string;
    verificationMethod?: string;
    signingKey?: KeyObject;
  }) {
    const sourceServiceId = args.sourceServiceId ?? solandServiceId();
    const realmId = args.realmId ?? typedId("realm");
    // Event actor_id is typed did_core_id; did:web is reserved for the
    // no-history service profile (spec index.md), so even negative cases use a
    // core-id actor (signature-layer rejection precedes actor validation).
    const actorId =
      args.actorId ??
      `ak:did_core:web:bot-applet-${args.stamp}.joint-e2e.local`;
    const verificationMethod =
      args.verificationMethod ??
      `${solandServiceDid()}#applet-service-key`;
    const authKeyId = verificationMethod.includes("#")
      ? verificationMethod.slice(verificationMethod.indexOf("#") + 1)
      : verificationMethod;
    const unidentified = {
      kind: "ak.message.create",
      realm_id: realmId,
      scope_ref: {
        kind: "realm",
        realm_id: realmId,
      },
      actor_id: actorId,
      // The Applet service authenticates the producer proof and transport;
      // the receiving Arkret node is still the Event's Station and
      // adds the admission proof before accepting the durable Event.
      station_id: solandServiceId(),
      actor_seq: 0,
      created_at: canonicalEventTimestamp(),
      hlc: hlcForStamp(args.stamp),
      prev_refs: [],
      refs: [],
      ...(args.sealRef
        ? {
            seal_ref: args.sealRef,
            auth_context: {
              actor_id: actorId,
              key_id: authKeyId,
              key_epoch: 0,
            },
          }
        : {}),
      requirements: {
        schema: ["ak.schema.message.v1"],
      },
      payload: {
        strand_id: args.strandId ?? typedId("strand"),
        track_name: "discussion",
        content: {
          kind: "ak.content.text",
          body: `inbound push ${args.stamp}`,
        },
      },
      executed_by: sourceServiceId,
      authorization_ref: args.authorizationRef ?? typedId("grant"),
      applet_id: args.appletId ?? typedAppletId(),
      external_ref: {
        protocol: "demo-bridge",
        instance_id: "joint-e2e",
        external_id: `ext-evt-${args.stamp}`,
      },
    };
    // The bridged Event's id is derived from the Event, so the envelope is
    // assembled first and identified afterwards.
    const event = {
      ...unidentified,
      event_id: sdkEventDerivedIds(unidentified).event_id,
    };
    return {
      applet_id: unidentified.applet_id,
      source_id: sourceServiceId,
      events: [
        {
          ...event,
          proofs: [
            appletEventProof(verificationMethod, event, args.signingKey),
          ],
        },
      ],
    };
  }

  // §7.3.1 currently places its discriminating `reason` at the Problem root.
  // The conflict with the operation registry's specific Problem types is
  // tracked in arkret-work/review/spec-open; do not accept an old nested shape.
  function signatureReason(body: unknown): string | undefined {
    if (!body || typeof body !== "object") {
      return undefined;
    }
    const record = body as Record<string, unknown>;
    const direct = record.reason;
    if (typeof direct === "string") {
      return direct;
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
    const realmId = await createAppletInstallRealm(request, token, {
      title: `applet inbound signed ${stamp}`,
      discoverability: "listed",
      history_access: "since_join",
    });
    const signed = await signPackage(request, registryBase, {
      package_id: `package:bridge:inbound-${stamp}`,
      namespace: `bridge.inbound.${stamp}`,
      capabilities: ["ak.message.create"],
      webhook_auth: {
        kind: "http_message_signature",
        accepted_signature_algorithms: ["ed25519"],
      },
    });
    const sourceServiceId = signed.applet_package.service_id;
    const registration = await installApplet(
      request,
      token,
      signed,
      realmId,
      `inbound-install-${stamp}`,
    );
    await addRealmMemberApi(request, token, realmId, registration.bot_actor_id);
    const sealBasis = await readRealmSealBasis(request, token, realmId);
    const sealRef = Array.isArray(sealBasis.leaves)
      ? sealBasis.leaves[0]
      : undefined;
    expect(
      sealRef,
      "applet transaction fixture requires a current Seal leaf",
    ).toBeTruthy();

    const idempotencyKey = `inbound-ok-${stamp}`;
    const body = transactionPushBody({
      stamp,
      sourceServiceId,
      realmId,
      actorId: registration.bot_actor_id,
      appletId: registration.applet_id,
      authorizationRef: capabilityGrantRefForAction(
        registration,
        "ak.message.create",
      ),
      strandId: await resolveDefaultStrandId(request, token, realmId),
      sealRef: String(sealRef),
      verificationMethod: String(
        (signed.applet_package.webhook_auth as Record<string, unknown>).key_ref,
      ),
      signingKey: signed.service_signing_private_key,
    });
    const targetUri = `${solandBaseUrl()}${TRANSACTIONS_PATH}`;
    const resp = await request.post(targetUri, {
      headers: {
        ...authHeaders(token),
        ...signedAppletTransactionHeaders({
          body,
          targetUri,
          sourceServiceId,
          keyId: String(
            (signed.applet_package.webhook_auth as Record<string, unknown>)
              .key_ref,
          ),
          destinationServiceId: solandServiceId(),
          idempotencyKey,
          signingKey: signed.service_signing_private_key,
        }),
      },
      data: canonicalJson(body),
    });
    const responseText = await resp.text();
    expect(resp.status(), responseText).toBe(200);
    const outcome = JSON.parse(responseText) as {
      ok?: boolean;
      rejections?: unknown[];
    };
    expect(outcome.ok).toBe(true);
    expect(outcome.rejections ?? []).toEqual([]);
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
        "Source-Service-ID": solandServiceId(),
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
        "Source-Service-ID": solandServiceId(),
        "Idempotency-Key": `inbound-badsig-${stamp}`,
        "Content-Digest":
          "sha-256=:b3JCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:",
        "Signature-Input":
          `sig1=("@method" "@target-uri" "@authority" "content-digest" "source-service-id" "destination-service-id" "idempotency-key");created=1700000000;expires=1700000200;keyid="${solandServiceDid()}#key-1";alg="ed25519"`,
        Signature:
          "sig1=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:",
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
    const sourceServiceId = solandServiceId();
    const idempotencyKey = `inbound-expired-${stamp}`;
    const body = transactionPushBody({ stamp, sourceServiceId });
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
          sourceServiceId,
          destinationServiceId: solandServiceId(),
          idempotencyKey,
          created: 1_000_000_000,
          expires: 1_000_000_200,
        }),
      },
      data: canonicalJson(body),
    });
    expect(expired.status()).toBe(401);
    expect(signatureReason(await expired.json())).toBe(
      "signature_window_invalid",
    );
  });
});

function signedAppletTransactionHeaders(args: {
  body: Record<string, unknown>;
  targetUri: string;
  sourceServiceId: string;
  keyId?: string;
  destinationServiceId: string;
  idempotencyKey: string;
  created?: number;
  expires?: number;
  signingKey?: KeyObject;
}): Record<string, string> {
  const canonicalBody = Buffer.from(canonicalJson(args.body), "utf8");
  const contentDigest = `sha-256=:${createHash("sha256").update(canonicalBody).digest("base64")}:`;
  const created = args.created ?? Math.floor(Date.now() / 1000);
  const expires = args.expires ?? created + 300;
  const keyid = args.keyId ?? `${args.sourceServiceId}#applet-service-key`;
  const selector = operationSelector("POST", args.targetUri);
  if (!selector) {
    throw new Error(`applet transaction has no registered operation selector: ${args.targetUri}`);
  }
  const signatureParams =
    `("@method" "@target-uri" "@authority" "content-digest" "arkret-operation" ` +
    `"source-service-id" "destination-service-id" "idempotency-key");` +
    `created=${created};expires=${expires};keyid="${keyid}";alg="ed25519"`;
  const signatureBase = [
    `"@method": POST`,
    `"@target-uri": ${args.targetUri}`,
    `"@authority": ${new URL(args.targetUri).host}`,
    `"content-digest": ${contentDigest}`,
    `"arkret-operation": ${selector}`,
    `"source-service-id": ${args.sourceServiceId}`,
    `"destination-service-id": ${args.destinationServiceId}`,
    `"idempotency-key": ${args.idempotencyKey}`,
    `"@signature-params": ${signatureParams}`,
  ].join("\n");
  const signature = sign(
    null,
    Buffer.from(signatureBase, "utf8"),
    args.signingKey ?? developmentAppletPrivateKey(keyid),
  );
  return {
    "content-type": "application/json",
    "content-digest": contentDigest,
    "arkret-operation": selector,
    "source-service-id": args.sourceServiceId,
    "destination-service-id": args.destinationServiceId,
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
  const ghostNamespaceToken = typedId("operation").split(":").at(-1)!;
  const serviceSigningKey = generateWebvhKey();
  const botSigningKey = generateWebvhKey();
  const versionTime = canonicalTimestamp();
  const servicePublicJwk = {
    crv: "Ed25519",
    kty: "OKP",
    x: serviceSigningKey.publicKey.toString("base64url"),
  };
  const built = buildWebvhGenesisEntry({
    baseUrl: solandBaseUrl(),
    localId: `applet-${typedId("operation").split(":").at(-1)}`,
    rootKey: generateWebvhKey(),
    nextRootKey: generateWebvhKey(),
    versionTime,
    document: (did) => ({
      "@context": ["https://www.w3.org/ns/did/v1"],
      id: did,
      verificationMethod: {
        [`${did}#applet-service-key`]: canonicalJson(servicePublicJwk),
      },
      updated: versionTime,
    }),
  });
  const botPublicJwk = {
    crv: "Ed25519",
    kty: "OKP",
    x: botSigningKey.publicKey.toString("base64url"),
  };
  const botBuilt = buildWebvhGenesisEntry({
    baseUrl: solandBaseUrl(),
    localId: `applet-bot-${typedId("operation").split(":").at(-1)}`,
    rootKey: generateWebvhKey(),
    nextRootKey: generateWebvhKey(),
    versionTime,
    document: (did) => ({
      "@context": ["https://www.w3.org/ns/did/v1"],
      id: did,
      verificationMethod: {
        [`${did}#bot-event-key`]: canonicalJson(botPublicJwk),
      },
      updated: versionTime,
    }),
  });
  const requestedWebhookAuth =
    data.webhook_auth && typeof data.webhook_auth === "object"
      ? (data.webhook_auth as Record<string, unknown>)
      : {};
  const response = await request.post(`${registryBase}/sign-package`, {
    data: {
      ...data,
      actor_namespace_pattern:
        data.actor_namespace_pattern ??
        `did:webvh:*:*:ghost-${ghostNamespaceToken}:*`,
      bot_actor_id: projectDidToCoreId(botBuilt.did),
      service_id: projectDidToCoreId(built.did),
      service_id_document: built.didDocument,
      service_id_method_version_evidence: {
        method: "did:webvh",
        version_id: built.versionId,
        version_time: versionTime,
        unversioned_refetch: false,
      },
      service_signing_public_jwk: servicePublicJwk,
      service_signing_private_jwk: serviceSigningKey.privateKey.export({
        format: "jwk",
      }),
      bot_signing_verification_method: `${botBuilt.did}#bot-event-key`,
      bot_signing_private_jwk: botSigningKey.privateKey.export({
        format: "jwk",
      }),
      bot_actor_initial_resolution:
        webvhManagedActorEvidence(botBuilt).initialResolution,
      bot_actor_method_history_evidence:
        webvhManagedActorEvidence(botBuilt).methodHistoryEvidence,
      webhook_auth: {
        kind: "http_message_signature",
        accepted_signature_algorithms: ["ed25519"],
        ...requestedWebhookAuth,
        key_ref: `${built.did}#applet-service-key`,
      },
    },
  });
  expect(response.status()).toBe(200);
  return {
    ...((await response.json()) as SignedPackage),
    service_id_operation: built,
    bot_actor_operation: botBuilt,
    ghost_namespace_token: ghostNamespaceToken,
    service_signing_private_key: serviceSigningKey.privateKey,
    bot_signing_private_key: botSigningKey.privateKey,
  };
}

// Deep-clone a controller-signed package and mutate its `applet_package` body
// WITHOUT re-sealing or re-signing, so the submitted bytes diverge from what the
// sealed `package_digest` / controller proof cover. Used by the COTEST-SEC-02
// production-mode signature negative tests.
function tamperSignedPackage(
  signed: SignedPackage,
  mutate: (appletPackage: SignedPackage["applet_package"]) => void,
): SignedPackage {
  const {
    service_signing_private_key: serviceSigningPrivateKey,
    bot_signing_private_key: botSigningPrivateKey,
    ...wirePackage
  } = signed;
  const cloned = structuredClone(wirePackage) as SignedPackage;
  cloned.service_signing_private_key = serviceSigningPrivateKey;
  cloned.bot_signing_private_key = botSigningPrivateKey;
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
  const result = await rawInstallApplet(
    request,
    token,
    signed,
    realmId,
    idempotencyKey,
  );
  const response = result.response;
  const responseText = await response.text();
  expect(response.status(), responseText).toBe(201);
  return installRegistrationFromResponse(
    signed,
    realmId,
    JSON.parse(responseText),
    result.grantActionsById,
  );
}

type PreparedAppletInstall = {
  commitBody: Record<string, unknown>;
  grantActionsById: Map<string, string[]>;
};

type RawAppletInstallResult = {
  response: APIResponse;
  prepared?: PreparedAppletInstall;
  grantActionsById: Map<string, string[]>;
};

async function rawInstallApplet(
  request: APIRequestContext,
  token: string,
  signed: SignedPackage,
  realmId: string,
  idempotencyKey: string,
  prepared?: PreparedAppletInstall,
  options: {
    commitDelayMs?: number;
    exerciseAuthoringKats?: boolean;
  } = {},
): Promise<RawAppletInstallResult> {
  await publishAppletServiceIdDocument(request, signed);
  let resolved = prepared;
  if (!resolved) {
    const effectiveScope = { kind: "realm", realm_id: realmId };
    const authoring = await prepareAppletInstallAuthoringBasis(
      request,
      token,
      signed,
      realmId,
      effectiveScope,
    );
    const previewUrl = `${solandBaseUrl()}/_arkret/self/applets/install/preview`;
    const preview = await request.fetch(previewUrl, {
      method: "POST",
      headers: {
        ...authHeaders(token),
        "content-type": "application/json",
      },
      data: canonicalJson({
        applet_package: signed.applet_package,
        authoring_request_basis: authoring.basis,
      }),
    });
    if (!preview.ok()) {
      return {
        response: preview,
        grantActionsById: new Map(),
      };
    }
    const previewOutcome = (await preview.json()) as Record<string, unknown>;
    const authoringRequest = previewOutcome.authoring_request;
    if (!authoringRequest || typeof authoringRequest !== "object") {
      throw new Error(
        "Applet install preview is missing its signed authoring request",
      );
    }
    const authorBaseUrl = String(signed.applet_package.base_url ?? "").replace(
      /\/$/,
      "",
    );
    const authorRequestOptions = {
      headers: { "content-type": "application/json" },
      data: canonicalJson({ authoring_request: authoringRequest }),
    };
    if (options.exerciseAuthoringKats !== false) {
      const rotateStationTrust = await request.post(
        `${authorBaseUrl}/inspect/station-key-current`,
        { data: { rotated: true } },
      );
      expect(rotateStationTrust.status()).toBe(200);
      const staleButCryptographicallyValid = await request.post(
        `${authorBaseUrl}/_arkret/edge/applet/managed-actors/author`,
        authorRequestOptions,
      );
      expect(staleButCryptographicallyValid.status()).toBe(400);
      expect((await staleButCryptographicallyValid.json()).error).toBe(
        "authoring_request_proof_invalid",
      );
      const restoreStationTrust = await request.post(
        `${authorBaseUrl}/inspect/station-key-current`,
        { data: { rotated: false } },
      );
      expect(restoreStationTrust.status()).toBe(200);
      const wrongTarget = structuredClone(authoringRequest) as Record<
        string,
        unknown
      >;
      const alternatePrincipalKey = generateWebvhKey();
      const alternatePrincipalDid = "did:web:wrong-principal.example";
      (
        wrongTarget.basis as Record<string, unknown>
      ).target_station_id = projectDidToCoreId(alternatePrincipalDid);
      const wrongTargetProof = wrongTarget.proof as Record<string, unknown>;
      wrongTargetProof.verification_method = `${alternatePrincipalDid}#notary-key`;
      wrongTargetProof.payload_digest = canonicalHash(
        authoringRequestUnsigned(wrongTarget),
      );
      const wrongTargetBinding = authoringProofBinding(
        wrongTargetProof,
        "ak.applet_managed_actor_authoring_request_proof.v1",
      );
      wrongTargetProof.jws = detachedJws(
        wrongTargetBinding,
        alternatePrincipalKey.privateKey,
      );
      expect(
        verifyDetachedJws(
          String(wrongTargetProof.jws),
          wrongTargetBinding,
          createPublicKey(alternatePrincipalKey.privateKey),
        ),
      ).toBe(true);
      const wrongTargetResponse = await request.post(
        `${authorBaseUrl}/_arkret/edge/applet/managed-actors/author`,
        {
          headers: { "content-type": "application/json" },
          data: canonicalJson({ authoring_request: wrongTarget }),
        },
      );
      expect(wrongTargetResponse.status()).toBe(400);
      expect((await wrongTargetResponse.json()).error).toBe(
        "authoring_request_coordinate_mismatch",
      );
      const nestedUnknown = structuredClone(authoringRequest) as Record<
        string,
        unknown
      >;
      const nestedUnknownBasis = nestedUnknown.basis as Record<string, unknown>;
      (nestedUnknownBasis.approval_request as Record<string, unknown>).legacy =
        true;
      const nestedUnknownResponse = await request.post(
        `${authorBaseUrl}/_arkret/edge/applet/managed-actors/author`,
        {
          headers: { "content-type": "application/json" },
          data: canonicalJson({ authoring_request: nestedUnknown }),
        },
      );
      expect(nestedUnknownResponse.status()).toBe(400);
      expect((await nestedUnknownResponse.json()).error).toBe(
        "authoring_request_coordinate_mismatch",
      );

      const invertedWindow = structuredClone(authoringRequest) as Record<
        string,
        unknown
      >;
      invertedWindow.issued_at = canonicalTimestamp(
        new Date(
          Date.parse(String(invertedWindow.expires_at)) + 1_000,
        ),
      );
      const invertedWindowResponse = await request.post(
        `${authorBaseUrl}/_arkret/edge/applet/managed-actors/author`,
        {
          headers: { "content-type": "application/json" },
          data: canonicalJson({ authoring_request: invertedWindow }),
        },
      );
      expect(invertedWindowResponse.status()).toBe(410);
      expect((await invertedWindowResponse.json()).error).toBe(
        "authoring_request_expired",
      );

      const untrustedStation = structuredClone(
        authoringRequest,
      ) as Record<string, unknown>;
      (untrustedStation.proof as Record<string, unknown>).jws =
        "eyJhbGciOiJFZDI1NTE5In0..dGFtcGVyZWQ";
      const untrustedStationResponse = await request.post(
        `${authorBaseUrl}/_arkret/edge/applet/managed-actors/author`,
        {
          headers: { "content-type": "application/json" },
          data: canonicalJson({ authoring_request: untrustedStation }),
        },
      );
      expect(untrustedStationResponse.status()).toBe(400);
      expect((await untrustedStationResponse.json()).error).toBe(
        "authoring_request_proof_invalid",
      );
    }

    const exerciseAuthoringKats = options.exerciseAuthoringKats !== false;
    const authoredRequests = exerciseAuthoringKats
      ? await Promise.all([
          request.post(
            `${authorBaseUrl}/_arkret/edge/applet/managed-actors/author`,
            authorRequestOptions,
          ),
          request.post(
            `${authorBaseUrl}/_arkret/edge/applet/managed-actors/author`,
            authorRequestOptions,
          ),
        ])
      : [
          await request.post(
            `${authorBaseUrl}/_arkret/edge/applet/managed-actors/author`,
            authorRequestOptions,
          ),
        ];
    const authored = authoredRequests[0];
    const authoredText = await authored.text();
    if (!authored.ok()) {
      throw new Error(
        `Applet install authoring returned ${authored.status()}: ${authoredText}`,
      );
    }
    const authorOutcome = JSON.parse(authoredText) as Record<string, unknown>;
    if (exerciseAuthoringKats) {
      const concurrentReplay = authoredRequests[1];
      expect(concurrentReplay.status()).toBe(200);
      expect(canonicalJson(await concurrentReplay.json())).toBe(
        canonicalJson(authorOutcome),
      );
      const reloaded = await request.post(
        `${authorBaseUrl}/inspect/authoring-reload`,
      );
      expect(reloaded.status()).toBe(200);
      const replayed = await request.post(
        `${authorBaseUrl}/_arkret/edge/applet/managed-actors/author`,
        {
          headers: { "content-type": "application/json" },
          data: canonicalJson({ authoring_request: authoringRequest }),
        },
      );
      expect(replayed.status()).toBe(200);
      expect(canonicalJson(await replayed.json())).toBe(
        canonicalJson(authorOutcome),
      );
    }
    const managedActorBundle = authorOutcome.managed_actor_bundle;
    if (!managedActorBundle || typeof managedActorBundle !== "object") {
      throw new Error(
        "Applet install author endpoint omitted managed_actor_bundle",
      );
    }
    resolved = {
      commitBody: {
        applet_package: signed.applet_package,
        authoring_request: authoringRequest,
        managed_actor_bundle: managedActorBundle,
      },
      grantActionsById: authoring.grantActionsById,
    };
    expect(Object.keys(resolved.commitBody).sort()).toEqual([
      "applet_package",
      "authoring_request",
      "managed_actor_bundle",
    ]);
  }
  const installUrl = `${solandBaseUrl()}/_arkret/self/applets/install`;
  if (options.exerciseAuthoringKats !== false) {
    const fifthRole = structuredClone(resolved.commitBody);
    const bundle = fifthRole.managed_actor_bundle as Record<string, unknown>;
    bundle.membership_event = structuredClone(bundle.profile_event);
    const fifthRoleResponse = await request.fetch(installUrl, {
      method: "POST",
      headers: {
        ...authHeaders(token),
        "content-type": "application/json",
        "Idempotency-Key": `${idempotencyKey}-fifth-role`,
      },
      data: canonicalJson(fifthRole),
    });
    expect(fifthRoleResponse.status()).toBe(400);
    expect(wireErrCode(await fifthRoleResponse.json())).toBe(
      "schema_violation",
    );
  }
  if (options.commitDelayMs) {
    await new Promise((resolve) => setTimeout(resolve, options.commitDelayMs));
  }
  const response = await request.fetch(installUrl, {
    method: "POST",
    headers: {
      ...authHeaders(token),
      "content-type": "application/json",
      "Idempotency-Key": idempotencyKey,
    },
    data: canonicalJson(resolved.commitBody),
  });
  return {
    response,
    prepared: resolved,
    grantActionsById: resolved.grantActionsById,
  };
}

async function prepareAppletInstallAuthoringBasis(
  request: APIRequestContext,
  token: string,
  signed: SignedPackage,
  realmId: string,
  effectiveScope: Record<string, unknown>,
  mutateRegistrationManifest?: (
    manifest: Record<string, unknown>,
  ) => void,
): Promise<{
  basis: Record<string, unknown>;
  grantActionsById: Map<string, string[]>;
}> {
  const actorId = await currentActorIdApi(request, token);
  const sealBasis = await readRealmSealBasis(request, token, realmId);
  const registrationPayload = appletRegistrationPayload(signed);
  const registrationManifest = registrationPayload.manifest;
  if (
    !registrationManifest ||
    typeof registrationManifest !== "object" ||
    Array.isArray(registrationManifest)
  ) {
    throw new Error("Applet registration payload has no manifest");
  }
  mutateRegistrationManifest?.(
    registrationManifest as Record<string, unknown>,
  );
  const approvedActions = Array.from(
    new Set(signed.applet_package.requested_scopes),
  );
  if (approvedActions.length === 0) {
    throw new Error("Applet install plan approved no capability actions");
  }

  const createdAt = canonicalTimestamp();
  const registrationEvent = signedEventEnvelope({
    actorId,
    realmId,
    kind: "ak.applet.registration",
    createdAt,
    scopeRef: effectiveScope,
    sealBasis,
    payload: registrationPayload as Record<string, unknown>,
  });
  await advanceEnvelopeToActorFrontier(request, token, registrationEvent);
  const registrationActorSeq = registrationEvent.actor_seq;
  const registrationEventId = registrationEvent.event_id;
  if (
    typeof registrationActorSeq !== "number" ||
    !Number.isSafeInteger(registrationActorSeq) ||
    typeof registrationEventId !== "string"
  ) {
    throw new Error(
      "Prepared Applet registration Event has an invalid actor frontier",
    );
  }

  let previousEventId = registrationEventId;
  const capabilityGrantEvents: Array<Record<string, unknown>> = [];
  const grantActionsById = new Map<string, string[]>();
  for (const [offset, action] of approvedActions.entries()) {
    const unsignedGrant: Record<string, unknown> = {
      schema: "ak.schema.capability.v1",
      realm_id: realmId,
      issuer_id: accountActorId(actorId),
      subject: serviceActorId(signed.applet_package.service_id),
      actions: [action],
      resources: [effectiveScope],
      constraints: [
        {
          constraint_kind: "authority_control",
          constraint_subkind: "applet_authority",
          effect: "allow",
          evaluation_class: "grant_local",
          applet_id: signed.applet_package.applet_id,
          executed_by: signed.applet_package.service_id,
          registration_epoch: signed.applet_package.registration_epoch,
        },
      ],
      issued_at: createdAt,
      expires_at: canonicalTimestamp(
        new Date(Date.parse(createdAt) + 24 * 60 * 60 * 1000),
      ),
      issuer_authority_refs: [
        {
          kind: "realm_root",
          realm_id: realmId,
          cell_ref: "ak:cell:ak.component.realm.authority_root.v1:null",
          controller_epoch_at_issuance: 0,
          authority_generation: 0,
        },
      ],
    };
    // The grant body is closed and carries no inner proof; the Event envelope
    // proof is the sole durable issuer signature.
    const grant = unsignedGrant;
    const event = signedEventEnvelope({
      actorId,
      realmId,
      kind: "ak.capability.grant",
      actorSeq: registrationActorSeq + offset + 1,
      createdAt,
      prevRefs: [previousEventId],
      scopeRef: effectiveScope,
      sealBasis,
      payload: {
        grant,
      },
    });
    const grantId = retypeEventDerivedId(String(event.event_id), "grant");
    previousEventId = String(event.event_id);
    capabilityGrantEvents.push(event);
    grantActionsById.set(grantId, [action]);
  }

  const basis: Record<string, unknown> = {
    schema: "ak.schema.applet_install_authoring_request_basis.v1",
    purpose: "install_bot",
    target_station_id: solandServiceId(),
    install_actor_id: actorId,
    applet_id: signed.applet_package.applet_id,
    service_id: signed.applet_package.service_id,
    package_digest: signed.applet_package.package_digest,
    effective_scope: effectiveScope,
    approval_request: {
      approve_actions: signed.applet_package.requested_scopes,
      ghost_actor_mode: "policy_declared",
      delegated_native_actors_allowed: false,
      e2ee_join_allowed: false,
      widget_allowed: false,
    },
    actor_policy: {
      ghost_actor_mode: "policy_declared",
    },
    e2ee_policy: { mls_join_allowed: false },
    widget_policy: { widget_allowed: false },
    registration_event: registrationEvent,
    capability_grant_events: capabilityGrantEvents,
  };
  return { basis, grantActionsById };
}

function appletRegistrationPayload(
  signed: SignedPackage,
): Record<string, unknown> {
  const pkg = signed.applet_package;
  const operation = signed.service_id_operation;
  const signingKey = signed.service_signing_private_key;
  if (!operation || !signingKey) {
    throw new Error(
      "Applet registration Event requires the formal service DID operation and signing key",
    );
  }
  const versionTime = operation.didDocument.updated;
  if (typeof versionTime !== "string") {
    throw new Error("Applet service DID document has no version timestamp");
  }
  const webhookAuth = pkg.webhook_auth as Record<string, unknown> | undefined;
  const verificationMethod = webhookAuth?.key_ref;
  if (typeof verificationMethod !== "string") {
    throw new Error("Applet package webhook auth has no verification method");
  }
  const publicJwk = createPublicKey(signingKey).export({ format: "jwk" });
  const manifest: Record<string, unknown> = {
    claimed_profiles: pkg.claimed_profiles,
    limits: pkg.limits,
    ghost_policy: pkg.ghost_policy,
    delegation_policy: pkg.delegation_policy,
    e2ee_policy: pkg.e2ee_policy,
    registration_epoch_evidence: {
      did: operation.did,
      document_digest: canonicalHash(operation.didDocument),
      method_version_evidence: {
        method: "did:webvh",
        version_id: operation.versionId,
        version_time: versionTime,
        unversioned_refetch: false,
      },
      accepted_signing_keys: [
        {
          key_ref: verificationMethod,
          public_key_digest: canonicalHash(publicJwk),
        },
      ],
    },
  };
  if (pkg.widget !== undefined) manifest.widget = pkg.widget;
  return {
    applet_id: pkg.applet_id,
    service_id: pkg.service_id,
    controller_id: pkg.controller_id,
    base_url: pkg.base_url,
    bot_actor_id: pkg.bot_actor_id,
    claimed_profiles: pkg.claimed_profiles,
    protocols: pkg.protocols,
    namespaces: pkg.namespaces,
    receive_events: pkg.receive_events,
    receive_signals: pkg.receive_signals,
    rate_limited: pkg.rate_limited,
    requested_scopes: pkg.requested_scopes,
    registration_epoch: pkg.registration_epoch,
    webhook_auth: pkg.webhook_auth,
    manifest,
    proof: pkg.proof,
    created_at: pkg.created_at,
  };
}

function registrationManifestFromBasis(
  basis: Record<string, unknown>,
): Record<string, unknown> {
  const registrationEvent = basis.registration_event as
    | Record<string, unknown>
    | undefined;
  const payload = registrationEvent?.payload as
    | Record<string, unknown>
    | undefined;
  const manifest = payload?.manifest as Record<string, unknown> | undefined;
  const evidence = manifest?.registration_epoch_evidence;
  if (
    !manifest ||
    !evidence ||
    typeof evidence !== "object" ||
    Array.isArray(evidence)
  ) {
    throw new Error(
      "Prepared registration Event has no registration epoch evidence",
    );
  }
  return manifest;
}

function webvhManagedActorEvidence(built: BuiltWebvhGenesis) {
  const historyHead = `sha256:${createHash("sha256")
    .update(canonicalJson(built.entry), "utf8")
    .digest("hex")}`;
  const emptyWitnessDigest = `sha256:${createHash("sha256")
    .update(canonicalJson([]), "utf8")
    .digest("hex")}`;
  const initialResolution = {
    did: built.did,
    method_history_head: historyHead,
    version_id: built.versionId,
  };
  return {
    initialResolution,
    methodHistoryEvidence: {
      adapter_version: "did:webvh:1.0",
      evidence_kind: "webvh_log",
      boundary: {
        from_method_history_head: historyHead,
        from_version_id: built.versionId,
        to_method_history_head: historyHead,
        to_version_id: built.versionId,
      },
      evidence: {
        kind: "ak.did.binding_evidence.v1",
        method: "webvh",
        document_digest: `sha256:${createHash("sha256")
          .update(canonicalJson(built.didDocument), "utf8")
          .digest("hex")}`,
        method_proofs: [
          {
            kind: "webvh_log",
            history_head: historyHead,
            witnesses: [],
            witness_proofs_digest: emptyWitnessDigest,
          },
        ],
      },
      log_entries: [built.entry],
      witness_records: [],
    },
  };
}

function replaceWithAppletServiceProof(
  event: Record<string, unknown>,
  signed: SignedPackage,
): Record<string, unknown> {
  const unsigned = { ...event };
  delete unsigned.proofs;
  return {
    ...unsigned,
    proofs: [
      appletEventProof(
        requiredAppletServiceDid(signed),
        unsigned,
        signed.service_signing_private_key,
      ),
    ],
  };
}

function requiredAppletServiceDid(signed: SignedPackage): string {
  const did = signed.service_id_operation?.did;
  if (!did) {
    throw new Error("Applet service proof requires the formal service DID operation");
  }
  return did;
}

function buildGhostManagedActorCreation(args: {
  signed: SignedPackage;
  registration: AppletRegistration;
  realmId: string;
  ghostBuilt: BuiltWebvhGenesis;
  externalUser: { id: string; display_name?: string };
  appletAuthorityRef: string;
  createdAt: string;
  serviceActorSeq: number;
  servicePrevRef?: string;
}) {
  const signingKey = args.signed.service_signing_private_key;
  if (!signingKey) {
    throw new Error("Ghost provision requires the Applet service signing key");
  }
  const serviceId = args.signed.applet_package.service_id;
  const ghostId = projectDidToCoreId(args.ghostBuilt.did);
  const evidence = webvhManagedActorEvidence(args.ghostBuilt);
  const externalRef = {
    protocol: "bridge",
    instance_id: "joint-e2e",
    external_id: args.externalUser.id,
  };
  let provisionEvent = signedEventEnvelope({
    actorId: serviceActorId(serviceId),
    realmId: args.realmId,
    kind: "ak.applet.managed_actor.provision",
    actorSeq: args.serviceActorSeq,
    createdAt: args.createdAt,
    prevRefs: args.servicePrevRef ? [args.servicePrevRef] : [],
    schemaId: "ak.schema.applet_managed_actor_provision.v1",
    authorizationRef: args.appletAuthorityRef,
    appletId: args.signed.applet_package.applet_id,
    payload: {
      schema: "ak.schema.applet_managed_actor_provision.v1",
      applet_id: args.signed.applet_package.applet_id,
      service_id: serviceId,
      actor_id: ghostId,
      actor_station_id: solandServiceId(),
      actor_role: "ghost",
      initial_resolution: evidence.initialResolution,
      method_history_evidence: evidence.methodHistoryEvidence,
      registration_ref: args.registration.registration_event_ref,
      applet_authority_ref: args.appletAuthorityRef,
      external_ref: externalRef,
    },
  });
  provisionEvent = replaceWithAppletServiceProof(provisionEvent, args.signed);
  const provisionEventId = String(provisionEvent.event_id);

  const genesis = signedRealmGenesisEnvelope({
    actorId: ghostId,
    realmId: "",
    kind: "ak.realm.create",
    actorSeq: 0,
    createdAt: args.createdAt,
    executedBy: serviceActorId(serviceId),
    stationId: solandServiceId(),
    appletId: args.signed.applet_package.applet_id,
    authorizationRef: args.appletAuthorityRef,
    refs: [
      {
        id: provisionEventId,
        role: "applet_managed_actor_provision",
        critical: true,
      },
    ],
    requirementsSchema: ["ak.schema.realm_genesis.v1"],
    preconditions: [
      {
        cell_id: "ak:cell:ak.component.realm.create.v1:null",
        predicate: { op: "head_eq", value: null },
      },
    ],
    payload: {
      object: {
        schema: "ak.schema.realm_genesis.v1",
        purpose: "applet_managed_control",
        genesis_salt: Buffer.alloc(32, 11).toString("base64url"),
        trust_domain: "ak:trust_domain:soland.local",
        schema_refs: [
          "ak.schema.realm.v1",
          "ak.profile.principal_control_realm.v1",
        ],
        reducer_profile: "ak.reducer.core.v1",
        encryption_profile: "mls_rfc9420",
        security_class: "standard",
        digest_algorithm: "sha256",
        notary: singleSignerNotaryFromDid(solandServiceDid()),
        initial_resolution: evidence.initialResolution,
      },
    },
  });
  const pcrGenesisEvent = replaceWithAppletServiceProof(
    genesis.envelope,
    args.signed,
  );

  const grantWithoutProof = {
    schema: "ak.schema.accountability_grant.v1",
    issuer_id: serviceId,
    subject_id: ghostId,
    accountability_scope: "contracted_service",
    not_before: args.createdAt,
    grant_status: "active",
  };
  const payloadDigest = `sha256:${createHash("sha256")
    .update("ak.accountability-grant-v1\n", "utf8")
    .update(canonicalJson(grantWithoutProof), "utf8")
    .digest("hex")}`;
  const verificationMethod = `${requiredAppletServiceDid(args.signed)}#applet-service-key`;
  let accountabilityEvent = signedEventEnvelope({
    actorId: serviceActorId(serviceId),
    realmId: args.realmId,
    kind: "ak.identity.accountability_grant",
    actorSeq: args.serviceActorSeq + 1,
    createdAt: args.createdAt,
    prevRefs: [provisionEventId],
    authorizationRef: args.appletAuthorityRef,
    appletId: args.signed.applet_package.applet_id,
    payload: {
      ...grantWithoutProof,
      proof: {
        kind: "detached_jws",
        verification_method: verificationMethod,
        payload_digest: payloadDigest,
        created_at: args.createdAt,
        jws: detachedJws(
          {
            context: "ak.accountability_grant_proof.v1",
            payload_digest: payloadDigest,
            issuer: serviceId,
            subject: ghostId,
            verification_method: verificationMethod,
            created_at: args.createdAt,
          },
          signingKey,
        ),
      },
    },
  });
  accountabilityEvent = replaceWithAppletServiceProof(
    accountabilityEvent,
    args.signed,
  );
  let profileEvent = signedEventEnvelope({
    actorId: ghostId,
    realmId: args.realmId,
    kind: "ak.profile.create",
    actorSeq: 0,
    createdAt: args.createdAt,
    executedBy: serviceActorId(serviceId),
    authorizationRef: args.appletAuthorityRef,
    appletId: args.signed.applet_package.applet_id,
    refs: [
      {
        id: accountabilityEvent.event_id,
        role: "accountability",
        critical: true,
      },
    ],
    payload: {
      object: {
        schema: "ak.schema.actor_profile.v1",
        realm_id: args.realmId,
        principal_id: ghostId,
        actor_kind: "integration",
        display_name: args.externalUser.display_name ?? args.externalUser.id,
        accountable_principal_ids: [serviceId],
        profile_fields: {
          managed_by_applet: args.signed.applet_package.applet_id,
          external_ref: externalRef,
        },
        created_at: args.createdAt,
      },
    },
  });
  profileEvent = replaceWithAppletServiceProof(profileEvent, args.signed);
  return {
    ghost_actor_id: ghostId,
    ghost_actor_did: args.ghostBuilt.did,
    actor_station_id: solandServiceId(),
    external_ref: externalRef,
    managed_actor_provision_event: provisionEvent,
    pcr_genesis_event: pcrGenesisEvent,
    accountability_grant_event: accountabilityEvent,
    profile_event: profileEvent,
  };
}

async function publishAppletServiceIdDocument(
  request: APIRequestContext,
  signed: SignedPackage,
): Promise<void> {
  if (!signed.service_id_operation) {
    return;
  }
  await submitPrincipalGenesisEntry(
    request,
    solandBaseUrl(),
    signed.service_id_operation,
  );
  if (signed.bot_actor_operation) {
    await submitPrincipalGenesisEntry(
      request,
      solandBaseUrl(),
      signed.bot_actor_operation,
    );
  }
}

function installRegistrationFromResponse(
  signed: SignedPackage,
  realmId: string,
  response: Record<string, unknown>,
  grantActionsById: Map<string, string[]>,
): AppletRegistration {
  const capabilityGrantRefs = Array.isArray(response.capability_grant_refs)
    ? response.capability_grant_refs.map(String)
    : [];
  expect(new Set(capabilityGrantRefs)).toEqual(
    new Set(grantActionsById.keys()),
  );
  return {
    applet_id: String(response.applet_id),
    bot_actor_id: String(response.bot_actor_id),
    portal_realm_id: realmId,
    namespace:
      signed.applet_package.namespaces?.handles?.[0]?.pattern ??
      signed.applet_package.applet_id,
    status: String(response.effective_status),
    registration_event_ref: String(response.registration_event_ref),
    capability_grants: capabilityGrantRefs.map((grantRef) => ({
      grant_ref: grantRef,
      actions: grantActionsById.get(grantRef) ?? [],
    })),
  };
}

function typedAppletId(): string {
  return typedId("operation").replace("ak:operation:", "ak:applet:");
}

function detachedJws(
  binding: Record<string, unknown>,
  signingKey: KeyObject,
): string {
  const protectedHeader = Buffer.from('{"alg":"Ed25519"}', "utf8").toString(
    "base64url",
  );
  const signingInput = `${protectedHeader}.${Buffer.from(
    canonicalJson(binding),
    "utf8",
  ).toString("base64url")}`;
  const signature = sign(
    null,
    Buffer.from(signingInput, "utf8"),
    signingKey,
  ).toString("base64url");
  return `${protectedHeader}..${signature}`;
}

function canonicalHash(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

function authoringRequestUnsigned(
  request: Record<string, unknown>,
): Record<string, unknown> {
  const unsigned: Record<string, unknown> = {
    schema: request.schema,
    purpose: request.purpose,
    basis: request.basis,
    hosting_notary: request.hosting_notary,
    issued_at: request.issued_at,
    expires_at: request.expires_at,
  };
  if (request.plan_digest !== undefined) {
    unsigned.plan_digest = request.plan_digest;
  }
  return unsigned;
}

function authoringProofBinding(
  proof: Record<string, unknown>,
  context: string,
): Record<string, unknown> {
  return {
    context,
    payload_digest: proof.payload_digest,
    verification_method: proof.verification_method,
    created_at: proof.created_at,
    audience: proof.audience,
  };
}

function verifyDetachedJws(
  jws: string,
  binding: Record<string, unknown>,
  publicKey: KeyObject,
): boolean {
  const [protectedHeader, payload, signature] = jws.split(".");
  if (!protectedHeader || payload !== "" || !signature) return false;
  const signingInput = `${protectedHeader}.${Buffer.from(
    canonicalJson(binding),
    "utf8",
  ).toString("base64url")}`;
  return verify(
    null,
    Buffer.from(signingInput, "utf8"),
    publicKey,
    Buffer.from(signature, "base64url"),
  );
}

function appletEventProof(
  verificationMethod: string,
  event: Record<string, unknown>,
  signingKey?: KeyObject,
): Record<string, unknown> {
  // `event.actor_id` is the projected core id; the proof binds to the authoring
  // DID, which is the DID URL prefix of the bot's verification method.
  const signingSeedB64url = signingKey?.export({ format: "jwk" }).d;
  return sdkEventEnvelopeProof({
    actorDid: verificationMethod.split("#", 1)[0]!,
    event,
    verificationMethod,
    createdAt: canonicalEventTimestamp(),
    signingSeedB64url,
  });
}

function hlcForStamp(stamp: number): string {
  const physical = Math.max(Date.now(), stamp)
    .toString(16)
    .padStart(12, "0")
    .slice(-12);
  const node = createHash("sha256")
    .update(String(stamp))
    .digest("hex")
    .slice(0, 8);
  return `${physical}-0000-${node}`;
}
