// Applet bridge (Service-only installation and independent Bot/Ghost actors)
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
import { encodeEd25519PubkeyMultibase } from "../../helpers/encoding";
import {
  expect,
  operationSelector,
  test,
  type APIRequestContext,
  type APIResponse,
} from "../../helpers/arkret-test";
import {
  mockAppletRegistryBaseUrl,
  colandBaseUrl,
  colandServiceDid,
  colandServiceId,
} from "../../helpers/env";
import {
  accountActorId,
  authHeaders,
  canonicalEventTimestamp,
  requireDidCoreId,
  canonicalTimestamp,
  canonicalJson,
  cotestWire,
  sdkEventDerivedIds,
  sdkEventEnvelopeProof,
  createRealmApi,
  currentActorIdApi,
  queryRealmEventsApi,
  rawSubmitSignedEventApi,
  prepareSignedEventBatchSubmissionsApi,
  projectDidToCoreId,
  realmAuthorityRootRef,
  retypeEventDerivedId,
  resolveDefaultStrandId,
  signedEventEnvelope,
  signedRealmGenesisEnvelope,
  submitSignedEventApi,
  typedId,
  serviceActorId,
  sha256CanonicalJson,
  wireErrCode,
} from "../../helpers/coland-api";
import {
  assertJointStackNotRequired,
  ensureRegistered,
  issueUserSession,
  openDpopUserPage,
  uniqueUser,
} from "../../helpers/users";
import {
  buildWebvhGenesisEntry,
  generateWebvhKey,
  submitPrincipalGenesisEntry,
  type BuiltWebvhGenesis,
} from "../../helpers/webvh-api";

import type { ActorId, AppletInstallOutcome, AppletBotProvisionOutcome, AppletAuthorityMaterialRequestBody, AppletAuthorityMaterialOutcome, CapabilityGrantObject } from "../../helpers/generated/spec-wire-objects";

// Each case provisions its own identities and Realm; a failed case must not
// skip the remaining independent admission and replay checks.
test.describe.configure({ mode: "default" });

type SignedPackage = {
  applet_package: Record<string, unknown> & {
    applet_id: string;
    service_id: string;
    controller_principal_id: string;
    namespaces?: {
      handles?: Array<{ pattern: string }>;
    };
    requested_scopes: string[];
    registration_epoch: string;
  };
  bot_actor_id: Extract<ActorId, { kind: "account" }>;
  package_digest: string;
  signing_did: string;
  service_id_document?: Record<string, unknown>;
  service_id_operation?: BuiltWebvhGenesis;
  bot_actor_operation?: BuiltWebvhGenesis;
  ghost_namespace_token?: string;
  service_signing_private_key?: KeyObject;
  bot_signing_private_key?: KeyObject;
};

// Private test bookkeeping combines two independently accepted outcomes.
// It is never an installation wire response.
type AppletRegistration = {
  applet_id: string;
  bot_actor_id: Extract<ActorId, { kind: "account" }>;
  portal_realm_id: string;
  namespace: string;
  status: string;
  /// `applet_install_outcome.registration_event_ref`: the bare EventId of the
  /// accepted registration (applet-install-operations.schema.json).
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
  return realmId;
}

async function revokeAppletRuntime(
  request: APIRequestContext,
  token: string,
  actorId: string,
  appletId: string,
  realmId: string,
  idempotencyKey: string,
  onCommit?: () => Promise<APIResponse>,
): Promise<Record<string, unknown>> {
  const effectiveScope = { kind: "realm" as const, realm_id: realmId };
  const reasonCode = "requested_by_admin";
  const revokeMode = "revoke_runtime_only";
  const base = `${colandBaseUrl()}/_arkret/self/applets/${encodeURIComponent(appletId)}/revoke`;
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
  // applet-integration.md §4b: the preview outcome carries only the canonical
  // plan; the caller computes `revoke_plan_digest = SHA-256(JCS(revoke_plan))`.
  // Every capability intent's `expected_revision` is copied byte-for-byte into
  // the caller-signed `CapabilityRevokePayload`, and every managed membership
  // intent gets one caller-signed `ak.member.state` removal.
  const plan = JSON.parse(previewText) as {
    revoke_plan: {
      registration_epoch: string;
      reason_code: string;
      capability_revocations: Array<{
        grant_id: string;
        expected_revision: Record<string, unknown>;
        reason_code: string;
      }>;
      membership_removals: Array<{
        member_id: ActorId;
        membership: "leave" | "remove";
        reason_code: string;
      }>;
    };
  };
  expect(plan).not.toHaveProperty("revoke_plan_digest");
  const revokePlanDigest = `sha256:${sha256CanonicalJson(plan.revoke_plan)}`;
  // The Realm controller's own authority comes from the committed genesis
  // projection, so the revoke cites no authorization source.
  const revokeEvents = plan.revoke_plan.capability_revocations.map((intent) =>
    signedEventEnvelope({
      actorId,
      realmId,
      kind: "ak.capability.revoke",
      scopeRef: effectiveScope,
      payload: {
        grant_id: intent.grant_id,
        expected_revision: intent.expected_revision,
        reason: intent.reason_code,
      },
    }),
  );
  const membershipEvents = plan.revoke_plan.membership_removals.map((intent) =>
    signedEventEnvelope({
      actorId,
      realmId,
      kind: "ak.member.state",
      scopeRef: effectiveScope,
      payload: {
        realm_id: realmId,
        member_id: intent.member_id,
        membership: intent.membership,
        reason: intent.reason_code,
      },
    }),
  );
  const capabilityRevokeEvents = await prepareSignedEventBatchSubmissionsApi(
    request,
    token,
    revokeEvents,
    { context: `prepare Applet capability revoke ${appletId}` },
  );
  const membershipStateEvents = await prepareSignedEventBatchSubmissionsApi(
    request,
    token,
    membershipEvents,
    { context: `prepare Applet membership removal ${appletId}` },
  );
  const body = canonicalJson({
    revoke_plan_digest: revokePlanDigest,
    effective_scope: effectiveScope,
    reason_code: reasonCode,
    revoke_mode: revokeMode,
    capability_revoke_events: capabilityRevokeEvents,
    membership_state_events: membershipStateEvents,
  });
  const submit = async (): Promise<Record<string, unknown>> => {
    const response = await request.post(base, {
      headers: {
        ...authHeaders(token, "POST", base),
        "content-type": "application/json",
        "Idempotency-Key": idempotencyKey,
      },
      data: body,
    });
    const responseText = await response.text();
    expect(response.status(), responseText).toBe(200);
    return JSON.parse(responseText) as Record<string, unknown>;
  };
  const concurrentDelivery = onCommit?.();
  const outcome = await submit();
  if (!concurrentDelivery || outcome.status !== "partially_completed") return outcome;

  // A competing stream Commit can make the candidate unavailable. Resume the
  // durable saga with the exact request after the competing delivery settles.
  const rejections = outcome.rejections as Array<{ reason_code: string }>;
  expect(rejections.length).toBeGreaterThan(0);
  for (const rejection of rejections) {
    expect(rejection.reason_code).toBe("temporarily_unavailable");
  }
  await concurrentDelivery;
  const resumed = await submit();
  expect(resumed.operation_id).toBe(outcome.operation_id);
  expect(resumed.revoke_plan_digest).toBe(outcome.revoke_plan_digest);
  const previousSteps = outcome.steps as Array<Record<string, unknown>>;
  const resumedSteps = resumed.steps as Array<Record<string, unknown>>;
  expect(resumedSteps).toHaveLength(previousSteps.length);
  for (const [index, previous] of previousSteps.entries()) {
    if (previous.submitted_event_id !== undefined) {
      expect(previous).not.toHaveProperty("committed_event_ref");
      expect(resumedSteps[index].committed_event_ref).toMatchObject({
        event_id: previous.submitted_event_id,
      });
    } else if (previous.committed_event_ref !== undefined) {
      expect(resumedSteps[index].committed_event_ref).toEqual(previous.committed_event_ref);
    } else {
      expect(resumedSteps[index].effect_ref).toBe(previous.effect_ref);
    }
  }
  return resumed;
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

type ManagedActorId = Extract<ActorId, { kind: "account" }>;

/// Issue one terminal child of the installed Service's action grants.
///
/// authz/capabilities.md §2.1 / §8: a Bot or Ghost acts only through an
/// explicit grant naming its own complete ActorId; the install grants name the
/// Applet Service. applet-integration.md §6 / §11 bind the grant to the exact
/// install with `authority_control` + `applet_authority`. The parent executor
/// is Service; the terminal child executor is its own complete Account subject.
async function grantManagedActorActions(request: APIRequestContext, token: string, signed: SignedPackage, realmId: string, actorId: ManagedActorId, actions: string[]): Promise<string> {
  const effectiveScope = {kind:"realm" as const, realm_id:realmId};
  const service = serviceActorId(signed.applet_package.service_id);
  const history = await queryRealmEventsApi(request,token,realmId);
  // The administrator's history identifies fixture grant IDs only. The Service
  // obtains accepted source material through its own signed dependency read.
  const parentIds = [...new Set(actions.map(action=> {
    const parent=(history.events as Array<Record<string,unknown>>).find(event=> {
      const grant=(event.payload as {grant?:CapabilityGrantObject})?.grant;
      return event.kind==="ak.capability.grant" && grant && canonicalJson(grant.subject)===canonicalJson(service) && grant.actions.includes(action);
    });
    if(!parent) throw new Error(`Missing Service parent grant for ${action}`);
    return retypeEventDerivedId(String(parent.event_id), "grant");
  }))];
  const materialUrl = `${colandBaseUrl()}/_arkret/self/applets/${encodeURIComponent(signed.applet_package.applet_id)}/authority/material`;
  // This live scenario exercises one real parent; multi-parent admission is guarded.
  expect(parentIds).toHaveLength(1);
  const materialRequest: AppletAuthorityMaterialRequestBody = {effective_scope:effectiveScope, grant_ids:parentIds};
  const materialResponse = await request.post(materialUrl, {
    headers: signedAppletTransactionHeaders({body:materialRequest, targetUri:materialUrl, sourceServiceId:signed.applet_package.service_id, destinationServiceId:colandServiceId(), idempotencyKey:typedId("operation"), keyId:appletProducerKeyRef(signed), signingKey:signed.service_signing_private_key}),
    data: canonicalJson(materialRequest),
  });
  expect(materialResponse.status(), await materialResponse.text()).toBe(200);
  const material = await materialResponse.json() as AppletAuthorityMaterialOutcome;
  // SDK carrier validation includes the original producer's required Device
  // evidence. Shape/cut validation does not claim signer crypto verification.
  expect(cotestWire("validate-applet-authority-material",material)).toEqual({valid:true});
  expect(material.applet_id).toBe(signed.applet_package.applet_id);
  expect(material.effective_scope).toEqual(effectiveScope);
  expect(material.registration.event.scope_ref).toEqual(effectiveScope);
  expect(material.grant_events).toHaveLength(parentIds.length);
  expect(material.current_results).toHaveLength(parentIds.length);
  for (const current of material.current_results) {
    expect(current.status).toBe("present");
    expect(current.realm_id).toBe(realmId);
    expect(current.governance_generation).toBeGreaterThanOrEqual(0);
    expect(current.effective_stream_head.stream_ref).toEqual(effectiveScope);
    expect(current.entry.source_stream_ref).toEqual(effectiveScope);
    expect(current.entry.selector.kind).toBe("capability_grant");
    expect(current.entry.revision.stream_position).toBeLessThanOrEqual(current.effective_stream_head.stream_position);
  }
  const parents = material.grant_events.map(({event,commit})=> {
    expect(event.scope_ref).toEqual(effectiveScope);
    expect(commit.event_ref).toBe(event.event_id);
    expect(parentIds).toContain(retypeEventDerivedId(event.event_id,"grant"));
    return event as Record<string,unknown>;
  });
  const expiries=parents.flatMap(parent=> ((parent.payload as {grant:CapabilityGrantObject}).grant.constraints ?? []).flatMap(c=>c.constraint_kind==="temporal" && "expires_at" in c && typeof c.expires_at==="string" ? [c.expires_at] : []));
  const createdAt=canonicalTimestamp();
  const grant: Pick<CapabilityGrantObject,"schema"|"realm_id"|"issuer_id"|"subject"|"actions"|"resources"|"constraints"|"issued_at"|"issuer_authority_refs">={
    schema:"ak.schema.capability.v1",realm_id:realmId,issuer_id:service,subject:actorId,actions,resources:[effectiveScope],issued_at:createdAt,
    issuer_authority_refs:[...new Set(parents.map(event=>retypeEventDerivedId(String(event.event_id),"grant")))].map(grant_id=>({kind:"grant" as const,grant_id})),
    constraints:[
      {constraint_kind:"authority_control",effect:"allow",evaluation_class:"grant_local",max_authority_depth:0,authority_regrant_allowed:false},
      {constraint_kind:"authority_control",constraint_subkind:"applet_authority",effect:"allow",evaluation_class:"grant_local",applet_id:signed.applet_package.applet_id,executed_by:actorId,registration_epoch:signed.applet_package.registration_epoch},
      ...(expiries.length ? [{constraint_kind:"temporal" as const,constraint_subkind:"window" as const,effect:"allow" as const,evaluation_class:"stateless" as const,not_before:createdAt,expires_at:expiries.sort()[0]}] : []),
    ],
  };
  const unsigned={actor_id:service,realm_id:realmId,kind:"ak.capability.grant",created_at:canonicalEventTimestamp(),scope_ref:effectiveScope,applet_id:signed.applet_package.applet_id,authorization_ref:parentIds[0],payload:{grant}};
  const event={...unsigned,event_id:sdkEventDerivedIds(unsigned).event_id};
  const signedEvent={...event,producer_proof:appletEventProof(appletProducerKeyRef(signed),event,signed.service_signing_private_key)};
  const outcome=await deliverAppletEvents(request,signed,[signedEvent],typedId("operation"));
  expect(outcome.status,JSON.stringify(outcome.rejections??[])).toBe("accepted");
  return retypeEventDerivedId(String(event.event_id),"grant");
}

/// Deliberately invalid Service proxy: a child naming the Account cannot
/// authorize its Service producer. Used only to verify zero-write rejection.
function serviceProxyManagedActorEvent(args: {
  signed: SignedPackage;
  realmId: string;
  actorId: ManagedActorId;
  authorizationRef: string;
  kind: string;
  payload: Record<string, unknown>;
}): Record<string, unknown> {
  const unidentified = {
    kind: args.kind,
    realm_id: args.realmId,
    scope_ref: { kind: "realm", realm_id: args.realmId },
    actor_id: args.actorId,
    executed_by: serviceActorId(args.signed.applet_package.service_id),
    authorization_ref: args.authorizationRef,
    applet_id: args.signed.applet_package.applet_id,
    created_at: canonicalEventTimestamp(),
    payload: args.payload,
  };
  const event = {
    ...unidentified,
    event_id: sdkEventDerivedIds(unidentified).event_id,
  };
  return {
    ...event,
    producer_proof: appletEventProof(
      appletProducerKeyRef(args.signed),
      event,
      args.signed.service_signing_private_key,
    ),
  };
}

function appletProducerKeyRef(signed: SignedPackage): string {
  return String(
    (signed.applet_package.webhook_auth as Record<string, unknown>).key_ref,
  );
}

/// Deliver Applet-carried Events through the inbound transaction rail with the
/// Service's per-delivery RFC 9421 signature (applet-integration.md §7.3.1).
async function rawDeliverAppletEvents(
  request: APIRequestContext,
  signed: SignedPackage,
  events: Array<Record<string, unknown>>,
  idempotencyKey: string,
): Promise<APIResponse> {
  const targetUri = `${colandBaseUrl()}/_arkret/edge/applet/transactions`;
  const body = {
    applet_id: signed.applet_package.applet_id,
    source_id: signed.applet_package.service_id,
    events,
  };
  return request.post(targetUri, {
    headers: signedAppletTransactionHeaders({
      body,
      targetUri,
      sourceServiceId: signed.applet_package.service_id,
      keyId: appletProducerKeyRef(signed),
      destinationServiceId: colandServiceId(),
      idempotencyKey,
      signingKey: signed.service_signing_private_key,
    }),
    data: canonicalJson(body),
  });
}

async function deliverAppletEvents(
  request: APIRequestContext,
  signed: SignedPackage,
  events: Array<Record<string, unknown>>,
  idempotencyKey: string,
): Promise<{
  status: "accepted" | "partial" | "rejected";
  rejections?: Array<Record<string, unknown>>;
}> {
  const response = await rawDeliverAppletEvents(
    request,
    signed,
    events,
    idempotencyKey,
  );
  const responseText = await response.text();
  expect(response.status(), responseText).toBe(200);
  return JSON.parse(responseText);
}

/// A directed Invite is valid, but the Service cannot accept it in place of
/// the actual Bot/Ghost. subject_only requires that Account's original proof.
async function rejectServiceProxyInviteAcceptance(args: {
  request: APIRequestContext;
  token: string;
  signed: SignedPackage;
  realmId: string;
  actorId: ManagedActorId;
  authorizationRef: string;
  idempotencyKey: string;
}): Promise<Record<string, unknown>> {
  const adminId = await currentActorIdApi(args.request, args.token);
  const evidence = { kind: "explicit_address" } as const;
  const inviteEvent = signedEventEnvelope({
    actorId: adminId,
    realmId: args.realmId,
    kind: "ak.invite.create",
    payload: {
      invitee_account_id: args.actorId.account_id,
      introduction_evidence_digest: `sha256:${sha256CanonicalJson(evidence)}`,
      expires_at: canonicalTimestamp(
        new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      ),
    },
  });
  await submitSignedEventApi(args.request, args.token, inviteEvent, {
    context: "administrator invites the managed actor",
  });
  const before = await queryRealmEventsApi(args.request, args.token, args.realmId);
  const accept = serviceProxyManagedActorEvent({
    signed: args.signed,
    realmId: args.realmId,
    actorId: args.actorId,
    authorizationRef: args.authorizationRef,
    kind: "ak.invite.accept",
    payload: {
      invite_id: retypeEventDerivedId(String(inviteEvent.event_id), "invite"),
      previous_state: "pending",
      invitee_account_id: args.actorId.account_id,
    },
  });
  const outcome = await deliverAppletEvents(
    args.request,
    args.signed,
    [accept],
    args.idempotencyKey,
  );
  expect(outcome.status, JSON.stringify(outcome.rejections ?? [])).toBe(
    "rejected",
  );
  expect(await queryRealmEventsApi(args.request, args.token, args.realmId)).toEqual(before);
  return accept;
}

test.describe("applet bridge", () => {
  test("Service installation creates zero Bots and permits two independent Bot provisions", async ({request}) => {
    test.setTimeout(300_000);
    const stamp = typedId("operation").split(":").at(-1)!;
    const user = uniqueUser(`applet-multiple-bots-${stamp}`);
    await ensureRegistered(request, user);
    const token = await issueUserSession(request, user);
    const realmId = await createAppletInstallRealm(request,token,{title:`multiple Bots ${stamp}`, discoverability:"listed",history_access:"since_join"});
    const signed = await signPackage(request,requireMockAppletRegistry(),{package_id:`package:multiple-bots:${stamp}`,namespace:`multiple.bots.${stamp}`,capabilities:["ak.applet.bot.provision"]});
    const installed = await rawInstallApplet(request,token,signed,realmId,`service-only-${stamp}`,undefined,{exerciseAuthoringKats:false});
    expect(installed.response.status(),await installed.response.text()).toBe(201);
    const installation = await installed.response.json();
    for (const field of ["bot_actor_id","managed_actor_provision_ref","principal_control_realm_id","profile_event_ref","accountability_grant_ref"]) expect(installation).not.toHaveProperty(field);
    const beforeBots = await queryRealmEventsApi(request,token,realmId);
    expect((beforeBots.events as Array<Record<string,unknown>>).some(event=>event.kind==="ak.applet.managed_actor.provision")).toBe(false);
    const first = await provisionAppletBot(request,signed,realmId,`first-${stamp}`,{exerciseAuthoringKats:false});
    const key = generateWebvhKey();
    const versionTime = canonicalTimestamp();
    const secondIdentity = buildWebvhGenesisEntry({baseUrl:colandBaseUrl(),localId:`applet-bot-second-${stamp}`,rootKey:generateWebvhKey(),nextRootKey:generateWebvhKey(),versionTime,document:did=>({"@context":["https://www.w3.org/ns/did/v1"],id:did,verificationMethod:{[`${did}#bot-event-key`]:encodeEd25519PubkeyMultibase(key.publicKey)},updated:versionTime})});
    const second = await provisionAppletBot(request,signed,realmId,`second-${stamp}`,{exerciseAuthoringKats:false,botOperation:secondIdentity});
    expect(first.bot_actor_id).not.toEqual(second.bot_actor_id);
    for (const field of ["managed_actor_provision_ref","principal_control_realm_id","profile_event_ref","accountability_grant_ref"]) {
      expect(first[field]).toEqual(expect.any(String));
      expect(second[field]).toEqual(expect.any(String));
      expect(first[field]).not.toEqual(second[field]);
    }
  });

  test("applet installs and provisions Bot and Ghost; Service child grants cannot authorize Account impersonation", async ({
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
    const aliceToken = await issueUserSession(request, alice);

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
      const realmId = await createAppletInstallRealm(request, aliceToken, {
        title: `applet-bridge Demo Space ${stamp}`,
        discoverability: "listed",
        history_access: "since_join",
        ownerId: alice.id,
      });
      await publishAppletServiceIdDocument(request, signed);
      const preInstallMembership = signedEventEnvelope({
        actorId: alice.id,
        realmId,
        kind: "ak.member.state",
        appletId: signed.applet_package.applet_id,
        // `applet_id` requires `authorization_ref` on the wire
        // (event-envelope.schema.json allOf), so the Event cannot be authored
        // without one at all. Nothing has been installed yet, so this names a
        // grant that resolves to no active registration. The Service producer
        // guard rejects this human-authored Applet Event before installation.
        authorizationRef: typedId("grant"),
        payload: {
          realm_id: realmId,
          member_id: signed.bot_actor_id,
          membership: "join",
        },
      });
      const preInstallSubmit = await rawSubmitSignedEventApi(
        request,
        aliceToken,
        preInstallMembership,
      );
      expect(preInstallSubmit.status()).not.toBe(200);
      const preInstallBody = await preInstallSubmit.json();
      expect(wireErrCode(preInstallBody), JSON.stringify(preInstallBody)).toBe(
        "failed_precondition",
      );
      const registration = await installApplet(
        request,
        aliceToken,
        signed,
        realmId,
        `register-${stamp}`,
        { exerciseAuthoringKats: false },
      );
      expect(registration.status).toBe("installed");
      expect(registration.bot_actor_id).toEqual(signed.bot_actor_id);
      expect(registration.portal_realm_id).toBe(realmId);
      const messageGrantRef = capabilityGrantRefForAction(
        registration,
        "ak.message.create",
      );
      const provisionGrantRef = capabilityGrantRefForAction(
        registration,
        "ak.applet.ghost.provision",
      );
      // Installation alone authorizes no Bot membership write: an
      // Applet-carried Event must cite an active grant of the Bot itself, and
      // the registration Event is not one (applet-integration.md §8, §11).
      const registrationOnlyJoin = serviceProxyManagedActorEvent({
        signed,
        realmId,
        actorId: registration.bot_actor_id,
        authorizationRef: registration.registration_event_ref,
        kind: "ak.member.state",
        payload: {
          realm_id: realmId,
          member_id: registration.bot_actor_id,
          membership: "join",
        },
      });
      const registrationOnlyOutcome = await deliverAppletEvents(
        request,
        signed,
        [registrationOnlyJoin],
        `bot-registration-only-join-${stamp}`,
      );
      expect(registrationOnlyOutcome.status).toBe("rejected");

      // Real Service-signed terminal creation succeeds. It grants the Bot,
      // so it cannot authorize the Service accepting the Bot's Invite.
      const botGrantRef = await grantManagedActorActions(
        request,
        aliceToken,
        signed,
        realmId,
        registration.bot_actor_id,
        ["ak.message.create"],
      );
      const botAcceptance = await rejectServiceProxyInviteAcceptance({
        request,
        token: aliceToken,
        signed,
        realmId,
        actorId: registration.bot_actor_id,
        authorizationRef: botGrantRef,
        idempotencyKey: `bot-join-${stamp}`,
      });
      const membershipTimeline = await queryRealmEventsApi(
        request,
        aliceToken,
        realmId,
      );
      const membershipEvents = (membershipTimeline.events ?? []) as Array<
        Record<string, unknown>
      >;
      expect(
        membershipEvents.some(
          (event) =>
            event.event_id === registrationOnlyJoin.event_id,
        ),
      ).toBe(false);
      expect(
        membershipEvents.some(
          (event) =>
            event.kind === "ak.invite.accept" &&
            event.event_id === botAcceptance.event_id &&
            canonicalJson(event.actor_id) === canonicalJson(registration.bot_actor_id) &&
            canonicalJson(event.executed_by) ===
              canonicalJson(serviceActorId(signed.applet_package.service_id)),
        ),
      ).toBe(false);

      const externalUser = { id: "ext-user-X", display_name: "External X" };
      if (!signed.ghost_namespace_token) {
        throw new Error(
          "signed Applet package is missing its Ghost namespace token",
        );
      }
      const ghostBuilt = buildWebvhGenesisEntry({
        baseUrl: colandBaseUrl(),
        localId: `ghost-${signed.ghost_namespace_token}:${externalUser.id.toLowerCase()}`,
        rootKey: generateWebvhKey(),
        nextRootKey: generateWebvhKey(),
        versionTime: canonicalTimestamp(),
        document: (did) => ({
          "@context": ["https://www.w3.org/ns/did/v1"],
          id: did,
          updated: canonicalTimestamp(),
        }),
      });
      await submitPrincipalGenesisEntry(request, colandBaseUrl(), ghostBuilt);
      const ghostCreation = await buildGhostManagedActorCreation({
        request,
        token: aliceToken,
        signed,
        registration,
        realmId,
        ghostBuilt,
        externalUser,
        registrationRef: registration.registration_event_ref,
      });
      const standaloneGenesis = await rawSubmitSignedEventApi(
        request,
        aliceToken,
        ghostCreation.managed_actor_bundle.pcr_genesis_event,
      );
      const standaloneGenesisText = await standaloneGenesis.text();
      // Alice's session cannot submit another Actor's PCR founding Event.
      // This producer refusal precedes managed-aggregate admission. The
      // authenticated Applet aggregate below remains the provisioning path.
      // The producer preflight reports registered conflict before reducer/CAS admission.
      expect(standaloneGenesis.status(), standaloneGenesisText).toBe(409);
      expect(wireErrCode(JSON.parse(standaloneGenesisText))).toBe("conflict");
      expect(JSON.parse(standaloneGenesisText).detail).toContain("exact authenticated actor");
      const provision = await request.post(`${registryBase}/external-event`, {
        headers: authHeaders(aliceToken, "POST", `${registryBase}/external-event`),
        data: {
          coland_base_url: colandBaseUrl(),
          destination_id: colandServiceId(),
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
      const ghostActorId = accountActorId(projectDidToCoreId(ghostBuilt.did));
      expect(provisionBody.ghost_actor_id).toEqual(ghostActorId);
      // Provisioning implies no membership. A terminal child names the
      // Ghost itself; the Service cannot substitute for its original signer.
      const ghostMessageGrantRef = await grantManagedActorActions(
        request,
        aliceToken,
        signed,
        realmId,
        ghostActorId,
        ["ak.message.create"],
      );
      await rejectServiceProxyInviteAcceptance({
        request,
        token: aliceToken,
        signed,
        realmId,
        actorId: ghostActorId,
        authorizationRef: ghostMessageGrantRef,
        idempotencyKey: `ghost-join-${stamp}`,
      });
      const portalStrandId = await resolveDefaultStrandId(
        request,
        aliceToken,
        realmId,
      );

      const text = `hi from outside ${stamp}`;
      const external = await request.post(`${registryBase}/external-event`, {
        headers: authHeaders(aliceToken, "POST", `${registryBase}/external-event`),
        data: {
          coland_base_url: colandBaseUrl(),
          destination_id: colandServiceId(),
          applet_id: registration.applet_id,
          realm_id: realmId,
          strand_id: portalStrandId,
          authorization_ref: ghostMessageGrantRef,
          provision_authorization_ref: provisionGrantRef,
          external_user: externalUser,
          ghost_creation: ghostCreation,
          payload: { kind: "message", text },
        },
      });
      const externalText = await external.text();
      expect(external.status(), externalText).toBe(422);
      expect(JSON.parse(externalText).status).toBe("rejected");
      expect(JSON.parse(externalText)).not.toHaveProperty("committed_event_refs");
      const events = await queryRealmEventsApi(request, aliceToken, realmId);
      expect(JSON.stringify(events)).not.toContain(text);
      const acceptedEvents = Array.isArray(events.events)
        ? (events.events as Array<Record<string, unknown>>)
        : [];
      expect(acceptedEvents.some(event => event.kind === "ak.member.state" &&
        canonicalJson((event.payload as Record<string,unknown>).member_id) === canonicalJson(ghostActorId) &&
        (event.payload as Record<string,unknown>).membership === "join")).toBe(false);
      // The provisioning aggregate the Ghost was created from: the
      // accountability grant is portal-scoped private source material, while the
      // Profile is principal-scoped state in the Ghost's own
      // `applet_managed_control` PCR and is checked from the submitted unit.
      const ghostBundle = ghostCreation.managed_actor_bundle;
      const ghostProfile = ghostBundle.profile_event;
      expect(ghostProfile.actor_id).toEqual(ghostActorId);
      expect(ghostProfile.realm_id).toBe(provisionBody.principal_control_realm_id);
      expect(
        (ghostProfile.payload as Record<string, unknown> | undefined)?.object,
      ).toEqual(
        expect.objectContaining({
          principal_id: ghostActorId.account_id.principal_id,
          actor_kind: "integration",
          accountable_principal_ids: [signed.applet_package.service_id],
        }),
      );
      // federation.md §3.2 keeps private source Events withheld from members.
      // A covering Commit proves acceptance of the exact producer Event.
      expect((events.commits as Array<Record<string, unknown>>).find(
        (commit) => commit.event_ref === ghostBundle.accountability_grant_event.event_id,
      ), "accepted Ghost accountability grant Commit").toBeDefined();
      const disclosedAccountabilityGrant = acceptedEvents.find(
        (event) => event.event_id === ghostBundle.accountability_grant_event.event_id,
      );
      if (disclosedAccountabilityGrant) {
        expect(disclosedAccountabilityGrant).toEqual(ghostBundle.accountability_grant_event);
      }
      const accountabilityGrant = ghostBundle.accountability_grant_event;
      expect(
        accountabilityGrant,
        "accepted Ghost accountability grant",
      ).toEqual(
        expect.objectContaining({
          kind: "ak.identity.accountability_grant",
          actor_id: serviceActorId(signed.applet_package.service_id),
          authorization_ref: provisionGrantRef,
        }),
      );
      expect(accountabilityGrant?.payload).toEqual(
        expect.objectContaining({
          issuer_id: signed.applet_package.service_id,
          subject_id: ghostActorId.account_id.principal_id,
          grant_status: "active",
        }),
      );
      expect(ghostProfile.semantic_refs).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            id: accountabilityGrant?.event_id,
            role: "accountability",
            critical: true,
          }),
        ]),
      );
      // The provisioning outcome echoes the provisioning grant; it never
      // authorizes later Ghost writes (§9.1).
      expect(provisionBody.authorization_ref).toBe(provisionGrantRef);
      expect(ghostMessageGrantRef).not.toBe(provisionGrantRef);
      // Direct delivery must also reject this proxy before revocation. The
      // valid HTTP Service signature cannot replace the Account producer.
      const directText = `direct Service write after revoke ${stamp}`;
      const directWrite = serviceProxyManagedActorEvent({
        signed,
        realmId,
        actorId: ghostActorId,
        authorizationRef: ghostMessageGrantRef,
        kind: "ak.message.create",
        payload: {
          strand_id: portalStrandId,
          track_name: "discussion",
          content: { kind: "ak.content.text", body: directText },
        },
      });
      const directRejected = await deliverAppletEvents(request, signed, [directWrite], `ghost-direct-proxy-${stamp}`);
      expect(directRejected.status).toBe("rejected");
      expect(await queryRealmEventsApi(request, aliceToken, realmId)).toEqual(events);
      await alicePage.gotoTimelineRealm(realmId);
      await expect(alicePage.page.getByTestId("message-list")).toBeVisible({timeout:30_000});
      await expect(alicePage.page.getByTestId("message-list")).not.toContainText(text);

      const revoke = await revokeAppletRuntime(
        request,
        aliceToken,
        alice.id,
        registration.applet_id,
        realmId,
        `revoke-${stamp}`,
      );
      expect(revoke.status).toBe("complete");
      expect(revoke.revoked_refs).toEqual(
        expect.arrayContaining([registration.bot_actor_id.account_id.principal_id, ghostActorId.account_id.principal_id]),
      );

      const afterRevokeText = `after revoke ${stamp}`;
      const afterRevoke = await request.post(`${registryBase}/external-event`, {
        headers: authHeaders(aliceToken, "POST", `${registryBase}/external-event`),
        data: {
          coland_base_url: colandBaseUrl(),
          destination_id: colandServiceId(),
          applet_id: registration.applet_id,
          realm_id: realmId,
          strand_id: portalStrandId,
          authorization_ref: ghostMessageGrantRef,
          provision_authorization_ref: provisionGrantRef,
          external_user: externalUser,
          ghost_creation: ghostCreation,
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

      // The Service transports the same invalid proxy after revocation. With the exact
      // install revoked there is no active effective install to select, so the
      // delivery fails closed before any Event admission (applet-integration.md
      // §7.3.1 failure codes; §9.1 Ghost writes follow the install fence).
      const directAfterRevoke = await rawDeliverAppletEvents(
        request,
        signed,
        [directWrite],
        `ghost-direct-after-revoke-${stamp}`,
      );
      const directAfterRevokeText = await directAfterRevoke.text();
      expect(directAfterRevoke.status(), directAfterRevokeText).toBe(403);
      expect(wireErrCode(JSON.parse(directAfterRevokeText)), directAfterRevokeText)
        .toBe("applet_registration_unauthorized");
      expect(JSON.stringify(await queryRealmEventsApi(request, aliceToken, realmId)))
        .not.toContain(directText);
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
    const aliceToken = await issueUserSession(request, alice);
    const namespace = `bridge.conflict.${stamp}`;

    const realmId = await createAppletInstallRealm(request, aliceToken, {
      title: `applet conflict ${stamp}`,
      discoverability: "listed",
      history_access: "since_join",
    });

    const first = await signPackage(request, registryBase, {
      package_id: `package:bridge:conflict-a-${stamp}`,
      namespace,
    }, { dropResponseAfterPersistence: true });
    await installApplet(
      request,
      aliceToken,
      first,
      realmId,
      `conflict-first-${stamp}`,
      { exerciseAuthoringKats: false },
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
    const aliceToken = await issueUserSession(request, alice);
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
    await rejectServiceProxyInviteAcceptance({
      request,
      token: aliceToken,
      signed,
      realmId,
      actorId: registration.bot_actor_id,
      authorizationRef: await grantManagedActorActions(
        request,
        aliceToken,
        signed,
        realmId,
        registration.bot_actor_id,
        ["ak.message.create"],
      ),
      idempotencyKey: `revoke-bot-join-${stamp}`,
    });

    const revoke = await revokeAppletRuntime(
      request,
      aliceToken,
      alice.id,
      registration.applet_id,
      realmId,
      `revoke-bot-${stamp}`,
    );
    expect(revoke.status).toBe("complete");
    expect(revoke.revoked_refs).toEqual(
      expect.arrayContaining([registration.bot_actor_id.account_id.principal_id]),
    );

    const history = await queryRealmEventsApi(request, aliceToken, realmId);
    expect(JSON.stringify(history)).toContain("ak.applet.registration");
    expect(canonicalJson(history)).toContain(canonicalJson(registration.bot_actor_id));

    const removedLegacyRoute = await request.post(
      `${colandBaseUrl()}/_coland/edge/applets/${encodeURIComponent(registration.applet_id)}/bot/messages`,
      {
        headers: {
          ...authHeaders(aliceToken, "POST", `${colandBaseUrl()}/_coland/edge/applets/${encodeURIComponent(registration.applet_id)}/bot/messages`),
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
    const aliceToken = await issueUserSession(request, alice);
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
    const first = await firstResponse.json();
    expect(first).not.toHaveProperty("bot_actor_id");

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
    const second = await secondResponse.json();
    expect(second.applet_id).toBe(first.applet_id);
    expect(second).not.toHaveProperty("bot_actor_id");

    const { response: conflict } = await rawInstallApplet(
      request,
      aliceToken,
      signed,
      realmId,
      `idem-other-${stamp}`,
      firstResult.prepared,
    );
    // `(applet_id, effective_scope)` is the durable install key
    // (applet-integration.md §4b); reusing it under another Idempotency-Key is
    // the registry's `duplicate_conflict`. `applet_already_registered` is a
    // `reserved` row that no producer may emit (conformance/schema-registry.md).
    expect(conflict.status()).toBe(409);
    expect(wireErrCode(await conflict.json())).toBe("duplicate_conflict");
  });

  // COTEST-SEC-02: production-mode controller-signed package signature negative
  // tests. Spec: extensions/applet-integration.md §4.1 — `controller_principal_id` MUST
  // sign the registration; `proof` MUST be a controller DID detached proof
  // covering the canonical registration object (excluding `proof` itself), and
  // a package whose proof does not cover its body MUST be rejected. coland's
  // canonical install validator (validate_applet_package) recomputes
  // `package_digest` over the bare body and recomputes the proof
  // `payload_digest`; a package mutated after signing therefore fails closed at
  // the preview/commit gate. These run for real against coland in dev-mode —
  // no live deployment required — mirroring the runnable positive install case
  // above and the RFC 9421 inbound-signature negative cases below.

  test("E4.4 install evidence has one carrier in the caller-signed registration manifest", async ({
    request,
  }) => {
    const registryBase = requireMockAppletRegistry();
    const stamp = Date.now();
    const alice = uniqueUser(`applet-evidence-carrier-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueUserSession(request, alice);
    const realmId = await createAppletInstallRealm(request, aliceToken, {
      title: `applet evidence carrier ${stamp}`,
      discoverability: "listed",
      history_access: "since_join",
    });
    const signed = await signPackage(request, registryBase, {
      package_id: `package:bridge:evidence-carrier-${stamp}`,
      namespace: `bridge.evidence.carrier.${stamp}`,
    });
    const previewUrl = `${colandBaseUrl()}/_arkret/self/applets/install/preview`;
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
        ...authHeaders(aliceToken, "POST", previewUrl),
        "content-type": "application/json",
      },
      data: canonicalJson({
        applet_package: signed.applet_package,
        authoring_request_basis: missingBasis,
      }),
    });
    expect(missingEvidence.status()).toBe(422);
    expect(wireErrCode(await missingEvidence.json())).toBe("schema_violation");

    const duplicateSibling = await request.fetch(previewUrl, {
      method: "POST",
      headers: {
        ...authHeaders(aliceToken, "POST", previewUrl),
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
    expect(duplicateSibling.status()).toBe(422);
    expect(wireErrCode(await duplicateSibling.json())).toBe("schema_violation");

    const misplacedPackage = {
      ...signed.applet_package,
      // Negative-only package probe; no positive helper carries this sibling.
      registration_epoch_evidence: registrationEvidence, // stale-literal-allow
    };
    const misplaced = await request.fetch(previewUrl, {
      method: "POST",
      headers: {
        ...authHeaders(aliceToken, "POST", previewUrl),
        "content-type": "application/json",
      },
      data: canonicalJson({
        applet_package: misplacedPackage,
        authoring_request_basis: prepared.basis,
      }),
    });
    expect(misplaced.status()).toBe(422);
    expect(wireErrCode(await misplaced.json())).toBe("schema_violation");

    // The nested evidence is schema-bound through
    // `applet-install-authoring.schema.json#/$defs/registration_event` to
    // `applet-registration-epoch-evidence.schema.json`: a shape violation is
    // `schema_violation` (422). A schema-valid carrier that disagrees with the
    // resolved service DID state fails closed as the active `param_invalid`
    // (400); `applet_registration_epoch_evidence_mismatch` is only a reserved
    // registry code and is never emitted as the top-level `error.code`.
    const expectNestedEvidenceRejected = async (
      label: string,
      evidence: Record<string, unknown>,
      expected: { status: 400; code: "param_invalid" } | { status: 422; code: "schema_violation" },
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
          ...authHeaders(aliceToken, "POST", previewUrl),
          "content-type": "application/json",
        },
        data: canonicalJson({
          applet_package: signed.applet_package,
          authoring_request_basis: candidate.basis,
        }),
      });
      const deniedBody = await denied.json();
      expect(denied.status(), `${label}: ${JSON.stringify(deniedBody)}`).toBe(
        expected.status,
      );
      expect(wireErrCode(deniedBody), label).toBe(expected.code);
    };
    const schemaViolation = { status: 422, code: "schema_violation" } as const;
    const evidenceMismatch = { status: 400, code: "param_invalid" } as const;

    // `accepted_signing_keys` is `minItems: 1`.
    const emptyKeys = structuredClone(registrationEvidence);
    emptyKeys.accepted_signing_keys = [];
    await expectNestedEvidenceRejected(
      "empty accepted key set",
      emptyKeys,
      schemaViolation,
    );

    // Only `did:webvh` and `did:key` are admitted evidence methods.
    const currentSnapshotDid = structuredClone(registrationEvidence);
    currentSnapshotDid.did = "did:web:swapped-applet.example";
    await expectNestedEvidenceRejected(
      "did:web current snapshot",
      currentSnapshotDid,
      schemaViolation,
    );

    // A schema-valid did:webvh naming another service.
    const serviceDid = String(registrationEvidence.did);
    const swappedDid = serviceDid.replace(
      /^(did:webvh:[^:]+):.+$/,
      "$1:swapped-applet.example",
    );
    if (swappedDid === serviceDid) {
      throw new Error(`fixture service DID is not did:webvh: ${serviceDid}`);
    }
    const swappedService = structuredClone(registrationEvidence);
    swappedService.did = swappedDid;
    await expectNestedEvidenceRejected(
      "swapped service DID",
      swappedService,
      evidenceMismatch,
    );

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
      evidenceMismatch,
    );
  });

  test("E4.4a runtime service identity cannot substitute for controller_principal_id", async ({
    request,
  }) => {
    const registryBase = requireMockAppletRegistry();
    const stamp = Date.now();
    const alice = uniqueUser(`applet-service-as-controller-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueUserSession(request, alice);
    const realmId = await createAppletInstallRealm(request, aliceToken, {
      title: `applet service as controller ${stamp}`,
      discoverability: "listed",
      history_access: "since_join",
    });
    const signed = await signPackage(request, registryBase, {
      package_id: `package:bridge:service-as-controller-${stamp}`,
      namespace: `bridge.service.as.controller.${stamp}`,
    });
    const serviceAsController = tamperSignedPackage(signed, (pkg) => {
      pkg.controller_principal_id = pkg.service_id;
    });

    const { response: denied } = await rawInstallApplet(
      request,
      aliceToken,
      serviceAsController,
      realmId,
      `service-as-controller-${stamp}`,
    );
    expect(denied.status()).toBe(422);
    expect(wireErrCode(await denied.json())).toBe("schema_violation");
  });

  test("E4.5 tampered package body: post-signing mutation breaks package_digest and is rejected with schema_violation", async ({
    request,
  }) => {
    const registryBase = requireMockAppletRegistry();
    const stamp = Date.now();
    const alice = uniqueUser(`applet-tamper-body-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueUserSession(request, alice);
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
    // sequence than what is submitted. coland recomputes the digest over the
    // bare body and MUST reject the mismatch.
    // The distribution ID is covered by the package seal, but is not part of
    // registration epoch or grant approval. Keep those independent gates valid
    // so this mutation reaches the package-digest check.
    const tampered = tamperSignedPackage(signed, (pkg) => {
      pkg.package_id = `${String(pkg.package_id)}:tampered`;
    });
    expect(tampered.applet_package.package_digest).toBe(signed.applet_package.package_digest);
    expect(tampered.applet_package.proof).toEqual(signed.applet_package.proof);
    const historyBefore = await queryRealmEventsApi(request, aliceToken, realmId);

    const { response: denied } = await rawInstallApplet(
      request,
      aliceToken,
      tampered,
      realmId,
      `tamper-body-${stamp}`,
    );
    expect(denied.status()).toBe(422);
    expect(wireErrCode(await denied.json())).toBe("schema_violation");
    expect(await queryRealmEventsApi(request, aliceToken, realmId)).toEqual(historyBefore);
  });

  test("E4.6 tampered proof: proof that no longer covers the package body is rejected with proof_invalid", async ({
    request,
  }) => {
    const registryBase = requireMockAppletRegistry();
    const stamp = Date.now();
    const alice = uniqueUser(`applet-tamper-proof-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueUserSession(request, alice);
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
    // registration object. §4.1: the proof MUST cover the body; coland
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
    expect(denied.status()).toBe(400);
    // `proof_invalid` is a registered reason code, not a top-level one.
    const deniedBody = (await denied.json()) as { reason_code?: unknown };
    expect(wireErrCode(deniedBody)).toBe("param_invalid");
    expect(deniedBody.reason_code).toBe("proof_invalid");
  });

  test("E4.7 an exact successful install replay remains byte-stable", async ({
    request,
  }) => {
    test.setTimeout(120_000);
    const registryBase = requireMockAppletRegistry();
    const stamp = Date.now();
    const alice = uniqueUser(`applet-commit-expiry-${stamp}`);
    await ensureRegistered(request, alice);
    const token = await issueUserSession(request, alice);
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
    actorId?: ActorId;
    appletId?: string;
    authorizationRef?: string;
    verificationMethod?: string;
    signingKey?: KeyObject;
  }) {
    const sourceServiceId = args.sourceServiceId ?? colandServiceId();
    const realmId = args.realmId ?? typedId("realm");
    const actorId = args.actorId ?? serviceActorId(sourceServiceId);
    const verificationMethod =
      args.verificationMethod ??
      `${colandServiceDid()}#applet-service-key`;
    const appletId = args.appletId ?? typedAppletId();
    const unidentified = {
      kind: "ak.applet.bridge_error",
      realm_id: realmId,
      scope_ref: {kind: "realm", realm_id: realmId},
      actor_id: actorId,
      created_at: canonicalEventTimestamp(),
      payload: {
        applet_id: appletId,
        realm_id: realmId,
        failed_transaction_ref: typedId("event"),
        error_class: "external_network",
        error_code: "external_unavailable",
        retriable: true,
        visibility_scope: "realm_members",
      },
      authorization_ref: args.authorizationRef ?? typedId("grant"),
      applet_id: appletId,
    };
    // The Service Event's id is derived from the Event, so the envelope is
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
          producer_proof: appletEventProof(
            verificationMethod,
            event,
            args.signingKey,
          ),
        },
      ],
    };
  }

  // RFC 9457 Problem `type` is the sole machine discriminator.  The operation
  // registry deliberately forbids a second generic `reason`/`reason_code`
  // discriminator for these signature failures.
  function signatureReason(body: unknown): string | undefined {
    return wireErrCode(body);
  }

  async function setupBearer(request: APIRequestContext): Promise<string> {
    const stamp = Date.now();
    const alice = uniqueUser(`applet-inbound-${stamp}`);
    await ensureRegistered(request, alice);
    return issueUserSession(request, alice);
  }

  test("valid applet service signature inbound transaction push → 200 accepted", async ({
    request,
  }) => {
    test.setTimeout(300_000);
    const registryBase = requireMockAppletRegistry();
    const stamp = Date.now();
    const alice = uniqueUser(`applet-inbound-ok-${stamp}`);
    await test.step("inbound preparation: ensureRegistered", () => ensureRegistered(request, alice), { box: true });
    const token = await test.step("inbound preparation: token", () => issueUserSession(request, alice), { box: true });
    const realmId = await test.step("inbound preparation: realmId", () => createAppletInstallRealm(request, token, {
      title: `applet inbound signed ${stamp}`,
      discoverability: "listed",
      history_access: "since_join",
    }), { box: true });
    const signed = await test.step("inbound preparation: signed", () => signPackage(request, registryBase, {
      package_id: `package:bridge:inbound-${stamp}`,
      namespace: `bridge.inbound.${stamp}`,
      capabilities: ["ak.message.create", "ak.applet.bridge_error"],
      webhook_auth: {
        kind: "http_message_signature",
        accepted_signature_algorithms: ["ed25519"],
      },
    }), { box: true });
    const sourceServiceId = signed.applet_package.service_id;
    const registration = await test.step("inbound preparation: registration", () => installApplet(
      request,
      token,
      signed,
      realmId,
      `inbound-install-${stamp}`,
    ), { box: true });
    const botGrantRef = await test.step("inbound preparation: botGrantRef", () => grantManagedActorActions(
      request,
      token,
      signed,
      realmId,
      registration.bot_actor_id,
      ["ak.message.create"],
    ), { box: true });
    const idempotencyKey = `inbound-ok-${stamp}`;
    const body = transactionPushBody({
      stamp,
      sourceServiceId,
      realmId,
      actorId: serviceActorId(sourceServiceId),
      appletId: registration.applet_id,
      authorizationRef: capabilityGrantRefForAction(registration, "ak.applet.bridge_error"),
      verificationMethod: String(
        (signed.applet_package.webhook_auth as Record<string, unknown>).key_ref,
      ),
      signingKey: signed.service_signing_private_key,
    });
    const targetUri = `${colandBaseUrl()}${TRANSACTIONS_PATH}`;
    const deliveryCreated = Math.floor(Date.now() / 1000);
    const resp = await test.step("inbound preparation: resp", () => request.post(targetUri, {
      headers: {
        ...signedAppletTransactionHeaders({
          body,
          targetUri,
          sourceServiceId,
          keyId: String(
            (signed.applet_package.webhook_auth as Record<string, unknown>)
              .key_ref,
          ),
          destinationServiceId: colandServiceId(),
          idempotencyKey,
          created: deliveryCreated,
          signingKey: signed.service_signing_private_key,
        }),
      },
      data: canonicalJson(body),
    }), { box: true });
    const responseText = await test.step("inbound preparation: responseText", () => resp.text(), { box: true });
    expect(resp.status(), responseText).toBe(200);
    const outcome = JSON.parse(responseText) as {
      status: "accepted" | "partial" | "rejected";
      rejections?: unknown[];
      committed_event_refs?: Array<Record<string, unknown>>;
    };
    expect(outcome.status, JSON.stringify(outcome.rejections ?? [])).toBe("accepted");
    expect(outcome.rejections ?? []).toEqual([]);
    // applet-integration.md §11.1 / applet_transaction_outcome: an accepted
    // Applet→Station submission names the exact Commit of every admitted Event.
    expect(outcome.committed_event_refs?.map((ref) => ref.event_id)).toEqual([
      body.events[0].event_id,
    ]);
    const timeline = await test.step("inbound preparation: timeline", () => queryRealmEventsApi(request, token, realmId), { box: true });
    const accepted = (timeline.events as Array<Record<string, unknown>>).find(
      (event) => event.event_id === body.events[0].event_id,
    );
    expect(accepted, "producer-only inbound is persisted as an accepted Event").toBeDefined();
    expect(accepted?.actor_id).toEqual(serviceActorId(sourceServiceId));
    expect(accepted?.executed_by).toBeUndefined();
    // The unique original producer proof is preserved byte-for-byte; no
    // Station signature joins the Event proof model.
    const producerProof = accepted?.producer_proof as Record<string, unknown>;
    expect(producerProof).toEqual(body.events[0].producer_proof);
    expect(producerProof.kind).toBe("detached_jws");
    expect(producerProof).not.toHaveProperty("signer_resolution_evidence_ref");
    expect(accepted).not.toHaveProperty("proofs");

    const deliver = async (payload: Record<string, unknown>, key: string) => request.post(targetUri, {
      headers: signedAppletTransactionHeaders({
        body: payload, targetUri, sourceServiceId,
        keyId: String((signed.applet_package.webhook_auth as Record<string, unknown>).key_ref),
        destinationServiceId: colandServiceId(), idempotencyKey: key,
        created: key === idempotencyKey ? deliveryCreated : undefined,
        signingKey: signed.service_signing_private_key,
      }),
      data: canonicalJson(payload),
    });
    const retry = await test.step("inbound preparation: retry", () => deliver(body, `inbound-event-retry-${stamp}`), { box: true });
    expect(retry.status(), await retry.text()).toBe(200);
    expect((await retry.json()).status).toBe("accepted");
    const transactionRetry = await test.step("inbound preparation: transactionRetry", () => deliver(body, idempotencyKey), { box: true });
    expect(transactionRetry.status(), await transactionRetry.text()).toBe(200);
    expect(await transactionRetry.json()).toEqual(JSON.parse(responseText));
    // Only an exact retry preserves the verified producer proof. The same
    // Event under a producer proof that does not verify is rejected per Event
    // (§7.3 per-event dedup; §7.3.1 independent producer_proof check).
    const { producer_proof: originalProducer, ...previousUnsigned } = body.events[0];
    for (const [label, submittedProof] of [
      [
        "foreign-key-producer",
        appletEventProof(
          String(originalProducer.verification_method),
          previousUnsigned,
          generateWebvhKey().privateKey,
        ),
      ],
      [
        "replaced-producer",
        { ...originalProducer, jws: `${String(originalProducer.jws).slice(0, -8)}AAAAAAAA` },
      ],
    ] as const) {
      const forbidden = { ...body, events: [{ ...previousUnsigned, producer_proof: submittedProof }] };
      const rejected = await deliver(forbidden, `inbound-forbidden-${label}-${stamp}`);
      const rejectedText = await rejected.text();
      expect(rejected.status(), rejectedText).toBe(200);
      const rejectedOutcome = JSON.parse(rejectedText);
      expect(rejectedOutcome.status, `${label}: ${rejectedText}`).toBe("rejected");
      expect(rejectedOutcome).not.toHaveProperty("committed_event_refs");
    }
    // The retired `proofs[]` carrier is not an Event Envelope member
    // (event-envelope.schema.json is closed and requires producer_proof).
    const legacyCarrier = {
      ...body,
      events: [{ ...previousUnsigned, proofs: [originalProducer] }],
    };
    const legacy = await test.step("inbound preparation: legacy", () => deliver(legacyCarrier, `inbound-legacy-proofs-${stamp}`), { box: true });
    const legacyText = await test.step("inbound preparation: legacyText", () => legacy.text(), { box: true });
    expect(legacy.status(), legacyText).toBe(422);
    expect(wireErrCode(JSON.parse(legacyText))).toBe("schema_violation");
    const after = await test.step("inbound preparation: after", () => queryRealmEventsApi(request, token, realmId), { box: true });
    const retained = (after.events as Array<Record<string, unknown>>).filter((event) => event.event_id === body.events[0].event_id);
    expect(retained).toHaveLength(1);
    expect(retained[0].producer_proof).toEqual(originalProducer);

    // A Service-actor self-signed write (§8): no delegation, so no
    // executed_by. Its explicit grant must name the Service subject pair
    // `(service_id, target_station_id)` (§4b), and is signed with the same
    // registration producer key.
    const serviceDraft = {
      kind: "ak.applet.bridge_error",
      realm_id: realmId,
      scope_ref: { kind: "realm", realm_id: realmId },
      actor_id: serviceActorId(sourceServiceId),
      applet_id: registration.applet_id,
      authorization_ref: capabilityGrantRefForAction(registration, "ak.applet.bridge_error"),
      created_at: canonicalEventTimestamp(),
      payload: {
        applet_id: registration.applet_id,
        realm_id: realmId,
        failed_transaction_ref: body.events[0].event_id,
        error_class: "external_network",
        error_code: "external_unavailable",
        retriable: true,
        visibility_scope: "realm_members",
      },
    };
    for (const [label, forbiddenDraft] of [
      ["borrowed-bot-grant", { ...serviceDraft, authorization_ref: botGrantRef }],
      ["account-masquerade", { ...serviceDraft, actor_id: accountActorId(sourceServiceId) }],
    ] as const) {
      const unsigned = { ...forbiddenDraft, event_id: sdkEventDerivedIds(forbiddenDraft).event_id };
      const forbiddenEvent = {
        ...unsigned,
        producer_proof: appletEventProof(String(originalProducer.verification_method), unsigned, signed.service_signing_private_key),
      };
      const rejected = await deliver({ ...body, events: [forbiddenEvent] }, `inbound-service-${label}-${stamp}`);
      const text = await rejected.text();
      expect(rejected.status(), text).toBe(200);
      expect(JSON.parse(text).status, text).toBe("rejected");
      expect(JSON.parse(text)).not.toHaveProperty("committed_event_refs");
      const history = await queryRealmEventsApi(request, token, realmId);
      expect((history.events as Array<Record<string, unknown>>).some((event) => event.event_id === forbiddenEvent.event_id)).toBe(false);
    }
    const authorizedServiceUnsigned = {
      ...serviceDraft,
      event_id: sdkEventDerivedIds(serviceDraft).event_id,
    };
    const serviceEvent = {
      ...authorizedServiceUnsigned,
      producer_proof: appletEventProof(
        String(originalProducer.verification_method),
        authorizedServiceUnsigned,
        signed.service_signing_private_key,
      ),
    };
    const serviceResponse = await test.step("inbound preparation: serviceResponse", () => deliver({ ...body, events: [serviceEvent] }, `inbound-service-self-${stamp}`), { box: true });
    const serviceResponseText = await test.step("inbound preparation: serviceResponseText", () => serviceResponse.text(), { box: true });
    expect(serviceResponse.status(), serviceResponseText).toBe(200);
    expect(JSON.parse(serviceResponseText).status, serviceResponseText).toBe("accepted");
    const serviceHistory = await test.step("inbound preparation: serviceHistory", () => queryRealmEventsApi(request, token, realmId), { box: true });
    const acceptedService = (serviceHistory.events as Array<Record<string, unknown>>).find((event) => event.event_id === serviceEvent.event_id);
    expect(acceptedService?.actor_id).toEqual(serviceActorId(sourceServiceId));
    expect(acceptedService?.executed_by).toBeUndefined();
    expect(acceptedService?.producer_proof).toEqual(serviceEvent.producer_proof);

    const nextUnidentified = {
      ...previousUnsigned,
      created_at: canonicalEventTimestamp(),
      payload: { ...previousUnsigned.payload, error_code: `race_${stamp}` },
    };
    const nextUnsigned = {
      ...nextUnidentified,
      event_id: sdkEventDerivedIds(nextUnidentified).event_id,
    };
    const next = {
      ...nextUnsigned,
      producer_proof: appletEventProof(
        String(originalProducer.verification_method),
        nextUnsigned,
        signed.service_signing_private_key,
      ),
    };
    let racingDelivery: ReturnType<typeof deliver> | undefined;
    const revoked = await test.step("inbound preparation: revoked", () => revokeAppletRuntime(request, token, alice.id, registration.applet_id, realmId, `inbound-revoke-${stamp}`, () => {
      racingDelivery = deliver({ ...body, events: [next] }, `inbound-revoke-race-${stamp}`);
      return racingDelivery;
    }), { box: true });
    expect(revoked.status).toBe("complete");
    expect(racingDelivery).toBeDefined();
    const raceResponse = await test.step("inbound preparation: raceResponse", () => racingDelivery!, { box: true });
    const raceText = await test.step("inbound preparation: raceText", () => raceResponse.text(), { box: true });
    const raceOutcome = JSON.parse(raceText);
    const racedHistory = await test.step("inbound preparation: racedHistory", () => queryRealmEventsApi(request, token, realmId), { box: true });
    const racedEvents = racedHistory.events as Array<Record<string, unknown>>;
    const racedEvent = racedEvents.find((event) => event.event_id === next.event_id);
    if (raceResponse.status() === 200 && raceOutcome.status === "accepted") {
      expect(racedEvent).toBeDefined();
      expect(racedEvents.filter((event) => event.event_id === next.event_id)).toHaveLength(1);
      expect(racedEvent!.producer_proof).toEqual(next.producer_proof);
    } else {
      // Lost the race: either the per-Event admission saw the fence, or the
      // delivery found no active effective install (§7.3.1).
      if (raceResponse.status() !== 200) {
        expect(raceResponse.status(), raceText).toBe(403);
        expect(wireErrCode(raceOutcome), raceText).toBe("applet_registration_unauthorized");
      }
      expect(racedEvent).toBeUndefined();
    }
    const fencedUnidentified = {
      ...previousUnsigned,
      created_at: canonicalEventTimestamp(),
      payload: { ...previousUnsigned.payload, error_code: `fenced_${stamp}` },
    };
    const fencedUnsigned = {
      ...fencedUnidentified,
      event_id: sdkEventDerivedIds(fencedUnidentified).event_id,
    };
    const fenced = {
      ...fencedUnsigned,
      producer_proof: appletEventProof(
        String(originalProducer.verification_method),
        fencedUnsigned,
        signed.service_signing_private_key,
      ),
    };
    // After the revoke commits there is no active effective install: the
    // inbound delivery fails closed before Event admission (§7.3.1).
    const afterRevoke = await test.step("inbound preparation: afterRevoke", () => deliver({ ...body, events: [fenced] }, `inbound-after-revoke-${stamp}`), { box: true });
    const afterRevokeText = await test.step("inbound preparation: afterRevokeText", () => afterRevoke.text(), { box: true });
    expect(afterRevoke.status(), afterRevokeText).toBe(403);
    expect(wireErrCode(JSON.parse(afterRevokeText)), afterRevokeText).toBe(
      "applet_registration_unauthorized",
    );
    const fencedServiceDraft = { ...serviceDraft, created_at: canonicalEventTimestamp() };
    const fencedServiceUnsigned = { ...fencedServiceDraft, event_id: sdkEventDerivedIds(fencedServiceDraft).event_id };
    const fencedService = {
      ...fencedServiceUnsigned,
      producer_proof: appletEventProof(String(originalProducer.verification_method), fencedServiceUnsigned, signed.service_signing_private_key),
    };
    const serviceAfterRevoke = await test.step("inbound preparation: serviceAfterRevoke", () => deliver({ ...body, events: [fencedService] }, `inbound-service-after-revoke-${stamp}`), { box: true });
    const serviceAfterRevokeText = await test.step("inbound preparation: serviceAfterRevokeText", () => serviceAfterRevoke.text(), { box: true });
    expect(serviceAfterRevoke.status(), serviceAfterRevokeText).toBe(403);
    expect(wireErrCode(JSON.parse(serviceAfterRevokeText)), serviceAfterRevokeText).toBe("applet_registration_unauthorized");
    const historical = await test.step("inbound preparation: historical", () => queryRealmEventsApi(request, token, realmId), { box: true });
    const historicalEvents = historical.events as Array<Record<string, unknown>>;
    expect(historicalEvents.find((event) => event.event_id === previousUnsigned.event_id)?.producer_proof).toEqual(originalProducer);
    expect(historicalEvents.some((event) => event.event_id === fenced.event_id)).toBe(false);
    expect(historicalEvents.some((event) => event.event_id === fencedService.event_id)).toBe(false);
  });

  test("missing Signature (bearer-only) inbound transaction push → 401 http_signature_required", async ({
    request,
  }) => {
    const token = await setupBearer(request);
    const stamp = Date.now();
    // Keep the otherwise complete delivery headers, but omit both RFC 9421
    // signature headers. Session authorization alone MUST NOT authenticate the
    // source service. §7.3.1: reject.
    const transactionUrl = `${colandBaseUrl()}${TRANSACTIONS_PATH}`;
    const body = transactionPushBody({ stamp });
    const unsignedDeliveryHeaders = signedAppletTransactionHeaders({
      body,
      targetUri: transactionUrl,
      sourceServiceId: colandServiceId(),
      keyId: `${colandServiceDid()}#applet-service-key`,
      destinationServiceId: colandServiceId(),
      idempotencyKey: `inbound-nosig-${stamp}`,
    });
    delete unsignedDeliveryHeaders.signature;
    delete unsignedDeliveryHeaders["signature-input"];
    const resp = await request.post(transactionUrl, {
      headers: {
        ...authHeaders(token, "POST", transactionUrl),
        ...unsignedDeliveryHeaders,
      },
      data: canonicalJson(body),
    });
    const responseText = await resp.text();
    expect(resp.status(), responseText).toBe(401);
    expect(signatureReason(JSON.parse(responseText))).toBe(
      "http_signature_required",
    );
  });

  test("invalid/forged Signature inbound transaction push → 401 http_signature_invalid", async ({
    request,
  }) => {
    test.setTimeout(300_000);
    const registryBase = requireMockAppletRegistry();
    const stamp = Date.now();
    const alice = uniqueUser(`applet-inbound-forged-${stamp}`);
    await ensureRegistered(request, alice);
    const token = await issueUserSession(request, alice);
    const realmId = await createAppletInstallRealm(request, token, {
      title: `applet inbound forged signature ${stamp}`,
      discoverability: "listed",
      history_access: "since_join",
    });
    const signed = await signPackage(request, registryBase, {
      package_id: `package:bridge:inbound-forged-${stamp}`,
      namespace: `bridge.inbound.forged.${stamp}`,
      capabilities: ["ak.message.create"],
      webhook_auth: {
        kind: "http_message_signature",
        accepted_signature_algorithms: ["ed25519"],
      },
    });
    const registration = await installApplet(
      request,
      token,
      signed,
      realmId,
      `inbound-forged-install-${stamp}`,
      { exerciseAuthoringKats: false },
    );
    const sourceServiceId = signed.applet_package.service_id;
    const verificationMethod = String(
      (signed.applet_package.webhook_auth as Record<string, unknown>).key_ref,
    );

    // Establish the exact active install and current webhook key first. The
    // request is otherwise signed correctly with that key; only Signature bytes
    // are then replaced, so a 401 proves the RFC 9421 verification gate rather
    // than the no-install 403 gate from §7.3.1.
    const transactionUrl = `${colandBaseUrl()}${TRANSACTIONS_PATH}`;
    const body = transactionPushBody({
      stamp,
      sourceServiceId,
      realmId,
      appletId: registration.applet_id,
      verificationMethod,
      signingKey: signed.service_signing_private_key,
    });
    const forgedHeaders = signedAppletTransactionHeaders({
      body,
      targetUri: transactionUrl,
      sourceServiceId,
      keyId: verificationMethod,
      destinationServiceId: colandServiceId(),
      idempotencyKey: `inbound-badsig-${stamp}`,
      signingKey: signed.service_signing_private_key,
    });
    // Keep the canonical body digest, covered components, key id and freshness
    // window valid so this case changes only the signature bytes.
    forgedHeaders.signature =
      "sig1=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==:";
    const resp = await request.post(transactionUrl, {
      headers: {
        ...authHeaders(token, "POST", transactionUrl),
        ...forgedHeaders,
      },
      data: canonicalJson(body),
    });
    expect(resp.status()).toBe(401);
    expect(signatureReason(await resp.json())).toBe("http_signature_invalid");
  });

  test("expired signature window inbound transaction push → 401 signature_window_invalid", async ({
    request,
  }) => {
    const token = await setupBearer(request);
    const stamp = Date.now();
    const sourceServiceId = colandServiceId();
    const idempotencyKey = `inbound-expired-${stamp}`;
    const body = transactionPushBody({ stamp, sourceServiceId });
    const targetUri = `${colandBaseUrl()}${TRANSACTIONS_PATH}`;
    // created/expires far in the past → outside the §7.3.1 freshness window
    // (expires-created ≤ 300s, created within ±30s skew, expires not past). Even
    // a byte-identical replay after replay-cache eviction MUST be rejected on the
    // created/expires check alone.
    const expired = await request.post(targetUri, {
      headers: {
        ...authHeaders(token, "POST", targetUri),
        ...signedAppletTransactionHeaders({
          body,
          targetUri,
          sourceServiceId,
          keyId: `${colandServiceDid()}#applet-service-key`,
          destinationServiceId: colandServiceId(),
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
    .update("coland:applet-service-key:")
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
  options: { dropResponseAfterPersistence?: boolean } = {},
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
    baseUrl: colandBaseUrl(),
    localId: `applet-${typedId("operation").split(":").at(-1)}`,
    rootKey: generateWebvhKey(),
    nextRootKey: generateWebvhKey(),
    versionTime,
    document: (did) => ({
      "@context": ["https://www.w3.org/ns/did/v1"],
      id: did,
      verificationMethod: {
        [`${did}#applet-service-key`]: encodeEd25519PubkeyMultibase(serviceSigningKey.publicKey),
      },
      assertionMethod: [`${did}#applet-service-key`],
      updated: versionTime,
    }),
  });
  const botPublicJwk = {
    crv: "Ed25519",
    kty: "OKP",
    x: botSigningKey.publicKey.toString("base64url"),
  };
  const botBuilt = buildWebvhGenesisEntry({
    baseUrl: colandBaseUrl(),
    localId: `applet-bot-${typedId("operation").split(":").at(-1)}`,
    rootKey: generateWebvhKey(),
    nextRootKey: generateWebvhKey(),
    versionTime,
    document: (did) => ({
      "@context": ["https://www.w3.org/ns/did/v1"],
      id: did,
      verificationMethod: {
        [`${did}#bot-event-key`]: encodeEd25519PubkeyMultibase(botSigningKey.publicKey),
      },
      assertionMethod: [`${did}#bot-event-key`],
      updated: versionTime,
    }),
  });
  const requestedWebhookAuth =
    data.webhook_auth && typeof data.webhook_auth === "object"
      ? (data.webhook_auth as Record<string, unknown>)
      : {};
  const requestOptions = {
    // Only this durable, keyed fixture operation can safely retry a reset.
    headers: {
      "Idempotency-Key": typedId("operation"),
      ...(options.dropResponseAfterPersistence
        ? { "x-cotest-drop-sign-package-response": "1" }
        : {}),
    },
    maxRetries: 1,
    data: {
      ...data,
      requested_scopes: [...new Set([...(data.requested_scopes as string[] ?? data.requested_capabilities as string[] ?? data.capabilities as string[] ?? ["ak.message.create", "ak.applet.ghost.provision"]), "ak.applet.bot.provision"])],
      actor_namespace_pattern:
        data.actor_namespace_pattern ??
        `did:webvh:*:${built.did.split(":")[3]}:webvh:ghost-${ghostNamespaceToken}:*`,
      bot_actor_id: accountActorId(projectDidToCoreId(botBuilt.did)),
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
  };
  let response = await request.post(`${registryBase}/sign-package`, requestOptions);
  // The HTTPS proxy converts this deliberate upstream response loss to 502.
  // Replay the same durable request, including its identity and idempotency key.
  if (options.dropResponseAfterPersistence && response.status() === 502) {
    response = await request.post(`${registryBase}/sign-package`, requestOptions);
  }
  expect(response.status()).toBe(200);
  return {
    ...((await response.json()) as SignedPackage),
    bot_actor_id: accountActorId(projectDidToCoreId(botBuilt.did)),
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
  options: {
    commitDelayMs?: number;
    exerciseAuthoringKats?: boolean;
  } = {},
): Promise<AppletRegistration> {
  const result = await rawInstallApplet(
    request,
    token,
    signed,
    realmId,
    idempotencyKey,
    undefined,
    options,
  );
  const response = result.response;
  const responseText = await response.text();
  expect(response.status(), responseText).toBe(201);
  const installed = JSON.parse(responseText) as AppletInstallOutcome;
  expect(installed).not.toHaveProperty("bot_actor_id");
  const bot = await provisionAppletBot(request,signed,realmId,idempotencyKey,options);
  return installRegistrationFromResponse(
    signed,
    realmId,
    installed,
    bot as AppletBotProvisionOutcome,
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
    const effectiveScope = { kind: "realm" as const, realm_id: realmId };
    const authoring = await prepareAppletInstallAuthoringBasis(
      request,
      token,
      signed,
      realmId,
      effectiveScope,
    );
    const previewUrl = `${colandBaseUrl()}/_arkret/self/applets/install/preview`;
    const preview = await request.fetch(previewUrl, {
      method: "POST",
      headers: {
        ...authHeaders(token, "POST", previewUrl),
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
    expect(previewOutcome).not.toHaveProperty("authoring_request");
    const plan = previewOutcome.plan as Record<string, unknown>;
    if (!plan || typeof plan.plan_digest !== "string") throw new Error("Service install preview omitted plan digest");
    resolved = {
      commitBody: {
        applet_package: signed.applet_package,
        authoring_request_basis: authoring.basis,
        plan_digest: plan.plan_digest,
      },
      grantActionsById: authoring.grantActionsById,
    };
    expect(Object.keys(resolved.commitBody).sort()).toEqual([
      "applet_package",
      "authoring_request_basis",
      "plan_digest",
    ]);
  }
  const installUrl = `${colandBaseUrl()}/_arkret/self/applets/install`;
  if (options.exerciseAuthoringKats !== false) {
    const obsolete = { ...structuredClone(resolved.commitBody), managed_actor_bundle: {} };
    const rejected = await request.fetch(installUrl, { method: "POST", headers: {...authHeaders(token,"POST",installUrl),"content-type":"application/json","Idempotency-Key":`${idempotencyKey}-obsolete-bundle`},data:canonicalJson(obsolete)});
    expect(rejected.status()).toBe(422);
    expect(wireErrCode(await rejected.json())).toBe("schema_violation");
  }
  if (options.commitDelayMs) {
    await new Promise((resolve) => setTimeout(resolve, options.commitDelayMs));
  }
  const response = await request.fetch(installUrl, {
    method: "POST",
    headers: {
      ...authHeaders(token, "POST", installUrl),
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

async function provisionAppletBot(request: APIRequestContext,signed: SignedPackage,realmId:string,idempotencyKey:string,options:{exerciseAuthoringKats?:boolean; botOperation?: BuiltWebvhGenesis}): Promise<Record<string,unknown>> {
    const previewUrl=`${colandBaseUrl()}/_arkret/self/applets/${encodeURIComponent(signed.applet_package.applet_id)}/bots/provision/preview`;
    const previewBody={effective_scope:{kind:"realm",realm_id:realmId},request_id:`${idempotencyKey}-bot`,display_name:"Applet Bot"};
    const serviceHeaders=(body:Record<string,unknown>,targetUri:string,key:string)=>signedAppletTransactionHeaders({body,targetUri,sourceServiceId:signed.applet_package.service_id,destinationServiceId:colandServiceId(),idempotencyKey:key,keyId:appletProducerKeyRef(signed),signingKey:signed.service_signing_private_key});
    const preview=await request.post(previewUrl,{headers:serviceHeaders(previewBody,previewUrl,`${idempotencyKey}-bot-preview`),data:canonicalJson(previewBody)});
    expect(preview.status(),await preview.text()).toBe(200);
    const previewOutcome=await preview.json() as Record<string,unknown>;
    const authoringRequest = previewOutcome.authoring_request;
    if (!authoringRequest || typeof authoringRequest !== "object") {
      throw new Error(
        "Bot provision preview is missing its signed authoring request",
      );
    }
    const authorBaseUrl = String(signed.applet_package.base_url ?? "").replace(
      /\/$/,
      "",
    );
    const botOperation = options.botOperation ?? signed.bot_actor_operation;
    if (!botOperation) throw new Error("Independent Bot provision requires its own identity material");
    await submitPrincipalGenesisEntry(request, colandBaseUrl(), botOperation);
    const evidence = webvhManagedActorEvidence(botOperation);
    const material = await request.post(`${authorBaseUrl}/inspect/bot-authoring-material`, {
      data: {applet_id:signed.applet_package.applet_id, effective_scope:previewBody.effective_scope, request_id:previewBody.request_id, material:{actor_id:accountActorId(projectDidToCoreId(botOperation.did)), initial_resolution:evidence.initialResolution, method_history_evidence:evidence.methodHistoryEvidence}},
    });
    expect(material.status(), await material.text()).toBe(200);
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
      const staleTrustBody = await staleButCryptographicallyValid.json();
      expect(staleButCryptographicallyValid.status(), JSON.stringify(staleTrustBody)).toBeGreaterThanOrEqual(400);
      expect(staleTrustBody.error, JSON.stringify(staleTrustBody)).toBe(
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
      nestedUnknownBasis.legacy = true;
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
        `Bot provision authoring returned ${authored.status()}: ${authoredText}`,
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
        "Bot provision author endpoint omitted managed_actor_bundle",
      );
    }

    const body={authoring_request:authoringRequest,managed_actor_bundle:managedActorBundle};
    const provisionUrl=previewUrl.replace(/\/preview$/,"");
    if(options.exerciseAuthoringKats!==false) {
        const fifth=structuredClone(body) as Record<string,unknown>;
        const bundle=fifth.managed_actor_bundle as Record<string,unknown>;
        bundle.membership_event=structuredClone(bundle.profile_event);
        const rejected=await request.post(provisionUrl,{headers:serviceHeaders(fifth,provisionUrl,`${idempotencyKey}-bot-fifth`),data:canonicalJson(fifth)});
        expect(rejected.status()).toBe(422);
        expect(wireErrCode(await rejected.json())).toBe("schema_violation");
    }
    const provision=await request.post(provisionUrl,{headers:serviceHeaders(body,provisionUrl,`${idempotencyKey}-bot-provision`),data:canonicalJson(body)});
    expect(provision.status(),await provision.text()).toBe(201);
    const outcome = await provision.json() as Record<string,unknown>;
    expect(outcome.bot_actor_id).toEqual(accountActorId(projectDidToCoreId(botOperation.did)));
    return outcome;
}

async function prepareAppletInstallAuthoringBasis(
  request: APIRequestContext,
  token: string,
  signed: SignedPackage,
  realmId: string,
  effectiveScope: CapabilityGrantObject["resources"][number],
  mutateRegistrationManifest?: (
    manifest: Record<string, unknown>,
  ) => void,
): Promise<{
  basis: Record<string, unknown>;
  grantActionsById: Map<string, string[]>;
}> {
  const actorId = await currentActorIdApi(request, token);
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
    payload: registrationPayload as Record<string, unknown>,
  });
  const registrationEventId = registrationEvent.event_id;
  if (typeof registrationEventId !== "string") {
    throw new Error(
      "Prepared Applet registration Event has an invalid actor frontier",
    );
  }

  const capabilityGrantEvents: Array<Record<string, unknown>> = [];
  const grantActionsById = new Map<string, string[]>();
  for (const [offset, action] of approvedActions.entries()) {
    const unsignedGrant: Pick<CapabilityGrantObject,
      "schema" | "realm_id" | "issuer_id" | "subject" | "actions" |
      "resources" | "constraints" | "issued_at" | "issuer_authority_refs"
    > = {
      schema: "ak.schema.capability.v1",
      realm_id: realmId,
      issuer_id: accountActorId(actorId),
      subject: serviceActorId(signed.applet_package.service_id),
      actions: [action],
      resources: [effectiveScope],
      constraints: [
        {constraint_kind:"authority_control",effect:"allow",evaluation_class:"grant_local",max_authority_depth:0,authority_regrant_allowed:false,allowed_managed_actor_roles:["bot","ghost"]},
        {
          constraint_kind: "authority_control",
          constraint_subkind: "applet_authority",
          effect: "allow",
          evaluation_class: "grant_local",
          applet_id: signed.applet_package.applet_id,
          executed_by: serviceActorId(signed.applet_package.service_id),
          registration_epoch: signed.applet_package.registration_epoch,
        },
        {
          constraint_kind: "temporal",
          constraint_subkind: "window",
          effect: "allow",
          evaluation_class: "stateless",
          not_before: createdAt,
          expires_at: canonicalTimestamp(
            new Date(Date.parse(createdAt) + 24 * 60 * 60 * 1000),
          ),
        },
      ],
      issued_at: createdAt,
      issuer_authority_refs: [
        {
          kind: "realm_root",
          realm_id: realmId,
          authority_event_ref: realmAuthorityRootRef(undefined, realmId)!,
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
      createdAt,
      scopeRef: effectiveScope,
      payload: {
        grant,
      },
    });
    const grantId = retypeEventDerivedId(String(event.event_id), "grant");
    capabilityGrantEvents.push(event);
    grantActionsById.set(grantId, [action]);
  }

  const basis: Record<string, unknown> = {
    schema: "ak.schema.applet_install_authoring_request_basis.v1",
    purpose: "install_service",
    target_station_id: colandServiceId(),
    install_actor_id: accountActorId(actorId),
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
  const verificationMethods = operation.didDocument.verificationMethod as Record<string, string>;
  const publicKeyMaterial = verificationMethods[verificationMethod];
  if (typeof publicKeyMaterial !== "string") {
    throw new Error("Applet service DID document has no webhook signing key");
  }
  const manifest: Record<string, unknown> = {
    claimed_profiles: pkg.claimed_profiles,
    limits: pkg.limits,
    ghost_policy: pkg.ghost_policy,
    delegation_policy: pkg.delegation_policy,
    e2ee_policy: pkg.e2ee_policy,
    registration_epoch_evidence: {
      did: operation.did,
      document_digest: cotestWire<string>("did-document-digest", operation.didDocument),
      method_version_evidence: {
        method: "did:webvh",
        version_id: operation.versionId,
        version_time: versionTime,
        unversioned_refetch: false,
      },
      accepted_signing_keys: [
        {
          key_ref: verificationMethod,
          public_key_digest: `sha256:${createHash("sha256").update(publicKeyMaterial).digest("hex")}`,
        },
      ],
    },
  };
  if (pkg.widget !== undefined) manifest.widget = pkg.widget;
  return {
    applet_id: pkg.applet_id,
    service_id: pkg.service_id,
    controller_principal_id: pkg.controller_principal_id,
    base_url: pkg.base_url,
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
        document_digest: cotestWire<string>("did-document-digest", built.didDocument),
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

function requiredAppletServiceDid(signed: SignedPackage): string {
  const did = signed.service_id_operation?.did;
  if (!did) {
    throw new Error("Applet service proof requires the formal service DID operation");
  }
  return did;
}

async function buildGhostManagedActorCreation(args: {
  request: APIRequestContext;
  token: string;
  signed: SignedPackage;
  registration: AppletRegistration;
  realmId: string;
  ghostBuilt: BuiltWebvhGenesis;
  externalUser: { id: string; display_name?: string };
  /// EventId of the exact active Applet registration
  /// (applet-managed-actor.schema.json `registration_ref`).
  registrationRef: string;
}) {
  const externalRef = {
    protocol: "bridge",
    instance_id: "joint-e2e",
    external_id: args.externalUser.id,
  };
  const targetUri = `${colandBaseUrl()}/_arkret/self/applets/${encodeURIComponent(args.registration.applet_id)}/ghosts/provision/preview`;
  const previewBody = {
    effective_scope: {kind:"realm",realm_id:args.realmId},
    external_ref: externalRef,
    display_name: args.externalUser.display_name ?? args.externalUser.id,
  };
  const preview = await args.request.post(targetUri, {
    headers: signedAppletTransactionHeaders({
      body: previewBody,
      targetUri,
      sourceServiceId: args.signed.applet_package.service_id,
      destinationServiceId: colandServiceId(),
      keyId: `${requiredAppletServiceDid(args.signed)}#applet-service-key`,
      signingKey: args.signed.service_signing_private_key,
      idempotencyKey: `ghost-preview-${args.externalUser.id}`,
    }),
    data: canonicalJson(previewBody),
  });
  expect(preview.status(), await preview.text()).toBe(200);
  const { authoring_request: authoringRequest } = await preview.json();
  const evidence = webvhManagedActorEvidence(args.ghostBuilt);
  const registryBase = String(args.signed.applet_package.base_url).replace(/\/$/, "");
  const material = await args.request.post(`${registryBase}/inspect/ghost-authoring-material`, {
    data: {
      applet_id: args.registration.applet_id,
      external_ref: externalRef,
      material: {
        actor_id: accountActorId(projectDidToCoreId(args.ghostBuilt.did)),
        initial_resolution: evidence.initialResolution,
        method_history_evidence: evidence.methodHistoryEvidence,
        registration_ref: args.registrationRef,
      },
    },
  });
  expect(material.status()).toBe(200);
  const authored = await args.request.post(`${registryBase}/_arkret/edge/applet/managed-actors/author`, {
    data: { authoring_request: authoringRequest },
  });
  expect(authored.status(), await authored.text()).toBe(200);
  const outcome = await authored.json();
  return {
    authoring_request: authoringRequest,
    managed_actor_bundle: outcome.managed_actor_bundle as Record<string, Record<string, unknown>>,
    ghost_actor_did: args.ghostBuilt.did,
    external_ref: externalRef,
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
    colandBaseUrl(),
    signed.service_id_operation,
  );
}

function installRegistrationFromResponse(
  signed: SignedPackage,
  realmId: string,
  response: AppletInstallOutcome,
  bot: AppletBotProvisionOutcome,
  grantActionsById: Map<string, string[]>,
): AppletRegistration {
  if (bot.bot_actor_id.kind !== "account") {
    throw new Error("A Bot provision outcome must name an Account actor");
  }
  expect(bot.bot_actor_id).toEqual(signed.bot_actor_id);
  const capabilityGrantRefs = Array.isArray(response.capability_grant_refs)
    ? response.capability_grant_refs.map(String)
    : [];
  expect(new Set(capabilityGrantRefs)).toEqual(
    new Set(grantActionsById.keys()),
  );
  // applet-install-operations.schema.json#/$defs/applet_install_outcome:
  // `registration_event_ref` is a bare EventId, not a CommittedEventRef.
  expect(
    response.registration_event_ref,
    JSON.stringify(response.registration_event_ref),
  ).toEqual(expect.stringMatching(/^ak:event:/));
  return {
    applet_id: String(response.applet_id),
    bot_actor_id: bot.bot_actor_id,
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
  // The request proof binds the closed authoring request without its proof
  // member; managed creation has no installation plan digest.
  const { proof: _proof, ...unsigned } = request;
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
    audience_id: proof.audience_id,
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
