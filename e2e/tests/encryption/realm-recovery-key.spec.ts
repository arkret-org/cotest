// Realm Recovery Key (RRK) — organizational history durability
// Contract: e2e/scenarios/encryption/realm-recovery-key.md
//
// Spec refs:
//   - crypto-media/encryption-and-audit.md §2.10   (mls_exporter_aead_v1 scheme)
//   - crypto-media/encryption-and-audit.md §2.10.1 (history_secret[N] / K_content[N])
//   - crypto-media/encryption-and-audit.md §2.10.4 (ak.realm_key.share delivery)
//   - crypto-media/encryption-and-audit.md §2.10.5 (retention + per-epoch FS)
//   - crypto-media/encryption-and-audit.md §2.10.8 (RRK eager-at-commit seal + RYW + fallback re-share)
//   - models/realm-and-space.md §2.3.1 (durability_policy)
//   - identity/identity-did.md §8.3 (ArkretRealmHistoryRecoveryKey service entry)
//   - error-code-registry: durability_scheme_incompatible /
//     durability_recovery_recipient_unverified / durability_seal_missing_before_gc
//
// STATUS: C1 is live. The remaining cases stay `test.fixme` until the RRK share,
// recovery-read, client retention/retry, and Inkson cryptographic paths are
// observable end to end. Their contracts pin the spec and MUST NOT be weakened
// or redirected to unregistered server APIs.

import { expect, test, type APIRequestContext } from "@playwright/test";
import { createHash, randomUUID } from "node:crypto";

import { solandBaseUrl } from "../../helpers/env";
import {
  alignSignedEventToActorFrontierApi,
  authHeaders,
  base64url,
  canonicalJson,
  canonicalTimestamp,
  createRealmApi,
  prepareSignedEventCbaApi,
  rawSubmitSignedEventApi,
  refreshEventEnvelopeProof,
  sdkCapabilityActionRegistryDigest,
  signedEventEnvelope,
  singleDidNotary,
  submitSignedEventApi,
  typedId,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
  type JointUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

const MLS_GOVERNANCE_BINDING_FULL_PROFILE =
  "ak.profile.mls_governance_binding.full.v1";
const MLS_REDUCER_PROFILE_V1 = "ak.reducer.core.v1";
const MLS_CIPHER_SUITE = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";

// Content scheme that makes per-epoch history_secret shareable (§2.10). RRK
// durability is ONLY meaningful for this scheme; the mls_rfc9420 default has no
// deliverable history_secret (§2.10.8 applicability + C1 below).
const CONTENT_SCHEME_EXPORTER_AEAD = "mls_exporter_aead_v1";
const CONTENT_SCHEME_RFC9420 = "mls_rfc9420";

function sha256Hash(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function digestNibble(nibble: string): string {
  return `sha256:${nibble.repeat(64)}`;
}

type MlsGroupContext = {
  groupId: string;
  realmId: string;
  effectiveScope: { kind: "realm"; realm_id: string };
  policyRoot: string;
  securityFrontierDigest: string;
  frontierRef: string;
};

function mlsGovernanceBinding(
  group: MlsGroupContext,
  previousEpoch: number,
  nextEpoch: number,
): Record<string, unknown> {
  return {
    binding_version: 1,
    encoding_profile: "cbor-deterministic-rfc8949-v1",
    realm_id: group.realmId,
    effective_scope: group.effectiveScope,
    mls_group_id: group.groupId,
    previous_epoch: previousEpoch,
    next_epoch: nextEpoch,
    security_frontier_digest: group.securityFrontierDigest,
    binding_profile: MLS_GOVERNANCE_BINDING_FULL_PROFILE,
    reducer_profile: MLS_REDUCER_PROFILE_V1,
  };
}

// Build a ak.realm.create envelope declaring durability_policy. The RRK suite
// still forges the envelope directly because durability_policy is not threaded
// through createRealmApi() (mirrors mls-group.spec.ts createEncryptedRealm).
function realmCreateEnvelope(args: {
  ownerDid: string;
  realmId: string;
  title: string;
  contentScheme?: string;
  durabilityPolicy?: Record<string, unknown>;
}) {
  const createdAt = canonicalTimestamp();
  const object: Record<string, unknown> = {
    id: args.realmId,
    schema: "ak.schema.realm.v1",
    title: args.title,
    created_by: args.ownerDid,
    trust_domain: "ak:trust_domain:soland.local",
    schema_refs: ["ak.schema.realm.v1"],
    default_discoverability: "listed",
    default_join_rule: "invite",
    // §2.10.4: later-joiner history sharing presupposes "shared" visibility;
    // org recovery still reads the durable RRK shares regardless.
    history_visibility: "shared",
    encryption_profile: "mls_rfc9420",
    security_class: "standard",
    federation_policy: "restricted",
    notary_profile: "single_did",
    digest_algorithm: "sha256",
    notary: singleDidNotary(args.ownerDid),
    // Create-locked genesis basis for the Realm authority-root cell
    // (realm-and-space.md section 2.5).
    capability_action_registry_digest: sdkCapabilityActionRegistryDigest(),
    created_at: createdAt,
  };
  if (args.contentScheme) {
    object.content_scheme = args.contentScheme;
  }
  if (args.durabilityPolicy) {
    object.durability_policy = args.durabilityPolicy;
  }
  return signedEventEnvelope({
    actorDid: args.ownerDid,
    realmId: args.realmId,
    kind: "ak.realm.create",
    createdAt,
    payload: { object },
  });
}

// A RecoveryRecipient (models/realm-and-space.md §2.3.1). verification_method
// MUST resolve to a VM designated by an active ArkretRealmHistoryRecoveryKey
// service entry (identity-did.md §8.3); domain-separated from did_recovery.
function recoveryRecipient(args: {
  recipientId: string;
  principalId: string;
  // The #fragment of the RRK HPKE VM on principalId's DID Document.
  rrkVerificationMethod: string;
  controllerOrganization?: string;
}): Record<string, unknown> {
  const out: Record<string, unknown> = {
    recipient_id: args.recipientId,
    principal_id: args.principalId,
    verification_method: args.rrkVerificationMethod,
  };
  if (args.controllerOrganization) {
    out.controller_organization = args.controllerOrganization;
  }
  return out;
}

// realm_key_scope (event-payload.schema.json#/$defs/realm_key_scope) pinning a
// single epoch N (from_epoch=to_epoch=N) of Realm-default history.
function realmKeyScope(
  group: MlsGroupContext,
  fromEpoch: number,
  toEpoch: number,
): Record<string, unknown> {
  return {
    effective_scope: group.effectiveScope,
    policy_digest: group.policyRoot,
    from_epoch: fromEpoch,
    to_epoch: toEpoch,
    history_visibility: "shared",
  };
}

// Forge a RRK-targeted ak.realm_key.share envelope. This is the eager seal a
// committer publishes after each epoch commit (§2.10.8): recipient is the
// offline org RRK principal, ciphertext is history_secret[from..to] HPKE-sealed
// to the RRK public key. provider-initiated (no recipient claim).
function signedRealmKeyShareEnvelope(args: {
  senderDid: string;
  senderDeviceId: string;
  group: MlsGroupContext;
  recipientPrincipalId: string;
  sourceAuthorizationRef: string;
  target:
    | {
        shareKind: "realm_recovery_key";
        recoveryRecipientId: string;
        recipientVerificationMethod: string;
      }
    | {
        shareKind: "member_device";
        recipientDeviceId: string;
      };
  fromEpoch: number;
  toEpoch: number;
  sealedCiphertext: string;
}) {
  const keyScope = realmKeyScope(args.group, args.fromEpoch, args.toEpoch);
  const createdAt = canonicalTimestamp();
  const targetFields =
    args.target.shareKind === "realm_recovery_key"
      ? {
          recipient_verification_method:
            args.target.recipientVerificationMethod,
          recovery_recipient_id: args.target.recoveryRecipientId,
        }
      : { recipient_device_id: args.target.recipientDeviceId };
  const aadDigest = sha256Hash(
    canonicalJson({
      share_kind: args.target.shareKind,
      recipient_principal_id: args.recipientPrincipalId,
      ...targetFields,
      sender_device_id: args.senderDeviceId,
      source_authorization_ref: args.sourceAuthorizationRef,
      key_scope: keyScope,
    }),
  );
  const transcript = {
    context: "ak.realm-key-share-sender-proof-v1",
    share_kind: args.target.shareKind,
    sender_device_id: args.senderDeviceId,
    source_authorization_ref: args.sourceAuthorizationRef,
    recipient_principal_id: args.recipientPrincipalId,
    ...targetFields,
    key_scope: keyScope,
    ciphertext: args.sealedCiphertext,
    aad_digest: aadDigest,
    created_at: createdAt,
  };
  const payload = {
    share_kind: args.target.shareKind,
    recipient_principal_id: args.recipientPrincipalId,
    ...targetFields,
    sender_device_id: args.senderDeviceId,
    source_authorization_ref: args.sourceAuthorizationRef,
    key_scope: keyScope,
    sender_device_signature: {
      verification_method: `${args.senderDid}#${args.senderDeviceId}`,
      alg: "EdDSA",
      transcript_digest: sha256Hash(canonicalJson(transcript)),
      signature: base64url(`rrk-share-sig-${randomUUID()}`),
    },
    ciphertext: args.sealedCiphertext,
    aad_digest: aadDigest,
    created_at: createdAt,
  };
  const envelope = signedEventEnvelope({
    actorDid: args.senderDid,
    realmId: args.group.realmId,
    kind: "ak.realm_key.share",
    payload,
  });
  return envelope;
}

function rrkDurabilityShareEnvelope(args: Omit<
  Parameters<typeof signedRealmKeyShareEnvelope>[0],
  "target"
> & {
  recoveryRecipientId: string;
  recipientVerificationMethod: string;
}) {
  return signedRealmKeyShareEnvelope({
    ...args,
    target: {
      shareKind: "realm_recovery_key",
      recoveryRecipientId: args.recoveryRecipientId,
      recipientVerificationMethod: args.recipientVerificationMethod,
    },
  });
}

function memberDeviceRealmKeyShareEnvelope(args: Omit<
  Parameters<typeof signedRealmKeyShareEnvelope>[0],
  "target"
> & {
  recipientDeviceId: string;
}) {
  return signedRealmKeyShareEnvelope({
    ...args,
    target: {
      shareKind: "member_device",
      recipientDeviceId: args.recipientDeviceId,
    },
  });
}

async function registeredSession(
  request: APIRequestContext,
  prefix: string,
): Promise<{ user: JointUser; token: string }> {
  const user = uniqueUser(prefix);
  await ensureRegistered(request, user);
  const token = await issueDevSession(request, user);
  return { user, token };
}

// Submit ak.mls.genesis (epoch 0) for a fresh group bound to realmId, with the
// content_scheme=mls_exporter_aead_v1 projected into its Security Frontier.
async function submitExporterAeadGenesis(
  request: APIRequestContext,
  token: string,
  owner: JointUser,
  realmId: string,
): Promise<MlsGroupContext> {
  const groupId = typedId("mls_group");
  const genesisEventId = typedId("event");
  const group: MlsGroupContext = {
    groupId,
    realmId,
    effectiveScope: { kind: "realm", realm_id: realmId },
    // RealmKey policy_digest remains an orthogonal key-release binding, while
    // the MLS transcript carries only security_frontier_digest.
    policyRoot: digestNibble("a"),
    securityFrontierDigest: digestNibble("b"),
    frontierRef: genesisEventId,
  };
  const body = await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: owner.did,
      realmId,
      kind: "ak.mls.genesis",
      eventId: genesisEventId,
      payload: {
        mls_group_id: groupId,
        effective_scope: group.effectiveScope,
        epoch: 0,
        creator_principal_id: owner.did,
        creator_device_id: owner.deviceId,
        cipher_suite: MLS_CIPHER_SUITE,
        group_info_digest: digestNibble("3"),
        ratchet_tree_digest: digestNibble("4"),
        content_scheme: CONTENT_SCHEME_EXPORTER_AEAD,
        governance_binding: mlsGovernanceBinding(group, 0, 0),
        created_at: canonicalTimestamp(),
      },
    }),
    { context: `submit exporter-aead MLS genesis ${groupId}` },
  );
  expect(body.accepted ?? []).toContain(genesisEventId);
  return group;
}

async function submitCommit(
  request: APIRequestContext,
  token: string,
  committer: JointUser,
  group: MlsGroupContext,
  baseEpoch: number,
  label: string,
): Promise<string> {
  const eventId = typedId("event");
  const nextEpoch = baseEpoch + 1;
  const body = await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: committer.did,
      realmId: group.realmId,
      kind: "ak.mls.commit",
      eventId,
      payload: {
        mls_group_id: group.groupId,
        base_epoch: baseEpoch,
        base_epoch_ref: group.frontierRef,
        proposal_refs: [],
        next_epoch: nextEpoch,
        commit_digest: sha256Hash(label),
        governance_binding: mlsGovernanceBinding(group, baseEpoch, nextEpoch),
      },
    }),
    { context: `submit MLS commit ${label}` },
  );
  expect(body.accepted ?? []).toContain(eventId);
  return eventId;
}

// Submit an mls_exporter_aead_v1 encrypted content event at epoch N. The
// ciphertext is opaque to soland; the plaintext MUST NOT appear on the wire.
async function submitExporterAeadMessage(
  request: APIRequestContext,
  token: string,
  author: JointUser,
  group: MlsGroupContext,
  epoch: number,
  plaintext: string,
): Promise<{ eventId: string; ciphertext: string }> {
  const eventId = typedId("event");
  const ciphertext = base64url(`exporter-aead-${epoch}-${randomUUID()}`);
  const envelope = signedEventEnvelope({
    actorDid: author.did,
    realmId: group.realmId,
    kind: "ak.message.create",
    eventId,
    payload: {
      encrypted_content: {
        envelope: {
          scheme: CONTENT_SCHEME_EXPORTER_AEAD,
          version: "1.0",
          group_id: group.groupId,
          epoch,
          content_type: "application/json",
          ciphertext,
          aad_visibility_event_id: "routing_digest",
          aad: {
            realm_id: group.realmId,
            event_kind: "ak.message.create",
            event_ref_digest: sha256Hash(`${eventId}:${group.realmId}`),
          },
          key_ref: {
            algorithm: "MLS-EXPORTER-AEAD",
            group_state_ref: group.frontierRef,
          },
          payload_digest: sha256Hash(ciphertext),
          aad_digest: sha256Hash(`aad:${eventId}`),
        },
      },
    },
  });
  const postData = JSON.stringify(envelope);
  expect(postData).toContain(CONTENT_SCHEME_EXPORTER_AEAD);
  expect(postData).not.toContain(plaintext);
  const body = await submitSignedEventApi(request, token, envelope, {
    context: `submit exporter-aead message epoch ${epoch}`,
  });
  expect(body.accepted ?? []).toContain(eventId);
  return { eventId, ciphertext };
}

test.describe("Realm Recovery Key (RRK) history durability", () => {
  // ---------------------------------------------------------------------------
  // Phase A — forward "organizational recovery"
  // ---------------------------------------------------------------------------
  test.fixme(
    // @blocking-on rrk-soland: content_scheme + durability_policy projection on
    //   ak.realm.create, RRK-targeted ak.realm_key.share acceptance with the
    //   eager-seal RYW guard, and the org recovery read surface that returns the
    //   durable RRK shares for HPKE-open.
    // @blocking-on rrk-inkson: mls_exporter_aead_v1 content seal/open, per-epoch
    //   history_secret derivation, and the RRK HPKE seal at commit time.
    // @user-promise: e2e/scenarios/encryption/realm-recovery-key.md (Phase A)
    // @expected-live-by: 2026Q3
    "org_recovery_key: every epoch is RRK-sealed; after total member loss the org HPKE-opens and restores history",
    async ({ request }) => {
      // spec: §2.10.1 / §2.10.4 / §2.10.8
      const { user: alice, token: aliceToken } = await registeredSession(
        request,
        "rrk-a-alice",
      );
      const { user: bob, token: bobToken } = await registeredSession(
        request,
        "rrk-a-bob",
      );
      // org-rrk is an OFFLINE recovery principal: it holds the RRK private key
      // but is NOT an MLS member and never receives realtime fanout (§2.3.1).
      const { user: orgRrk } = await registeredSession(request, "rrk-a-org");

      // org-rrk publishes a DID Document with an active
      // ArkretRealmHistoryRecoveryKey service entry whose serviceEndpoint
      // .verificationMethod points to a keyAgreement HPKE VM, domain=mls_history,
      // domain-separated from did_recovery (identity-did.md §8.3). The live
      // helper for this is a inkson/soland concern (publishRrkServiceEntry).
      const rrkVm = `${orgRrk.did}#realm-history-recovery-1`;

      const realmId = typedId("realm");
      const durabilityPolicy = {
        mode: "org_recovery_key",
        recovery_recipients: [
          recoveryRecipient({
            recipientId: "org-primary",
            principalId: orgRrk.did,
            rrkVerificationMethod: rrkVm,
          }),
        ],
      };
      const realmCreate = realmCreateEnvelope({
        ownerDid: alice.did,
        realmId,
        title: "RRK org recovery",
        contentScheme: CONTENT_SCHEME_EXPORTER_AEAD,
        durabilityPolicy,
      });
      const sourceAuthorizationRef = String(realmCreate.event_id);
      const create = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
        headers: authHeaders(aliceToken),
        data: realmCreate,
      });
      expect(create.status()).toBe(200);

      const group = await submitExporterAeadGenesis(
        request,
        aliceToken,
        alice,
        realmId,
      );

      // Advance several epochs; each carries content AND an eager RRK seal.
      const EPOCHS = 3;
      const sealedHistorySecrets: string[] = [];
      const plaintextByEpoch: string[] = [];
      for (let epoch = 1; epoch <= EPOCHS; epoch += 1) {
        await submitCommit(request, aliceToken, alice, group, epoch - 1, `rrk-a-c${epoch}`);

        const plaintext = `epoch ${epoch} confidential content ${randomUUID()}`;
        plaintextByEpoch.push(plaintext);
        const author = epoch % 2 === 0 ? bob : alice;
        const authorToken = epoch % 2 === 0 ? bobToken : aliceToken;
        await submitExporterAeadMessage(
          request,
          authorToken,
          author,
          group,
          epoch,
          plaintext,
        );

        // §2.10.8 eager seal: after the commit is accepted and BEFORE GC of
        // history_secret[epoch], the committer publishes a RRK-targeted share.
        const sealedCiphertext = base64url(`rrk-sealed-hs-${epoch}-${randomUUID()}`);
        sealedHistorySecrets.push(sealedCiphertext);
        const shareEnvelope = rrkDurabilityShareEnvelope({
          senderDid: alice.did,
          senderDeviceId: alice.deviceId,
          group,
          recipientPrincipalId: orgRrk.did,
          recoveryRecipientId: "org-primary",
          recipientVerificationMethod: rrkVm,
          sourceAuthorizationRef,
          fromEpoch: epoch,
          toEpoch: epoch,
          sealedCiphertext,
        });
        const share = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
          headers: authHeaders(aliceToken),
          data: shareEnvelope,
        });
        // provider-initiated durable seal MUST be accepted (no recipient claim).
        expect(share.status()).toBe(200);
      }

      // Simulate total member loss: alice + bob leave and their devices fail.
      for (const [user, token] of [
        [alice, aliceToken],
        [bob, bobToken],
      ] as const) {
        await submitSignedEventApi(
          request,
          token,
          signedEventEnvelope({
            actorDid: user.did,
            realmId,
            kind: "ak.member.state",
            payload: { realm_id: realmId, actor_id: user.did, membership: "leave" },
          }),
          { context: `member loss leave ${user.did}` },
        );
      }

      // Organizational recovery: the org retrieves the durable RRK shares (they
      // are stored ciphertext-only on the server, §2.10.8) and HPKE-opens each
      // with the RRK private key to recover history_secret[1..N].
      const recoveryUrl = `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(
        realmId,
      )}/durability/recovery-shares`;
      const sharesResp = await request.get(recoveryUrl, {
        headers: authHeaders(aliceToken),
      });
      expect(sharesResp.status()).toBe(200);
      const sharesBody = await sharesResp.json();
      // One durable share per sealed epoch, addressed to the org RRK.
      const shares = (sharesBody.recovery_shares ?? []) as Array<{
        recipient_principal_id: string;
        key_scope: { from_epoch: number; to_epoch: number };
        ciphertext: string;
      }>;
      expect(shares).toHaveLength(EPOCHS);
      for (let epoch = 1; epoch <= EPOCHS; epoch += 1) {
        const share = shares.find(
          (s) => s.key_scope.from_epoch === epoch && s.key_scope.to_epoch === epoch,
        );
        expect(share, `RRK share for epoch ${epoch}`).toBeTruthy();
        expect(share!.recipient_principal_id).toBe(orgRrk.did);
        expect(share!.ciphertext).toBe(sealedHistorySecrets[epoch - 1]);
      }

      // The org HPKE-opens with the RRK private key, derives K_content[N]
      // (§2.10.1) and decrypts each epoch's history. The restored plaintext MUST
      // equal the originally authored content, epoch-by-epoch.
      //
      //   const restored = await orgRecoverHistory(rrkPrivateKey, shares, group);
      //   for (let epoch = 1; epoch <= EPOCHS; epoch += 1) {
      //     expect(restored.get(epoch)).toContain(plaintextByEpoch[epoch - 1]);
      //   }
      //
      // orgRecoverHistory is the inkson RRK-open + AEAD primitive under
      // @blocking-on rrk-inkson.
      expect(plaintextByEpoch).toHaveLength(EPOCHS);
    },
  );

  // ---------------------------------------------------------------------------
  // Phase B — later joiner served via RRK fallback re-share
  // ---------------------------------------------------------------------------
  test.fixme(
    // @blocking-on rrk-soland: RRK-source re-share acceptance for a brand-new
    //   member when no live member can re-share, threading the device-lifecycle
    //   §13 key-share eligibility + history-visibility §6 gate.
    // @blocking-on rrk-inkson: RRK private-key HPKE-open of the sealed range,
    //   then re-seal of history_secret to dave's device HPKE public key, and the
    //   §2.3.5 late-recovery install on dave.
    // @user-promise: e2e/scenarios/encryption/realm-recovery-key.md (Phase B)
    // @expected-live-by: 2026Q3
    "no-live-member fallback: RRK holder re-seals an epoch range to a later joiner who then decrypts history",
    async ({ request }) => {
      // spec: §2.10.4 (re-share) + §2.10.8 ("unified later-joiner history" — RRK
      // is the always-present fallback re-sharer) + §2.3.5 (late-recovery state).
      const { user: alice, token: aliceToken } = await registeredSession(
        request,
        "rrk-b-alice",
      );
      const { user: orgRrk, token: orgRrkToken } = await registeredSession(
        request,
        "rrk-b-org",
      );
      const { user: dave } = await registeredSession(
        request,
        "rrk-b-dave",
      );

      const rrkVm = `${orgRrk.did}#realm-history-recovery-1`;
      const realmId = typedId("realm");
      const realmCreate = realmCreateEnvelope({
        ownerDid: alice.did,
        realmId,
        title: "RRK fallback re-share",
        contentScheme: CONTENT_SCHEME_EXPORTER_AEAD,
        durabilityPolicy: {
          mode: "org_recovery_key",
          recovery_recipients: [
            recoveryRecipient({
              recipientId: "org-primary",
              principalId: orgRrk.did,
              rrkVerificationMethod: rrkVm,
            }),
          ],
        },
      });
      const sourceAuthorizationRef = String(realmCreate.event_id);
      const create = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
        headers: authHeaders(aliceToken),
        data: realmCreate,
      });
      expect(create.status()).toBe(200);

      const group = await submitExporterAeadGenesis(
        request,
        aliceToken,
        alice,
        realmId,
      );
      // Build epochs 1..2 with content + RRK seals, then alice leaves (no live
      // member remains who can re-share).
      const plaintextByEpoch = new Map<number, string>();
      for (let epoch = 1; epoch <= 2; epoch += 1) {
        await submitCommit(request, aliceToken, alice, group, epoch - 1, `rrk-b-c${epoch}`);
        const plaintext = `fallback epoch ${epoch} ${randomUUID()}`;
        plaintextByEpoch.set(epoch, plaintext);
        await submitExporterAeadMessage(
          request,
          aliceToken,
          alice,
          group,
          epoch,
          plaintext,
        );
        const share = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
          headers: authHeaders(aliceToken),
          data: rrkDurabilityShareEnvelope({
            senderDid: alice.did,
            senderDeviceId: alice.deviceId,
            group,
            recipientPrincipalId: orgRrk.did,
            recoveryRecipientId: "org-primary",
            recipientVerificationMethod: rrkVm,
            sourceAuthorizationRef,
            fromEpoch: epoch,
            toEpoch: epoch,
            sealedCiphertext: base64url(`rrk-b-sealed-${epoch}-${randomUUID()}`),
          }),
        });
        expect(share.status()).toBe(200);
      }
      await submitSignedEventApi(
        request,
        aliceToken,
        signedEventEnvelope({
          actorDid: alice.did,
          realmId,
          kind: "ak.member.state",
          payload: { realm_id: realmId, actor_id: alice.did, membership: "leave" },
        }),
        { context: "alice leaves (no live re-sharer)" },
      );

      // dave joins later and publishes a device HPKE public key for the seal.
      await submitSignedEventApi(
        request,
        aliceToken,
        signedEventEnvelope({
          actorDid: alice.did,
          realmId,
          kind: "ak.member.state",
          payload: { realm_id: realmId, actor_id: dave.did, membership: "join" },
        }),
        { context: "dave joins after total live-member loss" },
      );
      const daveDeviceHpkePublicKey = base64url(`dave-device-hpke-${randomUUID()}`);

      // The RRK holder comes online transiently, HPKE-opens the sealed range
      // [1,2] with the RRK private key, then RE-SEALS history_secret[1..2] to
      // dave's device HPKE public key as a fresh ak.realm_key.share. The
      // sender_device of this re-share is the RRK holder's device.
      const reSeal = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
        headers: authHeaders(orgRrkToken),
        data: memberDeviceRealmKeyShareEnvelope({
          senderDid: orgRrk.did,
          senderDeviceId: orgRrk.deviceId,
          group,
          recipientPrincipalId: dave.did,
          recipientDeviceId: dave.deviceId,
          sourceAuthorizationRef,
          fromEpoch: 1,
          toEpoch: 2,
          // Re-sealed to dave's device HPKE public key (not the RRK key).
          sealedCiphertext: base64url(
            `reseal-to-dave-${daveDeviceHpkePublicKey}-${randomUUID()}`,
          ),
        }),
      });
      expect(reSeal.status()).toBe(200);

      // dave installs history_secret[1..2] and decrypts the historical content,
      // entering the §2.3.5 late-recovery state machine (late_recovered). The
      // restored plaintext MUST match what alice authored before dave joined.
      //
      //   const restored = await daveInstallAndDecrypt(reSeal, group);
      //   expect(restored.get(1)).toContain(plaintextByEpoch.get(1));
      //   expect(restored.get(2)).toContain(plaintextByEpoch.get(2));
      //
      // daveInstallAndDecrypt is the inkson late-recovery install path under
      // @blocking-on rrk-inkson.
      expect(plaintextByEpoch.size).toBe(2);
    },
  );

  // ---------------------------------------------------------------------------
  // Phase C — diagnostic vectors (negative)
  // ---------------------------------------------------------------------------

  // C1: durability_scheme_incompatible — declaring mode != none on a Realm whose
  // content_scheme is NOT mls_exporter_aead_v1 (here the mls_rfc9420 default).
  test(
    // Live regression for the policy-reducer admission preflight.
    // @user-promise: e2e/scenarios/encryption/realm-recovery-key.md (C1)
    "C1 durability_scheme_incompatible: mode != none on an mls_rfc9420 Realm is rejected",
    async ({ request }) => {
      const { user: alice, token: aliceToken } = await registeredSession(
        request,
        "rrk-c1-alice",
      );
      const { user: orgRrk } = await registeredSession(request, "rrk-c1-org");

      // Realm created WITHOUT mls_exporter_aead_v1 (explicit mls_rfc9420).
      const realmId = await createRealmApi(request, aliceToken, {
        title: "RRK incompatible scheme",
        history_visibility: "joined",
        encryption_profile: "mls_rfc9420",
        content_scheme: CONTENT_SCHEME_RFC9420,
      });

      // Writing durability_policy.mode != none via ak.realm.policy_bundle MUST
      // failed_precondition with reason durability_scheme_incompatible.
      const policyEvent = signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ak.realm.policy_bundle",
        payload: {
          policy_revision: 1,
          durability_policy: {
            mode: "org_recovery_key",
            recovery_recipients: [
              recoveryRecipient({
                recipientId: "org-primary",
                principalId: orgRrk.did,
                rrkVerificationMethod: `${orgRrk.did}#realm-history-recovery-1`,
              }),
            ],
          },
        },
      });
      const write = await rawSubmitSignedEventApi(
        request,
        aliceToken,
        policyEvent,
      );
      expect([400, 409, 412, 422]).toContain(write.status());
      expect(wireErrCode(await write.json())).toBe("durability_scheme_incompatible");
    },
  );

  // C2: recipient verification is a sender-side pre-seal gate. Merely storing a
  // durability_policy does not prove that its RecoveryRecipient is currently
  // resolvable, and MUST NOT raise this error. The client that is about to
  // produce the eager RRK share resolves the DID at send time and fails before
  // emitting an Event when the VM is not designated by an active
  // ArkretRealmHistoryRecoveryKey service entry.
  test.fixme(
    // @blocking-on rrk-inkson: expose the eager-seal attempt through a client
    //   observable result, resolve the current recipient DID Document at seal
    //   time, and surface durability_recovery_recipient_unverified without
    //   enqueueing ak.realm_key.share or falling back to another key.
    // @blocking-on rrk-cotest: add a DID resolver fixture that can publish a VM
    //   which is present but not designated by an active
    //   ArkretRealmHistoryRecoveryKey service entry, plus outbound Event capture.
    // @user-promise: e2e/scenarios/encryption/realm-recovery-key.md (C2)
    // @expected-live-by: 2026Q3
    "C2 durability_recovery_recipient_unverified: the client sealer rejects an undesignated RRK VM before emitting ak.realm_key.share",
    async ({ browser, request }) => {
      // Future live sequence:
      // 1. Publish org-rrk DID material containing `#did-recovery-1`, but do not
      //    designate it with an active ArkretRealmHistoryRecoveryKey service.
      // 2. Store a durability_policy RecoveryRecipient that references that VM.
      //    The policy write itself is allowed; this diagnostic is not a policy
      //    admission error.
      // 3. Advance an exporter-aead epoch through Inkson so its eager RRK sealer
      //    resolves the recipient immediately before HPKE sealing.
      // 4. Assert the client reports
      //    durability_recovery_recipient_unverified.
      // 5. Capture outbound self-events and assert that no ak.realm_key.share
      //    was emitted for the recipient and no alternate VM was selected.
      //
      // Do not replace this with a direct policy POST assertion: that was the
      // contract drift this test is intended to prevent.
      void browser;
      void request;
    },
  );

  // C3: history_secret retention is a client-side RYW invariant. There is no
  // registered server GC operation for client-held MLS exporter secrets.
  test.fixme(
    // @blocking-on rrk-inkson: expose deterministic eager-seal retry/acceptance
    //   state and retained-secret evidence. A future client GC implementation
    //   must additionally expose the local refusal reason
    //   durability_seal_missing_before_gc.
    // @blocking-on rrk-cotest: add a fault-injection fixture that rejects or
    //   drops the first RRK share submit, then permits the retry while preserving
    //   the same browser/client storage.
    // @user-promise: e2e/scenarios/encryption/realm-recovery-key.md (C3)
    // @expected-live-by: 2026Q3
    "C3 eager-seal RYW: an unaccepted RRK share leaves history_secret retained and available for retry",
    async ({ browser, request }) => {
      // Future live sequence:
      // 1. Drive an Inkson exporter-aead epoch commit with a valid RRK policy.
      // 2. Fault-inject the first ak.realm_key.share submission so it is not
      //    accepted, while retaining the same client instance/storage.
      // 3. Assert no client cleanup removes history_secret[N]. Inkson currently
      //    uses monotonic retention, so the observable contract is successful
      //    retry, not a fabricated server-side GC response.
      // 4. Remove the fault and retry the eager seal. Assert the share is
      //    accepted and the RRK holder can HPKE-open the same epoch secret.
      // 5. If/when Inkson adds local secret GC, separately attempt GC before
      //    step 4 and assert local refusal
      //    durability_seal_missing_before_gc plus retained-secret evidence.
      //
      // No request may target a `durability/history-secret/gc` HTTP path unless
      // such an operation is first registered by the spec.
      void browser;
      void request;
    },
  );
});
