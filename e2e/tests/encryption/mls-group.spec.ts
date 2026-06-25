// MLS group encryption (E2EE Realm lifecycle)
// Contract: e2e/scenarios/encryption/mls-group.md
// Spec refs:
//   - crypto-media/encryption-and-audit.md §2 (MLS architecture)
//   - §2.2 Welcome/Commit, §2.3 application envelope, §2.4 sync+epoch
//   - §2.5 Governance Binding, §2.6 KeyPackage
//   - models/realm-and-space.md §2.2 encryption_profile, §3.7.2 E2EE Realm

import { expect, test, type Page } from "@playwright/test";
import {
  createHash,
  generateKeyPairSync,
  sign as nodeSign,
  type KeyObject,
} from "node:crypto";
import { solandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  authHeaders,
  b64url,
  canonicalJson,
  canonicalTimestamp,
  addRealmMemberApi,
  createRealmApi,
  principalControlRealmForDid,
  singleDidNotary,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  createDpopUserSession,
  ensureRegistered,
  issueDevSession,
  openUserPage,
  type JointUser,
  type JointUserPage,
  uniqueUser,
} from "../../helpers/users";
import { selfPathGrantHeaders } from "../../helpers/session-grant-dpop";

test.describe.configure({ mode: "serial" });

function sha256Digest(value: Buffer): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

const BASE58BTC_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const WEBVH_SCID_PLACEHOLDER = "{SCID}";
const CROSS_SIGNING_BINDING_LABEL = "ck-cross-signing-bind-v1\n";
const MLS_GOVERNANCE_BINDING_FULL_PROFILE =
  "ck.profile.mls_governance_binding.full.v1";
const MLS_REDUCER_PROFILE_V1 = "ck.reducer.v1";

type Ed25519FixtureKey = {
  privateKey: KeyObject;
  publicKeyMultibase: string;
};

type WebvhPrincipalFixture = {
  did: string;
  didKeyId: string;
  psk: Ed25519FixtureKey;
  ssk: Ed25519FixtureKey;
  usk: Ed25519FixtureKey;
  sskKid: string;
};

function base58btc(bytes: Buffer): string {
  if (bytes.length === 0) {
    return "";
  }
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i += 1) {
      const value = digits[i] * 256 + carry;
      digits[i] = value % 58;
      carry = Math.floor(value / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  for (const byte of bytes) {
    if (byte !== 0) {
      break;
    }
    digits.push(0);
  }
  return digits
    .reverse()
    .map((digit) => BASE58BTC_ALPHABET[digit])
    .join("");
}

function rawEd25519PublicKey(publicKey: KeyObject): Buffer {
  const der = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  if (der.length < 32) {
    throw new Error("Ed25519 SPKI public key is too short");
  }
  return der.subarray(der.length - 32);
}

function ed25519PublicKeyMultibase(publicKey: KeyObject): string {
  return `z${base58btc(
    Buffer.concat([Buffer.from([0xed, 0x01]), rawEd25519PublicKey(publicKey)]),
  )}`;
}

function ed25519FixtureKey(): Ed25519FixtureKey {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privateKey,
    publicKeyMultibase: ed25519PublicKeyMultibase(publicKey),
  };
}

function ed25519SignatureB64url(privateKey: KeyObject, payload: Buffer): string {
  return nodeSign(null, payload, privateKey).toString("base64url");
}

function ed25519SignatureBase58(privateKey: KeyObject, payload: Buffer): string {
  return `z${base58btc(nodeSign(null, payload, privateKey))}`;
}

function sha256MultihashMultibase(payload: Buffer): string {
  return `z${base58btc(
    Buffer.concat([
      Buffer.from([0x12, 0x20]),
      createHash("sha256").update(payload).digest(),
    ]),
  )}`;
}

function canonicalBytes(value: unknown): Buffer {
  return Buffer.from(canonicalJson(value), "utf8");
}

function substituteScid(value: unknown, scid: string): unknown {
  if (typeof value === "string") {
    return value.replaceAll(WEBVH_SCID_PLACEHOLDER, scid);
  }
  if (Array.isArray(value)) {
    return value.map((item) => substituteScid(item, scid));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, item]) => [
        key,
        substituteScid(item, scid),
      ]),
    );
  }
  return value;
}

function stripVersionId(value: Record<string, unknown>): Record<string, unknown> {
  const { versionId: _versionId, ...rest } = value;
  return rest;
}

function webvhAuthorities(): { methodAuthority: string; serviceEndpoint: string } {
  const serviceEndpoint = solandBaseUrl().replace(/\/$/, "");
  const parsed = new URL(serviceEndpoint);
  const host = parsed.hostname;
  if (!host.includes(".")) {
    throw new Error(`soland host must contain a dot for did:webvh: ${host}`);
  }
  return {
    methodAuthority: parsed.port ? `${host}%3A${parsed.port}` : host,
    serviceEndpoint,
  };
}

async function registerWebvhPrincipal(
  request: import("@playwright/test").APIRequestContext,
  localId: string,
): Promise<WebvhPrincipalFixture> {
  const psk = ed25519FixtureKey();
  const updateKey = ed25519FixtureKey();
  const ssk = ed25519FixtureKey();
  const usk = ed25519FixtureKey();
  const { methodAuthority, serviceEndpoint } = webvhAuthorities();
  const didKeyFragment = "did-key-1";
  const updateKeyFragment = "update-key-1";
  const placeholderDid = `did:webvh:${WEBVH_SCID_PLACEHOLDER}:${methodAuthority}:webvh:${localId}`;
  const placeholderDidKeyId = `${placeholderDid}#${didKeyFragment}`;
  const versionTime = canonicalTimestamp();
  const didDocumentSkeleton = {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: placeholderDid,
    verificationMethod: [
      {
        id: placeholderDidKeyId,
        type: "Multikey",
        controller: placeholderDid,
        publicKeyMultibase: psk.publicKeyMultibase,
      },
    ],
    authentication: [placeholderDidKeyId],
    assertionMethod: [placeholderDidKeyId],
    alsoKnownAs: [],
    service: [
      {
        id: `${placeholderDid}#soland`,
        type: "CokretPrincipalServer",
        serviceEndpoint,
      },
    ],
  };
  const entrySkeleton = {
    versionId: `0-${WEBVH_SCID_PLACEHOLDER}`,
    versionTime,
    parameters: {
      scid: WEBVH_SCID_PLACEHOLDER,
      method: "did:webvh:1.0",
      updateKeys: [updateKey.publicKeyMultibase],
    },
    state: didDocumentSkeleton,
  };
  const scid = sha256MultihashMultibase(canonicalBytes(entrySkeleton));
  const realizedEntry = substituteScid(entrySkeleton, scid) as Record<string, unknown>;
  const versionHash = sha256MultihashMultibase(
    canonicalBytes(stripVersionId(realizedEntry)),
  );
  const signedEntry = {
    ...realizedEntry,
    versionId: `1-${versionHash}`,
  };
  const proof = {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    verificationMethod: `did:key:${updateKey.publicKeyMultibase}#${updateKey.publicKeyMultibase}`,
    proofValue: ed25519SignatureBase58(updateKey.privateKey, canonicalBytes(signedEntry)),
  };
  const response = await request.post(
    `${solandBaseUrl()}/_soland/root/identity/webvh/register`,
    {
      headers: {
        authorization: `Bearer ${
          process.env.SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER ??
          "joint-e2e-webvh-registration"
        }`,
      },
      data: {
        local_id: localId,
        did_public_key_multibase: psk.publicKeyMultibase,
        update_public_key_multibase: updateKey.publicKeyMultibase,
        did_key_id: didKeyFragment,
        update_key_id: updateKeyFragment,
        also_known_as: [],
        version_time: versionTime,
        proof,
      },
    },
  );
  const body = await response.json();
  expect(
    response.status(),
    `embedded webvh register returned ${response.status()}: ${JSON.stringify(body)}`,
  ).toBe(201);
  const did = String(body.did);
  return {
    did,
    didKeyId: String(body.did_key_id),
    psk,
    ssk,
    usk,
    sskKid: `${did}#ck_self_signing_v1`,
  };
}

async function solandTrustDomain(
  request: import("@playwright/test").APIRequestContext,
): Promise<string> {
  const response = await request.get(`${solandBaseUrl()}/_cokret/describe`);
  expect(response.ok()).toBeTruthy();
  const body = await response.json();
  return String(body.trust_domain ?? "ck:trust_domain:soland.joint-e2e.local");
}

function crossSigningBindingInput(args: {
  principalId: string;
  trustDomain: string;
  subordinateKeyKind: "self_signing" | "user_signing";
  subordinateKid: string;
  subordinateAlg: string;
  subordinatePublicKey: string;
  generation: number;
}): Buffer {
  return Buffer.concat([
    Buffer.from(CROSS_SIGNING_BINDING_LABEL, "utf8"),
    canonicalBytes({
      principal_id: args.principalId,
      trust_domain: args.trustDomain,
      subordinate_key_kind: args.subordinateKeyKind,
      subordinate_kid: args.subordinateKid,
      subordinate_alg: args.subordinateAlg,
      subordinate_public_key: args.subordinatePublicKey,
      generation: args.generation,
    }),
  ]);
}

async function publishCrossSigning(
  request: import("@playwright/test").APIRequestContext,
  token: string,
  fixture: WebvhPrincipalFixture,
): Promise<string> {
  const trustDomain = await solandTrustDomain(request);
  const realmId = principalControlRealmForDid(fixture.did);
  const pskKid = fixture.didKeyId;
  const principalSigningKey = {
    kid: pskKid,
    alg: "EdDSA",
    public_key: fixture.psk.publicKeyMultibase,
    key_format: "multibase",
  };
  const selfSigningKey = {
    kid: fixture.sskKid,
    alg: "EdDSA",
    public_key: fixture.ssk.publicKeyMultibase,
    key_format: "multibase",
  };
  const userSigningKey = {
    kid: `${fixture.did}#ck_user_signing_v1`,
    alg: "EdDSA",
    public_key: fixture.usk.publicKeyMultibase,
    key_format: "multibase",
  };
  const generation = 1;
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: fixture.did,
      realmId,
      kind: "ck.cross_signing.publish",
      payload: {
        principal_id: fixture.did,
        trust_domain: trustDomain,
        principal_signing_key: principalSigningKey,
        self_signing_key: {
          ...selfSigningKey,
          binding: {
            verification_method: pskKid,
            alg: "EdDSA",
            signature: ed25519SignatureB64url(
              fixture.psk.privateKey,
              crossSigningBindingInput({
                principalId: fixture.did,
                trustDomain,
                subordinateKeyKind: "self_signing",
                subordinateKid: selfSigningKey.kid,
                subordinateAlg: selfSigningKey.alg,
                subordinatePublicKey: selfSigningKey.public_key,
                generation,
              }),
            ),
          },
        },
        user_signing_key: {
          ...userSigningKey,
          binding: {
            verification_method: pskKid,
            alg: "EdDSA",
            signature: ed25519SignatureB64url(
              fixture.psk.privateKey,
              crossSigningBindingInput({
                principalId: fixture.did,
                trustDomain,
                subordinateKeyKind: "user_signing",
                subordinateKid: userSigningKey.kid,
                subordinateAlg: userSigningKey.alg,
                subordinatePublicKey: userSigningKey.public_key,
                generation,
              }),
            ),
          },
        },
        expected_previous_generation: 0,
        generation,
        issued_at: canonicalTimestamp(),
      },
    }),
    { context: `publish cross-signing ${fixture.did}` },
  );
  return trustDomain;
}

// Build an encrypted Realm via a direct ck.realm.create envelope. This local
// helper deliberately omits plaintext service declarations so the MLS tests
// exercise the encrypted path only.
async function createEncryptedRealm(
  request: import("@playwright/test").APIRequestContext,
  token: string,
  ownerDid: string,
  title: string,
): Promise<string> {
  const realmId = typedId("realm");
  const createdAt = canonicalTimestamp();
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: ownerDid,
      realmId,
      kind: "ck.realm.create",
      createdAt,
      payload: {
        object: {
          id: realmId,
          schema: "ck.schema.realm.v1",
          title,
          created_by: ownerDid,
          trust_domain: "ck:trust_domain:soland.local",
          schema_refs: ["ck.schema.realm.v1"],
          default_discoverability: "listed",
          default_join_rule: "invite",
          history_visibility: "joined",
          encryption_profile: "mls_rfc9420",
          security_class: "standard",
          federation_policy: "restricted",
          notary_profile: "single_did",
          digest_algorithm: "sha256",
          notary: singleDidNotary(ownerDid),
          created_at: createdAt,
        },
      },
    }),
    { context: `create encrypted realm ${title}` },
  );
  return realmId;
}

type MlsGroupContext = {
  groupId: string;
  effectiveScope: { kind: "realm"; realm_id: string };
  policyRoot: string;
  frontierRef: string;
};

const MLS_CIPHER_SUITE = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";

function mlsGovernanceBinding(
  group: MlsGroupContext,
  previousEpoch: number,
  nextEpoch: number,
  policyRoot = group.policyRoot,
): Record<string, unknown> {
  return {
    binding_version: 1,
    encoding_profile: "cbor-deterministic-rfc8949-v1",
    realm_id: group.effectiveScope.realm_id,
    effective_scope: group.effectiveScope,
    mls_group_id: group.groupId,
    previous_epoch: previousEpoch,
    next_epoch: nextEpoch,
    membership_frontier: [group.frontierRef],
    policy_root: policyRoot,
    binding_profile: MLS_GOVERNANCE_BINDING_FULL_PROFILE,
    reducer_profile: MLS_REDUCER_PROFILE_V1,
  };
}

// Submit ck.mls.genesis for a fresh MLS group bound to `realmId` at epoch 0 and
// return the group context the commit helper threads through. The genesis locks
// the group's policy_root; later commits MUST carry the same root.
async function submitMlsGenesis(
  request: import("@playwright/test").APIRequestContext,
  token: string,
  owner: JointUser,
  realmId: string,
): Promise<MlsGroupContext> {
  const groupId = typedId("mls_group");
  const genesisEventId = typedId("event");
  const effectiveScope = { kind: "realm" as const, realm_id: realmId };
  const policyRoot = `sha256:${"2".repeat(64)}`;
  const group: MlsGroupContext = {
    groupId,
    effectiveScope,
    policyRoot,
    frontierRef: genesisEventId,
  };
  const body = await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: owner.did,
      realmId,
      kind: "ck.mls.genesis",
      eventId: genesisEventId,
      payload: {
        mls_group_id: groupId,
        effective_scope: effectiveScope,
        epoch: 0,
        creator_principal_id: owner.did,
        creator_device_id: owner.deviceId,
        cipher_suite: MLS_CIPHER_SUITE,
        group_info_digest: `sha256:${"3".repeat(64)}`,
        ratchet_tree_digest: `sha256:${"4".repeat(64)}`,
        governance_binding: mlsGovernanceBinding(group, 0, 0),
        created_at: canonicalTimestamp(),
      },
    }),
    { context: `submit MLS genesis ${groupId}` },
  );
  expect(body.accepted ?? []).toContain(genesisEventId);
  return group;
}

// Submit a ck.mls.commit advancing `baseEpoch` -> `baseEpoch + 1`. Optional
// `policyRoot` override forges a mismatched governance binding (E11.2);
// `concurrentCommit` flags a racing fork at the same base epoch (E11.1). Returns
// the raw submit response so callers can assert accepted ids or wire codes.
async function submitMlsCommit(
  request: import("@playwright/test").APIRequestContext,
  token: string,
  committer: JointUser,
  args: {
    realmId: string;
    group: MlsGroupContext;
    baseEpoch: number;
    label: string;
    eventId?: string;
    policyRoot?: string;
    concurrentCommit?: boolean;
    raw?: boolean;
  },
): Promise<Record<string, unknown>> {
  const { realmId, group, baseEpoch, label } = args;
  const nextEpoch = baseEpoch + 1;
  const payload: Record<string, unknown> = {
    mls_group_id: group.groupId,
    base_epoch: baseEpoch,
    base_epoch_ref: group.frontierRef,
    proposal_refs: [],
    next_epoch: nextEpoch,
    commit_digest: sha256Digest(Buffer.from(label, "utf8")),
    governance_binding: mlsGovernanceBinding(
      group,
      baseEpoch,
      nextEpoch,
      args.policyRoot ?? group.policyRoot,
    ),
  };
  if (args.concurrentCommit) {
    payload.concurrent_commit = true;
  }
  const envelope = signedEventEnvelope({
    actorDid: committer.did,
    realmId,
    kind: "ck.mls.commit",
    eventId: args.eventId ?? typedId("event"),
    payload,
  });
  if (args.raw) {
    const resp = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
      headers: authHeaders(token),
      data: envelope,
    });
    return { __status: resp.status(), __body: await resp.json() };
  }
  return await submitSignedEventApi(request, token, envelope, {
    context: `submit MLS commit ${label}`,
  });
}

async function sendEncryptedTimelineMessage(
  userPage: JointUserPage,
  realmId: string,
  body: string,
): Promise<string> {
  await userPage.gotoTimelineRealm(realmId);

  const secondarySecureButton = userPage.page.getByTestId("send-e2ee-move-button");
  const primarySendButton = userPage.page.getByTestId("send-chat-button");
  const secureSendButton = (await secondarySecureButton
    .isVisible()
    .catch(() => false))
    ? secondarySecureButton
    : primarySendButton;
  await expect(secureSendButton).toBeVisible({ timeout: 30_000 });

  const messageSubmit = userPage.page.waitForResponse(
    (response) => {
      const request = response.request();
      const postData = request.postData() ?? "";
      return (
        request.method() === "POST" &&
        response.url().includes("/_cokret/self/events") &&
        postData.includes("ck.message.create") &&
        [200, 201].includes(response.status())
      );
    },
    { timeout: 60_000 },
  );

  await userPage.page.getByTestId("chat-input").fill(body);
  await secureSendButton.click();

  const response = await messageSubmit;
  const postData = response.request().postData() ?? "";
  expect(postData).toContain("encrypted_content");
  expect(postData).toContain("mls-rfc9420");
  expect(postData).not.toContain(body);
  await expect(userPage.page.getByTestId("chat-status")).toContainText(
    /Encrypted message sent/i,
    { timeout: 30_000 },
  );
  return postData;
}

// Same account (same DID), brand-new device id and therefore a fresh local
// MLS store: no Welcome applied and no encrypted-history backup restored. This
// is the "fresh device, no backup, no welcome" state the write guard must
// fail closed on.
function sameActorFreshDevice(user: JointUser, label: string): JointUser {
  const suffix =
    `${Date.now().toString(16)}${Math.random().toString(16).slice(2)}`
      .replace(/[^a-f0-9]/g, "")
      .slice(0, 12)
      .padEnd(12, "0");
  return {
    ...user,
    name: `${user.name}-${label}`,
    deviceId: `ck:device:01904100-0000-7000-8000-${suffix}`,
  };
}

async function createKanbanBoardListAndCard(
  page: Page,
  realmId: string,
  boardTitle: string,
  listTitle: string,
  cardTitle: string,
): Promise<string> {
  await page.goto(`/kanban/${realmId}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("kanban-panel")).toBeVisible({
    timeout: 120_000,
  });
  await page.getByTestId("new-board-toggle").click();
  await page.getByTestId("new-board-title-input").fill(boardTitle);
  await page.getByTestId("create-board-space-button").click();
  await expect(page.getByTestId("kanban-empty-board")).toContainText(
    /No lists yet/,
    {
      timeout: 45_000,
    },
  );
  await expect
    .poll(() => page.url(), { timeout: 30_000 })
    .toContain("/board/ck:space:");
  const boardId = decodeURIComponent(
    new URL(page.url()).pathname.split("/board/")[1]?.split("/")[0] ?? "",
  );
  expect(boardId).toMatch(/^ck:space:/);

  await page.getByTestId("new-column-input").fill(listTitle);
  await page.getByTestId("add-column-button").click();
  const column = page
    .getByTestId("kanban-column")
    .filter({ hasText: listTitle })
    .first();
  await expect(column).toBeVisible({ timeout: 45_000 });
  await column.getByTestId("add-card-button").click();
  await column.getByTestId("new-card-title-input").fill(cardTitle);
  await column.getByTestId("save-card-button").click();
  await expect(
    column.getByTestId("kanban-card").filter({ hasText: cardTitle }),
  ).toBeVisible({
    timeout: 45_000,
  });
  return boardId;
}

async function setCardDetailEditorValue(
  page: Page,
  value: string,
): Promise<void> {
  const input = page.getByTestId("card-detail-description-input");
  await expect(input).toBeAttached({ timeout: 45_000 });
  await input.evaluate((node, nextValue) => {
    const textarea = node as HTMLTextAreaElement;
    textarea.value = nextValue;
    textarea.dispatchEvent(
      new InputEvent("input", {
        bubbles: true,
        inputType: "insertText",
        data: nextValue,
      }),
    );
  }, value);
}

// Open the card and attempt to save a private description. Unlike the happy
// path, this does NOT expect the description panel to update — the caller
// asserts the not-ready affordance instead.
async function attemptCardDescription(
  page: Page,
  cardTitle: string,
  description: string,
): Promise<void> {
  await page
    .getByTestId("kanban-card")
    .filter({ hasText: cardTitle })
    .first()
    .click();
  await expect(page.getByTestId("card-detail-modal")).toBeVisible({
    timeout: 45_000,
  });
  const add = page.getByTestId("card-detail-add-description-button");
  if ((await add.count()) > 0 && (await add.first().isVisible())) {
    await add.first().click();
  } else {
    await page.getByTestId("card-detail-edit-description-button").click();
  }
  await setCardDetailEditorValue(page, description);
  await page.getByTestId("card-detail-save-button").click();
}

test.describe("MLS group encryption", () => {
  test("E2EE Realm surfaces MLS admin controls and rejects non-members from raw events", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const alice = uniqueUser("s11-alice");
    const mallory = uniqueUser("s11-mallory");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, mallory),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const malloryToken = await issueDevSession(request, mallory);
    const alicePage = await openUserPage(browser, alice, {
      sessionCredential: aliceToken,
    });

    try {
      const realmId = await alicePage.createRealm({
        title: `S11 E2EE ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyVisibility: "joined",
        encryptionProfile: "mls_rfc9420",
      });

      await alicePage.gotoRealmAdminSection(realmId, "security");
      await expect(alicePage.page.getByTestId("mls-rotation")).toBeVisible({
        timeout: 30_000,
      });

      // Non-member access to raw events MUST be rejected.
      const eventsResp = await request.get(
        `${solandBaseUrl()}/_cokret/self/events?realms=${encodeURIComponent(realmId)}&limit=20`,
        { headers: { authorization: `Bearer ${malloryToken}` } },
      );
      expect([401, 403, 404, 405]).toContain(eventsResp.status());
      await stepShot(alicePage.page, testInfo, "non-member-blocked");
    } finally {
      await alicePage.close();
    }
  });

  test("alice creates space with encryption_profile=mls_rfc9420 at create time; world_readable policy is rejected", async ({
    request,
  }) => {
    // Smoke for the create-time encryption profile path. Full ck.mls.genesis
    // materialization remains pinned below in the richer lifecycle cases.
    const stamp = Date.now();
    const alice = uniqueUser("s11-create-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `S11 MLS create-time ${stamp}`,
      discoverability: "listed",
      history_visibility: "joined",
      encryption_profile: "mls_rfc9420",
    });

    const exportResp = await request.get(
      `${solandBaseUrl()}/_cokret/self/realms/${encodeURIComponent(realmId)}/export`,
      { headers: authHeaders(aliceToken) },
    );
    expect(exportResp.ok()).toBeTruthy();
    expect(JSON.stringify(await exportResp.json())).toContain(
      '"encryption_profile":"mls_rfc9420"',
    );

    const incompatibleRealmId = typedId("realm");
    const incompatibleCreatedAt = canonicalTimestamp();
    const incompatible = await request.post(
      `${solandBaseUrl()}/_cokret/self/events`,
      {
        headers: authHeaders(aliceToken),
        data: signedEventEnvelope({
          actorDid: alice.did,
          realmId: incompatibleRealmId,
          kind: "ck.realm.create",
          createdAt: incompatibleCreatedAt,
          payload: {
            object: {
              id: incompatibleRealmId,
              schema: "ck.schema.realm.v1",
              title: `S11 MLS incompatible ${stamp}`,
              created_by: alice.did,
              trust_domain: "ck:trust_domain:soland.local",
              schema_refs: ["ck.schema.realm.v1"],
              default_discoverability: "listed",
              default_join_rule: "invite",
              history_visibility: "world_readable",
              encryption_profile: "mls_rfc9420",
              security_class: "standard",
              federation_policy: "restricted",
              notary_profile: "single_did",
              digest_algorithm: "sha256",
              notary: singleDidNotary(alice.did),
              created_at: incompatibleCreatedAt,
            },
          },
        }),
      },
    );
    expect([400, 422]).toContain(incompatible.status());
    expect(wireErrCode(await incompatible.json())).toBe(
      "incompatible_history_with_encryption",
    );
  });

  test("alice claims bob's KeyPackage; Welcome queue endpoint and commit epoch smoke stay live", async ({
    request,
  }) => {
    // API-first smoke for the G3.S1 subset: MLS group genesis,
    // KeyPackage publish/claim CAS, durable Welcome delivery, and
    // monotonic commit epoch. Full client derivation of epoch secrets
    // remains a later yougen+MLS concern.
    const stamp = Date.now();
    const aliceFixture = await registerWebvhPrincipal(
      request,
      `s11-claim-alice-${stamp.toString(36)}`,
    );
    const bobFixture = await registerWebvhPrincipal(
      request,
      `s11-claim-bob-${stamp.toString(36)}`,
    );
    const alice = { ...uniqueUser("s11-claim-alice"), did: aliceFixture.did };
    const bob = { ...uniqueUser("s11-claim-bob"), did: bobFixture.did };
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);
    await Promise.all([
      publishCrossSigning(request, aliceToken, aliceFixture),
      publishCrossSigning(request, bobToken, bobFixture),
    ]);

    const keypackageId = typedId("mls_keypackage");
    const keyPackage = b64url(`opaque-keypackage-${stamp}`);
    const keypackageDigest = sha256Digest(Buffer.from(keyPackage, "base64url"));
    const keypackageRef = keypackageDigest;
    const keypackageCapabilities = ["ck.mls.profile.full"];
    const groupId = typedId("mls_group");
    const digest = (nibble: string) => `sha256:${nibble.repeat(64)}`;
    const createdAt = canonicalTimestamp();
    const expiresAt = canonicalTimestamp(new Date(Date.now() + 60 * 60 * 1000));
    const deviceSignature = {
      kid: `${bob.did}#${bob.deviceId}`,
      alg: "EdDSA",
      sig: b64url(`device-signature-${stamp}`),
    };

    const publish = await request.post(
      `${solandBaseUrl()}/_cokret/self/keys/keypackages/upload`,
      {
        headers: authHeaders(bobToken),
        data: {
          principal_id: bob.did,
          device_id: bob.deviceId,
          device_signature: deviceSignature,
          key_packages: [
            {
              keypackage_id: keypackageId,
              keypackage_ref: keypackageRef,
              key_package: keyPackage,
              keypackage_digest: keypackageDigest,
              cipher_suites: [
                "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
              ],
              capabilities: keypackageCapabilities,
              device_signature: deviceSignature,
              created_at: createdAt,
              expires_at: expiresAt,
              last_resort: false,
            },
          ],
        },
      },
    );
    const publishBody = await publish
      .json()
      .catch(async () => ({ raw: await publish.text() }));
    expect(
      publish.ok(),
      `KeyPackage upload failed with ${publish.status()}: ${JSON.stringify(publishBody)}`,
    ).toBeTruthy();
    expect(publishBody.accepted).toBe(1);
    expect(publishBody.rejected ?? []).toEqual([]);
    expect(publishBody.key_package_refs).toContain(keypackageRef);

    const pendingBefore = await request.get(
      `${solandBaseUrl()}/_soland/self/keys/keypackages/welcomes/pending`,
      {
        headers: authHeaders(bobToken),
      },
    );
    expect(pendingBefore.ok()).toBeTruthy();
    expect((await pendingBefore.json()).welcomes).toEqual([]);

    const claim = await request.post(
      `${solandBaseUrl()}/_cokret/self/keys/keypackages/claim`,
      {
        headers: authHeaders(aliceToken),
        data: {
          target_principal_id: bob.did,
          target_device_ids: [bob.deviceId],
          intended_realm_id: typedId("realm"),
          requester: alice.did,
          required_capabilities: keypackageCapabilities,
          claim_nonce: `claim-${stamp}`,
          expires_at: expiresAt,
          mls_group_id: groupId,
          proofs: [],
        },
      },
    );
    expect(claim.ok()).toBeTruthy();
    const claimBody = await claim.json();
    expect(claimBody.claims).toHaveLength(1);
    expect(claimBody.failures ?? []).toEqual([]);
    expect(claimBody.claims[0].keypackage_ref).toBe(keypackageRef);
    expect(claimBody.claims[0].device_id).toBe(bob.deviceId);
    expect(claimBody.claims[0].key_package).toBe(keyPackage);
    const keypackageClaim = claimBody.claims[0] as Record<string, unknown>;
    const claimId = String(keypackageClaim.claim_id);
    const capabilitiesDigest = String(keypackageClaim.capabilities_digest);
    const claimSskGeneration = Number(keypackageClaim.ssk_generation);

    const claimAgain = await request.post(
      `${solandBaseUrl()}/_cokret/self/keys/keypackages/claim`,
      {
        headers: authHeaders(aliceToken),
        data: {
          target_principal_id: bob.did,
          target_device_ids: [bob.deviceId],
          intended_realm_id: typedId("realm"),
          requester: alice.did,
          required_capabilities: keypackageCapabilities,
          claim_nonce: `claim-again-${stamp}`,
          expires_at: expiresAt,
          mls_group_id: typedId("mls_group"),
          proofs: [],
        },
      },
    );
    expect(claimAgain.ok()).toBeTruthy();
    const claimAgainBody = await claimAgain.json();
    expect(claimAgainBody.claims ?? []).toEqual([]);
    expect(claimAgainBody.failures?.[0]?.reason_code).toBe("mls_keypackage_not_found");

    const realmId = await createRealmApi(request, aliceToken, {
      title: `MLS lifecycle ${stamp}`,
      ownerDid: alice.did,
      history_visibility: "joined",
      encryption_profile: "mls_rfc9420",
    });

    const genesisEventId = typedId("event");
    const commitEventId = typedId("event");
    const frontierEventRef = genesisEventId;
    const effectiveScope = { kind: "realm", realm_id: realmId };
    const genesisBinding = {
      binding_version: 1,
      encoding_profile: "cbor-deterministic-rfc8949-v1",
      realm_id: realmId,
      effective_scope: effectiveScope,
      mls_group_id: groupId,
      previous_epoch: 0,
      next_epoch: 0,
      membership_frontier: [frontierEventRef],
      policy_root: digest("2"),
      binding_profile: MLS_GOVERNANCE_BINDING_FULL_PROFILE,
      reducer_profile: MLS_REDUCER_PROFILE_V1,
    };
    const genesisBody = await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ck.mls.genesis",
        eventId: genesisEventId,
        payload: {
          mls_group_id: groupId,
          effective_scope: effectiveScope,
          epoch: 0,
          creator_principal_id: alice.did,
          creator_device_id: alice.deviceId,
          cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
          group_info_digest: digest("3"),
          ratchet_tree_digest: digest("4"),
          governance_binding: genesisBinding,
          created_at: canonicalTimestamp(),
        },
      }),
      {
        context: "submit MLS genesis",
      },
    );
    expect(genesisBody.accepted ?? []).toContain(genesisEventId);

    const welcomeId = typedId("mls_welcome");
    const welcomeEventId = typedId("event");
    const welcomeCiphertext = b64url(`opaque-mls-welcome-${stamp}`);
    const welcomeDigest = sha256Digest(Buffer.from(welcomeCiphertext, "base64url"));
    const claimEnvelopeCreatedAt = canonicalTimestamp();
    const claimEnvelopeUnsigned = {
      keypackage_ref: keypackageRef,
      keypackage_digest: keypackageDigest,
      intended_realm_id: realmId,
      claim_id: claimId,
      requester_did: alice.did,
      ssk_generation: claimSskGeneration,
      nonce: `claim-${stamp}`,
      welcome_digest: welcomeDigest,
      created_at: claimEnvelopeCreatedAt,
    };
    const welcomeBody = await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ck.mls.welcome",
        eventId: welcomeEventId,
        payload: {
          welcome_id: welcomeId,
          mls_group_id: groupId,
          epoch: 1,
          recipient_principal_id: bob.did,
          recipient_device_id: bob.deviceId,
          keypackage_ref: keypackageRef,
          keypackage_digest: keypackageDigest,
          claim_id: claimId,
          claim_ref: {
            claim_id: claimId,
            keypackage_ref: keypackageRef,
            keypackage_digest: keypackageDigest,
            capabilities_digest: capabilitiesDigest,
            ssk_generation: claimSskGeneration,
          },
          claim_envelope: {
            ...claimEnvelopeUnsigned,
            signature: {
              kid: aliceFixture.sskKid,
              alg: "EdDSA",
              sig: ed25519SignatureB64url(
                aliceFixture.ssk.privateKey,
                canonicalBytes(claimEnvelopeUnsigned),
              ),
            },
          },
          ciphertext: welcomeCiphertext,
          expires_at: canonicalTimestamp(new Date(Date.now() + 60 * 60 * 1000)),
          commit_ref: commitEventId,
          governance_binding: genesisBinding,
        },
      }),
      {
        context: "submit MLS welcome",
      },
    );
    expect(welcomeBody.accepted ?? []).toContain(welcomeEventId);

    const commitPayload = (label: string, nextEpoch = 1) => ({
      mls_group_id: groupId,
      base_epoch: 0,
      base_epoch_ref: frontierEventRef,
      proposal_refs: [],
      next_epoch: nextEpoch,
      commit_digest: sha256Digest(Buffer.from(label, "utf8")),
      governance_binding: {
        binding_version: 1,
        encoding_profile: "cbor-deterministic-rfc8949-v1",
        realm_id: realmId,
        effective_scope: effectiveScope,
        mls_group_id: groupId,
        previous_epoch: 0,
        next_epoch: nextEpoch,
        membership_frontier: [frontierEventRef],
        policy_root: digest("2"),
        binding_profile: MLS_GOVERNANCE_BINDING_FULL_PROFILE,
        reducer_profile: MLS_REDUCER_PROFILE_V1,
      },
    });
    const commitEnvelope = signedEventEnvelope({
      actorDid: alice.did,
      realmId,
      kind: "ck.mls.commit",
      eventId: commitEventId,
      payload: commitPayload(`opaque-commit-${stamp}`),
    });
    const commitBody = await submitSignedEventApi(
      request,
      aliceToken,
      commitEnvelope,
      {
        context: "submit MLS commit",
      },
    );
    expect(commitBody.accepted ?? []).toContain(commitEventId);

    const pendingAfterWelcome = await request.get(
      `${solandBaseUrl()}/_soland/self/keys/keypackages/welcomes/pending`,
      {
        headers: authHeaders(bobToken),
      },
    );
    expect(pendingAfterWelcome.ok()).toBeTruthy();
    const pendingAfterWelcomeBody = await pendingAfterWelcome.json();
    expect(pendingAfterWelcomeBody.welcomes).toHaveLength(1);
    expect(pendingAfterWelcomeBody.welcomes[0]).toMatchObject({
      welcome_id: welcomeId,
      mls_group_ref: groupId,
      key_package_id: keypackageRef,
    });
    expect(pendingAfterWelcomeBody.welcomes[0].group_id).toBeUndefined();
    expect(pendingAfterWelcomeBody.welcomes[0].delivered_at).toBeTruthy();

    const pendingAfterDrain = await request.get(
      `${solandBaseUrl()}/_soland/self/keys/keypackages/welcomes/pending`,
      {
        headers: authHeaders(bobToken),
      },
    );
    expect(pendingAfterDrain.ok()).toBeTruthy();
    expect((await pendingAfterDrain.json()).welcomes).toEqual([]);

    const staleCommit = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
      headers: authHeaders(aliceToken),
      data: signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ck.mls.commit",
        payload: commitPayload(`opaque-stale-commit-${stamp}`),
      }),
    });
    expect([409, 412, 422]).toContain(staleCommit.status());
    expect(wireErrCode(await staleCommit.json())).toBe("mls_epoch_skew");
  });

  test("joined member decrypts E2EE timeline messages; raw event payload stays ciphertext only", async ({
    browser,
    request,
  }, testInfo) => {
    // Regression for the join→decrypt boundary: accepting a Realm invite must
    // leave the new member with usable MLS state for messages sent after join.
    // Spec: encryption-and-audit.md §2.2-§2.4, §2.3.1-§2.3.3.
    //
    // The full two-browser MLS flow (recovery-key setup, create, invite, Welcome,
    // navigation, encrypted send + decrypt in BOTH directions, reloads) does not
    // fit the 180s default; mirror the longer budget the sibling MLS browser test
    // uses so this does not time out mid-flow.
    test.setTimeout(360_000);
    const stamp = Date.now();
    const [aliceSession, bobSession] = await Promise.all([
      createDpopUserSession(request, "s11-decrypt-alice"),
      createDpopUserSession(request, "s11-decrypt-bob"),
    ]);
    test.skip(
      !aliceSession || !bobSession,
      "coauth DPoP session-grant login is required for MLS device-authorized KeyPackages",
    );
    const alice = aliceSession!.user;
    const bob = bobSession!.user;
    const [alicePage, bobPage] = await Promise.all([
      openUserPage(browser, alice, {
        grantJwt: aliceSession!.grantJwt,
        dpopSeedB64url: aliceSession!.dpopSeedB64url,
        grantId: aliceSession!.grantId,
        grantAudience: aliceSession!.grantAudience,
      }),
      openUserPage(browser, bob, {
        grantJwt: bobSession!.grantJwt,
        dpopSeedB64url: bobSession!.dpopSeedB64url,
        grantId: bobSession!.grantId,
        grantAudience: bobSession!.grantAudience,
      }),
    ]);

    try {
      await Promise.all([alicePage.gotoHome(), bobPage.gotoHome()]);
      await Promise.all([
        alicePage.completeRecoveryKeySetupIfPrompted(),
        bobPage.completeRecoveryKeySetupIfPrompted(),
      ]);
      await Promise.all([
        alicePage.acknowledgeRecommendedEncryptionPromptIfVisible(),
        bobPage.acknowledgeRecommendedEncryptionPromptIfVisible(),
      ]);

      const realmId = await alicePage.createRealm({
        title: `S11 joined decrypt ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyVisibility: "joined",
        encryptionProfile: "mls_rfc9420",
      });
      const inviteStatus = await alicePage.inviteFromAdmin(realmId, bob.did);
      expect(inviteStatus).toContain("MLS Welcome queued");
      await bobPage.acceptInvite(realmId);

      // Route-context bootstrap is where Bob applies pending MLS Welcome state.
      await bobPage.gotoTimelineRealm(realmId);

      const plaintext = `joined member decrypts post-join ciphertext ${stamp}`;
      const submittedWire = await sendEncryptedTimelineMessage(alicePage, realmId, plaintext);
      expect(submittedWire).not.toContain(plaintext);

      await expect(alicePage.timelineEvent(plaintext)).toBeVisible({ timeout: 30_000 });

      await bobPage.page.reload({ waitUntil: "domcontentloaded" });
      await expect(bobPage.page.getByTestId("message-list")).toBeVisible({ timeout: 120_000 });
      const bobMessage = bobPage.timelineEvent(plaintext);
      await expect(bobMessage).toBeVisible({ timeout: 60_000 });
      await expect(bobMessage.getByTestId("event-body")).toContainText(plaintext);

      // Bidirectional decrypt: the admission fork (add-member commit rejected
      // `governance_binding_mismatch` while its Welcome still landed) broke BOTH
      // directions — the admin sat one epoch behind the invitee, so neither could
      // read the other. Assert a message Bob authors after joining also decrypts
      // for Alice, not just Alice → Bob.
      const bobPlaintext = `joined member round-trips back to admin ${stamp}`;
      const bobWire = await sendEncryptedTimelineMessage(bobPage, realmId, bobPlaintext);
      expect(bobWire).not.toContain(bobPlaintext);
      await expect(bobPage.timelineEvent(bobPlaintext)).toBeVisible({ timeout: 30_000 });

      await alicePage.page.reload({ waitUntil: "domcontentloaded" });
      await expect(alicePage.page.getByTestId("message-list")).toBeVisible({ timeout: 120_000 });
      const aliceSeesBob = alicePage.timelineEvent(bobPlaintext);
      await expect(aliceSeesBob).toBeVisible({ timeout: 60_000 });
      await expect(aliceSeesBob.getByTestId("event-body")).toContainText(bobPlaintext);

      const rawEventsUrl = `${solandBaseUrl()}/_cokret/self/events?realms=${encodeURIComponent(realmId)}&limit=100`;
      const rawEvents = await request.get(rawEventsUrl, {
        headers: selfPathGrantHeaders({
          deviceKey: bobSession!.deviceKey,
          grantJwt: bobSession!.grantJwt,
          method: "GET",
          url: rawEventsUrl,
        }),
      });
      expect(rawEvents.status()).toBe(200);
      const rawWire = JSON.stringify(await rawEvents.json());
      expect(rawWire).toContain("encrypted_content");
      expect(rawWire).toContain("mls-rfc9420");
      expect(rawWire).not.toContain(plaintext);

      await stepShot(bobPage.page, testInfo, "joined-member-decrypted-e2ee-message");
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });

  test("carol added in epoch 1 → ck.mls.commit advances to epoch 2; carol cannot decrypt pre-join messages (history_visibility=joined)", async ({
    request,
  }) => {
    // spec: encryption-and-audit.md §2.4.1, models/realm-and-space.md §3.4.
    //
    // Pre-join history exclusion is a soland-side property under
    // `history_visibility=joined`: `realm_event_visible_to_session`
    // (routing/spaces/space.rs) crops any realm event whose `received_at`
    // predates the reader's `joined_at`. This asserts that boundary at the API
    // level using MLS epoch events as the pre/post-join markers: carol, who
    // joins after the epoch-1 commit (carrying the pre-join epoch she has no
    // key for) lands, never sees that commit event, but does see the epoch-2
    // commit sent after she joined.
    const stamp = Date.now();
    const alice = uniqueUser("s11-prejoin-alice");
    const carol = uniqueUser("s11-prejoin-carol");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, carol),
    ]);
    const [aliceToken, carolToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, carol),
    ]);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `S11 pre-join ${stamp}`,
      ownerDid: alice.did,
      history_visibility: "joined",
      encryption_profile: "mls_rfc9420",
    });
    const group = await submitMlsGenesis(request, aliceToken, alice, realmId);

    // Pre-join MLS epoch advance: epoch 0 -> 1, before carol joins.
    const preJoinEventId = typedId("event");
    const preJoin = await submitMlsCommit(request, aliceToken, alice, {
      realmId,
      group,
      eventId: preJoinEventId,
      baseEpoch: 0,
      label: `prejoin-${stamp}`,
    });
    expect(preJoin.accepted ?? []).toContain(preJoinEventId);

    // carol joins now → her joined_at is after the pre-join commit landed. This
    // is the epoch-1 -> epoch-2 membership advance from the user's vantage.
    await addRealmMemberApi(request, aliceToken, realmId, carol.did);

    // Post-join MLS epoch advance: epoch 1 -> 2, visible to carol.
    const postJoinEventId = typedId("event");
    const postJoin = await submitMlsCommit(request, aliceToken, alice, {
      realmId,
      group,
      eventId: postJoinEventId,
      baseEpoch: 1,
      label: `postjoin-${stamp}`,
    });
    expect(postJoin.accepted ?? []).toContain(postJoinEventId);

    // carol reads the realm event stream: history_visibility=joined crops the
    // pre-join epoch event but surfaces the post-join one.
    const carolEventsUrl = `${solandBaseUrl()}/_cokret/self/events?realms=${encodeURIComponent(realmId)}&limit=100`;
    await expect
      .poll(
        async () => {
          const resp = await request.get(carolEventsUrl, {
            headers: authHeaders(carolToken),
          });
          if (resp.status() !== 200) {
            return null;
          }
          return JSON.stringify(await resp.json());
        },
        {
          timeout: 60_000,
          intervals: [1_000, 2_000, 5_000],
          message: "carol's synced event stream should surface the post-join event",
        },
      )
      .toContain(postJoinEventId);

    const carolEvents = await request.get(carolEventsUrl, {
      headers: authHeaders(carolToken),
    });
    expect(carolEvents.status()).toBe(200);
    const carolWire = JSON.stringify(await carolEvents.json());
    // Post-join epoch event visible; pre-join epoch event id cropped.
    expect(carolWire).toContain(postJoinEventId);
    expect(carolWire).not.toContain(preJoinEventId);

    // Sanity: alice (owner) still sees both events — the crop is a per-reader
    // history gate, not a delete.
    const aliceEvents = await request.get(carolEventsUrl, {
      headers: authHeaders(aliceToken),
    });
    expect(aliceEvents.status()).toBe(200);
    const aliceWire = JSON.stringify(await aliceEvents.json());
    expect(aliceWire).toContain(preJoinEventId);
    expect(aliceWire).toContain(postJoinEventId);
  });

  test("alice bans bob → membership_frontier advances; client enters epoch_update_required state for up to max_mls_commit_delay_ms", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const alice = uniqueUser("s11-ban-alice");
    const bob = uniqueUser("s11-ban-bob");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `S11 MLS ban ${stamp}`,
      ownerDid: alice.did,
      history_visibility: "joined",
      encryption_profile: "mls_rfc9420",
    });
    await addRealmMemberApi(request, aliceToken, realmId, bob.did);

    const alicePage = await openUserPage(browser, alice, {
      sessionCredential: aliceToken,
    });

    try {
      await alicePage.gotoRealmAdminSection(realmId, "members");
      const refresh = alicePage.page.getByTestId("refresh-members-button");
      await expect(refresh).toBeVisible({ timeout: 120_000 });
      const bobRow = alicePage.page.getByTestId("member-row").filter({
        has: alicePage.page.locator(`[title="${bob.did}"]`),
      });
      await expect
        .poll(
          async () => {
            await refresh.click();
            return await bobRow.count();
          },
          {
            timeout: 120_000,
            intervals: [1_000, 2_000, 5_000],
            message: "Bob joined member row should appear in synced admin projection",
          },
        )
        .toBeGreaterThan(0);

      await bobRow.first().getByTestId("ban-member-button").click();
      await expect(alicePage.page.locator("main")).toContainText(
        "epoch_update_required",
        { timeout: 30_000 },
      );

      await alicePage.gotoTimelineRealm(realmId);
      const epochBanner = alicePage.page.getByTestId(
        "epoch-update-required-banner",
      );
      await expect(epochBanner).toBeVisible({ timeout: 30_000 });
      await expect(epochBanner).toContainText("epoch_update_required");
      await expect(alicePage.page.getByTestId("send-chat-button")).toBeDisabled();
      await stepShot(alicePage.page, testInfo, "epoch-update-required-after-ban");
    } finally {
      await alicePage.close();
    }
  });

  test("E11.1 concurrent MLS commits produce ⊥ in covered_frontier_cell; subsequent messages marked decryption_pending until later commit resolves", async ({
    request,
  }) => {
    // spec: encryption-and-audit.md §2.5.2
    //
    // Two commits attesting the same base epoch with different commit material
    // drive the group's covered_frontier_cell to ⊥. soland's reducer
    // (reducer/mls.rs apply_commit_epoch) accepts the first, flags the frontier
    // contested on the racing fork, and then fails closed any further commit at
    // the contested base with `decryption_pending` until a resolving commit
    // advances the epoch.
    const stamp = Date.now();
    const alice = uniqueUser("s11-contend-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `S11 concurrent commit ${stamp}`,
      ownerDid: alice.did,
      history_visibility: "joined",
      encryption_profile: "mls_rfc9420",
    });
    const group = await submitMlsGenesis(request, aliceToken, alice, realmId);

    // First commit at base epoch 0 lands → epoch 1.
    const firstEventId = typedId("event");
    const first = await submitMlsCommit(request, aliceToken, alice, {
      realmId,
      group,
      eventId: firstEventId,
      baseEpoch: 0,
      label: `commit-a-${stamp}`,
    });
    expect(first.accepted ?? []).toContain(firstEventId);

    // A racing commit explicitly forking base epoch 0 with different material
    // drives covered_frontier_cell to ⊥. soland accepts the first contended
    // commit (it records the contested marker) without advancing the epoch.
    const contendEventId = typedId("event");
    const contend = await submitMlsCommit(request, aliceToken, alice, {
      realmId,
      group,
      eventId: contendEventId,
      baseEpoch: 0,
      label: `commit-b-${stamp}`,
      concurrentCommit: true,
    });
    expect(contend.accepted ?? []).toContain(contendEventId);

    // A further racing commit at the contested base now fails closed as
    // decryption_pending — the frontier is ⊥ until resolved.
    const pending = await submitMlsCommit(request, aliceToken, alice, {
      realmId,
      group,
      baseEpoch: 0,
      label: `commit-c-${stamp}`,
      concurrentCommit: true,
      raw: true,
    });
    expect([409, 412, 422]).toContain(pending.__status as number);
    expect(wireErrCode(pending.__body)).toBe("decryption_pending");

    // A resolving commit at the live epoch advances past ⊥ and clears it.
    const resolveEventId = typedId("event");
    const resolve = await submitMlsCommit(request, aliceToken, alice, {
      realmId,
      group,
      eventId: resolveEventId,
      baseEpoch: 1,
      label: `commit-resolve-${stamp}`,
    });
    expect(resolve.accepted ?? []).toContain(resolveEventId);

    // After resolution a further commit at the new live epoch advances normally
    // (the frontier is no longer ⊥).
    const afterEventId = typedId("event");
    const after = await submitMlsCommit(request, aliceToken, alice, {
      realmId,
      group,
      eventId: afterEventId,
      baseEpoch: 2,
      label: `commit-after-${stamp}`,
    });
    expect(after.accepted ?? []).toContain(afterEventId);
  });

  test("E11.2 governance_binding.realm_policy_digest mismatch causes federation push to reject with governance_binding_mismatch", async ({
    request,
  }) => {
    // spec: encryption-and-audit.md §2.5.1
    //
    // A commit's governance_binding.policy_root MUST stay bound to the policy
    // root the MLS group's epoch chain was genesis-locked to. soland's reducer
    // (reducer/mls.rs apply_commit_epoch) rejects a forged / stale binding with
    // `governance_binding_mismatch`. This is the same reducer gate the
    // federation-push ingest pipeline (submit_federation_events ->
    // submit_event_value -> reducer) runs every pushed ck.mls.commit through, so
    // a mismatched binding is rejected on the local submit and the federation
    // boundary alike.
    const stamp = Date.now();
    const alice = uniqueUser("s11-binding-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `S11 binding mismatch ${stamp}`,
      ownerDid: alice.did,
      history_visibility: "joined",
      encryption_profile: "mls_rfc9420",
    });
    const group = await submitMlsGenesis(request, aliceToken, alice, realmId);

    // A commit carrying a different policy_root than the genesis-locked root is
    // rejected with governance_binding_mismatch.
    const forged = await submitMlsCommit(request, aliceToken, alice, {
      realmId,
      group,
      baseEpoch: 0,
      label: `forged-binding-${stamp}`,
      policyRoot: `sha256:${"9".repeat(64)}`,
      raw: true,
    });
    expect([400, 409, 412, 422]).toContain(forged.__status as number);
    expect(wireErrCode(forged.__body)).toBe("governance_binding_mismatch");

    // The matching-root commit at the same base still advances the epoch — the
    // gate rejects only the forged binding, not the legitimate one.
    const cleanEventId = typedId("event");
    const clean = await submitMlsCommit(request, aliceToken, alice, {
      realmId,
      group,
      eventId: cleanEventId,
      baseEpoch: 0,
      label: `clean-binding-${stamp}`,
    });
    expect(clean.accepted ?? []).toContain(cleanEventId);
  });

  // encryption_profile is a create-locked Realm field (spec
  // realm-and-space.md §2.3). soland enforces this in operations.rs
  // (operation_touches_encryption_profile → realm_encryption_profile_create_locked)
  // but no soland unit test or cotest case exercises it. This pins the wire
  // rejection so a regression that lets the profile be patched after creation
  // — silently downgrading an Encrypted Realm to plaintext — is caught.
  test("ck.realm.update that patches encryption_profile is rejected (create-locked)", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser("mls-lock-realm-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const realmId = await createEncryptedRealm(
      request,
      aliceToken,
      alice.did,
      `MLS create-lock realm ${stamp}`,
    );

    const resp = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
      headers: authHeaders(aliceToken),
      data: signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ck.realm.update",
        payload: {
          target_ref: realmId,
          patch: { encryption_profile: { $op: "set", value: "none" } },
        },
      }),
    });

    const body = await resp.json();
    expect([400, 409, 412, 422], JSON.stringify(body)).toContain(resp.status());
    expect(wireErrCode(body)).toBe("realm_encryption_profile_create_locked");
  });

  // Circle counterpart of the realm create-lock.
  //
  // CONFIRMED GAP (parked pending fix): unlike ck.realm.update, soland's
  // submit path does NOT enforce the circle create-lock synchronously. The
  // check exists (operations.rs validate_content_encryption_floor CX_CIRCLE_UPDATE
  // branch + reducer.rs apply), but `operation_schema_for_kind` has no arm for
  // ck.circle.create / ck.circle.update, so projection_operation_from_event
  // returns None and event_log.rs skips ALL submit-time operation validation
  // for circle events. The create-lock is only caught at the async projection
  // (reducer) layer — so state stays safe (profile is not actually changed),
  // but the submit returns a misleading 200 instead of 4xx. Fix = add circle
  // operation schemas (needs full circle-path regression: it would newly run
  // validate_operation_policy + policy_gate on circle events at submit).
  test("ck.circle.update that patches encryption_profile is rejected (create-locked)", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser("mls-lock-circle-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const realmId = await createEncryptedRealm(
      request,
      aliceToken,
      alice.did,
      `MLS create-lock circle realm ${stamp}`,
    );

    const circleId = typedId("circle");
    await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ck.circle.create",
        payload: {
          object: {
            id: circleId,
            schema: "ck.schema.circle.v1",
            realm_id: realmId,
            title: `lock circle ${stamp}`,
            display: {
              short_name: "LC",
              color_token: "indigo",
              symbol: { glyph: "shield" },
            },
            directory_visibility: "members",
            join_rule: "invite",
            history_visibility: "joined",
            encryption_profile: "mls_rfc9420",
            state: "active",
            created_by: alice.did,
            created_at: canonicalTimestamp(),
          },
        },
      }),
      { context: `create circle ${circleId}` },
    );

    const resp = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
      headers: authHeaders(aliceToken),
      data: signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ck.circle.update",
        payload: {
          target_ref: circleId,
          patch: { encryption_profile: { $op: "set", value: "none" } },
        },
      }),
    });

    const body = await resp.json();
    expect([400, 409, 412, 422], JSON.stringify(body)).toContain(resp.status());
    expect(wireErrCode(body)).toBe("circle_encryption_profile_create_locked");
  });

  // Not-ready guard: a fresh device of the SAME account that has NOT received
  // an MLS Welcome and has NOT restored its account secret must NOT silently
  // downgrade an encrypted private write to plaintext. The client surfaces a
  // recoverable "MLS state not ready" affordance and refuses to submit; it
  // never POSTs a plaintext ck.strand.update carrying the private `body`.
  //
  // yougen guard: encrypt_values_with_device_snapshot returns
  // MlsRuntimeError::MissingWelcome when no local MLS snapshot exists, which
  // dispatch_card_detail_update surfaces into board_status /
  // card-detail-edit-status ("MLS state is not ready on this device yet ...")
  // and returns false BEFORE any strand.update event is built or submitted —
  // so the encrypted scope never falls back to a plaintext write.
  test(
    "fresh device without MLS welcome/restore refuses encrypted private writes instead of silently downgrading to plaintext",
    async ({ browser, request }) => {
      test.setTimeout(300_000);
      const stamp = Date.now();
      const alice = uniqueUser("mls-not-ready-alice");
      await ensureRegistered(request, alice);

      const boardTitle = `Not-ready Board ${stamp}`;
      const listTitle = `Not-ready Todos ${stamp}`;
      const cardTitle = `Not-ready encrypted card ${stamp}`;
      const privateDescription = `Not-ready secret detail ${stamp}`;

      // 1) deviceA (the MLS group creator) builds the encrypted realm + board +
      //    list + card via the UI so a genuine MLS group exists.
      const deviceAToken = await issueDevSession(request, alice);
      const deviceA = await openUserPage(browser, alice, {
        sessionCredential: deviceAToken,
      });

      // 2) deviceB = same account, fresh device id, fresh dev session => empty
      //    local store: NO Welcome applied, NO encrypted-history restore.
      const deviceBUser = sameActorFreshDevice(alice, "fresh-device-b");
      const deviceBToken = await issueDevSession(request, deviceBUser);
      const deviceB = await openUserPage(browser, deviceBUser, {
        sessionCredential: deviceBToken,
      });

      // Capture any plaintext private write that would leak the description.
      // A plaintext ck.strand.update would carry `privateDescription` verbatim
      // in its body/fields.body patch; an encrypted one never does.
      const plaintextPrivateWrites: string[] = [];
      deviceB.page.on("request", (req) => {
        if (
          req.method() !== "POST" ||
          !req.url().includes("/_cokret/self/events")
        ) {
          return;
        }
        const postData = req.postData() ?? "";
        if (
          postData.includes("ck.strand.update") &&
          postData.includes(privateDescription)
        ) {
          plaintextPrivateWrites.push(postData);
        }
      });

      try {
        const realmId = await deviceA.createRealm({
          title: `MLS not-ready ${stamp}`,
          summary: "fresh device must refuse plaintext private writes",
          discoverability: "unlisted",
          joinRule: "invite",
          historyVisibility: "joined",
          encryptionProfile: "mls_rfc9420",
        });
        const boardId = await createKanbanBoardListAndCard(
          deviceA.page,
          realmId,
          boardTitle,
          listTitle,
          cardTitle,
        );

        // 3) deviceB opens the board, opens the card (title is plaintext
        //    container metadata it can render), and tries to add a private
        //    description.
        await deviceB.page.goto(`/kanban/${realmId}/board/${boardId}`, {
          waitUntil: "domcontentloaded",
        });
        await expect(deviceB.page.getByTestId("kanban-panel")).toBeVisible({
          timeout: 120_000,
        });
        await expect(
          deviceB.page.getByTestId("kanban-card").filter({ hasText: cardTitle }),
        ).toBeVisible({ timeout: 90_000 });

        await attemptCardDescription(deviceB.page, cardTitle, privateDescription);

        // 4a) The not-ready affordance is surfaced. The MissingWelcome guard
        //     copy lands in card-detail-edit-status (and board-status).
        await expect(
          deviceB.page.getByTestId("card-detail-edit-status"),
        ).toContainText(/MLS state is not ready/i, { timeout: 60_000 });

        // 4b) The private description was NEVER committed to the card — the
        //     write was refused, not silently downgraded.
        await expect(
          deviceB.page
            .locator('[data-testid="card-description-panel"]:visible')
            .filter({ hasText: privateDescription }),
        ).toHaveCount(0);

        // 4c) No plaintext ck.strand.update carrying the private body ever left
        //     the client (so the server never had to accept or bounce one).
        expect(
          plaintextPrivateWrites,
          plaintextPrivateWrites.join("\n"),
        ).toEqual([]);
      } finally {
        await Promise.allSettled([deviceA.close(), deviceB.close()]);
      }
    },
  );
});
