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
import { coauthBaseUrl, solandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  alignSignedEventToActorFrontierApi,
  authHeaders,
  base64url,
  canonicalJson,
  canonicalTimestamp,
  addRealmMemberApi,
  createRealmApi,
  principalControlRealmForDid,
  queryRealmEventsApi,
  registerEventSigner,
  singleDidNotary,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
  wireErrCode,
  wireErrReason,
} from "../../helpers/soland-api";
import { ed25519PrivateKeySeedB64url } from "../../helpers/encoding";
import {
  buildDeviceCrossSigningBinding,
  buildDevicePossessionSignature,
  generateCrossSigningKey,
  TEST_DEVICE_ALGORITHMS,
  type CrossSigningIdentity,
  type CrossSigningKey,
} from "../../helpers/cross-signing-harness";
import {
  assertJointStackNotRequired,
  createDpopUserSession,
  ensureRegistered,
  issueDevSession,
  openDpopUserPage,
  openDpopUserPageForAccount,
  openUserPage,
  type JointUser,
  type JointUserPage,
  uniqueUser,
} from "../../helpers/users";
import { selfPathGrantHeaders } from "../../helpers/session-grant-dpop";
import { registerCoauthPasswordAccount } from "../../helpers/coauth-register";
import {
  buildPrincipalGenesisEntry,
  submitPrincipalGenesisEntry,
  type WebvhKey,
} from "../../helpers/webvh-api";
import { auditBrowserStorage } from "../../helpers/browser-storage-audit";

test.describe.configure({ mode: "serial" });

function sha256Digest(value: Buffer): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

const BASE58BTC_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const CROSS_SIGNING_BINDING_LABEL = "ak.cross-signing-bind-v1\n";
const MLS_GOVERNANCE_BINDING_FULL_PROFILE =
  "ak.profile.mls_governance_binding.full.v1";
const MLS_REDUCER_PROFILE_V1 = "ak.reducer.v1";

type Ed25519FixtureKey = {
  privateKey: KeyObject;
  publicKey: Buffer;
  publicKeyMultibase: string;
};

type WebvhPrincipalFixture = {
  did: string;
  principalSigningKeyId: string;
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
    publicKey: rawEd25519PublicKey(publicKey),
    publicKeyMultibase: ed25519PublicKeyMultibase(publicKey),
  };
}

function asWebvhKey(key: Ed25519FixtureKey): WebvhKey {
  return {
    privateKey: key.privateKey,
    publicKey: key.publicKey,
    multibase: key.publicKeyMultibase,
  };
}

function ed25519SignatureB64url(
  privateKey: KeyObject,
  payload: Buffer,
): string {
  return nodeSign(null, payload, privateKey).toString("base64url");
}

function canonicalBytes(value: unknown): Buffer {
  return Buffer.from(canonicalJson(value), "utf8");
}

async function registerWebvhPrincipal(
  request: import("@playwright/test").APIRequestContext,
  localId: string,
): Promise<WebvhPrincipalFixture> {
  const psk = ed25519FixtureKey();
  const enrollmentKey = ed25519FixtureKey();
  const rootKey = ed25519FixtureKey();
  const nextRootKey = ed25519FixtureKey();
  const ssk = ed25519FixtureKey();
  const usk = ed25519FixtureKey();
  const serviceEndpoint = solandBaseUrl().replace(/\/$/, "");
  const built = buildPrincipalGenesisEntry({
    baseUrl: serviceEndpoint,
    localId,
    rootKey: asWebvhKey(rootKey),
    nextRootKey: asWebvhKey(nextRootKey),
    principalSigningKey: asWebvhKey(psk),
    enrollmentKey: asWebvhKey(enrollmentKey),
    alsoKnownAs: [],
    serviceEndpoint,
    versionTime: canonicalTimestamp(),
  });
  await submitPrincipalGenesisEntry(request, serviceEndpoint, built);
  const did = built.did;
  return {
    did,
    principalSigningKeyId: built.principalSigningKeyId,
    psk,
    ssk,
    usk,
    sskKid: `${did}#ak_self_signing_v1`,
  };
}

async function solandTrustDomain(
  request: import("@playwright/test").APIRequestContext,
): Promise<string> {
  const response = await request.get(`${solandBaseUrl()}/_arkret/describe`);
  expect(response.ok()).toBeTruthy();
  const body = await response.json();
  return String(body.trust_domain ?? "ak:trust_domain:soland.joint-e2e.local");
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
  user: JointUser,
  fixture: WebvhPrincipalFixture,
): Promise<{ trustDomain: string; deviceKey: CrossSigningKey }> {
  const trustDomain = await solandTrustDomain(request);
  const realmId = principalControlRealmForDid(fixture.did);
  const pskKid = fixture.principalSigningKeyId;
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
    kid: `${fixture.did}#ak_user_signing_v1`,
    alg: "EdDSA",
    public_key: fixture.usk.publicKeyMultibase,
    key_format: "multibase",
  };
  const generation = 1;
  registerEventSigner({
    actorDid: fixture.did,
    deviceId: user.deviceId,
    verificationMethod: fixture.principalSigningKeyId,
    signingSeedB64url: ed25519PrivateKeySeedB64url(
      fixture.psk.privateKey,
    ),
  });
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: fixture.did,
      realmId,
      kind: "ak.cross_signing.publish",
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
  const identity: CrossSigningIdentity = {
    principalId: fixture.did,
    trustDomain,
    generation,
    psk: fixtureCrossSigningKey(fixture.psk, fixture.principalSigningKeyId),
    ssk: fixtureCrossSigningKey(fixture.ssk, fixture.sskKid),
    usk: fixtureCrossSigningKey(
      fixture.usk,
      `${fixture.did}#ak_user_signing_v1`,
    ),
  };
  const deviceKey = generateCrossSigningKey();
  const hpkeKeyMultibase = "z6LSCotestE2eDeviceHpkeKey";
  const notBefore = canonicalTimestamp();
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: fixture.did,
      realmId,
      kind: "ak.device.authorize",
      payload: {
        principal_id: fixture.did,
        device_id: user.deviceId,
        device_public_key: deviceKey.multibase,
        hpke_key: hpkeKeyMultibase,
        algorithms: TEST_DEVICE_ALGORITHMS,
        device_key_algorithm: "EdDSA",
        device_signature: {
          kid: `${fixture.did}#${user.deviceId}`,
          alg: "EdDSA",
          sig: buildDevicePossessionSignature({
            identity,
            deviceId: user.deviceId,
            devicePublicKeyMultibase: deviceKey.multibase,
            hpkeKeyMultibase,
            algorithms: TEST_DEVICE_ALGORITHMS,
            deviceKeyAlgorithm: "EdDSA",
            authorizedBy: user.deviceId,
            notBefore,
            privateKey: deviceKey.privateKey,
          }),
        },
        authorized_by: user.deviceId,
        not_before: notBefore,
        cross_signing_binding: buildDeviceCrossSigningBinding({
          identity,
          deviceId: user.deviceId,
          devicePublicKeyMultibase: deviceKey.multibase,
          hpkeKeyMultibase,
          algorithms: TEST_DEVICE_ALGORITHMS,
        }),
      },
    }),
    { context: `authorize device ${user.deviceId}` },
  );
  return { trustDomain, deviceKey };
}

function fixtureCrossSigningKey(
  key: Ed25519FixtureKey,
  verificationMethod: string,
): CrossSigningKey {
  return {
    privateKey: key.privateKey,
    rawPublicKey: key.publicKey,
    multibase: key.publicKeyMultibase,
    didKey: `did:key:${key.publicKeyMultibase}`,
    verificationMethod,
  };
}

// Build an encrypted Realm via a direct ak.realm.create envelope. This local
// helper deliberately omits plaintext service declarations so the MLS tests
// exercise the encrypted path only.
async function createEncryptedRealm(
  request: import("@playwright/test").APIRequestContext,
  token: string,
  ownerDid: string,
  title: string,
): Promise<string> {
  return createRealmApi(request, token, {
    title,
    ownerDid,
    history_visibility: "joined",
    encryption_profile: "mls_rfc9420",
  });
}

type MlsGroupContext = {
  groupId: string;
  effectiveScope: { kind: "realm"; realm_id: string };
  epochRefs: Map<number, string>;
};

const MLS_CIPHER_SUITE = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";

async function fetchMlsGovernanceBinding(
  request: import("@playwright/test").APIRequestContext,
  token: string,
  group: Pick<MlsGroupContext, "groupId" | "effectiveScope">,
  previousEpoch: number,
  nextEpoch: number,
): Promise<Record<string, unknown>> {
  const frontierResponse = await request.get(
    `${solandBaseUrl()}/_arkret/self/events/frontier?realm_id=${encodeURIComponent(group.effectiveScope.realm_id)}`,
    { headers: authHeaders(token) },
  );
  const frontierBody = await frontierResponse.json();
  expect(
    frontierResponse.ok(),
    `Realm Seal frontier failed with ${frontierResponse.status()}: ${JSON.stringify(frontierBody)}`,
  ).toBeTruthy();
  const trustedAnchorSealId = String(frontierBody.frontier?.seal_id ?? "");
  expect(trustedAnchorSealId).toMatch(/^ak:seal:/);
  const response = await request.post(
    `${solandBaseUrl()}/_arkret/self/events/mls-governance-proof`,
    {
      headers: authHeaders(token),
      data: {
        realm_id: group.effectiveScope.realm_id,
        effective_scope: group.effectiveScope,
        mls_group_id: group.groupId,
        previous_epoch: previousEpoch,
        next_epoch: nextEpoch,
        binding_profile: MLS_GOVERNANCE_BINDING_FULL_PROFILE,
        reducer_profile: MLS_REDUCER_PROFILE_V1,
        trusted_anchor_seal_id: trustedAnchorSealId,
        chunk_index: 0,
      },
    },
  );
  const body = await response
    .json()
    .catch(async () => ({ raw: await response.text() }));
  expect(
    response.ok(),
    `MLS governance proof failed with ${response.status()}: ${JSON.stringify(body)}`,
  ).toBeTruthy();
  expect(body.governance_binding).toMatchObject({
    realm_id: group.effectiveScope.realm_id,
    effective_scope: group.effectiveScope,
    mls_group_id: group.groupId,
    previous_epoch: previousEpoch,
    next_epoch: nextEpoch,
    binding_profile: MLS_GOVERNANCE_BINDING_FULL_PROFILE,
    reducer_profile: MLS_REDUCER_PROFILE_V1,
  });
  return body.governance_binding as Record<string, unknown>;
}

// Submit ak.mls.genesis for a fresh MLS group bound to `realmId` at epoch 0 and
// return the group context the commit helper threads through. Every binding is
// materialized from accepted Realm control state instead of fixture hashes.
async function submitMlsGenesis(
  request: import("@playwright/test").APIRequestContext,
  token: string,
  owner: JointUser,
  realmId: string,
): Promise<MlsGroupContext> {
  const groupId = base64url(typedId("mls_group"));
  const genesisEventId = typedId("event");
  const effectiveScope = { kind: "realm" as const, realm_id: realmId };
  const group: MlsGroupContext = {
    groupId,
    effectiveScope,
    epochRefs: new Map(),
  };
  const governanceBinding = await fetchMlsGovernanceBinding(
    request,
    token,
    group,
    0,
    0,
  );
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
        effective_scope: effectiveScope,
        epoch: 0,
        creator_principal_id: owner.did,
        creator_device_id: owner.deviceId,
        cipher_suite: MLS_CIPHER_SUITE,
        group_info_digest: `sha256:${"3".repeat(64)}`,
        ratchet_tree_digest: `sha256:${"4".repeat(64)}`,
        governance_binding: governanceBinding,
        created_at: canonicalTimestamp(),
      },
    }),
    { context: `submit MLS genesis ${groupId}` },
  );
  expect(body.accepted ?? []).toContain(genesisEventId);
  group.epochRefs.set(0, genesisEventId);
  return group;
}

// Submit a ak.mls.commit advancing `baseEpoch` -> `baseEpoch + 1`.
// `concurrentCommit` keeps the local epoch-ref cursor on the racing base rather
// than treating the accepted fork as the canonical next epoch. The wire
// payload itself stays schema-valid; soland detects the fork from the shared
// base epoch plus distinct commit material.
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
    governanceBinding?: Record<string, unknown>;
    concurrentCommit?: boolean;
    raw?: boolean;
  },
): Promise<Record<string, unknown>> {
  const { realmId, group, baseEpoch, label } = args;
  const nextEpoch = baseEpoch + 1;
  const eventId = args.eventId ?? typedId("event");
  const baseEpochRef = group.epochRefs.get(baseEpoch);
  if (!baseEpochRef) {
    throw new Error(`missing MLS epoch ${baseEpoch} event ref`);
  }
  const governanceBinding = args.governanceBinding
    ? structuredClone(args.governanceBinding)
    : await fetchMlsGovernanceBinding(
        request,
        token,
        group,
        baseEpoch,
        nextEpoch,
      );
  const payload: Record<string, unknown> = {
    mls_group_id: group.groupId,
    base_epoch: baseEpoch,
    base_epoch_ref: baseEpochRef,
    proposal_refs: [],
    next_epoch: nextEpoch,
    commit_digest: sha256Digest(Buffer.from(label, "utf8")),
    governance_binding: governanceBinding,
  };
  const envelope = signedEventEnvelope({
    actorDid: committer.did,
    realmId,
    kind: "ak.mls.commit",
    eventId,
    payload,
  });
  if (args.raw) {
    await alignSignedEventToActorFrontierApi(request, token, envelope);
    const resp = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
      headers: authHeaders(token),
      data: envelope,
    });
    return { __status: resp.status(), __body: await resp.json() };
  }
  const body = await submitSignedEventApi(request, token, envelope, {
    context: `submit MLS commit ${label}`,
  });
  if (
    !args.concurrentCommit &&
    ((body.accepted as string[] | undefined) ?? []).includes(eventId)
  ) {
    group.epochRefs.set(nextEpoch, eventId);
  }
  return body;
}

async function sendEncryptedTimelineMessage(
  userPage: JointUserPage,
  realmId: string,
  body: string,
): Promise<string> {
  await userPage.gotoTimelineRealm(realmId);

  const secondarySecureButton = userPage.page.getByTestId(
    "send-e2ee-move-button",
  );
  const primarySendButton = userPage.page.getByTestId("send-chat-button");
  const secureSendButton = (await secondarySecureButton
    .isVisible()
    .catch(() => false))
    ? secondarySecureButton
    : primarySendButton;
  await expect(secureSendButton).toBeVisible({ timeout: 30_000 });

  const chatStatus = userPage.page.getByTestId("chat-status");

  const messageSubmit = userPage.page.waitForResponse(
    (response) => {
      const request = response.request();
      const postData = request.postData() ?? "";
      return (
        request.method() === "POST" &&
        response.url().includes("/_arkret/self/events") &&
        postData.includes("ak.message.create") &&
        [200, 201].includes(response.status())
      );
    },
    { timeout: 60_000 },
  );

  await userPage.page.getByTestId("chat-input").fill(body);
  await secureSendButton.click();

  const response = await Promise.race([
    messageSubmit,
    chatStatus
      .filter({ hasText: /(?:_pending|failed|could not|error)/i })
      .waitFor({ state: "visible", timeout: 60_000 })
      .then(async () => {
        throw new Error(`secure send blocked: ${await chatStatus.innerText()}`);
      }),
  ]);
  const postData = response.request().postData() ?? "";
  const submittedEvent = JSON.parse(postData);
  expect(submittedEvent.payload?.encrypted_content).toMatchObject({
    scheme: "mls_exporter_aead_v1",
    key_ref: { algorithm: "MLS-EXPORTER-AEAD" },
  });
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
    deviceId: `ak:device:01904100-0000-7000-8000-${suffix}`,
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
    .toContain("/board/ak:space:");
  const boardId = decodeURIComponent(
    new URL(page.url()).pathname.split("/board/")[1]?.split("/")[0] ?? "",
  );
  expect(boardId).toMatch(/^ak:space:/);

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
    const [aliceFlow, mallorySession] = await Promise.all([
      openDpopUserPage(browser, request, "s11-alice"),
      createDpopUserSession(request, "s11-mallory", {
        skipDeviceEnrollment: true,
      }),
    ]);
    if (!aliceFlow || !mallorySession) {
      assertJointStackNotRequired("mls admin controls browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alicePage = aliceFlow.page;

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
      const eventsUrl = `${solandBaseUrl()}/_arkret/self/events?realms=${encodeURIComponent(realmId)}&limit=20`;
      const eventsResp = await request.get(eventsUrl, {
        headers: selfPathGrantHeaders({
          deviceKey: mallorySession.deviceKey,
          grantJwt: mallorySession.grantJwt,
          method: "GET",
          url: eventsUrl,
        }),
      });
      expect([401, 403, 404, 405]).toContain(eventsResp.status());
      await stepShot(alicePage.page, testInfo, "non-member-blocked");
    } finally {
      await alicePage.close();
    }
  });

  test("alice creates space with encryption_profile=mls_rfc9420 at create time; world_readable policy is rejected", async ({
    request,
  }) => {
    // Smoke for the create-time encryption profile path. Full ak.mls.genesis
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
      `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}/export`,
      { headers: authHeaders(aliceToken) },
    );
    expect(exportResp.ok()).toBeTruthy();
    expect(JSON.stringify(await exportResp.json())).toContain(
      '"encryption_profile":"mls_rfc9420"',
    );

    await expect(
      createRealmApi(request, aliceToken, {
        title: `S11 MLS incompatible ${stamp}`,
        ownerDid: alice.did,
        history_visibility: "world_readable",
        encryption_profile: "mls_rfc9420",
      }),
    ).rejects.toThrow("history_visibility_requires_history_capable_scheme");
  });

  test("alice claims bob's KeyPackage; durable Welcome delivery and commit epoch stay live", async ({
    request,
  }) => {
    // API-first smoke for the G3.S1 subset: MLS group genesis,
    // KeyPackage publish/claim CAS, durable Welcome delivery, and
    // monotonic commit epoch. Full client derivation of epoch secrets
    // remains a later inkson+MLS concern.
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
    const [, bobCrossSigning] = await Promise.all([
      publishCrossSigning(request, aliceToken, alice, aliceFixture),
      publishCrossSigning(request, bobToken, bob, bobFixture),
    ]);

    const keypackageId = typedId("mls_keypackage");
    const keyPackage = base64url(`opaque-keypackage-${stamp}`);
    const keypackageDigest = sha256Digest(Buffer.from(keyPackage, "base64url"));
    const keypackageRef = keypackageDigest;
    const keypackageCapabilities = ["ak.mls.profile.full"];
    const groupId = base64url(typedId("mls_group"));
    const digest = (nibble: string) => `sha256:${nibble.repeat(64)}`;
    const createdAt = canonicalTimestamp();
    const expiresAt = canonicalTimestamp(new Date(Date.now() + 60 * 60 * 1000));
    const keypackageExpiresAt = canonicalTimestamp(
      new Date(Date.now() + 2 * 60 * 60 * 1000),
    );
    const keyPackages = [
      {
        keypackage_id: keypackageId,
        keypackage_ref: keypackageRef,
        key_package: keyPackage,
        keypackage_digest: keypackageDigest,
        cipher_suites: ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
        capabilities: keypackageCapabilities,
        created_at: createdAt,
        expires_at: keypackageExpiresAt,
      },
    ];
    const unsignedUpload = {
      principal_id: bob.did,
      device_id: bob.deviceId,
      key_packages: keyPackages,
    };
    const deviceSignature = {
      kid: `${bob.did}#${bob.deviceId}`,
      alg: "EdDSA",
      sig: nodeSign(
        null,
        Buffer.concat([
          Buffer.from("ak.self.keys.keypackages.upload.create\n", "utf8"),
          canonicalBytes(unsignedUpload),
        ]),
        bobCrossSigning.deviceKey.privateKey,
      ).toString("base64url"),
    };

    const publish = await request.post(
      `${solandBaseUrl()}/_arkret/self/keys/keypackages/upload`,
      {
        headers: authHeaders(bobToken),
        data: {
          ...unsignedUpload,
          device_signature: deviceSignature,
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

    const realmId = await createRealmApi(request, aliceToken, {
      title: `MLS lifecycle ${stamp}`,
      ownerDid: alice.did,
      history_visibility: "joined",
      encryption_profile: "mls_rfc9420",
    });

    const pendingBefore = await request.get(
      `${solandBaseUrl()}/_arkret/self/device_messages`,
      {
        headers: authHeaders(bobToken),
      },
    );
    expect(pendingBefore.ok()).toBeTruthy();
    expect(
      ((await pendingBefore.json()).messages ?? []).filter(
        (message: Record<string, unknown>) => message.kind === "ak.mls.welcome",
      ),
    ).toEqual([]);

    const claim = await request.post(
      `${solandBaseUrl()}/_arkret/self/keys/keypackages/claim`,
      {
        headers: authHeaders(aliceToken),
        data: {
          target_principal_id: bob.did,
          target_device_ids: [bob.deviceId],
          intended_realm_id: realmId,
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
      `${solandBaseUrl()}/_arkret/self/keys/keypackages/claim`,
      {
        headers: authHeaders(aliceToken),
        data: {
          target_principal_id: bob.did,
          target_device_ids: [bob.deviceId],
          intended_realm_id: realmId,
          requester: alice.did,
          required_capabilities: keypackageCapabilities,
          claim_nonce: `claim-again-${stamp}`,
          expires_at: expiresAt,
          mls_group_id: groupId,
          proofs: [],
        },
      },
    );
    expect(claimAgain.ok()).toBeTruthy();
    const claimAgainBody = await claimAgain.json();
    expect(claimAgainBody.claims ?? []).toEqual([]);
    expect(claimAgainBody.failures?.[0]?.reason_code).toBe(
      "mls_keypackage_not_found",
    );

    const genesisEventId = typedId("event");
    const commitEventId = typedId("event");
    const effectiveScope = { kind: "realm" as const, realm_id: realmId };
    const group = { groupId, effectiveScope };
    const genesisBinding = await fetchMlsGovernanceBinding(
      request,
      aliceToken,
      group,
      0,
      0,
    );
    const genesisBody = await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ak.mls.genesis",
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

    const commitBinding = await fetchMlsGovernanceBinding(
      request,
      aliceToken,
      group,
      0,
      1,
    );

    const welcomeEventId = typedId("event");
    const welcomeCiphertext = base64url(`opaque-mls-welcome-${stamp}`);
    const welcomeDigest = sha256Digest(
      Buffer.from(welcomeCiphertext, "base64url"),
    );
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
    const commitPayload = (label: string) => ({
      mls_group_id: groupId,
      base_epoch: 0,
      base_epoch_ref: genesisEventId,
      proposal_refs: [],
      next_epoch: 1,
      commit_digest: sha256Digest(Buffer.from(label, "utf8")),
      governance_binding: commitBinding,
    });
    const commitEnvelope = signedEventEnvelope({
      actorDid: alice.did,
      realmId,
      kind: "ak.mls.commit",
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

    const welcomeBody = await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ak.mls.welcome",
        eventId: welcomeEventId,
        payload: {
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
          governance_binding: commitBinding,
        },
      }),
      {
        context: "submit MLS welcome",
      },
    );
    expect(welcomeBody.accepted ?? []).toContain(welcomeEventId);

    const pendingAfterWelcome = await request.get(
      `${solandBaseUrl()}/_arkret/self/device_messages`,
      {
        headers: authHeaders(bobToken),
      },
    );
    expect(pendingAfterWelcome.ok()).toBeTruthy();
    const pendingAfterWelcomeBody = await pendingAfterWelcome.json();
    const deliveredWelcomes = (pendingAfterWelcomeBody.messages ?? []).filter(
      (message: Record<string, unknown>) => message.kind === "ak.mls.welcome",
    );
    expect(deliveredWelcomes).toHaveLength(1);
    expect(deliveredWelcomes[0]).toMatchObject({
      kind: "ak.mls.welcome",
      recipient_principal_id: bob.did,
      recipient_device_id: bob.deviceId,
      content: {
        mls_group_id: groupId,
        keypackage_ref: keypackageRef,
        commit_ref: commitEventId,
        governance_binding: commitBinding,
      },
    });
    expect(pendingAfterWelcomeBody.ack_token).toBeTruthy();
    expect(pendingAfterWelcomeBody.next_cursor).toBeTruthy();

    const ackWelcome = await request.post(
      `${solandBaseUrl()}/_arkret/self/device_messages/ack`,
      {
        headers: authHeaders(bobToken),
        data: { ack_token: pendingAfterWelcomeBody.ack_token },
      },
    );
    expect(ackWelcome.ok()).toBeTruthy();
    expect((await ackWelcome.json()).ok).toBe(true);

    const pendingAfterAck = await request.get(
      `${solandBaseUrl()}/_arkret/self/device_messages?after=${encodeURIComponent(
        String(pendingAfterWelcomeBody.next_cursor),
      )}`,
      {
        headers: authHeaders(bobToken),
      },
    );
    expect(pendingAfterAck.ok()).toBeTruthy();
    expect(
      ((await pendingAfterAck.json()).messages ?? []).filter(
        (message: Record<string, unknown>) => message.kind === "ak.mls.welcome",
      ),
    ).toEqual([]);

    const staleCommitEnvelope = signedEventEnvelope({
      actorDid: alice.did,
      realmId,
      kind: "ak.mls.commit",
      payload: commitPayload(`opaque-commit-${stamp}`),
    });
    await alignSignedEventToActorFrontierApi(
      request,
      aliceToken,
      staleCommitEnvelope,
    );
    const staleCommit = await request.post(
      `${solandBaseUrl()}/_arkret/self/events`,
      {
        headers: authHeaders(aliceToken),
        data: staleCommitEnvelope,
      },
    );
    expect(staleCommit.status()).toBe(412);
    const staleCommitBody = await staleCommit.json();
    expect(wireErrCode(staleCommitBody)).toBe("mls_epoch_skew");
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
      createDpopUserSession(request, "s11-decrypt-alice", {
        skipDeviceEnrollment: true,
      }),
      createDpopUserSession(request, "s11-decrypt-bob", {
        skipDeviceEnrollment: true,
      }),
    ]);
    if (!aliceSession || !bobSession) {
      // Fail loud on the joint harness (coauth up) instead of green-skipping the
      // single most important cross-member decrypt test in the suite.
      assertJointStackNotRequired(
        "MLS joined-member decrypt requires coauth DPoP session-grant login",
      );
      test.skip(
        true,
        "coauth DPoP session-grant login is required for MLS device-authorized KeyPackages",
      );
      return;
    }
    const alice = aliceSession!.user;
    const bob = bobSession!.user;
    const alicePage = await openUserPage(browser, alice, {
      grantJwt: aliceSession.grantJwt,
      dpopSeedB64url: aliceSession.dpopSeedB64url,
      eventSigningSeedB64url: aliceSession.eventSigningSeedB64url,
      grantId: aliceSession.grantId,
      grantAudience: aliceSession.grantAudience,
    });
    let bobPage: JointUserPage | undefined;
    const invalidHistoryBackupWarnings: string[] = [];
    const recordInvalidHistoryBackupWarning = (userPage: JointUserPage) => {
      userPage.page.on("console", (message) => {
        const text = message.text();
        if (text.includes("encryption.aead is required")) {
          invalidHistoryBackupWarnings.push(text);
        }
      });
    };
    recordInvalidHistoryBackupWarning(alicePage);

    try {
      await alicePage.gotoHome();
      await alicePage.completeRecoveryKeySetupIfPrompted();
      await alicePage.acknowledgeRecommendedEncryptionPromptIfVisible();

      const realmId = await alicePage.createRealm({
        title: `S11 joined decrypt ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyVisibility: "joined",
        encryptionProfile: "mls_rfc9420",
      });
      const inviteStatus = await alicePage.inviteFromAdmin(realmId, bob.did);
      expect(inviteStatus).toContain("invited");
      expect(inviteStatus).not.toContain("MLS Welcome queued");

      bobPage = await openUserPage(browser, bob, {
        grantJwt: bobSession.grantJwt,
        dpopSeedB64url: bobSession.dpopSeedB64url,
        eventSigningSeedB64url: bobSession.eventSigningSeedB64url,
        grantId: bobSession.grantId,
        grantAudience: bobSession.grantAudience,
      });
      recordInvalidHistoryBackupWarning(bobPage);
      await bobPage.gotoHome();
      await bobPage.completeRecoveryKeySetupIfPrompted();
      await bobPage.acknowledgeRecommendedEncryptionPromptIfVisible();
      await bobPage.acceptInvite(realmId);

      // Route-context bootstrap is where Bob applies pending MLS Welcome state.
      await bobPage.gotoTimelineRealm(realmId);

      // Bob did not have a published KeyPackage when Alice first issued the
      // invite, so admission is completed asynchronously after Bob boots and
      // accepts. Drive Alice's membership refresh and wait for the accepted
      // Welcome before attempting the first encrypted write.
      const aliceDevToken = await issueDevSession(request, alice);
      await alicePage.gotoRealmAdminSection(realmId, "members");
      const refreshMembers = alicePage.page.getByTestId(
        "refresh-members-button",
      );
      const bobMemberRow = alicePage.page.locator(
        `[data-testid="member-row"][data-member-did="${bob.did}"]`,
      );
      await expect
        .poll(
          async () => {
            await refreshMembers.click();
            return bobMemberRow.count();
          },
          { timeout: 120_000, intervals: [1_000, 2_000, 5_000] },
        )
        .toBeGreaterThan(0);
      await expect
        .poll(
          async () => {
            await refreshMembers.click();
            const timeline = await queryRealmEventsApi(
              request,
              aliceDevToken,
              realmId,
            );
            return ((timeline.events ?? []) as Array<Record<string, any>>).some(
              (event) =>
                event.kind === "ak.mls.welcome" &&
                event.payload?.recipient_principal_id === bob.did,
            );
          },
          { timeout: 120_000, intervals: [1_000, 2_000, 5_000] },
        )
        .toBeTruthy();

      const plaintext = `joined member decrypts post-join ciphertext ${stamp}`;
      const submittedWire = await sendEncryptedTimelineMessage(
        alicePage,
        realmId,
        plaintext,
      );
      expect(submittedWire).not.toContain(plaintext);

      await expect(alicePage.timelineEvent(plaintext)).toBeVisible({
        timeout: 30_000,
      });

      await bobPage.page.reload({ waitUntil: "domcontentloaded" });
      await expect(bobPage.page.getByTestId("message-list")).toBeVisible({
        timeout: 120_000,
      });
      // An invitee viewing encrypted content is required to set up a Recovery Key
      // first; its modal (no dismiss) otherwise blocks the encrypted timeline from
      // rendering. Complete it before asserting the decrypted message. (soland DOES
      // deliver the message to bob's feed — verified separately — so a missing
      // message here is this client-side gate, not a delivery gap.)
      await bobPage.completeRecoveryKeySetupIfPrompted();
      const bobMessage = bobPage.timelineEvent(plaintext);
      await expect(bobMessage).toBeVisible({ timeout: 60_000 });
      await expect(bobMessage.getByTestId("event-body")).toContainText(
        plaintext,
      );

      // Bidirectional decrypt: the admission fork (add-member commit rejected
      // `governance_binding_mismatch` while its Welcome still landed) broke BOTH
      // directions — the admin sat one epoch behind the invitee, so neither could
      // read the other. Assert a message Bob authors after joining also decrypts
      // for Alice, not just Alice → Bob.
      const bobPlaintext = `joined member round-trips back to admin ${stamp}`;
      const bobWire = await sendEncryptedTimelineMessage(
        bobPage,
        realmId,
        bobPlaintext,
      );
      expect(bobWire).not.toContain(bobPlaintext);
      await expect(bobPage.timelineEvent(bobPlaintext)).toBeVisible({
        timeout: 30_000,
      });

      await alicePage.page.reload({ waitUntil: "domcontentloaded" });
      await expect(alicePage.page.getByTestId("message-list")).toBeVisible({
        timeout: 120_000,
      });
      const aliceSeesBob = alicePage.timelineEvent(bobPlaintext);
      await expect(aliceSeesBob).toBeVisible({ timeout: 60_000 });
      await expect(aliceSeesBob.getByTestId("event-body")).toContainText(
        bobPlaintext,
      );

      const rawEventsUrl = `${solandBaseUrl()}/_arkret/self/events?realms=${encodeURIComponent(realmId)}&limit=100`;
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
      expect(rawWire).toContain('"scheme":"mls_exporter_aead_v1"');
      expect(rawWire).not.toContain(plaintext);
      expect(rawWire).not.toContain(bobPlaintext);

      const storageNeedles = [plaintext, bobPlaintext];
      const [aliceStorage, bobStorage] = await Promise.all([
        auditBrowserStorage(alicePage.page, storageNeedles),
        auditBrowserStorage(bobPage.page, storageNeedles),
      ]);
      for (const audit of [aliceStorage, bobStorage]) {
        expect(
          audit.indexedDbEnumerationSupported,
          "Chromium must expose IndexedDB database enumeration for a complete storage audit",
        ).toBe(true);
        expect(audit.indexedDbStores).toContain(
          "inkson.secret.inkson/entries",
        );
        expect(
          audit.indexedDbEntryKeys.some((key) =>
            key.includes("inkson.e2ee_plaintext_cache.v1."),
          ),
          "the audit must observe the encrypted E2EE plaintext-cache entry",
        ).toBe(true);
        expect(audit.plaintextMatches).toEqual([]);
        expect(audit.weakE2eeLocalStorageKeys).toEqual([]);
      }
      expect(
        invalidHistoryBackupWarnings,
        "a metadata-only key-backup list summary must never reach the MLS envelope decoder",
      ).toEqual([]);

      await stepShot(
        bobPage.page,
        testInfo,
        "joined-member-decrypted-e2ee-message",
      );
    } finally {
      await Promise.allSettled([
        bobPage?.close() ?? Promise.resolve(),
        alicePage.close(),
      ]);
    }
  });

  test("carol added in epoch 1 → ak.mls.commit advances to epoch 2; carol cannot decrypt pre-join messages (history_visibility=joined)", async ({
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
    const carolEventsUrl = `${solandBaseUrl()}/_arkret/self/events?realms=${encodeURIComponent(realmId)}&limit=100`;
    await expect
      .poll(
        async () => {
          const resp = await request.get(carolEventsUrl, {
            headers: authHeaders(carolToken),
          });
          if (resp.status() !== 200) {
            return null;
          }
          const body = (await resp.json()) as {
            events?: Array<{ event_id?: unknown }>;
          };
          return (body.events ?? [])
            .map((event) => event.event_id)
            .filter((eventId): eventId is string => typeof eventId === "string");
        },
        {
          timeout: 60_000,
          intervals: [1_000, 2_000, 5_000],
          message:
            "carol's synced event stream should surface the post-join event",
        },
      )
      .toContain(postJoinEventId);

    const carolEvents = await request.get(carolEventsUrl, {
      headers: authHeaders(carolToken),
    });
    expect(carolEvents.status()).toBe(200);
    const carolBody = (await carolEvents.json()) as {
      events?: Array<{ event_id?: unknown }>;
    };
    const carolEventIds = (carolBody.events ?? [])
      .map((event) => event.event_id)
      .filter((eventId): eventId is string => typeof eventId === "string");
    // Post-join epoch event visible; pre-join epoch event id cropped.
    expect(carolEventIds).toContain(postJoinEventId);
    expect(carolEventIds).not.toContain(preJoinEventId);

    // Sanity: alice (owner) still sees both events — the crop is a per-reader
    // history gate, not a delete.
    const aliceEvents = await request.get(carolEventsUrl, {
      headers: authHeaders(aliceToken),
    });
    expect(aliceEvents.status()).toBe(200);
    const aliceBody = (await aliceEvents.json()) as {
      events?: Array<{ event_id?: unknown }>;
    };
    const aliceEventIds = (aliceBody.events ?? [])
      .map((event) => event.event_id)
      .filter((eventId): eventId is string => typeof eventId === "string");
    expect(aliceEventIds).toContain(preJoinEventId);
    expect(aliceEventIds).toContain(postJoinEventId);
  });

  test("alice bans bob → client pauses until the MLS Remove commit covers the membership frontier", async ({
    browser,
    request,
  }, testInfo) => {
    test.setTimeout(360_000);
    const stamp = Date.now();
    const [aliceSession, bobSession] = await Promise.all([
      createDpopUserSession(request, "s11-ban-alice", {
        skipDeviceEnrollment: true,
      }),
      createDpopUserSession(request, "s11-ban-bob", {
        skipDeviceEnrollment: true,
      }),
    ]);
    if (!aliceSession || !bobSession) {
      assertJointStackNotRequired(
        "MLS ban UI requires coauth DPoP session-grant login",
      );
      test.skip(
        true,
        "coauth DPoP session-grant login is required for MLS browser auth",
      );
      return;
    }
    const alice = aliceSession.user;
    const bob = bobSession.user;

    const [alicePage, bobPage] = await Promise.all([
      openUserPage(browser, alice, {
        grantJwt: aliceSession.grantJwt,
        dpopSeedB64url: aliceSession.dpopSeedB64url,
        eventSigningSeedB64url: aliceSession.eventSigningSeedB64url,
        grantId: aliceSession.grantId,
        grantAudience: aliceSession.grantAudience,
      }),
      openUserPage(browser, bob, {
        grantJwt: bobSession.grantJwt,
        dpopSeedB64url: bobSession.dpopSeedB64url,
        eventSigningSeedB64url: bobSession.eventSigningSeedB64url,
        grantId: bobSession.grantId,
        grantAudience: bobSession.grantAudience,
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
        title: `S11 MLS ban ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyVisibility: "joined",
        encryptionProfile: "mls_rfc9420",
      });
      const inviteStatus = await alicePage.inviteFromAdmin(realmId, bob.did);
      expect(inviteStatus).toContain("MLS Welcome queued");
      await bobPage.acceptInvite(realmId);
      await bobPage.gotoTimelineRealm(realmId);

      await alicePage.gotoRealmAdminSection(realmId, "members");
      const refresh = alicePage.page.getByTestId("refresh-members-button");
      await expect(refresh).toBeVisible({ timeout: 120_000 });
      const bobRow = alicePage.page.locator(
        `[data-testid="member-row"][data-member-did="${bob.did}"]`,
      );
      await expect
        .poll(
          async () => {
            await refresh.click();
            return await bobRow.count();
          },
          {
            timeout: 120_000,
            intervals: [1_000, 2_000, 5_000],
            message:
              "Bob joined member row should appear in synced admin projection",
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
      const sendButton = alicePage.page.getByTestId("send-chat-button");
      // The admin action already asserted that fail-closed was entered. The
      // background committer may finish before navigation reaches the
      // timeline, so the transient banner is optional at this exact instant.
      if (await epochBanner.isVisible()) {
        await expect(epochBanner).toContainText("epoch_update_required");
        await expect(sendButton).toBeDisabled();
      }
      await stepShot(
        alicePage.page,
        testInfo,
        "epoch-update-required-after-ban",
      );

      // Regression guard: membership Event effectiveness alone is not enough;
      // the client must submit and observe the covering MLS Remove commit,
      // clear the reconciliation gate, and restore encrypted sending.
      await expect(epochBanner).toBeHidden({ timeout: 120_000 });
      await expect(sendButton).toBeEnabled({ timeout: 120_000 });
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
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
    // submit_event_value -> reducer) runs every pushed ak.mls.commit through, so
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
    const originalCommitBinding = await fetchMlsGovernanceBinding(
      request,
      aliceToken,
      group,
      0,
      1,
    );

    const forgedCommitBinding = structuredClone(originalCommitBinding);
    forgedCommitBinding.policy_root = sha256Digest(
      Buffer.from(`forged-policy-root-${stamp}`, "utf8"),
    );

    // A syntactically valid binding with a policy_root that does not match the
    // accepted Realm control state is rejected with governance_binding_mismatch.
    const forged = await submitMlsCommit(request, aliceToken, alice, {
      realmId,
      group,
      baseEpoch: 0,
      label: `forged-binding-${stamp}`,
      governanceBinding: forgedCommitBinding,
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
      governanceBinding: originalCommitBinding,
    });
    expect(clean.accepted ?? []).toContain(cleanEventId);
  });

  // encryption_profile is a create-locked Realm field (spec
  // realm-and-space.md §2.3). soland enforces this in operations.rs
  // (operation_touches_encryption_profile → realm_encryption_profile_create_locked)
  // but no soland unit test or cotest case exercises it. This pins the wire
  // rejection so a regression that lets the profile be patched after creation
  // — silently downgrading an Encrypted Realm to plaintext — is caught.
  test("ak.realm.update that patches encryption_profile is rejected (create-locked)", async ({
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

    const updateEnvelope = signedEventEnvelope({
      actorDid: alice.did,
      realmId,
      kind: "ak.realm.update",
      payload: {
        target_ref: realmId,
        patch: { encryption_profile: { $op: "set", value: "none" } },
      },
    });
    await alignSignedEventToActorFrontierApi(
      request,
      aliceToken,
      updateEnvelope,
    );
    const resp = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
      headers: authHeaders(aliceToken),
      data: updateEnvelope,
    });

    const body = await resp.json();
    expect([400, 409, 412, 422], JSON.stringify(body)).toContain(resp.status());
    expect(wireErrCode(body)).toBe("realm_encryption_profile_create_locked");
  });

  // Circle counterpart of the realm create-lock.
  //
  // Historical regression: circle create/update events used to skip submit-time
  // operation validation, so create-lock enforcement only happened later during
  // projection. soland now registers circle operation schemas; this test pins
  // the synchronous rejection.
  test("ak.circle.update that patches encryption_profile is rejected (create-locked)", async ({
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
        kind: "ak.circle.create",
        payload: {
          object: {
            id: circleId,
            schema: "ak.schema.circle.v1",
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

    const updateEnvelope = signedEventEnvelope({
      actorDid: alice.did,
      realmId,
      kind: "ak.circle.update",
      payload: {
        target_ref: circleId,
        patch: { encryption_profile: { $op: "set", value: "none" } },
      },
    });
    await alignSignedEventToActorFrontierApi(
      request,
      aliceToken,
      updateEnvelope,
    );
    const resp = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
      headers: authHeaders(aliceToken),
      data: updateEnvelope,
    });

    const body = await resp.json();
    expect([400, 409, 412, 422], JSON.stringify(body)).toContain(resp.status());
    expect(wireErrCode(body)).toBe("circle_encryption_profile_create_locked");
  });

  // Not-ready guard: a fresh device of the SAME account that has NOT received
  // an MLS Welcome and has NOT restored its account secret must NOT silently
  // downgrade an encrypted private write to plaintext. The client surfaces a
  // recoverable "MLS state not ready" affordance and refuses to submit; it
  // never POSTs a plaintext ak.strand.update carrying the private `body`.
  //
  // inkson guard: encrypt_values_with_device_snapshot returns
  // MlsRuntimeError::MissingWelcome when no local MLS snapshot exists, which
  // dispatch_card_detail_update surfaces into board_status /
  // card-detail-edit-status ("MLS state is not ready on this device yet ...")
  // and returns false BEFORE any strand.update event is built or submitted —
  // so the encrypted scope never falls back to a plaintext write.
  test("fresh device without MLS welcome/restore refuses encrypted private writes instead of silently downgrading to plaintext", async ({
    browser,
    request,
  }) => {
    test.setTimeout(300_000);
    const stamp = Date.now();
    const coauth = coauthBaseUrl();
    if (!coauth) {
      assertJointStackNotRequired("MLS not-ready browser login");
      test.skip(
        true,
        "coauth DPoP session-grant login is required for fresh-device MLS",
      );
      return;
    }

    const boardTitle = `Not-ready Board ${stamp}`;
    const listTitle = `Not-ready Todos ${stamp}`;
    const cardTitle = `Not-ready encrypted card ${stamp}`;
    const privateDescription = `Not-ready secret detail ${stamp}`;

    // 1) deviceA (the MLS group creator) builds the encrypted realm + board +
    //    list + card via the UI so a genuine MLS group exists.
    const account = await registerCoauthPasswordAccount(request, coauth);
    const deviceAFlow = await openDpopUserPageForAccount(
      browser,
      request,
      `mls-not-ready-a-${stamp}`,
      account,
      { coauthBase: coauth },
    );
    const deviceBFlow = await openDpopUserPageForAccount(
      browser,
      request,
      `mls-not-ready-b-${stamp}`,
      account,
      { coauthBase: coauth, prepareMlsDevice: false },
    );
    if (!deviceAFlow || !deviceBFlow) {
      assertJointStackNotRequired("MLS not-ready browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const deviceA = deviceAFlow.page;

    // 2) deviceB = same account, fresh device id, fresh dev session => empty
    //    local store: NO Welcome applied, NO encrypted-history restore.
    const deviceB = deviceBFlow.page;

    // Capture any plaintext private write that would leak the description.
    // A plaintext ak.strand.update would carry `privateDescription` verbatim
    // in its body/fields.body patch; an encrypted one never does.
    const plaintextPrivateWrites: string[] = [];
    deviceB.page.on("request", (req) => {
      if (
        req.method() !== "POST" ||
        !req.url().includes("/_arkret/self/events")
      ) {
        return;
      }
      const postData = req.postData() ?? "";
      if (
        postData.includes("ak.strand.update") &&
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

      // 4c) No plaintext ak.strand.update carrying the private body ever left
      //     the client (so the server never had to accept or bounce one).
      expect(plaintextPrivateWrites, plaintextPrivateWrites.join("\n")).toEqual(
        [],
      );
    } finally {
      await Promise.allSettled([deviceA.close(), deviceB.close()]);
    }
  });
});
