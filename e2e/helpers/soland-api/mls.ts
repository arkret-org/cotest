// MLS group lifecycle for API-level fixtures.
//
// Spec: crypto-media/encryption-and-audit.md §2.5 (a scope is end-to-end
// encrypted exactly when its `ak.mls.genesis` is accepted; §2.5.2 send gate),
// §2.4.1 (every membership change advances the scope's key-access revision, so
// new ciphertext waits for a covering Commit), §2.6 / §2.6.1 (KeyPackage claim,
// Add Commit and the producer-signed Welcome), device-lifecycle.md §9.
//
// All MLS state is produced by the SDK through `cotest-wire` (the `mls-*`
// commands in `crates/test-support/src/mls_wire.rs`); this module only moves
// opaque state blobs between those steps and the Station. The order follows
// `cotest/src/scenarios/mls_lifecycle_live.rs`.

import { createHash, createPrivateKey, createPublicKey, randomBytes } from "node:crypto";
import { expect, type APIRequestContext } from "@playwright/test";
import { type SolandKey, solandBaseUrl, solandServiceId } from "../env";
import { authHeaders, expectJsonOk } from "./request";
import { canonicalJson, cotestWire } from "./wire-client";
import {
  accountActorId,
  assertAuthoritySubmitOutcome,
  canonicalTimestamp,
  registeredEventSigningSeedB64url,
  registeredEventVerificationMethod,
  signedEventEnvelope,
  submitSignedEventApi,
  uuidV7,
} from "../soland-api";

/// One human device endpoint the harness holds a session and device key for.
export type MlsDevice = {
  id: string;
  deviceId: string;
  token: string;
  server?: SolandKey;
};

/// The closed `typed-current-result.schema.json#/$defs/mls_group_value`.
export type MlsGroupCurrent = {
  effective_scope: Record<string, unknown>;
  genesis_event_ref: string;
  current_mls_commit_event_ref: string;
  epoch: number;
  current_key_access_revision: number;
  covered_key_access_revision: number;
  public_tree_ref: string;
};

/// A joined member's own group state, ready to encrypt at `epoch`.
export type MlsMemberGroup = {
  realmId: string;
  groupState: string;
  epoch: number;
  groupStateRef: string;
};

type LeafMember = {
  actor_id: Record<string, unknown>;
  device_id: string;
  device_authorize_event_id: string;
  device_public_key_b64url: string;
};

type RealmMlsCreator = {
  owner: MlsDevice;
  groupState: string;
  members: LeafMember[];
};

type PendingJoin = {
  identityState: string;
  commitEventId: string;
  welcomeId: string;
  members: LeafMember[];
  producerPublicKey: string;
};

const realmMlsCreators = new Map<string, RealmMlsCreator>();
const pendingJoins = new Map<string, PendingJoin>();

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const CLAIM_LIFETIME_SECONDS = 240;

function realmKey(server: SolandKey | undefined, realmId: string): string {
  return `${server ?? "default"}\0${realmId}`;
}

function joinKey(realmId: string, member: MlsDevice): string {
  return `${realmKey(member.server, realmId)}\0${member.id}\0${member.deviceId}`;
}

function deviceSigner(device: MlsDevice): {
  verificationMethod: string;
  signingSeedB64url: string;
  publicKeyB64url: string;
} {
  const verificationMethod = registeredEventVerificationMethod(
    device.id,
    device.deviceId,
  );
  const signingSeedB64url = verificationMethod
    ? registeredEventSigningSeedB64url(device.id, verificationMethod)
    : undefined;
  if (!verificationMethod || !signingSeedB64url) {
    throw new Error(
      `no accepted device signer registered for ${device.id}/${device.deviceId}`,
    );
  }
  const privateKey = createPrivateKey({
    key: Buffer.concat([
      PKCS8_ED25519_PREFIX,
      Buffer.from(signingSeedB64url, "base64url"),
    ]),
    format: "der",
    type: "pkcs8",
  });
  const jwk = createPublicKey(privateKey).export({ format: "jwk" });
  if (typeof jwk.x !== "string") {
    throw new Error("Ed25519 device key has no public component");
  }
  return { verificationMethod, signingSeedB64url, publicKeyB64url: jwk.x };
}

function endpointInput(device: MlsDevice): Record<string, unknown> {
  const signer = deviceSigner(device);
  return {
    actor_id: accountActorId(device.id, device.server),
    device_id: device.deviceId,
    verification_method: signer.verificationMethod,
    signing_seed_b64url: signer.signingSeedB64url,
  };
}

/// The accepted `ak.device.authorize` Event of the session's own device, as
/// the Account Station projects it in the account viewer.
async function deviceAuthorizeEventId(
  request: APIRequestContext,
  device: MlsDevice,
): Promise<string> {
  const url = `${solandBaseUrl(device.server)}/_arkret/self/account/viewer`;
  const viewer = await expectJsonOk<{
    devices?: Array<{ device_id?: unknown; authorized_event_ref?: unknown }>;
  }>(
    await request.get(url, { headers: authHeaders(device.token, "GET", url) }),
    `read account viewer for ${device.deviceId}`,
  );
  const row = (viewer.devices ?? []).find(
    (candidate) => candidate.device_id === device.deviceId,
  );
  const eventRef = row?.authorized_event_ref;
  if (typeof eventRef !== "string" || !eventRef.startsWith("ak:event:")) {
    throw new Error(
      `account viewer has no accepted authorization for ${device.deviceId}`,
    );
  }
  return eventRef;
}

/// Upload one epoch-0 public MLS state Blob (GroupInfo or ratchet tree).
///
/// encryption-and-audit.md section 5.1.2: the Genesis material is public MLS
/// state the creator uploads through `ak.self.blob.*` as a content-addressed
/// Blob, which the governance Station verifies and keeps as a public Blob. It
/// is no `plaintext_data_class` private content and carries no encryption
/// envelope. The request is the canonical `BlobUploadRequestBody`
/// (blob-operations.schema.json): `content`, `size_bytes` and the owning
/// `realm_id` and the required JSON `encryption: null` classification are
/// multipart form fields.
async function uploadPublicBlob(
  request: APIRequestContext,
  device: MlsDevice,
  realmId: string,
  bytesB64url: string,
): Promise<string> {
  const url = `${solandBaseUrl(device.server)}/_arkret/self/blob/upload`;
  const bytes = Buffer.from(bytesB64url, "base64url");
  const body = await expectJsonOk<{ blob_ref?: unknown }>(
    await request.post(url, {
      headers: authHeaders(device.token, "POST", url),
      multipart: {
        size_bytes: String(bytes.length),
        realm_id: realmId,
        encryption: "null",
        content: {
          name: "blob.bin",
          mimeType: "application/octet-stream",
          buffer: bytes,
        },
      },
    }),
    "upload MLS public group state Blob",
  );
  const expectedRef = `ak:blob:sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  if (body.blob_ref !== expectedRef) {
    throw new Error(
      `MLS public state Blob upload returned ${String(body.blob_ref)}, expected its content address ${expectedRef}`,
    );
  }
  return expectedRef;
}

async function committedEventFullView(
  request: APIRequestContext,
  reader: MlsDevice,
  eventId: string,
): Promise<{ commit: Record<string, unknown>; event: Record<string, unknown> }> {
  const url = `${solandBaseUrl(reader.server)}/_arkret/self/committed-events/${eventId}`;
  let view: { commit?: Record<string, unknown>; event?: Record<string, unknown> } = {};
  await expect
    .poll(
      async () => {
        const response = await request.get(url, {
          headers: authHeaders(reader.token, "GET", url),
        });
        if (!response.ok()) return response.status();
        view = (await response.json()) as typeof view;
        return view.event?.event_id === eventId && view.commit ? 200 : 0;
      },
      {
        message: `accepted MLS Commit ${eventId} is readable`,
        timeout: 30_000,
        intervals: [250, 500, 1_000],
      },
    )
    .toBe(200);
  return { commit: view.commit!, event: view.event! };
}

/// The scope's current `mls_group` typed result from the caller-visible
/// Realm state snapshot (realm-state-snapshot.schema.json
/// `current_state_entries`), or `undefined` before any accepted Genesis.
export async function readScopeMlsGroupCurrentApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  scopeRef: Record<string, unknown> = { kind: "realm", realm_id: realmId },
  server?: SolandKey,
): Promise<MlsGroupCurrent | undefined> {
  const url = new URL(`${solandBaseUrl(server)}/_arkret/self/realm-state-snapshot/head`);
  url.searchParams.set("realm_id", realmId);
  const snapshot = await expectJsonOk<{
    current_state_entries?: Array<{
      selector?: { kind?: unknown; scope_ref?: unknown };
      value?: unknown;
    }>;
  }>(
    await request.get(url.toString(), {
      headers: authHeaders(token, "GET", url.toString()),
    }),
    `read Realm state snapshot for ${realmId}`,
  );
  const scopeKey = canonicalJson(scopeRef);
  const entries = (snapshot.current_state_entries ?? []).filter(
    (entry) =>
      entry.selector?.kind === "mls_group" &&
      canonicalJson(entry.selector.scope_ref) === scopeKey,
  );
  if (entries.length > 1) {
    throw new Error(`Realm snapshot carries ${entries.length} mls_group results for one scope`);
  }
  return entries[0]?.value as MlsGroupCurrent | undefined;
}

/// Activate MLS for the Realm scope: the owner's device founds the epoch-zero
/// group and the governance Station accepts its `ak.mls.genesis`.
export async function activateRealmMlsApi(
  request: APIRequestContext,
  owner: MlsDevice,
  realmId: string,
  opts: { stationId?: string } = {},
): Promise<string> {
  const genesis = cotestWire<{
    cipher_suite: string;
    governance_binding: Record<string, unknown>;
    creator_leaf_authority: Record<string, unknown>;
    group_info_b64url: string;
    ratchet_tree_b64url: string;
    group_state: string;
  }>("mls-genesis", {
    endpoint: endpointInput(owner),
    device_authorize_event_id: await deviceAuthorizeEventId(request, owner),
    realm_id: realmId,
  });
  const groupInfoRef = await uploadPublicBlob(
    request,
    owner,
    realmId,
    genesis.group_info_b64url,
  );
  const ratchetTreeRef = await uploadPublicBlob(
    request,
    owner,
    realmId,
    genesis.ratchet_tree_b64url,
  );
  const event = signedEventEnvelope({
    actorId: owner.id,
    server: owner.server,
    stationId: opts.stationId,
    realmId,
    kind: "ak.mls.genesis",
    payload: {
      cipher_suite: genesis.cipher_suite,
      group_info_ref: groupInfoRef,
      ratchet_tree_ref: ratchetTreeRef,
      governance_binding: genesis.governance_binding,
      creator_leaf_authority: genesis.creator_leaf_authority,
      created_at: canonicalTimestamp(),
    },
  });
  await submitSignedEventApi(request, owner.token, event, {
    server: owner.server,
    context: `accept MLS Genesis for ${realmId}`,
  });
  const creatorAuthority = genesis.creator_leaf_authority as {
    authorization_event_ref: string;
  };
  realmMlsCreators.set(realmKey(owner.server, realmId), {
    owner,
    groupState: genesis.group_state,
    members: [
      {
        actor_id: accountActorId(owner.id, owner.server, opts.stationId),
        device_id: owner.deviceId,
        device_authorize_event_id: creatorAuthority.authorization_event_ref,
        device_public_key_b64url: deviceSigner(owner).publicKeyB64url,
      },
    ],
  });
  return String(event.event_id);
}

/// Add one joined member's device to the Realm group: the member publishes a
/// KeyPackage, the group creator claims it, and one inline Add Commit that
/// covers the scope's current key-access revision carries the Welcome naming
/// the claim. The member joins later with `joinRealmMlsWelcomeApi`.
export async function addRealmMlsMemberApi(
  request: APIRequestContext,
  realmId: string,
  member: MlsDevice,
  opts: { server?: SolandKey } = {},
): Promise<{ commitEventId: string; welcome: Record<string, unknown> }> {
  const creator = realmMlsCreators.get(realmKey(opts.server, realmId));
  if (!creator) {
    throw new Error(`Realm ${realmId} has no MLS group founded by this harness`);
  }
  const owner = creator.owner;
  const ownerSigner = deviceSigner(owner);
  const memberSigner = deviceSigner(member);

  const published = cotestWire<{
    upload_request: Record<string, unknown>;
    identity_state: string;
  }>("mls-keypackages", { endpoint: endpointInput(member), count: 1 });
  const uploadUrl = `${solandBaseUrl(member.server)}/_arkret/self/keys/keypackages/upload`;
  const uploaded = await expectJsonOk<{
    accepted?: number;
    rejections?: unknown[];
  }>(
    await request.post(uploadUrl, {
      headers: {
        ...authHeaders(member.token, "POST", uploadUrl),
        "content-type": "application/json",
      },
      data: canonicalJson(published.upload_request),
    }),
    `publish MLS KeyPackage for ${member.id}`,
  );
  expect(uploaded.accepted, `KeyPackage of ${member.id} was not published`).toBe(1);
  expect(uploaded.rejections ?? []).toEqual([]);

  const ownerAccount = accountActorId(owner.id, owner.server).account_id;
  const claimBody = cotestWire<{ claim_request_id: string }>(
    "mls-keypackage-claim-request",
    {
      requester: {
        account_id: ownerAccount,
        device_id: owner.deviceId,
        verification_method: ownerSigner.verificationMethod,
        device_authorize_event_id: creator.members[0]!.device_authorize_event_id,
        signing_seed_b64url: ownerSigner.signingSeedB64url,
      },
      target_account_id: accountActorId(member.id, member.server).account_id,
      target_device_id: member.deviceId,
      realm_id: realmId,
      source_id: solandServiceId(owner.server),
      destination_id: solandServiceId(member.server),
      claim_request_id: randomBytes(16).toString("base64url"),
      lifetime_seconds: CLAIM_LIFETIME_SECONDS,
    },
  );
  const claimUrl = `${solandBaseUrl(owner.server)}/_arkret/self/keys/keypackages/claim`;
  const claimed = await expectJsonOk<{ claims?: Array<Record<string, unknown>> }>(
    await request.post(claimUrl, {
      headers: {
        ...authHeaders(owner.token, "POST", claimUrl),
        "content-type": "application/json",
        "idempotency-key": claimBody.claim_request_id,
      },
      data: canonicalJson(claimBody),
    }),
    `claim MLS KeyPackage of ${member.id}`,
  );
  const claims = claimed.claims ?? [];
  expect(claims, `claim of ${member.id} selects exactly one KeyPackage`).toHaveLength(1);
  const claim = claims[0]!;
  const memberAuthorizeEventId = claim.device_authorize_event_id;
  if (typeof memberAuthorizeEventId !== "string") {
    throw new Error(`claim of ${member.id} does not name its device authorization`);
  }

  const current = await readScopeMlsGroupCurrentApi(
    request,
    owner.token,
    realmId,
    undefined,
    owner.server,
  );
  if (!current) {
    throw new Error(`Realm ${realmId} has no accepted MLS group`);
  }
  const added = cotestWire<{
    commit_payload: Record<string, unknown>;
    welcome: Record<string, unknown>;
    group_state: string;
  }>("mls-add-member", {
    group_state: creator.groupState,
    claim,
    base_group_state_ref: current.current_mls_commit_event_ref,
    key_access_revision: current.current_key_access_revision,
  });
  const commitEvent = signedEventEnvelope({
    actorId: owner.id,
    server: owner.server,
    realmId,
    kind: "ak.mls.commit",
    payload: added.commit_payload,
  });
  const welcome = cotestWire<Record<string, unknown>>("mls-welcome-delivery", {
    commit_event: commitEvent,
    recipient_actor_id: accountActorId(member.id, member.server),
    recipient_device_id: member.deviceId,
    welcome: added.welcome,
    signing_seed_b64url: ownerSigner.signingSeedB64url,
  });
  const eventsUrl = `${solandBaseUrl(owner.server)}/_arkret/self/events`;
  const context = `Add Commit for ${member.id}`;
  const outcome = await expectJsonOk<Record<string, unknown>>(
    await request.post(eventsUrl, {
      headers: {
        ...authHeaders(owner.token, "POST", eventsUrl),
        "content-type": "application/json",
      },
      data: canonicalJson({
        commit_event: commitEvent,
        welcomes: [welcome],
        idempotency_key: uuidV7(),
      }),
    }),
    context,
  );
  assertAuthoritySubmitOutcome(outcome, commitEvent, context);

  const commitEventId = String(commitEvent.event_id);
  const accepted = await committedEventFullView(request, owner, commitEventId);
  const members = [
    ...creator.members,
    {
      actor_id: accountActorId(member.id, member.server),
      device_id: member.deviceId,
      device_authorize_event_id: memberAuthorizeEventId,
      device_public_key_b64url: memberSigner.publicKeyB64url,
    },
  ];
  const installed = cotestWire<{ group_state: string; epoch: number }>(
    "mls-install-commit",
    {
      group_state: added.group_state,
      accepted_commit: accepted,
      base: current,
      members,
    },
  );
  expect(installed.epoch).toBe(current.epoch + 1);
  creator.groupState = installed.group_state;
  creator.members = members;
  pendingJoins.set(joinKey(realmId, member), {
    identityState: published.identity_state,
    commitEventId,
    welcomeId: String(welcome.welcome_id),
    members,
    producerPublicKey: ownerSigner.publicKeyB64url,
  });
  return { commitEventId, welcome };
}

/// The member reads its Welcome from its own recipient queue, verifies it
/// against the accepted Commit and joins at that Commit's epoch. A member must
/// join from the most recent Add to encrypt at the current epoch.
export async function joinRealmMlsWelcomeApi(
  request: APIRequestContext,
  realmId: string,
  member: MlsDevice,
): Promise<MlsMemberGroup> {
  const pending = pendingJoins.get(joinKey(realmId, member));
  if (!pending) {
    throw new Error(`no MLS Welcome was admitted for ${member.id} in ${realmId}`);
  }
  const queueUrl = `${solandBaseUrl(member.server)}/_arkret/self/device_messages`;
  let welcome: Record<string, unknown> | undefined;
  let ackToken: string | undefined;
  await expect
    .poll(
      async () => {
        const page = await expectJsonOk<{
          deliveries?: Array<Record<string, unknown>>;
          ack_token?: string;
        }>(
          await request.get(queueUrl, {
            headers: authHeaders(member.token, "GET", queueUrl),
          }),
          `read recipient queue of ${member.id}`,
        );
        welcome = (page.deliveries ?? [])
          .filter((delivery) => delivery.delivery_kind === "mls_welcome")
          .map((delivery) => delivery.mls_welcome as Record<string, unknown>)
          .find((candidate) => candidate?.welcome_id === pending.welcomeId);
        ackToken = page.ack_token;
        return welcome !== undefined;
      },
      {
        message: `MLS Welcome for ${member.id} reaches its recipient queue`,
        timeout: 30_000,
        intervals: [250, 500, 1_000],
      },
    )
    .toBe(true);
  const accepted = await committedEventFullView(
    request,
    member,
    pending.commitEventId,
  );
  const joined = cotestWire<{ group_state: string; epoch: number }>(
    "mls-join-welcome",
    {
      identity_state: pending.identityState,
      actor_id: accountActorId(member.id, member.server),
      device_id: member.deviceId,
      welcome,
      accepted_commit: accepted,
      producer_public_key_b64url: pending.producerPublicKey,
      members: pending.members,
    },
  );
  if (ackToken) {
    const ackUrl = `${queueUrl}/ack`;
    await expectJsonOk(
      await request.post(ackUrl, {
        headers: {
          ...authHeaders(member.token, "POST", ackUrl),
          "content-type": "application/json",
        },
        data: canonicalJson({ ack_token: ackToken }),
      }),
      `ACK recipient queue of ${member.id}`,
    );
  }
  pendingJoins.delete(joinKey(realmId, member));
  return {
    realmId,
    groupState: joined.group_state,
    epoch: joined.epoch,
    groupStateRef: pending.commitEventId,
  };
}

/// The group creator's own endpoint as an encrypting member at the scope's
/// accepted current epoch. The creator installed every Add Commit this harness
/// admitted, so its state is at `current_mls_commit_event_ref`; encrypting
/// through the returned group advances that same creator state.
export async function realmMlsCreatorGroupApi(
  request: APIRequestContext,
  realmId: string,
  opts: { server?: SolandKey } = {},
): Promise<MlsMemberGroup> {
  const creator = realmMlsCreators.get(realmKey(opts.server, realmId));
  if (!creator) {
    throw new Error(`Realm ${realmId} has no MLS group founded by this harness`);
  }
  const current = await readScopeMlsGroupCurrentApi(
    request,
    creator.owner.token,
    realmId,
    { kind: "realm", realm_id: realmId },
    opts.server,
  );
  if (!current) {
    throw new Error(`Realm ${realmId} has no accepted MLS group`);
  }
  return {
    realmId,
    epoch: current.epoch,
    groupStateRef: current.current_mls_commit_event_ref,
    get groupState() {
      return creator.groupState;
    },
    set groupState(next: string) {
      creator.groupState = next;
    },
  };
}

/// Encrypt one Message body with the member's group at its current epoch.
/// Returns the `encrypted_content` envelope and advances the member's state.
export function encryptMlsMessageContent(
  group: MlsMemberGroup,
  content: Record<string, unknown>,
): Record<string, unknown> {
  const sealed = cotestWire<{
    encrypted_content: Record<string, unknown>;
    group_state: string;
  }>("mls-encrypt-message", {
    group_state: group.groupState,
    group_state_ref: group.groupStateRef,
    content,
  });
  group.groupState = sealed.group_state;
  return sealed.encrypted_content;
}
