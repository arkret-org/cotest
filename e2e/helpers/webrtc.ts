import {
  expect,
  type APIRequestContext,
  type APIResponse,
} from "@playwright/test";
import {
  createHash,
  generateKeyPairSync,
  sign as nodeSign,
  type KeyObject,
} from "node:crypto";
import { solandBaseUrl, solandServiceId } from "./env";
import {
  accountActorId,
  eventPrincipalId,
  addRealmMemberApi,
  authHeaders,
  accountSubscribeFramesApi,
  base64url,
  base64urlJsonCanonical,
  canonicalEventTimestamp,
  canonicalJson,
  canonicalTimestamp,
  createRealmApi,
  readRealmSealBasis,
  registeredEventVerificationMethod,
  retypeEventDerivedId,
  seedConformanceRealmBasisApi,
  signedEventEnvelope,
  signWithRegisteredEventSigner,
  submitSignedEventApi,
  typedId,
  waitForRealmControlIdleApi,
  wireErrCode,
} from "./soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
  type JointUser,
} from "./users";

// ── Spec signal-type enum (webrtc-signaling.md §5.1) ─────────────────────────
//
// The canonical `payload.signal_kind` enum from `arkret_sdk::CALL_SIGNAL_TYPES`
// (14 values). The retired soland stack accepted `offer` / `ice` /
// `device_change`; those are NOT spec signal types and a spec-faithful receiver
// (`validate_call_signal_envelope`) rejects them with `schema_violation`. The
// 1:1 offer/answer/candidate exchange rides `invite` / `answer` / `candidate`
// (see §6), the device switch rides a `renegotiate{reason:ice_restart}` frame.
export const CALL_SIGNAL_TYPES = [
  "invite",
  "answer",
  "candidate",
  "renegotiate",
  "hangup",
  "ack",
  "reject",
  "mute_state",
  "media_state",
  "speaking",
  "focus_join",
  "focus_leave",
  "moderation",
  "error",
] as const;

export type CallSignalType = (typeof CALL_SIGNAL_TYPES)[number];

export interface TwoPartyCallRealm {
  alice: JointUser;
  aliceToken: string;
  bob: JointUser;
  bobToken: string;
  realmId: string;
}

export async function setupTwoPartyCallRealm(
  request: APIRequestContext,
  label: string,
  opts: { realmTitlePrefix?: string } = {},
): Promise<TwoPartyCallRealm> {
  const stamp = Date.now();
  const alice = uniqueUser(`${label}-alice-${stamp}`);
  const bob = uniqueUser(`${label}-bob-${stamp}`);
  await Promise.all([
    ensureRegistered(request, alice),
    ensureRegistered(request, bob),
  ]);
  const aliceToken = await issueDevSession(request, alice);
  const bobToken = await issueDevSession(request, bob);
  const realmId = await createRealmApi(request, aliceToken, {
    title: `${opts.realmTitlePrefix ?? label} ${stamp}`,
    public: true,
    // Every Signal is bound to an accepted MLS group state. A Realm created
    // with encryption_profile=none is forbidden from having an MLS group, so
    // call fixtures must declare the MLS capability axis at genesis.
    encryption_profile: "mls_rfc9420",
  });
  await addRealmMemberApi(request, aliceToken, realmId, bob.id);
  return { alice, aliceToken, bob, bobToken, realmId };
}

// ── Real device signer (ed25519 detached-JWS proof, webrtc-signaling.md §5.1) ─
//
// The retired soland stack accepted a placeholder `{actor, kid, sig:"cotest-
// device-proof"}`. The spec `ak.call.signal` `proof` is a detached-JWS whose
// transcript signs the canonical binding object `{event_digest, actor_id,
// verification_method, created_at}` (§5.1, byte-identical to the persistent
// Event proof binding). This helper mints a REAL ed25519 keypair per
// (actor, device) and produces a real signature so the relay's
// `validate_production` + `event_digest == canonical(envelope_without_proof)`
// gates pass AND a real receiver running `verify_ed25519_detached_jws_proof`
// against this device's public key accepts it. The public key is exported via
// `deviceVerifyingKeyHex` so a conformance verifier can prove the signature is
// genuine, not a shape stub.

interface DeviceSigner {
  actorId: string;
  deviceId: string;
  verificationMethod: string;
  privateKey: KeyObject;
  publicKeyHex: string;
}

const deviceSignerCache = new Map<string, DeviceSigner>();

/**
 * Mint (or reuse) a real ed25519 signer for an `(actor, device)`. The keypair
 * is generated in-process; it is a genuine ed25519 key, never a hard-coded
 * string. The `verification_method` follows the spec `{actor_id}#{device_id}` form.
 */
function deviceSigner(actorId: string, deviceId: string): DeviceSigner {
  const key = `${actorId}\0${deviceId}`;
  const cached = deviceSignerCache.get(key);
  if (cached) {
    return cached;
  }
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  // Raw 32-byte ed25519 public key lives at the tail of the DER SPKI.
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const publicKeyHex = spki.subarray(spki.length - 32).toString("hex");
  const signer: DeviceSigner = {
    actorId,
    deviceId,
    verificationMethod: `${actorId}#${deviceId}`,
    privateKey,
    publicKeyHex,
  };
  deviceSignerCache.set(key, signer);
  return signer;
}

/** Hex of the device's raw ed25519 verifying key (for conformance verification). */
export function deviceVerifyingKeyHex(
  actorId: string,
  deviceId: string,
): string {
  return deviceSigner(actorId, deviceId).publicKeyHex;
}

function deviceVerifyingKeyMultibase(
  actorId: string,
  deviceId: string,
): string {
  const rawKey = Buffer.from(
    deviceSigner(actorId, deviceId).publicKeyHex,
    "hex",
  );
  return `z${base58Encode(Buffer.concat([Buffer.from([0xed, 0x01]), rawKey]))}`;
}

function base58Encode(bytes: Uint8Array): string {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let value = BigInt(`0x${Buffer.from(bytes).toString("hex")}`);
  let encoded = "";
  while (value > 0n) {
    encoded = alphabet[Number(value % 58n)] + encoded;
    value /= 58n;
  }
  let leadingZeroes = 0;
  while (leadingZeroes < bytes.length && bytes[leadingZeroes] === 0) {
    leadingZeroes += 1;
  }
  return "1".repeat(leadingZeroes) + (encoded || "1");
}

/** Build an encrypted-only Signal envelope for arbitrary client plaintext. */
export function buildSignalEnvelope(args: {
  actorId: string;
  deviceId: string;
  realmId: string;
  scopeRef?: Record<string, unknown>;
  plaintext: Record<string, unknown>;
  signalClass?: "session" | "moderation" | "setup";
  sentAt?: Date;
  lifetimeMs?: number;
}): Record<string, unknown> {
  const sentAt = args.sentAt ?? new Date();
  const signalClass = args.signalClass ?? "session";
  const classCeilingMs =
    signalClass === "setup"
      ? 120_000
      : signalClass === "moderation"
        ? 60_000
        : 30_000;
  const expiresAt = new Date(
    sentAt.getTime() + Math.min(args.lifetimeMs ?? 25_000, classCeilingMs),
  );
  const envelope: Record<string, unknown> = {
    realm_id: args.realmId,
    scope_ref: args.scopeRef ?? { kind: "realm", realm_id: args.realmId },
    sender_actor_id: accountActorId(args.actorId),
    sender_device_id: args.deviceId,
    seal_ref: `ak:seal:sha256:${"0".repeat(64)}`,
    signal_class: signalClass,
    sent_at: canonicalTimestamp(sentAt),
    expires_at: canonicalTimestamp(expiresAt),
    encrypted_payload: {
      scheme: "ak.signal_exporter_aead.v1",
      key_ref: {
        algorithm: "MLS-EXPORTER-AEAD",
        // Frozen accepted MLS group-state Event fixture. Event references use
        // DID tokens, never UUID placeholders.
        group_state_ref:
          "ak:event:Ab8fF-_JIKTb1BX6GXVZLOEoeeVFftSuQTq3Y8wtAvJT",
      },
      purpose: "ak.signal.v1",
      aead_profile: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      epoch: 0,
      nonce: base64url(Buffer.alloc(12)),
      ciphertext: base64url(Buffer.from(canonicalJson(args.plaintext), "utf8")),
      aad_digest: `sha256:${"0".repeat(64)}`,
    },
    proof: {
      kind: "detached_jws",
      verification_method:
        registeredEventVerificationMethod(args.actorId, args.deviceId) ??
        `${args.actorId}#${args.deviceId}`,
      envelope_digest: `sha256:${"0".repeat(64)}`,
      created_at: canonicalEventTimestamp(sentAt),
      jws: "",
    },
  };
  finalizeSignalEnvelopeProof(envelope);
  return envelope;
}

/** Build an encrypted-only Signal envelope draft for a call plaintext. */
export function buildCallSignalEnvelope(args: {
  actorId: string;
  deviceId: string;
  realmId: string;
  callId: string;
  signalType: CallSignalType | string;
  seq: number;
  data?: Record<string, unknown>;
  sentAt?: Date;
  lifetimeMs?: number;
}): Record<string, unknown> {
  const signalClass =
    args.signalType === "moderation"
      ? "moderation"
      : args.signalType === "invite"
        ? "setup"
        : "session";
  return buildSignalEnvelope({
    actorId: args.actorId,
    deviceId: args.deviceId,
    realmId: args.realmId,
    signalClass,
    sentAt: args.sentAt,
    lifetimeMs: args.lifetimeMs,
    plaintext: {
      kind: "ak.call.signal",
      call_id: args.callId,
      signal_kind: args.signalType,
      seq: args.seq,
      data: args.data ?? {},
    },
  });
}

function finalizeSignalEnvelopeProof(envelope: Record<string, unknown>): void {
  const encryptedPayload = envelope.encrypted_payload as Record<
    string,
    unknown
  >;
  const proof = envelope.proof as Record<string, unknown>;
  const aad = {
    realm_id: envelope.realm_id,
    scope_ref: envelope.scope_ref,
    sender_actor_id: envelope.sender_actor_id,
    sender_device_id: envelope.sender_device_id,
    seal_ref: envelope.seal_ref,
    signal_class: envelope.signal_class,
    sent_at: envelope.sent_at,
    expires_at: envelope.expires_at,
    scheme: encryptedPayload.scheme,
    key_ref: encryptedPayload.key_ref,
    purpose: encryptedPayload.purpose,
    aead_profile: encryptedPayload.aead_profile,
    epoch: encryptedPayload.epoch,
    nonce: encryptedPayload.nonce,
  };
  encryptedPayload.aad_digest = `sha256:${createHash("sha256")
    .update(canonicalJson(aad), "utf8")
    .digest("hex")}`;

  const unsigned = { ...envelope };
  delete unsigned.proof;
  const envelopeDigest = `sha256:${createHash("sha256")
    .update(canonicalJson(unsigned), "utf8")
    .digest("hex")}`;
  proof.envelope_digest = envelopeDigest;
  const bindingObject = {
    context: "ak.signal_proof.v1",
    envelope_digest: envelopeDigest,
    sender_actor_id: envelope.sender_actor_id,
    sender_device_id: envelope.sender_device_id,
    verification_method: proof.verification_method,
    created_at: proof.created_at,
  };
  const protectedHeader = base64urlJsonCanonical({ alg: "Ed25519" });
  const bindingPayload = base64urlJsonCanonical(bindingObject);
  const signingInput = `${protectedHeader}.${bindingPayload}`;
  const actorId = eventPrincipalId({ actor_id: envelope.sender_actor_id });
  const deviceId = String(envelope.sender_device_id);
  const signature =
    signWithRegisteredEventSigner(
      actorId,
      String(proof.verification_method),
      signingInput,
    ) ??
    base64url(
      nodeSign(
        null,
        Buffer.from(signingInput, "utf8"),
        deviceSigner(actorId, deviceId).privateKey,
      ),
    );
  proof.jws = `${protectedHeader}..${signature}`;
}

export function signalPlaintext(
  envelope: Record<string, unknown>,
): Record<string, unknown> {
  const encryptedPayload = envelope.encrypted_payload as
    Record<string, unknown> | undefined;
  if (typeof encryptedPayload?.ciphertext !== "string") {
    throw new Error("Signal envelope has no encrypted_payload.ciphertext");
  }
  return JSON.parse(
    Buffer.from(encryptedPayload.ciphertext, "base64url").toString("utf8"),
  ) as Record<string, unknown>;
}

export const callSignalPlaintext = signalPlaintext;

// ── Capability grants (authz.rs default rules) ───────────────────────────────
//
// The realm owner holds ALL realm-scoped actions by default (authz `reason:
// "owner"`), so an owner can send call signals / join without an explicit
// grant. A non-owner member only holds `ak.strand.read` / `ak.message.create`
// by default and MUST be granted `ak.call.signal.send` / `ak.call.join`
// explicitly. Grants are owner-issued (`capabilities.md` §3 — the issuer MUST
// hold the action; the owner does).

export const CAP_CALL_SIGNAL_SEND = "ak.call.signal.send";
export const CAP_CALL_JOIN = "ak.call.join";

export async function grantCallCapability(
  request: APIRequestContext,
  ownerToken: string,
  ownerId: string,
  realmId: string,
  subjectId: string,
  action: string,
): Promise<void> {
  const resources = [{ kind: "realm", realm_id: realmId }];
  const issuedAt = canonicalTimestamp();
  const authorityConstraint: Record<string, unknown> = {
    constraint_kind: "authority_control",
    effect: "allow",
    max_authority_depth: 0,
  };
  if (
    [
      "ak.moderation.decision",
      "ak.moderation.decision.lift",
    ].includes(action)
  ) {
    authorityConstraint.depends_on_moderation_state = true;
  }
  const unsignedGrant: Record<string, unknown> = {
    schema: "ak.schema.capability.v1",
    realm_id: realmId,
    issuer_id: accountActorId(ownerId),
    subject: accountActorId(subjectId),
    actions: [action],
    resources,
    constraints: [authorityConstraint],
    issued_at: issuedAt,
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
  await submitSignedEventApi(
    request,
    ownerToken,
    signedEventEnvelope({
      actorId: ownerId,
      realmId,
      kind: "ak.capability.grant",
      payload: {
        grant,
      },
    }),
    { context: `grant ${action} to ${subjectId}` },
  );
}

// ── ak.call.state durable cell (call-state.md §4 / webrtc-signaling.md §3a) ───
//
// The media token issuer + ban gate read the durable `ak.call.state` cell.
// Seeding it over HTTP submits a signed `ak.call.state` event; the
// `apply_call_state` reducer projects it into
// `ak.component.call.state.v1:{call_id}`.

export interface RemovedParticipant {
  actor_id: string;
  device_id?: string;
  action: "kick" | "ban";
  removed_at?: string;
}

const callLifecycleByRealmAndCall = new Map<string, string>();

async function waitForRealmSealAdvance(
  request: APIRequestContext,
  token: string,
  realmId: string,
  previousBasis: Record<string, unknown>,
): Promise<void> {
  const previousLeaves = JSON.stringify(previousBasis.leaves);
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    const current = await readRealmSealBasis(request, token, realmId);
    // Event seal_basis carries only the sorted predecessor leaves. Seal roots
    // stay on the referenced Seal and are recomputed by the receiver.
    if (JSON.stringify(current.leaves) !== previousLeaves) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(
    `Realm Seal did not advance after Control Move in ${realmId}`,
  );
}

export async function seedCallState(
  request: APIRequestContext,
  ownerToken: string,
  ownerId: string,
  realmId: string,
  callId: string,
  opts: {
    state?: string;
    sessionFocus?: string;
    participants?: Array<Record<string, unknown>>;
    removedParticipants?: RemovedParticipant[];
  } = {},
): Promise<void> {
  if ((opts.participants?.length ?? 0) > 1) {
    throw new Error("ak.call.state carries at most one roster_delta per event");
  }
  if ((opts.removedParticipants?.length ?? 0) > 1) {
    throw new Error(
      "ak.call.state carries at most one moderation_delta per event",
    );
  }
  const lifecycleKey = `${realmId}\u001f${callId}`;
  const previousState = callLifecycleByRealmAndCall.get(lifecycleKey);
  if (!previousState) {
    throw new Error(
      `call ${callId} has no accepted ak.call.create lifecycle in ${realmId}`,
    );
  }
  const nextState = opts.state ?? "active";
  const payload: Record<string, unknown> = {
    call_id: callId,
    state_transition: {
      from: previousState,
      to: nextState,
    },
  };
  if (opts.sessionFocus) {
    const focus = { mode: "sfu", session_focus: opts.sessionFocus };
    payload.focus = focus;
  }
  const participant = opts.participants?.[0];
  if (participant) {
    payload.roster_delta = { op: "join", participant: { ...participant, actor_id: typeof participant.actor_id === "string" ? accountActorId(participant.actor_id) : participant.actor_id } };
  }
  const removedParticipant = opts.removedParticipants?.[0];
  if (removedParticipant) {
    const removal = {
      actor_id: accountActorId(removedParticipant.actor_id),
      ...(removedParticipant.device_id
        ? { device_id: removedParticipant.device_id }
        : {}),
      action: removedParticipant.action,
      removed_by: ownerId,
      removed_at: removedParticipant.removed_at ?? canonicalTimestamp(),
    };
    payload.moderation_delta = {
      op: "remove_participant",
      removal,
    };
  }
  const sealBasis = await readRealmSealBasis(request, ownerToken, realmId);
  await submitSignedEventApi(
    request,
    ownerToken,
    signedEventEnvelope({
      actorId: ownerId,
      realmId,
      kind: "ak.call.state",
      sealBasis,
      payload,
    }),
    { context: `seed ak.call.state ${callId}` },
  );
  await waitForRealmSealAdvance(request, ownerToken, realmId, sealBasis);
  callLifecycleByRealmAndCall.set(lifecycleKey, nextState);
}

export async function createCallApi(
  request: APIRequestContext,
  ownerToken: string,
  ownerId: string,
  realmId: string,
  initialState: "scheduled" | "ringing" | "connecting" = "ringing",
): Promise<string> {
  const sealBasis = await readRealmSealBasis(request, ownerToken, realmId);
  const envelope = signedEventEnvelope({
    actorId: ownerId,
    realmId,
    kind: "ak.call.create",
    sealBasis,
    payload: { initial_state: initialState },
  });
  await submitSignedEventApi(request, ownerToken, envelope, {
    context: `create call in ${realmId}`,
  });
  await waitForRealmSealAdvance(request, ownerToken, realmId, sealBasis);
  const callId = retypeEventDerivedId(String(envelope.event_id), "call");
  callLifecycleByRealmAndCall.set(`${realmId}\u001f${callId}`, initialState);
  return callId;
}

/** Mint a fresh `ak:call:<44-char-event-token>` id. */
export function newCallId(): string {
  return typedId("call");
}

// ── Signal submit + subscribe read-back (canonical wire) ────────────────────

/**
 * Submit one encrypted Signal envelope. The Seal reference is resolved just
 * before signing so the proof and AAD bind the current accepted basis.
 */
export async function prepareSignalEnvelope(
  request: APIRequestContext,
  token: string,
  envelope: Record<string, unknown>,
): Promise<void> {
  const realmId = String(envelope.realm_id);
  const actorId = eventPrincipalId({ actor_id: envelope.sender_actor_id });
  const deviceId = String(envelope.sender_device_id);
  if (!registeredEventVerificationMethod(actorId, deviceId)) {
    const keyResponse = await request.post(
      `${solandBaseUrl()}/_arkret/_conformance/device-signing-key`,
      {
        data: {
          actor_id: actorId,
          device_id: deviceId,
          public_key_multibase: deviceVerifyingKeyMultibase(actorId, deviceId),
        },
      },
    );
    expect(
      keyResponse.status(),
      `seed Signal device key returned ${keyResponse.status()}: ${await keyResponse.text()}`,
    ).toBe(200);
  }
  let basis: Record<string, unknown>;
  try {
    basis = await readRealmSealBasis(request, token, realmId);
    envelope.seal_ref = (basis.leaves as string[])[0];
  } catch {
    basis = await seedConformanceRealmBasisApi(
      request,
      realmId,
      actorId,
      ["ak.message.create"],
    );
    envelope.seal_ref = basis.seal_id;
  }
  const mlsBasis = await ensureSignalMlsBasis(
    request,
    actorId,
    deviceId,
    realmId,
    envelope.scope_ref as Record<string, unknown>,
    basis,
  );
  const encryptedPayload = envelope.encrypted_payload as Record<string, unknown>;
  const keyRef = encryptedPayload.key_ref as Record<string, unknown>;
  keyRef.group_state_ref = mlsBasis.group_state_ref;
  encryptedPayload.epoch = mlsBasis.epoch;
  finalizeSignalEnvelopeProof(envelope);
}

type SignalMlsBasis = {
  group_state_ref: string;
  mls_group_id: string;
  epoch: number;
};

const signalMlsBasisCache = new Map<string, Promise<SignalMlsBasis>>();

async function ensureSignalMlsBasis(
  request: APIRequestContext,
  actorId: string,
  deviceId: string,
  realmId: string,
  scopeRef: Record<string, unknown>,
  sealBasis: Record<string, unknown>,
): Promise<SignalMlsBasis> {
  const cacheKey = canonicalJson(scopeRef);
  const cached = signalMlsBasisCache.get(cacheKey);
  if (cached) return await cached;
  const pending = (async () => {
    const createdAt = canonicalTimestamp();
    const scopeKey =
      scopeRef.kind === "circle"
        ? String(scopeRef.circle_id)
        : scopeRef.kind === "sidecar"
          ? `${realmId}\u001f${String(scopeRef.sidecar_id)}`
          : realmId;
    // encryption-and-audit.md section 5.1 fixes this to unpadded base64url of
    // the canonical effective-scope key bytes.
    const mlsGroupId = base64url(Buffer.from(scopeKey, "utf8"));
    const genesis = signedEventEnvelope({
      actorId,
      realmId,
      kind: "ak.mls.genesis",
      createdAt,
      scopeRef,
      sealBasis,
      payload: {
        mls_group_id: mlsGroupId,
        effective_scope: scopeRef,
        epoch: 0,
        cipher_suite:
          "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        group_info_ref: `ak:blob:sha256:${"3".repeat(64)}`,
        ratchet_tree_ref: `ak:blob:sha256:${"4".repeat(64)}`,
        governance_binding: {
          binding_version: 1,
          encoding_profile: "cbor-deterministic-rfc8949-v1",
          realm_id: realmId,
          ...(scopeRef.kind === "circle"
            ? { circle_id: scopeRef.circle_id }
            : {}),
          ...(scopeRef.kind === "sidecar"
            ? { sidecar_id: scopeRef.sidecar_id }
            : {}),
          effective_scope: scopeRef,
          mls_group_id: mlsGroupId,
          previous_epoch: 0,
          next_epoch: 0,
          // The endpoint is a development-only state-injection fixture under
          // the exact namespace reserved by service-http-binding.md section
          // 2.1.3. Production Genesis still obtains this digest from the
          // verified governance-proof flow.
          security_frontier_digest: `sha256:${"0".repeat(64)}`,
          content_scheme: "mls_rfc9420",
          binding_profile: "ak.profile.mls_governance_binding.full.v1",
          reducer_profile: "ak.reducer.core.v1",
        },
        created_at: createdAt,
      },
    });
    const response = await request.post(
      `${solandBaseUrl()}/_arkret/_conformance/signal-mls-basis`,
      {
        headers: { "content-type": "application/json" },
        data: canonicalJson({
          creator_device_id: deviceId,
          genesis_event: genesis,
        }),
      },
    );
    const text = await response.text();
    expect(
      response.status(),
      `install Signal MLS basis returned ${response.status()}: ${text}`,
    ).toBe(200);
    return JSON.parse(text) as SignalMlsBasis;
  })();
  signalMlsBasisCache.set(cacheKey, pending);
  try {
    return await pending;
  } catch (error) {
    signalMlsBasisCache.delete(cacheKey);
    throw error;
  }
}

export async function postCallSignalRaw(
  request: APIRequestContext,
  token: string,
  envelope: Record<string, unknown>,
): Promise<APIResponse> {
  await prepareSignalEnvelope(request, token, envelope);
  return await postPreparedSignalEnvelopeRaw(request, token, envelope);
}

async function postPreparedSignalEnvelopeRaw(
  request: APIRequestContext,
  token: string,
  envelope: Record<string, unknown>,
): Promise<APIResponse> {
  return await request.post(`${solandBaseUrl()}/_arkret/self/signal`, {
    headers: { ...authHeaders(token), "content-type": "application/json" },
    data: canonicalJson(envelope),
  });
}

/**
 * Submit a call Signal and assert the opaque relay accepted it.
 */
export async function postCallSignal(
  request: APIRequestContext,
  token: string,
  envelope: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const response = await postCallSignalRaw(request, token, envelope);
  const text = await response.text();
  expect(
    response.status(),
    `relay ak.call.signal ${String(
      callSignalPlaintext(envelope).signal_kind,
    )} returned ${response.status()}: ${text}`,
  ).toBe(200);
  const body = JSON.parse(text) as Record<string, unknown>;
  expect(body.accepted, "relay accepted the signal").toBe(true);
  expect(body.realm_id).toBe(envelope.realm_id);
  return body;
}

/**
 * Read verbatim encrypted Signal envelopes from the dedicated live stream.
 */
export async function relayedCallSignals(
  request: APIRequestContext,
  token: string,
  realmId: string,
): Promise<Array<Record<string, unknown>>> {
  const url = new URL(`${solandBaseUrl()}/_arkret/self/signal/subscribe`);
  url.searchParams.set("max_duration_ms", "400");
  url.searchParams.set("heartbeat_ms", "600000");
  const response = await fetch(url, {
    headers: {
      ...authHeaders(token),
      accept: "application/x-ndjson",
      "Arkret-Operation": "ak.self.signal.stream.subscribe.v1",
    },
  });
  const text = await response.text();
  expect(
    response.status,
    `signal subscribe returned ${response.status}: ${text}`,
  ).toBe(200);
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line) as Record<string, unknown>)
    .filter((frame) => frame.kind === "signal")
    .map((frame) => frame.envelope as Record<string, unknown>)
    .filter(
      (envelope) =>
        envelope.realm_id === realmId &&
        envelope.encrypted_payload !== undefined,
    );
}

/**
 * Keep a receiver's live Signal rail open while `action` sends one or more
 * envelopes. Product-level assertions must decrypt/filter the returned
 * envelopes on the receiver side; the service only sees the outer class/scope.
 */
export async function captureSignalEnvelopes<T>(
  token: string,
  realmId: string,
  action: () => Promise<T>,
): Promise<{ result: T; envelopes: Array<Record<string, unknown>> }> {
  const url = new URL(`${solandBaseUrl()}/_arkret/self/signal/subscribe`);
  url.searchParams.set("max_duration_ms", "800");
  url.searchParams.set("heartbeat_ms", "25");
  const responsePromise = fetch(url, {
    headers: {
      ...authHeaders(token),
      accept: "application/x-ndjson",
      "Arkret-Operation": "ak.self.signal.stream.subscribe.v1",
    },
  });
  // Let the HTTP request reach the live subscriber registry before sending.
  await new Promise((resolve) => setTimeout(resolve, 75));
  const result = await action();
  const response = await responsePromise;
  const text = await response.text();
  expect(
    response.status,
    `signal subscribe returned ${response.status}: ${text}`,
  ).toBe(200);
  const envelopes = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line) as Record<string, unknown>)
    .filter((frame) => frame.kind === "signal")
    .map((frame) => frame.envelope as Record<string, unknown>)
    .filter(
      (envelope) =>
        envelope.realm_id === realmId &&
        envelope.encrypted_payload !== undefined,
    );
  return { result, envelopes };
}

/**
 * Prepare a Signal envelope before opening the receiver's live-only rail,
 * then submit it while that rail is active. Preparation may resolve a Seal
 * basis and register a device key, so doing it inside `action` can outlive the
 * deliberately short capture window.
 */
export async function captureSubmittedSignalEnvelope(
  request: APIRequestContext,
  senderToken: string,
  receiverToken: string,
  realmId: string,
  envelope: Record<string, unknown>,
): Promise<{
  result: APIResponse;
  envelopes: Array<Record<string, unknown>>;
}> {
  await prepareSignalEnvelope(request, senderToken, envelope);
  return await captureSignalEnvelopes(receiverToken, realmId, () =>
    postPreparedSignalEnvelopeRaw(request, senderToken, envelope),
  );
}

export { authHeaders };

// ── Media-service binding (AKP-0010) — token exchange helpers ────────────────
//
// These back the `ak.realm.media_service` foci configuration and the
// `POST /_arkret/self/rtc/token` media token exchange. The foci selection
// follows the spec oldest-membership-wins rule (media-service-binding.md §5);
// the issued LiveKit token is a standard 3-segment JWT so the harness can
// decode the LiveKit `video` grant claims without a live SFU.

export const PARTICIPANT_BINDING_SCHEME = "ak.media.participant_binding.v1";

// Closed `media_service_focus` shape (event-payload.schema.json:10721-10726,
// media-service-binding.md §2): required focus_id / focus_kind /
// token_endpoint / connect_url, additionalProperties false. Issuance
// configuration (issuer_kid, audience, TTL, e2ee key source) is deployment
// configuration of the issuing service, never Realm cell state.
export interface MediaFocusConfig {
  focus_id: string;
  focus_kind: string;
  token_endpoint: string;
  connect_url: string;
}

/**
 * Project a `ak.realm.media_service` epoch onto the realm so the token issuer
 * can resolve `service_id` and `foci[]`. `service_id` anchors every issued
 * `participant_binding.issuer_kid`
 * (media-service-binding.md §3): the deployment's media signing key
 * (`SOLAND_MEDIA_ISSUER_KID`, default `<service DID>#media-1`) must
 * project onto it, and each focus `token_endpoint` origin must be this
 * deployment's public base URL, or issuance fails closed.
 */
export async function configureMediaService(
  request: APIRequestContext,
  token: string,
  realmId: string,
  ownerId: string,
  serviceId: string,
  foci: MediaFocusConfig[],
): Promise<void> {
  const payload = { value: { service_id: serviceId, foci } };
  const cell = "ak:cell:ak.component.realm.media_service.v1:null";
  const sealBasis = await readRealmSealBasis(request, token, realmId);
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorId: ownerId,
      realmId,
      kind: "ak.realm.media_service",
      sealBasis,
      preconditions: [{ cell_id: cell, predicate: { op: "head_eq", value: null } }],
      payload,
    }),
    { context: `configure media_service for ${realmId}` },
  );
  await waitForRealmControlIdleApi(request, token, realmId, {
    afterControlEventSetRoot: String(sealBasis.control_event_set_root),
  });
}

export async function exchangeMediaToken(
  request: APIRequestContext,
  token: string,
  body: {
    realm_id: string;
    call_id: string;
    actor_id: string;
    device_id: string;
    focus_id: string;
    desired_media?: { audio?: boolean; video?: boolean; screen?: boolean };
    capability_refs?: string[];
  },
): Promise<APIResponse> {
  return await request.post(`${solandBaseUrl()}/_arkret/self/rtc/token`, {
    headers: { ...authHeaders(token), "content-type": "application/json" },
    data: canonicalJson({ ...body, actor_id: accountActorId(body.actor_id) }),
  });
}

/**
 * Derive the opaque backend room id specified by bindings/livekit.md.
 */
export function expectedLiveKitRoom(
  realmId: string,
  callId: string,
  focusId: string,
): string {
  const digest = createHash("sha256")
    .update(`${realmId}\0${callId}\0${focusId}`, "utf8")
    .digest("hex");
  return `ak_call_${digest.slice(0, 16)}`;
}

/**
 * Decode the standard LiveKit JWT backend token and return its claim object.
 * The payload is canonical-JSON base64url (no padding).
 */
export function decodeLiveKitToken(
  backendToken: string,
): Record<string, unknown> {
  const segments = backendToken.split(".");
  expect(segments.length, "livekit token is a standard 3-segment JWT").toBe(3);
  // bindings/livekit.md §2: backend_token is a real LiveKit JWT
  // (base64url(header).base64url(payload).base64url(HS256 sig)) — a wrapping
  // `livekit.` envelope prefix is not accepted. Header MUST be {alg:HS256, typ:JWT}.
  const header = JSON.parse(
    Buffer.from(segments[0], "base64url").toString("utf8"),
  ) as Record<string, unknown>;
  expect(header.alg, "livekit JWT alg").toBe("HS256");
  expect(header.typ, "livekit JWT typ").toBe("JWT");
  const payloadJson = Buffer.from(segments[1], "base64url").toString("utf8");
  return JSON.parse(payloadJson) as Record<string, unknown>;
}

export interface ArkretNativeBackendToken {
  kid: string;
  payload: {
    call_id: string;
    focus_id: string;
    participant_id: string;
    issued_at: string;
    expires_at: string;
    media: { audio: boolean; video: boolean; screen: boolean };
  };
  sig: string;
  signature_algorithm: "Ed25519";
}

/** Decode and validate the arkret-native binding's closed backend token. */
export function decodeArkretNativeToken(
  backendToken: unknown,
): ArkretNativeBackendToken {
  expect(typeof backendToken).toBe("object");
  expect(backendToken).not.toBeNull();
  expect(Array.isArray(backendToken)).toBe(false);
  const parsed = backendToken as Record<string, unknown>;
  expect(Object.keys(parsed).sort()).toEqual([
    "kid",
    "payload",
    "sig",
    "signature_algorithm",
  ]);
  expect(typeof parsed.kid).toBe("string");
  expect(typeof parsed.sig).toBe("string");
  expect(parsed.signature_algorithm).toBe("Ed25519");
  expect(typeof parsed.payload).toBe("object");
  expect(parsed.payload).not.toBeNull();
  return parsed as unknown as ArkretNativeBackendToken;
}

// ── ICE config (webrtc-signaling.md §4.1) ────────────────────────────────────

export async function fetchIceConfig(
  request: APIRequestContext,
  token: string,
  body: {
    realm_id: string;
    call_id: string;
    actor_id: string;
    device_id: string;
    mode?: string;
  },
): Promise<APIResponse> {
  return await request.post(`${solandBaseUrl()}/_arkret/self/rtc/ice-config`, {
    headers: { ...authHeaders(token), "content-type": "application/json" },
    data: canonicalJson({ mode: "p2p", ...body, actor_id: accountActorId(body.actor_id) }),
  });
}

export { wireErrCode };
