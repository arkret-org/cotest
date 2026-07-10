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
import { solandBaseUrl } from "./env";
import {
  addRealmMemberApi,
  authHeaders,
  accountSubscribeFramesApi,
  base64url,
  base64urlJsonCanonical,
  buildDetachedJwsProof,
  canonicalJson,
  canonicalTimestamp,
  createRealmApi,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
  uuidV7,
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
// The canonical `payload.signal_type` enum from `arkret_sdk::CALL_SIGNAL_TYPES`
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
  });
  await addRealmMemberApi(request, aliceToken, realmId, bob.did);
  return { alice, aliceToken, bob, bobToken, realmId };
}

// ── Real device signer (ed25519 detached-JWS proof, webrtc-signaling.md §5.1) ─
//
// The retired soland stack accepted a placeholder `{actor, kid, sig:"cotest-
// device-proof"}`. The spec `ck.call.signal` `proof` is a detached-JWS whose
// transcript signs the canonical binding object `{event_digest, actor_id,
// verification_method, created_at}` (§5.1, byte-identical to the persistent
// Event proof binding). This helper mints a REAL ed25519 keypair per
// (actor, device) and produces a real signature so the relay's
// `validate_production` + `event_digest == canonical(envelope_without_proof)`
// gates pass AND a real receiver running `verify_eddsa_detached_jws_proof`
// against this device's public key accepts it. The public key is exported via
// `deviceVerifyingKeyHex` so a conformance verifier can prove the signature is
// genuine, not a shape stub.

interface DeviceSigner {
  actorDid: string;
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
function deviceSigner(actorDid: string, deviceId: string): DeviceSigner {
  const key = `${actorDid}\0${deviceId}`;
  const cached = deviceSignerCache.get(key);
  if (cached) {
    return cached;
  }
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  // Raw 32-byte ed25519 public key lives at the tail of the DER SPKI.
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const publicKeyHex = spki.subarray(spki.length - 32).toString("hex");
  const signer: DeviceSigner = {
    actorDid,
    deviceId,
    verificationMethod: `${actorDid}#${deviceId}`,
    privateKey,
    publicKeyHex,
  };
  deviceSignerCache.set(key, signer);
  return signer;
}

/** Hex of the device's raw ed25519 verifying key (for conformance verification). */
export function deviceVerifyingKeyHex(
  actorDid: string,
  deviceId: string,
): string {
  return deviceSigner(actorDid, deviceId).publicKeyHex;
}

export function withBroadcastEphemeralProof(
  envelope: Record<string, unknown>,
): Record<string, unknown> {
  const actorDid = envelope.actor_id;
  const deviceId = envelope.device_id;
  if (typeof actorDid !== "string" || typeof deviceId !== "string") {
    throw new Error("broadcast ephemeral proof requires actor_id and device_id");
  }
  const signer = deviceSigner(actorDid, deviceId);
  const createdAt =
    typeof envelope.sent_at === "string"
      ? envelope.sent_at
      : canonicalTimestamp(new Date());
  const unsigned = { ...envelope };
  delete unsigned.proof;
  const eventDigest = `sha256:${createHash("sha256")
    .update(canonicalJson(unsigned), "utf8")
    .digest("hex")}`;
  const bindingObject = {
    event_digest: eventDigest,
    actor_id: actorDid,
    verification_method: signer.verificationMethod,
    created_at: createdAt,
  };
  const protectedHeader = base64urlJsonCanonical({ alg: "EdDSA" });
  const bindingPayload = base64urlJsonCanonical(bindingObject);
  const signingInput = `${protectedHeader}.${bindingPayload}`;
  const signature = nodeSign(
    null,
    Buffer.from(signingInput, "utf8"),
    signer.privateKey,
  );
  return {
    ...unsigned,
    proof: {
      kind: "detached_jws",
      alg: "EdDSA",
      verification_method: signer.verificationMethod,
      event_digest: eventDigest,
      created_at: createdAt,
      jws: `${protectedHeader}..${base64url(signature)}`,
    },
  };
}

/**
 * Build a real `ck.call.signal` ephemeral envelope (webrtc-signaling.md §5)
 * with a genuine detached-JWS `proof` (§5.1). `event_digest` =
 * `sha256:` || hex(sha256(canonical_json(envelope_without_proof))); the JWS
 * transcript signs the canonical binding object.
 */
export function buildCallSignalEnvelope(args: {
  actorDid: string;
  deviceId: string;
  realmId: string;
  callId: string;
  signalType: CallSignalType | string;
  seq: number;
  data?: Record<string, unknown>;
  sentAt?: Date;
  lifetimeMs?: number;
}): Record<string, unknown> {
  const signer = deviceSigner(args.actorDid, args.deviceId);
  const sentAt = args.sentAt ?? new Date();
  const expiresAt = new Date(sentAt.getTime() + (args.lifetimeMs ?? 30_000));
  const createdAt = canonicalTimestamp(sentAt);

  const envelope: Record<string, unknown> = {
    kind: "ak.call.signal",
    realm_id: args.realmId,
    actor_id: args.actorDid,
    device_id: args.deviceId,
    sent_at: canonicalTimestamp(sentAt),
    expires_at: canonicalTimestamp(expiresAt),
    payload: {
      call_id: args.callId,
      signal_type: args.signalType,
      seq: args.seq,
      data: args.data ?? {},
    },
  };

  // §5.1 — event_digest over the canonical envelope with `proof` removed.
  const eventDigest = `sha256:${createHash("sha256")
    .update(canonicalJson(envelope), "utf8")
    .digest("hex")}`;

  // §5.1 — the JWS transcript is the canonical binding object, NOT the raw
  // envelope bytes. Field-for-field identical to the SDK proof binding so a
  // single verifier (`verify_eddsa_detached_jws_proof`) serves call signals
  // and persistent events alike.
  const bindingObject = {
    event_digest: eventDigest,
    actor_id: args.actorDid,
    verification_method: signer.verificationMethod,
    created_at: createdAt,
  };
  // SDK-canonical detached-JWS protected header is EXACTLY `{"alg":"EdDSA"}`.
  // The SDK verifier (`verify_eddsa_detached_jws_proof`) deserialises the header
  // with deny-unknown-fields, so a `kid` (or any extra member) breaks real
  // receiver verification — the verification_method rides the proof object +
  // binding, not the header. (Pinned by the call_signal proof_detached_jws
  // conformance vector, which round-trips this exact construction.)
  const protectedHeader = base64urlJsonCanonical({ alg: "EdDSA" });
  const bindingPayload = base64urlJsonCanonical(bindingObject);
  // RFC 7797 detached-JWS signing input = `<protected>.<payload>`; the wire
  // `jws` blanks the payload segment (`<protected>..<sig>`).
  const signingInput = `${protectedHeader}.${bindingPayload}`;
  const signature = nodeSign(null, Buffer.from(signingInput, "utf8"), signer.privateKey);

  envelope.proof = {
    kind: "detached_jws",
    alg: "EdDSA",
    verification_method: signer.verificationMethod,
    event_digest: eventDigest,
    created_at: createdAt,
    jws: `${protectedHeader}..${base64url(signature)}`,
  };
  return envelope;
}

// ── Capability grants (authz.rs default rules) ───────────────────────────────
//
// The realm owner holds ALL realm-scoped actions by default (authz `reason:
// "owner"`), so an owner can send call signals / join without an explicit
// grant. A non-owner member only holds `ck.strand.read` / `ck.message.create`
// by default and MUST be granted `ck.call.signal.send` / `ck.call.join`
// explicitly. Grants are owner-issued (`capabilities.md` §3 — the issuer MUST
// hold the action; the owner does).

export const CAP_CALL_SIGNAL_SEND = "ak.call.signal.send";
export const CAP_CALL_JOIN = "ak.call.join";
export const CAP_CALL_MODERATE = "ak.call.moderate";

export async function grantCallCapability(
  request: APIRequestContext,
  ownerToken: string,
  ownerDid: string,
  realmId: string,
  subjectDid: string,
  action: string,
): Promise<void> {
  const grantId = typedId("grant");
  const resources = [{ kind: "realm", realm_id: realmId }];
  const issuedAt = canonicalTimestamp();
  const delegationConstraint: Record<string, unknown> = {
    constraint_type: "delegation_control",
    effect: "allow",
    max_delegation_depth: 0,
  };
  if (
    [
      "ak.moderation.decision",
      "ak.moderation.decision.lift",
      "ak.realm.moderation_policy",
    ].includes(action)
  ) {
    delegationConstraint.depends_on_moderation_state = true;
  }
  const unsignedGrant: Record<string, unknown> = {
    id: grantId,
    schema: "ak.schema.capability.v1",
    realm_id: realmId,
    issuer: ownerDid,
    subject: subjectDid,
    actions: [action],
    resources,
    constraints: [delegationConstraint],
    issued_at: issuedAt,
  };
  const grant = {
    ...unsignedGrant,
    proofs: [
      buildDetachedJwsProof({
        issuerDid: ownerDid,
        payload: unsignedGrant,
        createdAt: issuedAt,
      }),
    ],
  };
  await submitSignedEventApi(
    request,
    ownerToken,
    signedEventEnvelope({
      actorDid: ownerDid,
      realmId,
      kind: "ak.capability.grant",
      payload: {
        grant_id: grantId,
        grant,
      },
    }),
    { context: `grant ${action} to ${subjectDid}` },
  );
}

// ── ak.call.state durable cell (call-state.md §4 / webrtc-signaling.md §3a) ───
//
// The media token issuer + ban gate read the durable `ck.call.state` cell.
// Seeding it over HTTP submits a signed `ck.call.state` event; the
// `apply_call_state` reducer projects it into
// `ck.component.call.state.v1:{call_id}`.

export interface RemovedParticipant {
  actor_id: string;
  device_id?: string;
  action: "kick" | "ban";
  removed_at?: string;
}

export async function seedCallState(
  request: APIRequestContext,
  ownerToken: string,
  ownerDid: string,
  realmId: string,
  callId: string,
  opts: {
    state?: string;
    sessionFocus?: string;
    participants?: Array<Record<string, unknown>>;
    removedParticipants?: RemovedParticipant[];
  } = {},
): Promise<void> {
  const payload: Record<string, unknown> = {
    call_id: callId,
    state: opts.state ?? "active",
  };
  if (opts.sessionFocus) {
    payload.session_focus = opts.sessionFocus;
  }
  if (opts.participants) {
    payload.participants = opts.participants;
  }
  if (opts.removedParticipants) {
    payload.removed_participants = opts.removedParticipants.map((entry) => ({
      actor_id: entry.actor_id,
      ...(entry.device_id ? { device_id: entry.device_id } : {}),
      action: entry.action,
      removed_at: entry.removed_at ?? canonicalTimestamp(),
    }));
  }
  await submitSignedEventApi(
    request,
    ownerToken,
    signedEventEnvelope({
      actorDid: ownerDid,
      realmId,
      kind: "ak.call.state",
      payload,
    }),
    { context: `seed ak.call.state ${callId}` },
  );
}

/** Mint a fresh `ak:call:<uuidv7>` id. The media token issuer + signaling are
 *  decoupled from any prior session (media-service-binding.md settlement ordering).
 *  `ak:call:` is its own id-kind (id-kind-registry.json), independent of the
 *  generic `OperationKind` set, so we mint a uuidv7 directly. */
export function newCallId(): string {
  return `ak:call:${uuidV7()}`;
}

// ── Ephemeral submit + subscribe read-back (canonical wire) ──────────────────

/**
 * Submit a `ck.call.signal` envelope to `POST /_arkret/self/ephemeral`. Returns
 * the raw response so callers can assert both success and negative (e.g.
 * `capability_denied`) paths.
 */
export async function postCallSignalRaw(
  request: APIRequestContext,
  token: string,
  envelope: Record<string, unknown>,
): Promise<APIResponse> {
  return await request.post(`${solandBaseUrl()}/_arkret/self/ephemeral`, {
    headers: authHeaders(token),
    data: envelope,
  });
}

/**
 * Submit a `ck.call.signal` and assert it is accepted + relayed. Returns the
 * `EphemeralSubmitOutcome` body.
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
      (envelope.payload as Record<string, unknown>)?.signal_type,
    )} returned ${response.status()}: ${text}`,
  ).toBe(200);
  const body = JSON.parse(text) as Record<string, unknown>;
  expect(body.accepted, "relay accepted the signal").toBe(true);
  expect(body.kind).toBe("ak.call.signal");
  return body;
}

/**
 * Read the verbatim relayed `ck.call.signal` envelopes a Realm member receives
 * via `GET /_arkret/self/account/subscribe`. Returns them oldest-first across
 * all matching realms.
 */
export async function relayedCallSignals(
  request: APIRequestContext,
  token: string,
  realmId: string,
): Promise<Array<Record<string, unknown>>> {
  const frames = await accountSubscribeFramesApi(request, token);
  const frame = frames.find((candidate) => candidate.kind === "delta") as {
    realms?: Record<string, { ephemeral?: Array<Record<string, unknown>> }>;
  } | undefined;
  const ephemeral = frame?.realms?.[realmId]?.ephemeral ?? [];
  const out: Array<Record<string, unknown>> = [];
  for (const item of ephemeral) {
    if (item.type !== "ak.call.signal") {
      continue;
    }
    const signals = Array.isArray(item.call_signals)
      ? (item.call_signals as Array<Record<string, unknown>>)
      : [];
    out.push(...signals);
  }
  return out;
}

export async function expectCallSignalError(
  response: APIResponse,
  status: number,
  code: string,
) {
  expect(response.status()).toBe(status);
  const body = await response.json();
  expect(wireErrCode(body), JSON.stringify(body)).toBe(code);
}

export { authHeaders };

// ── Media-service binding (CKP-0010) — token exchange helpers ────────────────
//
// These back the `ck.realm.media_service` foci configuration and the
// `POST /_arkret/self/rtc/token` media token exchange. The foci selection
// follows the spec oldest-membership-wins rule (media-service-binding.md §5);
// the issued LiveKit token is a standard 3-segment JWT so the harness can
// decode the LiveKit `video` grant claims without a live SFU.

export const PARTICIPANT_BINDING_SCHEME = "ak.media.participant_binding.v1";
export const MEDIA_TOKEN_TTL_MAX_SECS = 600;

export interface MediaFocusConfig {
  focus_id: string;
  type: string;
  issuer_kid: string;
  connect_url: string;
  ttl_seconds?: number;
  e2ee_key_source?: string;
}

/**
 * Project a `ck.realm.media_service` epoch onto the realm so the token issuer
 * can resolve `service_id`, `issuer_kids`, and `foci[]`. The `service_id` is
 * derived from each focus `issuer_kid` (`<service_id>#<key>`).
 */
export async function configureMediaService(
  request: APIRequestContext,
  token: string,
  realmId: string,
  ownerDid: string,
  serviceDid: string,
  foci: MediaFocusConfig[],
): Promise<void> {
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid: ownerDid,
      realmId,
      kind: "ak.realm.media_service",
      payload: {
        media_service: {
          service_id: serviceDid,
          foci,
        },
      },
    }),
    { context: `configure media_service for ${realmId}` },
  );
}

export interface MediaParticipantBinding {
  scheme: string;
  sig: string;
  issuer_kid: string;
  realm_id: string;
  call_id: string;
  focus_id: string;
  actor_id: string;
  device_id: string;
  participant_identity: string;
  issued_at: string;
  expires_at: string;
}

export interface MediaServiceSignature {
  kid: string;
  sig: string;
}

export interface MediaTokenExchangeResult {
  focus_id: string;
  type: string;
  connect_url: string;
  backend_token: string;
  participant_identity: string;
  participant_binding: MediaParticipantBinding;
  expires_at: string;
  service_signature: MediaServiceSignature;
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
    headers: authHeaders(token),
    data: body,
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
  return `ck_call_${digest.slice(0, 16)}`;
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
  // (base64url(header).base64url(payload).base64url(HS256 sig)) — no legacy
  // `livekit.` envelope prefix. Header MUST be {alg:HS256, typ:JWT}.
  const header = JSON.parse(
    Buffer.from(segments[0], "base64url").toString("utf8"),
  ) as Record<string, unknown>;
  expect(header.alg, "livekit JWT alg").toBe("HS256");
  expect(header.typ, "livekit JWT typ").toBe("JWT");
  const payloadJson = Buffer.from(segments[1], "base64url").toString("utf8");
  return JSON.parse(payloadJson) as Record<string, unknown>;
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
    headers: authHeaders(token),
    data: { mode: "p2p", ...body },
  });
}

export { wireErrCode };
