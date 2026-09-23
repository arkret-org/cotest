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
  accountActorId,
  eventPrincipalId,
  authHeaders,
  base64url,
  base64urlJsonCanonical,
  canonicalJson,
  canonicalTimestamp,
  readCommitStreamHeadApi,
  registeredEventVerificationMethod,
  seedConformanceRealmBasisApi,
  signedEventEnvelope,
  signWithRegisteredEventSigner,
} from "./soland-api";

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
    authority_commit_id:
      "ak:realm_commit:Ac08ROpjn3Ilj_UaM-_XLY93u4SUTptG0-Q-_CUDb5aS",
    signal_class: signalClass,
    sent_at: canonicalTimestamp(sentAt),
    expires_at: canonicalTimestamp(expiresAt),
    encrypted_payload: {
      scheme: "ak.signal_exporter_aead.v1",
      key_ref: {
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
    },
    proof: {
      kind: "detached_jws",
      verification_method:
        registeredEventVerificationMethod(args.actorId, args.deviceId) ??
        `${args.actorId}#${args.deviceId}`,
      envelope_digest: `sha256:${"0".repeat(64)}`,
      jws: "",
    },
  };
  finalizeSignalEnvelopeProof(envelope);
  return envelope;
}

function finalizeSignalEnvelopeProof(envelope: Record<string, unknown>): void {
  const proof = envelope.proof as Record<string, unknown>;
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
    created_at: envelope.sent_at,
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

// ── Signal submit + subscribe read-back (canonical wire) ────────────────────

/**
 * Submit one encrypted Signal envelope. The independent commit-stream head is
 * resolved just before signing so the proof and AEAD bind current authority.
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
  {
    await seedConformanceRealmBasisApi(
      request,
      realmId,
      actorId,
      ["ak.message.create"],
    );
    const head = await readCommitStreamHeadApi(request, token, realmId);
    if (!head) {
      throw new Error(`seeded Realm ${realmId} has no accepted commit head`);
    }
    envelope.authority_commit_id = head.commit_id;
  }
  const mlsBasis = await ensureSignalMlsBasis(
    request,
    actorId,
    deviceId,
    realmId,
    envelope.scope_ref as Record<string, unknown>,
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
 * Keep a receiver's live Signal rail open while `action` sends one or more
 * envelopes. Product-level assertions must decrypt/filter the returned
 * envelopes on the receiver side; the service only sees the outer class/scope.
 */
async function captureSignalEnvelopes<T>(
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
