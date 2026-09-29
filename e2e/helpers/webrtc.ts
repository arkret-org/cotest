import {
  expect,
  type APIRequestContext,
  type APIResponse,
} from "@playwright/test";
import { createHash } from "node:crypto";
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
  signWithRegisteredEventSigner,
} from "./soland-api";
import { readScopeMlsGroupCurrentApi } from "./soland-api/mls";

// Signal proofs must use the exact device key installed by canonical account
// provisioning. Tests may not mint a second key or seed a verified inventory
// row through a conformance-only side door.
function requiredEventVerificationMethod(
  actorId: string,
  deviceId: string,
): string {
  const verificationMethod = registeredEventVerificationMethod(actorId, deviceId);
  if (!verificationMethod) {
    throw new Error(
      `canonical provisioning omitted the accepted device signer for ${actorId}/${deviceId}`,
    );
  }
  return verificationMethod;
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
      verification_method: requiredEventVerificationMethod(
        args.actorId,
        args.deviceId,
      ),
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
  const signature = signWithRegisteredEventSigner(
    actorId,
    String(proof.verification_method),
    signingInput,
  );
  if (!signature) {
    throw new Error(
      `canonical provisioning omitted the accepted device signer for ${actorId}/${deviceId}`,
    );
  }
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
  requiredEventVerificationMethod(actorId, deviceId);
  const head = await readCommitStreamHeadApi(request, token, realmId);
  if (!head) {
    throw new Error(`Realm ${realmId} has no accepted commit head`);
  }
  envelope.authority_commit_id = head.commit_id;
  // encryption-and-audit.md §2.5: the Signal AEAD binds the scope's accepted
  // current MLS group, read from the caller-visible Realm state snapshot.
  const scopeRef = envelope.scope_ref as Record<string, unknown>;
  const current = await readScopeMlsGroupCurrentApi(
    request,
    token,
    realmId,
    scopeRef,
  );
  if (!current) {
    throw new Error(
      `Signal scope ${canonicalJson(scopeRef)} has no accepted MLS group`,
    );
  }
  const encryptedPayload = envelope.encrypted_payload as Record<string, unknown>;
  const keyRef = encryptedPayload.key_ref as Record<string, unknown>;
  keyRef.group_state_ref = current.current_mls_commit_event_ref;
  encryptedPayload.epoch = current.epoch;
  finalizeSignalEnvelopeProof(envelope);
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
    headers: { ...authHeaders(token, "POST", `${solandBaseUrl()}/_arkret/self/signal`), "content-type": "application/json" },
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
      ...authHeaders(token, "GET", url.toString()),
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
 * then submit it while that rail is active. Preparation reads the current
 * commit head and MLS group, so doing it inside `action` can outlive the
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
