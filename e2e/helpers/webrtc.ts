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
  currentActorIdApi,
  readCommitStreamCutApi,
  readCommitStreamHeadApi,
  registeredEventVerificationMethod,
  signWithRegisteredEventSigner,
} from "./soland-api";
import { readScopeMlsGroupCurrentApi, scopeMlsMemberGroupApi } from "./soland-api/mls";
import { cotestWire } from "./soland-api/wire-client";

const signalRecipes = new WeakMap<Record<string, unknown>, Record<string, unknown>>();
const preparedSignals = new WeakSet<Record<string, unknown>>();
const openedSignals = new WeakMap<Record<string, unknown>, Record<string, unknown>>();

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
      // An unsent structural placeholder; prepare seals with the actual group.
      ciphertext: base64url(Buffer.alloc(16)),
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
  signalRecipes.set(envelope, args.plaintext);
  return envelope;
}

export function finalizeSignalEnvelopeProof(envelope: Record<string, unknown>): void {
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
  const plaintext = openedSignals.get(envelope);
  if (!plaintext) {
    throw new Error("Signal has not been independently opened by its recipient");
  }
  return plaintext;
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
  if (preparedSignals.has(envelope)) return;
  const realmId = String(envelope.realm_id);
  const actorId = eventPrincipalId({ actor_id: envelope.sender_actor_id });
  const deviceId = String(envelope.sender_device_id);
  requiredEventVerificationMethod(actorId, deviceId);
  const scopeRef = envelope.scope_ref as Record<string, unknown>;
  // Installing a Welcome can ACK accepted material. Complete that work before
  // observing the cut used by the final AEAD envelope.
  const group = await scopeMlsMemberGroupApi(request, token, realmId, scopeRef, { actorId, deviceId });
  const head = await readCommitStreamHeadApi(request, token, realmId, { streamRef: scopeRef });
  if (!head) {
    throw new Error(`Realm ${realmId} has no accepted commit head`);
  }
  envelope.authority_commit_id = head.commit_id;
  if (scopeRef.kind === "circle") {
    const parent = await readCommitStreamHeadApi(request, token, realmId);
    if (!parent) throw new Error("Circle Signal has no accepted parent Realm cut");
    envelope.parent_realm_authority_commit_id = parent.commit_id;
  } else {
    delete envelope.parent_realm_authority_commit_id;
  }
  // encryption-and-audit.md §2.5: the Signal AEAD binds the scope's accepted
  // current MLS group, read from the caller-visible Realm state snapshot.
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
  const plaintext = signalRecipes.get(envelope);
  if (!plaintext) throw new Error("Signal plaintext recipe is unavailable");
  const sealed = cotestWire<{
    encrypted_payload: Record<string, unknown>;
    group_state: string;
  }>("mls-encrypt-signal", { group_state: group.groupState, envelope, plaintext });
  group.groupState = sealed.group_state;
  envelope.encrypted_payload = sealed.encrypted_payload;
  finalizeSignalEnvelopeProof(envelope);
  preparedSignals.add(envelope);
}

export async function postCallSignalRaw(
  request: APIRequestContext,
  token: string,
  envelope: Record<string, unknown>,
): Promise<APIResponse> {
  await prepareSignalEnvelope(request, token, envelope);
  return await postPreparedSignalEnvelopeRaw(request, token, envelope);
}

export async function postPreparedSignalEnvelopeRaw(
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
): Promise<{
  result: T;
  envelopes: Array<Record<string, unknown>>;
  frames: Array<Record<string, unknown>>;
}> {
  const url = new URL(`${solandBaseUrl()}/_arkret/self/signal/subscribe`);
  url.searchParams.set("max_duration_ms", "5000");
  url.searchParams.set("heartbeat_ms", "100");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000);
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  try {
    const response = await fetch(url, {
      headers: {
        ...authHeaders(token, "GET", url.toString()),
        accept: "application/x-ndjson",
        "Arkret-Operation": "ak.self.signal.stream.subscribe.v1",
      },
      signal: controller.signal,
    });
    expect(response.status, "receiver Signal rail is authorized").toBe(200);
    expect(!!response.body, "receiver Signal rail has an NDJSON body").toBe(true);
    reader = response.body!.getReader();
    const decoder = new TextDecoder();
    let pending = "";
    async function nextFrame(): Promise<Record<string, unknown> | undefined> {
      while (true) {
        const newline = pending.indexOf("\n");
        if (newline >= 0) {
          const line = pending.slice(0, newline).trim();
          pending = pending.slice(newline + 1);
          if (line) return JSON.parse(line) as Record<string, unknown>;
          continue;
        }
        const chunk = await reader!.read();
        if (chunk.done) {
          const tail = (pending + decoder.decode()).trim();
          pending = "";
          return tail ? JSON.parse(tail) as Record<string, unknown> : undefined;
        }
        pending += decoder.decode(chunk.value, { stream: true });
      }
    }
    const envelopes: Array<Record<string, unknown>> = [];
    const frames: Array<Record<string, unknown>> = [];
    function retain(frame: Record<string, unknown>) {
      if (frame.kind !== "signal") return;
      const envelope = frame.envelope as Record<string, unknown>;
      if (envelope.realm_id === realmId && envelope.encrypted_payload !== undefined) {
        envelopes.push(envelope);
        frames.push(frame);
      }
    }
    // A received heartbeat proves the real authenticated live rail is running.
    // Preparation and an arbitrary delay cannot prove that under a busy stack.
    while (true) {
      const frame = await nextFrame();
      expect(!!frame && (frame.kind === "heartbeat" || frame.kind === "signal"),
        "receiver Signal rail becomes ready before closing").toBe(true);
      if (frame!.kind === "heartbeat") break;
      retain(frame!);
    }
    const [result] = await Promise.all([action(), (async () => {
      while (true) {
        const frame = await nextFrame();
        if (!frame || frame.kind === "drain") break;
        expect(frame.kind === "heartbeat" || frame.kind === "signal",
          "receiver Signal rail remains live during capture").toBe(true);
        retain(frame);
      }
    })()]);
    return { result, envelopes, frames };
  } finally {
    controller.abort();
    await reader?.cancel().catch(() => undefined);
    clearTimeout(timeout);
  }
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
  const scopeRef = envelope.scope_ref as Record<string, unknown>;
  const receiverGroup = await scopeMlsMemberGroupApi(request, receiverToken, realmId, scopeRef);
  await prepareSignalEnvelope(request, senderToken, envelope);
  const receiverId = await currentActorIdApi(request, receiverToken);
  const head = await readCommitStreamCutApi(
    request, receiverToken, realmId, String(envelope.authority_commit_id), { streamRef: scopeRef },
  );
  const parent = scopeRef.kind === "circle"
    ? await readCommitStreamCutApi(
      request, receiverToken, realmId, String(envelope.parent_realm_authority_commit_id),
    )
    : undefined;
  if (!head || (scopeRef.kind === "circle" && !parent)) {
    throw new Error("Signal receiver lacks the accepted independent authority cuts");
  }
  const captured = await captureSignalEnvelopes(receiverToken, realmId, () =>
    postPreparedSignalEnvelopeRaw(request, senderToken, envelope),
  );
  for (const candidate of captured.envelopes) {
    const payload = candidate.encrypted_payload as Record<string, unknown>;
    const keyRef = payload.key_ref as Record<string, unknown>;
    expect(keyRef.group_state_ref, "receiver installed the Signal's exact accepted MLS state")
      .toBe(receiverGroup.groupStateRef);
    expect(candidate.authority_commit_id, "receiver independently read the Signal's exact scope cut")
      .toBe(head.commit_id);
  }
  const opened = cotestWire<{ plaintexts: Array<Record<string, unknown>> }>("mls-open-signals", {
    group_state: receiverGroup.groupState,
    recipient_account_id: accountActorId(receiverId).account_id,
    group_state_ref: receiverGroup.groupStateRef,
    authority_commit_id: head.commit_id,
    parent_realm_authority_commit_id: parent?.commit_id ?? null,
    frames: captured.frames,
  });
  if (opened.plaintexts.length !== captured.envelopes.length) {
    throw new Error("Signal open omitted captured envelopes");
  }
  captured.envelopes.forEach((candidate, index) => openedSignals.set(candidate, opened.plaintexts[index]!));
  return { result: captured.result, envelopes: captured.envelopes };
}

export { authHeaders };
