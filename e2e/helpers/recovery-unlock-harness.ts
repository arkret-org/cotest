// Recovery-unlock (24-word Recovery Key) harness for the device-recovery
// state machine (device-lifecycle.md §15).
//
// soland verifies the `recovery_unlock` recovery-session proof for real:
//   routing/identity/recovery/session_endpoints.rs::verify_recovery_unlock_proof
// resolves `recovery_secret_ref` to a non-revoked, in-window entry of the
// principal's published `recovery_policy.recovery_keys[]`, verifies the proof
// signature under that entry's Ed25519 public key over the §15 generic recovery
// transcript, and re-derives the `unlock_commitment` binding. The trust root is
// the principal-signed recovery policy, NOT the DID document — so this harness
// does not need a 24-word BIP39 round-trip. It instead mints a fresh Ed25519
// "recovery signing key", declares its public key into the principal's recovery
// policy, and signs the unlock proof with the matching private key. soland
// accepts it because the policy itself authorized that key.
//
// The genesis recovery policy is published over the dev-session device path:
// soland's verify_recovery_policy_auth_signature falls back to the genesis
// session-device signature (verify_recovery_policy_session_device_signature)
// when auth_data.verification_method == `${principal_id}#${session.device_id}`
// and the session device carries an authoritative `device_public_key`. To give
// the dev-login session device that key, the harness first publishes a real
// cross-signing identity (PSK→SSK/USK) and a self-targeted ak.device.authorize
// for the session device — the same §5.1/§5.2 ingest path the multi-device
// suite drives — which projects `device_public_key` + verified state for it.
//
// Completion (§15 step 3) is then driven exactly as the spec requires: the
// recovering client publishes an SSK-signed ak.device.authorize (carrying
// recovery_session_id) plus a ak.device.list_update onto the principal control
// stream, and POST /complete references those two durable event ids. soland
// re-verifies the cross_signing_binding against the accepted SSK before flipping
// the session to `completed` and recording the recovered device key.

import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { type APIRequestContext, expect } from "@playwright/test";
import { solandBaseUrl } from "./env";
import {
  buildCrossSigningPublishPayload,
  buildDeviceCrossSigningBinding,
  buildDevicePossessionSignature,
  TEST_DEVICE_ALGORITHMS,
  type CrossSigningIdentity,
  deviceVerifyKeyMultibase,
  generateCrossSigningIdentity,
} from "./cross-signing-harness";
import {
  authHeaders,
  canonicalJson,
  principalControlRealmForDid,
  signedEventEnvelope,
  typedId,
  uuidV7,
} from "./soland-api";
import { ensureRegistered, issueDevSession, type JointUser } from "./users";
import { encodeEd25519PubkeyMultibase } from "./encoding";

function rfc3339Millis(date: Date): string {
  // soland serializes recovery timestamps with millisecond precision
  // (to_rfc3339_opts(SecondsFormat::Millis, true)).
  return date.toISOString();
}

/// A freshly-generated Ed25519 recovery signing key. The verification_method is
/// a self-contained `did:key:z…#z…` so soland decodes the public key from the
/// multibase fragment (recovery_key_multibase) without any DID-document lookup,
/// while still matching the recovery-policy.schema.json did_url shape (requires a
/// `#` fragment).
export type RecoverySigningKey = {
  privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"];
  multibase: string;
  /// `did:key:z…#z…` — the value used as both recovery_secret_ref and
  /// verification_method in the policy entry and the unlock proof.
  verificationMethod: string;
};

export function generateRecoverySigningKey(): RecoverySigningKey {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as { x?: string };
  if (!jwk.x) {
    throw new Error("Ed25519 public JWK missing 'x'");
  }
  const multibase = encodeEd25519PubkeyMultibase(
    Buffer.from(jwk.x, "base64url"),
  );
  return {
    privateKey,
    multibase,
    verificationMethod: `did:key:${multibase}#${multibase}`,
  };
}

/// One recovery_keys[] entry of a recovery policy.
export type RecoveryKeyEntry = {
  verification_method: string;
  alg: "Ed25519";
  not_before: string;
  expires_at: string;
  revoked_at?: string | null;
};

const TRUST_DOMAIN = "ak:trust_domain:soland.local";
const POLICY_SIGNATURE_TYPE = "ak.identity.recovery_policy.signature.v1";
// soland's verify_recovery_policy auth path allows exactly these signed_fields
// and requires all of them (POLICY_REQUIRED_SIGNED_FIELDS == ALLOWED in wire.rs).
const POLICY_SIGNED_FIELDS = [
  "schema",
  "policy_id",
  "principal_id",
  "version",
  "trust_domain",
  "allowed_proof_kinds",
  "supersedes",
  "issued_at",
  "expires_at",
] as const;

function signEd25519B64url(
  message: Buffer,
  privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"],
): string {
  return sign(null, message, privateKey).toString("base64url");
}

/// The signing transcript soland reconstructs for a recovery policy auth
/// signature: recovery_signature_transcript(POLICY_SIGNATURE_TYPE, payload,
/// signed_fields) = {type, signed_fields, payload: <payload restricted to
/// signed_fields>}.
function recoveryPolicyTranscriptBytes(
  payload: Record<string, unknown>,
  signedFields: readonly string[],
): Buffer {
  const restricted: Record<string, unknown> = {};
  for (const field of signedFields) {
    restricted[field] = field in payload ? payload[field] : null;
  }
  return Buffer.from(
    canonicalJson({
      type: POLICY_SIGNATURE_TYPE,
      signed_fields: [...signedFields],
      payload: restricted,
    }),
    "utf8",
  );
}

export type RecoveryPrincipal = {
  user: JointUser;
  token: string;
  realmId: string;
  identity: CrossSigningIdentity;
  recoveryKey: RecoverySigningKey;
  policyId: string;
  policyVersion: number;
};

/// Register a principal, give its dev-session device a real cross-signing
/// identity + authoritative device_public_key, then publish a genesis recovery
/// policy authorizing a freshly-minted recovery_unlock signing key.
export async function prepareRecoveryPrincipal(
  request: APIRequestContext,
  prefix: string,
  user: JointUser,
): Promise<RecoveryPrincipal> {
  await ensureRegistered(request, user);
  const token = await issueDevSession(request, user);
  const realmId = principalControlRealmForDid(user.did);
  const identity = generateCrossSigningIdentity({
    principalId: user.did,
    trustDomain: TRUST_DOMAIN,
  });

  // 1) Publish the cross-signing identity (PSK→SSK/USK) — accepts the SSK at
  //    generation 1 (§5.1 ingest).
  const publish = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
    headers: authHeaders(token),
    data: signedEventEnvelope({
      actorDid: user.did,
      realmId,
      kind: "ak.cross_signing.publish",
      payload: buildCrossSigningPublishPayload(identity),
    }),
  });
  expect(
    [200, 201],
    `ak.cross_signing.publish returned ${publish.status()}: ${await publish.text()}`,
  ).toContain(publish.status());

  // 2) Self-authorize the dev-session device with a real SSK-signed
  //    cross_signing_binding so it gains an authoritative device_public_key +
  //    verified state (§5.2 ingest, projected by project_device_authorize). The
  //    genesis recovery policy is signed by this device key.
  const sessionDeviceKey = deviceVerifyKeyMultibase();
  const sessionBinding = buildDeviceCrossSigningBinding({
    identity,
    deviceId: user.deviceId,
    devicePublicKeyMultibase: sessionDeviceKey.multibase,
    hpkeKeyMultibase: "z6LSCotestE2eDeviceHpkeKey",
    algorithms: TEST_DEVICE_ALGORITHMS,
  });
  const sessionNotBefore = rfc3339Millis(new Date()).replace(/\.\d{3}Z$/, "Z");
  const sessionDeviceSignature = buildDevicePossessionSignature({
    identity,
    deviceId: user.deviceId,
    devicePublicKeyMultibase: sessionDeviceKey.multibase,
    hpkeKeyMultibase: "z6LSCotestE2eDeviceHpkeKey",
    algorithms: TEST_DEVICE_ALGORITHMS,
    deviceKeyAlgorithm: "EdDSA",
    authorizedBy: user.deviceId,
    notBefore: sessionNotBefore,
    privateKey: sessionDeviceKey.privateKey,
  });
  const selfAuthorize = await request.post(
    `${solandBaseUrl()}/_arkret/self/events`,
    {
      headers: authHeaders(token),
      data: signedEventEnvelope({
        actorDid: user.did,
        realmId,
        kind: "ak.device.authorize",
        payload: {
          principal_id: user.did,
          device_id: user.deviceId,
          device_public_key: sessionDeviceKey.multibase,
          hpke_key: "z6LSCotestE2eDeviceHpkeKey",
          algorithms: TEST_DEVICE_ALGORITHMS,
          device_key_algorithm: "EdDSA",
          authorized_by: user.deviceId,
          not_before: sessionNotBefore,
          device_signature: sessionDeviceSignature,
          cross_signing_binding: sessionBinding,
        },
      }),
    },
  );
  expect(
    [200, 201],
    `session-device ak.device.authorize returned ${selfAuthorize.status()}: ${await selfAuthorize.text()}`,
  ).toContain(selfAuthorize.status());

  // Wait for the projection to record the session device with its key.
  await expect
    .poll(
      async () => {
        const viewer = await request.get(
          `${solandBaseUrl()}/_arkret/self/account/viewer`,
          { headers: authHeaders(token) },
        );
        if (!viewer.ok()) {
          return "http-" + viewer.status();
        }
        const body = (await viewer.json()) as {
          devices?: Array<{ device_id?: string; status?: string }>;
        };
        const row = (body.devices ?? []).find(
          (d) => d.device_id === user.deviceId,
        );
        return row?.status ?? "absent";
      },
      { timeout: 30_000, intervals: [500, 1_000, 2_000] },
    )
    .toBe("active");

  // 3) Mint a recovery signing key and publish a genesis recovery policy that
  //    authorizes it for `recovery_unlock`.
  const recoveryKey = generateRecoverySigningKey();
  const now = new Date();
  const policyId = `ak:policy:${uuidV7()}`;
  const entry: RecoveryKeyEntry = {
    verification_method: recoveryKey.verificationMethod,
    alg: "Ed25519",
    not_before: rfc3339Millis(new Date(now.getTime() - 60_000)),
    expires_at: rfc3339Millis(new Date(now.getTime() + 365 * 86_400_000)),
    revoked_at: null,
  };
  const policyVersion = 1;
  const policyCore = {
    schema: "ak.schema.recovery_policy.v1",
    policy_id: policyId,
    principal_id: user.did,
    version: policyVersion,
    supersedes: null,
    trust_domain: TRUST_DOMAIN,
    allowed_proof_kinds: ["recovery_unlock"],
    recovery_keys: [entry],
    issued_at: rfc3339Millis(now),
    expires_at: null,
  };
  const policySignature = signEd25519B64url(
    recoveryPolicyTranscriptBytes(policyCore, POLICY_SIGNED_FIELDS),
    sessionDeviceKey.privateKey,
  );
  const policyPayload = {
    ...policyCore,
    auth_data: {
      verification_method: `${user.did}#${user.deviceId}`,
      signature_algorithm: "Ed25519",
      signature: policySignature,
      signed_fields: [...POLICY_SIGNED_FIELDS],
    },
  };
  const policyResp = await request.post(
    `${solandBaseUrl()}/_arkret/root/identity/recovery-policy`,
    { headers: authHeaders(token), data: policyPayload },
  );
  expect(
    [200, 201],
    `recovery-policy publish returned ${policyResp.status()}: ${await policyResp.text()}`,
  ).toContain(policyResp.status());

  return {
    user,
    token,
    realmId,
    identity,
    recoveryKey,
    policyId,
    policyVersion,
  };
}

/// Read-back shape of the created/fetched recovery session — the exact session
/// fields soland reconstructs the proof transcript from.
type RecoverySessionState = {
  recovery_session_id: string;
  principal_id: string;
  requesting_device_id: string;
  trust_domain: string;
  policy_id: string;
  policy_version: number;
  ssk_generation: number;
  challenge: string;
  state: string;
  created_at: string;
  expires_at: string;
};

function sessionState(body: unknown): RecoverySessionState {
  const value = body as RecoverySessionState;
  if (!value || typeof value.recovery_session_id !== "string") {
    throw new Error(
      `recovery session response missing fields: ${JSON.stringify(body)}`,
    );
  }
  return value;
}

/// The §15 generic recovery transcript. `created_at`/`expires_at`/`policy_id`/…
/// are taken verbatim from the soland-issued session so the canonical bytes
/// match what soland reconstructs server-side (generic_recovery_proof_transcript).
function genericRecoveryTranscriptBytes(
  session: RecoverySessionState,
  proofBody: Record<string, unknown>,
): Buffer {
  return Buffer.from(
    canonicalJson({
      type: "ak.identity.recovery_proof.v1",
      kind: "recovery_unlock",
      principal_id: session.principal_id,
      requesting_device_id: session.requesting_device_id,
      trust_domain: session.trust_domain,
      policy_id: session.policy_id,
      policy_version: session.policy_version,
      recovery_session_id: session.recovery_session_id,
      ssk_generation: session.ssk_generation,
      challenge: session.challenge,
      created_at: session.created_at,
      expires_at: session.expires_at,
      proof_body: proofBody,
    }),
    "utf8",
  );
}

export type RecoveryUnlockResult = {
  recoverySessionId: string;
  deviceId: string;
  /// The recovered device's own dev-session token (a still-valid reader even
  /// after the original device-1 signer is revoked).
  deviceToken: string;
  authorizationEventId: string;
  deviceListUpdateEventId: string;
  completeResponse: Record<string, unknown>;
};

/// Drive a full device-2 restore over the recovery_unlock factor:
///   open session → submit recovery_unlock proof (pending→verified)
///   → publish SSK-signed ak.device.authorize + ak.device.list_update
///   → /complete referencing those durable event ids.
export async function restoreViaRecoveryUnlock(
  request: APIRequestContext,
  principal: RecoveryPrincipal,
  opts: { submitterToken?: string } = {},
): Promise<RecoveryUnlockResult> {
  // The §15 step-3 control-stream events (ak.device.authorize +
  // ak.device.list_update) MUST be submitted by a still-valid signer device.
  // Defaults to the principal's original device; callers running after that
  // device is revoked pass a peer device token via `submitterToken`.
  const submitterToken = opts.submitterToken ?? principal.token;
  const newDeviceId = typedId("device");
  // device-2 authenticates as the same principal (its own dev-login session).
  const device2Token = await issueDevSession(request, principal.user, {
    deviceId: newDeviceId,
  });

  // 1) Open a recovery session bound to the active policy snapshot.
  const createResp = await request.post(
    `${solandBaseUrl()}/_arkret/root/identity/recovery-sessions`,
    {
      headers: authHeaders(device2Token),
      data: {
        principal_id: principal.user.did,
        requesting_device_id: newDeviceId,
        trust_domain: TRUST_DOMAIN,
        ssk_generation: principal.identity.generation,
      },
    },
  );
  expect(
    [200, 201],
    `recovery-session create returned ${createResp.status()}: ${await createResp.text()}`,
  ).toContain(createResp.status());
  const session = sessionState(await createResp.json());
  expect(session.state).toBe("pending");

  // 2) Build the recovery_unlock proof. proof_body is the proof object minus
  //    `signature` + `unlock_commitment`; both the signature and the commitment
  //    cover the same generic-transcript bytes.
  const proofBody = {
    kind: "recovery_unlock",
    challenge: session.challenge,
    recovery_secret_ref: principal.recoveryKey.verificationMethod,
    verification_method: principal.recoveryKey.verificationMethod,
    alg: "Ed25519",
  };
  const transcriptBytes = genericRecoveryTranscriptBytes(session, proofBody);
  const signature = signEd25519B64url(
    transcriptBytes,
    principal.recoveryKey.privateKey,
  );
  const commitmentHash = createHash("sha256");
  commitmentHash.update(Buffer.from("ak.recovery-session-unlock-binding-v1\n", "utf8"));
  commitmentHash.update(Buffer.from(principal.recoveryKey.verificationMethod, "utf8"));
  commitmentHash.update(transcriptBytes);
  const unlockCommitment = `sha256:${commitmentHash.digest("hex")}`;

  const proofResp = await request.post(
    `${solandBaseUrl()}/_arkret/root/identity/recovery-sessions/${encodeURIComponent(session.recovery_session_id)}/proofs`,
    {
      headers: authHeaders(device2Token),
      data: {
        proof: {
          ...proofBody,
          signature,
          unlock_commitment: unlockCommitment,
        },
      },
    },
  );
  expect(
    proofResp.status(),
    `recovery_unlock /proofs returned ${proofResp.status()}: ${await proofResp.text()}`,
  ).toBe(200);
  const proofOutcome = (await proofResp.json()) as { verification?: unknown };
  expect(proofOutcome.verification).toBe("verified");

  // 3) Publish the recovering client's SSK-signed ak.device.authorize (carrying
  //    recovery_session_id) + a ak.device.list_update onto the control stream.
  const device2Key = deviceVerifyKeyMultibase();
  const binding = buildDeviceCrossSigningBinding({
    identity: principal.identity,
    deviceId: newDeviceId,
    devicePublicKeyMultibase: device2Key.multibase,
    hpkeKeyMultibase: "z6LSCotestE2eDeviceHpkeKey",
    algorithms: TEST_DEVICE_ALGORITHMS,
  });
  const device2NotBefore = rfc3339Millis(new Date()).replace(/\.\d{3}Z$/, "Z");
  const device2Signature = buildDevicePossessionSignature({
    identity: principal.identity,
    deviceId: newDeviceId,
    devicePublicKeyMultibase: device2Key.multibase,
    hpkeKeyMultibase: "z6LSCotestE2eDeviceHpkeKey",
    algorithms: TEST_DEVICE_ALGORITHMS,
    deviceKeyAlgorithm: "EdDSA",
    authorizedBy: principal.user.deviceId,
    notBefore: device2NotBefore,
    recoverySessionId: session.recovery_session_id,
    privateKey: device2Key.privateKey,
  });
  const authorizeEventId = typedId("event");
  const authorize = await request.post(
    `${solandBaseUrl()}/_arkret/self/events`,
    {
      headers: authHeaders(submitterToken),
      data: signedEventEnvelope({
        actorDid: principal.user.did,
        realmId: principal.realmId,
        kind: "ak.device.authorize",
        eventId: authorizeEventId,
        payload: {
          principal_id: principal.user.did,
          device_id: newDeviceId,
          device_public_key: device2Key.multibase,
          hpke_key: "z6LSCotestE2eDeviceHpkeKey",
          algorithms: TEST_DEVICE_ALGORITHMS,
          device_key_algorithm: "EdDSA",
          authorized_by: principal.user.deviceId,
          not_before: device2NotBefore,
          device_signature: device2Signature,
          recovery_session_id: session.recovery_session_id,
          cross_signing_binding: binding,
        },
      }),
    },
  );
  expect(
    [200, 201],
    `restore ak.device.authorize returned ${authorize.status()}: ${await authorize.text()}`,
  ).toContain(authorize.status());

  const listUpdateEventId = typedId("event");
  const listUpdate = await request.post(
    `${solandBaseUrl()}/_arkret/self/events`,
    {
      headers: authHeaders(submitterToken),
      data: signedEventEnvelope({
        actorDid: principal.user.did,
        realmId: principal.realmId,
        kind: "ak.device.list_update",
        eventId: listUpdateEventId,
        payload: {
          principal_id: principal.user.did,
          changed: [newDeviceId],
        },
      }),
    },
  );
  expect(
    [200, 201],
    `restore ak.device.list_update returned ${listUpdate.status()}: ${await listUpdate.text()}`,
  ).toContain(listUpdate.status());

  // 4) Complete the session by referencing the two durable event ids.
  const completeResp = await request.post(
    `${solandBaseUrl()}/_arkret/root/identity/recovery-sessions/${encodeURIComponent(session.recovery_session_id)}/complete`,
    {
      headers: authHeaders(device2Token),
      data: {
        authorization_event_id: authorizeEventId,
        device_list_update_event_id: listUpdateEventId,
      },
    },
  );
  expect(
    completeResp.status(),
    `recovery-session /complete returned ${completeResp.status()}: ${await completeResp.text()}`,
  ).toBe(200);
  const completeResponse = (await completeResp.json()) as Record<string, unknown>;

  return {
    recoverySessionId: session.recovery_session_id,
    deviceId: newDeviceId,
    deviceToken: device2Token,
    authorizationEventId: authorizeEventId,
    deviceListUpdateEventId: listUpdateEventId,
    completeResponse,
  };
}

/// Revoke a device on the principal control stream (peer revoke). Used by the
/// E8.7 post-revoke restore scenario.
export async function revokeDevice(
  request: APIRequestContext,
  principal: RecoveryPrincipal,
  deviceId: string,
  revokedBy: string,
  submitterToken: string,
): Promise<void> {
  const revoke = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
    headers: authHeaders(submitterToken),
    data: signedEventEnvelope({
      actorDid: principal.user.did,
      realmId: principal.realmId,
      kind: "ak.device.revoke",
      payload: {
        principal_id: principal.user.did,
        device_id: deviceId,
        revoked_by: revokedBy,
        revoked_at: new Date().toISOString(),
        reason: "lost_device",
      },
    }),
  });
  expect(
    [200, 201],
    `ak.device.revoke returned ${revoke.status()}: ${await revoke.text()}`,
  ).toContain(revoke.status());
}
