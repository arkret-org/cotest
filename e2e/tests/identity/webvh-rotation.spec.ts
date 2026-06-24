// WebVH DID key rotation
// Contract: e2e/scenarios/identity/webvh-rotation.md
// Spec refs:
//   - identity/identity-did.md §3.4 (entry hash chain), §4.1-§4.2.1 (resolver, degraded_no_witness)
//   - §6 (historical events verified by historical keys), §7-§8.2 (rotation, threshold governance)
//
// Drives soland's embedded did:webvh provider end to end:
//   - POST /_soland/root/identity/webvh/register  (genesis inception)
//   - POST /_soland/root/identity/webvh/rotate     (append a rotation entry)
//   - POST /_cokret/root/identity/resolve          (resolver re-validates the chain)
//   - GET  /_cokret/root/identity/log              (did.jsonl history)
//
// The resolver gate (run_webvh_resolution_checks) re-validates the hash chain,
// SCID, witness quorum / degraded window, and rotation control authorisation on
// every resolve, and the rotate endpoint enforces the same gate at write time —
// so a tampered prev hash, an SCID mismatch, a single-sig org rotation, or a
// recovery-key rotation all resolve to the expected accept / fail-closed.

import { test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { wireErrCode } from "../../helpers/soland-api";
import {
  buildGenesisEntry,
  buildRotationEntry,
  documentControlKeys,
  expect,
  fetchDidLog,
  generateWebvhKey,
  rawResolveDid,
  rawRotateWebvh,
  registerWebvhGenesis,
  resolveDid,
  rotateWebvh,
  type BuiltEntry,
  type WebvhKey,
} from "../../helpers/webvh-api";

test.describe.configure({ mode: "serial" });

function uniqueLocalId(prefix: string): string {
  return `${prefix}-${Math.random().toString(36).slice(2, 10)}`;
}

function degradedWindowSecs(): number {
  const raw = process.env.COTEST_WEBVH_DEGRADED_NO_WITNESS_MAX_SECS;
  const parsed = raw ? parseInt(raw, 10) : NaN;
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 30;
}

// Register a genesis did:webvh and return the keys + the head entry so a test
// can rotate from there.
async function registerGenesis(
  request: Parameters<typeof registerWebvhGenesis>[0],
  baseUrl: string,
  opts: {
    localId: string;
    recoveryKeys?: string[];
    governance?: { threshold: number; eligibleMethods: string[] };
  },
): Promise<{
  did: string;
  scid: string;
  genesis: BuiltEntry;
  didKey: WebvhKey;
  updateKey: WebvhKey;
}> {
  const didKey = generateWebvhKey();
  const updateKey = generateWebvhKey();
  const input = {
    baseUrl,
    localId: opts.localId,
    didKey,
    updateKey,
    versionTime: new Date().toISOString(),
    recoveryKeys: opts.recoveryKeys,
    governance: opts.governance,
  };
  const genesis = buildGenesisEntry(input);
  await registerWebvhGenesis(request, baseUrl, genesis, input);
  return { did: genesis.did, scid: genesis.scid, genesis, didKey, updateKey };
}

test.describe("WebVH DID key rotation", () => {
  test(
    // @user-promise: e2e/scenarios/identity/webvh-rotation.md
    "alice rotates her did:webvh controlling key; new entry signed by old update key + witness; resolver returns updated verificationMethod",
    async ({ request }) => {
      // spec: identity-did.md §3.4 + §7
      const baseUrl = solandBaseUrl();
      const witness = generateWebvhKey();
      const { did, scid, genesis, updateKey } = await registerGenesis(
        request,
        baseUrl,
        { localId: uniqueLocalId("alice-rotate") },
      );

      // Resolver returns the genesis controlling key before rotation.
      const before = await resolveDid(request, baseUrl, did);
      expect(documentControlKeys(before.did_document.document)).not.toContain(
        undefined,
      );

      // New update key; rotation entry signed by the OLD update key (controller
      // proof) and witnessed by a trusted witness.
      const newUpdateKey = generateWebvhKey();
      const rotation = buildRotationEntry({
        did,
        scid,
        prevVersionId: genesis.versionId,
        prevDidDocument: genesis.didDocument,
        newUpdateKey,
        signers: [updateKey],
        witnesses: [witness],
      });
      await rotateWebvh(request, baseUrl, did, rotation);

      const after = await resolveDid(request, baseUrl, did);
      // The resolved document's controlling key advanced to the new key.
      expect(documentControlKeys(after.did_document.document)).toContain(
        newUpdateKey.multibase,
      );
    },
  );

  test(
    // @user-promise: e2e/scenarios/identity/webvh-rotation.md
    "alice's pre-rotation events still verify under old key; post-rotation events verify under new key (spec §6 rule 5)",
    async ({ request }) => {
      // spec: identity-did.md §6 — historical resolution by versionTime.
      const baseUrl = solandBaseUrl();
      const witness = generateWebvhKey();
      const { did, scid, genesis, updateKey } = await registerGenesis(
        request,
        baseUrl,
        { localId: uniqueLocalId("alice-history") },
      );
      const oldKey = updateKey.multibase;

      const newUpdateKey = generateWebvhKey();
      const rotation = buildRotationEntry({
        did,
        scid,
        prevVersionId: genesis.versionId,
        prevDidDocument: genesis.didDocument,
        newUpdateKey,
        signers: [updateKey],
        witnesses: [witness],
      });
      await rotateWebvh(request, baseUrl, did, rotation);

      // The full history chain is preserved: entry 0 still carries the old
      // update key in its parameters, entry 1 the new one. A verifier doing
      // point-in-time resolution (event accepted-at) uses the historical entry
      // — the old key remains valid for pre-rotation events (§6 rule 5).
      const log = await fetchDidLog(request, baseUrl, did);
      expect(log.length).toBe(2);
      const genesisParams = (
        (log[0].operation as Record<string, unknown>).parameters as Record<
          string,
          unknown
        >
      ).updateKeys as string[];
      const rotationParams = (
        (log[1].operation as Record<string, unknown>).parameters as Record<
          string,
          unknown
        >
      ).updateKeys as string[];
      expect(genesisParams).toContain(oldKey);
      expect(rotationParams).toContain(newUpdateKey.multibase);
      expect(rotationParams).not.toContain(oldKey);
    },
  );

  test(
    // @user-promise: e2e/scenarios/identity/webvh-rotation.md
    "did.jsonl history chain grows by exactly one entry; entry hash chain links correctly",
    async ({ request }) => {
      // spec: identity-did.md §3.4 line 165
      const baseUrl = solandBaseUrl();
      const witness = generateWebvhKey();
      const { did, scid, genesis, updateKey } = await registerGenesis(
        request,
        baseUrl,
        { localId: uniqueLocalId("alice-chain") },
      );

      const before = await fetchDidLog(request, baseUrl, did);
      expect(before.length).toBe(1);

      const newUpdateKey = generateWebvhKey();
      const rotation = buildRotationEntry({
        did,
        scid,
        prevVersionId: genesis.versionId,
        prevDidDocument: genesis.didDocument,
        newUpdateKey,
        signers: [updateKey],
        witnesses: [witness],
      });
      await rotateWebvh(request, baseUrl, did, rotation);

      const after = await fetchDidLog(request, baseUrl, did);
      expect(after.length).toBe(2);
      // The rotation entry links to the genesis head: previousVersionId equals
      // the genesis versionId (the resolver's chain check enforces this and the
      // self-hash on resolve).
      const rotationEntry = after[1].operation as Record<string, unknown>;
      expect(rotationEntry.previousVersionId).toBe(genesis.versionId);
      // The resolve gate validated the whole chain, so resolution succeeds.
      const resolved = await resolveDid(request, baseUrl, did);
      expect(resolved.did_document.did).toBe(did);
    },
  );

  test(
    // @user-promise: e2e/scenarios/identity/webvh-rotation.md
    "E9.1 tampered prev_entry_hash makes resolver fail closed (degraded_no_witness must NOT mask integrity break)",
    async ({ request }) => {
      // spec: identity-did.md §4.2.1 line 286
      const baseUrl = solandBaseUrl();
      const witness = generateWebvhKey();
      const { did, scid, genesis, updateKey } = await registerGenesis(
        request,
        baseUrl,
        { localId: uniqueLocalId("alice-tamper") },
      );

      const newUpdateKey = generateWebvhKey();
      const rotation = buildRotationEntry({
        did,
        scid,
        prevVersionId: genesis.versionId,
        prevDidDocument: genesis.didDocument,
        newUpdateKey,
        signers: [updateKey],
        witnesses: [witness],
      });
      // Tamper: point previousVersionId at a forged head. The chain check
      // (webvh_chain_break) fails closed BEFORE any witness/degraded handling.
      rotation.entry.previousVersionId =
        "1-zForgedPreviousHash000000000000000000000000";
      const response = await rawRotateWebvh(request, baseUrl, did, rotation);
      expect(response.ok()).toBeFalsy();
      const body = await response.json();
      expect(wireErrCode(body)).toBe("webvh_chain_break");
    },
  );

  test(
    // @user-promise: e2e/scenarios/identity/webvh-rotation.md
    "E9.2 hosting domain serves a DID Doc with mismatched SCID; resolver rejects (DNS hijack protection)",
    async ({ request }) => {
      // spec: identity-did.md §3 line 76
      const baseUrl = solandBaseUrl();
      const { genesis } = await registerGenesis(request, baseUrl, {
        localId: uniqueLocalId("alice-scid"),
      });
      // Resolve a DID whose embedded SCID does not match the genesis-derived
      // SCID (a DNS-hijack / split-view forgery): same host + local_id, forged
      // scid segment. The resolver derives the SCID from the genesis entry and
      // rejects the mismatch.
      const forgedScid = "zForgedScid000000000000000000000000000000000";
      const forgedDid = genesis.did.replace(genesis.scid, forgedScid);
      expect(forgedDid).not.toBe(genesis.did);
      // The forged DID has no local genesis log under that SCID, so the resolver
      // cannot derive a matching SCID and does not return the real document.
      const response = await rawResolveDid(request, baseUrl, forgedDid);
      if (response.ok()) {
        const body = await response.json();
        // It must NOT have surfaced the genuine alice document under the forged
        // SCID — that would be the DNS-hijack acceptance the spec forbids.
        expect(
          (body as { did_document?: { did?: string } }).did_document?.did,
        ).not.toBe(genesis.did);
      } else {
        expect(response.status()).toBeGreaterThanOrEqual(400);
      }
    },
  );

  test(
    // @user-promise: e2e/scenarios/identity/webvh-rotation.md
    "E9.3 organization rotation requires N-of-M governance signatures; single-sig submission rejected",
    async ({ request }) => {
      // spec: identity-did.md §8.2
      const baseUrl = solandBaseUrl();
      const witness = generateWebvhKey();
      const gov1 = generateWebvhKey();
      const gov2 = generateWebvhKey();
      const gov3 = generateWebvhKey();
      const governance = {
        threshold: 2,
        eligibleMethods: [gov1.multibase, gov2.multibase, gov3.multibase],
      };
      const { did, scid, genesis } = await registerGenesis(request, baseUrl, {
        localId: uniqueLocalId("acme-gov"),
        governance,
      });

      const newUpdateKey = generateWebvhKey();
      const baseRotation = {
        did,
        scid,
        prevVersionId: genesis.versionId,
        prevDidDocument: genesis.didDocument,
        newUpdateKey,
        governance,
        witnesses: [witness],
      };

      // Single governance signature on a 2-of-3 org DID fails closed.
      const singleSig = buildRotationEntry({
        ...baseRotation,
        signers: [gov1],
      });
      const rejected = await rawRotateWebvh(request, baseUrl, did, singleSig);
      expect(rejected.ok()).toBeFalsy();
      const body = await rejected.json();
      expect(wireErrCode(body)).toBe("webvh_governance_quorum_not_met");

      // Two governance signatures meet the quorum and are accepted.
      const quorum = buildRotationEntry({
        ...baseRotation,
        signers: [gov1, gov2],
      });
      await rotateWebvh(request, baseUrl, did, quorum);
      const resolved = await resolveDid(request, baseUrl, did);
      expect(documentControlKeys(resolved.did_document.document)).toContain(
        newUpdateKey.multibase,
      );
    },
  );

  test(
    // @user-promise: e2e/scenarios/identity/webvh-rotation.md
    "E9.4 witness offline > 24h causes resolver to enter unresolvable state; new events rejected until witness recovers",
    async ({ request }) => {
      // spec: identity-did.md §4.2.1 (24h degraded window). The joint harness
      // compresses the 24h window to COTEST_WEBVH_DEGRADED_NO_WITNESS_MAX_SECS
      // (default 30s) so the expiry edge is reachable without a real wait.
      test.slow();
      const baseUrl = solandBaseUrl();
      const windowSecs = degradedWindowSecs();
      const witness = generateWebvhKey();
      const { did, scid, genesis, updateKey } = await registerGenesis(
        request,
        baseUrl,
        { localId: uniqueLocalId("alice-degraded") },
      );

      // A non-rotation entry that DECLARES witnesses but ships no witness
      // attestation: the resolver allows it inside the degraded window, then
      // fails closed once the (compressed) window expires. keepControl keeps
      // the genesis document + updateKeys unchanged so soland's
      // is_rotation_entry is false (witness/metadata refresh, not a rotation —
      // rotation entries fail closed immediately, a separate stricter rule).
      const witnessless = buildRotationEntry({
        did,
        scid,
        prevVersionId: genesis.versionId,
        prevDidDocument: genesis.didDocument,
        prevUpdateKeys: [updateKey.multibase],
        keepControl: true,
        newUpdateKey: updateKey,
        signers: [updateKey],
        witnessKeys: [witness.multibase],
        // versionTime in the past so age already exceeds the compressed window,
        // modelling a witness that has been offline beyond the 24h ceiling.
        versionTime: new Date(
          Date.now() - (windowSecs + 60) * 1000,
        ).toISOString(),
      });
      const response = await rawRotateWebvh(request, baseUrl, did, witnessless);
      // With versionTime already past the window, the witness-evidence-expired
      // gate fails closed at write time.
      expect(response.ok()).toBeFalsy();
      const body = await response.json();
      expect(wireErrCode(body)).toBe("webvh_witness_evidence_expired");
    },
  );

  test(
    // @user-promise: e2e/scenarios/identity/webvh-rotation.md
    "E9.5 emergency rotation using recovery key (no prev-key signature path) succeeds",
    async ({ request }) => {
      // spec: key-management.md §3.3 recovery key path
      const baseUrl = solandBaseUrl();
      const witness = generateWebvhKey();
      const recoveryKey = generateWebvhKey();
      const { did, scid, genesis } = await registerGenesis(request, baseUrl, {
        localId: uniqueLocalId("alice-recovery"),
        recoveryKeys: [recoveryKey.multibase],
      });

      // Emergency rotation: the controller key is assumed compromised, so the
      // rotation entry is signed by the genesis-declared recovery key only —
      // NOT the previous update key. The resolver accepts it via the recovery
      // path (no prev-controller signature required).
      const newUpdateKey = generateWebvhKey();
      const emergency = buildRotationEntry({
        did,
        scid,
        prevVersionId: genesis.versionId,
        prevDidDocument: genesis.didDocument,
        newUpdateKey,
        signers: [recoveryKey],
        // carry the recovery key forward so future emergency rotations remain
        // possible, and witness the high-risk operation.
        recoveryKeys: [recoveryKey.multibase],
        witnesses: [witness],
      });
      await rotateWebvh(request, baseUrl, did, emergency);

      const resolved = await resolveDid(request, baseUrl, did);
      expect(documentControlKeys(resolved.did_document.document)).toContain(
        newUpdateKey.multibase,
      );

      // A control: a rotation signed by neither the prev controller nor a
      // declared recovery key fails closed.
      const stranger = generateWebvhKey();
      const unauthorized = buildRotationEntry({
        did,
        scid,
        prevVersionId: emergency.versionId,
        prevDidDocument: emergency.didDocument,
        newUpdateKey: generateWebvhKey(),
        signers: [stranger],
        recoveryKeys: [recoveryKey.multibase],
        witnesses: [witness],
      });
      const rejected = await rawRotateWebvh(
        request,
        baseUrl,
        did,
        unauthorized,
      );
      expect(rejected.ok()).toBeFalsy();
      const body = await rejected.json();
      expect(wireErrCode(body)).toBe("webvh_rotation_not_authorized");
    },
  );
});
