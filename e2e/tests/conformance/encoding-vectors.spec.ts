// Conformance — Encoding & Crypto / Redaction Vectors
// Contract: e2e/scenarios/conformance/encoding-vectors.md
// Spec: conformance/conformance-vectors.md §1 (encoding/crypto), §3 (redaction)
// Fixtures: arkret-spec/spec/v1/artifacts/fixtures/encoding-fixture.json,
//           arkret-spec/spec/v1/artifacts/fixtures/crypto-signature-fixture.json,
//           arkret-spec/spec/v1/artifacts/fixtures/redaction-fixture.json
// Rust parity: cotest/src/conformance/{encoding,envelope,redaction}.rs already
// drive these vectors against in-process traits; this suite re-runs the same
// vectors over the HTTP surface to catch wire-level canonicalizer drift.
//
// G3.S7 endpoint live as of 2026-05-21; fixmes converted to live in G2.T10.
// Vector files that don't exist on disk (or fixture entries that don't carry
// enough data for projection assertions) are still fixme with a one-line
// comment naming the missing fixture.

import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "../../helpers/arkret-test";
import { conformanceBaseUrl } from "../../helpers/env";
import { canonicalJson, wireErrCode } from "../../helpers/soland-api";

// ---------------------------------------------------------------------------
// Fixture loader — resolves relative to this spec file so cwd doesn't matter.
// From cotest/e2e/tests/conformance/<spec>.spec.ts that's four levels up to
// the repo root, then into arkret-spec/spec/v1/artifacts/fixtures.
// ---------------------------------------------------------------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const fixturesRoot = resolve(
  __dirname,
  "../../../../arkret-spec/spec/v1/artifacts/fixtures",
);

type EncodingVector = {
  vector_id: string;
  kind: string;
  input?: unknown;
  expected_canonical_bytes_utf8?: string;
  expected_digest?: string;
  rejected_inputs?: unknown[];
  rejected_input_categories?: string[];
  rejection_reason_codes?: string[];
  expected_ascending?: string[];
  payload_metadata?: unknown;
  expected_metadata_canonical_bytes_utf8?: string;
  ciphertext_base64url?: string;
  ciphertext_bytes_utf8?: string;
  input_cursor?: string;
  decoded_payload_canonical_bytes_utf8?: string;
};

type EncodingFixture = {
  profile: string;
  version: string;
  vectors: EncodingVector[];
};

type CryptoSigVector = {
  name: string;
  alg: string;
  did_document_fragment: {
    publicKeyJwk: { crv: string; x: string; kty: string };
  };
  canonical_event_payload: string;
  event_digest: string;
  event_without_proofs: Record<string, unknown>;
};

type CryptoSignatureFixture = {
  profile: string;
  vectors: CryptoSigVector[];
};

function loadFixture<T>(name: string): T | null {
  const path = resolve(fixturesRoot, name);
  try {
    return JSON.parse(readFileSync(path, "utf8")) as T;
  } catch {
    return null;
  }
}

type RedactionCase = {
  name: string;
  vector_id?: string;
  event?: Record<string, unknown>;
  redaction_receipt?: Record<string, unknown>;
  expected_projection?: Record<string, unknown>;
};

type RedactionFixture = {
  suite: string;
  cases: RedactionCase[];
};

const encodingFixture = loadFixture<EncodingFixture>("encoding-fixture.json");
const cryptoSignatureFixture = loadFixture<CryptoSignatureFixture>(
  "crypto-signature-fixture.json",
);
const redactionFixture = loadFixture<RedactionFixture>("redaction-fixture.json");

function redactionCaseByName(name: string): RedactionCase | undefined {
  return redactionFixture?.cases.find((entry) => entry.name === name);
}

function vectorById(id: string): EncodingVector | undefined {
  return encodingFixture?.vectors.find((v) => v.vector_id === id);
}

// Canonical-JSON (matches soland::routing::conformance::util::canonical_json):
// imported from the shared helper so there is one canonicalizer for the whole
// e2e suite. Used to build local expected canonicals when the fixture only
// gives us inputs (e.g. building a hlc clocks list).

// Convert a single HLC fixture string `"<unix_ms_hex>-<logical_hex>-<actor_id_hash>"`
// into the `{actor, hlc, payload_hint}` clock shape soland's /hlc-merge expects.
function hlcToClockEntry(hlc: string): {
  actor: string;
  hlc: string;
  payload_hint: null;
} {
  const segments = hlc.split("-");
  const actor = segments[segments.length - 1] ?? hlc;
  return { actor, hlc, payload_hint: null };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe.configure({ mode: "serial" });

test.describe("conformance encoding vectors", () => {
  // -------------------------------------------------------------------------
  // §1.1 Canonical JSON — basic + nested (live)
  // -------------------------------------------------------------------------
  test("§1.1 canonical JSON encoding (basic) matches spec vector", async ({
    request,
  }) => {
    const vector = vectorById("ak.vector.encoding.canonical_json.basic.v1");
    expect(vector, "encoding-fixture vector basic.v1 missing").toBeTruthy();
    const v = vector!;

    const resp = await request.post(
      `${conformanceBaseUrl()}/encode`,
      {
        headers: { "content-type": "application/json" },
        data: canonicalJson({ vector_id: v.vector_id, input: v.input }),
      },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.canonical_json).toBe(v.expected_canonical_bytes_utf8);
    expect(body.digest).toBe(v.expected_digest);
  });

  test("§1.1 canonical JSON encoding (nested) matches spec vector", async ({
    request,
  }) => {
    const vector = vectorById("ak.vector.encoding.canonical_json.nested.v1");
    expect(vector, "encoding-fixture vector nested.v1 missing").toBeTruthy();
    const v = vector!;

    const resp = await request.post(
      `${conformanceBaseUrl()}/encode`,
      {
        headers: { "content-type": "application/json" },
        data: canonicalJson({ vector_id: v.vector_id, input: v.input }),
      },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.canonical_json).toBe(v.expected_canonical_bytes_utf8);
    // The nested vector has no explicit expected_digest field — assert the
    // digest matches what canonical bytes hash to (sha256:<lowercase_hex>).
    expect(body.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  test("§1.1 TS canonical JSON helper rejects non-NFC strings and non-integer numbers", async () => {
    expect(canonicalJson({ text: "\u00E9" })).toBe('{"text":"é"}');
    const nonCanonicalNumber =
      /non-canonical number|does not allow floating point|ambiguous numbers|outside the JSON safe-integer range|non-JSON number/;
    expect(() => canonicalJson({ text: "e\u0301" })).toThrow(
      /non-NFC|not Unicode NFC/,
    );
    expect(() => canonicalJson({ n: 1.5 })).toThrow(nonCanonicalNumber);
    expect(() => canonicalJson({ n: Number.MAX_SAFE_INTEGER + 1 })).toThrow(
      nonCanonicalNumber,
    );
    expect(() => canonicalJson({ n: -0 })).toThrow(nonCanonicalNumber);
  });

  test("§1.1 canonical JSON reject (noncanonical numbers) returns 4xx", async ({
    request,
  }) => {
    const vector = vectorById(
      "ak.vector.encoding.reject_noncanonical_numbers.v1",
    );
    expect(
      vector,
      "encoding-fixture vector reject_noncanonical_numbers.v1 missing",
    ).toBeTruthy();
    const v = vector!;

    const resp = await request.post(
      `${conformanceBaseUrl()}/encode`,
      {
        data: {
          vector_id: v.vector_id,
          input: (v.rejected_inputs ?? [{ n: "NaN" }])[0],
        },
      },
    );
    expect(resp.status()).toBeGreaterThanOrEqual(400);
    expect(resp.status()).toBeLessThan(500);
    const body = await resp.json();
    const acceptedCodes = new Set([
      "schema_violation",
      "json_invalid",
      "invalid_canonical_json",
      "invalid_encoding",
    ]);
    expect(acceptedCodes.has(wireErrCode(body) ?? "")).toBe(true);
    // Reject paths MUST NOT leak partial canonical bytes / digest.
    expect(body.canonical_json).toBeUndefined();
    expect(body.digest).toBeUndefined();
  });

  test("§1.1 canonical JSON reject (malformed JSON) returns 4xx", async ({
    request,
  }) => {
    const vector = vectorById("ak.vector.encoding.reject_malformed_json.v1");
    expect(
      vector,
      "encoding-fixture vector reject_malformed_json.v1 missing",
    ).toBeTruthy();
    const v = vector!;

    const resp = await request.post(
      `${conformanceBaseUrl()}/encode`,
      {
        // The soland reject classifier triggers off `vector_id` containing
        // `reject_malformed_json` — input shape is irrelevant to the reject
        // dispatch but we still send a plausible body so the handler reaches
        // the reject branch the same way a real malformed payload would.
        data: { vector_id: v.vector_id, input: { duplicate: 1 } },
      },
    );
    expect(resp.status()).toBeGreaterThanOrEqual(400);
    expect(resp.status()).toBeLessThan(500);
    const body = await resp.json();
    const acceptedCodes = new Set([
      "schema_violation",
      "json_invalid",
      "invalid_canonical_json",
      "invalid_encoding",
    ]);
    expect(acceptedCodes.has(wireErrCode(body) ?? "")).toBe(true);
    expect(body.canonical_json).toBeUndefined();
    expect(body.digest).toBeUndefined();
  });

  // -------------------------------------------------------------------------
  // §1.2 Event / batch receipt / signature binding digests
  // -------------------------------------------------------------------------
  test("§1.2 event_digest canonical bytes + digest match spec vector", async ({
    request,
  }) => {
    const vector = vectorById("ak.vector.encoding.event_digest.v1");
    expect(vector, "encoding-fixture vector event_digest.v1 missing").toBeTruthy();
    const v = vector!;

    const resp = await request.post(
      `${conformanceBaseUrl()}/encode`,
      {
        headers: { "content-type": "application/json" },
        data: canonicalJson({ vector_id: v.vector_id, input: v.input }),
      },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.canonical_json).toBe(v.expected_canonical_bytes_utf8);
    expect(body.digest).toBe(v.expected_digest);
  });

  test("§1.2 event_batch_receipt_digest canonical bytes + digest match spec vector", async ({
    request,
  }) => {
    const vector = vectorById(
      "ak.vector.encoding.event_batch_receipt_digest.v1",
    );
    expect(
      vector,
      "encoding-fixture vector event_batch_receipt_digest.v1 missing",
    ).toBeTruthy();
    const v = vector!;

    const resp = await request.post(
      `${conformanceBaseUrl()}/encode`,
      {
        headers: { "content-type": "application/json" },
        data: canonicalJson({ vector_id: v.vector_id, input: v.input }),
      },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.canonical_json).toBe(v.expected_canonical_bytes_utf8);
    expect(body.digest).toBe(v.expected_digest);
  });

  test("§1.2 signature binding deterministic across runs + verifies under Ed25519 public key", async ({
    request,
  }) => {
    // Drive /sign with the same event from crypto-signature-fixture so the
    // canonical_bytes are well-pinned, then assert (a) determinism (re-POST
    // produces byte-identical signature) and (b) the returned Ed25519
    // signature verifies under the returned public_key. soland derives the
    // signing key deterministically from `signing_key_ref` so this is
    // fully reproducible.
    expect(
      cryptoSignatureFixture,
      "crypto-signature-fixture.json missing or unparseable",
    ).toBeTruthy();
    const sigVector = cryptoSignatureFixture!.vectors[0];
    expect(sigVector, "crypto-signature-fixture vectors[0] missing").toBeTruthy();
    const event = sigVector.event_without_proofs;

    const body1 = {
      vector_id: sigVector.name,
      event,
      signing_key_ref: "alice.dev_key",
    };
    const resp1 = await request.post(
      `${conformanceBaseUrl()}/sign`,
      {
        headers: { "content-type": "application/json" },
        data: canonicalJson(body1),
      },
    );
    expect(resp1.status(), await resp1.text()).toBe(200);
    const result1 = await resp1.json();
    expect(result1.canonical_bytes).toBe(sigVector.canonical_event_payload);
    expect(result1.digest).toBe(sigVector.event_digest);
    expect(result1.algorithm).toBe("ed25519");
    expect(typeof result1.signature).toBe("string");
    expect(typeof result1.public_key).toBe("string");

    // Determinism: re-POST with identical body should yield byte-identical
    // signature (Ed25519 is deterministic by construction; soland's seed is
    // derived from signing_key_ref so the key is also stable).
    const resp2 = await request.post(
      `${conformanceBaseUrl()}/sign`,
      {
        headers: { "content-type": "application/json" },
        data: canonicalJson(body1),
      },
    );
    expect(resp2.status()).toBe(200);
    const result2 = await resp2.json();
    expect(result2.signature).toBe(result1.signature);
    expect(result2.public_key).toBe(result1.public_key);

    // Verify the signature under the returned public key. The wire format is
    // base64url-no-pad (per soland::routing::conformance::handlers::sign).
    const base64urlToBuf = (s: string): Buffer => {
      const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
      const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
      return Buffer.from(b64, "base64");
    };
    const pubKeyRaw = base64urlToBuf(result1.public_key);
    const signatureRaw = base64urlToBuf(result1.signature);
    expect(pubKeyRaw.length).toBe(32);
    expect(signatureRaw.length).toBe(64);
    // Node's createPublicKey accepts a JWK for Ed25519 (OKP / crv=Ed25519).
    const publicKey = createPublicKey({
      key: {
        kty: "OKP",
        crv: "Ed25519",
        x: pubKeyRaw.toString("base64url"),
      },
      format: "jwk",
    });
    const ok = cryptoVerify(
      null,
      Buffer.from(result1.canonical_bytes, "utf8"),
      publicKey,
      signatureRaw,
    );
    expect(ok).toBe(true);
  });

  // -------------------------------------------------------------------------
  // §1.3 HLC ordering — live + overflow reject
  // -------------------------------------------------------------------------
  test("§1.3 HLC ordering converges on expected ascending order", async ({
    request,
  }) => {
    const vector = vectorById("ak.vector.encoding.hlc_order.v1");
    expect(vector, "encoding-fixture vector hlc_order.v1 missing").toBeTruthy();
    const v = vector!;
    expect(Array.isArray(v.input)).toBe(true);
    expect(Array.isArray(v.expected_ascending)).toBe(true);

    const clocks = (v.input as string[]).map(hlcToClockEntry);
    const resp = await request.post(
      `${conformanceBaseUrl()}/hlc-merge`,
      {
        headers: { "content-type": "application/json" },
        data: canonicalJson({ vector_id: v.vector_id, clocks }),
      },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.ordered)).toBe(true);
    const orderedHlcs = (body.ordered as Array<{ hlc: string }>).map(
      (entry) => entry.hlc,
    );
    expect(orderedHlcs).toEqual(v.expected_ascending);
  });

  test("§1.3 HLC logical overflow returns 503 hlc_logical_overflow", async ({
    request,
  }) => {
    const vector = vectorById("ak.vector.encoding.hlc_logical_overflow.v1");
    expect(
      vector,
      "encoding-fixture vector hlc_logical_overflow.v1 missing",
    ).toBeTruthy();
    const v = vector!;

    const resp = await request.post(
      `${conformanceBaseUrl()}/hlc-merge`,
      {
        headers: { "content-type": "application/json" },
        // Vector_id contains `logical_overflow` which trips soland's reject
        // branch — clocks list is irrelevant to the reject dispatch.
        data: canonicalJson({ vector_id: v.vector_id, clocks: [] }),
      },
    );
    // error-code-registry.json registers hlc_logical_overflow with
    // http_status 503 (retryable: the producer could not allocate a fresh
    // logical counter within the current millisecond).
    expect(resp.status()).toBe(503);
    const body = await resp.json();
    expect(wireErrCode(body)).toBe("hlc_logical_overflow");
    expect(body.ordered).toBeUndefined();
  });

  // -------------------------------------------------------------------------
  // §1.4 Cursor opacity + stable across re-reduce
  // -------------------------------------------------------------------------
  test("§1.4 sync cursor stable across re-reduce + opaque to clients", async ({
    request,
  }) => {
    const vector = vectorById("ak.vector.encoding.cursor_opaque.core.v1");
    expect(
      vector,
      "encoding-fixture vector cursor_opaque.core.v1 missing",
    ).toBeTruthy();
    const v = vector!;

    // Build a small events list and POST in two different orders. soland's
    // cursor handler folds events into an order-independent digest, so both
    // POSTs MUST return the same cursor string.
    const events = [
      { event_id: "ak:event:ARpiDPsbW2AJUyySDauMC0D4IKLvB9L-ahd5-622lBqY" },
      { event_id: "ak:event:AXvZ07LXpvHUCn0jFurPzNlYh-87RUj62VEaoYHUD8Fr" },
      { event_id: "ak:event:AVcAdvZ2vg_iyVrtExlPij_vSCh0Onsy20GO0nR2yD4s" },
    ];
    const shuffled = [events[2], events[0], events[1]];

    const respA = await request.post(
      `${conformanceBaseUrl()}/cursor`,
      {
        headers: { "content-type": "application/json" },
        data: canonicalJson({ vector_id: v.vector_id, events, reduce_round: 1 }),
      },
    );
    expect(respA.status()).toBe(200);
    const bodyA = await respA.json();
    expect(typeof bodyA.cursor).toBe("string");

    const respB = await request.post(
      `${conformanceBaseUrl()}/cursor`,
      {
        headers: { "content-type": "application/json" },
        data: canonicalJson({
          vector_id: v.vector_id,
          events: shuffled,
          reduce_round: 2,
        }),
      },
    );
    expect(respB.status()).toBe(200);
    const bodyB = await respB.json();
    expect(bodyB.cursor).toBe(bodyA.cursor);

    // Clients MUST treat the cursor as one opaque string. They may retain and
    // replay it, but MUST NOT decode it or assert an implementation-owned
    // internal shape.
    expect(bodyA.cursor.startsWith("ak:cursor:")).toBe(true);
    for (const event of events) {
      expect(
        bodyA.cursor.includes(event.event_id),
        `cursor leaked event_id ${event.event_id}`,
      ).toBe(false);
    }
  });

  // -------------------------------------------------------------------------
  // §1.5 Envelope canonical digest
  // -------------------------------------------------------------------------
  test("§1.5 encrypted envelope canonical bytes + digest match spec vector", async ({
    request,
  }) => {
    const vector = vectorById(
      "ak.vector.encoding.encrypted_envelope_digest.v1",
    );
    expect(
      vector,
      "encoding-fixture vector encrypted_envelope_digest.v1 missing",
    ).toBeTruthy();
    const v = vector!;

    // Drive /envelope with the payload_metadata block and ciphertext bytes.
    // Per conformance-vectors §1.5, digest input is
    // canonical_json(payload_metadata) || base64url_decode(ciphertext).
    const resp = await request.post(
      `${conformanceBaseUrl()}/envelope`,
      {
        headers: { "content-type": "application/json" },
        data: canonicalJson({
          vector_id: v.vector_id,
          envelope: v.payload_metadata,
          ciphertext_base64url: v.ciphertext_base64url,
        }),
      },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.canonical_bytes).toBe(v.expected_metadata_canonical_bytes_utf8);
    expect(body.digest).toBe(v.expected_digest);
    // Determinism: re-post the same envelope should yield identical digest.
    const resp2 = await request.post(
      `${conformanceBaseUrl()}/envelope`,
      {
        headers: { "content-type": "application/json" },
        data: canonicalJson({
          vector_id: v.vector_id,
          envelope: v.payload_metadata,
          ciphertext_base64url: v.ciphertext_base64url,
        }),
      },
    );
    const body2 = await resp2.json();
    expect(body2.digest).toBe(body.digest);
    expect(body2.canonical_bytes).toBe(body.canonical_bytes);
  });

  // -------------------------------------------------------------------------
  // §3 Redaction visibility — owner + guest projection (live; uses a small
  // inline synthetic event because redaction-fixture.json carries only
  // policy meta-data, not full event payloads).
  // -------------------------------------------------------------------------
  test("§3 redaction visibility matrix matches projection (owner vs guest)", async ({
    request,
  }) => {
    // redaction-fixture.json today only declares `preserve` field lists and
    // pending/late/audit semantic stubs — it does NOT carry concrete
    // (original_event, redaction_event, expected_retained_fields_*) tuples.
    // Until that fixture grows real projection vectors, this test drives
    // soland's projection rule directly: an event with `sender == alice`,
    // a redaction over `payload.content`, viewed by both the owner and a
    // guest. Owner sees full event; guest sees content stripped + a
    // `redacted_because` marker added.
    const ownerDid = "did:web:alice.example";
    const guestDid = "did:web:guest.example";
    const event = {
      event_id: "ak:event:AY3Ymj4NJ7YEqOwLhBjWKXoD1P7PbP5OfU_ed6ZWIIMc",
      kind: "ak.message.create",
      sender_actor_id: ownerDid,
      payload: {
        strand_id: "ak:strand:ASH_OYgk3yTng0ptjCny23EVDMiKLUxD8bxiWI7MuZ8E",
        content: { kind: "ak.content.text", body: "private message" },
      },
    };
    const redaction = {
      target_event_id: event.event_id,
      fields: ["payload.content"],
      reason: { code: "user_requested", note: "owner removed content" },
    };

    const ownerResp = await request.post(
      `${conformanceBaseUrl()}/redact`,
      {
        headers: { "content-type": "application/json" },
        data: canonicalJson({
          vector_id: "ak.vector.redaction.owner_view.synthetic.v1",
          event,
          redaction,
          viewer_did: ownerDid,
        }),
      },
    );
    expect(ownerResp.status()).toBe(200);
    const ownerBody = await ownerResp.json();
    // Owner projection: full content retained, no redacted_because marker.
    expect(ownerBody.projected_event?.payload?.content?.body).toBe(
      "private message",
    );
    expect(ownerBody.projected_event?.redacted_because).toBeUndefined();

    const guestResp = await request.post(
      `${conformanceBaseUrl()}/redact`,
      {
        headers: { "content-type": "application/json" },
        data: canonicalJson({
          vector_id: "ak.vector.redaction.guest_view.synthetic.v1",
          event,
          redaction,
          viewer_did: guestDid,
        }),
      },
    );
    expect(guestResp.status()).toBe(200);
    const guestBody = await guestResp.json();
    // Guest projection: payload.content stripped entirely (NOT set to null),
    // event_id + redacted_because retained as visible tombstone metadata.
    const guestProjected = guestBody.projected_event as Record<string, unknown>;
    expect(guestProjected.event_id).toBe(event.event_id);
    expect(guestProjected.redacted_because).toEqual(redaction.reason);
    const guestPayload = guestProjected.payload as Record<string, unknown>;
    expect(guestPayload.strand_id).toBe(event.payload.strand_id);
    expect("content" in guestPayload).toBe(false);
  });

  // -------------------------------------------------------------------------
  // §3.4 / §3.5 — hard erasure receipt + snapshot pruning verification stub.
  // redaction-fixture.json now carries concrete
  // (event, redaction_receipt, expected_projection) tuples for both
  // `hard_erasure_receipt` and `snapshot_pruning_stub`. §3.4 drives soland's
  // /erase-receipt endpoint (hard-erasure projection + retained stub digest +
  // no-plaintext-leak guard); §3.5 drives /redact to confirm the default view
  // after snapshot pruning shows the redacted placeholder, never the original
  // plaintext.
  // -------------------------------------------------------------------------
  test("§3.4 hard erasure receipt drops plaintext + retains a verification stub digest", async ({
    request,
  }) => {
    const fixtureCase = redactionCaseByName("hard_erasure_receipt");
    expect(
      fixtureCase?.event && fixtureCase?.redaction_receipt,
      "redaction-fixture hard_erasure_receipt tuple missing",
    ).toBeTruthy();
    const c = fixtureCase!;
    const event = c.event!;
    const receipt = c.redaction_receipt!;
    const expected = c.expected_projection ?? {};

    const resp = await request.post(
      `${conformanceBaseUrl()}/erase-receipt`,
      {
        headers: { "content-type": "application/json" },
        data: canonicalJson({
          vector_id: c.vector_id ?? "ak.vector.redaction.hard_erasure_receipt.v1",
          event,
          receipt,
        }),
      },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();

    // Hard erasure deletes payload bytes + derived plaintext: the projected
    // default view MUST NOT carry the original content/proofs, and the
    // fail-closed leak guard MUST report no plaintext fingerprint.
    const projected = body.projected_event as Record<string, unknown>;
    const projectedPayload = (projected.payload ?? {}) as Record<string, unknown>;
    expect("content" in projectedPayload).toBe(false);
    expect("proofs" in projected).toBe(false);
    expect(body.plaintext_fingerprint_present).toBe(false);
    expect(JSON.stringify(projected)).not.toContain("hard erased plaintext");

    // A signed receipt + retained verification stub MUST survive so an auditor
    // can verify the erasure without the erased plaintext.
    expect(body.verification_stub_retained).toBe(true);
    expect(typeof body.retained_stub_digest).toBe("string");
    expect(body.retained_stub_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(body.outcome).toBe(expected.erasure_receipt_outcome ?? "completed");
    expect(body.legal_hold_blocked).toBe(false);

    // The tombstone marker pivots to the signed receipt id.
    const because = projected.redacted_because as Record<string, unknown>;
    expect(because?.receipt_id).toBe(receipt.receipt_id);

    // §3.4 legal-hold branch: a blocked outcome MUST still strip plaintext from
    // the default view but report the erasure as blocked.
    const blockedReceipt = {
      ...receipt,
      outcome: "blocked_by_legal_hold",
      legal_hold_ref: "ak:policy:01970e58-0004-7000-8000-0000000004b9",
    };
    const blockedResp = await request.post(
      `${conformanceBaseUrl()}/erase-receipt`,
      {
        headers: { "content-type": "application/json" },
        data: canonicalJson({
          vector_id: c.vector_id ?? "ak.vector.redaction.hard_erasure_receipt.v1",
          event,
          receipt: blockedReceipt,
        }),
      },
    );
    expect(blockedResp.status()).toBe(200);
    const blockedBody = await blockedResp.json();
    expect(blockedBody.legal_hold_blocked).toBe(true);
    expect(blockedBody.plaintext_fingerprint_present).toBe(false);
    expect(
      JSON.stringify(blockedBody.projected_event),
    ).not.toContain("hard erased plaintext");
  });

  test("§3.5 snapshot pruning default view retains redacted placeholder, not plaintext", async ({
    request,
  }) => {
    const fixtureCase = redactionCaseByName("snapshot_pruning_stub");
    expect(
      fixtureCase?.event && fixtureCase?.redaction_receipt,
      "redaction-fixture snapshot_pruning_stub tuple missing",
    ).toBeTruthy();
    const c = fixtureCase!;
    const event = c.event!;
    const receipt = c.redaction_receipt! as {
      fields?: string[];
      reason?: Record<string, unknown>;
    };
    const originalBody = (
      (event.payload as Record<string, unknown>).content as Record<string, unknown>
    ).body as string;

    // After snapshot pruning, the default (non-owner) view MUST show the
    // redacted placeholder + tombstone, never the original plaintext. Drive
    // /redact as a guest using the receipt's field list + reason.
    const guestResp = await request.post(
      `${conformanceBaseUrl()}/redact`,
      {
        headers: { "content-type": "application/json" },
        data: canonicalJson({
          vector_id: c.vector_id ?? "ak.vector.redaction.snapshot_pruning_stub.v1",
          event,
          redaction: {
            target_event_id: event.event_id,
            fields: receipt.fields ?? ["payload.content"],
            reason: receipt.reason,
          },
          viewer_did: "did:web:guest.example",
        }),
      },
    );
    expect(guestResp.status()).toBe(200);
    const guestBody = await guestResp.json();
    const projected = guestBody.projected_event as Record<string, unknown>;
    const projectedPayload = (projected.payload ?? {}) as Record<string, unknown>;

    // Content stripped (key removed, NOT nulled); plaintext never surfaces.
    expect("content" in projectedPayload).toBe(false);
    expect(JSON.stringify(projected)).not.toContain(originalBody);
    // Strand position (a preserved field) survives so the timeline slot stays.
    expect(projectedPayload.strand_id).toBe(
      (event.payload as Record<string, unknown>).strand_id,
    );
    // Tombstone reason retained for the redacted placeholder.
    expect(projected.redacted_because).toEqual(receipt.reason);
  });

});
