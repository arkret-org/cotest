// Conformance — Cross-language canonical-JSON parity (TS side)
//
// `canonicalJson` delegates to the Rust `cotest-wire` bridge and therefore to
// the SDK's authoritative `arkret_canonical` implementation (RFC 8785 JCS,
// integer-only number profile). The TypeScript harness owns transport and
// typing only; it does not carry a second canonicalisation algorithm.
//
// This suite and the Rust gate (cotest/src/conformance/canonical_cross_lang.rs)
// read the SAME golden vectors in e2e/fixtures/canonical-cross-check.json. The
// `canonical` column is produced by the SDK; this test asserts the Node-to-Rust
// bridge returns it byte-for-byte, while the Rust gate asserts the SDK does.
//
// Third lane: the `.mjs` runtime (mocks + scripts) carries its own
// canonicalJson in e2e/mocks/_shared/http.mjs whose digests must equally match
// what soland/the SDK verify. It is asserted here against the same golden so
// its "lock-step with the TS helper" contract is machine-checked, not a
// comment promise.
//
// Pure logic test: no live server, no network. It exercises the canonicaliser
// in isolation.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "../../helpers/arkret-test";
import { canonicalJson } from "../../helpers/soland-api";
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore — plain-ESM mock helper module without type declarations.
import { canonicalJson as canonicalJsonMjs } from "../../mocks/_shared/http.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
// From cotest/e2e/tests/conformance/<spec>.spec.ts up to cotest/e2e/fixtures.
const fixturePath = resolve(
  __dirname,
  "../../fixtures/canonical-cross-check.json",
);

type CrossCheckVector = {
  value: unknown;
  canonical: string;
};

type CrossCheckDoc = {
  vectors: CrossCheckVector[];
};

const doc = JSON.parse(readFileSync(fixturePath, "utf8")) as CrossCheckDoc;

test.describe("canonical JSON cross-language parity (typed bridge vs SDK golden)", () => {
  test("golden fixture carries vectors", () => {
    expect(Array.isArray(doc.vectors)).toBe(true);
    expect(doc.vectors.length).toBeGreaterThan(0);
  });

  for (const [index, vector] of doc.vectors.entries()) {
    test(`vector[${index}] typed bridge canonicalJson matches SDK golden byte-for-byte`, () => {
      const produced = canonicalJson(vector.value);
      expect(produced).toBe(vector.canonical);
    });

    test(`vector[${index}] mjs canonicalJson (mocks/_shared/http.mjs) matches SDK golden byte-for-byte`, () => {
      const produced = (canonicalJsonMjs as (value: unknown) => string)(vector.value);
      expect(produced).toBe(vector.canonical);
    });
  }
});
