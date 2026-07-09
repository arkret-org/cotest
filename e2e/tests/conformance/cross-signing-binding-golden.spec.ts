// Conformance — Cross-language cross-signing / device-trust signing-input parity
//
// The e2e helpers in cotest/e2e/helpers/cross-signing-harness.ts byte-mirror the
// SDK's device-lifecycle §5.1 / §5.2 canonical signing-input construction in
// TypeScript (crossSigningBindingInput -> `ck-cross-signing-bind-v1`,
// deviceTrustBindingInput -> `ck-device-trust-bind-v1`) because the e2e harness
// runs on Node and cannot call the Rust SDK directly. The authoritative
// construction is `arkret_crypto::CrossSigningPublishContent::{self,user}_signing_binding_input`
// and `arkret_crypto::DeviceTrustBinding::canonical_input`, and soland verifies
// the resulting signatures with those exact bytes — so any byte-level drift
// between the TS mirror and the SDK is a silent signature
// false-negative/false-positive vector.
//
// This suite and the Rust gate
// (cotest/src/conformance/cross_signing_binding_golden.rs) read the SAME golden
// vectors in e2e/fixtures/cross-signing-binding-golden.json. The
// `expected_*_input_b64` columns are produced by the SDK (via the cotest-wire
// bin); this test asserts the TS byte-mirror reproduces them byte-for-byte,
// while the Rust gate asserts the SDK does. If the TS mirror drifts, only this
// side fails — localising the regression.
//
// Pure logic test: no live server. The TS `crossSigningBindingInput` /
// `deviceTrustBindingInput` do route their canonical-JSON body through the
// cotest-wire SDK canonicaliser (canonicalJson), so a built `cotest-wire`
// binary (cargo) is the only dependency, exactly like canonical-cross-lang.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";
import {
  crossSigningBindingInput,
  deviceTrustBindingInput,
} from "../../helpers/cross-signing-harness";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const fixturePath = resolve(
  __dirname,
  "../../fixtures/cross-signing-binding-golden.json",
);

type KeyRecord = { kid: string; alg: string; public_key: string };

type CrossSigningVector = {
  name: string;
  publish_payload: {
    principal_id: string;
    trust_domain: string;
    self_signing_key: KeyRecord;
    user_signing_key: KeyRecord;
    generation: number;
  };
  expected_self_signing_input_b64: string;
  expected_user_signing_input_b64: string;
};

type DeviceTrustVector = {
  name: string;
  input: {
    principal_id: string;
    device_id: string;
    device_public_key: string;
    hpke_key: string;
    algorithms: string[];
    ssk_generation: number;
  };
  expected_input_b64: string;
};

type GoldenDoc = {
  cross_signing_vectors: CrossSigningVector[];
  device_trust_vectors: DeviceTrustVector[];
};

const doc = JSON.parse(readFileSync(fixturePath, "utf8")) as GoldenDoc;

test.describe("cross-signing / device-trust signing-input parity (TS mirror vs SDK golden)", () => {
  test("golden fixture carries vectors", () => {
    expect(doc.cross_signing_vectors.length).toBeGreaterThan(0);
    expect(doc.device_trust_vectors.length).toBeGreaterThan(0);
  });

  for (const vector of doc.cross_signing_vectors) {
    test(`cross_signing[${vector.name}] TS crossSigningBindingInput matches SDK golden byte-for-byte`, () => {
      const payload = vector.publish_payload;
      const selfSigning = crossSigningBindingInput({
        principalId: payload.principal_id,
        trustDomain: payload.trust_domain,
        subordinateKind: "self_signing",
        subordinateKid: payload.self_signing_key.kid,
        subordinateAlg: payload.self_signing_key.alg,
        subordinatePublicKey: payload.self_signing_key.public_key,
        generation: payload.generation,
      }).toString("base64");
      const userSigning = crossSigningBindingInput({
        principalId: payload.principal_id,
        trustDomain: payload.trust_domain,
        subordinateKind: "user_signing",
        subordinateKid: payload.user_signing_key.kid,
        subordinateAlg: payload.user_signing_key.alg,
        subordinatePublicKey: payload.user_signing_key.public_key,
        generation: payload.generation,
      }).toString("base64");
      expect(selfSigning).toBe(vector.expected_self_signing_input_b64);
      expect(userSigning).toBe(vector.expected_user_signing_input_b64);
    });
  }

  for (const vector of doc.device_trust_vectors) {
    test(`device_trust[${vector.name}] TS deviceTrustBindingInput matches SDK golden byte-for-byte`, () => {
      const produced = deviceTrustBindingInput({
        principalId: vector.input.principal_id,
        deviceId: vector.input.device_id,
        devicePublicKey: vector.input.device_public_key,
        hpkeKey: vector.input.hpke_key,
        algorithms: vector.input.algorithms,
        sskGeneration: vector.input.ssk_generation,
      }).toString("base64");
      expect(produced).toBe(vector.expected_input_b64);
    });
  }
});
