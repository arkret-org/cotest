// WebVH DID key rotation
// Contract: e2e/scenarios/identity/webvh-rotation.md
// Spec refs:
//   - identity/identity-did.md §3.4 (entry hash chain), §4.1-§4.2.1 (resolver, degraded_no_witness)
//   - §6 (historical events verified by historical keys), §7-§8.2 (rotation, threshold governance)

import { test } from "@playwright/test";

test.describe.configure({ mode: "serial" });

test.describe("WebVH DID key rotation", () => {
  test.fixme(
    "alice rotates her did:webvh controlling key; new entry signed by old update key + witness; resolver returns updated verificationMethod",
    async () => {
      // spec: identity-did.md §3.4 + §7
      // soland gap: did:webvh resolver implementation, witness service integration.
    },
  );

  test.fixme(
    "alice's pre-rotation events still verify under old key; post-rotation events verify under new key (spec §6 rule 5)",
    async () => {
      // spec: identity-did.md §6
    },
  );

  test.fixme(
    "did.jsonl history chain grows by exactly one entry; entry hash chain links correctly",
    async () => {
      // spec: identity-did.md §3.4 line 165
    },
  );

  test.fixme(
    "E9.1 tampered prev_entry_hash makes resolver fail closed (degraded_no_witness must NOT mask integrity break)",
    async () => {
      // spec: identity-did.md §4.2.1 line 286
    },
  );

  test.fixme(
    "E9.2 hosting domain serves a DID Doc with mismatched SCID; resolver rejects (DNS hijack protection)",
    async () => {
      // spec: identity-did.md §3 line 76
    },
  );

  test.fixme(
    "E9.3 organization rotation requires N-of-M governance signatures; single-sig submission rejected",
    async () => {
      // spec: identity-did.md §8.2
    },
  );

  test.fixme(
    "E9.4 witness offline > 24h causes resolver to enter unresolvable state; new events rejected until witness recovers",
    async () => {
      // spec: identity-did.md §4.2.1 (24h degraded window)
    },
  );

  test.fixme(
    "E9.5 emergency rotation using recovery key (no prev-key signature path) succeeds",
    async () => {
      // spec: key-management.md §3.3 recovery key path
    },
  );
});
