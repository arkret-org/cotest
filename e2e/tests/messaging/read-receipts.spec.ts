// Read receipts + privacy toggle
// Contract: e2e/scenarios/messaging/read-receipts.md
// Spec refs:
//   - discovery/read-receipts.md §2.1-§2.5 (ephemeral format, debounce, policy)
//   - §3.1-§3.2 (actor-private read marker)

import { test } from "@playwright/test";

test.describe.configure({ mode: "serial" });

test.describe("read receipts + privacy", () => {
  test.fixme(
    "alice reads N messages while preference=send_read_receipts true; bob sees alice's receipt at the highest visible event within debounce window",
    async () => {
      // spec: read-receipts.md §2.2-§2.3
      // yougen gap: read-receipt avatar/timestamp rendering with stable testid.
    },
  );

  test.fixme(
    "alice toggles preference=false; subsequent reads do NOT emit cx.receipt.read; bob's view stops updating",
    async () => {
      // spec: read-receipts.md §2.4 + client-preferences.md
    },
  );

  test.fixme(
    "alice re-enables preference; new reads emit a single fresh cx.receipt.read; reads during the disabled window stay invisible",
    async () => {
      // spec: read-receipts.md §2.4 (no retroactive emission)
    },
  );

  test.fixme(
    "space disclosure=required locks the client toggle; even with preference=false, client sends receipts",
    async () => {
      // spec: read-receipts.md §2.5
    },
  );

  test.fixme(
    "space disclosure=disabled: client does not send; Sync Service silently drops any inbound cx.receipt.read for the space",
    async () => {
      // spec: read-receipts.md §2.5
    },
  );

  test.fixme(
    "actor-private read marker (cx.read.marker) syncs across alice's devices but does NOT broadcast to bob",
    async () => {
      // spec: read-receipts.md §3.1-§3.2
    },
  );

  test.fixme(
    "E22.1 high-frequency scroll: debounce window ≥1s; only a single receipt covering the highest visible event is emitted",
    async () => {
      // spec: read-receipts.md §2.3
    },
  );

  test.fixme(
    "E22.3 multi-device receipt coordination: HLC tie-break decides which device's marker fans out for shared receipt",
    async () => {
      // spec: read-receipts.md §3.2
    },
  );
});
