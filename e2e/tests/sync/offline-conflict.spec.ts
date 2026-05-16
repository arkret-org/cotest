// Offline edit / reconnect sync / conflict repair (bottom_cells)
// Contract: e2e/scenarios/sync/offline-conflict.md
// Spec: sync/client-sync.md §2, sync/operations-sync.md §2-§2.1, authz/event-auth-state-resolution.md §2, §8.1

import { test } from "@playwright/test";

test.describe.configure({ mode: "serial" });

test.describe("offline sync + conflict repair", () => {
  test.fixme(
    "bob composes a message while offline; on reconnect the message persists and is visible to alice",
    async () => {
      // spec: sync/client-sync.md §2 (outbox + reconnect flush)
      // yougen gap: no client-side outbox observed today; send on offline
      // returns failure with no retry queue. Spec contract is "compose
      // during partition + auto-flush on reconnect"; until yougen ships
      // an outbox + status indicator, this stays fixme.
    },
  );

  test.fixme(
    "during offline window alice writes; on bob's reconnect both writes are visible with deterministic ordering",
    async () => {
      // spec: sync/operations-sync.md §2
    },
  );

  test.fixme(
    "concurrent writes to the same cas-register cell trigger bottom_expose; bottom-cells-banner shows the conflict",
    async () => {
      // spec: sync/operations-sync.md §2.1 + authz/event-auth-state-resolution.md §2
    },
  );

  test.fixme(
    "bob clicks prefer-safer-side-button to repair; reducer accepts repair Move with state_witness + inclusion_proof; banner clears",
    async () => {
      // spec: authz/event-auth-state-resolution.md §8.1
    },
  );

  test.fixme(
    "long offline → on reconnect, pull-operations backfills missing events; bob's timeline catches up to head",
    async () => {
      // spec: sync/federation.md §4.2 (single-server uses same pull endpoint)
    },
  );
});
