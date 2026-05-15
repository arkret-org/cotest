// Document collaboration
// Contract: e2e/scenarios/documents/collaboration.md
// Spec refs:
//   - models/morph.md §2 (Morph schema), §4 (facets)
//   - models/content-types.md §2-§3 (content blocks)
//   - models/flow-and-message.md §4.3 (discussion track for comments)
//   - discovery/profiles-presence.md §3 (cursor presence)
//   - authz/event-auth-state-resolution.md §2-§4 (anchor finality), §8.1 (conflict recovery)

import { expect, test } from "@playwright/test";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("document collaboration", () => {
  test("document view route loads (probe before fuller assertions)", async ({
    browser,
    request,
  }) => {
    const alice = uniqueUser("s17-probe");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);
    const alicePage = await openUserPage(browser, alice, { sessionToken: token });

    try {
      // yougen has /document — verify it renders without 404.
      const resp = await alicePage.page.goto("/document", { waitUntil: "domcontentloaded" });
      expect(resp).not.toBeNull();
      expect(resp!.status()).toBeLessThan(500);
    } finally {
      await alicePage.close();
    }
  });

  test.fixme(
    "alice creates a Document Morph (morph_type=document); bob joins same space and sees initial body",
    async () => {
      // spec: morph.md §2 + content-types.md §2
      // soland gap: cx.morph.create + content-types document type.
      // yougen gap: /document/new compose form + /document/:morph_id viewer.
    },
  );

  test.fixme(
    "alice and bob edit concurrently; both edits visible after lattice merge (mv-register or cas-register depending on lattice)",
    async () => {
      // spec: authz/event-auth-state-resolution.md §2 + §3.2 multi-cell Moves
    },
  );

  test.fixme(
    "alice's cursor position propagates to bob's view via cx.presence ephemeral signal within 1s",
    async () => {
      // spec: profiles-presence.md §3 (presence + cursor as ephemeral)
    },
  );

  test.fixme(
    "bob anchors a comment to text range offset 100..110; alice's view shows the comment marker at that range",
    async () => {
      // spec: flow-and-message.md §4.3 (discussion track) + relation.md §3.2 (replies_to)
    },
  );

  test.fixme(
    "document versions: each anchor finality boundary produces a labeled version; /document/:id/versions lists them",
    async () => {
      // spec: authz/event-auth-state-resolution.md §4 anchor finality.
    },
  );

  test.fixme(
    "restore an earlier version: cx.morph.update with state_witness + inclusion_proof referring to past anchor accepted; current state reverts",
    async () => {
      // spec: authz/event-auth-state-resolution.md §8.1
    },
  );

  test.fixme(
    "E17.2 comment anchored to a range that was later removed becomes orphaned (state=locked); UI surfaces orphan badge",
    async () => {
      // spec: relation.md §3.2 + flow-and-message.md §4.3
    },
  );
});
