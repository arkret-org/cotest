// Discussion track upgrade to independent child Space
// Contract: e2e/scenarios/messaging/discussion-upgrade.md
// Spec refs:
//   - models/flow-and-message.md §5, §5.1 (discussion_space_ref)
//   - models/space-hierarchy.md §3-§4 (parent/child confirmed edge)
//   - discovery/read-receipts.md §2.5 (scope override)

import { test } from "@playwright/test";

test.describe.configure({ mode: "serial" });

test.describe("discussion upgrade to child space", () => {
  test.fixme(
    "alice creates Flow F1 in S_parent; alice and bob exchange messages on F1's inline discussion track",
    async () => {
      // spec: flow-and-message.md §4.3 inline discussion track.
      // baseline: covered indirectly in S1.
    },
  );

  test.fixme(
    "alice promotes F1's discussion to a new child space S_discussion; F1.discussion_space_ref = S_discussion.id; parent/child edges confirmed",
    async () => {
      // spec: flow-and-message.md §5 + space-hierarchy.md §3-§4
      // yougen gap: "Promote discussion to separate space" button.
    },
  );

  test.fixme(
    "after promotion, new messages on F1 route to S_discussion, not S_parent; F1 comments view stitches pre+post messages from both spaces",
    async () => {
      // spec: flow-and-message.md §5.1
    },
  );

  test.fixme(
    "carol invited to S_discussion (not S_parent); carol sees only post-promotion messages; pre-promotion stays in S_parent and is invisible to carol",
    async () => {
      // spec: space-hierarchy.md §3.4 (no auto-cascade of membership)
    },
  );

  test.fixme(
    "S_discussion can be E2EE while S_parent stays plaintext; parent's MLS key cannot decrypt child (spec §9)",
    async () => {
      // spec: space-hierarchy.md cryptographic isolation.
    },
  );

  test.fixme(
    "E21.1 setting discussion_space_ref to a non-existent space rejects cx.flow.update with orphan_discussion_space_ref",
    async () => {},
  );

  test.fixme(
    "E21.F read-receipts policy override: S_discussion.disclosure=required overrides S_parent.disclosure=optional",
    async () => {
      // spec: read-receipts.md §2.5 scope_overrides_allowed
    },
  );
});
