// Consent grant flow
// Contract: e2e/scenarios/identity/consent-grant.md
// Spec: identity/consent-model.md §2-§4

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("consent grant", () => {
  test.fixme(
    "alice grants consent and bob can establish contact (full lifecycle)",
    async () => {
      /* spec: identity/consent-model.md §2-§4. soland gap: cx.consent.* reducer 未实现 */
    },
  );

  test.fixme(
    "E1.1 time-windowed consent expires after valid_until elapses",
    async () => {
      /* spec: identity/consent-model.md §2. soland gap: cx.consent.* reducer 未实现 */
    },
  );

  test.fixme("E1.2 revoke then re-grant lifecycle", async () => {
    /* spec: identity/consent-model.md §3. soland gap: cx.consent.* reducer 未实现 */
  });

  test.fixme(
    "E1.3 scope-granularity: invite-scope consent does not allow call",
    async () => {
      /* spec: identity/consent-model.md §2. soland gap: cx.consent.* reducer 未实现 */
    },
  );

  test.fixme(
    "E1.4 pairwise DID consent isolates contact channels",
    async () => {
      /* spec: identity/consent-model.md §4. soland gap: cx.consent.* reducer 未实现 */
    },
  );
});
