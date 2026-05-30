// Third-party invite (email → token commitment → binding proof → claim)
// Contract: e2e/scenarios/invites/third-party.md
// Spec: sync/third-party-invites.md §3-§4

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("third-party invite", () => {
  test("third-party invite endpoint surface probe", async ({ request }) => {
    const alice = uniqueUser("s3-probe");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);

    // Unauthenticated POST must not succeed. 405 (path routed but method
    // not allowed) is acceptable too — treated as "endpoint absent" for
    // the probe.
    const probe = await request.post(`${solandBaseUrl()}/api/v1/invites/third-party`, {
      data: { space_id: "cx:space:probe", token_commitment: "sha256:0".repeat(64) },
    });
    expect([401, 403, 404, 405]).toContain(probe.status());

    // With auth: either implemented or absent. 5xx is a bug.
    const authProbe = await request.post(`${solandBaseUrl()}/api/v1/invites/third-party`, {
      headers: { authorization: `Bearer ${token}` },
      data: { space_id: "cx:space:probe", token_commitment: "sha256:0".repeat(64) },
    });
    expect(authProbe.status()).toBeLessThan(500);
  });

  test.fixme(
    // @blocking-on: soland#invites-third-party-gap
    // @user-promise: e2e/scenarios/invites/third-party.md
    // @expected-live-by: 2026Q3
    "alice issues cx.invite.third_party with token_commitment; plaintext email never leaves client",
    async () => {
      // spec: third-party-invites.md §3.1
    },
  );

  test.fixme(
    // @blocking-on: soland#invites-third-party-gap
    // @user-promise: e2e/scenarios/invites/third-party.md
    // @expected-live-by: 2026Q3
    "mock verification service receives invite token via email; bob registers DID; verification service signs binding_proof",
    async () => {
      // soland gap + harness gap: mock email service.
    },
  );

  test.fixme(
    // @blocking-on: soland#invites-third-party-gap
    // @user-promise: e2e/scenarios/invites/third-party.md
    // @expected-live-by: 2026Q3
    "bob submits cx.invite.claim with binding_proof + subject_proof; reducer accepts and converts to cx.invite.create + accept",
    async () => {
      // spec: third-party-invites.md §4
    },
  );

  test.fixme(
    // @blocking-on: soland#invites-third-party-gap
    // @user-promise: e2e/scenarios/invites/third-party.md
    // @expected-live-by: 2026Q3
    "E3.1 expired token: reducer rejects claim with invite_expired",
    async () => {},
  );

  test.fixme(
    // @blocking-on: soland#invites-third-party-gap
    // @user-promise: e2e/scenarios/invites/third-party.md
    // @expected-live-by: 2026Q3
    "E3.2 wrong DID claim (subject_proof != binding_proof.subject) rejected with binding_mismatch",
    async () => {},
  );

  test.fixme(
    // @blocking-on: soland#invites-third-party-gap
    // @user-promise: e2e/scenarios/invites/third-party.md
    // @expected-live-by: 2026Q3
    "E3.3 double-claim: second claim of same token rejected (token consumed)",
    async () => {},
  );
});
