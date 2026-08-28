// OIDC login-chain regression guards (API level).
//
// These lock the *server-side* contracts that the real inkson→coauth→soland
// browser login depends on — the layers that broke (and were fixed) while
// bringing the login flow up end-to-end on 2026-06-16. The full browser
// ceremony (login form + consent) lives in oidc-login-flow.spec.ts; it is not
// CI-automatable yet (see that file's header), so the invariants it would have
// caught are pinned here at the HTTP layer instead, where they are stable.
//
// Coverage:
//   1. Discovery — `/_arkret/describe` advertises a usable OIDC method:
//      a non-empty `client_id` (else coauth answers "could not find client")
//      and an Account Authority pinned to the Auth Server origin (so the
//      session-grant POST + its DPoP `htu` line up with coauth, not soland).
//   2. Self-path auth — a session grant only authenticates a `/_arkret/root/*`
//      authenticated read when accompanied by a bound DPoP proof; a bare grant
//      (no DPoP) is rejected. This is the contract the inkson fix relied on
//      when it started attaching DPoP to `/_arkret/root/` calls (recovery-policy
//      had been going out as a naked bearer → 401 → spurious logout).
//
// Spec refs: sync/service-surface.md §2.5.1 (Account Authority discovery),
// sync/api-conventions.md §3.3 (session-grant + DPoP self-path), and
// arkret-rust-sdk service-describe.schema.json (auth_metadata shape).

import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import {
  coauthBaseUrl,
  coauthOidcClientId,
  solandBaseUrl,
  solandServiceId,
} from "../../helpers/env";
import { registerCoauthPasswordAccount } from "../../helpers/coauth-register";
import { ensureRegistered, issueDevSession, uniqueUser } from "../../helpers/users";
import {
  generateDpopDeviceKey,
  mintDpopBoundGrant,
  mintDpopProof,
  type DpopBoundGrant,
  type DpopDeviceKey,
} from "../../helpers/session-grant-dpop";

// A `/_arkret/root/*` authenticated read. recovery-policy is the exact endpoint
// whose naked-bearer 401 derailed login; it is principal-isolated and returns
// `{ active_policy: null }` for a fresh account, so a 200 here proves the
// inbound credential authenticated on a root path.
const RECOVERY_POLICY_PATH = "/_arkret/root/identity/recovery-policy";

function describeUrl(): string {
  return `${solandBaseUrl()}/_arkret/describe`;
}

function recoveryPolicyUrl(): string {
  return `${solandBaseUrl()}${RECOVERY_POLICY_PATH}`;
}

test.describe.configure({ mode: "serial" });

test.describe("OIDC login chain (server-side discovery + DPoP)", () => {
  test("1. /_arkret/describe advertises the OIDC client_id and Auth-Server Account Authority", async ({
    request,
  }) => {
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "coauth not started for this run (no OIDC method to advertise)");

    const response = await request.get(describeUrl());
    const raw = await response.text();
    expect(response.status(), `describe returned ${response.status()}: ${raw}`).toBe(200);
    const body = JSON.parse(raw);

    // `ServerDescribeOutcome` is `#[serde(transparent)]`, so `auth_metadata` is
    // a top-level field of the describe document.
    const authMetadata = body.auth_metadata;
    expect(authMetadata, `describe.auth_metadata missing: ${raw}`).toBeTruthy();

    // ── OIDC method with a usable client_id ────────────────────────────────
    const methods: Array<{
      method: string;
      client_id?: string;
      issuer?: string;
      grant_exchange?: { kind?: string };
    }> = authMetadata.methods ?? [];
    const oidc = methods.find((m) => m.method === "oidc");
    expect(
      oidc,
      `auth_metadata.methods has no oidc entry (an Auth Server is configured, so it must): ${JSON.stringify(methods)}`,
    ).toBeTruthy();
    // The web client sends this verbatim to coauth's /authorize; absent it,
    // coauth answers "could not find client" and login dead-ends.
    expect(
      oidc!.client_id,
      "oidc method must advertise a non-empty client_id (SOLAND_OAUTH_CLIENT_ID)",
    ).toBeTruthy();
    const expectedClientId = coauthOidcClientId();
    if (expectedClientId) {
      expect(oidc!.client_id).toBe(expectedClientId);
    }
    expect(oidc!.grant_exchange).toEqual({ kind: "account_handoff" });

    // ── Account Authority pinned to the Auth Server origin ─────────────────
    // The client POSTs session-grants to the Account Authority and DPoP-binds
    // the proof to its origin; that origin MUST be coauth, not soland, or the
    // grant POST 404s / the DPoP htu mismatches.
    const accountAuthority = authMetadata.account_authority;
    expect(accountAuthority, "auth_metadata.account_authority missing").toBeTruthy();
    const coauthOrigin = new URL(coauth!).origin;
    expect(new URL(accountAuthority.origin).origin).toBe(coauthOrigin);
    expect(accountAuthority.gate_account_base_url).toBe(`${coauthOrigin}/_arkret/gate/account`);

    // The advertised OIDC issuer is the Auth Server too (OIDC discovery target).
    expect(new URL(oidc!.issuer!).origin).toBe(coauthOrigin);
  });

  // ── Session-grant + DPoP on a root path ──────────────────────────────────
  //
  // Shared setup: register a user and mint a real DPoP-bound grant from coauth's
  // cotest debug seam. Dependent tests skip cleanly when the seam (debug build +
  // COAUTH_ENABLE_TEST_ENDPOINTS) is unavailable.
  async function setupGrant(
    request: APIRequestContext,
  ): Promise<{ deviceKey: DpopDeviceKey; grant: DpopBoundGrant; actorId: string } | undefined> {
    const coauth = coauthBaseUrl();
    if (!coauth) {
      return undefined;
    }
    const account = await registerCoauthPasswordAccount(request, coauth);
    const deviceKey = generateDpopDeviceKey();
    const grant = await mintDpopBoundGrant(
      request,
      coauth,
      account.id,
      account.genesisDeviceId,
      deviceKey,
      { audience: solandServiceId() },
    );
    if (!grant) {
      return undefined;
    }
    return { deviceKey, grant, actorId: account.id };
  }

  test("2. a session grant authenticates a /_arkret/root/* read only WITH a bound DPoP proof", async ({
    request,
  }) => {
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "coauth not started for this run");
    const ctx = await setupGrant(request);
    test.skip(
      !ctx,
      "coauth debug grant-mint seam unavailable (release build or COAUTH_ENABLE_TEST_ENDPOINTS unset)",
    );
    const { deviceKey, grant } = ctx!;
    const url = recoveryPolicyUrl();

    // Grant + matching DPoP → authenticated. A fresh account has no policy, so
    // the body is `{ active_policy: null }`.
    const dpop = mintDpopProof({ deviceKey, method: "GET", url, grantJwt: grant.grantJwt });
    const ok = await request.get(url, {
      headers: { authorization: `DPoP ${grant.grantJwt}`, dpop },
    });
    const okBody = await ok.text();
    expect(ok.status(), `root-path recovery-policy with grant+DPoP returned ${ok.status()}: ${okBody}`).toBe(
      200,
    );
    expect(JSON.parse(okBody)).toHaveProperty("active_policy");

    // Same grant as a bare Bearer (no DPoP) → rejected. This is the regression
    // the inkson root-path DPoP fix protects against: without the DPoP header
    // soland treats the grant as an opaque OAuth/dev bearer, fails to resolve
    // it, and returns 401 — which the client read as session-expired and logged
    // the user out mid-login.
    const naked = await request.get(url, {
      headers: { authorization: `Bearer ${grant.grantJwt}` },
    });
    expect([401, 403], `bare grant (no DPoP) on root path: ${naked.status()}`).toContain(
      naked.status(),
    );
  });

  test("3. a dev-login bearer still authenticates the /_arkret/root/* read (no regression)", async ({
    request,
  }) => {
    // The dev bearer (no DPoP) must keep working on root paths so the
    // tri-modal inbound contract did not regress the dev path.
    const alice = uniqueUser("oidc-chain-devbearer");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);

    const response = await request.get(recoveryPolicyUrl(), {
      headers: { authorization: `Bearer ${token}` },
    });
    const body = await response.text();
    expect(response.status(), `dev-bearer recovery-policy returned ${response.status()}: ${body}`).toBe(
      200,
    );
    expect(JSON.parse(body)).toHaveProperty("active_policy");
  });
});
