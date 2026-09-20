import { expect, test } from "../../helpers/arkret-test";
import {
  accountHandoffHeaders,
  registerCoauthPasswordAccount,
} from "../../helpers/coauth-register";
import { coauthBaseUrl } from "../../helpers/env";

test.describe("identity-scope boot safety", () => {
  test("legacy anonymous account state fails closed without a WASM panic", async ({
    page,
  }) => {
    const failures: string[] = [];
    page.on("pageerror", (error) => failures.push(`pageerror:${error.message}`));
    page.on("console", (message) => {
      if (message.type() === "error") {
        failures.push(`console:${message.text()}`);
      }
    });
    await page.addInitScript(() => {
      const deviceId =
        "ak:device:019f0000-0000-7000-8000-000000000001";
      localStorage.setItem(
        "inkson.config.v1",
        JSON.stringify({
          server_url: "https://local.host",
          stations: ["https://local.host"],
          account_did: "anonymous",
          device_id: deviceId,
          session_credential: "legacy-incomplete-session",
        }),
      );
      localStorage.setItem(
        "inkson.local_state.v1",
        JSON.stringify({
          active_did: "anonymous",
          device_prefs: { values: {} },
          pending_login: null,
          known_dids: ["anonymous"],
        }),
      );
    });

    await page.goto("/login", { waitUntil: "domcontentloaded" });
    await expect(page.getByTestId("login-panel")).toBeVisible({
      timeout: 60_000,
    });
    await page.waitForTimeout(1_000);

    expect(
      failures.filter((failure) =>
        /identity-owned key|RuntimeError: unreachable|wasm-bindgen.*not marked as `catch`/i.test(
          failure,
        ),
      ),
    ).toEqual([]);
  });
});

test.describe("first registration PCR genesis @fully-implemented", () => {
  test("the creating device is accepted without a second approver", async ({
    request,
  }) => {
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "joint Coauth endpoint is unavailable");

    const account = await registerCoauthPasswordAccount(request, coauth!);
    const checkpoint = account.principalRegistrationCheckpoint;
    const unit = checkpoint.pcr_genesis_unit as Record<string, unknown>;
    expect(unit).toBeTruthy();
    const events = unit.events as Array<Record<string, unknown>>;
    expect(events).toHaveLength(2);
    expect(events.map((event) => event.kind)).toEqual([
      "ak.realm.create",
      "ak.device.authorize",
    ]);
    expect(account.pcrGenesisCommits).toHaveLength(2);
    expect(account.initialGrant.eventSigningKey?.publicJwk.x).toBeTruthy();
  });

  test("a register-consumed handoff can still read the terminal onboarding state", async ({
    request,
  }) => {
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "joint Coauth endpoint is unavailable");

    const account = await registerCoauthPasswordAccount(request, coauth!);
    const url = `${coauth}/_arkret/gate/account/onboarding`;
    const response = await request.get(url, {
      headers: accountHandoffHeaders({
        deviceKey: account.initialHolderKey,
        accountHandoffGrant: account.accountHandoffGrant,
        method: "GET",
        url,
      }),
    });
    const raw = await response.text();
    expect(response.status(), raw).toBe(200);
    const snapshot = JSON.parse(raw) as {
      handoff_request_id?: string;
      binding?: { state?: string; principal_id?: string };
    };
    expect(snapshot.binding?.state).toBe("bound");
    expect(snapshot.binding?.principal_id).toBe(account.id);
  });
});
