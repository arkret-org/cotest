// `TestClient` backed by Inkson, driven as a product.
//
// This one opens a browser on purpose. An "Inkson client" that reached the
// Station over the harness's own HTTP would be the harness wearing Inkson's
// name, and a parity run against it would compare Garth to a mirror. So
// `createUser` provisions through the shared canonical chain and then opens the
// product, and `syncAccount` is the product's own runtime reaching its
// authenticated shell.
//
// The asymmetry with `GarthTestClient` is the subject rather than a defect:
// Garth reports a cursor because a host can ask it to, and Inkson does not
// because its durable state lives in browser storage a test has no supported
// handle on. `capabilities.durableCursor` states that instead of letting the
// parity spec quietly assert nothing.

import { expect, type APIRequestContext, type Browser } from "./arkret-test";
import { openDpopUserPage, type DpopUserPageSession } from "./users";
import type { ClientKind, SyncOutcome, TestClient, TestUser } from "./test-client";

export class InksonTestClient implements TestClient {
  readonly kind: ClientKind = "inkson";
  readonly capabilities = { durableCursor: false };

  #browser: Browser;
  #request: APIRequestContext;
  #sessions = new Map<string, DpopUserPageSession>();

  constructor(args: { browser: Browser; request: APIRequestContext }) {
    this.#browser = args.browser;
    this.#request = args.request;
  }

  async createUser(label: string): Promise<TestUser> {
    const opened = await openDpopUserPage(this.#browser, this.#request, label);
    if (!opened) {
      throw new Error(
        `Inkson client could not open a session for ${label}; the run has no Coauth`,
      );
    }
    this.#sessions.set(label, opened);
    const accountId = opened.session.accountId;
    return {
      label,
      principalId: accountId.principal_id,
      deviceId: opened.session.user.deviceId,
      stationId: accountId.station_id,
    };
  }

  #sessionFor(user: TestUser): DpopUserPageSession {
    const session = this.#sessions.get(user.label);
    if (!session) {
      throw new Error(`no Inkson session for ${user.label}; createUser first`);
    }
    return session;
  }

  async syncAccount(user: TestUser): Promise<SyncOutcome> {
    // Inkson's client runtime decides it has synced by mounting the
    // authenticated shell. There is no cursor to read: the equivalent
    // assertion is that the product reached a state only a synced client
    // reaches.
    const session = this.#sessionFor(user);
    await session.page.gotoHome();
    await expect(session.page.page.getByTestId("client-shell")).toBeVisible({
      timeout: 60_000,
    });
    return {
      hasCursor: false,
      detail: "inkson reached its authenticated shell",
    };
  }

  async cursorAfterRestart(_user: TestUser): Promise<string | undefined> {
    // Not "no cursor" — no supported way for a test to read one. Reported as
    // absent so the parity spec can say which client this run could check.
    return undefined;
  }

  async dispose(): Promise<void> {
    await Promise.allSettled(
      [...this.#sessions.values()].map((session) => session.page.close()),
    );
    this.#sessions.clear();
  }
}
