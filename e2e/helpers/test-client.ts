// One journey, two clients.
//
// A joint test says what a user does; it should not say *which product* does
// it. `TestClient` is that separation: the journey calls `createUser` and
// `syncAccount`, and `--client-kind` decides whether those run through Inkson
// in a browser or through Garth's own runtime.
//
// The point is not code reuse. It is that "Garth can do this" and "Inkson can
// do this" become the same assertion evaluated twice, so a capability Inkson
// has and Garth does not shows up as a failing parity run instead of as an
// absence nobody measures. Today that absence is most of Garth's client
// surface — see
// `arkret-work/tasks/impl-active/2026-09-07-0600-garth-as-the-complete-client-inkson-as-a-shell.md`.
//
// **What belongs in this interface.** Only operations both clients genuinely
// execute *through their own runtime*. Founding a principal is shared
// infrastructure — the canonical chain in `cotest-test-support::provisioning`,
// which both sides call — so `createUser` is honest for both. `syncAccount` is
// not shared: Inkson syncs through its own client, Garth through
// `ArkretClient`. An operation only one side can do does not go here with a
// stub on the other; it stays out until both can, and the parity spec is what
// makes that visible.

import type { Browser } from "./arkret-test";

export type ClientKind = "inkson" | "garth";

/** A principal a `TestClient` provisioned and now holds a session for. */
export type TestUser = {
  /** The label the caller asked for, for diagnostics. */
  label: string;
  /** Projected `ak:did_core:` principal id. */
  principalId: string;
  /** The device this client authenticates as. */
  deviceId: string;
  /** The Station that bound the principal. */
  stationId: string;
};

/** What one account-sync round did, as the client reports it. */
export type SyncOutcome = {
  /** Whether the client ended up holding a durable cursor for the account. */
  hasCursor: boolean;
  /** The cursor, when the client exposes it. Inkson does not. */
  cursor?: string;
  /** Client-specific detail, for failure messages only — never asserted on. */
  detail: string;
};

/**
 * A client under test.
 *
 * Implementations differ in how they do each step and in how they decide it
 * succeeded — that difference is the subject, not an inconvenience. What is
 * shared is the sequence.
 */
export interface TestClient {
  readonly kind: ClientKind;
  /** Provision a principal and hold a session for it. */
  createUser(label: string): Promise<TestUser>;
  /** Sync the account through this client's own runtime. */
  syncAccount(user: TestUser): Promise<SyncOutcome>;
  /**
   * What this client reports after a restart.
   *
   * A client that cannot survive one is not a client a host can build on, so
   * this is part of the interface rather than a Garth-specific extra.
   */
  cursorAfterRestart(user: TestUser): Promise<string | undefined>;
  dispose(): Promise<void>;
}

/** What a client needs from the run to reach the deployment. */
export type TestClientDeps = {
  /** Required by `inkson`; unused by `garth`. */
  browser?: Browser;
};

/**
 * The kind this run selects.
 *
 * `COTEST_CLIENT_KIND` is exported by `run-joint-e2e.ps1 -ClientKind`. It fails
 * closed on an unknown value rather than defaulting: a typo that silently ran
 * the other client would make a parity result meaningless.
 */
export function selectedClientKind(): ClientKind {
  const raw = (process.env.COTEST_CLIENT_KIND ?? "inkson").trim().toLowerCase();
  if (raw === "inkson" || raw === "garth") return raw;
  throw new Error(
    `COTEST_CLIENT_KIND must be "inkson" or "garth"; got ${JSON.stringify(raw)}`,
  );
}
