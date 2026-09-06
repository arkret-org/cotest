// TypeScript client for `cotest-provision`, the Rust provisioning bridge.
//
// The canonical registration chain — Coauth account, OAuth authorization, gate
// handoff, PCR founding — exists once, in Rust
// (`cotest/crates/test-support/src/provisioning/`). This module is how the
// Playwright suite calls it, so the two sides cannot drift on what founding a
// principal means.
//
// **Placement**: 1725's P2 asks for this to live in a private
// `e2e/packages/test-support` package. It is here for now because the API is a
// handful of calls and a lifecycle; move it once the surface is settled enough
// that a package boundary buys something. What must not change in the move is
// the ownership below.
//
// **One bridge per worker, not per call.** The bridge holds the cookie jar
// carrying Coauth's authenticated account session, and the gate handoff
// authorizes against it. Restarting it between steps loses the session. It also
// holds the founding device key and the handoff grant, which deliberately never
// cross this boundary: a caller that could read the grant could present it.

import { spawn, type ChildProcessByStdio } from "node:child_process";
import type { Readable, Writable } from "node:stream";
import { createInterface, type Interface } from "node:readline";

import { requiredEnv } from "./env";

/// How long a single bridge call may take before the caller is told it failed.
///
/// The chain's slowest leg is the mock-email poll, which the Rust side bounds
/// at 30s. Anything past a minute is a hang, not a slow deployment.
const CALL_TIMEOUT_MS = 60_000;

type BridgeResponse =
  | { id: string; ok: true; result: Record<string, unknown> }
  | { id: string; ok: false; error: string };

export type DeploymentEndpoints = {
  coauthBaseUrl: string;
  solandBaseUrl: string;
  mockEmailBaseUrl?: string;
};

export type StationFacts = {
  trustDomain: string;
  serviceId: string;
};

/// The closed `AccountId`: a principal is only addressable together with the
/// Station that holds it.
export type AccountId = {
  principal_id: string;
  station_id: string;
};

/// The initial DPoP-bound session grant, as the register step issued it.
export type SessionGrant = {
  sessionGrant: string;
  sessionGrantId: string;
  audienceId: string;
  deviceId?: string;
  grantedScope: string[];
  expiresAt: string;
};

/**
 * A principal the canonical chain founded.
 *
 * Named fields rather than the raw register response: the Rust side parses that
 * into the SDK's own `AccountRegisterOutcome`, and re-deriving the same paths
 * here would be a second reader of the same shape, free to drift from it.
 *
 * What is deliberately absent is key material. The founding device key, the
 * handoff grant and the Event signer's seed all stay in the bridge process;
 * `eventVerificationMethod` is the public name of the last one, and acting *as*
 * this principal means asking the bridge to, not holding its keys.
 */
export type FoundedPrincipal = {
  principalId: string;
  did: string;
  deviceId: string;
  accountId: AccountId;
  eventVerificationMethod: string;
  recoveryKey: string;
  grant: SessionGrant;
  bindingReceipt: Record<string, unknown>;
  pcrGenesisReceipt: Record<string, unknown>;
};

function endpointsWire(endpoints: DeploymentEndpoints) {
  return {
    coauth_base_url: endpoints.coauthBaseUrl,
    soland_base_url: endpoints.solandBaseUrl,
    mock_email_base_url: endpoints.mockEmailBaseUrl ?? null,
  };
}

// stderr is inherited so the bridge's diagnostics land in the run log rather
// than in a buffer nobody reads; that is why the third stream is `null` here.
type BridgeProcess = ChildProcessByStdio<Writable, Readable, null>;

/**
 * A running bridge process, owned by whoever created it.
 *
 * Create one per Playwright worker and `dispose()` it in worker teardown. The
 * class deliberately has no global instance: two callers sharing one bridge
 * would share one Coauth account session, and the second caller's handoff would
 * authorize as the first caller's account.
 */
export class ProvisioningBridge {
  #child: BridgeProcess;
  #lines: Interface;
  #pending = new Map<
    string,
    { resolve: (value: Record<string, unknown>) => void; reject: (error: Error) => void }
  >();
  #nextId = 1;
  #exited?: Error;

  private constructor(child: BridgeProcess) {
    this.#child = child;
    this.#lines = createInterface({ input: child.stdout });
    this.#lines.on("line", (line) => this.#onLine(line));
    // A bridge that dies takes every in-flight call with it. Without this the
    // callers would sit until their own timeout and report the wrong thing.
    child.on("exit", (code, signal) => {
      this.#exited = new Error(
        `cotest-provision exited (code=${code ?? "null"}, signal=${signal ?? "null"})`,
      );
      for (const [, waiter] of this.#pending) waiter.reject(this.#exited);
      this.#pending.clear();
    });
  }

  static start(): ProvisioningBridge {
    // The runner builds the binary and exports its path; `cargo run` here would
    // contend on the build-directory lock while holding a session open.
    const binary = requiredEnv("COTEST_PROVISION_BIN");
    const child = spawn(binary, [], {
      stdio: ["pipe", "pipe", "inherit"],
      env: process.env,
    });
    return new ProvisioningBridge(child);
  }

  #onLine(line: string) {
    if (!line.trim()) return;
    let response: BridgeResponse;
    try {
      response = JSON.parse(line) as BridgeResponse;
    } catch (error) {
      // Unparseable output means the protocol is broken, not that one call
      // failed; fail everyone rather than leave them waiting.
      const failure = new Error(
        `cotest-provision emitted a non-JSON line: ${line} (${String(error)})`,
      );
      for (const [, waiter] of this.#pending) waiter.reject(failure);
      this.#pending.clear();
      return;
    }
    const waiter = this.#pending.get(response.id);
    if (!waiter) return;
    this.#pending.delete(response.id);
    if (response.ok) waiter.resolve(response.result);
    else waiter.reject(new Error(response.error));
  }

  async #call(op: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
    if (this.#exited) throw this.#exited;
    const id = String(this.#nextId++);
    const request = JSON.stringify({ id, op, ...body });
    const settled = new Promise<Record<string, unknown>>((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
    });
    this.#child.stdin.write(`${request}\n`);

    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error(`cotest-provision ${op} did not answer within ${CALL_TIMEOUT_MS}ms`));
      }, CALL_TIMEOUT_MS);
    });
    try {
      return await Promise.race([settled, timeout]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  async describeStation(endpoints: DeploymentEndpoints): Promise<StationFacts> {
    const result = await this.#call("describe_station", endpointsWire(endpoints));
    return {
      trustDomain: String(result.trust_domain),
      serviceId: String(result.service_id),
    };
  }

  /** Register an account through Coauth's product API and authenticate it. */
  async provisionUnboundAccount(
    endpoints: DeploymentEndpoints,
    account: { handle: string; password: string; email?: string; displayName?: string },
  ): Promise<void> {
    await this.#call("provision_unbound_account", {
      endpoints: endpointsWire(endpoints),
      account: {
        handle: account.handle,
        password: account.password,
        email: account.email ?? null,
        display_name: account.displayName ?? null,
      },
    });
  }

  /**
   * Exchange an authorization for a handoff.
   *
   * Returns only the handoff id: the grant and the founding device key stay in
   * the bridge process, and `foundPrincipal` refers back to them by that id.
   */
  async createAccountHandoff(args: {
    coauthBaseUrl: string;
    clientId: string;
    audienceId: string;
    deviceLabel: string;
  }): Promise<{ handoffId: string; binding: Record<string, unknown> }> {
    const result = await this.#call("create_account_handoff", {
      coauth_base_url: args.coauthBaseUrl,
      client_id: args.clientId,
      audience_id: args.audienceId,
      device_label: args.deviceLabel,
    });
    return {
      handoffId: String(result.handoff_id),
      binding: (result.binding ?? {}) as Record<string, unknown>,
    };
  }

  async foundPrincipal(args: {
    handoffId: string;
    endpoints: DeploymentEndpoints;
    trustDomain: string;
    audienceId: string;
    deviceId: string;
    displayName: string;
  }): Promise<FoundedPrincipal> {
    const result = await this.#call("found_principal", {
      handoff_id: args.handoffId,
      coauth_base_url: args.endpoints.coauthBaseUrl,
      soland_base_url: args.endpoints.solandBaseUrl,
      trust_domain: args.trustDomain,
      audience_id: args.audienceId,
      device_id: args.deviceId,
      display_name: args.displayName,
    });
    const grant = result.session_grant as Record<string, unknown>;
    return {
      principalId: String(result.principal_id),
      did: String(result.did),
      deviceId: String(result.device_id),
      accountId: result.account_id as AccountId,
      eventVerificationMethod: String(result.event_verification_method),
      recoveryKey: String(result.recovery_key),
      grant: {
        sessionGrant: String(grant.session_grant),
        sessionGrantId: String(grant.session_grant_id),
        audienceId: String(grant.audience_id),
        deviceId: grant.device_id === null ? undefined : String(grant.device_id),
        grantedScope: (grant.granted_scope ?? []) as string[],
        expiresAt: String(grant.expires_at),
      },
      bindingReceipt: (result.binding_receipt ?? {}) as Record<string, unknown>,
      pcrGenesisReceipt: (result.pcr_genesis_receipt ?? {}) as Record<string, unknown>,
    };
  }

  /**
   * Read a founded principal's own account, as the Station sees it.
   *
   * Referred to by handoff id because both halves of the authorization stay in
   * the bridge: the grant and the device key whose proof the Station checks
   * against it. The endpoint and its operation id are chosen on the Rust side —
   * a caller that passed its own URL would be carrying protocol knowledge on
   * this side of the boundary, which is the thing one implementation of the
   * chain is meant to prevent.
   *
   * Returns the status rather than throwing on a rejection, so a test can
   * assert that the Station refuses what it should refuse.
   */
  async readSelfAccountViewer(args: {
    handoffId: string;
    solandBaseUrl: string;
  }): Promise<{ status: number; body: Record<string, unknown> }> {
    const result = await this.#call("read_self_account_viewer", {
      handoff_id: args.handoffId,
      soland_base_url: args.solandBaseUrl,
    });
    return {
      status: Number(result.status),
      body: (result.body ?? {}) as Record<string, unknown>,
    };
  }

  /** Close stdin and let the bridge exit; safe to call twice. */
  async dispose(): Promise<void> {
    if (this.#child.exitCode !== null || this.#child.signalCode !== null) return;
    this.#child.stdin.end();
    this.#lines.close();
    await new Promise<void>((resolve) => {
      this.#child.once("exit", () => resolve());
      // A bridge that will not exit on closed stdin is a bug, but a test run
      // must not hang on it.
      setTimeout(() => {
        this.#child.kill();
        resolve();
      }, 5_000);
    });
  }
}
