// `TestClient` backed by Garth's own client runtime.
//
// Everything here goes through `cotest-provision`, which holds the founded
// principal's grant and device key and builds an `ArkretClient` over
// `NativeExecutor` and the durable `FileStore` in the same process. The
// distinction that matters: `createUser` uses the shared canonical chain
// (Garth's builders), while `syncAccount` runs Garth's subscription engine.
// Only the second one is a claim about Garth as a client, and the parity spec
// is written so a reader can tell which is which.

import { newDeviceId } from "./ids";
import { ProvisioningBridge, type DeploymentEndpoints } from "./provisioning-bridge";
import type { ClientKind, SyncOutcome, TestClient, TestUser } from "./test-client";

export class GarthTestClient implements TestClient {
  readonly kind: ClientKind = "garth";

  #bridge: ProvisioningBridge;
  #endpoints: DeploymentEndpoints;
  #oidcClientId: string;
  #stationId?: string;
  #trustDomain?: string;
  /** Handoff id per user label: the bridge's handle on that principal. */
  #handoffs = new Map<string, string>();

  constructor(args: {
    endpoints: DeploymentEndpoints;
    oidcClientId: string;
  }) {
    this.#bridge = ProvisioningBridge.start();
    this.#endpoints = args.endpoints;
    this.#oidcClientId = args.oidcClientId;
  }

  async #station(): Promise<{ serviceId: string; trustDomain: string }> {
    if (!this.#stationId || !this.#trustDomain) {
      const facts = await this.#bridge.describeStation(this.#endpoints);
      this.#stationId = facts.serviceId;
      this.#trustDomain = facts.trustDomain;
    }
    return { serviceId: this.#stationId, trustDomain: this.#trustDomain };
  }

  async createUser(label: string): Promise<TestUser> {
    const station = await this.#station();
    const handle = `${label}-${Date.now()}${Math.floor(Math.random() * 1000)}`
      .toLowerCase()
      .replace(/[^a-z0-9-]/g, "-");
    await this.#bridge.provisionUnboundAccount(this.#endpoints, {
      handle,
      password: "1amTester!",
    });
    const handoff = await this.#bridge.createAccountHandoff({
      coauthBaseUrl: this.#endpoints.coauthBaseUrl,
      clientId: this.#oidcClientId,
      audienceId: station.serviceId,
      deviceLabel: handle,
    });
    const deviceId = newDeviceId();
    const founded = await this.#bridge.foundPrincipal({
      handoffId: handoff.handoffId,
      endpoints: this.#endpoints,
      trustDomain: station.trustDomain,
      audienceId: station.serviceId,
      deviceId,
      displayName: `Garth client ${handle}`,
    });

    // From here on the principal is Garth's: the bridge builds an
    // `ArkretClient` bound to this grant and device key, and every later call
    // for this user runs through it.
    await this.#bridge.openGarthClient({
      handoffId: handoff.handoffId,
      colandBaseUrl: this.#endpoints.colandBaseUrl,
      accountId: founded.accountId,
      deviceId: founded.deviceId,
    });
    this.#handoffs.set(label, handoff.handoffId);

    return {
      label,
      principalId: founded.accountId.principal_id,
      deviceId: founded.deviceId,
      stationId: founded.accountId.station_id,
    };
  }

  #handoffFor(user: TestUser): string {
    const handoffId = this.#handoffs.get(user.label);
    if (!handoffId) {
      throw new Error(`no Garth client for ${user.label}; createUser first`);
    }
    return handoffId;
  }

  async syncAccount(user: TestUser): Promise<SyncOutcome> {
    const outcome = await this.#bridge.garthSyncAccount({
      handoffId: this.#handoffFor(user),
    });
    return {
      hasCursor: Boolean(outcome.cursor),
      cursor: outcome.cursor ?? undefined,
      detail: `garth rounds=${outcome.rounds} stop=${outcome.stopReason}`,
    };
  }

  async cursorAfterRestart(user: TestUser): Promise<string | undefined> {
    const outcome = await this.#bridge.garthCursorAfterRestart({
      handoffId: this.#handoffFor(user),
    });
    return outcome.cursor ?? undefined;
  }

  async dispose(): Promise<void> {
    await this.#bridge.dispose();
  }
}
