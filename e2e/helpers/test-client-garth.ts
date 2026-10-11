// `TestClient` backed by Garth's own client runtime.
//
// Everything here goes through `cotest-provision`, which holds the founded
// principal's grant and device key and builds an `ArkretClient` over
// `NativeExecutor` and the durable `FileStore` in the same process. The
// distinction that matters: `createUser` uses the shared canonical chain
// (Garth's builders), while `syncAccount` runs Garth's subscription engine.
// Writes use the durable outbound engine, reads authenticate the Realm history,
// and restart reconstructs the complete runtime over the original durable store.

import { newDeviceId } from "./ids";
import { ProvisioningBridge, type DeploymentEndpoints } from "./provisioning-bridge";
import type { ClientKind, SyncOutcome, WritingTestClient, TestRealm, TestUser } from "./test-client";

export class GarthTestClient implements WritingTestClient {
  readonly kind: ClientKind = "garth";

  #bridge: ProvisioningBridge;
  #endpoints: DeploymentEndpoints;
  #oidcClientId: string;
  #stationId?: string;
  #trustDomain?: string;
  /** Handoff id per user label: the bridge's handle on that principal. */
  #handoffs = new Map<string, { handoffId: string; user: TestUser; identitySnapshotPath: string; storeRoot: string }>();

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
    if (this.#handoffs.has(label)) throw new Error(`Garth user label already provisioned: ${label}`);
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
    const opened = await this.#bridge.openGarthClient({
      handoffId: handoff.handoffId,
      colandBaseUrl: this.#endpoints.colandBaseUrl,
      accountId: founded.accountId,
      deviceId: founded.deviceId,
    });
    const user: TestUser = {
      label,
      principalId: founded.accountId.principal_id,
      deviceId: founded.deviceId,
      stationId: founded.accountId.station_id,
    };
    this.#handoffs.set(label, { handoffId: handoff.handoffId, user: { ...user },
      identitySnapshotPath: opened.identitySnapshotPath, storeRoot: opened.storeRoot });
    return user;
  }

  #handoffFor(user: TestUser): string {
    const retained = this.#handoffs.get(user.label);
    if (!retained) {
      throw new Error(`no Garth client for ${user.label}; createUser first`);
    }
    if (user.principalId !== retained.user.principalId || user.stationId !== retained.user.stationId ||
        user.deviceId !== retained.user.deviceId) {
      throw new Error(`Garth user identity does not match its canonical provisioned source: ${user.label}`);
    }
    return retained.handoffId;
  }

  async syncAccount(user: TestUser, realm?: TestRealm): Promise<SyncOutcome> {
    const outcome = await this.#bridge.garthSyncAccount({
      handoffId: this.#handoffFor(user),
      realmId: realm?.realmId,
    });
    return {
      hasCursor: Boolean(outcome.cursor),
      cursor: outcome.cursor ?? undefined,
      eventIds: outcome.eventIds,
      detail: `garth rounds=${outcome.rounds} stop=${outcome.stopReason}`,
    };
  }

  async cursorAfterRestart(user: TestUser, realm?: TestRealm): Promise<string | undefined> {
    const outcome = await this.#bridge.garthCursorAfterRestart({
      handoffId: this.#handoffFor(user),
      realmId: realm?.realmId,
    });
    if (!outcome.identityRestoredFromDisk) throw new Error("Garth restart did not restore the durable accepted identity");
    return outcome.cursor ?? undefined;
  }

  /** Run-owned custody coordinates for failure probes; no key material crosses the bridge. */
  custodyPaths(user: TestUser): { identitySnapshotPath: string; storeRoot: string } {
    this.#handoffFor(user);
    const retained = this.#handoffs.get(user.label)!;
    return { identitySnapshotPath: retained.identitySnapshotPath, storeRoot: retained.storeRoot };
  }

  async createRealm(owner: TestUser, member: TestUser, title: string): Promise<TestRealm> {
    const realm = await this.#bridge.garthCreateRealm({ handoffId: this.#handoffFor(owner), title });
    await this.#bridge.garthJoinRealm({ handoffId: this.#handoffFor(member), realmId: realm.realmId });
    await this.#bridge.garthGrantMessages({ handoffId: this.#handoffFor(owner), realmId: realm.realmId,
      genesisEventId: realm.genesisEventId,
      subjectAccountId: { principal_id: member.principalId, station_id: member.stationId } });
    return realm;
  }

  async sendMessage(user: TestUser, realm: TestRealm, body: string): Promise<{ eventId: string; commitId: string }> {
    return this.#bridge.garthSendMessage({ handoffId: this.#handoffFor(user), realmId: realm.realmId,
      strandId: realm.strandId, body });
  }

  async readMessages(user: TestUser, realm: TestRealm): Promise<Array<Record<string, any>>> {
    return this.#bridge.garthReadMessages({ handoffId: this.#handoffFor(user), realmId: realm.realmId });
  }

  async retainedMessage(user: TestUser, eventId: string): Promise<Record<string, any>> {
    return this.#bridge.garthRetainedMessage({ handoffId: this.#handoffFor(user), eventId });
  }

  async dispose(): Promise<void> {
    await this.#bridge.dispose();
  }
}
