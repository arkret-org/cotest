// Playwright fixtures over the Rust provisioning bridge.
//
// `provisioning-bridge.ts` is the transport; this is how a spec gets one
// without managing its lifetime. The split matters because the two have
// different owners: the bridge process belongs to the worker that started it,
// while the deployment it talks to belongs to the runner.
//
// **Ownership.** The worker owns its bridge and disposes it in teardown. It
// does not own Coauth, Soland or the mocks: the runner starts those, and a
// worker that stopped one would take the rest of the run with it. That is why
// `AttachedDeployment` has no teardown and no `close()` — there is nothing here
// that a test is allowed to shut down.
//
// **One bridge per worker, not per test.** Starting one costs a process spawn,
// but the reason is not cost: the bridge holds the Coauth account session, and
// `provisionPrincipal` below relies on the handoff authorizing against the
// account the same bridge just registered.

import { test as base } from "./arkret-test";
import {
  coauthBaseUrl,
  coauthOidcClientId,
  mockEmailBaseUrl,
  solandBaseUrl,
} from "./env";
import { newDeviceId } from "./ids";
import {
  ProvisioningBridge,
  type DeploymentEndpoints,
  type FoundedPrincipal,
  type StationFacts,
} from "./provisioning-bridge";

/**
 * The deployment this run is pointed at.
 *
 * Attached, never owned. The `ownership` tag is here so a future owned
 * deployment — a spec that starts its own Station — has to say so rather than
 * inheriting cleanup behaviour by accident.
 */
export type AttachedDeployment = DeploymentEndpoints & {
  readonly ownership: "attached";
  readonly oidcClientId: string;
};

export type ProvisionedPrincipal = FoundedPrincipal & {
  /** The Coauth handle the account was registered under. */
  handle: string;
  deviceId: string;
  /**
   * The handoff this principal was founded through.
   *
   * It is the bridge's handle on the grant and the device key, neither of which
   * crosses the boundary, so anything that needs to act *as* this principal
   * goes through the bridge with this id rather than with credentials.
   */
  handoffId: string;
  /** The closed `AccountId` the Station bound, principal and Station both. */
  accountId: { principal_id: string; station_id: string };
  /** The `ak.session.grant` JWT the register step returned. */
  sessionGrant: string;
};

export type CanonicalProvisioning = {
  deployment: AttachedDeployment;
  station: StationFacts;
  bridge: ProvisioningBridge;
  /**
   * Register an account and found a principal on it, end to end.
   *
   * Sequential by construction: the bridge holds one Coauth session, so the
   * account registered by the most recent call is the one a handoff will
   * authorize as. Callers that want two principals ask twice and use the first
   * result before asking for the second.
   */
  provisionPrincipal(label: string): Promise<ProvisionedPrincipal>;
  /**
   * Present a founded principal's grant back to the Station.
   *
   * The one assertion the register response cannot make on its own: a chain
   * that produced a well-formed but unusable grant passes every check about its
   * receipts and fails here.
   */
  readSelfAccountViewer(
    principal: ProvisionedPrincipal,
  ): Promise<{ status: number; body: Record<string, unknown> }>;
};

/**
 * Holds the worker's bridge without starting it.
 *
 * Playwright resolves worker fixtures before it knows whether the test will
 * skip, so starting the process eagerly would turn "this lane has no Coauth"
 * from a skip into a missing-binary error. Nothing is spawned until a test
 * actually asks.
 */
class WorkerProvisioning {
  #bridge?: ProvisioningBridge;

  bridge(): ProvisioningBridge {
    this.#bridge ??= ProvisioningBridge.start();
    return this.#bridge;
  }

  async dispose(): Promise<void> {
    await this.#bridge?.dispose();
    this.#bridge = undefined;
  }
}

export const test = base.extend<
  { canonicalProvisioning: CanonicalProvisioning },
  { provisioningWorker: WorkerProvisioning }
>({
  provisioningWorker: [
    async ({}, use) => {
      const worker = new WorkerProvisioning();
      try {
        await use(worker);
      } finally {
        // Owned: the worker started it, the worker stops it. The deployment it
        // was talking to is left running.
        await worker.dispose();
      }
    },
    { scope: "worker" },
  ],

  canonicalProvisioning: async ({ provisioningWorker }, use, testInfo) => {
    const coauth = coauthBaseUrl();
    testInfo.skip(!coauth, "canonical provisioning requires a Coauth deployment");
    const oidcClientId = coauthOidcClientId();
    testInfo.skip(
      !oidcClientId,
      "canonical provisioning requires COTEST_OIDC_CLIENT_ID alongside Coauth",
    );
    testInfo.skip(
      !process.env.COTEST_PROVISION_BIN,
      "COTEST_PROVISION_BIN is exported by run-joint-e2e.ps1; this lane has no bridge",
    );

    const deployment: AttachedDeployment = {
      ownership: "attached",
      coauthBaseUrl: coauth as string,
      solandBaseUrl: solandBaseUrl(),
      mockEmailBaseUrl: mockEmailBaseUrl(),
      oidcClientId: oidcClientId as string,
    };
    const bridge = provisioningWorker.bridge();
    const station = await bridge.describeStation(deployment);

    await use({
      deployment,
      station,
      bridge,
      async provisionPrincipal(label: string): Promise<ProvisionedPrincipal> {
        const handle = `${label}-${Date.now()}${Math.floor(Math.random() * 1000)}`
          .toLowerCase()
          .replace(/[^a-z0-9-]/g, "-");
        const password = "1amTester!";
        await bridge.provisionUnboundAccount(deployment, { handle, password });

        const handoff = await bridge.createAccountHandoff({
          coauthBaseUrl: deployment.coauthBaseUrl,
          clientId: deployment.oidcClientId,
          audienceId: station.serviceId,
          deviceLabel: handle,
        });
        const deviceId = newDeviceId();
        const founded = await bridge.foundPrincipal({
          handoffId: handoff.handoffId,
          endpoints: deployment,
          trustDomain: station.trustDomain,
          audienceId: station.serviceId,
          deviceId,
          displayName: `E2E ${handle}`,
        });

        const grant = founded.sessionGrantOutcome as {
          session_grant?: string;
          account_id?: { principal_id?: string; station_id?: string };
        };
        // Read the closed AccountId out here rather than letting each spec
        // reach into the raw outcome: a principal without a Station is not a
        // provisioned principal, and this is the one place that can say so.
        const principalId = grant.account_id?.principal_id;
        const stationId = grant.account_id?.station_id;
        if (!grant.session_grant || !principalId || !stationId) {
          throw new Error(
            `provisioning ${handle} returned an incomplete grant: ` +
              `session_grant=${Boolean(grant.session_grant)} ` +
              `principal_id=${principalId ?? "absent"} station_id=${stationId ?? "absent"}`,
          );
        }
        return {
          ...founded,
          handle,
          deviceId,
          handoffId: handoff.handoffId,
          accountId: { principal_id: principalId, station_id: stationId },
          sessionGrant: grant.session_grant,
        };
      },
      readSelfAccountViewer(principal: ProvisionedPrincipal) {
        return bridge.readSelfAccountViewer({
          handoffId: principal.handoffId,
          solandBaseUrl: deployment.solandBaseUrl,
        });
      },
    });
    // Nothing to tear down: the principal exists on an attached deployment and
    // outlives the test on purpose, so a failure can be inspected against the
    // Station that recorded it.
  },
});

export { expect } from "./arkret-test";
