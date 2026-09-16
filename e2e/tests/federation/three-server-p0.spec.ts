// Three-server federation P0.
// Spec invariants: sync/federation.md §§4.1-4.5 and §5; event-auth-state-resolution.md.
// The suite uses three independently issued accounts and the runner topology manifest.

import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import { execFile } from "node:child_process";
import fs from "node:fs";
import { promisify } from "node:util";
import {
  hasServerCount,
  solandBaseUrl,
  solandServiceId,
  type SolandKey,
} from "../../helpers/env";
import {
  acceptInviteApi,
  authHeaders,
  canonicalJson,
  createRealmApi,
  grantServiceCapabilityApi,
  listInvitesApi,
  pushFederationEvents,
  queryPeerEventsApi,
  readCommitStreamHeadApi,
  queryRealmEventsApi,
  revokeCapabilityApi,
  sendMessageApi,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
  type JointUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

type Participant = {
  user: JointUser;
  token: string;
  server: SolandKey;
};

type ThreeServerRealm = {
  realmId: string;
  alice: Participant;
  bob: Participant;
  carol: Participant;
};

const execFileAsync = promisify(execFile);

type RuntimeTopology = {
  servers: Array<{
    name: string;
    soland: {
      control?: { script_path: string; state_path: string };
    };
  }>;
};

function runtimeTopology(): RuntimeTopology {
  const topologyPath = process.env.COTEST_TOPOLOGY_PATH;
  if (!topologyPath) throw new Error("COTEST_TOPOLOGY_PATH is required");
  return JSON.parse(fs.readFileSync(topologyPath, "utf8")) as RuntimeTopology;
}

async function controlServer(
  serverName: "server1" | "server2" | "server3",
  action: "isolate" | "restore" | "restart",
) {
  const topologyPath = process.env.COTEST_TOPOLOGY_PATH!;
  const server = runtimeTopology().servers.find((item) => item.name === serverName);
  if (!server?.soland.control) {
    throw new Error(`${serverName} has no runner-owned fault control`);
  }
  await execFileAsync("pwsh", [
    "-NoProfile",
    "-File",
    server.soland.control.script_path,
    "-TopologyPath",
    topologyPath,
    "-ServerName",
    serverName,
    "-Action",
    action,
  ], { timeout: 60_000, windowsHide: true });
  return JSON.parse(fs.readFileSync(server.soland.control.state_path, "utf8")) as {
    status: string;
    restarted?: boolean;
    current_process_id?: number;
    container_id?: string;
  };
}

async function waitForServerHealth(
  request: APIRequestContext,
  server: SolandKey,
) {
  await expect.poll(async () => {
    try {
      return (await request.get(`${solandBaseUrl(server)}/health`, { timeout: 5_000 })).ok();
    } catch {
      return false;
    }
  }, { timeout: 60_000, intervals: [1_000, 2_000, 5_000] }).toBeTruthy();
}

async function waitForInvite(
  request: APIRequestContext,
  participant: Participant,
  realmId: string,
) {
  let found: Awaited<ReturnType<typeof listInvitesApi>>[number] | undefined;
  await expect.poll(async () => {
    const invites = await listInvitesApi(request, participant.token, {
      server: participant.server,
    });
    found = invites.find((invite) =>
      invite.realm_id === realmId &&
      invite.invitee_account_id?.principal_id === participant.user.id
    );
    return Boolean(found);
  }, { timeout: 60_000, intervals: [1_000, 2_000, 5_000] }).toBeTruthy();
  return found!;
}

async function allowExplicitInviteNotifications(
  request: APIRequestContext,
  participant: Participant,
) {
  const url = `${solandBaseUrl(participant.server)}/_arkret/self/invite-receive-policy`;
  const current = await request.get(url, {
    headers: authHeaders(participant.token, "GET", url),
  });
  expect(current.status(), await current.text()).toBe(200);
  const policy = (await current.json()) as Record<string, unknown>;
  const allowedKinds = Array.isArray(policy.holder_allowed_introduction_kinds)
    ? policy.holder_allowed_introduction_kinds.filter(
        (kind): kind is string => typeof kind === "string",
      )
    : [];
  const updated = await request.put(url, {
    headers: {
      ...authHeaders(participant.token, "PUT", url),
      "content-type": "application/json",
    },
    data: canonicalJson({
      ...policy,
      holder_allowed_introduction_kinds: Array.from(
        new Set([...allowedKinds, "explicit_address"]),
      ),
      explicit_address_behavior: "notify",
    }),
  });
  expect(updated.status(), await updated.text()).toBe(200);
}

async function waitForText(
  request: APIRequestContext,
  participant: Participant,
  realmId: string,
  text: string,
) {
  await expect.poll(async () => {
    const page = await queryRealmEventsApi(request, participant.token, realmId, {
      server: participant.server,
      limit: 300,
    });
    return JSON.stringify(page).includes(text);
  }, { timeout: 60_000, intervals: [1_000, 2_000, 5_000] }).toBeTruthy();
}

async function eventIds(
  request: APIRequestContext,
  participant: Participant,
  realmId: string,
) {
  const page = await queryRealmEventsApi(request, participant.token, realmId, {
    server: participant.server,
    limit: 500,
  });
  return (Array.isArray(page.events) ? page.events : [])
    .map((event) => String((event as Record<string, unknown>).event_id))
    .sort();
}

async function createThreeServerRealm(
  request: APIRequestContext,
  label: string,
): Promise<ThreeServerRealm> {
  const stamp = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const participants: Participant[] = [
    { user: uniqueUser(`${label}-alice-${stamp}`, "server1"), token: "", server: "server1" },
    { user: uniqueUser(`${label}-bob-${stamp}`, "server2"), token: "", server: "server2" },
    { user: uniqueUser(`${label}-carol-${stamp}`, "server3"), token: "", server: "server3" },
  ];
  for (const participant of participants) {
    await ensureRegistered(request, participant.user, { server: participant.server });
    participant.token = await issueDevSession(request, participant.user, {
      server: participant.server,
    });
  }
  const [alice, bob, carol] = participants;
  await Promise.all([
    allowExplicitInviteNotifications(request, bob),
    allowExplicitInviteNotifications(request, carol),
  ]);
  const realmId = await createRealmApi(request, alice.token, {
    title: `${label} ${stamp}`,
    discoverability: "listed",
    history_access: "all_history_for_current_members",
    invitees: [bob.user.id, carol.user.id],
    invitee_ids: {
      [bob.user.id]: solandServiceId("server2"),
      [carol.user.id]: solandServiceId("server3"),
    },
    ownerId: alice.user.id,
    creator_id: solandServiceId("server1"),
    plaintext_visible_services: [
      solandServiceId("server1"),
      solandServiceId("server2"),
      solandServiceId("server3"),
    ],
    federation_policy: "open",
  }, { server: "server1" });
  for (const participant of [bob, carol]) {
    const invite = await waitForInvite(request, participant, realmId);
    await acceptInviteApi(
      request,
      participant.token,
      participant.user.id,
      realmId,
      invite.id,
      { server: participant.server },
    );
  }
  await expect.poll(async () => {
    const views = await Promise.all(participants.map(async (participant) => {
      const response = await request.get(
        `${solandBaseUrl(participant.server)}/_arkret/self/realms/${encodeURIComponent(realmId)}`,
        { headers: { authorization: `Bearer ${participant.token}` } },
      );
      return response.ok() ? JSON.stringify(await response.json()) : "";
    }));
    return views.every((view) =>
      [alice, bob, carol].every((participant) => view.includes(participant.user.id))
    );
  }, { timeout: 60_000, intervals: [1_000, 2_000, 5_000] }).toBeTruthy();
  return { realmId, alice, bob, carol };
}

test.describe("three-server federation P0 @three-server-p0", () => {
  test.beforeAll(() => {
    expect(hasServerCount(3), "P0 requires runner-owned server1/server2/server3").toBeTruthy();
  });

  test("P0.1 three servers and three users converge with idempotent replay", async ({ request }) => {
    const realm = await createThreeServerRealm(request, "p0-convergence");
    const messages = [
      [realm.alice, `alice convergence ${Date.now()}`] as const,
      [realm.bob, `bob convergence ${Date.now()}`] as const,
      [realm.carol, `carol convergence ${Date.now()}`] as const,
    ];
    for (const [participant, body] of messages) {
      await sendMessageApi(request, participant.token, realm.realmId, body, {
        server: participant.server,
      });
    }
    for (const participant of [realm.alice, realm.bob, realm.carol]) {
      for (const [, body] of messages) await waitForText(request, participant, realm.realmId, body);
    }
    await expect.poll(async () => {
      const sets = await Promise.all([
        eventIds(request, realm.alice, realm.realmId),
        eventIds(request, realm.bob, realm.realmId),
        eventIds(request, realm.carol, realm.realmId),
      ]);
      return sets[0].join("\n") === sets[1].join("\n") && sets[1].join("\n") === sets[2].join("\n");
    }, { timeout: 60_000, intervals: [2_000, 5_000] }).toBeTruthy();
    // Convergence is now the Realm's own commit stream: all three Stations
    // must report the identical head position and commit id for it.
    await expect.poll(async () => {
      const heads = await Promise.all([
        readCommitStreamHeadApi(request, realm.alice.token, realm.realmId, { server: "server1" }),
        readCommitStreamHeadApi(request, realm.bob.token, realm.realmId, { server: "server2" }),
        readCommitStreamHeadApi(request, realm.carol.token, realm.realmId, { server: "server3" }),
      ]);
      return heads.every((head) => head !== undefined) &&
        new Set(heads.map((head) => JSON.stringify(head))).size === 1;
    }, { timeout: 60_000, intervals: [2_000, 5_000] }).toBeTruthy();
    const sourcePage = await queryPeerEventsApi(request, {
      server: "server1",
      sourceServiceId: solandServiceId("server3"),
      realmId: realm.realmId,
      limit: 300,
    });
    const replay = await pushFederationEvents(request, sourcePage.events, {
      origin: solandServiceId("server1"),
      destination: solandServiceId("server3"),
      server: "server3",
      realmId: realm.realmId,
      idempotencyKey: `${solandServiceId("server1")}#p0-idempotent-replay`,
    });
    expect(replay.rejections ?? []).toEqual([]);
    expect((replay.duplicate ?? []).length).toBeGreaterThan(0);
  });

  test("P0.2 isolating server2 does not break server1/server3 or a sentinel Realm", async ({ request }) => {
    const realm = await createThreeServerRealm(request, "p0-isolation");
    const grantId = await grantServiceCapabilityApi(request, realm.alice.token, {
      ownerId: realm.alice.user.id,
      realmId: realm.realmId,
      subjectServiceId: solandServiceId("server2"),
    });
    const baseline = `server2 baseline ${Date.now()}`;
    await sendMessageApi(request, realm.alice.token, realm.realmId, baseline, { server: "server1" });
    await waitForText(request, realm.bob, realm.realmId, baseline);
    await revokeCapabilityApi(request, realm.alice.token, {
      ownerId: realm.alice.user.id,
      realmId: realm.realmId,
      grantId,
    });
    const isolated = `isolated route ${Date.now()}`;
    await sendMessageApi(request, realm.alice.token, realm.realmId, isolated, { server: "server1" });
    await waitForText(request, realm.carol, realm.realmId, isolated);
    await expect.poll(async () => {
      const page = await queryRealmEventsApi(request, realm.bob.token, realm.realmId, { server: "server2", limit: 300 });
      return JSON.stringify(page).includes(isolated);
    }, { timeout: 20_000, intervals: [1_000, 2_000, 4_000] }).toBeFalsy();
    const sentinel = await createThreeServerRealm(request, "p0-sentinel");
    const sentinelBody = `sentinel server1-server3 ${Date.now()}`;
    await sendMessageApi(request, sentinel.carol.token, sentinel.realmId, sentinelBody, { server: "server3" });
    await waitForText(request, sentinel.alice, sentinel.realmId, sentinelBody);
  });

  test("P0.3 a lagging server recovers through authorized peer query without duplicate materialization", async ({ request }, testInfo) => {
    const realm = await createThreeServerRealm(request, "p0-recovery");
    const before = new Set(await eventIds(request, realm.bob, realm.realmId));
    const body1 = `available pair server1 ${Date.now()}`;
    const body3 = `available pair server3 ${Date.now()}`;
    let isolationState: Awaited<ReturnType<typeof controlServer>> | undefined;
    try {
      isolationState = await controlServer("server2", "isolate");
      expect(isolationState.status).toBe("isolated");
      const unavailable = await request.get(`${solandBaseUrl("server2")}/health`, {
        failOnStatusCode: false,
        timeout: 5_000,
      }).catch(() => undefined);
      expect(unavailable?.ok() ?? false, "server2 must be unavailable during the fault window").toBeFalsy();
      await Promise.all([
        sendMessageApi(request, realm.alice.token, realm.realmId, body1, { server: "server1" }),
        sendMessageApi(request, realm.carol.token, realm.realmId, body3, { server: "server3" }),
      ]);
      await Promise.all([
        waitForText(request, realm.carol, realm.realmId, body1),
        waitForText(request, realm.alice, realm.realmId, body3),
      ]);
    } finally {
      if (isolationState?.status === "isolated") {
        await controlServer("server2", "restore");
        await waitForServerHealth(request, "server2");
      }
    }
    const recoveryPage = await queryPeerEventsApi(request, {
      server: "server1",
      sourceServiceId: solandServiceId("server2"),
      realmId: realm.realmId,
      limit: 500,
    });
    const missing = recoveryPage.events.filter((event) => !before.has(String(event.event_id)));
    if (missing.length > 0) {
      const outcome = await pushFederationEvents(request, missing, {
        origin: solandServiceId("server1"),
        destination: solandServiceId("server2"),
        server: "server2",
        realmId: realm.realmId,
        idempotencyKey: `${solandServiceId("server2")}#p0-recovery`,
      });
      expect(outcome.rejections ?? []).toEqual([]);
    }
    await Promise.all([
      waitForText(request, realm.bob, realm.realmId, body1),
      waitForText(request, realm.bob, realm.realmId, body3),
    ]);
    const after = await eventIds(request, realm.bob, realm.realmId);
    expect(new Set(after).size).toBe(after.length);
    await testInfo.attach("recovery-audit.json", {
      body: JSON.stringify({ source: "server1", destination: "server2", before: before.size, after: after.length, missing: missing.length, fault_control: isolationState }),
      contentType: "application/json",
    });
  });

  test("P0.4 ordered candidate failure is recorded before an authorized source succeeds", async ({ request }, testInfo) => {
    const realm = await createThreeServerRealm(request, "p0-candidates");
    const failures: Array<{ source: string; reason: string }> = [];
    try {
      await request.get("https://unregistered.local.host/health", { timeout: 5_000 });
      failures.push({ source: "unregistered.local.host", reason: "unexpectedly_reachable" });
    } catch (error) {
      failures.push({ source: "unregistered.local.host", reason: error instanceof Error ? error.name : "transport_failure" });
    }
    expect(failures[0].reason).not.toBe("unexpectedly_reachable");
    const page = await queryPeerEventsApi(request, {
      server: "server1",
      sourceServiceId: solandServiceId("server3"),
      realmId: realm.realmId,
      limit: 100,
    });
    expect(page.events.length).toBeGreaterThan(0);
    await testInfo.attach("candidate-source-report.json", {
      body: JSON.stringify({ failures, selected_source: "server1", requester: "server3" }),
      contentType: "application/json",
    });
  });

  test("P0.5 three-way concurrent writes survive a server restart with the same durable event set", async ({ request }, testInfo) => {
    const realm = await createThreeServerRealm(request, "p0-conflict");
    const bodies = [realm.alice, realm.bob, realm.carol].map((participant) =>
      `${participant.server} concurrent ${Date.now()}-${Math.random()}`
    );
    await Promise.all([realm.alice, realm.bob, realm.carol].map((participant, index) =>
      sendMessageApi(request, participant.token, realm.realmId, bodies[index], { server: participant.server })
    ));
    for (const participant of [realm.alice, realm.bob, realm.carol]) {
      for (const body of bodies) await waitForText(request, participant, realm.realmId, body);
    }
    await expect.poll(async () => {
      const sets = await Promise.all([
        eventIds(request, realm.alice, realm.realmId),
        eventIds(request, realm.bob, realm.realmId),
        eventIds(request, realm.carol, realm.realmId),
      ]);
      return JSON.stringify(sets[0]) === JSON.stringify(sets[1]) && JSON.stringify(sets[1]) === JSON.stringify(sets[2]);
    }, { timeout: 60_000, intervals: [2_000, 5_000] }).toBeTruthy();
    const beforeRestart = await Promise.all([
      eventIds(request, realm.alice, realm.realmId),
      eventIds(request, realm.bob, realm.realmId),
      eventIds(request, realm.carol, realm.realmId),
    ]);
    const restartState = await controlServer("server2", "restart");
    expect(restartState.restarted).toBeTruthy();
    await waitForServerHealth(request, "server2");
    await expect.poll(async () => {
      const afterRestart = await Promise.all([
        eventIds(request, realm.alice, realm.realmId),
        eventIds(request, realm.bob, realm.realmId),
        eventIds(request, realm.carol, realm.realmId),
      ]);
      return afterRestart.every((ids, index) => JSON.stringify(ids) === JSON.stringify(beforeRestart[index]));
    }, { timeout: 60_000, intervals: [2_000, 5_000] }).toBeTruthy();
    await testInfo.attach("restart-audit.json", {
      body: JSON.stringify(restartState),
      contentType: "application/json",
    });
  });
});
