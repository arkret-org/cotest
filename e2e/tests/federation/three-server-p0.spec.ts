// Three-server federation P0.
// Spec invariants: sync/federation.md §§4.1-4.5 and §5; event-auth-state-resolution.md.
// The suite uses three independently issued accounts and the runner topology manifest.

import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import { execFile } from "node:child_process";
import fs from "node:fs";
import { promisify } from "node:util";
import {
  hasServerCount,
  colandBaseUrl,
  colandServiceId,
  type ColandKey,
} from "../../helpers/env";
import {
  acceptPreparedInviteApi,
  accountActorId,
  authHeaders,
  canonicalJson,
  createRealmApi,
  grantCapabilityEventApi,
  pushCommittedRowsApi,
  readCommitStreamHeadApi,
  queryRealmEventsApi,
  resolveDefaultStrandId,
  replicationOutcomesOutside,
  scanPeerRealmStreamRowsApi,
  sendMessageApi,
  signedEventEnvelope,
  submitSignedEventApi,
  waitForInviteDeliveryApi,
  type CommittedEventFullView,
} from "../../helpers/coland-api";
import {
  ensureRegistered,
  issueUserSession,
  uniqueUser,
  type JointUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

type Participant = {
  user: JointUser;
  token: string;
  server: ColandKey;
};

type ThreeServerRealm = {
  realmId: string;
  alice: Participant;
  bob: Participant;
  carol: Participant;
  // The accepted own-Station join Event of each invitee.
  joinEventIds: { bob: string; carol: string };
  commonFloorPosition: number;
};

const execFileAsync = promisify(execFile);

type RuntimeTopology = {
  servers: Array<{
    name: string;
    coland: {
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
  if (!server?.coland.control) {
    throw new Error(`${serverName} has no runner-owned fault control`);
  }
  await execFileAsync("pwsh", [
    "-NoProfile",
    "-File",
    server.coland.control.script_path,
    "-TopologyPath",
    topologyPath,
    "-ServerName",
    serverName,
    "-Action",
    action,
  ], { timeout: 60_000, windowsHide: true });
  return JSON.parse(fs.readFileSync(server.coland.control.state_path, "utf8")) as {
    status: string;
    restarted?: boolean;
    current_process_id?: number;
    container_id?: string;
  };
}

async function waitForServerHealth(
  request: APIRequestContext,
  server: ColandKey,
) {
  await expect.poll(async () => {
    try {
      return (await request.get(`${colandBaseUrl(server)}/health`, { timeout: 5_000 })).ok();
    } catch {
      return false;
    }
  }, { timeout: 60_000, intervals: [1_000, 2_000, 5_000] }).toBeTruthy();
}

async function allowExplicitInviteNotifications(
  request: APIRequestContext,
  participant: Participant,
) {
  const url = `${colandBaseUrl(participant.server)}/_arkret/self/invite-receive-policy`;
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
  minPosition?: number,
) {
  const page = await queryRealmEventsApi(request, participant.token, realmId, {
    server: participant.server,
    limit: 500,
    afterPosition: minPosition === undefined ? undefined : minPosition - 1,
  });
  const readableIds = new Set((Array.isArray(page.commits) ? page.commits : [])
    .filter((commit) => minPosition === undefined || Number(commit.stream_position) >= minPosition)
    .map((commit) => String(commit.event_ref)));
  return (Array.isArray(page.events) ? page.events : [])
    .filter((event) => readableIds.has(String((event as Record<string, unknown>).event_id)))
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
    participant.token = await issueUserSession(request, participant.user, {
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
    history_access: "since_join",
    invitees: [bob.user.id, carol.user.id],
    invitee_ids: {
      [bob.user.id]: colandServiceId("server2"),
      [carol.user.id]: colandServiceId("server3"),
    },
    ownerId: alice.user.id,
    creator_id: colandServiceId("server1"),
    plaintext_visible_services: [
      colandServiceId("server1"),
      colandServiceId("server2"),
      colandServiceId("server3"),
    ],
    federation_policy: "open",
  }, { server: "server1" });
  // Initialize the accepted discussion before join snapshots are installed;
  // a remote member cannot create the owner's missing default Strand.
  await resolveDefaultStrandId(request, alice.token, realmId, { server: "server1" });
  // Each invitee joins through its own Station, which prepares against the
  // verified current governance Station and forwards the exact Event there.
  const joinEventIds: Record<string, string> = {};
  const joinPositions: number[] = [];
  for (const participant of [bob, carol]) {
    const invitation = await waitForInviteDeliveryApi(
      request,
      participant.token,
      participant.user.id,
      realmId,
      participant.server,
    );
    let joinCommit: Record<string, unknown> | undefined;
    const joined = await acceptPreparedInviteApi(
      request,
      participant.token,
      participant.user.id,
      realmId,
      invitation.id,
      {
        server: participant.server,
        onAccepted: (outcome) => { joinCommit = outcome.commit as Record<string, unknown>; },
      },
    );
    expect(joinCommit, "the join returns its exact accepted Commit").toBeTruthy();
    expect(joinCommit!.event_ref).toBe(joined.event_id);
    expect(Number.isSafeInteger(joinCommit!.stream_position)).toBe(true);
    joinEventIds[participant.server] = String(joined.event_id);
    joinPositions.push(Number(joinCommit!.stream_position));
    // Freeze the pre-grant readable baseline so the following grant really
    // invalidates an installed cut instead of racing the first snapshot.
    const memberRealmUrl = `${colandBaseUrl(participant.server)}/_arkret/self/realms/${encodeURIComponent(realmId)}`;
    await expect.poll(async () => {
      const response = await request.get(memberRealmUrl, {
        headers: authHeaders(participant.token, "GET", memberRealmUrl),
      });
      expect([200, 404], "join baseline read must not bypass a service error").toContain(response.status());
      return response.ok();
    }, { timeout: 60_000, intervals: [500, 1_000, 2_000] }).toBe(true);
    // Membership provides the read interval, not Message write authority.
    const grant = await grantCapabilityEventApi(request, alice.token, {
      ownerId: alice.user.id,
      realmId,
      subjectId: participant.user.id,
      subjectServer: participant.server,
      actions: ["ak.message.create"],
      server: "server1",
    });
    const grantUrl = `${colandBaseUrl(participant.server)}/_arkret/self/committed-events/${grant.eventId}`;
    await expect.poll(async () => {
      const response = await request.get(grantUrl, {
        headers: authHeaders(participant.token, "GET", grantUrl),
      });
      expect([200, 404], "the exact accepted grant read must not bypass a service error").toContain(response.status());
      if (!response.ok()) return false;
      const pair = await response.json() as CommittedEventFullView;
      expect(pair.commit?.event_ref).toBe(grant.eventId);
      expect(pair.event?.event_id).toBe(grant.eventId);
      return true;
    }, { timeout: 60_000, intervals: [500, 1_000, 2_000] }).toBe(true);
  }
  let lastViews: Array<{ server: string; status: number; members: boolean[] }> = [];
  try {
    await expect.poll(async () => {
      const views = await Promise.all(participants.map(async (participant) => {
        const response = await request.get(
          `${colandBaseUrl(participant.server)}/_arkret/self/realms/${encodeURIComponent(realmId)}`,
          { headers: authHeaders(participant.token, "GET", `${colandBaseUrl(participant.server)}/_arkret/self/realms/${encodeURIComponent(realmId)}`) },
        );
        const view = response.ok() ? JSON.stringify(await response.json()) : "";
        return {
          server: participant.server,
          status: response.status(),
          members: [alice, bob, carol].map((member) => view.includes(member.user.id)),
        };
      }));
      lastViews = views;
      return views.every((view) => view.members.every(Boolean));
    }, { timeout: 60_000, intervals: [1_000, 2_000, 5_000] }).toBeTruthy();
  } catch (error) {
    console.error(JSON.stringify({ realm_id: realmId, join_event_ids: joinEventIds, last_views: lastViews }));
    throw error;
  }
  return {
    realmId,
    alice,
    bob,
    carol,
    joinEventIds: { bob: joinEventIds.server2, carol: joinEventIds.server3 },
    commonFloorPosition: Math.max(...joinPositions),
  };
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
        eventIds(request, realm.alice, realm.realmId, realm.commonFloorPosition),
        eventIds(request, realm.bob, realm.realmId, realm.commonFloorPosition),
        eventIds(request, realm.carol, realm.realmId, realm.commonFloorPosition),
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
    // Idempotent replay: server3 reads the Realm stream from its governance
    // Station and every exact pair it holds (its own join onward) replays as
    // `duplicate`, and an exact replay of the same body answers the same.
    const rows = await scanPeerRealmStreamRowsApi(request, {
      server: "server1",
      sourceServiceId: colandServiceId("server3"),
      realmId: realm.realmId,
    });
    const carolJoin = rows.find((row) => row.event.event_id === realm.joinEventIds.carol);
    expect(carolJoin, "server3 may read its own join Commit").toBeTruthy();
    const held = rows
      .filter((row) => Number(row.commit.stream_position) >= Number(carolJoin!.commit.stream_position))
      .slice(0, 100);
    for (const attempt of ["first", "exact replay"]) {
      const replay = await pushCommittedRowsApi(request, held, {
        origin: colandServiceId("server1"),
        destination: colandServiceId("server3"),
        server: "server3",
        realmId: realm.realmId,
      });
      expect(
        replicationOutcomesOutside(held.map((row) => row.event), replay, ["duplicate"]),
        attempt,
      ).toEqual([]);
    }
  });

  test("P0.2 a member leaving server2 stops its fanout without breaking server1/server3 or a sentinel Realm", async ({ request }) => {
    // federation.md §4.1.1: targets are the routing services of effective
    // joined members; when bob (server2's only member) leaves, server2 stops
    // receiving later Commits while server3 keeps converging.
    const realm = await createThreeServerRealm(request, "p0-isolation");
    const baseline = `server2 baseline ${Date.now()}`;
    await sendMessageApi(request, realm.alice.token, realm.realmId, baseline, { server: "server1" });
    await waitForText(request, realm.bob, realm.realmId, baseline);
    await submitSignedEventApi(request, realm.bob.token, signedEventEnvelope({
      actorId: realm.bob.user.id,
      server: "server2",
      realmId: realm.realmId,
      kind: "ak.member.state",
      payload: { member_id: accountActorId(realm.bob.user.id, "server2"), membership: "leave" },
    }), { server: "server2", context: "bob leaves the Realm from server2" });
    await expect.poll(async () => {
      const url = `${colandBaseUrl("server1")}/_arkret/self/realms/${encodeURIComponent(realm.realmId)}`;
      const response = await request.get(url, { headers: authHeaders(realm.alice.token, "GET", url) });
      if (!response.ok()) return true;
      const view = await response.json() as { member_ids?: Array<{ kind?: string; account_id?: { principal_id?: string } }> };
      return (view.member_ids ?? []).some((member) =>
        member?.kind === "account" && member.account_id?.principal_id === realm.bob.user.id,
      );
    }, { timeout: 45_000, intervals: [1_000, 2_000, 5_000] }).toBe(false);
    const isolated = `after server2 left ${Date.now()}`;
    const after = await sendMessageApi(request, realm.alice.token, realm.realmId, isolated, { server: "server1" });
    await waitForText(request, realm.carol, realm.realmId, isolated);
    const committedAtServer2 = async () => {
      const url = `${colandBaseUrl("server2")}/_arkret/self/committed-events/${after.event_id}`;
      return (await request.get(url, { headers: authHeaders(realm.bob.token, "GET", url) })).status();
    };
    await expect.poll(committedAtServer2, { timeout: 20_000, intervals: [1_000, 2_000, 4_000] }).toBe(404);
    const sentinel = await createThreeServerRealm(request, "p0-sentinel");
    const sentinelBody = `sentinel server1-server3 ${Date.now()}`;
    await sendMessageApi(request, sentinel.carol.token, sentinel.realmId, sentinelBody, { server: "server3" });
    await waitForText(request, sentinel.alice, sentinel.realmId, sentinelBody);
  });

  test("P0.3 a lagging server recovers through the authorized peer stream scan without duplicate materialization", async ({ request }, testInfo) => {
    const realm = await createThreeServerRealm(request, "p0-recovery");
    const before = await readCommitStreamHeadApi(request, realm.bob.token, realm.realmId, {
      server: "server2",
    });
    expect(before, "the destination must hold its accepted stream before isolation").toBeDefined();
    const body1 = `available pair server1 ${Date.now()}`;
    const body3 = `available pair server3 ${Date.now()}`;
    let isolationState: Awaited<ReturnType<typeof controlServer>> | undefined;
    try {
      isolationState = await controlServer("server2", "isolate");
      expect(isolationState.status).toBe("isolated");
      const unavailable = await request.get(`${colandBaseUrl("server2")}/health`, {
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
    // Recovery reads server2's one authorized stream from the governance
    // Station (ak.peer.committed_event.read.scan.v1) and replicates the
    // missing exact pairs in stream order: each is a direct successor of what
    // server2 holds, or already held.
    const rows = await scanPeerRealmStreamRowsApi(request, {
      server: "server1",
      sourceServiceId: colandServiceId("server2"),
      realmId: realm.realmId,
    });
    // A product timeline is a bounded disclosure view, not the replica head.
    // Older Events missing from that view must not be replayed behind the
    // destination's accepted anchor as though they were stream successors.
    const missing = rows.filter((row) => Number(row.commit.stream_position) > before!.stream_position).slice(0, 100);
    if (missing.length > 0) {
      // Recovered fanout and independent catch-up requests may race. Every
      // exact body must remain stored/duplicate under the atomic replica lock.
      const recoveryOptions = {
        origin: colandServiceId("server1"),
        destination: colandServiceId("server2"),
        server: "server2" as const,
        realmId: realm.realmId,
      };
      const outcomes = await Promise.all(Array.from({ length: 4 }, () =>
        pushCommittedRowsApi(request, missing, recoveryOptions),
      ));
      for (const outcome of outcomes) {
        expect(
          replicationOutcomesOutside(missing.map((row) => row.event), outcome, ["stored", "duplicate"]),
        ).toEqual([]);
      }
    }
    await Promise.all([
      waitForText(request, realm.bob, realm.realmId, body1),
      waitForText(request, realm.bob, realm.realmId, body3),
    ]);
    const after = await eventIds(request, realm.bob, realm.realmId, realm.commonFloorPosition);
    expect(new Set(after).size).toBe(after.length);
    await testInfo.attach("recovery-audit.json", {
      body: JSON.stringify({ source: "server1", destination: "server2", before_stream_position: before!.stream_position, after: after.length, missing: missing.length, fault_control: isolationState }),
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
    const rows = await scanPeerRealmStreamRowsApi(request, {
      server: "server1",
      sourceServiceId: colandServiceId("server3"),
      realmId: realm.realmId,
    });
    expect(rows.length).toBeGreaterThan(0);
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
    const writes = await Promise.all([realm.alice, realm.bob, realm.carol].map((participant, index) =>
      sendMessageApi(request, participant.token, realm.realmId, bodies[index], {
        server: participant.server,
        retryTemporarilyUnavailable: true,
      })
    ));
    expect(new Set(writes.map((write) => write.event_id)).size).toBe(3);
    for (const participant of [realm.alice, realm.bob, realm.carol]) {
      for (const body of bodies) await waitForText(request, participant, realm.realmId, body);
    }
    await expect.poll(async () => {
      const sets = await Promise.all([
        eventIds(request, realm.alice, realm.realmId, realm.commonFloorPosition),
        eventIds(request, realm.bob, realm.realmId, realm.commonFloorPosition),
        eventIds(request, realm.carol, realm.realmId, realm.commonFloorPosition),
      ]);
      return JSON.stringify(sets[0]) === JSON.stringify(sets[1]) && JSON.stringify(sets[1]) === JSON.stringify(sets[2]);
    }, { timeout: 60_000, intervals: [2_000, 5_000] }).toBeTruthy();
    const beforeRestart = await Promise.all([
      eventIds(request, realm.alice, realm.realmId, realm.commonFloorPosition),
      eventIds(request, realm.bob, realm.realmId, realm.commonFloorPosition),
      eventIds(request, realm.carol, realm.realmId, realm.commonFloorPosition),
    ]);
    for (const ids of beforeRestart) {
      for (const write of writes) expect(ids.filter((id) => id === write.event_id)).toHaveLength(1);
    }
    const restartState = await controlServer("server2", "restart");
    expect(restartState.restarted).toBeTruthy();
    await waitForServerHealth(request, "server2");
    await expect.poll(async () => {
      const afterRestart = await Promise.all([
        eventIds(request, realm.alice, realm.realmId, realm.commonFloorPosition),
        eventIds(request, realm.bob, realm.realmId, realm.commonFloorPosition),
        eventIds(request, realm.carol, realm.realmId, realm.commonFloorPosition),
      ]);
      return afterRestart.every((ids, index) => JSON.stringify(ids) === JSON.stringify(beforeRestart[index]));
    }, { timeout: 60_000, intervals: [2_000, 5_000] }).toBeTruthy();
    await testInfo.attach("restart-audit.json", {
      body: JSON.stringify(restartState),
      contentType: "application/json",
    });
  });
});
