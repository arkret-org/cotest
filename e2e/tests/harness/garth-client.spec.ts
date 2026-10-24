// Garth's client runtime driven without Inkson or a browser.
//
// This is deliberately separate from `test-client-parity.spec.ts`. A test that
// declares Playwright's `browser` fixture starts a browser before its runtime
// client-kind branch runs, so putting the Garth branch in that spec made the
// `joint-api` lane browser-shaped even when it selected Garth. The parity spec
// remains useful in an Inkson lane; this one is the fail-closed joint-api
// assertion.

import { readFile, rename, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import { ProvisioningBridge } from "../../helpers/provisioning-bridge";
import { newDeviceId } from "../../helpers/ids";

import { expect, test } from "../../helpers/arkret-test";
import {
  coauthBaseUrl,
  coauthOidcClientId,
  mockEmailBaseUrl,
  colandBaseUrl,
} from "../../helpers/env";
import { GarthTestClient } from "../../helpers/test-client-garth";

test.describe("Garth client without Inkson @fully-implemented", () => {
  test("founds a principal, syncs, and restores its durable cursor", async ({}, testInfo) => {
    testInfo.setTimeout(Math.max(testInfo.timeout, 300_000));
    const coauth = coauthBaseUrl();
    testInfo.skip(!coauth, "the Garth client journey requires a Coauth deployment");
    testInfo.skip(
      !process.env.COTEST_PROVISION_BIN,
      "the Garth client runs inside cotest-provision; run through run-joint-e2e.ps1",
    );

    const clientId = coauthOidcClientId();
    expect(clientId, "COTEST_OIDC_CLIENT_ID must be set alongside Coauth").toBeTruthy();
    const client = new GarthTestClient({
      endpoints: {
        coauthBaseUrl: coauth as string,
        colandBaseUrl: colandBaseUrl(),
        mockEmailBaseUrl: mockEmailBaseUrl(),
      },
      oidcClientId: clientId as string,
    });

    try {
      const user = await client.createUser("joint-api-garth");
      expect(user.principalId).toMatch(/^ak:did_core:/);
      expect(user.deviceId).toMatch(/^ak:device:/);
      expect(user.stationId).toMatch(/^ak:did_core:/);

      const sync = await client.syncAccount(user);
      testInfo.annotations.push({
        type: "client:garth",
        description: sync.detail,
      });
      expect(sync.hasCursor, "Garth completed a sync round but committed no cursor").toBe(
        true,
      );
      expect(sync.cursor).toBeTruthy();

      const restored = await client.cursorAfterRestart(user);
      expect(restored, "Garth lost its cursor across a restart").toBe(sync.cursor);
    } finally {
      await client.dispose();
    }
  });
});

test("Garth commits a two-member Realm, exchanges messages and resumes a rebuilt runtime @fully-implemented @garth-runtime", async () => {
  test.setTimeout(300_000);
  const coauth = coauthBaseUrl();
  const clientId = coauthOidcClientId();
  expect(coauth, "canonical Garth journey requires Coauth").toBeTruthy();
  expect(clientId, "canonical Garth journey requires the registered OIDC client").toBeTruthy();
  expect(process.env.COTEST_PROVISION_BIN, "canonical Garth journey requires the freshly built bridge").toBeTruthy();
  const client = new GarthTestClient({ endpoints: {
    coauthBaseUrl: coauth!, colandBaseUrl: colandBaseUrl(), mockEmailBaseUrl: mockEmailBaseUrl(),
  }, oidcClientId: clientId! });
  try {
    const alice = await client.createUser("journey-alice");
    const bob = await client.createUser("journey-bob");
    expect(alice.principalId).not.toBe(bob.principalId);
    const realm = await client.createRealm(alice, bob, "Garth runtime journey");
    const first = await client.sendMessage(alice, realm, "alice before restart");
    const second = await client.sendMessage(bob, realm, "bob before restart");
    await expect(client.sendMessage({ ...bob, principalId: alice.principalId }, realm, "wrong source"))
      .rejects.toThrow("does not match its canonical provisioned source");
    const rows = await client.readMessages(bob, realm);
    expect(rows.map(row => row.event.event_id)).toEqual([first.eventId, second.eventId]);
    expect(rows.map(row => row.event.payload.content.body)).toEqual(["alice before restart", "bob before restart"]);
    expect(rows.map(row => row.event.actor_id.account_id.principal_id)).toEqual([alice.principalId, bob.principalId]);
    const sync = await client.syncAccount(bob, realm);
    expect(sync.hasCursor, "real account subscription commits a cursor before runtime destruction").toBe(true);
    expect(sync.eventIds, "subscription delivers the IDs corroborated by the authenticated Realm read").toEqual(expect.arrayContaining([first.eventId, second.eventId]));
    expect(await client.cursorAfterRestart(bob, realm)).toBe(sync.cursor);
    const retained = await client.retainedMessage(bob, second.eventId);
    expect(retained.commit.commit_id).toBe(second.commitId);
    expect(retained.event.payload.content.body).toBe("bob before restart");
    expect(retained.seen, "authenticated read cache survives runtime destruction").toBe(true);
    const third = await client.sendMessage(bob, realm, "bob after restart");
    const restored = await client.readMessages(alice, realm);
    expect(restored.map(row => row.event.event_id)).toEqual([first.eventId, second.eventId, third.eventId]);
    expect(restored.at(-1)!.event.payload.content.body).toBe("bob after restart");
    const resumed = await client.syncAccount(bob, realm);
    expect(resumed.hasCursor).toBe(true);
    expect(resumed.eventIds, "rebuilt runtime resumes the subscription and receives a new committed message").toContain(third.eventId);
    const beforeCold = await client.durableCursor(bob);
    const processRestart = await client.killAndReopen();
    expect(processRestart.newPid).not.toBe(processRestart.oldPid);
    expect(await client.durableCursor(bob), "whole bridge process restores its original committed cursor").toBe(beforeCold);
    expect((await client.retainedMessage(bob, third.eventId)).commit.commit_id).toBe(third.commitId);
    const fourth = await client.sendMessage(bob, realm, "bob after process SIGKILL");
    expect((await client.readMessages(alice, realm)).map(row => row.event.event_id))
      .toEqual([first.eventId, second.eventId, third.eventId, fourth.eventId]);
    const coldResumed = await client.syncAccount(bob, realm);
    expect(coldResumed.eventIds, "new process receives real committed delta with original cursor").toContain(fourth.eventId);
    const custody = client.custodyPaths(bob);
    if (process.platform !== "win32") {
      expect((await stat(custody.identitySnapshotPath)).mode & 0o077).toBe(0);
      expect((await stat(custody.storeRoot)).mode & 0o077).toBe(0);
    }
    const queuePath = path.join(custody.storeRoot, "account.json");
    const storedBeforeFailure = await readFile(queuePath);
    const movedSnapshot = `${custody.identitySnapshotPath}.unavailable`;
    await rename(custody.identitySnapshotPath, movedSnapshot);
    try {
      await expect(client.cursorAfterRestart(bob, realm)).rejects.toThrow("durable accepted identity snapshot unavailable");
      expect((await readFile(queuePath)).equals(storedBeforeFailure),
        "missing custody causes no message, receipt, cache or cursor writes").toBe(true);
    } finally {
      await rename(movedSnapshot, custody.identitySnapshotPath);
    }
    expect(await client.cursorAfterRestart(bob, realm)).toBe(coldResumed.cursor);
    expect((await client.retainedMessage(bob, third.eventId)).commit.commit_id).toBe(third.commitId);
    const snapshotBytes = await readFile(custody.identitySnapshotPath);
    for (const corruptedKey of ["missing-grant", "session", "event"] as const) {
      const snapshot = JSON.parse(snapshotBytes.toString("utf8"));
      const wrongSeed = Buffer.alloc(32).toString("base64url");
      if (corruptedKey === "missing-grant") snapshot.principal.outcome.issued_session = null;
      else if (corruptedKey === "session") snapshot.session_signing_seed_b64url = wrongSeed;
      else snapshot.principal.checkpoint.device_signing_seed_b64url = wrongSeed;
      const queueBefore = await readFile(queuePath);
      await writeFile(custody.identitySnapshotPath, JSON.stringify(snapshot));
      try {
        await expect(client.cursorAfterRestart(bob, realm)).rejects.toThrow(corruptedKey === "missing-grant"
          ? "durable accepted initial session grant unavailable"
          : corruptedKey === "session" ? "session holder binding differs" : "private key or trust domain differs");
        expect((await readFile(queuePath)).equals(queueBefore),
          "wrong key source cannot write durable Garth state").toBe(true);
      } finally {
        await writeFile(custody.identitySnapshotPath, snapshotBytes);
      }
      expect(await client.cursorAfterRestart(bob, realm)).toBeTruthy();
      expect((await client.retainedMessage(bob, third.eventId)).commit.commit_id).toBe(third.commitId);
    }


  } finally {
    await client.dispose();
  }
});

// Independent host accepted-before-persist cut; not the issuer response-loss suite.
test("accepted registration survives whole-process loss before host persistence @fully-implemented @garth-runtime @provisioning-cold", async () => {
  test.setTimeout(180_000);
  expect(coauthBaseUrl(), "canonical accepted custody requires Coauth").toBeTruthy();
  expect(coauthOidcClientId(), "canonical accepted custody requires OIDC").toBeTruthy();
  const endpoints = { coauthBaseUrl: coauthBaseUrl()!, colandBaseUrl: colandBaseUrl(), mockEmailBaseUrl: mockEmailBaseUrl() };
  let bridge = ProvisioningBridge.start();
  try {
    const session = await bridge.custodySession();
    // A valid but absent run-owned address must fail closed, never create a replacement store.
    const absent = ProvisioningBridge.start(`ak:request:01904100-0000-7000-8000-${newDeviceId().slice(-12)}`);
    try { await expect(absent.custodySession()).rejects.toThrow("cotest-provision exited"); }
    finally { await absent.dispose(); }
    const station = await bridge.describeStation(endpoints);
    const handle = `cold-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    await bridge.provisionUnboundAccount(endpoints, { handle, password: "1amTester!" });
    const handoff = await bridge.createAccountHandoff({ coauthBaseUrl: endpoints.coauthBaseUrl,
      clientId: coauthOidcClientId()!, audienceId: station.serviceId, deviceLabel: handle });
    const accepted = await bridge.acceptBeforePersist({ handoffId: handoff.handoffId, endpoints,
      trustDomain: station.trustDomain, audienceId: station.serviceId,
      deviceId: newDeviceId(), displayName: "Host persistence loss" });
    const before = await bridge.registrationCustody(handoff.handoffId);
    expect(before.requestDigest).toMatch(/^[a-f0-9]{64}$/);
    expect(before.acceptedPersisted, "accepted outcome has not entered host custody at the cut").toBe(false);
    expect(accepted.pid).toBe(session.pid);
    await bridge.kill();
    bridge = ProvisioningBridge.start(session.sessionId);
    const reopened = await bridge.custodySession();
    expect(reopened.sessionId).toBe(session.sessionId);
    expect(reopened.pid).not.toBe(session.pid);
    const diskBefore = await bridge.registrationCustody(handoff.handoffId);
    expect(diskBefore).toEqual(before);
    const recovered = await bridge.recoverPrincipal(handoff.handoffId);
    expect(recovered.principal_id).toBe(accepted.outcome.principal_id);
    expect(isDeepStrictEqual(recovered.binding_receipt, accepted.outcome.binding_receipt),
      "recovery retains the complete original binding receipt").toBe(true);
    expect(isDeepStrictEqual(recovered.pcr_genesis_commits, accepted.outcome.pcr_genesis_commits),
      "recovery retains the complete original PCR Commit receipts").toBe(true);
    expect(isDeepStrictEqual(recovered.accepted_outcome, accepted.outcome), "exact replay returns the original complete receipt/grant/PCR outcome").toBe(true);
    expect(await bridge.registrationCustody(handoff.handoffId)).toEqual({ requestDigest: before.requestDigest, acceptedPersisted: true });
    const replay = await bridge.recoverPrincipal(handoff.handoffId);
    expect(isDeepStrictEqual(replay, recovered), "repeat recovery returns the exact original complete outcome").toBe(true);
    expect((await bridge.readSelfAccountViewer({ handoffId: handoff.handoffId, colandBaseUrl: endpoints.colandBaseUrl })).status).toBe(200);
    const opened = await bridge.openGarthClient({ handoffId: handoff.handoffId,
      colandBaseUrl: endpoints.colandBaseUrl, accountId: recovered.account_id as { principal_id: string; station_id: string },
      deviceId: String(recovered.device_id) });
    expect(opened.identityRestoredFromDisk).toBe(true);
    // No generated replacement handoff, account, session holder or registration window.
    expect((await bridge.garthSyncAccount({ handoffId: handoff.handoffId })).cursor).toBeTruthy();
  } finally {
    await bridge.dispose();
  }
});
