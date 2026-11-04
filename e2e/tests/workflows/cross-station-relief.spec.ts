// Contract: e2e/scenarios/workflows/cross-station-relief.md
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { expect, test, type Page } from "../../helpers/arkret-test";
import { accountActorId, assertAuthoritySubmitOutcome, canonicalJson, sdkEventDerivedObjectId, wireErrCode } from "../../helpers/coland-api";
import { decodeIngressEvents, type IngressEvent } from "../../helpers/event-ingress";
import { colandServiceId, configuredServerCount, type ColandKey } from "../../helpers/env";
import { prepareBrowserNetworkOutage } from "../../helpers/browser-network-outage";
import { openRegisteredUserPage } from "../../helpers/users";
import { uint64Decimal } from "../../helpers/uint64-decimal";
import { submitOrdinaryComposerDraft } from "../../helpers/composer-handoff";

test.use({ trace: "off", video: "off", screenshot: "off" });

type Flow = Awaited<ReturnType<typeof openRegisteredUserPage>> & { server: ColandKey };
type Cut = { members: Set<string>; covered: boolean; epoch: string; revision: string };

async function admitted(page: Page, kind: string, realm: string, action: () => Promise<unknown>) {
  const pending = page.waitForResponse(response => response.request().method() === "POST"
    && new URL(response.url()).pathname === "/_arkret/self/events"
    && decodeIngressEvents(response.request().postData()).some(event => event.kind === kind && event.realm_id === realm),
  { timeout: 240_000 });
  const [response] = await Promise.all([pending, action()]);
  const outcome = await response.json();
  expect(response.status(), `${kind} refusal=${wireErrCode(outcome) || "none"}`).toBe(200);
  expect(outcome.status).toBe("committed");
  const event = decodeIngressEvents(response.request().postData()).find(event => event.kind === kind && event.realm_id === realm)!;
  assertAuthoritySubmitOutcome(outcome, event, `cross-station relief ${kind}`);
  return event;
}

async function delivered(author: Flow, readers: Flow[], realm: string, text: string) {
  const event = await admitted(author.page.page, "ak.message.create", realm, () => author.page.sendTimelineMessage(realm, text));
  expect(JSON.stringify(event).includes(text), "project content stays encrypted on ingress").toBe(false);
  for (const reader of readers) await expect(reader.page.page.locator(".chat-message").filter({ hasText: text }), `${reader.server} decrypts the accepted report exactly once`).toHaveCount(1, { timeout: 120_000 });
  return event;
}

async function grantWriting(manager: Flow, member: Flow, realm: string): Promise<string> {
  const page = manager.page.page;
  await manager.page.gotoRealmAdminSection(realm, "security");
  await page.locator(".advanced-access-toggle").click();
  await page.locator(".cap-grant-tag-input input").fill("ak.message.create");
  await page.locator(".cap-grant-subject-input input").fill(canonicalJson({ principal_id: member.user.id, station_id: colandServiceId(member.server) }));
  const event = await admitted(page, "ak.capability.grant", realm, () => page.locator(".cap-grant-submit-button").click());
  expect(event.payload?.grant).toMatchObject({ subject: accountActorId(member.user.id, member.server), actions: ["ak.message.create"] });
  await expect(page.locator(".realm-settings-content > .write-status")).toContainText("Permission granted. Grant ID:", { timeout: 120_000 });
  return sdkEventDerivedObjectId(event);
}

test("three Stations deliver relief supplies through offline replay, revoked writes and member departure @cross-station-relief-gate", async ({ browser, request }, testInfo) => {
  test.setTimeout(1_800_000);
  expect(configuredServerCount(), "this project requires three independently configured Stations").toBeGreaterThanOrEqual(3);
  expect(new Set(["server1", "server2", "server3"].map(server => colandServiceId(server as ColandKey))).size).toBe(3);
  const stamp = Date.now();
  const flows: Flow[] = [];
  const phases: Array<{ phase: string; completed_at: string }> = [];
  const cuts = new Map<string, Cut>();
  const bobMessages: Array<{ event_id: string; digest: string }> = [];
  const failures: Array<{ method: string; path: string; status: number; code?: string }> = [];
  const transports = new Map<ColandKey, Awaited<ReturnType<typeof prepareBrowserNetworkOutage>>>();
  let outage: Awaited<ReturnType<typeof prepareBrowserNetworkOutage>> | undefined;
  let releaseHeld: ((forward: boolean) => void) | undefined;
  let realm: string | undefined;
  let twoMemberEpoch: string | undefined;
  const checkpoint = (phase: string) => {
    phases.push({ phase, completed_at: new Date().toISOString() });
    writeFileSync(testInfo.outputPath("relief-progress.json"), JSON.stringify({ realm, phases }, null, 2));
  };
  checkpoint("project started");
  try {
    for (const [index, role] of ["coordinator", "logistics", "auditor"].entries()) {
      const server = `server${index + 1}` as ColandKey;
      const flow = await openRegisteredUserPage(browser, request, `relief-${role}`, {
        server,
        beforeNavigate: async page => {
          const transport = await prepareBrowserNetworkOutage(page);
          transports.set(server, transport);
          if (index === 1) outage = transport;
          page.on("response", async response => {
            const path = new URL(response.url()).pathname;
            if (path.startsWith("/_arkret/") && response.status() >= 400) failures.push({ method: response.request().method(), path, status: response.status(), code: wireErrCode(await response.json().catch(() => undefined)) });
            if (index !== 0 || path !== "/_arkret/self/realm-state-snapshot/head" || response.status() !== 200) return;
            const body = await response.json().catch(() => undefined);
            const entries = body?.current_state_entries;
            if (!Array.isArray(entries)) return;
            const target = new URL(response.url()).searchParams.get("realm_id");
            const mls = entries.find(entry => entry.selector?.kind === "mls_group" && entry.selector.scope_ref?.kind === "realm" && entry.selector.scope_ref.realm_id === target)?.value;
            if (target && mls) cuts.set(target, {
              members: new Set(entries.filter(entry => entry.selector?.kind === "member_state" && entry.value?.membership === "join").map(entry => canonicalJson(entry.selector.actor_id))),
              covered: typeof mls.current_key_access_revision === "string" && mls.current_key_access_revision === mls.covered_key_access_revision,
              epoch: uint64Decimal(mls.epoch), revision: mls.current_key_access_revision,
            });
          });
          if (index === 1) page.on("request", request => {
            if (request.method() !== "POST" || new URL(request.url()).pathname !== "/_arkret/self/events") return;
            for (const event of decodeIngressEvents(request.postData())) if (event.kind === "ak.message.create") bobMessages.push({ event_id: String(event.event_id), digest: createHash("sha256").update(canonicalJson(event)).digest("hex") });
          });
        },
      });
      flows.push({ ...flow, server });
    }
    const [alice, bob, carol] = flows;
    checkpoint("three browser-owned identities registered at three distinct Stations");
    realm = await alice.page.createRealm({ title: `Relief supply operation ${stamp}`, summary: "Coordination, logistics and audit collaborate across three independent Stations.", joinRule: "invite", mlsActivated: true });
    await alice.page.gotoRealmAdminSection(realm, "access");
    const panel = alice.page.page.locator(".realm-invite-links");
    await panel.getByLabel("Maximum different accounts", { exact: true }).fill("2");
    await panel.getByRole("button", { name: "Prepare invitation", exact: true }).click();
    await expect(panel.locator(".realm-invite-link-message")).toContainText("prepared locally");
    await panel.getByRole("button", { name: "Publish / retry same invitation", exact: true }).click();
    const shared = panel.locator("textarea.realm-invite-link-share");
    await expect(shared).toBeVisible({ timeout: 90_000 });
    await expect.poll(async () => (await shared.inputValue()).includes("lt=invite"), { timeout: 90_000 }).toBe(true);
    const link = await shared.inputValue();
    for (const member of [bob, carol]) {
      await member.page.page.goto("/realms/manage");
      const join = member.page.page.locator(".realm-invite-links");
      await join.getByLabel("Paste invitation link after signing in", { exact: true }).fill(link);
      await join.locator(".realm-invite-link-confirm").click();
      await expect(join.locator(".realm-invite-link-message")).toContainText("Joined. Membership is accepted", { timeout: 120_000 });
      if (member === bob) {
        await outage!.disconnect();
        await alice.page.gotoTimelineRealm(realm);
        await expect.poll(() => {
          const cut = cuts.get(realm!);
          return cut?.covered && cut.members.size === 2;
        }, { timeout: 180_000 }).toBe(true);
        twoMemberEpoch = cuts.get(realm)!.epoch;
        checkpoint("logistics disconnects after joining while the coordinator covers the two-member MLS group");
      }
    }
    checkpoint("two remote members join through their own Stations using the limited invitation");
    const bobGrant = await grantWriting(alice, bob, realm);
    await grantWriting(alice, carol, realm);
    for (const flow of [alice, carol]) await flow.page.gotoTimelineRealm(realm);
    await expect.poll(() => {
      const cut = cuts.get(realm!);
      return cut?.covered && BigInt(cut.epoch) > BigInt(twoMemberEpoch!)
        && flows.every(flow => cut.members.has(canonicalJson(accountActorId(flow.user.id, flow.server))));
    }, { timeout: 180_000 }).toBe(true);
    const initialCut = cuts.get(realm)!;
    await outage!.reconnect();
    await bob.page.gotoTimelineRealm(realm);
    const kickoff = `Relief approved: 120 water packs, three trucks and an audited delivery window. ${stamp}`;
    const kickoffEvent = await delivered(alice, flows, realm, kickoff);
    await expect.poll(() => transports.get("server3")!.hasReceivedEvent(String(kickoffEvent.event_id)), { timeout: 120_000,
      message: "the departed-Station transport observer must first observe a real authorized project Event" }).toBe(true);
    await delivered(bob, flows, realm, `Logistics confirms three trucks and driver assignments. ${stamp}`);
    await delivered(carol, flows, realm, `Audit confirms the sealed supply manifest. ${stamp}`);
    checkpoint("all three Stations exchange and decrypt encrypted project reports");

    const beforeOffline = bobMessages.length;
    const queued = `Offline logistics report: truck 2 loaded and awaiting dispatch. ${stamp}`;
    const missed = `Coordinator update during logistics outage: use gate B. ${stamp}`;
    const offlineEvent = await admitted(bob.page.page, "ak.message.create", realm, async () => {
      const retiredBefore = outage!.stats().retired_sockets;
      await outage!.disconnect();
      expect(outage!.stats().retired_sockets, "this outage retires its established WebSockets too").toBeGreaterThan(retiredBefore);
      await bob.page.page.bringToFront();
      await bob.page.page.locator(".chat-input").fill(queued);
      await submitOrdinaryComposerDraft(bob.page.page, queued);
      await expect(bob.page.page.locator(".chat-input")).toHaveValue("");
      await expect(bob.page.page.locator(".chat-outbox-count")).toHaveText("1", { timeout: 60_000 });
      await delivered(alice, [alice, carol], realm!, missed);
      await expect(bob.page.page.locator(".chat-message").filter({ hasText: missed })).toHaveCount(0);
      await expect(alice.page.page.locator(".chat-message").filter({ hasText: queued })).toHaveCount(0);
      await expect(carol.page.page.locator(".chat-message").filter({ hasText: queued })).toHaveCount(0);
      checkpoint("logistics queues one durable report offline and misses an accepted remote update");
      await outage!.reconnect();
    });
    expect(JSON.stringify(offlineEvent).includes(queued)).toBe(false);
    for (const reader of flows) await expect(reader.page.page.locator(".chat-message").filter({ hasText: queued })).toHaveCount(1, { timeout: 120_000 });
    await bob.page.waitForTimelineEventSettled(queued, 120_000);
    await expect(bob.page.page.locator(".chat-outbox-count")).toHaveCount(0, { timeout: 120_000 });
    await expect(bob.page.page.locator(".chat-message").filter({ hasText: missed })).toHaveCount(1, { timeout: 120_000 });
    await outage!.disconnect();
    await outage!.reconnect();
    await bob.page.page.reload({ waitUntil: "domcontentloaded" });
    await bob.page.expectTimelineEventVisible(queued, 120_000);
    await expect(bob.page.page.locator(".chat-message").filter({ hasText: queued })).toHaveCount(1);
    expect(new Set(bobMessages.slice(beforeOffline).map(event => event.event_id))).toEqual(new Set([String(offlineEvent.event_id)]));
    expect(new Set(bobMessages.slice(beforeOffline).map(event => event.digest)).size, "retries keep the exact signed Event bytes").toBe(1);
    checkpoint("reconnect catches up and accepts the original queued Event once; another reconnect and reload do not duplicate it");

    let heldEvent: IngressEvent | undefined;
    let captureHeld!: () => void;
    const captured = new Promise<void>(resolve => { captureHeld = resolve; });
    const held = new Promise<boolean>(resolve => { releaseHeld = resolve; });
    let armed = true;
    await bob.page.page.route(url => url.pathname === "/_arkret/self/events", async route => {
      const event = decodeIngressEvents(route.request().postData()).find(event => event.kind === "ak.message.create" && event.realm_id === realm);
      if (!armed || !event) { await route.continue(); return; }
      armed = false; heldEvent = event; captureHeld();
      if (await held) await route.continue(); else await route.abort("aborted");
    });
    const forbiddenReport = `Revoked dispatch instruction must never be accepted. ${stamp}`;
    await bob.page.page.bringToFront();
    await expect(bob.page.page.locator(".send-chat-button")).toBeEnabled({ timeout: 120_000 });
    await bob.page.page.locator(".chat-input").fill(forbiddenReport);
    await submitOrdinaryComposerDraft(bob.page.page, forbiddenReport);
    await expect.poll(() => heldEvent !== undefined, { timeout: 120_000 }).toBe(true);
    await captured;
    expect(JSON.stringify(heldEvent).includes(forbiddenReport)).toBe(false);
    await alice.page.gotoRealmAdminSection(realm, "security");
    await alice.page.page.locator(".advanced-access-toggle").click();
    await alice.page.page.locator(".cap-grant-id-input input").fill(bobGrant);
    await alice.page.page.locator(".cap-grant-subject-input input").fill(canonicalJson({ principal_id: bob.user.id, station_id: colandServiceId("server2") }));
    const revoked = await admitted(alice.page.page, "ak.capability.revoke", realm, () => alice.page.page.locator(".cap-revoke-submit-button").click());
    expect(revoked.payload?.grant_id).toBe(bobGrant);
    const refusal = bob.page.page.waitForResponse(response => response.request().method() === "POST"
      && new URL(response.url()).pathname === "/_arkret/self/events"
      && decodeIngressEvents(response.request().postData()).some(event => event.event_id === heldEvent!.event_id), { timeout: 120_000 });
    releaseHeld!(true);
    const denied = await refusal;
    expect(denied.status()).toBe(403);
    expect(wireErrCode(await denied.json())).toBe("capability_denied");
    await alice.page.gotoTimelineRealm(realm);
    const afterRevoke = `Coordinator publishes the final route; logistics now has read-only access. ${stamp}`;
    await delivered(alice, flows, realm, afterRevoke);
    for (const reader of [alice, carol]) await expect(reader.page.page.locator(".chat-message").filter({ hasText: forbiddenReport })).toHaveCount(0);
    await expect(bob.page.page.locator(".chat-message.is-canonical-message").filter({ hasText: forbiddenReport })).toHaveCount(0);
    expect(cuts.get(realm)!.members.size, "revoking writing does not remove membership or reading access").toBe(3);
    checkpoint("the authority rejects a real pre-signed delayed write after capability revocation while logistics keeps reading");

    await carol.page.gotoRealmAdminSection(realm, "repair");
    const left = await admitted(carol.page.page, "ak.member.state", realm, async () => {
      await carol.page.page.locator(".leave-realm-button").click();
      await carol.page.page.locator(".leave-realm-confirm-button").click();
    });
    expect(left.payload).toMatchObject({ member_id: accountActorId(carol.user.id, "server3"), membership: "leave" });
    await expect(carol.page.page.locator(".realm-settings-content > .write-status")).toContainText(/^left /, { timeout: 120_000 });
    await alice.page.gotoTimelineRealm(realm);
    await expect.poll(() => {
      const cut = cuts.get(realm!);
      return cut?.covered && cut.members.size === 2
        && !cut.members.has(canonicalJson(accountActorId(carol.user.id, "server3")))
        && BigInt(cut.epoch) > BigInt(initialCut.epoch) && cut.revision !== initialCut.revision;
    }, { timeout: 180_000 }).toBe(true);
    const final = `Relief operation completed after auditor departure; remaining Stations retain authorized access. ${stamp}`;
    const finalEvent = await delivered(alice, [alice, bob], realm, final);
    checkpoint("auditor leaves through Station three; remaining members cover the new membership with a later MLS epoch and continue delivery");
    for (const member of [alice, bob]) {
      await member.page.page.reload({ waitUntil: "domcontentloaded" });
      for (const body of [kickoff, queued, missed, afterRevoke, final]) await expect(member.page.page.locator(".chat-message").filter({ hasText: body })).toHaveCount(1, { timeout: 120_000 });
      await expect(member.page.page.locator(".chat-message.is-canonical-message").filter({ hasText: forbiddenReport })).toHaveCount(0);
    }
    await carol.page.page.goto(`/chat/${encodeURIComponent(realm)}`);
    await carol.page.page.reload({ waitUntil: "domcontentloaded" });
    await expect(carol.page.page.locator(".shell.app")).toBeVisible({ timeout: 120_000 });
    await expect(carol.page.page.locator(".connection-status .sync-cursor")).toContainText("ak:cursor:", { timeout: 120_000 });
    await expect(carol.page.page.locator(".send-chat-button:enabled")).toHaveCount(0);
    await expect(carol.page.page.locator(".chat-message").filter({ hasText: final })).toHaveCount(0);
    expect(transports.get("server3")!.hasReceivedEvent(String(finalEvent.event_id)), "the departed Station's client receives no post-leave Event, even as undecryptable ciphertext").toBe(false);
    writeFileSync(testInfo.outputPath("relief-security.json"), JSON.stringify({ denied_event_id: heldEvent!.event_id, denied_status: denied.status(), denied_code: "capability_denied", initial_epoch: initialCut.epoch, final_epoch: cuts.get(realm)!.epoch, departed_received_post_leave_event: false, outage: outage!.stats() }, null, 2));
    checkpoint("cold readers retain accepted history exactly once, rejected content stays absent, and the departed member cannot send or see post-leave content");
  } catch (error) {
    for (const flow of flows) {
      try {
        writeFileSync(testInfo.outputPath(`relief-ui-${flow.server}.json`), JSON.stringify({
          path: new URL(flow.page.page.url()).pathname,
          status: await flow.page.page.locator(".chat-status, .chat-compose-status, .write-status, .chat-outbox-count, .chat-message-error").allTextContents(),
          send_buttons: await flow.page.page.locator(".send-chat-button").evaluateAll(nodes => nodes.map(node => ({ disabled: (node as HTMLButtonElement).disabled }))),
          connection: await flow.page.page.locator(".connection-status .status-label").allTextContents(),
          convergence: await flow.page.page.locator(".connection-status .last-error, .epoch-update-required-banner").allTextContents(),
          message_states: await flow.page.page.locator(".chat-message-row").evaluateAll(nodes => nodes.map(node => ({ id: node.id, class: node.className }))),
        }, null, 2));
      } catch { /* Preserve the original business failure when a page has closed. */ }
    }
    throw error;
  } finally {
    releaseHeld?.(false);
    await outage?.reconnect().catch(() => {});
    writeFileSync(testInfo.outputPath("relief-response-failures.json"), JSON.stringify(failures, null, 2));
    await testInfo.attach("relief-progress", { path: testInfo.outputPath("relief-progress.json"), contentType: "application/json" }).catch(() => {});
    await Promise.allSettled(flows.map(flow => flow.page.close()));
  }
});
