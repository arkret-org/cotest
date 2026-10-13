// A normal member confirms a narrow owned source through Inkson, without an
// admin granting capability-management actions or a runtime pairing prerequisite.
import { test, expect } from "../../helpers/joint-fixture";
import type { Page, Locator, APIRequestContext } from "../../helpers/arkret-test";
import { coauthBaseUrl, colandBaseUrl, mockEmailBaseUrl } from "../../helpers/env";
import { grantInviteConsentArkret, deliverInviteWithConsentGrant } from "../../helpers/contact-api";
import { assertAuthoritySubmitOutcome, buildCapabilityGrantEnvelope, canonicalJson, grantCapabilityEventApi, rawSubmitSignedEventApi, refreshEventEnvelopeProof, resolveDefaultStrandId, retypeEventDerivedId, signedEventEnvelope, wireErrCode } from "../../helpers/coland-api";
import { addCircleMemberRaw, createCircleArkret } from "../../helpers/circle-api";
import { decodeIngressEvents } from "../../helpers/event-ingress";
import { openDpopUserPageFromSession, registeredSubjectIdentityControl, selfPathHeadersForDpopSession, type DpopUserSession, type JointUserPage } from "../../helpers/users";
import { createHash } from "node:crypto";
import { ProvisioningBridge } from "../../helpers/provisioning-bridge";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { readFile } from "node:fs/promises";

test.use({ trace: "off", screenshot: "off", video: "off" });
test.setTimeout(720_000);

type Footprint = { tables: Record<string, { count: number; sha256: string }>;
  candidate_absence?: Record<string, number> };

async function footprint(realm: string, station: string, candidate?: string): Promise<Footprint> {
  const topology = JSON.parse(await readFile(process.env.COTEST_TOPOLOGY_PATH!, "utf8"));
  const servers = topology.servers.filter((s: { coland: { service_id: string } }) => s.coland.service_id === station);
  expect(servers).toHaveLength(1);
  const script = fileURLToPath(new URL("../../../scripts/realm-business-footprint.py", import.meta.url));
  const args = [script, "--server", servers[0].name, "--realm", realm];
  if (candidate) args.push("--candidate-event", candidate);
  const { stdout } = await promisify(execFile)("python3", args, { timeout: 45_000, maxBuffer: 1_048_576 });
  return JSON.parse(stdout) as Footprint;
}

async function rejectedWithoutEffects(bridge: ProvisioningBridge, runtime: string, realm: string, strand: string, station: string) {
  const event = await bridge.prepareAgentMessage({ runtimeId: runtime, realmId: realm, strandId: strand,
    text: "revoked owned source must not commit this original Agent intent" });
  expect(event).toMatch(/^ak:event:/);
  const before = await footprint(realm, station, event);
  expect(Object.values(before.candidate_absence!)).toEqual([0, 0, 0, 0, 0, 0]);
  const result = await bridge.submitAgentMessage(runtime, event);
  expect(result.eventId).toBe(event);
  expect(result.accepted).toBe(false);
  expect(result.registeredCode).toBe("capability_denied");
  // A typed HTTP refusal carries its original status; a registered wire
  // Rejected outcome carries its reason code rather than an invented status.
  if (result.httpStatus !== undefined) expect(result.httpStatus).toBe(403);
  const after = await footprint(realm, station, event);
  expect(after.tables).toEqual(before.tables);
  expect(Object.values(after.candidate_absence!)).toEqual([0, 0, 0, 0, 0, 0]);
}

async function provisionOwnedAgent(user: JointUserPage): Promise<string> {
  const page = user.page;
  await user.gotoSettings();
  await page.getByTestId("settings-nav-item-agents").click();
  await expect(page.getByTestId("agent-admin")).toBeVisible();
  await page.getByTestId("agent-admin-create-open-button").click();
  await page.getByTestId("agent-admin-provision-agent-slug").fill(`owned-member-${Date.now().toString(36)}`);
  const committed = page.waitForResponse(response => {
    const request = response.request();
    return response.status() === 201 && request.method() === "POST"
      && new URL(response.url()).pathname === "/_arkret/self/agents"
      && request.postDataJSON()?.phase === "commit";
  }, { timeout: 180_000 });
  await page.getByTestId("agent-admin-provision-button").click();
  // This response also carries private pairing material. Retain only the public
  // principal locator and never attach/dump its body or pairing code.
  const agent = (await (await committed).json()).agent_id;
  expect(typeof agent).toBe("string");
  expect(agent).toMatch(/^ak:did_core:/);
  return agent;
}

async function members(page: Page, realm: string, agent: string): Promise<Locator> {
  await page.goto(`/realms/${realm}/members`, { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("realm-members-panel")).toBeVisible({ timeout: 120_000 });
  await page.getByTestId("members-section-my-agents").click();
  return page.locator(`[data-testid="member-self-agent-row"][data-agent-id="${agent}"]`);
}

async function confirm(page: Page, panel: Locator, realm: string, account: unknown, agent: unknown, strand: string): Promise<string> {
  await panel.getByTestId("owned-agent-scope").selectOption(strand);
  await panel.getByRole("checkbox", { name: "发送消息", exact: true }).check();
  const published = page.waitForResponse(response => {
    const request = response.request();
    if (request.method() !== "POST" || new URL(response.url()).pathname !== "/_arkret/self/events") return false;
    return decodeIngressEvents(request.postData()).some(event => event.realm_id === realm && event.kind === "ak.capability.grant");
  }, { timeout: 180_000 });
  await panel.getByTestId("owned-agent-confirm-authority").click();
  const response = await published;
  expect(response.ok()).toBe(true);
  const event = decodeIngressEvents(response.request().postData()).find(event => event.kind === "ak.capability.grant")!;
  expect(event.actor_id).toEqual({ kind: "account", account_id: account });
  const grant = event.payload!.grant as Record<string, unknown>;
  expect(grant.subject).toEqual({ kind: "account", account_id: agent });
  expect(grant.actions).toEqual(["ak.message.create"]);
  expect(grant.resources).toEqual([{ kind: "strand", realm_id: realm, strand_id: strand }]);
  const sources = grant.issuer_authority_refs as Array<Record<string, unknown>>;
  expect(sources).toHaveLength(1);
  expect(sources[0].kind).toBe("owned_agent");
  expect(sources[0].controller_account_id).toEqual(account);
  expect(sources[0].controller_join_event_id).toMatch(/^ak:event:/);
  expect(sources[0].agent_join_event_id).toMatch(/^ak:event:/);
  expect(sources[0].controller_join_event_id).not.toBe(sources[0].agent_join_event_id);
  const id = retypeEventDerivedId(event.event_id!, "grant");
  await expect(panel.locator(`[data-testid="owned-agent-accepted-grant"][data-grant-id="${id}"]`))
    .toContainText("Active", { timeout: 180_000 });
  return id;
}

test("ordinary member explicitly grants, withdraws cold and confirms a new owned Agent source @fully-implemented @owned-agent-authority", async ({ jointRealm, request }) => {
  expect(coauthBaseUrl(), "canonical Coauth founding is required").toBeTruthy();
  expect(mockEmailBaseUrl(), "canonical founding verification delivery is required").toBeTruthy();
  const realm = jointRealm.realmId;
  const consent = await grantInviteConsentArkret(request, jointRealm.bobToken, jointRealm.bob, jointRealm.alice.id);
  const delivery = await deliverInviteWithConsentGrant(request, {
    inviterId: jointRealm.alice.id, inviterToken: jointRealm.aliceToken, realmId: realm,
    inviteeId: jointRealm.bob.id, consentGrantRef: consent.eventRef,
    originServer: "server1", recipientServer: "server1",
  });
  expect(delivery.outcome.disclosed_outcome).toBe("delivered");
  await jointRealm.bobPage.acceptInvite(realm);
  const strand = await resolveDefaultStrandId(request, jointRealm.aliceToken, realm);
  // Only the underlying content action is granted to Bob. The dedicated owned
  // source must work even though ordinary grant/revoke/admin authority is denied.
  await grantCapabilityEventApi(request, jointRealm.aliceToken, {
    ownerId: jointRealm.alice.id, subjectId: jointRealm.bob.id,
    realmId: realm, actions: ["ak.message.create"],
  });
  const url = `${colandBaseUrl()}/_arkret/self/authz/check`;
  for (const action of ["ak.capability.grant", "ak.capability.revoke", "ak.realm.admin"]) {
    const response = await request.post(url, {
      headers: { ...selfPathHeadersForDpopSession(jointRealm.bobSession, "POST", url), "content-type": "application/json" },
      data: canonicalJson({ actor_id: { kind: "account", account_id: jointRealm.bobSession.accountId }, action,
        resource: { kind: "realm", realm_id: realm }, context: null }),
    });
    expect(response.status()).toBe(200);
    expect((await response.json()).decision).toBe("hard_deny");
  }
  await jointRealm.bobPage.sendTimelineMessage(realm, "ordinary controller content before Agent confirmation");
  const bob = jointRealm.bobPage.page;
  const agentId = await provisionOwnedAgent(jointRealm.bobPage);
  const row = await members(bob, realm, agentId);
  await bob.getByTestId("open-add-realm-agent-modal-button").click();
  const available = bob.locator(`[data-testid="available-realm-agent-row"][data-agent-id="${agentId}"]`);
  await expect(available).toBeVisible({ timeout: 120_000 });
  await available.getByTestId("confirm-add-agent-to-realm").click();
  await expect(row).toBeVisible({ timeout: 180_000 });
  const panel = row.getByTestId("member-agent-authority");
  await expect(panel).toBeVisible({ timeout: 180_000 });
  // The roster row already existed before Add. Re-read the two accepted join
  // generations through the normal control before asserting confirmation UI.
  await expect(async () => {
    const confirmButton = panel.getByTestId("owned-agent-confirm-authority");
    if (!await confirmButton.isVisible()) {
      const refresh = panel.getByRole("button", { name: "刷新当前权限与管理限制", exact: true });
      if (await refresh.isEnabled()) await refresh.click();
    }
    await expect(confirmButton).toBeVisible({ timeout: 1_000 });
  }).toPass({ timeout: 120_000, intervals: [1_000, 2_000, 5_000] }).catch(async error => {
    const status = await panel.getByTestId("owned-agent-authority-status").textContent().catch(() => null);
    const safeStatus = status && !/Bearer|eyJ[A-Za-z0-9_-]{20}|recovery.key|private.key/i.test(status)
      ? status.slice(0, 1_000) : "status unavailable";
    await test.info().attach("owned-agent-authority-join-status", {
      body: Buffer.from(JSON.stringify({ status: safeStatus })), contentType: "application/json",
    });
    throw error;
  });
  await expect(panel.getByTestId("owned-agent-confirm-authority")).toBeDisabled();
  await expect(panel.getByRole("checkbox", { name: "发送消息", exact: true })).not.toBeChecked();
  const agentAccount = { principal_id: agentId, station_id: jointRealm.bobSession.accountId.station_id };
  const first = await confirm(bob, panel, realm, jointRealm.bobSession.accountId, agentAccount, strand);
  await expect(panel.locator(`[data-grant-id="${first}"]`)).toContainText("当前权限/管理预检允许（运行时仍需验收）", { timeout: 120_000 });
  // Preflight is separately labelled. Only a real paired Agent's signed
  // accepted Message and exact read-back prove the business action below.
  await expect(panel.locator(`[data-grant-id="${first}"]`)).not.toContainText(/未确认|基础权限|不可达/, { timeout: 120_000 });
  await row.getByTestId("member-agent-interaction-mode").getByRole("button", { name: /^(公开|Public)$/ }).click();
  const reply = row.getByTestId("member-agent-reply-toggle");
  if (await reply.getAttribute("aria-checked") !== "true") await reply.click();
  await expect(reply).toHaveAttribute("aria-checked", "true", { timeout: 120_000 });
  const bridge = ProvisioningBridge.start();
  try {
    const session = jointRealm.bobSession;
    const runtime = await bridge.pairAgentRuntime({
      endpoints: { colandBaseUrl: colandBaseUrl(), coauthBaseUrl: coauthBaseUrl()! },
      controllerAccountId: session.accountId, controllerGrant: session.grantJwt,
      controllerHolderSeed: session.dpopSeedB64url, controllerEventSeed: session.eventSigningSeedB64url,
      controllerVerificationMethod: `${session.user.did}#${session.user.deviceId}`,
      agentId, realmId: realm, strandId: strand,
    });
    expect(runtime.authorizationEventId).toMatch(/^ak:event:/);
    const authored = await bridge.prepareAgentMessage({ runtimeId: runtime.runtimeId, realmId: realm, strandId: strand,
      text: "real Agent signs and commits using the explicitly confirmed narrow owned source" });
    const accepted = await bridge.submitAgentMessage(runtime.runtimeId, authored);
    expect(accepted.accepted).toBe(true);
    expect(accepted.eventId).toBe(authored);
    expect(accepted.commitId).toMatch(/^ak:realm_commit:/);
    await bob.reload({ waitUntil: "domcontentloaded" });
    await members(bob, realm, agentId);
    const ledger = bob.getByTestId("owned-agent-withdrawal-ledger");
    const retained = ledger.locator(`[data-grant-id="${first}"]`);
    await expect(retained).toContainText("Active", { timeout: 120_000 });
    await retained.getByTestId("owned-agent-withdraw-retained").click();
    await expect(retained).toContainText("Revoked", { timeout: 180_000 });
    await expect(retained.getByTestId("owned-agent-withdraw-retained")).toHaveCount(0);
    await rejectedWithoutEffects(bridge, runtime.runtimeId, realm, strand, session.accountId.station_id);
    const currentPanel = (await members(bob, realm, agentId)).getByTestId("member-agent-authority");
    await expect(currentPanel.getByTestId("owned-agent-confirm-authority")).toBeDisabled();
    const second = await confirm(bob, currentPanel, realm, jointRealm.bobSession.accountId, agentAccount, strand);
    expect(second).not.toBe(first);
    await expect(currentPanel.locator(`[data-grant-id="${first}"]`)).toContainText("Revoked");
    await expect(currentPanel.locator(`[data-grant-id="${second}"]`)).toContainText("Active");
    const renewed = await bridge.prepareAgentMessage({ runtimeId: runtime.runtimeId, realmId: realm, strandId: strand,
      text: "new explicit owned confirmation authorizes a new Agent message" });
    expect((await bridge.submitAgentMessage(runtime.runtimeId, renewed)).accepted).toBe(true);
    // Departure must not hide the dedicated original-issuer withdrawal, even
    // though the ordinary snapshot/Agent roster read gate now refuses access.
    await bob.getByTestId("members-section-members").click();
    await expect(bob.getByTestId("member-row-leave-button")).toHaveCount(1);
    await bob.getByTestId("member-row-leave-button").click();
    await members(bob, realm, agentId);
    const departed = bob.getByTestId("owned-agent-withdrawal-ledger").locator(`[data-grant-id="${second}"]`);
    await expect(departed).toContainText("Active", { timeout: 120_000 });
    await departed.getByTestId("owned-agent-withdraw-retained").click();
    await expect(departed).toContainText("Revoked", { timeout: 180_000 });
    await rejectedWithoutEffects(bridge, runtime.runtimeId, realm, strand, session.accountId.station_id);
  } finally {
    await bridge.dispose();
  }
});

// Configuration acceptance is separate from business effectiveness. These
// scenarios use the mounted administrator editor and its original SDK author;
// the signed HTTP negatives below retain the same registered Event contract.
const managementOperations = ["join", "authorize", "execute", "read", "deliver", "publish", "serve"] as const;

async function policyEditor(user: JointUserPage, realm: string): Promise<Locator> {
  await user.gotoRealmAdminSection(realm, "access");
  const editor = user.page.getByTestId("agent-policy-editor");
  await expect(editor).toBeVisible({ timeout: 120_000 });
  return editor;
}

async function loadPolicyEditor(user: JointUserPage, realm: string, id?: string): Promise<Locator> {
  const editor = await policyEditor(user, realm);
  if (id) await editor.getByLabel("Exact Policy id", { exact: true }).fill(id);
  await editor.getByTestId("agent-policy-read-current").click();
  await expect(editor.getByTestId("agent-policy-status"))
    .toContainText(/Accepted current|Authoritative never_written/, { timeout: 120_000 });
  return editor;
}

async function chooseManagementOperations(rule: Locator, operations: readonly string[]) {
  for (const operation of managementOperations) {
    await rule.getByRole("checkbox", { name: operation, exact: true }).setChecked(operations.includes(operation));
  }
}

async function exactPolicy(request: APIRequestContext, session: DpopUserSession, realm: string, id: string) {
  const url = `${colandBaseUrl()}/_arkret/self/current-results/exact`;
  const response = await request.post(url, {
    headers: { ...selfPathHeadersForDpopSession(session, "POST", url), "content-type": "application/json" },
    data: canonicalJson({ realm_id: realm, selector: { kind: "policy", policy_id: id } }),
  });
  expect(response.status(), "exact administrator Policy read").toBe(200);
  const result = await response.json() as Record<string, any>;
  expect(result.realm_id).toBe(realm);
  expect(result.status).toBe("present");
  expect(result.entry.selector.policy_id).toBe(id);
  return result;
}

async function savePolicyEditor(user: JointUserPage, editor: Locator, realm: string) {
  const id = await editor.getByLabel("Exact Policy id", { exact: true }).inputValue();
  const response = user.page.waitForResponse(response => {
    if (response.request().method() !== "POST" || new URL(response.url()).pathname !== "/_arkret/self/events") return false;
    return decodeIngressEvents(response.request().postData()).some(event =>
      event.kind === "ak.policy.set" && event.realm_id === realm && event.payload?.policy_id === id);
  }, { timeout: 180_000 });
  await expect(editor.getByTestId("agent-policy-save")).toBeEnabled();
  await editor.getByTestId("agent-policy-save").click();
  const observed = await response;
  const outcome = await observed.json() as Record<string, any>;
  // Never stringify a surprising signed Commit or whole outcome as diagnostics.
  expect(observed.status(), `Policy ${String(outcome.status)} ${String(outcome.reason_code ?? outcome.code ?? "")}`).toBe(200);
  expect(outcome.status).toBe("committed");
  const event = decodeIngressEvents(observed.request().postData()).find(event => event.payload?.policy_id === id)!;
  expect(typeof event.producer_proof === "object").toBe(true);
  expect(outcome.commit?.event_ref).toBe(event.event_id);
  await expect(editor.getByTestId("agent-policy-status"))
    .toContainText("Policy committed and exact current confirmed", { timeout: 180_000 });
  return { event, outcome };
}

async function assertPolicyCurrent(request: APIRequestContext, session: DpopUserSession, realm: string,
  write: Awaited<ReturnType<typeof savePolicyEditor>>) {
  const current = await exactPolicy(request, session, realm, String(write.event.payload!.policy_id));
  expect(canonicalJson(current.entry.value) === canonicalJson(write.event.payload!.value), "whole accepted Policy value").toBe(true);
  expect(current.entry.revision.commit_id).toBe(write.outcome.commit.commit_id);
  expect(current.entry.revision.stream_position).toBe(write.outcome.commit.stream_position);
  expect(canonicalJson(current.entry.source_stream_ref) === canonicalJson(write.event.scope_ref)).toBe(true);
  return current;
}

test("administrator configures all Realm operations and Circle operations with exact current CAS through normal UI @agent-policy-admin", async ({ jointRealm, request }) => {
  const realm = jointRealm.realmId;
  const user = jointRealm.alicePage;
  const circle = await createCircleArkret(request, jointRealm.aliceToken, {
    actorId: jointRealm.alice.id, realmId: realm, title: "Management configuration Circle", joinRule: "public",
  });
  // The editor's original snapshot fence must have a genuinely readable Circle
  // stream; creation/admin status alone is not a Circle membership fact.
  expect((await addCircleMemberRaw(request, jointRealm.aliceToken, circle.circle_id, {
    signerId: jointRealm.alice.id, actorId: jointRealm.alice.id, realmId: realm,
  })).status()).toBe(200);
  // Circle publish inherits Realm interaction and has no local producer. Its
  // schema-valid configuration is not counted as a seventh Circle consumer.
  for (const circleId of [undefined, circle.circle_id]) {
    let editor = await loadPolicyEditor(user, realm);
    if (circleId) await editor.getByLabel("Scope Circle id (blank means this Realm)", { exact: true }).fill(circleId);
    const id = await editor.getByLabel("Exact Policy id", { exact: true }).inputValue();
    let previous: Record<string, unknown> | null = null;
    for (const operation of managementOperations.filter(op => !circleId || op !== "publish")) {
      const rule = editor.getByTestId("agent-policy-rule");
      await chooseManagementOperations(rule, [operation]);
      await rule.getByLabel("Effect", { exact: true }).selectOption("deny");
      const write = await savePolicyEditor(user, editor, realm);
      expect(canonicalJson(write.event.payload!.expected_revision) === canonicalJson(previous), "exact nullable CAS predecessor").toBe(true);
      expect((write.event.payload!.value as any).rules[0].agent_operations).toEqual([operation]);
      expect((write.event.payload!.value as any).policy_kind).toBe("agent");
      const current = await assertPolicyCurrent(request, jointRealm.aliceSession, realm, write);
      previous = current.entry.revision;
      // A reload must re-read accepted exact current, not reuse the form as proof.
      await user.page.reload({ waitUntil: "domcontentloaded" });
      editor = await loadPolicyEditor(user, realm, id);
      await expect(editor.getByTestId("agent-policy-rule").getByRole("checkbox", { name: operation, exact: true })).toBeChecked();
      await expect(editor.getByLabel("Scope Circle id (blank means this Realm)", { exact: true })).toHaveValue(circleId ?? "");
    }
    if (circleId) {
      // This is only a legal Policy value. Public interaction still has its
      // single Realm producer; this write is not Circle publish effectiveness.
      const rule = editor.getByTestId("agent-policy-rule");
      await chooseManagementOperations(rule, ["publish"]);
      const publish = await savePolicyEditor(user, editor, realm);
      await assertPolicyCurrent(request, jointRealm.aliceSession, realm, publish);
      // No Circle management-review carrier exists. The editor must keep this
      // otherwise well-shaped review intent from reaching Event publication.
      await rule.getByLabel("Effect", { exact: true }).selectOption("require_review");
      await rule.getByLabel("Approvers: complete SDK ActorId array", { exact: true }).fill(canonicalJson([
        { kind: "account", account_id: jointRealm.aliceSession.accountId },
      ]));
      await expect(editor.getByTestId("agent-policy-save")).toBeDisabled();
      expect(canonicalJson((await exactPolicy(request, jointRealm.aliceSession, realm, id)).entry.value)
        === canonicalJson(publish.event.payload!.value)).toBe(true);
    }
  }
});

test("administrator Policy stale CAS and ordinary member edits refuse without effects through normal UI and HTTP @agent-policy-admin", async ({ jointRealm, browser, request }) => {
  const realm = jointRealm.realmId;
  const user = jointRealm.alicePage;
  const editor = await loadPolicyEditor(user, realm);
  const id = await editor.getByLabel("Exact Policy id", { exact: true }).inputValue();
  const sibling = await openDpopUserPageFromSession(browser, jointRealm.aliceSession, { prepareMlsDevice: false });
  expect(Boolean(sibling)).toBe(true);
  try {
    const staleEditor = await loadPolicyEditor(sibling!.page, realm, id);
    const first = await savePolicyEditor(user, editor, realm);
    const accepted = await assertPolicyCurrent(request, jointRealm.aliceSession, realm, first);
    await staleEditor.getByTestId("agent-policy-rule").getByLabel("Effect", { exact: true }).selectOption("allow");
    const staleResponse = sibling!.page.page.waitForResponse(response =>
      response.request().method() === "POST" && new URL(response.url()).pathname === "/_arkret/self/events"
      && decodeIngressEvents(response.request().postData()).some(event => event.payload?.policy_id === id));
    const before = await footprint(realm, jointRealm.aliceSession.accountId.station_id);
    await staleEditor.getByTestId("agent-policy-save").click();
    const refusal = await staleResponse;
    const body = await refusal.json();
    expect(refusal.status(), "stale null revision must not overwrite the accepted Policy").toBe(409);
    expect(wireErrCode(body) ?? body.reason_code).toBe("failed_precondition");
    expect(body.commit === undefined && body.commits === undefined).toBe(true);
    await expect(staleEditor.getByTestId("agent-policy-status")).toContainText("The original Policy was rejected", { timeout: 120_000 });
    expect(canonicalJson((await footprint(realm, jointRealm.aliceSession.accountId.station_id)).tables) === canonicalJson(before.tables)).toBe(true);
    const unchanged = await exactPolicy(request, jointRealm.aliceSession, realm, id);
    expect(canonicalJson(unchanged.entry) === canonicalJson(accepted.entry)).toBe(true);
  } finally { await sibling!.page.close(); }

  const consent = await grantInviteConsentArkret(request, jointRealm.bobToken, jointRealm.bob, jointRealm.alice.id);
  const delivery = await deliverInviteWithConsentGrant(request, {
    inviterId: jointRealm.alice.id, inviterToken: jointRealm.aliceToken, realmId: realm,
    inviteeId: jointRealm.bob.id, consentGrantRef: consent.eventRef, originServer: "server1", recipientServer: "server1",
  });
  expect(delivery.outcome.disclosed_outcome).toBe("delivered");
  await jointRealm.bobPage.acceptInvite(realm);
  const memberEditor = await policyEditor(jointRealm.bobPage, realm);
  await memberEditor.getByLabel("Exact Policy id", { exact: true }).fill(id);
  const read = jointRealm.bobPage.page.waitForResponse(response => response.request().method() === "POST"
    && new URL(response.url()).pathname === "/_arkret/self/current-results/exact"
    && response.request().postDataJSON()?.selector?.policy_id === id);
  await memberEditor.getByTestId("agent-policy-read-current").click();
  expect((await read).status()).toBe(404);
  await expect(memberEditor.getByTestId("agent-policy-status")).toContainText("creation remains blocked", { timeout: 120_000 });
  await expect(memberEditor.getByTestId("agent-policy-save")).toBeDisabled();
  const accepted = await exactPolicy(request, jointRealm.aliceSession, realm, id);
  const event = signedEventEnvelope({ actorId: jointRealm.bob.id, realmId: realm, kind: "ak.policy.set",
    payload: { policy_id: id, expected_revision: accepted.entry.revision, value: accepted.entry.value } });
  const before = await footprint(realm, jointRealm.bobSession.accountId.station_id, String(event.event_id));
  const refusal = await rawSubmitSignedEventApi(request, jointRealm.bobToken, event);
  const body = await refusal.json();
  expect(refusal.status(), "membership does not authorize administrator Policy writes").toBe(403);
  expect(wireErrCode(body) ?? body.reason_code).toBe("capability_denied");
  expect(body.commit === undefined && body.commits === undefined).toBe(true);
  const after = await footprint(realm, jointRealm.bobSession.accountId.station_id, String(event.event_id));
  expect(canonicalJson(after) === canonicalJson(before), "rejected Policy has no Event/Commit/current/quota/delivery effects").toBe(true);
});

test("normal administrator default denial admits an exact controller exception and Circle allow cannot override Realm denial @agent-policy-admin", async ({ jointRealm, request }) => {
  const realm = jointRealm.realmId;
  const user = jointRealm.alicePage;
  const consent = await grantInviteConsentArkret(request, jointRealm.bobToken, jointRealm.bob, jointRealm.alice.id);
  const delivery = await deliverInviteWithConsentGrant(request, { inviterId: jointRealm.alice.id, inviterToken: jointRealm.aliceToken,
    realmId: realm, inviteeId: jointRealm.bob.id, consentGrantRef: consent.eventRef, originServer: "server1", recipientServer: "server1" });
  expect(delivery.outcome.disclosed_outcome).toBe("delivered");
  await jointRealm.bobPage.acceptInvite(realm);
  // Discover the real accepted Realm root through the original signed grant helper.
  await grantCapabilityEventApi(request, jointRealm.aliceToken, { ownerId: jointRealm.alice.id, realmId: realm,
    subjectId: jointRealm.bob.id, actions: ["ak.message.create"] });
  const agent = await provisionOwnedAgent(user);
  let editor = await loadPolicyEditor(user, realm);
  const id = await editor.getByLabel("Exact Policy id", { exact: true }).inputValue();
  await editor.getByLabel("Default effect", { exact: true }).selectOption("deny");
  let rule = editor.getByTestId("agent-policy-rule");
  await chooseManagementOperations(rule, ["join"]);
  await rule.getByLabel("Effect", { exact: true }).selectOption("allow");
  await rule.getByLabel("Agent selector", { exact: true }).selectOption("controller");
  await rule.getByLabel("Complete Account: principal_id", { exact: true }).fill(jointRealm.aliceSession.accountId.principal_id);
  await rule.getByLabel("Complete Account: station_id", { exact: true }).fill(jointRealm.aliceSession.accountId.station_id);
  await assertPolicyCurrent(request, jointRealm.aliceSession, realm, await savePolicyEditor(user, editor, realm));
  await members(user.page, realm, agent);
  await user.page.getByTestId("open-add-realm-agent-modal-button").click();
  const available = user.page.locator(`[data-testid="available-realm-agent-row"][data-agent-id="${agent}"]`);
  await expect(available).toBeVisible({ timeout: 120_000 });
  const joining = user.page.waitForResponse(response => response.request().method() === "POST"
    && new URL(response.url()).pathname === "/_arkret/self/events"
    && decodeIngressEvents(response.request().postData()).some(event => event.kind === "ak.member.state"
      && canonicalJson(event.payload?.member_id) === canonicalJson({ kind: "account", account_id: {
        principal_id: agent, station_id: jointRealm.aliceSession.accountId.station_id } })));
  await available.getByTestId("confirm-add-agent-to-realm").click();
  expect((await joining).status()).toBe(200);
  await expect(user.page.locator(`[data-testid="member-self-agent-row"][data-agent-id="${agent}"]`)).toBeVisible({ timeout: 120_000 });

  const other = await provisionOwnedAgent(jointRealm.bobPage);
  await members(jointRealm.bobPage.page, realm, other);
  await jointRealm.bobPage.page.getByTestId("open-add-realm-agent-modal-button").click();
  const denied = jointRealm.bobPage.page.locator(`[data-testid="available-realm-agent-row"][data-agent-id="${other}"]`);
  await expect(denied).toBeVisible({ timeout: 120_000 });
  const beforeJoin = await footprint(realm, jointRealm.bobSession.accountId.station_id);
  const refusing = jointRealm.bobPage.page.waitForResponse(response => response.request().method() === "POST"
    && new URL(response.url()).pathname === "/_arkret/self/events"
    && decodeIngressEvents(response.request().postData()).some(event => event.kind === "ak.member.state"
      && (event.payload?.member_id as any)?.account_id?.principal_id === other));
  await denied.getByTestId("confirm-add-agent-to-realm").click();
  const rejection = await refusing;
  const rejectionBody = await rejection.json();
  expect(rejection.status()).toBe(403);
  expect(wireErrCode(rejectionBody) ?? rejectionBody.reason_code).toBe("capability_denied");
  expect(rejectionBody.commit === undefined && rejectionBody.commits === undefined).toBe(true);
  expect(canonicalJson((await footprint(realm, jointRealm.bobSession.accountId.station_id)).tables) === canonicalJson(beforeJoin.tables)).toBe(true);

  const circle = await createCircleArkret(request, jointRealm.aliceToken, {
    actorId: jointRealm.alice.id, realmId: realm, title: "Parent management intersection", joinRule: "public" });
  expect((await addCircleMemberRaw(request, jointRealm.aliceToken, circle.circle_id, {
    signerId: jointRealm.alice.id, actorId: jointRealm.alice.id, realmId: realm,
  })).status()).toBe(200);
  editor = await loadPolicyEditor(user, realm, id);
  await editor.getByLabel("Default effect", { exact: true }).selectOption("allow");
  rule = editor.getByTestId("agent-policy-rule");
  await chooseManagementOperations(rule, ["authorize"]);
  await rule.getByLabel("Effect", { exact: true }).selectOption("deny");
  await savePolicyEditor(user, editor, realm);
  const child = await loadPolicyEditor(user, realm);
  await child.getByLabel("Scope Circle id (blank means this Realm)", { exact: true }).fill(circle.circle_id);
  await chooseManagementOperations(child.getByTestId("agent-policy-rule"), ["authorize"]);
  await child.getByTestId("agent-policy-rule").getByLabel("Effect", { exact: true }).selectOption("allow");
  await assertPolicyCurrent(request, jointRealm.aliceSession, realm, await savePolicyEditor(user, child, realm));
  const built = buildCapabilityGrantEnvelope({ ownerId: jointRealm.alice.id, realmId: realm, subjectId: agent,
    subjectStationId: jointRealm.aliceSession.accountId.station_id, actions: ["ak.message.create"] });
  (built.envelope.payload as any).grant.resources = [{ kind: "circle", realm_id: realm, circle_id: circle.circle_id }];
  refreshEventEnvelopeProof(built.envelope);
  const before = await footprint(realm, jointRealm.aliceSession.accountId.station_id, String(built.envelope.event_id));
  const parentDenied = await rawSubmitSignedEventApi(request, jointRealm.aliceToken, built.envelope);
  const body = await parentDenied.json();
  expect(parentDenied.status(), "Circle allow cannot override its Realm parent deny").toBe(403);
  expect(wireErrCode(body) ?? body.reason_code).toBe("capability_denied");
  expect(body.commit === undefined && body.commits === undefined).toBe(true);
  expect(canonicalJson(await footprint(realm, jointRealm.aliceSession.accountId.station_id, String(built.envelope.event_id))) === canonicalJson(before)).toBe(true);
  editor = await loadPolicyEditor(user, realm, id);
  await editor.getByTestId("agent-policy-rule").getByLabel("Effect", { exact: true }).selectOption("allow");
  await savePolicyEditor(user, editor, realm);
  const accepted = await rawSubmitSignedEventApi(request, jointRealm.aliceToken, built.envelope);
  expect(accepted.status(), "removing the parent denial admits the same narrow original grant").toBe(200);
  const outcome = await accepted.json();
  expect(outcome.status).toBe("committed");
  expect(outcome.commit?.event_ref).toBe(built.envelope.event_id);
});

async function reviewPanel(user: JointUserPage, realm: string) {
  await user.gotoRealmAdminSection(realm, "access");
  const panel = user.page.getByTestId("management-review-panel");
  await expect(panel).toBeVisible({ timeout: 120_000 });
  return panel;
}

function reviewResponse(page: Page, operation: "requests" | "status" | "decisions") {
  return page.waitForResponse(response => response.request().method() === "POST"
    && new URL(response.url()).pathname === `/_arkret/self/management-reviews/${operation}`,
  { timeout: 180_000 });
}

async function confirmReview(panel: Locator) {
  await panel.getByRole("checkbox", { name: /我已核对当前 Realm/ }).check();
}

async function loseAcceptedReviewResponse(page: Page, operation: "requests" | "decisions", click: () => Promise<void>) {
  const pattern = `**/_arkret/self/management-reviews/${operation}`;
  let settle!: (value: { body: Record<string, any>; outcome: Record<string, any> }) => void;
  let fail!: (error: unknown) => void;
  let retained: { body: Record<string, any>; outcome: Record<string, any> } | undefined;
  const observed = new Promise<{ body: Record<string, any>; outcome: Record<string, any> }>((resolve, reject) => {
    settle = resolve; fail = reject;
  });
  await page.route(pattern, async route => {
    try {
      if (retained) {
        expect(canonicalJson(route.request().postDataJSON()) === canonicalJson(retained.body), "transport retry preserves its original request").toBe(true);
        await route.abort("failed");
        return;
      }
      // The actual governing Station accepts first. Only the response to the
      // browser is lost; the test never synthesizes an approval or outcome.
      const accepted = await route.fetch({ timeout: 180_000, maxRedirects: 0 });
      expect(accepted.status()).toBe(200);
      const value = { body: route.request().postDataJSON(), outcome: await accepted.json() };
      retained = value;
      await route.abort("failed");
      settle(value);
    } catch (error) { fail(error); }
  });
  try {
    await click();
    const value = await observed;
    await expect(page.getByTestId("management-review-status")).toContainText("操作被拒绝或当前证据不可用", { timeout: 180_000 });
    return value;
  } finally { await page.unroute(pattern); }
}

async function sharedReview(panel: Locator, candidate: Record<string, any>) {
  const summary = panel.getByText("分享原审批请求", { exact: false });
  if (await summary.locator("..").getAttribute("open") === null) await summary.click();
  const json = await panel.getByTestId("management-review-share-json").inputValue();
  // Both sides retain the complete signed candidate. Boolean equality keeps
  // unexpected producer signatures out of Playwright diagnostics.
  expect(canonicalJson(JSON.parse(json)) === canonicalJson(candidate)).toBe(true);
  return json;
}

async function switchReviewRealmAndReload(user: JointUserPage, originalRealm: string, otherRealm: string,
  share: string, expectedStatus: string) {
  const page = user.page;
  const documentOrigin = await page.evaluate(() => performance.timeOrigin);
  for (const realm of [otherRealm, originalRealm]) {
    // Keep the same authenticated document and traverse the real application
    // router, so a cold reload cannot hide a missing Realm component key.
    await user.gotoAppPanel(`/realms/${encodeURIComponent(realm)}/settings/access`, "realm-admin-panel");
    await expect.poll(() => new URL(page.url()).pathname).toBe(`/realms/${encodeURIComponent(realm)}/settings/access`);
    const panel = page.getByTestId("management-review-panel");
    await expect(panel).toBeVisible({ timeout: 120_000 });
    await expect(panel.getByTestId("management-review-frozen-candidate")).toHaveCount(0);
    await expect(panel.getByTestId("management-review-share-json")).toHaveCount(0);
    await expect(panel.getByTestId("management-review-request-json")).toHaveValue("");
    await expect(panel.getByTestId("management-review-recovery-key")).toHaveCount(0);
    await expect(panel.getByTestId("management-review-retry-decision")).toHaveCount(0);
    await expect(panel.getByTestId("management-review-submit")).toHaveCount(0);
    await expect(panel.getByTestId("management-review-request")).toHaveText("冻结候选并请求审批（不提交业务）");
    expect(await page.evaluate(() => performance.timeOrigin), "Realm switch keeps the original document").toBe(documentOrigin);
  }
  const panel = page.getByTestId("management-review-panel");
  await panel.getByTestId("management-review-request-json").fill(share);
  const response = reviewResponse(page, "status");
  await panel.getByTestId("management-review-load").click();
  const loaded = await response;
  expect(loaded.status()).toBe(200);
  const outcome = await loaded.json();
  expect(outcome.status).toBe(expectedStatus);
  const request = JSON.parse(share);
  expect(outcome.request_id).toBe(request.request_id);
  await expect(panel.getByTestId("management-review-frozen-candidate"))
    .toContainText(request.target.event.event_id);
  await expect(panel.getByTestId("management-review-retry-decision")).toHaveCount(0);
}

test("normal controller requests join and public review, distinct administrator signs native control and exact durable Events commit @agent-management-review", async ({ jointRealm, request }) => {
  const realm = jointRealm.realmId;
  const station = jointRealm.bobSession.accountId.station_id;
  const consent = await grantInviteConsentArkret(request, jointRealm.bobToken, jointRealm.bob, jointRealm.alice.id);
  const delivery = await deliverInviteWithConsentGrant(request, { inviterId: jointRealm.alice.id,
    inviterToken: jointRealm.aliceToken, realmId: realm, inviteeId: jointRealm.bob.id,
    consentGrantRef: consent.eventRef, originServer: "server1", recipientServer: "server1" });
  expect(delivery.outcome.disclosed_outcome).toBe("delivered");
  await jointRealm.bobPage.acceptInvite(realm);
  const agent = await provisionOwnedAgent(jointRealm.bobPage);
  const secondAccepted = jointRealm.alicePage.page.waitForResponse(response =>
    response.request().method() === "POST" && new URL(response.url()).pathname === "/_arkret/self/events"
    && decodeIngressEvents(response.request().postData()).some(value => value.kind === "ak.realm.create"),
  { timeout: 180_000 });
  const otherRealm = await jointRealm.alicePage.createRealm({ title: "Management review state isolation", joinRule: "invite" });
  const created = await secondAccepted;
  expect(created.status()).toBe(200);
  const createdEvents = decodeIngressEvents(created.request().postData());
  const contract = JSON.parse(await readFile(fileURLToPath(new URL(
    "../../../../arkret-spec/spec/v1/artifacts/registry/contract-registry.json", import.meta.url,
  )), "utf8"));
  // This normal wizard declares plaintext visibility and requests no alias.
  // Derive the one registered order instead of keeping a second slot list.
  const slots = contract.realm_bootstrap_registry.ordinary_collaboration.ordered_slots as
    Array<{ event_kind: string; presence: string }>;
  expect(createdEvents.map(event => event.kind)).toEqual(slots
    .filter(slot => slot.presence !== "optional").map(slot => slot.event_kind));
  const createdEvent = createdEvents[0];
  const createdOutcome = await created.json();
  expect(createdEvent.realm_id).toBe(otherRealm);
  expect(createdOutcome.unit_kind).toBe("ordinary_realm_bootstrap");
  expect(createdOutcome.status).toBe("committed");
  expect(createdOutcome.commits).toHaveLength(createdEvents.length);
  for (const [index, event] of createdEvents.entries()) {
    const commit = createdOutcome.commits[index];
    assertAuthoritySubmitOutcome({ status: createdOutcome.status, commit }, event,
      `management isolation Realm bootstrap ${index}`);
    expect(commit.stream_position).toBe(index);
    expect(commit.previous_commit_ref ?? null).toBe(index ? createdOutcome.commits[index - 1].commit_id : null);
  }
  expect(otherRealm).not.toBe(realm);
  const editor = await loadPolicyEditor(jointRealm.alicePage, realm);
  await editor.getByLabel("Default effect", { exact: true }).selectOption("allow");
  const rule = editor.getByTestId("agent-policy-rule");
  await chooseManagementOperations(rule, ["join", "publish"]);
  await rule.getByLabel("Agent selector", { exact: true }).selectOption("controller");
  await rule.getByLabel("Complete Account: principal_id", { exact: true }).fill(jointRealm.bobSession.accountId.principal_id);
  await rule.getByLabel("Complete Account: station_id", { exact: true }).fill(station);
  await rule.getByLabel("Effect", { exact: true }).selectOption("require_review");
  await rule.getByLabel("Approvers: complete SDK ActorId array", { exact: true }).fill(canonicalJson([
    { kind: "account", account_id: jointRealm.aliceSession.accountId },
  ]));
  await rule.getByLabel("Approval threshold", { exact: true }).fill("1");
  await rule.getByLabel("Approval lifetime seconds (1–86400)", { exact: true }).fill("3600");
  await assertPolicyCurrent(request, jointRealm.aliceSession, realm,
    await savePolicyEditor(jointRealm.alicePage, editor, realm));
  const controller = await reviewPanel(jointRealm.bobPage, realm);
  const administrator = await reviewPanel(jointRealm.alicePage, realm);
  await controller.getByLabel("Agent Account: principal_id", { exact: true }).fill(agent);
  await controller.getByLabel("Agent Account: station_id", { exact: true }).fill(station);
  for (const terminal of ["cancel", "reject"] as const) {
    const before = await footprint(realm, station);
    let lostRequest: Record<string, any> | undefined;
    if (terminal === "cancel") {
      const lost = await loseAcceptedReviewResponse(jointRealm.bobPage.page, "requests",
        () => controller.getByTestId("management-review-request").click());
      lostRequest = lost.body;
      expect(lost.outcome.status).toBe("pending");
      await expect(controller.getByTestId("management-review-status")).toContainText("操作被拒绝或当前证据不可用");
      await expect(controller.getByTestId("management-review-request")).toHaveText("重试原审批请求（保留原候选）");
    }
    const requested = reviewResponse(jointRealm.bobPage.page, "requests");
    await controller.getByTestId("management-review-request").click();
    const response = await requested;
    expect(response.status()).toBe(200);
    const candidate = response.request().postDataJSON() as Record<string, any>;
    if (lostRequest) expect(canonicalJson(candidate) === canonicalJson(lostRequest), "request response loss retries its exact retained signed request").toBe(true);
    expect((await response.json()).status).toBe("pending");
    let decidingPanel = controller;
    let decidingPage = jointRealm.bobPage.page;
    if (terminal === "reject") {
      await administrator.getByTestId("management-review-request-json").fill(await sharedReview(controller, candidate));
      const loaded = reviewResponse(jointRealm.alicePage.page, "status");
      await administrator.getByTestId("management-review-load").click();
      expect((await (await loaded).json()).status).toBe("pending");
      decidingPanel = administrator;
      decidingPage = jointRealm.alicePage.page;
    }
    await confirmReview(decidingPanel);
    if (terminal === "reject") {
      const share = await sharedReview(controller, candidate);
      const lost = await loseAcceptedReviewResponse(decidingPage, "decisions",
        () => decidingPanel.getByTestId("management-review-reject").click());
      expect(lost.outcome.status).toBe("rejected");
      await expect(decidingPanel.getByTestId("management-review-retry-decision")).toBeVisible();
      await switchReviewRealmAndReload(jointRealm.alicePage, realm, otherRealm, share, "rejected");
    } else {
      const decision = reviewResponse(decidingPage, "decisions");
      await decidingPanel.getByTestId("management-review-cancel").click();
      const refused = await decision;
      expect(refused.status()).toBe(200);
      expect((await refused.json()).status).toBe("cancelled");
    }
    const after = await footprint(realm, station, candidate.target.event.event_id);
    expect(canonicalJson(after.tables) === canonicalJson(before.tables)).toBe(true);
    expect(Object.values(after.candidate_absence!)).toEqual([0, 0, 0, 0, 0, 0]);
    await expect(decidingPanel.getByTestId("management-review-submit")).toHaveCount(0);
  }
  for (const operation of ["join", "publish"] as const) {
    await controller.getByLabel("原管理意图", { exact: true }).selectOption(operation);
    const before = await footprint(realm, station);
    const pendingResponse = reviewResponse(jointRealm.bobPage.page, "requests");
    await controller.getByTestId("management-review-request").click();
    const response = await pendingResponse;
    expect(response.status()).toBe(200);
    const candidate = response.request().postDataJSON() as Record<string, any>;
    const pending = await response.json();
    expect(pending.status).toBe("pending");
    expect(candidate.management_operation).toBe(operation);
    expect(candidate.target.kind).toBe("event");
    const event = candidate.target.event;
    expect(event.kind).toBe(operation === "join" ? "ak.member.state" : "ak.agent.interaction.set");
    expect(canonicalJson(event.actor_id) === canonicalJson({ kind: "account", account_id: jointRealm.bobSession.accountId })).toBe(true);
    expect(event.executed_by === undefined).toBe(true);
    expect(pending.target_digest).toBe(createHash("sha256").update(canonicalJson(event)).digest("hex"));
    const inactive = await footprint(realm, station, event.event_id);
    expect(canonicalJson(inactive.tables) === canonicalJson(before.tables)).toBe(true);
    expect(Object.values(inactive.candidate_absence!)).toEqual([0, 0, 0, 0, 0, 0]);
    await expect(controller.getByTestId("management-review-submit")).toHaveCount(0);
    await expect(controller.getByTestId("management-review-approve")).toHaveCount(0);
    const share = await sharedReview(controller, candidate);
    await administrator.getByTestId("management-review-request-json").fill(share);
    const statusResponse = reviewResponse(jointRealm.alicePage.page, "status");
    await administrator.getByTestId("management-review-load").click();
    expect((await (await statusResponse).json()).target_digest).toBe(pending.target_digest);
    await expect(administrator.getByTestId("management-review-frozen-candidate")).toContainText(event.event_id);
    await confirmReview(administrator);
    // This accepted principal's Recovery Key is typed into the normal password
    // form. The browser resolves and verifies native history, then derives and
    // signs with its effective update key; no Device/registration VM substitute.
    await administrator.getByTestId("management-review-recovery-key").fill(
      registeredSubjectIdentityControl(jointRealm.alice).recoveryKey);
    if (operation === "join") {
      expect((await administrator.getByTestId("management-review-recovery-key").inputValue()).length > 0).toBe(true);
      await switchReviewRealmAndReload(jointRealm.alicePage, realm, otherRealm, share, "pending");
      await expect(administrator.getByTestId("management-review-recovery-key")).toHaveValue("");
      await confirmReview(administrator);
      await administrator.getByTestId("management-review-recovery-key").fill(
        registeredSubjectIdentityControl(jointRealm.alice).recoveryKey);
    }
    let approved: Record<string, any>;
    if (operation === "join") {
      const lost = await loseAcceptedReviewResponse(jointRealm.alicePage.page, "decisions",
        () => administrator.getByTestId("management-review-approve").click());
      expect(lost.outcome.status).toBe("approved");
      await expect(administrator.getByTestId("management-review-status")).toContainText("操作被拒绝或当前证据不可用");
      await expect(administrator.getByTestId("management-review-approve")).toHaveCount(0);
      await confirmReview(administrator);
      const reconciled = reviewResponse(jointRealm.alicePage.page, "status");
      await administrator.getByTestId("management-review-retry-decision").click();
      approved = await (await reconciled).json();
      expect(canonicalJson(approved.approval_signatures) === canonicalJson(lost.body.approval_signatures),
        "accepted response loss observes the exact original signature and timestamp").toBe(true);
      await expect(administrator.getByTestId("management-review-retry-decision")).toHaveCount(0);
    } else {
      const decisionResponse = reviewResponse(jointRealm.alicePage.page, "decisions");
      await administrator.getByTestId("management-review-approve").click();
      const decision = await decisionResponse;
      expect(decision.status()).toBe(200);
      approved = await decision.json();
    }
    expect(approved.status).toBe("approved");
    expect(approved.target_digest).toBe(pending.target_digest);
    expect(approved.approval_signatures.length).toBe(1);
    const signature = approved.approval_signatures[0];
    expect(signature.proof.verification_method).toMatch(/^did:key:/);
    expect(signature.input.approver_did).toBe(jointRealm.alice.did);
    expect(signature.input.approval_context.request_id).toBe(candidate.request_id);
    expect(signature.input.approval_target.event_id).toBe(event.event_id);
    expect(signature.input.request_canonical_digest).toBe(pending.target_digest);
    await expect(administrator.getByTestId("management-review-recovery-key")).toHaveCount(0);
    const stillInactive = await footprint(realm, station, event.event_id);
    expect(canonicalJson(stillInactive) === canonicalJson(inactive)).toBe(true);
    const refresh = reviewResponse(jointRealm.bobPage.page, "status");
    await controller.getByTestId("management-review-refresh").click();
    expect((await (await refresh).json()).status).toBe("approved");
    await expect(controller.getByTestId("management-review-submit")).toBeVisible();
    await confirmReview(controller);
    const submittedResponse = jointRealm.bobPage.page.waitForResponse(response =>
      response.request().method() === "POST" && new URL(response.url()).pathname === "/_arkret/self/events"
      && decodeIngressEvents(response.request().postData()).some(value => value.event_id === event.event_id),
    { timeout: 180_000 });
    await controller.getByTestId("management-review-submit").click();
    const submitted = await submittedResponse;
    expect(submitted.status()).toBe(200);
    const actualEvent = decodeIngressEvents(submitted.request().postData()).find(value => value.event_id === event.event_id);
    expect(canonicalJson(actualEvent) === canonicalJson(event), "exact original signed candidate").toBe(true);
    expect(canonicalJson(submitted.request().postDataJSON().approval_signatures)
      === canonicalJson(approved.approval_signatures), "exact original approved signature set").toBe(true);
    const outcome = await submitted.json();
    expect(outcome.status).toBe("committed");
    expect(outcome.commit?.event_ref).toBe(event.event_id);
    await expect(controller.getByTestId("management-review-status")).toContainText("原候选业务已提交", { timeout: 180_000 });
    const lookupUrl = `${colandBaseUrl()}/_arkret/self/management-reviews/status`;
    const consumed = await request.post(lookupUrl, { headers: selfPathHeadersForDpopSession(jointRealm.bobSession, "POST", lookupUrl),
      data: canonicalJson({ request_id: candidate.request_id }) });
    expect(consumed.status()).toBe(200);
    expect((await consumed.json()).status).toBe("consumed");
    if (operation === "publish") {
      const url = `${colandBaseUrl()}/_arkret/self/current-results/exact`;
      const current = await request.post(url, { headers: selfPathHeadersForDpopSession(jointRealm.bobSession, "POST", url),
        data: canonicalJson({ realm_id: realm, selector: { kind: "agent_interaction", agent_account_id: {
          principal_id: agent, station_id: station } } }) });
      expect(current.status()).toBe(200);
      const read = await current.json();
      expect(read.entry.value.interaction_mode).toBe("public");
      expect(read.entry.revision.commit_id).toBe(outcome.commit.commit_id);
    }
  }
});
