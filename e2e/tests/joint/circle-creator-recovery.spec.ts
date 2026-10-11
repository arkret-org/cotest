// Real product Circle creation and RFC MLS recovery under one accepted Device.
// Session injection and holder diagnostics make this fixture-only evidence.
import { expect, test } from "../../helpers/arkret-test";
import { createDpopUserSession, openUserPage, type JointUserPage } from "../../helpers/users";
import { installCircleCreatorCommitFault, readCreatorRecords } from "../../helpers/creator-bootstrap";
import { canonicalJson, scanRealmStreamApi } from "../../helpers/coland-api";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const commitCuts = {
  realm_accepted: "genesis_intent_persisted",
  governance_result_pinned: "realm_accepted",
  epoch0_state_persisted: "governance_result_pinned",
  genesis_queued: "epoch0_state_persisted",
  genesis_accepted: "genesis_queued",
  artifacts_converged: "genesis_accepted",
  ready: "artifacts_converged",
} as const;

for (const cut of ["none", "create_response_loss", "public_blob_response_loss", ...Object.keys(commitCuts)] as const) {
  test("Circle creator independently encrypts and resumes original bytes; " + cut, async ({ browser, request }, testInfo) => {
    test.setTimeout(360_000);
    const session = await createDpopUserSession(request, "circle-creator");
    expect(session, "joint provisioning must establish an accepted Device").toBeTruthy();
    const profile = fs.mkdtempSync(path.join(os.tmpdir(), "cc-"));
    const device = { ...session!, persistentUserDataDir: profile };
    let client: JointUserPage | undefined;
    const refusals: Record<string, unknown>[] = [];
    const authoringFailures: string[] = [];
    const watchAuthoring = (page: JointUserPage["page"]) => {
      page.on("console", message => {
        const text = message.text();
        if (/ordinary message authoring failed|ordinary message pre-submit (?:gate failed|stage)|encrypted message (?:preparation|send|authoring) failed|MLS send readiness probe failed/.test(text)
          && !/bearer |recovery_key|mnemonic|access_token|dpop:|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/i.test(text)) {
          authoringFailures.push(text.slice(0, 1800));
        }
      });
      page.on("response", async response => {
        if (!/\/_arkret\/self\/events(?:\?.*)?$/.test(response.url()) || response.status() < 400) return;
        const body = response.request().postDataJSON() as Record<string, any>;
        const problem = await response.json().catch(() => ({}));
        refusals.push({ kind: body.event?.kind, scope: body.event?.scope_ref,
          status: response.status(), type: problem.type, detail: problem.detail, reason: problem.reason });
      });
    };
    try {
      client = await openUserPage(browser, session!.user, device);
      let page = client.page;
      watchAuthoring(page);
      await client.gotoHome();
      const realm = await client.createRealm({ title: `Circle creator parent ${Date.now()}`,
        discoverability: "public", joinRule: "invite", historyAccess: "since_join", mlsActivated: false });
      await client.completeRecoveryKeySetupIfPrompted(30_000);
      const circlesUrl = `/realms/${encodeURIComponent(realm)}/circles`;
      await page.goto(circlesUrl, { waitUntil: "domcontentloaded" });
      await page.getByTestId("circle-create-open").click();
      await page.getByTestId("circle-create-title").fill("Plain sibling");
      await expect(page.getByTestId("circle-create-encrypted")).not.toBeChecked();
      await page.getByTestId("circle-create-submit").click();
      await expect(page).toHaveURL(/\/realms\/[^/]+\/circles\/[^/]+$/);
      const sibling = decodeURIComponent(page.url().split("/").at(-1)!);
      await client.completeRecoveryKeySetupIfPrompted(2_000);
      await page.goto(circlesUrl, { waitUntil: "domcontentloaded" });

      let circle: string | undefined;
      let lost = false;
      let blocked = cut !== "none";
      let intentAtCut: Record<string, any> | undefined;
      let epochAtCut: Record<string, any> | undefined;
      const createIds = new Set<string>();
      const genesisIds = new Set<string>();
      const createBytes = new Set<string>();
      const genesisBytes = new Set<string>();
      let signedAtCut: Record<string, any> | undefined;
      const commitCut = Object.hasOwn(commitCuts, cut);
      if (commitCut) await installCircleCreatorCommitFault(page, cut);
      await page.route(/\/_arkret\/self\/events(?:\?.*)?$/, async route => {
        const body = route.request().postDataJSON() as Record<string, any>;
        const event = body.event;
        if (event?.kind === "ak.circle.create") {
          createIds.add(event.event_id);
          createBytes.add(canonicalJson(body));
          circle = event.event_id.replace(/^ak:event:/, "ak:circle:");
          const record = (await readCreatorRecords(page)).find(value => value.intent.effective_scope.circle_id === circle);
          expect(record, "closed intent must commit before the first Circle write").toBeDefined();
          expect(record!.intent.signed_scope_create_unit).toEqual(body);
          expect(record!.queue_items.some((item: Record<string, any>) => item.submission.request.event?.kind === "ak.circle.member.state"
            && item.submission.request.event.scope_ref.circle_id === circle)).toBe(true);
          expect(record!.queue_items.some((item: Record<string, any>) => item.submission.request.event?.kind === "ak.strand.create"
            && item.submission.request.event.scope_ref.circle_id === circle
            && item.submission.request.event.payload.object.metadata === undefined)).toBe(true);
          intentAtCut = record!.intent;
          if (cut === "create_response_loss" && blocked) {
            if (!lost) {
              const accepted = await route.fetch();
              expect(accepted.ok()).toBe(true);
              lost = true;
            }
            await route.abort("connectionfailed");
            return;
          }
        }
        if (event?.kind === "ak.mls.genesis" && event.scope_ref.circle_id === circle) {
          genesisIds.add(event.event_id);
          genesisBytes.add(canonicalJson(body));
          const record = (await readCreatorRecords(page)).find(value => value.intent.effective_scope.circle_id === circle)!;
          expect(record.state).toBe("genesis_queued");
          expect(record.queued_genesis.signed_genesis.event).toEqual(event);
          expect(record.governance_evidence.genesis_absence.visible_stream_heads.some((head: Record<string, any>) =>
            head.stream_ref.kind === "circle" && head.stream_ref.circle_id === circle)).toBe(true);
          if (epochAtCut) expect(record.epoch_zero).toEqual(epochAtCut);
        }
        await route.continue();
      });
      await page.route(/\/_arkret\/self\/blob\/upload(?:\?.*)?$/, async route => {
        if (cut !== "public_blob_response_loss" || !blocked || !circle) { await route.continue(); return; }
        const record = (await readCreatorRecords(page)).find(value => value.intent.effective_scope.circle_id === circle);
        if (!record?.epoch_zero) { await route.continue(); return; }
        epochAtCut = record.epoch_zero;
        if (!lost) {
          const accepted = await route.fetch();
          expect(accepted.ok()).toBe(true);
          lost = true;
        }
        await route.abort("connectionfailed");
      });
      await page.getByTestId("circle-create-open").click();
      await page.getByTestId("circle-create-title").fill("Encrypted independent Circle");
      await page.getByTestId("circle-create-encrypted").check();
      await page.getByTestId("circle-create-submit").click();
      await expect.poll(() => circle, { timeout: 60_000 }).toMatch(/^ak:circle:/);
      if (cut !== "none") {
        if (commitCut) {
          await expect.poll(() => page.evaluate(() => (window as any).__circleCreatorCommitFault),
            { timeout: 120_000 }).toEqual({ state: cut, circle });
        } else {
          await expect.poll(() => lost, { timeout: 60_000 }).toBe(true);
        }
        expect(intentAtCut).toBeDefined();
        const original = (await readCreatorRecords(page)).find(value => value.intent.effective_scope.circle_id === circle)!;
        expect(original.state).toBe(commitCut ? commitCuts[cut as keyof typeof commitCuts]
          : cut === "create_response_loss" ? "genesis_intent_persisted" : "epoch0_state_persisted");
        if (commitCut) epochAtCut = original.epoch_zero;
        expect(original.epoch_zero).toEqual(epochAtCut);
        expect(original.ready_receipt).toBeUndefined();
        expect(original.ready_index.filter((receipt: Record<string, any>) => receipt.effective_scope.circle_id === circle)).toHaveLength(0);
        signedAtCut = original.queued_genesis;
        // Repeated worker attempts must not change any formal transaction field.
        await page.waitForTimeout(500);
        const still = (await readCreatorRecords(page)).find(value => value.intent.effective_scope.circle_id === circle)!;
        expect(still.state).toBe(original.state);
        expect(still.intent).toEqual(original.intent);
        expect(still.governance_evidence).toEqual(original.governance_evidence);
        expect(still.epoch_zero).toEqual(original.epoch_zero);
        expect(still.queued_genesis).toEqual(original.queued_genesis);
        expect(still.accepted_genesis).toEqual(original.accepted_genesis);
        expect(still.artifacts).toEqual(original.artifacts);
        // Destroy the browser process, retain the same non-extractable key.
        await client.session.context.close();
        blocked = false;
        client = await openUserPage(browser, session!.user, device);
        page = client.page;
        watchAuthoring(page);
        await client.gotoHome();
      }
      await expect.poll(async () => (await readCreatorRecords(page)).find(value => value.intent.effective_scope.circle_id === circle)?.state,
        { timeout: 120_000 }).toBe("ready");
      const ready = (await readCreatorRecords(page)).find(value => value.intent.effective_scope.circle_id === circle)!;
      expect(ready.intent).toEqual(intentAtCut);
      if (epochAtCut) expect(ready.epoch_zero).toEqual(epochAtCut);
      if (signedAtCut) expect(ready.queued_genesis).toEqual(signedAtCut);
      expect(ready.accepted_create.accepted_event.kind).toBe("ak.circle.create");
      expect(ready.accepted_create.accepted_event.event_id).toBe(ready.intent.scope_create_event_id);
      expect(ready.accepted_create.covering_commit.stream_ref).toEqual({ kind: "realm", realm_id: realm });
      expect(ready.accepted_genesis.accepted.event.scope_ref).toEqual({ kind: "circle", realm_id: realm, circle_id: circle });
      expect((await readCreatorRecords(page)).filter(value => value.intent.effective_scope.realm_id === realm)).toHaveLength(1);
      expect(createIds.size).toBe(1);
      expect(createBytes.size).toBe(1);
      if (cut === "none") expect(genesisIds.size).toBe(1);
      expect(genesisBytes.size).toBeLessThanOrEqual(1);
      const parent = await scanRealmStreamApi(request, session!.grantJwt, realm);
      expect(parent.events.filter(event => event.kind === "ak.mls.genesis")).toHaveLength(0);
      expect(parent.events.filter(event => event.kind === "ak.circle.create")).toHaveLength(2);
      const ownStream = { kind: "circle", realm_id: realm, circle_id: circle };
      const own = await scanRealmStreamApi(request, session!.grantJwt, realm, { streamRef: ownStream });
      expect(own.events.filter(event => event.kind === "ak.mls.genesis")).toHaveLength(1);
      const siblingScan = await scanRealmStreamApi(request, session!.grantJwt, realm,
        { streamRef: { kind: "circle", realm_id: realm, circle_id: sibling } });
      expect(siblingScan.events.filter(event => event.kind === "ak.mls.genesis")).toHaveLength(0);

      await client.gotoTimelineRealm(realm);
      await client.completeRecoveryKeySetupIfPrompted(2_000);
      await expect(page.getByTestId("open-poll-composer-button")).toBeVisible({ timeout: 60_000 });
      const initialDiscussions = own.events.filter(event => event.kind === "ak.strand.create");
      expect(initialDiscussions).toHaveLength(1);
      expect((initialDiscussions[0].payload as Record<string, any>).object).not.toHaveProperty("metadata");
      const strand = String(initialDiscussions[0].event_id).replace(/^ak:event:/, "ak:strand:");
      const channel = page.getByTestId("channel-item").filter({ hasText: strand });
      await expect(channel).toBeVisible({ timeout: 60_000 });
      await channel.click();
      await expect(page.getByTestId("open-poll-composer-button")).toHaveCount(0);
      const secret = `Circle private body ${Date.now()}`;
      await expect(page.getByTestId("chat-input")).toBeEnabled({ timeout: 60_000 });
      await page.getByTestId("chat-input").fill(secret);
      await page.getByTestId("send-chat-button").click();
      await expect(page.getByTestId("chat-message").filter({ hasText: secret })).toBeVisible({ timeout: 60_000 });
      await expect.poll(async () => (await scanRealmStreamApi(request, session!.grantJwt, realm, { streamRef: ownStream }))
        .events.filter(event => event.kind === "ak.message.create"), { timeout: 60_000 }).toHaveLength(1);
      const stored = await scanRealmStreamApi(request, session!.grantJwt, realm, { streamRef: ownStream });
      const messages = stored.events.filter(event => event.kind === "ak.message.create");
      expect(messages).toHaveLength(1);
      expect(messages[0].payload).toHaveProperty("encrypted_content");
      expect(canonicalJson(messages)).not.toContain(secret);
      await page.reload({ waitUntil: "domcontentloaded" });
      // The Realm route reopens its default discussion. Select the same
      // Circle discussion before demanding decrypted durable readback.
      await expect(channel).toBeVisible({ timeout: 60_000 });
      await channel.click();
      await expect(page.getByTestId("chat-message").filter({ hasText: secret })).toBeVisible({ timeout: 60_000 });
      expect((await readCreatorRecords(page)).find(value => value.intent.effective_scope.circle_id === circle)?.epoch_zero).toEqual(ready.epoch_zero);
    } catch (error) {
      const records = client ? await readCreatorRecords(client.page, true).catch(() => []) : [];
      const bootstrap = client ? await client.page.locator('[role="status"]').allTextContents().catch(() => []) : [];
      const chatStatus = client ? await client.page.getByTestId("chat-status").allTextContents().catch(() => []) : [];
      const sendGate = client ? await client.page.getByTestId("send-chat-button").evaluate(button => ({
        bindingPending: button.getAttribute("data-mls-binding-pending"),
        creatorPending: button.getAttribute("data-creator-bootstrap-pending"),
        reason: button.getAttribute("title"),
      })).catch(() => null) : null;
      const queue = records.flatMap(record => record.queue_items ?? []).map(item => ({
        kind: item.submission.request.event?.kind, scope: item.submission.request.event?.scope_ref,
        status: item.status, last_error: item.last_error, last_problem: item.last_problem,
        state: item.submission.state.Rejected ?? item.submission.state.Queued,
      }));
      await testInfo.attach("safe-circle-failure-coordinates", { contentType: "application/json",
        body: JSON.stringify({ refusals, sendGate, chatStatus, authoringFailures: authoringFailures.slice(-12), bootstrap: bootstrap.filter(text => text.includes("Creator MLS bootstrap:")), records: records.map(record => ({ scope: record.intent.effective_scope, state: record.state, group: record.intent.mls_group_id, accepted: record.accepted_genesis?.accepted.event.event_id, checkpoints: record.checkpoint_coordinates })), queue }, null, 2) });
      throw error;
    } finally {
      await client?.session.context.close();
      fs.rmSync(profile, { recursive: true, force: true });
    }
  });
}
