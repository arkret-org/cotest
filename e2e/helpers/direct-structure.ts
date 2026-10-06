import { expect, test, operationSelector } from "./arkret-test";
import type { Page, Response, Request } from "@playwright/test";
import { assertAuthoritySubmitOutcome, canonicalJson, sdkEventDerivedIds, sha256CanonicalJson } from "./soland-api";
import { decodeEventIngressBody, ingressEvents, type IngressEvent } from "./event-ingress";
import { readFile } from "node:fs/promises";
import { isDeepStrictEqual } from "node:util";

// Diagnostic pairing of one real self submit; not an independent authority/Ed verifier.
async function observeSelectedHumanSend(page: Page, strandId: string) {
  const source = await page.evaluate(() => {
    const config = JSON.parse(localStorage.getItem("inkson.config.v1") ?? "{}");
    const active = config.active_account;
    if (!active?.authority?.principal_id || !active?.authority?.station_id || !active?.device_id || !active?.server_url) {
      throw new Error("send diagnostic active Account source unavailable");
    }
    return { account: active.authority, device: active.device_id, station: active.server_url };
  });
  const realm = decodeURIComponent(new URL(page.url()).pathname.split("/")[2] ?? "");
  let requestCount = 0;
  let responseCount = 0;
  let raw: string | undefined;
  let original: IngressEvent | undefined;
  let originalCommit: unknown;
  let accepted = false;
  let paired = false;
  let unchanged = true;
  let failed: string | undefined;
  let status = 0;
  const log = (stage: "observing" | "request" | "response" | "transport_failed" | "model_progress" | "finished") => {
    console.info("Direct Chat send diagnostic", JSON.stringify({
      stage, route: "ak.self.events.command.submit.v1", http_status: status,
      matching_request_count: requestCount, matching_response_count: responseCount,
      frozen_request_unchanged: unchanged, typed_pair_ok: paired, accepted,
      gate_failed: failed !== undefined, reason: failed ?? "none",
    }));
  };
  const require = (ok: boolean, reason: string) => { if (!ok) throw new Error(reason); };
  const select = (request: Request): IngressEvent | undefined => {
    const url = new URL(request.url());
    if (request.method() !== "POST" || url.pathname !== "/_arkret/self/events" || url.origin !== new URL(source.station).origin) return;
    const body = request.postDataJSON();
    const rows = decodeEventIngressBody(body, { context: "Direct Chat send diagnostic" });
    const selected = rows.map(row => row.event).filter(event => event.kind === "ak.message.create" && event.realm_id === realm && event.payload?.strand_id === strandId);
    if (!selected.length) return;
    require(selected.length === 1 && rows.length === 1 && body.event && !body.unit_kind && !body.commit_event,
      "message_submission_branch_mismatch");
    const event = selected[0];
    require(canonicalJson(event.actor_id) === canonicalJson({ kind: "account", account_id: source.account }), "message_account_mismatch");
    require(typeof (event.producer_proof as Record<string, unknown>)?.verification_method === "string" && String((event.producer_proof as Record<string, unknown>).verification_method).split("#")[1] === source.device && source.device.startsWith("ak:device:"), "message_not_human_device");
    require(operationSelector("POST", request.url()) === "ak.self.events.command.submit.v1", "unregistered_submit_route");
    return event;
  };
  const onRequest = (request: Request) => {
    try {
      const event = select(request);
      if (!event) return;
      requestCount += 1;
      const bytes = request.postData()!;
      if (raw === undefined) { raw = bytes; original = event; }
      else {
        unchanged = unchanged && raw === bytes && isDeepStrictEqual(original, event);
        require(unchanged, "frozen_request_changed");
      }
      log("request");
    } catch (error) {
      const reasons = ["message_submission_branch_mismatch", "message_account_mismatch", "message_not_human_device", "unregistered_submit_route", "frozen_request_changed"];
      failed = error instanceof Error && reasons.includes(error.message) ? error.message : "request_pairing_failed";
      log("request");
    }
  };
  const onResponse = async (response: Response) => {
    try {
      const event = select(response.request());
      if (!event) return;
      responseCount += 1;
      status = response.status();
      require(original !== undefined && raw === response.request().postData() && isDeepStrictEqual(original, event), "response_request_mismatch");
      const outcome = await response.json() as Record<string, unknown>;
      // Keep the existing registered temporary operation result nonterminal.
      if (status === 503 && outcome.type === "https://arkret.org/problems/temporarily_unavailable" && outcome.status === 503) { log("response"); return; }
      require(response.ok() && (outcome.status === "committed" || outcome.status === "duplicate"), "submit_not_accepted");
      require(Object.keys(outcome).every(key => key === "status" || key === "commit"), "ordinary_outcome_branch_mismatch");
      try { assertAuthoritySubmitOutcome(outcome, event, "Direct Chat send diagnostic"); }
      catch { throw new Error("accepted_coordinate_pairing_failed"); }
      const commit = outcome.commit as Record<string, unknown>;
      const keys = ["commit_id", "realm_id", "stream_ref", "stream_position", "previous_commit_ref", "event_ref", "governance_generation", "authority_ref", "committed_at", "signature"];
      require(keys.every(key => key in commit) && Object.keys(commit).every(key => keys.includes(key) || key === "producer_signer_fact_digest"), "commit_closed_shape_mismatch");
      require(commit.realm_id === realm && commit.event_ref === event.event_id && canonicalJson(commit.stream_ref) === canonicalJson({ kind: "realm", realm_id: realm }), "accepted_scope_pairing_failed");
      require(typeof commit.stream_position === "number" && Number.isSafeInteger(commit.stream_position) && commit.stream_position >= 0 && typeof commit.governance_generation === "number" && Number.isSafeInteger(commit.governance_generation) && commit.governance_generation >= 0, "accepted_integer_pairing_failed");
      require(sdkEventDerivedIds(event).event_id === event.event_id, "event_content_id_mismatch");
      const { commit_id, signature, ...unsigned } = commit;
      const expectedId = "ak:realm_commit:" + Buffer.concat([Buffer.from([1]), Buffer.from(sha256CanonicalJson(unsigned), "hex")]).toString("base64url");
      require(commit_id === expectedId, "commit_content_id_mismatch");
      const proof = signature as Record<string, unknown>;
      require(proof.context === "ak.realm_commit_signature.v1" && proof.signature_algorithm === "Ed25519" && proof.signed_digest === "sha256:" + sha256CanonicalJson({ commit_id, ...unsigned }), "commit_signature_binding_mismatch");
      if (originalCommit !== undefined) require(isDeepStrictEqual(originalCommit, commit), "accepted_original_changed");
      originalCommit = commit;
      paired = true;
      accepted = true;
      log("response");
    } catch (error) {
      const reasons = ["response_request_mismatch", "submit_not_accepted", "ordinary_outcome_branch_mismatch", "accepted_coordinate_pairing_failed", "commit_closed_shape_mismatch", "accepted_scope_pairing_failed", "accepted_integer_pairing_failed", "event_content_id_mismatch", "commit_content_id_mismatch", "commit_signature_binding_mismatch", "accepted_original_changed"];
      failed = error instanceof Error && reasons.includes(error.message) ? error.message : "response_pairing_failed";
      log("response");
    }
  };
  const onFailed = (request: Request) => {
    try { if (select(request)) { status = -1; log("transport_failed"); } }
    catch { failed = "request_pairing_failed"; log("transport_failed"); }
  };
  page.on("request", onRequest);
  page.on("response", onResponse);
  page.on("requestfailed", onFailed);
  log("observing");
  return {
    check: () => { if (failed) throw new Error(`Direct Chat send diagnostic: ${failed}`); },
    paired: () => accepted && paired,
    modelProgress: () => log("model_progress"),
    dispose: () => { page.off("request", onRequest); page.off("response", onResponse); page.off("requestfailed", onFailed); log("finished"); },
  };
}

export async function structureWrite(page: Page, action: string, kind: string, title?: string, topic?: string): Promise<IngressEvent> {
  const panel = page.getByTestId("direct-structure");
  await expect(panel).toBeVisible();
  if (!await panel.getByRole("combobox", { name: "Action", exact: true }).isVisible()) {
    await panel.getByRole("button", { name: "Manage chats and topics" }).click();
  }
  await panel.getByRole("combobox", { name: "Action", exact: true }).selectOption(action);
  if (title) await panel.getByRole("textbox", { name: "Title", exact: true }).fill(title);
  if (topic) await panel.getByRole("combobox", { name: "Topic", exact: true }).selectOption(topic);
  await expect(panel.getByRole("button", { name: "Save", exact: true })).toBeEnabled({ timeout: 180_000 });
  const responses: Response[] = [];
  let wake: (() => void) | undefined;
  const capture = (response: Response) => {
    if (response.request().method() !== "POST" || new URL(response.url()).pathname !== "/_arkret/self/events") return;
    if (!ingressEvents(decodeEventIngressBody(response.request().postDataJSON())).some(event => event.kind === kind)) return;
    responses.push(response);
    wake?.();
  };
  page.on("response", capture);
  const deadline = Date.now() + 90_000;
  let frozen: IngressEvent | undefined;
  try {
    await panel.getByRole("button", { name: "Save", exact: true }).click();
    while (Date.now() < deadline) {
      if (!responses.length) {
        await new Promise<void>(resolve => {
          const timer = setTimeout(() => { wake = undefined; resolve(); }, Math.max(0, deadline - Date.now()));
          wake = () => { clearTimeout(timer); wake = undefined; resolve(); };
        });
      }
      const accepted = responses.shift();
      if (!accepted) break;
      const event = ingressEvents(decodeEventIngressBody(accepted.request().postDataJSON())).find(event => event.kind === kind)!;
      if (!frozen) frozen = event;
      expect(isDeepStrictEqual(event, frozen), "retry must preserve the complete frozen signed Event").toBe(true);
      const outcome = await accepted.json() as Record<string, unknown>;
      if (accepted.status() === 503 && outcome.type === "https://arkret.org/problems/temporarily_unavailable"
        && outcome.status === 503) continue;
      expect(accepted.ok(), `structure HTTP refusal: ${accepted.status()} ${String(outcome.type)}`).toBeTruthy();
      expect(outcome.status, `structure refusal: ${String(outcome.reason_code)}`).toBe("committed");
      assertAuthoritySubmitOutcome(outcome, event, action);
      await expect(panel.getByTestId("direct-structure-status")).toHaveText("Saved", { timeout: Math.max(1, deadline - Date.now()) });
      return event;
    }
    throw new Error("structure write did not commit within the original 90 second budget");
  } finally {
    page.off("response", capture);
    wake?.();
  }
}

export async function agentTopicChats(page: Page, receiptPath: string) {
  expect(receiptPath, "actual runtime model receipt path").not.toBe("");
  const panel = page.getByTestId("direct-structure");
  const mainId = decodeURIComponent(new URL(page.url()).pathname.split("/")[3]);
  const suffix = Date.now();
  const topic = await structureWrite(page, "new_topic", "ak.space.create", `agent-topic-${suffix}`);
  const topicId = topic.event_id!.replace("ak:event:", "ak:space:");
  const chats: string[] = [];
  for (const name of ["a", "b"]) {
    const created = await structureWrite(page, "new_chat", "ak.strand.create", `agent-chat-${name}-${suffix}`);
    const id = created.event_id!.replace("ak:event:", "ak:strand:");
    const choose = panel.getByRole("combobox", { name: "Chat", exact: true });
    try {
      await expect(choose.locator(`option[value=${JSON.stringify(id)}]`)).toContainText(`agent-chat-${name}-${suffix}`);
    } catch (error) {
      const controls = await panel.evaluate(element => Array.from(element.querySelectorAll("select")).map(select => ({
        label: select.getAttribute("aria-label"),
        role: select.getAttribute("role"),
        hidden: select.hidden,
        disabled: select.disabled,
        multiple: select.multiple,
        size: select.size,
        value: select.value,
        display: getComputedStyle(select).display,
        visibility: getComputedStyle(select).visibility,
        options: Array.from(select.options).map(option => ({ value: option.value, title: option.text })),
      })));
      await test.info().attach("chat-selector-dom", {
        body: JSON.stringify({ expectedChat: id, controls }),
        contentType: "application/json",
      });
      throw error;
    }
    await choose.selectOption(id);
    await structureWrite(page, "place", "ak.strand.update", undefined, topicId);
    const preference = panel.getByTestId("direct-agent-reply-preference");
    await expect(preference).toBeVisible();
    const replacing = page.waitForResponse(response => response.request().method() === "PUT"
      && /^\/_arkret\/self\/agents\/[^/]+\/participation$/.test(new URL(response.url()).pathname)
      && response.request().postDataJSON()?.target_scope?.strand_id === id);
    await preference.getByRole("button", { name: "Allow Agent replies in this Chat", exact: true }).click();
    const replaced = await replacing;
    expect(replaced.ok(), "selected Chat participation must be accepted").toBeTruthy();
    const request = replaced.request().postDataJSON();
    expect(request.target_scope).toEqual({ kind: "strand", realm_id: created.realm_id, strand_id: id });
    expect(request.expected_version).toBe(0);
    expect(request.selection).toEqual({
      reply_message: true, reaction_add: false, reaction_remove: false,
      accept_third_party_mention: false, act_on_behalf: false,
    });
    const outcome = await replaced.json();
    expect(outcome.participation_entries).toEqual(expect.arrayContaining([
      expect.objectContaining({ target_scope: request.target_scope, selection: request.selection, version: 1 }),
    ]));
    await expect(preference.getByRole("status")).toHaveText("Reply preference saved for this Chat");
    chats.push(id);
  }
  const markerA = `isolated-chat-a-${suffix}`;
  const markerB = `isolated-chat-b-${suffix}`;
  const receipts = async (): Promise<Array<{ request: unknown }>> => (await readFile(receiptPath, "utf8"))
    .trim().split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line));
  const send = async (id: string, marker: string, prior?: string, excluded?: string) => {
    await panel.getByRole("combobox", { name: "Chat", exact: true }).selectOption(id);
    const before = (await receipts()).length;
    const repliesBefore = await page.getByTestId("chat-message").filter({ has: page.getByTestId("content-block-text").filter({ hasText: /^pong(?:\r?\n|$)/ }) }).count();
    await expect(page.getByTestId("send-chat-button")).toBeEnabled({ timeout: 180_000 });
    await page.getByTestId("chat-input").fill(marker);
    const observed = await observeSelectedHumanSend(page, id);
    try {
      await page.getByTestId("send-chat-button").click();
      // One original 180s window covers both pairing and model receipt progress.
      await expect.poll(async () => {
        observed.check();
        const count = (await receipts()).length;
        return observed.paired() ? count : before;
      }, { timeout: 180_000 }).toBeGreaterThan(before);
      observed.modelProgress();
    } finally {
      observed.dispose();
    }
    const inputs = (await receipts()).slice(before).map(row => JSON.stringify(row.request));
    const input = inputs.find(value => value.includes(marker));
    expect(input, "live runtime must forward the selected Chat message").toBeDefined();
    if (prior) expect(input).toContain(prior);
    if (excluded) expect(input).not.toContain(excluded);
    await expect(page.getByTestId("chat-message").filter({ has: page.getByTestId("content-block-text").filter({ hasText: /^pong(?:\r?\n|$)/ }) })).toHaveCount(repliesBefore + 1, { timeout: 180_000 });
  };
  await send(chats[0], markerA, undefined, markerB);
  await send(chats[1], markerB, undefined, markerA);
  await structureWrite(page, "rename_topic_target", "ak.space.update", `agent-topic-renamed-${suffix}`, topicId);
  await structureWrite(page, "archive_topic_target", "ak.space.archive", undefined, topicId);
  await send(chats[0], `continued-chat-a-${suffix}`, markerA, markerB);
  await structureWrite(page, "unplace", "ak.strand.update");
  await send(chats[0], `unclassified-chat-a-${suffix}`, markerA, markerB);
  await panel.getByRole("combobox", { name: "Chat", exact: true }).selectOption(mainId);
}

export async function flatTopicChats(alice: Page, bob: Page, mainMessages: string[], extraDevices: Page[] = []) {
  const pages = [alice, bob, ...extraDevices];
  for (const page of pages) {
    await page.addLocatorHandler(page.getByTestId("mls-backup-modal"), async () => {
      await page.getByTestId("mls-backup-dismiss").click();
    });
  }
  try {
    await runFlatTopicChats(alice, bob, mainMessages, extraDevices);
  } finally {
    for (const page of pages) {
      await page.removeLocatorHandler(page.getByTestId("mls-backup-modal"));
    }
  }
}

async function runFlatTopicChats(alice: Page, bob: Page, mainMessages: string[], extraDevices: Page[]) {
  const mainPath = new URL(alice.url()).pathname;
  const mainId = decodeURIComponent(mainPath.split("/")[3]);
  const suffix = Date.now();
  const topicName = `topic-${suffix}`;
  const chatName = `chat-${suffix}`;
  const topic = await structureWrite(alice, "new_topic", "ak.space.create", topicName);
  const topicId = topic.event_id!.replace("ak:event:", "ak:space:");
  const object = topic.payload?.object as Record<string, unknown>;
  expect(object.kind).toBe("topic");
  expect(object.parent_space_id).toBeUndefined();
  expect(object.title).toBeUndefined();
  expect(object.encrypted_metadata).toBeTruthy();
  expect(JSON.stringify(object)).not.toContain(topicName);
  const chat = await structureWrite(alice, "new_chat", "ak.strand.create", chatName);
  const chatId = chat.event_id!.replace("ak:event:", "ak:strand:");
  expect(chatId).not.toBe(mainId);
  expect((chat.payload?.object as Record<string, unknown>).topic).toBeUndefined();
  expect(JSON.stringify(chat.payload)).not.toContain(chatName);
  for (const page of [alice, bob, ...extraDevices]) {
    const choose = page.getByTestId("direct-structure").getByRole("combobox", { name: "Chat", exact: true });
    await expect(choose.locator(`option[value=${JSON.stringify(chatId)}]`)).toContainText(chatName, { timeout: 90_000 });
    await choose.selectOption(chatId);
    for (const message of mainMessages) await expect(page.getByTestId("chat-message").filter({ hasText: message })).toHaveCount(0);
  }
  await bob.getByTestId("watch-level-toggle").click({ timeout: 30_000 });
  await bob.getByTestId("watch-level-menu").locator('[data-watch-level="all"]').click();
  await expect(bob.getByTestId("watch-level-toggle")).toContainText("All", { timeout: 90_000 });
  const classified = await structureWrite(alice, "place", "ak.strand.update", undefined, topicId);
  expect(classified.payload?.target_ref).toBe(chatId);
  expect(classified.payload?.expected_state_digest).toMatch(/^sha256:[a-f0-9]{64}$/);
  const patch = classified.payload?.patch as Record<string, { $op: string; value?: { space_id: string } }>;
  expect(patch.topic.value?.space_id).toBe(topicId);
  const chooseAlice = alice.getByTestId("direct-structure").getByRole("combobox", { name: "Chat", exact: true });
  const chatDraft = `draft-chat-${suffix}`;
  const mainDraft = `draft-main-${suffix}`;
  await alice.getByTestId("chat-input").fill(chatDraft);
  await chooseAlice.selectOption(mainId);
  await expect(alice.getByTestId("chat-input")).toHaveValue("");
  await alice.getByTestId("chat-input").fill(mainDraft);
  await chooseAlice.selectOption(chatId);
  await expect(alice.getByTestId("chat-input")).toHaveValue(chatDraft);
  for (const [sender, recipient] of [[alice, bob], [bob, alice]] as const) {
    const text = `topic-chat-${sender === alice ? "a" : "b"}-${suffix}`;
    if (sender === alice) {
      await bob.getByTestId("direct-structure").getByRole("combobox", { name: "Chat", exact: true }).selectOption(mainId);
    }
    await sender.getByTestId("chat-input").fill(text);
    const sending = sender.waitForResponse(response => response.request().method() === "POST"
      && new URL(response.url()).pathname === "/_arkret/self/events"
      && ingressEvents(decodeEventIngressBody(response.request().postDataJSON())).some(event => event.kind === "ak.message.create"));
    await sender.getByTestId("send-chat-button").click();
    const sent = await sending;
    const message = ingressEvents(decodeEventIngressBody(sent.request().postDataJSON())).find(event => event.kind === "ak.message.create")!;
    expect(message.payload?.strand_id).toBe(chatId);
    expect(message.payload?.encrypted_content).toBeTruthy();
    expect(JSON.stringify(message.payload)).not.toContain(text);
    if (sender === alice) {
      await expect(bob.getByTestId("direct-structure").getByRole("combobox", { name: "Chat", exact: true })
        .locator(`option[value=${JSON.stringify(chatId)}]`)).toContainText(/\d+ unread/, { timeout: 90_000 });
      await bob.getByTestId("topbar-notifications-button").click();
      const notification = bob.getByTestId("notification-item").filter({
        has: bob.locator(`a[href$=${JSON.stringify(`/${chatId}`)}]`),
      }).first();
      await expect(notification).toBeVisible({ timeout: 90_000 });
      await notification.getByTestId("notification-open-chat").click();
      await expect(bob.getByTestId("notifications-drawer")).toHaveCount(0);
      await expect(bob).toHaveURL(new RegExp(`/direct/.*/${chatId}$`));
      await expect(bob.getByTestId("direct-structure").getByRole("combobox", { name: "Chat", exact: true })).toHaveValue(chatId);
      await expect(bob.getByTestId("direct-structure").getByRole("combobox", { name: "Chat", exact: true })
        .locator(`option[value=${JSON.stringify(chatId)}]`)).not.toContainText("unread", { timeout: 90_000 });
    }
    await expect(recipient.getByTestId("chat-message").filter({ hasText: text })).toBeVisible({ timeout: 90_000 });
    for (const device of extraDevices) {
      await expect(device.getByTestId("chat-message").filter({ hasText: text })).toBeVisible({ timeout: 90_000 });
    }
  }
  await chooseAlice.selectOption(mainId);
  await expect(alice.getByTestId("chat-input")).toHaveValue(mainDraft);
  await chooseAlice.selectOption(chatId);
  await expect(alice.getByTestId("chat-input")).toHaveValue("");
  const renamed = `${topicName}-renamed`;
  await structureWrite(bob, "rename_topic_target", "ak.space.update", renamed, topicId);
  await Promise.all([alice, bob, ...extraDevices].map(page => page.reload()));
  for (const page of [alice, bob, ...extraDevices]) {
    const choose = page.getByTestId("direct-structure").getByRole("combobox", { name: "Chat", exact: true });
    await expect(choose.locator(`option[value=${JSON.stringify(chatId)}]`)).toContainText(renamed, { timeout: 90_000 });
    await choose.selectOption(chatId);
  }
  const cleared = await structureWrite(alice, "unplace", "ak.strand.update");
  expect((cleared.payload?.patch as Record<string, unknown>).topic).toEqual({ $op: "unset" });
  await structureWrite(bob, "delete_topic_target", "ak.space.tombstone", undefined, topicId);
  for (const page of [alice, bob]) {
    await page.getByTestId("direct-structure").getByRole("combobox", { name: "Chat", exact: true }).selectOption(mainId);
    for (const message of mainMessages) await expect(page.getByTestId("chat-message").filter({ hasText: message })).toBeVisible({ timeout: 90_000 });
  }
  expect(new URL(alice.url()).pathname).toBe(mainPath);
  expect(decodeURIComponent(new URL(bob.url()).pathname.split("/")[2])).toBe(decodeURIComponent(mainPath.split("/")[2]));
}
