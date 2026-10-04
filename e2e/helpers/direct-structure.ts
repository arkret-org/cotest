import { expect } from "./arkret-test";
import type { Page, Response } from "@playwright/test";
import { assertAuthoritySubmitOutcome } from "./soland-api";
import { decodeEventIngressBody, ingressEvents, type IngressEvent } from "./event-ingress";
import { readFile } from "node:fs/promises";
import { isDeepStrictEqual } from "node:util";

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
      await expect(panel.getByRole("status")).toHaveText("Saved", { timeout: Math.max(1, deadline - Date.now()) });
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
    await expect(choose.locator(`option[value=${JSON.stringify(id)}]`)).toContainText(`agent-chat-${name}-${suffix}`);
    await choose.selectOption(id);
    await structureWrite(page, "place", "ak.strand.update", undefined, topicId);
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
    await page.getByTestId("send-chat-button").click();
    await expect.poll(async () => (await receipts()).length, { timeout: 180_000 }).toBeGreaterThan(before);
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
