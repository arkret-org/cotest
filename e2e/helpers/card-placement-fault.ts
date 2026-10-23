import { expect, type Page, type Request, type Route } from "@playwright/test";
import { assertAuthoritySubmitOutcome, retypeEventDerivedId } from "./coland-api";
import { decodeIngressEvents } from "./event-ingress";

export type CardPlacementFault = "card-before-send" | "card-create-response-lost" | "card-move-response-lost";

// Cut the real request or its accepted response. Only public coordinates leave
// the holder vault; neither private content nor signing material is attached.
export async function installCardPlacementFault(page: Page, realm: string, fault: CardPlacementFault, cardTitle: string) {
  const submit = ({ pathname }: URL) => pathname === "/_arkret/self/events";
  const originals = new Map<string, string>();
  const ids = { create: new Set<string>(), move: new Set<string>() };
  let createId: string | undefined;
  let cutId: string | undefined;
  let acceptedCommit: string | undefined;
  let active = true;
  const selected = (request: Request) => {
    if (request.method() !== "POST" || !submit(new URL(request.url()))) return [];
    return decodeIngressEvents(request.postData(), { context: "card placement recovery" }).filter(event => {
      if (event.realm_id !== realm) return false;
      if (event.kind === "ak.strand.create") {
        const object = event.payload?.object as { tracks?: { synthesis?: { profile?: string } } } | undefined;
        if (object?.tracks?.synthesis?.profile !== "kanban_card") return false;
        createId ??= event.event_id;
        ids.create.add(String(event.event_id));
      } else if (event.kind === "ak.strand.move") {
        if (!createId || event.payload?.strand_id !== retypeEventDerivedId(createId, "strand")) return false;
        ids.move.add(String(event.event_id));
      } else return false;
      const key = String(event.kind);
      const original = originals.get(key);
      if (original) expect(request.postData() === original, `${key} must resume the frozen original`).toBe(true);
      else originals.set(key, request.postData()!);
      return true;
    });
  };
  const observe = (request: Request) => { selected(request); };
  page.on("request", observe);
  const handler = async (route: Route) => {
    const events = selected(route.request());
    const kind = fault === "card-move-response-lost" ? "ak.strand.move" : "ak.strand.create";
    const event = events.find(event => event.kind === kind);
    if (!active || !event) { await route.continue(); return; }
    if (!cutId && fault !== "card-before-send") {
      const response = await route.fetch();
      if (!response.ok()) { await route.fulfill({ response }); return; }
      const outcome = await response.json();
      assertAuthoritySubmitOutcome(outcome, event, "real card response-loss cut");
      acceptedCommit = String(outcome.commit.commit_id);
    }
    cutId ??= String(event.event_id);
    expect(event.event_id).toBe(cutId);
    await route.abort("connectionfailed");
  };
  await page.route(submit, handler);
  return {
    async restartAtCut(restartClient?: () => Promise<Page>) {
      await expect.poll(() => cutId, { timeout: 120_000 }).toBeTruthy();
      expect(ids.create.size).toBe(1);
      if (fault !== "card-before-send") expect(acceptedCommit).toMatch(/^ak:realm_commit:/);
      const durable = await page.evaluate(async ({ createId }) => {
        const read = <T>(request: IDBRequest<T>) => new Promise<T>((resolve, reject) => {
          request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
        });
        const db = await read(indexedDB.open("inkson.secret.inkson", 1));
        try {
          const tx = db.transaction(["entries", "wrapping_keys"], "readonly");
          const [key, names, entries] = await Promise.all([
            read(tx.objectStore("wrapping_keys").get("primary")) as Promise<CryptoKey>,
            read(tx.objectStore("entries").getAllKeys()), read(tx.objectStore("entries").getAll()),
          ]);
          if (!key || key.extractable) throw new Error("card queue requires its non-extractable wrapping key");
          for (let index = 0; index < names.length; index++) {
            if (!String(names[index]).startsWith("inkson.outbound.v1::") || !String(names[index]).endsWith(".standard")) continue;
            const entry = entries[index] as { iv: Uint8Array; ct: Uint8Array };
            const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: Uint8Array.from(entry.iv).buffer }, key, Uint8Array.from(entry.ct).buffer);
            const state = JSON.parse(new TextDecoder().decode(plain));
            const plan = state.card_placements?.[createId!];
            if (plan) return { create: createId, move: plan.move_event ?? null,
              localOperation: plan.local_operation_id,
              createCount: state.items.filter((item: Record<string, any>) => item.submission.event_id === createId).length,
              moveCount: plan.move_event ? state.items.filter((item: Record<string, any>) => item.submission.event_id === plan.move_event).length : 0 };
          }
          return null;
        } finally { db.close(); }
      }, { createId });
      expect(durable).toBeTruthy();
      expect(durable!.createCount).toBe(1);
      expect(durable!.localOperation.length).toBeGreaterThan(0);
      if (fault === "card-move-response-lost") {
        expect(durable!.move).toBe(cutId); expect(durable!.moveCount).toBe(1);
      } else expect(durable!.move).toBeNull();
      if (fault !== "card-move-response-lost") {
        await expect(page.getByTestId("kanban-card").filter({ hasText: cardTitle })).toHaveAttribute("data-card-draft", "true");
      }
      const url = page.url();
      let processRestarted = false;
      if (restartClient) {
        const originalPage = page;
        const originalContext = page.context();
        originalPage.off("request", observe);
        page = await restartClient();
        expect(originalPage.isClosed()).toBe(true);
        expect(page.context()).not.toBe(originalContext);
        page.on("request", observe);
        active = false;
        // The new process has not navigated yet. Observe its very first queue
        // recovery request without reseeding or exporting its private vault.
        await page.goto(url, { waitUntil: "domcontentloaded" });
        processRestarted = true;
      } else {
        await page.reload({ waitUntil: "domcontentloaded" });
        active = false;
        await page.unroute(submit, handler);
      }
      return { fault, original_create: createId, original_move: durable!.move, accepted_commit: acceptedCommit ?? null,
        runtime_reloaded: true, browser_process_restarted: processRestarted };
    },
    assertOneCardAndPlacement() {
      expect([...ids.create]).toEqual([createId]);
      expect(ids.move.size).toBe(1);
      return { creates: ids.create.size, moves: ids.move.size, exact_originals: true };
    },
    async dispose() { active = false; await page.unroute(submit, handler); page.off("request", observe); },
  };
}
