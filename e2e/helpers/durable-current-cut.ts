import { expect, type Page } from "@playwright/test";
import type { CommitStreamHead } from "./generated/spec-wire-objects";

// This is test evidence from the real durable current index, not a transport
// receipt, history cursor, or a synthetic replacement for product installation.
export async function waitForDurableCurrentCut(page: Page, acknowledged: CommitStreamHead | undefined,
  { timeoutMs = 90_000 } = {}) {
  if (!acknowledged || acknowledged.stream_ref.kind !== "realm"
      || !/^ak:realm:[A-Za-z0-9_-]{40,64}$/.test(acknowledged.stream_ref.realm_id)
      || !/^ak:realm_commit:[A-Za-z0-9_-]{40,64}$/.test(acknowledged.commit_id)
      || !Number.isSafeInteger(acknowledged.stream_position) || acknowledged.stream_position < 0) {
    throw new Error("durable current readiness requires an acknowledged Realm head");
  }
  let observed: CommitStreamHead | null = null;
  await expect.poll(async () => {
    // Validate and project inside the browser. No arbitrary hook output leaves
    // this observer, even if a malformed test build returns unrelated data.
    observed = await page.evaluate(async ({ realm }) => {
      const hook = (window as unknown as {
        __inkson_durable_current_cut?: (realm: string) => Promise<string>
      }).__inkson_durable_current_cut;
      if (typeof hook !== "function") return null;
      let cut: unknown;
      try { cut = JSON.parse(await hook(realm)); } catch { return null; }
      if (!cut || typeof cut !== "object") return null;
      const value = cut as Record<string, unknown>;
      if (value.complete !== true || !Array.isArray(value.heads)
          || Object.keys(value).some(key => key !== "complete" && key !== "heads")) return null;
      const heads = value.heads.filter((candidate): candidate is Record<string, unknown> =>
        Boolean(candidate) && typeof candidate === "object");
      const matches = heads.filter(head => {
        const stream = head.stream_ref as Record<string, unknown> | undefined;
        return stream?.kind === "realm" && stream.realm_id === realm;
      });
      if (matches.length !== 1) return null;
      const head = matches[0];
      const stream = head.stream_ref as Record<string, unknown>;
      if (Object.keys(head).some(key => !["stream_ref", "stream_position", "commit_id"].includes(key))
          || Object.keys(stream).some(key => key !== "kind" && key !== "realm_id")
          || typeof head.commit_id !== "string" || !/^ak:realm_commit:[A-Za-z0-9_-]{40,64}$/.test(head.commit_id)
          || typeof head.stream_position !== "number" || !Number.isSafeInteger(head.stream_position)
          || head.stream_position < 0) return null;
      return { stream_ref: { kind: "realm" as const, realm_id: realm },
        stream_position: head.stream_position, commit_id: head.commit_id };
    }, { realm: acknowledged.stream_ref.realm_id });
    if (observed === null || observed.stream_position < acknowledged.stream_position) return false;
    // A verified later head covers this accepted prefix in the same ordered
    // stream. Equal positions must retain the exact original Commit identity.
    if (observed.stream_position === acknowledged.stream_position
        && observed.commit_id !== acknowledged.commit_id) {
      throw new Error("durable current cut forks the acknowledged Realm head");
    }
    return true;
  }, { timeout: timeoutMs, message: "complete durable current cut must cover the accepted Realm head" }).toBe(true);
  return observed!;
}
