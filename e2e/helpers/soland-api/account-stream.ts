import { expect, type APIRequestContext } from "@playwright/test";

import { type SolandKey, solandBaseUrl } from "../env";
import { authHeaders } from "./request";
import { canonicalJson } from "./wire-client";

type AccountSubscribeOptions = {
  server?: SolandKey;
  filter?: Record<string, unknown>;
  catchup?: boolean;
  after?: string;
  waitFor?: string;
  timeoutMs?: number;
  headers?: Record<string, string>;
};

// A catchup_complete frame completes one response, not a selected Realm's
// detail baseline. Keep the exact filter and opaque continuation until the
// Station discloses the complete current window or refuses it.
export async function accountSubscribeRealmFramesApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  opts: AccountSubscribeOptions & {
    onRead?: (diagnostic: Record<string, unknown>) => Promise<void>;
  } = {},
): Promise<Array<Record<string, unknown>>> {
  const { onRead, ...subscription } = opts;
  const timeoutMs = opts.timeoutMs ?? 60_000;
  const deadline = Date.now() + timeoutMs;
  let after = opts.after;
  let attempt = 0;
  while (Date.now() < deadline) {
    const frames = await accountSubscribeFramesApi(request, token, {
      ...subscription,
      after,
      timeoutMs: Math.max(1, Math.min(35_000, deadline - Date.now())),
    });
    const kinds = [
      "delta", "catchup_complete", "checkpoint", "heartbeat",
      "dropped", "resync_required", "unauthorized",
    ];
    const codes = [
      "revision_unavailable", "limit_exceeded", "temporarily_unavailable",
      "not_found", "witness_disagreement",
    ];
    const buckets = frames.map((frame) =>
      (frame.realms as Record<string, Record<string, unknown>> | undefined)?.[realmId],
    );
    await onRead?.({
      attempt: ++attempt,
      resumed: !!after,
      frames: frames.map((frame, index) => {
        const bucket = buckets[index];
        const code = (bucket?.unavailable as Record<string, unknown> | undefined)?.error_code;
        return {
          kind: kinds.includes(String(frame.kind)) ? String(frame.kind) : "unknown",
          selectedRealm: !!bucket,
          current: !!bucket?.current,
          hasCursor: typeof frame.cursor === "string",
          accountBaseline: !!frame.baseline,
          errorCode: code === undefined ? null
            : codes.includes(String(code)) ? String(code) : "unknown",
        };
      }),
    });
    expect(frames.every((frame) => kinds.includes(String(frame.kind))),
      "Account read carries registered frame kinds").toBe(true);
    expect(frames.some((frame) => frame.kind === "unauthorized"),
      "Account Realm read remains authorized").toBe(false);
    for (const bucket of buckets) {
      const unavailable = bucket?.unavailable as Record<string, unknown> | undefined;
      expect(unavailable === undefined || unavailable.error_code === "temporarily_unavailable",
        "Account Realm read retries only registered temporary unavailability").toBe(true);
    }
    const control = frames.find((frame) =>
      frame.kind === "dropped" || frame.kind === "resync_required");
    if (!control && buckets.some((bucket) => !!bucket?.current)) return frames;
    if (control?.kind === "resync_required") {
      after = undefined;
    } else {
      after = [...frames].reverse()
        .find((frame) => typeof frame.cursor === "string")?.cursor as string | undefined;
      expect(typeof after === "string",
        "Account segmented baseline or dropped stream carries its opaque continuation").toBe(true);
    }
    const delay = Number(control?.reconnect_after_ms ?? 500);
    expect(Number.isInteger(delay) && delay > 0,
      "Account reconnect delay is a positive server hint").toBe(true);
    if (Date.now() + delay >= deadline) break;
    await new Promise((resolve) => setTimeout(resolve, delay));
  }
  throw new Error(`Account stream did not disclose selected Realm current within ${timeoutMs}ms`);
}

export async function accountSubscribeDeltaApi(
  request: APIRequestContext,
  token: string,
  opts: AccountSubscribeOptions = {},
): Promise<Record<string, unknown>> {
  const frames = await accountSubscribeFramesApi(request, token, opts);
  const delta = frames.find((frame) => frame.kind === "delta") ?? frames[0];
  expect(delta, "account subscribe delta frame").toBeTruthy();
  return delta;
}

export async function accountSubscribeFramesApi(
  request: APIRequestContext,
  token: string,
  opts: AccountSubscribeOptions = {},
): Promise<Array<Record<string, unknown>>> {
  void request;
  const url = new URL(
    `${solandBaseUrl(opts.server)}/_arkret/self/account/subscribe`,
  );
  if (opts.catchup !== false) {
    url.searchParams.set("catchup", "true");
  }
  if (opts.filter) {
    url.searchParams.set("filter", canonicalJson(opts.filter));
  }
  if (opts.after) {
    url.searchParams.set("after", opts.after);
  }

  const controller = new AbortController();
  const timeoutMs = opts.timeoutMs ?? 30_000;
  const frames: Array<Record<string, unknown>> = [];
  let timedOut = false;
  const timeout = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  try {
    const response = await fetch(url, {
      headers: {
        ...authHeaders(token, "GET", url.toString()),
        ...opts.headers,
        ...(opts.waitFor ? { "X-Arkret-Wait-For": opts.waitFor } : {}),
        accept: "application/x-ndjson",
        "Arkret-Operation": "ak.self.account.stream.subscribe.v1",
      },
      signal: controller.signal,
    });
    if (response.status !== 200) {
      const text = await response.text();
      expect(
        response.status,
        `account subscribe returned ${response.status}: ${text}`,
      ).toBe(200);
    }
    if (!response.body) {
      const text = await response.text();
      frames.push(...parseNdjsonFrames(text));
      return frames;
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let pending = "";
    let decided = false;
    while (!decided) {
      const chunk = await reader.read();
      if (chunk.done) {
        break;
      }
      pending += decoder.decode(chunk.value, { stream: true });
      let newline = pending.search(/\r?\n/);
      while (newline >= 0) {
        const line = pending.slice(0, newline).trim();
        pending = pending.slice(
          pending.charCodeAt(newline) === 13 ? newline + 2 : newline + 1,
        );
        if (line) {
          const frame = JSON.parse(line) as Record<string, unknown>;
          frames.push(frame);
          if (accountSubscribeFrameCompletesSnapshot(frame)) {
            decided = true;
            break;
          }
        }
        newline = pending.search(/\r?\n/);
      }
    }
    const tail = (pending + decoder.decode()).trim();
    if (!decided && tail) {
      frames.push(...parseNdjsonFrames(tail));
    }
    await reader.cancel().catch(() => undefined);
  } catch (error) {
    if (timedOut || (error instanceof Error && error.name === "AbortError")) {
      throw new Error(`account subscribe timed out after ${timeoutMs}ms`);
    }
    throw error;
  } finally {
    clearTimeout(timeout);
    controller.abort();
  }

  expect(frames.length, "account subscribe frames").toBeGreaterThan(0);
  return frames;
}

function accountSubscribeFrameCompletesSnapshot(
  frame: Record<string, unknown>,
): boolean {
  return (
    frame.kind === "catchup_complete" ||
    frame.kind === "dropped" ||
    frame.kind === "resync_required" ||
    frame.kind === "unauthorized"
  );
}

function parseNdjsonFrames(text: string): Array<Record<string, unknown>> {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}
