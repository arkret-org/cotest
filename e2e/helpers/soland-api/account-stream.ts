import { expect, type APIRequestContext } from "@playwright/test";

import { type SolandKey, solandBaseUrl } from "../env";
import { authHeaders } from "./request";
import { canonicalJson } from "./wire-client";

type AccountSubscribeOptions = {
  server?: SolandKey;
  filter?: Record<string, unknown>;
  catchup?: boolean;
  after?: string;
  timeoutMs?: number;
  headers?: Record<string, string>;
};

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
        ...(opts.headers ?? authHeaders(token, "GET", url.toString())),
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
