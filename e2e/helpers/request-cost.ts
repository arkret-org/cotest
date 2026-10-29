import type { Page, Request, WebSocket } from "@playwright/test";

type HttpCost = { method: string; origin: string; path: string; started_ms: number; elapsed_ms: number | null;
  failed: boolean; response_body_bytes: number | null; response_header_bytes: number | null;
  request_body_bytes: number | null; request_header_bytes: number | null; rows: number | null };
type SocketCost = { origin: string; path: string; opened_ms: number; sent_frames: number; received_frames: number;
  sent_bytes: number; received_bytes: number;
  received_kinds: Record<string, number>; channel_frame_kinds: Record<string, Record<string, number>>;
  closed_ms: number | null; socket_errors: number;
  requested_channels: Array<{ channel_id: string; operation_id: string }>;
  opened_channels: Array<{ channel_id: string; operation_id: string }> };

const socketKinds = new Set(["challenge", "welcome", "opened", "data", "channel_control", "closed", "error", "ping", "pong", "connection_control"]);
const streamKinds = new Set(["delta", "checkpoint", "heartbeat", "catchup_complete", "resync_required", "dropped", "unauthorized", "committed_event"]);

// Observe the actual browser transport, excluding Node fixture/oracle callers.
// Retain only costs and public operation coordinates, never headers or bodies.
export function observeRequestCost(page: Page) {
  const started = performance.now();
  const beforeNavigation = page.url() === "about:blank";
  const requests = new Map<Request, HttpCost>();
  const sockets: SocketCost[] = [];
  const pending = new Set<Promise<void>>();
  const active = new Map<string, number>();
  const maximum = new Map<string, number>();
  const elapsed = () => Math.round((performance.now() - started) * 100) / 100;
  const collection = (path: string) => path.match(/\/_arkret\/self\/realms\/[^/]+\/(spaces|strands)$/)?.[1];
  const onRequest = (request: Request) => {
    const { origin, pathname: path } = new URL(request.url());
    if (!path.startsWith("/_arkret/")) return;
    requests.set(request, { method: request.method(), origin, path, started_ms: elapsed(), elapsed_ms: null,
      failed: false, response_body_bytes: null, response_header_bytes: null,
      request_body_bytes: null, request_header_bytes: null, rows: null });
    const key = collection(path);
    const scope = origin + path;
    if (key) { const count = (active.get(scope) ?? 0) + 1; active.set(scope, count);
      maximum.set(scope, Math.max(maximum.get(scope) ?? 0, count)); }
  };
  const finish = (request: Request, failed: boolean) => {
    const row = requests.get(request);
    if (!row || row.elapsed_ms !== null) return;
    row.elapsed_ms = Math.max(0, elapsed() - row.started_ms);
    row.failed = failed;
    const key = collection(row.path);
    const scope = row.origin + row.path;
    if (key) active.set(scope, Math.max(0, (active.get(scope) ?? 1) - 1));
    const work = (async () => {
      if (failed) return;
      try {
        const sizes = await request.sizes();
        const known = (value: number) => Number.isFinite(value) && value >= 0 ? value : null;
        row.response_body_bytes = known(sizes.responseBodySize);
        row.response_header_bytes = known(sizes.responseHeadersSize);
        row.request_body_bytes = known(sizes.requestBodySize);
        row.request_header_bytes = known(sizes.requestHeadersSize);
      } catch { /* Unavailable transport sizes remain null. */ }
      if (failed || !key && !/\/(scan|snapshot|current)$/.test(row.path)) return;
      try {
        const response = await request.response();
        if (!response?.ok() || !(await response.headerValue("content-type"))?.includes("application/json")) return;
        const body = await response.json();
        const values = key ? body[key] : body.committed_events ?? body.events ?? body.items;
        if (Array.isArray(values)) row.rows = values.length;
      } catch { /* A non-list response has no inferred zero row count. */ }
    })();
    pending.add(work);
    void work.finally(() => pending.delete(work));
  };
  const onFinished = (request: Request) => finish(request, false);
  const onFailed = (request: Request) => finish(request, true);
  const onSocket = (socket: WebSocket) => {
    const { origin, pathname: path } = new URL(socket.url());
    if (!path.startsWith("/_arkret/")) return;
    const row: SocketCost = { origin, path, opened_ms: elapsed(), sent_frames: 0, received_frames: 0,
      sent_bytes: 0, received_bytes: 0, requested_channels: [], opened_channels: [],
      received_kinds: {}, channel_frame_kinds: {}, closed_ms: null, socket_errors: 0 };
    sockets.push(row);
    socket.on("close", () => { row.closed_ms = elapsed(); });
    socket.on("socketerror", () => { row.socket_errors += 1; });
    socket.on("framesent", ({ payload }) => {
      row.sent_frames += 1; row.sent_bytes += Buffer.byteLength(payload);
      try {
        const frame = JSON.parse(payload.toString());
        if (frame.kind === "open" && typeof frame.channel_id === "string" && typeof frame.operation_id === "string") {
          row.requested_channels.push({ channel_id: frame.channel_id, operation_id: frame.operation_id });
        }
      } catch { /* Binary or non-JSON frames still contribute their actual bytes. */ }
    });
    socket.on("framereceived", ({ payload }) => {
      row.received_frames += 1; row.received_bytes += Buffer.byteLength(payload);
      try {
        const frame = JSON.parse(payload.toString());
        // Keep only closed discriminator counts. Payloads, cursors, challenges,
        // credentials and arbitrary error text must never enter this evidence.
        const kind = socketKinds.has(frame.kind) ? frame.kind : "other";
        row.received_kinds[kind] = (row.received_kinds[kind] ?? 0) + 1;
        if (typeof frame.channel_id === "string"
          && row.requested_channels.some(channel => channel.channel_id === frame.channel_id)) {
          const counts = row.channel_frame_kinds[frame.channel_id] ??= {};
          const payloadKind = streamKinds.has(frame.payload?.kind) ? frame.payload.kind : "other";
          const key = kind === "data" || kind === "channel_control" ? `${kind}:${payloadKind}` : kind;
          counts[key] = (counts[key] ?? 0) + 1;
        }
        if (frame.kind === "opened" && typeof frame.channel_id === "string" && typeof frame.operation_id === "string") {
          row.opened_channels.push({ channel_id: frame.channel_id, operation_id: frame.operation_id });
        }
      } catch { /* Non-JSON frames have no inferred channel acceptance. */ }
    });
  };
  page.on("request", onRequest);
  page.on("requestfinished", onFinished);
  page.on("requestfailed", onFailed);
  page.on("websocket", onSocket);
  return {
    mark: () => elapsed(),
    async snapshot(since = 0) {
      await Promise.all([...pending]);
      return { observation_started_before_navigation: beforeNavigation, observed_ms: elapsed(), since_ms: since,
        http: [...requests.values()].filter(row => row.started_ms >= since).map(row => ({ ...row })),
        maximum_parallel_lists: Object.fromEntries(maximum), active_lists: Object.fromEntries(active),
        websocket: structuredClone(sockets),
        byte_semantics: "HTTP encoded response body and request/response headers from Request.sizes; unavailable=null; WS application payload bytes exclude framing/TLS" };
    },
    dispose() {
      page.off("request", onRequest); page.off("requestfinished", onFinished);
      page.off("requestfailed", onFailed); page.off("websocket", onSocket);
    },
  };
}
