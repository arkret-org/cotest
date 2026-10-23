import type { APIResponse } from "@playwright/test";
import { wireErrCode } from "./coland-api/request";

// Current /head reads can await native member-cut convergence. Exact historical
// reads and denied/malformed responses must never enter this readiness loop.
export async function readCurrentSnapshot<T>(
  read: (remainingMs: number) => Promise<Pick<APIResponse, "status" | "json">>,
  accept: (body: unknown) => Promise<T>,
  { timeoutMs = 90_000, retryDelayMs = 500 } = {},
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const response = await read(Math.max(1, deadline - Date.now()));
    const body: unknown = await response.json();
    const status = response.status();
    if (status === 200) return await accept(body);
    const code = wireErrCode(body);
    const declaredStatus = body && typeof body === "object"
      ? (body as Record<string, unknown>).status : undefined;
    if (status === 503 && declaredStatus === 503
      && code === "realm_state_snapshot_unavailable" && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, Math.min(retryDelayMs, deadline - Date.now())));
      if (Date.now() < deadline) continue;
    }
    const safeCode = code && /^[a-z][a-z0-9_]{0,79}$/.test(code) ? code : "unregistered";
    throw new Error(`Direct current Snapshot read failed: HTTP ${status}; code=${safeCode}`);
  }
}
