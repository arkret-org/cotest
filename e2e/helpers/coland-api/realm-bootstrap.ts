import type { APIRequestContext, APIResponse } from "@playwright/test";
import { authHeaders, wireErrCode } from "./request";

// authority-commit-log §3 permits exact retry of retryable_unavailable.
// The caller freezes the complete canonical atomic unit before this boundary.
export async function postFrozenRealmBootstrap(
  request: APIRequestContext,
  token: string,
  url: string,
  submission: string,
): Promise<APIResponse> {
  const deadline = Date.now() + 30_000;
  for (let retry = 0; ; retry += 1) {
    const response = await request.post(url, {
      headers: {
        ...authHeaders(token, "POST", url),
        "content-type": "application/json",
      },
      data: submission,
      timeout: Math.max(1, deadline - Date.now()),
    });
    if (response.status() !== 503 || retry >= 5) return response;
    const problem: unknown = await response.json().catch(() => undefined);
    if (wireErrCode(problem) !== "temporarily_unavailable") return response;
    const retryAfter = response.headers()["retry-after"];
    const bodyHint = (problem as Record<string, unknown>).retry_after_ms;
    const hint = retryAfter
      ? /^\d+$/.test(retryAfter)
        ? Number(retryAfter) * 1_000
        : Date.parse(retryAfter) - Date.now()
      : typeof bodyHint === "number" ? bodyHint : 0;
    const delay = Math.max(Number.isFinite(hint) ? hint : 0, 1_000 * 2 ** retry);
    if (Date.now() + delay >= deadline) return response;
    await response.dispose();
    await new Promise(resolve => setTimeout(resolve, delay));
  }
}
