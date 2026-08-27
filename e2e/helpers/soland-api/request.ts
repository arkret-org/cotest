import { expect, type APIResponse } from "@playwright/test";

const registeredRequestAuth = new Map<
  string,
  (method: string, url: string) => Record<string, string>
>();

export function registerRequestAuth(
  token: string,
  buildHeaders: (method: string, url: string) => Record<string, string>,
): void {
  registeredRequestAuth.set(token, buildHeaders);
}

export function authHeaders(
  token: string,
  method?: string,
  url?: string,
): Record<string, string> {
  const buildHeaders = registeredRequestAuth.get(token);
  if (buildHeaders) {
    if (!method || !url) {
      throw new Error(
        "DPoP-bound session grant requires the exact request method and URL",
      );
    }
    return buildHeaders(method, url);
  }
  return { authorization: `Bearer ${token}` };
}

export function wireErrCode(body: unknown): string | undefined {
  if (!body || typeof body !== "object") {
    return undefined;
  }
  const record = body as Record<string, unknown>;
  const nested =
    record.error && typeof record.error === "object"
      ? (record.error as Record<string, unknown>)
      : undefined;
  const problemType = stringValue(record.type);
  const problemCode = problemType?.startsWith("https://arkret.org/problems/")
    ? problemType.slice("https://arkret.org/problems/".length)
    : undefined;
  return (
    stringValue(record.errcode) ??
    stringValue(record.code) ??
    stringValue(record.error_code) ??
    problemCode ??
    stringValue(record.reason_code) ??
    stringValue(nested?.errcode) ??
    stringValue(nested?.code) ??
    stringValue(nested?.error_code) ??
    stringValue(nested?.reason_code) ??
    stringValue(record.reason) ??
    stringValue(nested?.reason)
  );
}

export async function expectJsonOk<T = Record<string, unknown>>(
  response: APIResponse,
  context: string,
): Promise<T> {
  const text = await response.text();
  expect(
    response.ok(),
    `${context} returned ${response.status()}: ${text}`,
  ).toBeTruthy();
  return JSON.parse(text) as T;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}
