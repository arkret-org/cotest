import type { Page, Request } from "@playwright/test";
import type { AccountId } from "./generated/spec-wire-objects";
import type { Ed25519PublicJwk } from "./session-grant-dpop";

// Observe the real issuer response already consumed by the browser. This is
// fixture bookkeeping, not a grant issuer or a decoder of opaque grant claims.
export function observeBrowserSessionRefresh(
  page: Pick<Page, "on" | "off">,
  inputOptions: {
    issuerUrl: string;
    accountId: AccountId;
    deviceId: string;
    audience: string;
    grantedScope: string[];
    holderJwk: Ed25519PublicJwk;
    initialCredential: string;
    initialGrantId: string;
  },
) {
  const options = { ...inputOptions, accountId: { ...inputOptions.accountId },
    grantedScope: [...inputOptions.grantedScope], holderJwk: { ...inputOptions.holderJwk } };
  if (options.audience !== options.accountId.station_id) {
    throw new Error("browser fixture grant belongs to another Station");
  }
  const issuerOrigin = new URL(options.issuerUrl).origin;
  const successors = new Map<string, { credential: string; id: string; previous: string; expiresAt: string }>();
  const retired = new Set<string>();
  let credential = options.initialCredential;
  let grantId = options.initialGrantId;
  let expiresAt: string | undefined;
  let closed = false;
  let conflict = false;
  let refreshCount = 0;
  const pending = new Set<Promise<void>>();
  const acceptRefresh = async (request: Request) => {
    try {
      const response = await request.response();
      if (!response || response.status() !== 200) return;
      const input = request.postDataJSON();
      const authorization = (await request.allHeaders()).authorization;
      const outcome = await response.json();
      if (closed || typeof input?.session_grant !== "string" || authorization !== `DPoP ${input.session_grant}` ||
          input.device_id !== options.deviceId ||
          (input.audience_id !== undefined && input.audience_id !== options.audience) ||
          outcome?.account_id?.principal_id !== options.accountId.principal_id ||
          outcome?.account_id?.station_id !== options.accountId.station_id ||
          outcome?.device_id !== options.deviceId || outcome?.audience_id !== options.audience ||
          outcome?.issuer_id !== options.accountId.station_id ||
          JSON.stringify(outcome?.granted_scope) !== JSON.stringify(options.grantedScope) ||
          typeof outcome?.session_grant !== "string" || !outcome.session_grant ||
          typeof outcome?.session_grant_id !== "string" || !outcome.session_grant_id ||
          typeof outcome?.previous_session_grant_id !== "string" ||
          typeof outcome?.session_public_key !== "string" ||
          !Number.isFinite(Date.parse(outcome?.expires_at)) || Date.parse(outcome.expires_at) <= Date.now()) return;
      const key = JSON.parse(outcome.session_public_key);
      if (key?.kty !== options.holderJwk.kty || key?.crv !== options.holderJwk.crv ||
          key?.x !== options.holderJwk.x) return;
      const next = { credential: outcome.session_grant, id: outcome.session_grant_id,
        previous: outcome.previous_session_grant_id, expiresAt: outcome.expires_at };
      const known = successors.get(input.session_grant);
      if (known && (known.credential !== next.credential || known.id !== next.id ||
          known.previous !== next.previous || known.expiresAt !== next.expiresAt)) {
        conflict = true;
        return;
      }
      successors.set(input.session_grant, next);
      // A later response may finish decoding first. Join only the exact chain
      // rooted at this fixture's original credential and grant id.
      for (;;) {
        const successor = successors.get(credential);
        if (!successor) return;
        if (successor.previous !== grantId || successor.id === grantId ||
            successor.credential === credential || retired.has(successor.credential)) {
          conflict = true;
          return;
        }
        retired.add(credential);
        credential = successor.credential;
        grantId = successor.id;
        expiresAt = successor.expiresAt;
        refreshCount++;
      }
    } catch {
      // Cancelled or incomplete responses cannot replace known credentials.
    }
  };
  const onRequest = (request: Request) => {
    const url = new URL(request.url());
    if (closed || request.method() !== "POST" || url.origin !== issuerOrigin ||
        url.pathname !== "/_arkret/gate/account/session-grants/refresh") return;
    const refresh = acceptRefresh(request);
    pending.add(refresh);
    void refresh.then(() => pending.delete(refresh));
  };
  const currentCredential = () => {
    if (closed || conflict) throw new Error("browser fixture refresh chain is unavailable");
    return credential;
  };
  const dispose = () => {
    closed = true;
    credential = "";
    successors.clear();
    retired.clear();
    pending.clear();
    page.off("request", onRequest);
    page.off("close", dispose);
  };
  page.on("request", onRequest);
  page.on("close", dispose);
  return {
    credential: currentCredential,
    settledGrant: async () => {
      while (!closed && pending.size) await Promise.all([...pending]);
      return { grantJwt: currentCredential(), grantId, ...(expiresAt ? { grantExpiresAt: expiresAt } : {}) };
    },
    refreshCount: () => refreshCount,
    dispose,
  };
}
