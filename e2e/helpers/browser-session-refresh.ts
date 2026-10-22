import type { Page, Response } from "@playwright/test";
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
  const successors = new Map<string, { credential: string; id: string; previous: string }>();
  const retired = new Set<string>();
  let credential = options.initialCredential;
  let grantId = options.initialGrantId;
  let closed = false;
  let conflict = false;
  let refreshCount = 0;
  const onResponse = async (response: Response) => {
    const request = response.request();
    const url = new URL(request.url());
    if (closed || request.method() !== "POST" || response.status() !== 200 ||
        url.origin !== issuerOrigin || url.pathname !== "/_arkret/gate/account/session-grants/refresh") return;
    try {
      const input = request.postDataJSON();
      const outcome = await response.json();
      if (closed || typeof input?.grant_jwt !== "string" || input.device_id !== options.deviceId ||
          (input.audience_id !== undefined && input.audience_id !== options.audience) ||
          outcome?.account_id?.principal_id !== options.accountId.principal_id ||
          outcome?.account_id?.station_id !== options.accountId.station_id ||
          outcome?.device_id !== options.deviceId || outcome?.audience_id !== options.audience ||
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
        previous: outcome.previous_session_grant_id };
      const known = successors.get(input.grant_jwt);
      if (known && (known.credential !== next.credential || known.id !== next.id || known.previous !== next.previous)) {
        conflict = true;
        return;
      }
      successors.set(input.grant_jwt, next);
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
        refreshCount++;
      }
    } catch {
      // Cancelled or incomplete responses cannot replace known credentials.
    }
  };
  const dispose = () => {
    closed = true;
    credential = "";
    successors.clear();
    retired.clear();
    page.off("response", onResponse);
    page.off("close", dispose);
  };
  page.on("response", onResponse);
  page.on("close", dispose);
  return {
    credential: () => {
      if (closed || conflict) throw new Error("browser fixture refresh chain is unavailable");
      return credential;
    },
    refreshCount: () => refreshCount,
    dispose,
  };
}
