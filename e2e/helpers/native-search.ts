// A test-only observer over the real Inkson native Account host and local query.
import { execFile } from "node:child_process";
import path from "node:path";
import { canonicalJson } from "./coland-api";
import { colandBaseUrl, type ColandKey } from "./env";
import type { DpopUserSession } from "./users";

export type NativeSearchObservation = {
  view: { query: string; results: Array<Record<string, any>>; next_cursor: string | null };
  recheck_at: string | null;
  account_id: { principal_id: string; station_id: string };
};

export async function observeNativeSearch(
  session: DpopUserSession,
  realmId: string,
  query: string,
  statePath: string,
  server?: ColandKey,
): Promise<NativeSearchObservation> {
  const binary = process.env.INKSON_WIRE_BIN;
  if (!binary) throw new Error("real native search acceptance requires the frozen INKSON_WIRE_BIN");
  const ca = process.env.SSL_CERT_FILE ?? process.env.NODE_EXTRA_CA_CERTS;
  if (!ca) throw new Error("real native search acceptance requires this run's explicit TLS trust root");
  const input = {
    outcome: {
      session_grant: session.grantJwt,
      session_grant_id: session.grantId,
      session_public_key: canonicalJson(session.deviceKey.publicJwk),
      audience_id: session.grantAudience,
      granted_scope: session.grantedScope,
      account_id: session.accountId,
      device_id: session.user.deviceId,
      expires_at: session.grantExpiresAt,
      previous_session_grant_id: null,
    },
    station_url: colandBaseUrl(server),
    holder_seed_b64url: session.dpopSeedB64url,
    identity_did: session.user.did,
    identity_seed_b64url: session.eventSigningSeedB64url,
    state_path: statePath,
    realm_id: realmId,
    query,
  };
  // Credentials cross only the owned child's stdin. Artifacts contain its
  // observed public result, never the login envelope or private seed material.
  return await new Promise<NativeSearchObservation>((resolve, reject) => {
    const child = execFile(binary, ["native-account-search"], {
      encoding: "utf8", maxBuffer: 16 * 1024 * 1024, timeout: 180_000,
      windowsHide: true,
      env: { ...process.env, SSL_CERT_FILE: ca,
        INKSON_CONFIG_PATH: path.join(path.dirname(statePath), "native-config.json") },
    }, (error, stdout, stderr) => {
      if (error) {
        reject(new Error(`native Account search observer failed: ${stderr.trim() || error.message}`));
        return;
      }
      try { resolve(JSON.parse(stdout.trim()) as NativeSearchObservation); }
      catch { reject(new Error("native Account search observer did not return its public observation")); }
    });
    child.stdin!.end(JSON.stringify(input));
  });
}
