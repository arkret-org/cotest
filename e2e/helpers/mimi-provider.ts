// A remote MIMI provider as seen by a Coland MIMI facade.
//
// extensions/mimi-interop.md section 5 closes the per-request RFC 9421
// provider-source signature over the listed operation ids
// (`ak.http_signature.scenario.mimi_provider.v1`): the request carries
// `Signature`, `Signature-Input`, `Content-Digest`, `Source-Service-ID`,
// `Destination-Service-ID` and `Provider-ID` (plus `MIMI-Room-URI` on a
// room-scoped endpoint), the content is the exact `canonical_json(body)` bytes,
// and `keyid` is an Ed25519 method controlled by `Source-Service-ID`.
//
// The provider identity is a fresh `did:key`, whose document every receiver
// derives locally, so no service key binding has to be staged first.

import { createHash, sign } from "node:crypto";
import type { APIRequestContext, APIResponse } from "@playwright/test";
import { operationSelector } from "./arkret-test";
import { canonicalJson, projectDidToCoreId } from "./coland-api";
import { generateDidKeyIdentity, type DidKeyIdentity } from "./third-party-invite";

export type MimiProvider = {
  identity: DidKeyIdentity;
  sourceServiceId: string;
  providerId: string;
};

export function createMimiProvider(label: string): MimiProvider {
  const identity = generateDidKeyIdentity();
  return {
    identity,
    sourceServiceId: projectDidToCoreId(identity.did),
    providerId: `mimi://${label}.cotest.example`,
  };
}

export function signedMimiProviderHeaders(
  provider: MimiProvider,
  destinationServiceId: string,
  targetUri: string,
  body: unknown,
  opts: { method?: string; roomUri?: string } = {},
): { headers: Record<string, string>; content: string } {
  const method = opts.method ?? "POST";
  const selector = operationSelector(method, targetUri);
  if (!selector) {
    throw new Error(`MIMI request has no registered operation: ${method} ${targetUri}`);
  }
  const content = canonicalJson(body);
  const contentDigest = `sha-256=:${createHash("sha256")
    .update(Buffer.from(content, "utf8"))
    .digest("base64")}:`;
  const created = Math.floor(Date.now() / 1000);
  const expires = created + 300;
  const roomComponent = opts.roomUri === undefined ? "" : ' "mimi-room-uri"';
  const signatureParams =
    `("@method" "@target-uri" "@authority" "arkret-operation" "content-digest" ` +
    `"source-service-id" "destination-service-id" "provider-id"${roomComponent});` +
    `created=${created};expires=${expires};keyid="${provider.identity.verificationMethod}";alg="ed25519"`;
  const signatureBase = [
    `"@method": ${method}`,
    `"@target-uri": ${targetUri}`,
    `"@authority": ${new URL(targetUri).host}`,
    `"arkret-operation": ${selector}`,
    `"content-digest": ${contentDigest}`,
    `"source-service-id": ${provider.sourceServiceId}`,
    `"destination-service-id": ${destinationServiceId}`,
    `"provider-id": ${provider.providerId}`,
    ...(opts.roomUri === undefined ? [] : [`"mimi-room-uri": ${opts.roomUri}`]),
    `"@signature-params": ${signatureParams}`,
  ].join("\n");
  const signature = sign(
    null,
    Buffer.from(signatureBase, "utf8"),
    provider.identity.privateKey,
  ).toString("base64");
  return {
    content,
    headers: {
      "content-type": "application/json",
      "content-digest": contentDigest,
      "arkret-operation": selector,
      "source-service-id": provider.sourceServiceId,
      "destination-service-id": destinationServiceId,
      "provider-id": provider.providerId,
      ...(opts.roomUri === undefined ? {} : { "mimi-room-uri": opts.roomUri }),
      "signature-input": `sig1=${signatureParams}`,
      signature: `sig1=:${signature}:`,
    },
  };
}

export async function postSignedMimiProviderRequest(
  request: APIRequestContext,
  provider: MimiProvider,
  destinationServiceId: string,
  targetUri: string,
  body: unknown,
  opts: { roomUri?: string } = {},
): Promise<APIResponse> {
  const signed = signedMimiProviderHeaders(
    provider,
    destinationServiceId,
    targetUri,
    body,
    opts,
  );
  return await request.post(targetUri, {
    headers: signed.headers,
    data: signed.content,
  });
}
