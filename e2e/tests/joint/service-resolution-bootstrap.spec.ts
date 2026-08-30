import { createHash } from "node:crypto";

import { expect, test } from "../../helpers/arkret-test";

import { solandBaseUrl } from "../../helpers/env";
import { canonicalJson, wireErrCode } from "../../helpers/soland-api";

type ServiceDescribe = {
  service_id: string;
  service_kind: string;
  service_resolution: Record<string, unknown>;
  transport_bindings: Array<{ kind: string; base_url?: string }>;
};

type AuthenticatedServiceResolution = {
  service_resolution_record: {
    record: {
      service_id: string;
      service_kind: string;
      did: string;
      method_history_head: string;
      version_id: string;
      record_sequence: number;
      previous_record_digest: string | null;
      current_record_url: string;
      base_url: string;
      describe_digest: string;
      issued_at: string;
      refresh_after: string;
      expires_at: string;
    };
    proof: { verification_method: string };
  };
  method_history_evidence: Record<string, unknown>;
  normalized_did_document: {
    id?: string;
    assertionMethod?: Array<string | { id?: string }>;
  };
};

test.describe("service resolution bootstrap @fully-implemented", () => {
  test("current signed record is stable and reverse-bound to role-scoped Describe", async ({
    request,
  }) => {
    const baseUrl = solandBaseUrl();
    const describeUrl = `${baseUrl}/_arkret/describe?service_kind=station`;
    const describeResponse = await request.get(describeUrl);
    expect(describeResponse.status(), await describeResponse.text()).toBe(200);
    const describe = (await describeResponse.json()) as ServiceDescribe;
    expect(describe.service_kind).toBe("station");

    const httpBinding = describe.transport_bindings.find(
      (binding) => binding.kind === "http_json",
    );
    expect(httpBinding?.base_url, "Describe http_json base URL").toBeTruthy();

    const recordUrl = `${baseUrl}/_arkret/open/services/${encodeURIComponent(describe.service_id)}/resolution`;
    const firstResponse = await request.get(recordUrl, {
      maxRedirects: 0,
    });
    expect(firstResponse.status(), await firstResponse.text()).toBe(200);
    const first =
      (await firstResponse.json()) as AuthenticatedServiceResolution;
    const signedRecord = first.service_resolution_record;
    const record = signedRecord.record;

    expect(record.service_id).toBe(describe.service_id);
    expect(record.service_kind).toBe(describe.service_kind);
    expect(record.did).toBe(describe.service_resolution.did);
    expect(record.method_history_head).toBe(
      describe.service_resolution.method_history_head,
    );
    expect(record.version_id).toBe(describe.service_resolution.version_id);
    expect(record.current_record_url).toBe(recordUrl);
    expect(record.base_url).toBe(httpBinding!.base_url);
    expect(record.record_sequence).toBeGreaterThanOrEqual(0);
    expect(record.previous_record_digest === null).toBe(
      record.record_sequence === 0,
    );

    const describeProjection = {
      service_id: describe.service_id,
      service_kind: describe.service_kind,
      service_resolution: describe.service_resolution,
      http_json_base_url: httpBinding!.base_url,
    };
    const expectedDescribeDigest = `sha256:${createHash("sha256")
      .update(canonicalJson(describeProjection), "utf8")
      .digest("hex")}`;
    expect(record.describe_digest).toBe(expectedDescribeDigest);

    expect(first.normalized_did_document.id).toBe(record.did);
    expect(first.method_history_evidence).toBeTruthy();
    const assertionMethods = (first.normalized_did_document.assertionMethod ?? [])
      .map((method) => (typeof method === "string" ? method : method.id))
      .filter((method): method is string => typeof method === "string");
    expect(assertionMethods).toContain(signedRecord.proof.verification_method);

    const issuedAt = Date.parse(record.issued_at);
    const refreshAfter = Date.parse(record.refresh_after);
    const expiresAt = Date.parse(record.expires_at);
    expect(Number.isFinite(issuedAt)).toBe(true);
    expect(refreshAfter).toBeGreaterThanOrEqual(issuedAt);
    expect(expiresAt).toBeGreaterThan(refreshAfter);

    const secondResponse = await request.get(recordUrl, { maxRedirects: 0 });
    expect(secondResponse.status(), await secondResponse.text()).toBe(200);
    expect(await secondResponse.json()).toEqual(first);
  });

  test("an unrelated service core cannot reuse the endpoint", async ({
    request,
  }) => {
    const response = await request.get(
      `${solandBaseUrl()}/_arkret/open/services/${encodeURIComponent(
        "ak:did_core:key:z6MkiNotTheRunningService",
      )}/resolution`,
      { maxRedirects: 0 },
    );
    expect(response.status()).toBe(404);
    expect(wireErrCode(await response.json())).toBe("not_found");
  });
});
