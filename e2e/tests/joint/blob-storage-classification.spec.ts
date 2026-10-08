// media-and-blob.md §§2, 2.1, 5: classification, authorized bytes and durable refusal.
import { createHash, randomBytes } from "node:crypto";
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { promisify } from "node:util";
import { expect, test } from "../../helpers/arkret-test";
import { solandBaseUrl } from "../../helpers/env";
import { canonicalJson, createRealmApi } from "../../helpers/soland-api";
import { createDpopUserSession, openDpopUserPage, selfPathHeadersForDpopSession } from "../../helpers/users";

async function presignProblemDiagnostic(response: import("@playwright/test").APIResponse): Promise<string> {
  if (response.status() < 400) return "";
  try {
    const problem = await response.json();
    const detail = typeof problem.detail === "string" ? problem.detail : "";
    return JSON.stringify({
      type: typeof problem.type === "string" && /^https:\/\/arkret\.org\/problems\/[a-z_]+$/.test(problem.type)
        ? problem.type : "unregistered_problem_type",
      status: typeof problem.status === "number" ? problem.status : response.status(),
      detail_kind: detail.includes("canonical JSON input is not byte-for-byte canonical")
        ? "noncanonical_json" : "other",
      detail_sha256: createHash("sha256").update(detail, "utf8").digest("hex"),
    });
  } catch {
    return "presign did not return a JSON Problem";
  }
}

test("Chat file drop keeps plaintext usable and refuses raw file upload into an encrypted scope", async ({ browser, request }, testInfo) => {
  test.setTimeout(300_000);
  const flow = await openDpopUserPage(browser, request, `blob-drop-${Date.now()}`);
  if (!flow) throw new Error("Blob file-drop acceptance requires real Coauth DPoP login");
  const evidence: Array<{ realm_id: string; blob_ref: string; encryption: null; size_bytes: number }> = [];
  try {
    for (const encrypted of [false, true]) {
      const realmId = await flow.page.createRealm({
        title: `Blob drop ${encrypted} ${Date.now()}`,
        discoverability: "listed", joinRule: "invite", historyAccess: "since_join", mlsActivated: encrypted,
      });
      await flow.page.gotoTimelineRealm(realmId);
      const page = flow.page.page;
      const uploadRequests: import("@playwright/test").Request[] = [];
      const observe = (req: import("@playwright/test").Request) => {
        if (new URL(req.url()).pathname === "/_arkret/self/blob/upload" && req.method() === "POST") {
          uploadRequests.push(req);
        }
      };
      page.on("request", observe);
      try {
        const body = `private attachment ${Date.now()}`;
        const uploaded = encrypted ? undefined : page.waitForResponse(response =>
          new URL(response.url()).pathname === "/_arkret/self/blob/upload" && response.request().method() === "POST");
        await page.getByTestId("compose-drop-zone").evaluate((zone, body) => {
          const transfer = new DataTransfer();
          transfer.items.add(new File([body], "private-note.txt", { type: "text/plain" }));
          zone.dispatchEvent(new DragEvent("drop", { bubbles: true, cancelable: true, dataTransfer: transfer }));
        }, body);
        if (encrypted) {
          await expect(page.getByTestId("compose-upload-progress")).toContainText(/unavailable for this encrypted conversation/);
          expect(uploadRequests).toHaveLength(0);
          await expect(page.getByTestId("chat-input")).toHaveValue("");
        } else {
          const response = await uploaded!;
          expect(response.status()).toBe(200);
          const outcome = await response.json();
          const bytes = Buffer.from(body, "utf8");
          const expectedRef = `ak:blob:sha256:${createHash("sha256").update(bytes).digest("hex")}`;
          expect(outcome.blob_ref).toBe(expectedRef);
          await expect(page.getByTestId("compose-upload-progress")).toContainText("1 attachment(s) uploaded");
          expect(uploadRequests).toHaveLength(1);
          await expect(page.getByTestId("chat-input")).toHaveValue(new RegExp(`\\[Attachment: ${expectedRef}`));
          const base = solandBaseUrl();
          const downloadUrl = `${base}/_arkret/self/blob/get?blob_ref=${encodeURIComponent(expectedRef)}`;
          const download = await request.get(downloadUrl, {
            headers: selfPathHeadersForDpopSession(flow.session, "GET", downloadUrl),
          });
          expect(download.status()).toBe(200);
          expect(download.headers()["content-type"]?.split(";", 1)[0].trim()).toBe("text/plain");
          expect(await download.body()).toEqual(bytes);
          // This Realm has not opted into direct download; plaintext also
          // requires policy authorization before a bearer URL can be issued.
          const presignUrl = `${base}/_arkret/self/blob/presign`;
          const presigned = await request.post(presignUrl, {
            headers: { ...selfPathHeadersForDpopSession(flow.session, "POST", presignUrl), "content-type": "application/json" },
            data: canonicalJson({ blob_ref: expectedRef, realm_id: realmId, purpose: "media_inline" }),
          });
          expect(presigned.status(), await presignProblemDiagnostic(presigned)).toBe(404);
          const problem = await presigned.json();
          expect(problem.type).toBe("https://arkret.org/problems/not_found");
          expect(problem.status).toBe(presigned.status());
          evidence.push({ realm_id: realmId, blob_ref: expectedRef, encryption: null, size_bytes: bytes.length });
        }
      } finally { page.off("request", observe); }
    }
    await testInfo.attach("blob-file-drop-classification-refs.json", {
      body: JSON.stringify({ blobs: evidence }), contentType: "application/json",
    });
  } finally { await flow.page.close(); }
});

test("Blob storage classification survives multipart, tus and a real Station restart", async ({ request }, testInfo) => {
  test.setTimeout(240_000);
  const owner = await createDpopUserSession(request, `blob-owner-${Date.now()}`);
  const outsider = await createDpopUserSession(request, `blob-outsider-${Date.now()}`);
  if (!owner || !outsider) throw new Error("Blob acceptance requires real Coauth DPoP sessions");
  const realmId = await createRealmApi(request, owner.grantJwt, {
    title: `Blob acceptance ${Date.now()}`, ownerId: owner.user.id,
  });
  const base = solandBaseUrl();
  const uploadUrl = `${base}/_arkret/self/blob/upload`;
  const presignUrl = `${base}/_arkret/self/blob/presign`;
  const tusUrl = `${base}/_arkret/self/blob/resumable`;
  const whole = JSON.stringify({ scheme: "ak.blob.whole_file_aead.v1" });
  const stream = JSON.stringify({ scheme: "ak.blob.stream_aead.v1" });
  const headers = (method: string, url: string) => selfPathHeadersForDpopSession(owner, method, url);
  const refFor = (bytes: Buffer) => `ak:blob:sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  const metadata = (encryption: string) => `encryption ${Buffer.from(encryption).toString("base64")},realm_id ${Buffer.from(realmId).toString("base64")}`;
  const getUrl = (ref: string) => `${base}/_arkret/self/blob/get?blob_ref=${encodeURIComponent(ref)}`;
  const evidence: Array<{ blob_ref: string; encryption: unknown; size_bytes: number }> = [];
  const rejectedRefs: string[] = [];

  // Unique rejected bytes ensure an existing upload cannot hide a write.
  for (const variant of ["missing", "private_descriptor", "conflicting_mime", "ciphertext_mime"]) {
    const bytes = randomBytes(37);
    const form: Record<string, string | { name: string; mimeType: string; buffer: Buffer }> = {
      content: { name: "blob", mimeType: variant === "ciphertext_mime" ? "image/png" : "application/octet-stream", buffer: bytes },
      size_bytes: String(bytes.length), realm_id: realmId,
    };
    if (variant !== "missing") form.encryption = variant === "private_descriptor"
      ? JSON.stringify({ scheme: "ak.blob.stream_aead.v1", key_ref: "private" }) : stream;
    if (variant === "conflicting_mime") form.media_type = "image/png";
    const rejected = await request.post(uploadUrl, { headers: headers("POST", uploadUrl), multipart: form });
    expect(rejected.status(), variant).toBe(422);
    const problem = await rejected.json();
    expect(problem.type, variant).toBe("https://arkret.org/problems/schema_violation");
    expect(problem.status, variant).toBe(rejected.status());
    const absentUrl = getUrl(refFor(bytes));
    rejectedRefs.push(refFor(bytes));
    expect((await request.get(absentUrl, { headers: headers("GET", absentUrl) })).status()).toBe(404);
  }

  for (const encryption of ["null", whole, stream]) {
    const bytes = Buffer.from(`classification bytes ${randomBytes(32).toString("hex")}`);
    const mediaType = encryption === "null" ? "text/plain" : "application/octet-stream";
    const response = await request.post(uploadUrl, {
      headers: headers("POST", uploadUrl), multipart: {
        content: { name: "blob", mimeType: mediaType, buffer: bytes },
        size_bytes: String(bytes.length), encryption, realm_id: realmId,
      },
    });
    expect(response.status()).toBe(200);
    const outcome = await response.json();
    expect(outcome.blob_ref).toBe(refFor(bytes));
    evidence.push({ blob_ref: outcome.blob_ref, encryption: JSON.parse(encryption), size_bytes: bytes.length });
    const url = getUrl(outcome.blob_ref);
    const download = await request.get(url, { headers: headers("GET", url) });
    expect(download.status()).toBe(200);
    expect(download.headers()["content-type"]).toBe(mediaType);
    expect(await download.body()).toEqual(bytes);
    const head = await request.head(url, { headers: headers("HEAD", url) });
    expect(head.status()).toBe(200);
    expect(Number(head.headers()["content-length"])).toBe(bytes.length);
    expect((await head.body()).length).toBe(0);
    const range = await request.get(url, { headers: { ...headers("GET", url), range: "bytes=2-7" } });
    expect(range.status()).toBe(206);
    expect(await range.body()).toEqual(bytes.subarray(2, 8));
    for (const method of ["GET", "HEAD"] as const) {
      const denied = await request.fetch(url, { method, headers: selfPathHeadersForDpopSession(outsider, method, url) });
      expect(denied.status()).toBe(404);
      expect(denied.headers()["content-range"]).toBeUndefined();
      expect((await request.fetch(url, { method })).status()).toBe(401);
    }
    if (encryption !== "null") {
      const denied = await request.post(presignUrl, {
        headers: { ...headers("POST", presignUrl), "content-type": "application/json" },
        data: canonicalJson({ blob_ref: outcome.blob_ref, purpose: "media_inline" }),
      });
      expect(denied.status(), await presignProblemDiagnostic(denied)).toBe(403);
      const problem = await denied.json();
      expect(problem.type).toBe("https://arkret.org/problems/capability_denied");
      expect(problem.status).toBe(denied.status());
    }
  }

  const tusBytes = randomBytes(51);
  const tusHeaders = (method: string, url: string) => ({
    ...headers(method, url), "arkret-operation": "ak.self.blob.upload.create.v1", "tus-resumable": "1.0.0",
  });
  for (const classification of [undefined, "{}", JSON.stringify({ scheme: "unknown" })]) {
    const rejected = await request.post(tusUrl, { headers: {
      ...tusHeaders("POST", tusUrl), "upload-length": "51",
      ...(classification === undefined ? {} : { "upload-metadata": metadata(classification) }),
    } });
    expect(rejected.status()).toBe(422);
  }
  const created = await request.post(tusUrl, { headers: {
    ...tusHeaders("POST", tusUrl), "upload-length": String(tusBytes.length), "upload-metadata": metadata(stream),
  } });
  expect(created.status()).toBe(201);
  const location = new URL(created.headers().location, base).toString();
  expect(new URL(location).origin).toBe(new URL(base).origin);
  const patched = await request.patch(location, { headers: {
    ...tusHeaders("PATCH", location), "upload-offset": "0", "content-type": "application/offset+octet-stream",
  }, data: tusBytes });
  expect(patched.status()).toBe(204);
  const override = await request.patch(location, { headers: {
    ...tusHeaders("PATCH", location), "upload-offset": String(tusBytes.length),
    "content-type": "application/offset+octet-stream", "upload-metadata": metadata("null"),
  } });
  expect(override.status()).toBe(422);
  const unchangedOffset = await request.head(location, { headers: tusHeaders("HEAD", location) });
  expect(unchangedOffset.status()).toBe(200);
  expect(unchangedOffset.headers()["upload-offset"]).toBe(String(tusBytes.length));
  const finalizeUrl = `${location}/finalize`;
  const finalized = await request.post(finalizeUrl, { headers: tusHeaders("POST", finalizeUrl) });
  expect(finalized.status()).toBe(200);
  expect((await finalized.json()).blob_ref).toBe(refFor(tusBytes));
  evidence.push({ blob_ref: refFor(tusBytes), encryption: JSON.parse(stream), size_bytes: tusBytes.length });

  const topologyPath = process.env.COTEST_TOPOLOGY_PATH;
  if (!topologyPath) throw new Error("Blob durability requires runner-owned Station restart control");
  const topology = JSON.parse(readFileSync(topologyPath, "utf8")) as {
    servers: Array<{ name: string; soland: { control?: { script_path: string; state_path: string } } }>;
  };
  const control = topology.servers.find(server => server.name === "server1")?.soland.control;
  if (!control) throw new Error("server1 restart control is unavailable");
  await promisify(execFile)("pwsh", ["-NoProfile", "-File", control.script_path,
    "-TopologyPath", topologyPath, "-ServerName", "server1", "-Action", "restart"],
  { timeout: 60_000, windowsHide: true });
  expect(JSON.parse(readFileSync(control.state_path, "utf8")).restarted).toBe(true);
  await expect.poll(async () => {
    try { return (await request.get(`${base}/health`, { timeout: 5_000 })).ok(); } catch { return false; }
  }, { timeout: 60_000 }).toBe(true);
  for (const row of evidence) {
    const url = getUrl(row.blob_ref);
    const restored = await request.get(url, { headers: headers("GET", url) });
    expect(restored.status()).toBe(200);
    expect(refFor(await restored.body())).toBe(row.blob_ref);
    if (row.encryption !== null) {
      const denied = await request.post(presignUrl, {
        headers: { ...headers("POST", presignUrl), "content-type": "application/json" },
        data: canonicalJson({ blob_ref: row.blob_ref, purpose: "media_inline" }),
      });
      expect(denied.status(), await presignProblemDiagnostic(denied)).toBe(403);
      const problem = await denied.json();
      expect(problem.type).toBe("https://arkret.org/problems/capability_denied");
      expect(problem.status).toBe(denied.status());
      const changed = await request.post(uploadUrl, { headers: headers("POST", uploadUrl), multipart: {
        content: { name: "blob", mimeType: "application/octet-stream", buffer: await restored.body() },
        size_bytes: String(row.size_bytes), realm_id: realmId, encryption: "null",
      } });
      expect(changed.status()).toBe(409);
      const changedProblem = await changed.json();
      expect(changedProblem.type).toBe("https://arkret.org/problems/failed_precondition");
      expect(changedProblem.status).toBe(changed.status());
    }
  }
  await testInfo.attach("blob-classification-durable-refs.json", {
    body: JSON.stringify({ realm_id: realmId, blobs: evidence, rejected_refs: rejectedRefs }), contentType: "application/json",
  });
});
