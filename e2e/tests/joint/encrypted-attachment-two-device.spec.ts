// Real product attachment selection, durable preparation, upload, send and receive.
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";
import { expect, test, type Page } from "../../helpers/arkret-test";
import { canonicalJson } from "../../helpers/coland-api";
import { colandBaseUrl } from "../../helpers/env";
import { grantInviteConsentArkret } from "../../helpers/contact-api";
import { readScopeMlsGroupCurrentApi } from "../../helpers/coland-api/mls";
import { createDpopUserSession, issueInviteLocatorToken, openDpopUserPageFromSession, selfPathHeadersForDpopSession, type JointUserPage } from "../../helpers/users";

const sha = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");

async function inspectStoredBlobs(refs: string[]) {
  const controls = process.env.COTEST_READONLY_DATABASE_CONTROLS;
  if (!controls) throw new Error("attachment acceptance requires the managed Station database lease");
  const lease = JSON.parse(readFileSync(join(controls, "server1.json"), "utf8"));
  expect(new URL(lease.public_url).origin).toBe(new URL(colandBaseUrl()).origin);
  const connection = new URL(lease.database_url);
  for (const ref of refs) expect(ref).toMatch(/^ak:blob:sha256:[0-9a-f]{64}$/);
  const query = `BEGIN READ ONLY; SELECT COALESCE(json_agg(json_build_object('id',id,'media_type',media_type,'filename',filename,'size_bytes',size_bytes,'payload',payload)), '[]'::json) FROM public.blobs WHERE id IN (${refs.map(ref => "'" + ref + "'").join(",")}); ROLLBACK;`;
  const {stdout} = await promisify(execFile)("psql", ["-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", query], {
    windowsHide: true, timeout: 30_000, env: {...process.env,
      PGHOST: connection.hostname, PGPORT: connection.port || "5432", PGUSER: decodeURIComponent(connection.username),
      PGPASSWORD: decodeURIComponent(connection.password), PGDATABASE: decodeURIComponent(connection.pathname.slice(1))},
  });
  return JSON.parse(stdout.trim()) as Array<{id: string;media_type: string;filename: string|null;size_bytes: number;payload: any}>;
}

async function holderAttachments(page: Page) {
  return page.evaluate(async () => {
    const result = <T>(request: IDBRequest<T>): Promise<T> => new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
    });
    const db = await result(indexedDB.open("inkson.secret.inkson", 1));
    try {
      const tx = db.transaction(["entries", "wrapping_keys"], "readonly");
      const [key, names, entries] = await Promise.all([
        result(tx.objectStore("wrapping_keys").get("primary")) as Promise<CryptoKey>,
        result(tx.objectStore("entries").getAllKeys()), result(tx.objectStore("entries").getAll()),
      ]);
      if (!key || key.extractable) throw new Error("attachment vault needs its non-extractable wrapping key");
      const objects: Record<string, any>[] = [];
      for (let i = 0; i < names.length; ++i) {
        if (!String(names[i]).startsWith("inkson.outbound.v1::") || !String(names[i]).endsWith(".standard")) continue;
        const entry = entries[i] as {iv: Uint8Array; ct: Uint8Array};
        const bytes = await crypto.subtle.decrypt({name: "AES-GCM", iv: Uint8Array.from(entry.iv).buffer}, key, Uint8Array.from(entry.ct).buffer);
        const state = JSON.parse(new TextDecoder().decode(bytes));
        const canonical = (value: any): string => {
          if (value === null || typeof value !== "object") return JSON.stringify(value);
          if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
          return "{" + Object.keys(value).sort().map(name => JSON.stringify(name) + ":" + canonical(value[name])).join(",") + "}";
        };
        for (const object of state.attachments ?? []) {
          const identityBytes = new TextEncoder().encode(canonical([object.authority,object.device_id,object.id]));
          const identity = "sha256:" + Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",identityBytes)), byte => byte.toString(16).padStart(2,"0")).join("");
          const ciphertext: number[] = [];
          for (let part = 0; part < (object.prepared?.part_count ?? 0); ++part) {
            const entryName = `inkson.current.v1/attachment_objects/${identity}/ciphertext/${part.toString(16).padStart(8,"0")}`;
            const position = names.findIndex(name => String(name) === entryName);
            if (position < 0) throw new Error("prepared attachment lost its ciphertext part");
            const wrapped = entries[position] as {iv: Uint8Array;ct: Uint8Array};
            const packed = await crypto.subtle.decrypt({name:"AES-GCM",iv:Uint8Array.from(wrapped.iv).buffer},key,Uint8Array.from(wrapped.ct).buffer);
            const [boundName,encoded] = JSON.parse(new TextDecoder().decode(packed));
            if (boundName !== entryName) throw new Error("attachment part binding differs");
            const base64 = String(encoded).replace(/-/g,"+").replace(/_/g,"/");
            for (const char of atob(base64 + "=".repeat((4-base64.length%4)%4))) ciphertext.push(char.charCodeAt(0));
          }
          objects.push({id: object.id, salt: object.salt, scope: object.scope, strand: object.strand_id, uploaded: object.uploaded,
            submitted: object.submitted_operation, filename: object.filename, inputLength: object.input?.length ?? 0,
            descriptor: object.prepared?.descriptor, ciphertext, blobRef: object.prepared?.blob_ref});
        }

      }
      return objects;
    } finally { db.close(); }
  });
}

async function drop(page: Page, name: string, mime: string, bytes: Uint8Array) {
  await expect(page.getByTestId("send-chat-button")).toBeEnabled({timeout: 120_000});
  await page.getByTestId("compose-drop-zone").evaluate((zone, file) => {
    const transfer = new DataTransfer();
    transfer.items.add(new File([Uint8Array.from(file.bytes)], file.name, {type: file.mime}));
    zone.dispatchEvent(new DragEvent("drop", {bubbles: true, cancelable: true, dataTransfer: transfer}));
  }, {name, mime, bytes: Array.from(bytes)});
}

async function scrollTimeline(page: Page, edge: "oldest" | "latest") {
  await page.getByTestId("message-list").evaluate((feed, last) => {
    feed.scrollTop = last ? feed.scrollHeight : 0;
    feed.dispatchEvent(new Event("scroll", {bubbles: true}));
  }, edge === "latest");
}

test("encrypted attachment two-device upload/send/history/render and exact restart recovery @fully-implemented", async ({browser, request}, testInfo) => {
  test.setTimeout(1_800_000);
  const [aliceSession, bobSession] = await Promise.all([
    createDpopUserSession(request, "attachment-alice"), createDpopUserSession(request, "attachment-bob"),
  ]);
  if (!aliceSession || !bobSession) throw new Error("attachment acceptance requires the real joint Coauth deployment");
  const alice = (await openDpopUserPageFromSession(browser, aliceSession))?.page;
  if (!alice) throw new Error("sender device did not open");
  let bob: JointUserPage | undefined;
  let late: JointUserPage | undefined;
  const png = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/5h8AAAAASUVORK5CYII=", "base64");
  const marker = `private attachment two-device ${Date.now()}`;
  const uploads: Array<{ref: string; size: number; digest: string; metadata: Record<string, string>}> = [];
  let cut = true;
  try {
    await alice.completeRecoveryKeySetupIfPrompted();
    await alice.acknowledgeRecommendedEncryptionPromptIfVisible();
    await alice.completeMlsAccountRecoveryIfPrompted(aliceSession.recoveryKey!);
    const realm = await alice.createRealm({title: marker, discoverability: "listed", joinRule: "invite", historyAccess: "since_join", mlsActivated: true});
    await alice.completeMlsAccountRecoveryIfPrompted(aliceSession.recoveryKey!);
    await grantInviteConsentArkret(request, bobSession.grantJwt, bobSession.user, aliceSession.user.id);
    const locator = await issueInviteLocatorToken(request, bobSession.grantJwt);
    await alice.inviteFromAdmin(realm, bobSession.user.id, bobSession.user.id, {token: locator});
    bob = (await openDpopUserPageFromSession(browser, bobSession))?.page;
    if (!bob) throw new Error("receiver device did not open");
    await bob.completeRecoveryKeySetupIfPrompted();
    await bob.acknowledgeRecommendedEncryptionPromptIfVisible();
    await bob.completeMlsAccountRecoveryIfPrompted(bobSession.recoveryKey!);
    await bob.acceptInvite(realm);
    await expect.poll(async () => (await readScopeMlsGroupCurrentApi(request, aliceSession.grantJwt, realm))?.epoch ?? -1,
      {timeout: 120_000, intervals: [1_000, 2_000]}).toBeGreaterThanOrEqual(1);
    await bob.completeMlsAccountRecoveryIfPrompted(bobSession.recoveryKey!);
    await Promise.all([alice.gotoTimelineRealm(realm), bob.gotoTimelineRealm(realm)]);

    // Lose the first accepted upload response. The restarted sender must reuse
    // the exact already accepted object rather than encrypt another nonce.
    const uploadPattern = /\/_arkret\/self\/blob\/upload(?:\?.*)?$/;
    await alice.page.route(uploadPattern, async route => {
      const response = await route.fetch();
      expect(response.status()).toBe(200);
      const outcome = await response.json();
      const objects = await holderAttachments(alice.page);
      const object = objects.find(o => o.blobRef === outcome.blob_ref);
      expect(object?.descriptor?.scheme).toBe("ak.blob.stream_aead.v1");
      expect(object?.descriptor?.content_key_salt).toBe(object?.salt);
      const ciphertext = Buffer.from(object!.ciphertext);
      expect(sha(ciphertext)).toBe(outcome.blob_ref.split(":").at(-1));
      expect(ciphertext.equals(png)).toBe(false);
      const body = route.request().postDataBuffer()!.toString("latin1");
      expect(body).not.toContain("private-image.png");
      expect(body).not.toContain("image/png");
      expect(body).not.toContain(object!.salt);
      expect(body).toContain("application/octet-stream");
      expect(body).toContain('{"scheme":"ak.blob.stream_aead.v1"}');
      uploads.push({ref: outcome.blob_ref, size: outcome.size_bytes, digest: sha(ciphertext), metadata: {scheme: "ak.blob.stream_aead.v1"}});
      if (cut) { cut = false; await route.abort("failed"); } else { await route.fulfill({response}); }
    });
    await drop(alice.page, "private-image.png", "image/png", png);
    await expect.poll(async () => uploads.length, {timeout: 60_000}).toBe(1);
    const before = (await holderAttachments(alice.page)).find(o => o.scope.realm_id === realm)!;
    expect(before.inputLength).toBe(0);
    expect(before.uploaded).toBe(false);
    await alice.page.reload({waitUntil: "domcontentloaded"});
    await alice.completeRecoveryKeySetupIfPrompted();
    await alice.gotoTimelineRealm(realm);
    try {
      await expect(alice.page.getByTestId("compose-attachment")).toHaveCount(1, {timeout: 120_000});
      await expect.poll(async () => (await holderAttachments(alice.page)).find(o => o.id === before.id)?.uploaded,
        {timeout: 120_000}).toBe(true);
    } catch (error) {
      await testInfo.attach("attachment-recovery-targets.json", {contentType: "application/json", body: JSON.stringify({
        frozen: {id:before.id,scope:before.scope,strand:before.strand,blob_ref:before.blobRef},
        objects: (await holderAttachments(alice.page)).map(o => ({id:o.id,scope:o.scope,strand:o.strand,uploaded:o.uploaded})),
        source: await alice.page.getByTestId("composer-send-scope").allTextContents(),
        progress: await alice.page.getByTestId("compose-upload-progress").allTextContents(),
        chips: await alice.page.getByTestId("compose-attachment").count(),
        uploads: uploads.map(u=>u.ref),
      })});
      throw error;
    }
    const resumed = (await holderAttachments(alice.page)).find(o => o.id === before.id)!;
    expect(resumed.descriptor).toEqual(before.descriptor);
    expect(resumed.ciphertext).toEqual(before.ciphertext);
    expect(resumed.uploaded).toBe(true);
    expect(uploads.length).toBeGreaterThanOrEqual(2);
    expect(new Set(uploads.map(u => u.ref)).size).toBe(1);
    await alice.page.unroute(uploadPattern);

    let create: Record<string, any> | undefined;
    alice.page.on("request", req => {
      if (req.method() !== "POST" || new URL(req.url()).pathname !== "/_arkret/self/events") return;
      const body = req.postDataJSON();
      const event = body.event ?? body.submission?.event;
      if (event?.kind === "ak.message.create" && event.realm_id === realm) create = event;
    });
    await alice.sendTimelineMessage(realm, marker);
    await expect.poll(() => create?.payload?.blob_refs ?? [], {timeout: 60_000}).toContain(before.blobRef);
    expect(create!.payload.content).toBeUndefined();
    expect(JSON.stringify(create)).not.toContain("private-image.png");
    expect(JSON.stringify(create)).not.toContain(marker);
    const originalMessageId = create!.event_id as string;
    await expect(bob.page.getByRole("img", {name: "private-image.png", exact: true})).toBeVisible({timeout: 120_000});
    const verifyImage = async () => {
      const image = bob!.page.getByRole("img", {name: "private-image.png", exact: true});
      const bytes = await image.evaluate(async (img: HTMLImageElement) => Array.from(new Uint8Array(await (await fetch(img.src)).arrayBuffer())));
      expect(Buffer.from(bytes)).toEqual(png);
      await expect.poll(() => image.evaluate((img: HTMLImageElement) => img.naturalWidth)).toBe(1);
    };
    await verifyImage();

    // Editing away and back must still cancel the old upload continuation.
    // The server accepted its bytes, but no stale result may mark it ready.
    let abaAccepted = false;
    let releaseAba!: () => void;
    const abaHeld = new Promise<void>(resolve => { releaseAba = resolve; });
    await alice.page.route(uploadPattern, async route => {
      const response = await route.fetch();
      expect(response.status()).toBe(200);
      abaAccepted = true;
      await abaHeld;
      await route.fulfill({response}).catch(() => {});
    });
    await drop(alice.page, "target-aba.png", "image/png", png);
    await expect.poll(() => abaAccepted, {timeout: 60_000}).toBe(true);
    await alice.page.getByTestId("chat-input").fill("temporary changed target draft");
    await alice.page.getByTestId("chat-input").fill("");
    await expect(alice.page.getByTestId("compose-upload-progress")).toContainText(/target changed/, {timeout: 30_000});
    releaseAba();
    await alice.page.unroute(uploadPattern);
    const aba = (await holderAttachments(alice.page)).find(o => o.filename === "target-aba.png")!;
    expect(aba.uploaded).toBe(false);
    await expect(alice.page.getByTestId("send-chat-button")).toBeDisabled();
    await alice.page.getByRole("button", {name: "Retry attachments", exact: true}).click();
    await expect.poll(async () => (await holderAttachments(alice.page)).find(o => o.id === aba.id)?.uploaded,
      {timeout: 120_000}).toBe(true);
    expect((await holderAttachments(alice.page)).find(o => o.id === aba.id)?.descriptor).toEqual(aba.descriptor);
    await alice.sendTimelineMessage(realm, `${marker} target cancellation recovered`);
    await expect(bob.page.getByRole("img", {name: "target-aba.png", exact: true})).toBeVisible({timeout: 120_000});

    // New objects use fresh salt/key material even for identical source bytes.
    await drop(alice.page, "fresh-private-image.png", "image/png", png);
    await expect.poll(async () => (await holderAttachments(alice.page)).find(o => o.filename === "fresh-private-image.png")?.uploaded,
      {timeout: 120_000}).toBe(true);
    const fresh = (await holderAttachments(alice.page)).find(o => o.filename === "fresh-private-image.png")!;
    expect(fresh.salt).not.toBe(before.salt);
    expect(fresh.blobRef).not.toBe(before.blobRef);
    expect(fresh.ciphertext).not.toEqual(before.ciphertext);
    const large = Buffer.alloc(3 * 1024 * 1024 + 11);
    for (let i = 0; i < large.length; ++i) large[i] = (i * 17 + 9) % 251;
    await alice.page.evaluate(() => {
      const original = Blob.prototype.arrayBuffer;
      (window as any).__attachmentSourceReads = {sizes: [] as number[], original};
      Blob.prototype.arrayBuffer = function(this: Blob) {
        (window as any).__attachmentSourceReads.sizes.push(this.size);
        return original.call(this);
      };
    });
    await drop(alice.page, "large-private.bin", "application/octet-stream", large);
    await expect.poll(async () => (await holderAttachments(alice.page)).find(o => o.filename === "large-private.bin")?.uploaded,
      {timeout: 120_000}).toBe(true);
    const sourceReads = await alice.page.evaluate(() => {
      const trace = (window as any).__attachmentSourceReads;
      Blob.prototype.arrayBuffer = trace.original;
      return trace.sizes as number[];
    });
    expect(sourceReads.reduce((sum, size) => sum + size, 0)).toBe(large.length);
    expect(Math.max(...sourceReads)).toBeLessThanOrEqual(262_144);
    expect(sourceReads.length).toBe(Math.ceil(large.length / 262_144));
    await alice.sendTimelineMessage(realm, `${marker} fresh and segmented`);
    await expect(bob.page.getByRole("img", {name: "fresh-private-image.png", exact: true})).toBeVisible({timeout: 120_000});
    const largeLink = bob.page.getByTestId("verified-attachment-download").filter({hasText: "large-private.bin"});
    await expect(largeLink).toBeVisible({timeout: 120_000});
    const downloaded = await largeLink.evaluate(async (link: HTMLAnchorElement) => Array.from(new Uint8Array(await (await fetch(link.href)).arrayBuffer())));
    expect(sha(Buffer.from(downloaded))).toBe(sha(large));

    const longBody = `${marker} long text\n` + "segmented UTF-8 正文\n".repeat(20_000) + "long-text-final-验收";
    const longInput = alice.page.getByTestId("chat-input");
    try {
      await expect(longInput).toBeVisible({timeout: 120_000});
      await expect(longInput).toBeEditable({timeout: 120_000});
      // Enter one large paste through the production input handler. The full
      // receiver byte comparison below checks that the entire draft is consumed.
      await longInput.evaluate((input: HTMLTextAreaElement, text) => {
        const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!;
        setter.call(input, text);
        input.dispatchEvent(new InputEvent("input", {bubbles: true, inputType: "insertFromPaste", data: text}));
      }, longBody);
      await expect(longInput).toHaveValue(longBody);
    } catch (error) {
      await testInfo.attach("long-text-input-boundary.json", {contentType: "application/json", body: JSON.stringify({
        path: new URL(alice.page.url()).pathname,
        input: await longInput.evaluate((input: HTMLTextAreaElement) => ({length: input.value.length,
          disabled: input.disabled, readOnly: input.readOnly, rectangle: input.getBoundingClientRect().toJSON(),
          display: getComputedStyle(input).display, visibility: getComputedStyle(input).visibility})),
      })});
      await testInfo.attach("long-text-input-boundary.png", {contentType: "image/png", body: await alice.page.screenshot()});
      throw error;
    }
    await expect(alice.page.getByTestId("send-chat-button")).toBeEnabled({timeout: 120_000});
    await alice.page.getByTestId("send-chat-button").click();
    await expect(bob.page.getByTestId("verified-long-text-page")).toContainText(`${marker} long text`, {timeout: 120_000});
    const textLink = bob.page.getByRole("link", {name: "Download full text", exact: true});
    const firstPageUrl = await textLink.getAttribute("href");
    expect(firstPageUrl).toMatch(/^blob:/);
    const textReader = bob.page.getByTestId("verified-long-text");
    const firstReaderId = await textReader.getAttribute("data-reader-id");
    const textViewport = bob.page.getByTestId("verified-long-text-viewport");
    const firstPageHeight = await textViewport.evaluate((element: HTMLElement) => element.getBoundingClientRect().height);
    expect(firstPageHeight).toBeGreaterThan(0);
    expect(firstPageHeight).toBeLessThanOrEqual(384);
    let fullText: string;
    try {
      await bob.page.getByTestId("verified-long-text-last").click();
      await expect(bob.page.getByTestId("verified-long-text-page")).toContainText("long-text-final-验收");
      // Let ResizeObserver/virtual-window feedback settle; paging must keep the
      // same mounted verified artifact, rather than recreating a revoked URL.
      await bob.page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
      await expect(bob.page.getByTestId("verified-long-text-page")).toContainText("long-text-final-验收");
      await expect(textReader).toHaveAttribute("data-reader-id", firstReaderId!);
      await expect(textLink).toHaveAttribute("href", firstPageUrl!);
      expect(await textViewport.evaluate((element: HTMLElement) => element.getBoundingClientRect().height)).toBe(firstPageHeight);
      fullText = await textLink.evaluate(async (link: HTMLAnchorElement) => await (await fetch(link.href)).text());
    } catch (error) {
      await testInfo.attach("long-text-reader-boundary.json", {contentType: "application/json", body: JSON.stringify({
        firstPageUrl, firstReaderId, firstPageHeight,
        current: await textReader.evaluate((element: HTMLElement) => ({
          reader: element.dataset.readerId, page: element.dataset.pageIndex,
          url: element.querySelector("a")?.getAttribute("href"),
          row: element.closest("[data-message-id]")?.getAttribute("data-message-id"),
          rectangle: element.getBoundingClientRect().toJSON(),
          lastDisabled: (element.querySelector('[data-testid="verified-long-text-last"]') as HTMLButtonElement)?.disabled,
          feed: element.closest('[id^="chat-feed-"]')?.scrollTop,
        })).catch(() => null),
      })});
      throw error;
    }
    expect(fullText).toBe(longBody);
    const preparedBlobs = (await holderAttachments(alice.page)).filter(o => o.scope.realm_id === realm && o.uploaded);
    const storedBlobs = await inspectStoredBlobs(preparedBlobs.map(o => o.blobRef));
    expect(storedBlobs).toHaveLength(preparedBlobs.length);
    for (const stored of storedBlobs) {
      expect(stored.payload).toEqual({encryption: {scheme: "ak.blob.stream_aead.v1"}});
      expect(stored.media_type).toBe("application/octet-stream");
      expect(stored.filename).toBeNull();
      expect(stored.size_bytes).toBe(preparedBlobs.find(o => o.blobRef === stored.id)!.ciphertext.length);
    }

    // A genuine Add advances the accepted epoch. Existing members retain old
    // authorized checkpoints, while a since-join member has no historical key.
    const oldEpoch = (await readScopeMlsGroupCurrentApi(request, aliceSession.grantJwt, realm))!.epoch;
    const lateSession = await createDpopUserSession(request, "attachment-late-history");
    if (!lateSession) throw new Error("historical authorization needs a real third participant");
    await grantInviteConsentArkret(request, lateSession.grantJwt, lateSession.user, aliceSession.user.id);
    const lateLocator = await issueInviteLocatorToken(request, lateSession.grantJwt);
    await alice.inviteFromAdmin(realm, lateSession.user.id, lateSession.user.id, {token: lateLocator});
    late = (await openDpopUserPageFromSession(browser, lateSession))?.page;
    if (!late) throw new Error("late-history device did not open");
    await late.completeRecoveryKeySetupIfPrompted();
    await late.acknowledgeRecommendedEncryptionPromptIfVisible();
    await late.completeMlsAccountRecoveryIfPrompted(lateSession.recoveryKey!);
    await late.acceptInvite(realm);
    await expect.poll(async () => (await readScopeMlsGroupCurrentApi(request, aliceSession.grantJwt, realm))?.epoch ?? -1,
      {timeout: 120_000}).toBeGreaterThan(oldEpoch);
    await late.gotoTimelineRealm(realm);
    const historicalSourceUrl = `${colandBaseUrl()}/_arkret/self/committed-events/${encodeURIComponent(originalMessageId)}`;
    const historicalSource = await request.get(historicalSourceUrl, {
      headers: selfPathHeadersForDpopSession(lateSession, "GET", historicalSourceUrl),
    });
    expect(historicalSource.status()).toBe(404);
    expect((await historicalSource.json()).type).toBe("https://arkret.org/problems/not_found");
    await expect(late.page.getByTestId("verified-attachment-image")).toHaveCount(0);
    await expect(late.page.getByTestId("verified-long-text")).toHaveCount(0);
    await bob.page.reload({waitUntil: "domcontentloaded"});
    await bob.gotoTimelineRealm(realm);
    await scrollTimeline(bob.page, "oldest");
    await expect(bob.page.getByRole("img", {name: "private-image.png", exact: true})).toBeVisible({timeout: 120_000});
    await verifyImage();
    const previousPreviewUrl = await bob.page.getByRole("img", {name: "private-image.png", exact: true}).getAttribute("src");
    expect(previousPreviewUrl).toMatch(/^blob:/);
    await bob.gotoHome();
    expect(await bob.page.evaluate(async url => {
      try { await fetch(url!); return true; } catch { return false; }
    }, previousPreviewUrl)).toBe(false);
    await expect(bob.page.getByTestId("verified-attachment-image")).toHaveCount(0);
    await bob.gotoTimelineRealm(realm);
    await scrollTimeline(bob.page, "oldest");
    await expect(bob.page.getByRole("img", {name: "private-image.png", exact: true})).toBeVisible({timeout: 120_000});
    await scrollTimeline(bob.page, "latest");
    await expect(bob.page.getByTestId("verified-long-text-page")).toContainText(`${marker} long text`, {timeout: 120_000});
    await bob.page.reload({waitUntil: "domcontentloaded"});
    await bob.gotoTimelineRealm(realm);
    await scrollTimeline(bob.page, "oldest");
    await expect(bob.page.getByRole("img", {name: "private-image.png", exact: true})).toBeVisible({timeout: 120_000});
    await verifyImage();

    const base = colandBaseUrl();
    const presignUrl = `${base}/_arkret/self/blob/presign`;
    const denied = await request.post(presignUrl, {headers: {...selfPathHeadersForDpopSession(aliceSession, "POST", presignUrl), "content-type": "application/json"},
      data: canonicalJson({blob_ref: before.blobRef, realm_id: realm, purpose: "media_inline"})});
    expect(denied.status()).toBe(403);
    expect((await denied.json()).type).toBe("https://arkret.org/problems/capability_denied");

    // A corrupt authenticated HTTP response must not create a usable preview.
    let tampered = 0;
    await bob.page.route(/\/_arkret\/self\/blob\/get\?/, async route => {
      if (new URL(route.request().url()).searchParams.get("blob_ref") !== before.blobRef) { await route.continue(); return; }
      const response = await route.fetch();
      const bytes = await response.body(); bytes[0] ^= 1; tampered += 1;
      await route.fulfill({response, body: bytes});
    });
    await bob.page.reload({waitUntil: "domcontentloaded"});
    await bob.gotoTimelineRealm(realm);
    await scrollTimeline(bob.page, "oldest");
    await expect(bob.page.getByTestId("attachment-error").first()).toBeVisible({timeout: 120_000});
    expect(tampered).toBeGreaterThan(0);
    await expect(bob.page.getByRole("img", {name: "private-image.png", exact: true})).toHaveCount(0);
    await testInfo.attach("encrypted-attachment-two-device-evidence.json", {body: JSON.stringify({realm, senderDevice: aliceSession.user.deviceId, receiverDevice: bobSession.user.deviceId,
      blobs: preparedBlobs.map(o => ({blob_ref: o.blobRef, encryption: {scheme: "ak.blob.stream_aead.v1"}, size_bytes: o.ciphertext.length})),
      postgres_rows: storedBlobs, uploads, original_descriptor: before.descriptor,
      assertions: {exact_restart_object: true, private_structured_send: true, receiver_bytes_and_pixels: true, receiver_restart: true,
        target_draft_aba_cancel_and_exact_recovery: true, fresh_object_salt_and_ciphertext: true,
        bounded_browser_source_reads: sourceReads, large_segmented_file_sha256: sha(large), long_text_full_sha256: sha(Buffer.from(fullText)),
        long_text_paging_keeps_artifact_url: true, long_text_viewport_height: firstPageHeight,
        historical_epoch_advanced_from: oldEpoch, since_join_historical_source_not_found: true, since_join_no_historical_preview: true,
        preview_url_revoked_on_target_navigation: true,
        ciphertext_presign_refused: true, tamper_no_preview: tampered}}), contentType: "application/json"});
  } finally { await late?.close(); await bob?.close(); await alice.close(); }
});
