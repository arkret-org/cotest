import { expect, test, operationSelector, isDirectAdmissionOutcomeReason } from "./arkret-test";
import type { Page, Response, Request, APIRequestContext } from "@playwright/test";
import { assertAuthoritySubmitOutcome, authHeaders, canonicalJson, readCommitStreamHeadApi, scanRealmStreamApi, sdkEventDerivedIds, sha256CanonicalJson, signedEventEnvelope, wireErrCode } from "./coland-api";
import { decodeEventIngressBody, ingressEvents, type IngressEvent } from "./event-ingress";
import { readFile, writeFile, rename, rm } from "node:fs/promises";
import { randomBytes, randomUUID } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { colandBaseUrl, colandServiceDid, colandServiceId, colandServiceResolution, configuredServerKeys, type ColandKey } from "./env";
import { cotestWire } from "./coland-api/wire-client";
import { orderByCanonicalKey } from "./direct-structure-order";
import { readCurrentSnapshot } from "./direct-current-snapshot";
import type { ActorId } from "./generated/spec-wire-objects";

// Negative structure targets must exist outside Direct's protected Realm.
// Circle creation does not create a Strand: author it with an explicit scope.
export async function createDirectBoundaryCircleStrand(
  page: Page, request: APIRequestContext, token: string, realmId: string, title: string,
): Promise<string> {
  await page.goto(`/realms/${encodeURIComponent(realmId)}/circles`, { waitUntil: "domcontentloaded" });
  await page.getByTestId("circle-create-open").click();
  await page.getByTestId("circle-create-title").fill(title);
  await expect(page.getByTestId("circle-create-encrypted")).not.toBeChecked();
  await page.getByTestId("circle-create-submit").click();
  await expect(page).toHaveURL(/\/realms\/[^/]+\/circles\/[^/]+$/);
  const circleId = decodeURIComponent(new URL(page.url()).pathname.split("/").at(-1)!);
  expect(circleId).toMatch(/^ak:circle:/);

  await page.goto(`/chat/${encodeURIComponent(realmId)}`, { waitUntil: "domcontentloaded" });
  await page.getByTestId("open-channel-dialog").click();
  await expect(page.getByTestId("channel-create-modal")).toBeVisible();
  await page.getByTestId("new-channel-name").fill(`${title} Strand`);
  const picker = page.getByTestId("new-channel-circle-scope");
  await picker.locator('button[aria-haspopup="listbox"]').click();
  await picker.locator(`[role="option"][data-value="${circleId}"]`).click();
  await expect(picker.locator('button[aria-haspopup="listbox"]')).toContainText(title);
  await page.getByTestId("create-channel-button").click();
  const channel = page.getByTestId("channel-item").filter({ hasText: `${title} Strand` });
  // The joined Circle can appear in the picker before its signed current cut
  // is installed. Only retry this known pre-authoring refusal; an unknown
  // submission outcome must retain its original durable write identity.
  await expect(async () => {
    if (await channel.isVisible()) return;
    const status = await page.getByTestId("chat-status").textContent();
    if (status === "Strand create failed: MLS send gate is not ready: Circle send requires a verified Circle member current") {
      await page.getByTestId("create-channel-button").click();
    }
    await expect(channel).toBeVisible({ timeout: 1_000 });
  }).toPass({ timeout: 60_000, intervals: [1_000, 2_000, 5_000] });

  let strandId: string | undefined;
  await expect.poll(async () => {
    const history = await scanRealmStreamApi(request, token, realmId, {
      streamRef: { kind: "circle", realm_id: realmId, circle_id: circleId }, limit: 1000,
    });
    expect(history.truncated).toBe(false);
    const created = history.events.find(event => event.kind === "ak.strand.create");
    if (!created) return undefined;
    expect(created.scope_ref).toEqual({ kind: "circle", realm_id: realmId, circle_id: circleId });
    if (typeof created.event_id !== "string") throw new Error("accepted Circle Strand has no Event id");
    strandId = created.event_id.replace(/^ak:event:/, "ak:strand:");
    return strandId;
  }).toMatch(/^ak:strand:/);
  return strandId!;
}

// Refusal diagnostics must not dump unexpected accepted Commit signatures.
function structureOutcomeDiagnostic(outcome: Record<string, unknown>): string {
  const safe = Object.fromEntries(["status", "reason_code", "type", "code"].map(key => {
    const value = outcome[key];
    return [key, value === undefined || value === null || ["string", "number", "boolean"].includes(typeof value)
      ? value : "[non-scalar metadata]"];
  }));
  return JSON.stringify(safe);
}

// Diagnostic pairing of one real self submit; not an independent authority/Ed verifier.
async function observeSelectedHumanSend(page: Page, strandId: string) {
  const source = await page.evaluate(() => {
    const config = JSON.parse(localStorage.getItem("inkson.config.v1") ?? "{}");
    const active = config.active_account;
    if (!active?.authority?.principal_id || !active?.authority?.station_id || !active?.device_id || !active?.server_url) {
      throw new Error("send diagnostic active Account source unavailable");
    }
    return { account: active.authority, device: active.device_id, station: active.server_url };
  });
  const realm = decodeURIComponent(new URL(page.url()).pathname.split("/")[2] ?? "");
  let requestCount = 0;
  let responseCount = 0;
  let raw: string | undefined;
  let original: IngressEvent | undefined;
  let originalCommit: unknown;
  let accepted = false;
  let paired = false;
  let unchanged = true;
  let failed: string | undefined;
  let status = 0;
  const log = (stage: "observing" | "request" | "response" | "transport_failed" | "model_progress" | "finished") => {
    console.info("Direct Chat send diagnostic", JSON.stringify({
      stage, route: "ak.self.events.command.submit.v1", http_status: status,
      matching_request_count: requestCount, matching_response_count: responseCount,
      frozen_request_unchanged: unchanged, typed_pair_ok: paired, accepted,
      gate_failed: failed !== undefined, reason: failed ?? "none",
    }));
  };
  const require = (ok: boolean, reason: string) => { if (!ok) throw new Error(reason); };
  const select = (request: Request): IngressEvent | undefined => {
    const url = new URL(request.url());
    if (request.method() !== "POST" || url.pathname !== "/_arkret/self/events" || url.origin !== new URL(source.station).origin) return;
    const body = request.postDataJSON();
    const rows = decodeEventIngressBody(body, { context: "Direct Chat send diagnostic" });
    const selected = rows.map(row => row.event).filter(event => event.kind === "ak.message.create" && event.realm_id === realm && event.payload?.strand_id === strandId);
    if (!selected.length) return;
    require(selected.length === 1 && rows.length === 1 && body.event && !body.unit_kind && !body.commit_event,
      "message_submission_branch_mismatch");
    const event = selected[0];
    require(canonicalJson(event.actor_id) === canonicalJson({ kind: "account", account_id: source.account }), "message_account_mismatch");
    require(typeof (event.producer_proof as Record<string, unknown>)?.verification_method === "string" && String((event.producer_proof as Record<string, unknown>).verification_method).split("#")[1] === source.device && source.device.startsWith("ak:device:"), "message_not_human_device");
    require(operationSelector("POST", request.url()) === "ak.self.events.command.submit.v1", "unregistered_submit_route");
    return event;
  };
  const onRequest = (request: Request) => {
    try {
      const event = select(request);
      if (!event) return;
      requestCount += 1;
      const bytes = request.postData()!;
      if (raw === undefined) { raw = bytes; original = event; }
      else {
        unchanged = unchanged && raw === bytes && isDeepStrictEqual(original, event);
        require(unchanged, "frozen_request_changed");
      }
      log("request");
    } catch (error) {
      const reasons = ["message_submission_branch_mismatch", "message_account_mismatch", "message_not_human_device", "unregistered_submit_route", "frozen_request_changed"];
      failed = error instanceof Error && reasons.includes(error.message) ? error.message : "request_pairing_failed";
      log("request");
    }
  };
  const onResponse = async (response: Response) => {
    try {
      const event = select(response.request());
      if (!event) return;
      responseCount += 1;
      status = response.status();
      require(original !== undefined && raw === response.request().postData() && isDeepStrictEqual(original, event), "response_request_mismatch");
      const outcome = await response.json() as Record<string, unknown>;
      // Keep the existing registered temporary operation result nonterminal.
      if (status === 503 && outcome.type === "https://arkret.org/problems/temporarily_unavailable" && outcome.status === 503) { log("response"); return; }
      require(response.ok() && (outcome.status === "committed" || outcome.status === "duplicate"), "submit_not_accepted");
      require(Object.keys(outcome).every(key => key === "status" || key === "commit"), "ordinary_outcome_branch_mismatch");
      try { assertAuthoritySubmitOutcome(outcome, event, "Direct Chat send diagnostic"); }
      catch { throw new Error("accepted_coordinate_pairing_failed"); }
      const commit = outcome.commit as Record<string, unknown>;
      const keys = ["commit_id", "realm_id", "stream_ref", "stream_position", "previous_commit_ref", "event_ref", "governance_generation", "authority_ref", "committed_at", "signature"];
      require(keys.every(key => key in commit) && Object.keys(commit).every(key => keys.includes(key) || key === "producer_signer_fact_digest"), "commit_closed_shape_mismatch");
      require(commit.realm_id === realm && commit.event_ref === event.event_id && canonicalJson(commit.stream_ref) === canonicalJson({ kind: "realm", realm_id: realm }), "accepted_scope_pairing_failed");
      require(typeof commit.stream_position === "number" && Number.isSafeInteger(commit.stream_position) && commit.stream_position >= 0 && typeof commit.governance_generation === "number" && Number.isSafeInteger(commit.governance_generation) && commit.governance_generation >= 0, "accepted_integer_pairing_failed");
      require(sdkEventDerivedIds(event).event_id === event.event_id, "event_content_id_mismatch");
      const { commit_id, signature, ...unsigned } = commit;
      const expectedId = "ak:realm_commit:" + Buffer.concat([Buffer.from([1]), Buffer.from(sha256CanonicalJson(unsigned), "hex")]).toString("base64url");
      require(commit_id === expectedId, "commit_content_id_mismatch");
      const proof = signature as Record<string, unknown>;
      require(proof.context === "ak.realm_commit_signature.v1" && proof.signature_algorithm === "Ed25519" && proof.signed_digest === "sha256:" + sha256CanonicalJson({ commit_id, ...unsigned }), "commit_signature_binding_mismatch");
      if (originalCommit !== undefined) require(isDeepStrictEqual(originalCommit, commit), "accepted_original_changed");
      originalCommit = commit;
      paired = true;
      accepted = true;
      log("response");
    } catch (error) {
      const reasons = ["response_request_mismatch", "submit_not_accepted", "ordinary_outcome_branch_mismatch", "accepted_coordinate_pairing_failed", "commit_closed_shape_mismatch", "accepted_scope_pairing_failed", "accepted_integer_pairing_failed", "event_content_id_mismatch", "commit_content_id_mismatch", "commit_signature_binding_mismatch", "accepted_original_changed"];
      failed = error instanceof Error && reasons.includes(error.message) ? error.message : "response_pairing_failed";
      log("response");
    }
  };
  const onFailed = (request: Request) => {
    try { if (select(request)) { status = -1; log("transport_failed"); } }
    catch { failed = "request_pairing_failed"; log("transport_failed"); }
  };
  page.on("request", onRequest);
  page.on("response", onResponse);
  page.on("requestfailed", onFailed);
  log("observing");
  return {
    check: () => { if (failed) throw new Error(`Direct Chat send diagnostic: ${failed}`); },
    paired: () => accepted && paired,
    modelProgress: () => log("model_progress"),
    dispose: () => { page.off("request", onRequest); page.off("response", onResponse); page.off("requestfailed", onFailed); log("finished"); },
  };
}

// These are observations of complete Station-signed cuts, not projected UI rows.
// The WeakMap is process-only and tied to the actual page owning this fixture.
const structuralBoundaries = new WeakMap<Page, DirectStructureProof>();
type StructureCut = { rows: Array<Record<string, any>>; floor: unknown;
  position: number; head: string; groups: Array<Record<string, unknown>>; authority: Record<string, any> };
async function verifyStructureSnapshotAuthority(request: APIRequestContext, realm: string,
  snapshot: Record<string, any>) {
  // Replicas retain the governing Station's original Snapshot signature.
  // Its method is only a routing hint; the SDK below must still qualify the
  // complete nonce-bound authority chain and method-native key history.
  const signerDid = snapshot.signature?.verification_method?.split("#")[0];
  const candidates = configuredServerKeys().filter(key => colandServiceDid(key) === signerDid);
  expect(candidates.length, "Snapshot signer has one configured authority candidate").toBe(1);
  const candidate = candidates[0]!;
  const authorityRequest = { realm_id: realm, nonce: randomBytes(32).toString("base64url") };
  const authority = await request.post(`${colandBaseUrl(candidate)}/_arkret/open/realm-authority/bundle`, {
    headers: { "content-type": "application/json" }, data: canonicalJson(authorityRequest) });
  expect(authority.status(), "candidate must supply the actual nonce-bound authority bundle").toBe(200);
  const resolution = await request.get(colandServiceResolution(candidate).resolution_url);
  expect(resolution.status(), "candidate's method-native service history is available").toBe(200);
  const authorityBundle = await authority.json();
  expect(cotestWire<{ verified: boolean }>("verify-realm-state-snapshot", {
    snapshot, expected_snapshot_id: snapshot.snapshot_id, authority_request: authorityRequest,
    authority_bundle: authorityBundle, trusted_service_id: colandServiceId(candidate),
    service_resolution: await resolution.json(),
  }).verified, "SDK must verify the whole current snapshot and native authority history").toBe(true);
  return authorityBundle as Record<string, any>;
}
async function readDirectCurrentSnapshot(proof: DirectStructureProof, realm: string,
  viewer?: { token: string; server: ColandKey }): Promise<Record<string, any>> {
  const url = new URL(`${colandBaseUrl(viewer?.server)}/_arkret/self/realm-state-snapshot/head`);
  url.searchParams.set("realm_id", realm);
  return readCurrentSnapshot(
    remainingMs => proof.request.get(url.toString(), { headers: authHeaders(viewer?.token ?? proof.token, "GET", url.toString()), timeout: Math.min(30_000, remainingMs) }),
    async body => {
      const snapshot = body as Record<string, any>;
      await verifyStructureSnapshotAuthority(proof.request, realm, snapshot);
      return snapshot;
    },
  );
}
async function structureCut(proof: DirectStructureProof, realm: string,
  viewer?: { token: string; server: ColandKey }): Promise<StructureCut> {
  let result!: StructureCut;
  await expect(async () => {
    const base = colandBaseUrl(viewer?.server);
    const url = `${base}/_arkret/self/realm-state-snapshot/head?realm_id=${encodeURIComponent(realm)}`;
    const response = await proof.request.get(url, { headers: authHeaders(viewer?.token ?? proof.token, "GET", url) });
    expect(response.status(), "complete signed structure-boundary snapshot").toBe(200);
    const snapshot = await response.json();
    const authority = await verifyStructureSnapshotAuthority(proof.request, realm, snapshot);
    const stream = { kind: "realm", realm_id: realm };
    const heads = snapshot.visible_stream_heads.filter((head: any) => isDeepStrictEqual(head.stream_ref, stream));
    expect(heads.length, "exact visible Realm head").toBe(1);
    const scan = await scanRealmStreamApi(proof.request, viewer?.token ?? proof.token, realm,
      { limit: 1000, server: viewer?.server });
    expect(scan.truncated, "boundary requires the complete readable accepted prefix").toBe(false);
    const last = scan.commits.at(-1) as Record<string, unknown> | undefined;
    expect(last?.commit_id === heads[0].commit_id, "scan and complete current must cover one exact head").toBe(true);
    const protectedKinds = ["member_state", "circle_member_state", "realm_history_access",
      "direct_conversation_binding", "mls_group"];
    const rows = orderByCanonicalKey(
      snapshot.current_state_entries.filter((row: any) => protectedKinds.includes(row.selector.kind)),
      (row: any) => canonicalJson(row.selector),
    );
    expect(rows.filter((r: any) => r.selector.kind === "member_state").length).toBeGreaterThan(0);
    expect(rows.filter((r: any) => r.selector.kind === "direct_conversation_binding").length).toBe(1);
    const mls = rows.filter((r: any) => r.selector.kind === "mls_group");
    expect(mls.filter((row: any) => isDeepStrictEqual(row.selector.scope_ref, stream)).length,
      "the actual shared Realm MLS scope must exist").toBe(1);
    const groups: Array<Record<string, unknown>> = [];
    for (const row of mls) {
      const scope = row.selector.scope_ref;
      expect(isDeepStrictEqual(scope, row.value.effective_scope), "typed MLS selector must name its exact effective scope").toBe(true);
      expect(row.value.covered_key_access_revision === row.value.current_key_access_revision,
        "all real device Adds must finish before this boundary").toBe(true);
      const scopeHeads = snapshot.visible_stream_heads.filter((head: any) => isDeepStrictEqual(head.stream_ref, scope));
      expect(scopeHeads.length, "each disclosed MLS scope needs its actual visible accepted head").toBe(1);
      const source = isDeepStrictEqual(scope, stream) ? scan : await scanRealmStreamApi(proof.request,
        viewer?.token ?? proof.token, realm, { limit: 1000, server: viewer?.server, streamRef: scope });
      expect(source.truncated, "qualify all visible scope groups through their complete accepted prefix").toBe(false);
      expect(source.commits.at(-1)?.commit_id === scopeHeads[0].commit_id).toBe(true);
      let genesis = source.events.find((event: any) => event.event_id === row.value.genesis_event_ref);
      if (!genesis && proof.peer) {
        // The founder qualifies the public Genesis; this never widens the
        // peer's own readable prefix or its authenticated history floor.
        const other = viewer ? undefined : proof.peer;
        const founderHistory = await scanRealmStreamApi(proof.request, other?.token ?? proof.token, realm,
          { limit: 1000, server: other?.server, streamRef: scope });
        expect(founderHistory.truncated).toBe(false);
        genesis = founderHistory.events.find((event: any) => event.event_id === row.value.genesis_event_ref);
      }
      expect(genesis?.kind === "ak.mls.genesis", "group is sourced by the actual accepted Genesis").toBe(true);
      const material = cotestWire<Record<string, unknown>>("mls-genesis-material", genesis!.payload);
      expect(isDeepStrictEqual(material.effective_scope, row.value.effective_scope)).toBe(true);
      groups.push(material);
    }
    result = { rows, floor: snapshot.retention_and_history_floor,
      position: heads[0].stream_position, head: heads[0].commit_id, groups, authority };
  }).toPass({ timeout: 90_000 });
  return result;
}
async function readVerifiedDirectSuccessors(proof: DirectStructureProof, realm: string,
  authority: Record<string, any>, beforePosition: number, endPosition: number,
  commits: Array<Record<string, unknown>>): Promise<Array<{
    commit: Record<string, unknown>; event_id: string; event_kind: string;
  }>> {
  const genesis = authority.genesis_event;
  const fixed = genesis.payload.object;
  expect(genesis.kind).toBe("ak.realm.create");
  expect(fixed.purpose, "private original lookup is restricted to verified Direct Genesis").toBe("direct_conversation");
  expect(authority.authority_transitions, "Direct has no governance transfer history").toEqual([]);
  expect(authority.current_generation).toBe(0);
  expect(authority.current_service_id).toBe(fixed.governance_station_id);
  const topology = JSON.parse(await readFile(process.env.COTEST_TOPOLOGY_PATH!, "utf8"));
  const servers = topology.servers.filter((server: { coland: { service_id: string } }) =>
    server.coland.service_id === fixed.governance_station_id);
  expect(servers, "verified fixed Direct governor has exactly one runner-owned lease").toHaveLength(1);
  const directSource = { service_id: fixed.governance_station_id,
    genesis_event_id: genesis.event_id, genesis_commit: authority.genesis_commit,
    expected_commits: commits };
  const script = fileURLToPath(new URL("../../scripts/realm-business-footprint.py", import.meta.url));
  const { stdout } = await promisify(execFile)("python3", [script, "--server", servers[0].name,
    "--realm", realm, "--stream-after-position", String(beforePosition),
    "--stream-end-position", String(endPosition),
    "--verified-direct-source", JSON.stringify(directSource)], { timeout: 45_000, maxBuffer: 1_048_576 });
  const stored = JSON.parse(stdout).stream_successors;
  expect(Array.isArray(stored)).toBe(true);
  expect(stored).toHaveLength(commits.length);
  return stored;
}
async function assertStructureBoundary(proof: DirectStructureProof, realm: string,
  before: StructureCut[], event: IngressEvent) {
  const viewers = [undefined, ...(proof.peer ? [proof.peer] : [])];
  for (let index = 0; index < viewers.length; index++) {
    const after = await structureCut(proof, realm, viewers[index]);
    expect(isDeepStrictEqual(after.rows, before[index].rows),
      "Chat/Topic writes preserve every visible member, binding, history and MLS typed row with exact source/revision").toBe(true);
    expect(isDeepStrictEqual(after.floor, before[index].floor), "each participant's complete history floors stay exact").toBe(true);
    expect(isDeepStrictEqual(after.groups, before[index].groups), "accepted SDK Genesis group identities stay exact").toBe(true);
    const successor = await scanRealmStreamApi(proof.request, viewers[index]?.token ?? proof.token, realm,
      { limit: 1000, server: viewers[index]?.server, afterPosition: before[index].position });
    expect(successor.truncated).toBe(false);
    expect(successor.commits.length).toBe(successor.eventSlots.length);
    const end = successor.commits.findIndex(commit => commit.commit_id === after.head
      && commit.stream_position === after.position);
    expect(end, "accepted tail reaches the exact after-Snapshot head").toBeGreaterThanOrEqual(0);
    const slots = successor.eventSlots.slice(0, end + 1);
    const commits = successor.commits.slice(0, end + 1);
    const stored = slots.some(row => row === undefined)
      ? await readVerifiedDirectSuccessors(proof, realm, after.authority,
        before[index].position, after.position, commits) : [];
    const interval = slots.filter((row): row is Record<string, unknown> => row !== undefined);
    for (const [offset, commit] of successor.commits.slice(0, end + 1).entries()) {
      expect(commit.stream_position, "structure interval is a complete continuous accepted tail")
        .toBe(before[index].position + offset + 1);
      const original = slots[offset];
      if (original === undefined) {
        expect(isDeepStrictEqual(stored[offset].commit, commit),
          "hidden successor retains the entire publicly disclosed accepting Commit").toBe(true);
        expect(stored[offset].event_id === commit.event_ref).toBe(true);
        expect(stored[offset].event_kind, "only a verified independent franking receipt may be withheld")
          .toBe("ak.moderation.franking_proof");
      } else {
        expect(commit.event_ref, "each visible interval Commit binds its actual Event").toBe(original.event_id);
      }
    }
    expect(interval.some((row: any) => row.event_id === event.event_id)).toBe(true);
    // Ordinary encrypted messages and their receiving-service franking
    // proofs can finish asynchronously without changing any custody row.
    // Never include writes beyond the exact signed after-cut in this interval.
    const unexpectedKinds = [...new Set(interval.filter((row: any) => !["ak.space.create", "ak.space.update", "ak.space.archive",
      "ak.space.restore", "ak.space.tombstone", "ak.strand.create", "ak.strand.update", "ak.strand.archive",
      "ak.strand.restore", "ak.strand.watch.set", "ak.message.create", "ak.moderation.franking_proof"].includes(row.kind))
      .map(row => row.kind))];
    expect(unexpectedKinds, "structure interval cannot conceal a member/history/MLS/Realm transition").toEqual([]);
    await test.info().attach(`structure-custody-boundary-${index}-${event.event_id}`, {
      body: JSON.stringify({ realm_id: realm, viewer_station: viewers[index]?.server ?? "default",
        protected_rows: after.rows.length, groups: after.groups, history_floor_unchanged: true,
        member_and_mls_rows_exact: true, before_head: before[index].head, after_head: after.head,
        actual_structure_event: event.event_id, accepted_successors: commits.length, withheld_franking_successors: slots.length - interval.length }), contentType: "application/json" });
  }
}

// Existing test-feature hook: actual Device/MLS sender; no private material crosses JS.
async function realTyping(page: Page, realm: string, strand: string, typing: boolean) {
  await expect.poll(() => page.evaluate(() => typeof (window as any).__inkson_signal_sender_evidence),
    { timeout: 30_000 }).toBe("function");
  return page.evaluate(async ({ realm, strand, typing }) => JSON.parse(await
    (window as any).__inkson_signal_sender_evidence(realm, strand, typing)), { realm, strand, typing }) as Promise<{
      accepted: boolean; dispatched_recipient_count?: number; envelope_digest: string;
      group_id: string; epoch: number; sender_actor_id: unknown; sender_device_id: string;
    }>;
}
async function realSignalReceiver(page: Page, clear = false): Promise<Array<Record<string, any>>> {
  await expect.poll(() => page.evaluate(() => typeof (window as any).__inkson_signal_receiver_evidence),
    { timeout: 30_000 }).toBe("function");
  return page.evaluate(clear => JSON.parse((window as any).__inkson_signal_receiver_evidence(clear ? "clear" : "read")), clear);
}
async function assertWrongPlaintextStrand(alice: Page, bob: Page, realm: string, chat: string,
  proof: DirectStructureProof) {
  const target = proof.boundaryTargets?.realmStrand;
  expect(target, "negative requires an actual accepted Strand in another Realm").toBeDefined();
  const before = await readCommitStreamHeadApi(proof.request, proof.token, realm);
  expect(before !== undefined).toBe(true);
  await realSignalReceiver(bob, true);
  const positive = await realTyping(alice, realm, chat, true);
  expect(positive.accepted, "same-group positive Typing must reach the actual Station").toBe(true);
  expect(positive.dispatched_recipient_count ?? 0).toBeGreaterThan(0);
  await expect.poll(async () => (await realSignalReceiver(bob)).some(row => row.strand_id === chat
    && isDeepStrictEqual(row.sender_actor_id, positive.sender_actor_id)
    && row.sender_endpoint?.device_id === positive.sender_device_id
    && row.admitted_and_decrypted === true && row.target_scope_matches === true
    && row.live_applied === true && row.visible_count > 0), { timeout: 15_000 }).toBe(true);
  await expect(bob.getByTestId("typing-indicator")).toHaveCount(1);
  const negative = await realTyping(alice, realm, target!, true);
  expect(negative.accepted, "wrong plaintext target must still have a legal encrypted outer Signal").toBe(true);
  expect(negative.dispatched_recipient_count ?? 0).toBeGreaterThan(0);
  expect(negative.group_id === positive.group_id && negative.epoch === positive.epoch,
    "positive and negative use the same genuine MLS group/epoch").toBe(true);
  let rows: Array<Record<string, any>> = [];
  await expect.poll(async () => {
    rows = (await realSignalReceiver(bob)).filter(row => row.strand_id === target
      && isDeepStrictEqual(row.sender_actor_id, negative.sender_actor_id)
      && row.sender_endpoint?.device_id === negative.sender_device_id);
    return rows.some(row => row.admitted_and_decrypted === true && row.target_scope_matches === false);
  }, { timeout: 15_000 }).toBe(true);
  expect(rows.every(row => row.scope_ref?.kind === "realm" && row.scope_ref.realm_id === realm
    && row.strand_id === target && row.live_applied === false && row.visible_count === 0),
    "actual decrypted wrong-Strand Typing produces no live AppSink state").toBe(true);
  // Stop the same actual positive indicator; no fabricated final Message is involved.
  const stopped = await realTyping(alice, realm, chat, false);
  expect(stopped.accepted).toBe(true);
  await expect.poll(async () => (await realSignalReceiver(bob)).some(row => row.strand_id === chat
    && row.typing === false && row.target_scope_matches === true && row.live_applied === true
    && row.visible_count === 0 && isDeepStrictEqual(row.sender_actor_id, positive.sender_actor_id)
    && row.sender_endpoint?.device_id === positive.sender_device_id), { timeout: 15_000 }).toBe(true);
  await expect(bob.getByTestId("typing-indicator")).toHaveCount(0);
  const after = await readCommitStreamHeadApi(proof.request, proof.token, realm);
  expect(isDeepStrictEqual(after, before), "ephemeral Typing must not append Event/Commit").toBe(true);
  await test.info().attach("encrypted-signal-actual-wrong-plaintext-strand", {
    body: JSON.stringify({ group_id: positive.group_id, epoch: positive.epoch,
      positive_delivered_and_applied: true, negative_delivered_and_decrypted: true,
      negative_target_scope_rejected: true, app_sink_output_count: 0, event_commit_unchanged: true }),
    contentType: "application/json" });
}

export async function structureWrite(page: Page, action: string, kind: string, title?: string, topic?: string, refusal?: string): Promise<IngressEvent> {
  const panel = page.getByTestId("direct-structure");
  await expect(panel).toBeVisible();
  if (!await panel.getByRole("combobox", { name: "Action", exact: true }).isVisible()) {
    await panel.getByRole("button", { name: "Manage chats and topics" }).click();
  }
  await panel.getByRole("combobox", { name: "Action", exact: true }).selectOption(action);
  if (title) await panel.getByRole("textbox", { name: "Title", exact: true }).fill(title);
  if (topic) await panel.getByRole("combobox", { name: "Topic", exact: true }).selectOption(topic);
  await expect(panel.getByRole("button", { name: "Save", exact: true })).toBeEnabled({ timeout: 180_000 });
  const boundaryProof = structuralBoundaries.get(page);
  const boundaryRealm = decodeURIComponent(new URL(page.url()).pathname.split("/")[2] ?? "");
  const boundaryBefore = boundaryProof ? await Promise.all([structureCut(boundaryProof, boundaryRealm),
    ...(boundaryProof.peer ? [structureCut(boundaryProof, boundaryRealm, boundaryProof.peer)] : [])]) : undefined;
  const responses: Response[] = [];
  let signedRequestEmitted = false;
  let preAuthoringRetries = 0;
  let wake: (() => void) | undefined;
  const captureRequest = (request: Request) => {
    if (request.method() !== "POST" || new URL(request.url()).pathname !== "/_arkret/self/events") return;
    if (ingressEvents(decodeEventIngressBody(request.postDataJSON())).some(event => event.kind === kind)) {
      signedRequestEmitted = true;
    }
  };
  const capture = (response: Response) => {
    if (response.request().method() !== "POST" || new URL(response.url()).pathname !== "/_arkret/self/events") return;
    if (!ingressEvents(decodeEventIngressBody(response.request().postDataJSON())).some(event => event.kind === kind)) return;
    responses.push(response);
    wake?.();
  };
  page.on("request", captureRequest);
  page.on("response", capture);
  const deadline = Date.now() + 90_000;
  let frozen: IngressEvent | undefined;
  try {
    await panel.getByRole("button", { name: "Save", exact: true }).click();
    while (Date.now() < deadline) {
      if (!responses.length) {
        await new Promise<void>(resolve => {
          const timer = setTimeout(() => { wake = undefined; resolve(); }, Math.max(0, Math.min(100, deadline - Date.now())));
          wake = () => { clearTimeout(timer); wake = undefined; resolve(); };
        });
      }
      const accepted = responses.shift();
      if (!accepted) {
        // A concurrent committed read may refuse before an Event is frozen.
        // Retry the retained editor draft only while no signed request exists;
        // an emitted request still follows the exact original Event checks.
        const status = await panel.getByTestId("direct-structure-status").textContent();
        if (!signedRequestEmitted && preAuthoringRetries < 3
          && /^(?:MLS send gate is not ready: )?account checkpoint changed (?:before|during) committed read$/.test(status?.trim() ?? "")
          && await panel.getByRole("button", { name: "Save", exact: true }).isEnabled()
          && Date.now() < deadline) {
          preAuthoringRetries++;
          await panel.getByRole("button", { name: "Save", exact: true }).click({
            timeout: Math.max(1, Math.min(3_000, deadline - Date.now())),
          });
        }
        continue;
      }
      const event = ingressEvents(decodeEventIngressBody(accepted.request().postDataJSON())).find(event => event.kind === kind)!;
      if (!frozen) frozen = event;
      expect(isDeepStrictEqual(event, frozen), "retry must preserve the complete frozen signed Event").toBe(true);
      const outcome = await accepted.json() as Record<string, unknown>;
      if (accepted.status() === 503 && outcome.type === "https://arkret.org/problems/temporarily_unavailable"
        && outcome.status === 503) continue;
      if (refusal) {
        expect(accepted.status(), structureOutcomeDiagnostic(outcome)).toBe(409);
        expect(wireErrCode(outcome)).toBe("failed_precondition");
        expect(outcome.reason_code).toBe(refusal);
        expect(outcome.commit === undefined, "refused write must omit Commit").toBe(true);
        await expect(panel.getByTestId("direct-structure-status")).not.toHaveText("Saved");
        return event;
      }
      expect(accepted.ok(), `structure HTTP refusal: ${accepted.status()} ${String(outcome.type)}`).toBeTruthy();
      expect(outcome.status, `structure refusal: ${String(outcome.reason_code)}`).toBe("committed");
      assertAuthoritySubmitOutcome(outcome, event, action);
      await expect(panel.getByTestId("direct-structure-status")).toHaveText("Saved", { timeout: Math.max(1, deadline - Date.now()) });
      if (boundaryProof && boundaryBefore) await assertStructureBoundary(boundaryProof, boundaryRealm, boundaryBefore, event);
      return event;
    }
    const diagnostic = {
      action,
      expected_kind: kind,
      matching_responses_remaining: responses.length,
      signed_event_observed: signedRequestEmitted,
      pre_authoring_retries: preAuthoringRetries,
      panel_visible: await panel.isVisible().catch(() => false),
      status: await panel.getByTestId("direct-structure-status").textContent().catch(() => null),
      save_enabled: await panel.getByRole("button", { name: "Save", exact: true }).isEnabled().catch(() => false),
    };
    await test.info().attach("direct-structure-write-timeout", {
      body: JSON.stringify(diagnostic), contentType: "application/json",
    });
    console.warn("Direct structure timeout diagnostic", JSON.stringify(diagnostic));
    throw new Error("structure write did not commit within the original 90 second budget");
  } finally {
    page.off("request", captureRequest);
    page.off("response", capture);
    wake?.();
    if (preAuthoringRetries) await test.info().attach("direct-structure-pre-authoring-retries", {
      body: JSON.stringify({ action, expected_kind: kind, pre_authoring_retries: preAuthoringRetries,
        signed_request_emitted: signedRequestEmitted }), contentType: "application/json",
    });
  }
}

export async function agentTopicChats(page: Page, receiptPath: string, proof: DirectStructureProof) {
  structuralBoundaries.set(page, proof);
  expect(receiptPath, "actual runtime model receipt path").not.toBe("");
  const panel = page.getByTestId("direct-structure");
  const mainId = decodeURIComponent(new URL(page.url()).pathname.split("/")[3]);
  const suffix = Date.now();
  const topic = await structureWrite(page, "new_topic", "ak.space.create", `agent-topic-${suffix}`);
  const topicId = topic.event_id!.replace("ak:event:", "ak:space:");
  const chats: string[] = [];
  let lastChat: IngressEvent | undefined;
  for (const name of ["a", "b"]) {
    const created = await structureWrite(page, "new_chat", "ak.strand.create", `agent-chat-${name}-${suffix}`);
    lastChat = created;
    const id = created.event_id!.replace("ak:event:", "ak:strand:");
    const choose = panel.getByRole("combobox", { name: "Chat", exact: true });
    try {
      await expect(choose.locator(`option[value=${JSON.stringify(id)}]`)).toContainText(`agent-chat-${name}-${suffix}`);
    } catch (error) {
      const controls = await panel.evaluate(element => Array.from(element.querySelectorAll("select")).map(select => ({
        label: select.getAttribute("aria-label"),
        role: select.getAttribute("role"),
        hidden: select.hidden,
        disabled: select.disabled,
        multiple: select.multiple,
        size: select.size,
        value: select.value,
        display: getComputedStyle(select).display,
        visibility: getComputedStyle(select).visibility,
        options: Array.from(select.options).map(option => ({ value: option.value, title: option.text })),
      })));
      await test.info().attach("chat-selector-dom", {
        body: JSON.stringify({ expectedChat: id, controls }),
        contentType: "application/json",
      });
      throw error;
    }
    await choose.selectOption(id);
    await structureWrite(page, "place", "ak.strand.update", undefined, topicId);
    const preference = panel.getByTestId("direct-agent-reply-preference");
    await expect(preference).toBeVisible();
    const replacing = page.waitForResponse(response => response.request().method() === "PUT"
      && /^\/_arkret\/self\/agents\/[^/]+\/participation$/.test(new URL(response.url()).pathname)
      && response.request().postDataJSON()?.target_scope?.strand_id === id);
    await preference.getByRole("button", { name: "Allow Agent replies in this Chat", exact: true }).click();
    const replaced = await replacing;
    expect(replaced.ok(), "selected Chat participation must be accepted").toBeTruthy();
    const request = replaced.request().postDataJSON();
    expect(request.target_scope).toEqual({ kind: "strand", realm_id: created.realm_id, strand_id: id });
    expect(request.expected_version).toBe(0);
    expect(request.selection).toEqual({
      reply_message: true, reaction_add: false, reaction_remove: false,
      accept_third_party_mention: false, act_on_behalf: false,
    });
    const outcome = await replaced.json();
    expect(outcome.participation_entries).toEqual(expect.arrayContaining([
      expect.objectContaining({ target_scope: request.target_scope, selection: request.selection, version: 1 }),
    ]));
    await expect(preference.getByRole("status")).toHaveText("Reply preference saved for this Chat");
    chats.push(id);
  }
  const markerA = `isolated-chat-a-${suffix}`;
  const markerB = `isolated-chat-b-${suffix}`;
  const receipts = async (): Promise<Array<{ request: unknown; response_pending?: boolean; hold_token?: string }>> => (await readFile(receiptPath, "utf8"))
    .trim().split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line));
  const replyIds = async (): Promise<Set<string>> => {
    const feed = page.getByTestId("message-list").last();
    const ids = new Set<string>();
    let top = 0;
    // Count the actual rendered history across every virtual window. A viewport
    // count can decrease when an older reply leaves the mounted slice.
    for (let step = 0; step < 500; step++) {
      const window = await feed.evaluate(async (element, offset) => {
        element.scrollTop = offset;
        await new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve())));
        const rows = Array.from(element.querySelectorAll<HTMLElement>('[data-message-id][data-virtual-index]'));
        return {
          top: element.scrollTop, height: element.clientHeight, total: element.scrollHeight,
          replies: rows.filter(row => Array.from(row.querySelectorAll('[data-testid="content-block-text"]'))
            .some(block => /^pong(?:\r?\n|$)/.test(block.textContent ?? "")))
            .map(row => row.dataset.messageId!),
        };
      }, top);
      for (const id of window.replies) ids.add(id);
      if (window.top + window.height >= window.total - 1) return ids;
      expect(window.height, "message timeline must have a scrollable viewport").toBeGreaterThan(0);
      top = window.top + window.height;
    }
    throw new Error("message history scan did not reach the final virtual window");
  };
  const send = async (id: string, marker: string, prior?: string, excluded?: string, switchTo?: string) => {
    const realmId = decodeURIComponent(new URL(page.url()).pathname.split("/")[2]);
    const humanActor = await page.evaluate(() => {
      const config = JSON.parse(localStorage.getItem("inkson.config.v1") ?? "{}");
      return { kind: "account", account_id: config.active_account.authority };
    });
    const head = switchTo ? await readCommitStreamHeadApi(proof.request, proof.token, realmId) : undefined;
    let otherReplies: Set<string> | undefined;
    if (switchTo) {
      await panel.getByRole("combobox", { name: "Chat", exact: true }).selectOption(switchTo);
      otherReplies = await replyIds();
    }
    const holdPath = `${receiptPath}.hold.json`;
    const holdToken = randomUUID();
    if (switchTo) {
      await writeFile(`${holdPath}.tmp`, JSON.stringify({ marker, token: holdToken }));
      await rename(`${holdPath}.tmp`, holdPath);
    }
    try {
    await panel.getByRole("combobox", { name: "Chat", exact: true }).selectOption(id);
    const before = (await receipts()).length;
    const repliesBefore = await replyIds();
    await expect(page.getByTestId("send-chat-button")).toBeEnabled({ timeout: 180_000 });
    await page.getByTestId("chat-input").fill(marker);
    const observed = await observeSelectedHumanSend(page, id);
    try {
      await page.getByTestId("send-chat-button").click();
      // One original 180s window covers both pairing and model receipt progress.
      await expect.poll(async () => {
        observed.check();
        const count = (await receipts()).length;
        return observed.paired() ? count : before;
      }, { timeout: 180_000 }).toBeGreaterThan(before);
      observed.modelProgress();
    } finally {
      observed.dispose();
    }
    const inputs = (await receipts()).slice(before).map(row => JSON.stringify(row.request));
    const input = inputs.find(value => value.includes(marker));
    expect(input, "live runtime must forward the selected Chat message").toBeDefined();
    if (prior) expect(input).toContain(prior);
    if (excluded) expect(input).not.toContain(excluded);
    if (switchTo) {
      const held = (await receipts()).slice(before).find(row => row.hold_token === holdToken);
      expect(held?.response_pending, "the actual model request must be held before its reply").toBe(true);
      await panel.getByRole("combobox", { name: "Chat", exact: true }).selectOption(switchTo);
      await expect(panel.getByRole("combobox", { name: "Chat", exact: true })).toHaveValue(switchTo);
      expect([...await replyIds()].sort()).toEqual([...otherReplies!].sort());
      await rm(holdPath, { force: true });
      expect(head, "held generation must have an authenticated accepted cut").toBeDefined();
      let acceptedReply: Record<string, unknown> | undefined;
      await expect.poll(async () => {
        const scan = await scanRealmStreamApi(proof.request, proof.token, realmId, { afterPosition: head!.stream_position });
        expect(scan.truncated).toBe(false);
        const agentReplies = scan.events.filter(event => event.kind === "ak.message.create"
          && canonicalJson(event.actor_id) !== canonicalJson(humanActor));
        expect(agentReplies.every(event => (event.payload as Record<string, unknown>).strand_id === id)).toBe(true);
        acceptedReply = agentReplies[0];
        return agentReplies.length;
      }, { timeout: 180_000 }).toBe(1);
      expect([...await replyIds()].sort()).toEqual([...otherReplies!].sort());
      await test.info().attach("direct-generation-ui-switch-original-strand", {
        body: Buffer.from(JSON.stringify({ hold_token: holdToken, original_strand_id: id, selected_during_generation: switchTo,
          reply_event_id: acceptedReply!.event_id, reply_strand_id: (acceptedReply!.payload as Record<string, unknown>).strand_id })),
        contentType: "application/json",
      });
      await panel.getByRole("combobox", { name: "Chat", exact: true }).selectOption(id);
    }

    await expect.poll(async () => {
      const replies = await replyIds();
      return { total: replies.size, added: [...replies].filter(id => !repliesBefore.has(id)).length,
        retained: [...repliesBefore].every(id => replies.has(id)) };
    }, { timeout: 180_000 }).toEqual({ total: repliesBefore.size + 1, added: 1, retained: true }).catch(async (error: unknown) => {
      const geometry = await page.getByTestId("message-list").last().evaluate(feed => ({
        height: feed.getBoundingClientRect().height,
        viewport: feed.clientHeight,
        scrollHeight: feed.scrollHeight,
        scrollTop: feed.scrollTop,
        mountedRows: feed.querySelectorAll('[data-testid="chat-message"]').length,
        indexes: Array.from(feed.querySelectorAll('[data-virtual-index]')).map(row =>
          Number((row as HTMLElement).dataset.virtualIndex)),
        rows: Array.from(feed.querySelectorAll<HTMLElement>('[data-virtual-index]')).map(row => ({
          index: Number(row.dataset.virtualIndex), crypto: row.dataset.cryptoState,
          pong: Array.from(row.querySelectorAll('[data-testid="content-block-text"]'))
            .some(block => /^pong(?:\r?\n|$)/.test(block.textContent ?? "")),
        })),
      })).catch(() => null);
      await test.info().attach("direct-reply-timeline-geometry", {
        body: Buffer.from(JSON.stringify(geometry)), contentType: "application/json",
      });
      throw error;
    });
    } finally {
      if (switchTo) await rm(holdPath, { force: true });
    }
  };
  await send(chats[0], markerA, undefined, markerB, chats[1]);
  await send(chats[1], markerB, undefined, markerA);
  const movedTopic = await structureWrite(page, "new_topic", "ak.space.create", `agent-topic-moved-${suffix}`);
  const movedTopicId = movedTopic.event_id!.replace("ak:event:", "ak:space:");
  await panel.getByRole("combobox", { name: "Chat", exact: true }).selectOption(chats[0]);
  const moved = await structureWrite(page, "place", "ak.strand.update", undefined, movedTopicId);
  expect(moved.payload?.target_ref).toBe(chats[0]);
  await send(chats[0], `moved-chat-a-${suffix}`, markerA, markerB);
  await structureWrite(page, "place", "ak.strand.update", undefined, topicId);
  await structureWrite(page, "rename_topic_target", "ak.space.update", `agent-topic-renamed-${suffix}`, topicId);
  await structureWrite(page, "archive_topic_target", "ak.space.archive", undefined, topicId);
  await send(chats[0], `continued-chat-a-${suffix}`, markerA, markerB);
  await structureWrite(page, "unplace", "ak.strand.update");
  await send(chats[0], `unclassified-chat-a-${suffix}`, markerA, markerB);
  const returnPath = new URL(page.url()).pathname;
  const selectedAgent = proof.agentId ?? "";
  await page.goto("/settings/agents", { waitUntil: "domcontentloaded" });
  // The controller's ordinary registered administration UI changes the
  // actual lifecycle; the rejected writes keep the previously valid binding.
  expect(selectedAgent, "pause negative requires the exact Direct Agent").not.toBe("");
  await page.locator(`[data-testid="agent-admin-row"][data-agent-id=${JSON.stringify(selectedAgent)}]`).click();
  await page.getByTestId("agent-admin-enabled-switch").click();
  await expect(page.getByTestId("agent-admin-last-op")).toContainText("Paused", { timeout: 180_000 });
  try {
    await rejectDirectStructureEvent(proof, lastChat!, "paused-agent-chat", "ak.strand.archive", { target_ref: chats[0] }, "direct_conversation_participant_authority_denied");
    await rejectDirectStructureEvent(proof, topic, "paused-agent-topic", "ak.space.archive", { space_id: movedTopicId }, "direct_conversation_participant_authority_denied");
  } finally {
    await page.getByTestId("agent-admin-enabled-switch").click();
    await expect(page.getByTestId("agent-admin-last-op")).toContainText("Resumed. Status: active.", { timeout: 180_000 });
    await page.goto(returnPath, { waitUntil: "domcontentloaded" });
  }
  await panel.getByRole("combobox", { name: "Chat", exact: true }).selectOption(mainId);
}

type DirectStructureProof = { request: APIRequestContext; token: string; agentId?: string; peer?: { token: string; server: ColandKey }; boundaryTargets?: { realmStrand: string; circleStrand: string; thirdActor: ActorId; thirdToken: string } };

export async function rejectDirectStructureEvent(proof: DirectStructureProof, template: IngressEvent,
  name: string, kind: string, payload: Record<string, unknown>, reason?: string,
  sender?: { token: string; server?: ColandKey; actor?: ActorId; scope?: Record<string, unknown> }) {
  const realm = template.realm_id!;
  const snapshot = () => readDirectCurrentSnapshot(proof, realm);
  const beforeHead = await readCommitStreamHeadApi(proof.request, proof.token, realm);
  expect(beforeHead, "refusal must have a real observer's accepted head").toBeDefined();
  const beforeSnapshot = await snapshot();
  const before = beforeSnapshot.current_state_entries;
  const event = signedEventEnvelope({
    actorId: sender?.actor ?? template.actor_id as ActorId, realmId: realm, kind, payload,
    authorizationRef: template.authorization_ref as string,
    semanticRefs: template.semantic_refs as Array<Record<string, unknown>>,
    scopeRef: sender?.scope,
    ...(!sender?.actor ? { proofVerificationMethod: (template.producer_proof as { verification_method: string }).verification_method } : {}),
  });
  const url = `${colandBaseUrl(sender?.server)}/_arkret/self/events`;
  const response = await proof.request.post(url, {
    headers: { ...authHeaders(sender?.token ?? proof.token, "POST", url), "content-type": "application/json" },
    data: canonicalJson({ event }),
  });
  const body = await response.json() as Record<string, unknown>;
  const outcomeDiagnostic = structureOutcomeDiagnostic(body);
  if (isDirectAdmissionOutcomeReason(reason)) {
    expect(response.status(), outcomeDiagnostic).toBe(200);
    expect(body.status, outcomeDiagnostic).toBe("rejected");
    expect(Object.keys(body).sort()).toEqual(["reason_code", "status"]);
    expect(body).toEqual({ status: "rejected", reason_code: reason });
  } else {
    expect(response.status(), outcomeDiagnostic).toBe(409);
    expect(wireErrCode(body)).toBe("failed_precondition");
    if (reason) expect(body.reason_code).toBe(reason);
  }
  expect(body.commit === undefined, "refused write must omit Commit").toBe(true);
  expect(body.commits === undefined, "refused write must omit Commits").toBe(true);
  const afterHead = await readCommitStreamHeadApi(proof.request, proof.token, realm);
  expect(afterHead, "refusal observer retains its actual accepted head").toBeDefined();
  expect(afterHead!.stream_ref).toEqual(beforeHead!.stream_ref);
  const unchangedRows = (entries: Array<Record<string, any>>) => orderByCanonicalKey(
    entries.filter(row => row.selector.kind !== "moderation_franking_proof"),
    row => canonicalJson(row.selector),
  );
  expect(unchangedRows((await snapshot()).current_state_entries)).toEqual(unchangedRows(before));
  const after = await scanRealmStreamApi(proof.request, proof.token, realm, { afterPosition: beforeHead!.stream_position });
  expect(after.truncated).toBe(false);
  expect(after.commits.length).toBe(after.eventSlots.length);
  expect(after.events.some(row => row?.event_id === event.event_id), "refused Event never enters the accepted stream").toBe(false);
  expect(after.commits.some(commit => commit.event_ref === event.event_id), "refused Event has no accepting Commit").toBe(false);
  let independentFrankingSuccessors = 0;
  if (afterHead!.commit_id === beforeHead!.commit_id) {
    expect(afterHead).toEqual(beforeHead);
  } else {
    const end = after.commits.findIndex(commit => commit.commit_id === afterHead!.commit_id
      && commit.stream_position === afterHead!.stream_position);
    expect(end, "refusal observation reaches its exact after-head").toBeGreaterThanOrEqual(0);
    independentFrankingSuccessors = end + 1;
    // A private receiving proof can legally be Withheld, and a departed peer
    // cannot supply a new member read. The runner-owned readonly test oracle
    // checks accepted kind/ID plus the same full Commit, without exposing the
    // hidden payload or treating omission as a protocol proof.
    let stored: Array<{ commit: Record<string, unknown>; event_id: string; event_kind: string }> = [];
    if (after.eventSlots.slice(0, end + 1).some(row => row === undefined)) {
      // Verify the accepted Genesis/current authority before selecting a
      // private runner lease. Direct's governor is fixed from creation; an
      // observer can legally hold only the same disclosed Withheld Commit.
      const authority = await verifyStructureSnapshotAuthority(proof.request, realm, beforeSnapshot);
      stored = await readVerifiedDirectSuccessors(proof, realm, authority,
        beforeHead!.stream_position, afterHead!.stream_position, after.commits.slice(0, end + 1));
    }
    for (const [offset, commit] of after.commits.slice(0, end + 1).entries()) {
      expect(commit.stream_position).toBe(beforeHead!.stream_position + offset + 1);
      const original = after.eventSlots[offset];
      if (original === undefined) {
        expect(stored[offset].commit, "the stored original has the same entire accepting Commit").toEqual(commit);
        expect(stored[offset].event_id).toBe(commit.event_ref);
        expect(stored[offset].event_kind).toBe("ak.moderation.franking_proof");
        continue;
      }
      expect(original, "a private omission cannot prove a successor's Event kind").toBeDefined();
      expect(commit.event_ref).toBe(original.event_id);
      // A delayed receiving-service receipt is independent of this refused
      // write. It must not conceal any business or governance Event.
      expect(original.kind, "only concurrent franking receipts may advance the refusal observation")
        .toBe("ak.moderation.franking_proof");
    }
  }
  await test.info().attach(`direct-negative-${name}`, {
    body: Buffer.from(JSON.stringify({ event_id: event.event_id, expected_reason: reason ?? "failed_precondition",
      stream_head: beforeHead, current_unchanged: true, refused_events: 0, accepting_commits: 0,
      independent_franking_successors: independentFrankingSuccessors })),
    contentType: "application/json",
  });
}

export async function directStructureLifecycleGate(alice: Page, bob: Page, proof: DirectStructureProof,
  name: string, change: (author: IngressEvent) => Promise<void>) {
  const topic = await structureWrite(alice, "new_topic", "ak.space.create", `${name}-topic-${Date.now()}`);
  const chat = await structureWrite(bob, "new_chat", "ak.strand.create", `${name}-chat-${Date.now()}`);
  const chatId = chat.event_id!.replace("ak:event:", "ak:strand:");
  const topicId = topic.event_id!.replace("ak:event:", "ak:space:");
  // These actual accepted participant commands are the positive controls.
  // Change one authoritative prerequisite, then reuse their binding basis.
  await change(chat);
  await rejectDirectStructureEvent(proof, chat, `${name}-chat`, "ak.strand.archive", { target_ref: chatId },
    "direct_conversation_participant_authority_denied", proof.peer);
  // Membership activation is actor-specific; leave does not remove the stable pair.
  const topicAuthor = name === "leave" ? chat : topic;
  await rejectDirectStructureEvent(proof, topicAuthor, `${name}-topic`, "ak.space.archive", { space_id: topicId },
    "direct_conversation_participant_authority_denied", name === "leave" ? proof.peer : undefined);
  await rejectDirectStructureEvent(proof, chat, `${name}-watch`, "ak.strand.watch.set", {
    strand_id: chatId, watcher_actor_id: chat.actor_id, level: "muted",
  }, "direct_conversation_participant_authority_denied", proof.peer);
  if (name === "leave") {
    const accepted = await structureWrite(alice, "archive_topic_target", "ak.space.archive", undefined, topicId);
    expect(accepted.actor_id).toEqual(topic.actor_id);
    expect(accepted.payload?.space_id).toBe(topicId);
    await test.info().attach("direct-positive-active-participant-after-peer-leave", {
      body: Buffer.from(JSON.stringify({ event_id: accepted.event_id, actor_id: accepted.actor_id,
        realm_id: accepted.realm_id, target_space_id: topicId, inactive_participant: chat.actor_id,
        actor_membership_active_join: true, stable_pair_retained_after_peer_leave: true })),
      contentType: "application/json",
    });
  }
}

async function ownWatchTransitions(page: Page, otherPages: Page[], strandId: string) {
  let previous: Record<string, unknown> | null | undefined;
  let last: IngressEvent | undefined;
  const writes: Array<{ event_id: string | undefined; level: string | null; expected_value: unknown }> = [];
  for (const level of ["all", "muted", "mentions_only", "participating", "default", "all"]) {
    await page.getByTestId("watch-level-toggle").click();
    const option = page.getByTestId("watch-level-menu").locator(`[data-watch-level="${level}"]`);
    await expect(option, "the actual self current must enable this choice before observing its write").toBeEnabled({ timeout: 30_000 });
    const [response] = await Promise.all([
      page.waitForResponse(response => response.request().method() === "POST"
        && new URL(response.url()).pathname === "/_arkret/self/events"
        && ingressEvents(decodeEventIngressBody(response.request().postDataJSON())).some(event => event.kind === "ak.strand.watch.set")),
      option.click(),
    ]);
    expect(response.ok(), await response.text()).toBe(true);
    const event = ingressEvents(decodeEventIngressBody(response.request().postDataJSON())).find(event => event.kind === "ak.strand.watch.set")!;
    const outcome = await response.json() as Record<string, unknown>;
    expect(outcome.status).toBe("committed");
    assertAuthoritySubmitOutcome(outcome, event, `watch ${level}`);
    last = event;
    const payload = event.payload!;
    expect(payload.strand_id).toBe(strandId);
    expect(payload.watcher_actor_id).toEqual(event.actor_id);
    expect(payload.level).toBe(level === "default" ? null : level);
    if (writes.length) expect(payload.expected_value, "CAS is the entire previous cell, including a written null").toEqual(previous);
    const label = { all: "All", muted: "Muted", mentions_only: "Mentions", participating: "Participating", default: "Default" }[level]!;
    await expect(page.getByTestId("watch-level-toggle")).toContainText(label, { timeout: 90_000 });
    previous = level === "default" ? null : {
      level,
      ...(Object.hasOwn(payload, "level_public") ? { level_public: payload.level_public } : {}),
    };
    writes.push({ event_id: event.event_id, level: payload.level as string | null, expected_value: payload.expected_value });
  }
  await page.reload();
  await expect(page.getByTestId("watch-level-toggle")).toContainText("All", { timeout: 90_000 });
  for (const other of otherPages) {
    await expect(other.getByTestId("watch-level-toggle"), "another participant's private watch never changes this participant's cell").toContainText("Default", { timeout: 90_000 });
  }
  await test.info().attach("watch-whole-value-transitions", {
    body: Buffer.from(JSON.stringify({ strand_id: strandId, writes, private_other_cells_unchanged: true, cold_level: "all" })),
    contentType: "application/json",
  });
  return last!;
}

// A keepalive request holds a real IndexedDB transaction until the test aborts
// it. No secret backend or durability acknowledgement is replaced. Router
// navigation keeps this document alive while unmounting the settings component.
async function indexedDbClearRecovery(page: Page, mainId: string, chatId: string, oldDraft: string, cancelSettings: boolean) {
  const input = page.getByTestId("chat-input");
  const choose = page.getByTestId("direct-structure").getByRole("combobox", { name: "Chat", exact: true });
  await choose.selectOption(mainId);
  await input.fill(oldDraft);
  await expect(input).toHaveAttribute("data-draft-storage", "saved");
  await page.evaluate(() => {
    type Barrier = {
      held: number; aborted: number; committed: number; armed: boolean;
      release: () => void; dispose: () => void;
    };
    const target = window as typeof window & { __directCacheBarrier?: Barrier };
    if (target.__directCacheBarrier) throw new Error("cache barrier already installed");
    const originalPut = IDBObjectStore.prototype.put;
    const originalDelete = IDBObjectStore.prototype.delete;
    let heldTransaction: IDBTransaction | undefined;
    const state: Barrier = {
      held: 0, aborted: 0, committed: 0, armed: false,
      release: () => {
        const transaction = heldTransaction;
        heldTransaction = undefined;
        transaction?.abort();
      },
      dispose: () => {
        state.release();
        IDBObjectStore.prototype.put = originalPut;
        IDBObjectStore.prototype.delete = originalDelete;
        delete target.__directCacheBarrier;
      },
    };
    target.__directCacheBarrier = state;
    const observe = (store: IDBObjectStore, key: IDBValidKey | IDBKeyRange | undefined) => {
      if (store.name !== "entries" || store.transaction.db.name !== "inkson.secret.inkson"
        || typeof key !== "string" || !key.startsWith("inkson.e2ee_plaintext_cache.v1.")) return;
      const transaction = store.transaction;
      if (state.armed && state.held === 0) {
        state.held += 1;
        heldTransaction = transaction;
        transaction.addEventListener("abort", () => { state.aborted += 1; }, { once: true });
        const keepAlive = () => {
          if (heldTransaction !== transaction) return;
          const read = store.get(key);
          read.onsuccess = keepAlive;
          read.onerror = () => { heldTransaction = undefined; };
        };
        keepAlive();
      } else {
        transaction.addEventListener("complete", () => { state.committed += 1; }, { once: true });
      }
    };
    IDBObjectStore.prototype.put = function (value, key) {
      const request = originalPut.call(this, value, key);
      observe(this, key);
      return request;
    };
    IDBObjectStore.prototype.delete = function (key) {
      const request = originalDelete.call(this, key);
      observe(this, key);
      return request;
    };
  });
  const barrier = async () => page.evaluate(() => {
    const value = (window as typeof window & { __directCacheBarrier?: { held: number; aborted: number; committed: number } }).__directCacheBarrier;
    if (!value) throw new Error("router navigation replaced the IndexedDB barrier document");
    return { held: value.held, aborted: value.aborted, committed: value.committed };
  });
  try {
    await page.getByTestId("account-menu-button").click();
    await page.getByTestId("account-menu-settings").click();
    await page.getByTestId("settings-nav-item-storage").click();
    await expect(page.getByTestId("e2ee-cache-clear-all")).toBeEnabled();
    await page.evaluate(() => { (window as any).__directCacheBarrier.armed = true; });
    await page.getByTestId("e2ee-cache-clear-all").click();
    await page.getByTestId("e2ee-cache-clear-confirm").click();
    await expect.poll(async () => (await barrier()).held).toBe(1);
    if (cancelSettings) {
      // Same-document back unmounts the pending settings component before the
      // real transaction fails; the independent cache completion must survive.
      await page.goBack();
      await expect(page.getByTestId("e2ee-plaintext-cache")).toHaveCount(0);
      await page.goBack();
      await expect(choose).toBeVisible();
      await choose.selectOption(chatId);
      const newer = `${oldDraft}-new-chat`;
      await input.fill(newer);
      await expect(input).toHaveAttribute("data-draft-storage", "saving");
      await page.evaluate(() => { (window as any).__directCacheBarrier.release(); });
      await expect.poll(async () => (await barrier()).aborted).toBe(1);
      await expect(input).toHaveAttribute("data-draft-storage", "saved");
      await expect.poll(async () => (await barrier()).committed).toBeGreaterThan(0);
      await page.reload();
      await expect(input).toHaveValue(newer, { timeout: 90_000 });
      await choose.selectOption(mainId);
      await expect(input).toHaveValue(oldDraft);
      await choose.selectOption(chatId);
      await input.fill("");
      await expect(input).toHaveAttribute("data-draft-storage", "saved");
    } else {
      await page.evaluate(() => { (window as any).__directCacheBarrier.release(); });
      await expect.poll(async () => (await barrier()).aborted).toBe(1);
      await expect(page.getByTestId("e2ee-plaintext-cache").getByRole("status")).toContainText("cleanup failed");
      await expect.poll(async () => (await barrier()).committed).toBeGreaterThan(0);
      await page.goBack();
      await page.goBack();
      await expect(choose).toBeVisible();
      await page.reload();
      await choose.selectOption(mainId);
      await expect(input).toHaveValue(oldDraft, { timeout: 90_000 });
    }
    await test.info().attach(`indexeddb-clear-recovery-${cancelSettings ? "cancelled-page" : "visible-error"}`, {
      body: Buffer.from(JSON.stringify({ native_indexeddb_transaction_aborts: 1, cold_old_draft_retained: true,
        cold_new_chat_retained: cancelSettings, settings_unmounted_before_abort: cancelSettings })),
      contentType: "application/json",
    });
  } finally {
    await page.evaluate(() => { (window as any).__directCacheBarrier?.dispose(); });
  }
}

export async function flatTopicChats(alice: Page, bob: Page, mainMessages: string[], extraDevices: Page[] = [], proof?: DirectStructureProof) {
  const pages = [alice, bob, ...extraDevices];
  for (const page of pages) {
    await page.addLocatorHandler(page.getByTestId("mls-backup-modal"), async () => {
      await page.getByTestId("mls-backup-dismiss").click();
    });
  }
  try {
    await runFlatTopicChats(alice, bob, mainMessages, extraDevices, proof);
  } finally {
    for (const page of pages) {
      await page.removeLocatorHandler(page.getByTestId("mls-backup-modal"));
    }
  }
}

async function runFlatTopicChats(alice: Page, bob: Page, mainMessages: string[], extraDevices: Page[], proof?: DirectStructureProof) {
  expect(proof, "structure coverage requires the actual accepted participant credentials").toBeDefined();
  structuralBoundaries.set(alice, proof!);
  await expect(alice.getByTestId("direct-structure").getByRole("combobox", { name: "Action", exact: true })).toHaveCount(0);
  const mainPath = new URL(alice.url()).pathname;
  const mainId = decodeURIComponent(mainPath.split("/")[3]);
  const suffix = Date.now();
  const topicName = `topic-${suffix}`;
  let chatName = `chat-${suffix}`;
  const topic = await structureWrite(alice, "new_topic", "ak.space.create", topicName);
  const topicId = topic.event_id!.replace("ak:event:", "ak:space:");
  const object = topic.payload?.object as Record<string, unknown>;
  expect(object.kind).toBe("topic");
  expect(object.parent_space_id).toBeUndefined();
  expect(object.title).toBeUndefined();
  expect(object.encrypted_metadata).toBeTruthy();
  expect(JSON.stringify(object)).not.toContain(topicName);
  const chat = await structureWrite(alice, "new_chat", "ak.strand.create", chatName);
  const chatId = chat.event_id!.replace("ak:event:", "ak:strand:");
  expect(chatId).not.toBe(mainId);
  expect((chat.payload?.object as Record<string, unknown>).topic).toBeUndefined();
  expect(JSON.stringify(chat.payload)).not.toContain(chatName);
  for (const page of [alice, bob, ...extraDevices]) {
    const choose = page.getByTestId("direct-structure").getByRole("combobox", { name: "Chat", exact: true });
    await expect(choose.locator(`option[value=${JSON.stringify(chatId)}]`)).toContainText(chatName, { timeout: 90_000 });
    await choose.selectOption(chatId);
    for (const message of mainMessages) await expect(page.getByTestId("chat-message").filter({ hasText: message })).toHaveCount(0);
  }
  const bobWatch = await ownWatchTransitions(bob, [alice, ...extraDevices], chatId);
  await assertWrongPlaintextStrand(alice, bob, chat.realm_id!, chatId, proof!);
  const classified = await structureWrite(alice, "place", "ak.strand.update", undefined, topicId);
  expect(classified.payload?.target_ref).toBe(chatId);
  expect(classified.payload?.expected_state_digest).toMatch(/^sha256:[a-f0-9]{64}$/);
  const patch = classified.payload?.patch as Record<string, { $op: string; value?: { space_id: string } }>;
  expect(patch.topic.value?.space_id).toBe(topicId);
  const chooseAlice = alice.getByTestId("direct-structure").getByRole("combobox", { name: "Chat", exact: true });
  const allPages = [alice, bob, ...extraDevices];
  const chatOptions = (page: Page) => page.getByTestId("direct-structure").getByRole("combobox", { name: "Chat", exact: true });
  const renamedChat = `${chatName}-renamed`;
  const renameChat = await structureWrite(alice, "rename_chat", "ak.strand.update", renamedChat);
  expect(renameChat.payload?.target_ref).toBe(chatId);
  expect(Object.keys(renameChat.payload?.patch as object)).toEqual(["encrypted_metadata"]);
  expect(JSON.stringify(renameChat.payload)).not.toContain(renamedChat);
  chatName = renamedChat;
  for (const page of allPages) await expect(chatOptions(page).locator(`option[value=${JSON.stringify(chatId)}]`)).toContainText(chatName, { timeout: 90_000 });

  const secondTopicName = `${topicName}-second`;
  const secondTopic = await structureWrite(alice, "new_topic", "ak.space.create", secondTopicName);
  const secondTopicId = secondTopic.event_id!.replace("ak:event:", "ak:space:");
  const secondChat = await structureWrite(alice, "new_chat", "ak.strand.create", `${chatName}-second`);
  const secondChatId = secondChat.event_id!.replace("ak:event:", "ak:strand:");
  await expect(chooseAlice).toHaveValue(secondChatId);
  const secondClassification = await structureWrite(alice, "place", "ak.strand.update", undefined, topicId);
  const secondRank = ((secondClassification.payload?.patch as any).topic.value as { rank: string }).rank;
  const firstRank = (patch.topic.value as { space_id: string; rank: string }).rank;
  expect(secondRank > firstRank, "new Chat receives a rank after the existing actual Chat").toBe(true);
  expect(secondClassification.payload?.target_ref).toBe(secondChatId);
  // The accepted receipt can precede installation in the visible current view.
  // Reorder only after both actual Chat classifications are visible and the
  // router has selected the intended first Chat.
  for (const page of allPages) {
    await expect(chatOptions(page).locator(`option[value=${JSON.stringify(secondChatId)}]`))
      .toContainText(topicName, { timeout: 90_000 });
  }
  await chooseAlice.selectOption(chatId);
  await expect.poll(() => decodeURIComponent(new URL(alice.url()).pathname).split("/")[3]).toBe(chatId);
  await expect(chooseAlice).toHaveValue(chatId);
  const reorder = await structureWrite(alice, "reorder", "ak.strand.update", undefined, topicId);
  const reordered = (reorder.payload?.patch as any).topic.value;
  await test.info().attach("direct-reorder-target-and-ranks", {
    body: JSON.stringify({ actual_target_ref: reorder.payload?.target_ref, expected_chat_id: chatId,
      first_rank: firstRank, second_rank: secondRank, reordered_rank: reordered.rank }), contentType: "application/json",
  });
  expect(reorder.payload?.target_ref).toBe(chatId);
  expect(reordered.space_id).toBe(topicId);
  expect(reordered.rank > secondRank).toBe(true);
  for (const page of allPages) {
    await expect.poll(async () => {
      const ids = await chatOptions(page).locator("option").evaluateAll(options => options.map(option => (option as HTMLOptionElement).value));
      return ids.indexOf(secondChatId) < ids.indexOf(chatId);
    }).toBe(true);
  }
  const topicReorder = await structureWrite(alice, "reorder_topic", "ak.space.update", undefined, topicId);
  expect(Object.keys(topicReorder.payload?.patch as object)).toEqual(["rank"]);
  expect((topicReorder.payload?.patch as any).rank.value).toMatch(/^[A-Za-z0-9]{1,128}$/);
  for (const page of allPages) {
    const manage = page.getByTestId("direct-structure");
    if (!await manage.getByRole("combobox", { name: "Action", exact: true }).isVisible()) await manage.getByRole("button", { name: "Manage chats and topics" }).click();
    await manage.getByRole("combobox", { name: "Action", exact: true }).selectOption("reorder_topic");
    await expect.poll(async () => await manage.getByRole("combobox", { name: "Topic", exact: true }).locator("option").evaluateAll(options => options.map(option => (option as HTMLOptionElement).value))).toEqual(["", secondTopicId, topicId]);
  }
  const migrated = await structureWrite(alice, "place", "ak.strand.update", undefined, secondTopicId);
  expect(migrated.payload?.target_ref).toBe(chatId);
  expect((migrated.payload?.patch as any).topic.value.space_id).toBe(secondTopicId);
  for (const page of allPages) {
    await expect(chatOptions(page).locator(`option[value=${JSON.stringify(chatId)}]`)).toContainText(secondTopicName, { timeout: 90_000 });
    await chatOptions(page).selectOption(chatId);
    expect(decodeURIComponent(new URL(page.url()).pathname.split("/")[3])).toBe(chatId);
  }
  await structureWrite(alice, "archive_topic_target", "ak.space.archive", undefined, secondTopicId);
  for (const page of allPages) {
    const option = chatOptions(page).locator(`option[value=${JSON.stringify(chatId)}]`);
    await expect(option).toContainText(secondTopicName);
    await expect(option).not.toContainText("(archived)");
  }
  const rawEntries = (await readDirectCurrentSnapshot(proof!, migrated.realm_id!)).current_state_entries as Array<{ selector: { kind: string; strand_id?: string }; value: unknown }>;
  const exactChat = rawEntries.filter(row => row.selector.kind === "strand" && row.selector.strand_id === chatId);
  expect(exactChat).toHaveLength(1);
  await rejectDirectStructureEvent(proof!, migrated, "classify-archived-topic", "ak.strand.update", {
    target_ref: chatId, expected_state_digest: `sha256:${sha256CanonicalJson(exactChat[0].value)}`,
    patch: { topic: { $op: "set", value: { space_id: secondTopicId, rank: "a0" } } },
  }, "direct_conversation_participant_authority_denied");
  const repaired = await structureWrite(alice, "unplace", "ak.strand.update");
  expect(repaired.payload?.target_ref).toBe(chatId);
  expect(repaired.payload?.patch).toEqual({ topic: { $op: "unset" } });
  for (const page of allPages) {
    await expect(chatOptions(page).locator(`option[value=${JSON.stringify(chatId)}]`)).not.toContainText(secondTopicName);
    expect(decodeURIComponent(new URL(page.url()).pathname.split("/")[3])).toBe(chatId);
  }
  const restoredTopic = await structureWrite(alice, "restore_topic_target", "ak.space.restore", undefined, secondTopicId);
  expect(restoredTopic.payload?.space_id).toBe(secondTopicId);
  await structureWrite(alice, "place", "ak.strand.update", undefined, topicId);
  for (const page of allPages) await expect(chatOptions(page).locator(`option[value=${JSON.stringify(chatId)}]`)).toContainText(topicName, { timeout: 90_000 });
  await chooseAlice.selectOption(secondChatId);
  await structureWrite(alice, "unplace", "ak.strand.update");
  await chooseAlice.selectOption(chatId);
  await structureWrite(alice, "delete_topic_target", "ak.space.tombstone", undefined, secondTopicId);
  // Collapsing classification management is a local navigation preference;
  // the selected actual Chat and its watch cell stay available.
  await alice.getByTestId("direct-structure").getByRole("button", { name: "Manage chats and topics" }).click();
  await expect(alice.getByTestId("direct-structure").getByRole("combobox", { name: "Action", exact: true })).toHaveCount(0);
  await expect(chooseAlice).toHaveValue(chatId);
  const chatDraft = `draft-chat-${suffix}`;
  const mainDraft = `draft-main-${suffix}`;
  await alice.getByTestId("chat-input").fill(chatDraft);
  await chooseAlice.selectOption(mainId);
  await expect(alice.getByTestId("chat-input")).toHaveValue("");
  await alice.getByTestId("chat-input").fill(mainDraft);
  await expect(alice.getByTestId("chat-input")).toHaveAttribute("data-draft-storage", "saved");
  await chooseAlice.selectOption(chatId);
  await expect(alice.getByTestId("chat-input")).toHaveValue(chatDraft);
  await expect(alice.getByTestId("chat-input")).toHaveAttribute("data-draft-storage", "saved");
  // Both drafts are nonempty at process restart. Storage must isolate the
  // actual Strand and device rather than merely preserve mounted Signals.
  await expect(alice).toHaveURL(url => {
    const parts = url.pathname.split("/");
    return parts[1] === "direct"
      && decodeURIComponent(parts[2]) === decodeURIComponent(mainPath.split("/")[2])
      && decodeURIComponent(parts[3]) === chatId;
  });
  await alice.reload();
  await expect(chooseAlice).toHaveValue(chatId, { timeout: 90_000 });
  await expect(alice.getByTestId("chat-input")).toHaveValue(chatDraft);
  await chooseAlice.selectOption(mainId);
  await expect(alice.getByTestId("chat-input")).toHaveValue(mainDraft);
  await chooseAlice.selectOption(chatId);
  for (const device of extraDevices) {
    await expect(device.getByTestId("chat-input")).toHaveValue("");
  }
  for (const [sender, recipient] of [[alice, bob], [bob, alice]] as const) {
    const text = `topic-chat-${sender === alice ? "a" : "b"}-${suffix}`;
    if (sender === alice) {
      const navigation = bob.getByTestId("direct-structure");
      if (await navigation.getByRole("combobox", { name: "Action", exact: true }).isVisible()) {
        await navigation.getByRole("button", { name: "Manage chats and topics" }).click();
      }
      await expect(navigation.getByRole("combobox", { name: "Action", exact: true })).toHaveCount(0);
      await navigation.getByRole("combobox", { name: "Chat", exact: true }).selectOption(mainId);
    }
    await sender.getByTestId("chat-input").fill(text);
    const sending = sender.waitForResponse(response => response.request().method() === "POST"
      && new URL(response.url()).pathname === "/_arkret/self/events"
      && ingressEvents(decodeEventIngressBody(response.request().postDataJSON())).some(event => event.kind === "ak.message.create"));
    await sender.getByTestId("send-chat-button").click();
    const sent = await sending;
    const message = ingressEvents(decodeEventIngressBody(sent.request().postDataJSON())).find(event => event.kind === "ak.message.create")!;
    expect(message.payload?.strand_id).toBe(chatId);
    expect(message.payload?.encrypted_content).toBeTruthy();
    expect(JSON.stringify(message.payload)).not.toContain(text);
    if (sender === alice) {
      await expect(bob.getByTestId("direct-structure").getByRole("combobox", { name: "Chat", exact: true })
        .locator(`option[value=${JSON.stringify(chatId)}]`)).toContainText(/\d+ unread/, { timeout: 90_000 });
      await bob.getByTestId("topbar-notifications-button").click();
      const notification = bob.getByTestId("notification-item").filter({
        has: bob.locator(`a[href$=${JSON.stringify(`/${chatId}`)}]`),
      }).first();
      await expect(notification).toBeVisible({ timeout: 90_000 });
      await notification.getByTestId("notification-open-chat").click();
      await expect(bob.getByTestId("notifications-drawer")).toHaveCount(0);
      await expect(bob).toHaveURL(new RegExp(`/direct/.*/${chatId}$`));
      await expect(bob.getByTestId("direct-structure").getByRole("combobox", { name: "Chat", exact: true })).toHaveValue(chatId);
      await expect(bob.getByTestId("direct-structure").getByRole("combobox", { name: "Chat", exact: true })
        .locator(`option[value=${JSON.stringify(chatId)}]`)).not.toContainText("unread", { timeout: 90_000 });
    }
    await expect(recipient.getByTestId("chat-message").filter({ hasText: text })).toBeVisible({ timeout: 90_000 });
    for (const device of extraDevices) {
      await expect(device.getByTestId("chat-message").filter({ hasText: text })).toBeVisible({ timeout: 90_000 });
    }
  }
  await chooseAlice.selectOption(mainId);
  await expect(alice.getByTestId("chat-input")).toHaveValue(mainDraft);
  await chooseAlice.selectOption(chatId);
  await expect(alice.getByTestId("chat-input")).toHaveValue("");
  await indexedDbClearRecovery(alice, mainId, chatId, mainDraft, false);
  await indexedDbClearRecovery(alice, mainId, chatId, mainDraft, true);
  await chooseAlice.selectOption(chatId);
  const renamed = `${topicName}-renamed`;
  await structureWrite(bob, "rename_topic_target", "ak.space.update", renamed, topicId);
  await Promise.all([alice, bob, ...extraDevices].map(page => page.reload()));
  for (const page of [alice, bob, ...extraDevices]) {
    const choose = page.getByTestId("direct-structure").getByRole("combobox", { name: "Chat", exact: true });
    await expect(choose.locator(`option[value=${JSON.stringify(chatId)}]`)).toContainText(renamed, { timeout: 90_000 });
    await choose.selectOption(chatId);
  }
  const realmId = decodeURIComponent(mainPath.split("/")[2]);
  const snapshot = async (viewer?: { token: string; server: ColandKey }) => {
    if (!proof) return undefined;
    const body = await readDirectCurrentSnapshot(proof, realmId, viewer);
    return body.current_state_entries as Array<Record<string, unknown>>;
  };
  const rejectSigned = (name: string, template: IngressEvent, kind: string, payload: Record<string, unknown>, reason?: string) =>
    rejectDirectStructureEvent(proof!, template, name, kind, payload, reason);
  await rejectSigned("stale-full-chat-cas", classified, "ak.strand.update", classified.payload!);
  await rejectSigned("own-watch-stale-whole-value", classified, "ak.strand.watch.set", {
    strand_id: chatId, watcher_actor_id: classified.actor_id, level: "muted", expected_value: { level: "all" },
  });
  await rejectSigned("other-participant-watch", classified, "ak.strand.watch.set", {
    strand_id: chatId, watcher_actor_id: bobWatch.actor_id, level: "muted", expected_value: { level: "all" },
  }, "direct_conversation_participant_authority_denied");
  await rejectSigned("main-archive", classified, "ak.strand.archive", { target_ref: mainId }, "direct_conversation_participant_authority_denied");
  // Redaction is the registered cross-object command, not an invented Strand kind.
  const acceptedHistory = await scanRealmStreamApi(proof!.request, proof!.token, realmId, { limit: 1000 });
  expect(acceptedHistory.truncated).toBe(false);
  const genesis = acceptedHistory.events.find(event => event.kind === "ak.realm.create")!;
  expect(genesis).toBeDefined();
  const founderTemplate = isDeepStrictEqual(genesis.actor_id, classified.actor_id) ? classified : bobWatch;
  expect(founderTemplate.actor_id).toEqual(genesis.actor_id);
  const founderSender = founderTemplate === classified ? undefined : proof!.peer;
  await rejectDirectStructureEvent(proof!, founderTemplate, "technical-root-operational", "ak.realm.freeze", {},
    "direct_conversation_root_mask_violation", founderSender);
  await rejectDirectStructureEvent(proof!, founderTemplate, "main-redaction", "ak.redaction", { target_ref: mainId },
    "direct_conversation_root_mask_violation", founderSender);
  const boundary = proof!.boundaryTargets!;
  expect(boundary, "full DM-P1 requires real registered third-party and outside targets").toBeDefined();
  await rejectSigned("third-party-join", classified, "ak.member.state", { member_id: boundary.thirdActor, membership: "join" },
    "direct_conversation_third_party_member_forbidden");
  await rejectDirectStructureEvent(proof!, classified, "third-party-chat-write", "ak.strand.archive", { target_ref: chatId },
    "direct_conversation_participant_authority_denied", { token: boundary.thirdToken, actor: boundary.thirdActor });
  const privateCurrent = new URL(`${colandBaseUrl()}/_arkret/self/realm-state-snapshot/head`);
  privateCurrent.searchParams.set("realm_id", realmId);
  await readDirectCurrentSnapshot(proof!, realmId);
  const hidden = await proof!.request.get(privateCurrent.toString(), {
    headers: authHeaders(boundary.thirdToken, "GET", privateCurrent.toString()),
  });
  expect(hidden.status(), await hidden.text()).toBe(404);
  const hiddenBody = await hidden.json();
  expect(wireErrCode(hiddenBody)).toBe("not_found");
  for (const secret of [chatId, topicId, chatName, topicName]) expect(JSON.stringify(hiddenBody)).not.toContain(secret);
  for (const [name, target] of [["cross-realm", boundary.realmStrand], ["cross-circle", boundary.circleStrand]]) {
    await rejectSigned(`${name}-chat-write`, classified, "ak.strand.archive", { target_ref: target }, "direct_conversation_participant_authority_denied");
    await rejectSigned(`${name}-watch`, classified, "ak.strand.watch.set", {
      strand_id: target, watcher_actor_id: classified.actor_id, level: "muted",
    }, "direct_conversation_participant_authority_denied");
  }
  await rejectSigned("chat-track-overflow", classified, "ak.strand.update", {
    target_ref: chatId, patch: { tracks: { $op: "set", value: (chat.payload!.object as Record<string, unknown>).tracks } },
  }, "direct_conversation_participant_authority_denied");
  await rejectSigned("chat-topic-subpath", classified, "ak.strand.update", {
    target_ref: chatId, expected_state_digest: classified.payload!.expected_state_digest,
    patch: { "topic.rank": { $op: "set", value: "a0" } },
  }, "direct_conversation_participant_authority_denied");
  await rejectSigned("topic-parent", topic, "ak.space.create", {
    object: { ...object, parent_space_id: topicId },
  }, "direct_conversation_participant_authority_denied");
  await rejectSigned("unknown-topic-kind", topic, "ak.space.create", {
    object: { ...object, kind: "unknown_topic_kind" },
  }, "direct_conversation_space_forbidden");
  await rejectSigned("topic-plaintext-mirror", topic, "ak.space.create", {
    object: { ...object, title: `forbidden-plaintext-${suffix}` },
  }, "direct_conversation_participant_authority_denied");
  const visibleCurrent = await snapshot();
  expect(JSON.stringify(visibleCurrent)).toContain(chatId);
  expect(JSON.stringify(visibleCurrent)).toContain(topicId);
  for (const title of [topicName, chatName, renamed, secondTopicName]) expect(JSON.stringify(visibleCurrent)).not.toContain(title);
  const originalRead = await scanRealmStreamApi(proof!.request, proof!.token, realmId);
  expect(originalRead.truncated, "full Direct history read cannot hide a truncated prefix").toBe(false);
  if (proof?.peer) {
    const structuralCurrent = (entries: Array<Record<string, unknown>> | undefined) => orderByCanonicalKey(
      entries!.filter(entry => ["strand", "space"].includes(String((entry.selector as { kind?: string })?.kind))),
      row => canonicalJson(row.selector),
    );
    const shared = structuralCurrent(visibleCurrent);
    expect(shared.length, "the complete typed current includes actual Chat and Topic results").toBeGreaterThan(0);
    await expect.poll(async () => structuralCurrent(await snapshot(proof.peer)), { timeout: 90_000 }).toEqual(shared);
    const structuralEvents = (events: Array<Record<string, unknown>>) => events
      .filter(event => ["ak.strand.create", "ak.strand.update", "ak.strand.archive", "ak.strand.restore",
        "ak.space.create", "ak.space.update", "ak.space.archive", "ak.space.restore", "ak.space.tombstone"].includes(String(event.kind)));
    const sharedEvents = structuralEvents(originalRead.events);
    expect(sharedEvents.map(event => event.event_id)).toEqual(expect.arrayContaining([chat.event_id, topic.event_id]));
    let peerRead: Awaited<ReturnType<typeof scanRealmStreamApi>> | undefined;
    await expect(async () => {
      peerRead = await scanRealmStreamApi(proof.request, proof.peer!.token, realmId, { server: proof.peer!.server });
      expect(peerRead.truncated, "the peer's own authenticated Station must supply complete history").toBe(false);
      expect(structuralEvents(peerRead.events)).toEqual(sharedEvents);
    }).toPass({ timeout: 90_000 });
    for (const title of [topicName, chatName, renamed, secondTopicName]) expect(JSON.stringify(peerRead)).not.toContain(title);
    await test.info().attach("direct-peer-station-full-current-read", {
      body: Buffer.from(JSON.stringify({ peer_station: proof.peer.server, complete_structural_current_rows: shared.length,
        complete_structural_events: sharedEvents.length, exact_revisions_values_events_equal: true,
        peer_read_uses_own_station_and_credential: true, metadata_plaintext_mirrors: 0 })), contentType: "application/json",
    });
  }
  for (const title of [topicName, chatName, renamed, secondTopicName]) expect(JSON.stringify(originalRead.events)).not.toContain(title);
  await test.info().attach("direct-full-read-encrypted-metadata", {
    body: Buffer.from(JSON.stringify({ realm_id: realmId, events: originalRead.events.length,
      commits: originalRead.commits.length, complete_snapshot: true, metadata_plaintext_mirrors: 0 })), contentType: "application/json",
  });
  const refusedTopic = async (referenceState: "active" | "archived") => {
    const head = proof && await readCommitStreamHeadApi(proof.request, proof.token, realmId);
    const current = await snapshot();
    const event = await structureWrite(alice, "delete_topic_target", "ak.space.tombstone", undefined, topicId, "space_has_live_dependents");
    expect(event.payload?.space_id).toBe(topicId);
    if (proof) {
      expect(head, "rejection must have an authenticated pre-submit cut").toBeDefined();
      expect(await readCommitStreamHeadApi(proof.request, proof.token, realmId)).toEqual(head);
      expect(await snapshot()).toEqual(current);
      const scan = await scanRealmStreamApi(proof.request, proof.token, realmId, { afterPosition: head!.stream_position });
      expect(scan.truncated).toBe(false);
      expect(scan.events).toEqual([]);
      expect(scan.commits).toEqual([]);
    }
    await test.info().attach(`topic-tombstone-${referenceState}-refusal`, {
      body: Buffer.from(JSON.stringify({ event_id: event.event_id, reason_code: "space_has_live_dependents", head, current_unchanged: !!proof })),
      contentType: "application/json",
    });
    await alice.reload();
    await expect(chooseAlice.locator(`option[value=${JSON.stringify(chatId)}]`)).toContainText(renamed, { timeout: 90_000 });
    await chooseAlice.selectOption(chatId);
  };
  await refusedTopic("active");
  const archived = await structureWrite(alice, "archive_chat", "ak.strand.archive");
  // The registered object lifecycle payload single-sources its target_ref.
  expect(archived.payload?.target_ref).toBe(chatId);
  expect(archived.payload?.target_ref).not.toBe(mainId);
  for (const page of [alice, bob, ...extraDevices]) {
    await expect(page.getByTestId("direct-structure").getByRole("combobox", { name: "Chat", exact: true })
      .locator(`option[value=${JSON.stringify(chatId)}]`)).toContainText("(archived)", { timeout: 90_000 });
  }
  await refusedTopic("archived");
  const restored = await structureWrite(alice, "restore_chat", "ak.strand.restore");
  expect(restored.payload?.target_ref).toBe(chatId);
  expect(restored.payload?.target_ref).not.toBe(mainId);
  for (const page of [alice, bob, ...extraDevices]) {
    const option = page.getByTestId("direct-structure").getByRole("combobox", { name: "Chat", exact: true })
      .locator(`option[value=${JSON.stringify(chatId)}]`);
    await expect(option).not.toContainText("(archived)", { timeout: 90_000 });
    await expect(option).toContainText(renamed);
  }
  // Committed sends cleared the extra Chat, while the untouched main draft
  // survived the second cold reload and both lifecycle transitions.
  await chooseAlice.selectOption(mainId);
  await expect(alice.getByTestId("chat-input")).toHaveValue(mainDraft);
  await chooseAlice.selectOption(chatId);
  await expect(alice.getByTestId("chat-input")).toHaveValue("");
  const cleared = await structureWrite(alice, "unplace", "ak.strand.update");
  expect((cleared.payload?.patch as Record<string, unknown>).topic).toEqual({ $op: "unset" });
  await structureWrite(bob, "delete_topic_target", "ak.space.tombstone", undefined, topicId);
  for (const page of [alice, bob]) {
    await page.getByTestId("direct-structure").getByRole("combobox", { name: "Chat", exact: true }).selectOption(mainId);
    for (const message of mainMessages) await expect(page.getByTestId("chat-message").filter({ hasText: message })).toBeVisible({ timeout: 90_000 });
  }
  expect(decodeURIComponent(new URL(alice.url()).pathname)).toBe(decodeURIComponent(mainPath));
  expect(decodeURIComponent(new URL(bob.url()).pathname.split("/")[2])).toBe(decodeURIComponent(mainPath.split("/")[2]));
}
