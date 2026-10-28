import { createHash } from "node:crypto";
import { expect, test, type Response } from "../../helpers/arkret-test";
import { canonicalJson, accountActorId, sdkEventDerivedIds } from "../../helpers/coland-api";
import type { ContactOperationResponseBody, ContactRespondRequestBody } from "../../helpers/generated/spec-wire-objects";
import { openRegisteredUserPage, type JointUser } from "../../helpers/users";

function isContactPhase(response: Response, endpoint: string, phase: string): boolean {
  return new URL(response.url()).pathname.endsWith(`/_arkret/self/contacts/${endpoint}`)
    && response.request().method() === "POST" && response.request().postDataJSON()?.phase === phase;
}

async function expectFrozenResponse(prepared: Response, committed: Response, recipient: JointUser) {
  expect(prepared.status()).toBe(200);
  const outcome = await prepared.json() as ContactOperationResponseBody;
  if (outcome.status !== "prepared" || outcome.operation_kind !== "response") {
    throw new Error("The recipient did not prepare its Contact response");
  }
  const prepare = prepared.request().postDataJSON() as Extract<ContactRespondRequestBody, { phase: "prepare" }>;
  const commit = committed.request().postDataJSON() as Extract<ContactRespondRequestBody, { phase: "commit" }>;
  expect(commit).toMatchObject({ phase: "commit", operation_id: prepare.operation_id,
    idempotency_key: prepare.idempotency_key, reservation_handle: outcome.reservation_handle });
  expect(outcome.operation_id).toBe(prepare.operation_id);
  const bytes = Buffer.from(outcome.event_draft.unsigned_event_base64url, "base64url");
  const unsigned = JSON.parse(bytes.toString("utf8"));
  expect(canonicalJson(unsigned)).toBe(bytes.toString("utf8"));
  expect(`sha256:${createHash("sha256").update(bytes).digest("hex")}`).toBe(outcome.event_draft.event_digest);
  const { event_id, producer_proof, unsigned: reducerFields, ...payload } = commit.signed_event;
  expect(reducerFields).toBeUndefined();
  expect(payload, "signing preserves every field of the original prepared Event").toEqual(unsigned);
  expect(event_id).toBe(sdkEventDerivedIds(unsigned).event_id);
  expect(commit.signed_event.actor_id).toEqual(accountActorId(recipient.id));
  expect(commit.signed_event.executed_by).toBeUndefined();
  expect(producer_proof.event_digest).toBe(outcome.event_draft.event_digest);
  expect(producer_proof.verification_method).toBe(`${recipient.did}#${recipient.deviceId}`);
  expect(commit.signed_event.payload).toMatchObject({ peer: prepare.peer, request_event_ref: prepare.request_event_ref });
  expect(committed.status(), "the recipient's original signed commit is accepted").toBe(200);
  const accepted = await committed.json() as ContactOperationResponseBody;
  if (accepted.status !== "accepted" || accepted.operation_kind !== "response") {
    throw new Error("The exact Contact response has no final acceptance receipt");
  }
  expect(accepted.operation_id).toBe(prepare.operation_id);
  const receipt = accepted.normal_response_acceptance_receipt;
  expect(receipt.response_event_ref).toBe(event_id);
  expect(receipt.producer_signer.verification_method).toBe(producer_proof.verification_method);
  expect(receipt.request_receipt.core.request_event_ref).toBe(prepare.request_event_ref);
  expect(receipt.request_receipt.core.peer).toEqual({ kind: "human", account_id: accountActorId(recipient.id).account_id });
  return receipt;
}

for (const coldRecipient of [false, true]) {
test(`cold requester signs a real locator Contact request; recipient=${coldRecipient ? "cold" : "established"} @fully-implemented`, async ({ browser, request }) => {
  test.setTimeout(600_000);
  const stamp = Date.now();
  const flows: Array<Awaited<ReturnType<typeof openRegisteredUserPage>>> = [];
  try {
    const alice = await openRegisteredUserPage(browser, request, `contact-ui-alice-${stamp}`);
    flows.push(alice);
    const bob = await openRegisteredUserPage(browser, request, `contact-ui-bob-${stamp}`);
    flows.push(bob);
    await bob.page.page.goto("/settings/account");
    await bob.page.page.getByTestId("settings-invite-locator-refresh").click();
    const locator = bob.page.page.getByTestId("settings-invite-locator-url");
    await expect(locator).toBeVisible({ timeout: 60_000 });
    const address = await locator.inputValue();
    expect(address.includes("#token="), "real locator is available").toBe(true);
    await alice.page.page.goto("/contacts");
    await alice.page.page.reload({ waitUntil: "domcontentloaded" });
    await expect(alice.page.page.getByTestId("status-label")).toHaveText(/^Online(?:$|:)/, { timeout: 90_000 });
    await alice.page.page.getByTestId("add-contact-button").click();
    const form = alice.page.page.getByTestId("contact-request-panel");
    const target = form.getByTestId("contact-target-input");
    await target.fill(address);
    await form.getByTestId("contact-message-input").fill("Please coordinate the project artwork with me.");
    const committed = alice.page.page.waitForResponse(response => {
      if (!new URL(response.url()).pathname.endsWith("/_arkret/self/contacts/request") || response.request().method() !== "POST") return false;
      return response.request().postDataJSON()?.phase === "commit";
    }, { timeout: 90_000 });
    await form.getByTestId("send-contact-request-button").click();
    const requested = await committed;
    expect(requested.status(), "the original signed Contact commit is accepted").toBe(200);
    expect((await requested.json()).status).toBe("accepted");
    await expect(alice.page.page.getByTestId("add-contact-modal")).toBeHidden({ timeout: 60_000 });
    if (coldRecipient) {
      // Inkson #32: an incoming row must not lose its action during connect.
      await bob.page.page.goto("/contacts");
    } else {
      await bob.page.page.getByRole("tab", { name: "Contacts", exact: true }).click();
      await bob.page.page.getByTestId("sidebar-new-contact-cta").click();
      await expect(bob.page.page.getByTestId("status-label")).toHaveText(/^Online(?:$|:)/, { timeout: 90_000 });
    }
    // The cold path acts as soon as the incoming row is available. Waiting
    // for Online here would hide the bootstrap transition reported in #32.
    const incoming = bob.page.page.locator('[data-testid^="contact-accept-"]');
    await expect(incoming).toHaveCount(1, { timeout: 90_000 });
    const preparedResponse = bob.page.page.waitForResponse(response => isContactPhase(response, "respond", "prepare"), { timeout: 60_000 });
    const committedResponse = bob.page.page.waitForResponse(response => isContactPhase(response, "respond", "commit"), { timeout: 90_000 })
      .then(response => ({ response }), error => ({ error }));
    await incoming.click();
    const prepared = await preparedResponse;
    expect(prepared.status()).toBe(200);
    expect(await prepared.json()).toMatchObject({ status: "prepared", operation_kind: "response" });
    const completion = await committedResponse;
    if ("error" in completion) throw completion.error;
    const receipt = await expectFrozenResponse(prepared, completion.response, bob.user);
    expect(receipt.request_receipt.core).toEqual((await requested.json()).request_acceptance_receipt.core);
    await expect(bob.page.page.getByTestId("status-label")).toHaveText(/^Online(?:$|:)/, { timeout: 90_000 });
    await expect(bob.page.page.locator('[data-testid^="contact-message-"]')).toHaveCount(1, { timeout: 90_000 });
    await alice.page.page.reload({ waitUntil: "domcontentloaded" });
    await expect(alice.page.page.locator('[data-testid^="contact-message-"]')).toHaveCount(1, { timeout: 90_000 });
  } finally {
    for (const flow of flows) await test.info().attach(`browser-locks-${flow.user.name}`, {
      body: JSON.stringify(await flow.page.page.evaluate(() => navigator.locks.query())),
      contentType: "application/json",
    });
    await Promise.all(flows.map(flow => flow.page.close()));
  }
});
}

test("Contact address instructions advertise only supported inputs @fully-implemented", async ({ browser, request }) => {
  test.setTimeout(300_000);
  const flow = await openRegisteredUserPage(browser, request, `contact-address-hint-${Date.now()}`);
  try {
    await flow.page.page.goto("/contacts");
    await flow.page.page.getByTestId("add-contact-button").click();
    const form = flow.page.page.getByTestId("contact-request-panel");
    await expect(form).toContainText(/invite link.*complete account/i);
    await expect(form.getByTestId("contact-target-input")).not.toHaveAttribute("placeholder", /alice:|handle/i);
  } finally { await flow.page.close(); }
});
