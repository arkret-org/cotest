// Document collaboration
// Contract: e2e/scenarios/documents/collaboration.md
// Spec refs:
//   - models/morph.md §2 (Morph schema), §4 (facets)
//   - models/content-types.md §2-§3 (content blocks)
//   - models/strand-and-message.md §4.3 (discussion track for comments)
//   - discovery/profiles-presence.md §3 (cursor presence)
//   - authz/event-auth-state-resolution.md §2-§4 (anchor finality)

import { expect, test, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  authHeaders,
  createRealmApi,
  resolveDefaultStrandId,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("Document Morph collaboration", () => {
  test("Document Morph projection reports body versions, relation links, range comments, and orphan state", async ({
    request,
  }) => {
    // spec: morph.md §2/§4 + strand-and-message.md §4.3 + relation.md §3.2.
    const alice = uniqueUser("doc-projection-alice");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);
    const realmId = await createRealmApi(request, token, {
      title: `Document projection ${Date.now()}`,
      history_visibility: "shared",
    });
    const morphId = documentMorphId();
    const relationId = documentRelationId();
    const initialBody = paragraphDocumentBody("abcdefghij");
    const updatedBody = paragraphDocumentBody("abc");

    await submitSignedEventApi(
      request,
      token,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ck.morph.create",
        payload: {
          morph_id: morphId,
          object: {
            id: morphId,
            schema: "ck.schema.morph.v1",
            realm_id: realmId,
            morph_type: "document",
            metadata: { title: "Projection draft" },
            stage: "draft",
            schema_refs: ["ck.schema.morph.v1"],
            facets: { documentable: {} },
            fields: { document: initialBody },
            created_by: alice.did,
            created_at: nowIso(),
          },
        },
      }),
      { context: "create document morph" },
    );

    await submitSignedEventApi(
      request,
      token,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ck.relation.create",
        payload: {
          relation_id: relationId,
          kind: "references",
          from_ref: morphId,
          to_ref: realmId,
          fields: { role: "postmortem_for" },
        },
      }),
      { context: "link document morph relation" },
    );

    const strandId = await resolveDefaultStrandId(request, token, realmId);
    await submitSignedEventApi(
      request,
      token,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ck.message.create",
        payload: {
          strand_id: strandId,
          thread_id: morphId,
          track_name: "discussion",
          content: {
            kind: "ck.content.text",
            morph_id: morphId,
            body: "tighten this range",
            anchor_range: {
              target_ref: morphId,
              start: 2,
              end: 9,
            },
          },
        },
      }),
      { context: "create document range comment" },
    );

    await submitSignedEventApi(
      request,
      token,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId,
        kind: "ck.morph.update",
        payload: {
          morph_id: morphId,
          target_ref: morphId,
          patch: {
            fields: {
              $op: "set",
              value: { document: updatedBody },
            },
          },
        },
      }),
      { context: "update document morph body" },
    );

    const projection = await readDocumentProjection(request, token, morphId);
    expect(projection.document.morph_id).toBe(morphId);
    expect(projection.document.realm_id).toBe(realmId);
    expect(projection.document.morph_type).toBe("document");
    expect(projection.document.body.blocks[0].content).toBe("abc");
    expect(projection.versions).toHaveLength(2);
    expect(projection.versions[0].body.blocks[0].content).toBe("abcdefghij");
    expect(projection.versions[1].body.blocks[0].content).toBe("abc");
    expect(projection.relations).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          relation_id: relationId,
          relation_kind: "references",
          from: morphId,
          to: realmId,
        }),
      ]),
    );
    expect(projection.comments).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          body: "tighten this range",
          state: "orphaned",
          anchor_range: expect.objectContaining({ start: 2, end: 9 }),
        }),
      ]),
    );
    expect(projection.cursor_presence).toEqual([]);
  });

  test("yougen creates and hydrates Document Morphs with versions, range comments, and cursor presence UI", async ({
    browser,
    request,
  }, testInfo) => {
    // spec: morph.md §2 + strand-and-message.md §4.3 + profiles-presence.md §3.
    const stamp = Date.now();
    const alice = uniqueUser("doc-ui-alice");
    const bob = uniqueUser("doc-ui-bob");
    await ensureRegistered(request, alice);
    await ensureRegistered(request, bob);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);
    const alicePage = await openUserPage(browser, alice, { sessionCredential: aliceToken });
    const bobPage = await openUserPage(browser, bob, { sessionCredential: bobToken });

    try {
      const realmId = await alicePage.createRealm({
        title: `Document UI ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        seedMembers: [bob.did],
      });
      await bobPage.acceptInvite(realmId);

      await alicePage.page.goto("/document/new", { waitUntil: "domcontentloaded" });
      await expect(alicePage.page.getByTestId("document-panel")).toBeVisible({
        timeout: 120_000,
      });
      const title = `Design doc ${stamp}`;
      await alicePage.page.getByTestId("document-title-input").fill(title);
      await alicePage.page
        .getByTestId("document-body-editor")
        .fill("Goals first section with detail for a range comment.");
      await alicePage.page.getByTestId("document-link-incident-input").fill(realmId);
      await alicePage.page.getByTestId("save-document-button").click();
      await expect(alicePage.page.getByTestId("document-status")).toContainText(
        /document ck:morph:/i,
        { timeout: 45_000 },
      );
      const morphId = await waitForDocumentMorphId(request, aliceToken, realmId, title);

      await bobPage.page.goto(`/document/${morphId}`, { waitUntil: "domcontentloaded" });
      await expect(bobPage.page.getByTestId("document-panel")).toBeVisible({
        timeout: 120_000,
      });
      await expect(bobPage.page.getByTestId("document-body-editor")).toHaveValue(
        "Goals first section with detail for a range comment.",
        { timeout: 45_000 },
      );
      await expect(bobPage.page.getByTestId("document-cursor-self")).toBeVisible();
      await expect(
        bobPage.page.getByTestId("document-presence-list").locator("li").first(),
      ).toHaveAttribute("title", bob.did);

      await bobPage.page.getByTestId("document-comment-add-button").click();
      await bobPage.page.getByTestId("document-comment-range-input").fill("6..40");
      await bobPage.page.getByTestId("document-comment-text-input").fill("needs more evidence");
      await bobPage.page.getByTestId("document-comment-submit-button").click();
      await expect(bobPage.page.getByTestId("document-comment-thread")).toContainText(
        "needs more evidence",
        { timeout: 45_000 },
      );
      await waitForDocumentComment(request, bobToken, morphId, "needs more evidence");

      await alicePage.page.getByTestId("document-body-editor").fill("Short.");
      await alicePage.page.getByTestId("save-document-button").click();
      await expect(alicePage.page.getByTestId("document-status")).toContainText(
        /saved and synced document/i,
        { timeout: 45_000 },
      );

      await alicePage.page.goto(`/document/${morphId}`, { waitUntil: "domcontentloaded" });
      await expect(alicePage.page.getByTestId("document-body-editor")).toHaveValue("Short.", {
        timeout: 45_000,
      });
      await expect(alicePage.page.getByTestId("document-version-row")).toHaveCount(2, {
        timeout: 45_000,
      });
      await expect(alicePage.page.getByTestId("document-comment-thread")).toContainText(
        "needs more evidence",
        { timeout: 45_000 },
      );
      await expect(alicePage.page.getByTestId("document-comment-orphan-badge")).toBeVisible();
      await alicePage.page.getByTestId("document-version-restore-button").first().click();
      await expect(alicePage.page.getByTestId("document-version-restore-status")).toContainText(
        /restored|already at/i,
      );
      await stepShot(alicePage.page, testInfo, "document-morph-projection-ui");
    } finally {
      await alicePage.close();
      await bobPage.close();
    }
  });
});

function documentMorphId(): string {
  return typedId("operation").replace("ck:operation:", "ck:morph:");
}

function documentRelationId(): string {
  return typedId("operation").replace("ck:operation:", "ck:relation:");
}

function paragraphDocumentBody(body: string) {
  return {
    schema_version: 1,
    blocks: [{ id: "body", kind: "Paragraph", content: body }],
  };
}

async function readDocumentProjection(request: APIRequestContext, token: string, morphId: string) {
  const response = await request.get(
    `${solandBaseUrl()}/_cokret/self/projection/documents/${encodeURIComponent(morphId)}`,
    { headers: authHeaders(token) },
  );
  const text = await response.text();
  expect(response.ok(), `read document projection returned ${response.status()}: ${text}`).toBeTruthy();
  return JSON.parse(text);
}

async function waitForDocumentMorphId(
  request: APIRequestContext,
  token: string,
  realmId: string,
  title: string,
): Promise<string> {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const response = await request.get(
      `${solandBaseUrl()}/_cokret/self/projection/morphs?realm_id=${encodeURIComponent(realmId)}`,
      { headers: authHeaders(token) },
    );
    if (response.ok()) {
      const body = await response.json();
      const match = (body.morphs ?? []).find(
        (morph: Record<string, unknown>) =>
          morph.morph_type === "document" && morph.title === title && typeof morph.morph_id === "string",
      );
      if (match?.morph_id) {
        return String(match.morph_id);
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  throw new Error(`document morph with title ${title} not projected in ${realmId}`);
}

async function waitForDocumentComment(
  request: APIRequestContext,
  token: string,
  morphId: string,
  body: string,
) {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const projection = await readDocumentProjection(request, token, morphId);
    if ((projection.comments ?? []).some((comment: Record<string, unknown>) => comment.body === body)) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  throw new Error(`document comment ${body} not projected for ${morphId}`);
}

function nowIso(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}
