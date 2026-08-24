import { expect, test } from "@playwright/test";

import { solandBaseUrl } from "../../helpers/env";
import { authHeaders, createRealmApi } from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";

test.describe("MLS group encryption", () => {
  test("an encrypted Realm stays create-locked and exports no plaintext downgrade", async ({
    request,
  }) => {
    const alice = uniqueUser(`mls-create-${Date.now()}`);
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);
    const realmId = await createRealmApi(request, token, {
      title: "MLS create-lock smoke",
      ownerDid: alice.did,
      history_access: "since_join",
      encryption_profile: "mls_rfc9420",
    });

    const exported = await request.get(
      `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}/export`,
      { headers: authHeaders(token) },
    );
    expect(exported.ok()).toBe(true);
    const body = JSON.stringify(await exported.json());
    expect(body).toContain('"encryption_profile":"mls_rfc9420"');
    expect(body).not.toContain('"encryption_profile":"plaintext"');
    // `content_scheme` is fixed only by an accepted `ak.mls.genesis`, never
    // inferred from the Realm encryption mechanism or smuggled through the
    // mutable policy bundle. This Realm has not created its group yet.
    expect(body).not.toContain('"content_scheme"');
  });
});
