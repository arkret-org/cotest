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
      history_visibility: "joined",
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

    await expect(
      createRealmApi(request, token, {
        title: "MLS incompatible visibility",
        ownerDid: alice.did,
        history_visibility: "world_readable",
        encryption_profile: "mls_rfc9420",
      }),
    ).rejects.toThrow("history_visibility_requires_history_capable_scheme");
  });
});
