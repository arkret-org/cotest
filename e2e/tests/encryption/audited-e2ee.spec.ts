// Ordinary moderation reports on MLS-encrypted content.
// Contract: e2e/scenarios/encryption/audited-e2ee.md
// Spec: governance/content-moderation.md §3.1, §3.3, §3.4, §3.4.1;
// crypto-media/encryption-and-audit.md §2.4.1, §2.5.2, §2.6; authz/capabilities.md §5.5

import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import { solandBaseUrl, solandServiceId } from "../../helpers/env";
import { acceptInviteViaApi } from "../../helpers/api";
import {
  accountActorId,
  authHeaders,
  canonicalJson,
  canonicalTimestamp,
  createRealmApi,
  grantCapabilityEventApi,
  scanRealmStreamApi,
  signedEventEnvelope,
  submitSignedEventApi,
} from "../../helpers/soland-api";
import {
  addRealmMlsMemberApi,
  encryptMlsMessageContent,
  joinRealmMlsWelcomeApi,
  type MlsDevice,
} from "../../helpers/soland-api/mls";
import {
  allowExplicitInviteNotifications,
  ensureRegistered,
  issueUserSession,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("moderation reports and audited E2EE", () => {
  test("ordinary reports stay in the scoped moderation workflow and never create audit-release events", async ({
    request,
  }) => {
    const setup = await setupEncryptedMessage(request, "s25-report");
    // Receiving-service proof publication is asynchronous and independent of
    // the report (content-moderation.md section 3.4). Put its accepted Commit
    // in the baseline so the report's exact-one-write assertion stays strict.
    await expect.poll(async () => {
      const scan = await scanRealmStreamApi(request, setup.aliceToken, setup.realmId);
      expect(scan.truncated).toBe(false);
      return scan.events.some((event) =>
        event?.kind === "ak.moderation.franking_proof"
        && (event.payload as Record<string, unknown>)?.event_id === setup.message.event_id,
      );
    }, { timeout: 30_000 }).toBe(true);
    const before = await scanRealmStreamApi(
      request,
      setup.aliceToken,
      setup.realmId,
    );
    expect(before.truncated).toBe(false);
    const report = await fileModerationReport(request, setup);

    expect(report.status).toBe("submitted");
    expect(report.routed_to).toBeUndefined();

    const after = await scanRealmStreamApi(
      request,
      setup.aliceToken,
      setup.realmId,
    );
    expect(after.truncated).toBe(false);
    // Keep proof-bearing Commit objects out of assertion telemetry.
    expect(
      canonicalJson(after.commits.slice(0, before.commits.length)) === canonicalJson(before.commits),
      "the complete pre-report Commit prefix remains byte-identical",
    ).toBe(true);
    const accepted = after.commits.slice(before.commits.length);
    const reportEventId = report.report_id.replace("ak:report:", "ak:event:");
    expect(
      accepted.length,
      "the ordinary report commits exactly one Event and no audit-release Event",
    ).toBe(1);
    expect(accepted[0].event_ref).toBe(reportEventId);
    const reportEvent = after.events[before.commits.length];
    expect(reportEvent?.event_id).toBe(reportEventId);
    expect(reportEvent?.kind).toBe("ak.self.moderation.report");
    expect(reportEvent?.payload).toMatchObject({
      target_ref: setup.message.event_id,
      reporter_id: setup.reporterId,
    });

    // The complete post-report suffix contains only that covering Commit;
    // even a withheld audit Event would add a slot and fail this assertion.
    expect(
      after.events.filter((event) => event?.kind === "ak.audit.accessed").length,
      "ak.audit.accessed must not be derived from a moderation report",
    ).toBe(0);
  });
});

type EncryptedMessageSetup = {
  aliceToken: string;
  reporterToken: string;
  reporterId: string;
  realmId: string;
  message: Record<string, unknown>;
};

async function setupEncryptedMessage(
  request: APIRequestContext,
  label: string,
): Promise<EncryptedMessageSetup> {
  const alice = uniqueUser(`${label}-alice`);
  const bob = uniqueUser(`${label}-bob`);
  const reporter = uniqueUser(`${label}-reporter`);
  await Promise.all([
    ensureRegistered(request, alice),
    ensureRegistered(request, bob),
    ensureRegistered(request, reporter),
  ]);
  const [aliceToken, bobToken, reporterToken] = await Promise.all([
    issueUserSession(request, alice),
    issueUserSession(request, bob),
    issueUserSession(request, reporter),
  ]);
  await Promise.all([
    allowExplicitInviteNotifications(request, bobToken),
    allowExplicitInviteNotifications(request, reporterToken),
  ]);

  // The Realm is end-to-end encrypted exactly because alice's `ak.mls.genesis`
  // is accepted before any invite (encryption-and-audit.md §2.5).
  const realmId = await createRealmApi(request, aliceToken, {
    title: `S25 moderation report ${label} ${Date.now()}`,
    discoverability: "listed",
    history_access: "since_join",
    mls_activated: true,
    ownerId: alice.id,
    invitees: [bob.id, reporter.id],
    invitee_ids: {
      [bob.id]: solandServiceId(),
      [reporter.id]: solandServiceId(),
    },
  });
  await acceptInviteViaApi(request, bobToken, bob.id, realmId);
  await acceptInviteViaApi(request, reporterToken, reporter.id, realmId);
  await grantCapabilityEventApi(request, aliceToken, {
    ownerId: alice.id,
    realmId,
    subjectId: bob.id,
    actions: ["ak.message.create"],
  });

  const strandCreatedAt = canonicalTimestamp();
  const strandEvent = signedEventEnvelope({
    actorId: alice.id,
    realmId,
    kind: "ak.strand.create",
    createdAt: strandCreatedAt,
    payload: {
      object: {
        schema: "ak.schema.strand.v1",
        realm_id: realmId,
        tracks: {
          discussion: {
            enabled: true,
            is_primary: true,
            profile: "discussion",
          },
        },
        created_by: accountActorId(alice.id),
        created_at: strandCreatedAt,
      },
    },
  });
  const strandId = String(strandEvent.event_id).replace(
    /^ak:event:/,
    "ak:strand:",
  );
  await submitSignedEventApi(request, aliceToken, strandEvent, {
    context: "create encrypted moderation Strand",
  });

  // Both joins advanced the key-access revision (§2.4.1); new ciphertext is
  // refused with `epoch_update_required` until Add Commits cover it. bob is
  // added last so he joins from his Welcome at the current epoch.
  const reporterDevice: MlsDevice = {
    id: reporter.id,
    deviceId: reporter.deviceId,
    token: reporterToken,
  };
  const bobDevice: MlsDevice = {
    id: bob.id,
    deviceId: bob.deviceId,
    token: bobToken,
  };
  await addRealmMlsMemberApi(request, realmId, reporterDevice);
  const bobAdd = await addRealmMlsMemberApi(request, realmId, bobDevice);
  const bobGroup = await joinRealmMlsWelcomeApi(request, realmId, bobDevice);
  expect(bobGroup.epoch).toBe(2);
  expect(bobGroup.groupStateRef).toBe(bobAdd.commitEventId);

  const message = signedEventEnvelope({
    actorId: bob.id,
    realmId,
    kind: "ak.message.create",
    payload: {
      strand_id: strandId,
      track_name: "discussion",
      encrypted_content: encryptMlsMessageContent(bobGroup, {
        kind: "ak.content.text",
        body: `S25 reported message ${label} ${Date.now()}`,
        format: "plain",
      }),
    },
  });
  await submitSignedEventApi(request, bobToken, message, {
    context: "submit MLS-encrypted message at the covering epoch",
  });

  return {
    aliceToken,
    reporterToken,
    reporterId: reporter.id,
    realmId,
    message,
  };
}
/// content-moderation.md §3.1: the closed `{report_event}` body carries only
/// the reporter's own signed Event. An ordinary report on E2EE content has no
/// franking proof: the reporter can read only the minimized, non-verifiable
/// projection of a proof (§3.4), which must not be resubmitted.
async function fileModerationReport(
  request: APIRequestContext,
  setup: EncryptedMessageSetup,
) {
  const reportEvent = signedEventEnvelope({
    actorId: setup.reporterId,
    realmId: setup.realmId,
    kind: "ak.self.moderation.report",
    payload: {
      realm_id: setup.realmId,
      target_ref: setup.message.event_id,
      report_reason_code: "harassment",
      reporter_id: setup.reporterId,
      provenance: "self",
      description: "ordinary moderation report for scoped administrators",
      evidence_refs: [],
    },
  });
  const url = `${solandBaseUrl()}/_arkret/self/moderation/report`;
  const response = await request.post(url, {
    headers: {
      ...authHeaders(setup.reporterToken, "POST", url),
      "content-type": "application/json",
    },
    data: canonicalJson({ report_event: { event: reportEvent } }),
  });
  const text = await response.text();
  expect(response.ok(), text).toBeTruthy();
  return JSON.parse(text) as {
    report_id: string;
    status: string;
    routed_to?: string[];
  };
}
