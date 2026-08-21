# Agent Journeys

Agent Journeys are goal-driven acceptance audits. A browser agent receives a
business story and checkpoint outcomes, but it does not receive a prerecorded
selector sequence. The agent must interpret the visible UI, choose its own
actions, and retain evidence for every checkpoint.

This layer complements `e2e/tests/**/*.spec.ts`:

- Playwright specs are deterministic regression gates.
- Agent Journeys discover semantic, navigation, recovery, and multi-user UX
  failures.
- A repeatable product defect found here must be converted into a deterministic
  Playwright regression.

## Scenario catalog

| Scenario | Topology | Primary story |
|---|---|---|
| `first-realm-continuity` | single | First registration, ordinary Realm bootstrap, messages, offline retry, reload, and sign-in continuity |
| `device-pairing-revocation-recovery` | single | Pair a second device, restore history, revoke it, recover on a fresh device, and fence old devices |
| `invite-history-bootstrap` | federated | Private cross-server invitation, MLS readiness, joined-history cutoff, catch-up, and privacy |
| `federated-team-incident` | federated | Broad multi-user onboarding, incident collaboration, interruption, and authorization boundaries |

The flow-to-scenario map and explicit harness/product gaps are recorded in
[`docs/agent-journey-coverage.md`](../docs/agent-journey-coverage.md).

Validate the full catalog without starting services:

```powershell
node .\agent-journeys\scripts\journey.mjs validate-scenarios `
  --scenario-dir .\agent-journeys\scenarios

node --test .\agent-journeys\scripts\journey.tests.mjs
```

The same Node test is part of `scripts/run-hygiene.ps1`; use
`-SkipAgentJourneyTests` only when deliberately narrowing a local hygiene run.

## Safety and evidence rules

Actor actions must use the visible Inkson UI. Direct Soland or Coauth API calls
may be used only by an independent read-only oracle after the UI action; they
must not bootstrap or mutate the story on the actor's behalf.

The browser agent must use
`scripts/invoke-agent-browser.ps1`. The wrapper gives every actor a distinct
agent-browser session plus a persistent Chrome profile under
`profiles/<actor>/`, and appends every command and result to `actions.ndjson`.
Use `-Sensitive` for password, verification-code, recovery-key, or token input
so the value is redacted from the transcript.

Every required checkpoint needs:

- one explicit outcome classification;
- at least one hard check;
- one screenshot;
- attempt count and concise observations;
- any UX friction encountered.

Allowed outcome classes are `PASS`, `PRODUCT_FAIL`, `AGENT_FAIL`,
`HARNESS_FAIL`, and `INCONCLUSIVE`. Product, agent, and harness failures are
kept distinct so a model navigation error is not reported as an Arkret defect.

## Topologies

`single` starts one Soland and one Inkson origin.

`federated` starts two isolated principal servers on the same physical machine:

- distinct Soland processes or containers;
- distinct ports and public base URLs;
- distinct service DIDs and signing keys;
- distinct keystore/state and object-storage roots;
- distinct Inkson origins;
- explicit peer links between alpha and beta.

The current joint harness uses one shared external Coauth authority for both
principal servers. The runtime manifest reports this as
`account_authority_mode = shared-external-authority`; sharing the external
account authority does not share principal-server state.

Use Docker runtime when process isolation is insufficient:

```powershell
.\scripts\run-agent-journey.ps1 `
  -Action Prepare `
  -Scenario federated-team-incident `
  -Topology federated `
  -SolandRuntime docker
```

## Agent workflow

Prepare the stack:

```powershell
$run = .\scripts\run-agent-journey.ps1 `
  -Action Prepare `
  -Scenario federated-team-incident `
  -Topology federated
```

Read `$run.runtime_manifest`, then operate each actor:

```powershell
.\agent-journeys\scripts\invoke-agent-browser.ps1 `
  -RunDir $run.run_dir `
  -Actor alice `
  -BrowserArgs @("open", "http://127.0.0.1:4527")

.\agent-journeys\scripts\invoke-agent-browser.ps1 `
  -RunDir $run.run_dir `
  -Actor alice `
  -BrowserArgs @("snapshot", "-i")
```

Record a checkpoint after taking its screenshot:

```powershell
node .\agent-journeys\scripts\journey.mjs checkpoint `
  --run-dir $run.run_dir `
  --id J02 `
  --actor alice `
  --status PASS `
  --screenshot screenshots/J02-alice-registered.png `
  --hard-check "signed-in-user-visible=PASS" `
  --attempts 1 `
  --note "Alice reached the authenticated home page without hidden setup."
```

Finalize only after all required checkpoints have evidence:

```powershell
.\scripts\run-agent-journey.ps1 -Action Finalize -RunDir $run.run_dir
```

Finalization closes browser sessions, validates the result, releases the
managed service stack, and writes `summary.md`.
