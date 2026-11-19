# Joint E2E test-machine environment

## Running joint-full on two test machines

Use two independent three-Station machines with the same frozen sources,
checkout layout and Cargo configuration. Each machine owns its databases,
services and a single Playwright worker. From the Cotest repository on the
first machine, create one plan in a fresh artifact directory.

```powershell
New-Item -ItemType Directory -Force artifacts/full-pair | Out-Null
python scripts/joint_full_shards.py plan --output artifacts/full-pair/plan.json --history PATH/TO/previous/junit.xml
```

The optional history weights files by measured case durations. Without it,
case counts determine the allocation. Copy the same plan to the second
machine. On each machine run the usual three-Station joint-full command with
all its normal service, topology and acceptance arguments. Add
`-JointFullShardPlan artifacts/full-pair/plan.json -JointFullShard 1 -JointDir artifacts/full-pair/part1`
on the first machine and the corresponding `2` and `part2` on the second.
Use a fresh output directory for each invocation. Both runners re-collect the
unfiltered Chrome suite; each executes entire assigned files and the real
Inkson build-id setup. Shard 1 also runs the full native API catalog. The
shard owning the P0 file enforces the mandatory P0 gate. Both execute local
service, cleanup, source and artifact checks.

Bring both run directories together and run the coverage check.

```powershell
python scripts/joint_full_shards.py merge artifacts/full-pair/plan.json artifacts/full-pair/part1 artifacts/full-pair/part2
```

The merge checks both original runner verdicts, frozen source identities,
setup, native coverage and the exact JUnit business case assignment. A single
shard reports its profile as `joint-full-shard`.

## Local topology

The supported production-shaped local topology uses runner-owned processes, independent PostgreSQL stores, a run-scoped CA, and Caddy on loopback. Plain HTTP is diagnostic-only and is not an acceptance topology.

If the system proxy intercepts the managed loopback names, set
`$env:COTEST_BROWSER_NO_PROXY = '1'` in the shell launching the joint run.
The test browser connects directly and checks the pinned TLS certificate.
Use this option for stacks whose browser endpoints are reachable directly.

The default `.localhost` suffix gives each Station and Coauth instance a distinct
DNS name. HTTP and WebSocket use the same Station hostname and TLS port.
If every service name and the unregistered probe already resolve exclusively
to loopback, the runner uses native DNS. Otherwise it installs exact loopback
entries for the run, verifies their resolution and removes its marker on exit.
The legacy `-DnsSuffix arkret_local` option uses managed hosts entries. Its
underscore prevents Coland from advertising the protocol's WebSocket binding.

On Windows with a manually configured proxy, the runner passes the proxy map
and its existing exemptions to Playwright's Chromium processes. It adds each
run-owned loopback name, including the unregistered probe, to those exemptions
so browser discovery reaches Caddy. With a PAC file, the PAC must route these
names to loopback directly.

Platform package auto-installation is currently implemented for Windows. On
macOS and Linux, already installed prerequisites are verified and accepted;
missing prerequisites still fail the initializer with their exact names.

## One entry and administrator initialization

The only test entry is `scripts/run-joint-e2e.ps1`. It always invokes the environment initializer before preparation or service startup:

```powershell
pwsh -NoProfile -File scripts/run-joint-e2e.ps1 -RunProfile joint-smoke -ServerCount 1 -StartCoauth
pwsh -NoProfile -File scripts/run-joint-e2e.ps1 -RunProfile joint-full -ServerCount 1 -StartCoauth
pwsh -NoProfile -File scripts/run-joint-e2e.ps1 -RunProfile joint-full -ServerCount 3 -StartCoauth
pwsh -NoProfile -File scripts/run-joint-e2e.ps1 -RunProfile joint-api -ServerCount 1 -StartCoauth
```

`joint-api` is the browserless Garth lane. It selects the closed API-only
manifest, forces the Garth client journey, and neither builds nor starts
Inkson. Passing `-ClientKind inkson` or any Inkson-specific argument with this
profile fails before preparation.

Every invocation attempts to install missing packages, local npm dependencies, and required Docker images. Browser profiles also install Playwright Chromium; `joint-api` does not need or check the browser payload. Most of these operations can succeed as a standard user. If an installation command is denied or otherwise fails, the run stops before preparation and tells the user to retry from an elevated PowerShell. Hosts ACL initialization is the only operation that is deliberately never attempted without administrator rights:

```powershell
pwsh -NoProfile -File scripts/initialize-joint-e2e-environment.ps1 -ServerCount 3 -StartCoauth -RequireDocker -TestUser "DOMAIN\developer"
```

In an elevated Windows shell, the same flow additionally initializes the exact developer account's hosts access. The hosts initializer backs up the hosts bytes and ACL, grants only that account `Modify`, proves a marked append/remove cycle, and records recovery state under `%ProgramData%\cotest\joint-e2e-hosts`.

The restore script is never called by the entry or initializer. It is an explicit manual operation from an elevated shell:

```powershell
pwsh -NoProfile -File scripts/restore-joint-e2e-hosts.ps1
```

The rollback verifies the backup SHA-256, removes only `cotest-joint-e2e:<run-id>` blocks from the current hosts content, preserves every other line, and restores the saved ACL. The runner still removes its own run-scoped hosts block in `finally`; that normal per-run cleanup is not an ACL restore. macOS and Linux currently support detection and local dependency installation, but automatic platform-package and hosts initialization are currently implemented only for Windows.

## Prerequisites

The initializer records the OS, architecture, PowerShell, `PATH`, package managers, absolute tool paths, and versions. Required tools are Node.js/npm/npx, the local Playwright package and Chromium, OpenSSL, Rust/cargo, Caddy `>=2.8,<3`, and Docker when runner-owned PostgreSQL is requested. Runner-owned databases use the reproducible `postgres:18.6-alpine` image. A local checkout/build also needs the Coland, Coauth, Inkson and cotest-wire artifacts described by the runner.

Caddy must include the standard TLS and reverse-proxy modules. The report records its absolute path, version output, SHA-256, module result, and inferred source. On Windows every invocation first runs an exact `winget search` and installs only the package ID returned by that search; it never guesses a Caddy package ID. Chocolatey and Scoop remain supported fallbacks and are recorded as community-maintained. If the package manager requires elevation, the failed command is reported and the user is told to retry elevated.

## Hosts and TLS contract

For `-ServerCount N`, the runner temporarily adds only these names to the actual platform hosts file, all at `127.0.0.1`:

- `coland-server1.localhost` through `coland-serverN.localhost`;
- `coauth-server1.localhost` through `coauth-serverN.localhost` when independent Coauth authorities are enabled;
- `unregistered.localhost` as a negative probe.

The first two groups are Caddy sites using the run-scoped certificate. `unregistered.localhost` resolves to the same loopback Caddy listener but has no site; successful application traffic on it is a failure. The gate also checks the generated CA, certificate SANs, served leaf, SPKI pin, service DID history URL, HTTP downgrade, wrong CA/SPKI, and wrong-server identity paths. The CA is passed only to the managed process tree and is never imported into a user or machine root store.

Each run holds a machine-local exclusive lock. Its marker names the exact run, and `finally` removes only that block. Initialization reports stale markers and the exact manual restore command; neither the entry nor initializer invokes restore automatically.

## Three-server budget

Three-server acceptance starts three Coland processes or containers, three independent service identity/state/object roots, three Coland PostgreSQL instances, and—when `-StartCoauth` is used—three Coauth processes and three more PostgreSQL instances. Caddy adds one listener and six virtual sites. Inkson may be shared as a static client origin because it is not a server identity.

Reserve at least 8 GiB of available RAM, 4 CPU cores, 10 GiB of free disk, 13 free loopback TCP ports plus metrics/mock ports, and capacity for six PostgreSQL containers. The preflight prints the calculated host, port, and database count before startup. `topology.json` is the authoritative machine-readable inventory of public URLs, listeners, service identities, storage, peers, process/container IDs, and the runner-owned fault-control state used by recovery tests.

## Reports and cleanup

The initializer writes under the run’s `environment/` directory, even when it blocks startup. A run that reaches report finalization writes `summary.md`, `summary.json`, `topology.json`, `junit.xml`, the Playwright HTML report and output directory, per-service logs, `scenarios.md`, TLS evidence, managed-service failures, PostgreSQL dumps, and the secret scan under one absolute run directory. Normal completion, test failure, and Ctrl+C all pass through the same cleanup block unless `-KeepServices` is explicitly selected for debugging.

Temporary native tools, the served Inkson bundle and Savfox working directories are removed during normal teardown. Build receipts remain in `build-evidence/`; `latest/joint-e2e/` keeps only summaries and a pointer to the authoritative run.
