# Joint E2E test-machine environment

The supported production-shaped local topology uses runner-owned processes, independent PostgreSQL stores, a run-scoped CA, and Caddy on loopback. Plain HTTP is diagnostic-only and is not an acceptance topology.

## One entry and administrator initialization

The only test entry is `scripts/run-joint-e2e.ps1`. It always invokes the environment initializer before preparation or service startup:

```powershell
pwsh -NoProfile -File scripts/run-joint-e2e.ps1 -RunProfile joint-smoke -ServerCount 1 -StartCoauth
pwsh -NoProfile -File scripts/run-joint-e2e.ps1 -RunProfile joint-full -ServerCount 1 -StartCoauth
pwsh -NoProfile -File scripts/run-joint-e2e.ps1 -RunProfile joint-full -ServerCount 3 -StartCoauth
```

Every invocation attempts to install missing packages, local npm dependencies, Playwright Chromium, and required Docker images. Most of these operations can succeed as a standard user. If an installation command is denied or otherwise fails, the run stops before preparation and tells the user to retry from an elevated PowerShell. Hosts ACL initialization is the only operation that is deliberately never attempted without administrator rights:

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

The initializer records the OS, architecture, PowerShell, `PATH`, package managers, absolute tool paths, and versions. Required tools are Node.js/npm/npx, the local Playwright package and Chromium, OpenSSL, Rust/cargo, Caddy `>=2.8,<3`, and Docker when runner-owned PostgreSQL is requested. Runner-owned databases use the reproducible `postgres:18.6-alpine` image. A local checkout/build also needs the Soland, Coauth, Inkson and cotest-wire artifacts described by the runner.

Caddy must include the standard TLS and reverse-proxy modules. The report records its absolute path, version output, SHA-256, module result, and inferred source. On Windows every invocation first runs an exact `winget search` and installs only the package ID returned by that search; it never guesses a Caddy package ID. Chocolatey and Scoop remain supported fallbacks and are recorded as community-maintained. If the package manager requires elevation, the failed command is reported and the user is told to retry elevated.

## Hosts and TLS contract

For `-ServerCount N`, the runner temporarily adds only these names to the actual platform hosts file, all at `127.0.0.1`:

- `soland-server1.local.host` through `soland-serverN.local.host`;
- `coauth-server1.local.host` through `coauth-serverN.local.host` when independent Coauth authorities are enabled;
- `unregistered.local.host` as a negative probe.

The first two groups are Caddy sites using the run-scoped certificate. `unregistered.local.host` resolves to the same loopback Caddy listener but has no site; successful application traffic on it is a failure. The gate also checks the generated CA, certificate SANs, served leaf, SPKI pin, service DID history URL, HTTP downgrade, wrong CA/SPKI, and wrong-server identity paths. The CA is passed only to the managed process tree and is never imported into a user or machine root store.

Each run holds a machine-local exclusive lock. Its marker names the exact run, and `finally` removes only that block. Initialization reports stale markers and the exact manual restore command; neither the entry nor initializer invokes restore automatically.

## Three-server budget

Three-server acceptance starts three Soland processes or containers, three independent service identity/state/object roots, three Soland PostgreSQL instances, and—when `-StartCoauth` is used—three Coauth processes and three more PostgreSQL instances. Caddy adds one listener and six virtual sites. Inkson may be shared as a static client origin because it is not a server identity.

Reserve at least 8 GiB of available RAM, 4 CPU cores, 10 GiB of free disk, 13 free loopback TCP ports plus metrics/mock ports, and capacity for six PostgreSQL containers. The preflight prints the calculated host, port, and database count before startup. `topology.json` is the authoritative machine-readable inventory of public URLs, listeners, service identities, storage, peers, process/container IDs, and the runner-owned fault-control state used by recovery tests.

## Reports and cleanup

Every run writes `summary.md`, `summary.json`, `topology.json`, `junit.xml`, the Playwright HTML report and output directory, per-service logs, `scenarios.md`, TLS evidence, managed-service failures, PostgreSQL dumps, and the secret scan under one absolute run directory. Normal completion, test failure, and Ctrl+C all pass through the same cleanup block unless `-KeepServices` is explicitly selected for debugging.
