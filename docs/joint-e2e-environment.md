# Joint E2E test-machine environment

The supported production-shaped local topology uses runner-owned processes, independent PostgreSQL stores, a run-scoped CA, and Caddy on loopback. Plain HTTP is diagnostic-only and is not an acceptance topology.

## One-time and per-run commands

On Windows, an administrator performs the auditable one-time initialization for the exact developer account:

```powershell
pwsh -NoProfile -File scripts/setup-joint-e2e-hosts.ps1 -ServerCount 3 -TestUser "DOMAIN\developer"
```

The script backs up the hosts bytes and ACL, grants only that account `Modify`, proves a marked append/remove cycle, and records recovery state under `%ProgramData%\cotest\joint-e2e-hosts`. It does not install software or leave host entries behind. Run it twice to verify the idempotent no-op. Roll back with an elevated shell:

```powershell
pwsh -NoProfile -File scripts/restore-joint-e2e-hosts.ps1
```

The rollback verifies the backup SHA-256, removes only `cotest-joint-e2e:<run-id>` blocks from the current hosts content, preserves every other line, and restores the saved ACL. macOS and Linux currently support read-only detection only; the preflight reports privileged setup as unsupported instead of suggesting Windows commands.

Developers then run one command:

```powershell
pwsh -NoProfile -File scripts/run-joint-e2e-ready.ps1 -RunProfile joint-smoke -ServerCount 1 -StartCoauth
pwsh -NoProfile -File scripts/run-joint-e2e-ready.ps1 -RunProfile joint-full -ServerCount 1 -StartCoauth
pwsh -NoProfile -File scripts/run-joint-e2e-ready.ps1 -RunProfile joint-full -ServerCount 3 -StartCoauth
```

The ready entry point runs the read-only preflight first and refuses to start services if it fails. It does not accept `-SkipPreflight` or the deprecated two-server switch.

## Prerequisites

The preflight records the OS, architecture, PowerShell, `PATH`, package managers, absolute tool paths, and versions. Required tools are Node.js/npm/npx, the local Playwright package and Chromium, OpenSSL, Rust/cargo, Caddy `>=2.8,<3`, and Docker when runner-owned PostgreSQL is requested. A local checkout/build also needs the Soland, Coauth, Inkson, cotest-wire, and PostgreSQL images described by the runner.

Caddy must include the standard TLS and reverse-proxy modules. The report records its absolute path, version output, SHA-256, module result, and inferred source. Caddy is never downloaded or installed by the preflight. Windows advice first runs an exact `winget search` so the current package ID is resolved rather than hard-coded; Chocolatey and Scoop are marked community-maintained. Homebrew is also community-maintained. Debian/Ubuntu advice points to Caddy's signed official APT repository, Fedora/RHEL to the official COPR/DNF instructions, and other systems to the signed/checksum-verified official release or container documentation.

## Hosts and TLS contract

For `-ServerCount N`, the runner temporarily adds only these names to the actual platform hosts file, all at `127.0.0.1`:

- `soland-server1.local.host` through `soland-serverN.local.host`;
- `coauth-server1.local.host` through `coauth-serverN.local.host` when independent Coauth authorities are enabled;
- `unregistered.local.host` as a negative probe.

The first two groups are Caddy sites using the run-scoped certificate. `unregistered.local.host` resolves to the same loopback Caddy listener but has no site; successful application traffic on it is a failure. The gate also checks the generated CA, certificate SANs, served leaf, SPKI pin, service DID history URL, HTTP downgrade, wrong CA/SPKI, and wrong-server identity paths. The CA is passed only to the managed process tree and is never imported into a user or machine root store.

Each run holds a machine-local exclusive lock. Its marker names the exact run, and `finally` removes only that block. A read-only preflight reports stale markers and the exact restore command; it never silently edits them.

## Three-server budget

Three-server acceptance starts three Soland processes or containers, three independent service identity/state/object roots, three Soland PostgreSQL instances, and—when `-StartCoauth` is used—three Coauth processes and three more PostgreSQL instances. Caddy adds one listener and six virtual sites. Inkson may be shared as a static client origin because it is not a server identity.

Reserve at least 8 GiB of available RAM, 4 CPU cores, 10 GiB of free disk, 13 free loopback TCP ports plus metrics/mock ports, and capacity for six PostgreSQL containers. The preflight prints the calculated host, port, and database count before startup. `topology.json` is the authoritative machine-readable inventory of public URLs, listeners, service identities, storage, peers, process/container IDs, and the runner-owned fault-control state used by recovery tests.

## Reports and cleanup

Every run writes `summary.md`, `summary.json`, `topology.json`, `junit.xml`, the Playwright HTML report and output directory, per-service logs, `scenarios.md`, TLS evidence, managed-service failures, PostgreSQL dumps, and the secret scan under one absolute run directory. Normal completion, test failure, and Ctrl+C all pass through the same cleanup block unless `-KeepServices` is explicitly selected for debugging.
