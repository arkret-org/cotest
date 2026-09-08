<#
.SYNOPSIS
    Drives a joint-services Playwright run for the cotest harness.

.DESCRIPTION
    Supports two run profiles via -RunProfile:

    joint-smoke (PR gate)
      - Runs only describe blocks tagged @fully-implemented.
      - Excludes retained executable fixme tests so the PR gate stays under
        ~5 min on the joint harness.
      - An explicit -Grep argument fully overrides the smoke inclusion filter.

    joint-full (nightly / on-demand)
      - Runs every regular joint spec discovered by Playwright. Provider-backed
        @platform-live tests remain in the protected controlled lane. The
        retained, fully attributed fixme tests exit as skipped via test.fixme().

    Both profiles share the same service-startup, preflight, and reporting
    code paths. Only the Playwright invocation step branches on the profile.

    Runner-owned process-mode services publish their public identity through a
    managed TLS reverse proxy (0530-C): the processes keep plain loopback
    listeners, while public base URLs, issuers and minted service DIDs use
    stable `https://<service>.local.host:<port>` names. Trust stays process-local:
    Node receives the run-scoped CA and Chromium receives the exact leaf SPKI
    pin; the current user's Root store is never modified. The exact host names
    are registered in the system hosts file for the duration of the run.
    Caller-owned URLs (-SolandBaseUrl / -CoauthBaseUrl /
    -SolandCommand / docker runtime) bypass this topology unchanged.
#>
[CmdletBinding()]
param(
    [string]$OutputRoot,
    # Exact directory that receives this run's joint outputs (junit.xml,
    # summary.json, playwright-report/, services/, ...). When set, the script
    # writes there directly and skips both the standalone `runs/joint-e2e/`
    # layout and the `latest/joint-e2e` mirror — used by run-server-conformance.ps1 to
    # embed joint results inside its own run directory without nesting a
    # second runs/latest tree.
    [string]$JointDir,
    # How many timestamped run directories to keep under <OutputRoot>/runs
    # (standalone runs only). 0 disables pruning.
    [int]$KeepRuns = 20,
    [string]$SutManifest,
    [string]$InksonRoot,
    [string]$SolandBaseUrl,
    [string]$InksonBaseUrl,
    [string]$InksonServer2BaseUrl,
    [string]$CoauthBaseUrl,
    # Required for caller-owned Coauth: the configured owning Station identity,
    # not an identity discovered from the private Account Authority endpoint.
    [string]$CoauthServiceId,
    [string]$SolandCommand,
    [string]$SolandBin,
    # Optional externally provisioned PostgreSQL store for one managed
    # process-mode Soland. Multi-server runs always use one isolated ephemeral
    # PostgreSQL instance per server.
    [string]$SolandDatabaseUrl,
    [string]$SolandPostgresImage = "postgres:18.6-alpine",
    [switch]$RequireDecisionRace,
    [ValidateSet("process", "docker")]
    [string]$SolandRuntime = "process",
    [string]$SolandImage = "cotest-soland:latest",
    [int]$SolandContainerPort = 8008,
    [switch]$BuildSolandImage,
    [string[]]$DockerCacheFrom = @(),
    [string]$DockerCacheTo,
    [switch]$DockerPull,
    [switch]$DockerNoCache,
    [string]$InksonCommand,
    [string]$InksonServer2Command,
    [string]$CoauthCommand,
    [string]$CoauthHealthUrl,
    [switch]$StartCoauth,
    # Start a second Coauth process with the same public origin, secrets, and
    # PostgreSQL database but a separate listener. Passkey E2E uses it to prove
    # that a ceremony started on one process can finish on another.
    [switch]$DualCoauth,
    [string]$CoauthBin,
    [string]$CoauthPostgresImage = "postgres:18.6-alpine",
    # Optional externally-provisioned Postgres DSN for coauth. When set, the
    # harness skips the docker-backed ephemeral Postgres entirely (useful when
    # Docker Desktop is unavailable and a local PostgreSQL serves instead).
    [string]$CoauthPostgresUrl,
    [switch]$StartTeabay,
    [string]$TeabayBin,
    [string]$TeabayBaseUrl,
    [string]$TeabayDatabaseUrl,
    [string]$TeabayServiceId = "did:webvh:z6mkfixture:teabay.joint-e2e.local",
    [switch]$StartSavfox,
    [string]$SavfoxRoot,
    [string]$SavfoxBin,
    [string]$SavfoxBaseUrl,
    [string]$SavfoxToken = "cotest-savfox-joint-e2e-token-0000000000000001",
    [string]$SolandNotarySigningKey = "OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk=",
    [string]$SolandKeyStoreMasterKey = "d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3c=",
    [string]$CoauthSessionGrantIntrospectionBearer = "joint-e2e-session-grant-introspection",
    [string]$CoauthEmbeddedWebvhRegistrationBearer = "joint-e2e-webvh-registration",
    # did:webvh degraded_no_witness window (identity-did.md §4.2.1). Compressed
    # for resolver and harness witness-health checks; production clamps any
    # value back to the protocol ceiling, so this can only tighten the window.
    [int]$WebvhDegradedNoWitnessMaxSecs = 30,
    # OAuth `client_id` soland advertises in `/_arkret/describe.auth_metadata.methods[].client_id`
    # (soland config `oidc_client_id`). MUST match a client registered at coauth; the joint
    # coauth config (coauth/config.dev.yaml) seeds the "Inkson Dev" client under this ULID.
    # Without it soland advertises no client_id and the browser OIDC bridge gets
    # `could not find client` from coauth's /authorize. See cotest oidc-login-chain.spec.ts.
    [string]$CoauthOAuthClientId = "01GFWR28C4KNE04WG3HKXB7C9R",
    [int]$StartupTimeoutSeconds = 900,
    [switch]$SkipBuild,
    [switch]$KeepServices,
    # Run `tests/canonical_client_live.rs` against this run's deployment.
    # Off by default: it builds the root package, which is the dependency graph
    # the browserless lane exists to skip.
    [switch]$RunHarnessClientCheck,
    # Run `tests/garth_client_live.rs`: Garth driven as a headless client over
    # its own durable store, against this run's Coauth and Soland. Same build
    # cost as above, and the only path that exercises Garth's client runtime
    # without a browser.
    [switch]$RunGarthClientCheck,
    # Which client the `TestClient` journeys run against. `inkson` drives the
    # product in a browser; `garth` drives Garth's own runtime through
    # `cotest-provision`. The two are not interchangeable and the value is
    # exported rather than defaulted per-spec, so a parity result always names
    # the client it measured.
    [ValidateSet("inkson", "garth")]
    [string]$ClientKind = "inkson",
    [switch]$PreflightOnly,
    [switch]$RunnerSelfTest,
    [ValidateRange(1, 32)]
    [int]$ServerCount = 1,
    [ValidateSet("full-mesh", "ordered-candidates")]
    [string]$NetworkShape = "full-mesh",
    [string]$SolandServer2NotarySigningKey = "ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg=",
    [string]$SolandServer2KeyStoreMasterKey = "ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmY=",
    [switch]$StartMockIdp,
    [switch]$StartMockEmail,
    [switch]$StartMockWitness,
    [switch]$StartMockPushGateway,
    [string]$MockPushGatewayIss,
    [switch]$StartMockAppletRegistry,
    [string]$MockAppletRegistryDid,
    [switch]$StartMockTspEndpoint,
    [string]$MockTspEndpointVid,
    [switch]$StartMockMimiFacade,
    [string]$MockMimiFacadeDid = "did:webvh:z6mkfixture:mimi-facade.joint-e2e.local",
    [switch]$StartMockClaimIssuer,
    [string]$MockClaimIssuerDid = "did:webvh:z6mkfixture:vc-issuer.joint-e2e.local",
    [switch]$StartMockChallengeProvider,
    [string]$MockChallengeProviderDid = "did:webvh:z6mkfixture:captcha.joint-e2e.local",
    [switch]$StartMockDidHost,
    [string]$MockDidHostAuthority = "did-host.joint-e2e.local",
    [string]$MockDidHostScid = "z6mkfixture",
    [string[]]$MockDidHostExtraDids = @(),
    [switch]$StartMocks,
    [string]$MockWitnessDid = "did:webvh:z6mkfixture:witness.joint-e2e.local",
    [string[]]$MockWitnessExtraDids = @(),
    [ValidateSet("joint-smoke", "joint-full", "joint-api")]
    [string]$RunProfile,
    [string]$PlaywrightProject = "chrome",
    [string]$Grep,
    # Comma-separated canonical scenario keys which must occur in junit.xml.
    # This turns a stale grep/project selector into a hard gate failure instead
    # of accepting a different matching test (or no test) as coverage.
    [string]$RequireScenario,
    # Dedicated release lanes use this when every selected live test is a hard
    # requirement. Ordinary broad joint runs may still contain attributed,
    # topology-dependent skips and therefore do not enable it by default.
    [switch]$ForbidSkippedTests
)

if ($StartMocks) {
    $StartMockIdp = $true
    $StartMockEmail = $true
    $StartMockWitness = $true
    $StartMockPushGateway = $true
    $StartMockAppletRegistry = $true
    $StartMockTspEndpoint = $true
    $StartMockMimiFacade = $true
    $StartMockClaimIssuer = $true
    $StartMockChallengeProvider = $true
    $StartMockDidHost = $true
}

$MockDidHostExtraDids = @(
    $MockDidHostExtraDids |
        ForEach-Object { $_ -split "," } |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ }
)
if ($MockDidHostExtraDids.Count -gt 0) {
    $StartMockDidHost = $true
}

$MockWitnessExtraDids = @(
    $MockWitnessExtraDids |
        ForEach-Object { $_ -split "," } |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ }
)
if ($MockWitnessExtraDids.Count -gt 0) {
    $StartMockWitness = $true
}

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$multiServer = $ServerCount -ge 2

. (Join-Path $PSScriptRoot "lib\artifacts.ps1")
. (Join-Path $PSScriptRoot "lib\build-freshness.ps1")
. (Join-Path $PSScriptRoot "lib\secret-scan.ps1")
. (Join-Path $PSScriptRoot "lib\failure-fingerprint.ps1")
. (Join-Path $PSScriptRoot "lib\selection-gate.ps1")
. (Join-Path $PSScriptRoot "lib\joint-e2e-environment.ps1")

$SolandServiceId = $null
$SolandServiceDid = $null
$SolandServer2ServiceId = $null
$SolandServer2ServiceDid = $null
$script:UseManagedCoauthAssertionKey = [bool]($StartCoauth -and -not $CoauthCommand)

# The Playwright projects this runner knows how to provision, split by whether
# they open a browser. Kept in step with `e2e/playwright.config.ts`; a name in
# neither list stops the run rather than letting the resource decision below
# guess. `inkson-build-id` is absent on purpose: it is a setup project that the
# browser projects pull in through `dependencies`, never selected directly.
$script:BrowserPlaywrightProjects = @("chrome", "chromium", "joint-inkson")
$script:BrowserlessPlaywrightProjects = @("joint-api")

function Resolve-PlaywrightProjects {
    param(
        [string]$RunProfile,
        [string]$PlaywrightProject,
        [bool]$PlaywrightProjectWasExplicit
    )

    if ($RunProfile -eq "joint-smoke" -and -not $PlaywrightProjectWasExplicit) {
        return @("chrome")
    }
    if ($RunProfile -eq "joint-full" -and -not $PlaywrightProjectWasExplicit) {
        # Joint scenarios all run on the chrome project after the @mobile /
        # @visual smoke tests were retired in favor of scenario-driven specs.
        return @("chrome")
    }
    if ($RunProfile -eq "joint-api" -and -not $PlaywrightProjectWasExplicit) {
        return @("joint-api")
    }

    $projects = @()
    foreach ($project in ($PlaywrightProject -split ",")) {
        $trimmed = $project.Trim()
        if ($trimmed) {
            $projects += $trimmed
        }
    }
    if ($projects.Count -eq 0) {
        return @("chrome")
    }
    return $projects
}

# Whether this selection needs an Inkson bundle, static server and browser.
#
# Every Inkson-shaped action in this runner — source and cargo-target probing,
# port allocation, build, freshness and marker verification, the run-scoped
# copy, service start and readiness waits, the Coauth redirect allowlist, the
# environment and the topology record — is conditioned on the single answer
# this returns, and it is computed before any of them so none can half-happen.
# The removed `-SkipInkson` switch was the opposite shape: a free flag that
# could be combined with a browser profile, which is how it came to serve a
# placeholder URL to 45 browser specs. There is no flag here; the projects
# decide, and a contradictory selection is refused.
function Resolve-InksonRequirement {
    param(
        [string[]]$PlaywrightProjects,
        [string]$RunProfile,
        [hashtable]$InksonArguments
    )

    $selected = @($PlaywrightProjects | Where-Object { $_ })
    if ($selected.Count -eq 0) {
        throw "no Playwright project selected; the runner cannot decide which services to start."
    }
    $unknown = @($selected | Where-Object {
            $_ -notin $script:BrowserPlaywrightProjects -and
            $_ -notin $script:BrowserlessPlaywrightProjects
        })
    if ($unknown.Count -gt 0) {
        throw (("unknown Playwright project(s): {0}. Known browser projects: {1}; browserless: {2}. " +
                "Add the project to e2e/playwright.config.ts and to this runner's lists together.") -f
            ($unknown -join ", "),
            ($script:BrowserPlaywrightProjects -join ", "),
            ($script:BrowserlessPlaywrightProjects -join ", "))
    }

    $browserless = @($selected | Where-Object { $_ -in $script:BrowserlessPlaywrightProjects })
    $browser = @($selected | Where-Object { $_ -in $script:BrowserPlaywrightProjects })
    if ($browserless.Count -gt 0 -and $browser.Count -gt 0) {
        # `joint-api` selects files that `chrome`/`chromium` also collect, so a
        # mixed run would execute them twice and report both results.
        throw (("browserless project(s) {0} cannot be combined with browser project(s) {1}: " +
                "their file sets overlap, so the same specs would run twice. Run them separately.") -f
            ($browserless -join ", "), ($browser -join ", "))
    }

    $requiresInkson = $browser.Count -gt 0
    if (-not $requiresInkson) {
        $supplied = @($InksonArguments.Keys | Sort-Object)
        if ($supplied.Count -gt 0) {
            throw (("profile/project selection '{0}' starts no browser, so Inkson arguments ({1}) " +
                    "cannot take effect. Remove them, or select a browser project.") -f
                ($selected -join ", "), ($supplied -join ", "))
        }
    }
    if ($RunProfile -eq "joint-api" -and $requiresInkson) {
        throw (("-RunProfile joint-api was overridden with browser project(s) {0}; " +
                "the API profile exists to run without Inkson.") -f ($browser -join ", "))
    }
    return $requiresInkson
}

function Add-PreflightResult {
    param(
        [Parameter(Mandatory = $true)]$Results,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][string]$Detail
    )

    $Results.Add([pscustomobject]@{
            name   = $Name
            status = $Status
            detail = $Detail
        }) | Out-Null
}

function Find-CommandPath {
    param([Parameter(Mandatory = $true)][string[]]$Names)

    foreach ($name in $Names) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($command) {
            return $command.Source
        }
    }
    return $null
}

function Find-OpenSslPath {
    [string]$command = Find-CommandPath @("openssl.exe", "openssl")
    if (-not [string]::IsNullOrWhiteSpace($command)) {
        return $command
    }

    # Git for Windows and the standard Win64 OpenSSL installer both keep the
    # executable outside the default PATH on common installations. Resolve
    # those stable locations explicitly so a non-interactive runner does not
    # depend on a developer shell having amended PATH first.
    $candidates = @()
    if ($env:ProgramFiles) {
        $candidates += (Join-Path $env:ProgramFiles "Git\usr\bin\openssl.exe")
        $candidates += (Join-Path $env:ProgramFiles "OpenSSL-Win64\bin\openssl.exe")
    }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    return $null
}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @()
    )

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        return & $FilePath @Arguments 2>&1
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
}

function Get-RepositoryBuildInputState {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$BinaryPath
    )

    $resolvedRepository = (Resolve-Path $RepositoryRoot).Path
    $resolvedBinary = (Resolve-Path $BinaryPath).Path
    $git = Find-CommandPath @("git.exe", "git")
    if (-not $git) {
        throw "git is required to validate binary freshness"
    }

    $headOutput = @(Invoke-NativeCapture -FilePath $git -Arguments @(
            "-C", $resolvedRepository, "rev-parse", "HEAD"
        ))
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to resolve repository HEAD for ${resolvedRepository}: $($headOutput -join ' ')"
    }
    $head = ($headOutput -join "").Trim()

    $buildInputPaths = @(
        "Cargo.toml", "Cargo.lock", "build.rs", "Dioxus.toml", "crates", "src",
        "migrations", "assets", "public",
        ":(exclude)crates/**/tests/**", ":(exclude)tests/**",
        ":(exclude)crates/**/benches/**", ":(exclude)benches/**",
        ":(exclude)crates/**/examples/**", ":(exclude)examples/**"
    )
    $commitArguments = @(
        "-C", $resolvedRepository, "log", "-1", "--format=%cI", "--"
    ) + $buildInputPaths
    $commitTimeOutput = @(Invoke-NativeCapture -FilePath $git -Arguments $commitArguments)
    if ($LASTEXITCODE -ne 0 -or $commitTimeOutput.Count -eq 0) {
        throw "Unable to resolve build-input commit time for $resolvedRepository"
    }
    $commitTime = [DateTimeOffset]::Parse(
        ($commitTimeOutput -join "").Trim(),
        [System.Globalization.CultureInfo]::InvariantCulture
    ).UtcDateTime

    $trackedArguments = @("-C", $resolvedRepository, "ls-files", "--") + $buildInputPaths
    $trackedOutput = @(Invoke-NativeCapture -FilePath $git -Arguments $trackedArguments)
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to enumerate build inputs for $resolvedRepository"
    }

    $latestInputTime = [DateTime]::MinValue
    $latestInputPath = $null
    $buildExtensions = @(
        ".rs", ".toml", ".lock", ".sql", ".proto", ".json", ".html", ".css",
        ".js", ".ts", ".svg", ".png", ".webp"
    )
    foreach ($relativePath in $trackedOutput) {
        if (-not $relativePath) {
            continue
        }
        $fullPath = Join-Path $resolvedRepository ([string]$relativePath)
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            continue
        }
        $extension = [System.IO.Path]::GetExtension($fullPath).ToLowerInvariant()
        if ($buildExtensions -notcontains $extension -and
            [System.IO.Path]::GetFileName($fullPath) -ne "build.rs") {
            continue
        }
        $writeTime = (Get-Item -LiteralPath $fullPath).LastWriteTimeUtc
        if ($writeTime -gt $latestInputTime) {
            $latestInputTime = $writeTime
            $latestInputPath = [string]$relativePath
        }
    }

    $requiredTime = $commitTime
    $requiredBy = "HEAD build-input commit"
    if ($latestInputTime -gt $requiredTime) {
        $requiredTime = $latestInputTime
        $requiredBy = $latestInputPath
    }

    [pscustomobject]@{
        RepositoryRoot = $resolvedRepository
        RepositoryName = Split-Path -Leaf $resolvedRepository
        Head = $head
        RequiredTimeUtc = $requiredTime
        RequiredBy = $requiredBy
        BinaryPath = $resolvedBinary
        BinaryTimeUtc = (Get-Item -LiteralPath $resolvedBinary).LastWriteTimeUtc
    }
}

function Add-BinaryFreshnessPreflight {
    param(
        [Parameter(Mandatory = $true)]$Results,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$BinaryPath,
        [Parameter(Mandatory = $true)][string[]]$RepositoryRoots,
        [bool]$RequireBuildStamp = $true
    )

    try {
        $states = @(
            foreach ($repositoryRoot in $RepositoryRoots) {
                Get-RepositoryBuildInputState `
                    -RepositoryRoot $repositoryRoot `
                    -BinaryPath $BinaryPath
            }
        )
        $newest = $states | Sort-Object RequiredTimeUtc -Descending | Select-Object -First 1
        $stamp = Test-ArtifactBuildStamp -ArtifactPath $BinaryPath -RepositoryStates $states
        $shortHead = if ($newest.Head.Length -gt 12) { $newest.Head.Substring(0, 12) } else { $newest.Head }
        $detail = "binary=$($newest.BinaryTimeUtc.ToString('o')); newest_input=$($newest.RequiredTimeUtc.ToString('o')); repo=$($newest.RepositoryName); head=$shortHead; input=$($newest.RequiredBy)"
        if ($newest.BinaryTimeUtc -lt $newest.RequiredTimeUtc) {
            Add-PreflightResult $Results $Name "fail" "stale binary; $detail"
        } elseif ($RequireBuildStamp -and -not $stamp.Matches) {
            Add-PreflightResult $Results $Name "fail" "$detail; $($stamp.Detail)"
        } else {
            Add-PreflightResult $Results $Name "pass" "$detail; $($stamp.Detail)"
        }
    }
    catch {
        Add-PreflightResult $Results $Name "fail" $_.Exception.Message
    }
}

function Get-ArtifactFreshness {
    param(
        [Parameter(Mandatory = $true)][string]$ArtifactPath,
        [Parameter(Mandatory = $true)][string[]]$RepositoryRoots
    )

    if (-not (Test-Path -LiteralPath $ArtifactPath -PathType Leaf)) {
        return [pscustomobject]@{ Fresh = $false; Detail = "artifact missing: $ArtifactPath" }
    }
    try {
        $states = @(
            foreach ($repositoryRoot in $RepositoryRoots) {
                Get-RepositoryBuildInputState -RepositoryRoot $repositoryRoot -BinaryPath $ArtifactPath
            }
        )
        $newest = $states | Sort-Object RequiredTimeUtc -Descending | Select-Object -First 1
        $stamp = Test-ArtifactBuildStamp -ArtifactPath $ArtifactPath -RepositoryStates $states
        return [pscustomobject]@{
            Fresh = $newest.BinaryTimeUtc -ge $newest.RequiredTimeUtc -and $stamp.Matches
            Detail = "artifact=$($newest.BinaryTimeUtc.ToString('o')); newest_input=$($newest.RequiredTimeUtc.ToString('o')); repo=$($newest.RepositoryName); input=$($newest.RequiredBy); $($stamp.Detail)"
        }
    } catch {
        return [pscustomobject]@{ Fresh = $false; Detail = $_.Exception.Message }
    }
}

# One managed Savfox probe instance: home directory, deterministic model
# provider, and the gateway that serves it.
#
# The joint gate runs two fully independent probes (addressed and unaddressed)
# that differ only in ports, home directory, and token. Maintaining that as two
# parallel copies of the config text, process commands, readiness waits, and
# manifest fields is how a third probe — a revoke or restart case — would start
# by duplicating a whole runner branch again. Everything a probe is made of is
# derived from its name here, so the caller supplies only what actually differs.
function New-ManagedSavfoxProbe {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$JointDirectory,
        [Parameter(Mandatory = $true)][string]$MocksRoot,
        [Parameter(Mandatory = $true)][string]$LogDirectory,
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Token,
        [Parameter(Mandatory = $true)][string]$ModelBaseUrl,
        [Parameter(Mandatory = $true)][int]$ModelPort,
        [Parameter(Mandatory = $true)][System.Collections.IList]$ManagedServices
    )

    $probeHome = Join-Path $JointDirectory "$Name-home"
    New-Item -ItemType Directory -Path $probeHome -Force | Out-Null
    $receiptPath = Join-Path $JointDirectory "$Name-model-receipts.jsonl"
    $config = @"
approval_policy = "never"
sandbox_mode = "read-only"
model_provider = "joint_mock"

[model]
slug = "joint-pong"
provider = "joint_mock"

[features]
remote_models = false

[model_providers.joint_mock]
name = "Cotest deterministic Savfox model"
base_url = "$ModelBaseUrl/v1"
wire_api = "responses"
request_max_retries = 0
stream_max_retries = 0
requires_openai_auth = false
"@
    $config | Set-Content -LiteralPath (Join-Path $probeHome "config.toml") -Encoding UTF8

    $modelCommand = (
        "`$env:MOCK_SAVFOX_MODEL_PORT='{0}'; `$env:MOCK_SAVFOX_MODEL_RECEIPT_PATH={1}; node {2}"
    ) -f $ModelPort, (Quote-PsLiteral $receiptPath), (Quote-PsLiteral (Join-Path $MocksRoot "mock-savfox-model.mjs"))
    $modelService = Start-ManagedCommand `
        -Name "mock-$Name-model" `
        -Command $modelCommand `
        -WorkingDirectory $MocksRoot `
        -LogDirectory $LogDirectory
    $ManagedServices.Add($modelService) | Out-Null
    Wait-HttpReady -Url "$ModelBaseUrl/health" -TimeoutSeconds 30

    [pscustomobject]@{
        Name         = $Name
        BaseUrl      = $BaseUrl
        Port         = $Port
        Token        = $Token
        Home         = $probeHome
        ModelBaseUrl = $ModelBaseUrl
        ReceiptPath  = $receiptPath
        Services     = [System.Collections.Generic.List[object]]@($modelService)
    }
}

# Start a probe's gateway once its model provider is ready. Kept separate from
# the factory so the gateway still boots in the same phase as the other
# Arkret-facing services.
function Start-ManagedSavfoxGateway {
    param(
        [Parameter(Mandatory = $true)][psobject]$Probe,
        [Parameter(Mandatory = $true)][string]$Binary,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$LogDirectory,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][System.Collections.IList]$ManagedServices
    )

    $command = (
        "`$env:SAVFOX_HOME={0}; `$env:RUST_LOG='info'; & {1} gateway --host 127.0.0.1 --port {2} --token {3}"
    ) -f (Quote-PsLiteral $Probe.Home), (Quote-PsLiteral $Binary), $Probe.Port, (Quote-PsLiteral $Probe.Token)
    $service = Start-ManagedCommand `
        -Name $Probe.Name `
        -Command $command `
        -WorkingDirectory $WorkingDirectory `
        -LogDirectory $LogDirectory
    $ManagedServices.Add($service) | Out-Null
    $Probe.Services.Add($service)
    Wait-HttpReady -Url "$($Probe.BaseUrl.TrimEnd('/'))/health" -TimeoutSeconds $TimeoutSeconds
    $service
}

function Test-BinaryContainsAsciiMarker {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Marker
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $text = [System.Text.Encoding]::ASCII.GetString($bytes)
    return $text.Contains($Marker)
}

function Resolve-PlaywrightCliInvocation {
    param([Parameter(Mandatory = $true)][string]$E2eRoot)

    $node = Find-CommandPath @("node.exe", "node")
    if ($node) {
        foreach ($cliPath in @(
                (Join-Path $E2eRoot "node_modules\@playwright\test\cli.js"),
                (Join-Path $E2eRoot "node_modules\playwright\cli.js")
            )) {
            if (Test-Path $cliPath) {
                return [pscustomobject]@{
                    FilePath  = $node
                    Arguments = @($cliPath)
                    Detail    = "$node $cliPath"
                }
            }
        }
    }

    $npx = Find-CommandPath @("npx.cmd", "npx")
    if ($npx) {
        return [pscustomobject]@{
            FilePath  = $npx
            Arguments = @("playwright")
            Detail    = $npx
        }
    }

    return $null
}

function Test-DockerImagePresent {
    param([Parameter(Mandatory = $true)][string]$ImageTag)

    $docker = Find-CommandPath @("docker.exe", "docker")
    if (-not $docker) {
        return $false
    }
    $null = Invoke-NativeCapture -FilePath $docker -Arguments @("image", "inspect", $ImageTag)
    return $LASTEXITCODE -eq 0
}

function Invoke-SolandImageBuild {
    param(
        [Parameter(Mandatory = $true)][string]$ImageTag,
        [string[]]$CacheFrom = @(),
        [string]$CacheTo,
        [switch]$Pull,
        [switch]$NoCache
    )

    $buildRepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
    $buildWorkspaceRoot = (Resolve-Path (Join-Path $buildRepoRoot "..")).Path
    $buildDockerfilePath = Join-Path $buildRepoRoot "docker\soland.Dockerfile"
    foreach ($path in @(
            (Join-Path $buildWorkspaceRoot "soland"),
            (Join-Path $buildWorkspaceRoot "arkret-rust-sdk"),
            $buildDockerfilePath
        )) {
        if (-not (Test-Path $path)) {
            throw "Required path not found: $path"
        }
    }

    $buildArgs = @("build", "--file", $buildDockerfilePath, "--tag", $ImageTag)
    foreach ($cache in $CacheFrom) {
        if ($cache) {
            $buildArgs += @("--cache-from", $cache)
        }
    }
    if ($CacheTo) {
        $buildArgs += @("--cache-to", $CacheTo)
    }
    if ($Pull) {
        $buildArgs += "--pull"
    }
    if ($NoCache) {
        $buildArgs += "--no-cache"
    }
    $buildArgs += $buildWorkspaceRoot

    Write-Host "Building $ImageTag from $buildDockerfilePath with context $buildWorkspaceRoot"
    & docker @buildArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to build Docker image $ImageTag"
    }
}

function Invoke-JointE2ePreflight {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$WorkspaceRoot,
        [Parameter(Mandatory = $true)][string]$E2eRoot,
        [Parameter(Mandatory = $true)][string[]]$PlaywrightProjects,
        [Parameter(Mandatory = $true)][bool]$StartCoauth,
        [Parameter(Mandatory = $true)][string]$CoauthPostgresImage,
        [string]$CoauthBin,
        [bool]$StartTeabay = $false,
        [string]$TeabayBin,
        [string]$TeabayDatabaseUrl,
        [string]$SolandBaseUrl,
        [string]$SolandCommand,
        [string]$SolandBin,
        [string]$SolandDatabaseUrl,
        [string]$SolandPostgresImage = "postgres:18.6-alpine",
        [bool]$WillStartDefaultSoland = $false,
        [ValidateSet("process", "docker")][string]$SolandRuntime = "process",
        [string]$SolandImage,
        [bool]$WillStartDockerSoland = $false,
        [string]$InksonBaseUrl,
        [string]$InksonCommand,
        # False for a browserless lane. Without it the "neither URL nor command"
        # arm below reads an absent Inkson as "the harness will serve the cached
        # bundle" and fails the run on a bundle it is never going to load.
        [bool]$RequiresInkson = $true,
        [bool]$WillStartDefaultInkson = $false,
        [string]$InksonStaticIndex,
        [bool]$JointTlsTopology = $false,
        [string]$JsonPath,
        [string]$MarkdownPath
    )

    $results = New-Object System.Collections.Generic.List[object]

    $node = Find-CommandPath @("node.exe", "node")
    if ($node) {
        $version = (& $node --version 2>&1) -join "`n"
        Add-PreflightResult $results "node" "pass" "$node $version"
    } else {
        Add-PreflightResult $results "node" "fail" "node is required"
    }

    $npm = Find-CommandPath @("npm.cmd", "npm")
    if ($npm) {
        $version = (& $npm --version 2>&1) -join "`n"
        Add-PreflightResult $results "npm" "pass" "$npm $version"
    } else {
        Add-PreflightResult $results "npm" "fail" "npm is required to install e2e dependencies"
    }

    $npx = Find-CommandPath @("npx.cmd", "npx")
    if ($npx) {
        Add-PreflightResult $results "npx" "pass" $npx
    } else {
        Add-PreflightResult $results "npx" "fail" "npx is required to invoke Playwright"
    }

    $nodeModules = Join-Path $E2eRoot "node_modules"
    if (Test-Path $nodeModules) {
        Add-PreflightResult $results "e2e node_modules" "pass" $nodeModules
    } else {
        Add-PreflightResult $results "e2e node_modules" "fail" "missing after environment initialization"
    }

    $playwrightCli = Resolve-PlaywrightCliInvocation -E2eRoot $E2eRoot
    if ($playwrightCli) {
        Add-PreflightResult $results "playwright cli" "pass" $playwrightCli.Detail
        Push-Location $E2eRoot
        try {
            $playwrightBaseArgs = @($playwrightCli.Arguments)
            $playwrightVersionOutput = Invoke-NativeCapture -FilePath $playwrightCli.FilePath -Arguments ($playwrightBaseArgs + @("--version"))
            $playwrightVersionExitCode = $LASTEXITCODE
            $playwrightVersion = $playwrightVersionOutput -join "`n"
            if ($playwrightVersionExitCode -eq 0) {
                Add-PreflightResult $results "playwright package" "pass" $playwrightVersion
            } else {
                Add-PreflightResult $results "playwright package" "fail" $playwrightVersion
            }

            $listArgs = @("test", "--config", "playwright.config.ts", "--list")
            foreach ($project in $PlaywrightProjects) {
                $listArgs += @("--project", $project)
            }
            $listCommandOutput = Invoke-NativeCapture -FilePath $playwrightCli.FilePath -Arguments ($playwrightBaseArgs + $listArgs)
            $listExitCode = $LASTEXITCODE
            $listOutput = $listCommandOutput -join "`n"
            if ($listExitCode -eq 0) {
                Add-PreflightResult $results "playwright projects" "pass" ($PlaywrightProjects -join ",")
            } else {
                Add-PreflightResult $results "playwright projects" "fail" $listOutput
            }

            $browserListOutput = Invoke-NativeCapture -FilePath $playwrightCli.FilePath -Arguments ($playwrightBaseArgs + @("install", "--list"))
            $browserListExitCode = $LASTEXITCODE
            $browserList = $browserListOutput -join "`n"
            if ($browserListExitCode -eq 0) {
                Add-PreflightResult $results "playwright browsers" "pass" "browser registry readable"
            } else {
                Add-PreflightResult $results "playwright browsers" "fail" $browserList
            }
        }
        finally {
            Pop-Location
        }
    } else {
        Add-PreflightResult $results "playwright cli" "fail" "Playwright CLI is required"
    }

    if ($WillStartDefaultSoland -or (-not $SolandBaseUrl -and -not $SolandCommand)) {
        if ($SolandRuntime -eq "docker") {
            Add-PreflightResult $results "soland runtime" "pass" "docker"
        } else {
            try {
                $solandBinary = Resolve-SolandBinary -ExplicitPath $SolandBin -WorkspaceRoot $WorkspaceRoot
                Add-PreflightResult $results "soland binary" "pass" $solandBinary
                Add-BinaryFreshnessPreflight `
                    -Results $results `
                    -Name "soland binary freshness" `
                    -BinaryPath $solandBinary `
                    -RepositoryRoots @(
                        (Join-Path $WorkspaceRoot "soland"),
                        (Join-Path $WorkspaceRoot "arkret-rust-sdk")
                    ) `
                    -RequireBuildStamp (-not [bool]$SolandBin)
            } catch {
                Add-PreflightResult $results "soland binary" "fail" $_.Exception.Message
            }
        }
    }

    if ($WillStartDefaultSoland -and -not $SolandDatabaseUrl) {
        $docker = Find-CommandPath @("docker.exe", "docker")
        if ($docker) {
            Add-PreflightResult $results "soland postgres docker" "pass" $docker
            $dockerInfo = (Invoke-NativeCapture -FilePath $docker -Arguments @("info")) -join "`n"
            if ($LASTEXITCODE -eq 0) {
                Add-PreflightResult $results "soland postgres daemon" "pass" "daemon reachable"
            } else {
                Add-PreflightResult $results "soland postgres daemon" "fail" $dockerInfo
            }
            $imageInspect = (Invoke-NativeCapture -FilePath $docker -Arguments @("image", "inspect", $SolandPostgresImage)) -join "`n"
            if ($LASTEXITCODE -eq 0) {
                Add-PreflightResult $results "soland postgres image" "pass" $SolandPostgresImage
            } else {
                Add-PreflightResult $results "soland postgres image" "warn" "$SolandPostgresImage not present locally; docker run may pull it"
            }
        } else {
            Add-PreflightResult $results "soland postgres docker" "fail" "docker is required for managed Soland PostgreSQL"
        }
    }

    if ($WillStartDockerSoland) {
        $docker = Find-CommandPath @("docker.exe", "docker")
        if ($docker) {
            Add-PreflightResult $results "docker cli" "pass" $docker
            $dockerInfo = (Invoke-NativeCapture -FilePath $docker -Arguments @("info")) -join "`n"
            if ($LASTEXITCODE -eq 0) {
                Add-PreflightResult $results "docker daemon" "pass" "daemon reachable"
            } else {
                Add-PreflightResult $results "docker daemon" "fail" $dockerInfo
            }
            $imageInspect = (Invoke-NativeCapture -FilePath $docker -Arguments @("image", "inspect", $SolandImage)) -join "`n"
            if ($LASTEXITCODE -eq 0) {
                Add-PreflightResult $results "soland image" "pass" $SolandImage
            } else {
                Add-PreflightResult $results "soland image" "fail" "$SolandImage not present after image build/check"
            }
        } else {
            Add-PreflightResult $results "docker cli" "fail" "docker is required for -SolandRuntime docker"
        }
    }

    if ($RequiresInkson -and ($WillStartDefaultInkson -or (-not $InksonBaseUrl -and -not $InksonCommand))) {
        if ($InksonStaticIndex -and (Test-Path -LiteralPath $InksonStaticIndex -PathType Leaf)) {
            Add-PreflightResult $results "inkson web bundle" "pass" $InksonStaticIndex
            $inksonFreshness = Get-ArtifactFreshness `
                -ArtifactPath $InksonStaticIndex `
                -RepositoryRoots @(
                    (Join-Path $WorkspaceRoot "inkson"),
                    (Join-Path $WorkspaceRoot "arkret-rust-sdk"),
                    (Join-Path $WorkspaceRoot "garth"),
                    (Join-Path $WorkspaceRoot "chime")
                )
            if ($inksonFreshness.Fresh) {
                Add-PreflightResult $results "inkson bundle freshness" "pass" $inksonFreshness.Detail
            } else {
                Add-PreflightResult $results "inkson bundle freshness" "fail" $inksonFreshness.Detail
            }
            $inksonWasm = Join-Path (Split-Path -Parent $InksonStaticIndex) "wasm\inkson_bg.wasm"
            if (Test-BinaryContainsAsciiMarker -Path $inksonWasm -Marker "inkson.test.session_injection.v1") {
                Add-PreflightResult $results "inkson test-session feature" "pass" $inksonWasm
            } else {
                Add-PreflightResult $results "inkson test-session feature" "fail" "cached Wasm lacks wasm-localstorage-secrets-test marker; rerun without -SkipBuild"
            }
        } else {
            Add-PreflightResult $results "inkson web bundle" "fail" "cached bundle missing; rerun without -SkipBuild"
        }
    }

    if ($StartTeabay) {
        try {
            $teabayBinary = Resolve-TeabayBinary -ExplicitPath $TeabayBin -WorkspaceRoot $WorkspaceRoot
            Add-PreflightResult $results "teabay binary" "pass" $teabayBinary
            Add-BinaryFreshnessPreflight `
                -Results $results `
                -Name "teabay binary freshness" `
                -BinaryPath $teabayBinary `
                    -RepositoryRoots @(
                        (Join-Path $WorkspaceRoot "teabay"),
                        (Join-Path $WorkspaceRoot "arkret-rust-sdk")
                    ) `
                    -RequireBuildStamp $false
        } catch {
            Add-PreflightResult $results "teabay binary" "fail" $_.Exception.Message
        }
        if (-not $TeabayDatabaseUrl -and -not $env:DATABASE_URL) {
            Add-PreflightResult $results "teabay database url" "fail" "-StartTeabay requires -TeabayDatabaseUrl or DATABASE_URL in env"
        } else {
            $dbUrl = if ($TeabayDatabaseUrl) { $TeabayDatabaseUrl } else { $env:DATABASE_URL }
            Add-PreflightResult $results "teabay database url" "pass" $dbUrl
        }
    }

    if ($StartCoauth) {
        try {
            $coauthBinary = Resolve-CoauthBinary -ExplicitPath $CoauthBin -WorkspaceRoot $WorkspaceRoot
            Add-PreflightResult $results "coauth binary" "pass" $coauthBinary
            Add-BinaryFreshnessPreflight `
                -Results $results `
                -Name "coauth binary freshness" `
                -BinaryPath $coauthBinary `
                    -RepositoryRoots @(
                        (Join-Path $WorkspaceRoot "coauth"),
                        (Join-Path $WorkspaceRoot "arkret-rust-sdk")
                    ) `
                    -RequireBuildStamp (-not [bool]$CoauthBin)
        } catch {
            Add-PreflightResult $results "coauth binary" "fail" $_.Exception.Message
        }

        if ($CoauthPostgresUrl) {
            Add-PreflightResult $results "coauth postgres" "pass" "external DSN provided; docker not required"
        } else {
            $docker = Find-CommandPath @("docker.exe", "docker")
            if ($docker) {
                Add-PreflightResult $results "docker cli" "pass" $docker
                $dockerInfo = (Invoke-NativeCapture -FilePath $docker -Arguments @("info")) -join "`n"
                if ($LASTEXITCODE -eq 0) {
                    Add-PreflightResult $results "docker daemon" "pass" "daemon reachable"
                } else {
                    Add-PreflightResult $results "docker daemon" "fail" $dockerInfo
                }
                $imageInspect = (Invoke-NativeCapture -FilePath $docker -Arguments @("image", "inspect", $CoauthPostgresImage)) -join "`n"
                if ($LASTEXITCODE -eq 0) {
                    Add-PreflightResult $results "postgres image" "pass" $CoauthPostgresImage
                } else {
                    Add-PreflightResult $results "postgres image" "warn" "$CoauthPostgresImage not present locally; docker run may pull it"
                }
            } else {
                Add-PreflightResult $results "docker cli" "fail" "docker is required for -StartCoauth PostgreSQL"
            }
        }
    }

    if ($JointTlsTopology) {
        # 0530-C static gates for the HTTPS identity topology. The dynamic
        # proofs (DNS answers, CA/SAN, did.jsonl history, negative probes) run
        # in Assert-JointTlsTopology once the services are up; here we only
        # check that the host environment can host the topology at all.
        $caddyInspection = Get-CotestCaddyInspection
        Add-PreflightResult $results "tls proxy (caddy)" $caddyInspection.status $caddyInspection.detail
        $openssl = Find-OpenSslPath
        if ($openssl) {
            Add-PreflightResult $results "tls assets (openssl)" "pass" $openssl
        } else {
            Add-PreflightResult $results "tls assets (openssl)" "fail" "openssl is required to mint the joint CA and server certificates"
        }
        $hostsPath = Get-CotestHostsPath
        try {
            $hostsStream = [System.IO.File]::Open(
                $hostsPath,
                [System.IO.FileMode]::Append,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::ReadWrite
            )
            $hostsStream.Close()
            Add-PreflightResult $results "hosts file writable" "pass" $hostsPath
        } catch {
            $platform = Get-CotestPlatformInfo
            $repair = if ($platform.os -eq "windows") { "Run elevated: pwsh -NoProfile -File $PSScriptRoot\initialize-joint-e2e-environment.ps1 -ServerCount $ServerCount" } else { "Privileged setup is not yet supported on $($platform.os)" }
            Add-PreflightResult $results "hosts file writable" "fail" "$hostsPath is not writable: $($_.Exception.Message). $repair"
        }
    }

    if ($JsonPath) {
        $results | ConvertTo-Json -Depth 6 | Set-Content -Path $JsonPath -Encoding UTF8
    }
    if ($MarkdownPath) {
        $lines = @("# joint e2e preflight", "")
        foreach ($result in $results) {
            $lines += "- [$($result.status)] $($result.name): $($result.detail)"
        }
        $lines | Set-Content -Path $MarkdownPath -Encoding UTF8
    }

    Write-Host "Joint E2E preflight"
    foreach ($result in $results) {
        Write-Host "  [$($result.status)] $($result.name): $($result.detail)"
    }

    $failures = @($results | Where-Object { $_.status -eq "fail" })
    if ($failures.Count -gt 0) {
        throw "Joint E2E preflight failed: $($failures.name -join ', ')"
    }
}

$script:AllocatedTcpPorts = [System.Collections.Generic.HashSet[int]]::new()
$script:NextTcpPortCandidate = 20000 + (Get-Random -Minimum 0 -Maximum 5000)
$script:WindowsExcludedTcpPortRanges = $null

function Get-WindowsExcludedTcpPortRanges {
    $isWindowsPlatform = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [System.Runtime.InteropServices.OSPlatform]::Windows
    )
    if (-not $isWindowsPlatform) {
        return @()
    }
    if ($null -ne $script:WindowsExcludedTcpPortRanges) {
        return $script:WindowsExcludedTcpPortRanges
    }

    $ranges = @()
    $netsh = Get-Command netsh -ErrorAction SilentlyContinue
    if ($netsh) {
        $output = & netsh interface ipv4 show excludedportrange protocol=tcp 2>$null
        foreach ($line in @($output)) {
            if ($line -match '^\s*(\d+)\s+(\d+)\s*(\*)?\s*$') {
                $ranges += [pscustomobject]@{
                    Start = [int]$Matches[1]
                    End   = [int]$Matches[2]
                }
            }
        }
    }

    $script:WindowsExcludedTcpPortRanges = $ranges
    return $script:WindowsExcludedTcpPortRanges
}

function Test-TcpPortExcluded {
    param([Parameter(Mandatory = $true)][int]$Port)
    foreach ($range in @(Get-WindowsExcludedTcpPortRanges)) {
        if ($Port -ge $range.Start -and $Port -le $range.End) {
            return $true
        }
    }
    return $false
}

function Test-TcpPortBindable {
    param([Parameter(Mandatory = $true)][int]$Port)
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse("127.0.0.1"), $Port)
    try {
        $listener.Start()
        return $true
    }
    catch {
        return $false
    }
    finally {
        $listener.Stop()
    }
}

function Get-FreeTcpPort {
    for ($attempt = 0; $attempt -lt 10000; $attempt++) {
        $port = $script:NextTcpPortCandidate
        $script:NextTcpPortCandidate++
        if ($script:NextTcpPortCandidate -gt 29999) {
            $script:NextTcpPortCandidate = 20000
        }

        if ($script:AllocatedTcpPorts.Contains($port)) {
            continue
        }
        if (Test-TcpPortExcluded -Port $port) {
            continue
        }
        if (-not (Test-TcpPortBindable -Port $port)) {
            continue
        }

        $null = $script:AllocatedTcpPorts.Add($port)
        return $port
    }

    throw "Unable to allocate a free TCP port in the joint e2e harness range."
}

function Quote-PsLiteral {
    param([Parameter(Mandatory = $true)][string]$Value)
    return "'" + ($Value -replace "'", "''") + "'"
}

function Write-DotEnvFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Values
    )

    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($entry in $Values.GetEnumerator()) {
        $escaped = ([string]$entry.Value).
            Replace('\', '\\').
            Replace('"', '\"').
            Replace("`r", '\r').
            Replace("`n", '\n')
        $lines.Add("$($entry.Key)=`"$escaped`"")
    }
    [System.IO.File]::WriteAllLines(
        $Path,
        $lines,
        [System.Text.UTF8Encoding]::new($false)
    )
}

# ── Joint TLS identity topology (0530-C) ─────────────────────
# Runner-owned services keep their plain loopback listeners, but their public
# base URLs — and therefore the service `did:webvh` they mint — are stable
# HTTPS names (`<service>.local.host:<tls port>`) fronted by one managed Caddy
# reverse proxy. Trust is run-scoped rather than machine-scoped: Node and
# coauth receive the CA file, while Chromium receives the exact leaf SPKI pin.
# The topology gate independently verifies the CA chain, served leaf and every
# SAN before business tests run. Hosts entries and key files are reverted in
# the finally block unless -KeepServices is set.

function New-JointTlsAssets {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string[]]$DnsNames,
        [Parameter(Mandatory = $true)][string]$RunLabel
    )

    $openssl = Find-OpenSslPath
    if (-not $openssl) {
        throw "openssl is required to mint the joint TLS topology certificates"
    }
    $null = New-Item -ItemType Directory -Force -Path $Directory
    $caName = "cotest-joint-e2e-ca-$RunLabel"
    $caKey = Join-Path $Directory "ca.key"
    $caPem = Join-Path $Directory "ca.pem"
    $requestConfig = Join-Path $Directory "request.cnf"
    $requestConfigLines = @(
        "[req]",
        "distinguished_name=req_dn",
        "prompt=no",
        "[req_dn]",
        "CN=cotest-joint-e2e"
    )
    [System.IO.File]::WriteAllLines(
        $requestConfig,
        $requestConfigLines,
        [System.Text.UTF8Encoding]::new($false)
    )
    & $openssl req -x509 -newkey rsa:2048 -keyout $caKey -out $caPem -days 2 -nodes `
        -config $requestConfig `
        -subj "/CN=$caName" `
        -addext "basicConstraints=critical,CA:TRUE" `
        -addext "keyUsage=critical,keyCertSign,cRLSign"
    if ($LASTEXITCODE -ne 0) {
        throw "openssl CA generation failed (exit $LASTEXITCODE)"
    }

    $serverKey = Join-Path $Directory "server.key"
    $serverCsr = Join-Path $Directory "server.csr"
    $serverPem = Join-Path $Directory "server.pem"
    $sanFile = Join-Path $Directory "server-san.cnf"
    # PowerShell 7.6.5 splits `"subjectAltName=" + (<pipeline> -join ",")` into
    # two array elements when written inline in the array literal; bind the
    # string first (same class of regression as Parse-CotestLog in the server runner).
    $subjectAltNameLine = "subjectAltName=" + (($DnsNames | ForEach-Object { "DNS:$_" }) -join ",")
    $sanLines = @(
        "[req_ext]",
        "basicConstraints=critical,CA:FALSE",
        "keyUsage=critical,digitalSignature,keyEncipherment",
        "extendedKeyUsage=serverAuth",
        $subjectAltNameLine
    )
    [System.IO.File]::WriteAllLines($sanFile, $sanLines, [System.Text.UTF8Encoding]::new($false))
    & $openssl req -newkey rsa:2048 -keyout $serverKey -out $serverCsr -nodes `
        -config $requestConfig `
        -subj "/CN=$($DnsNames[0])"
    if ($LASTEXITCODE -ne 0) {
        throw "openssl server key generation failed (exit $LASTEXITCODE)"
    }
    & $openssl x509 -req -in $serverCsr -CA $caPem -CAkey $caKey -CAcreateserial `
        -out $serverPem -days 2 -extfile $sanFile -extensions req_ext
    if ($LASTEXITCODE -ne 0) {
        throw "openssl server certificate signing failed (exit $LASTEXITCODE)"
    }
    Remove-Item -LiteralPath $serverCsr -ErrorAction SilentlyContinue

    $serverCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($serverPem)
    $serverRsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($serverCertificate)
    try {
        $serverSpki = $serverRsa.ExportSubjectPublicKeyInfo()
        $serverSpkiSha256 = [Convert]::ToBase64String(
            [System.Security.Cryptography.SHA256]::HashData($serverSpki)
        )
    } finally {
        $serverRsa.Dispose()
        $serverCertificate.Dispose()
    }

    return [pscustomobject]@{
        CaPemPath        = $caPem
        CaKeyPath        = $caKey
        ServerPemPath    = $serverPem
        ServerKeyPath    = $serverKey
        ServerSpkiSha256 = $serverSpkiSha256
        CaSubjectName    = $caName
    }
}

function Install-JointLoopbackHosts {
    param(
        [Parameter(Mandatory = $true)][string[]]$Hosts,
        [Parameter(Mandatory = $true)][string]$Marker
    )

    $hostsPath = Get-CotestHostsPath
    $existing = [System.IO.File]::ReadAllText($hostsPath)
    $patched = Add-CotestHostsBlock -Content $existing -Hosts $Hosts -Marker $Marker
    try {
        [System.IO.File]::WriteAllText($hostsPath, $patched, [System.Text.UTF8Encoding]::new($false))
    } catch {
        throw "joint TLS topology: cannot register loopback hosts in $hostsPath ($($_.Exception.Message)). Run initialize-joint-e2e-environment.ps1 from an elevated PowerShell."
    }
}

function Remove-JointLoopbackHosts {
    param([Parameter(Mandatory = $true)][string]$Marker)

    $hostsPath = Get-CotestHostsPath
    $existing = [System.IO.File]::ReadAllText($hostsPath)
    $patched = Remove-CotestHostsBlocks -Content $existing -Marker $Marker
    if ($patched -ne $existing) {
        [System.IO.File]::WriteAllText($hostsPath, $patched, [System.Text.UTF8Encoding]::new($false))
    }
}

function Sync-JointControlledServices {
    param(
        [Parameter(Mandatory = $true)][string]$TopologyPath,
        [Parameter(Mandatory = $true)]$ManagedServices
    )
    if (-not (Test-Path -LiteralPath $TopologyPath -PathType Leaf)) { return @() }
    $failures = [System.Collections.Generic.List[string]]::new()
    $topology = Get-Content -Raw -LiteralPath $TopologyPath | ConvertFrom-Json
    foreach ($server in @($topology.servers)) {
        $controlProperty = $server.soland.PSObject.Properties["control"]
        $control = if ($controlProperty) { $controlProperty.Value } else { $null }
        if (-not $control -or -not $control.state_path -or -not (Test-Path -LiteralPath $control.state_path)) { continue }
        $state = Get-Content -Raw -LiteralPath $control.state_path | ConvertFrom-Json
        if ($state.status -eq "isolated") {
            try {
                & $control.script_path -TopologyPath $TopologyPath -ServerName $server.name -Action restore
                if ($LASTEXITCODE -ne 0) { throw "controller exited with $LASTEXITCODE" }
                $state = Get-Content -Raw -LiteralPath $control.state_path | ConvertFrom-Json
            } catch {
                $failures.Add("failed to restore isolated $($server.name): $($_.Exception.Message)")
                continue
            }
        }
        if ($control.kind -eq "process" -and $state.current_process_id -and [int]$state.current_process_id -ne [int]$server.soland.process_id) {
            $managed = @($ManagedServices | Where-Object { $_.Kind -eq "process" -and $_.Name -eq "soland-$($server.name)" }) | Select-Object -Last 1
            $replacement = Get-Process -Id ([int]$state.current_process_id) -ErrorAction SilentlyContinue
            if (-not $managed -or -not $replacement) {
                $failures.Add("replacement process for $($server.name) is unavailable")
                continue
            }
            $managed.Process = $replacement
            if ($state.stdout) { $managed.Stdout = [string]$state.stdout }
            if ($state.stderr) { $managed.Stderr = [string]$state.stderr }
        }
    }
    return @($failures)
}

function Write-JointCaddyConfig {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$TlsPort,
        [Parameter(Mandatory = $true)][object[]]$Routes,
        [Parameter(Mandatory = $true)][string]$CertificatePath,
        [Parameter(Mandatory = $true)][string]$KeyPath
    )

    $certificate = $CertificatePath -replace '\\', '/'
    $key = $KeyPath -replace '\\', '/'
    $lines = @(
        "{",
        "`tadmin off",
        "`tauto_https disable_redirects",
        "}",
        ""
    )
    foreach ($route in $Routes) {
        $lines += "https://$($route.Host):$TlsPort {"
        $lines += "`tbind 127.0.0.1"
        $lines += "`ttls $certificate $key"
        $logoutBackend = $route.PSObject.Properties['LogoutBackendPort']
        if ($null -ne $logoutBackend) {
            # service-http-binding §2.1.2 exposes one Account Authority base
            # to clients. The deployment gateway dispatches the canonical hard
            # logout to the Principal service that owns its to-device/push
            # cleanup, while all other gate/account operations remain on
            # coauth. The external Host/URI are preserved for DPoP `htu`.
            $lines += "`thandle /_arkret/gate/account/logout {"
            $lines += "`t`treverse_proxy 127.0.0.1:$($logoutBackend.Value)"
            $lines += "`t}"
            $lines += "`thandle {"
            $lines += "`t`treverse_proxy 127.0.0.1:$($route.BackendPort)"
            $lines += "`t}"
        } else {
            $lines += "`treverse_proxy 127.0.0.1:$($route.BackendPort)"
        }
        $lines += "}"
        $lines += ""
    }
    [System.IO.File]::WriteAllLines($Path, $lines, [System.Text.UTF8Encoding]::new($false))
}

function Get-WebvhLogUrlFromDid {
    param([Parameter(Mandatory = $true)][string]$Did)

    # Mirror the SDK's did:webvh URL derivation:
    # did:webvh:<scid>:<percent-encoded authority>[:<path segment>...]
    $segments = $Did -split ":"
    if ($segments.Count -lt 4 -or $segments[0] -ne "did" -or $segments[1] -ne "webvh") {
        throw "not an authority-bearing did:webvh: $Did"
    }
    $authority = [System.Uri]::UnescapeDataString($segments[3])
    $path = ""
    if ($segments.Count -gt 4) {
        $path = ($segments[4..($segments.Count - 1)] -join "/") + "/"
    }
    return "https://$authority/$($path)did.jsonl"
}

function Assert-JointTlsTopology {
    param(
        [Parameter(Mandatory = $true)][int]$TlsPort,
        [Parameter(Mandatory = $true)][string[]]$TrustedHosts,
        [Parameter(Mandatory = $true)][string]$UnregisteredProbeHost,
        [Parameter(Mandatory = $true)][string]$CaPemPath,
        [Parameter(Mandatory = $true)][string]$ServerPemPath,
        [Parameter(Mandatory = $true)][string]$CotestWireBin,
        [Parameter(Mandatory = $true)][string]$EvidenceDir,
        [Parameter(Mandatory = $true)][object[]]$Services
    )

    $null = New-Item -ItemType Directory -Force -Path $EvidenceDir

    $openssl = Find-OpenSslPath
    if (-not $openssl) {
        throw "joint TLS topology: openssl disappeared after preflight"
    }
    $verifyOutput = & $openssl verify -CAfile $CaPemPath $ServerPemPath 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "joint TLS topology: generated server certificate does not verify against the run-scoped CA: $($verifyOutput -join ' ')"
    }
    $expectedServerCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ServerPemPath)
    $expectedServerThumbprint = $expectedServerCertificate.Thumbprint
    $expectedServerCertificate.Dispose()

    # 1. Every topology name — including the unregistered negative probe —
    #    resolves wholly to loopback. One non-loopback answer fails the run
    #    before any business test starts.
    foreach ($hostName in ($TrustedHosts + $UnregisteredProbeHost)) {
        $answers = [System.Net.Dns]::GetHostAddresses($hostName)
        if (-not $answers -or $answers.Count -eq 0) {
            throw "joint TLS topology: $hostName returned no DNS answer"
        }
        foreach ($answer in $answers) {
            $isLoopback = (
                $answer.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and
                $answer.GetAddressBytes()[0] -eq 127
            ) -or ($answer.ToString() -eq "::1")
            if (-not $isLoopback) {
                throw "joint TLS topology: $hostName resolved to non-loopback address $answer"
            }
        }
    }

    foreach ($hostName in $TrustedHosts) {
        # 2a. The runner deliberately does not mutate the Windows Root store.
        #     The chain was verified against the exact run CA above; now prove
        #     that this host serves that exact leaf and that its SAN is bound.
        $healthUrl = "https://${hostName}:$TlsPort/health"
        try {
            $response = Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -SkipCertificateCheck -TimeoutSec 10 -ErrorAction Stop
        } catch {
            throw "joint TLS topology: verified HTTPS fetch $healthUrl failed: $($_.Exception.Message)"
        }
        if ($response.StatusCode -ne 200) {
            throw "joint TLS topology: $healthUrl returned HTTP $($response.StatusCode)"
        }

        # 2b. The served certificate must carry this exact host in its SAN.
        $tcp = [System.Net.Sockets.TcpClient]::new()
        try {
            $tcp.Connect($hostName, $TlsPort)
            $acceptAll = { param($sender, $cert, $chain, $errors) return $true }
            $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false, $acceptAll)
            $ssl.AuthenticateAsClient($hostName)
            $remote = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
            if ($remote.Thumbprint -ne $expectedServerThumbprint) {
                throw "joint TLS topology: $hostName served leaf $($remote.Thumbprint), expected $expectedServerThumbprint"
            }
            $san = $remote.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.17" } | Select-Object -First 1
            $sanText = if ($san) { $san.Format($false) } else { "" }
            if ($sanText -notmatch [regex]::Escape($hostName)) {
                throw "joint TLS topology: served certificate SAN '$sanText' does not cover $hostName"
            }
        } finally {
            $tcp.Close()
        }
    }

    # 3. Each service DID's did.jsonl is read over verified HTTPS and its
    #    history is verified independently by cotest-wire (not by the service
    #    that published it).
    foreach ($service in $Services) {
        $did = [string]$service.ServiceDid
        $logUrl = Get-WebvhLogUrlFromDid -Did $did
        $logPath = Join-Path $EvidenceDir "$($service.Name)-did.jsonl"
        try {
            $logResponse = Invoke-WebRequest -Uri $logUrl -UseBasicParsing -SkipCertificateCheck -TimeoutSec 15 -ErrorAction Stop
        } catch {
            throw "joint TLS topology: cannot read $logUrl over HTTPS: $($_.Exception.Message)"
        }
        $logContent = $logResponse.Content
        if ($logContent -is [byte[]]) {
            [System.IO.File]::WriteAllBytes($logPath, $logContent)
        } else {
            [System.IO.File]::WriteAllText($logPath, [string]$logContent, [System.Text.UTF8Encoding]::new($false))
        }
        $verifyInput = [pscustomobject]@{ did = $did; log_path = $logPath; profile = "service" } | ConvertTo-Json -Compress
        $verifyOutput = $verifyInput | & $CotestWireBin "webvh-verify-log" 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "joint TLS topology: history verification failed for $did : $($verifyOutput -join ' ')"
        }
        $verified = $verifyOutput | ConvertFrom-Json
        if (-not $verified.verified) {
            throw "joint TLS topology: cotest-wire did not verify $did"
        }
    }

    # 4a. HTTP downgrade: the proxy terminates TLS only, so a plain-HTTP
    #     request on the same authority must never reach a backend.
    $downgradeUrl = "http://$($TrustedHosts[0]):$TlsPort/health"
    $downgradeRejected = $false
    try {
        $null = Invoke-WebRequest -Uri $downgradeUrl -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    } catch {
        $downgradeRejected = $true
    }
    if (-not $downgradeRejected) {
        throw "joint TLS topology: HTTP downgrade $downgradeUrl unexpectedly succeeded"
    }

    # 4b. An unregistered loopback host has no proxy site and no trust-anchor
    #     entry, even though its DNS answer is loopback.
    $unregisteredUrl = "https://${UnregisteredProbeHost}:$TlsPort/health"
    $unregisteredRejected = $false
    try {
        $null = Invoke-WebRequest -Uri $unregisteredUrl -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    } catch {
        $unregisteredRejected = $true
    }
    if (-not $unregisteredRejected) {
        throw "joint TLS topology: unregistered host $unregisteredUrl unexpectedly succeeded"
    }
    # 4c. A mixed public+loopback DNS answer cannot be staged from the runner
    #     without owning DNS; that rejection is pinned by coauth's
    #     `configured_trusted_hosts_are_the_only_loopback_widening` unit test.

    Write-Host "Joint TLS topology verified: $($TrustedHosts -join ', ') on port $TlsPort"
}

$script:ContainerHostGatewayIpv4 = $null

function Get-ContainerHostGatewayIpv4 {
    if ($script:ContainerHostGatewayIpv4) {
        return $script:ContainerHostGatewayIpv4
    }
    if ($SolandRuntime -ne "docker" -or -not (Get-Command docker -ErrorAction SilentlyContinue)) {
        return $null
    }
    $resolved = & docker run --rm --entrypoint getent `
        --add-host "host.docker.internal:host-gateway" `
        $SolandImage ahostsv4 host.docker.internal 2>$null
    foreach ($line in @($resolved)) {
        if ($line -match '^\s*(\d{1,3}(?:\.\d{1,3}){3})\s') {
            $script:ContainerHostGatewayIpv4 = $Matches[1]
            return $script:ContainerHostGatewayIpv4
        }
    }
    return $null
}

function Convert-ToContainerReachableUrl {
    param([AllowNull()][string]$Url)

    if (-not $Url) {
        return $Url
    }
    try {
        $uri = [System.Uri]$Url
    } catch {
        return $Url
    }
    if ($uri.Host -ne "127.0.0.1" -and $uri.Host -ne "localhost" -and $uri.Host -ne "::1") {
        return $Url
    }

    $builder = [System.UriBuilder]::new($uri)
    $containerHostIpv4 = Get-ContainerHostGatewayIpv4
    $builder.Host = if ($containerHostIpv4) { $containerHostIpv4 } else { "host.docker.internal" }
    return $builder.Uri.AbsoluteUri.TrimEnd("/")
}

function Get-PythonExecutable {
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        return $python.Source
    }
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        return $py.Source
    }
    throw "Python is required to patch generated coauth config"
}

function Get-CargoTargetDirectory {
    param([Parameter(Mandatory = $true)][string]$RepositoryRoot)

    $metadataOutput = $null
    Push-Location $RepositoryRoot
    try {
        $metadataOutput = & cargo metadata --no-deps --format-version 1
        if ($LASTEXITCODE -ne 0) {
            throw "cargo metadata failed for $RepositoryRoot (exit=$LASTEXITCODE)"
        }
    }
    finally {
        Pop-Location
    }
    $metadata = ($metadataOutput -join [Environment]::NewLine) | ConvertFrom-Json
    $targetDirectory = [string]$metadata.target_directory
    if ([string]::IsNullOrWhiteSpace($targetDirectory)) {
        throw "cargo metadata did not return a target directory for $RepositoryRoot"
    }
    return $targetDirectory
}

function Resolve-CoauthBinary {
    param(
        [string]$ExplicitPath,
        [Parameter(Mandatory = $true)][string]$WorkspaceRoot
    )

    $candidates = @()
    if ($ExplicitPath) {
        $candidates += $ExplicitPath
    }
    if ($env:COAUTH_BIN) {
        $candidates += $env:COAUTH_BIN
    }
    $targetDirectory = Get-CargoTargetDirectory -RepositoryRoot (Join-Path $WorkspaceRoot "coauth")
    $candidates += (Join-Path $targetDirectory "debug\coauth.exe")
    $candidates += (Join-Path $targetDirectory "release\coauth.exe")

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) {
            return (Resolve-Path $candidate).Path
        }
    }

    throw "Unable to find coauth binary. Build coauth first or pass -CoauthBin."
}

function Resolve-SolandBinary {
    param(
        [string]$ExplicitPath,
        [Parameter(Mandatory = $true)][string]$WorkspaceRoot
    )

    $candidates = @()
    if ($ExplicitPath) { $candidates += $ExplicitPath }
    if ($env:SOLAND_BIN) { $candidates += $env:SOLAND_BIN }
    $targetDirectory = Get-CargoTargetDirectory -RepositoryRoot (Join-Path $WorkspaceRoot "soland")
    $candidates += (Join-Path $targetDirectory "debug\soland.exe")
    $candidates += (Join-Path $targetDirectory "release\soland.exe")

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) {
            return (Resolve-Path $candidate).Path
        }
    }
    throw "Unable to find soland binary. Build soland first or pass -SolandBin."
}

function Resolve-TeabayBinary {
    param(
        [string]$ExplicitPath,
        [Parameter(Mandatory = $true)][string]$WorkspaceRoot
    )

    $candidates = @()
    if ($ExplicitPath) { $candidates += $ExplicitPath }
    if ($env:TEABAY_BIN) { $candidates += $env:TEABAY_BIN }
    $targetDirectory = Get-CargoTargetDirectory -RepositoryRoot (Join-Path $WorkspaceRoot "teabay")
    $candidates += (Join-Path $targetDirectory "debug\teabay.exe")
    $candidates += (Join-Path $targetDirectory "release\teabay.exe")

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) {
            return (Resolve-Path $candidate).Path
        }
    }
    throw "Unable to find teabay binary. Build teabay first or pass -TeabayBin."
}

function Start-EphemeralPostgres {
    param(
        [Parameter(Mandatory = $true)][string]$Image,
        [Parameter(Mandatory = $true)][string]$NamePrefix,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $null = Get-Command docker -ErrorAction Stop
    $port = Get-FreeTcpPort
    $containerName = "$NamePrefix-pg-$PID"
    $runOutput = Invoke-NativeCapture -FilePath "docker" -Arguments @(
        "run",
        "--rm",
        "-d",
        "--name", $containerName,
        "-e", "POSTGRES_USER=arkret",
        "-e", "POSTGRES_PASSWORD=arkret",
        "-e", "POSTGRES_DB=arkret",
        "-p", "127.0.0.1:$port`:5432",
        $Image
    )
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to start PostgreSQL container: $($runOutput -join "`n")"
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastError = $null
    $stableReadyChecks = 0
    while ((Get-Date) -lt $deadline) {
        $readyOutput = Invoke-NativeCapture -FilePath "docker" -Arguments @("exec", $containerName, "pg_isready", "-U", "arkret", "-d", "arkret")
        if ($LASTEXITCODE -eq 0) {
            $tcp = [System.Net.Sockets.TcpClient]::new()
            try {
                $connect = $tcp.ConnectAsync("127.0.0.1", $port)
                $hostReady = $connect.Wait(1000) -and $tcp.Connected
            } catch {
                $hostReady = $false
                $lastError = $_.Exception.Message
            } finally {
                $tcp.Dispose()
            }
            if ($hostReady) {
                $stableReadyChecks += 1
                if ($stableReadyChecks -ge 2) {
                    return [pscustomobject]@{
                        ContainerName = $containerName
                        HostPort = $port
                        Url = "postgresql://arkret:arkret@127.0.0.1:$port/arkret"
                    }
                }
            } else {
                $stableReadyChecks = 0
            }
        } else {
            $stableReadyChecks = 0
            $lastError = $readyOutput -join "`n"
        }
        Start-Sleep -Milliseconds 500
    }

    & docker rm -f $containerName | Out-Null
    throw "Timed out waiting for PostgreSQL container $containerName. Last error: $lastError"
}

function Stop-EphemeralPostgres {
    param([Parameter(Mandatory = $true)][string]$ContainerName)
    & docker rm -f $ContainerName 2>$null | Out-Null
}

# Dump the ephemeral database so the secret scan can read the durable protocol
# store, not only the logs.
#
# `--column-inserts` because the scan is line-oriented and this form puts one
# row per line with its column list attached. Note that it does NOT produce
# `column = value` adjacency -- the name is in the column list and the value is
# in `VALUES (...)` -- so the field-name detectors match nothing here. That is
# what `sql_private_material_column` exists for: it matches the column list and
# flags the whole statement.
#
# A dump failure is returned to the caller as `$null`. The joint runner records
# that as incomplete durable-store coverage and fails the run: a scan must never
# claim success when a database it was expected to inspect disappeared.
function Export-EphemeralPostgresDump {
    param(
        [Parameter(Mandatory = $true)][string]$ContainerName,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )

    $parent = Split-Path -Parent $OutputPath
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $dump = Invoke-NativeCapture -FilePath "docker" -Arguments @(
        "exec", $ContainerName,
        "pg_dump", "--column-inserts", "--no-owner", "--no-privileges",
        "-U", "arkret", "-d", "arkret"
    )
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "pg_dump of $ContainerName failed; the durable store is not covered by this run's secret scan"
        return $null
    }
    $dump -join [Environment]::NewLine | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    return $OutputPath
}

function New-CoauthJointConfig {
    param(
        [Parameter(Mandatory = $true)][string]$CoauthBinary,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$JointDir,
        [Parameter(Mandatory = $true)][string]$PostgresUrl,
        [Parameter(Mandatory = $true)][string]$CoauthBaseUrl,
        [Parameter(Mandatory = $true)][string]$CoauthBind,
        [Parameter(Mandatory = $true)][string]$CedarPolicyFile,
        # Absent for a browserless lane: with no Inkson served there is no
        # callback origin to register, and `patch-coauth-config.py` keeps the
        # loopback callbacks the non-browser flows use.
        [string]$InksonBaseUrl,
        [string]$InksonServer2BaseUrl,
        [string[]]$InksonBaseUrls = @(),
        [Parameter(Mandatory = $true)][string]$OAuthClientId,
        [Parameter(Mandatory = $true)][string]$SolandBaseUrl,
        [string]$SolandServer2BaseUrl,
        [string[]]$StationBaseUrls = @(),
        [string]$OwningStation = "server1",
        [Parameter(Mandatory = $true)][string]$SessionGrantIntrospectionBearer,
        [Parameter(Mandatory = $true)][string]$EmbeddedWebvhRegistrationBearer,
        [string]$MockEmailBaseUrl
    )

    $rawConfig = Join-Path $JointDir "coauth.raw.yaml"
    [void](New-Item -ItemType Directory -Force -Path $JointDir)
    $configPath = Join-Path $JointDir "coauth.yaml"
    $generateLog = Join-Path $JointDir "coauth-config-generate.log"
    $generateOutput = & $CoauthBinary config generate --dev 2>"$generateLog"
    if ($LASTEXITCODE -ne 0) {
        throw "coauth config generate failed; see $generateLog"
    }
    $generateOutput | Set-Content -Path $rawConfig -Encoding UTF8

    $python = Get-PythonExecutable
    $patcher = Join-Path $RepoRoot "scripts\patch-coauth-config.py"
    $patchArgs = @(
        $patcher,
        $rawConfig,
        $configPath,
        "--postgres-url", $PostgresUrl,
        "--coauth-base-url", $CoauthBaseUrl,
        "--coauth-bind", $CoauthBind,
        "--cedar-policy-file", $CedarPolicyFile,
        "--oauth-client-id", $OAuthClientId,
        "--owning-station", $OwningStation,
        "--session-grant-introspection-bearer", $SessionGrantIntrospectionBearer,
        "--embedded-webvh-registration-bearer", $EmbeddedWebvhRegistrationBearer
    )
    if ($MockEmailBaseUrl) {
        $patchArgs += @("--mock-email-base-url", $MockEmailBaseUrl)
    }
    # Filter before counting: a browserless lane passes an empty
    # `-InksonBaseUrls`, which PowerShell delivers as `$null` rather than an
    # empty array, so `@($null).Count` is 1 and the loop below would emit a
    # `--inkson-base-url` flag with no value.
    $explicitInksonUrls = @($InksonBaseUrls | Where-Object { $_ })
    $resolvedInksonUrls = @(if ($explicitInksonUrls.Count -gt 0) { $explicitInksonUrls } else { @($InksonBaseUrl, $InksonServer2BaseUrl) | Where-Object { $_ } })
    foreach ($url in $resolvedInksonUrls) {
        $patchArgs += @("--inkson-base-url", $url)
    }
    $resolvedStationUrls = @(if (@($StationBaseUrls).Count -gt 0) { @($StationBaseUrls) } else { @($SolandBaseUrl, $SolandServer2BaseUrl) | Where-Object { $_ } })
    for ($index = 0; $index -lt $resolvedStationUrls.Count; $index++) {
        $patchArgs += @("--station", "server$($index + 1)=$($resolvedStationUrls[$index])")
    }
    if ((Split-Path -Leaf $python) -ieq "py.exe") {
        $patchArgs = @("-3") + $patchArgs
    }
    $patchOutput = & $python @patchArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        $patchOutput | Set-Content -Path (Join-Path $JointDir "coauth-config-patch.log") -Encoding UTF8
        throw "coauth config patch failed"
    }

    return (Resolve-Path $configPath).Path
}

function Invoke-CoauthMigrations {
    param(
        [Parameter(Mandatory = $true)][string]$CoauthBinary,
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][string]$LogDirectory,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $migrateLog = Join-Path $LogDirectory "coauth-migrate.log"
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $attempt = 0
    $attemptLogs = [System.Collections.Generic.List[string]]::new()
    while ($true) {
        $attempt++
        $migrateOutput = & $CoauthBinary database migrate -c $ConfigPath --no-env-overrides 2>&1
        $exitCode = $LASTEXITCODE
        $attemptLogs.Add("attempt $attempt (exit $exitCode)")
        foreach ($line in $migrateOutput) {
            $attemptLogs.Add([string]$line)
        }
        if ($exitCode -eq 0) {
            $attemptLogs | Set-Content -Path $migrateLog -Encoding UTF8
            return
        }

        $failureText = $migrateOutput -join "`n"
        $transientConnectionFailure = $failureText -match "(?i)(connection (closed|refused|timed out)|could not connect to server|error communicating with the server|server closed the connection unexpectedly|the database system is starting up)"
        if (-not $transientConnectionFailure -or (Get-Date) -ge $deadline) {
            $attemptLogs | Set-Content -Path $migrateLog -Encoding UTF8
            throw "coauth database migrate failed after $attempt attempt(s); see $migrateLog"
        }
        Start-Sleep -Milliseconds 500
    }
}

function Invoke-CoauthConfigSync {
    param(
        [Parameter(Mandatory = $true)][string]$CoauthBinary,
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][string]$LogDirectory
    )

    $syncLog = Join-Path $LogDirectory "coauth-config-sync.log"
    $syncOutput = & $CoauthBinary config sync -c $ConfigPath --no-env-overrides 2>&1
    $syncOutput | Set-Content -Path $syncLog -Encoding UTF8
    if ($LASTEXITCODE -ne 0) {
        throw "coauth config sync failed; see $syncLog"
    }
}

function Set-CoauthStationServiceIds {
    param(
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$StationServiceIds
    )

    $config = Get-Content -LiteralPath $ConfigPath -Raw
    foreach ($entry in $StationServiceIds.GetEnumerator()) {
        if (-not $entry.Value.StartsWith("ak:did_core:", [System.StringComparison]::Ordinal)) {
            throw "Coauth Station '$($entry.Key)' received an invalid service_id pin"
        }
        $name = [regex]::Escape([string]$entry.Key)
        $pattern = "(?m)(^  - name: $name\r?`n)"
        $replacement = "`${1}    service_id: $($entry.Value)`n"
        $patched = [regex]::Replace($config, $pattern, $replacement, 1)
        if ($patched -eq $config) {
            throw "Could not locate Coauth Station '$($entry.Key)' in $ConfigPath"
        }
        $config = $patched
    }
    # Windows PowerShell 5's `Set-Content -Encoding UTF8` prepends a BOM,
    # while PowerShell 7 does not. Coauth's YAML loader treats that rewritten
    # file as a second document boundary, so keep the runner byte-identical
    # across both hosts and write explicit UTF-8 without BOM.
    [System.IO.File]::WriteAllText(
        $ConfigPath,
        $config,
        [System.Text.UTF8Encoding]::new($false)
    )
}

function Wait-HttpReady {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        $ManagedService = $null
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastError = $null
    while ((Get-Date) -lt $deadline) {
        if ($ManagedService -and $ManagedService.Kind -eq "process" -and $ManagedService.Process.HasExited) {
            throw "Managed service $($ManagedService.Name) exited before readiness; see its service logs"
        }
        try {
            $requestOptions = @{}
            if (([System.Uri]$Url).Scheme -eq "https" -and $env:COTEST_RUN_SCOPED_CA_PEM) {
                $requestOptions.SkipCertificateCheck = $true
            }
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop @requestOptions
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
                return
            }
            $lastError = "HTTP $($response.StatusCode)"
        } catch {
            $lastError = $_.Exception.Message
        }
        Start-Sleep -Milliseconds 500
    }
    throw "Timed out waiting for $Url. Last error: $lastError"
}

function Get-DescribedServiceId {
    param(
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [int]$TimeoutSeconds = 60
    )

    $url = "$($BaseUrl.TrimEnd('/'))/_arkret/describe"
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastError = $null
    while ((Get-Date) -lt $deadline) {
        try {
            $requestOptions = @{}
            if (([System.Uri]$url).Scheme -eq "https" -and $env:COTEST_RUN_SCOPED_CA_PEM) {
                $requestOptions.SkipCertificateCheck = $true
            }
            $requestOptions.Headers = @{
                "Arkret-Operation" = "ak.server.read.describe.v1"
            }
            $describe = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 10 -ErrorAction Stop @requestOptions
            $serviceId = [string]$describe.service_id
            if (-not [string]::IsNullOrWhiteSpace($serviceId) -and $serviceId.StartsWith("ak:did_core:", [System.StringComparison]::Ordinal)) {
                return $serviceId
            }
            $lastError = "response did not contain a valid service_id"
        } catch {
            $lastError = $_.Exception.Message
        }
        Start-Sleep -Milliseconds 500
    }
    throw "Timed out waiting for $ServiceName describe at $url. Last error: $lastError"
}

function Get-DescribedServiceDid {
    param(
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [int]$TimeoutSeconds = 60
    )

    $url = "$($BaseUrl.TrimEnd('/'))/_arkret/describe"
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastError = $null
    while ((Get-Date) -lt $deadline) {
        try {
            $requestOptions = @{}
            if (([System.Uri]$url).Scheme -eq "https" -and $env:COTEST_RUN_SCOPED_CA_PEM) {
                $requestOptions.SkipCertificateCheck = $true
            }
            $requestOptions.Headers = @{
                "Arkret-Operation" = "ak.server.read.describe.v1"
            }
            $describe = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 10 -ErrorAction Stop @requestOptions
            $did = [string]$describe.service_resolution.did
            if (-not [string]::IsNullOrWhiteSpace($did) -and $did.StartsWith("did:", [System.StringComparison]::Ordinal)) {
                return $did
            }
            $lastError = "response did not contain a valid service_resolution.did"
        } catch {
            $lastError = $_.Exception.Message
        }
        Start-Sleep -Milliseconds 500
    }
    throw "Timed out waiting for $ServiceName full service identity at $url. Last error: $lastError"
}

function Assert-CoauthDpopGrantSeamReady {
    param([Parameter(Mandatory = $true)][string]$BaseUrl)

    $url = "$($BaseUrl.TrimEnd('/'))/_coauth/account/test/debug/issue-dpop-grant"
    try {
        # An empty object is intentionally invalid. Any non-404 HTTP response
        # proves the debug-only route is registered; the joint tests create the
        # valid account/device-bound request later.
        $requestOptions = @{}
        if (([System.Uri]$url).Scheme -eq "https" -and $env:COTEST_RUN_SCOPED_CA_PEM) {
            $requestOptions.SkipCertificateCheck = $true
        }
        Invoke-WebRequest `
            -Uri $url `
            -Method Post `
            -ContentType "application/json" `
            -Body "{}" `
            -UseBasicParsing `
            -TimeoutSec 5 `
            -ErrorAction Stop `
            @requestOptions | Out-Null
    } catch {
        $response = $_.Exception.Response
        if ($response -and [int]$response.StatusCode -ne 404) {
            return
        }
        throw "Coauth DPoP grant seam is unavailable at $url. Joint-full requires a debug coauth binary built with the cotest endpoint; release binaries return 404."
    }
}

function Wait-LogContains {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Pattern,
        [string[]]$FailPattern = @(),
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path $Path) {
            $content = Get-Content -Path $Path -Raw -ErrorAction SilentlyContinue
            if ($content) {
                foreach ($candidate in $FailPattern) {
                    if ($content.Contains($candidate)) {
                        throw "Log $Path contains failure pattern '$candidate'"
                    }
                }
                foreach ($candidate in $Pattern) {
                    if ($content.Contains($candidate)) {
                        return
                    }
                }
            }
        }
        Start-Sleep -Milliseconds 500
    }
    throw "Timed out waiting for any log pattern '$($Pattern -join "', '")' in $Path"
}

function Test-DioxusBuildPlaceholder {
    param([AllowNull()][string]$Content)

    if (-not $Content) {
        return $true
    }

    $markers = @(
        "We're building your app now",
        "One sec!",
        "qrcode compiling",
        "image compiling"
    )
    foreach ($marker in $markers) {
        if ($Content.IndexOf($marker, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $true
        }
    }
    return $false
}

function Wait-DioxusAppReady {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastError = $null
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
                if (-not (Test-DioxusBuildPlaceholder -Content $response.Content)) {
                    return
                }
                $lastError = "Dioxus build placeholder still served"
            } else {
                $lastError = "HTTP $($response.StatusCode)"
            }
        } catch {
            $lastError = $_.Exception.Message
        }
        Start-Sleep -Milliseconds 1000
    }
    throw "Timed out waiting for Dioxus app at $Url. Last error: $lastError"
}

function Start-ManagedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$LogDirectory
    )

    $stdout = Join-Path $LogDirectory "$Name.stdout.log"
    $stderr = Join-Path $LogDirectory "$Name.stderr.log"
    $commandLog = Join-Path $LogDirectory "$Name.command.txt"
    $Command | Set-Content -Path $commandLog -Encoding UTF8
    $wrappedCommand = "$Command; `$managedCommandSucceeded = `$?; `$managedCommandExitCode = `$LASTEXITCODE; if (-not `$managedCommandSucceeded) { if (`$null -ne `$managedCommandExitCode -and `$managedCommandExitCode -ne 0) { exit `$managedCommandExitCode }; exit 1 }; exit 0"
    $process = Start-Process `
        -FilePath "powershell" `
        -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $wrappedCommand) `
        -WorkingDirectory $WorkingDirectory `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -WindowStyle Hidden `
        -PassThru

    [pscustomobject]@{
        Kind = "process"
        Name = $Name
        Process = $process
        WorkingDirectory = [System.IO.Path]::GetFullPath($WorkingDirectory)
        Stdout = $stdout
        Stderr = $stderr
        CommandLog = $commandLog
    }
}

function Get-CargoLockPackageVersion {
    param(
        [Parameter(Mandatory = $true)][string]$CargoLockPath,
        [Parameter(Mandatory = $true)][string]$PackageName
    )

    if (-not (Test-Path $CargoLockPath)) {
        return $null
    }

    $inPackage = $false
    $name = $null
    foreach ($line in Get-Content -Path $CargoLockPath) {
        if ($line -eq "[[package]]") {
            $inPackage = $true
            $name = $null
            continue
        }
        if (-not $inPackage) {
            continue
        }
        if ($line -match '^name = "([^"]+)"') {
            $name = $Matches[1]
            continue
        }
        if ($line -match '^version = "([^"]+)"') {
            if ($name -eq $PackageName) {
                return $Matches[1]
            }
            continue
        }
    }

    return $null
}

function Get-DioxusNoDownloadsPathPrefix {
    param(
        [string]$ProjectRoot
    )

    $dxHome = if ($env:DX_HOME) { $env:DX_HOME } else { Join-Path $HOME ".dx" }
    $toolsRoot = Join-Path $dxHome "tools"
    $segments = @()

    if (Test-Path $toolsRoot) {
        $preferredWasmBindgenDir = $null
        if ($ProjectRoot) {
            $wasmBindgenVersion = Get-CargoLockPackageVersion `
                -CargoLockPath (Join-Path $ProjectRoot "Cargo.lock") `
                -PackageName "wasm-bindgen"
            if ($wasmBindgenVersion) {
                $candidate = Join-Path $toolsRoot "wasm-bindgen-$wasmBindgenVersion"
                if (Test-Path $candidate) {
                    $preferredWasmBindgenDir = (Resolve-Path $candidate).Path
                    $segments += $preferredWasmBindgenDir
                }
            }
        }

        $segments += Get-ChildItem -Path $toolsRoot -Directory -Filter "wasm-bindgen-*" -ErrorAction SilentlyContinue |
            Sort-Object -Property Name -Descending |
            ForEach-Object { $_.FullName } |
            Where-Object { -not $preferredWasmBindgenDir -or $_ -ne $preferredWasmBindgenDir }
        $segments += Get-ChildItem -Path $toolsRoot -Directory -Filter "esbuild-*" -ErrorAction SilentlyContinue |
            Sort-Object -Property Name -Descending |
            ForEach-Object { $_.FullName }
        $segments += Get-ChildItem -Path $toolsRoot -Directory -Filter "binaryen-*" -ErrorAction SilentlyContinue |
            Sort-Object -Property Name -Descending |
            ForEach-Object { Join-Path $_.FullName "bin" }
    }

    $cargoBin = Join-Path $HOME ".cargo\bin"
    if (Test-Path $cargoBin) {
        $segments += $cargoBin
    }

    $existing = @($segments | Where-Object { $_ -and (Test-Path $_) })
    return ($existing -join [System.IO.Path]::PathSeparator)
}

function Add-DioxusNoDownloadsEnvironment {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [string]$ProjectRoot
    )

    $pathPrefix = Get-DioxusNoDownloadsPathPrefix -ProjectRoot $ProjectRoot
    $prefix = "`$env:NO_DOWNLOADS='1'; "
    if ($pathPrefix) {
        $escapedPathPrefix = $pathPrefix.Replace("'", "''")
        $prefix += "`$env:PATH='$escapedPathPrefix' + [System.IO.Path]::PathSeparator + `$env:PATH; "
    }
    return "$prefix$Command"
}

function Start-ManagedDockerSoland {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Image,
        [Parameter(Mandatory = $true)][int]$HostPort,
        [Parameter(Mandatory = $true)][int]$ContainerPort,
        [Parameter(Mandatory = $true)][string]$ObjectsRoot,
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][string]$LogDirectory,
        [Parameter(Mandatory = $true)]$Environment
    )

    $null = New-Item -ItemType Directory -Force -Path $ObjectsRoot
    $null = New-Item -ItemType Directory -Force -Path $StateRoot
    $null = New-Item -ItemType Directory -Force -Path $LogDirectory

    $safeName = ($Name.ToLowerInvariant() -replace '[^a-z0-9_.-]', '-')
    $containerName = "cotest-joint-$safeName-$PID-$([Guid]::NewGuid().ToString('n').Substring(0, 8))"
    $stdout = Join-Path $LogDirectory "$Name.stdout.log"
    $stderr = Join-Path $LogDirectory "$Name.stderr.log"
    $commandLog = Join-Path $LogDirectory "$Name.command.txt"

    $runArgs = @(
        "run",
        "-d",
        "--name", $containerName,
        "--label", "cotest.runner=joint-e2e",
        "--add-host", "host.docker.internal:host-gateway",
        "-p", ("127.0.0.1:{0}:{1}" -f $HostPort, $ContainerPort),
        "-v", ("{0}:/tmp/soland-blobs" -f $ObjectsRoot),
        "-v", ("{0}:/tmp/soland-state" -f $StateRoot),
        "-v", ("{0}:/cotest-logs" -f $LogDirectory)
    )
    foreach ($key in $Environment.Keys) {
        $value = [string]$Environment[$key]
        $runArgs += @("-e", "$key=$value")
    }
    $runArgs += @($Image, "--bind", ("0.0.0.0:{0}" -f $ContainerPort))

    ("docker " + ($runArgs -join " ")) | Set-Content -Path $commandLog -Encoding UTF8
    $runOutput = Invoke-NativeCapture -FilePath "docker" -Arguments $runArgs
    $runOutput | Set-Content -Path $stdout -Encoding UTF8
    "" | Set-Content -Path $stderr -Encoding UTF8
    if ($LASTEXITCODE -ne 0) {
        throw "docker run failed for $Name; see $stdout"
    }

    [pscustomobject]@{
        Kind = "docker"
        Name = $Name
        ContainerName = $containerName
        Stdout = $stdout
        Stderr = $stderr
        CommandLog = $commandLog
    }
}

function Stop-ManagedCommand {
    param([Parameter(Mandatory = $true)]$Service)

    if (($Service.PSObject.Properties.Name -contains "Kind") -and $Service.Kind -eq "docker") {
        $logs = Invoke-NativeCapture -FilePath "docker" -Arguments @("logs", $Service.ContainerName)
        $logs | Set-Content -Path $Service.Stdout -Encoding UTF8
        "" | Set-Content -Path $Service.Stderr -Encoding UTF8
        & docker rm -f $Service.ContainerName 2>$null | Out-Null
        return
    }

    if (-not $Service.Process.HasExited) {
        Stop-ProcessTree -ProcessId $Service.Process.Id
        $Service.Process.WaitForExit()
    }
}

function Get-ManagedServiceRuntimePanic {
    param([Parameter(Mandatory = $true)]$Service)

    $panicPattern = "(?i)(thread\s+['""][^'""]+['""]\s+panicked\s+at|panicked with message|fatal runtime error|overflowed its stack|stack overflow|STATUS_STACK_OVERFLOW|0xc00000fd)"
    foreach ($property in @("Stderr", "Stdout")) {
        if (-not ($Service.PSObject.Properties.Name -contains $property)) {
            continue
        }
        $path = [string]$Service.$property
        if (-not $path -or -not (Test-Path -LiteralPath $path)) {
            continue
        }
        $match = Select-String `
            -LiteralPath $path `
            -Pattern $panicPattern `
            -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($match) {
            $line = $match.Line.Trim()
            if ($line.Length -gt 280) {
                $line = $line.Substring(0, 280) + "..."
            }
            return [pscustomobject]@{
                path = $path
                line_number = $match.LineNumber
                line = $line
            }
        }
    }
    return $null
}

function Get-ManagedServiceFailures {
    param([Parameter(Mandatory = $true)]$Services)

    $failures = New-Object System.Collections.Generic.List[object]
    foreach ($service in $Services) {
        if ($service.Kind -eq "docker") {
            $stateOutput = @(Invoke-NativeCapture -FilePath "docker" -Arguments @(
                    "inspect", "--format", "{{.State.Running}}|{{.State.ExitCode}}", $service.ContainerName
                ))
            $inspectExitCode = $LASTEXITCODE
            $state = ($stateOutput -join "").Trim()
            if ($inspectExitCode -ne 0) {
                $failures.Add([pscustomobject]@{
                        name = $service.Name
                        kind = $service.Kind
                        exit_code = $null
                        detail = "container missing or inspect failed: $state"
                        stdout = $service.Stdout
                        stderr = $service.Stderr
                    }) | Out-Null
                continue
            }
            $parts = $state -split "\|", 2
            if ($parts[0] -ne "true") {
                $failures.Add([pscustomobject]@{
                        name = $service.Name
                        kind = $service.Kind
                        exit_code = if ($parts.Count -gt 1) { [int]$parts[1] } else { $null }
                        detail = "container exited before test completion"
                        stdout = $service.Stdout
                        stderr = $service.Stderr
                    }) | Out-Null
                continue
            }
            $logs = @(Invoke-NativeCapture -FilePath "docker" -Arguments @(
                    "logs", $service.ContainerName
                ))
            if ($LASTEXITCODE -eq 0) {
                $logs | Set-Content -Path $service.Stdout -Encoding UTF8
            }
        } else {
            $service.Process.Refresh()
            if ($service.Process.HasExited) {
                $service.Process.WaitForExit()
                $failures.Add([pscustomobject]@{
                        name = $service.Name
                        kind = $service.Kind
                        exit_code = $service.Process.ExitCode
                        detail = "process exited before test completion"
                        stdout = $service.Stdout
                        stderr = $service.Stderr
                    }) | Out-Null
                continue
            }
        }

        $panic = Get-ManagedServiceRuntimePanic -Service $service
        if ($panic) {
            $failures.Add([pscustomobject]@{
                    name = $service.Name
                    kind = $service.Kind
                    exit_code = $null
                    detail = "runtime panic in $($panic.path):L$($panic.line_number): $($panic.line)"
                    stdout = $service.Stdout
                    stderr = $service.Stderr
                }) | Out-Null
        }
    }
    return $failures.ToArray()
}

function Get-JointTopologyHealthFailures {
    param(
        [Parameter(Mandatory = $true)][string]$TopologyPath,
        [Parameter(Mandatory = $true)]$ManagedServices
    )

    if (-not (Test-Path -LiteralPath $TopologyPath -PathType Leaf)) {
        return @()
    }

    $managedNames = @{}
    foreach ($service in $ManagedServices) {
        $managedNames[[string]$service.Name] = $service
    }

    $failures = [System.Collections.Generic.List[object]]::new()
    $topology = Get-Content -Raw -LiteralPath $TopologyPath | ConvertFrom-Json
    foreach ($server in @($topology.servers)) {
        foreach ($kind in @("soland", "coauth")) {
            $serviceProperty = $server.PSObject.Properties[$kind]
            if (-not $serviceProperty -or -not $serviceProperty.Value) { continue }

            $name = "$kind-$($server.name)"
            if (-not $managedNames.ContainsKey($name)) { continue }

            $baseUrl = [string]$serviceProperty.Value.public_url
            if ([string]::IsNullOrWhiteSpace($baseUrl)) { continue }

            $healthy = $false
            try {
                $requestOptions = @{}
                if (([System.Uri]$baseUrl).Scheme -eq "https") {
                    $requestOptions.SkipCertificateCheck = $true
                }
                $response = Invoke-WebRequest `
                    -Uri "$($baseUrl.TrimEnd('/'))/health" `
                    -UseBasicParsing `
                    -TimeoutSec 5 `
                    -ErrorAction Stop `
                    @requestOptions
                $healthy = $response.StatusCode -ge 200 -and $response.StatusCode -lt 300
            }
            catch {
                $healthy = $false
            }

            if (-not $healthy) {
                $managed = $managedNames[$name]
                $failures.Add([pscustomobject]@{
                        name = $name
                        kind = $managed.Kind
                        exit_code = $null
                        detail = "managed service health endpoint was unavailable after test execution"
                        stdout = $managed.Stdout
                        stderr = $managed.Stderr
                    }) | Out-Null
            }
        }
    }
    return $failures.ToArray()
}

function Write-ManagedServiceFailureReport {
    param(
        [Parameter(Mandatory = $true)]$Failures,
        [Parameter(Mandatory = $true)][string]$JsonPath,
        [Parameter(Mandatory = $true)][string]$MarkdownPath
    )

    ConvertTo-Json -InputObject @($Failures) -Depth 4 |
        Set-Content -Path $JsonPath -Encoding UTF8

    $lines = @("# managed service failures", "")
    if (@($Failures).Count -eq 0) {
        $lines += "- none"
    } else {
        foreach ($failure in $Failures) {
            $exitCode = if ($null -eq $failure.exit_code) { "unknown" } else { [string]$failure.exit_code }
            $lines += "- $($failure.name) ($($failure.kind)): exit=$exitCode; $($failure.detail); stdout=$($failure.stdout); stderr=$($failure.stderr)"
        }
    }
    $lines | Set-Content -Path $MarkdownPath -Encoding UTF8
}

function Stop-ProcessTree {
    param([Parameter(Mandatory = $true)][int]$ProcessId)

    $children = Get-CimInstance Win32_Process -Filter "ParentProcessId = $ProcessId" -ErrorAction SilentlyContinue
    foreach ($child in $children) {
        Stop-ProcessTree -ProcessId $child.ProcessId
    }
    Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
}

function Open-ExclusiveRunnerLock {
    param([Parameter(Mandatory = $true)][string]$Path)

    $lockPath = [System.IO.Path]::GetFullPath($Path)
    $lockParent = Split-Path -Parent $lockPath
    $null = New-Item -ItemType Directory -Path $lockParent -Force
    try {
        $stream = [System.IO.File]::Open(
            $lockPath,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None
        )
    }
    catch [System.IO.IOException] {
        throw "another joint-e2e runner owns the shared workspace build outputs (lock: $lockPath)"
    }

    $owner = [System.Text.Encoding]::UTF8.GetBytes(
        "pid=$PID started_at=$([DateTimeOffset]::Now.ToString('O'))"
    )
    $stream.SetLength(0)
    $stream.Write($owner, 0, $owner.Length)
    $stream.Flush()
    return $stream
}

function Invoke-RunnerSelfTest {
    $repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
    $tempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    $tempRoot = Join-Path $tempBase "cotest-runner-self-test-$PID"
    $null = New-Item -ItemType Directory -Path $tempRoot -Force
    $binaryPath = Join-Path $tempRoot "fixture.exe"
    $null = New-Item -ItemType File -Path $binaryPath -Force
    $runningProcess = $null
    $firstRunnerLock = $null

    try {
        $runnerLockPath = Join-Path $tempRoot "joint-e2e-run.lock"
        $firstRunnerLock = Open-ExclusiveRunnerLock -Path $runnerLockPath
        $secondRunnerRejected = $false
        try {
            $secondRunnerLock = Open-ExclusiveRunnerLock -Path $runnerLockPath
            $secondRunnerLock.Dispose()
        }
        catch {
            $secondRunnerRejected =
                $_.Exception.Message -like "another joint-e2e runner owns*"
        }
        if (-not $secondRunnerRejected) {
            throw "runner lock self-test allowed a second workspace owner"
        }

        $tlsAssets = New-JointTlsAssets `
            -Directory (Join-Path $tempRoot "tls") `
            -DnsNames @("self-test.local.host") `
            -RunLabel "self-test"
        if (-not (Test-Path -LiteralPath $tlsAssets.CaPemPath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $tlsAssets.ServerPemPath -PathType Leaf) -or
            -not $tlsAssets.ServerSpkiSha256) {
            throw "joint TLS asset self-test did not mint a CA and server certificate"
        }

        (Get-Item -LiteralPath $binaryPath).LastWriteTimeUtc = [DateTime]::UtcNow.AddYears(-10)
        $staleResults = New-Object System.Collections.Generic.List[object]
        Add-BinaryFreshnessPreflight `
            -Results $staleResults `
            -Name "fixture freshness" `
            -BinaryPath $binaryPath `
            -RepositoryRoots @($repositoryRoot)
        if ($staleResults.Count -ne 1 -or $staleResults[0].status -ne "fail") {
            throw "stale binary self-test did not fail"
        }

        (Get-Item -LiteralPath $binaryPath).LastWriteTimeUtc = [DateTime]::UtcNow.AddDays(1)
        $freshRepositoryStates = @(
            Get-RepositoryBuildInputState `
                -RepositoryRoot $repositoryRoot `
                -BinaryPath $binaryPath
        )
        Write-ArtifactBuildStamp `
            -ArtifactPath $binaryPath `
            -RepositoryStates $freshRepositoryStates | Out-Null
        $freshResults = New-Object System.Collections.Generic.List[object]
        Add-BinaryFreshnessPreflight `
            -Results $freshResults `
            -Name "fixture freshness" `
            -BinaryPath $binaryPath `
            -RepositoryRoots @($repositoryRoot)
        if ($freshResults.Count -ne 1 -or $freshResults[0].status -ne "pass") {
            throw "fresh binary self-test did not pass: $($freshResults | ConvertTo-Json -Compress)"
        }

        $exitedProcess = Start-Process `
            -FilePath "powershell" `
            -ArgumentList @("-NoProfile", "-Command", "exit 23") `
            -WindowStyle Hidden `
            -PassThru
        $exitedProcess.WaitForExit()
        $exitedService = [pscustomobject]@{
            Kind = "process"
            Name = "self-test-exited"
            Process = $exitedProcess
            Stdout = Join-Path $tempRoot "exited.stdout.log"
            Stderr = Join-Path $tempRoot "exited.stderr.log"
        }
        $failures = @(Get-ManagedServiceFailures -Services @($exitedService))
        if ($failures.Count -ne 1 -or $failures[0].exit_code -ne 23) {
            throw "managed service exit self-test did not preserve exit code 23"
        }

        $wrappedFailure = Start-ManagedCommand `
            -Name "self-test-native-failure" `
            -Command "cmd /c exit 29" `
            -WorkingDirectory $tempRoot `
            -LogDirectory $tempRoot
        $wrappedFailure.Process.WaitForExit()
        $wrappedFailure.Process.Refresh()
        if ($wrappedFailure.Process.ExitCode -ne 29) {
            throw "managed command wrapper lost native exit code 29"
        }

        $failureJson = Join-Path $tempRoot "managed-service-failures.json"
        $failureMarkdown = Join-Path $tempRoot "managed-service-failures.md"
        Write-ManagedServiceFailureReport `
            -Failures $failures `
            -JsonPath $failureJson `
            -MarkdownPath $failureMarkdown
        $reported = @(Get-Content -Raw -LiteralPath $failureJson | ConvertFrom-Json)
        if ($reported.Count -ne 1 -or $reported[0].name -ne "self-test-exited" -or
            $reported[0].exit_code -ne 23) {
            throw "managed service failure report self-test failed"
        }

        $runningProcess = Start-Process `
            -FilePath "powershell" `
            -ArgumentList @("-NoProfile", "-Command", "Start-Sleep -Seconds 30") `
            -WindowStyle Hidden `
            -PassThru
        $runningService = [pscustomobject]@{
            Kind = "process"
            Name = "self-test-running"
            Process = $runningProcess
            Stdout = Join-Path $tempRoot "running.stdout.log"
            Stderr = Join-Path $tempRoot "running.stderr.log"
        }
        if (@(Get-ManagedServiceFailures -Services @($runningService)).Count -ne 0) {
            throw "running managed service was incorrectly classified as failed"
        }
        "thread 'tokio-rt-worker' panicked at fixture.rs:1:1:" |
            Set-Content -LiteralPath $runningService.Stderr -Encoding UTF8
        $panicFailures = @(Get-ManagedServiceFailures -Services @($runningService))
        if ($panicFailures.Count -ne 1 -or
            $panicFailures[0].detail -notmatch "runtime panic") {
            throw "managed service runtime panic self-test was not classified as failed"
        }
        "thread 'tokio-runtime-worker' has overflowed its stack`nerror: process exited with 0xc00000fd, STATUS_STACK_OVERFLOW" |
            Set-Content -LiteralPath $runningService.Stderr -Encoding UTF8
        $stackFailures = @(Get-ManagedServiceFailures -Services @($runningService))
        if ($stackFailures.Count -ne 1 -or
            $stackFailures[0].detail -notmatch "overflowed its stack") {
            throw "managed service stack overflow self-test was not classified as failed"
        }

        $eventPlaneGate = Join-Path $PSScriptRoot "tests\event-plane-classification.tests.ps1"
        $gateWorkspaceRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
        & (Get-Process -Id $PID).Path `
            -NoProfile `
            -ExecutionPolicy Bypass `
            -File $eventPlaneGate `
            -WorkspaceRoot $gateWorkspaceRoot
        if ($LASTEXITCODE -ne 0) {
            throw "Event plane classification gate failed"
        }

        Write-Host "Joint E2E runner self-test passed."
    }
    finally {
        if ($firstRunnerLock) {
            $firstRunnerLock.Dispose()
        }
        if ($runningProcess -and -not $runningProcess.HasExited) {
            Stop-Process -Id $runningProcess.Id -Force -ErrorAction SilentlyContinue
            $runningProcess.WaitForExit()
        }
        $resolvedTempRoot = [System.IO.Path]::GetFullPath($tempRoot)
        if ($resolvedTempRoot.StartsWith($tempBase, [System.StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $resolvedTempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

if ($RunnerSelfTest) {
    Invoke-RunnerSelfTest
    exit 0
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$workspaceRoot = (Resolve-Path (Join-Path $repoRoot "..")).Path
$requiresDocker = (
    ($StartCoauth -and -not $CoauthPostgresUrl) -or
    ((-not $SolandBaseUrl -and -not $SolandCommand -and -not $SolandDatabaseUrl)) -or
    $SolandRuntime -eq "docker"
)
# Decide the Playwright selection, and with it whether this run needs Inkson at
# all, before anything else happens — before the manifest gates below, before
# the environment probe, before the exclusive runner lock. A contradictory
# selection (`joint-api` mixed with a browser project, an unknown project name,
# Inkson arguments passed to a browserless lane) is a caller mistake that should
# report itself immediately rather than after taking a lock another run is
# waiting on. Every Inkson-shaped step further down is guarded by
# `$requiresInkson`.
$playwrightProjects = Resolve-PlaywrightProjects `
    -RunProfile $RunProfile `
    -PlaywrightProject $PlaywrightProject `
    -PlaywrightProjectWasExplicit ($PSBoundParameters.ContainsKey("PlaywrightProject"))
$inksonArguments = @{}
foreach ($name in "InksonRoot", "InksonBaseUrl", "InksonServer2BaseUrl", "InksonCommand", "InksonServer2Command") {
    if ($PSBoundParameters.ContainsKey($name)) {
        $inksonArguments[$name] = $PSBoundParameters[$name]
    }
}
$requiresInkson = Resolve-InksonRequirement `
    -PlaywrightProjects $playwrightProjects `
    -RunProfile $RunProfile `
    -InksonArguments $inksonArguments

# Three manifest gates, run before anything expensive.
#
# All three already existed and none was wired into a lane anyone runs, which is
# exactly how they went red unnoticed: a spec rename on 2026-09-06 left
# `check_api_only_migration.py` failing across four commits, the same rename
# aborted a joint run at the evidence-manifest check after a full Inkson wasm
# build, and `generate-scenario-evidence.ps1 -Check` had been stale long enough
# that `federation/three-server-p0` was recorded without the wire oracle it
# actually uses. `api-only-migration.json` is now also the `joint-api` project's
# file list, so a stale entry there selects the wrong specs rather than merely
# misreporting. Running them here costs seconds and fails before any build.
#
# The evidence manifest is checked here rather than only at the reporting step
# far below: that check is pure static source plus JSON, so paying for service
# startup and a whole Playwright run before it fires buys nothing.
$offlineGateFailures = @()
$apiOnlyGateOutput = & (Get-PythonExecutable) (Join-Path $PSScriptRoot "check_api_only_migration.py") 2>&1
if ($LASTEXITCODE -ne 0) {
    $offlineGateFailures += "check_api_only_migration.py: $($apiOnlyGateOutput -join ' ')"
}
$coverageGateOutput = & (Get-Process -Id $PID).Path @(
    "-NoProfile",
    "-File", (Join-Path $PSScriptRoot "generate-e2e-coverage.ps1"),
    "-Check"
) 2>&1
if ($LASTEXITCODE -ne 0) {
    $offlineGateFailures += "generate-e2e-coverage.ps1 -Check: $($coverageGateOutput -join ' ')"
}
$evidenceGateOutput = & (Get-Process -Id $PID).Path @(
    "-NoProfile",
    "-File", (Join-Path $PSScriptRoot "generate-scenario-evidence.ps1"),
    "-Check"
) 2>&1
if ($LASTEXITCODE -ne 0) {
    $offlineGateFailures += "generate-scenario-evidence.ps1 -Check: $($evidenceGateOutput -join ' ')"
}
if ($offlineGateFailures.Count -gt 0) {
    throw ("offline manifest gates failed before any build:{0}{1}" -f
        [Environment]::NewLine, ($offlineGateFailures -join [Environment]::NewLine))
}

$environmentOutputDirectory = if ($JointDir) {
    Join-Path ([System.IO.Path]::GetFullPath($JointDir)) "environment"
} else {
    $environmentRoot = if ($OutputRoot) { [System.IO.Path]::GetFullPath($OutputRoot) } else { Join-Path $repoRoot "artifacts" }
    Join-Path $environmentRoot ("environment\" + (Get-Date -Format "yyyyMMdd-HHmmss"))
}
$environmentArgs = @(
    "-NoProfile",
    "-File", (Join-Path $PSScriptRoot "initialize-joint-e2e-environment.ps1"),
    "-ServerCount", "$ServerCount",
    "-OutputDirectory", $environmentOutputDirectory,
    "-PostgresImage"
)
$environmentPostgresImages = @($SolandPostgresImage, $CoauthPostgresImage) | Sort-Object -Unique
$environmentArgs += $environmentPostgresImages
if ($StartCoauth) { $environmentArgs += "-StartCoauth" }
if ($requiresDocker) { $environmentArgs += "-RequireDocker" }
& (Get-Process -Id $PID).Path @environmentArgs
$environmentExit = $LASTEXITCODE
if ($environmentExit -ne 0) {
    Write-Host "Joint E2E stopped before preparation or service startup. Environment report: $environmentOutputDirectory"
    exit $environmentExit
}
if ($IsWindows) {
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:PATH = @($machinePath, $userPath) | Where-Object { $_ } | Join-String -Separator ";"
}

$jointRunnerLock = Open-ExclusiveRunnerLock `
    -Path (Join-Path $repoRoot "artifacts\.joint-e2e-run.lock")
if (-not $OutputRoot) {
    $OutputRoot = Join-Path $repoRoot "artifacts"
}
$OutputRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputRoot)
if (-not $SutManifest) {
    $SutManifest = Join-Path $workspaceRoot "soland\Cargo.toml"
}
$SutManifest = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($SutManifest)
$inksonTargetDirectory = $null
if ($requiresInkson) {
    if (-not $InksonRoot) {
        $InksonRoot = Join-Path $workspaceRoot "inkson"
    }
    $InksonRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($InksonRoot)
    $inksonTargetDirectory = Get-CargoTargetDirectory -RepositoryRoot $InksonRoot
}
$cotestTargetDirectory = Get-CargoTargetDirectory -RepositoryRoot $repoRoot
$solandTargetDirectory = Get-CargoTargetDirectory -RepositoryRoot (Split-Path -Parent $SutManifest)
$coauthTargetDirectory = Get-CargoTargetDirectory -RepositoryRoot (Join-Path $workspaceRoot "coauth")
if (-not $SavfoxRoot) {
    $SavfoxRoot = Join-Path (Split-Path -Parent $workspaceRoot) "savfox-ai\savfox"
}
$SavfoxRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($SavfoxRoot)

# Canonical artifacts layout (see cotest/README.md "Artifacts layout"):
#   <OutputRoot>/runs/joint-e2e/<timestamp>-<profile>/ — authoritative outputs
#   <OutputRoot>/latest/joint-e2e/                     — latest non-targeted suite
# With -JointDir the caller owns the run directory and both are skipped.
function Get-JointServerArtifactLayout {
    param(
        [Parameter(Mandatory = $true)][string]$JointDirectory,
        [Parameter(Mandatory = $true)][ValidatePattern('^server[1-9][0-9]*$')][string]$ServerName
    )

    $solandName = "soland-$ServerName"
    return [pscustomobject]@{
        ServerName = $ServerName
        CoauthDirectory = Join-Path $JointDirectory "coauth-$ServerName"
        SolandConfigPath = Join-Path $JointDirectory "$solandName.env"
        SolandObjectsRoot = Join-Path $JointDirectory "$solandName-objects"
        SolandStateRoot = Join-Path $JointDirectory "$solandName-state"
        SolandChaosControlPath = Join-Path $JointDirectory "$solandName-decision-chaos.json"
        CoauthStoreDumpName = "coauth-$ServerName-postgres.sql"
        SolandStoreDumpName = "$solandName-postgres.sql"
    }
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
if ($JointDir) {
    $jointDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($JointDir)
} else {
    $jointRunLabel = if ($RunProfile) { $RunProfile } else { "custom" }
    if ($Grep) {
        $jointRunLabel += "-selection"
    } elseif ($PreflightOnly) {
        $jointRunLabel += "-preflight"
    }
    $jointDir = New-ArtifactRunDirectory `
        -OutputRoot $OutputRoot `
        -Family "joint-e2e" `
        -Label $jointRunLabel `
        -Timestamp $timestamp
    Remove-StaleArtifactRuns -OutputRoot $OutputRoot -Family "joint-e2e" -KeepRuns $KeepRuns
}
$serviceLogDir = Join-Path $jointDir "services"
$screenshotDir = Join-Path $jointDir "screenshots"
$visualBaselineDir = Join-Path $jointDir "visual-baselines"
$null = New-Item -ItemType Directory -Force -Path $serviceLogDir
$null = New-Item -ItemType Directory -Force -Path $screenshotDir
$null = New-Item -ItemType Directory -Force -Path $visualBaselineDir
$serverServiceLogDirs = @{}
$serverArtifactLayouts = @{}
for ($serverIndex = 1; $serverIndex -le $ServerCount; $serverIndex++) {
    $serverName = "server$serverIndex"
    $serverServiceLogDirs[$serverName] = Join-Path $serviceLogDir $serverName
    $serverArtifactLayouts[$serverName] = Get-JointServerArtifactLayout -JointDirectory $jointDir -ServerName $serverName
    $null = New-Item -ItemType Directory -Force -Path $serverServiceLogDirs[$serverName]
}
$solandChaosControlFile = $serverArtifactLayouts["server1"].SolandChaosControlPath

# 0530-C: decide the public-identity topology before any base URL is minted.
# Runner-owned process-mode services keep plain loopback listeners but publish
# stable HTTPS names fronted by the managed TLS proxy; caller-owned or
# docker-runtime lanes keep their existing URLs unchanged.
$jointTlsProcessSoland = (-not $SolandCommand -and -not $SolandBaseUrl -and $SolandRuntime -eq "process")
$jointTlsCoauth = ($StartCoauth -and -not $CoauthBaseUrl)
$jointTlsEnabled = $jointTlsProcessSoland -or $jointTlsCoauth
$jointTlsPort = $null
$solandPublicHost = $null
$solandServer2PublicHost = $null
$coauthPublicHost = $null
$coauthServer2PublicHost = $null
$jointTlsAssets = $null
$jointTlsHostNames = @()
$jointTlsHostsMarker = New-CotestHostsMarker -RunId $timestamp
$jointTlsUnregisteredProbeHost = "unregistered.local.host"
if ($jointTlsEnabled) {
    $jointTlsPort = Get-FreeTcpPort
    if ($jointTlsProcessSoland) {
        $solandPublicHost = "soland-server1.local.host"
        if ($multiServer) {
            $solandServer2PublicHost = "soland-server2.local.host"
        }
    }
    if ($jointTlsCoauth) {
        $coauthPublicHost = "coauth-server1.local.host"
        if ($multiServer) { $coauthServer2PublicHost = "coauth-server2.local.host" }
    }
}

if (-not $SolandBaseUrl) {
    $solandPort = Get-FreeTcpPort
    if ($solandPublicHost) {
        $SolandBaseUrl = "https://${solandPublicHost}:$jointTlsPort"
    } else {
        $SolandBaseUrl = "http://127.0.0.1:$solandPort"
    }
} else {
    $solandPort = $null
}
$solandServer2Port = $null
$solandServer2BaseUrl = $null
if ($multiServer) {
    if ($SolandCommand) {
        throw "Multi-server runs are incompatible with -SolandCommand; use the indexed topology interface."
    }
    $solandServer2Port = Get-FreeTcpPort
    if ($solandServer2PublicHost) {
        $solandServer2BaseUrl = "https://${solandServer2PublicHost}:$jointTlsPort"
    } else {
        $solandServer2BaseUrl = "http://127.0.0.1:$solandServer2Port"
    }
}
if ($SolandRuntime -eq "docker" -and $SolandCommand) {
    throw "-SolandRuntime docker is incompatible with -SolandCommand; omit -SolandCommand so the harness can start the image."
}
if ($SolandDatabaseUrl -and ($SolandRuntime -ne "process" -or $SolandCommand -or -not $solandPort)) {
    throw "-SolandDatabaseUrl is supported only when the harness owns one process-mode Soland."
}
if ($SolandDatabaseUrl -and $multiServer) {
    throw "-SolandDatabaseUrl cannot be shared by a multi-server run; use isolated runner-owned databases."
}
$inksonPort = $null
if ($requiresInkson -and -not $InksonBaseUrl) {
    $inksonPort = Get-FreeTcpPort
    $InksonBaseUrl = "http://127.0.0.1:$inksonPort"
}
$inksonServer2Port = $null
$inksonServer2BaseUrl = $null
$inksonBaseUrlWasExplicit = $PSBoundParameters.ContainsKey("InksonBaseUrl")
if ($multiServer -and $requiresInkson) {
    if ($InksonServer2BaseUrl) {
        $inksonServer2BaseUrl = $InksonServer2BaseUrl
    } elseif ($InksonServer2Command) {
        throw "-InksonServer2Command requires -InksonServer2BaseUrl so the harness can route browser contexts."
    } elseif ($InksonCommand -or $inksonBaseUrlWasExplicit) {
        $inksonServer2BaseUrl = $InksonBaseUrl
    } else {
        $inksonServer2Port = Get-FreeTcpPort
        $inksonServer2BaseUrl = "http://127.0.0.1:$inksonServer2Port"
    }
}

function Get-RelativePathCompat {
    param(
        [Parameter(Mandatory = $true)][string]$BasePath,
        [Parameter(Mandatory = $true)][string]$TargetPath
    )

    $method = [System.IO.Path].GetMethod(
        "GetRelativePath",
        [type[]]@([string], [string])
    )
    if ($method) {
        return [System.IO.Path]::GetRelativePath($BasePath, $TargetPath)
    }

    $baseFull = [System.IO.Path]::GetFullPath($BasePath)
    $targetFull = [System.IO.Path]::GetFullPath($TargetPath)
    $separator = [System.IO.Path]::DirectorySeparatorChar
    if (-not $baseFull.EndsWith([string]$separator)) {
        $baseFull += $separator
    }
    $baseUri = [System.Uri]::new($baseFull)
    $targetUri = [System.Uri]::new($targetFull)
    return [System.Uri]::UnescapeDataString(
        $baseUri.MakeRelativeUri($targetUri).ToString()
    ).Replace('/', $separator)
}
if ($StartCoauth -and $CoauthCommand) {
    throw "Use either -StartCoauth or -CoauthCommand, not both."
}
if ($DualCoauth -and -not $StartCoauth) {
    throw "-DualCoauth requires -StartCoauth so both processes share generated configuration."
}
if ($StartCoauth -and -not $CoauthBaseUrl) {
    $coauthPort = Get-FreeTcpPort
    # WebAuthn RP IDs are effective domains. An IP-literal origin has no
    # effective domain in url/webauthn-rs. Under the joint TLS topology the
    # listener stays bound to 127.0.0.1 while the advertised public origin is
    # the real HTTPS name fronted by the proxy — an effective domain by
    # construction. The fallback keeps the localhost secure-context exception
    # for loopback development.
    if ($coauthPublicHost) {
        $CoauthBaseUrl = "https://${coauthPublicHost}:$jointTlsPort"
    } else {
        $CoauthBaseUrl = "http://localhost:$coauthPort"
    }
} else {
    $coauthPort = $null
}
$coauthSecondaryPort = $null
$coauthServer2Port = $null
$coauthServer2BaseUrl = $null
$coauthServer2ConfigPath = $null
$CoauthServer2Command = $null
if ($StartCoauth -and $multiServer) {
    $coauthServer2Port = Get-FreeTcpPort
    $coauthServer2BaseUrl = if ($coauthServer2PublicHost) { "https://${coauthServer2PublicHost}:$jointTlsPort" } else { "http://localhost:$coauthServer2Port" }
}
$additionalServers = [System.Collections.Generic.List[object]]::new()
for ($serverIndex = 3; $serverIndex -le $ServerCount; $serverIndex++) {
    if ($SolandCommand) {
        throw "-ServerCount $ServerCount is incompatible with -SolandCommand; use indexed caller-owned topology input instead"
    }
    $additionalSolandPort = Get-FreeTcpPort
    $additionalSolandHost = if ($jointTlsProcessSoland) { "soland-server$serverIndex.local.host" } else { $null }
    $additionalSolandBaseUrl = if ($additionalSolandHost) { "https://${additionalSolandHost}:$jointTlsPort" } else { "http://127.0.0.1:$additionalSolandPort" }
    $additionalCoauthPort = if ($StartCoauth) { Get-FreeTcpPort } else { $null }
    $additionalCoauthHost = if ($jointTlsCoauth) { "coauth-server$serverIndex.local.host" } else { $null }
    $additionalCoauthBaseUrl = if ($additionalCoauthPort) {
        if ($additionalCoauthHost) { "https://${additionalCoauthHost}:$jointTlsPort" } else { "http://localhost:$additionalCoauthPort" }
    } else { $null }
    $additionalServers.Add([pscustomobject]@{
        Index = $serverIndex
        Name = "server$serverIndex"
        SolandName = "soland-server$serverIndex"
        SolandPort = $additionalSolandPort
        SolandHost = $additionalSolandHost
        SolandBaseUrl = $additionalSolandBaseUrl
        SolandMetricsPort = $null
        SolandService = $null
        SolandServiceId = $null
        SolandServiceDid = $null
        SolandDatabase = $null
        SolandDatabaseDsn = $null
        CoauthName = "coauth-server$serverIndex"
        CoauthPort = $additionalCoauthPort
        CoauthHost = $additionalCoauthHost
        CoauthBaseUrl = $additionalCoauthBaseUrl
        CoauthConfigPath = $null
        CoauthCommand = $null
        CoauthDatabase = $null
        KeyStoreMasterKey = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
        NotarySigningKey = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    })
}
$allSolandBaseUrls = @($SolandBaseUrl, $solandServer2BaseUrl) + @($additionalServers | ForEach-Object { $_.SolandBaseUrl }) | Where-Object { $_ }
$allInksonBaseUrls = @($InksonBaseUrl, $inksonServer2BaseUrl) | Where-Object { $_ } | Select-Object -Unique
$coauthSecondaryBaseUrl = $null
$CoauthSecondaryCommand = $null
if ($DualCoauth) {
    $coauthSecondaryPort = Get-FreeTcpPort
    $coauthSecondaryBaseUrl = "http://127.0.0.1:$coauthSecondaryPort"
}

# CT-6: teabay joint participant. Mirrors the -StartCoauth port allocation
# pattern. Teabay additionally needs a DATABASE_URL because the binary will
# refuse to boot without one (per TEABAY_SPEC.required_env_vars in the cotest
# helper).
$teabayPort = $null
if ($StartTeabay) {
    if (-not $TeabayDatabaseUrl -and -not $env:DATABASE_URL) {
        throw "-StartTeabay requires -TeabayDatabaseUrl (or DATABASE_URL in env). Teabay refuses to boot without a Postgres DSN."
    }
    if (-not $TeabayBaseUrl) {
        $teabayPort = Get-FreeTcpPort
        $TeabayBaseUrl = "http://127.0.0.1:$teabayPort"
    }
}

$savfoxPort = $null
$savfoxModelPort = $null
$savfoxModelBaseUrl = $null
$savfoxUnaddressedPort = $null
$savfoxUnaddressedBaseUrl = $null
$savfoxUnaddressedModelPort = $null
$savfoxUnaddressedModelBaseUrl = $null
$savfoxUnaddressedToken = $null
if ($StartSavfox) {
    if (-not (Test-Path -LiteralPath $SavfoxRoot -PathType Container)) {
        throw "-StartSavfox requires a Savfox checkout; not found: $SavfoxRoot"
    }
    if ($SavfoxToken.Length -lt 32) {
        throw "-SavfoxToken must contain at least 32 characters"
    }
    if (-not $SavfoxBaseUrl) {
        $savfoxPort = Get-FreeTcpPort
        $SavfoxBaseUrl = "http://127.0.0.1:$savfoxPort"
    } else {
        $savfoxPort = ([System.Uri]$SavfoxBaseUrl).Port
    }
    $savfoxModelPort = Get-FreeTcpPort
    $savfoxModelBaseUrl = "http://127.0.0.1:$savfoxModelPort"
    $savfoxUnaddressedPort = Get-FreeTcpPort
    $savfoxUnaddressedBaseUrl = "http://127.0.0.1:$savfoxUnaddressedPort"
    $savfoxUnaddressedModelPort = Get-FreeTcpPort
    $savfoxUnaddressedModelBaseUrl = "http://127.0.0.1:$savfoxUnaddressedModelPort"
    $savfoxUnaddressedToken = "$SavfoxToken-unaddressed"
}

$mockIdpPort = $null
$mockIdpBaseUrl = $null
if ($StartMockIdp) {
    $mockIdpPort = Get-FreeTcpPort
    $mockIdpBaseUrl = "http://127.0.0.1:$mockIdpPort"
}
$mockEmailPort = $null
$mockEmailBaseUrl = $null
if ($StartMockEmail) {
    $mockEmailPort = Get-FreeTcpPort
    $mockEmailBaseUrl = "http://127.0.0.1:$mockEmailPort"
}
$mockWitnessPort = $null
$mockWitnessBaseUrl = $null
$mockWitnessExtraInstances = New-Object System.Collections.Generic.List[object]
$mockWitnessQuorumBaseUrls = @()
$mockWitnessQuorumDids = @()
if ($StartMockWitness) {
    $mockWitnessPort = Get-FreeTcpPort
    $mockWitnessBaseUrl = "http://127.0.0.1:$mockWitnessPort"
    $mockWitnessQuorumBaseUrls += $mockWitnessBaseUrl
    $mockWitnessQuorumDids += $MockWitnessDid
    foreach ($extraDid in $MockWitnessExtraDids) {
        if ($extraDid -eq $MockWitnessDid -or ($mockWitnessQuorumDids -contains $extraDid)) {
            throw "Duplicate mock witness DID '$extraDid'"
        }
        $extraPort = Get-FreeTcpPort
        $extraBaseUrl = "http://127.0.0.1:$extraPort"
        $mockWitnessExtraInstances.Add([pscustomobject]@{
                did      = $extraDid
                port     = $extraPort
                base_url = $extraBaseUrl
            })
        $mockWitnessQuorumBaseUrls += $extraBaseUrl
        $mockWitnessQuorumDids += $extraDid
    }
}
# DID-P1-C02 — Prometheus listeners for the two services that export the
# DID-boundary counters (soland_/teabay_did_resolve_total{source="network"} and
# *_signature_verify_total). Bound to known free ports here and exported to the
# tests as COTEST_SOLAND_METRICS_URL / COTEST_TEABAY_METRICS_URL, the same way
# -StartMockDidHost exports COTEST_MOCK_DID_HOST_BASE_URL. coauth / inkson /
# bridges expose no metrics endpoint, so they have no counterpart here.
$solandMetricsPort = $null
$solandServer2MetricsPort = $null
$teabayMetricsPort = $null
$solandMetricsBaseUrl = $null
$teabayMetricsBaseUrl = $null

# DID-P1-C01 — counting DID document authority. Started after the witness so
# it can be handed the witness base URL for POST /control/attest.
$mockDidHostPort = $null
$mockDidHostBaseUrl = $null
if ($StartMockDidHost) {
    $mockDidHostPort = Get-FreeTcpPort
    $mockDidHostBaseUrl = "http://127.0.0.1:$mockDidHostPort"
}
$mockPushGatewayPort = $null
$mockPushGatewayBaseUrl = $null
if ($StartMockPushGateway) {
    $mockPushGatewayPort = Get-FreeTcpPort
    $mockPushGatewayBaseUrl = "http://127.0.0.1:$mockPushGatewayPort"
}
$mockAppletRegistryPort = $null
$mockAppletRegistryBaseUrl = $null
if ($StartMockAppletRegistry) {
    $mockAppletRegistryPort = Get-FreeTcpPort
    $mockAppletRegistryBaseUrl = "http://127.0.0.1:$mockAppletRegistryPort"
}
$mockTspEndpointPort = $null
$mockTspEndpointBaseUrl = $null
if ($StartMockTspEndpoint) {
    $mockTspEndpointPort = Get-FreeTcpPort
    $mockTspEndpointBaseUrl = "http://127.0.0.1:$mockTspEndpointPort"
}
$mockMimiFacadePort = $null
$mockMimiFacadeBaseUrl = $null
if ($StartMockMimiFacade) {
    $mockMimiFacadePort = Get-FreeTcpPort
    $mockMimiFacadeBaseUrl = "http://127.0.0.1:$mockMimiFacadePort"
}
$mockClaimIssuerPort = $null
$mockClaimIssuerBaseUrl = $null
if ($StartMockClaimIssuer) {
    $mockClaimIssuerPort = Get-FreeTcpPort
    $mockClaimIssuerBaseUrl = "http://127.0.0.1:$mockClaimIssuerPort"
}
$mockChallengeProviderPort = $null
$mockChallengeProviderBaseUrl = $null
if ($StartMockChallengeProvider) {
    $mockChallengeProviderPort = Get-FreeTcpPort
    $mockChallengeProviderBaseUrl = "http://127.0.0.1:$mockChallengeProviderPort"
}

$managedServices = New-Object System.Collections.Generic.List[object]
$managedServiceFailures = @()
$runtimeServers = [System.Collections.Generic.List[object]]::new()
$topologyPath = Join-Path $jointDir "topology.json"
$topology = New-CotestServerTopology `
    -ServerCount $ServerCount `
    -StartCoauth ([bool]$StartCoauth) `
    -NetworkShape $NetworkShape `
    -TlsPort $(if ($jointTlsPort) { $jointTlsPort } else { 443 }) `
    -RunRoot $jointDir
$topology | Add-Member -NotePropertyName generated_at -NotePropertyValue ((Get-Date).ToUniversalTime().ToString("o"))
$topology | Add-Member -NotePropertyName lifecycle -NotePropertyValue "planned"
$topology | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $topologyPath -Encoding utf8NoBOM
$mockAppletRegistryStateKeyFile = $null
$ephemeralCoauthServer1Postgres = $null
$ephemeralCoauthServer2Postgres = $null
$ephemeralSolandPostgres = $null
$ephemeralSolandServer2Postgres = $null
$additionalPostgresContainers = [System.Collections.Generic.List[object]]::new()
$solandDatabaseDsn = $SolandDatabaseUrl
$solandServer2DatabaseDsn = $null
# Durable protocol stores exported for the secret scan. Kept apart from the log
# roots because the verdict differs by artifact class: signed authorization
# evidence is expected here, recovery private material never is.
$storeDumpDir = Join-Path $jointDir "stores"
$storeDumpFailures = [System.Collections.Generic.List[string]]::new()
$exitCode = 1
$runnerError = $null
$startedAt = Get-Date
$generatedSolandCommand = $false
$generatedInksonCommand = $false
$willStartDefaultSoland = (-not $SolandCommand -and $null -ne $solandPort)
$willStartDefaultInkson = ($requiresInkson -and -not $InksonCommand -and $null -ne $inksonPort)
$willStartDockerSoland = ($SolandRuntime -eq "docker" -and ($willStartDefaultSoland -or ($multiServer -and $null -ne $solandServer2Port)))
$startedSolandRuntime = if ($willStartDockerSoland) { "docker" } elseif ($willStartDefaultSoland) { "process" } elseif ($SolandCommand) { "process-command" } else { "attached" }
$coauthConfigPath = $null
$e2eRoot = Join-Path $repoRoot "e2e"
$preflightJson = Join-Path $jointDir "preflight.json"
$preflightMd = Join-Path $jointDir "preflight.md"
$managedServiceFailuresJson = Join-Path $jointDir "managed-service-failures.json"
$managedServiceFailuresMd = Join-Path $jointDir "managed-service-failures.md"
# The harness serves a static bundle, not a Dioxus devserver. A debug bundle
# enables dioxus-web devtools and repeatedly opens `/_dioxus` hot-reload
# WebSockets; the static server cannot satisfy that protocol and the failed
# CloseEvent path can corrupt the wasm callback heap. Inkson's joint-e2e profile
# compiles out devtools while retaining the cotest-only session injection feature.
# Dioxus places every non-release custom profile under its `debug` web output
# directory even though Cargo itself uses the named `joint-e2e` profile.
$inksonStaticRoot = $null
$inksonStaticIndex = $null
if ($requiresInkson) {
    $inksonStaticRoot = Join-Path $inksonTargetDirectory "dx\inkson\debug\web\public"
    $inksonStaticIndex = Join-Path $inksonStaticRoot "index.html"
}

try {
    if ($willStartDockerSoland -and ($BuildSolandImage -or -not (Test-DockerImagePresent -ImageTag $SolandImage))) {
        $imageBuildArgs = @{
            ImageTag = $SolandImage
        }
        if (@($DockerCacheFrom).Count -gt 0) {
            $imageBuildArgs.CacheFrom = $DockerCacheFrom
        }
        if ($DockerCacheTo) {
            $imageBuildArgs.CacheTo = $DockerCacheTo
        }
        if ($DockerPull) {
            $imageBuildArgs.Pull = $true
        }
        if ($DockerNoCache) {
            $imageBuildArgs.NoCache = $true
        }
        Invoke-SolandImageBuild @imageBuildArgs
    }

    $preparationTasks = New-Object System.Collections.Generic.List[object]
    $preparationTimings = New-Object System.Collections.Generic.List[object]
    if (-not $SkipBuild -and $willStartDefaultSoland -and $SolandRuntime -eq "process" -and -not $SolandBin -and -not $env:SOLAND_BIN) {
        $defaultSolandBinary = Join-Path $solandTargetDirectory "debug\soland.exe"
        $freshness = Get-ArtifactFreshness `
            -ArtifactPath $defaultSolandBinary `
            -RepositoryRoots @(
                (Join-Path $workspaceRoot "soland"),
                (Join-Path $workspaceRoot "arkret-rust-sdk")
            )
        if (-not $freshness.Fresh) {
            Write-Host "Preparing soland binary: $($freshness.Detail)"
            $started = Get-Date
            # `conformance-harness` compiles the development-only
            # `/_arkret/_conformance/*` namespace into the SUT. It is off in
            # soland's default (production) build, and the e2e conformance
            # suites drive those endpoints, so the harness build must ask for it.
            #
            # Keep this comment ABOVE the call. A comment between a backtick
            # continuation and the next argument ends the statement, so the
            # earlier placement dispatched `Start-ManagedCommand -Name` alone
            # and every stale-binary run died on "missing mandatory parameters:
            # Command WorkingDirectory LogDirectory" instead of rebuilding.
            $service = Start-ManagedCommand `
                -Name "prepare-soland" `
                -Command ("cargo build --manifest-path {0} -p soland --bin soland --features conformance-harness" -f (Quote-PsLiteral $SutManifest)) `
                -WorkingDirectory (Split-Path -Parent $SutManifest) `
                -LogDirectory $serviceLogDir
            $preparationTasks.Add([pscustomobject]@{ Name = "soland"; Service = $service; Started = $started; Artifact = $defaultSolandBinary; AllowUnchangedArtifact = $true; RepositoryRoots = @((Join-Path $workspaceRoot "soland"), (Join-Path $workspaceRoot "arkret-rust-sdk")) })
        } else {
            $preparationTimings.Add([pscustomobject]@{ name = "soland"; status = "cache-hit"; duration_seconds = 0; detail = $freshness.Detail })
        }
    }

    # `cotest-wire` is the cross-language canonical oracle: the SDK's Rust
    # implementation stays the single source of truth for canonical JSON, ids
    # and digests, and TypeScript never reimplements them. But the helper used
    # to shell out to `cargo run --bin cotest-wire` on EVERY assertion and
    # fixture. Even with the binary already built, each call pays Cargo
    # discovery and, with two Playwright workers, contends on the package-cache
    # and build-directory locks -- a per-assertion cost across a 3357-second
    # full run. Build it once here and let the helper exec the binary directly
    # (`COTEST_WIRE_BIN`), which is what CI already does.
    if (-not $SkipBuild -and -not $env:COTEST_WIRE_BIN) {
        $cotestWireBinary = Join-Path $cotestTargetDirectory "debug\cotest-wire.exe"
        $cotestProvisionBinary = Join-Path $cotestTargetDirectory "debug\cotest-provision.exe"
        $buildInputRoots = @($repoRoot, (Join-Path $workspaceRoot "arkret-rust-sdk"))
        # One `cargo build` produces both bins, so both have to be checked. With
        # only the wire binary gated, a tree whose `cotest-wire.exe` was built
        # before `cotest-provision` existed reports a cache hit, skips the
        # build, and leaves no bridge — which does not fail anything: the
        # provisioning specs skip on the missing `COTEST_PROVISION_BIN` and the
        # run goes green having tested none of the canonical chain.
        $wireFreshness = Get-ArtifactFreshness `
            -ArtifactPath $cotestWireBinary `
            -RepositoryRoots $buildInputRoots
        $provisionFreshness = Get-ArtifactFreshness `
            -ArtifactPath $cotestProvisionBinary `
            -RepositoryRoots $buildInputRoots
        if ($wireFreshness.Fresh -and -not $provisionFreshness.Fresh) {
            $wireFreshness = $provisionFreshness
        }
        if (-not $wireFreshness.Fresh) {
            Write-Host "Preparing cotest-wire binary: $($wireFreshness.Detail)"
            $started = Get-Date
            # Build the package, not the workspace root. `cotest-wire` lives in
            # `crates/test-support`, whose dependency graph is SDK + Garth and
            # excludes Inkson and the soland implementation crates the root
            # package pulls in — 486 crates instead of 952. Naming the root
            # manifest without `-p` would resolve the bin through the root
            # package again and rebuild all of it.
            $cotestManifest = Join-Path $repoRoot "Cargo.toml"
            $service = Start-ManagedCommand `
                -Name "prepare-cotest-wire" `
                -Command ("cargo build --manifest-path {0} -p cotest-test-support --bin cotest-wire --bin cotest-provision" -f (Quote-PsLiteral $cotestManifest)) `
                -WorkingDirectory $repoRoot `
                -LogDirectory $serviceLogDir
            $preparationTasks.Add([pscustomobject]@{ Name = "cotest-wire"; Service = $service; Started = $started; Artifact = $cotestWireBinary; AllowUnchangedArtifact = $true; RepositoryRoots = @($repoRoot, (Join-Path $workspaceRoot "arkret-rust-sdk")) })
            # Both executables come from this one successful Cargo command.
            # Validate and stamp each output so provisioning does not force a
            # fresh build on every run merely because its stamp is absent.
            $preparationTasks.Add([pscustomobject]@{ Name = "cotest-provision"; Service = $service; Started = $started; Artifact = $cotestProvisionBinary; AllowUnchangedArtifact = $true; RepositoryRoots = @($repoRoot, (Join-Path $workspaceRoot "arkret-rust-sdk")) })
        } else {
            $preparationTimings.Add([pscustomobject]@{ name = "cotest-wire"; status = "cache-hit"; duration_seconds = 0; detail = $wireFreshness.Detail })
        }
    }

    if (-not $SkipBuild -and $StartCoauth -and -not $CoauthBin) {
        # Coauth serves its browser UI from ./dist. Building only the backend
        # binary can therefore run current handlers behind a stale frontend
        # bundle (for example, the Passkey API exists while /security still
        # renders the pre-Passkey page). Keep the served Wasm bundle under the
        # same source-freshness gate as the backend binary.
        $coauthRoot = Join-Path $workspaceRoot "coauth"
        $coauthFrontendArtifact = Join-Path $coauthRoot "dist\wasm\coauth-frontend_bg.wasm"
        $coauthFrontendFreshness = Get-ArtifactFreshness `
            -ArtifactPath $coauthFrontendArtifact `
            -RepositoryRoots @(
                $coauthRoot,
                (Join-Path $workspaceRoot "arkret-rust-sdk")
            )
        if (-not $coauthFrontendFreshness.Fresh) {
            Write-Host "Preparing coauth frontend: $($coauthFrontendFreshness.Detail)"
            $started = Get-Date
            $service = Start-ManagedCommand `
                -Name "prepare-coauth-frontend" `
                -Command "just frontend-assets" `
                -WorkingDirectory $coauthRoot `
                -LogDirectory $serviceLogDir
            $preparationTasks.Add([pscustomobject]@{ Name = "coauth-frontend"; Service = $service; Started = $started; Artifact = $coauthFrontendArtifact; AllowUnchangedArtifact = $true; RepositoryRoots = @($coauthRoot, (Join-Path $workspaceRoot "arkret-rust-sdk")) })
        } else {
            $preparationTimings.Add([pscustomobject]@{ name = "coauth-frontend"; status = "cache-hit"; duration_seconds = 0; detail = $coauthFrontendFreshness.Detail })
        }

        $defaultCoauthBinary = Join-Path $coauthTargetDirectory "debug\coauth.exe"
        $coauthFreshness = Get-ArtifactFreshness `
            -ArtifactPath $defaultCoauthBinary `
            -RepositoryRoots @(
                (Join-Path $workspaceRoot "coauth"),
                (Join-Path $workspaceRoot "arkret-rust-sdk")
            )
        if (-not $coauthFreshness.Fresh) {
            Write-Host "Preparing coauth binary: $($coauthFreshness.Detail)"
            $started = Get-Date
            $coauthManifest = Join-Path $coauthRoot "Cargo.toml"
            $service = Start-ManagedCommand `
                -Name "prepare-coauth" `
                -Command ("cargo build --manifest-path {0} --bin coauth" -f (Quote-PsLiteral $coauthManifest)) `
                -WorkingDirectory (Split-Path -Parent $coauthManifest) `
                -LogDirectory $serviceLogDir
            $preparationTasks.Add([pscustomobject]@{ Name = "coauth"; Service = $service; Started = $started; Artifact = $defaultCoauthBinary; AllowUnchangedArtifact = $true; RepositoryRoots = @((Join-Path $workspaceRoot "coauth"), (Join-Path $workspaceRoot "arkret-rust-sdk")) })
        } else {
            $preparationTimings.Add([pscustomobject]@{ name = "coauth"; status = "cache-hit"; duration_seconds = 0; detail = $coauthFreshness.Detail })
        }
    }

    if (-not $SkipBuild -and $StartSavfox -and -not $SavfoxBin -and -not $env:SAVFOX_BIN) {
        $savfoxTargetDirectory = Get-CargoTargetDirectory -RepositoryRoot $SavfoxRoot
        $defaultSavfoxBinary = Join-Path $savfoxTargetDirectory "debug\savfox.exe"
        $savfoxFreshness = Get-ArtifactFreshness `
            -ArtifactPath $defaultSavfoxBinary `
            -RepositoryRoots @(
                $SavfoxRoot,
                (Join-Path $workspaceRoot "arkret-rust-sdk")
            )
        Write-Host "Preparing savfox web bundle and binary: $($savfoxFreshness.Detail)"
        $started = Get-Date
        $savfoxManifest = Join-Path $SavfoxRoot "Cargo.toml"
        $savfoxWebBuild = Join-Path $SavfoxRoot "scripts\build-web.ps1"
        $savfoxPowerShell = Find-CommandPath @("pwsh.exe", "pwsh")
        if (-not $savfoxPowerShell) {
            throw "Preparing the Savfox web bundle requires PowerShell 7 (pwsh)"
        }
        $buildCommand = "& {0} -NoProfile -File {1}; if (`$LASTEXITCODE -ne 0) {{ exit `$LASTEXITCODE }}; cargo build --manifest-path {2} --bin savfox --features savfox-gateway-server/arkret" -f `
            (Quote-PsLiteral $savfoxPowerShell),
            (Quote-PsLiteral $savfoxWebBuild),
            (Quote-PsLiteral $savfoxManifest)
        $service = Start-ManagedCommand `
            -Name "prepare-savfox" `
            -Command $buildCommand `
            -WorkingDirectory $SavfoxRoot `
            -LogDirectory $serviceLogDir
        $preparationTasks.Add([pscustomobject]@{ Name = "savfox"; Service = $service; Started = $started; Artifact = $defaultSavfoxBinary; AllowUnchangedArtifact = $true; RepositoryRoots = @($SavfoxRoot, (Join-Path $workspaceRoot "arkret-rust-sdk")) })
    }

    if (-not $SkipBuild -and $willStartDefaultInkson) {
        $inksonWasm = Join-Path $inksonStaticRoot "wasm\inkson_bg.wasm"
        $inksonFreshness = Get-ArtifactFreshness `
            -ArtifactPath $inksonStaticIndex `
            -RepositoryRoots @(
                $InksonRoot,
                (Join-Path $workspaceRoot "arkret-rust-sdk"),
                (Join-Path $workspaceRoot "garth"),
                # `yoface` is intentionally absent: inkson consumes it as a
                # cargo git dependency, so there is no local checkout whose
                # mtime could invalidate the bundle. A yoface bump lands here
                # through inkson's Cargo.lock, which is under $InksonRoot.
                (Join-Path $workspaceRoot "chime")
            )
        $inksonTestFeaturePresent = Test-BinaryContainsAsciiMarker `
            -Path $inksonWasm `
            -Marker "inkson.test.session_injection.v1"
        if (-not $inksonFreshness.Fresh -or -not $inksonTestFeaturePresent) {
            Write-Host "Preparing inkson web bundle: $($inksonFreshness.Detail)"
            $started = Get-Date
            $buildCommand = Add-DioxusNoDownloadsEnvironment `
                -Command "dx build --profile joint-e2e --platform web --features wasm-localstorage-secrets-test" `
                -ProjectRoot $InksonRoot
            # Dioxus 0.7.10 can assemble the shared debug output from a stale
            # wasm-dev executable even though Cargo built the requested custom
            # profile. Re-run wasm-bindgen against Cargo's exact joint-e2e
            # artifact so the static bundle cannot silently lose the cotest
            # feature or regain debug-only devtools.
            $jointE2eWasm = Join-Path $inksonTargetDirectory "wasm32-unknown-unknown\joint-e2e\inkson.wasm"
            $inksonWasmOutputDir = Join-Path $inksonStaticRoot "wasm"
            $finalizeInksonWasm = Join-Path $repoRoot "scripts\finalize-inkson-joint-e2e-wasm.ps1"
            $buildCommand = "$buildCommand; if (`$LASTEXITCODE -ne 0) { exit `$LASTEXITCODE }; & $(Quote-PsLiteral $finalizeInksonWasm) -SourceWasm $(Quote-PsLiteral $jointE2eWasm) -OutputDirectory $(Quote-PsLiteral $inksonWasmOutputDir)"
            $service = Start-ManagedCommand `
                -Name "prepare-inkson" `
                -Command $buildCommand `
                -WorkingDirectory $InksonRoot `
                -LogDirectory $serviceLogDir
            $preparationTasks.Add([pscustomobject]@{ Name = "inkson"; Service = $service; Started = $started; Artifact = $inksonStaticIndex; AllowUnchangedArtifact = $false; RepositoryRoots = @($InksonRoot, (Join-Path $workspaceRoot "arkret-rust-sdk"), (Join-Path $workspaceRoot "garth"), (Join-Path $workspaceRoot "chime")) })
        } else {
            $preparationTimings.Add([pscustomobject]@{ name = "inkson"; status = "cache-hit"; duration_seconds = 0; detail = $inksonFreshness.Detail })
        }
    }

    foreach ($task in $preparationTasks) {
        $task.Service.Process.WaitForExit()
        $task.Service.Process.Refresh()
    }
    foreach ($task in $preparationTasks) {
        $duration = [Math]::Round(((Get-Date) - $task.Started).TotalSeconds, 3)
        $exitCode = $task.Service.Process.ExitCode
        $artifactExists = Test-Path -LiteralPath $task.Artifact -PathType Leaf
        $artifactUpdated = $artifactExists -and `
            (Get-Item -LiteralPath $task.Artifact).LastWriteTimeUtc -ge $task.Started.ToUniversalTime().AddSeconds(-2)
        if (($null -ne $exitCode -and $exitCode -ne 0) -or -not $artifactExists) {
            throw "preparing $($task.Name) failed (exit=$exitCode, artifact_updated=$artifactUpdated); see $($task.Service.Stdout) and $($task.Service.Stderr)"
        }
        $status = "built"
        if (-not $artifactUpdated) {
            if (-not $task.AllowUnchangedArtifact) {
                throw "preparing $($task.Name) failed (exit=$exitCode, artifact_updated=False); see $($task.Service.Stdout) and $($task.Service.Stderr)"
            }
            # Cargo may prove the current source tree already matches an existing
            # executable and exit successfully without relinking it. Refresh the
            # filesystem timestamp only after that successful build so the HEAD
            # freshness gate records this explicit verification.
            (Get-Item -LiteralPath $task.Artifact).LastWriteTimeUtc = [DateTime]::UtcNow
            $status = "verified-cargo-cache-hit"
        }
        $repositoryStates = @(
            foreach ($repositoryRoot in $task.RepositoryRoots) {
                Get-RepositoryBuildInputState -RepositoryRoot $repositoryRoot -BinaryPath $task.Artifact
            }
        )
        Write-ArtifactBuildStamp -ArtifactPath $task.Artifact -RepositoryStates $repositoryStates | Out-Null
        $preparationTimings.Add([pscustomobject]@{ name = $task.Name; status = $status; duration_seconds = $duration; detail = $task.Artifact })
    }
    if ($willStartDefaultInkson) {
        $inksonWasm = Join-Path $inksonStaticRoot "wasm\inkson_bg.wasm"
        if (-not (Test-BinaryContainsAsciiMarker -Path $inksonWasm -Marker "inkson.test.session_injection.v1")) {
            throw "prepared inkson bundle lacks the wasm-localstorage-secrets-test marker: $inksonWasm"
        }
        if (Test-BinaryContainsAsciiMarker -Path $inksonWasm -Marker "/_dioxus") {
            throw "prepared inkson static bundle unexpectedly embeds Dioxus devtools: $inksonWasm"
        }
    }
    ConvertTo-Json -InputObject @($preparationTimings.ToArray()) -Depth 4 |
        Set-Content -Path (Join-Path $jointDir "preparation-timings.json") -Encoding UTF8

    Invoke-JointE2ePreflight `
        -RepoRoot $repoRoot `
        -WorkspaceRoot $workspaceRoot `
        -E2eRoot $e2eRoot `
        -PlaywrightProjects $playwrightProjects `
        -StartCoauth ([bool]$StartCoauth) `
        -CoauthPostgresImage $CoauthPostgresImage `
        -CoauthBin $CoauthBin `
        -StartTeabay ([bool]$StartTeabay) `
        -TeabayBin $TeabayBin `
        -TeabayDatabaseUrl $TeabayDatabaseUrl `
        -SolandBaseUrl $SolandBaseUrl `
        -SolandCommand $SolandCommand `
        -SolandBin $SolandBin `
        -SolandDatabaseUrl $SolandDatabaseUrl `
        -SolandPostgresImage $SolandPostgresImage `
        -WillStartDefaultSoland $willStartDefaultSoland `
        -SolandRuntime $SolandRuntime `
        -SolandImage $SolandImage `
        -WillStartDockerSoland $willStartDockerSoland `
        -InksonBaseUrl $InksonBaseUrl `
        -InksonCommand $InksonCommand `
        -RequiresInkson $requiresInkson `
        -WillStartDefaultInkson $willStartDefaultInkson `
        -InksonStaticIndex $inksonStaticIndex `
        -JointTlsTopology ([bool]$jointTlsEnabled) `
        -JsonPath $preflightJson `
        -MarkdownPath $preflightMd

    if ($PreflightOnly) {
        Write-Host "Preflight completed; no services were started."
        exit 0
    }

    # Serve an immutable, run-scoped copy of the verified Inkson bundle. A
    # separately running `dx serve` watches the same repository and can replace
    # target\dx\...\public in place with a dev build while a long joint-full run
    # is active. Besides transient 404/MIME failures, that replacement drops the
    # cotest-only session-injection feature and turns later browser failures into
    # misleading "no session grant" cascades.
    if ($willStartDefaultInkson) {
        $inksonRuntimeRoot = Join-Path $jointDir "inkson-web"
        New-Item -ItemType Directory -Path $inksonRuntimeRoot -Force | Out-Null
        Copy-Item -Path (Join-Path $inksonStaticRoot "*") -Destination $inksonRuntimeRoot -Recurse -Force
        $runtimeWasm = Join-Path $inksonRuntimeRoot "wasm\inkson_bg.wasm"
        if (-not (Test-BinaryContainsAsciiMarker -Path $runtimeWasm -Marker "inkson.test.session_injection.v1")) {
            throw "run-scoped inkson bundle lacks the wasm-localstorage-secrets-test marker: $runtimeWasm"
        }
        if (Test-BinaryContainsAsciiMarker -Path $runtimeWasm -Marker "/_dioxus") {
            throw "run-scoped inkson bundle unexpectedly embeds Dioxus devtools: $runtimeWasm"
        }
        $inksonStaticRoot = $inksonRuntimeRoot
    }

    # 0530-C: stand up the HTTPS identity front before any owned service
    # starts, so readiness probes, service-to-service calls and the browser all
    # traverse the real TLS path from the first request. Trust is confined to
    # this process tree; Windows CurrentUser Root is intentionally untouched.
    $jointTlsAssets = $null
    $jointTlsDir = $null
    if ($jointTlsEnabled) {
        $jointTlsDir = Join-Path $jointDir "tls"
        $jointTlsHostNames = @(
            @($solandPublicHost, $solandServer2PublicHost, $coauthPublicHost, $coauthServer2PublicHost) +
            @($additionalServers | ForEach-Object { @($_.SolandHost, $_.CoauthHost) })
        ) | ForEach-Object { $_ } | Where-Object { $_ }
        $jointTlsAssets = New-JointTlsAssets `
            -Directory $jointTlsDir `
            -DnsNames $jointTlsHostNames `
            -RunLabel $timestamp
        Install-JointLoopbackHosts `
            -Hosts (@($jointTlsHostNames) + @($jointTlsUnregisteredProbeHost)) `
            -Marker $jointTlsHostsMarker
        $env:NODE_EXTRA_CA_CERTS = $jointTlsAssets.CaPemPath
        $env:COTEST_RUN_SCOPED_CA_PEM = $jointTlsAssets.CaPemPath
        $env:COTEST_TLS_SPKI_SHA256 = $jointTlsAssets.ServerSpkiSha256

        $jointTlsRoutes = @()
        if ($solandPublicHost) {
            $jointTlsRoutes += [pscustomobject]@{ Host = $solandPublicHost; BackendPort = $solandPort }
        }
        if ($solandServer2PublicHost) {
            $jointTlsRoutes += [pscustomobject]@{ Host = $solandServer2PublicHost; BackendPort = $solandServer2Port }
        }
        if ($coauthPublicHost) {
            $jointTlsRoutes += [pscustomobject]@{
                Host = $coauthPublicHost
                BackendPort = $coauthPort
                LogoutBackendPort = $solandPort
            }
        }
        if ($coauthServer2PublicHost) {
            $jointTlsRoutes += [pscustomobject]@{
                Host = $coauthServer2PublicHost
                BackendPort = $coauthServer2Port
                LogoutBackendPort = $solandServer2Port
            }
        }
        foreach ($server in $additionalServers) {
            if ($server.SolandHost) {
                $jointTlsRoutes += [pscustomobject]@{ Host = $server.SolandHost; BackendPort = $server.SolandPort }
            }
            if ($server.CoauthHost) {
                $jointTlsRoutes += [pscustomobject]@{
                    Host = $server.CoauthHost
                    BackendPort = $server.CoauthPort
                    LogoutBackendPort = $server.SolandPort
                }
            }
        }
        $caddyfilePath = Join-Path $jointTlsDir "Caddyfile"
        Write-JointCaddyConfig `
            -Path $caddyfilePath `
            -TlsPort $jointTlsPort `
            -Routes $jointTlsRoutes `
            -CertificatePath $jointTlsAssets.ServerPemPath `
            -KeyPath $jointTlsAssets.ServerKeyPath
        $caddyBinary = Find-CommandPath @("caddy.exe", "caddy")
        if (-not $caddyBinary) {
            throw "caddy is required for the joint TLS identity topology"
        }
        $caddyCommand = "& {0} run --config {1} --adapter caddyfile" -f `
            (Quote-PsLiteral $caddyBinary), (Quote-PsLiteral $caddyfilePath)
        $managedServices.Add((Start-ManagedCommand -Name "tls-proxy" -Command $caddyCommand -WorkingDirectory $jointTlsDir -LogDirectory $serviceLogDir))
        # Only the listener is provable at this point; the backends start below
        # and the full topology is asserted after every service is ready.
        $tlsDeadline = (Get-Date).AddSeconds(30)
        $tlsListening = $false
        while ((Get-Date) -lt $tlsDeadline) {
            try {
                $tlsProbe = [System.Net.Sockets.TcpClient]::new()
                $tlsProbe.Connect("127.0.0.1", $jointTlsPort)
                $tlsProbe.Close()
                $tlsListening = $true
                break
            } catch {
                Start-Sleep -Milliseconds 250
            }
        }
        if (-not $tlsListening) {
            throw "joint TLS topology: Caddy did not open 127.0.0.1:$jointTlsPort; see $serviceLogDir\tls-proxy.stderr.log"
        }
    }

    # Child mocks must inherit the prepared oracle before they start.
    if (-not $env:COTEST_WIRE_BIN) {
        $preparedWireBinary = Join-Path $cotestTargetDirectory "debug\cotest-wire.exe"
        if (Test-Path -LiteralPath $preparedWireBinary) {
            $env:COTEST_WIRE_BIN = $preparedWireBinary
        }
    }
    if ($StartMockAppletRegistry -and (-not $env:COTEST_WIRE_BIN -or
        -not (Test-Path -LiteralPath $env:COTEST_WIRE_BIN -PathType Leaf))) {
        throw "Applet mock requires a prepared cotest-wire binary; run the preparation batch first"
    }

    # Start mock services first so coauth/soland configurations can reference them.
    $mocksRoot = Join-Path $repoRoot "e2e\mocks"
    if ($StartMockIdp) {
        $mockIdpCmd = "`$env:MOCK_IDP_PORT='$mockIdpPort'; node " + (Quote-PsLiteral (Join-Path $mocksRoot "mock-idp.mjs"))
        $managedServices.Add((Start-ManagedCommand -Name "mock-idp" -Command $mockIdpCmd -WorkingDirectory $mocksRoot -LogDirectory $serviceLogDir))
        Wait-HttpReady -Url "$mockIdpBaseUrl/.well-known/openid-configuration" -TimeoutSeconds 30
    }
    if ($StartMockEmail) {
        $mockEmailCmd = "`$env:MOCK_EMAIL_PORT='$mockEmailPort'; node " + (Quote-PsLiteral (Join-Path $mocksRoot "mock-email.mjs"))
        $managedServices.Add((Start-ManagedCommand -Name "mock-email" -Command $mockEmailCmd -WorkingDirectory $mocksRoot -LogDirectory $serviceLogDir))
        Wait-HttpReady -Url "$mockEmailBaseUrl/jwks" -TimeoutSeconds 30
    }
    if ($StartMockWitness) {
        $mockWitnessCmd = (
            "`$env:MOCK_WITNESS_PORT='$mockWitnessPort'; `$env:MOCK_WITNESS_DID={0}; node {1}"
        ) -f (Quote-PsLiteral $MockWitnessDid), (Quote-PsLiteral (Join-Path $mocksRoot "mock-witness.mjs"))
        $managedServices.Add((Start-ManagedCommand -Name "mock-witness" -Command $mockWitnessCmd -WorkingDirectory $mocksRoot -LogDirectory $serviceLogDir))
        Wait-HttpReady -Url "$mockWitnessBaseUrl/mock/witness/policy" -TimeoutSeconds 30
        $witnessIndex = 2
        foreach ($witness in $mockWitnessExtraInstances) {
            $extraWitnessCmd = (
                "`$env:MOCK_WITNESS_PORT='{0}'; `$env:MOCK_WITNESS_DID={1}; node {2}"
            ) -f $witness.port, (Quote-PsLiteral $witness.did), (Quote-PsLiteral (Join-Path $mocksRoot "mock-witness.mjs"))
            $managedServices.Add((Start-ManagedCommand -Name "mock-witness-$witnessIndex" -Command $extraWitnessCmd -WorkingDirectory $mocksRoot -LogDirectory $serviceLogDir))
            Wait-HttpReady -Url "$($witness.base_url)/mock/witness/policy" -TimeoutSeconds 30
            $witnessIndex++
        }
    }
    if ($StartMockDidHost) {
        $envExpr = (
            "`$env:MOCK_DID_HOST_PORT='{0}'; `$env:MOCK_DID_HOST_AUTHORITY={1}; `$env:MOCK_DID_HOST_SCID={2}"
        ) -f $mockDidHostPort, (Quote-PsLiteral $MockDidHostAuthority), (Quote-PsLiteral $MockDidHostScid)
        if ($MockDidHostExtraDids.Count -gt 0) {
            $envExpr = "$envExpr; `$env:MOCK_DID_HOST_EXTRA_DIDS=" + (Quote-PsLiteral ($MockDidHostExtraDids -join ","))
        }
        if ($mockWitnessBaseUrl) {
            # Witness signing stays in mock-witness.mjs; the DID host only
            # relays through it for POST /control/attest.
            $envExpr = "$envExpr; `$env:MOCK_DID_HOST_WITNESS_URL=" + (Quote-PsLiteral $mockWitnessBaseUrl)
        }
        $mockDidHostCmd = "$envExpr; node " + (Quote-PsLiteral (Join-Path $mocksRoot "mock-did-host.mjs"))
        $managedServices.Add((Start-ManagedCommand -Name "mock-did-host" -Command $mockDidHostCmd -WorkingDirectory $mocksRoot -LogDirectory $serviceLogDir))
        Wait-HttpReady -Url "$mockDidHostBaseUrl/health" -TimeoutSeconds 30
    }
    if ($StartMockPushGateway) {
        $envExpr = "`$env:MOCK_PUSH_GATEWAY_PORT='$mockPushGatewayPort'"
        if ($MockPushGatewayIss) {
            $envExpr = "$envExpr; `$env:MOCK_PUSH_GATEWAY_ISS=" + (Quote-PsLiteral $MockPushGatewayIss)
        }
        $mockPushGatewayCmd = "$envExpr; node " + (Quote-PsLiteral (Join-Path $mocksRoot "mock-push-gateway.mjs"))
        $managedServices.Add((Start-ManagedCommand -Name "mock-push-gateway" -Command $mockPushGatewayCmd -WorkingDirectory $mocksRoot -LogDirectory $serviceLogDir))
        Wait-HttpReady -Url "$mockPushGatewayBaseUrl/jwks" -TimeoutSeconds 30
    }
    if ($StartMockTspEndpoint) {
        $envExpr = "`$env:MOCK_TSP_ENDPOINT_PORT='$mockTspEndpointPort'"
        if ($MockTspEndpointVid) {
            $envExpr = "$envExpr; `$env:MOCK_TSP_ENDPOINT_VID=" + (Quote-PsLiteral $MockTspEndpointVid)
        }
        $mockTspEndpointCmd = "$envExpr; node " + (Quote-PsLiteral (Join-Path $mocksRoot "mock-tsp-endpoint.mjs"))
        $managedServices.Add((Start-ManagedCommand -Name "mock-tsp-endpoint" -Command $mockTspEndpointCmd -WorkingDirectory $mocksRoot -LogDirectory $serviceLogDir))
        Wait-HttpReady -Url "$mockTspEndpointBaseUrl/identity" -TimeoutSeconds 30
    }
    if ($StartMockMimiFacade) {
        $mockMimiFacadeCmd = (
            "`$env:MOCK_MIMI_FACADE_PORT='$mockMimiFacadePort'; `$env:MOCK_MIMI_FACADE_DID={0}; node {1}"
        ) -f (Quote-PsLiteral $MockMimiFacadeDid), (Quote-PsLiteral (Join-Path $mocksRoot "mock-mimi-facade.mjs"))
        $managedServices.Add((Start-ManagedCommand -Name "mock-mimi-facade" -Command $mockMimiFacadeCmd -WorkingDirectory $mocksRoot -LogDirectory $serviceLogDir))
        Wait-HttpReady -Url "$mockMimiFacadeBaseUrl/health" -TimeoutSeconds 30
    }
    if ($StartMockClaimIssuer) {
        $mockClaimIssuerCmd = (
            "`$env:MOCK_CLAIM_ISSUER_PORT='$mockClaimIssuerPort'; `$env:MOCK_CLAIM_ISSUER_DID={0}; node {1}"
        ) -f (Quote-PsLiteral $MockClaimIssuerDid), (Quote-PsLiteral (Join-Path $mocksRoot "mock-claim-issuer.mjs"))
        $managedServices.Add((Start-ManagedCommand -Name "mock-claim-issuer" -Command $mockClaimIssuerCmd -WorkingDirectory $mocksRoot -LogDirectory $serviceLogDir))
        Wait-HttpReady -Url "$mockClaimIssuerBaseUrl/health" -TimeoutSeconds 30
    }
    if ($StartMockChallengeProvider) {
        $mockChallengeProviderCmd = (
            "`$env:MOCK_CHALLENGE_PROVIDER_PORT='$mockChallengeProviderPort'; `$env:MOCK_CHALLENGE_PROVIDER_DID={0}; node {1}"
        ) -f (Quote-PsLiteral $MockChallengeProviderDid), (Quote-PsLiteral (Join-Path $mocksRoot "mock-challenge-provider.mjs"))
        $managedServices.Add((Start-ManagedCommand -Name "mock-challenge-provider" -Command $mockChallengeProviderCmd -WorkingDirectory $mocksRoot -LogDirectory $serviceLogDir))
        Wait-HttpReady -Url "$mockChallengeProviderBaseUrl/health" -TimeoutSeconds 30
    }
    if ($StartSavfox) {
        $savfoxAddressedProbe = New-ManagedSavfoxProbe `
            -Name "savfox" `
            -JointDirectory $jointDir `
            -MocksRoot $mocksRoot `
            -LogDirectory $serviceLogDir `
            -BaseUrl $SavfoxBaseUrl `
            -Port $savfoxPort `
            -Token $SavfoxToken `
            -ModelBaseUrl $savfoxModelBaseUrl `
            -ModelPort $savfoxModelPort `
            -ManagedServices $managedServices
        $savfoxUnaddressedProbe = New-ManagedSavfoxProbe `
            -Name "savfox-unaddressed" `
            -JointDirectory $jointDir `
            -MocksRoot $mocksRoot `
            -LogDirectory $serviceLogDir `
            -BaseUrl $savfoxUnaddressedBaseUrl `
            -Port $savfoxUnaddressedPort `
            -Token $savfoxUnaddressedToken `
            -ModelBaseUrl $savfoxUnaddressedModelBaseUrl `
            -ModelPort $savfoxUnaddressedModelPort `
            -ManagedServices $managedServices
        $savfoxModelReceipts = $savfoxAddressedProbe.ReceiptPath
        $savfoxUnaddressedModelReceipts = $savfoxUnaddressedProbe.ReceiptPath
    }

    if ($StartCoauth) {
        if (-not $coauthPort) {
            $coauthUri = [System.Uri]$CoauthBaseUrl
            $coauthPort = $coauthUri.Port
        }
        $coauthBinary = Resolve-CoauthBinary -ExplicitPath $CoauthBin -WorkspaceRoot $workspaceRoot
        $coauthPolicyFile = Join-Path $workspaceRoot "coauth\policies\cedar\default.cedar"
        if (-not (Test-Path -LiteralPath $coauthPolicyFile -PathType Leaf)) {
            throw "Coauth Cedar policy file not found: $coauthPolicyFile"
        }
        if ($CoauthPostgresUrl) {
            Write-Host "coauth postgres: using externally-provisioned DSN (docker skipped)"
            $coauthPostgresDsn = $CoauthPostgresUrl
        } else {
            $ephemeralCoauthServer1Postgres = Start-EphemeralPostgres -Image $CoauthPostgresImage -NamePrefix "cotest-coauth-$timestamp" -TimeoutSeconds $StartupTimeoutSeconds
            $coauthPostgresDsn = $ephemeralCoauthServer1Postgres.Url
        }
        $coauthServer1Dir = $serverArtifactLayouts["server1"].CoauthDirectory
        $coauthConfigPath = New-CoauthJointConfig `
            -CoauthBinary $coauthBinary `
            -RepoRoot $repoRoot `
            -JointDir $coauthServer1Dir `
            -PostgresUrl $coauthPostgresDsn `
            -CoauthBaseUrl $CoauthBaseUrl `
            -CoauthBind "127.0.0.1:$coauthPort" `
            -CedarPolicyFile $coauthPolicyFile `
            -InksonBaseUrl $InksonBaseUrl `
            -InksonServer2BaseUrl $inksonServer2BaseUrl `
            -InksonBaseUrls $allInksonBaseUrls `
            -OAuthClientId $CoauthOAuthClientId `
            -SolandBaseUrl $SolandBaseUrl `
            -SolandServer2BaseUrl $solandServer2BaseUrl `
            -StationBaseUrls $allSolandBaseUrls `
            -SessionGrantIntrospectionBearer $CoauthSessionGrantIntrospectionBearer `
            -EmbeddedWebvhRegistrationBearer $CoauthEmbeddedWebvhRegistrationBearer `
            -MockEmailBaseUrl $mockEmailBaseUrl
        if ($multiServer) {
            # Each Station owns a separate Account Authority and durable account
            # store. DualCoauth remains a replica of Server1, not Server2's authority.
            $ephemeralCoauthServer2Postgres = Start-EphemeralPostgres -Image $CoauthPostgresImage -NamePrefix "cotest-coauth-server2-$timestamp" -TimeoutSeconds $StartupTimeoutSeconds
            $coauthServer2Dir = $serverArtifactLayouts["server2"].CoauthDirectory
            $coauthServer2ConfigPath = New-CoauthJointConfig `
                -CoauthBinary $coauthBinary -RepoRoot $repoRoot -JointDir $coauthServer2Dir `
                -PostgresUrl $ephemeralCoauthServer2Postgres.Url `
                -CoauthBaseUrl $coauthServer2BaseUrl -CoauthBind "127.0.0.1:$coauthServer2Port" `
                -CedarPolicyFile $coauthPolicyFile -InksonBaseUrl $InksonBaseUrl -InksonServer2BaseUrl $inksonServer2BaseUrl `
                -InksonBaseUrls $allInksonBaseUrls `
                -OAuthClientId $CoauthOAuthClientId -SolandBaseUrl $SolandBaseUrl -SolandServer2BaseUrl $solandServer2BaseUrl `
                -StationBaseUrls $allSolandBaseUrls -OwningStation "server2" `
                -SessionGrantIntrospectionBearer $CoauthSessionGrantIntrospectionBearer `
                -EmbeddedWebvhRegistrationBearer $CoauthEmbeddedWebvhRegistrationBearer -MockEmailBaseUrl $mockEmailBaseUrl
            Invoke-CoauthMigrations -CoauthBinary $coauthBinary -ConfigPath $coauthServer2ConfigPath -LogDirectory $coauthServer2Dir -TimeoutSeconds $StartupTimeoutSeconds
        }
        foreach ($server in $additionalServers) {
            $server.CoauthDatabase = Start-EphemeralPostgres -Image $CoauthPostgresImage -NamePrefix "cotest-$($server.CoauthName)-$timestamp" -TimeoutSeconds $StartupTimeoutSeconds
            $additionalPostgresContainers.Add($server.CoauthDatabase)
            $coauthServerDir = $serverArtifactLayouts[$server.Name].CoauthDirectory
            $server.CoauthConfigPath = New-CoauthJointConfig `
                -CoauthBinary $coauthBinary -RepoRoot $repoRoot -JointDir $coauthServerDir `
                -PostgresUrl $server.CoauthDatabase.Url -CoauthBaseUrl $server.CoauthBaseUrl `
                -CoauthBind "127.0.0.1:$($server.CoauthPort)" -CedarPolicyFile $coauthPolicyFile `
                -InksonBaseUrl $InksonBaseUrl -InksonBaseUrls $allInksonBaseUrls `
                -OAuthClientId $CoauthOAuthClientId -SolandBaseUrl $SolandBaseUrl `
                -StationBaseUrls $allSolandBaseUrls -OwningStation $server.Name `
                -SessionGrantIntrospectionBearer $CoauthSessionGrantIntrospectionBearer `
                -EmbeddedWebvhRegistrationBearer $CoauthEmbeddedWebvhRegistrationBearer `
                -MockEmailBaseUrl $mockEmailBaseUrl
            Invoke-CoauthMigrations -CoauthBinary $coauthBinary -ConfigPath $server.CoauthConfigPath -LogDirectory $coauthServerDir -TimeoutSeconds $StartupTimeoutSeconds
        }
        if ($DualCoauth) {
            $coauthSecondaryConfigPath = Join-Path $coauthServer1Dir "coauth-secondary.yaml"
            $primaryBind = "address: `"127.0.0.1:$coauthPort`""
            $secondaryBind = "address: `"127.0.0.1:$coauthSecondaryPort`""
            $primaryConfig = Get-Content -LiteralPath $coauthConfigPath -Raw
            if (-not $primaryConfig.Contains($primaryBind)) {
                throw "Could not locate primary Coauth bind '$primaryBind' in $coauthConfigPath"
            }
            $primaryConfig.Replace($primaryBind, $secondaryBind) |
                Set-Content -LiteralPath $coauthSecondaryConfigPath -Encoding UTF8
        }
        Invoke-CoauthMigrations -CoauthBinary $coauthBinary -ConfigPath $coauthConfigPath -LogDirectory $coauthServer1Dir -TimeoutSeconds $StartupTimeoutSeconds
        # Enable the cotest-only debug seam (`/api/v1/test/debug/issue-dpop-grant`)
        # so the joint harness can mint real DPoP-bound ak.session.grants instead
        # of dev-login bearers (see helpers/session-grant-dpop.ts mintDpopBoundGrant).
        #
        # The generated dev config enables `account.registration_email_delivery_bypass_allowed`
        # (in-band verification code, no SMTP) so the harness can register accounts
        # headlessly. coauth's config validator fails closed and refuses to start
        # unless the dev-only escape hatch is also set (mirrors coauth/justfile),
        # so set it here too — otherwise coauth panics on boot and the whole MLS
        # joint suite (which needs DPoP session-grant login) silently `test.skip`s.
        #
        # The generated config likewise enables `arkret.password_login_session_grants_enabled`
        # so the headless password-bootstrap login path works. coauth's validator fails
        # closed on that one too and demands `COAUTH_ALLOW_INSECURE_PASSWORD_BOOTSTRAP`;
        # without it coauth panics on boot ("password-bootstrap scaffold is for dev/test
        # only") and the whole joint suite never starts.
        # Coauth's production client is HTTPS/public-egress only. The joint
        # services still bind plain loopback listeners behind the TLS proxy, so
        # enable the debug-only, loopback-only transport seam alongside test
        # endpoints. Under the 0530-C topology the public origin itself is
        # HTTPS, so coauth additionally receives SSL_CERT_FILE: its outbound
        # client merges the run-scoped CA into the verified root set.
        $coauthCaPrefix = ""
        if ($coauthPublicHost -and $jointTlsAssets) {
            $coauthCaPrefix = "`$env:SSL_CERT_FILE=$(Quote-PsLiteral $jointTlsAssets.CaPemPath); "
        }
        $CoauthCommand = "$coauthCaPrefix& {0} --config {1} --no-env-overrides --enable-test-endpoints --allow-insecure-loopback-http --allow-insecure-dev-email-bypass --allow-insecure-password-bootstrap server --no-migrate --no-sync" -f (Quote-PsLiteral $coauthBinary), (Quote-PsLiteral $coauthConfigPath)
        $CoauthHealthUrl = "$($CoauthBaseUrl.TrimEnd('/'))/health"
        if ($coauthServer2ConfigPath) {
            $CoauthServer2Command = "$coauthCaPrefix& {0} --config {1} --no-env-overrides --enable-test-endpoints --allow-insecure-loopback-http --allow-insecure-dev-email-bypass --allow-insecure-password-bootstrap server --no-migrate --no-sync" -f (Quote-PsLiteral $coauthBinary), (Quote-PsLiteral $coauthServer2ConfigPath)
        }
        foreach ($server in $additionalServers) {
            $server.CoauthCommand = "$coauthCaPrefix& {0} --config {1} --no-env-overrides --enable-test-endpoints --allow-insecure-loopback-http --allow-insecure-dev-email-bypass --allow-insecure-password-bootstrap server --no-migrate --no-sync" -f (Quote-PsLiteral $coauthBinary), (Quote-PsLiteral $server.CoauthConfigPath)
        }
        if ($DualCoauth) {
            $CoauthSecondaryCommand = "$coauthCaPrefix& {0} --config {1} --no-env-overrides --enable-test-endpoints --allow-insecure-loopback-http --allow-insecure-dev-email-bypass --allow-insecure-password-bootstrap server --no-migrate --no-sync" -f (Quote-PsLiteral $coauthBinary), (Quote-PsLiteral $coauthSecondaryConfigPath)
        }
    }

    # CT-6: teabay (directory) - needs a Postgres DSN. The validation block
    # above already guaranteed $TeabayDatabaseUrl is set when -StartTeabay
    # is passed.
    if ($StartTeabay) {
        if (-not $teabayPort) {
            $teabayUri = [System.Uri]$TeabayBaseUrl
            $teabayPort = $teabayUri.Port
        }
        $teabayBinary = Resolve-TeabayBinary -ExplicitPath $TeabayBin -WorkspaceRoot $workspaceRoot
        $teabayDb = if ($TeabayDatabaseUrl) { $TeabayDatabaseUrl } else { $env:DATABASE_URL }
        $teabayConfigPath = Join-Path $jointDir "teabay.env"
        # DID-P1-C02 — teabay is launched with --no-env-overrides, so the
        # metrics bind has to travel in the config file rather than the ambient
        # environment. Without an explicit port it would fall back to the fixed
        # 127.0.0.1:9095 and collide with a developer's running dev stack.
        $teabayMetricsPort = Get-FreeTcpPort
        $teabayMetricsBaseUrl = "http://127.0.0.1:$teabayMetricsPort"
        Write-DotEnvFile -Path $teabayConfigPath -Values ([ordered]@{
                DATABASE_URL = $teabayDb
                TEABAY_PUBLIC_BASE_URL = $TeabayBaseUrl
                TEABAY_SERVICE_ID = $TeabayServiceId
                TEABAY_DEVELOPMENT_MODE = "true"
                TEABAY_METRICS_BIND = "127.0.0.1:$teabayMetricsPort"
            })
        $teabayCmd = "& {0} --config {1} --no-env-overrides --bind 127.0.0.1:{2}" -f `
            (Quote-PsLiteral $teabayBinary),
            (Quote-PsLiteral $teabayConfigPath),
            $teabayPort
        $managedServices.Add((Start-ManagedCommand -Name "teabay" -Command $teabayCmd -WorkingDirectory (Split-Path -Parent $teabayBinary) -LogDirectory $serviceLogDir))
        Wait-HttpReady -Url "$($TeabayBaseUrl.TrimEnd('/'))/health" -TimeoutSeconds $StartupTimeoutSeconds
    }

    if ($StartSavfox) {
        $savfoxBinary = if ($SavfoxBin) {
            $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($SavfoxBin)
        } elseif ($env:SAVFOX_BIN) {
            $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($env:SAVFOX_BIN)
        } else {
            $savfoxTargetDirectory = Get-CargoTargetDirectory -RepositoryRoot $SavfoxRoot
            Join-Path $savfoxTargetDirectory "debug\savfox.exe"
        }
        if (-not (Test-Path -LiteralPath $savfoxBinary -PathType Leaf)) {
            throw "Savfox binary not found: $savfoxBinary"
        }
        foreach ($probe in @($savfoxAddressedProbe, $savfoxUnaddressedProbe)) {
            Start-ManagedSavfoxGateway `
                -Probe $probe `
                -Binary $savfoxBinary `
                -WorkingDirectory $SavfoxRoot `
                -LogDirectory $serviceLogDir `
                -TimeoutSeconds $StartupTimeoutSeconds `
                -ManagedServices $managedServices | Out-Null
        }
    }

    if ($willStartDefaultSoland -and -not $solandDatabaseDsn) {
        $ephemeralSolandPostgres = Start-EphemeralPostgres `
            -Image $SolandPostgresImage `
            -NamePrefix "cotest-soland-$timestamp" `
            -TimeoutSeconds $StartupTimeoutSeconds
        $solandDatabaseDsn = $ephemeralSolandPostgres.Url
    }
    if ($multiServer) {
        $ephemeralSolandServer2Postgres = Start-EphemeralPostgres `
            -Image $SolandPostgresImage `
            -NamePrefix "cotest-soland-server2-$timestamp" `
            -TimeoutSeconds $StartupTimeoutSeconds
        $solandServer2DatabaseDsn = $ephemeralSolandServer2Postgres.Url
    }
    foreach ($server in $additionalServers) {
        $server.SolandDatabase = Start-EphemeralPostgres `
            -Image $SolandPostgresImage `
            -NamePrefix "cotest-$($server.SolandName)-$timestamp" `
            -TimeoutSeconds $StartupTimeoutSeconds
        $server.SolandDatabaseDsn = $server.SolandDatabase.Url
        $additionalPostgresContainers.Add($server.SolandDatabase)
    }

    function Build-SolandDockerEnvironment {
        param(
            [string]$AccountAuthorityBaseUrl = $CoauthBaseUrl,
            [string]$AccountAuthorityServiceId = $CoauthServiceId,
            [Parameter(Mandatory = $true)][string]$BaseUrl,
            [Parameter(Mandatory = $true)][string]$DatabaseUrl,
            [Parameter(Mandatory = $true)][int]$MetricsPort,
            [Parameter(Mandatory = $true)][string]$LogFileName,
            [Parameter(Mandatory = $true)][string]$CorsAllowOrigin,
            [Parameter(Mandatory = $true)][string]$KeyStoreMasterKey,
            [string]$NotarySigningKey = "",
            [string]$FederationPeers = ""
        )

        $rustLog = if ($env:RUST_LOG -and -not [string]::IsNullOrWhiteSpace($env:RUST_LOG)) {
            $env:RUST_LOG
        } else {
            "info"
        }
        $map = [ordered]@{
            RUST_LOG = $rustLog
            DATABASE_URL = (Convert-ToContainerReachableUrl $DatabaseUrl)
            SOLAND_BIND = "0.0.0.0:$SolandContainerPort"
            SOLAND_PUBLIC_BASE_URL = $BaseUrl
            SOLAND_TRUST_DOMAIN = "ak:trust_domain:local.host"
            SOLAND_DEVELOPMENT_MODE = "true"
            SOLAND_FIRST_PROVISIONING = "true"
            SOLAND_KEYSTORE_BACKEND = "encrypted_file"
            SOLAND_KEYSTORE_PATH = "/tmp/soland-state/keystore.v1"
            SOLAND_KEYSTORE_MASTER_KEY = $KeyStoreMasterKey
            SOLAND_SERVICE_IDENTITY_BUNDLE_DIR = "/tmp/soland-state/identity-bundle"
            SOLAND_EMBEDDED_WEBVH_PROVIDER_ENABLED = "true"
            SOLAND_EGRESS_ALLOW_PRIVATE_NETWORKS = "true"
            SOLAND_CORS_ALLOW_ORIGIN = $CorsAllowOrigin
            SOLAND_METRICS_BIND = "0.0.0.0:$MetricsPort"
            SOLAND_OBJECT_STORAGE_BACKEND = "filesystem"
            SOLAND_OBJECT_STORAGE_LOCAL_ROOT = "/tmp/soland-blobs"
            SOLAND_LOG_FILE = "/cotest-logs/$LogFileName"
            SOLAND_LIVEKIT_API_KEY = "did:web:media.example#media-token"
            SOLAND_LIVEKIT_API_SECRET = "joint-e2e-livekit-secret"
            SOLAND_WEBVH_DEGRADED_NO_WITNESS_MAX_SECS = "$WebvhDegradedNoWitnessMaxSecs"
            SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER = $CoauthEmbeddedWebvhRegistrationBearer
        }
        if ($script:UseManagedCoauthAssertionKey) {
            # Public half of patch-coauth-config.py's managed authority key;
            # the Station commits it before deriving its signed DID inception.
            $map.SOLAND_ACCOUNT_AUTHORITY_PUBLIC_KEY_MULTIBASE = "z6Mkfmm57fsb6VL7zVusP8zeA9SYkCKdvUhby2G7Yh8vvQ1P"
            if ($AccountAuthorityBaseUrl) {
                $map.SOLAND_ACCOUNT_AUTHORITY_URL = $AccountAuthorityBaseUrl.TrimEnd("/")
            }
        }
        if ($AccountAuthorityBaseUrl -and $AccountAuthorityServiceId) {
            $coauthPublic = $AccountAuthorityBaseUrl.TrimEnd("/")
            $coauthContainer = (Convert-ToContainerReachableUrl $coauthPublic).TrimEnd("/")
            $map.SOLAND_ACCOUNT_AUTHORITY_URL = $coauthPublic
            $map.SOLAND_ACCOUNT_AUTHORITY_SERVICE_ID = $AccountAuthorityServiceId
            $map.SOLAND_SESSION_GRANT_INTROSPECTION_URL = "$coauthContainer/_arkret/gate/account/session-grants/introspect"
            $map.SOLAND_AUTH_SESSION_LOGOUT_URL = "$coauthContainer/_arkret/gate/account/auth-sessions/logout"
            $map.SOLAND_SESSION_GRANT_INTROSPECTION_BEARER = $CoauthSessionGrantIntrospectionBearer
            $map.SOLAND_OAUTH_CLIENT_ID = $CoauthOAuthClientId
        }
        if ($TeabayBaseUrl) {
            $teabayContainer = (Convert-ToContainerReachableUrl $TeabayBaseUrl).TrimEnd("/")
            $map.SOLAND_DIRECTORY_ANNOUNCE_URL = "$teabayContainer/_arkret/find/directory/announce"
        }
        if ($FederationPeers) {
            $parts = $FederationPeers -split "\|", 2
            $map.SOLAND_FEDERATION_PEERS = Convert-ToContainerReachableUrl $parts[0]
        }
        if ($NotarySigningKey) {
            $map.SOLAND_NOTARY_SIGNING_KEY = $NotarySigningKey
        }
        return $map
    }

    function Build-SolandCommand {
        param(
            [string]$AccountAuthorityBaseUrl = $CoauthBaseUrl,
            [string]$AccountAuthorityServiceId = $CoauthServiceId,
            [Parameter(Mandatory = $true)][string]$BinaryPath,
            [Parameter(Mandatory = $true)][string]$ConfigPath,
            [Parameter(Mandatory = $true)][string]$BaseUrl,
            [Parameter(Mandatory = $true)][string]$DatabaseUrl,
            [Parameter(Mandatory = $true)][string]$ObjectsRoot,
            [Parameter(Mandatory = $true)][string]$StateRoot,
            [Parameter(Mandatory = $true)][int]$Port,
            [Parameter(Mandatory = $true)][int]$MetricsPort,
            [Parameter(Mandatory = $true)][string]$LogFile,
            [Parameter(Mandatory = $true)][string]$CorsAllowOrigin,
            [Parameter(Mandatory = $true)][string]$KeyStoreMasterKey,
            [string]$NotarySigningKey = "",
            [string]$FederationPeers = ""
        )
        $null = New-Item -ItemType Directory -Force -Path $StateRoot
        $rustLog = if ($env:RUST_LOG -and -not [string]::IsNullOrWhiteSpace($env:RUST_LOG)) { $env:RUST_LOG } else { "info" }
        $values = [ordered]@{
            RUST_LOG = $rustLog
            DATABASE_URL = $DatabaseUrl
            SOLAND_PUBLIC_BASE_URL = $BaseUrl
            SOLAND_TRUST_DOMAIN = "ak:trust_domain:local.host"
            SOLAND_DEVELOPMENT_MODE = "true"
            SOLAND_FIRST_PROVISIONING = "true"
            SOLAND_KEYSTORE_BACKEND = "encrypted_file"
            SOLAND_KEYSTORE_PATH = (Join-Path $StateRoot "keystore.v1")
            SOLAND_KEYSTORE_MASTER_KEY = $KeyStoreMasterKey
            SOLAND_SERVICE_IDENTITY_BUNDLE_DIR = (Join-Path $StateRoot "identity-bundle")
            SOLAND_EMBEDDED_WEBVH_PROVIDER_ENABLED = "true"
            SOLAND_EGRESS_ALLOW_PRIVATE_NETWORKS = "true"
            SOLAND_CORS_ALLOW_ORIGIN = $CorsAllowOrigin
            SOLAND_METRICS_BIND = "127.0.0.1:$MetricsPort"
            SOLAND_OBJECT_STORAGE_BACKEND = "filesystem"
            SOLAND_OBJECT_STORAGE_LOCAL_ROOT = $ObjectsRoot
            SOLAND_LOG_FILE = $LogFile
            SOLAND_LIVEKIT_API_KEY = "did:web:media.example#media-token"
            SOLAND_LIVEKIT_API_SECRET = "joint-e2e-livekit-secret"
            SOLAND_WEBVH_DEGRADED_NO_WITNESS_MAX_SECS = "$WebvhDegradedNoWitnessMaxSecs"
            SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER = $CoauthEmbeddedWebvhRegistrationBearer
        }
        if ($script:UseManagedCoauthAssertionKey) {
            $values.SOLAND_ACCOUNT_AUTHORITY_PUBLIC_KEY_MULTIBASE = "z6Mkfmm57fsb6VL7zVusP8zeA9SYkCKdvUhby2G7Yh8vvQ1P"
            if ($AccountAuthorityBaseUrl) {
                $values.SOLAND_ACCOUNT_AUTHORITY_URL = $AccountAuthorityBaseUrl.TrimEnd("/")
            }
        }
        if ($AccountAuthorityBaseUrl -and $AccountAuthorityServiceId) {
            $coauthTrimmed = $AccountAuthorityBaseUrl.TrimEnd("/")
            $values.SOLAND_ACCOUNT_AUTHORITY_URL = $coauthTrimmed
            $values.SOLAND_ACCOUNT_AUTHORITY_SERVICE_ID = $AccountAuthorityServiceId
            $values.SOLAND_SESSION_GRANT_INTROSPECTION_URL = "$coauthTrimmed/_arkret/gate/account/session-grants/introspect"
            $values.SOLAND_AUTH_SESSION_LOGOUT_URL = "$coauthTrimmed/_arkret/gate/account/auth-sessions/logout"
            $values.SOLAND_SESSION_GRANT_INTROSPECTION_BEARER = $CoauthSessionGrantIntrospectionBearer
            $values.SOLAND_OAUTH_CLIENT_ID = $CoauthOAuthClientId
        }
        if ($TeabayBaseUrl) {
            $values.SOLAND_DIRECTORY_ANNOUNCE_URL = "$($TeabayBaseUrl.TrimEnd('/'))/_arkret/find/directory/announce"
        }
        if ($FederationPeers) {
            $values.SOLAND_FEDERATION_PEERS = $FederationPeers
        }
        if ($NotarySigningKey) {
            $values.SOLAND_NOTARY_SIGNING_KEY = $NotarySigningKey
        }
        Write-DotEnvFile -Path $ConfigPath -Values $values
        return "& {{ Remove-Item Env:RUST_MIN_STACK -ErrorAction SilentlyContinue; `$env:SOLAND_ENABLE_TEST_ENDPOINTS='1'; `$env:SOLAND_TEST_CHAOS_CONTROL_FILE={0}; & {1} --config {2} --no-env-overrides --bind 127.0.0.1:{3} }}" -f `
            (Quote-PsLiteral $solandChaosControlFile),
            (Quote-PsLiteral $BinaryPath),
            (Quote-PsLiteral $ConfigPath),
            $Port
    }

    # Coauth is a private component of its owning Station, not a separate
    # service identity. Provision the managed Station first, then pin that
    # persisted identity when enabling its Account Authority process.
    $needsAuthorityBootstrap = $StartCoauth -and $willStartDefaultSoland
    $solandRestartPlans = [System.Collections.Generic.List[object]]::new()
    $solandService = $null
    $solandServer2Service = $null
    if ($CoauthBaseUrl -and -not $StartCoauth -and -not $CoauthServiceId) {
        throw "Caller-owned Coauth requires -CoauthServiceId with its configured owning Station identity"
    }

    # Per-instance tracing files. Windows fully-buffers stdout when
    # `Start-Process -RedirectStandardOutput` may buffer service output on
    # Windows. The `SOLAND_LOG_FILE` path is a second, durable sink soland
    # writes through a non-blocking
    # tracing-appender (see soland/src/main.rs `init_tracing`). This is the
    # file scenarios should `tail -f` when debugging projection / reducer
    # paths against the runner.
    $solandTraceFile = Join-Path $serverServiceLogDirs["server1"] "soland-server1.trace.log"
    $server1Peer = ""
    $solandCorsOrigins = @(
        $InksonBaseUrl
        $inksonServer2BaseUrl
    ) | Where-Object { $_ } | Select-Object -Unique
    $solandCorsAllowOrigin = if (@($solandCorsOrigins).Count -gt 0) {
        $solandCorsOrigins -join ","
    } else {
        "http://127.0.0.1"
    }
    if (-not $SolandCommand -and $solandPort -and $SolandRuntime -eq "process") {
        $generatedSolandCommand = $true
        $solandBinary = Resolve-SolandBinary -ExplicitPath $SolandBin -WorkspaceRoot $workspaceRoot
        $server1Peer = @($allSolandBaseUrls | Where-Object { $_ -ne $SolandBaseUrl }) -join ","
        $solandMetricsPort = Get-FreeTcpPort
        # DID-P1-C02 — process runtime binds the metrics listener on loopback,
        # so the tests can scrape it. The docker runtime below only publishes
        # the HTTP port, so no metrics URL is exported for that mode.
        $solandMetricsBaseUrl = "http://127.0.0.1:$solandMetricsPort"
        $solandProcessArguments = @{
            BinaryPath = $solandBinary
            ConfigPath = $serverArtifactLayouts["server1"].SolandConfigPath
            BaseUrl = $SolandBaseUrl
            DatabaseUrl = $solandDatabaseDsn
            ObjectsRoot = $serverArtifactLayouts["server1"].SolandObjectsRoot
            StateRoot = $serverArtifactLayouts["server1"].SolandStateRoot
            Port = $solandPort
            MetricsPort = $solandMetricsPort
            LogFile = $solandTraceFile
            CorsAllowOrigin = $solandCorsAllowOrigin
            KeyStoreMasterKey = $SolandKeyStoreMasterKey
            NotarySigningKey = $SolandNotarySigningKey
            FederationPeers = $server1Peer
        }
        $SolandCommand = Build-SolandCommand @solandProcessArguments
        if ($jointTlsAssets) {
            $SolandCommand = "`$env:SSL_CERT_FILE=$(Quote-PsLiteral $jointTlsAssets.CaPemPath); $SolandCommand"
        }
    }
    if ($SolandCommand) {
        $solandWorkingDirectory = if ($generatedSolandCommand) { $repoRoot } else { Split-Path -Parent $SutManifest }
        $solandName = "soland-server1"
        $launchName = if ($needsAuthorityBootstrap) { "$solandName-bootstrap" } else { $solandName }
        $solandService = Start-ManagedCommand -Name $launchName -Command $SolandCommand -WorkingDirectory $solandWorkingDirectory -LogDirectory $serverServiceLogDirs["server1"]
        $managedServices.Add($solandService)
        if ($needsAuthorityBootstrap) {
            $solandRestartPlans.Add(@{
                Name = $solandName; BaseUrl = $SolandBaseUrl; Service = $solandService
                ConfigArguments = $solandProcessArguments; Command = $SolandCommand
                WorkingDirectory = $solandWorkingDirectory; LogDirectory = $serverServiceLogDirs["server1"]
            })
        }
    } elseif ($willStartDockerSoland) {
        $server1Peer = @($allSolandBaseUrls | Where-Object { $_ -ne $SolandBaseUrl }) -join ","
        $solandMetricsPort = Get-FreeTcpPort
        $solandDockerArguments = @{
            BaseUrl = $SolandBaseUrl
            DatabaseUrl = $solandDatabaseDsn
            MetricsPort = $solandMetricsPort
            LogFileName = ([System.IO.Path]::GetFileName($solandTraceFile))
            CorsAllowOrigin = $solandCorsAllowOrigin
            KeyStoreMasterKey = $SolandKeyStoreMasterKey
            NotarySigningKey = $SolandNotarySigningKey
            FederationPeers = $server1Peer
        }
        $solandDockerEnv = Build-SolandDockerEnvironment @solandDockerArguments
        $solandName = "soland-server1"
        $solandDockerStartArguments = @{
            Name = $solandName
            Image = $SolandImage
            HostPort = $solandPort
            ContainerPort = $SolandContainerPort
            ObjectsRoot = $serverArtifactLayouts["server1"].SolandObjectsRoot
            StateRoot = $serverArtifactLayouts["server1"].SolandStateRoot
            LogDirectory = $serverServiceLogDirs["server1"]
            Environment = $solandDockerEnv
        }
        if ($needsAuthorityBootstrap) { $solandDockerStartArguments.Name += "-bootstrap" }
        $solandService = Start-ManagedDockerSoland @solandDockerStartArguments
        $managedServices.Add($solandService)
        if ($needsAuthorityBootstrap) {
            $solandRestartPlans.Add(@{
                Name = $solandName; BaseUrl = $SolandBaseUrl; Service = $solandService
                ConfigArguments = $solandDockerArguments; DockerArguments = $solandDockerStartArguments
            })
        }
    }
    Wait-HttpReady -Url "$($SolandBaseUrl.TrimEnd('/'))/health" -TimeoutSeconds $StartupTimeoutSeconds -ManagedService $solandService
    $SolandServiceId = Get-DescribedServiceId -BaseUrl $SolandBaseUrl -ServiceName "soland"
    $SolandServiceDid = Get-DescribedServiceDid -BaseUrl $SolandBaseUrl -ServiceName "soland"

    if ($multiServer) {
        $solandServer2TraceFile = Join-Path $serverServiceLogDirs["server2"] "soland-server2.trace.log"
        $solandServer2MetricsPort = Get-FreeTcpPort
        $solandServer2CorsAllowOrigin = $solandCorsAllowOrigin
        if ($SolandRuntime -eq "docker") {
            $solandServer2DockerArguments = @{
                BaseUrl = $solandServer2BaseUrl
                DatabaseUrl = $solandServer2DatabaseDsn
                MetricsPort = $solandServer2MetricsPort
                LogFileName = ([System.IO.Path]::GetFileName($solandServer2TraceFile))
                CorsAllowOrigin = $solandServer2CorsAllowOrigin
                KeyStoreMasterKey = $SolandServer2KeyStoreMasterKey
                NotarySigningKey = $SolandServer2NotarySigningKey
                FederationPeers = (@($allSolandBaseUrls | Where-Object { $_ -ne $solandServer2BaseUrl }) -join ",")
            }
            $solandServer2DockerEnv = Build-SolandDockerEnvironment @solandServer2DockerArguments
            $solandServer2DockerStartArguments = @{
                Name = "soland-server2"
                Image = $SolandImage
                HostPort = $solandServer2Port
                ContainerPort = $SolandContainerPort
                ObjectsRoot = $serverArtifactLayouts["server2"].SolandObjectsRoot
                StateRoot = $serverArtifactLayouts["server2"].SolandStateRoot
                LogDirectory = $serverServiceLogDirs["server2"]
                Environment = $solandServer2DockerEnv
            }
            if ($needsAuthorityBootstrap) { $solandServer2DockerStartArguments.Name += "-bootstrap" }
            $solandServer2Service = Start-ManagedDockerSoland @solandServer2DockerStartArguments
            $managedServices.Add($solandServer2Service)
            if ($needsAuthorityBootstrap) {
                $solandRestartPlans.Add(@{
                    Name = "soland-server2"; BaseUrl = $solandServer2BaseUrl; Service = $solandServer2Service
                    ConfigArguments = $solandServer2DockerArguments; DockerArguments = $solandServer2DockerStartArguments
                })
            }
        } else {
            $solandServer2ProcessArguments = @{
                BinaryPath = $solandBinary
                ConfigPath = $serverArtifactLayouts["server2"].SolandConfigPath
                BaseUrl = $solandServer2BaseUrl
                DatabaseUrl = $solandServer2DatabaseDsn
                ObjectsRoot = $serverArtifactLayouts["server2"].SolandObjectsRoot
                StateRoot = $serverArtifactLayouts["server2"].SolandStateRoot
                Port = $solandServer2Port
                MetricsPort = $solandServer2MetricsPort
                LogFile = $solandServer2TraceFile
                CorsAllowOrigin = $solandServer2CorsAllowOrigin
                KeyStoreMasterKey = $SolandServer2KeyStoreMasterKey
                NotarySigningKey = $SolandServer2NotarySigningKey
                FederationPeers = (@($allSolandBaseUrls | Where-Object { $_ -ne $solandServer2BaseUrl }) -join ",")
            }
            $solandServer2Command = Build-SolandCommand @solandServer2ProcessArguments
            if ($jointTlsAssets) {
                $solandServer2Command = "`$env:SSL_CERT_FILE=$(Quote-PsLiteral $jointTlsAssets.CaPemPath); $solandServer2Command"
            }
            $launchName = if ($needsAuthorityBootstrap) { "soland-server2-bootstrap" } else { "soland-server2" }
            $solandServer2Service = Start-ManagedCommand -Name $launchName -Command $solandServer2Command -WorkingDirectory $repoRoot -LogDirectory $serverServiceLogDirs["server2"]
            $managedServices.Add($solandServer2Service)
            if ($needsAuthorityBootstrap) {
                $solandRestartPlans.Add(@{
                    Name = "soland-server2"; BaseUrl = $solandServer2BaseUrl; Service = $solandServer2Service
                    ConfigArguments = $solandServer2ProcessArguments; Command = $solandServer2Command
                    WorkingDirectory = $repoRoot; LogDirectory = $serverServiceLogDirs["server2"]
                })
            }
        }
        Wait-HttpReady -Url "$($solandServer2BaseUrl.TrimEnd('/'))/health" -TimeoutSeconds $StartupTimeoutSeconds -ManagedService $solandServer2Service
        $SolandServer2ServiceId = Get-DescribedServiceId -BaseUrl $solandServer2BaseUrl -ServiceName "soland-server2"
        $SolandServer2ServiceDid = Get-DescribedServiceDid -BaseUrl $solandServer2BaseUrl -ServiceName "soland-server2"
    }

    foreach ($server in $additionalServers) {
        $server.SolandMetricsPort = Get-FreeTcpPort
        $traceFile = Join-Path $serverServiceLogDirs[$server.Name] "$($server.SolandName).trace.log"
        $configArguments = @{
            BaseUrl = $server.SolandBaseUrl
            DatabaseUrl = $server.SolandDatabaseDsn
            MetricsPort = $server.SolandMetricsPort
            CorsAllowOrigin = $solandCorsAllowOrigin
            KeyStoreMasterKey = $server.KeyStoreMasterKey
            NotarySigningKey = $server.NotarySigningKey
            FederationPeers = (@($allSolandBaseUrls | Where-Object { $_ -ne $server.SolandBaseUrl }) -join ",")
        }
        if ($SolandRuntime -eq "docker") {
            $configArguments.LogFileName = [System.IO.Path]::GetFileName($traceFile)
            $dockerEnvironment = Build-SolandDockerEnvironment @configArguments
            $startArguments = @{
                Name = $(if ($needsAuthorityBootstrap) { "$($server.SolandName)-bootstrap" } else { $server.SolandName })
                Image = $SolandImage
                HostPort = $server.SolandPort
                ContainerPort = $SolandContainerPort
                ObjectsRoot = $serverArtifactLayouts[$server.Name].SolandObjectsRoot
                StateRoot = $serverArtifactLayouts[$server.Name].SolandStateRoot
                LogDirectory = $serverServiceLogDirs[$server.Name]
                Environment = $dockerEnvironment
            }
            $server.SolandService = Start-ManagedDockerSoland @startArguments
            $managedServices.Add($server.SolandService)
            if ($needsAuthorityBootstrap) {
                $solandRestartPlans.Add(@{ Name = $server.SolandName; BaseUrl = $server.SolandBaseUrl; Service = $server.SolandService; ConfigArguments = $configArguments; DockerArguments = $startArguments })
            }
        } else {
            $configArguments.BinaryPath = $solandBinary
            $configArguments.ConfigPath = $serverArtifactLayouts[$server.Name].SolandConfigPath
            $configArguments.ObjectsRoot = $serverArtifactLayouts[$server.Name].SolandObjectsRoot
            $configArguments.StateRoot = $serverArtifactLayouts[$server.Name].SolandStateRoot
            $configArguments.Port = $server.SolandPort
            $configArguments.LogFile = $traceFile
            $command = Build-SolandCommand @configArguments
            if ($jointTlsAssets) { $command = "`$env:SSL_CERT_FILE=$(Quote-PsLiteral $jointTlsAssets.CaPemPath); $command" }
            $launchName = if ($needsAuthorityBootstrap) { "$($server.SolandName)-bootstrap" } else { $server.SolandName }
            $server.SolandService = Start-ManagedCommand -Name $launchName -Command $command -WorkingDirectory $repoRoot -LogDirectory $serverServiceLogDirs[$server.Name]
            $managedServices.Add($server.SolandService)
            if ($needsAuthorityBootstrap) {
                $solandRestartPlans.Add(@{ Name = $server.SolandName; BaseUrl = $server.SolandBaseUrl; Service = $server.SolandService; ConfigArguments = $configArguments; Command = $command; WorkingDirectory = $repoRoot; LogDirectory = $serverServiceLogDirs[$server.Name] })
            }
        }
        Wait-HttpReady -Url "$($server.SolandBaseUrl.TrimEnd('/'))/health" -TimeoutSeconds $StartupTimeoutSeconds -ManagedService $server.SolandService
        $server.SolandServiceId = Get-DescribedServiceId -BaseUrl $server.SolandBaseUrl -ServiceName $server.SolandName
        $server.SolandServiceDid = Get-DescribedServiceDid -BaseUrl $server.SolandBaseUrl -ServiceName $server.SolandName
    }

    if ($needsAuthorityBootstrap) {
        $CoauthServiceId = $SolandServiceId
        foreach ($plan in $solandRestartPlans) {
            $expectedStationId = Get-DescribedServiceId -BaseUrl $plan.BaseUrl -ServiceName $plan.Name
            Stop-ManagedCommand -Service $plan.Service
            [void]$managedServices.Remove($plan.Service)
            $configArguments = $plan.ConfigArguments
            if ($StartCoauth) {
                $configArguments.AccountAuthorityServiceId = $expectedStationId
                if ($plan.BaseUrl -eq $SolandBaseUrl) {
                    $configArguments.AccountAuthorityBaseUrl = $CoauthBaseUrl
                } elseif ($plan.BaseUrl -eq $solandServer2BaseUrl) {
                    $configArguments.AccountAuthorityBaseUrl = $coauthServer2BaseUrl
                } else {
                    $matchedServer = $additionalServers | Where-Object { $_.SolandBaseUrl -eq $plan.BaseUrl } | Select-Object -First 1
                    if (-not $matchedServer) { throw "No Account Authority mapping exists for $($plan.Name)" }
                    $configArguments.AccountAuthorityBaseUrl = $matchedServer.CoauthBaseUrl
                }
            }
            if ($plan.Service.Kind -eq "docker") {
                $startArguments = $plan.DockerArguments
                $startArguments.Name = $plan.Name
                $startArguments.Environment = Build-SolandDockerEnvironment @configArguments
                $service = Start-ManagedDockerSoland @startArguments
            } else {
                Build-SolandCommand @configArguments | Out-Null
                $service = Start-ManagedCommand -Name $plan.Name -Command $plan.Command -WorkingDirectory $plan.WorkingDirectory -LogDirectory $plan.LogDirectory
            }
            $managedServices.Add($service)
            Wait-HttpReady -Url "$($plan.BaseUrl.TrimEnd('/'))/health" -TimeoutSeconds $StartupTimeoutSeconds -ManagedService $service
            $restartedStationId = Get-DescribedServiceId -BaseUrl $plan.BaseUrl -ServiceName $plan.Name
            if ($restartedStationId -ne $expectedStationId) {
                throw "Station identity changed while enabling Account Authority: $($plan.Name)"
            }
        }
    }

    if ($StartCoauth) {
        $CoauthServiceId = $SolandServiceId
        $stationServiceIds = [ordered]@{ server1 = $SolandServiceId }
        if ($SolandServer2ServiceId) { $stationServiceIds.server2 = $SolandServer2ServiceId }
        foreach ($server in $additionalServers) { $stationServiceIds[$server.Name] = $server.SolandServiceId }
        Set-CoauthStationServiceIds -ConfigPath $coauthConfigPath -StationServiceIds $stationServiceIds
        if ($DualCoauth) {
            Set-CoauthStationServiceIds -ConfigPath $coauthSecondaryConfigPath -StationServiceIds $stationServiceIds
        }
        Invoke-CoauthConfigSync -CoauthBinary $coauthBinary -ConfigPath $coauthConfigPath -LogDirectory $coauthServer1Dir
        if ($coauthServer2ConfigPath) {
            Set-CoauthStationServiceIds -ConfigPath $coauthServer2ConfigPath -StationServiceIds $stationServiceIds
            Invoke-CoauthConfigSync -CoauthBinary $coauthBinary -ConfigPath $coauthServer2ConfigPath -LogDirectory (Split-Path -Parent $coauthServer2ConfigPath)
        }
        foreach ($server in $additionalServers) {
            Set-CoauthStationServiceIds -ConfigPath $server.CoauthConfigPath -StationServiceIds $stationServiceIds
            Invoke-CoauthConfigSync -CoauthBinary $coauthBinary -ConfigPath $server.CoauthConfigPath -LogDirectory (Split-Path -Parent $server.CoauthConfigPath)
        }
    }

    if ($CoauthCommand) {
        if (-not $CoauthBaseUrl -and -not $CoauthHealthUrl) {
            throw "CoauthCommand requires CoauthBaseUrl or CoauthHealthUrl"
        }
        $coauthWorkingDirectory = if ($StartCoauth) { Join-Path $workspaceRoot "coauth" } else { $workspaceRoot }
        $managedServices.Add((Start-ManagedCommand -Name "coauth-server1" -Command $CoauthCommand -WorkingDirectory $coauthWorkingDirectory -LogDirectory $serverServiceLogDirs["server1"]))
        $health = if ($CoauthHealthUrl) { $CoauthHealthUrl } else { "$($CoauthBaseUrl.TrimEnd('/'))/health" }
        Wait-HttpReady -Url $health -TimeoutSeconds $StartupTimeoutSeconds
    }
    if ($CoauthSecondaryCommand) {
        $managedServices.Add((Start-ManagedCommand -Name "coauth-secondary" -Command $CoauthSecondaryCommand -WorkingDirectory (Join-Path $workspaceRoot "coauth") -LogDirectory $serviceLogDir))
        Wait-HttpReady -Url "$coauthSecondaryBaseUrl/health" -TimeoutSeconds $StartupTimeoutSeconds
    }
    if ($CoauthServer2Command) {
        $managedServices.Add((Start-ManagedCommand -Name "coauth-server2" -Command $CoauthServer2Command -WorkingDirectory (Join-Path $workspaceRoot "coauth") -LogDirectory $serverServiceLogDirs["server2"]))
        Wait-HttpReady -Url "$coauthServer2BaseUrl/health" -TimeoutSeconds $StartupTimeoutSeconds
    }
    foreach ($server in $additionalServers) {
        if ($server.CoauthCommand) {
            $coauthService = Start-ManagedCommand -Name $server.CoauthName -Command $server.CoauthCommand -WorkingDirectory (Join-Path $workspaceRoot "coauth") -LogDirectory $serverServiceLogDirs[$server.Name]
            $managedServices.Add($coauthService)
            $server | Add-Member -NotePropertyName CoauthService -NotePropertyValue $coauthService -Force
            Wait-HttpReady -Url "$($server.CoauthBaseUrl)/health" -TimeoutSeconds $StartupTimeoutSeconds -ManagedService $coauthService
        }
    }

    $inksonService = $null
    $inksonServer2Service = $null
    $generatedInksonServer2Command = $false
    # Absolute path to the provisioning bridge, so callers exec it instead of
    # paying Cargo discovery and the build-directory lock. It is a long-lived
    # process — the TypeScript side spawns one per Playwright worker — which
    # makes `cargo run` per invocation worse here than it was for cotest-wire.
    $provisionBinary = Join-Path $cotestTargetDirectory "debug\cotest-provision.exe"
    if (Test-Path -LiteralPath $provisionBinary) {
        $env:COTEST_PROVISION_BIN = $provisionBinary
    } else {
        Remove-Item Env:COTEST_PROVISION_BIN -ErrorAction SilentlyContinue
        # Say it out loud. Without the bridge the canonical provisioning specs
        # skip, and a skip that only shows up as a missing line in the report is
        # how a lane keeps passing while testing less than it did.
        Write-Warning ("no provisioning bridge at {0}; canonical provisioning scenarios will skip" -f $provisionBinary)
    }

    if ($requiresInkson -and -not $InksonCommand -and $inksonPort) {
        $InksonCommand = "node {0} {1} {2} 127.0.0.1" -f `
            (Quote-PsLiteral (Join-Path $e2eRoot "scripts\serve-static.mjs")),
            (Quote-PsLiteral $inksonStaticRoot),
            $inksonPort
        $generatedInksonCommand = $true
    }
    if ($requiresInkson -and $InksonCommand) {
        $inksonName = "inkson-server1"
        $inksonService = Start-ManagedCommand -Name $inksonName -Command $InksonCommand -WorkingDirectory $InksonRoot -LogDirectory $serviceLogDir
        $managedServices.Add($inksonService)
    }
    # This readiness wait used to be unconditional, which is what forced a
    # browserless run to point `-InksonBaseUrl` at a placeholder and then hang
    # on it for the whole startup timeout.
    if ($requiresInkson) {
        Wait-HttpReady -Url $InksonBaseUrl -TimeoutSeconds $StartupTimeoutSeconds
        if ($generatedInksonCommand) {
            Wait-DioxusAppReady -Url $InksonBaseUrl -TimeoutSeconds $StartupTimeoutSeconds
        }
    }
    if ($requiresInkson -and $multiServer -and $inksonServer2BaseUrl -and $inksonServer2BaseUrl -ne $InksonBaseUrl) {
        if (-not $InksonServer2Command -and $inksonServer2Port) {
            $InksonServer2Command = "node {0} {1} {2} 127.0.0.1" -f `
                (Quote-PsLiteral (Join-Path $e2eRoot "scripts\serve-static.mjs")),
                (Quote-PsLiteral $inksonStaticRoot),
                $inksonServer2Port
            $generatedInksonServer2Command = $true
        }
        if ($InksonServer2Command) {
            $inksonServer2Service = Start-ManagedCommand -Name "inkson-server2" -Command $InksonServer2Command -WorkingDirectory $InksonRoot -LogDirectory $serviceLogDir
            $managedServices.Add($inksonServer2Service)
        }
        Wait-HttpReady -Url $inksonServer2BaseUrl -TimeoutSeconds $StartupTimeoutSeconds
        if ($generatedInksonServer2Command) {
            Wait-DioxusAppReady -Url $inksonServer2BaseUrl -TimeoutSeconds $StartupTimeoutSeconds
        }
    }

    # 0530-C: prove the HTTPS identity topology before any business test runs.
    # A failure here is a topology defect, not a product regression, so it must
    # not be allowed to masquerade as 94 misleading testcase failures.
    if ($jointTlsEnabled) {
        if (-not $env:COTEST_WIRE_BIN) {
            throw "joint TLS topology verification requires the cotest-wire binary; rerun without -SkipBuild or set COTEST_WIRE_BIN"
        }
        $jointTlsServices = @()
        if ($solandPublicHost -and $SolandServiceDid) {
            $jointTlsServices += [pscustomobject]@{ Name = "soland-server1"; ServiceDid = $SolandServiceDid }
        }
        if ($solandServer2PublicHost -and $SolandServer2ServiceDid) {
            $jointTlsServices += [pscustomobject]@{ Name = "soland-server2"; ServiceDid = $SolandServer2ServiceDid }
        }
        foreach ($server in $additionalServers) {
            if ($server.SolandHost -and $server.SolandServiceDid) {
                $jointTlsServices += [pscustomobject]@{ Name = $server.SolandName; ServiceDid = $server.SolandServiceDid }
            }
        }
        Assert-JointTlsTopology `
            -TlsPort $jointTlsPort `
            -TrustedHosts $jointTlsHostNames `
            -UnregisteredProbeHost $jointTlsUnregisteredProbeHost `
            -CaPemPath $jointTlsAssets.CaPemPath `
            -ServerPemPath $jointTlsAssets.ServerPemPath `
            -CotestWireBin $env:COTEST_WIRE_BIN `
            -EvidenceDir (Join-Path $jointDir "tls-preflight") `
            -Services $jointTlsServices
    }

    $env:COTEST_JOINT_RUN_DIR = $jointDir
    $env:COTEST_UI_SCREENSHOT_DIR = $screenshotDir
    $env:COTEST_UI_VISUAL_BASELINE_DIR = $visualBaselineDir
    $env:COTEST_SOLAND_BASE_URL = $SolandBaseUrl
    $env:COTEST_SOLAND_SERVICE_ID = $SolandServiceId
    $env:COTEST_SOLAND_SERVICE_DID = $SolandServiceDid
    $env:COTEST_SERVER_COUNT = "$ServerCount"
    $env:COTEST_REQUIRED_SERVER_COUNT = if ($ServerCount -ge 3 -and $RunProfile -eq "joint-full") { "3" } else { "0" }
    if ($generatedSolandCommand -and $solandDatabaseDsn) {
        $env:COTEST_SOLAND_CHAOS_CONTROL_FILE = $solandChaosControlFile
        $env:COTEST_SOLAND_STORAGE = "postgres"
        if ($RequireDecisionRace) {
            $env:COTEST_REQUIRE_DECISION_RACE = "1"
        } else {
            Remove-Item Env:COTEST_REQUIRE_DECISION_RACE -ErrorAction SilentlyContinue
        }
    } else {
        Remove-Item Env:COTEST_SOLAND_CHAOS_CONTROL_FILE -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_SOLAND_STORAGE -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_REQUIRE_DECISION_RACE -ErrorAction SilentlyContinue
    }
    $env:COTEST_EMBEDDED_WEBVH_REGISTRATION_BEARER = $CoauthEmbeddedWebvhRegistrationBearer
    if ($SolandNotarySigningKey) {
        # The peer-surface fixtures must sign as the configured service
        # identity. A deterministic development key is only correct when the
        # managed Soland instance also uses that fallback.
        $env:COTEST_SOLAND_SERVICE_SIGNING_KEY = $SolandNotarySigningKey
    } else {
        Remove-Item Env:COTEST_SOLAND_SERVICE_SIGNING_KEY -ErrorAction SilentlyContinue
    }
    # The Applet author must inherit the described Station coordinates and
    # its configured signing material before starting the mock process.
    if ($StartMockAppletRegistry) {
        $mockAppletRegistryStateFile = Join-Path $serviceLogDir "mock-applet-registry-state.json"
        $mockAppletRegistryStateKeyFile = Join-Path ([System.IO.Path]::GetTempPath()) "cotest-mock-applet-registry-$timestamp.key"
        [System.IO.File]::WriteAllBytes(
            $mockAppletRegistryStateKeyFile,
            [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
        )
        $envExpr = "`$env:MOCK_APPLET_REGISTRY_PORT='$mockAppletRegistryPort'; `$env:MOCK_APPLET_REGISTRY_STATE_FILE=" + (Quote-PsLiteral $mockAppletRegistryStateFile) + "; `$env:MOCK_APPLET_REGISTRY_STATE_KEY_FILE=" + (Quote-PsLiteral $mockAppletRegistryStateKeyFile)
        if ($MockAppletRegistryDid) {
            $envExpr = "$envExpr; `$env:MOCK_APPLET_REGISTRY_DID=" + (Quote-PsLiteral $MockAppletRegistryDid)
        }
        $mockAppletRegistryCmd = "$envExpr; node " + (Quote-PsLiteral (Join-Path $mocksRoot "mock-applet-registry.mjs"))
        $managedServices.Add((Start-ManagedCommand -Name "mock-applet-registry" -Command $mockAppletRegistryCmd -WorkingDirectory $mocksRoot -LogDirectory $serviceLogDir))
        Wait-HttpReady -Url "$mockAppletRegistryBaseUrl/identity" -TimeoutSeconds 30
    }
    if ($InksonBaseUrl) {
        $env:COTEST_INKSON_BASE_URL = $InksonBaseUrl
    } else {
        Remove-Item Env:COTEST_INKSON_BASE_URL -ErrorAction SilentlyContinue
    }
    $runtimeServers.Clear()
    $runtimeServers.Add([pscustomobject]@{ Index = 1; Name = "server1"; SolandBaseUrl = $SolandBaseUrl; SolandServiceId = $SolandServiceId; SolandServiceDid = $SolandServiceDid; SolandPort = $solandPort; SolandService = $solandService; SolandDatabase = $ephemeralSolandPostgres; CoauthBaseUrl = $CoauthBaseUrl; CoauthPort = $coauthPort; CoauthConfigPath = $coauthConfigPath; InksonBaseUrl = $InksonBaseUrl; SigningKey = $SolandNotarySigningKey })
    if ($multiServer) {
        $runtimeServers.Add([pscustomobject]@{ Index = 2; Name = "server2"; SolandBaseUrl = $solandServer2BaseUrl; SolandServiceId = $SolandServer2ServiceId; SolandServiceDid = $SolandServer2ServiceDid; SolandPort = $solandServer2Port; SolandService = $solandServer2Service; SolandDatabase = $ephemeralSolandServer2Postgres; CoauthBaseUrl = $coauthServer2BaseUrl; CoauthPort = $coauthServer2Port; CoauthConfigPath = $coauthServer2ConfigPath; InksonBaseUrl = $(if ($inksonServer2BaseUrl) { $inksonServer2BaseUrl } else { $InksonBaseUrl }); SigningKey = $SolandServer2NotarySigningKey })
    }
    foreach ($server in $additionalServers) {
        $runtimeServers.Add([pscustomobject]@{ Index = $server.Index; Name = $server.Name; SolandBaseUrl = $server.SolandBaseUrl; SolandServiceId = $server.SolandServiceId; SolandServiceDid = $server.SolandServiceDid; SolandPort = $server.SolandPort; SolandService = $server.SolandService; SolandDatabase = $server.SolandDatabase; CoauthBaseUrl = $server.CoauthBaseUrl; CoauthPort = $server.CoauthPort; CoauthConfigPath = $server.CoauthConfigPath; InksonBaseUrl = $InksonBaseUrl; SigningKey = $server.NotarySigningKey })
    }
    foreach ($server in $runtimeServers) {
        $solandStoragePrefix = if ($server.Index -eq 1) { "soland" } else { "soland-$($server.Name)" }
        Set-Item -Path "Env:COTEST_SOLAND_$($server.Name.ToUpperInvariant())_BASE_URL" -Value $server.SolandBaseUrl
        Set-Item -Path "Env:COTEST_SOLAND_$($server.Name.ToUpperInvariant())_SERVICE_ID" -Value $server.SolandServiceId
        Set-Item -Path "Env:COTEST_SOLAND_$($server.Name.ToUpperInvariant())_SERVICE_DID" -Value $server.SolandServiceDid
        if ($server.SigningKey) { Set-Item -Path "Env:COTEST_SOLAND_$($server.Name.ToUpperInvariant())_SERVICE_SIGNING_KEY" -Value $server.SigningKey }
        if ($server.InksonBaseUrl) { Set-Item -Path "Env:COTEST_INKSON_$($server.Name.ToUpperInvariant())_BASE_URL" -Value $server.InksonBaseUrl }
        if ($server.CoauthBaseUrl) { Set-Item -Path "Env:COTEST_COAUTH_$($server.Name.ToUpperInvariant())_BASE_URL" -Value $server.CoauthBaseUrl }
    }
    $topologyServers = @()
    foreach ($server in $runtimeServers) {
        $solandStoragePrefix = if ($server.Index -eq 1) { "soland" } else { "soland-$($server.Name)" }
        $solandManaged = @($managedServices | Where-Object { $_.Name -eq "soland-$($server.Name)" }) | Select-Object -Last 1
        $coauthManaged = @($managedServices | Where-Object { $_.Name -eq "coauth-$($server.Name)" }) | Select-Object -Last 1
        $peerNames = @($runtimeServers | Where-Object { $_.Name -ne $server.Name } | ForEach-Object { $_.Name })
        if ($NetworkShape -eq "ordered-candidates") {
            $peerNames = @(
                for ($offset = 1; $offset -lt $runtimeServers.Count; $offset++) {
                    $candidateIndex = (($server.Index - 1 + $offset) % $runtimeServers.Count) + 1
                    "server$candidateIndex"
                }
            )
        }
        $topologyServers += [pscustomobject]@{
            name = $server.Name
            role = "station"
            soland = [pscustomobject]@{
                public_url = $server.SolandBaseUrl
                listen_address = if ($server.SolandPort) { "127.0.0.1:$($server.SolandPort)" } else { $null }
                service_id = $server.SolandServiceId
                service_did = $server.SolandServiceDid
                storage = [pscustomobject]@{
                    database = if ($server.SolandDatabase) { $server.SolandDatabase.ContainerName } else { "caller-owned" }
                    objects = Join-Path $jointDir "$solandStoragePrefix-objects"
                    state = Join-Path $jointDir "$solandStoragePrefix-state"
                }
                log_directory = $serverServiceLogDirs[$server.Name]
                process_id = if ($solandManaged -and $solandManaged.Kind -eq "process") { $solandManaged.Process.Id } else { $null }
                container_id = if ($solandManaged -and $solandManaged.Kind -eq "docker") { $solandManaged.ContainerName } else { $null }
                control = if ($solandManaged) { [pscustomobject]@{
                    kind = $solandManaged.Kind
                    script_path = (Join-Path $PSScriptRoot "control-joint-e2e-service.ps1")
                    state_path = (Join-Path $jointDir "controls\$($server.Name).json")
                    working_directory = if ($solandManaged.Kind -eq "process") { $solandManaged.WorkingDirectory } else { $null }
                    command_log = if ($solandManaged.Kind -eq "process") { $solandManaged.CommandLog } else { $null }
                } } else { $null }
            }
            coauth = if ($server.CoauthBaseUrl) { [pscustomobject]@{
                public_url = $server.CoauthBaseUrl
                listen_address = if ($server.CoauthPort) { "127.0.0.1:$($server.CoauthPort)" } else { $null }
                owning_service_id = $server.SolandServiceId
                storage = [pscustomobject]@{ database = if ($server.Index -eq 1 -and $ephemeralCoauthServer1Postgres) { $ephemeralCoauthServer1Postgres.ContainerName } elseif ($server.Index -eq 2 -and $ephemeralCoauthServer2Postgres) { $ephemeralCoauthServer2Postgres.ContainerName } elseif ($server.Index -ge 3) { $additionalServers[$server.Index - 3].CoauthDatabase.ContainerName } else { "caller-owned" }; state = Split-Path -Parent $server.CoauthConfigPath }
                config_path = $server.CoauthConfigPath
                log_directory = $serverServiceLogDirs[$server.Name]
                process_id = if ($coauthManaged -and $coauthManaged.Kind -eq "process") { $coauthManaged.Process.Id } else { $null }
                container_id = $null
            } } else { $null }
            peers = $peerNames
            candidate_sources = $peerNames
        }
    }
    $topology = [pscustomobject]@{
        schema = "cotest.joint-topology.v1"
        generated_at = (Get-Date).ToUniversalTime().ToString("o")
        lifecycle = "running"
        network_shape = $NetworkShape
        server_count = $ServerCount
        tls = [pscustomobject]@{ enabled = [bool]$jointTlsEnabled; port = $jointTlsPort; ca_path = if ($jointTlsAssets) { $jointTlsAssets.CaPemPath } else { $null }; unregistered_probe = if ($jointTlsPort) { "https://unregistered.local.host:$jointTlsPort" } else { $null } }
        servers = $topologyServers
    }
    $topologyCandidatePath = Join-Path $jointDir "topology.candidate.json"
    $topology | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $topologyCandidatePath -Encoding utf8NoBOM
    Assert-CotestTopologyIsolation -Topology $topology
    $topology | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $topologyPath -Encoding utf8NoBOM
    Remove-Item -LiteralPath $topologyCandidatePath -ErrorAction SilentlyContinue
    $env:COTEST_TOPOLOGY_PATH = $topologyPath
    if ($CoauthBaseUrl) {
        Assert-CoauthDpopGrantSeamReady -BaseUrl $CoauthBaseUrl
        $env:COTEST_COAUTH_BASE_URL = $CoauthBaseUrl.TrimEnd("/")
        if ($coauthServer2BaseUrl) {
            Assert-CoauthDpopGrantSeamReady -BaseUrl $coauthServer2BaseUrl
        }
        foreach ($server in $additionalServers) { Assert-CoauthDpopGrantSeamReady -BaseUrl $server.CoauthBaseUrl }
        $env:COTEST_COAUTH_SERVICE_ID = $CoauthServiceId
        $env:COTEST_COAUTH_SESSION_GRANT_INTROSPECTION_BEARER = $CoauthSessionGrantIntrospectionBearer
        # The OAuth client_id soland is configured to advertise (see
        # SOLAND_OAUTH_CLIENT_ID in the generated soland config). Surfaced to e2e so
        # oidc-login-chain.spec.ts can assert /_arkret/describe advertises it.
        $env:COTEST_OIDC_CLIENT_ID = $CoauthOAuthClientId
        # The notary signing seed this run configured soland with. A Rust
        # scenario attaching to this deployment cannot derive the notary
        # descriptor from `/_arkret/describe` — the seed is the operator's — so
        # it has to be told which key the runner chose.
        $env:COTEST_SOLAND_NOTARY_SIGNING_KEY = $SolandNotarySigningKey
        $env:COTEST_CLIENT_KIND = $ClientKind
        # Anti-false-green: coauth is up, so the crown-jewel cross-member paths
        # (MLS decrypt, cross-member kanban, multi-profile) MUST run. This flag
        # turns their "coauth session unavailable" branch from a silent
        # test.skip() into a hard failure (helpers/users.ts
        # assertJointStackNotRequired), so a green joint run genuinely means those
        # flows executed rather than self-disabled.
        $env:COTEST_REQUIRE_JOINT_STACK = "1"
        # The joint harness provisions coauth with the dev login/consent hooks
        # and deterministic registration code required by the real browser OIDC
        # lifecycle specs. Keep these critical regressions in the default
        # joint-smoke gate instead of requiring a manual opt-in.
        $env:COTEST_REAL_OIDC_LOGIN = "1"
        if ($coauthSecondaryBaseUrl) {
            $env:COTEST_COAUTH_SECONDARY_BASE_URL = $coauthSecondaryBaseUrl
        } else {
            Remove-Item Env:COTEST_COAUTH_SECONDARY_BASE_URL -ErrorAction SilentlyContinue
        }
    } else {
        Remove-Item Env:COTEST_COAUTH_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_COAUTH_SERVICE_ID -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_COAUTH_SESSION_GRANT_INTROSPECTION_BEARER -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_OIDC_CLIENT_ID -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_SOLAND_NOTARY_SIGNING_KEY -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_CLIENT_KIND -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_REQUIRE_JOINT_STACK -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_REAL_OIDC_LOGIN -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_COAUTH_SECONDARY_BASE_URL -ErrorAction SilentlyContinue
    }
    if ($TeabayBaseUrl) {
        $env:COTEST_TEABAY_BASE_URL = $TeabayBaseUrl.TrimEnd("/")
        $env:COTEST_TEABAY_SERVICE_ID = $TeabayServiceId
    } else {
        Remove-Item Env:COTEST_TEABAY_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_TEABAY_SERVICE_ID -ErrorAction SilentlyContinue
    }
    # DID-P1-C02 — the two DID-boundary counter endpoints. Only exported when
    # this run actually owns the listener: an unset variable makes the metrics
    # helpers report "not part of this run" instead of silently scraping some
    # other process's counters (the default binds are the fixed 9090 / 9095,
    # which a developer's dev stack is very likely already holding).
    if ($solandMetricsBaseUrl) {
        $env:COTEST_SOLAND_METRICS_URL = $solandMetricsBaseUrl
    } else {
        Remove-Item Env:COTEST_SOLAND_METRICS_URL -ErrorAction SilentlyContinue
    }
    if ($teabayMetricsBaseUrl) {
        $env:COTEST_TEABAY_METRICS_URL = $teabayMetricsBaseUrl
    } else {
        Remove-Item Env:COTEST_TEABAY_METRICS_URL -ErrorAction SilentlyContinue
    }
    if ($StartSavfox) {
        $env:COTEST_SAVFOX_BASE_URL = $SavfoxBaseUrl.TrimEnd("/")
        $env:COTEST_SAVFOX_TOKEN = $SavfoxToken
        $env:COTEST_SAVFOX_MODEL_RECEIPTS = $savfoxModelReceipts
        $env:COTEST_SAVFOX_UNADDRESSED_BASE_URL = $savfoxUnaddressedBaseUrl.TrimEnd("/")
        $env:COTEST_SAVFOX_UNADDRESSED_TOKEN = $savfoxUnaddressedToken
        $env:COTEST_SAVFOX_UNADDRESSED_MODEL_RECEIPTS = $savfoxUnaddressedModelReceipts
        $env:COTEST_REQUIRE_SAVFOX = "1"
    } else {
        Remove-Item Env:COTEST_SAVFOX_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_SAVFOX_TOKEN -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_SAVFOX_MODEL_RECEIPTS -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_SAVFOX_UNADDRESSED_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_SAVFOX_UNADDRESSED_TOKEN -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_SAVFOX_UNADDRESSED_MODEL_RECEIPTS -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_REQUIRE_SAVFOX -ErrorAction SilentlyContinue
    }
    if ($mockIdpBaseUrl) {
        $env:COTEST_MOCK_IDP_BASE_URL = $mockIdpBaseUrl
    } else {
        Remove-Item Env:COTEST_MOCK_IDP_BASE_URL -ErrorAction SilentlyContinue
    }
    if ($mockEmailBaseUrl) {
        $env:COTEST_MOCK_EMAIL_BASE_URL = $mockEmailBaseUrl
    } else {
        Remove-Item Env:COTEST_MOCK_EMAIL_BASE_URL -ErrorAction SilentlyContinue
    }
    $env:COTEST_WEBVH_DEGRADED_NO_WITNESS_MAX_SECS = "$WebvhDegradedNoWitnessMaxSecs"
    if ($mockWitnessBaseUrl) {
        $env:COTEST_MOCK_WITNESS_BASE_URL = $mockWitnessBaseUrl
        $env:COTEST_MOCK_WITNESS_DID = $MockWitnessDid
        $env:COTEST_MOCK_WITNESS_QUORUM_BASE_URLS = ($mockWitnessQuorumBaseUrls -join ",")
        $env:COTEST_MOCK_WITNESS_QUORUM_DIDS = ($mockWitnessQuorumDids -join ",")
    } else {
        Remove-Item Env:COTEST_MOCK_WITNESS_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_MOCK_WITNESS_DID -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_MOCK_WITNESS_QUORUM_BASE_URLS -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_MOCK_WITNESS_QUORUM_DIDS -ErrorAction SilentlyContinue
    }
    if ($mockPushGatewayBaseUrl) {
        $env:COTEST_MOCK_PUSH_GATEWAY_BASE_URL = $mockPushGatewayBaseUrl
    } else {
        Remove-Item Env:COTEST_MOCK_PUSH_GATEWAY_BASE_URL -ErrorAction SilentlyContinue
    }
    if ($mockAppletRegistryBaseUrl) {
        $env:COTEST_MOCK_APPLET_REGISTRY_BASE_URL = $mockAppletRegistryBaseUrl
    } else {
        Remove-Item Env:COTEST_MOCK_APPLET_REGISTRY_BASE_URL -ErrorAction SilentlyContinue
    }
    if ($mockTspEndpointBaseUrl) {
        $env:COTEST_MOCK_TSP_ENDPOINT_BASE_URL = $mockTspEndpointBaseUrl
        if ($MockTspEndpointVid) {
            $env:COTEST_MOCK_TSP_ENDPOINT_VID = $MockTspEndpointVid
        } else {
            Remove-Item Env:COTEST_MOCK_TSP_ENDPOINT_VID -ErrorAction SilentlyContinue
        }
    } else {
        Remove-Item Env:COTEST_MOCK_TSP_ENDPOINT_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_MOCK_TSP_ENDPOINT_VID -ErrorAction SilentlyContinue
    }
    if ($mockMimiFacadeBaseUrl) {
        $env:COTEST_MOCK_MIMI_FACADE_BASE_URL = $mockMimiFacadeBaseUrl
        $env:COTEST_MOCK_MIMI_FACADE_DID = $MockMimiFacadeDid
    } else {
        Remove-Item Env:COTEST_MOCK_MIMI_FACADE_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_MOCK_MIMI_FACADE_DID -ErrorAction SilentlyContinue
    }
    if ($mockClaimIssuerBaseUrl) {
        $env:COTEST_MOCK_CLAIM_ISSUER_BASE_URL = $mockClaimIssuerBaseUrl
    } else {
        Remove-Item Env:COTEST_MOCK_CLAIM_ISSUER_BASE_URL -ErrorAction SilentlyContinue
    }
    if ($mockChallengeProviderBaseUrl) {
        $env:COTEST_MOCK_CHALLENGE_PROVIDER_BASE_URL = $mockChallengeProviderBaseUrl
        $env:COTEST_MOCK_CHALLENGE_PROVIDER_DID = $MockChallengeProviderDid
    } else {
        Remove-Item Env:COTEST_MOCK_CHALLENGE_PROVIDER_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_MOCK_CHALLENGE_PROVIDER_DID -ErrorAction SilentlyContinue
    }
    # DID-P1-C01. NOTE: these are consumed by cotest's own harness
    # (e2e/helpers/did-host.ts, src/scenarios/_helpers/did_host.rs) only. The
    # services under test cannot currently be pointed at this host — soland /
    # teabay / the SDK derive the DID-document URL from the DID string itself
    # and judge egress per request against configured trust anchors (0530-C:
    # joint services resolve through the TLS-fronted `<service>.local.host`
    # names, not this mock), with no resolver-base-URL or host-override env.
    # See the DID-P1-C01 report.
    if ($mockDidHostBaseUrl) {
        $env:COTEST_MOCK_DID_HOST_BASE_URL = $mockDidHostBaseUrl
        $env:COTEST_MOCK_DID_HOST_AUTHORITY = $MockDidHostAuthority
        $env:COTEST_MOCK_DID_HOST_SCID = $MockDidHostScid
    } else {
        Remove-Item Env:COTEST_MOCK_DID_HOST_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_MOCK_DID_HOST_AUTHORITY -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_MOCK_DID_HOST_SCID -ErrorAction SilentlyContinue
    }

    # The Rust provisioning module against the deployment this run owns.
    #
    # It has to run here and nowhere else: it needs a real Coauth and Soland,
    # and `-KeepServices` does not outlive a runner started as a background
    # process, so there is no way to hand a running deployment to a separate
    # `cargo test` invocation. Placing it before Playwright also means a broken
    # canonical provisioning chain fails here, with its own error, rather than
    # as a wave of "no session grant" failures across the suite.
    #
    # Failure is fatal. The whole point of the module is that a test suite and a
    # Rust scenario prepare identities the same way; a check that is allowed to
    # soft-skip proves nothing about that.
    if ($StartCoauth) {
        Write-Host ""
        Write-Host "=== Rust provisioning check (live Coauth + Soland) ==="
        $provisioningLog = Join-Path $jointDir "rust-provisioning-check.log"
        $provisioningArgs = @(
            "test", "--manifest-path", (Join-Path $repoRoot "Cargo.toml"),
            "-p", "cotest-test-support", "--test", "provisioning_live",
            "--", "--ignored", "--nocapture"
        )
        $provisioningOutput = & cargo @provisioningArgs 2>&1
        $provisioningExit = $LASTEXITCODE
        $provisioningOutput | Set-Content -LiteralPath $provisioningLog -Encoding UTF8
        foreach ($line in $provisioningOutput) { Write-Host $line }
        if ($provisioningExit -ne 0) {
            throw "Rust provisioning check failed (exit=$provisioningExit); see $provisioningLog"
        }

        # The same deployment, one layer up: `ArkretServer::canonical_client`
        # building a `TestActorClient` on a canonical session.
        #
        # Opt-in because it lives in the root package, and building that pulls
        # the 952-crate graph the `joint-api` lane exists to avoid. The check
        # above stays on by default precisely because `cotest-test-support` is
        # the light edge.
        if ($RunHarnessClientCheck) {
            Write-Host ""
            Write-Host "=== Rust harness client check (live Coauth + Soland) ==="
            $harnessClientLog = Join-Path $jointDir "rust-harness-client-check.log"
            $harnessClientArgs = @(
                "test", "--manifest-path", (Join-Path $repoRoot "Cargo.toml"),
                "-p", "cotest", "--test", "canonical_client_live",
                "--", "--ignored", "--nocapture"
            )
            $harnessClientOutput = & cargo @harnessClientArgs 2>&1
            $harnessClientExit = $LASTEXITCODE
            $harnessClientOutput | Set-Content -LiteralPath $harnessClientLog -Encoding UTF8
            foreach ($line in $harnessClientOutput) { Write-Host $line }
            if ($harnessClientExit -ne 0) {
                throw "Rust harness client check failed (exit=$harnessClientExit); see $harnessClientLog"
            }
        }

        # Garth as a client, headless. Cotest otherwise touches Garth only as a
        # builder, so without this its client runtime has no consumer outside
        # Inkson's browser.
        if ($RunGarthClientCheck) {
            Write-Host ""
            Write-Host "=== Garth client check (live Coauth + Soland) ==="
            $garthClientLog = Join-Path $jointDir "garth-client-check.log"
            $garthClientArgs = @(
                "test", "--manifest-path", (Join-Path $repoRoot "Cargo.toml"),
                "-p", "cotest", "--test", "garth_client_live",
                "--", "--ignored", "--nocapture"
            )
            $garthClientOutput = & cargo @garthClientArgs 2>&1
            $garthClientExit = $LASTEXITCODE
            $garthClientOutput | Set-Content -LiteralPath $garthClientLog -Encoding UTF8
            foreach ($line in $garthClientOutput) { Write-Host $line }
            if ($garthClientExit -ne 0) {
                throw "Garth client check failed (exit=$garthClientExit); see $garthClientLog"
            }
        }
    }

        $playwrightArgs = @("test", "--config", "playwright.config.ts")
        foreach ($project in $playwrightProjects) {
            $playwrightArgs += @("--project", $project)
        }
        # G4.T1: joint-smoke is the PR gate. It runs only describe blocks tagged
        # @fully-implemented. The remaining attributed fixme tests are excluded
        # so the gate stays fast (< 5 min on joint). An explicit -Grep overrides
        # this entirely.
        $effectiveGrep = $Grep
        if (-not $effectiveGrep -and $RunProfile -eq "joint-smoke") {
            $effectiveGrep = "@fully-implemented"
        }

        if ($RunProfile -eq "joint-smoke") {
            Write-Host ""
            Write-Host "=== joint-smoke profile: PR gate ==="
            Write-Host "- includes: @fully-implemented"
            Write-Host "- excludes: fixme + remaining mixed specs"
            Write-Host ("- grep: {0}" -f $effectiveGrep)
            Write-Host ""
        }

        if ($effectiveGrep) {
            $playwrightArgs += @("--grep", $effectiveGrep)
        }
        # Provider-backed live tests are a separate controlled lane: they require
        # protected endpoints and credentials injected by controlled.yml. A normal
        # joint run must not fail merely because those secrets are intentionally
        # absent. An explicit grep for @platform-live remains the opt-in path and
        # keeps the test's fail-closed precondition checks intact.
        $grepInvertPatterns = [System.Collections.Generic.List[string]]::new()
        if (-not ($effectiveGrep -and $effectiveGrep.Contains("@platform-live"))) {
            $grepInvertPatterns.Add("@platform-live")
        }
        # The three-server P0 describe block deliberately fails closed when its
        # topology is absent. Broad one/two-server runs must not select it in the
        # first place; an explicit grep remains an opt-in fail-closed probe.
        if ($ServerCount -lt 3 -and -not ($effectiveGrep -and $effectiveGrep.Contains("@three-server-p0"))) {
            $grepInvertPatterns.Add("@three-server-p0")
        }
        if ($grepInvertPatterns.Count -gt 0) {
            $playwrightArgs += @("--grep-invert", ($grepInvertPatterns -join "|"))
        }
        $playwrightStdout = Join-Path $jointDir "playwright.stdout.log"
        $playwrightStderr = Join-Path $jointDir "playwright.stderr.log"
        $playwrightCli = Resolve-PlaywrightCliInvocation -E2eRoot $e2eRoot
        if (-not $playwrightCli) {
            throw "Playwright CLI is required"
        }
        $playwrightCommand = $playwrightCli.FilePath
        $playwrightCommandArgs = @($playwrightCli.Arguments) + $playwrightArgs
        Push-Location $e2eRoot
        $playwrightWriter = $null
        try {
            $previousErrorActionPreference = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            $playwrightWriter = [System.IO.StreamWriter]::new(
                $playwrightStdout,
                $false,
                [System.Text.UTF8Encoding]::new($false)
            )
            $playwrightWriter.AutoFlush = $true
            & $playwrightCommand @playwrightCommandArgs 2>&1 | ForEach-Object {
                $line = [string]$_
                $safeLine = [regex]::Replace(
                    $line,
                    '(?i)(authorization\s*:\s*(?:bearer|dpop)\s+)(?!\[redacted\])\S+',
                    '$1[redacted]'
                )
                $playwrightWriter.WriteLine($safeLine)
                Write-Host $safeLine
            }
            $exitCode = $LASTEXITCODE
            "" | Set-Content -Path $playwrightStderr -Encoding UTF8
        }
        finally {
            if ($playwrightWriter) {
                $playwrightWriter.Dispose()
            }
            if ($null -ne $previousErrorActionPreference) {
                $ErrorActionPreference = $previousErrorActionPreference
            }
            Pop-Location
        }
}
catch {
    $exitCode = 1
    # Capture a bounded diagnostic without config contents or command arguments.
    # Continue through cleanup and report/secret-scan finalization on setup errors.
    $runnerErrorLog = Join-Path $jointDir "runner-error.log"
    $runnerStackTrace = [string]$_.ScriptStackTrace
    $runnerReason = ConvertTo-SecretPreview -Line ([string]$_.Exception.Message)
    @(
        "type=$($_.Exception.GetType().FullName)"
        "line=$($_.InvocationInfo.ScriptLineNumber)"
        "reason=$runnerReason"
        "stack=$runnerStackTrace"
    ) | Set-Content -LiteralPath $runnerErrorLog -Encoding UTF8
    $runnerError = [pscustomobject]@{
        type = $_.Exception.GetType().FullName
        message = $runnerReason
        line = $_.InvocationInfo.ScriptLineNumber
        phase = "runner"
        diagnostic = $runnerErrorLog
    }
    Write-Warning "Joint runner failed at line $($runnerError.line) ($($runnerError.type)): $($runnerError.message); see $runnerErrorLog"
}
finally {
    $controlFailures = @(Sync-JointControlledServices -TopologyPath $topologyPath -ManagedServices $managedServices)
    if ($controlFailures.Count -gt 0) {
        $exitCode = 1
        foreach ($controlFailure in $controlFailures) { Write-Warning $controlFailure }
    }
    $managedServiceFailures = @(Get-ManagedServiceFailures -Services $managedServices)
    $failedManagedNames = @($managedServiceFailures | ForEach-Object { [string]$_.name })
    $topologyHealthFailures = @(
        Get-JointTopologyHealthFailures `
            -TopologyPath $topologyPath `
            -ManagedServices $managedServices |
            Where-Object { $_.name -notin $failedManagedNames }
    )
    $managedServiceFailures = @($managedServiceFailures; $topologyHealthFailures)
    if (-not $KeepServices) {
        for ($index = $managedServices.Count - 1; $index -ge 0; $index--) {
            Stop-ManagedCommand -Service $managedServices[$index]
        }
        if ($ephemeralCoauthServer1Postgres) {
            # Dump before teardown: the durable protocol store is the one
            # artifact the secret scan cannot reconstruct afterwards, and it is
            # where a recovery-material leak would be most damaging and least
            # visible. Scanned as `durable_protocol_store`, so the signed
            # evidence the spec requires the server to persist does not drown
            # the finding.
            $postgresDump = Export-EphemeralPostgresDump `
                -ContainerName $ephemeralCoauthServer1Postgres.ContainerName `
                -OutputPath (Join-Path $storeDumpDir $serverArtifactLayouts["server1"].CoauthStoreDumpName)
            if ($postgresDump) {
                Write-Host "postgres dump: $postgresDump"
            } else {
                $storeDumpFailures.Add($ephemeralCoauthServer1Postgres.ContainerName) | Out-Null
            }
            Stop-EphemeralPostgres -ContainerName $ephemeralCoauthServer1Postgres.ContainerName
        }
        if ($ephemeralCoauthServer2Postgres) {
            $postgresDump = Export-EphemeralPostgresDump `
                -ContainerName $ephemeralCoauthServer2Postgres.ContainerName `
                -OutputPath (Join-Path $storeDumpDir $serverArtifactLayouts["server2"].CoauthStoreDumpName)
            if ($postgresDump) {
                Write-Host "postgres dump: $postgresDump"
            } else {
                $storeDumpFailures.Add($ephemeralCoauthServer2Postgres.ContainerName) | Out-Null
            }
            Stop-EphemeralPostgres -ContainerName $ephemeralCoauthServer2Postgres.ContainerName
        }
        if ($ephemeralSolandPostgres) {
            $postgresDump = Export-EphemeralPostgresDump `
                -ContainerName $ephemeralSolandPostgres.ContainerName `
                -OutputPath (Join-Path $storeDumpDir $serverArtifactLayouts["server1"].SolandStoreDumpName)
            if ($postgresDump) {
                Write-Host "postgres dump: $postgresDump"
            } else {
                $storeDumpFailures.Add($ephemeralSolandPostgres.ContainerName) | Out-Null
            }
            Stop-EphemeralPostgres -ContainerName $ephemeralSolandPostgres.ContainerName
        }
        if ($ephemeralSolandServer2Postgres) {
            $postgresDump = Export-EphemeralPostgresDump `
                -ContainerName $ephemeralSolandServer2Postgres.ContainerName `
                -OutputPath (Join-Path $storeDumpDir $serverArtifactLayouts["server2"].SolandStoreDumpName)
            if ($postgresDump) {
                Write-Host "postgres dump: $postgresDump"
            } else {
                $storeDumpFailures.Add($ephemeralSolandServer2Postgres.ContainerName) | Out-Null
            }
            Stop-EphemeralPostgres -ContainerName $ephemeralSolandServer2Postgres.ContainerName
        }
        foreach ($server in $additionalServers) {
            foreach ($store in @(
                [pscustomobject]@{ Database = $server.CoauthDatabase; File = $serverArtifactLayouts[$server.Name].CoauthStoreDumpName },
                [pscustomobject]@{ Database = $server.SolandDatabase; File = $serverArtifactLayouts[$server.Name].SolandStoreDumpName }
            )) {
                if ($store.Database) {
                    $postgresDump = Export-EphemeralPostgresDump -ContainerName $store.Database.ContainerName -OutputPath (Join-Path $storeDumpDir $store.File)
                    if ($postgresDump) {
                        Write-Host "postgres dump: $postgresDump"
                    } else {
                        $storeDumpFailures.Add($store.Database.ContainerName) | Out-Null
                    }
                    Stop-EphemeralPostgres -ContainerName $store.Database.ContainerName
                }
            }
        }
        if ($jointTlsEnabled) {
            # 0530-C: revert the hosts entries and delete private keys.
            # Process-local trust disappears with the environment below.
            try {
                Remove-JointLoopbackHosts -Marker $jointTlsHostsMarker
            } catch {
                Write-Warning "joint TLS topology: failed to remove hosts entries ($jointTlsHostsMarker): $($_.Exception.Message)"
            }
            if ($jointTlsAssets) {
                Remove-Item -LiteralPath $jointTlsAssets.CaKeyPath, $jointTlsAssets.ServerKeyPath -Force -ErrorAction SilentlyContinue
            }
            Remove-Item Env:NODE_EXTRA_CA_CERTS -ErrorAction SilentlyContinue
            Remove-Item Env:COTEST_RUN_SCOPED_CA_PEM -ErrorAction SilentlyContinue
            Remove-Item Env:COTEST_TLS_SPKI_SHA256 -ErrorAction SilentlyContinue
        }
        if ($mockAppletRegistryStateKeyFile) {
            Remove-Item -LiteralPath $mockAppletRegistryStateKeyFile -Force -ErrorAction SilentlyContinue
        }
    }

    foreach ($containerName in $storeDumpFailures) {
        $managedServiceFailures += [pscustomobject]@{
            name = $containerName
            kind = "postgres"
            exit_code = $null
            detail = "required durable-store export failed; secret-scan coverage is incomplete"
            stdout = $null
            stderr = $null
        }
    }
    Write-ManagedServiceFailureReport `
        -Failures $managedServiceFailures `
        -JsonPath $managedServiceFailuresJson `
        -MarkdownPath $managedServiceFailuresMd
    if ($managedServiceFailures.Count -gt 0) {
        $exitCode = 1
        foreach ($failure in $managedServiceFailures) {
            Write-Warning "Managed service '$($failure.name)' failed during the test run; see $managedServiceFailuresMd"
        }
    }
}

$finishedAt = Get-Date
$screenshotIndex = Join-Path $jointDir "screenshots.md"
$screenshotFiles = @(Get-ChildItem -Path $screenshotDir -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -in @(".png", ".jpg", ".jpeg", ".webp") } |
    Sort-Object FullName)
$screenshotLines = @("# joint e2e screenshots", "")
if ($screenshotFiles.Count -eq 0) {
    $screenshotLines += "- no screenshots captured"
} else {
    foreach ($file in $screenshotFiles) {
        $relative = Get-RelativePathCompat -BasePath $jointDir -TargetPath $file.FullName
        $screenshotLines += "- [$relative]($relative)"
    }
}
$screenshotLines | Set-Content -Path $screenshotIndex -Encoding UTF8

$visualBaselineIndex = Join-Path $jointDir "visual-baselines.md"
$visualBaselineFiles = @(Get-ChildItem -Path $visualBaselineDir -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -in @(".png", ".jpg", ".jpeg", ".webp") } |
    Sort-Object FullName)
$visualBaselineLines = @("# joint e2e visual baselines", "")
if ($visualBaselineFiles.Count -eq 0) {
    $visualBaselineLines += "- no visual baselines captured"
} else {
    foreach ($file in $visualBaselineFiles) {
        $relative = Get-RelativePathCompat -BasePath $jointDir -TargetPath $file.FullName
        $visualBaselineLines += "- [$relative]($relative)"
    }
}
$visualBaselineManifest = Join-Path $visualBaselineDir "manifest.jsonl"
if (Test-Path $visualBaselineManifest) {
    $relativeManifest = Get-RelativePathCompat -BasePath $jointDir -TargetPath $visualBaselineManifest
    $visualBaselineLines += ""
    $visualBaselineLines += "- manifest: [$relativeManifest]($relativeManifest)"
}
$visualBaselineLines | Set-Content -Path $visualBaselineIndex -Encoding UTF8

# H-SHIM-3: service-log gap report. Scan each managed service's stderr log
# for WARN/denied/FORBIDDEN/reject lines and aggregate into service-gaps.md
# so reviewers can spot why an expected feature did not light up without
# tail-grepping every log file by hand.
$serviceGapsReport = Join-Path $jointDir "service-gaps.md"
$serviceGapPattern = '(?i)(WARN|ERROR).*(denied|FORBIDDEN|capability_denied|policy_reject|reject|unauthorized)'
$serviceGapMaxPerService = 50
$serviceGapLines = @("# joint e2e service gap signals", "",
    "Aggregated WARN/ERROR lines containing denied / FORBIDDEN / reject keywords.",
    "Use these as starting points when a fixme could not be promoted because the",
    "server rejected the request.",
    "")
if (Test-Path $serviceLogDir) {
    $stderrFiles = @(Get-ChildItem -Path $serviceLogDir -Recurse -File -Filter "*.stderr.log" -ErrorAction SilentlyContinue |
        Sort-Object FullName)
    if ($stderrFiles.Count -eq 0) {
        $serviceGapLines += "- no service stderr logs found"
    } else {
        foreach ($file in $stderrFiles) {
            $matchesList = @(Select-String -LiteralPath $file.FullName -Pattern $serviceGapPattern -ErrorAction SilentlyContinue)
            if ($matchesList.Count -eq 0) { continue }
            $relative = Get-RelativePathCompat -BasePath $jointDir -TargetPath $file.FullName
            $serviceGapLines += "## $relative"
            $serviceGapLines += ""
            $shown = 0
            foreach ($match in $matchesList) {
                if ($shown -ge $serviceGapMaxPerService) { break }
                $line = $match.Line.Trim()
                if ($line.Length -gt 280) { $line = $line.Substring(0, 280) + "..." }
                $serviceGapLines += ("- L{0}: {1}" -f $match.LineNumber, $line)
                $shown++
            }
            if ($matchesList.Count -gt $shown) {
                $serviceGapLines += ("- (...{0} more match(es) truncated)" -f ($matchesList.Count - $shown))
            }
            $serviceGapLines += ""
        }
        if ($serviceGapLines.Count -le 6) {
            $serviceGapLines += "- no WARN/ERROR gap signals detected across services"
        }
    }
} else {
    $serviceGapLines += "- service log directory missing"
}
$serviceGapLines | Set-Content -Path $serviceGapsReport -Encoding UTF8

$serviceTracesReport = Join-Path $jointDir "service-traces.md"
$serviceTraceLines = @("# joint e2e service traces", "",
    "Runtime log index for reducer/projection/federation debugging.",
    "")
if (Test-Path $serviceLogDir) {
    $traceFiles = @(Get-ChildItem -Path $serviceLogDir -Recurse -File -Include "*.trace.log", "*.stdout.log", "*.stderr.log", "*.command.txt" -ErrorAction SilentlyContinue |
        Sort-Object FullName)
    if ($traceFiles.Count -eq 0) {
        $serviceTraceLines += "- no service trace files found"
    } else {
        $serviceTraceLines += "| file | bytes |"
        $serviceTraceLines += "| --- | ---: |"
        foreach ($file in $traceFiles) {
            $relative = (Get-RelativePathCompat -BasePath $jointDir -TargetPath $file.FullName) -replace '\\', '/'
            $serviceTraceLines += "| [$relative]($relative) | $($file.Length) |"
        }
    }
} else {
    $serviceTraceLines += "- service log directory missing"
}
$serviceTraceLines | Set-Content -Path $serviceTracesReport -Encoding UTF8

# Scenario report: group junit testcases by spec file (= scenario) and emit
# pass / fail / skipped counts so reviewers can read scenario-level health
# without crunching the raw junit.xml.
#
# G0.T4 (test-gap alignment): spec layout is now `tests/<domain>/<name>.spec.ts`
# so the old `s\d-...` regex never matched. Playwright's JUnit reporter cannot
# distinguish `test.fixme()` from `test.skip()` (both emit a bare <skipped/>),
# so we pre-walk the spec source to harvest fixme titles and intersect them
# against the junit testcase names. The drift section compares junit-observed
# totals against the static-source counts so reviewers can spot crashes that
# truncated the junit (junit_total < static_total) or fixme-detection misses.
$scenariosReport = Join-Path $jointDir "scenarios.md"
$junitPath = Join-Path $jointDir "junit.xml"
$gapTodosPath = Join-Path $repoRoot "_cotest_gap_todos.md"
$fixmeChecklistPath = Join-Path $repoRoot "docs\fixme-promotion-checklist.md"

# Extracts fixme test titles from a Playwright spec file. Handles both
# `test.fixme("title", ...)` and `test.fixme('title', ...)`. Multi-line first
# arguments (titles broken across lines for readability) are joined; trailing
# args (the test body) are stripped. Returns @() on read failure.
function Get-FixmeTitlesForSpec {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    $source = $null
    try { $source = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop } catch { return @() }
    if ([string]::IsNullOrEmpty($source)) { return @() }
    $titles = New-Object System.Collections.Generic.List[string]
    # Match `test.fixme(<whitespace>"...."` or `test.fixme(<whitespace>'....'`.
    # The (?s) flag lets `.` match newlines so titles broken across source
    # lines are captured as one. Non-greedy + escape-aware: backslash-escaped
    # quotes inside the title are tolerated.
    $pattern = '(?s)test\.fixme\s*\(\s*(?:(?://[^\r\n]*(?:\r?\n|\n|\r)\s*)*)(?:"((?:[^"\\]|\\.)*)"|''((?:[^''\\]|\\.)*)'')'
    foreach ($m in [regex]::Matches($source, $pattern)) {
        $raw = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value }
        # Unescape \" and \' so the title matches what Playwright emits in junit.
        $raw = $raw -replace '\\"', '"' -replace "\\'", "'"
        # Collapse any internal whitespace (including embedded newlines from a
        # multi-line title literal) so the comparison against the junit name
        # is whitespace-insensitive.
        $normalized = ($raw -replace '\s+', ' ').Trim()
        if ($normalized.Length -gt 0) { $titles.Add($normalized) | Out-Null }
    }
    return $titles.ToArray()
}

# Walks the spec source tree once and returns a hashtable keyed by the
# canonical scenario key (`<domain>/<name>.spec.ts`) with per-spec
# static counts: live tests, fixme tests, and the harvested fixme title set.
function Get-StaticSpecStats {
    param([Parameter(Mandatory)][string]$TestsRoot)
    $result = @{}
    if (-not (Test-Path -LiteralPath $TestsRoot)) { return $result }
    $specFiles = @(Get-ChildItem -LiteralPath $TestsRoot -Recurse -File -Filter "*.spec.ts" -ErrorAction SilentlyContinue)
    foreach ($file in $specFiles) {
        $rel = (Get-RelativePathCompat -BasePath $TestsRoot -TargetPath $file.FullName) -replace '\\', '/'
        $source = $null
        try { $source = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop } catch { $source = "" }
        $fixmeTitles = @(Get-FixmeTitlesForSpec -Path $file.FullName)
        $ownerGapSet = @{}
        foreach ($m in [regex]::Matches($source, '@blocking-on:\s*([^\r\n]+)')) {
            $gap = $m.Groups[1].Value.Trim()
            if ($gap) { $ownerGapSet[$gap] = $true }
        }
        $ownerGaps = @($ownerGapSet.Keys | Sort-Object)
        # Count `test(` and `test.skip(` (but not `test.fixme`, `test.describe`,
        # `test.beforeAll`, etc.) as "live" definitions.
        $liveMatches = [regex]::Matches($source, '(?m)(^|[^.\w])test\s*\(\s*[''"]')
        $skipMatches = [regex]::Matches($source, '(?s)test\.skip\s*\(\s*[''"]')
        $live = $liveMatches.Count + $skipMatches.Count
        $result[$rel] = [pscustomobject]@{
            spec        = $rel
            live        = $live
            fixme       = $fixmeTitles.Count
            fixmeTitles = $fixmeTitles
            ownerGaps   = $ownerGaps
        }
    }
    return $result
}

# Build the static-source picture first so the drift section can be emitted
# even when junit.xml is absent (playwright crashed before reporting).
$testsRoot = Join-Path $e2eRoot "tests"
$staticStats = Get-StaticSpecStats -TestsRoot $testsRoot
$scenarioEvidenceByKey = @{}
$scenarioEvidenceManifestPath = Join-Path $repoRoot "e2e\scenarios\evidence-manifest.json"
if (-not (Test-Path -LiteralPath $scenarioEvidenceManifestPath -PathType Leaf)) {
    throw "scenario evidence manifest is missing: $scenarioEvidenceManifestPath"
}
$scenarioEvidenceManifest = Get-Content -Raw -LiteralPath $scenarioEvidenceManifestPath | ConvertFrom-Json
if ($scenarioEvidenceManifest.schema -ne "arkret.scenario-evidence.v1" -or
    $scenarioEvidenceManifest.suite_kind -ne "joint-e2e") {
    throw "scenario evidence manifest has an unsupported schema or suite_kind"
}
foreach ($entry in @($scenarioEvidenceManifest.scenarios)) {
    $scenarioEvidenceKey = [string]$entry.scenario_key
    # Manifest keys are canonical scenario ids (`domain/name`), while both the
    # static source walk and Playwright JUnit use `domain/name.spec.ts`.
    # Normalize once at ingestion so targeted runs still reach their process-
    # liveness/report gates instead of failing on an all-scenarios false drift.
    if (-not $scenarioEvidenceKey.EndsWith(".spec.ts")) {
        $scenarioEvidenceKey += ".spec.ts"
    }
    $scenarioEvidenceByKey[$scenarioEvidenceKey] = $entry
}
$missingEvidence = @($staticStats.Keys | Where-Object { -not $scenarioEvidenceByKey.ContainsKey($_) })
$staleEvidence = @($scenarioEvidenceByKey.Keys | Where-Object { -not $staticStats.ContainsKey($_) })
if ($missingEvidence.Count -gt 0 -or $staleEvidence.Count -gt 0) {
    throw "scenario evidence manifest drift: missing=$($missingEvidence -join ',') stale=$($staleEvidence -join ',')"
}

$gapTodosDisplay = $gapTodosPath -replace '\\', '/'
$fixmeChecklistDisplay = $fixmeChecklistPath -replace '\\', '/'
$scenarioLines = @(
    "# joint e2e scenarios",
    "",
    "- gap todos: $gapTodosDisplay",
    "- fixme promotion checklist: $fixmeChecklistDisplay",
    ""
)
$junitByScenario = @{}
$totals = [pscustomobject]@{
    passed  = 0
    failed  = 0
    skipped = 0
    fixme   = 0
}
$junitParseError = $null
$finalFailures = New-Object System.Collections.Generic.List[object]
if (Test-Path $junitPath) {
    try {
        [xml]$junit = Get-Content -Path $junitPath -Raw
        # Playwright JUnit nests <testsuites><testsuite ...><testcase ...>;
        # testsuite.name is the spec path, normally relative to the e2e tests
        # dir. On Windows it uses backslashes (e.g. `identity\multi-device.spec.ts`).
        $suiteList = @($junit.testsuites.testsuite)
        foreach ($suite in $suiteList) {
            $suiteName = $suite.GetAttribute("name")
            if (-not $suiteName) {
                $suiteName = "<unnamed>"
            }
            # Normalize backslashes to forward slashes so the key matches the
            # canonical `<domain>/<name>.spec.ts` form used by the static walk.
            $normalizedSuite = $suiteName -replace '\\', '/'
            # A setup project's cases are infrastructure, not coverage. Left in,
            # the Inkson build-id check would become a scenario of its own, add a
            # passed case no static walk can account for, and show up as drift on
            # every browser run. Its failure still fails the run: Playwright exits
            # non-zero and every dependent test is reported as not run.
            if ($normalizedSuite -match '\.setup\.ts$') {
                continue
            }
            # Narrow: prefer `<domain>/<name>.spec.ts` (single nesting level
            # under tests/). Fall back to the wider `*.spec.ts` anywhere in the
            # suite name string for suites without a domain directory (e.g.
            # `joint-smoke.spec.ts` lives at tests/ root).
            $specMatch = [regex]::Match($normalizedSuite, '([a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9-]*\.spec\.ts)')
            if (-not $specMatch.Success) {
                $specMatch = [regex]::Match($normalizedSuite, '([a-z0-9][a-z0-9-]*\.spec\.ts)')
            }
            $scenarioKey = if ($specMatch.Success) { $specMatch.Groups[1].Value } else { $normalizedSuite }
            if (-not $junitByScenario.ContainsKey($scenarioKey)) {
                $junitByScenario[$scenarioKey] = [pscustomobject]@{
                    cases   = New-Object System.Collections.Generic.List[object]
                    passed  = 0
                    failed  = 0
                    skipped = 0
                    fixme   = 0
                }
            }
            $bucket = $junitByScenario[$scenarioKey]
            # Pre-compute the fixme title set (whitespace-normalized) for this
            # scenario so each <skipped/> case can be classified deterministically.
            $fixmeSet = @{}
            if ($staticStats.ContainsKey($scenarioKey)) {
                foreach ($t in $staticStats[$scenarioKey].fixmeTitles) { $fixmeSet[$t] = $true }
            }
            foreach ($case in @($suite.SelectNodes("testcase"))) {
                $caseName = $case.GetAttribute("name")
                if (-not $caseName) {
                    $caseName = "<unnamed test>"
                }
                $normalizedCaseName = ($caseName -replace '\s+', ' ').Trim()
                # NB: PowerShell evaluates an empty XmlElement (e.g. <skipped/>
                # with no text content) as $false in a boolean test, so we use
                # $null -ne <element> to detect presence instead.
                $failureNode = $case.SelectSingleNode("failure")
                $errorNode = $case.SelectSingleNode("error")
                $skippedNode = $case.SelectSingleNode("skipped")
                $hasFailure = ($null -ne $failureNode -or $null -ne $errorNode)
                $hasSkipped = ($null -ne $skippedNode)
                $status = "passed"
                if ($hasFailure) {
                    $status = "failed"; $totals.failed += 1; $bucket.failed += 1
                }
                elseif ($hasSkipped) {
                    # Playwright JUnit reporter emits <skipped/> with no message
                    # for BOTH test.skip() and test.fixme(). Newer versions
                    # ALSO emit <property name="fixme" value=""/> on fixme'd
                    # cases - use that as the primary signal when present,
                    # then fall back to intersecting the case name with the
                    # per-spec fixme title set harvested from source.
                    $isFixme = $false
                    $propertyNodes = $case.SelectNodes("properties/property")
                    if ($null -ne $propertyNodes) {
                        foreach ($prop in @($propertyNodes)) {
                            if ($prop.GetAttribute("name") -eq "fixme") { $isFixme = $true; break }
                        }
                    }
                    if (-not $isFixme) {
                        foreach ($title in $fixmeSet.Keys) {
                            if ([string]::IsNullOrEmpty($title)) { continue }
                            if ($normalizedCaseName -eq $title) { $isFixme = $true; break }
                            if ($normalizedCaseName.EndsWith($title)) { $isFixme = $true; break }
                            # Some Playwright JUnit reporters insert U+203A ">"
                            # or plain ">" between describe and test title; an
                            # EndsWith match against the bare title catches it,
                            # and Contains() covers nested-describe edge cases.
                            if ($normalizedCaseName.Contains($title)) { $isFixme = $true; break }
                        }
                    }
                    if ($isFixme) {
                        $status = "fixme"; $totals.fixme += 1; $bucket.fixme += 1
                    } else {
                        $status = "skipped"; $totals.skipped += 1; $bucket.skipped += 1
                    }
                }
                else { $totals.passed += 1; $bucket.passed += 1 }
                $caseTime = $case.GetAttribute("time")
                $time = if ($caseTime) { [math]::Round([double]$caseTime, 2) } else { 0 }
                $bucket.cases.Add([pscustomobject]@{
                    name   = $caseName
                    status = $status
                    time   = $time
                }) | Out-Null
                # Keep the failure text of FINAL failures only. junit.xml already
                # reflects the last attempt, so a test that failed twice and then
                # passed contributes nothing here - which is the whole point of
                # the reconciliation below.
                if ($hasFailure) {
                    $detailNode = if ($null -ne $failureNode) { $failureNode } else { $errorNode }
                    $systemOutNode = $case.SelectSingleNode("system-out")
                    $finalFailures.Add([pscustomobject]@{
                        scenario = $scenarioKey
                        name     = $normalizedCaseName
                        message  = $detailNode.GetAttribute("message")
                        detail   = $detailNode.InnerText
                        system_out = if ($null -ne $systemOutNode) { $systemOutNode.InnerText } else { "" }
                    }) | Out-Null
                }
            }
        }
    } catch {
        $junitParseError = $_.Exception.Message
    }
} else {
    $junitParseError = "junit.xml not present; playwright may have failed before emitting reports"
}

$scenarioLines += "## totals"
$scenarioLines += ""
if ($junitParseError -and -not (Test-Path $junitPath)) {
    $scenarioLines += "- $junitParseError"
} elseif ($junitParseError) {
    $scenarioLines += "- failed to parse junit.xml: $junitParseError"
} else {
    $scenarioLines += "- passed: $($totals.passed)"
    $scenarioLines += "- failed: $($totals.failed)"
    $scenarioLines += "- skipped: $($totals.skipped)"
    $scenarioLines += "- fixme (pending spec implementation): $($totals.fixme)"
}
$evidenceTotals = [ordered]@{
    live_product_verified = 0
    server_contract_verified = 0
    fixture_only = 0
}
foreach ($scenarioKey in $junitByScenario.Keys) {
    $passedCases = @($junitByScenario[$scenarioKey].cases | Where-Object status -eq "passed").Count
    if ($passedCases -eq 0) { continue }
    $evidenceClass = [string]$scenarioEvidenceByKey[$scenarioKey].evidence_class
    switch ($evidenceClass) {
        "live-product" { $evidenceTotals.live_product_verified += $passedCases }
        "server-contract" { $evidenceTotals.server_contract_verified += $passedCases }
        default { $evidenceTotals.fixture_only += $passedCases }
    }
}
$scenarioLines += "- live product verified: $($evidenceTotals.live_product_verified)"
$scenarioLines += "- server contract verified: $($evidenceTotals.server_contract_verified)"
$scenarioLines += "- fixture-only: $($evidenceTotals.fixture_only)"
$scenarioLines += "- evidence manifest: $scenarioEvidenceManifestPath"
$scenarioLines += ""

if ($junitByScenario.Count -gt 0) {
    foreach ($key in $junitByScenario.Keys | Sort-Object) {
        $scenarioLines += "## $key"
        $scenarioLines += ""
        foreach ($case in $junitByScenario[$key].cases) {
            $marker = switch ($case.status) {
                "passed"  { "[x]" }
                "failed"  { "[F]" }
                "skipped" { "[S]" }
                "fixme"   { "[~]" }
                default   { "[?]" }
            }
            $scenarioLines += "- $marker ($($case.time)s) $($case.name)"
        }
        $scenarioLines += "- evidence class: $($scenarioEvidenceByKey[$key].evidence_class)"
        $scenarioLines += "- realism level: $($scenarioEvidenceByKey[$key].realism_level)"
        $scenarioLines += "- real services: $(@($scenarioEvidenceByKey[$key].real_services) -join ', ')"
        $scenarioLines += "- mocks: $(@($scenarioEvidenceByKey[$key].mocks) -join ', ')"
        $scenarioLines += "- identity establishment: $(@($scenarioEvidenceByKey[$key].identity_establishment) -join ', ')"
        $scenarioLines += "- protocol object producers: $(@($scenarioEvidenceByKey[$key].protocol_object_producers) -join ', ')"
        $scenarioLines += "- declared test bypasses: $(@($scenarioEvidenceByKey[$key].declared_test_bypasses) -join ', ')"
        $scenarioLines += "- claims excluded: $(@($scenarioEvidenceByKey[$key].claims_excluded) -join ', ')"
        $scenarioLines += ""
    }
}

# Drift section: compare static-source counts vs junit-observed counts. The
# union of keys catches both directions of drift - specs in the source tree
# that junit never saw (likely crashed pre-report) and junit suites that
# don't correspond to any static spec file (likely a key-extraction miss).
$scenarioLines += "## drift vs static count"
$scenarioLines += ""
$scenarioLines += "Static counts come from a regex walk of tests/**/*.spec.ts;"
$scenarioLines += "junit counts come from this run. `[!]` flags a divergence."
$scenarioLines += ""
$scenarioLines += "| spec | static live | static fixme | owner gaps | junit pass | junit fail | junit skip | junit fixme | flag |"
$scenarioLines += "|------|-------------|--------------|------------|------------|------------|------------|-------------|------|"
$allKeys = New-Object System.Collections.Generic.HashSet[string]
foreach ($k in $staticStats.Keys)      { [void]$allKeys.Add($k) }
foreach ($k in $junitByScenario.Keys)  { [void]$allKeys.Add($k) }
$driftAny = $false
foreach ($key in ($allKeys | Sort-Object)) {
    $sLive = 0; $sFixme = 0; $ownerGaps = "-"
    if ($staticStats.ContainsKey($key)) {
        $sLive = $staticStats[$key].live
        $sFixme = $staticStats[$key].fixme
        if ($staticStats[$key].ownerGaps.Count -gt 0) {
            $ownerGaps = ($staticStats[$key].ownerGaps -join "<br>")
        }
    }
    $jPass = 0; $jFail = 0; $jSkip = 0; $jFixme = 0
    if ($junitByScenario.ContainsKey($key)) {
        $jPass  = $junitByScenario[$key].passed
        $jFail  = $junitByScenario[$key].failed
        $jSkip  = $junitByScenario[$key].skipped
        $jFixme = $junitByScenario[$key].fixme
    }
    $flag = ""
    if (Test-Path $junitPath) {
        $junitLiveSeen = $jPass + $jFail + $jSkip
        if ($junitLiveSeen -ne $sLive) { $flag = "[!]" }
        if ($jFixme -ne $sFixme)       { $flag = "[!]" }
    } else {
        # No junit: drift is undefined; report static-only with a dash.
        $flag = "-"
    }
    if ($flag -eq "[!]") { $driftAny = $true }
    $scenarioLines += "| $key | $sLive | $sFixme | $ownerGaps | $jPass | $jFail | $jSkip | $jFixme | $flag |"
}
$scenarioLines += ""
if (-not (Test-Path $junitPath)) {
    $scenarioLines += "Note: junit.xml absent - only static counts shown above."
} elseif ($driftAny) {
    $scenarioLines += "Drift detected - investigate `[!]` rows: either tests crashed before junit emission, or fixme parsing missed a title."
} else {
    $scenarioLines += "No drift - junit totals align with static-source counts."
}

$requiredScenarios = @(
    $RequireScenario -split "," |
        ForEach-Object { $_.Trim() -replace '\\', '/' } |
        Where-Object { $_ } |
        ForEach-Object { ConvertTo-CanonicalScenarioKey -Scenario $_ }
)
$forbidRuntimeSkips = [bool]$ForbidSkippedTests -or $RunProfile -eq "joint-smoke"
if ($ServerCount -ge 3 -and $RunProfile -eq "joint-full") {
    $requiredScenarios = @(@($requiredScenarios; "federation/three-server-p0") | Sort-Object -Unique)
}
if ($RunProfile -eq "joint-smoke" -and -not $Grep) {
    $requiredScenarios = @(@(
        $requiredScenarios
        "encryption/key-backup"
        "identity/multi-device"
        "identity/recovery-key-to-encrypted-realm"
        "kanban/cross-member-encrypted"
    ) | Sort-Object -Unique)
}
$selectionGateFailures = @()
if ($requiredScenarios.Count -gt 0 -or $forbidRuntimeSkips) {
    $selectionGateFailures = @(Get-JointSelectionGateFailures `
            -RequiredScenarios $requiredScenarios `
            -JunitByScenario $junitByScenario `
            -Totals $totals `
            -ForbidRuntimeSkips $forbidRuntimeSkips `
            -JunitParseError $junitParseError)
}
# A run that executed no business test cannot be green. The setup project is
# excluded from `$junitByScenario` above, so these totals count business cases
# only: a grep that matched nothing, a project whose file set resolved empty, or
# a crash before the first test all surface here instead of passing as "nothing
# failed". `$junitParseError` has its own gate; this one covers a well-formed
# report that simply contains no work.
$businessCaseCount = $totals.passed + $totals.failed + $totals.skipped + $totals.fixme
if (-not $junitParseError -and $businessCaseCount -eq 0) {
    $selectionGateFailures += "no business test case ran; the selection resolved to nothing"
}
if ($selectionGateFailures.Count -gt 0) {
    $exitCode = 1
}
if ($ServerCount -ge 3 -and $RunProfile -eq "joint-full") {
    $p0ScenarioKey = "federation/three-server-p0.spec.ts"
    if ($junitByScenario.ContainsKey($p0ScenarioKey)) {
        $p0Cases = $junitByScenario[$p0ScenarioKey].cases
        if ($p0Cases.Count -lt 5) {
            $selectionGateFailures += "three-server P0 selected fewer than five mandatory cases"
            $exitCode = 1
        }
        $p0Skipped = @($p0Cases | Where-Object { $_.status -in @("skipped", "fixme") })
        if ($p0Skipped.Count -gt 0) {
            $selectionGateFailures += "three-server P0 contains runtime skips or fixmes"
            $exitCode = 1
        }
    }
}
$scenarioLines += ""
$scenarioLines += "## selection gate"
$scenarioLines += ""
$scenarioLines += "- required scenarios: $(if ($requiredScenarios.Count -gt 0) { $requiredScenarios -join ', ' } else { '-' })"
$scenarioLines += "- skipped tests forbidden: $forbidRuntimeSkips"
$scenarioLines += "- status: $(if ($selectionGateFailures.Count -eq 0) { 'passed' } else { 'failed' })"
foreach ($failure in $selectionGateFailures) {
    $scenarioLines += "- failure: $failure"
}

$scenarioLines | Set-Content -Path $scenariosReport -Encoding UTF8

# Failure report: one structured fingerprint per FINAL failure, plus the
# reconciliation that stops `playwright-output/` from being read as a failure
# count. Classification is reporting only -- junit.xml remains the verdict.
$failuresJson = Join-Path $jointDir "failures.json"
$failuresMd = Join-Path $jointDir "failures.md"
$failureFingerprintSelfTest = Join-Path $PSScriptRoot "tests\failure-fingerprint.tests.ps1"
& (Get-Process -Id $PID).Path -NoProfile -ExecutionPolicy Bypass -File $failureFingerprintSelfTest | Out-Null
$failureFingerprintSelfTestStatus = if ($LASTEXITCODE -eq 0) { "passed" } else { "failed" }

$fingerprintedFailures = @($finalFailures | ForEach-Object {
        Get-FailureFingerprint `
            -Scenario $_.scenario `
            -TestName $_.name `
            -Message ([string]$_.message) `
            -Detail ([string]$_.detail) `
            -SystemOut ([string]$_.system_out)
    })
$distinctFingerprints = @($fingerprintedFailures | Group-Object -Property fingerprint | Sort-Object -Property Count -Descending)
$retryReconciliation = Get-RetryArtifactReconciliation `
    -PlaywrightOutputDir (Join-Path $jointDir "playwright-output") `
    -FinalFailures $finalFailures

$failureReport = [pscustomobject]@{
    generated_at        = (Get-Date).ToString("o")
    self_test           = $failureFingerprintSelfTestStatus
    final_failures      = $fingerprintedFailures.Count
    distinct_root_causes = $distinctFingerprints.Count
    failures            = $fingerprintedFailures
    retry_reconciliation = $retryReconciliation
}
$failureReport | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $failuresJson -Encoding UTF8

$failureLines = @(
    "# joint e2e failures",
    "",
    "- self_test: $failureFingerprintSelfTestStatus",
    "- final_failures: $($failureReport.final_failures)",
    "- distinct_root_causes: $($failureReport.distinct_root_causes)",
    "- artifact_directories: $($retryReconciliation.artifact_directories)",
    "- final_failure_artifacts: $($retryReconciliation.final_failure_artifacts)",
    "- retry_only_artifacts: $($retryReconciliation.retry_only_artifacts)",
    "",
    "`final_failures` counts junit outcomes. `retry_only_artifacts` are directories",
    "left behind by tests that failed an attempt and then passed - they are NOT",
    "failures, and counting directories instead of outcomes overstates the damage.",
    ""
)
if ($fingerprintedFailures.Count -eq 0) {
    $failureLines += "No final failures."
} else {
    $failureLines += "## distinct root causes"
    $failureLines += ""
    $failureLines += "| Fingerprint | Count | Shared origin | Scenario | Endpoint | Wire code | Assertion site |"
    $failureLines += "| --- | --- | --- | --- | --- | --- | --- |"
    foreach ($group in $distinctFingerprints) {
        $sample = $group.Group[0]
        $failureLines += "| $($sample.fingerprint) | $($group.Count) | $($sample.origin_site) | $($sample.scenario) | $($sample.endpoint) | $($sample.wire_code) | $($sample.assertion_site) |"
    }
    $failureLines += ""
    $failureLines += "## final failures"
    $failureLines += ""
    $failureLines += "| Fingerprint | Test | HTTP | Correlation id |"
    $failureLines += "| --- | --- | --- | --- |"
    foreach ($failure in $fingerprintedFailures) {
        $failureLines += "| $($failure.fingerprint) | $($failure.test) | $($failure.http_status) | $($failure.correlation_id) |"
    }
}
if ($retryReconciliation.retry_only_artifacts -gt 0) {
    $failureLines += ""
    $failureLines += "## retry debris (not failures)"
    $failureLines += ""
    foreach ($entry in @($retryReconciliation.entries | Where-Object { $_.classification -eq "retry_artifact_of_passing_test" })) {
        $failureLines += "- $($entry.directory)"
    }
}
$failureLines | Set-Content -LiteralPath $failuresMd -Encoding UTF8
if ($failureFingerprintSelfTestStatus -ne "passed") {
    $exitCode = 1
}

$secretScanRoots = New-Object System.Collections.Generic.List[string]
if (Test-Path -LiteralPath $serviceLogDir) {
    $secretScanRoots.Add($serviceLogDir)
}
foreach ($directory in Get-ChildItem -LiteralPath $jointDir -Directory -ErrorAction SilentlyContinue) {
    if ($directory.Name -match '(?i)(state|objects|diagnostic|test-results|playwright-output|crash|checkpoint|telemetry)') {
        if ($directory.Name -match '(?i)^soland(?:-[a-z0-9_-]+)?-state$') {
            # The service identity bundle is a durable restore store whose
            # signed registration receipts and WebVH operations necessarily
            # contain JWS evidence. Classify it separately; scanning the whole
            # parent as telemetry would count and then destroy valid protocol
            # state. Every sibling and top-level state file remains strict.
            foreach ($child in Get-ChildItem -LiteralPath $directory.FullName -ErrorAction SilentlyContinue) {
                if ($child.Name -ne "identity-bundle") {
                    $secretScanRoots.Add($child.FullName)
                }
            }
        } else {
            $secretScanRoots.Add($directory.FullName)
        }
    }
}
foreach ($file in Get-ChildItem -LiteralPath $jointDir -File -ErrorAction SilentlyContinue) {
    if ($file.Name -match '(?i)(\.log$|\.ndjson$|crash|checkpoint|telemetry)') {
        $secretScanRoots.Add($file.FullName)
    }
}
$secretScanSelfTest = Join-Path $PSScriptRoot "tests\secret-scan.tests.ps1"
$psHostExe = (Get-Process -Id $PID).Path
& $psHostExe -NoProfile -ExecutionPolicy Bypass -File $secretScanSelfTest | Out-Null
$secretScanSelfTestStatus = if ($LASTEXITCODE -eq 0) { "passed" } else { "failed" }
# Logs, diagnostics, and ordinary runtime state take the strict class.
$secretScanRootDescriptors = @(
    $secretScanRoots.ToArray() | ForEach-Object {
        [pscustomobject]@{ path = $_; artifact_class = "log_or_telemetry" }
    }
)
# The verified service-identity bundle is durable protocol state: its JWS
# receipt chain is required for restart/restore, while private recovery
# material remains forbidden by the category/class verdict matrix.
$identityBundleDirs = @(
    Get-ChildItem -LiteralPath $jointDir -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '(?i)^soland(?:-[a-z0-9_-]+)?-state$' } |
        ForEach-Object { Join-Path $_.FullName "identity-bundle" } |
        Where-Object { Test-Path -LiteralPath $_ }
)
foreach ($identityBundleDir in $identityBundleDirs) {
    $secretScanRootDescriptors += [pscustomobject]@{
        path           = $identityBundleDir
        artifact_class = "durable_protocol_store"
    }
}
# The exported database is a durable protocol store, not telemetry: the spec
# requires the server to persist signed authorization evidence there, so
# `credential_exposure` findings are expected and allowed. Recovery private
# material still fails, and the private-material detectors fire independently of
# the credential ones, so allowing the former cannot mask the latter.
if (Test-Path -LiteralPath $storeDumpDir) {
    $secretScanRootDescriptors += [pscustomobject]@{
        path           = $storeDumpDir
        artifact_class = "durable_protocol_store"
    }
}
$secretLeaks = @(Find-SecretLeaks -ScanRoots $secretScanRootDescriptors)
$secretScanCounts = Get-SecretScanSummary -Leaks $secretLeaks
# Playwright writes the full received object into stdout and error-context.md
# whenever an object assertion fails, so a secret-bearing response reaches these
# artifacts without any test asking for it. Scan first so the report keeps the
# file, line, pattern and category, then redact the artifacts themselves so the
# retained copies carry no plaintext.
$secretRedaction = Protect-SecretBearingArtifacts -Leaks $secretLeaks
# Count from the descriptors, not from the log-root list: the store dump is a
# descriptor-only root, and a `scanned_files` that silently omits it would
# understate the coverage the report claims.
$secretScanFileCount = 0
foreach ($descriptor in $secretScanRootDescriptors) {
    $root = $descriptor.path
    if (-not (Test-Path -LiteralPath $root)) {
        continue
    }
    if ((Get-Item -LiteralPath $root).PSIsContainer) {
        $secretScanFileCount += @(Get-ChildItem -LiteralPath $root -Recurse -File).Count
    } else {
        $secretScanFileCount += 1
    }
}
$secretScan = [pscustomobject]@{
    generated_at = (Get-Date).ToString("o")
    status = if (
        $secretScanSelfTestStatus -eq "passed" -and
        $secretScanCounts.failing -eq 0 -and
        $storeDumpFailures.Count -eq 0
    ) {
        "passed"
    } else {
        "failed"
    }
    self_test = $secretScanSelfTestStatus
    scanned_roots = $secretScanRootDescriptors
    scanned_files = $secretScanFileCount
    store_coverage = [pscustomobject]@{
        status = if ($storeDumpFailures.Count -eq 0) { "complete" } else { "incomplete" }
        failed_containers = $storeDumpFailures.ToArray()
    }
    counts = $secretScanCounts
    redaction = $secretRedaction
    leaks = $secretLeaks
}
if ($secretScan.status -ne "passed") {
    $exitCode = 1
}
$secretScanJson = Join-Path $jointDir "secret-scan.json"
$secretScanMd = Join-Path $jointDir "secret-scan.md"
$secretScan | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $secretScanJson -Encoding UTF8
$secretScanLines = @(
    "# joint e2e secret scan",
    "",
    "- status: $($secretScan.status)",
    "- self_test: $($secretScan.self_test)",
    "- scanned_files: $($secretScan.scanned_files)",
    "- durable_store_coverage: $($secretScan.store_coverage.status)",
    "- findings: $($secretScan.counts.findings)",
    "- failing: $($secretScan.counts.failing)",
    "- allowed_by_artifact_class: $($secretScan.counts.allowed_by_artifact_class)",
    "- recovery_private_material: $($secretScan.counts.recovery_private_material)",
    "- credential_exposure: $($secretScan.counts.credential_exposure)",
    "- redacted_files: $(@($secretScan.redaction.redacted_files).Count)",
    ""
)
if ($secretScan.store_coverage.status -ne "complete") {
    $secretScanLines += "Required PostgreSQL dumps were unavailable: $($secretScan.store_coverage.failed_containers -join ', ')"
    $secretScanLines += ""
}
if (@($secretScan.redaction.not_redacted).Count -gt 0) {
    $secretScanLines += "NOT redacted (archive members - drop the archive): $(@($secretScan.redaction.not_redacted) -join ', ')"
    $secretScanLines += ""
}
if ($secretScan.counts.findings -eq 0) {
    $secretScanLines += "No unredacted secret-shaped material was found in runtime stores, logs, telemetry, checkpoints, crash artifacts, or nested trace archives."
} else {
    $secretScanLines += "| File | Line | Pattern | Category | Artifact class | Verdict | Preview |"
    $secretScanLines += "| --- | --- | --- | --- | --- | --- | --- |"
    foreach ($leak in $secretScan.leaks) {
        $preview = $leak.preview -replace '\|', '\|'
        $secretScanLines += "| $($leak.path) | $($leak.line) | $($leak.pattern) | $($leak.category) | $($leak.artifact_class) | $($leak.verdict) | ``$preview`` |"
    }
}
$secretScanLines | Set-Content -LiteralPath $secretScanMd -Encoding UTF8

$summary = [pscustomobject]@{
    report_schema = "arkret.test-report.v1"
    suite_kind = "joint-e2e"
    suite_name = "Arkret Joint Product E2E"
    status = if ($exitCode -eq 0) { "success" } else { "failure" }
    run_profile = if ($RunProfile) { $RunProfile } else { "custom" }
    playwright_projects = $playwrightProjects -join ","
    # The single decision that governs whether this run probed Inkson sources,
    # allocated its port, built or verified its bundle, served it, waited on it,
    # or registered its OAuth callback. Recorded so a reader can tell a genuine
    # browserless run from one that merely happened to find a warm cache.
    requires_inkson = $requiresInkson
    test_execution = if (($totals.passed + $totals.failed + $totals.skipped + $totals.fixme) -gt 0) { "executed" } else { "not_executed" }
    test_totals = $totals
    required_scenarios = $requiredScenarios
    forbid_skipped_tests = $forbidRuntimeSkips
    selection_gate_failures = @($selectionGateFailures)
    evidence_counts = $evidenceTotals
    scenario_evidence_manifest = $scenarioEvidenceManifestPath
    started_at = $startedAt.ToString("o")
    finished_at = $finishedAt.ToString("o")
    duration_seconds = [Math]::Round(($finishedAt - $startedAt).TotalSeconds, 2)
    exit_code = $exitCode
    runner_error = $runnerError
    soland_runtime = $startedSolandRuntime
    soland_image = if ($startedSolandRuntime -eq "docker") { $SolandImage } else { $null }
    server_count = $ServerCount
    network_shape = $NetworkShape
    topology_json = $topologyPath
    servers = if ($topology) { $topology.servers } else { @() }
    mock_idp_base_url = $mockIdpBaseUrl
    mock_email_base_url = $mockEmailBaseUrl
    mock_witness_base_url = $mockWitnessBaseUrl
    mock_witness_did = if ($mockWitnessBaseUrl) { $MockWitnessDid } else { $null }
    mock_witness_quorum_base_urls = if ($mockWitnessBaseUrl) { $mockWitnessQuorumBaseUrls } else { @() }
    mock_witness_quorum_dids = if ($mockWitnessBaseUrl) { $mockWitnessQuorumDids } else { @() }
    mock_did_host_base_url = $mockDidHostBaseUrl
    mock_did_host_authority = if ($mockDidHostBaseUrl) { $MockDidHostAuthority } else { $null }
    mock_did_host_scid = if ($mockDidHostBaseUrl) { $MockDidHostScid } else { $null }
    # DID-P1-C02 resolver call-count trace: the endpoints the run's
    # authority_network_call_count / signature_verify_count were read from.
    soland_server1_metrics_url = $solandMetricsBaseUrl
    teabay_metrics_url = $teabayMetricsBaseUrl
    mock_mimi_facade_base_url = $mockMimiFacadeBaseUrl
    mock_mimi_facade_did = if ($mockMimiFacadeBaseUrl) { $MockMimiFacadeDid } else { $null }
    inkson_server1_base_url = $InksonBaseUrl
    coauth_server1_base_url = if ($CoauthBaseUrl) { $CoauthBaseUrl } else { $null }
    coauth_secondary_base_url = $coauthSecondaryBaseUrl
    dual_coauth = [bool]$DualCoauth
    coauth_server1_service_id = if ($CoauthBaseUrl) { $CoauthServiceId } else { $null }
    teabay_base_url = if ($TeabayBaseUrl) { $TeabayBaseUrl } else { $null }
    teabay_service_id = if ($TeabayBaseUrl) { $TeabayServiceId } else { $null }
    teabay_database_url = if ($TeabayBaseUrl) { $TeabayDatabaseUrl } else { $null }
    coauth_server1_oauth_introspection_url = if ($CoauthBaseUrl) { "$($CoauthBaseUrl.TrimEnd('/'))/oauth/introspect" } else { $null }
    coauth_server1_session_grant_introspection_url = if ($CoauthBaseUrl) { "$($CoauthBaseUrl.TrimEnd('/'))/_arkret/gate/account/session-grants/introspect" } else { $null }
    screenshots = $screenshotDir
    visual_baselines = $visualBaselineDir
    diagnostics = Join-Path $jointDir "diagnostics"
    playwright_report = Join-Path $jointDir "playwright-report"
    playwright_stdout = Join-Path $jointDir "playwright.stdout.log"
    playwright_stderr = Join-Path $jointDir "playwright.stderr.log"
    preflight_json = $preflightJson
    preflight_md = $preflightMd
    junit_xml = Join-Path $jointDir "junit.xml"
    screenshot_index = $screenshotIndex
    visual_baseline_index = $visualBaselineIndex
    scenarios_report = $scenariosReport
    service_gaps_report = $serviceGapsReport
    service_traces_report = $serviceTracesReport
    managed_service_failure_count = $managedServiceFailures.Count
    managed_service_failures_json = $managedServiceFailuresJson
    managed_service_failures_report = $managedServiceFailuresMd
    secret_scan_status = $secretScan.status
    secret_scan_json = $secretScanJson
    secret_scan_report = $secretScanMd
    gap_todos = $gapTodosPath
    fixme_promotion_checklist = $fixmeChecklistPath
    services = $serviceLogDir
}
$summaryJson = Join-Path $jointDir "summary.json"
$summaryMd = Join-Path $jointDir "summary.md"
$summary | ConvertTo-Json -Depth 6 | Set-Content -Path $summaryJson -Encoding UTF8
@"
# Arkret Joint Product E2E summary

- report_schema: $($summary.report_schema)
- suite_kind: $($summary.suite_kind)
- suite_name: $($summary.suite_name)
- status: $($summary.status)
- run_profile: $($summary.run_profile)
- playwright_projects: $($summary.playwright_projects)
- requires_inkson: $($summary.requires_inkson)
- required_scenarios: $($requiredScenarios -join ",")
- forbid_skipped_tests: $($summary.forbid_skipped_tests)
- selection_gate_failures: $(@($summary.selection_gate_failures) -join "; ")
- started_at: $($summary.started_at)
- finished_at: $($summary.finished_at)
- duration_seconds: $($summary.duration_seconds)
- exit_code: $($summary.exit_code)
- soland_runtime: $($summary.soland_runtime)
- soland_image: $($summary.soland_image)
- server_count: $($summary.server_count)
- network_shape: $($summary.network_shape)
- topology_json: $($summary.topology_json)
- mock_idp_base_url: $($summary.mock_idp_base_url)
- mock_email_base_url: $($summary.mock_email_base_url)
- mock_witness_base_url: $($summary.mock_witness_base_url)
- mock_witness_did: $($summary.mock_witness_did)
- mock_witness_quorum_base_urls: $($mockWitnessQuorumBaseUrls -join ",")
- mock_witness_quorum_dids: $($mockWitnessQuorumDids -join ",")
- mock_mimi_facade_base_url: $($summary.mock_mimi_facade_base_url)
- mock_mimi_facade_did: $($summary.mock_mimi_facade_did)
- inkson_server1_base_url: $($summary.inkson_server1_base_url)
- coauth_server1_base_url: $($summary.coauth_server1_base_url)
- coauth_server1_service_id: $($summary.coauth_server1_service_id)
- coauth_server1_oauth_introspection_url: $($summary.coauth_server1_oauth_introspection_url)
- coauth_server1_session_grant_introspection_url: $($summary.coauth_server1_session_grant_introspection_url)
- teabay_base_url: $($summary.teabay_base_url)
- teabay_service_id: $($summary.teabay_service_id)
- screenshots: $($summary.screenshots)
- visual_baselines: $($summary.visual_baselines)
- diagnostics: $($summary.diagnostics)
- playwright_report: $($summary.playwright_report)
- playwright_stdout: $($summary.playwright_stdout)
- playwright_stderr: $($summary.playwright_stderr)
- preflight_json: $($summary.preflight_json)
- preflight_md: $($summary.preflight_md)
- junit_xml: $($summary.junit_xml)
- screenshot_index: $($summary.screenshot_index)
- visual_baseline_index: $($summary.visual_baseline_index)
- scenarios_report: $($summary.scenarios_report)
- service_gaps_report: $($summary.service_gaps_report)
- service_traces_report: $($summary.service_traces_report)
- managed_service_failure_count: $($summary.managed_service_failure_count)
- managed_service_failures_json: $($summary.managed_service_failures_json)
- managed_service_failures_report: $($summary.managed_service_failures_report)
- secret_scan_status: $($summary.secret_scan_status)
- secret_scan_json: $($summary.secret_scan_json)
- secret_scan_report: $($summary.secret_scan_report)
- gap_todos: $($summary.gap_todos)
- fixme_promotion_checklist: $($summary.fixme_promotion_checklist)
- services: $($summary.services)
"@ | Set-Content -Path $summaryMd -Encoding UTF8

$isStandaloneJointSuite = Test-IsStandaloneJointSuite `
    -IsStandalone (-not [bool]$JointDir) `
    -Grep $Grep `
    -PreflightOnly ([bool]$PreflightOnly)
if ($isStandaloneJointSuite) {
    Publish-ArtifactMirror `
        -SourceDirectory $jointDir `
        -OutputRoot $OutputRoot `
        -Channel "joint-e2e"
}

Write-Host ""
Write-Host "Arkret Joint Product E2E Summary"
Write-Host "  status      : $($summary.status)"
Write-Host "  profile     : $($summary.run_profile)"
Write-Host "  projects    : $($summary.playwright_projects)"
Write-Host "  soland rt   : $($summary.soland_runtime)"
if ($summary.soland_image) {
    Write-Host "  soland image: $($summary.soland_image)"
}
foreach ($server in $runtimeServers) { Write-Host "  soland-$($server.Name): $($server.SolandBaseUrl)" }
if ($mockIdpBaseUrl) {
    Write-Host "  mock-idp    : $mockIdpBaseUrl"
}
if ($mockEmailBaseUrl) {
    Write-Host "  mock-email  : $mockEmailBaseUrl"
}
if ($mockWitnessBaseUrl) {
    Write-Host "  mock-witness: $mockWitnessBaseUrl ($MockWitnessDid)"
    if ($mockWitnessQuorumBaseUrls.Count -gt 1) {
        Write-Host "  mock-witness-quorum: $($mockWitnessQuorumBaseUrls -join ', ')"
    }
}
if ($mockDidHostBaseUrl) {
    Write-Host "  mock-did-host: $mockDidHostBaseUrl ($MockDidHostAuthority, scid=$MockDidHostScid)"
}
if ($solandMetricsBaseUrl) {
    Write-Host "  soland-server1 metrics: $solandMetricsBaseUrl/metrics"
}
if ($teabayMetricsBaseUrl) {
    Write-Host "  teabay metrics: $teabayMetricsBaseUrl/metrics"
}
if ($mockMimiFacadeBaseUrl) {
    Write-Host "  mock-mimi-facade: $mockMimiFacadeBaseUrl ($MockMimiFacadeDid)"
}
if ($InksonBaseUrl) {
    Write-Host "  inkson-server1 : $InksonBaseUrl"
}
if ($multiServer -and $inksonServer2BaseUrl) {
    Write-Host "  inkson-server2 : $inksonServer2BaseUrl"
}
if ($CoauthBaseUrl) {
    Write-Host "  coauth-server1 : $CoauthBaseUrl"
}
if ($coauthSecondaryBaseUrl) {
    Write-Host "  coauth-server1-replica : $coauthSecondaryBaseUrl"
}
if ($TeabayBaseUrl) {
    Write-Host "  teabay      : $TeabayBaseUrl"
}
Write-Host "  screenshots : $screenshotDir"
Write-Host "  visual base : $visualBaselineDir"
Write-Host "  report      : $summaryMd"
Write-Host "  topology    : $topologyPath"
Write-Host "  secret scan : $($summary.secret_scan_status) ($secretScanMd)"
if ($isStandaloneJointSuite) {
    Write-Host "  latest      : $(Join-Path $OutputRoot 'latest\joint-e2e')"
}

$jointRunnerLock.Dispose()
exit $exitCode
