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
#>
[CmdletBinding()]
param(
    [string]$OutputRoot,
    # Exact directory that receives this run's joint outputs (junit.xml,
    # summary.json, playwright-report/, services/, ...). When set, the script
    # writes there directly and skips both the standalone `runs/joint-e2e/`
    # layout and the `latest/joint-e2e` mirror — used by run-cotest.ps1 to
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
    [string]$InksonBetaBaseUrl,
    [string]$CoauthBaseUrl,
    [string]$SolandCommand,
    [string]$SolandBin,
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
    [string]$InksonBetaCommand,
    [switch]$SkipInkson,
    [string]$CoauthCommand,
    [string]$CoauthHealthUrl,
    [switch]$StartCoauth,
    # Start a second Coauth process with the same public origin, secrets, and
    # PostgreSQL database but a separate listener. Passkey E2E uses it to prove
    # that a ceremony started on one process can finish on another.
    [switch]$DualCoauth,
    [string]$CoauthBin,
    [string]$CoauthPostgresImage = "postgres:16-alpine",
    # Optional externally-provisioned Postgres DSN for coauth. When set, the
    # harness skips the docker-backed ephemeral Postgres entirely (useful when
    # Docker Desktop is unavailable and a local PostgreSQL serves instead).
    [string]$CoauthPostgresUrl,
    [switch]$StartStarid,
    [string]$StaridBin,
    [string]$StaridBaseUrl,
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
    [switch]$SkipNpmInstall,
    [switch]$SkipBrowserInstall,
    [switch]$SkipBuild,
    [switch]$KeepServices,
    [switch]$SkipPreflight,
    [switch]$PreflightOnly,
    [switch]$RunnerSelfTest,
    [switch]$DualSoland,
    [string]$SolandBetaNotarySigningKey = "ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg=",
    [string]$SolandBetaKeyStoreMasterKey = "ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmY=",
    [switch]$StartMockIdp,
    [switch]$StartMockEmail,
    [switch]$StartMockWitness,
    [switch]$StartMockPolicyServer,
    [string]$MockPolicyServerDid,
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
    [switch]$StartMocks,
    [string]$MockWitnessDid = "did:webvh:z6mkfixture:witness.joint-e2e.local",
    [string[]]$MockWitnessExtraDids = @(),
    [ValidateSet("joint-smoke", "joint-full")]
    [string]$RunProfile,
    [string]$PlaywrightProject = "chrome",
    [string]$Grep,
    # Run a non-Playwright driver while the managed stack is alive. This is
    # used by agent-journeys so the browser agent can operate the real stack
    # while this runner retains lifecycle ownership and deterministic cleanup.
    [string]$ExternalDriverScript,
    [string[]]$ExternalDriverArgument = @(),
    [string]$RuntimeManifestPath
)

if ($StartMocks) {
    $StartMockIdp = $true
    $StartMockEmail = $true
    $StartMockWitness = $true
    $StartMockPolicyServer = $true
    $StartMockPushGateway = $true
    $StartMockAppletRegistry = $true
    $StartMockTspEndpoint = $true
    $StartMockMimiFacade = $true
    $StartMockClaimIssuer = $true
    $StartMockChallengeProvider = $true
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

. (Join-Path $PSScriptRoot "lib\artifacts.ps1")
. (Join-Path $PSScriptRoot "lib\secret-scan.ps1")
. (Join-Path $PSScriptRoot "lib\failure-fingerprint.ps1")

$StaridServiceId = $null
$SolandServiceId = $null
$SolandBetaServiceId = $null
$CoauthServiceId = $null
$CoauthEnrollmentAuthorityDid = "did:key:z6Mkfmm57fsb6VL7zVusP8zeA9SYkCKdvUhby2G7Yh8vvQ1P"

if ($PreflightOnly -and $SkipPreflight) {
    throw "-PreflightOnly cannot be combined with -SkipPreflight"
}
if ($ExternalDriverArgument.Count -gt 0 -and -not $ExternalDriverScript) {
    throw "-ExternalDriverArgument requires -ExternalDriverScript"
}
if ($ExternalDriverScript -and -not (Test-Path -LiteralPath $ExternalDriverScript -PathType Leaf)) {
    throw "External driver script not found: $ExternalDriverScript"
}

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
        [Parameter(Mandatory = $true)][string[]]$RepositoryRoots
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
        $shortHead = if ($newest.Head.Length -gt 12) { $newest.Head.Substring(0, 12) } else { $newest.Head }
        $detail = "binary=$($newest.BinaryTimeUtc.ToString('o')); newest_input=$($newest.RequiredTimeUtc.ToString('o')); repo=$($newest.RepositoryName); head=$shortHead; input=$($newest.RequiredBy)"
        if ($newest.BinaryTimeUtc -lt $newest.RequiredTimeUtc) {
            Add-PreflightResult $Results $Name "fail" "stale binary; $detail"
        } else {
            Add-PreflightResult $Results $Name "pass" $detail
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
        return [pscustomobject]@{
            Fresh = $newest.BinaryTimeUtc -ge $newest.RequiredTimeUtc
            Detail = "artifact=$($newest.BinaryTimeUtc.ToString('o')); newest_input=$($newest.RequiredTimeUtc.ToString('o')); repo=$($newest.RepositoryName); input=$($newest.RequiredBy)"
        }
    } catch {
        return [pscustomobject]@{ Fresh = $false; Detail = $_.Exception.Message }
    }
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
        [Parameter(Mandatory = $true)][bool]$SkipNpmInstall,
        [Parameter(Mandatory = $true)][bool]$StartCoauth,
        [Parameter(Mandatory = $true)][string]$CoauthPostgresImage,
        [string]$CoauthBin,
        [bool]$StartStarid = $false,
        [string]$StaridBin,
        [bool]$StartTeabay = $false,
        [string]$TeabayBin,
        [string]$TeabayDatabaseUrl,
        [string]$SolandBaseUrl,
        [string]$SolandCommand,
        [string]$SolandBin,
        [bool]$WillStartDefaultSoland = $false,
        [ValidateSet("process", "docker")][string]$SolandRuntime = "process",
        [string]$SolandImage,
        [bool]$WillStartDockerSoland = $false,
        [string]$InksonBaseUrl,
        [string]$InksonCommand,
        [bool]$WillStartDefaultInkson = $false,
        [string]$InksonStaticIndex,
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
    } elseif ($SkipNpmInstall) {
        Add-PreflightResult $results "e2e node_modules" "fail" "node_modules missing while -SkipNpmInstall is set"
    } else {
        Add-PreflightResult $results "e2e node_modules" "pass" "missing; runner will execute npm install"
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
                    )
            } catch {
                Add-PreflightResult $results "soland binary" "fail" $_.Exception.Message
            }
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

    if ($WillStartDefaultInkson -or (-not $InksonBaseUrl -and -not $InksonCommand)) {
        if ($InksonStaticIndex -and (Test-Path -LiteralPath $InksonStaticIndex -PathType Leaf)) {
            Add-PreflightResult $results "inkson web bundle" "pass" $InksonStaticIndex
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

    if ($StartStarid) {
        try {
            $staridBinary = Resolve-StaridBinary -ExplicitPath $StaridBin -WorkspaceRoot $WorkspaceRoot
            Add-PreflightResult $results "starid binary" "pass" $staridBinary
            Add-BinaryFreshnessPreflight `
                -Results $results `
                -Name "starid binary freshness" `
                -BinaryPath $staridBinary `
                -RepositoryRoots @(
                    (Join-Path $WorkspaceRoot "starid"),
                    (Join-Path $WorkspaceRoot "arkret-rust-sdk")
                )
        } catch {
            Add-PreflightResult $results "starid binary" "fail" $_.Exception.Message
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
                )
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
                )
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
    $candidates += (Join-Path $WorkspaceRoot "coauth\target\debug\coauth.exe")
    $candidates += (Join-Path $WorkspaceRoot "coauth\target\release\coauth.exe")

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
    $candidates += (Join-Path $WorkspaceRoot "soland\target\debug\soland.exe")
    $candidates += (Join-Path $WorkspaceRoot "soland\target\release\soland.exe")

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) {
            return (Resolve-Path $candidate).Path
        }
    }
    throw "Unable to find soland binary. Build soland first or pass -SolandBin."
}

function Resolve-StaridBinary {
    param(
        [string]$ExplicitPath,
        [Parameter(Mandatory = $true)][string]$WorkspaceRoot
    )

    $candidates = @()
    if ($ExplicitPath) { $candidates += $ExplicitPath }
    if ($env:STARID_BIN) { $candidates += $env:STARID_BIN }
    $candidates += (Join-Path $WorkspaceRoot "starid\target\debug\starid.exe")
    $candidates += (Join-Path $WorkspaceRoot "starid\target\release\starid.exe")

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) {
            return (Resolve-Path $candidate).Path
        }
    }
    throw "Unable to find starid binary. Build starid first or pass -StaridBin."
}

function Resolve-TeabayBinary {
    param(
        [string]$ExplicitPath,
        [Parameter(Mandatory = $true)][string]$WorkspaceRoot
    )

    $candidates = @()
    if ($ExplicitPath) { $candidates += $ExplicitPath }
    if ($env:TEABAY_BIN) { $candidates += $env:TEABAY_BIN }
    $candidates += (Join-Path $WorkspaceRoot "teabay\target\debug\teabay.exe")
    $candidates += (Join-Path $WorkspaceRoot "teabay\target\release\teabay.exe")

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
    while ((Get-Date) -lt $deadline) {
        $readyOutput = Invoke-NativeCapture -FilePath "docker" -Arguments @("exec", $containerName, "pg_isready", "-U", "arkret", "-d", "arkret")
        if ($LASTEXITCODE -eq 0) {
            return [pscustomobject]@{
                ContainerName = $containerName
                HostPort = $port
                Url = "postgresql://arkret:arkret@127.0.0.1:$port/arkret"
            }
        }
        $lastError = $readyOutput -join "`n"
        Start-Sleep -Milliseconds 500
    }

    & docker rm -f $containerName | Out-Null
    throw "Timed out waiting for PostgreSQL container $containerName. Last error: $lastError"
}

function Stop-EphemeralPostgres {
    param([Parameter(Mandatory = $true)][string]$ContainerName)
    & docker rm -f $ContainerName 2>$null | Out-Null
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
        [Parameter(Mandatory = $true)][string]$InksonBaseUrl,
        [Parameter(Mandatory = $true)][string]$OAuthClientId,
        [Parameter(Mandatory = $true)][string]$SolandBaseUrl,
        [string]$SolandBetaBaseUrl,
        [Parameter(Mandatory = $true)][string]$SessionGrantIntrospectionBearer,
        [Parameter(Mandatory = $true)][string]$EmbeddedWebvhRegistrationBearer,
        [string]$MockEmailBaseUrl
    )

    $rawConfig = Join-Path $JointDir "coauth.raw.yaml"
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
        "--inkson-base-url", $InksonBaseUrl,
        "--oauth-client-id", $OAuthClientId,
        "--soland-base-url", $SolandBaseUrl,
        "--session-grant-introspection-bearer", $SessionGrantIntrospectionBearer,
        "--embedded-webvh-registration-bearer", $EmbeddedWebvhRegistrationBearer
    )
    if ($MockEmailBaseUrl) {
        $patchArgs += @("--mock-email-base-url", $MockEmailBaseUrl)
    }
    if ($SolandBetaBaseUrl) {
        $patchArgs += @("--soland-beta-base-url", $SolandBetaBaseUrl)
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

function Wait-HttpReady {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastError = $null
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
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
            $describe = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 10 -ErrorAction Stop
            $serviceId = [string]$describe.service_id
            if (-not [string]::IsNullOrWhiteSpace($serviceId) -and $serviceId.StartsWith("did:")) {
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

function Assert-CoauthDpopGrantSeamReady {
    param([Parameter(Mandatory = $true)][string]$BaseUrl)

    $url = "$($BaseUrl.TrimEnd('/'))/_coauth/account/test/debug/issue-dpop-grant"
    try {
        # An empty object is intentionally invalid. Any non-404 HTTP response
        # proves the debug-only route is registered; the joint tests create the
        # valid account/device-bound request later.
        Invoke-WebRequest `
            -Uri $url `
            -Method Post `
            -ContentType "application/json" `
            -Body "{}" `
            -UseBasicParsing `
            -TimeoutSec 5 `
            -ErrorAction Stop | Out-Null
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
    $process = Start-Process `
        -FilePath "powershell" `
        -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $Command) `
        -WorkingDirectory $WorkingDirectory `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -WindowStyle Hidden `
        -PassThru

    [pscustomobject]@{
        Kind = "process"
        Name = $Name
        Process = $process
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

    $panicPattern = "(?i)(thread\s+['""][^'""]+['""]\s+panicked\s+at|panicked with message|fatal runtime error)"
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
if (-not $InksonRoot) {
    $InksonRoot = Join-Path $workspaceRoot "inkson"
}
$InksonRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($InksonRoot)
if (-not $SavfoxRoot) {
    $SavfoxRoot = Join-Path (Split-Path -Parent $workspaceRoot) "savfox-ai\savfox"
}
$SavfoxRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($SavfoxRoot)

# Canonical artifacts layout (see cotest/README.md "Artifacts layout"):
#   <OutputRoot>/runs/joint-e2e/<timestamp>-<profile>/ — authoritative outputs
#   <OutputRoot>/latest/joint-e2e/                     — latest non-targeted suite
# With -JointDir the caller owns the run directory and both are skipped.
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
if ($JointDir) {
    $jointDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($JointDir)
} else {
    $jointRunLabel = if ($RunProfile) { $RunProfile } else { "custom" }
    if ($Grep) {
        $jointRunLabel += "-selection"
    } elseif ($ExternalDriverScript) {
        $jointRunLabel += "-external-driver"
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

if (-not $SolandBaseUrl) {
    $solandPort = Get-FreeTcpPort
    $SolandBaseUrl = "http://127.0.0.1:$solandPort"
} else {
    $solandPort = $null
}
$solandBetaPort = $null
$solandBetaBaseUrl = $null
if ($DualSoland) {
    if ($SolandCommand) {
        throw "-DualSoland is incompatible with -SolandCommand; the harness must generate both soland invocations."
    }
    $solandBetaPort = Get-FreeTcpPort
    $solandBetaBaseUrl = "http://127.0.0.1:$solandBetaPort"
}
if ($SolandRuntime -eq "docker" -and $SolandCommand) {
    throw "-SolandRuntime docker is incompatible with -SolandCommand; omit -SolandCommand so the harness can start the image."
}
if ($SkipInkson -and ($InksonCommand -or $InksonBetaCommand -or $PSBoundParameters.ContainsKey("InksonBaseUrl") -or $PSBoundParameters.ContainsKey("InksonBetaBaseUrl"))) {
    throw "-SkipInkson cannot be combined with Inkson URLs or commands."
}
# Coauth's generated development config still requires an Inkson origin even
# for API-only runs. Keep that service URL out of the caller's scope while
# providing a harmless placeholder for config generation; no Inkson process or
# readiness probe is started when -SkipInkson is set.
if ($SkipInkson -and -not $InksonBaseUrl) {
    $InksonBaseUrl = "http://127.0.0.1:22817"
}
$inksonPort = $null
if (-not $SkipInkson) {
    if (-not $InksonBaseUrl) {
        $inksonPort = Get-FreeTcpPort
        $InksonBaseUrl = "http://127.0.0.1:$inksonPort"
    }
}
$inksonBetaPort = $null
$inksonBetaBaseUrl = $null
$inksonBaseUrlWasExplicit = $PSBoundParameters.ContainsKey("InksonBaseUrl")
if ($DualSoland -and -not $SkipInkson) {
    if ($InksonBetaBaseUrl) {
        $inksonBetaBaseUrl = $InksonBetaBaseUrl
    } elseif ($InksonBetaCommand) {
        throw "-InksonBetaCommand requires -InksonBetaBaseUrl so the harness can route browser contexts."
    } elseif ($InksonCommand -or $inksonBaseUrlWasExplicit) {
        $inksonBetaBaseUrl = $InksonBaseUrl
    } else {
        $inksonBetaPort = Get-FreeTcpPort
        $inksonBetaBaseUrl = "http://127.0.0.1:$inksonBetaPort"
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
    # effective domain in url/webauthn-rs, while localhost is the standard
    # secure-context exception for loopback development. Keep the listener
    # bound to 127.0.0.1 below, but advertise a WebAuthn-valid public origin.
    $CoauthBaseUrl = "http://localhost:$coauthPort"
} else {
    $coauthPort = $null
}
$coauthSecondaryPort = $null
$coauthSecondaryBaseUrl = $null
$CoauthSecondaryCommand = $null
if ($DualCoauth) {
    $coauthSecondaryPort = Get-FreeTcpPort
    $coauthSecondaryBaseUrl = "http://127.0.0.1:$coauthSecondaryPort"
}

# CT-6: starid + teabay joint participants. Mirror the -StartCoauth port
# allocation pattern. Teabay additionally needs a DATABASE_URL because the
# binary will refuse to boot without one (per TEABAY_SPEC.required_env_vars
# in the cotest helper).
$staridPort = $null
if ($StartStarid -and -not $StaridBaseUrl) {
    $staridPort = Get-FreeTcpPort
    $StaridBaseUrl = "http://127.0.0.1:$staridPort"
}
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
$mockPolicyServerPort = $null
$mockPolicyServerBaseUrl = $null
if ($StartMockPolicyServer) {
    $mockPolicyServerPort = Get-FreeTcpPort
    $mockPolicyServerBaseUrl = "http://127.0.0.1:$mockPolicyServerPort"
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
$ephemeralPostgres = $null
$exitCode = 1
$startedAt = Get-Date
$generatedSolandCommand = $false
$generatedInksonCommand = $false
$willStartDefaultSoland = (-not $SolandCommand -and $null -ne $solandPort)
$willStartDefaultInkson = (-not $SkipInkson -and -not $InksonCommand -and $null -ne $inksonPort)
$willStartDockerSoland = ($SolandRuntime -eq "docker" -and ($willStartDefaultSoland -or ($DualSoland -and $null -ne $solandBetaPort)))
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
$inksonStaticRoot = Join-Path $InksonRoot "target\dx\inkson\debug\web\public"
$inksonStaticIndex = Join-Path $inksonStaticRoot "index.html"
$playwrightProjects = Resolve-PlaywrightProjects `
    -RunProfile $RunProfile `
    -PlaywrightProject $PlaywrightProject `
    -PlaywrightProjectWasExplicit ($PSBoundParameters.ContainsKey("PlaywrightProject"))

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
        $defaultSolandBinary = Join-Path $workspaceRoot "soland\target\debug\soland.exe"
        $freshness = Get-ArtifactFreshness `
            -ArtifactPath $defaultSolandBinary `
            -RepositoryRoots @(
                (Join-Path $workspaceRoot "soland"),
                (Join-Path $workspaceRoot "arkret-rust-sdk")
            )
        if (-not $freshness.Fresh) {
            Write-Host "Preparing soland binary: $($freshness.Detail)"
            $started = Get-Date
            $service = Start-ManagedCommand `
                -Name "prepare-soland" `
                -Command ("cargo build --manifest-path {0} --bin soland" -f (Quote-PsLiteral $SutManifest)) `
                -WorkingDirectory (Split-Path -Parent $SutManifest) `
                -LogDirectory $serviceLogDir
            $preparationTasks.Add([pscustomobject]@{ Name = "soland"; Service = $service; Started = $started; Artifact = $defaultSolandBinary; AllowUnchangedArtifact = $true })
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
        $cotestWireBinary = Join-Path $repoRoot "target\debug\cotest-wire.exe"
        $wireFreshness = Get-ArtifactFreshness `
            -ArtifactPath $cotestWireBinary `
            -RepositoryRoots @(
                $repoRoot,
                (Join-Path $workspaceRoot "arkret-rust-sdk")
            )
        if (-not $wireFreshness.Fresh) {
            Write-Host "Preparing cotest-wire binary: $($wireFreshness.Detail)"
            $started = Get-Date
            $cotestManifest = Join-Path $repoRoot "Cargo.toml"
            $service = Start-ManagedCommand `
                -Name "prepare-cotest-wire" `
                -Command ("cargo build --manifest-path {0} --bin cotest-wire" -f (Quote-PsLiteral $cotestManifest)) `
                -WorkingDirectory $repoRoot `
                -LogDirectory $serviceLogDir
            $preparationTasks.Add([pscustomobject]@{ Name = "cotest-wire"; Service = $service; Started = $started; Artifact = $cotestWireBinary; AllowUnchangedArtifact = $true })
        } else {
            $preparationTimings.Add([pscustomobject]@{ name = "cotest-wire"; status = "cache-hit"; duration_seconds = 0; detail = $wireFreshness.Detail })
        }
    }

    if (-not $SkipBuild -and $StartCoauth -and -not $CoauthBin) {
        $defaultCoauthBinary = Join-Path $workspaceRoot "coauth\target\debug\coauth.exe"
        $coauthFreshness = Get-ArtifactFreshness `
            -ArtifactPath $defaultCoauthBinary `
            -RepositoryRoots @(
                (Join-Path $workspaceRoot "coauth"),
                (Join-Path $workspaceRoot "arkret-rust-sdk")
            )
        if (-not $coauthFreshness.Fresh) {
            Write-Host "Preparing coauth binary: $($coauthFreshness.Detail)"
            $started = Get-Date
            $coauthManifest = Join-Path $workspaceRoot "coauth\Cargo.toml"
            $service = Start-ManagedCommand `
                -Name "prepare-coauth" `
                -Command ("cargo build --manifest-path {0} --bin coauth" -f (Quote-PsLiteral $coauthManifest)) `
                -WorkingDirectory (Split-Path -Parent $coauthManifest) `
                -LogDirectory $serviceLogDir
            $preparationTasks.Add([pscustomobject]@{ Name = "coauth"; Service = $service; Started = $started; Artifact = $defaultCoauthBinary; AllowUnchangedArtifact = $true })
        } else {
            $preparationTimings.Add([pscustomobject]@{ name = "coauth"; status = "cache-hit"; duration_seconds = 0; detail = $coauthFreshness.Detail })
        }
    }

    if (-not $SkipBuild -and $StartStarid -and -not $StaridBin -and -not $env:STARID_BIN) {
        $defaultStaridBinary = Join-Path $workspaceRoot "starid\target\debug\starid.exe"
        $staridFreshness = Get-ArtifactFreshness `
            -ArtifactPath $defaultStaridBinary `
            -RepositoryRoots @(
                (Join-Path $workspaceRoot "starid"),
                (Join-Path $workspaceRoot "arkret-rust-sdk")
            )
        if (-not $staridFreshness.Fresh) {
            Write-Host "Preparing starid binary: $($staridFreshness.Detail)"
            $started = Get-Date
            $staridManifest = Join-Path $workspaceRoot "starid\Cargo.toml"
            $service = Start-ManagedCommand `
                -Name "prepare-starid" `
                -Command ("cargo build --manifest-path {0} --bin starid" -f (Quote-PsLiteral $staridManifest)) `
                -WorkingDirectory (Split-Path -Parent $staridManifest) `
                -LogDirectory $serviceLogDir
            $preparationTasks.Add([pscustomobject]@{ Name = "starid"; Service = $service; Started = $started; Artifact = $defaultStaridBinary; AllowUnchangedArtifact = $true })
        } else {
            $preparationTimings.Add([pscustomobject]@{ name = "starid"; status = "cache-hit"; duration_seconds = 0; detail = $staridFreshness.Detail })
        }
    }

    if (-not $SkipBuild -and $StartSavfox -and -not $SavfoxBin -and -not $env:SAVFOX_BIN) {
        $defaultSavfoxBinary = Join-Path $SavfoxRoot "target\debug\savfox.exe"
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
        $preparationTasks.Add([pscustomobject]@{ Name = "savfox"; Service = $service; Started = $started; Artifact = $defaultSavfoxBinary; AllowUnchangedArtifact = $true })
    }

    if (-not $SkipBuild -and $willStartDefaultInkson) {
        $inksonWasm = Join-Path $inksonStaticRoot "wasm\inkson_bg.wasm"
        $inksonFreshness = Get-ArtifactFreshness `
            -ArtifactPath $inksonStaticIndex `
            -RepositoryRoots @(
                $InksonRoot,
                (Join-Path $workspaceRoot "arkret-rust-sdk"),
                (Join-Path $workspaceRoot "garth"),
                (Join-Path $workspaceRoot "chime"),
                (Join-Path $workspaceRoot "yoface")
            )
        $inksonTestFeaturePresent = Test-BinaryContainsAsciiMarker `
            -Path $inksonWasm `
            -Marker "inkson.test.session_injection.v1"
        if (-not $inksonFreshness.Fresh -or -not $inksonTestFeaturePresent) {
            Write-Host "Preparing inkson web bundle: $($inksonFreshness.Detail)"
            $started = Get-Date
            $buildCommand = Add-DioxusNoDownloadsEnvironment `
                -Command "dx build --profile joint-e2e --platform web --features experimental-agents,wasm-localstorage-secrets-test" `
                -ProjectRoot $InksonRoot
            # Dioxus 0.7.9 can assemble the shared debug output from a stale
            # wasm-dev executable even though Cargo built the requested custom
            # profile. Re-run wasm-bindgen against Cargo's exact joint-e2e
            # artifact so the static bundle cannot silently lose the cotest
            # feature or regain debug-only devtools.
            $jointE2eWasm = Join-Path $InksonRoot "target\wasm32-unknown-unknown\joint-e2e\inkson.wasm"
            $inksonWasmOutputDir = Join-Path $inksonStaticRoot "wasm"
            $finalizeInksonWasm = Join-Path $repoRoot "scripts\finalize-inkson-joint-e2e-wasm.ps1"
            $buildCommand = "$buildCommand; if (`$LASTEXITCODE -ne 0) { exit `$LASTEXITCODE }; & $(Quote-PsLiteral $finalizeInksonWasm) -SourceWasm $(Quote-PsLiteral $jointE2eWasm) -OutputDirectory $(Quote-PsLiteral $inksonWasmOutputDir)"
            $service = Start-ManagedCommand `
                -Name "prepare-inkson" `
                -Command $buildCommand `
                -WorkingDirectory $InksonRoot `
                -LogDirectory $serviceLogDir
            $preparationTasks.Add([pscustomobject]@{ Name = "inkson"; Service = $service; Started = $started; Artifact = $inksonStaticIndex; AllowUnchangedArtifact = $false })
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

    if (-not $SkipPreflight) {
        Invoke-JointE2ePreflight `
            -RepoRoot $repoRoot `
            -WorkspaceRoot $workspaceRoot `
            -E2eRoot $e2eRoot `
            -PlaywrightProjects $playwrightProjects `
            -SkipNpmInstall ([bool]$SkipNpmInstall) `
            -StartCoauth ([bool]$StartCoauth) `
            -CoauthPostgresImage $CoauthPostgresImage `
            -CoauthBin $CoauthBin `
            -StartStarid ([bool]$StartStarid) `
            -StaridBin $StaridBin `
            -StartTeabay ([bool]$StartTeabay) `
            -TeabayBin $TeabayBin `
            -TeabayDatabaseUrl $TeabayDatabaseUrl `
            -SolandBaseUrl $SolandBaseUrl `
            -SolandCommand $SolandCommand `
            -SolandBin $SolandBin `
            -WillStartDefaultSoland $willStartDefaultSoland `
            -SolandRuntime $SolandRuntime `
            -SolandImage $SolandImage `
            -WillStartDockerSoland $willStartDockerSoland `
            -InksonBaseUrl $InksonBaseUrl `
            -InksonCommand $InksonCommand `
            -WillStartDefaultInkson $willStartDefaultInkson `
            -InksonStaticIndex $inksonStaticIndex `
            -JsonPath $preflightJson `
            -MarkdownPath $preflightMd
    }

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
    if ($StartMockPolicyServer) {
        $envExpr = "`$env:MOCK_POLICY_SERVER_PORT='$mockPolicyServerPort'"
        if ($MockPolicyServerDid) {
            $envExpr = "$envExpr; `$env:MOCK_POLICY_SERVER_DID=" + (Quote-PsLiteral $MockPolicyServerDid)
        }
        $mockPolicyServerCmd = "$envExpr; node " + (Quote-PsLiteral (Join-Path $mocksRoot "mock-policy-server.mjs"))
        $managedServices.Add((Start-ManagedCommand -Name "mock-policy-server" -Command $mockPolicyServerCmd -WorkingDirectory $mocksRoot -LogDirectory $serviceLogDir))
        Wait-HttpReady -Url "$mockPolicyServerBaseUrl/_arkret/self/policy/health" -TimeoutSeconds 30
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
    if ($StartMockAppletRegistry) {
        $envExpr = "`$env:MOCK_APPLET_REGISTRY_PORT='$mockAppletRegistryPort'"
        if ($MockAppletRegistryDid) {
            $envExpr = "$envExpr; `$env:MOCK_APPLET_REGISTRY_DID=" + (Quote-PsLiteral $MockAppletRegistryDid)
        }
        $mockAppletRegistryCmd = "$envExpr; node " + (Quote-PsLiteral (Join-Path $mocksRoot "mock-applet-registry.mjs"))
        $managedServices.Add((Start-ManagedCommand -Name "mock-applet-registry" -Command $mockAppletRegistryCmd -WorkingDirectory $mocksRoot -LogDirectory $serviceLogDir))
        Wait-HttpReady -Url "$mockAppletRegistryBaseUrl/identity" -TimeoutSeconds 30
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
        $savfoxHome = Join-Path $jointDir "savfox-home"
        $savfoxUnaddressedHome = Join-Path $jointDir "savfox-unaddressed-home"
        New-Item -ItemType Directory -Path $savfoxHome -Force | Out-Null
        New-Item -ItemType Directory -Path $savfoxUnaddressedHome -Force | Out-Null
        $savfoxModelReceipts = Join-Path $jointDir "savfox-model-receipts.jsonl"
        $savfoxUnaddressedModelReceipts = Join-Path $jointDir "savfox-unaddressed-model-receipts.jsonl"
        $savfoxConfig = @"
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
base_url = "$savfoxModelBaseUrl/v1"
wire_api = "responses"
request_max_retries = 0
stream_max_retries = 0
requires_openai_auth = false
"@
        $savfoxConfig | Set-Content -LiteralPath (Join-Path $savfoxHome "config.toml") -Encoding UTF8
        $savfoxConfig.Replace($savfoxModelBaseUrl, $savfoxUnaddressedModelBaseUrl) |
            Set-Content -LiteralPath (Join-Path $savfoxUnaddressedHome "config.toml") -Encoding UTF8
        $savfoxModelCommand = (
            "`$env:MOCK_SAVFOX_MODEL_PORT='{0}'; `$env:MOCK_SAVFOX_MODEL_RECEIPT_PATH={1}; node {2}"
        ) -f $savfoxModelPort, (Quote-PsLiteral $savfoxModelReceipts), (Quote-PsLiteral (Join-Path $mocksRoot "mock-savfox-model.mjs"))
        $managedServices.Add((Start-ManagedCommand -Name "mock-savfox-model" -Command $savfoxModelCommand -WorkingDirectory $mocksRoot -LogDirectory $serviceLogDir))
        Wait-HttpReady -Url "$savfoxModelBaseUrl/health" -TimeoutSeconds 30
        $savfoxUnaddressedModelCommand = (
            "`$env:MOCK_SAVFOX_MODEL_PORT='{0}'; `$env:MOCK_SAVFOX_MODEL_RECEIPT_PATH={1}; node {2}"
        ) -f $savfoxUnaddressedModelPort, (Quote-PsLiteral $savfoxUnaddressedModelReceipts), (Quote-PsLiteral (Join-Path $mocksRoot "mock-savfox-model.mjs"))
        $managedServices.Add((Start-ManagedCommand -Name "mock-savfox-unaddressed-model" -Command $savfoxUnaddressedModelCommand -WorkingDirectory $mocksRoot -LogDirectory $serviceLogDir))
        Wait-HttpReady -Url "$savfoxUnaddressedModelBaseUrl/health" -TimeoutSeconds 30
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
            $ephemeralPostgres = Start-EphemeralPostgres -Image $CoauthPostgresImage -NamePrefix "cotest-coauth-$timestamp" -TimeoutSeconds $StartupTimeoutSeconds
            $coauthPostgresDsn = $ephemeralPostgres.Url
        }
        $coauthConfigPath = New-CoauthJointConfig `
            -CoauthBinary $coauthBinary `
            -RepoRoot $repoRoot `
            -JointDir $jointDir `
            -PostgresUrl $coauthPostgresDsn `
            -CoauthBaseUrl $CoauthBaseUrl `
            -CoauthBind "127.0.0.1:$coauthPort" `
            -CedarPolicyFile $coauthPolicyFile `
            -InksonBaseUrl $InksonBaseUrl `
            -OAuthClientId $CoauthOAuthClientId `
            -SolandBaseUrl $SolandBaseUrl `
            -SolandBetaBaseUrl $solandBetaBaseUrl `
            -SessionGrantIntrospectionBearer $CoauthSessionGrantIntrospectionBearer `
            -EmbeddedWebvhRegistrationBearer $CoauthEmbeddedWebvhRegistrationBearer `
            -MockEmailBaseUrl $mockEmailBaseUrl
        if ($DualCoauth) {
            $coauthSecondaryConfigPath = Join-Path $jointDir "coauth-secondary.yaml"
            $primaryBind = "address: `"127.0.0.1:$coauthPort`""
            $secondaryBind = "address: `"127.0.0.1:$coauthSecondaryPort`""
            $primaryConfig = Get-Content -LiteralPath $coauthConfigPath -Raw
            if (-not $primaryConfig.Contains($primaryBind)) {
                throw "Could not locate primary Coauth bind '$primaryBind' in $coauthConfigPath"
            }
            $primaryConfig.Replace($primaryBind, $secondaryBind) |
                Set-Content -LiteralPath $coauthSecondaryConfigPath -Encoding UTF8
        }
        Invoke-CoauthMigrations -CoauthBinary $coauthBinary -ConfigPath $coauthConfigPath -LogDirectory $serviceLogDir -TimeoutSeconds $StartupTimeoutSeconds
        Invoke-CoauthConfigSync -CoauthBinary $coauthBinary -ConfigPath $coauthConfigPath -LogDirectory $serviceLogDir
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
        # Coauth's production client is HTTPS/public-egress only. The joint stack
        # intentionally binds every dependency to loopback over HTTP, so enable
        # the debug-only, loopback-only transport seam alongside test endpoints.
        $CoauthCommand = "& {0} --config {1} --no-env-overrides --enable-test-endpoints --allow-insecure-loopback-http --allow-insecure-dev-email-bypass --allow-insecure-password-bootstrap server --no-migrate --no-sync" -f (Quote-PsLiteral $coauthBinary), (Quote-PsLiteral $coauthConfigPath)
        $CoauthHealthUrl = "$($CoauthBaseUrl.TrimEnd('/'))/health"
        if ($DualCoauth) {
            $CoauthSecondaryCommand = "& {0} --config {1} --no-env-overrides --enable-test-endpoints --allow-insecure-loopback-http --allow-insecure-dev-email-bypass --allow-insecure-password-bootstrap server --no-migrate --no-sync" -f (Quote-PsLiteral $coauthBinary), (Quote-PsLiteral $coauthSecondaryConfigPath)
        }
    }

    # CT-6: starid (DID resolver) - no external deps. Spawned
    # before soland so soland's SOLAND_STARID_WEBVH_RESOLVER_URL points at a
    # live listener from the first request onwards.
    if ($StartStarid) {
        if (-not $staridPort) {
            $staridUri = [System.Uri]$StaridBaseUrl
            $staridPort = $staridUri.Port
        }
        $staridBinary = Resolve-StaridBinary -ExplicitPath $StaridBin -WorkspaceRoot $workspaceRoot
        $staridConfigPath = Join-Path $jointDir "starid.env"
        Write-DotEnvFile -Path $staridConfigPath -Values ([ordered]@{
                STARID_DEVELOPMENT_MODE = "true"
            })
        $staridCmd = "& {0} --config {1} --no-env-overrides --bind 127.0.0.1:{2}" -f `
            (Quote-PsLiteral $staridBinary),
            (Quote-PsLiteral $staridConfigPath),
            $staridPort
        $managedServices.Add((Start-ManagedCommand -Name "starid" -Command $staridCmd -WorkingDirectory (Split-Path -Parent $staridBinary) -LogDirectory $serviceLogDir))
        Wait-HttpReady -Url "$($StaridBaseUrl.TrimEnd('/'))/health" -TimeoutSeconds $StartupTimeoutSeconds
        $StaridServiceId = Get-DescribedServiceId -BaseUrl $StaridBaseUrl -ServiceName "starid"
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
        Write-DotEnvFile -Path $teabayConfigPath -Values ([ordered]@{
                DATABASE_URL = $teabayDb
                TEABAY_PUBLIC_BASE_URL = $TeabayBaseUrl
                TEABAY_SERVICE_ID = $TeabayServiceId
                TEABAY_DEVELOPMENT_MODE = "true"
                TEABAY_PRIVATE_CONTACT_DISCOVERY_ENABLED = "true"
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
            Join-Path $SavfoxRoot "target\debug\savfox.exe"
        }
        if (-not (Test-Path -LiteralPath $savfoxBinary -PathType Leaf)) {
            throw "Savfox binary not found: $savfoxBinary"
        }
        $savfoxCommand = (
            "`$env:SAVFOX_HOME={0}; `$env:RUST_LOG='info'; & {1} gateway --host 127.0.0.1 --port {2} --token {3}"
        ) -f (Quote-PsLiteral $savfoxHome), (Quote-PsLiteral $savfoxBinary), $savfoxPort, (Quote-PsLiteral $SavfoxToken)
        $managedServices.Add((Start-ManagedCommand -Name "savfox" -Command $savfoxCommand -WorkingDirectory $SavfoxRoot -LogDirectory $serviceLogDir))
        Wait-HttpReady -Url "$($SavfoxBaseUrl.TrimEnd('/'))/health" -TimeoutSeconds $StartupTimeoutSeconds
        $savfoxUnaddressedCommand = (
            "`$env:SAVFOX_HOME={0}; `$env:RUST_LOG='info'; & {1} gateway --host 127.0.0.1 --port {2} --token {3}"
        ) -f (Quote-PsLiteral $savfoxUnaddressedHome), (Quote-PsLiteral $savfoxBinary), $savfoxUnaddressedPort, (Quote-PsLiteral $savfoxUnaddressedToken)
        $managedServices.Add((Start-ManagedCommand -Name "savfox-unaddressed" -Command $savfoxUnaddressedCommand -WorkingDirectory $SavfoxRoot -LogDirectory $serviceLogDir))
        Wait-HttpReady -Url "$($savfoxUnaddressedBaseUrl.TrimEnd('/'))/health" -TimeoutSeconds $StartupTimeoutSeconds
    }

    function Build-SolandDockerEnvironment {
        param(
            [Parameter(Mandatory = $true)][string]$BaseUrl,
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
            DATABASE_URL = ""
            SOLAND_BIND = "0.0.0.0:$SolandContainerPort"
            SOLAND_PUBLIC_BASE_URL = $BaseUrl
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
            SOLAND_CANDIDATE_JOIN_POLICY = "true"
            SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER = $CoauthEmbeddedWebvhRegistrationBearer
        }
        if ($CoauthBaseUrl) {
            $coauthPublic = $CoauthBaseUrl.TrimEnd("/")
            $coauthContainer = (Convert-ToContainerReachableUrl $coauthPublic).TrimEnd("/")
            $map.SOLAND_ACCOUNT_AUTHORITY_URL = $coauthPublic
            $map.SOLAND_ACCOUNT_AUTHORITY_ENROLLMENT_DID = $CoauthEnrollmentAuthorityDid
            $map.SOLAND_SESSION_GRANT_INTROSPECTION_URL = "$coauthContainer/_arkret/gate/account/session-grants/introspect"
            $map.SOLAND_SESSION_GRANT_INTROSPECTION_BEARER = $CoauthSessionGrantIntrospectionBearer
            $map.SOLAND_OAUTH_CLIENT_ID = $CoauthOAuthClientId
        }
        if ($StaridBaseUrl) {
            $map.SOLAND_DID_RESOLVER_ALLOW_METHODS = "did:webvh,did:key"
            $map.SOLAND_STARID_WEBVH_RESOLVER_URL = Convert-ToContainerReachableUrl $StaridBaseUrl
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
            [Parameter(Mandatory = $true)][string]$BinaryPath,
            [Parameter(Mandatory = $true)][string]$ConfigPath,
            [Parameter(Mandatory = $true)][string]$BaseUrl,
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
            DATABASE_URL = ""
            SOLAND_PUBLIC_BASE_URL = $BaseUrl
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
            SOLAND_CANDIDATE_JOIN_POLICY = "true"
            SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER = $CoauthEmbeddedWebvhRegistrationBearer
        }
        if ($CoauthBaseUrl) {
            $coauthTrimmed = $CoauthBaseUrl.TrimEnd("/")
            $values.SOLAND_ACCOUNT_AUTHORITY_URL = $coauthTrimmed
            $values.SOLAND_ACCOUNT_AUTHORITY_ENROLLMENT_DID = $CoauthEnrollmentAuthorityDid
            $values.SOLAND_SESSION_GRANT_INTROSPECTION_URL = "$coauthTrimmed/_arkret/gate/account/session-grants/introspect"
            $values.SOLAND_SESSION_GRANT_INTROSPECTION_BEARER = $CoauthSessionGrantIntrospectionBearer
            $values.SOLAND_OAUTH_CLIENT_ID = $CoauthOAuthClientId
        }
        if ($StaridBaseUrl) {
            $values.SOLAND_DID_RESOLVER_ALLOW_METHODS = "did:webvh,did:key"
            $values.SOLAND_STARID_WEBVH_RESOLVER_URL = $StaridBaseUrl
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
        return "& {0} --config {1} --no-env-overrides --bind 127.0.0.1:{2}" -f `
            (Quote-PsLiteral $BinaryPath),
            (Quote-PsLiteral $ConfigPath),
            $Port
    }

    # Per-instance tracing files. Windows fully-buffers stdout when
    # `Start-Process -RedirectStandardOutput` may buffer service output on
    # Windows. The `SOLAND_LOG_FILE` path is a second, durable sink soland
    # writes through a non-blocking
    # tracing-appender (see soland/src/main.rs `init_tracing`). This is the
    # file scenarios should `tail -f` when debugging projection / reducer
    # paths against the runner.
    $solandTraceFile = Join-Path $serviceLogDir "soland.trace.log"
    $alphaPeer = ""
    $solandCorsOrigins = @(
        $InksonBaseUrl
        $inksonBetaBaseUrl
    ) | Where-Object { $_ } | Select-Object -Unique
    $solandCorsAllowOrigin = if (@($solandCorsOrigins).Count -gt 0) {
        $solandCorsOrigins -join ","
    } else {
        "http://127.0.0.1"
    }
    if (-not $SolandCommand -and $solandPort -and $SolandRuntime -eq "process") {
        $generatedSolandCommand = $true
        $solandBinary = Resolve-SolandBinary -ExplicitPath $SolandBin -WorkspaceRoot $workspaceRoot
        $alphaPeer = if ($DualSoland) { $solandBetaBaseUrl } else { "" }
        $solandMetricsPort = Get-FreeTcpPort
        $SolandCommand = Build-SolandCommand `
            -BinaryPath $solandBinary `
            -ConfigPath (Join-Path $jointDir "soland.env") `
            -BaseUrl $SolandBaseUrl `
            -ObjectsRoot (Join-Path $jointDir "soland-objects") `
            -StateRoot (Join-Path $jointDir "soland-state") `
            -Port $solandPort `
            -MetricsPort $solandMetricsPort `
            -LogFile $solandTraceFile `
            -CorsAllowOrigin $solandCorsAllowOrigin `
            -KeyStoreMasterKey $SolandKeyStoreMasterKey `
            -NotarySigningKey $SolandNotarySigningKey `
            -FederationPeers $alphaPeer
    }
    if ($SolandCommand) {
        $solandWorkingDirectory = if ($generatedSolandCommand) { $repoRoot } else { Split-Path -Parent $SutManifest }
        $solandName = if ($DualSoland) { "soland-alpha" } else { "soland" }
        $managedServices.Add((Start-ManagedCommand -Name $solandName -Command $SolandCommand -WorkingDirectory $solandWorkingDirectory -LogDirectory $serviceLogDir))
    } elseif ($willStartDockerSoland) {
        $alphaPeer = if ($DualSoland) { $solandBetaBaseUrl } else { "" }
        $solandMetricsPort = Get-FreeTcpPort
        $solandDockerEnv = Build-SolandDockerEnvironment `
            -BaseUrl $SolandBaseUrl `
            -MetricsPort $solandMetricsPort `
            -LogFileName ([System.IO.Path]::GetFileName($solandTraceFile)) `
            -CorsAllowOrigin $solandCorsAllowOrigin `
            -KeyStoreMasterKey $SolandKeyStoreMasterKey `
            -NotarySigningKey $SolandNotarySigningKey `
            -FederationPeers $alphaPeer
        $solandName = if ($DualSoland) { "soland-alpha" } else { "soland" }
        $managedServices.Add((Start-ManagedDockerSoland `
                    -Name $solandName `
                    -Image $SolandImage `
                    -HostPort $solandPort `
                    -ContainerPort $SolandContainerPort `
                    -ObjectsRoot (Join-Path $jointDir "soland-objects") `
                    -StateRoot (Join-Path $jointDir "soland-state") `
                    -LogDirectory $serviceLogDir `
                    -Environment $solandDockerEnv))
    }
    Wait-HttpReady -Url "$($SolandBaseUrl.TrimEnd('/'))/health" -TimeoutSeconds $StartupTimeoutSeconds
    $SolandServiceId = Get-DescribedServiceId -BaseUrl $SolandBaseUrl -ServiceName "soland"

    if ($DualSoland) {
        $solandBetaTraceFile = Join-Path $serviceLogDir "soland-beta.trace.log"
        $solandBetaMetricsPort = Get-FreeTcpPort
        $solandBetaCorsAllowOrigin = $solandCorsAllowOrigin
        if ($SolandRuntime -eq "docker") {
            $solandBetaDockerEnv = Build-SolandDockerEnvironment `
                -BaseUrl $solandBetaBaseUrl `
                -MetricsPort $solandBetaMetricsPort `
                -LogFileName ([System.IO.Path]::GetFileName($solandBetaTraceFile)) `
                -CorsAllowOrigin $solandBetaCorsAllowOrigin `
                -KeyStoreMasterKey $SolandBetaKeyStoreMasterKey `
                -NotarySigningKey $SolandBetaNotarySigningKey `
                -FederationPeers $SolandBaseUrl
            $managedServices.Add((Start-ManagedDockerSoland `
                        -Name "soland-beta" `
                        -Image $SolandImage `
                        -HostPort $solandBetaPort `
                        -ContainerPort $SolandContainerPort `
                        -ObjectsRoot (Join-Path $jointDir "soland-beta-objects") `
                        -StateRoot (Join-Path $jointDir "soland-beta-state") `
                        -LogDirectory $serviceLogDir `
                        -Environment $solandBetaDockerEnv))
        } else {
            $solandBetaCommand = Build-SolandCommand `
                -BinaryPath $solandBinary `
                -ConfigPath (Join-Path $jointDir "soland-beta.env") `
                -BaseUrl $solandBetaBaseUrl `
                -ObjectsRoot (Join-Path $jointDir "soland-beta-objects") `
                -StateRoot (Join-Path $jointDir "soland-beta-state") `
                -Port $solandBetaPort `
                -MetricsPort $solandBetaMetricsPort `
                -LogFile $solandBetaTraceFile `
                -CorsAllowOrigin $solandBetaCorsAllowOrigin `
                -KeyStoreMasterKey $SolandBetaKeyStoreMasterKey `
                -NotarySigningKey $SolandBetaNotarySigningKey `
                -FederationPeers $SolandBaseUrl
            $managedServices.Add((Start-ManagedCommand -Name "soland-beta" -Command $solandBetaCommand -WorkingDirectory $repoRoot -LogDirectory $serviceLogDir))
        }
        Wait-HttpReady -Url "$($solandBetaBaseUrl.TrimEnd('/'))/health" -TimeoutSeconds $StartupTimeoutSeconds
        $SolandBetaServiceId = Get-DescribedServiceId -BaseUrl $solandBetaBaseUrl -ServiceName "soland-beta"
    }

    if ($CoauthCommand) {
        if (-not $CoauthBaseUrl -and -not $CoauthHealthUrl) {
            throw "CoauthCommand requires CoauthBaseUrl or CoauthHealthUrl"
        }
        $coauthWorkingDirectory = if ($StartCoauth) { Join-Path $workspaceRoot "coauth" } else { $workspaceRoot }
        $managedServices.Add((Start-ManagedCommand -Name "coauth" -Command $CoauthCommand -WorkingDirectory $coauthWorkingDirectory -LogDirectory $serviceLogDir))
        $health = if ($CoauthHealthUrl) { $CoauthHealthUrl } else { "$($CoauthBaseUrl.TrimEnd('/'))/health" }
        Wait-HttpReady -Url $health -TimeoutSeconds $StartupTimeoutSeconds
        if ($CoauthBaseUrl) {
            $CoauthServiceId = Get-DescribedServiceId -BaseUrl $CoauthBaseUrl -ServiceName "coauth"
        }
    }
    if ($CoauthSecondaryCommand) {
        $managedServices.Add((Start-ManagedCommand -Name "coauth-secondary" -Command $CoauthSecondaryCommand -WorkingDirectory (Join-Path $workspaceRoot "coauth") -LogDirectory $serviceLogDir))
        Wait-HttpReady -Url "$coauthSecondaryBaseUrl/health" -TimeoutSeconds $StartupTimeoutSeconds
    }

    $inksonService = $null
    $inksonBetaService = $null
    $generatedInksonBetaCommand = $false
    if (-not $SkipInkson -and -not $InksonCommand -and $inksonPort) {
        $InksonCommand = "node {0} {1} {2} 127.0.0.1" -f `
            (Quote-PsLiteral (Join-Path $e2eRoot "scripts\serve-static.mjs")),
            (Quote-PsLiteral $inksonStaticRoot),
            $inksonPort
        $generatedInksonCommand = $true
    }
    if ($InksonCommand) {
        $inksonName = if ($DualSoland) { "inkson-alpha" } else { "inkson" }
        $inksonService = Start-ManagedCommand -Name $inksonName -Command $InksonCommand -WorkingDirectory $InksonRoot -LogDirectory $serviceLogDir
        $managedServices.Add($inksonService)
    }
    if (-not $SkipInkson) {
        Wait-HttpReady -Url $InksonBaseUrl -TimeoutSeconds $StartupTimeoutSeconds
        if ($generatedInksonCommand) {
            Wait-DioxusAppReady -Url $InksonBaseUrl -TimeoutSeconds $StartupTimeoutSeconds
        }
    }
    if (-not $SkipInkson -and $DualSoland -and $inksonBetaBaseUrl -and $inksonBetaBaseUrl -ne $InksonBaseUrl) {
        if (-not $InksonBetaCommand -and $inksonBetaPort) {
            $InksonBetaCommand = "node {0} {1} {2} 127.0.0.1" -f `
                (Quote-PsLiteral (Join-Path $e2eRoot "scripts\serve-static.mjs")),
                (Quote-PsLiteral $inksonStaticRoot),
                $inksonBetaPort
            $generatedInksonBetaCommand = $true
        }
        if ($InksonBetaCommand) {
            $inksonBetaService = Start-ManagedCommand -Name "inkson-beta" -Command $InksonBetaCommand -WorkingDirectory $InksonRoot -LogDirectory $serviceLogDir
            $managedServices.Add($inksonBetaService)
        }
        Wait-HttpReady -Url $inksonBetaBaseUrl -TimeoutSeconds $StartupTimeoutSeconds
        if ($generatedInksonBetaCommand) {
            Wait-DioxusAppReady -Url $inksonBetaBaseUrl -TimeoutSeconds $StartupTimeoutSeconds
        }
    }

    if (-not $SkipNpmInstall -and -not (Test-Path (Join-Path $e2eRoot "node_modules"))) {
        Push-Location $e2eRoot
        try {
            & npm install
            if ($LASTEXITCODE -ne 0) {
                throw "npm install failed"
            }
        }
        finally {
            Pop-Location
        }
    }
    $needsBundledChromium = ($playwrightProjects -contains "chromium") -or ($playwrightProjects -contains "joint-inkson")
    if (-not $SkipBrowserInstall -and $needsBundledChromium) {
        Push-Location $e2eRoot
        try {
            $playwrightCli = Resolve-PlaywrightCliInvocation -E2eRoot $e2eRoot
            if (-not $playwrightCli) {
                throw "Playwright CLI is required"
            }
            $browserInstallArgs = @($playwrightCli.Arguments) + @("install", "chromium")
            & $playwrightCli.FilePath @browserInstallArgs
            if ($LASTEXITCODE -ne 0) {
                throw "playwright browser install failed"
            }
        }
        finally {
            Pop-Location
        }
    }

    if ($StaridBaseUrl -and -not $StaridServiceId) {
        $StaridServiceId = Get-DescribedServiceId -BaseUrl $StaridBaseUrl -ServiceName "starid"
    }
    if ($CoauthBaseUrl -and -not $CoauthServiceId) {
        $CoauthServiceId = Get-DescribedServiceId -BaseUrl $CoauthBaseUrl -ServiceName "coauth"
    }

    # Point the wire helper at the prebuilt binary so no test pays `cargo run`.
    # Only when it actually exists: falling back to `cargo run` is slow but
    # correct, whereas exec'ing a missing path fails every canonical assertion.
    if (-not $env:COTEST_WIRE_BIN) {
        $preparedWireBinary = Join-Path $repoRoot "target\debug\cotest-wire.exe"
        if (Test-Path -LiteralPath $preparedWireBinary) {
            $env:COTEST_WIRE_BIN = $preparedWireBinary
        }
    }
    $env:COTEST_JOINT_RUN_DIR = $jointDir
    $env:COTEST_UI_SCREENSHOT_DIR = $screenshotDir
    $env:COTEST_UI_VISUAL_BASELINE_DIR = $visualBaselineDir
    $env:COTEST_SOLAND_BASE_URL = $SolandBaseUrl
    $env:COTEST_SOLAND_SERVICE_ID = $SolandServiceId
    $env:COTEST_EMBEDDED_WEBVH_REGISTRATION_BEARER = $CoauthEmbeddedWebvhRegistrationBearer
    if ($SolandNotarySigningKey) {
        # The peer-surface fixtures must sign as the configured service
        # identity. A deterministic development key is only correct when the
        # managed Soland instance also uses that fallback.
        $env:COTEST_SOLAND_SERVICE_SIGNING_KEY = $SolandNotarySigningKey
    } else {
        Remove-Item Env:COTEST_SOLAND_SERVICE_SIGNING_KEY -ErrorAction SilentlyContinue
    }
    if ($InksonBaseUrl) {
        $env:COTEST_INKSON_BASE_URL = $InksonBaseUrl
    } else {
        Remove-Item Env:COTEST_INKSON_BASE_URL -ErrorAction SilentlyContinue
    }
    if ($DualSoland) {
        $env:COTEST_SOLAND_ALPHA_BASE_URL = $SolandBaseUrl
        $env:COTEST_SOLAND_ALPHA_SERVICE_ID = $SolandServiceId
        $env:COTEST_SOLAND_BETA_BASE_URL = $solandBetaBaseUrl
        $env:COTEST_SOLAND_BETA_SERVICE_ID = $SolandBetaServiceId
        if ($SolandBetaNotarySigningKey) {
            $env:COTEST_SOLAND_BETA_SERVICE_SIGNING_KEY = $SolandBetaNotarySigningKey
        } else {
            Remove-Item Env:COTEST_SOLAND_BETA_SERVICE_SIGNING_KEY -ErrorAction SilentlyContinue
        }
        $env:COTEST_REQUIRE_DUAL_SOLAND = "1"
        if ($InksonBaseUrl) {
            $env:COTEST_INKSON_ALPHA_BASE_URL = $InksonBaseUrl
        } else {
            Remove-Item Env:COTEST_INKSON_ALPHA_BASE_URL -ErrorAction SilentlyContinue
        }
        if ($inksonBetaBaseUrl) {
            $env:COTEST_INKSON_BETA_BASE_URL = $inksonBetaBaseUrl
        } else {
            Remove-Item Env:COTEST_INKSON_BETA_BASE_URL -ErrorAction SilentlyContinue
        }
    } else {
        Remove-Item Env:COTEST_SOLAND_ALPHA_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_SOLAND_ALPHA_SERVICE_ID -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_SOLAND_BETA_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_SOLAND_BETA_SERVICE_ID -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_SOLAND_BETA_SERVICE_SIGNING_KEY -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_REQUIRE_DUAL_SOLAND -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_INKSON_ALPHA_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_INKSON_BETA_BASE_URL -ErrorAction SilentlyContinue
    }
    if ($CoauthBaseUrl) {
        Assert-CoauthDpopGrantSeamReady -BaseUrl $CoauthBaseUrl
        $env:COTEST_COAUTH_BASE_URL = $CoauthBaseUrl.TrimEnd("/")
        $env:COTEST_COAUTH_SERVICE_ID = $CoauthServiceId
        # The OAuth client_id soland is configured to advertise (see
        # SOLAND_OAUTH_CLIENT_ID in the generated soland config). Surfaced to e2e so
        # oidc-login-chain.spec.ts can assert /_arkret/describe advertises it.
        $env:COTEST_OIDC_CLIENT_ID = $CoauthOAuthClientId
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
        Remove-Item Env:COTEST_OIDC_CLIENT_ID -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_REQUIRE_JOINT_STACK -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_REAL_OIDC_LOGIN -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_COAUTH_SECONDARY_BASE_URL -ErrorAction SilentlyContinue
    }
    if ($StaridBaseUrl) {
        $env:COTEST_STARID_BASE_URL = $StaridBaseUrl.TrimEnd("/")
        $env:COTEST_STARID_SERVICE_ID = $StaridServiceId
    } else {
        Remove-Item Env:COTEST_STARID_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_STARID_SERVICE_ID -ErrorAction SilentlyContinue
    }
    if ($TeabayBaseUrl) {
        $env:COTEST_TEABAY_BASE_URL = $TeabayBaseUrl.TrimEnd("/")
        $env:COTEST_TEABAY_SERVICE_ID = $TeabayServiceId
    } else {
        Remove-Item Env:COTEST_TEABAY_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_TEABAY_SERVICE_ID -ErrorAction SilentlyContinue
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
    if ($mockPolicyServerBaseUrl) {
        $env:COTEST_MOCK_POLICY_SERVER_BASE_URL = $mockPolicyServerBaseUrl
        if ($MockPolicyServerDid) {
            $env:COTEST_MOCK_POLICY_SERVER_DID = $MockPolicyServerDid
        } else {
            Remove-Item Env:COTEST_MOCK_POLICY_SERVER_DID -ErrorAction SilentlyContinue
        }
    } else {
        Remove-Item Env:COTEST_MOCK_POLICY_SERVER_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_MOCK_POLICY_SERVER_DID -ErrorAction SilentlyContinue
    }
    if ($mockPushGatewayBaseUrl) {
        $env:COTEST_MOCK_PUSH_GATEWAY_BASE_URL = $mockPushGatewayBaseUrl
    } else {
        Remove-Item Env:COTEST_MOCK_PUSH_GATEWAY_BASE_URL -ErrorAction SilentlyContinue
    }
    if ($mockAppletRegistryBaseUrl) {
        $env:COTEST_MOCK_APPLET_REGISTRY_BASE_URL = $mockAppletRegistryBaseUrl
        if ($MockAppletRegistryDid) {
            $env:COTEST_MOCK_APPLET_REGISTRY_DID = $MockAppletRegistryDid
        } else {
            Remove-Item Env:COTEST_MOCK_APPLET_REGISTRY_DID -ErrorAction SilentlyContinue
        }
    } else {
        Remove-Item Env:COTEST_MOCK_APPLET_REGISTRY_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_MOCK_APPLET_REGISTRY_DID -ErrorAction SilentlyContinue
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
        $env:COTEST_MOCK_CLAIM_ISSUER_DID = $MockClaimIssuerDid
    } else {
        Remove-Item Env:COTEST_MOCK_CLAIM_ISSUER_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_MOCK_CLAIM_ISSUER_DID -ErrorAction SilentlyContinue
    }
    if ($mockChallengeProviderBaseUrl) {
        $env:COTEST_MOCK_CHALLENGE_PROVIDER_BASE_URL = $mockChallengeProviderBaseUrl
        $env:COTEST_MOCK_CHALLENGE_PROVIDER_DID = $MockChallengeProviderDid
    } else {
        Remove-Item Env:COTEST_MOCK_CHALLENGE_PROVIDER_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_MOCK_CHALLENGE_PROVIDER_DID -ErrorAction SilentlyContinue
    }

    if (-not $RuntimeManifestPath) {
        $RuntimeManifestPath = Join-Path $jointDir "runtime-manifest.json"
    } else {
        $RuntimeManifestPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($RuntimeManifestPath)
    }
    $alphaManagedServiceName = if ($DualSoland) { "soland-alpha" } else { "soland" }
    $alphaManagedService = @($managedServices | Where-Object { $_.Name -eq $alphaManagedServiceName }) | Select-Object -First 1
    $betaManagedService = @($managedServices | Where-Object { $_.Name -eq "soland-beta" }) | Select-Object -First 1
    $alphaRuntimeInstance = if ($alphaManagedService -and $alphaManagedService.Kind -eq "process") {
        "process:$($alphaManagedService.Process.Id)"
    } elseif ($alphaManagedService -and $alphaManagedService.Kind -eq "docker") {
        "docker:$($alphaManagedService.ContainerName)"
    } else {
        $null
    }
    $betaRuntimeInstance = if ($betaManagedService -and $betaManagedService.Kind -eq "process") {
        "process:$($betaManagedService.Process.Id)"
    } elseif ($betaManagedService -and $betaManagedService.Kind -eq "docker") {
        "docker:$($betaManagedService.ContainerName)"
    } else {
        $null
    }
    $alphaStateRoot = Join-Path $jointDir "soland-state"
    $alphaObjectRoot = Join-Path $jointDir "soland-objects"
    $betaStateRoot = Join-Path $jointDir "soland-beta-state"
    $betaObjectRoot = Join-Path $jointDir "soland-beta-objects"
    $runtimeManifestParent = Split-Path -Parent $RuntimeManifestPath
    $null = New-Item -ItemType Directory -Force -Path $runtimeManifestParent
    $runtimeManifest = [ordered]@{
        schema_version = "v1"
        generated_at = (Get-Date).ToUniversalTime().ToString("o")
        topology = if ($DualSoland) { "federated" } else { "single" }
        soland_runtime = $startedSolandRuntime
        account_authority_mode = if ($DualSoland -and $CoauthBaseUrl) { "shared-external-authority" } elseif ($CoauthBaseUrl) { "single" } else { "none" }
        services = [ordered]@{
            alpha = [ordered]@{
                soland_base_url = $SolandBaseUrl
                soland_service_id = $SolandServiceId
                runtime_instance = $alphaRuntimeInstance
                inkson_base_url = $InksonBaseUrl
                state_root = $alphaStateRoot
                object_root = $alphaObjectRoot
                federation_peer = $alphaPeer
            }
            beta = if ($DualSoland) {
                [ordered]@{
                    soland_base_url = $solandBetaBaseUrl
                    soland_service_id = $SolandBetaServiceId
                    runtime_instance = $betaRuntimeInstance
                    inkson_base_url = $inksonBetaBaseUrl
                    state_root = $betaStateRoot
                    object_root = $betaObjectRoot
                    federation_peer = $SolandBaseUrl
                }
            } else {
                $null
            }
            coauth = if ($CoauthBaseUrl) {
                [ordered]@{
                    base_url = $CoauthBaseUrl
                    service_id = $CoauthServiceId
                }
            } else {
                $null
            }
            savfox = if ($StartSavfox) {
                $savfoxManagedService = @($managedServices | Where-Object { $_.Name -eq "savfox" }) | Select-Object -First 1
                $savfoxUnaddressedManagedService = @($managedServices | Where-Object { $_.Name -eq "savfox-unaddressed" }) | Select-Object -First 1
                [ordered]@{
                    base_url = $SavfoxBaseUrl
                    runtime_instance = if ($savfoxManagedService) { "process:$($savfoxManagedService.Process.Id)" } else { $null }
                    model_receipts = $savfoxModelReceipts
                    unaddressed_probe = [ordered]@{
                        base_url = $savfoxUnaddressedBaseUrl
                        runtime_instance = if ($savfoxUnaddressedManagedService) { "process:$($savfoxUnaddressedManagedService.Process.Id)" } else { $null }
                        model_receipts = $savfoxUnaddressedModelReceipts
                    }
                }
            } else {
                $null
            }
        }
        isolation = [ordered]@{
            distinct_principal_server_processes = [bool]($DualSoland -and $alphaRuntimeInstance -and $betaRuntimeInstance -and $alphaRuntimeInstance -ne $betaRuntimeInstance)
            distinct_service_identities = [bool]($DualSoland -and $SolandServiceId -and $SolandBetaServiceId -and $SolandServiceId -ne $SolandBetaServiceId)
            distinct_state_roots = [bool]($DualSoland -and $alphaStateRoot -ne $betaStateRoot)
            distinct_object_roots = [bool]($DualSoland -and $alphaObjectRoot -ne $betaObjectRoot)
            distinct_browser_origins = [bool]($DualSoland -and $InksonBaseUrl -and $inksonBetaBaseUrl -and $InksonBaseUrl -ne $inksonBetaBaseUrl)
            explicit_federation_peer_links = [bool]($DualSoland -and $alphaPeer -eq $solandBetaBaseUrl)
        }
        artifacts = [ordered]@{
            root = $jointDir
            services = $serviceLogDir
            screenshots = $screenshotDir
        }
    }
    $runtimeManifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $RuntimeManifestPath -Encoding UTF8
    $env:COTEST_RUNTIME_MANIFEST = $RuntimeManifestPath

    if ($ExternalDriverScript) {
        $playwrightStdout = Join-Path $jointDir "external-driver.stdout.log"
        $playwrightStderr = Join-Path $jointDir "external-driver.stderr.log"
        $previousErrorActionPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = "Continue"
            $driverOutput = & $ExternalDriverScript @ExternalDriverArgument 2>&1
            $exitCode = $LASTEXITCODE
            $driverOutput | Set-Content -LiteralPath $playwrightStdout -Encoding UTF8
            "" | Set-Content -LiteralPath $playwrightStderr -Encoding UTF8
            $driverOutput | ForEach-Object { Write-Host $_ }
        }
        finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
    } else {
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
        if (-not ($effectiveGrep -and $effectiveGrep.Contains("@platform-live"))) {
            $playwrightArgs += @("--grep-invert", "@platform-live")
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
        try {
            $previousErrorActionPreference = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            $playwrightOutput = & $playwrightCommand @playwrightCommandArgs 2>&1
            $exitCode = $LASTEXITCODE
            $playwrightOutput | Set-Content -Path $playwrightStdout -Encoding UTF8
            "" | Set-Content -Path $playwrightStderr -Encoding UTF8
            $playwrightOutput | ForEach-Object { Write-Host $_ }
        }
        finally {
            if ($null -ne $previousErrorActionPreference) {
                $ErrorActionPreference = $previousErrorActionPreference
            }
            Pop-Location
        }
    }
}
finally {
    $managedServiceFailures = @(Get-ManagedServiceFailures -Services $managedServices)
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
    if (-not $KeepServices) {
        for ($index = $managedServices.Count - 1; $index -ge 0; $index--) {
            Stop-ManagedCommand -Service $managedServices[$index]
        }
        if ($ephemeralPostgres) {
            Stop-EphemeralPostgres -ContainerName $ephemeralPostgres.ContainerName
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
    $failureLines += "| Fingerprint | Count | Scenario | Endpoint | Wire code | Assertion site |"
    $failureLines += "| --- | --- | --- | --- | --- | --- |"
    foreach ($group in $distinctFingerprints) {
        $sample = $group.Group[0]
        $failureLines += "| $($sample.fingerprint) | $($group.Count) | $($sample.scenario) | $($sample.endpoint) | $($sample.wire_code) | $($sample.assertion_site) |"
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
        $secretScanRoots.Add($directory.FullName)
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
# Everything the joint runner collects here is log / telemetry / crash
# material, where a credential is as much a leak as a seed. Nothing in this set
# is a durable protocol store, so all roots take the strict class.
$secretScanRootDescriptors = @(
    $secretScanRoots.ToArray() | ForEach-Object {
        [pscustomobject]@{ path = $_; artifact_class = "log_or_telemetry" }
    }
)
$secretLeaks = @(Find-SecretLeaks -ScanRoots $secretScanRootDescriptors)
$secretScanCounts = Get-SecretScanSummary -Leaks $secretLeaks
# Playwright writes the full received object into stdout and error-context.md
# whenever an object assertion fails, so a secret-bearing response reaches these
# artifacts without any test asking for it. Scan first so the report keeps the
# file, line, pattern and category, then redact the artifacts themselves so the
# retained copies carry no plaintext.
$secretRedaction = Protect-SecretBearingArtifacts -Leaks $secretLeaks
$secretScanFileCount = 0
foreach ($root in $secretScanRoots) {
    if ((Get-Item -LiteralPath $root).PSIsContainer) {
        $secretScanFileCount += @(Get-ChildItem -LiteralPath $root -Recurse -File).Count
    } else {
        $secretScanFileCount += 1
    }
}
$secretScan = [pscustomobject]@{
    generated_at = (Get-Date).ToString("o")
    status = if ($secretScanSelfTestStatus -eq "passed" -and $secretScanCounts.failing -eq 0) {
        "passed"
    } else {
        "failed"
    }
    self_test = $secretScanSelfTestStatus
    scanned_roots = $secretScanRootDescriptors
    scanned_files = $secretScanFileCount
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
    "- findings: $($secretScan.counts.findings)",
    "- failing: $($secretScan.counts.failing)",
    "- allowed_by_artifact_class: $($secretScan.counts.allowed_by_artifact_class)",
    "- recovery_private_material: $($secretScan.counts.recovery_private_material)",
    "- credential_exposure: $($secretScan.counts.credential_exposure)",
    "- redacted_files: $(@($secretScan.redaction.redacted_files).Count)",
    ""
)
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
    status = if ($exitCode -eq 0) { "success" } else { "failure" }
    run_profile = if ($RunProfile) { $RunProfile } else { "custom" }
    playwright_projects = $playwrightProjects -join ","
    started_at = $startedAt.ToString("o")
    finished_at = $finishedAt.ToString("o")
    duration_seconds = [Math]::Round(($finishedAt - $startedAt).TotalSeconds, 2)
    exit_code = $exitCode
    soland_runtime = $startedSolandRuntime
    soland_image = if ($startedSolandRuntime -eq "docker") { $SolandImage } else { $null }
    soland_base_url = $SolandBaseUrl
    soland_service_id = $SolandServiceId
    soland_beta_base_url = $solandBetaBaseUrl
    soland_beta_service_id = if ($DualSoland) { $SolandBetaServiceId } else { $null }
    dual_soland = [bool]$DualSoland
    inkson_alpha_base_url = if ($DualSoland) { $InksonBaseUrl } else { $null }
    inkson_beta_base_url = if ($DualSoland) { $inksonBetaBaseUrl } else { $null }
    mock_idp_base_url = $mockIdpBaseUrl
    mock_email_base_url = $mockEmailBaseUrl
    mock_witness_base_url = $mockWitnessBaseUrl
    mock_witness_did = if ($mockWitnessBaseUrl) { $MockWitnessDid } else { $null }
    mock_witness_quorum_base_urls = if ($mockWitnessBaseUrl) { $mockWitnessQuorumBaseUrls } else { @() }
    mock_witness_quorum_dids = if ($mockWitnessBaseUrl) { $mockWitnessQuorumDids } else { @() }
    mock_mimi_facade_base_url = $mockMimiFacadeBaseUrl
    mock_mimi_facade_did = if ($mockMimiFacadeBaseUrl) { $MockMimiFacadeDid } else { $null }
    inkson_base_url = $InksonBaseUrl
    coauth_base_url = if ($CoauthBaseUrl) { $CoauthBaseUrl } else { $null }
    coauth_secondary_base_url = $coauthSecondaryBaseUrl
    dual_coauth = [bool]$DualCoauth
    coauth_service_id = if ($CoauthBaseUrl) { $CoauthServiceId } else { $null }
    coauth_config = $coauthConfigPath
    coauth_postgres_container = if ($ephemeralPostgres) { $ephemeralPostgres.ContainerName } else { $null }
    starid_base_url = if ($StaridBaseUrl) { $StaridBaseUrl } else { $null }
    starid_service_id = if ($StaridBaseUrl) { $StaridServiceId } else { $null }
    teabay_base_url = if ($TeabayBaseUrl) { $TeabayBaseUrl } else { $null }
    teabay_service_id = if ($TeabayBaseUrl) { $TeabayServiceId } else { $null }
    teabay_database_url = if ($TeabayBaseUrl) { $TeabayDatabaseUrl } else { $null }
    coauth_oauth_introspection_url = if ($CoauthBaseUrl) { "$($CoauthBaseUrl.TrimEnd('/'))/oauth/introspect" } else { $null }
    coauth_session_grant_introspection_url = if ($CoauthBaseUrl) { "$($CoauthBaseUrl.TrimEnd('/'))/_arkret/gate/account/session-grants/introspect" } else { $null }
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
# joint e2e summary

- status: $($summary.status)
- run_profile: $($summary.run_profile)
- playwright_projects: $($summary.playwright_projects)
- started_at: $($summary.started_at)
- finished_at: $($summary.finished_at)
- duration_seconds: $($summary.duration_seconds)
- exit_code: $($summary.exit_code)
- soland_runtime: $($summary.soland_runtime)
- soland_image: $($summary.soland_image)
- soland_base_url: $($summary.soland_base_url)
- soland_service_id: $($summary.soland_service_id)
- soland_beta_base_url: $($summary.soland_beta_base_url)
- soland_beta_service_id: $($summary.soland_beta_service_id)
- dual_soland: $($summary.dual_soland)
- inkson_alpha_base_url: $($summary.inkson_alpha_base_url)
- inkson_beta_base_url: $($summary.inkson_beta_base_url)
- mock_idp_base_url: $($summary.mock_idp_base_url)
- mock_email_base_url: $($summary.mock_email_base_url)
- mock_witness_base_url: $($summary.mock_witness_base_url)
- mock_witness_did: $($summary.mock_witness_did)
- mock_witness_quorum_base_urls: $($mockWitnessQuorumBaseUrls -join ",")
- mock_witness_quorum_dids: $($mockWitnessQuorumDids -join ",")
- mock_mimi_facade_base_url: $($summary.mock_mimi_facade_base_url)
- mock_mimi_facade_did: $($summary.mock_mimi_facade_did)
- inkson_base_url: $($summary.inkson_base_url)
- coauth_base_url: $($summary.coauth_base_url)
- coauth_service_id: $($summary.coauth_service_id)
- coauth_config: $($summary.coauth_config)
- coauth_oauth_introspection_url: $($summary.coauth_oauth_introspection_url)
- coauth_session_grant_introspection_url: $($summary.coauth_session_grant_introspection_url)
- starid_base_url: $($summary.starid_base_url)
- starid_service_id: $($summary.starid_service_id)
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
    -ExternalDriverScript $ExternalDriverScript `
    -PreflightOnly ([bool]$PreflightOnly)
if ($isStandaloneJointSuite) {
    Publish-ArtifactMirror `
        -SourceDirectory $jointDir `
        -OutputRoot $OutputRoot `
        -Channel "joint-e2e"
}

Write-Host ""
Write-Host "Joint E2E Summary"
Write-Host "  status      : $($summary.status)"
Write-Host "  profile     : $($summary.run_profile)"
Write-Host "  projects    : $($summary.playwright_projects)"
Write-Host "  soland rt   : $($summary.soland_runtime)"
if ($summary.soland_image) {
    Write-Host "  soland image: $($summary.soland_image)"
}
Write-Host "  soland      : $SolandBaseUrl"
if ($DualSoland) {
    Write-Host "  soland-beta : $solandBetaBaseUrl"
}
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
if ($mockMimiFacadeBaseUrl) {
    Write-Host "  mock-mimi-facade: $mockMimiFacadeBaseUrl ($MockMimiFacadeDid)"
}
if ($InksonBaseUrl) {
    Write-Host "  inkson      : $InksonBaseUrl"
}
if ($DualSoland -and $inksonBetaBaseUrl) {
    Write-Host "  inkson-beta : $inksonBetaBaseUrl"
}
if ($CoauthBaseUrl) {
    Write-Host "  coauth      : $CoauthBaseUrl"
}
if ($coauthSecondaryBaseUrl) {
    Write-Host "  coauth-beta : $coauthSecondaryBaseUrl"
}
if ($StaridBaseUrl) {
    Write-Host "  starid      : $StaridBaseUrl"
}
if ($TeabayBaseUrl) {
    Write-Host "  teabay      : $TeabayBaseUrl"
}
Write-Host "  screenshots : $screenshotDir"
Write-Host "  visual base : $visualBaselineDir"
Write-Host "  report      : $summaryMd"
Write-Host "  secret scan : $($summary.secret_scan_status) ($secretScanMd)"
if ($isStandaloneJointSuite) {
    Write-Host "  latest      : $(Join-Path $OutputRoot 'latest\joint-e2e')"
}

$jointRunnerLock.Dispose()
exit $exitCode
