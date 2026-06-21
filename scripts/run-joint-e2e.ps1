<#
.SYNOPSIS
    Drives a joint-services Playwright run for the cotest harness.

.DESCRIPTION
    Supports two run profiles via -RunProfile:

    joint-smoke (PR gate)
      - Runs only describe blocks tagged @fully-implemented.
      - Skips the ~248 placeholder fixme tests so the PR gate stays under
        ~5 min on the joint harness.
      - An explicit -Grep argument fully overrides the smoke inclusion filter.

    joint-full (nightly / on-demand)
      - Unfiltered: runs every spec discovered by Playwright. The placeholder
        fixme tests are expected; they exit as skipped via test.fixme().

    Both profiles share the same service-startup, preflight, and reporting
    code paths. Only the Playwright invocation step branches on the profile.
#>
[CmdletBinding()]
param(
    [string]$OutputRoot,
    [string]$SutManifest,
    [string]$YougenRoot,
    [string]$SolandBaseUrl,
    [string]$YougenBaseUrl,
    [string]$YougenBetaBaseUrl,
    [string]$CoauthBaseUrl,
    [string]$SolandCommand,
    [ValidateSet("process", "docker")]
    [string]$SolandRuntime = "process",
    [string]$SolandImage = "cotest-soland:latest",
    [int]$SolandContainerPort = 8008,
    [switch]$BuildSolandImage,
    [string[]]$DockerCacheFrom = @(),
    [string]$DockerCacheTo,
    [switch]$DockerPull,
    [switch]$DockerNoCache,
    [string]$YougenCommand,
    [string]$YougenBetaCommand,
    [switch]$SkipYougen,
    [string]$CoauthCommand,
    [string]$CoauthHealthUrl,
    [switch]$StartCoauth,
    [string]$CoauthBin,
    [string]$CoauthPostgresImage = "postgres:16-alpine",
    [switch]$StartStarid,
    [string]$StaridBin,
    [string]$StaridBaseUrl,
    [string]$StaridServiceDid = "did:web:starid.joint-e2e.local",
    [switch]$StartTeabay,
    [string]$TeabayBin,
    [string]$TeabayBaseUrl,
    [string]$TeabayDatabaseUrl,
    [string]$TeabayServiceDid = "did:web:teabay.joint-e2e.local",
    [string]$SolandServiceDid = "did:web:soland.joint-e2e.local",
    [string]$CoauthServiceDid = "did:web:coauth.joint-e2e.local",
    [string]$CoauthOAuthIntrospectionBearer = "joint-e2e-oauth-introspection",
    [string]$CoauthSessionGrantIntrospectionBearer = "joint-e2e-session-grant-introspection",
    [string]$CoauthEmbeddedWebvhRegistrationBearer = "joint-e2e-webvh-registration",
    # OAuth `client_id` soland advertises in `/_cokret/describe.auth_metadata.methods[].client_id`
    # (soland config `oidc_client_id`). MUST match a client registered at coauth; the joint
    # coauth config (coauth/config.dev.yaml) seeds the "Yougen Dev" client under this ULID.
    # Without it soland advertises no client_id and the browser OIDC bridge gets
    # `could not find client` from coauth's /authorize. See cotest oidc-login-chain.spec.ts.
    [string]$CoauthOAuthClientId = "01GFWR28C4KNE04WG3HKXB7C9R",
    [int]$StartupTimeoutSeconds = 240,
    [switch]$SkipNpmInstall,
    [switch]$SkipBrowserInstall,
    [switch]$KeepServices,
    [switch]$SkipPreflight,
    [switch]$DualSoland,
    [string]$SolandBetaServiceDid = "did:web:soland-beta.joint-e2e.local",
    [switch]$StartMockIdp,
    [switch]$StartMockEmail,
    [switch]$StartMockWitness,
    [switch]$StartMockAuditAgent,
    [switch]$StartMockPolicyServer,
    [string]$MockPolicyServerDid,
    [switch]$StartMockPushGateway,
    [string]$MockPushGatewayIss,
    [switch]$StartMockAppletRegistry,
    [string]$MockAppletRegistryDid,
    [switch]$StartMockTspEndpoint,
    [string]$MockTspEndpointVid,
    [switch]$StartMockMimiFacade,
    [string]$MockMimiFacadeDid = "did:web:mimi-facade.joint-e2e.local",
    [switch]$StartMocks,
    [string]$MockWitnessDid = "did:web:witness.joint-e2e.local",
    [string[]]$MockWitnessExtraDids = @(),
    [string]$MockAuditAgentDid,
    [ValidateSet("joint-smoke", "joint-full")]
    [string]$RunProfile,
    [string]$PlaywrightProject = "chrome",
    [string]$Grep
)

if ($StartMocks) {
    $StartMockIdp = $true
    $StartMockEmail = $true
    $StartMockWitness = $true
    $StartMockAuditAgent = $true
    $StartMockPolicyServer = $true
    $StartMockPushGateway = $true
    $StartMockAppletRegistry = $true
    $StartMockTspEndpoint = $true
    $StartMockMimiFacade = $true
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
            (Join-Path $buildWorkspaceRoot "cokret-rust-sdk"),
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
        [bool]$WillStartDefaultSoland = $false,
        [ValidateSet("process", "docker")][string]$SolandRuntime = "process",
        [string]$SolandImage,
        [bool]$WillStartDockerSoland = $false,
        [string]$YougenBaseUrl,
        [string]$YougenCommand,
        [bool]$WillStartDefaultYougen = $false,
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

    if ($npx) {
        Push-Location $E2eRoot
        try {
            $playwrightVersionOutput = Invoke-NativeCapture -FilePath $npx -Arguments @("playwright", "--version")
            $playwrightVersionExitCode = $LASTEXITCODE
            $playwrightVersion = $playwrightVersionOutput -join "`n"
            if ($playwrightVersionExitCode -eq 0) {
                Add-PreflightResult $results "playwright package" "pass" $playwrightVersion
            } else {
                Add-PreflightResult $results "playwright package" "fail" $playwrightVersion
            }

            $listArgs = @("playwright", "test", "--config", "playwright.config.ts", "--list")
            foreach ($project in $PlaywrightProjects) {
                $listArgs += @("--project", $project)
            }
            $listCommandOutput = Invoke-NativeCapture -FilePath $npx -Arguments $listArgs
            $listExitCode = $LASTEXITCODE
            $listOutput = $listCommandOutput -join "`n"
            if ($listExitCode -eq 0) {
                Add-PreflightResult $results "playwright projects" "pass" ($PlaywrightProjects -join ",")
            } else {
                Add-PreflightResult $results "playwright projects" "fail" $listOutput
            }

            $browserListOutput = Invoke-NativeCapture -FilePath $npx -Arguments @("playwright", "install", "--list")
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
    }

    if ($WillStartDefaultSoland -or (-not $SolandBaseUrl -and -not $SolandCommand)) {
        if ($SolandRuntime -eq "docker") {
            Add-PreflightResult $results "soland runtime" "pass" "docker"
        } else {
            $cargo = Find-CommandPath @("cargo.exe", "cargo")
            if ($cargo) {
                $version = (& $cargo --version 2>&1) -join "`n"
                Add-PreflightResult $results "cargo" "pass" "$cargo $version"
            } else {
                Add-PreflightResult $results "cargo" "fail" "cargo is required to start the default soland command"
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

    if ($WillStartDefaultYougen -or (-not $YougenBaseUrl -and -not $YougenCommand)) {
        $dx = Find-CommandPath @("dx.exe", "dx")
        if ($dx) {
            $version = (& $dx --version 2>&1) -join "`n"
            Add-PreflightResult $results "dioxus cli" "pass" "$dx $version"
        } else {
            Add-PreflightResult $results "dioxus cli" "fail" "dx is required to start the default yougen web server"
        }
    }

    if ($StartStarid) {
        try {
            $staridBinary = Resolve-StaridBinary -ExplicitPath $StaridBin -WorkspaceRoot $WorkspaceRoot
            Add-PreflightResult $results "starid binary" "pass" $staridBinary
        } catch {
            Add-PreflightResult $results "starid binary" "fail" $_.Exception.Message
        }
    }

    if ($StartTeabay) {
        try {
            $teabayBinary = Resolve-TeabayBinary -ExplicitPath $TeabayBin -WorkspaceRoot $WorkspaceRoot
            Add-PreflightResult $results "teabay binary" "pass" $teabayBinary
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
        } catch {
            Add-PreflightResult $results "coauth binary" "fail" $_.Exception.Message
        }

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
    $builder.Host = "host.docker.internal"
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
        "-e", "POSTGRES_USER=cokret",
        "-e", "POSTGRES_PASSWORD=cokret",
        "-e", "POSTGRES_DB=cokret",
        "-p", "127.0.0.1:$port`:5432",
        $Image
    )
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to start PostgreSQL container: $($runOutput -join "`n")"
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastError = $null
    while ((Get-Date) -lt $deadline) {
        $readyOutput = Invoke-NativeCapture -FilePath "docker" -Arguments @("exec", $containerName, "pg_isready", "-U", "cokret", "-d", "cokret")
        if ($LASTEXITCODE -eq 0) {
            return [pscustomobject]@{
                ContainerName = $containerName
                HostPort = $port
                Url = "postgresql://cokret:cokret@127.0.0.1:$port/cokret"
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
        [Parameter(Mandatory = $true)][string]$SolandBaseUrl,
        [Parameter(Mandatory = $true)][string]$SolandServiceDid,
        [Parameter(Mandatory = $true)][string]$CoauthServiceDid,
        [Parameter(Mandatory = $true)][string]$OAuthIntrospectionBearer,
        [Parameter(Mandatory = $true)][string]$SessionGrantIntrospectionBearer,
        [Parameter(Mandatory = $true)][string]$EmbeddedWebvhRegistrationBearer,
        [string]$MockEmailBaseUrl
    )

    $rawConfig = Join-Path $JointDir "coauth.raw.yaml"
    $configPath = Join-Path $JointDir "coauth.yaml"
    $generateLog = Join-Path $JointDir "coauth-config-generate.log"
    $generateOutput = & $CoauthBinary config generate 2>"$generateLog"
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
        "--soland-base-url", $SolandBaseUrl,
        "--soland-service-did", $SolandServiceDid,
        "--coauth-service-did", $CoauthServiceDid,
        "--oauth-introspection-bearer", $OAuthIntrospectionBearer,
        "--session-grant-introspection-bearer", $SessionGrantIntrospectionBearer,
        "--embedded-webvh-registration-bearer", $EmbeddedWebvhRegistrationBearer
    )
    if ($MockEmailBaseUrl) {
        $patchArgs += @("--mock-email-base-url", $MockEmailBaseUrl)
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
        [Parameter(Mandatory = $true)][string]$LogDirectory
    )

    $migrateLog = Join-Path $LogDirectory "coauth-migrate.log"
    $migrateOutput = & $CoauthBinary database migrate -c $ConfigPath 2>&1
    $migrateOutput | Set-Content -Path $migrateLog -Encoding UTF8
    if ($LASTEXITCODE -ne 0) {
        throw "coauth database migrate failed; see $migrateLog"
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

function Wait-LogContains {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path $Path) {
            $content = Get-Content -Path $Path -Raw -ErrorAction SilentlyContinue
            if ($content -and $content.Contains($Pattern)) {
                return
            }
        }
        Start-Sleep -Milliseconds 500
    }
    throw "Timed out waiting for log pattern '$Pattern' in $Path"
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

function Start-ManagedDockerSoland {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Image,
        [Parameter(Mandatory = $true)][int]$HostPort,
        [Parameter(Mandatory = $true)][int]$ContainerPort,
        [Parameter(Mandatory = $true)][string]$ObjectsRoot,
        [Parameter(Mandatory = $true)][string]$LogDirectory,
        [Parameter(Mandatory = $true)]$Environment
    )

    $null = New-Item -ItemType Directory -Force -Path $ObjectsRoot
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

function Stop-ProcessTree {
    param([Parameter(Mandatory = $true)][int]$ProcessId)

    $children = Get-CimInstance Win32_Process -Filter "ParentProcessId = $ProcessId" -ErrorAction SilentlyContinue
    foreach ($child in $children) {
        Stop-ProcessTree -ProcessId $child.ProcessId
    }
    Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
}

function Copy-ToLatest {
    param(
        [Parameter(Mandatory = $true)][string]$RunJointDir,
        [Parameter(Mandatory = $true)][string]$LatestJointDir
    )

    $resolvedRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
    $targetParent = Split-Path -Parent $LatestJointDir
    $null = New-Item -ItemType Directory -Force -Path $targetParent
    if (Test-Path $LatestJointDir) {
        $resolvedTarget = (Resolve-Path $LatestJointDir).Path
        if (-not $resolvedTarget.StartsWith($resolvedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to remove latest dir outside repo: $resolvedTarget"
        }
        Remove-Item -LiteralPath $resolvedTarget -Recurse -Force
    }
    Copy-Item -Path $RunJointDir -Destination $LatestJointDir -Recurse -Force
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$workspaceRoot = (Resolve-Path (Join-Path $repoRoot "..")).Path
if (-not $OutputRoot) {
    $OutputRoot = Join-Path $repoRoot "artifacts"
}
$OutputRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputRoot)
if (-not $SutManifest) {
    $SutManifest = Join-Path $workspaceRoot "soland\Cargo.toml"
}
$SutManifest = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($SutManifest)
if (-not $YougenRoot) {
    $YougenRoot = Join-Path $workspaceRoot "yougen"
}
$YougenRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($YougenRoot)

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$runDir = Join-Path $OutputRoot "runs\$timestamp"
$jointDir = Join-Path $runDir "joint-e2e"
$serviceLogDir = Join-Path $jointDir "services"
$screenshotDir = Join-Path $jointDir "screenshots"
$visualBaselineDir = Join-Path $jointDir "visual-baselines"
$latestJointDir = Join-Path $OutputRoot "latest\joint-e2e"
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
if ($SkipYougen -and ($YougenCommand -or $YougenBetaCommand -or $PSBoundParameters.ContainsKey("YougenBaseUrl") -or $PSBoundParameters.ContainsKey("YougenBetaBaseUrl"))) {
    throw "-SkipYougen cannot be combined with Yougen URLs or commands."
}
$yougenPort = $null
if (-not $SkipYougen) {
    if (-not $YougenBaseUrl) {
        $yougenPort = Get-FreeTcpPort
        $YougenBaseUrl = "http://127.0.0.1:$yougenPort"
    }
}
$yougenBetaPort = $null
$yougenBetaBaseUrl = $null
$yougenBaseUrlWasExplicit = $PSBoundParameters.ContainsKey("YougenBaseUrl")
if ($DualSoland -and -not $SkipYougen) {
    if ($YougenBetaBaseUrl) {
        $yougenBetaBaseUrl = $YougenBetaBaseUrl
    } elseif ($YougenBetaCommand) {
        throw "-YougenBetaCommand requires -YougenBetaBaseUrl so the harness can route browser contexts."
    } elseif ($YougenCommand -or $yougenBaseUrlWasExplicit) {
        $yougenBetaBaseUrl = $YougenBaseUrl
    } else {
        $yougenBetaPort = Get-FreeTcpPort
        $yougenBetaBaseUrl = "http://127.0.0.1:$yougenBetaPort"
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
if ($StartCoauth -and -not $CoauthBaseUrl) {
    $coauthPort = Get-FreeTcpPort
    $CoauthBaseUrl = "http://127.0.0.1:$coauthPort"
} else {
    $coauthPort = $null
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
$mockAuditAgentPort = $null
$mockAuditAgentBaseUrl = $null
if ($StartMockAuditAgent) {
    $mockAuditAgentPort = Get-FreeTcpPort
    $mockAuditAgentBaseUrl = "http://127.0.0.1:$mockAuditAgentPort"
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

$managedServices = New-Object System.Collections.Generic.List[object]
$ephemeralPostgres = $null
$exitCode = 1
$startedAt = Get-Date
$generatedSolandCommand = $false
$generatedYougenCommand = $false
$willStartDefaultSoland = (-not $SolandCommand -and $null -ne $solandPort)
$willStartDockerSoland = ($SolandRuntime -eq "docker" -and ($willStartDefaultSoland -or ($DualSoland -and $null -ne $solandBetaPort)))
$startedSolandRuntime = if ($willStartDockerSoland) { "docker" } elseif ($willStartDefaultSoland) { "process" } elseif ($SolandCommand) { "process-command" } else { "attached" }
$coauthConfigPath = $null
$e2eRoot = Join-Path $repoRoot "e2e"
$preflightJson = Join-Path $jointDir "preflight.json"
$preflightMd = Join-Path $jointDir "preflight.md"
$playwrightProjects = Resolve-PlaywrightProjects `
    -RunProfile $RunProfile `
    -PlaywrightProject $PlaywrightProject `
    -PlaywrightProjectWasExplicit ($PSBoundParameters.ContainsKey("PlaywrightProject"))

try {
    if ($willStartDockerSoland -and ($BuildSolandImage -or -not (Test-DockerImagePresent -ImageTag $SolandImage))) {
        $imageBuildArgs = @{
            ImageTag = $SolandImage
        }
        if ($DockerCacheFrom.Count -gt 0) {
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
            -WillStartDefaultSoland $willStartDefaultSoland `
            -SolandRuntime $SolandRuntime `
            -SolandImage $SolandImage `
            -WillStartDockerSoland $willStartDockerSoland `
            -YougenBaseUrl $YougenBaseUrl `
            -YougenCommand $YougenCommand `
            -WillStartDefaultYougen (-not $SkipYougen -and -not $YougenCommand -and $null -ne $yougenPort) `
            -JsonPath $preflightJson `
            -MarkdownPath $preflightMd
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
    if ($StartMockAuditAgent) {
        $auditEnv = "`$env:MOCK_AUDIT_AGENT_PORT='$mockAuditAgentPort'"
        if ($MockAuditAgentDid) {
            $auditEnv = "$auditEnv; `$env:MOCK_audit_agent_principal_id=" + (Quote-PsLiteral $MockAuditAgentDid)
        }
        $mockAuditAgentCmd = "$auditEnv; node " + (Quote-PsLiteral (Join-Path $mocksRoot "mock-audit-agent.mjs"))
        $managedServices.Add((Start-ManagedCommand -Name "mock-audit-agent" -Command $mockAuditAgentCmd -WorkingDirectory $mocksRoot -LogDirectory $serviceLogDir))
        Wait-HttpReady -Url "$mockAuditAgentBaseUrl/_soland/admin/audit-agent/identity" -TimeoutSeconds 30
    }
    if ($StartMockPolicyServer) {
        $envExpr = "`$env:MOCK_POLICY_SERVER_PORT='$mockPolicyServerPort'"
        if ($MockPolicyServerDid) {
            $envExpr = "$envExpr; `$env:MOCK_POLICY_SERVER_DID=" + (Quote-PsLiteral $MockPolicyServerDid)
        }
        $mockPolicyServerCmd = "$envExpr; node " + (Quote-PsLiteral (Join-Path $mocksRoot "mock-policy-server.mjs"))
        $managedServices.Add((Start-ManagedCommand -Name "mock-policy-server" -Command $mockPolicyServerCmd -WorkingDirectory $mocksRoot -LogDirectory $serviceLogDir))
        Wait-HttpReady -Url "$mockPolicyServerBaseUrl/_cokret/self/policy/health" -TimeoutSeconds 30
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

    if ($StartCoauth) {
        if (-not $coauthPort) {
            $coauthUri = [System.Uri]$CoauthBaseUrl
            $coauthPort = $coauthUri.Port
        }
        $coauthBinary = Resolve-CoauthBinary -ExplicitPath $CoauthBin -WorkspaceRoot $workspaceRoot
        $ephemeralPostgres = Start-EphemeralPostgres -Image $CoauthPostgresImage -NamePrefix "cotest-coauth-$timestamp" -TimeoutSeconds $StartupTimeoutSeconds
        $coauthConfigPath = New-CoauthJointConfig `
            -CoauthBinary $coauthBinary `
            -RepoRoot $repoRoot `
            -JointDir $jointDir `
            -PostgresUrl $ephemeralPostgres.Url `
            -CoauthBaseUrl $CoauthBaseUrl `
            -CoauthBind "127.0.0.1:$coauthPort" `
            -SolandBaseUrl $SolandBaseUrl `
            -SolandServiceDid $SolandServiceDid `
            -CoauthServiceDid $CoauthServiceDid `
            -OAuthIntrospectionBearer $CoauthOAuthIntrospectionBearer `
            -SessionGrantIntrospectionBearer $CoauthSessionGrantIntrospectionBearer `
            -EmbeddedWebvhRegistrationBearer $CoauthEmbeddedWebvhRegistrationBearer `
            -MockEmailBaseUrl $mockEmailBaseUrl
        Invoke-CoauthMigrations -CoauthBinary $coauthBinary -ConfigPath $coauthConfigPath -LogDirectory $serviceLogDir
        # Enable the cotest-only debug seam (`/api/v1/test/debug/issue-dpop-grant`)
        # so the joint harness can mint real DPoP-bound ck.session.grants instead
        # of dev-login bearers (see helpers/session-grant-dpop.ts mintDpopBoundGrant).
        $CoauthCommand = "`$env:COAUTH_ENABLE_TEST_ENDPOINTS='1'; & {0} --config {1} server --no-migrate --no-sync" -f (Quote-PsLiteral $coauthBinary), (Quote-PsLiteral $coauthConfigPath)
        $CoauthHealthUrl = "$($CoauthBaseUrl.TrimEnd('/'))/health"
    }

    if ($CoauthCommand) {
        if (-not $CoauthBaseUrl -and -not $CoauthHealthUrl) {
            throw "CoauthCommand requires CoauthBaseUrl or CoauthHealthUrl"
        }
        $coauthWorkingDirectory = if ($StartCoauth) { Join-Path $workspaceRoot "coauth" } else { $workspaceRoot }
        $managedServices.Add((Start-ManagedCommand -Name "coauth" -Command $CoauthCommand -WorkingDirectory $coauthWorkingDirectory -LogDirectory $serviceLogDir))
        $health = if ($CoauthHealthUrl) { $CoauthHealthUrl } else { "$($CoauthBaseUrl.TrimEnd('/'))/health" }
        Wait-HttpReady -Url $health -TimeoutSeconds $StartupTimeoutSeconds
    }

    # CT-6: starid (DID resolver) - env-driven, no external deps. Spawned
    # before soland so soland's SOLAND_STARID_WEBVH_RESOLVER_URL points at a
    # live listener from the first request onwards.
    if ($StartStarid) {
        if (-not $staridPort) {
            $staridUri = [System.Uri]$StaridBaseUrl
            $staridPort = $staridUri.Port
        }
        $staridBinary = Resolve-StaridBinary -ExplicitPath $StaridBin -WorkspaceRoot $workspaceRoot
        $staridCmd = (
            "`$env:STARID_BIND='127.0.0.1:{0}'; " +
            "`$env:STARID_SERVICE_DID={1}; " +
            "`$env:STARID_DEVELOPMENT_MODE='true'; " +
            "& {2}"
        ) -f $staridPort, (Quote-PsLiteral $StaridServiceDid), (Quote-PsLiteral $staridBinary)
        $managedServices.Add((Start-ManagedCommand -Name "starid" -Command $staridCmd -WorkingDirectory (Split-Path -Parent $staridBinary) -LogDirectory $serviceLogDir))
        Wait-HttpReady -Url "$($StaridBaseUrl.TrimEnd('/'))/health" -TimeoutSeconds $StartupTimeoutSeconds
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
        $teabayCmd = (
            "`$env:TEABAY_BIND='127.0.0.1:{0}'; " +
            "`$env:TEABAY_PUBLIC_BASE_URL={1}; " +
            "`$env:TEABAY_SERVICE_DID={2}; " +
            "`$env:TEABAY_DEVELOPMENT_MODE='true'; " +
            "`$env:TEABAY_PRIVATE_CONTACT_DISCOVERY_ENABLED='true'; " +
            "`$env:DATABASE_URL={3}; " +
            "& {4}"
        ) -f `
            $teabayPort,
            (Quote-PsLiteral $TeabayBaseUrl),
            (Quote-PsLiteral $TeabayServiceDid),
            (Quote-PsLiteral $teabayDb),
            (Quote-PsLiteral $teabayBinary)
        $managedServices.Add((Start-ManagedCommand -Name "teabay" -Command $teabayCmd -WorkingDirectory (Split-Path -Parent $teabayBinary) -LogDirectory $serviceLogDir))
        Wait-HttpReady -Url "$($TeabayBaseUrl.TrimEnd('/'))/health" -TimeoutSeconds $StartupTimeoutSeconds
    }

    $solandCoauthEnv = ""
    if ($CoauthBaseUrl) {
        $coauthTrimmed = $CoauthBaseUrl.TrimEnd("/")
        $solandCoauthEnv = (
            "`$env:SOLAND_ACCOUNT_AUTHORITY_URL={0}; " +
            "`$env:SOLAND_OAUTH_INTROSPECTION_URL={1}; " +
            "`$env:SOLAND_OAUTH_INTROSPECTION_BEARER={2}; " +
            "`$env:SOLAND_SESSION_GRANT_INTROSPECTION_URL={3}; " +
            "`$env:SOLAND_SESSION_GRANT_INTROSPECTION_BEARER={4}; " +
            "`$env:SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER={5}; " +
            "`$env:SOLAND_OAUTH_CLIENT_ID={6}; "
        ) -f `
            (Quote-PsLiteral $coauthTrimmed),
            (Quote-PsLiteral "$coauthTrimmed/oauth/introspect"),
            (Quote-PsLiteral $CoauthOAuthIntrospectionBearer),
            (Quote-PsLiteral "$coauthTrimmed/_cokret/gate/account/session-grants/introspect"),
            (Quote-PsLiteral $CoauthSessionGrantIntrospectionBearer),
            (Quote-PsLiteral $CoauthEmbeddedWebvhRegistrationBearer),
            (Quote-PsLiteral $CoauthOAuthClientId)
    }

    # CT-6: wire soland -> starid (DID resolver) + soland -> teabay
    # (directory announce). Each block is no-op when its service is not
    # part of the joint stack.
    $solandStaridEnv = ""
    if ($StaridBaseUrl) {
        $solandStaridEnv = (
            "`$env:SOLAND_DID_RESOLVER_ALLOW_METHODS='did:web,did:key,did:webvh'; " +
            "`$env:SOLAND_STARID_WEBVH_RESOLVER_URL={0}; "
        ) -f (Quote-PsLiteral $StaridBaseUrl)
    }
    $solandTeabayEnv = ""
    if ($TeabayBaseUrl) {
        $teabayTrimmed = $TeabayBaseUrl.TrimEnd("/")
        $solandTeabayEnv = (
            "`$env:SOLAND_DIRECTORY_ANNOUNCE_URL={0}; "
        ) -f (Quote-PsLiteral "$teabayTrimmed/_cokret/find/directory/announce")
    }

    function Build-SolandDockerEnvironment {
        param(
            [Parameter(Mandatory = $true)][string]$BaseUrl,
            [Parameter(Mandatory = $true)][string]$ServiceDid,
            [Parameter(Mandatory = $true)][int]$MetricsPort,
            [Parameter(Mandatory = $true)][string]$LogFileName,
            [Parameter(Mandatory = $true)][string]$CorsAllowOrigin,
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
            SOLAND_SERVICE_DID = $ServiceDid
            SOLAND_DEVELOPMENT_MODE = "true"
            SOLAND_CORS_ALLOW_ORIGIN = $CorsAllowOrigin
            SOLAND_METRICS_BIND = "0.0.0.0:$MetricsPort"
            SOLAND_OBJECT_STORAGE_BACKEND = "filesystem"
            SOLAND_OBJECT_STORAGE_LOCAL_ROOT = "/tmp/soland-blobs"
            SOLAND_LOG_FILE = "/cotest-logs/$LogFileName"
            SOLAND_LIVEKIT_API_KEY = "did:web:media.example#media-token"
            SOLAND_LIVEKIT_API_SECRET = "joint-e2e-livekit-secret"
        }
        if ($CoauthBaseUrl) {
            $coauthPublic = $CoauthBaseUrl.TrimEnd("/")
            $coauthContainer = (Convert-ToContainerReachableUrl $coauthPublic).TrimEnd("/")
            $map.SOLAND_ACCOUNT_AUTHORITY_URL = $coauthPublic
            $map.SOLAND_OAUTH_INTROSPECTION_URL = "$coauthContainer/oauth/introspect"
            $map.SOLAND_OAUTH_INTROSPECTION_BEARER = $CoauthOAuthIntrospectionBearer
            $map.SOLAND_SESSION_GRANT_INTROSPECTION_URL = "$coauthContainer/_cokret/gate/account/session-grants/introspect"
            $map.SOLAND_SESSION_GRANT_INTROSPECTION_BEARER = $CoauthSessionGrantIntrospectionBearer
            $map.SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER = $CoauthEmbeddedWebvhRegistrationBearer
            $map.SOLAND_OAUTH_CLIENT_ID = $CoauthOAuthClientId
        }
        if ($StaridBaseUrl) {
            $map.SOLAND_DID_RESOLVER_ALLOW_METHODS = "did:web,did:key,did:webvh"
            $map.SOLAND_STARID_WEBVH_RESOLVER_URL = Convert-ToContainerReachableUrl $StaridBaseUrl
        }
        if ($TeabayBaseUrl) {
            $teabayContainer = (Convert-ToContainerReachableUrl $TeabayBaseUrl).TrimEnd("/")
            $map.SOLAND_DIRECTORY_ANNOUNCE_URL = "$teabayContainer/_cokret/find/directory/announce"
        }
        if ($FederationPeers) {
            $parts = $FederationPeers -split "\|", 2
            if ($parts.Count -eq 2) {
                $map.SOLAND_FEDERATION_POLICY = "Mesh"
                $map.SOLAND_FEDERATION_PEERS = "$(Convert-ToContainerReachableUrl $parts[0])|$($parts[1])"
            }
        }
        return $map
    }

    function Build-SolandCommand {
        param(
            [Parameter(Mandatory = $true)][string]$BaseUrl,
            [Parameter(Mandatory = $true)][string]$ServiceDid,
            [Parameter(Mandatory = $true)][string]$ObjectsRoot,
            [Parameter(Mandatory = $true)][int]$Port,
            [Parameter(Mandatory = $true)][int]$MetricsPort,
            [Parameter(Mandatory = $true)][string]$LogFile,
            [Parameter(Mandatory = $true)][string]$CorsAllowOrigin,
            [string]$FederationPeers = ""
        )
        $federationEnv = ""
        if ($FederationPeers) {
            $federationEnv = (
                "`$env:SOLAND_FEDERATION_POLICY='Mesh'; " +
                "`$env:SOLAND_FEDERATION_PEERS={0}; "
            ) -f (Quote-PsLiteral $FederationPeers)
        }
        # Forward the harness's RUST_LOG into the soland child so the runner
        # can drive verbose tracing on demand (e.g. when debugging a specific
        # projection path) without editing this file. The value is baked
        # into the spawned PowerShell command string so it survives whatever
        # env handling `Start-Process` applies.
        #
        # Default RUST_LOG to `info` so the soland-side tracing file
        # (SOLAND_LOG_FILE below) actually contains the
        # `tracing::info!(...)` events service code emits. Without an
        # explicit filter, `EnvFilter::from_default_env()` falls back to
        # OFF and the file is just startup metadata.
        $rustLogForward = ""
        if ($env:RUST_LOG -and -not [string]::IsNullOrWhiteSpace($env:RUST_LOG)) {
            $rustLogForward = "`$env:RUST_LOG=" + (Quote-PsLiteral $env:RUST_LOG) + "; "
        } else {
            $rustLogForward = "`$env:RUST_LOG='info'; "
        }
        return (
            $rustLogForward +
            "`$env:DATABASE_URL=''; " +
            "`$env:SOLAND_PUBLIC_BASE_URL={0}; " +
            "`$env:SOLAND_SERVICE_DID={1}; " +
            "`$env:SOLAND_DEVELOPMENT_MODE='true'; " +
            "`$env:SOLAND_CORS_ALLOW_ORIGIN={2}; " +
            "`$env:SOLAND_METRICS_BIND='127.0.0.1:{3}'; " +
            "`$env:SOLAND_OBJECT_STORAGE_BACKEND='filesystem'; " +
            "`$env:SOLAND_OBJECT_STORAGE_LOCAL_ROOT={4}; " +
            "`$env:SOLAND_LOG_FILE={5}; " +
            "`$env:SOLAND_LIVEKIT_API_KEY='did:web:media.example#media-token'; " +
            "`$env:SOLAND_LIVEKIT_API_SECRET='joint-e2e-livekit-secret'; " +
            "{6}" +
            "{7}" +
            "{8}" +
            "{9}" +
            "cargo run --manifest-path {10} -- --bind 127.0.0.1:{11}"
        ) -f `
            (Quote-PsLiteral $BaseUrl),
            (Quote-PsLiteral $ServiceDid),
            (Quote-PsLiteral $CorsAllowOrigin),
            $MetricsPort,
            (Quote-PsLiteral $ObjectsRoot),
            (Quote-PsLiteral $LogFile),
            $solandCoauthEnv,
            $solandStaridEnv,
            $solandTeabayEnv,
            $federationEnv,
            (Quote-PsLiteral $SutManifest),
            $Port
    }

    # Per-instance tracing files. Windows fully-buffers stdout when
    # `Start-Process -RedirectStandardOutput` is chained through
    # `cargo run`, so the soland.stdout.log captured by the harness ends up
    # holding only cargo's build output. The `SOLAND_LOG_FILE` path is a
    # second, durable sink soland writes through a non-blocking
    # tracing-appender (see soland/src/main.rs `init_tracing`). This is the
    # file scenarios should `tail -f` when debugging projection / reducer
    # paths against the runner.
    $solandTraceFile = Join-Path $serviceLogDir "soland.trace.log"
    $solandCorsAllowOrigin = if ($YougenBaseUrl) { $YougenBaseUrl } else { "http://127.0.0.1" }
    if (-not $SolandCommand -and $solandPort -and $SolandRuntime -eq "process") {
        $generatedSolandCommand = $true
        $alphaPeer = if ($DualSoland) { "$solandBetaBaseUrl|$SolandBetaServiceDid" } else { "" }
        $solandMetricsPort = Get-FreeTcpPort
        $SolandCommand = Build-SolandCommand `
            -BaseUrl $SolandBaseUrl `
            -ServiceDid $SolandServiceDid `
            -ObjectsRoot (Join-Path $jointDir "soland-objects") `
            -Port $solandPort `
            -MetricsPort $solandMetricsPort `
            -LogFile $solandTraceFile `
            -CorsAllowOrigin $solandCorsAllowOrigin `
            -FederationPeers $alphaPeer
    }
    if ($SolandCommand) {
        $solandWorkingDirectory = if ($generatedSolandCommand) { $repoRoot } else { Split-Path -Parent $SutManifest }
        $solandName = if ($DualSoland) { "soland-alpha" } else { "soland" }
        $managedServices.Add((Start-ManagedCommand -Name $solandName -Command $SolandCommand -WorkingDirectory $solandWorkingDirectory -LogDirectory $serviceLogDir))
    } elseif ($willStartDockerSoland) {
        $alphaPeer = if ($DualSoland) { "$solandBetaBaseUrl|$SolandBetaServiceDid" } else { "" }
        $solandMetricsPort = Get-FreeTcpPort
        $solandDockerEnv = Build-SolandDockerEnvironment `
            -BaseUrl $SolandBaseUrl `
            -ServiceDid $SolandServiceDid `
            -MetricsPort $solandMetricsPort `
            -LogFileName ([System.IO.Path]::GetFileName($solandTraceFile)) `
            -CorsAllowOrigin $solandCorsAllowOrigin `
            -FederationPeers $alphaPeer
        $solandName = if ($DualSoland) { "soland-alpha" } else { "soland" }
        $managedServices.Add((Start-ManagedDockerSoland `
                    -Name $solandName `
                    -Image $SolandImage `
                    -HostPort $solandPort `
                    -ContainerPort $SolandContainerPort `
                    -ObjectsRoot (Join-Path $jointDir "soland-objects") `
                    -LogDirectory $serviceLogDir `
                    -Environment $solandDockerEnv))
    }
    Wait-HttpReady -Url "$($SolandBaseUrl.TrimEnd('/'))/health" -TimeoutSeconds $StartupTimeoutSeconds

    if ($DualSoland) {
        $solandBetaTraceFile = Join-Path $serviceLogDir "soland-beta.trace.log"
        $solandBetaMetricsPort = Get-FreeTcpPort
        $solandBetaCorsAllowOrigin = if ($yougenBetaBaseUrl) { $yougenBetaBaseUrl } else { $solandCorsAllowOrigin }
        if ($SolandRuntime -eq "docker") {
            $solandBetaDockerEnv = Build-SolandDockerEnvironment `
                -BaseUrl $solandBetaBaseUrl `
                -ServiceDid $SolandBetaServiceDid `
                -MetricsPort $solandBetaMetricsPort `
                -LogFileName ([System.IO.Path]::GetFileName($solandBetaTraceFile)) `
                -CorsAllowOrigin $solandBetaCorsAllowOrigin `
                -FederationPeers "$SolandBaseUrl|$SolandServiceDid"
            $managedServices.Add((Start-ManagedDockerSoland `
                        -Name "soland-beta" `
                        -Image $SolandImage `
                        -HostPort $solandBetaPort `
                        -ContainerPort $SolandContainerPort `
                        -ObjectsRoot (Join-Path $jointDir "soland-beta-objects") `
                        -LogDirectory $serviceLogDir `
                        -Environment $solandBetaDockerEnv))
        } else {
            $solandBetaCommand = Build-SolandCommand `
                -BaseUrl $solandBetaBaseUrl `
                -ServiceDid $SolandBetaServiceDid `
                -ObjectsRoot (Join-Path $jointDir "soland-beta-objects") `
                -Port $solandBetaPort `
                -MetricsPort $solandBetaMetricsPort `
                -LogFile $solandBetaTraceFile `
                -CorsAllowOrigin $solandBetaCorsAllowOrigin `
                -FederationPeers "$SolandBaseUrl|$SolandServiceDid"
            $managedServices.Add((Start-ManagedCommand -Name "soland-beta" -Command $solandBetaCommand -WorkingDirectory $repoRoot -LogDirectory $serviceLogDir))
        }
        Wait-HttpReady -Url "$($solandBetaBaseUrl.TrimEnd('/'))/health" -TimeoutSeconds $StartupTimeoutSeconds
    }

    $yougenService = $null
    $yougenBetaService = $null
    $generatedYougenBetaCommand = $false
    if (-not $SkipYougen -and -not $YougenCommand -and $yougenPort) {
        $YougenCommand = "dx serve --platform web --addr 127.0.0.1 --port $yougenPort --open false --hot-reload false --watch false --features experimental-agents"
        $generatedYougenCommand = $true
    }
    if ($YougenCommand) {
        $yougenName = if ($DualSoland) { "yougen-alpha" } else { "yougen" }
        $yougenService = Start-ManagedCommand -Name $yougenName -Command $YougenCommand -WorkingDirectory $YougenRoot -LogDirectory $serviceLogDir
        $managedServices.Add($yougenService)
    }
    if (-not $SkipYougen) {
        Wait-HttpReady -Url $YougenBaseUrl -TimeoutSeconds $StartupTimeoutSeconds
        if ($generatedYougenCommand -and $yougenService) {
            Wait-LogContains -Path $yougenService.Stdout -Pattern "Build completed successfully" -TimeoutSeconds $StartupTimeoutSeconds
        }
    }
    if (-not $SkipYougen -and $DualSoland -and $yougenBetaBaseUrl -and $yougenBetaBaseUrl -ne $YougenBaseUrl) {
        if (-not $YougenBetaCommand -and $yougenBetaPort) {
            $YougenBetaCommand = "dx serve --platform web --addr 127.0.0.1 --port $yougenBetaPort --open false --hot-reload false --watch false --features experimental-agents"
            $generatedYougenBetaCommand = $true
        }
        if ($YougenBetaCommand) {
            $yougenBetaService = Start-ManagedCommand -Name "yougen-beta" -Command $YougenBetaCommand -WorkingDirectory $YougenRoot -LogDirectory $serviceLogDir
            $managedServices.Add($yougenBetaService)
        }
        Wait-HttpReady -Url $yougenBetaBaseUrl -TimeoutSeconds $StartupTimeoutSeconds
        if ($generatedYougenBetaCommand -and $yougenBetaService) {
            Wait-LogContains -Path $yougenBetaService.Stdout -Pattern "Build completed successfully" -TimeoutSeconds $StartupTimeoutSeconds
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
    $needsBundledChromium = ($playwrightProjects -contains "chromium") -or ($playwrightProjects -contains "joint-yougen")
    if (-not $SkipBrowserInstall -and $needsBundledChromium) {
        Push-Location $e2eRoot
        try {
            $npxInstallCommandInfo = Get-Command npx.cmd -ErrorAction SilentlyContinue
            if (-not $npxInstallCommandInfo) {
                $npxInstallCommandInfo = Get-Command npx -ErrorAction Stop
            }
            & $npxInstallCommandInfo.Source playwright install chromium
            if ($LASTEXITCODE -ne 0) {
                throw "playwright browser install failed"
            }
        }
        finally {
            Pop-Location
        }
    }

    $env:COTEST_JOINT_RUN_DIR = $jointDir
    $env:COTEST_UI_SCREENSHOT_DIR = $screenshotDir
    $env:COTEST_UI_VISUAL_BASELINE_DIR = $visualBaselineDir
    $env:COTEST_SOLAND_BASE_URL = $SolandBaseUrl
    $env:COTEST_SOLAND_SERVICE_DID = $SolandServiceDid
    if ($YougenBaseUrl) {
        $env:COTEST_YOUGEN_BASE_URL = $YougenBaseUrl
    } else {
        Remove-Item Env:COTEST_YOUGEN_BASE_URL -ErrorAction SilentlyContinue
    }
    if ($DualSoland) {
        $env:COTEST_SOLAND_ALPHA_BASE_URL = $SolandBaseUrl
        $env:COTEST_SOLAND_ALPHA_SERVICE_DID = $SolandServiceDid
        $env:COTEST_SOLAND_BETA_BASE_URL = $solandBetaBaseUrl
        $env:COTEST_SOLAND_BETA_SERVICE_DID = $SolandBetaServiceDid
        if ($YougenBaseUrl) {
            $env:COTEST_YOUGEN_ALPHA_BASE_URL = $YougenBaseUrl
        } else {
            Remove-Item Env:COTEST_YOUGEN_ALPHA_BASE_URL -ErrorAction SilentlyContinue
        }
        if ($yougenBetaBaseUrl) {
            $env:COTEST_YOUGEN_BETA_BASE_URL = $yougenBetaBaseUrl
        } else {
            Remove-Item Env:COTEST_YOUGEN_BETA_BASE_URL -ErrorAction SilentlyContinue
        }
    } else {
        Remove-Item Env:COTEST_SOLAND_ALPHA_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_SOLAND_ALPHA_SERVICE_DID -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_SOLAND_BETA_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_SOLAND_BETA_SERVICE_DID -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_YOUGEN_ALPHA_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_YOUGEN_BETA_BASE_URL -ErrorAction SilentlyContinue
    }
    if ($CoauthBaseUrl) {
        $env:COTEST_COAUTH_BASE_URL = $CoauthBaseUrl.TrimEnd("/")
        $env:COTEST_COAUTH_SERVICE_DID = $CoauthServiceDid
        # The OAuth client_id soland is configured to advertise (see
        # $solandCoauthEnv / SOLAND_OAUTH_CLIENT_ID). Surfaced to e2e so
        # oidc-login-chain.spec.ts can assert /_cokret/describe advertises it.
        $env:COTEST_OIDC_CLIENT_ID = $CoauthOAuthClientId
    } else {
        Remove-Item Env:COTEST_COAUTH_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_COAUTH_SERVICE_DID -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_OIDC_CLIENT_ID -ErrorAction SilentlyContinue
    }
    if ($StaridBaseUrl) {
        $env:COTEST_STARID_BASE_URL = $StaridBaseUrl.TrimEnd("/")
        $env:COTEST_STARID_SERVICE_DID = $StaridServiceDid
    } else {
        Remove-Item Env:COTEST_STARID_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_STARID_SERVICE_DID -ErrorAction SilentlyContinue
    }
    if ($TeabayBaseUrl) {
        $env:COTEST_TEABAY_BASE_URL = $TeabayBaseUrl.TrimEnd("/")
        $env:COTEST_TEABAY_SERVICE_DID = $TeabayServiceDid
    } else {
        Remove-Item Env:COTEST_TEABAY_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_TEABAY_SERVICE_DID -ErrorAction SilentlyContinue
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
    if ($mockAuditAgentBaseUrl) {
        $env:COTEST_MOCK_AUDIT_AGENT_BASE_URL = $mockAuditAgentBaseUrl
        if ($MockAuditAgentDid) {
            $env:COTEST_MOCK_audit_agent_principal_id = $MockAuditAgentDid
        } else {
            Remove-Item Env:COTEST_MOCK_audit_agent_principal_id -ErrorAction SilentlyContinue
        }
    } else {
        Remove-Item Env:COTEST_MOCK_AUDIT_AGENT_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_MOCK_audit_agent_principal_id -ErrorAction SilentlyContinue
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

    $playwrightArgs = @("playwright", "test", "--config", "playwright.config.ts")
    foreach ($project in $playwrightProjects) {
        $playwrightArgs += @("--project", $project)
    }
    # G4.T1: joint-smoke is the PR gate. It runs only describe blocks tagged
    # @fully-implemented. The remaining fixme placeholders are excluded
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
    $playwrightStdout = Join-Path $jointDir "playwright.stdout.log"
    $playwrightStderr = Join-Path $jointDir "playwright.stderr.log"
    $npxCommandInfo = Get-Command npx.cmd -ErrorAction SilentlyContinue
    if (-not $npxCommandInfo) {
        $npxCommandInfo = Get-Command npx -ErrorAction Stop
    }
    $npxCommand = $npxCommandInfo.Source
    Push-Location $e2eRoot
    try {
        $previousErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $playwrightOutput = & $npxCommand @playwrightArgs 2>&1
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
finally {
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

# Optional self-test: validates Get-FixmeTitlesForSpec against a known spec
# (read-receipts.spec.ts has 8 fixme entries and 0 live tests as of G0.T4).
if ($env:COTEST_SELFTEST -eq '1') {
    $selftestSpec = Join-Path $e2eRoot "tests/messaging/read-receipts.spec.ts"
    $selftestTitles = @(Get-FixmeTitlesForSpec -Path $selftestSpec)
    if ($selftestTitles.Count -ne 8) {
        throw "G0.T4 self-test failed: Get-FixmeTitlesForSpec returned $($selftestTitles.Count) titles for read-receipts.spec.ts (expected 8)"
    }
    Write-Host "[selftest] Get-FixmeTitlesForSpec: 8 entries for read-receipts.spec.ts (OK)"
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
    soland_service_did = $SolandServiceDid
    soland_beta_base_url = $solandBetaBaseUrl
    soland_beta_service_did = if ($DualSoland) { $SolandBetaServiceDid } else { $null }
    dual_soland = [bool]$DualSoland
    yougen_alpha_base_url = if ($DualSoland) { $YougenBaseUrl } else { $null }
    yougen_beta_base_url = if ($DualSoland) { $yougenBetaBaseUrl } else { $null }
    mock_idp_base_url = $mockIdpBaseUrl
    mock_email_base_url = $mockEmailBaseUrl
    mock_witness_base_url = $mockWitnessBaseUrl
    mock_witness_did = if ($mockWitnessBaseUrl) { $MockWitnessDid } else { $null }
    mock_witness_quorum_base_urls = if ($mockWitnessBaseUrl) { $mockWitnessQuorumBaseUrls } else { @() }
    mock_witness_quorum_dids = if ($mockWitnessBaseUrl) { $mockWitnessQuorumDids } else { @() }
    mock_audit_agent_base_url = $mockAuditAgentBaseUrl
    mock_audit_agent_principal_id = if ($mockAuditAgentBaseUrl -and $MockAuditAgentDid) { $MockAuditAgentDid } else { $null }
    mock_mimi_facade_base_url = $mockMimiFacadeBaseUrl
    mock_mimi_facade_did = if ($mockMimiFacadeBaseUrl) { $MockMimiFacadeDid } else { $null }
    yougen_base_url = $YougenBaseUrl
    coauth_base_url = if ($CoauthBaseUrl) { $CoauthBaseUrl } else { $null }
    coauth_service_did = if ($CoauthBaseUrl) { $CoauthServiceDid } else { $null }
    coauth_config = $coauthConfigPath
    coauth_postgres_container = if ($ephemeralPostgres) { $ephemeralPostgres.ContainerName } else { $null }
    starid_base_url = if ($StaridBaseUrl) { $StaridBaseUrl } else { $null }
    starid_service_did = if ($StaridBaseUrl) { $StaridServiceDid } else { $null }
    teabay_base_url = if ($TeabayBaseUrl) { $TeabayBaseUrl } else { $null }
    teabay_service_did = if ($TeabayBaseUrl) { $TeabayServiceDid } else { $null }
    teabay_database_url = if ($TeabayBaseUrl) { $TeabayDatabaseUrl } else { $null }
    coauth_oauth_introspection_url = if ($CoauthBaseUrl) { "$($CoauthBaseUrl.TrimEnd('/'))/oauth/introspect" } else { $null }
    coauth_session_grant_introspection_url = if ($CoauthBaseUrl) { "$($CoauthBaseUrl.TrimEnd('/'))/_cokret/gate/account/session-grants/introspect" } else { $null }
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
- soland_service_did: $($summary.soland_service_did)
- soland_beta_base_url: $($summary.soland_beta_base_url)
- soland_beta_service_did: $($summary.soland_beta_service_did)
- dual_soland: $($summary.dual_soland)
- yougen_alpha_base_url: $($summary.yougen_alpha_base_url)
- yougen_beta_base_url: $($summary.yougen_beta_base_url)
- mock_idp_base_url: $($summary.mock_idp_base_url)
- mock_email_base_url: $($summary.mock_email_base_url)
- mock_witness_base_url: $($summary.mock_witness_base_url)
- mock_witness_did: $($summary.mock_witness_did)
- mock_witness_quorum_base_urls: $($mockWitnessQuorumBaseUrls -join ",")
- mock_witness_quorum_dids: $($mockWitnessQuorumDids -join ",")
- mock_audit_agent_base_url: $($summary.mock_audit_agent_base_url)
- mock_audit_agent_principal_id: $($summary.mock_audit_agent_principal_id)
- mock_mimi_facade_base_url: $($summary.mock_mimi_facade_base_url)
- mock_mimi_facade_did: $($summary.mock_mimi_facade_did)
- yougen_base_url: $($summary.yougen_base_url)
- coauth_base_url: $($summary.coauth_base_url)
- coauth_service_did: $($summary.coauth_service_did)
- coauth_config: $($summary.coauth_config)
- coauth_oauth_introspection_url: $($summary.coauth_oauth_introspection_url)
- coauth_session_grant_introspection_url: $($summary.coauth_session_grant_introspection_url)
- starid_base_url: $($summary.starid_base_url)
- starid_service_did: $($summary.starid_service_did)
- teabay_base_url: $($summary.teabay_base_url)
- teabay_service_did: $($summary.teabay_service_did)
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
- gap_todos: $($summary.gap_todos)
- fixme_promotion_checklist: $($summary.fixme_promotion_checklist)
- services: $($summary.services)
"@ | Set-Content -Path $summaryMd -Encoding UTF8

Copy-ToLatest -RunJointDir $jointDir -LatestJointDir $latestJointDir

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
if ($mockAuditAgentBaseUrl) {
    $auditAgentLabel = if ($MockAuditAgentDid) { " ($MockAuditAgentDid)" } else { "" }
    Write-Host "  mock-audit-agent: $mockAuditAgentBaseUrl$auditAgentLabel"
}
if ($mockMimiFacadeBaseUrl) {
    Write-Host "  mock-mimi-facade: $mockMimiFacadeBaseUrl ($MockMimiFacadeDid)"
}
if ($YougenBaseUrl) {
    Write-Host "  yougen      : $YougenBaseUrl"
}
if ($DualSoland -and $yougenBetaBaseUrl) {
    Write-Host "  yougen-beta : $yougenBetaBaseUrl"
}
if ($CoauthBaseUrl) {
    Write-Host "  coauth      : $CoauthBaseUrl"
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
Write-Host "  latest      : $latestJointDir"

exit $exitCode
