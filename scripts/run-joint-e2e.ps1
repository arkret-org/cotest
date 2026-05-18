[CmdletBinding()]
param(
    [string]$OutputRoot,
    [string]$SutManifest,
    [string]$YougenRoot,
    [string]$SolandBaseUrl,
    [string]$YougenBaseUrl,
    [string]$CoauthBaseUrl,
    [string]$SolandCommand,
    [string]$YougenCommand,
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
    [switch]$StartMocks,
    [string]$MockWitnessDid = "did:web:witness.joint-e2e.local",
    [ValidateSet("joint-smoke", "joint-full")]
    [string]$RunProfile,
    [string]$PlaywrightProject = "chrome",
    [string]$Grep
)

if ($StartMocks) {
    $StartMockIdp = $true
    $StartMockEmail = $true
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
        [string]$YougenBaseUrl,
        [string]$YougenCommand,
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
            $playwrightVersion = (& $npx playwright --version 2>&1) -join "`n"
            if ($LASTEXITCODE -eq 0) {
                Add-PreflightResult $results "playwright package" "pass" $playwrightVersion
            } else {
                Add-PreflightResult $results "playwright package" "fail" $playwrightVersion
            }

            $listArgs = @("playwright", "test", "--config", "playwright.config.ts", "--list")
            foreach ($project in $PlaywrightProjects) {
                $listArgs += @("--project", $project)
            }
            $listOutput = (& $npx @listArgs 2>&1) -join "`n"
            if ($LASTEXITCODE -eq 0) {
                Add-PreflightResult $results "playwright projects" "pass" ($PlaywrightProjects -join ",")
            } else {
                Add-PreflightResult $results "playwright projects" "fail" $listOutput
            }

            $browserList = (& $npx playwright install --list 2>&1) -join "`n"
            if ($LASTEXITCODE -eq 0) {
                Add-PreflightResult $results "playwright browsers" "pass" "browser registry readable"
            } else {
                Add-PreflightResult $results "playwright browsers" "fail" $browserList
            }
        }
        finally {
            Pop-Location
        }
    }

    if (-not $SolandBaseUrl -and -not $SolandCommand) {
        $cargo = Find-CommandPath @("cargo.exe", "cargo")
        if ($cargo) {
            $version = (& $cargo --version 2>&1) -join "`n"
            Add-PreflightResult $results "cargo" "pass" "$cargo $version"
        } else {
            Add-PreflightResult $results "cargo" "fail" "cargo is required to start the default soland command"
        }
    }

    if (-not $YougenBaseUrl -and -not $YougenCommand) {
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
            $dockerInfo = (& $docker info 2>&1) -join "`n"
            if ($LASTEXITCODE -eq 0) {
                Add-PreflightResult $results "docker daemon" "pass" "daemon reachable"
            } else {
                Add-PreflightResult $results "docker daemon" "fail" $dockerInfo
            }
            $imageInspect = (& $docker image inspect $CoauthPostgresImage 2>&1) -join "`n"
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

function Get-FreeTcpPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse("127.0.0.1"), 0)
    try {
        $listener.Start()
        return $listener.LocalEndpoint.Port
    }
    finally {
        $listener.Stop()
    }
}

function Quote-PsLiteral {
    param([Parameter(Mandatory = $true)][string]$Value)
    return "'" + ($Value -replace "'", "''") + "'"
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
    $runOutput = & docker run --rm -d `
        --name $containerName `
        -e POSTGRES_USER=contrix `
        -e POSTGRES_PASSWORD=contrix `
        -e POSTGRES_DB=contrix `
        -p "127.0.0.1:$port`:5432" `
        $Image 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to start PostgreSQL container: $($runOutput -join "`n")"
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastError = $null
    while ((Get-Date) -lt $deadline) {
        $readyOutput = & docker exec $containerName pg_isready -U contrix -d contrix 2>&1
        if ($LASTEXITCODE -eq 0) {
            return [pscustomobject]@{
                ContainerName = $containerName
                HostPort = $port
                Url = "postgresql://contrix:contrix@127.0.0.1:$port/contrix"
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
        [Parameter(Mandatory = $true)][string]$EmbeddedWebvhRegistrationBearer
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
    if ((Split-Path -Leaf $python) -ieq "py.exe") {
        $patchArgs = @("-3") + $patchArgs
    }
    $patchOutput = & $python @patchArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        $patchOutput | Set-Content -Path (Join-Path $JointDir "coauth-config-patch.log") -Encoding UTF8
        throw "coauth config patch failed"
    }

    return $configPath
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
    $process = Start-Process `
        -FilePath "powershell" `
        -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $Command) `
        -WorkingDirectory $WorkingDirectory `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -WindowStyle Hidden `
        -PassThru

    [pscustomobject]@{
        Name = $Name
        Process = $process
        Stdout = $stdout
        Stderr = $stderr
    }
}

function Stop-ManagedCommand {
    param([Parameter(Mandatory = $true)]$Service)

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
if (-not $SutManifest) {
    $SutManifest = Join-Path $workspaceRoot "soland\Cargo.toml"
}
if (-not $YougenRoot) {
    $YougenRoot = Join-Path $workspaceRoot "yougen"
}

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
if (-not $YougenBaseUrl) {
    $yougenPort = Get-FreeTcpPort
    $YougenBaseUrl = "http://127.0.0.1:$yougenPort"
} else {
    $yougenPort = $null
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
if ($StartMockWitness) {
    $mockWitnessPort = Get-FreeTcpPort
    $mockWitnessBaseUrl = "http://127.0.0.1:$mockWitnessPort"
}

$managedServices = New-Object System.Collections.Generic.List[object]
$ephemeralPostgres = $null
$exitCode = 1
$startedAt = Get-Date
$generatedSolandCommand = $false
$generatedYougenCommand = $false
$coauthConfigPath = $null
$e2eRoot = Join-Path $repoRoot "e2e"
$preflightJson = Join-Path $jointDir "preflight.json"
$preflightMd = Join-Path $jointDir "preflight.md"
$playwrightProjects = Resolve-PlaywrightProjects `
    -RunProfile $RunProfile `
    -PlaywrightProject $PlaywrightProject `
    -PlaywrightProjectWasExplicit ($PSBoundParameters.ContainsKey("PlaywrightProject"))

try {
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
            -YougenBaseUrl $YougenBaseUrl `
            -YougenCommand $YougenCommand `
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
        Wait-HttpReady -Url "$mockWitnessBaseUrl/api/v1/witness/policy" -TimeoutSeconds 30
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
            -EmbeddedWebvhRegistrationBearer $CoauthEmbeddedWebvhRegistrationBearer
        Invoke-CoauthMigrations -CoauthBinary $coauthBinary -ConfigPath $coauthConfigPath -LogDirectory $serviceLogDir
        $CoauthCommand = "& {0} server --config {1} --no-sync" -f (Quote-PsLiteral $coauthBinary), (Quote-PsLiteral $coauthConfigPath)
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

    # CT-6: starid (DID resolver) — env-driven, no external deps. Spawned
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

    # CT-6: teabay (directory) — needs a Postgres DSN. The validation block
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
            "`$env:SOLAND_OAUTH_INTROSPECTION_URL={0}; " +
            "`$env:SOLAND_OAUTH_INTROSPECTION_BEARER={1}; " +
            "`$env:SOLAND_SESSION_GRANT_INTROSPECTION_URL={2}; " +
            "`$env:SOLAND_SESSION_GRANT_INTROSPECTION_BEARER={3}; " +
            "`$env:SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER={4}; "
        ) -f `
            (Quote-PsLiteral "$coauthTrimmed/oauth/introspect"),
            (Quote-PsLiteral $CoauthOAuthIntrospectionBearer),
            (Quote-PsLiteral "$coauthTrimmed/api/v1/session-grants/introspect"),
            (Quote-PsLiteral $CoauthSessionGrantIntrospectionBearer),
            (Quote-PsLiteral $CoauthEmbeddedWebvhRegistrationBearer)
    }

    # CT-6: wire soland → starid (DID resolver) + soland → teabay
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
        ) -f (Quote-PsLiteral "$teabayTrimmed/api/v1/directory/announce")
    }

    function Build-SolandCommand {
        param(
            [Parameter(Mandatory = $true)][string]$BaseUrl,
            [Parameter(Mandatory = $true)][string]$ServiceDid,
            [Parameter(Mandatory = $true)][string]$ObjectsRoot,
            [Parameter(Mandatory = $true)][int]$Port,
            [string]$FederationPeers = ""
        )
        $federationEnv = ""
        if ($FederationPeers) {
            $federationEnv = (
                "`$env:SOLAND_FEDERATION_POLICY='Mesh'; " +
                "`$env:SOLAND_FEDERATION_PEERS={0}; "
            ) -f (Quote-PsLiteral $FederationPeers)
        }
        return (
            "`$env:DATABASE_URL=''; " +
            "`$env:SOLAND_PUBLIC_BASE_URL={0}; " +
            "`$env:SOLAND_SERVICE_DID={1}; " +
            "`$env:SOLAND_DEVELOPMENT_MODE='true'; " +
            "`$env:SOLAND_CORS_ALLOW_ORIGIN={2}; " +
            "`$env:SOLAND_OBJECT_STORAGE_BACKEND='filesystem'; " +
            "`$env:SOLAND_OBJECT_STORAGE_LOCAL_ROOT={3}; " +
            "{4}" +
            "{5}" +
            "{6}" +
            "{7}" +
            "cargo run --manifest-path {8} -- --bind 127.0.0.1:{9}"
        ) -f `
            (Quote-PsLiteral $BaseUrl),
            (Quote-PsLiteral $ServiceDid),
            (Quote-PsLiteral $YougenBaseUrl),
            (Quote-PsLiteral $ObjectsRoot),
            $solandCoauthEnv,
            $solandStaridEnv,
            $solandTeabayEnv,
            $federationEnv,
            (Quote-PsLiteral $SutManifest),
            $Port
    }

    if (-not $SolandCommand -and $solandPort) {
        $generatedSolandCommand = $true
        $alphaPeer = if ($DualSoland) { $solandBetaBaseUrl } else { "" }
        $SolandCommand = Build-SolandCommand `
            -BaseUrl $SolandBaseUrl `
            -ServiceDid $SolandServiceDid `
            -ObjectsRoot (Join-Path $jointDir "soland-objects") `
            -Port $solandPort `
            -FederationPeers $alphaPeer
    }
    if ($SolandCommand) {
        $solandWorkingDirectory = if ($generatedSolandCommand) { $repoRoot } else { Split-Path -Parent $SutManifest }
        $solandName = if ($DualSoland) { "soland-alpha" } else { "soland" }
        $managedServices.Add((Start-ManagedCommand -Name $solandName -Command $SolandCommand -WorkingDirectory $solandWorkingDirectory -LogDirectory $serviceLogDir))
    }
    Wait-HttpReady -Url "$($SolandBaseUrl.TrimEnd('/'))/health" -TimeoutSeconds $StartupTimeoutSeconds

    if ($DualSoland) {
        $solandBetaCommand = Build-SolandCommand `
            -BaseUrl $solandBetaBaseUrl `
            -ServiceDid $SolandBetaServiceDid `
            -ObjectsRoot (Join-Path $jointDir "soland-beta-objects") `
            -Port $solandBetaPort `
            -FederationPeers $SolandBaseUrl
        $managedServices.Add((Start-ManagedCommand -Name "soland-beta" -Command $solandBetaCommand -WorkingDirectory $repoRoot -LogDirectory $serviceLogDir))
        Wait-HttpReady -Url "$($solandBetaBaseUrl.TrimEnd('/'))/health" -TimeoutSeconds $StartupTimeoutSeconds
    }

    if (-not $YougenCommand -and $yougenPort) {
        $YougenCommand = "dx serve --platform web --addr 127.0.0.1 --port $yougenPort --open false --hot-reload false --watch false"
        $generatedYougenCommand = $true
    }
    if ($YougenCommand) {
        $yougenService = Start-ManagedCommand -Name "yougen" -Command $YougenCommand -WorkingDirectory $YougenRoot -LogDirectory $serviceLogDir
        $managedServices.Add($yougenService)
    }
    Wait-HttpReady -Url $YougenBaseUrl -TimeoutSeconds $StartupTimeoutSeconds
    if ($generatedYougenCommand) {
        Wait-LogContains -Path $yougenService.Stdout -Pattern "Build completed successfully" -TimeoutSeconds $StartupTimeoutSeconds
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
    if (-not $SkipBrowserInstall -and ($playwrightProjects -contains "chromium")) {
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
    $env:COTEST_YOUGEN_BASE_URL = $YougenBaseUrl
    if ($DualSoland) {
        $env:COTEST_SOLAND_ALPHA_BASE_URL = $SolandBaseUrl
        $env:COTEST_SOLAND_ALPHA_SERVICE_DID = $SolandServiceDid
        $env:COTEST_SOLAND_BETA_BASE_URL = $solandBetaBaseUrl
        $env:COTEST_SOLAND_BETA_SERVICE_DID = $SolandBetaServiceDid
    } else {
        Remove-Item Env:COTEST_SOLAND_ALPHA_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_SOLAND_ALPHA_SERVICE_DID -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_SOLAND_BETA_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_SOLAND_BETA_SERVICE_DID -ErrorAction SilentlyContinue
    }
    if ($CoauthBaseUrl) {
        $env:COTEST_COAUTH_BASE_URL = $CoauthBaseUrl.TrimEnd("/")
        $env:COTEST_COAUTH_SERVICE_DID = $CoauthServiceDid
    } else {
        Remove-Item Env:COTEST_COAUTH_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_COAUTH_SERVICE_DID -ErrorAction SilentlyContinue
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
    } else {
        Remove-Item Env:COTEST_MOCK_WITNESS_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_MOCK_WITNESS_DID -ErrorAction SilentlyContinue
    }

    $playwrightArgs = @("playwright", "test", "--config", "playwright.config.ts")
    foreach ($project in $playwrightProjects) {
        $playwrightArgs += @("--project", $project)
    }
    if ($Grep) {
        $playwrightArgs += @("--grep", $Grep)
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
        $playwrightOutput = & $npxCommand @playwrightArgs 2>&1
        $exitCode = $LASTEXITCODE
        $playwrightOutput | Set-Content -Path $playwrightStdout -Encoding UTF8
        "" | Set-Content -Path $playwrightStderr -Encoding UTF8
        $playwrightOutput | ForEach-Object { Write-Host $_ }
    }
    finally {
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
        $relative = [System.IO.Path]::GetRelativePath($jointDir, $file.FullName)
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
        $relative = [System.IO.Path]::GetRelativePath($jointDir, $file.FullName)
        $visualBaselineLines += "- [$relative]($relative)"
    }
}
$visualBaselineManifest = Join-Path $visualBaselineDir "manifest.jsonl"
if (Test-Path $visualBaselineManifest) {
    $relativeManifest = [System.IO.Path]::GetRelativePath($jointDir, $visualBaselineManifest)
    $visualBaselineLines += ""
    $visualBaselineLines += "- manifest: [$relativeManifest]($relativeManifest)"
}
$visualBaselineLines | Set-Content -Path $visualBaselineIndex -Encoding UTF8

# Scenario report: group junit testcases by spec file (= scenario) and emit
# pass / fail / skipped counts so reviewers can read scenario-level health
# without crunching the raw junit.xml.
$scenariosReport = Join-Path $jointDir "scenarios.md"
$junitPath = Join-Path $jointDir "junit.xml"
$scenarioLines = @("# joint e2e scenarios", "")
if (Test-Path $junitPath) {
    try {
        [xml]$junit = Get-Content -Path $junitPath -Raw
        # Playwright JUnit nests <testsuites><testsuite ...><testcase ...>; the
        # outer suite name is the project, inner suite name is the spec file.
        $suiteList = @($junit.testsuites.testsuite)
        $totals = [pscustomobject]@{
            passed = 0
            failed = 0
            skipped = 0
            fixme = 0
        }
        $scenarioGroups = @{}
        foreach ($suite in $suiteList) {
            $suiteName = if ($suite.name) { $suite.name } else { "<unnamed>" }
            # Try to extract the spec file name (e.g. "s1-single-server-triad.spec.ts").
            $specMatch = [regex]::Match($suiteName, "(s\d[a-zA-Z0-9\-]*\.spec\.ts)")
            $scenarioKey = if ($specMatch.Success) { $specMatch.Groups[1].Value } else { $suiteName }
            if (-not $scenarioGroups.ContainsKey($scenarioKey)) {
                $scenarioGroups[$scenarioKey] = New-Object System.Collections.Generic.List[object]
            }
            foreach ($case in @($suite.testcase)) {
                $caseName = if ($case.name) { $case.name } else { "<unnamed test>" }
                $status = "passed"
                if ($case.failure) { $status = "failed"; $totals.failed += 1 }
                elseif ($case.skipped) {
                    $status = "skipped"; $totals.skipped += 1
                    if ($caseName -match "fixme|fixmed") { $status = "fixme"; $totals.fixme += 1; $totals.skipped -= 1 }
                }
                else { $totals.passed += 1 }
                $time = if ($case.time) { [math]::Round([double]$case.time, 2) } else { 0 }
                $scenarioGroups[$scenarioKey].Add([pscustomobject]@{
                    name = $caseName
                    status = $status
                    time = $time
                }) | Out-Null
            }
        }
        $scenarioLines += "## totals"
        $scenarioLines += ""
        $scenarioLines += "- passed: $($totals.passed)"
        $scenarioLines += "- failed: $($totals.failed)"
        $scenarioLines += "- skipped: $($totals.skipped)"
        $scenarioLines += "- fixme (pending spec implementation): $($totals.fixme)"
        $scenarioLines += ""
        foreach ($key in $scenarioGroups.Keys | Sort-Object) {
            $scenarioLines += "## $key"
            $scenarioLines += ""
            foreach ($case in $scenarioGroups[$key]) {
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
    } catch {
        $scenarioLines += "- failed to parse junit.xml: $($_.Exception.Message)"
    }
} else {
    $scenarioLines += "- junit.xml not present; playwright may have failed before emitting reports"
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
    soland_base_url = $SolandBaseUrl
    soland_service_did = $SolandServiceDid
    soland_beta_base_url = $solandBetaBaseUrl
    soland_beta_service_did = if ($DualSoland) { $SolandBetaServiceDid } else { $null }
    dual_soland = [bool]$DualSoland
    mock_idp_base_url = $mockIdpBaseUrl
    mock_email_base_url = $mockEmailBaseUrl
    mock_witness_base_url = $mockWitnessBaseUrl
    mock_witness_did = if ($mockWitnessBaseUrl) { $MockWitnessDid } else { $null }
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
    coauth_session_grant_introspection_url = if ($CoauthBaseUrl) { "$($CoauthBaseUrl.TrimEnd('/'))/api/v1/session-grants/introspect" } else { $null }
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
- soland_base_url: $($summary.soland_base_url)
- soland_service_did: $($summary.soland_service_did)
- soland_beta_base_url: $($summary.soland_beta_base_url)
- soland_beta_service_did: $($summary.soland_beta_service_did)
- dual_soland: $($summary.dual_soland)
- mock_idp_base_url: $($summary.mock_idp_base_url)
- mock_email_base_url: $($summary.mock_email_base_url)
- mock_witness_base_url: $($summary.mock_witness_base_url)
- mock_witness_did: $($summary.mock_witness_did)
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
- services: $($summary.services)
"@ | Set-Content -Path $summaryMd -Encoding UTF8

Copy-ToLatest -RunJointDir $jointDir -LatestJointDir $latestJointDir

Write-Host ""
Write-Host "Joint E2E Summary"
Write-Host "  status      : $($summary.status)"
Write-Host "  profile     : $($summary.run_profile)"
Write-Host "  projects    : $($summary.playwright_projects)"
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
}
Write-Host "  yougen      : $YougenBaseUrl"
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
