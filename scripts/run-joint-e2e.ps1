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
    [ValidateSet("joint-smoke", "joint-full")]
    [string]$RunProfile,
    [string]$PlaywrightProject = "chrome",
    [string]$Grep
)

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
        return @("chrome", "mobile-chrome", "visual-chrome")
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
    $generateOutput = & $CoauthBinary config generate 2>&1
    if ($LASTEXITCODE -ne 0) {
        $generateOutput | Set-Content -Path (Join-Path $JointDir "coauth-config-generate.log") -Encoding UTF8
        throw "coauth config generate failed"
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
            -SolandBaseUrl $SolandBaseUrl `
            -SolandCommand $SolandCommand `
            -YougenBaseUrl $YougenBaseUrl `
            -YougenCommand $YougenCommand `
            -JsonPath $preflightJson `
            -MarkdownPath $preflightMd
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

    if (-not $SolandCommand -and $solandPort) {
        $generatedSolandCommand = $true
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
                (Quote-PsLiteral "$coauthTrimmed/oauth2/introspect"),
                (Quote-PsLiteral $CoauthOAuthIntrospectionBearer),
                (Quote-PsLiteral "$coauthTrimmed/api/v1/session-grants/introspect"),
                (Quote-PsLiteral $CoauthSessionGrantIntrospectionBearer),
                (Quote-PsLiteral $CoauthEmbeddedWebvhRegistrationBearer)
        }
        $SolandCommand = (
            "`$env:DATABASE_URL=''; " +
            "`$env:SOLAND_PUBLIC_BASE_URL={0}; " +
            "`$env:SOLAND_SERVICE_DID={1}; " +
            "`$env:SOLAND_DEVELOPMENT_MODE='true'; " +
            "`$env:SOLAND_CORS_ALLOW_ORIGIN={2}; " +
            "`$env:SOLAND_OBJECT_STORAGE_BACKEND='filesystem'; " +
            "`$env:SOLAND_OBJECT_STORAGE_LOCAL_ROOT={3}; " +
            "{4}" +
            "cargo run --manifest-path {5} -- --bind 127.0.0.1:{6}"
        ) -f `
            (Quote-PsLiteral $SolandBaseUrl),
            (Quote-PsLiteral $SolandServiceDid),
            (Quote-PsLiteral $YougenBaseUrl),
            (Quote-PsLiteral (Join-Path $jointDir "soland-objects")),
            $solandCoauthEnv,
            (Quote-PsLiteral $SutManifest),
            $solandPort
    }
    if ($SolandCommand) {
        $solandWorkingDirectory = if ($generatedSolandCommand) { $repoRoot } else { Split-Path -Parent $SutManifest }
        $managedServices.Add((Start-ManagedCommand -Name "soland" -Command $SolandCommand -WorkingDirectory $solandWorkingDirectory -LogDirectory $serviceLogDir))
    }
    Wait-HttpReady -Url "$($SolandBaseUrl.TrimEnd('/'))/health" -TimeoutSeconds $StartupTimeoutSeconds

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
    if ($CoauthBaseUrl) {
        $env:COTEST_COAUTH_BASE_URL = $CoauthBaseUrl.TrimEnd("/")
        $env:COTEST_COAUTH_SERVICE_DID = $CoauthServiceDid
    } else {
        Remove-Item Env:COTEST_COAUTH_BASE_URL -ErrorAction SilentlyContinue
        Remove-Item Env:COTEST_COAUTH_SERVICE_DID -ErrorAction SilentlyContinue
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
    yougen_base_url = $YougenBaseUrl
    coauth_base_url = if ($CoauthBaseUrl) { $CoauthBaseUrl } else { $null }
    coauth_service_did = if ($CoauthBaseUrl) { $CoauthServiceDid } else { $null }
    coauth_config = $coauthConfigPath
    coauth_postgres_container = if ($ephemeralPostgres) { $ephemeralPostgres.ContainerName } else { $null }
    coauth_oauth_introspection_url = if ($CoauthBaseUrl) { "$($CoauthBaseUrl.TrimEnd('/'))/oauth2/introspect" } else { $null }
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
- yougen_base_url: $($summary.yougen_base_url)
- coauth_base_url: $($summary.coauth_base_url)
- coauth_service_did: $($summary.coauth_service_did)
- coauth_config: $($summary.coauth_config)
- coauth_oauth_introspection_url: $($summary.coauth_oauth_introspection_url)
- coauth_session_grant_introspection_url: $($summary.coauth_session_grant_introspection_url)
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
- services: $($summary.services)
"@ | Set-Content -Path $summaryMd -Encoding UTF8

Copy-ToLatest -RunJointDir $jointDir -LatestJointDir $latestJointDir

Write-Host ""
Write-Host "Joint E2E Summary"
Write-Host "  status      : $($summary.status)"
Write-Host "  profile     : $($summary.run_profile)"
Write-Host "  projects    : $($summary.playwright_projects)"
Write-Host "  soland      : $SolandBaseUrl"
Write-Host "  yougen      : $YougenBaseUrl"
if ($CoauthBaseUrl) {
    Write-Host "  coauth      : $CoauthBaseUrl"
}
Write-Host "  screenshots : $screenshotDir"
Write-Host "  visual base : $visualBaselineDir"
Write-Host "  report      : $summaryMd"
Write-Host "  latest      : $latestJointDir"

exit $exitCode
