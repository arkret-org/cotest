[CmdletBinding()]
param(
    [string]$SutManifest,
    [string]$OutputRoot,
    [string]$CargoTestTarget,
    [string]$CargoTestFilter,
    [string]$CoauthBaseUrl,
    [string]$FloriaBaseUrl,
    [string]$SodminBaseUrl,
    [string]$InksonBaseUrl,
    [string]$CoauthCommand,
    [string]$FloriaCommand,
    [string]$SodminCommand,
    [string]$InksonCommand,
    [string]$CoauthHealthUrl,
    [string]$FloriaHealthUrl,
    [string]$SodminHealthUrl,
    [string]$InksonHealthUrl,
    [int]$StartupTimeoutSeconds = 120,
    [switch]$AllowSecretLeaks,
    [switch]$FailOnCoverageRegression
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Normalize-BaseUrl {
    param([AllowNull()][string]$Value)

    if (-not $Value) {
        return $null
    }
    $trimmed = $Value.Trim().TrimEnd("/")
    if ($trimmed.Length -eq 0) {
        return $null
    }
    return $trimmed
}

function Resolve-HealthUrl {
    param(
        [AllowNull()][string]$BaseUrl,
        [AllowNull()][string]$HealthUrl
    )

    if ($HealthUrl) {
        return $HealthUrl
    }
    if ($BaseUrl) {
        return "$BaseUrl/health"
    }
    return $null
}

function Save-EnvVar {
    param([Parameter(Mandatory = $true)][string]$Name)

    [pscustomobject]@{
        Name   = $Name
        Exists = Test-Path "Env:$Name"
        Value  = [Environment]::GetEnvironmentVariable($Name)
    }
}

function Restore-EnvVar {
    param([Parameter(Mandatory = $true)]$Entry)

    if ($Entry.Exists) {
        [Environment]::SetEnvironmentVariable($Entry.Name, $Entry.Value)
    } else {
        Remove-Item "Env:$($Entry.Name)" -ErrorAction SilentlyContinue
    }
}

function Start-ManagedService {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()][string]$Command,
        [AllowNull()][string]$BaseUrl,
        [AllowNull()][string]$HealthUrl,
        [Parameter(Mandatory = $true)][string]$LogRoot
    )

    if (-not $Command) {
        return $null
    }

    $resolvedHealthUrl = Resolve-HealthUrl -BaseUrl $BaseUrl -HealthUrl $HealthUrl
    if (-not $resolvedHealthUrl) {
        throw "$Name command was supplied but no base URL or health URL was provided"
    }

    $stdout = Join-Path $LogRoot "$Name.stdout.log"
    $stderr = Join-Path $LogRoot "$Name.stderr.log"
    $process = Start-Process `
        -FilePath "powershell" `
        -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $Command) `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -WindowStyle Hidden `
        -PassThru

    [pscustomobject]@{
        Name      = $Name
        Process   = $process
        HealthUrl = $resolvedHealthUrl
        Stdout    = $stdout
        Stderr    = $stderr
    }
}

function Wait-ManagedService {
    param(
        [Parameter(Mandatory = $true)]$Service,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if ($Service.Process.HasExited) {
            $stdout = if (Test-Path $Service.Stdout) { Get-Content $Service.Stdout -Raw } else { "" }
            $stderr = if (Test-Path $Service.Stderr) { Get-Content $Service.Stderr -Raw } else { "" }
            throw "$($Service.Name) exited before health check passed. stdout: $stdout stderr: $stderr"
        }

        try {
            $response = Invoke-WebRequest -Uri $Service.HealthUrl -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
                return
            }
        } catch {
            Start-Sleep -Seconds 1
            continue
        }
        Start-Sleep -Seconds 1
    }

    throw "$($Service.Name) did not become healthy at $($Service.HealthUrl) within $TimeoutSeconds seconds"
}

function Stop-ManagedService {
    param([Parameter(Mandatory = $true)]$Service)

    if (-not $Service.Process.HasExited) {
        Stop-Process -Id $Service.Process.Id -Force -ErrorAction SilentlyContinue
        $Service.Process.WaitForExit()
    }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$workspaceRoot = (Resolve-Path (Join-Path $repoRoot "..")).Path
$logRoot = Join-Path $repoRoot "artifacts\compose"
$null = New-Item -ItemType Directory -Force -Path $logRoot

if (-not $SutManifest) {
    $SutManifest = Join-Path $workspaceRoot "soland\Cargo.toml"
}

$coauthBase = Normalize-BaseUrl $CoauthBaseUrl
$floriaBase = Normalize-BaseUrl $FloriaBaseUrl
$sodminBase = Normalize-BaseUrl $SodminBaseUrl
$inksonBase = Normalize-BaseUrl $InksonBaseUrl

$envNames = @(
    "COAUTH_BASE_URL",
    "FLORIA_BASE_URL",
    "SODMIN_BASE_URL",
    "INKSON_BASE_URL",
    "COTEST_COMPOSE_PROFILE"
)
$originalEnv = @($envNames | ForEach-Object { Save-EnvVar $_ })
$managedServices = New-Object System.Collections.Generic.List[object]
$exitCode = 1

try {
    $env:COTEST_COMPOSE_PROFILE = "process"
    if ($coauthBase) { $env:COAUTH_BASE_URL = $coauthBase }
    if ($floriaBase) { $env:FLORIA_BASE_URL = $floriaBase }
    if ($sodminBase) { $env:SODMIN_BASE_URL = $sodminBase }
    if ($inksonBase) { $env:INKSON_BASE_URL = $inksonBase }

    foreach ($service in @(
            [pscustomobject]@{ Name = "coauth"; Command = $CoauthCommand; BaseUrl = $coauthBase; HealthUrl = $CoauthHealthUrl },
            [pscustomobject]@{ Name = "floria"; Command = $FloriaCommand; BaseUrl = $floriaBase; HealthUrl = $FloriaHealthUrl },
            [pscustomobject]@{ Name = "sodmin"; Command = $SodminCommand; BaseUrl = $sodminBase; HealthUrl = $SodminHealthUrl },
            [pscustomobject]@{ Name = "inkson"; Command = $InksonCommand; BaseUrl = $inksonBase; HealthUrl = $InksonHealthUrl }
        )) {
        $managed = Start-ManagedService `
            -Name $service.Name `
            -Command $service.Command `
            -BaseUrl $service.BaseUrl `
            -HealthUrl $service.HealthUrl `
            -LogRoot $logRoot
        if ($managed) {
            $managedServices.Add($managed)
            Wait-ManagedService -Service $managed -TimeoutSeconds $StartupTimeoutSeconds
        }
    }

    $runCotestArgs = @{
        Runtime     = "process"
        Profile     = "compose"
        SutManifest = $SutManifest
    }
    if ($OutputRoot) {
        $runCotestArgs.OutputRoot = $OutputRoot
    }
    if ($CargoTestTarget) {
        $runCotestArgs.CargoTestTarget = $CargoTestTarget
    }
    if ($CargoTestFilter) {
        $runCotestArgs.CargoTestFilter = $CargoTestFilter
    }
    if ($AllowSecretLeaks) {
        $runCotestArgs.AllowSecretLeaks = $true
    }
    if ($FailOnCoverageRegression) {
        $runCotestArgs.FailOnCoverageRegression = $true
    }

    & (Join-Path $PSScriptRoot "run-server-conformance.ps1") @runCotestArgs
    $exitCode = $LASTEXITCODE
}
finally {
    for ($index = $managedServices.Count - 1; $index -ge 0; $index--) {
        Stop-ManagedService -Service $managedServices[$index]
    }
    foreach ($entry in $originalEnv) {
        Restore-EnvVar $entry
    }
}

exit $exitCode
