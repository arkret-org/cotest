<#
.SYNOPSIS
Performs a read-only readiness check for the cotest joint E2E environment.
.DESCRIPTION
The check reports every missing prerequisite in one pass. It never installs
software, changes the hosts file, starts Docker containers, or changes ACLs.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 32)][int]$ServerCount = 1,
    [switch]$StartCoauth,
    [string]$OutputDirectory,
    [string]$HostsPath,
    [switch]$AllowUninitializedHostsAcl
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "lib\joint-e2e-environment.ps1")

if (-not $OutputDirectory) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutputDirectory = Join-Path (Split-Path -Parent $PSScriptRoot) "artifacts\environment\$stamp"
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$null = New-Item -ItemType Directory -Force -Path $OutputDirectory
$platform = Get-CotestPlatformInfo
$resolvedHostsPath = Get-CotestHostsPath -Override $HostsPath
$results = [System.Collections.Generic.List[object]]::new()

function Add-Check {
    param([string]$Name, [ValidateSet("pass", "fail", "warn", "unsupported")][string]$Status, [string]$Detail, [string[]]$Repair = @())
    $results.Add([pscustomobject]@{ name = $Name; status = $Status; detail = $Detail; repair = @($Repair) })
}

function Find-Tool {
    param([string]$Name, [string[]]$Arguments = @("--version"), [bool]$Required = $true)
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $command) {
        Add-Check $Name $(if ($Required) { "fail" } else { "warn" }) "not found on PATH"
        return
    }
    $version = (& $command.Source @Arguments 2>&1 | Out-String).Trim()
    Add-Check $Name "pass" "path=$($command.Source); version=$version"
}

Add-Check "platform" "pass" "os=$($platform.os); architecture=$($platform.architecture); shell=$($platform.shell) $($platform.shell_version); package_managers=$((@($platform.package_managers.name) -join ','))"
Find-Tool "node"
Find-Tool "npm"
Find-Tool "npx"
Find-Tool "openssl"
Find-Tool "cargo"
Find-Tool "rustc"
Find-Tool "docker" @("--version") $StartCoauth.IsPresent

$e2eRoot = Join-Path (Split-Path -Parent $PSScriptRoot) "e2e"
$playwrightPackage = Join-Path $e2eRoot "node_modules\@playwright\test\package.json"
if (Test-Path -LiteralPath $playwrightPackage) {
    $package = Get-Content -Raw -LiteralPath $playwrightPackage | ConvertFrom-Json
    Add-Check "playwright package" "pass" "path=$playwrightPackage; version=$($package.version)"
    if (Get-Command npx -ErrorAction SilentlyContinue) {
        $browserProbe = (& npx --prefix $e2eRoot playwright install --dry-run chromium 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -eq 0) { Add-Check "playwright chromium" "pass" $browserProbe } else { Add-Check "playwright chromium" "fail" $browserProbe @("Push-Location '$e2eRoot'; npx playwright install chromium; Pop-Location") }
    } else {
        Add-Check "playwright chromium" "fail" "npx is unavailable"
    }
} else {
    Add-Check "playwright package" "fail" "missing $playwrightPackage" @("Push-Location '$e2eRoot'; npm ci; Pop-Location")
}

$caddy = Get-CotestCaddyInspection
$caddyRepair = if ($caddy.status -eq "pass") { @() } else { @(Get-CotestCaddyRepairAdvice -PlatformInfo $platform) }
Add-Check "caddy" $caddy.status $caddy.detail $caddyRepair

if (-not (Test-Path -LiteralPath $resolvedHostsPath -PathType Leaf)) {
    Add-Check "hosts file" "fail" "not found: $resolvedHostsPath"
} else {
    try {
        $content = [System.IO.File]::ReadAllText($resolvedHostsPath)
        Add-Check "hosts readable" "pass" $resolvedHostsPath
        $staleMarkers = @(Get-CotestHostsMarkers -Content $content)
        if ($staleMarkers.Count -gt 0) {
            Add-Check "hosts stale markers" "fail" "found=$($staleMarkers -join ',')" @("Run the platform restore script as administrator: pwsh -NoProfile -File '$PSScriptRoot\restore-joint-e2e-hosts.ps1'")
        } else {
            Add-Check "hosts stale markers" "pass" "none"
        }
        try {
            $stream = [System.IO.File]::Open($resolvedHostsPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite)
            $stream.Dispose()
            Add-Check "hosts runner access" "pass" "current user can perform run-scoped writes"
        } catch {
            $status = if ($AllowUninitializedHostsAcl) { "warn" } else { "fail" }
            $repair = if ($platform.os -eq "windows") {
                $currentTestUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name.Replace("'", "''")
                @("Run as administrator: pwsh -NoProfile -File '$PSScriptRoot\setup-joint-e2e-hosts.ps1' -ServerCount $ServerCount -TestUser '$currentTestUser'")
            } else {
                @("The hosts setup adapter is not yet supported on $($platform.os); use a reviewed privileged helper for $resolvedHostsPath.")
            }
            Add-Check "hosts runner access" $status $_.Exception.Message $repair
        }
    } catch {
        Add-Check "hosts readable" "fail" $_.Exception.Message
    }
}

if ($platform.os -ne "windows") {
    Add-Check "hosts setup adapter" "unsupported" "read-only detection is supported; privileged setup/rollback is currently implemented only for Windows"
} else {
    Add-Check "hosts setup adapter" "pass" "Windows ACL backup/grant/restore adapter available"
}

$requiredHosts = @(Get-CotestJointHostNames -ServerCount $ServerCount -IncludeCoauth $StartCoauth.IsPresent -IncludeUnregisteredProbe $true)
$portsPerServer = if ($StartCoauth) { 4 } else { 2 }
$minimumMemoryGb = [math]::Max(4, 2 + ($ServerCount * $(if ($StartCoauth) { 2 } else { 1 })))
Add-Check "topology budget" "pass" "servers=$ServerCount; hosts=$($requiredHosts -join ','); estimated_tcp_ports=$($ServerCount * $portsPerServer + 1); recommended_memory_gb=$minimumMemoryGb; independent_databases=$($ServerCount * $(if ($StartCoauth) { 2 } else { 1 }))"
$availableMemoryGb = if ($platform.os -eq "windows") { [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB, 2) } else { $null }
if ($null -ne $availableMemoryGb) {
    Add-Check "available memory" $(if ($availableMemoryGb -ge $minimumMemoryGb) { "pass" } else { "fail" }) "available_gb=$availableMemoryGb; required_gb=$minimumMemoryGb"
}
$outputDrive = [System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($OutputDirectory))
$freeDiskGb = [math]::Round($outputDrive.AvailableFreeSpace / 1GB, 2)
Add-Check "artifact disk" $(if ($freeDiskGb -ge 10) { "pass" } else { "fail" }) "path=$OutputDirectory; free_gb=$freeDiskGb; required_gb=10"
if ($StartCoauth) {
    $dockerCommand = Get-Command docker -ErrorAction SilentlyContinue
    if ($dockerCommand) {
        $dockerInfo = (& $dockerCommand.Source info 2>&1 | Out-String).Trim()
        Add-Check "docker daemon" $(if ($LASTEXITCODE -eq 0) { "pass" } else { "fail" }) $dockerInfo
        $postgresInspect = (& $dockerCommand.Source image inspect postgres:16-alpine 2>&1 | Out-String).Trim()
        Add-Check "postgres image" $(if ($LASTEXITCODE -eq 0) { "pass" } else { "fail" }) $(if ($LASTEXITCODE -eq 0) { "postgres:16-alpine present" } else { $postgresInspect }) @("docker pull postgres:16-alpine")
    }
}

$report = [pscustomobject]@{
    schema = "cotest.joint-preflight.v1"
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    platform = $platform
    server_count = $ServerCount
    start_coauth = $StartCoauth.IsPresent
    hosts_path = $resolvedHostsPath
    required_hosts = $requiredHosts
    caddy = $caddy
    results = @($results)
    passed = (@($results | Where-Object { $_.status -eq "fail" }).Count -eq 0)
}
$jsonPath = Join-Path $OutputDirectory "preflight.json"
$markdownPath = Join-Path $OutputDirectory "preflight.md"
$report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $jsonPath -Encoding utf8NoBOM
$lines = @("# Joint E2E preflight", "", "- Platform: $($platform.os)/$($platform.architecture)", "- Server count: $ServerCount", "- Hosts path: $resolvedHostsPath", "- Passed: $($report.passed)", "")
foreach ($result in $results) {
    $lines += "- [$($result.status)] $($result.name): $($result.detail)"
    foreach ($repair in @($result.repair)) { $lines += "  - Repair: ``$repair``" }
}
$lines | Set-Content -LiteralPath $markdownPath -Encoding utf8NoBOM
foreach ($result in $results) { Write-Host "[$($result.status)] $($result.name): $($result.detail)" }
Write-Host "Preflight report: $OutputDirectory"
if (-not $report.passed) { exit 2 }
