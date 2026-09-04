<#
.SYNOPSIS
Performs the one-time Windows administrator initialization for joint E2E hosts access.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateRange(1, 32)][int]$ServerCount = 1,
    [string]$TestUser,
    [string]$HostsPath,
    [string]$StateDirectory
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "lib\joint-e2e-environment.ps1")

$platform = Get-CotestPlatformInfo
if ($platform.os -ne "windows") { throw "Privileged hosts setup is not yet supported on $($platform.os); no changes were made." }
if (-not (Test-CotestAdministrator)) { throw "setup-joint-e2e-hosts.ps1 must run in an elevated Administrator PowerShell." }
$resolvedHostsPath = Get-CotestHostsPath -Override $HostsPath
if (-not $TestUser) { $TestUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name }
if (-not $StateDirectory) { $StateDirectory = Join-Path $env:ProgramData "cotest\joint-e2e-hosts" }
$StateDirectory = [System.IO.Path]::GetFullPath($StateDirectory)
$manifestPath = Join-Path $StateDirectory "manifest.json"
$backupPath = Join-Path $StateDirectory "hosts.original"
$aclPath = Join-Path $StateDirectory "hosts-acl.clixml"
$logPath = Join-Path $StateDirectory "setup.log"
$originalAcl = $null
$probeMarker = $null

if (Test-Path -LiteralPath $manifestPath) {
    $existing = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
    if ($existing.hosts_path -ne $resolvedHostsPath -or $existing.test_user -ne $TestUser) {
        throw "An initialization exists for a different hosts path or test user. Run restore-joint-e2e-hosts.ps1 first."
    }
    Write-Host "Joint E2E hosts access is already initialized for $TestUser (idempotent no-op)."
    exit 0
}

$null = New-Item -ItemType Directory -Force -Path $StateDirectory
try {
    [System.IO.File]::WriteAllBytes($backupPath, [System.IO.File]::ReadAllBytes($resolvedHostsPath))
    $originalAcl = Get-Acl -LiteralPath $resolvedHostsPath
    $originalAcl | Export-Clixml -LiteralPath $aclPath
    $backupHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $backupPath).Hash.ToLowerInvariant()
    $identity = [Security.Principal.NTAccount]::new($TestUser)
    $sid = $identity.Translate([Security.Principal.SecurityIdentifier]).Value
    if ($PSCmdlet.ShouldProcess($resolvedHostsPath, "grant Modify to $TestUser")) {
        $icaclsOutput = & icacls.exe $resolvedHostsPath /grant "${TestUser}:(M)" 2>&1
        if ($LASTEXITCODE -ne 0) { throw "icacls grant failed: $($icaclsOutput -join ' ')" }
    }
    $probeMarker = New-CotestHostsMarker -RunId "setup-probe-$PID"
    $before = [System.IO.File]::ReadAllText($resolvedHostsPath)
    $withProbe = Add-CotestHostsBlock -Content $before -Hosts (Get-CotestJointHostNames -ServerCount $ServerCount -IncludeCoauth $true -IncludeUnregisteredProbe $true) -Marker $probeMarker
    [System.IO.File]::WriteAllText($resolvedHostsPath, $withProbe, [System.Text.UTF8Encoding]::new($false))
    $afterProbe = [System.IO.File]::ReadAllText($resolvedHostsPath)
    foreach ($hostName in (Get-CotestJointHostNames -ServerCount $ServerCount -IncludeCoauth $true -IncludeUnregisteredProbe $true)) {
        $answers = [Net.Dns]::GetHostAddresses($hostName)
        if ($answers.Count -eq 0 -or @($answers | Where-Object { -not [Net.IPAddress]::IsLoopback($_) }).Count -gt 0) {
            throw "hosts setup probe resolved $hostName outside loopback"
        }
    }
    $cleaned = Remove-CotestHostsBlocks -Content $afterProbe -Marker $probeMarker
    [System.IO.File]::WriteAllText($resolvedHostsPath, $cleaned, [System.Text.UTF8Encoding]::new($false))
    if ((Get-CotestHostsMarkers -Content ([System.IO.File]::ReadAllText($resolvedHostsPath))).Count -ne 0) { throw "setup probe marker cleanup failed" }
    $manifest = [pscustomobject]@{
        schema = "cotest.joint-hosts-setup.v1"
        created_at = (Get-Date).ToUniversalTime().ToString("o")
        hosts_path = $resolvedHostsPath
        test_user = $TestUser
        test_user_sid = $sid
        backup_path = $backupPath
        backup_sha256 = $backupHash
        acl_backup_path = $aclPath
        acl_sddl = $originalAcl.Sddl
        acl_owner = $originalAcl.Owner
        permission = "Modify"
    }
    $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM
    "$(Get-Date -Format o) initialized hosts access for $TestUser ($sid)" | Set-Content -LiteralPath $logPath -Encoding utf8NoBOM
    Write-Host "Joint E2E hosts access initialized for $TestUser. Recovery state: $StateDirectory"
} catch {
    try {
        if (Test-Path -LiteralPath $resolvedHostsPath) {
            $current = [System.IO.File]::ReadAllText($resolvedHostsPath)
            $cleaned = if ($probeMarker) {
                Remove-CotestHostsBlocks -Content $current -Marker $probeMarker
            } else {
                $current
            }
            [System.IO.File]::WriteAllText($resolvedHostsPath, $cleaned, [System.Text.UTF8Encoding]::new($false))
        }
        if ($originalAcl) { Set-Acl -LiteralPath $resolvedHostsPath -AclObject $originalAcl }
    } catch {
        Write-Warning "Automatic ACL/content rollback also failed; use the recovery files in $StateDirectory"
    }
    Write-Error "Setup failed closed. Recovery files, when created, are in $StateDirectory. $($_.Exception.Message)"
    throw
}
