<#
.SYNOPSIS
Removes cotest hosts blocks and restores the ACL saved by setup-joint-e2e-hosts.ps1.
#>
[CmdletBinding(SupportsShouldProcess)]
param([string]$StateDirectory, [string]$HostsPath)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "lib\joint-e2e-environment.ps1")
if (-not $IsWindows) { throw "Privileged hosts rollback is not yet supported on this platform; no changes were made." }
if (-not (Test-CotestAdministrator)) { throw "restore-joint-e2e-hosts.ps1 must run in an elevated Administrator PowerShell." }
if (-not $StateDirectory) { $StateDirectory = Join-Path $env:ProgramData "cotest\joint-e2e-hosts" }
$manifestPath = Join-Path $StateDirectory "manifest.json"
if (-not (Test-Path -LiteralPath $manifestPath)) {
    $resolvedHostsPath = Get-CotestHostsPath -Override $HostsPath
    $current = [System.IO.File]::ReadAllText($resolvedHostsPath)
    $markers = @(Get-CotestHostsMarkers -Content $current)
    if ($markers.Count -eq 0) {
        Write-Host "No joint E2E hosts initialization or stale run marker exists; nothing to restore."
        exit 0
    }
    if ($PSCmdlet.ShouldProcess($resolvedHostsPath, "remove stale cotest run markers without changing ACLs")) {
        $cleaned = Remove-CotestHostsBlocks -Content $current
        [System.IO.File]::WriteAllText($resolvedHostsPath, $cleaned, [System.Text.UTF8Encoding]::new($false))
    }
    $null = New-Item -ItemType Directory -Force -Path $StateDirectory
    $staleLog = Join-Path $StateDirectory "stale-marker-cleanup-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
    "$(Get-Date -Format o) removed stale markers $($markers -join ',') from $resolvedHostsPath; ACL unchanged" | Set-Content -LiteralPath $staleLog -Encoding utf8NoBOM
    Write-Host "Removed stale cotest hosts markers without changing ACLs. Log: $staleLog"
    exit 0
}
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
$resolvedHostsPath = Get-CotestHostsPath -Override $(if ($HostsPath) { $HostsPath } else { $manifest.hosts_path })
if ($resolvedHostsPath -ne $manifest.hosts_path) { throw "Requested hosts path differs from the setup manifest" }
$actualBackupHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $manifest.backup_path).Hash.ToLowerInvariant()
if ($actualBackupHash -ne $manifest.backup_sha256) { throw "Hosts recovery backup checksum mismatch; refusing rollback. Recover manually from $($manifest.backup_path)." }
try {
    $current = [System.IO.File]::ReadAllText($resolvedHostsPath)
    $cleaned = Remove-CotestHostsBlocks -Content $current
    if ($PSCmdlet.ShouldProcess($resolvedHostsPath, "remove cotest markers and restore original ACL")) {
        [System.IO.File]::WriteAllText($resolvedHostsPath, $cleaned, [System.Text.UTF8Encoding]::new($false))
        $restoredAcl = Get-Acl -LiteralPath $resolvedHostsPath
        $restoredAcl.SetSecurityDescriptorSddlForm([string]$manifest.acl_sddl)
        Set-Acl -LiteralPath $resolvedHostsPath -AclObject $restoredAcl
    }
    $rollbackLog = Join-Path $StateDirectory "rollback-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
    "$(Get-Date -Format o) removed cotest markers and restored ACL for $resolvedHostsPath" | Set-Content -LiteralPath $rollbackLog -Encoding utf8NoBOM
    Remove-Item -LiteralPath $manifestPath
    Write-Host "Joint E2E hosts access restored. Non-cotest hosts content was preserved. Log: $rollbackLog"
} catch {
    Write-Error "Rollback failed closed. Manual recovery backup: $($manifest.backup_path). $($_.Exception.Message)"
    throw
}
