<#
.SYNOPSIS
Checks the joint E2E environment and installs missing prerequisites when possible.
.DESCRIPTION
Every invocation attempts supported missing dependency installations. Hosts ACL
initialization is the only operation that requires an elevated Windows process.
Failed commands are reported with an instruction to retry from an elevated shell.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateRange(1, 32)][int]$ServerCount = 1,
    [ValidateSet('local.host', 'localhost')][string]$DnsSuffix = 'local.host',
    [switch]$StartCoauth,
    # Browserless profiles still use Playwright's test runner, but do not need
    # its multi-hundred-megabyte Chromium payload.
    [switch]$RequireBrowser,
    [switch]$RequireDocker,
    [string[]]$PostgresImage = @("postgres:18.6-alpine"),
    [string]$OutputDirectory,
    [string]$HostsPath,
    [string]$TestUser,
    [string]$StateDirectory
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "lib\joint-e2e-environment.ps1")

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path (Split-Path -Parent $PSScriptRoot) ("artifacts\environment\" + (Get-Date -Format "yyyyMMdd-HHmmss"))
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$null = New-Item -ItemType Directory -Force -Path $OutputDirectory
$platform = Get-CotestPlatformInfo
$isAdministrator = Test-CotestAdministrator
$resolvedHostsPath = Get-CotestHostsPath -Override $HostsPath
$e2eRoot = Join-Path (Split-Path -Parent $PSScriptRoot) "e2e"
$results = [System.Collections.Generic.List[object]]::new()
$actions = [System.Collections.Generic.List[object]]::new()

function Add-Check {
    param(
        [string]$Name,
        [ValidateSet("pass", "fail", "warn", "unsupported")][string]$Status,
        [string]$Detail,
        [string[]]$Repair = @()
    )
    $results.Add([pscustomobject]@{ name = $Name; status = $Status; detail = $Detail; repair = @($Repair) })
}

function Add-InstallAction {
    param([string]$Name, [string]$Status, [string]$Detail)
    $actions.Add([pscustomobject]@{ name = $Name; status = $Status; detail = $Detail })
}

function Update-CotestProcessPath {
    if (-not $IsWindows) { return }
    # Refresh from the persisted stores so a just-installed package becomes
    # visible, but keep the entries the caller handed this process first. A
    # plain overwrite silently discards a run-scoped PATH prefix, which makes a
    # tool that is installed-but-unregistered impossible to surface without
    # editing the machine or user environment.
    $inherited = @(($env:PATH -split ";") | Where-Object { $_ -and $_.Trim() })
    $persisted = @(
        @(
            [Environment]::GetEnvironmentVariable("Path", "Machine"),
            [Environment]::GetEnvironmentVariable("Path", "User")
        ) |
            Where-Object { $_ } |
            ForEach-Object { $_ -split ";" } |
            Where-Object { $_ -and $_.Trim() }
    )
    $ordered = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($entry in @($inherited + $persisted)) {
        $trimmed = $entry.TrimEnd("\")
        if ($seen.Add($trimmed)) { $ordered.Add($entry) | Out-Null }
    }
    $env:PATH = $ordered -join ";"
}

# Git for Windows and the standard Win64 OpenSSL installer both keep the
# executable outside the default PATH. run-joint-e2e.ps1 resolves those stable
# locations before it mints the run-scoped CA, so this gate MUST accept the
# same installations instead of failing a machine the runner can actually use.
function Find-CotestOpenSslPath {
    $command = Get-Command "openssl" -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
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

function Invoke-CotestPackageCommand {
    param([string]$Name, [string]$FilePath, [string[]]$Arguments)
    if (-not $PSCmdlet.ShouldProcess($Name, "install missing joint E2E prerequisite")) {
        Add-InstallAction $Name "skipped" "WhatIf or confirmation declined"
        return $false
    }
    try {
        $output = (& $FilePath @Arguments 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) { throw "$FilePath exited with $LASTEXITCODE`: $output" }
        Add-InstallAction $Name "installed" $output
        Update-CotestProcessPath
        return $true
    } catch {
        Add-InstallAction $Name "failed" "$($_.Exception.Message) Retry from an elevated PowerShell."
        return $false
    }
}

function Install-CotestVerifiedWingetPackage {
    param([string]$Name, [string]$PackageId)
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) { return $false }
    $show = (& $winget.Source show --id $PackageId --exact --accept-source-agreements 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        Add-InstallAction $Name "failed" "winget could not verify package id '$PackageId': $show"
        return $false
    }
    return Invoke-CotestPackageCommand -Name $Name -FilePath $winget.Source -Arguments @(
        "install", "--id", $PackageId, "--exact", "--accept-package-agreements", "--accept-source-agreements", "--silent"
    )
}

function Resolve-CotestCaddyWingetPackageId {
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) { return $null }
    $search = (& $winget.Source search --name Caddy --exact --accept-source-agreements 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        Add-InstallAction "caddy" "failed" "winget exact search failed: $search"
        return $null
    }
    $match = [regex]::Match($search, '(?m)^Caddy\s+(\S+)\s+[0-9]')
    if (-not $match.Success) {
        Add-InstallAction "caddy" "failed" "winget exact search did not resolve a package id; no id was guessed"
        return $null
    }
    return $match.Groups[1].Value
}

function Install-CotestWindowsPrerequisite {
    param(
        [string]$Name,
        [string]$WingetId,
        [string]$ChocolateyPackage,
        [string]$ScoopPackage
    )
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        return Install-CotestVerifiedWingetPackage -Name $Name -PackageId $WingetId
    }
    $choco = Get-Command choco -ErrorAction SilentlyContinue
    if ($choco -and $ChocolateyPackage) {
        return Invoke-CotestPackageCommand -Name $Name -FilePath $choco.Source -Arguments @("install", $ChocolateyPackage, "-y")
    }
    $scoop = Get-Command scoop -ErrorAction SilentlyContinue
    if ($scoop -and $ScoopPackage) {
        return Invoke-CotestPackageCommand -Name $Name -FilePath $scoop.Source -Arguments @("install", $ScoopPackage)
    }
    Add-InstallAction $Name "failed" "no supported Windows package manager is available"
    return $false
}

function Install-CotestCaddy {
    if ($platform.os -ne "windows") {
        Add-InstallAction "caddy" "failed" "automatic installation is currently supported only on Windows"
        return $false
    }
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        $packageId = Resolve-CotestCaddyWingetPackageId
        if (-not $packageId) { return $false }
        return Install-CotestVerifiedWingetPackage -Name "caddy" -PackageId $packageId
    }
    $choco = Get-Command choco -ErrorAction SilentlyContinue
    if ($choco) { return Invoke-CotestPackageCommand -Name "caddy" -FilePath $choco.Source -Arguments @("install", "caddy", "-y") }
    $scoop = Get-Command scoop -ErrorAction SilentlyContinue
    if ($scoop) { return Invoke-CotestPackageCommand -Name "caddy" -FilePath $scoop.Source -Arguments @("install", "caddy") }
    Add-InstallAction "caddy" "failed" "no supported Windows package manager is available"
    return $false
}

function Test-CotestPlaywrightChromium {
    $node = Get-Command node -ErrorAction SilentlyContinue
    $packagePath = Join-Path $e2eRoot "node_modules\@playwright\test\package.json"
    if (-not $node -or -not (Test-Path -LiteralPath $packagePath)) { return $false }
    Push-Location $e2eRoot
    try {
        $executablePath = (& $node.Source -e "const { chromium } = require('@playwright/test'); process.stdout.write(chromium.executablePath())" 2>$null | Out-String).Trim()
        return ($LASTEXITCODE -eq 0 -and $executablePath -and (Test-Path -LiteralPath $executablePath -PathType Leaf))
    } finally {
        Pop-Location
    }
}

function Initialize-CotestWindowsHostsAccess {
    if ($platform.os -ne "windows") {
        Add-InstallAction "hosts access" "failed" "privileged hosts initialization is currently supported only on Windows"
        return $false
    }
    if (-not $isAdministrator) { return $false }
    $targetUser = if ($TestUser) { $TestUser } else { [Security.Principal.WindowsIdentity]::GetCurrent().Name }
    $stateRoot = if ($StateDirectory) { $StateDirectory } else { Join-Path $env:ProgramData "cotest\joint-e2e-hosts" }
    $stateRoot = [System.IO.Path]::GetFullPath($stateRoot)
    $manifestPath = Join-Path $stateRoot "manifest.json"
    $backupPath = Join-Path $stateRoot "hosts.original"
    $aclPath = Join-Path $stateRoot "hosts-acl.clixml"
    $logPath = Join-Path $stateRoot "setup.log"

    if (Test-Path -LiteralPath $manifestPath) {
        $existing = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
        $sameUser = [string]::Equals([string]$existing.test_user, $targetUser, [System.StringComparison]::OrdinalIgnoreCase)
        if ($existing.hosts_path -ne $resolvedHostsPath -or -not $sameUser) {
            Add-InstallAction "hosts access" "failed" "initialization belongs to a different hosts path or user; run restore-joint-e2e-hosts.ps1 manually first"
            return $false
        }
        Add-InstallAction "hosts access" "ready" "already initialized for $targetUser"
        return $true
    }

    $currentHosts = [System.IO.File]::ReadAllText($resolvedHostsPath)
    $staleMarkers = @(Get-CotestHostsMarkers -Content $currentHosts)
    if ($staleMarkers.Count -gt 0) {
        Add-InstallAction "hosts access" "failed" "stale markers require a manual elevated restore: $($staleMarkers -join ',')"
        return $false
    }
    if (-not $PSCmdlet.ShouldProcess($resolvedHostsPath, "back up hosts ACL and grant Modify to $targetUser")) {
        Add-InstallAction "hosts access" "skipped" "WhatIf or confirmation declined"
        return $false
    }

    $originalAcl = $null
    $probeMarker = $null
    $null = New-Item -ItemType Directory -Force -Path $stateRoot
    try {
        [System.IO.File]::WriteAllBytes($backupPath, [System.IO.File]::ReadAllBytes($resolvedHostsPath))
        $originalAcl = Get-Acl -LiteralPath $resolvedHostsPath
        $originalAcl | Export-Clixml -LiteralPath $aclPath
        $backupHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $backupPath).Hash.ToLowerInvariant()
        $identity = [Security.Principal.NTAccount]::new($targetUser)
        $sid = $identity.Translate([Security.Principal.SecurityIdentifier]).Value
        $icaclsOutput = & icacls.exe $resolvedHostsPath /grant "${targetUser}:(M)" 2>&1
        if ($LASTEXITCODE -ne 0) { throw "icacls grant failed: $($icaclsOutput -join ' ')" }

        $probeMarker = New-CotestHostsMarker -RunId "setup-probe-$PID"
        $probeHosts = Get-CotestJointHostNames -ServerCount $ServerCount -IncludeCoauth $true -IncludeUnregisteredProbe $true
        $before = [System.IO.File]::ReadAllText($resolvedHostsPath)
        $withProbe = Add-CotestHostsBlock -Content $before -Hosts $probeHosts -Marker $probeMarker
        [System.IO.File]::WriteAllText($resolvedHostsPath, $withProbe, [System.Text.UTF8Encoding]::new($false))
        foreach ($hostName in $probeHosts) {
            $answers = @([Net.Dns]::GetHostAddresses($hostName))
            if ($answers.Count -eq 0 -or @($answers | Where-Object { -not [Net.IPAddress]::IsLoopback($_) }).Count -gt 0) {
                throw "hosts setup probe resolved $hostName outside loopback"
            }
        }
        $cleaned = Remove-CotestHostsBlocks -Content ([System.IO.File]::ReadAllText($resolvedHostsPath)) -Marker $probeMarker
        [System.IO.File]::WriteAllText($resolvedHostsPath, $cleaned, [System.Text.UTF8Encoding]::new($false))
        if (@(Get-CotestHostsMarkers -Content ([System.IO.File]::ReadAllText($resolvedHostsPath))).Count -ne 0) {
            throw "hosts setup probe marker cleanup failed"
        }
        $manifest = [pscustomobject]@{
            schema = "cotest.joint-hosts-setup.v1"
            created_at = (Get-Date).ToUniversalTime().ToString("o")
            hosts_path = $resolvedHostsPath
            test_user = $targetUser
            test_user_sid = $sid
            backup_path = $backupPath
            backup_sha256 = $backupHash
            acl_backup_path = $aclPath
            acl_sddl = $originalAcl.Sddl
            acl_owner = $originalAcl.Owner
            permission = "Modify"
        }
        $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM
        "$(Get-Date -Format o) initialized hosts access for $targetUser ($sid)" | Set-Content -LiteralPath $logPath -Encoding utf8NoBOM
        Add-InstallAction "hosts access" "initialized" "target_user=$targetUser; recovery_state=$stateRoot"
        return $true
    } catch {
        try {
            if (Test-Path -LiteralPath $resolvedHostsPath) {
                $current = [System.IO.File]::ReadAllText($resolvedHostsPath)
                $cleaned = if ($probeMarker) { Remove-CotestHostsBlocks -Content $current -Marker $probeMarker } else { $current }
                [System.IO.File]::WriteAllText($resolvedHostsPath, $cleaned, [System.Text.UTF8Encoding]::new($false))
            }
            if ($originalAcl) { Set-Acl -LiteralPath $resolvedHostsPath -AclObject $originalAcl }
        } catch {
            Add-InstallAction "hosts access rollback" "failed" "automatic rollback failed; use recovery files in $stateRoot"
        }
        Add-InstallAction "hosts access" "failed" $_.Exception.Message
        return $false
    }
}

Update-CotestProcessPath
if ($platform.os -eq "windows") {
        if (-not (Get-Command node -ErrorAction SilentlyContinue) -or -not (Get-Command npm -ErrorAction SilentlyContinue) -or -not (Get-Command npx -ErrorAction SilentlyContinue)) {
            $null = Install-CotestWindowsPrerequisite -Name "Node.js LTS" -WingetId "OpenJS.NodeJS.LTS" -ChocolateyPackage "nodejs-lts" -ScoopPackage "nodejs-lts"
        }
        if (-not (Get-Command cargo -ErrorAction SilentlyContinue) -or -not (Get-Command rustc -ErrorAction SilentlyContinue)) {
            $null = Install-CotestWindowsPrerequisite -Name "Rustup" -WingetId "Rustlang.Rustup" -ChocolateyPackage "rustup.install" -ScoopPackage "rustup"
        }
        if (-not (Find-CotestOpenSslPath)) {
            $null = Install-CotestWindowsPrerequisite -Name "OpenSSL" -WingetId "ShiningLight.OpenSSL.Dev" -ChocolateyPackage "openssl" -ScoopPackage "openssl"
        }
        if ((Get-CotestCaddyInspection).status -ne "pass") { $null = Install-CotestCaddy }
        if ($RequireDocker -and -not (Get-Command docker -ErrorAction SilentlyContinue)) {
            $null = Install-CotestWindowsPrerequisite -Name "Docker Desktop" -WingetId "Docker.DockerDesktop" -ChocolateyPackage "docker-desktop" -ScoopPackage $null
        }
        Update-CotestProcessPath
} else {
    $requiredTools = @('node', 'npm', 'npx', 'cargo', 'rustc')
    if ($RequireDocker) { $requiredTools += 'docker' }
    $missingTools = @($requiredTools | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) })
    if (-not (Find-CotestOpenSslPath)) { $missingTools += 'openssl' }
    if ((Get-CotestCaddyInspection).status -ne 'pass') { $missingTools += 'verified caddy' }
    if ($missingTools.Count -gt 0) {
        Add-InstallAction "platform packages" "failed" "missing=$($missingTools -join ','); automatic platform package installation is currently supported only on Windows"
    } else {
        Add-InstallAction "platform packages" "ready" "all required platform packages are already installed and verified"
    }
}

$npm = Get-Command npm -ErrorAction SilentlyContinue
$packagePath = Join-Path $e2eRoot "node_modules\@playwright\test\package.json"
if ($npm -and -not (Test-Path -LiteralPath $packagePath)) {
    $null = Invoke-CotestPackageCommand -Name "e2e npm dependencies" -FilePath $npm.Source -Arguments @("--prefix", $e2eRoot, "ci")
}
$npx = Get-Command npx -ErrorAction SilentlyContinue
if ($RequireBrowser -and $npx -and (Test-Path -LiteralPath $packagePath) -and -not (Test-CotestPlaywrightChromium)) {
    $null = Invoke-CotestPackageCommand -Name "Playwright Chromium" -FilePath $npx.Source -Arguments @("--prefix", $e2eRoot, "playwright", "install", "chromium")
}

if ($RequireDocker) {
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if ($docker) {
        $null = & $docker.Source info 2>&1
        if ($LASTEXITCODE -eq 0) {
            foreach ($image in @($PostgresImage | Sort-Object -Unique)) {
                $null = & $docker.Source image inspect $image 2>&1
                if ($LASTEXITCODE -ne 0) {
                    $null = Invoke-CotestPackageCommand -Name $image -FilePath $docker.Source -Arguments @("pull", $image)
                }
            }
        } else {
            Add-InstallAction "docker daemon" "failed" "Docker is installed but its daemon is unavailable; start Docker Desktop and retry, using an elevated PowerShell if startup or access is denied"
        }
    }
}

if ($DnsSuffix -eq 'local.host') {
    if ($isAdministrator) {
        $null = Initialize-CotestWindowsHostsAccess
    }
}

function Find-CotestTool {
    param(
        [string]$Name,
        [string[]]$Arguments = @("--version"),
        [bool]$Required = $true,
        [string[]]$Repair = @(),
        [scriptblock]$Resolver
    )
    $source = if ($Resolver) {
        & $Resolver
    } else {
        (Get-Command $Name -ErrorAction SilentlyContinue).Source
    }
    if ([string]::IsNullOrWhiteSpace($source)) {
        Add-Check $Name $(if ($Required) { "fail" } else { "warn" }) "not found on PATH" $Repair
        return
    }
    $version = (& $source @Arguments 2>&1 | Out-String).Trim()
    Add-Check $Name "pass" "path=$source; version=$version"
}

Add-Check "mode" "pass" $(if ($isAdministrator) { "install missing prerequisites, initialize hosts access, then check" } else { "install missing prerequisites when permitted, then check; hosts access remains read-only" })
Add-Check "platform" "pass" "os=$($platform.os); architecture=$($platform.architecture); shell=$($platform.shell) $($platform.shell_version); package_managers=$((@($platform.package_managers.name) -join ','))"
Find-CotestTool "node"
Find-CotestTool "npm"
Find-CotestTool "npx"
Find-CotestTool "openssl" -Resolver { Find-CotestOpenSslPath }
Find-CotestTool "cargo"
Find-CotestTool "rustc"
Find-CotestTool "docker" @("--version") $RequireDocker.IsPresent

$playwrightPackage = Join-Path $e2eRoot "node_modules\@playwright\test\package.json"
if (Test-Path -LiteralPath $playwrightPackage) {
    $package = Get-Content -Raw -LiteralPath $playwrightPackage | ConvertFrom-Json
    Add-Check "playwright package" "pass" "path=$playwrightPackage; version=$($package.version)"
    if (-not $RequireBrowser) {
        Add-Check "playwright chromium" "pass" "not required by the selected browserless profile"
    } elseif (Test-CotestPlaywrightChromium) {
        Add-Check "playwright chromium" "pass" "bundled Chromium executable is installed"
    } else {
        Add-Check "playwright chromium" "fail" "bundled Chromium executable is missing after installation was attempted" @("Retry this initializer from an elevated PowerShell.")
    }
} else {
    Add-Check "playwright package" "fail" "missing $playwrightPackage after installation was attempted" @("Retry this initializer from an elevated PowerShell.")
}

$caddy = Get-CotestCaddyInspection
$caddyRepair = if ($caddy.status -eq "pass") { @() } else { @(Get-CotestCaddyRepairAdvice -PlatformInfo $platform) }
Add-Check "caddy" $caddy.status $caddy.detail $caddyRepair

if ($DnsSuffix -eq 'localhost') {
    try {
        Assert-CotestLoopbackDns -Hosts (Get-CotestJointHostNames -ServerCount $ServerCount -IncludeCoauth $StartCoauth.IsPresent -DnsSuffix $DnsSuffix)
        Add-Check "loopback DNS" "pass" "all localhost service names and the unregistered probe resolve only to loopback"
    } catch {
        Add-Check "loopback DNS" "fail" $_.Exception.Message
    }
} elseif (-not (Test-Path -LiteralPath $resolvedHostsPath -PathType Leaf)) {
    Add-Check "hosts file" "fail" "not found: $resolvedHostsPath"
} else {
    try {
        $content = [System.IO.File]::ReadAllText($resolvedHostsPath)
        Add-Check "hosts readable" "pass" $resolvedHostsPath
        $staleMarkers = @(Get-CotestHostsMarkers -Content $content)
        if ($staleMarkers.Count -gt 0) {
            Add-Check "hosts stale markers" "fail" "found=$($staleMarkers -join ',')" @("Run manually as administrator: pwsh -NoProfile -File '$PSScriptRoot\restore-joint-e2e-hosts.ps1'")
        } else {
            Add-Check "hosts stale markers" "pass" "none"
        }
        try {
            $stream = [System.IO.File]::Open($resolvedHostsPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite)
            $stream.Dispose()
            Add-Check "hosts runner access" "pass" "current user can perform run-scoped writes"
        } catch {
            $currentUser = if ($IsWindows) { [Security.Principal.WindowsIdentity]::GetCurrent().Name.Replace("'", "''") } else { [Environment]::UserName.Replace("'", "''") }
            Add-Check "hosts runner access" "fail" $_.Exception.Message @(
                "Rerun scripts/run-joint-e2e.ps1 from an elevated PowerShell, or run as administrator: pwsh -NoProfile -File '$PSScriptRoot\initialize-joint-e2e-environment.ps1' -ServerCount $ServerCount -TestUser '$currentUser'"
            )
        }
    } catch {
        Add-Check "hosts readable" "fail" $_.Exception.Message
    }
}

if ($DnsSuffix -eq 'localhost') {
    Add-Check "hosts setup adapter" "pass" "localhost topology requires no hosts mutation; DNS was verified above"
} elseif ($platform.os -ne "windows") {
    Add-Check "hosts setup adapter" "unsupported" "read-only detection is supported; privileged initialization is currently implemented only for Windows"
} else {
    Add-Check "hosts setup adapter" "pass" "Windows ACL backup/grant/restore adapter available"
}

$requiredHosts = @(Get-CotestJointHostNames -ServerCount $ServerCount -IncludeCoauth $StartCoauth.IsPresent -IncludeUnregisteredProbe $true -DnsSuffix $DnsSuffix)
$portsPerServer = if ($StartCoauth) { 4 } else { 2 }
$recommendedMemoryGb = [math]::Max(4, 2 + ($ServerCount * $(if ($StartCoauth) { 2 } else { 1 })))
# The recommendation includes headroom for transient browser/build activity;
# treating that exact boundary as a hard prerequisite made healthy machines
# fail preflight because free memory naturally fluctuates by a few hundred MB.
# Keep a lower safety floor as the actual gate and surface the headroom gap as
# a warning so callers can close applications before a resource-heavy run.
$minimumMemoryGb = [math]::Max(4, [math]::Ceiling($recommendedMemoryGb * 0.75))
Add-Check "topology budget" "pass" "servers=$ServerCount; hosts=$($requiredHosts -join ','); estimated_tcp_ports=$($ServerCount * $portsPerServer + 1); recommended_memory_gb=$recommendedMemoryGb; minimum_memory_gb=$minimumMemoryGb; independent_databases=$($ServerCount * $(if ($StartCoauth) { 2 } else { 1 }))"
if ($platform.os -eq "windows") {
    $availableMemoryGb = [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB, 2)
    $memoryStatus = if ($availableMemoryGb -ge $recommendedMemoryGb) {
        "pass"
    } elseif ($availableMemoryGb -ge $minimumMemoryGb) {
        "warn"
    } else {
        "fail"
    }
    Add-Check "available memory" $memoryStatus "available_gb=$availableMemoryGb; recommended_gb=$recommendedMemoryGb; minimum_gb=$minimumMemoryGb"
}
$outputDrive = [System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($OutputDirectory))
$freeDiskGb = [math]::Round($outputDrive.AvailableFreeSpace / 1GB, 2)
Add-Check "artifact disk" $(if ($freeDiskGb -ge 10) { "pass" } else { "fail" }) "path=$OutputDirectory; free_gb=$freeDiskGb; required_gb=10"

if ($RequireDocker) {
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if ($docker) {
        $dockerInfo = (& $docker.Source info 2>&1 | Out-String).Trim()
        $dockerReady = $LASTEXITCODE -eq 0
        Add-Check "docker daemon" $(if ($dockerReady) { "pass" } else { "fail" }) $dockerInfo @("Start Docker Desktop, then rerun the entry command.")
        if ($dockerReady) {
            foreach ($image in @($PostgresImage | Sort-Object -Unique)) {
                $postgresInspect = (& $docker.Source image inspect $image 2>&1 | Out-String).Trim()
                Add-Check "postgres image" $(if ($LASTEXITCODE -eq 0) { "pass" } else { "fail" }) $(if ($LASTEXITCODE -eq 0) { "$image present" } else { $postgresInspect }) @("Retry from an elevated PowerShell, or run: docker pull $image")
            }
        }
    }
}

$report = [pscustomobject]@{
    schema = "cotest.joint-environment.v1"
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    mode = "install-and-check"
    administrator = $isAdministrator
    platform = $platform
    server_count = $ServerCount
    start_coauth = $StartCoauth.IsPresent
    require_docker = $RequireDocker.IsPresent
    postgres_images = @($PostgresImage | Sort-Object -Unique)
    hosts_path = $resolvedHostsPath
    required_hosts = $requiredHosts
    caddy = $caddy
    actions = @($actions)
    results = @($results)
    passed = (
        @($results | Where-Object { $_.status -eq "fail" }).Count -eq 0 -and
        @($actions | Where-Object { $_.status -eq "failed" }).Count -eq 0
    )
}
$jsonPath = Join-Path $OutputDirectory "environment.json"
$markdownPath = Join-Path $OutputDirectory "environment.md"
$report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $jsonPath -Encoding utf8NoBOM
$lines = @(
    "# Joint E2E environment",
    "",
    "- Mode: $($report.mode)",
    "- Platform: $($platform.os)/$($platform.architecture)",
    "- Server count: $ServerCount",
    "- PostgreSQL images: $((@($PostgresImage | Sort-Object -Unique)) -join ', ')",
    "- Hosts path: $resolvedHostsPath",
    "- Passed: $($report.passed)",
    ""
)
foreach ($action in $actions) { $lines += "- [action/$($action.status)] $($action.name): $($action.detail)" }
foreach ($result in $results) {
    $lines += "- [$($result.status)] $($result.name): $($result.detail)"
    foreach ($repair in @($result.repair)) { $lines += "  - Repair: ``$repair``" }
}
$lines | Set-Content -LiteralPath $markdownPath -Encoding utf8NoBOM
foreach ($action in $actions) { Write-Host "[action/$($action.status)] $($action.name): $($action.detail)" }
foreach ($result in $results) { Write-Host "[$($result.status)] $($result.name): $($result.detail)" }
Write-Host "Environment report: $OutputDirectory"

if (-not $report.passed) {
    Write-Host "Environment is incomplete after installation attempts. Retry the entry from an elevated PowerShell; hosts access can also be initialized separately with initialize-joint-e2e-environment.ps1."
    exit 2
}
exit 0
