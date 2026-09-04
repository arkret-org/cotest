Set-StrictMode -Version Latest

$script:CotestHostsMarkerPrefix = "cotest-joint-e2e"
$script:CotestCaddyMinimumVersion = [version]"2.8.0"
$script:CotestCaddyMaximumVersionExclusive = [version]"3.0.0"

function Get-CotestPlatformInfo {
    $os = if ($IsWindows) { "windows" } elseif ($IsMacOS) { "macos" } elseif ($IsLinux) { "linux" } else { "unknown" }
    $architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
    $shell = if ($PSVersionTable.PSEdition -eq "Core") { "pwsh" } else { "powershell" }
    $packageManagers = @()
    foreach ($candidate in @("winget", "choco", "scoop", "brew", "apt-get", "dnf", "yum", "docker")) {
        $command = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($command) {
            $packageManagers += [pscustomobject]@{ name = $candidate; path = $command.Source }
        }
    }

    return [pscustomobject]@{
        os = $os
        architecture = $architecture
        shell = $shell
        shell_version = $PSVersionTable.PSVersion.ToString()
        package_managers = $packageManagers
        path = [Environment]::GetEnvironmentVariable("PATH")
    }
}

function Get-CotestHostsPath {
    param([string]$Override)
    if ($Override) { return [System.IO.Path]::GetFullPath($Override) }
    if ($IsWindows) { return Join-Path $env:SystemRoot "System32\drivers\etc\hosts" }
    return "/etc/hosts"
}

function Get-CotestJointHostNames {
    param(
        [ValidateRange(1, 32)][int]$ServerCount = 1,
        [bool]$IncludeCoauth = $true,
        [bool]$IncludeUnregisteredProbe = $true
    )
    $names = [System.Collections.Generic.List[string]]::new()
    for ($index = 1; $index -le $ServerCount; $index++) {
        $names.Add("soland-server$index.local.host")
        if ($IncludeCoauth) { $names.Add("coauth-server$index.local.host") }
    }
    if ($IncludeUnregisteredProbe) { $names.Add("unregistered.local.host") }
    return @($names)
}

function New-CotestHostsMarker {
    param([Parameter(Mandatory = $true)][string]$RunId)
    if ($RunId -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$') {
        throw "RunId contains characters that are unsafe for a hosts marker"
    }
    return "${script:CotestHostsMarkerPrefix}:$RunId"
}

function Add-CotestHostsBlock {
    param(
        [Parameter(Mandatory = $true)][string]$Content,
        [Parameter(Mandatory = $true)][string[]]$Hosts,
        [Parameter(Mandatory = $true)][string]$Marker
    )
    if ($Marker -notlike "${script:CotestHostsMarkerPrefix}:*") {
        throw "Refusing non-cotest hosts marker '$Marker'"
    }
    $begin = "# $Marker begin"
    $end = "# $Marker end"
    if ($Content.Contains($begin) -or $Content.Contains($end)) {
        throw "hosts marker '$Marker' is already present"
    }
    $normalizedHosts = @($Hosts | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique)
    if ($normalizedHosts.Count -eq 0) { throw "At least one hosts name is required" }
    foreach ($hostName in $normalizedHosts) {
        if ($hostName -notmatch '^(?:soland|coauth)-server[1-9][0-9]*\.local\.host$' -and $hostName -ne "unregistered.local.host") {
            throw "Refusing host outside the cotest joint namespace: $hostName"
        }
    }
    $newline = if ($Content.Contains("`r`n")) { "`r`n" } else { "`n" }
    $prefix = if ($Content.Length -eq 0 -or $Content.EndsWith("`n")) { "" } else { $newline }
    $block = @($begin) + @($normalizedHosts | ForEach-Object { "127.0.0.1`t$_" }) + @($end)
    return $Content + $prefix + ($block -join $newline) + $newline
}

function Remove-CotestHostsBlocks {
    param(
        [Parameter(Mandatory = $true)][string]$Content,
        [string]$Marker
    )
    if ($Marker -and $Marker -notlike "${script:CotestHostsMarkerPrefix}:*") {
        throw "Refusing non-cotest hosts marker '$Marker'"
    }
    $markerPattern = if ($Marker) { [regex]::Escape($Marker) } else { [regex]::Escape($script:CotestHostsMarkerPrefix) + ':[A-Za-z0-9_.-]+' }
    $pattern = "(?ms)(?:^|\r?\n)# $markerPattern begin\r?\n.*?^# $markerPattern end(?:\r?\n|$)"
    return [regex]::Replace($Content, $pattern, { param($match) if ($match.Value.StartsWith("`r`n")) { "`r`n" } elseif ($match.Value.StartsWith("`n")) { "`n" } else { "" } })
}

function Get-CotestHostsMarkers {
    param([Parameter(Mandatory = $true)][string]$Content)
    return @([regex]::Matches($Content, "(?m)^# ($([regex]::Escape($script:CotestHostsMarkerPrefix)):[A-Za-z0-9_.-]+) begin\r?$") | ForEach-Object { $_.Groups[1].Value })
}

function Test-CotestAdministrator {
    if ($IsWindows) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    $id = Get-Command id -ErrorAction SilentlyContinue
    if (-not $id) { return $false }
    return ((& $id -u) -eq "0")
}

function Get-CotestCaddyInspection {
    $command = Get-Command caddy -ErrorAction SilentlyContinue
    if (-not $command) {
        return [pscustomobject]@{ status = "fail"; detail = "caddy was not found on PATH"; path = $null; version = $null; sha256 = $null; modules_verified = $false; source = "unknown" }
    }
    $path = [System.IO.Path]::GetFullPath($command.Source)
    $versionOutput = (& $path version 2>&1 | Out-String).Trim()
    $match = [regex]::Match($versionOutput, '(?<![0-9])v?([0-9]+\.[0-9]+\.[0-9]+)')
    $version = if ($match.Success) { [version]$match.Groups[1].Value } else { $null }
    $versionAccepted = $version -and $version -ge $script:CotestCaddyMinimumVersion -and $version -lt $script:CotestCaddyMaximumVersionExclusive
    $moduleOutput = (& $path list-modules 2>&1 | Out-String)
    $requiredModules = @("http.handlers.reverse_proxy", "tls")
    $missingModules = @($requiredModules | Where-Object { $moduleOutput -notmatch [regex]::Escape($_) })
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
    $source = "unverified-path"
    $sourceVerified = $false
    $integrityVerified = $false
    if ($path -match '(?i)\\scoop\\') {
        $source = "scoop-community"
        $sourceVerified = $true
        $integrityVerified = $true
    } elseif ($path -match '(?i)chocolatey') {
        $source = "chocolatey-community"
        $sourceVerified = $true
        $integrityVerified = $true
    } elseif ($path -match '(?i)homebrew|\\brew\\|/brew/') {
        $source = "homebrew-community"
        $sourceVerified = $true
        $integrityVerified = $true
    } elseif ($IsWindows -and (Get-Command winget -ErrorAction SilentlyContinue)) {
        $wingetList = (& winget list --name Caddy --exact --accept-source-agreements 2>&1 | Out-String)
        $wingetMatch = [regex]::Match($wingetList, '(?m)^Caddy\s+(\S+)\s+[0-9]')
        if ($LASTEXITCODE -eq 0 -and $wingetMatch.Success) {
            $source = "winget-community:$($wingetMatch.Groups[1].Value)"
            $sourceVerified = $true
            $integrityVerified = $true
        }
    }
    $declaredSource = [Environment]::GetEnvironmentVariable("COTEST_CADDY_SOURCE")
    $expectedHash = [Environment]::GetEnvironmentVariable("COTEST_CADDY_EXPECTED_SHA256")
    if ($declaredSource -eq "official-static" -and $expectedHash -and $expectedHash.Trim().ToLowerInvariant() -eq $hash) {
        $source = "official-static"
        $sourceVerified = $true
        $integrityVerified = $true
    }
    $status = if ($versionAccepted -and $missingModules.Count -eq 0 -and $sourceVerified -and $integrityVerified) { "pass" } else { "fail" }
    $detail = "path=$path; version=$versionOutput; accepted_range=>=$script:CotestCaddyMinimumVersion,<$script:CotestCaddyMaximumVersionExclusive; sha256=$hash; source=$source; source_verified=$sourceVerified; integrity_verified=$integrityVerified"
    if ($missingModules.Count -gt 0) { $detail += "; missing_modules=$($missingModules -join ',')" }
    return [pscustomobject]@{ status = $status; detail = $detail; path = $path; version = $versionOutput; sha256 = $hash; modules_verified = ($missingModules.Count -eq 0); source = $source; source_verified = $sourceVerified; integrity_verified = $integrityVerified }
}

function Get-CotestCaddyRepairAdvice {
    param([Parameter(Mandatory = $true)]$PlatformInfo)
    $advice = [System.Collections.Generic.List[string]]::new()
    $managerNames = @($PlatformInfo.package_managers | ForEach-Object { $_.name })
    switch ($PlatformInfo.os) {
        "windows" {
            if ($managerNames -contains "winget") {
                $winget = Get-Command winget -ErrorAction SilentlyContinue
                $searchOutput = if ($winget) { (& $winget.Source search --name Caddy --exact --accept-source-agreements 2>&1 | Out-String).Trim() } else { "" }
                $packageMatch = [regex]::Match($searchOutput, '(?m)^Caddy\s+(\S+)\s+[0-9]')
                if ($LASTEXITCODE -eq 0 -and $packageMatch.Success) {
                    $oneLine = ($searchOutput -replace '\s+', ' ').Trim()
                    if ($oneLine.Length -gt 500) { $oneLine = $oneLine.Substring(0, 500) }
                    $advice.Add("winget exact-search result: $oneLine")
                    $packageId = $packageMatch.Groups[1].Value
                    $advice.Add("winget install --id $packageId --exact --accept-package-agreements --accept-source-agreements")
                } else {
                    $advice.Add("winget search --name Caddy --exact --accept-source-agreements")
                    $advice.Add("No exact package was resolved; do not guess or hard-code a package ID.")
                }
            }
            if ($managerNames -contains "choco") { $advice.Add("choco search caddy --exact; choco install caddy") }
            if ($managerNames -contains "scoop") { $advice.Add("scoop search caddy; scoop install caddy") }
            $advice.Add("Community Windows packages must be recorded as community-maintained; alternatively verify the checksum/signature of an official Caddy release archive.")
        }
        "macos" {
            if ($managerNames -contains "brew") { $advice.Add("brew install caddy") }
            $advice.Add("Homebrew is community-maintained. Official static archives require published checksum/signature verification.")
        }
        "linux" {
            if ($managerNames -contains "apt-get") { $advice.Add("Use the signed official Caddy APT repository described at https://caddyserver.com/docs/install#debian-ubuntu-raspbian") }
            elseif ($managerNames -contains "dnf" -or $managerNames -contains "yum") { $advice.Add("Use the official Caddy COPR/DNF instructions described at https://caddyserver.com/docs/install#fedora-redhat-centos") }
            elseif ($managerNames -contains "docker") { $advice.Add("Use the official caddy container image, or a checksum-verified official static archive.") }
            else { $advice.Add("Follow the distribution-specific signed package or checksum-verified static archive instructions at https://caddyserver.com/docs/install") }
        }
        default { $advice.Add("This platform is not supported by the setup adapter. Follow https://caddyserver.com/docs/install and verify signatures/checksums.") }
    }
    return @($advice)
}

function New-CotestServerTopology {
    param(
        [ValidateRange(1, 32)][int]$ServerCount = 1,
        [bool]$StartCoauth = $false,
        [ValidateSet("full-mesh", "ordered-candidates")][string]$NetworkShape = "full-mesh",
        [int]$TlsPort = 443,
        [int]$SolandPortBase = 28080,
        [int]$CoauthPortBase = 29080,
        [string]$RunRoot = ""
    )
    $servers = [System.Collections.Generic.List[object]]::new()
    for ($index = 1; $index -le $ServerCount; $index++) {
        $name = "server$index"
        $peers = [System.Collections.Generic.List[string]]::new()
        if ($NetworkShape -eq "full-mesh") {
            for ($peerIndex = 1; $peerIndex -le $ServerCount; $peerIndex++) {
                if ($peerIndex -ne $index) { $peers.Add("server$peerIndex") }
            }
        } elseif ($ServerCount -gt 1) {
            for ($offset = 1; $offset -lt $ServerCount; $offset++) {
                $peerIndex = (($index - 1 + $offset) % $ServerCount) + 1
                $peers.Add("server$peerIndex")
            }
        }
        $serverRoot = if ($RunRoot) { Join-Path $RunRoot $name } else { $name }
        $servers.Add([pscustomobject]@{
            name = $name
            role = "station"
            soland = [pscustomobject]@{
                public_url = "https://soland-$name.local.host:$TlsPort"
                listen_address = "127.0.0.1:$($SolandPortBase + $index - 1)"
                service_did = $null
                storage = [pscustomobject]@{ database = Join-Path $serverRoot "soland-postgres"; objects = Join-Path $serverRoot "objects"; state = Join-Path $serverRoot "state" }
                log_directory = Join-Path $serverRoot "logs\soland"
                process_id = $null
                container_id = $null
            }
            coauth = if ($StartCoauth) { [pscustomobject]@{
                public_url = "https://coauth-$name.local.host:$TlsPort"
                listen_address = "127.0.0.1:$($CoauthPortBase + $index - 1)"
                service_did = $null
                storage = [pscustomobject]@{ database = Join-Path $serverRoot "coauth-postgres"; state = Join-Path $serverRoot "coauth-state" }
                log_directory = Join-Path $serverRoot "logs\coauth"
                process_id = $null
                container_id = $null
            } } else { $null }
            peers = @($peers)
            candidate_sources = @($peers)
        })
    }
    return [pscustomobject]@{
        schema = "cotest.joint-topology.v1"
        network_shape = $NetworkShape
        server_count = $ServerCount
        loopback_address = "127.0.0.1"
        unregistered_probe = "https://unregistered.local.host:$TlsPort"
        servers = @($servers)
    }
}

function Assert-CotestUniqueTopologyValues {
    param(
        [Parameter(Mandatory = $true)]$Values,
        [Parameter(Mandatory = $true)][string]$FailureMessage
    )

    $allValues = [System.Collections.Generic.List[string]]::new()
    $uniqueValues = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($value in $Values) {
        if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) { continue }
        $text = [string]$value
        $allValues.Add($text)
        [void]$uniqueValues.Add($text)
    }
    if ($uniqueValues.Count -ne $allValues.Count) { throw $FailureMessage }
}

function Assert-CotestTopologyIsolation {
    param([Parameter(Mandatory = $true)]$Topology)
    if (@($Topology.servers).Count -ne [int]$Topology.server_count) { throw "topology server count does not match its server list" }
    Assert-CotestUniqueTopologyValues `
        -Values @($Topology.servers | ForEach-Object { $_.name }) `
        -FailureMessage "topology contains duplicate logical names"
    foreach ($property in @("public_url", "listen_address", "service_did", "log_directory", "process_id", "container_id")) {
        Assert-CotestUniqueTopologyValues `
            -Values @($Topology.servers | ForEach-Object { $_.soland.$property }) `
            -FailureMessage "topology reuses soland $property across servers"
    }
    foreach ($property in @("database", "objects", "state")) {
        Assert-CotestUniqueTopologyValues `
            -Values @($Topology.servers | ForEach-Object { $_.soland.storage.$property }) `
            -FailureMessage "topology reuses Soland storage.$property across servers"
    }
    $coauthServers = @($Topology.servers | Where-Object { $_.coauth })
    foreach ($property in @("public_url", "listen_address", "owning_service_id", "log_directory", "process_id", "container_id")) {
        Assert-CotestUniqueTopologyValues `
            -Values @($coauthServers | ForEach-Object {
                $entry = $_.coauth.PSObject.Properties[$property]
                if ($entry) { $entry.Value }
            }) `
            -FailureMessage "topology reuses coauth $property across servers"
    }
    foreach ($property in @("database", "state")) {
        Assert-CotestUniqueTopologyValues `
            -Values @($coauthServers | ForEach-Object { $_.coauth.storage.$property }) `
            -FailureMessage "topology reuses Coauth storage.$property across servers"
    }
}
