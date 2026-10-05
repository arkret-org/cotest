# Source identity and artifact-byte sidecars for runner-managed builds.

function Get-RepositoryBuildContent {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)][string[]]$InputPaths
    )
    $files = @(& $GitPath -C $RepositoryRoot -c core.quotepath=false ls-files --cached --others --exclude-standard -- @InputPaths)
    if ($LASTEXITCODE -ne 0) { throw "Unable to enumerate build input contents for $RepositoryRoot" }
    $extensions = @('.rs', '.toml', '.lock', '.sql', '.proto', '.json', '.html', '.css', '.js', '.ts', '.svg', '.png', '.webp')
    $material = [System.Text.StringBuilder]::new()
    $included = @()
    foreach ($relative in @($files | Sort-Object -Unique)) {
        $absolute = Join-Path $RepositoryRoot $relative
        if (!(Test-Path -LiteralPath $absolute -PathType Leaf)) { continue }
        if ($extensions -notcontains [System.IO.Path]::GetExtension($absolute).ToLowerInvariant()) { continue }
        $included += $relative
        $hash = (Get-FileHash -LiteralPath $absolute -Algorithm SHA256).Hash.ToLowerInvariant()
        [void]$material.Append($relative).Append("`n").Append($hash).Append("`n")
    }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($material.ToString())
    [pscustomobject]@{
        Files = $included
        SourceSha256 = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
    }
}

function Get-ArtifactBuildStampPath {
    param([Parameter(Mandatory = $true)][string]$ArtifactPath)

    return "$ArtifactPath.cotest-build-input.json"
}

function ConvertTo-BuildStampInputs {
    param([Parameter(Mandatory = $true)]$RepositoryStates)

    return @(
        $RepositoryStates |
            ForEach-Object {
                [pscustomobject]@{
                    repository_root = [System.IO.Path]::GetFullPath([string]$_.RepositoryRoot)
                    head = ([string]$_.Head).Trim().ToLowerInvariant()
                    source_sha256 = ([string]$_.SourceSha256).Trim().ToLowerInvariant()
                }
            } |
            Sort-Object repository_root
    )
}

function Write-ArtifactBuildStamp {
    param(
        [Parameter(Mandatory = $true)][string]$ArtifactPath,
        [Parameter(Mandatory = $true)]$RepositoryStates
    )

    $stampPath = Get-ArtifactBuildStampPath -ArtifactPath $ArtifactPath
    [pscustomobject]@{
        schema = "cotest.build_input_stamp.v1"
        artifact = [System.IO.Path]::GetFullPath($ArtifactPath)
        artifact_sha256 = (Get-FileHash -LiteralPath $ArtifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
        built_at = [DateTimeOffset]::UtcNow.ToString("o")
        inputs = ConvertTo-BuildStampInputs -RepositoryStates $RepositoryStates
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $stampPath -Encoding UTF8
    return $stampPath
}

function Test-ArtifactBuildStamp {
    param(
        [Parameter(Mandatory = $true)][string]$ArtifactPath,
        [Parameter(Mandatory = $true)]$RepositoryStates
    )

    $stampPath = Get-ArtifactBuildStampPath -ArtifactPath $ArtifactPath
    if (-not (Test-Path -LiteralPath $stampPath -PathType Leaf)) {
        return [pscustomobject]@{ Matches = $false; Detail = "build-input stamp missing: $stampPath" }
    }
    try {
        $stamp = Get-Content -Raw -LiteralPath $stampPath | ConvertFrom-Json
        if ($stamp.schema -ne "cotest.build_input_stamp.v1") {
            return [pscustomobject]@{ Matches = $false; Detail = "build-input stamp schema is invalid: $stampPath" }
        }
        if ($stamp.artifact -ne [System.IO.Path]::GetFullPath($ArtifactPath) -or
            -not $stamp.PSObject.Properties["artifact_sha256"]) {
            return [pscustomobject]@{ Matches = $false; Detail = "build-input stamp has no matching artifact identity: $stampPath" }
        }
        $artifactHash = (Get-FileHash -LiteralPath $ArtifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($stamp.artifact_sha256 -cne $artifactHash) {
            return [pscustomobject]@{ Matches = $false; Detail = "artifact bytes changed after the managed build: $ArtifactPath" }
        }
        $expected = ConvertTo-BuildStampInputs -RepositoryStates $RepositoryStates
        if (@($stamp.inputs | Where-Object { !$_.PSObject.Properties['source_sha256'] -or $_.source_sha256 -notmatch '^[a-f0-9]{64}$' }).Count -gt 0) {
            return [pscustomobject]@{ Matches = $false; Detail = "build-input content identity missing: $stampPath" }
        }
        $actual = ConvertTo-BuildStampInputs -RepositoryStates @(
            $stamp.inputs | ForEach-Object {
                [pscustomobject]@{ RepositoryRoot = $_.repository_root; Head = $_.head; SourceSha256 = $_.source_sha256 }
            }
        )
        $expectedJson = ConvertTo-Json -InputObject @($expected) -Depth 4 -Compress
        $actualJson = ConvertTo-Json -InputObject @($actual) -Depth 4 -Compress
        if ($actualJson -ne $expectedJson) {
            return [pscustomobject]@{ Matches = $false; Detail = "build-input commit or contents changed: $stampPath" }
        }
        return [pscustomobject]@{ Matches = $true; Detail = "build-input commits, contents and artifact bytes match: $stampPath" }
    }
    catch {
        return [pscustomobject]@{ Matches = $false; Detail = "build-input stamp unreadable: $stampPath ($($_.Exception.Message))" }
    }
}

function Test-ArtifactSourceFreshness {
    param(
        [Parameter(Mandatory = $true)][DateTime]$ArtifactTimeUtc,
        [Parameter(Mandatory = $true)]$RepositoryStates,
        [Parameter(Mandatory = $true)][bool]$StampMatches
    )

    if (-not $StampMatches) {
        return $false
    }
    $newest = $RepositoryStates | Sort-Object RequiredTimeUtc -Descending | Select-Object -First 1
    if ($ArtifactTimeUtc -ge $newest.RequiredTimeUtc) {
        return $true
    }
    # A clean checkout at the exact stamped commits has the same tracked inputs
    # even when a formatter or checkout has refreshed file modification times.
    # Dirty inputs still require a build newer than their on-disk contents.
    return @($RepositoryStates | Where-Object { $_.BuildInputsDirty }).Count -eq 0
}
