# Source identity and artifact-byte sidecars for runner-managed builds.

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
        $actual = ConvertTo-BuildStampInputs -RepositoryStates @(
            $stamp.inputs | ForEach-Object {
                [pscustomobject]@{ RepositoryRoot = $_.repository_root; Head = $_.head }
            }
        )
        $expectedJson = ConvertTo-Json -InputObject @($expected) -Depth 4 -Compress
        $actualJson = ConvertTo-Json -InputObject @($actual) -Depth 4 -Compress
        if ($actualJson -ne $expectedJson) {
            return [pscustomobject]@{ Matches = $false; Detail = "build-input commit identity changed: $stampPath" }
        }
        return [pscustomobject]@{ Matches = $true; Detail = "build-input commits and artifact bytes match: $stampPath" }
    }
    catch {
        return [pscustomobject]@{ Matches = $false; Detail = "build-input stamp unreadable: $stampPath ($($_.Exception.Message))" }
    }
}
