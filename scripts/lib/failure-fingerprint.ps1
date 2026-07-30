# Structured root-cause fingerprints for final joint-e2e failures.
#
# The runner already emits junit.xml and a scenario report, but neither answers
# "how many distinct things broke". Triage was done by eye over the failure text
# and the `playwright-output/` directory listing, and both mislead:
#
#   * Playwright keeps the artifact directory of every failed ATTEMPT. A test
#     that failed twice and passed on the third try leaves two directories
#     behind and zero final failures, so counting directories inflates the
#     number. A 47-final-failure run reads as far worse than it is.
#   * Two failures with the same root cause -- one endpoint returning one wire
#     code -- look like two unrelated problems when the only thing compared is
#     free-form assertion text.
#
# So each final failure gets a fingerprint built from the structural facts:
# the endpoint, the wire code, the first assertion site, and the managed-service
# correlation id. The first three form a stable dedupe key; the correlation id
# varies per run and is carried for lookup only.
#
# Classification is reporting only. It never changes a test's verdict: the
# junit result is the outcome, and this only explains it.
#
# Deliberately structural: no free-form failure text reaches the report. A
# failing object assertion serialises the whole received value (see
# `secret-scan.ps1` and `e2e/helpers/secret-safe.ts`), so copying raw messages
# into another artifact would re-publish exactly what that work removed.

$script:UuidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'

# Collapse per-run identity out of a path so the same endpoint fingerprints the
# same way across runs and across actors.
function ConvertTo-StableEndpoint {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Endpoint)

    if ([string]::IsNullOrWhiteSpace($Endpoint)) {
        return ""
    }
    $stable = $Endpoint
    $stable = $stable -replace "ak:[a-z_]+:$script:UuidPattern", '{id}'
    $stable = $stable -replace $script:UuidPattern, '{id}'
    $stable = $stable -replace 'did:[a-z0-9]+:[^/?#]+', '{did}'
    $stable = $stable -replace '/\d+(?=/|$)', '/{n}'
    return $stable
}

# First `/_arkret/...` request path mentioned in the failure evidence.
function Get-FailureEndpoint {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)

    $match = [regex]::Match($Text, '(/_arkret/[A-Za-z0-9_\-./{}:]*)')
    if (-not $match.Success) {
        return ""
    }
    return ConvertTo-StableEndpoint -Endpoint $match.Groups[1].Value.TrimEnd('.', ',', ')', '"', "'")
}

# First protocol wire code. Arkret wire codes are snake_case tokens carried
# either as a JSON `code` member or as a bare `wire_code=` field in a log line.
function Get-FailureWireCode {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)

    $match = [regex]::Match($Text, '"code"\s*:\s*"([a-z][a-z0-9_]{2,})"')
    if ($match.Success) {
        return $match.Groups[1].Value
    }
    $match = [regex]::Match($Text, '\bwire_code\s*[=:]\s*"?([a-z][a-z0-9_]{2,})"?')
    if ($match.Success) {
        return $match.Groups[1].Value
    }
    return ""
}

# First spec-file assertion site, as `<spec>:<line>`. The column is dropped: a
# reformat shifts columns without changing the assertion.
function Get-FailureAssertionSite {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)

    $match = [regex]::Match($Text, '([A-Za-z0-9_\-./\\]*\.spec\.ts):(\d+)(?::\d+)?')
    if (-not $match.Success) {
        return ""
    }
    $file = $match.Groups[1].Value -replace '\\', '/'
    # Keep the last two path segments so the site is readable but not tied to
    # the absolute checkout location.
    $segments = @($file -split '/' | Where-Object { $_ })
    if ($segments.Count -gt 2) {
        $file = ($segments[-2], $segments[-1]) -join '/'
    }
    return "$($file):$($match.Groups[2].Value)"
}

# Managed-service correlation / request id, for pulling the server side of the
# failure out of services/<service>.log. Varies per run, so it is NOT part of
# the dedupe key.
function Get-FailureCorrelationId {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)

    $match = [regex]::Match($Text, '\b(?:correlation_id|request_id|x-request-id)\b["\s=:]+"?([A-Za-z0-9_\-]{6,})"?')
    if ($match.Success) {
        return $match.Groups[1].Value
    }
    return ""
}

# HTTP status, when the evidence names one.
function Get-FailureHttpStatus {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)

    $match = [regex]::Match($Text, '\b(?:status|statusCode|status_code|HTTP)\b["\s=:]+"?([1-5]\d{2})\b')
    if ($match.Success) {
        return $match.Groups[1].Value
    }
    return ""
}

# Build the fingerprint record for one final failure.
#
# `fingerprint` is a short stable hash over scenario + endpoint + wire code +
# assertion site. Two failures sharing it share a root cause; the count of
# distinct fingerprints is the number of things actually broken.
function Get-FailureFingerprint {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Scenario,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$TestName,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Message,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Detail,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$SystemOut
    )

    $evidence = @($Message, $Detail, $SystemOut) -join "`n"
    $endpoint = Get-FailureEndpoint -Text $evidence
    $wireCode = Get-FailureWireCode -Text $evidence
    $assertionSite = Get-FailureAssertionSite -Text $evidence
    $correlationId = Get-FailureCorrelationId -Text $evidence
    $httpStatus = Get-FailureHttpStatus -Text $evidence

    $key = @($Scenario, $endpoint, $wireCode, $assertionSite) -join '|'
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($key))
    } finally {
        $sha.Dispose()
    }
    $fingerprint = (($hashBytes[0..7] | ForEach-Object { $_.ToString("x2") }) -join "")

    return [pscustomobject]@{
        fingerprint    = $fingerprint
        scenario       = $Scenario
        test           = $TestName
        endpoint       = $endpoint
        wire_code      = $wireCode
        assertion_site = $assertionSite
        http_status    = $httpStatus
        correlation_id = $correlationId
    }
}

# Reconcile Playwright's per-attempt artifact directories against the final
# outcomes in junit.xml.
#
# Playwright names a retry directory `<base>-retry<N>`. A directory whose test
# is not in the final-failure set is retry debris from a test that ultimately
# passed; reporting it as such is what stops the directory listing from being
# read as a failure count.
function Get-RetryArtifactReconciliation {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$PlaywrightOutputDir,
        [Parameter(Mandatory = $true)]$FinalFailures
    )

    $directories = @()
    if ($PlaywrightOutputDir -and (Test-Path -LiteralPath $PlaywrightOutputDir)) {
        $directories = @(Get-ChildItem -LiteralPath $PlaywrightOutputDir -Directory -ErrorAction SilentlyContinue)
    }
    # Playwright names a directory `<spec path>-<test title>-<project>`, with
    # separators normalised and the whole thing truncated when long. Compare on
    # lowercase alphanumerics, dropping the `.spec.ts` the directory name never
    # carries, and match on the common prefix so truncation and the trailing
    # project name do not break the association.
    $failureSlugs = @($FinalFailures | ForEach-Object {
            $scenario = ($_.scenario -replace '\.spec\.ts$', '')
            (($scenario + $_.test) -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
        })
    $entries = New-Object System.Collections.Generic.List[object]
    foreach ($directory in $directories) {
        $retryMatch = [regex]::Match($directory.Name, '-retry(\d+)$')
        $slug = ($directory.Name -replace '-retry\d+$', '') -replace '[^A-Za-z0-9]', ''
        $slug = $slug.ToLowerInvariant()
        $matchesFinalFailure = $false
        foreach ($failureSlug in $failureSlugs) {
            # Require a substantial prefix so two unrelated specs in the same
            # domain directory cannot be conflated.
            $common = [Math]::Min($failureSlug.Length, $slug.Length)
            if ($common -lt 20) { continue }
            if ($failureSlug.Substring(0, $common) -eq $slug.Substring(0, $common)) {
                $matchesFinalFailure = $true
                break
            }
        }
        $entries.Add([pscustomobject]@{
            directory   = $directory.Name
            attempt     = if ($retryMatch.Success) { [int]$retryMatch.Groups[1].Value } else { 0 }
            is_retry    = $retryMatch.Success
            classification = if ($matchesFinalFailure) {
                "final_failure_artifact"
            } else {
                "retry_artifact_of_passing_test"
            }
        }) | Out-Null
    }
    $all = $entries.ToArray()
    return [pscustomobject]@{
        artifact_directories   = $all.Count
        final_failure_artifacts = @($all | Where-Object { $_.classification -eq "final_failure_artifact" }).Count
        retry_only_artifacts   = @($all | Where-Object { $_.classification -eq "retry_artifact_of_passing_test" }).Count
        entries                = $all
    }
}
