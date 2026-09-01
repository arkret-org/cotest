function ConvertTo-CanonicalScenarioKey {
    param([Parameter(Mandatory = $true)][string]$Scenario)

    $normalized = $Scenario.Trim() -replace '\\', '/'
    if ($normalized.EndsWith(".spec.ts", [System.StringComparison]::OrdinalIgnoreCase)) {
        return $normalized.Substring(0, $normalized.Length - ".spec.ts".Length)
    }
    return $normalized
}

function Get-JointSelectionGateFailures {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$RequiredScenarios,
        [Parameter(Mandatory = $true)][hashtable]$JunitByScenario,
        [Parameter(Mandatory = $true)]$Totals,
        [Parameter(Mandatory = $true)][bool]$ForbidRuntimeSkips,
        [AllowNull()][string]$JunitParseError
    )

    $failures = New-Object System.Collections.Generic.List[string]
    if ($JunitParseError) {
        $failures.Add("junit evidence unavailable: $JunitParseError") | Out-Null
        return $failures.ToArray()
    }

    $observedCases = $Totals.passed + $Totals.failed + $Totals.skipped + $Totals.fixme
    if ($observedCases -eq 0) {
        $failures.Add("Playwright selected zero tests") | Out-Null
    }

    foreach ($requiredScenario in $RequiredScenarios) {
        $canonicalScenario = ConvertTo-CanonicalScenarioKey -Scenario $requiredScenario
        $junitScenario = "$canonicalScenario.spec.ts"
        if (-not $JunitByScenario.ContainsKey($junitScenario)) {
            $failures.Add("required scenario was not selected: $canonicalScenario") | Out-Null
            continue
        }
        # `cases` is a generic List[object]. Wrapping that list directly in
        # `@(...)` trips PowerShell's dynamic binder on some 7.x builds.
        $scenarioTotal = $JunitByScenario[$junitScenario].cases.Count
        if ($scenarioTotal -eq 0) {
            $failures.Add("required scenario selected zero testcases: $canonicalScenario") | Out-Null
        }
    }

    if ($ForbidRuntimeSkips -and $Totals.skipped -gt 0) {
        $failures.Add("selected live tests skipped: $($Totals.skipped)") | Out-Null
    }
    return $failures.ToArray()
}
