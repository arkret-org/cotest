$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$runner = Join-Path $PSScriptRoot "../run-server-conformance.ps1"
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($runner, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "Invalid conformance runner syntax" }
foreach ($name in @("Get-RequiredTestStatuses", "New-ReleaseGateCheck", "New-ReleaseGate")) {
    $function = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if (-not $function) { throw "Missing release gate function $name" }
    . ([scriptblock]::Create($function.Extent.Text))
}
$tests = @([pscustomobject]@{ name = "unrelated"; status = "passed" })
$passing = [pscustomobject]@{ status = "passed" }
foreach ($status in @("passed", "failed", "skipped")) {
    $gate = New-ReleaseGate -Profile "release-gate" -Tests $tests -CoverageGate $passing `
        -SecretScan $passing -SpecSyncGate $passing -JointSmokeGate ([pscustomobject]@{ status = $status })
    $joint = @($gate.checks | Where-Object id -eq "joint_smoke")
    $expected = if ($status -eq "passed") { "passed" } else { "failed" }
    if ($joint.Count -ne 1 -or $joint[0].status -ne $expected) {
        throw "Release gate treated joint/native state '$status' as '$($joint[0].status)'"
    }
}
Write-Host "native-api-release-gate.tests.ps1: PASS"
