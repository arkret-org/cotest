$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$topologyFiles = @(
    "scripts\run-joint-e2e.ps1",
    "scripts\initialize-joint-e2e-environment.ps1",
    "scripts\control-joint-e2e-service.ps1",
    "scripts\lib\joint-e2e-environment.ps1",
    "e2e\helpers\env.ts"
)
$forbidden = '(?i)(soland|coauth|inkson)[_-](alpha|beta|gamma)|COTEST_(SOLAND|COAUTH|INKSON)_(ALPHA|BETA|GAMMA)'
$violations = @()
foreach ($relative in $topologyFiles) {
    $path = Join-Path $repoRoot $relative
    $lineNumber = 0
    foreach ($line in Get-Content -LiteralPath $path) {
        $lineNumber++
        if ($line -match $forbidden) { $violations += "${relative}:${lineNumber}:$line" }
    }
}
if ($violations.Count -gt 0) { throw "Forbidden fixed topology naming found:`n$($violations -join "`n")" }

$tokens = $null
$parseErrors = $null
$runnerPath = Join-Path $repoRoot "scripts\run-joint-e2e.ps1"
$ast = [System.Management.Automation.Language.Parser]::ParseFile($runnerPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw "Joint runner has PowerShell parse errors" }
$layoutFunction = $ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq "Get-JointServerArtifactLayout"
}, $true)
if ($layoutFunction.Count -ne 1) { throw "Expected one generic joint server artifact layout function" }
Invoke-Expression $layoutFunction[0].Extent.Text

$executableFunction = $ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq "Get-NativeExecutableName"
}, $true)
if ($executableFunction.Count -ne 1) { throw "Expected one native executable naming function" }
Invoke-Expression $executableFunction[0].Extent.Text
foreach ($name in @("soland", "coauth", "flagon", "savfox", "cotest-wire", "cotest-provision")) {
    $expectedName = if ($IsWindows) { "$name.exe" } else { $name }
    if ((Get-NativeExecutableName -Name $name) -ne $expectedName) {
        throw "Incorrect native executable name for $name"
    }
}
$runnerSource = Get-Content -LiteralPath $runnerPath -Raw
if ($runnerSource -match '"(?:debug|release)\\(?:soland|coauth|flagon|savfox|cotest-wire|cotest-provision)\.exe"') {
    throw "Cargo executable paths must use platform-native executable names"
}

$jointDirectory = Join-Path ([System.IO.Path]::GetTempPath()) "cotest-layout"
foreach ($serverIndex in 1..3) {
    $serverName = "server$serverIndex"
    $layout = Get-JointServerArtifactLayout -JointDirectory $jointDirectory -ServerName $serverName
    $expected = @{
        CoauthDirectory = Join-Path $jointDirectory "coauth-$serverName"
        SolandConfigPath = Join-Path $jointDirectory "soland-$serverName.env"
        SolandObjectsRoot = Join-Path $jointDirectory "soland-$serverName-objects"
        SolandStateRoot = Join-Path $jointDirectory "soland-$serverName-state"
        SolandChaosControlPath = Join-Path $jointDirectory "soland-$serverName-decision-chaos.json"
        CoauthStoreDumpName = "coauth-$serverName-postgres.sql"
        SolandStoreDumpName = "soland-$serverName-postgres.sql"
    }
    foreach ($property in $expected.Keys) {
        if ($layout.$property -ne $expected[$property]) {
            throw "$serverName artifact layout mismatch for ${property}: $($layout.$property)"
        }
    }
}
Write-Host "joint-topology-naming.tests.ps1: PASS"
