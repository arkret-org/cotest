$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-Equal($Expected, $Actual, [string]$Message) {
    if ($Expected -ne $Actual) { throw "$Message expected='$Expected' actual='$Actual'" }
}

function Assert-Throws([scriptblock]$Action, [string]$ExpectedMessage, [string]$Message) {
    try {
        & $Action
    }
    catch {
        if ($_.Exception.Message -notlike "*$ExpectedMessage*") {
            throw "$Message wrong error: $($_.Exception.Message)"
        }
        return
    }
    throw "$Message did not throw"
}

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$runnerPath = Join-Path $repoRoot "scripts\run-joint-e2e.ps1"
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $runnerPath,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -gt 0) { throw "Joint runner has PowerShell parse errors" }

foreach ($name in @("Resolve-PlaywrightProjects", "Resolve-ClientKind", "Resolve-InksonRequirement")) {
    $function = @($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq $name
            }, $true))
    if ($function.Count -ne 1) { throw "Expected exactly one $name function" }
    Invoke-Expression $function[0].Extent.Text
}

$script:BrowserPlaywrightProjects = @("chrome", "chromium", "joint-inkson")
$script:BrowserlessPlaywrightProjects = @("joint-api")

$projects = @(Resolve-PlaywrightProjects `
        -RunProfile "joint-api" `
        -PlaywrightProject "chrome" `
        -PlaywrightProjectWasExplicit $false)
Assert-Equal 1 $projects.Count "joint-api must select one project"
Assert-Equal "joint-api" $projects[0] "joint-api must select its browserless project"
Assert-Equal "garth" (Resolve-ClientKind -PlaywrightProjects @("joint-api") -ClientKind "inkson" -ClientKindWasExplicit $false) "joint-api default client"
Assert-Equal "inkson" (Resolve-ClientKind -PlaywrightProjects @("chrome") -ClientKind "inkson" -ClientKindWasExplicit $false) "browser profile client"
Assert-Throws {
    Resolve-ClientKind -PlaywrightProjects @("joint-api") -ClientKind "inkson" -ClientKindWasExplicit $true
} "does not run Inkson" "joint-api must reject an explicit Inkson client"
Assert-Equal $false (Resolve-InksonRequirement -PlaywrightProjects $projects -RunProfile "joint-api" -InksonArguments @{}) "joint-api Inkson requirement"

Write-Host "joint-client-selection.tests.ps1: PASS"
