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

foreach ($name in @("Resolve-PlaywrightProjects", "Resolve-ClientKind", "Resolve-InksonRequirement", "Quote-PsLiteral", "Get-JointInksonRequiredArtifactPaths", "Get-JointInksonBuildPlan")) {
    $function = @($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq $name
            }, $true))
    if ($function.Count -ne 1) { throw "Expected exactly one $name function" }
    Invoke-Expression $function[0].Extent.Text
}

foreach ($name in @("BrowserPlaywrightProjects", "BrowserlessPlaywrightProjects")) {
    $assignment = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -eq ('$script:' + $name)
    }, $true))
    Assert-Equal 1 $assignment.Count "runner project registry must have one assignment"
    Invoke-Expression $assignment[0].Extent.Text
}

$collaboration = @(Resolve-PlaywrightProjects -RunProfile "joint-smoke" `
    -PlaywrightProject "joint-collaboration" -PlaywrightProjectWasExplicit $true)
Assert-Equal 1 $collaboration.Count "collaboration lane selects exactly one browser project"
Assert-Equal "joint-collaboration" $collaboration[0] "collaboration project selection"
Assert-Equal $true (Resolve-InksonRequirement -PlaywrightProjects $collaboration `
    -RunProfile "joint-smoke" -InksonArguments @{}) "collaboration must prepare the real Inkson test bundle"

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

# Exercise the production build decision for all cache/marker combinations.
foreach ($fresh in @($false, $true)) {
    foreach ($marker in @($false, $true)) {
        $standard = Get-JointInksonBuildPlan -StartMockAppletRegistry $false -ArtifactFresh $fresh -TestFeaturePresent $marker
        Assert-Equal (-not $fresh -or -not $marker) $standard.ShouldBuild "standard lane preserves its freshness/marker decision"
        Assert-Equal "& 'python' 'scripts/build_web.py' --profile joint-e2e --features 'web,wasm-localstorage-secrets-test'" $standard.Command "standard lane must not add Applet UI features"
        $applet = Get-JointInksonBuildPlan -StartMockAppletRegistry $true -ArtifactFresh $fresh -TestFeaturePresent $marker
        Assert-Equal $true $applet.ShouldBuild "Applet lane must build even with source-fresh bytes and the session marker"
        Assert-Equal "& 'python' 'scripts/build_web.py' --profile joint-e2e --features 'web,wasm-localstorage-secrets-test,experimental-applets'" $applet.Command "Applet lane must compile the actual UI feature"
    }
}
# Bind that tested decision to the real managed WASM preparation path.
$plans = @($ast.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -eq "Get-JointInksonBuildPlan"
}, $true))
Assert-Equal 1 $plans.Count "normal managed build must consume the production plan exactly once"
Assert-Equal $true ($plans[0].Extent.Text.Contains('-StartMockAppletRegistry ([bool]$StartMockAppletRegistry)')) "build selection must use the actual lane switch"
$buildBranch = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.IfStatementAst] -and
    $node.Clauses[0].Item1.Extent.Text -eq '$inksonBuildPlan.ShouldBuild'
}, $true)
Assert-Equal $true ($null -ne $buildBranch) "normal managed build must obey ShouldBuild"
$buildText = $buildBranch.Extent.Text
Assert-Equal $true ($buildText.Contains('$buildCommand = $inksonBuildPlan.Command')) "managed build must use the official tested plan"
Assert-Equal $false ($buildText.Contains('finalize-inkson-joint-e2e-wasm.ps1')) "Glory startup must not receive the obsolete Dioxus loader"
Assert-Equal $true ($plans[0].Extent.Text.Contains('-PythonExecutable (Get-PythonExecutable)')) "build must use the discovered Python runtime"
Assert-Equal $true ($plans[0].Extent.Text.Contains('-BuildScript (Join-Path $InksonRoot "scripts/build_web.py")')) "build must use the actual checked-out Inkson entry point"
$required = @(Get-JointInksonRequiredArtifactPaths)
$expected = @("index.html", "bootstrap.js", "assets/pkg/inkson_bg.wasm", "assets/pkg/inkson.js", "assets/app.css", "assets/sapid.css", "ui-build-info.json")
Assert-Equal ($expected -join ',') ($required -join ',') "content identity must cover the official bootstrap, code, styles and provenance"
Assert-Equal 7 @($required | Select-Object -Unique).Count "required bundle members must be unique"
$quoted = Get-JointInksonBuildPlan -StartMockAppletRegistry $false -ArtifactFresh $false -TestFeaturePresent $false `
    -PythonExecutable "D:/Tool Dir/python.exe" -BuildScript "D:/Repo's/inkson/scripts/build_web.py"
Assert-Equal "& 'D:/Tool Dir/python.exe' 'D:/Repo''s/inkson/scripts/build_web.py' --profile joint-e2e --features 'web,wasm-localstorage-secrets-test'" $quoted.Command "real runtime and repository paths must be quoted without shell reinterpretation"

Write-Host "joint-client-selection.tests.ps1: PASS (client selection and Applet build feature/cache decisions)"
