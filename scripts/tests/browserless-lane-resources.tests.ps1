# The browserless lane's two standing claims, as a gate.
#
# 1. `joint-api` prepares no browser resources. The runner half of that is
#    already covered by joint-client-selection.tests.ps1 (Resolve-InksonRequirement
#    returns false). What was never covered is the Playwright half: the project
#    could grow a `dependencies: ["inkson-build-id"]` entry, or a browser
#    device, and the runner would still refuse to start Inkson -- so the setup
#    project would run against nothing. Collection is the observable: a project
#    that depends on the setup collects its test, and one that does not, does
#    not.
#
# 2. The selection does not shrink. The counts below are floors captured on
#    2026-09-15, not equalities: adding specs is the normal case and must not
#    fail a gate, while a lane that quietly collects fewer tests than it used to
#    is exactly the regression the light-edge and api-only work can cause. Raise
#    a floor deliberately when a lane grows; never lower one to make this pass.
#
# Requires only `e2e/node_modules` -- no services, no browsers, no sibling
# repositories.

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$e2eRoot = Join-Path $repoRoot "e2e"
$runnerText = Get-Content -LiteralPath (Join-Path $repoRoot "scripts\run-joint-e2e.ps1") -Raw
$playwrightCli = Join-Path $e2eRoot "node_modules\playwright\cli.js"
if (-not (Test-Path -LiteralPath $playwrightCli -PathType Leaf)) {
    throw "Playwright CLI is not installed: $playwrightCli (run 'npm install' in e2e/)"
}

# The setup project. It is never selected directly; the browser lanes pull it in
# through `dependencies`, which is what makes its presence in a collection the
# signal this gate reads.
$setupProject = "inkson-build-id"

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Get-RunnerProjectList {
    param([Parameter(Mandatory = $true)][string]$Variable)

    $pattern = '\$script:' + $Variable + '\s*=\s*@\(([^)]*)\)'
    $match = [regex]::Match($runnerText, $pattern)
    Assert-True $match.Success "run-joint-e2e.ps1 no longer declares `$script:$Variable"
    return @([regex]::Matches($match.Groups[1].Value, '"([^"]+)"') |
        ForEach-Object { $_.Groups[1].Value })
}

function Invoke-PlaywrightList {
    param(
        [Parameter(Mandatory = $true)][string]$Project,
        [string]$Grep
    )

    $arguments = @($playwrightCli, "test", "--config", "playwright.config.ts", "--project=$Project", "--list")
    if ($Grep) { $arguments += @("--grep", $Grep) }
    Push-Location $e2eRoot
    try {
        $output = @(& node @arguments 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "Playwright listing for project '$Project' failed:`n$($output -join [Environment]::NewLine)"
        }
    }
    finally {
        Pop-Location
    }

    $text = ($output -join "`n")
    $total = [regex]::Match($text, 'Total:\s+(\d+)\s+tests?\s+in\s+(\d+)\s+files?')
    Assert-True $total.Success "Playwright listing for '$Project' printed no total:`n$text"
    return [pscustomobject]@{
        project = $Project
        text    = $text
        tests   = [int]$total.Groups[1].Value
        files   = [int]$total.Groups[2].Value
        setup   = @([regex]::Matches($text, [regex]::Escape("[$setupProject]"))).Count
    }
}

# --- 1. The runner and the Playwright config must describe the same projects ---

# `@()` at the call site: a single-element list returned from a function
# unrolls to a scalar, and the emptiness check below needs an array.
$browserProjects = @(Get-RunnerProjectList -Variable "BrowserPlaywrightProjects")
$browserlessProjects = @(Get-RunnerProjectList -Variable "BrowserlessPlaywrightProjects")
Assert-True ($browserlessProjects.Count -gt 0) "the runner declares no browserless project"
Assert-True ($browserProjects -notcontains $setupProject) "the setup project must not be listed as a selectable browser project"
Assert-True ($browserlessProjects -notcontains $setupProject) "the setup project must not be listed as a browserless project"

# `config.projects` in the JSON report is the resolved project list, so a
# project added to playwright.config.ts and not to the runner's two lists is
# caught here rather than by a run that guesses at its resources.
Push-Location $e2eRoot
try {
    $reportJson = & node $playwrightCli test --config playwright.config.ts --project=$($browserlessProjects[0]) --list --reporter=json 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Playwright JSON listing failed for project '$($browserlessProjects[0])'"
    }
}
finally {
    Pop-Location
}
$configuredProjects = @((($reportJson -join "`n") | ConvertFrom-Json).config.projects | ForEach-Object { $_.name })
$known = @($browserProjects + $browserlessProjects + $setupProject)
$unknown = @($configuredProjects | Where-Object { $_ -notin $known })
Assert-True ($unknown.Count -eq 0) (
    "playwright.config.ts declares project(s) the runner cannot classify: $($unknown -join ', '). " +
    "Add them to `$script:BrowserPlaywrightProjects or `$script:BrowserlessPlaywrightProjects in run-joint-e2e.ps1.")
$missing = @($known | Where-Object { $_ -notin $configuredProjects })
Assert-True ($missing.Count -eq 0) (
    "run-joint-e2e.ps1 names project(s) playwright.config.ts does not define: $($missing -join ', ')")

# --- 2. Browserless projects prepare no browser resources -------------------

foreach ($project in $browserlessProjects) {
    $listing = Invoke-PlaywrightList -Project $project
    Assert-True ($listing.setup -eq 0) (
        "project '$project' collects the $setupProject setup project, so it prepares an Inkson bundle " +
        "and a browser. A browserless lane must declare no browser dependency.")
    Assert-True ($listing.tests -gt 0) "project '$project' collects no tests; an empty lane reports green having tested nothing"
}

# The same assertion the other way round, so the check above cannot pass because
# collection stopped reporting the setup project at all.
foreach ($project in $browserProjects) {
    $listing = Invoke-PlaywrightList -Project $project
    Assert-True ($listing.setup -ge 1) (
        "browser project '$project' no longer collects the $setupProject setup project; " +
        "its build-id gate is not running.")
}

# --- 3. Selection floors ----------------------------------------------------

# Captured 2026-09-15 from this checkout. Floors, not equalities.
$floors = @(
    @{ project = "chrome"; grep = $null; tests = 279; files = 67; label = "joint-full default lane" },
    @{ project = "chromium"; grep = $null; tests = 279; files = 67; label = "chromium lane" },
    @{ project = "chrome"; grep = "@fully-implemented"; tests = 69; files = 29; label = "joint-smoke PR gate" },
    @{ project = "joint-inkson"; grep = $null; tests = 38; files = 17; label = "joint-inkson identity lane" },
    @{ project = "joint-api"; grep = $null; tests = 71; files = 16; label = "joint-api browserless lane" }
)

foreach ($floor in $floors) {
    $listing = Invoke-PlaywrightList -Project $floor.project -Grep $floor.grep
    Assert-True ($listing.tests -ge $floor.tests) (
        "$($floor.label) shrank: project '$($floor.project)'" +
        $(if ($floor.grep) { " --grep $($floor.grep)" } else { "" }) +
        " collects $($listing.tests) tests, floor is $($floor.tests).")
    Assert-True ($listing.files -ge $floor.files) (
        "$($floor.label) shrank: project '$($floor.project)'" +
        $(if ($floor.grep) { " --grep $($floor.grep)" } else { "" }) +
        " collects $($listing.files) files, floor is $($floor.files).")
    Write-Host ("  {0,-22} {1,-18} {2,3} tests / {3,2} files (floor {4}/{5})" -f
        $floor.project, ($floor.grep ?? "-"), $listing.tests, $listing.files, $floor.tests, $floor.files)
}

Write-Host "browserless-lane-resources.tests.ps1: PASS"
