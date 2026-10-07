$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-Equal($Expected, $Actual, [string]$Message) {
    if ($Expected -ne $Actual) { throw "$Message expected='$Expected' actual='$Actual'" }
}

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $repoRoot "scripts\run-joint-e2e.ps1"),
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -gt 0) { throw "Joint runner has PowerShell parse errors" }
foreach ($name in @("Quote-PsLiteral", "New-ManagedSavfoxProbe")) {
    $functions = @($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq $name
            }, $true))
    Assert-Equal 1 $functions.Count "$name function count"
    Invoke-Expression $functions[0].Extent.Text
}

function Start-ManagedCommand {
    param($Name, $Command, $WorkingDirectory, $LogDirectory)
    if ($Command -notlike "*mock-savfox-model.mjs*") { throw "Unexpected model command" }
    [pscustomobject]@{ Name = $Name }
}

function Wait-HttpReady {
    param($Url, $TimeoutSeconds)
    Assert-Equal 30 $TimeoutSeconds "model readiness budget"
    if ($Url -notlike "*/health") { throw "Unexpected readiness route" }
}

$tempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$tempRoot = [System.IO.Path]::GetFullPath((Join-Path $tempBase ("cotest-savfox-probe-" + [guid]::NewGuid().ToString("N"))))
try {
    $services = [System.Collections.ArrayList]@([pscustomobject]@{ Name = "existing" })
    foreach ($name in @("savfox", "savfox-unaddressed")) {
        $probe = New-ManagedSavfoxProbe -Name $name -JointDirectory $tempRoot `
            -MocksRoot (Join-Path $repoRoot "e2e\mocks") -LogDirectory $tempRoot `
            -BaseUrl "http://127.0.0.1:18001" -Port 18001 -Token "probe-test-token" `
            -ModelBaseUrl "http://127.0.0.1:18002" -ModelPort 18002 -ManagedServices $services
        $configPath = Join-Path $probe.Home "config.toml"
        $json = & python -X utf8 -c 'import json,sys,tomllib; print(json.dumps(tomllib.loads(open(sys.argv[1],encoding="utf-8-sig").read())))' $configPath
        if ($LASTEXITCODE -ne 0) { throw "Generated probe TOML is invalid" }
        $config = $json | ConvertFrom-Json
        Assert-Equal $false $config.gateway.response_footer.enabled "$name reply decoration"
        Assert-Equal "joint_mock" $config.model_provider "$name provider"
        Assert-Equal "joint-pong" $config.model.slug "$name deterministic model"
        Assert-Equal 0 $config.model_providers.joint_mock.request_max_retries "$name model request budget"
        Assert-Equal 0 $config.model_providers.joint_mock.stream_max_retries "$name model stream budget"
        Assert-Equal "read-only" $config.sandbox_mode "$name sandbox"
        Assert-Equal $name $probe.Name "$name identity"
    }
    Assert-Equal 3 $services.Count "both probes register independent managed models"
}
finally {
    $resolvedRoot = [System.IO.Path]::GetFullPath($tempRoot)
    if (-not $resolvedRoot.StartsWith($tempBase, [System.StringComparison]::OrdinalIgnoreCase) -or
        [System.IO.Path]::GetFileName($resolvedRoot) -notlike "cotest-savfox-probe-*") {
        throw "Refusing to remove a path outside the generated probe test directory"
    }
    if (Test-Path -LiteralPath $resolvedRoot) { Remove-Item -LiteralPath $resolvedRoot -Recurse -Force }
}

Write-Host "joint-savfox-probe.tests.ps1: PASS"
