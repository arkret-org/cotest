$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$runner = Join-Path $PSScriptRoot '../run-joint-e2e.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($runner, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Runner must parse' }
foreach ($name in @('Quote-PsLiteral', 'Get-JointSavfoxBuildCommand')) {
    $functions = @($ast.FindAll({param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true))
    if ($functions.Count -ne 1) { throw "Expected actual production function $name" }
    Invoke-Expression $functions[0].Extent.Text
}
$calls = @($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Get-JointSavfoxBuildCommand'
}, $true))
if ($calls.Count -ne 1) { throw 'Managed preparation must consume the tested builder exactly once' }
$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$temporary = Join-Path $tempBase ('cotest-savfox-build-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $temporary
$shell = (Get-Process -Id $PID).Path
try {
    foreach ($case in @(
        @{name='windows-cli-only-debug';windows=$true;webExit=0;exit=0},
        @{name='other-platform-unchanged';windows=$false;webExit=0;exit=0},
        @{name='web-failure-stops-cargo';windows=$true;webExit=37;exit=37}
    )) {
        $caseRoot = Join-Path $temporary $case.name
        $null = New-Item -ItemType Directory -Path $caseRoot
        $stepsPath = Join-Path $caseRoot 'steps.json'
        $savfoxPowerShell = 'Invoke-FixtureWebBuild'
        $savfoxWebBuild = "D:/fixture/Savfox web's/build-web.ps1"
        $savfoxManifest = "D:/fixture/Savfox repo's/Cargo.toml"
        # Evaluate the real managed branch call with only its platform input
        # replaced, so argument forwarding and the builder stay connected.
        $call = $calls[0].Extent.Text.Replace('([bool]$IsWindows)', ('$' + $case.windows.ToString().ToLowerInvariant()))
        $command = Invoke-Expression $call
        $prelude = @'
$ErrorActionPreference='Stop'
$script:steps=[Collections.Generic.List[object]]::new()
function Invoke-FixtureWebBuild {
 param([switch]$NoProfile,[string]$File)
 $script:steps.Add(@{kind='web';file=$File;no_profile=[bool]$NoProfile})
 $global:LASTEXITCODE=__WEB_EXIT__
}
function cargo {
 $script:steps.Add(@{kind='cargo';arguments=@($args)})
 $global:LASTEXITCODE=0
}
try {
__COMMAND__
} finally {
 $script:steps | ConvertTo-Json -Depth 6 -AsArray | Set-Content -LiteralPath __STEPS__ -Encoding utf8
}
'@
        $fixture = $prelude.Replace('__WEB_EXIT__', [string]$case.webExit).Replace('__COMMAND__', $command).Replace('__STEPS__', (Quote-PsLiteral $stepsPath))
        $fixturePath = Join-Path $caseRoot 'fixture.ps1'
        Set-Content -LiteralPath $fixturePath -Value $fixture -Encoding utf8
        & $shell -NoProfile -File $fixturePath *> (Join-Path $caseRoot 'output.log')
        $actualExit = $LASTEXITCODE
        if ($actualExit -ne $case.exit) { throw "Wrong actual child exit for $($case.name): $actualExit" }
        $steps = @(Get-Content -LiteralPath $stepsPath -Raw | ConvertFrom-Json)
        if ($steps[0].kind -cne 'web' -or $steps[0].file -cne $savfoxWebBuild -or -not $steps[0].no_profile) { throw 'Web build must run first with its exact quoted path' }
        if ($case.webExit -ne 0) {
            if ($steps.Count -ne 1) { throw 'Cargo ran after web build failed' }
        } else {
            if ($steps.Count -ne 2 -or $steps[1].kind -cne 'cargo') { throw 'Expected exactly web then Cargo' }
            $expected = @('build','--manifest-path',$savfoxManifest,'--bin','savfox','--features','savfox-gateway-server/arkret')
            if ($case.windows) { $expected += @('--config','profile.dev.package.savfox-cli.debug=0') }
            if ((ConvertTo-Json -InputObject @($steps[1].arguments) -Compress) -cne (ConvertTo-Json -InputObject $expected -Compress)) { throw 'Normal command arguments or narrow Windows override changed' }
        }
        Write-Host "PASS $($case.name) (actual builder and mock process argv/exit)"
    }
    Write-Host 'joint-savfox-build.tests.ps1: PASS (3 mock command cases; no Cargo build)'
} finally {
    $resolved = [IO.Path]::GetFullPath($temporary)
    if (-not $resolved.StartsWith($tempBase.TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolved) -notlike 'cotest-savfox-build-*') { throw 'Test cleanup escaped its unique temporary directory' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
