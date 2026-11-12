$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$runner = Join-Path $repoRoot 'scripts/run-joint-e2e.ps1'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($runner, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw 'Runner parse failed' }
$definition = @($ast.FindAll({param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Assert-SdkGeneratedSourcesCurrent'
}, $true))
if ($definition.Count -ne 1) { throw 'Expected one SDK generated-source guard' }
Invoke-Expression $definition[0].Extent.Text
$calls = @($ast.FindAll({param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -eq 'Assert-SdkGeneratedSourcesCurrent'
}, $true))
$builds = @($ast.FindAll({param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -eq 'Start-ManagedCommand' -and
    $node.Extent.Text.Contains('"prepare-coland"')
}, $true))
if ($calls.Count -ne 1 -or $builds.Count -ne 1 -or
    $calls[0].Extent.StartOffset -ge $builds[0].Extent.StartOffset) {
    throw 'SDK source guard must precede the first Coland preparation'
}
$artifactRoot = Join-Path $repoRoot ('artifacts/sdk-generated-preflight/' + [Guid]::NewGuid().ToString('N'))
$sdk = Join-Path $artifactRoot 'sdk source'
$spec = Join-Path $artifactRoot 'spec source'
$logs = Join-Path $artifactRoot 'logs'
$null = New-Item -ItemType Directory -Force -Path (Join-Path $sdk 'tools'), $spec
$fake = @'
param([string]$ArtifactsDir, [switch]$Check)
if (-not $Check -or -not (Test-Path -LiteralPath $ArtifactsDir)) { exit 23 }
if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot '../generated-current'))) {
    Write-Output 'stale generated input refused'
    exit 17
}
Write-Output 'current generated inputs accepted'
'@
[System.IO.File]::WriteAllText((Join-Path $sdk 'tools/sync-spec.ps1'), $fake)
$refused = $false
try { Assert-SdkGeneratedSourcesCurrent -SdkRoot $sdk -SpecArtifactsDirectory $spec -LogDirectory $logs }
catch {
    if ($_.Exception.Message -notlike '*exit=17*') { throw }
    $refused = $true
}
if (-not $refused) { throw 'Stale generated inputs were accepted' }
if ((Get-Content -LiteralPath (Join-Path $logs 'check-sdk-generated.log') -Raw) -notlike '*stale generated input refused*') {
    throw 'The original checker failure was not retained'
}
[System.IO.File]::WriteAllText((Join-Path $sdk 'generated-current'), 'ready')
Assert-SdkGeneratedSourcesCurrent -SdkRoot $sdk -SpecArtifactsDirectory $spec -LogDirectory $logs
if ((Get-Content -LiteralPath (Join-Path $logs 'check-sdk-generated.log') -Raw) -notlike '*current generated inputs accepted*') {
    throw 'The read-only Check invocation did not succeed'
}
Write-Output 'SDK preflight: stale refusal, current acceptance, argument paths and preparation order passed.'
