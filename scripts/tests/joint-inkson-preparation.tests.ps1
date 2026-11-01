$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../lib/build-freshness.ps1')
$runner = Join-Path $PSScriptRoot '../run-joint-e2e.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($runner, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Runner must parse' }
$pathsFunction = @($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-JointInksonRequiredArtifactPaths'
}, $true))
Invoke-Expression $pathsFunction[0].Extent.Text
$taskDefinition = @($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.HashtableAst] -and $node.Extent.Text.Contains('Name = "inkson";')
}, $true))
$verification = @($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.ForEachStatementAst] -and
    $node.Condition.Extent.Text -eq '$preparationTasks' -and
    $node.Body.Extent.Text.Contains('artifact_updated=False')
}, $true))
if ($taskDefinition.Count -ne 1 -or $verification.Count -ne 1) { throw 'Expected actual Inkson task and preparation verification loop' }

$parent = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../artifacts/inkson-preparation-tests'))
$null = New-Item -ItemType Directory -Path $parent -Force
$jointDir = Join-Path $parent ([guid]::NewGuid().ToString('N'))
$inksonStaticRoot = Join-Path $jointDir 'web'
$inksonStaticIndex = Join-Path $inksonStaticRoot 'index.html'
$inksonWasm = Join-Path $inksonStaticRoot 'assets/pkg/inkson_bg.wasm'
$InksonRoot = Join-Path $jointDir 'source'
$workspaceRoot = $jointDir
$preBuildStates = @([pscustomobject]@{RepositoryRoot=$InksonRoot;Head=('a'*40);SourceSha256=('b'*64);DirtySha256=('c'*64)})
function Get-ArtifactBuildRepositoryStates { param($ArtifactPath, $RepositoryRoots, $ArtifactRoot) return $preBuildStates }
function Assert-Rejected([scriptblock]$Action, [string]$Expected) {
    try { & $Action } catch {
        if ($_.Exception.Message -notlike "*$Expected*") { throw }
        return
    }
    throw "Expected rejection: $Expected"
}
try {
    foreach ($relative in @(Get-JointInksonRequiredArtifactPaths)) {
        $file = Join-Path $inksonStaticRoot $relative
        $null = New-Item -ItemType Directory -Path (Split-Path $file -Parent) -Force
        Set-Content -LiteralPath $file -Value 'fixture bundle member'
    }
    $started = (Get-Date).AddSeconds(-10)
    $old = $started.ToUniversalTime().AddDays(-1)
    [IO.File]::SetLastWriteTimeUtc($inksonStaticIndex, $old)
    $service = [pscustomobject]@{Process=[pscustomobject]@{ExitCode=0;ExitTime=(Get-Date)};Stdout='fixture stdout';Stderr='fixture stderr'}
    $preparationTasks = @((Invoke-Expression ('[pscustomobject]' + $taskDefinition[0].Extent.Text)))
    $preparationTimings = [Collections.Generic.List[object]]::new()
    [IO.File]::SetLastWriteTimeUtc($inksonWasm, $old)
    Assert-Rejected { Invoke-Expression $verification[0].Extent.Text } 'artifact_updated=False'
    [IO.File]::SetLastWriteTimeUtc($inksonWasm, [DateTime]::UtcNow)
    Invoke-Expression $verification[0].Extent.Text
    if ((Get-Item $inksonStaticIndex).LastWriteTimeUtc -ne $old) { throw 'Preparation must preserve the copied HTML timestamp' }
    $stamp = Test-ArtifactBuildStamp -ArtifactPath $inksonStaticIndex -ArtifactRoot $inksonStaticRoot -RequiredArtifactPaths @(Get-JointInksonRequiredArtifactPaths) -RepositoryStates $preBuildStates
    if (-not $stamp.Matches) { throw 'Fresh WASM and unchanged copied HTML must produce a content-bound stamp' }
    $service.Process.ExitCode = 37
    Assert-Rejected { Invoke-Expression $verification[0].Extent.Text } 'exit=37'
    $service.Process.ExitCode = 0
    $wasmTime = (Get-Item $inksonWasm).LastWriteTimeUtc
    Add-Content -LiteralPath $inksonWasm -Value 'tampered content'
    [IO.File]::SetLastWriteTimeUtc($inksonWasm, $wasmTime)
    if ((Test-ArtifactBuildStamp -ArtifactPath $inksonStaticIndex -ArtifactRoot $inksonStaticRoot -RepositoryStates $preBuildStates).Matches) { throw 'Changed WASM bytes must invalidate the stamp even at unchanged mtime' }
    Remove-Item -LiteralPath (Join-Path $inksonStaticRoot 'assets/app.css')
    Assert-Rejected { Invoke-Expression $verification[0].Extent.Text } 'Required served bundle member is missing'
    Write-Host 'PASS: copied HTML mtime, fresh/stale WASM, failed build, content tampering and missing bundle members'
} finally {
    $resolved = [IO.Path]::GetFullPath($jointDir)
    if ((Split-Path $resolved -Parent) -ne $parent) { throw 'Unexpected preparation fixture cleanup target' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
