$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../lib/build-freshness.ps1')
function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot '../run-joint-e2e.ps1'), [ref]$tokens, [ref]$errors)
Assert-True ($errors.Count -eq 0) 'Runner must parse'
foreach ($name in @('Get-CargoTargetDirectory', 'Get-NativeExecutableName', 'Resolve-ColandBinary', 'Add-PreflightResult', 'Add-BinaryFreshnessPreflight')) {
    $definition = $ast.Find({param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    Assert-True ($null -ne $definition) "Production function must exist: $name"
    Invoke-Expression $definition.Extent.Text
}
$freshnessCall = @($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -eq 'Add-BinaryFreshnessPreflight' -and
    $node.Extent.Text.Contains('"coland binary freshness"')
}, $true))
Assert-True ($freshnessCall.Count -eq 1) 'Test the actual Coland preflight call'
$task = @($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.HashtableAst] -and
    $node.Extent.Text.Contains('Name = "coland"; BuildInputsBefore =')
}, $true))
Assert-True ($task.Count -eq 1) 'Test the actual Coland build task source roots'
$resolveCalls = @($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Resolve-ColandBinary'
}, $true))
Assert-True ($resolveCalls.Count -eq 3) 'Preflight, service startup and provisioning must resolve the SUT'
foreach ($call in $resolveCalls) {
    Assert-True ($call.Extent.Text -match '-RepositoryRoot \$colandRepositoryRoot') 'Every consumer must resolve the selected checkout'
}

$parent = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../artifacts/coland-source-selection-tests'))
$testRoot = Join-Path $parent ([guid]::NewGuid().ToString('N'))
$workspaceRoot = Join-Path $testRoot 'workspace'
$defaultRoot = Join-Path $workspaceRoot 'coland'
$sdkRoot = Join-Path $workspaceRoot 'arkret-rust-sdk'
$colandRepositoryRoot = Join-Path $testRoot 'selected-worktree'
$oldBinary = $env:COLAND_BIN
$oldTarget = $env:CARGO_TARGET_DIR
$prepare = Join-Path $PSScriptRoot '../prepare-cargo-artifact.ps1'
function Initialize-Source([string]$Directory, [string]$Name, [bool]$Binary) {
    $null = New-Item -ItemType Directory -Path (Join-Path $Directory 'src') -Force
    $null = New-Item -ItemType Directory -Path (Join-Path $Directory '.cargo') -Force
    Set-Content -LiteralPath (Join-Path $Directory '.gitignore') -Value '/cargo-output/'
    Set-Content -LiteralPath (Join-Path $Directory '.cargo/config.toml') -Value "[build]`ntarget-dir = 'cargo-output'"
    Set-Content -LiteralPath (Join-Path $Directory 'Cargo.toml') -Value @"
[package]
name = '$Name'
version = '0.1.0'
edition = '2021'
[workspace]
"@
    $source = if ($Binary) { 'main.rs' } else { 'lib.rs' }
    Set-Content -LiteralPath (Join-Path $Directory "src/$source") -Value $(if ($Binary) { 'fn main() { println!("default"); }' } else { 'pub fn fixture() {}' })
    $null = Invoke-BuildInputNative -FilePath (Get-Command cargo).Source -WorkingDirectory $Directory -Arguments @('generate-lockfile', '--offline')
    $null = Invoke-BuildInputGit -RepositoryRoot $Directory -Arguments @('init', '-q')
    $null = Invoke-BuildInputGit -RepositoryRoot $Directory -Arguments @('add', '.')
    $null = Invoke-BuildInputGit -RepositoryRoot $Directory -Arguments @('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'source fixture')
}
function Read-SelectedFreshness {
    $results = [Collections.Generic.List[object]]::new()
    Invoke-Expression $freshnessCall[0].Extent.Text
    Assert-True ($results.Count -eq 1) 'Exactly one source-bound preflight result is required'
    return $results[0]
}
try {
    Remove-Item Env:COLAND_BIN, Env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue
    Initialize-Source $defaultRoot 'coland' $true
    Initialize-Source $sdkRoot 'sdk_fixture' $false
    $default = & $prepare -ManifestPath (Join-Path $defaultRoot 'Cargo.toml') -BinaryName coland -Jobs 1 -RepositoryRoots @($sdkRoot)
    $null = Invoke-BuildInputGit -RepositoryRoot $defaultRoot -Arguments @('worktree', 'add', '--detach', $colandRepositoryRoot, 'HEAD')
    Set-Content -LiteralPath (Join-Path $colandRepositoryRoot 'src/main.rs') -Value 'fn main() { println!("selected"); }'
    $selected = & $prepare -ManifestPath (Join-Path $colandRepositoryRoot 'Cargo.toml') -BinaryName coland -Jobs 1 -RepositoryRoots @($sdkRoot)
    $colandBin = ''
    $colandBinary = Resolve-ColandBinary -RepositoryRoot $colandRepositoryRoot
    Assert-True ($colandBinary -ceq $selected.ArtifactPath -and $colandBinary -cne $default.ArtifactPath) 'Selected worktree must win over an existing default binary and use Cargo target configuration'
    Assert-True ((Invoke-BuildInputNative -FilePath $colandBinary).Trim() -ceq 'selected') 'The selected executable must contain the selected source behavior'
    Assert-True ((Read-SelectedFreshness).status -ceq 'pass') 'Selected artifact must pass its actual source preflight'
    $preBuildStates = @(Get-ArtifactBuildRepositoryStates -ArtifactPath $colandBinary -RepositoryRoots @($colandRepositoryRoot, $sdkRoot))
    $defaultColandBinary = $colandBinary; $service = $null; $started = Get-Date
    $preparedTask = Invoke-Expression ('[pscustomobject]' + $task[0].Extent.Text)
    $taskStates = @(Get-ArtifactBuildRepositoryStates -ArtifactPath $colandBinary -RepositoryRoots $preparedTask.RepositoryRoots)
    Assert-True (Test-ArtifactBuildStamp -ArtifactPath $colandBinary -RepositoryStates $taskStates).Matches 'Managed build task and preflight must attest the same selected inputs'
    Set-Content -LiteralPath (Join-Path $defaultRoot 'README.md') -Value 'unrelated default checkout changed'
    Assert-True ((Read-SelectedFreshness).status -ceq 'pass') 'Unselected checkout must not control selected artifact freshness'
    $colandBinary = $default.ArtifactPath
    Assert-True ((Read-SelectedFreshness).status -ceq 'fail') 'Default artifact must not masquerade as the selected worktree artifact'
    $colandBinary = $selected.ArtifactPath
    Set-Content -LiteralPath (Join-Path $colandRepositoryRoot 'README.md') -Value 'selected build inputs changed'
    Assert-True ((Read-SelectedFreshness).status -ceq 'fail') 'Changed selected inputs must remain rejected without a new managed build'
    Write-Host 'PASS: selected worktree binary, Cargo target directory, actual executable behavior, matching build/preflight inputs and stale/wrong-source refusal'
} finally {
    $env:COLAND_BIN = $oldBinary; $env:CARGO_TARGET_DIR = $oldTarget
    if ((Test-Path -LiteralPath (Join-Path $defaultRoot '.git')) -and (Test-Path -LiteralPath (Join-Path $colandRepositoryRoot '.git'))) {
        $null = Invoke-BuildInputGit -RepositoryRoot $defaultRoot -Arguments @('worktree', 'remove', '--force', $colandRepositoryRoot)
    }
    if ((Split-Path $testRoot -Parent) -ne $parent) { throw 'Unexpected fixture cleanup target' }
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
