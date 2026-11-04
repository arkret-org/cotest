$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
. (Join-Path $PSScriptRoot '../lib/build-freshness.ps1')
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot '../run-joint-e2e.ps1'), [ref]$tokens, [ref]$errors)
Assert-True ($errors.Count -eq 0) 'production runner must parse'
foreach ($name in @('Get-JointSourceHeads', 'Select-JointSourceFreezePaths', 'Get-JointSourceFreezeState', 'Complete-JointSourceFreeze')) {
    $definition = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    Assert-True ($null -ne $definition) "production $name must exist"
    Invoke-Expression $definition.Extent.Text
}
$root = Join-Path ([IO.Path]::GetTempPath()) ('cotest-source-freeze-' + [guid]::NewGuid())
$null = New-Item -ItemType Directory -Path $root
try {
    $repo = Join-Path $root 'selected-coland'
    $other = Join-Path $root 'default-coland'
    foreach ($path in @($repo, $other)) {
        $null = New-Item -ItemType Directory -Path $path
        $null = Invoke-BuildInputGit -RepositoryRoot $path -Arguments @('init', '--quiet')
        Set-Content -LiteralPath (Join-Path $path '.gitignore') -Value 'artifacts/'
        Set-Content -LiteralPath (Join-Path $path 'input.rs') -Value 'original source'
        $null = Invoke-BuildInputGit -RepositoryRoot $path -Arguments @('add', '.')
        $null = Invoke-BuildInputGit -RepositoryRoot $path -Arguments @('-c', 'user.name=Cotest Fixture', '-c', 'user.email=cotest@example.invalid', 'commit', '--quiet', '-m', 'original')
    }
    $nested = Join-Path $repo 'nested'; $null = New-Item -ItemType Directory -Path $nested
    $paths = [ordered]@{ selected = $repo; nested = $nested; missing = (Join-Path $root 'missing') }
    $allSources = [ordered]@{ coland = $repo; inkson = $other }
    $apiSources = Select-JointSourceFreezePaths -RepositoryPaths $allSources -RequiresInkson $false
    Assert-True (-not $apiSources.Contains('inkson')) 'a browserless run must not inventory unused Inkson sources'
    Assert-True ($apiSources.coland -eq $repo) 'the actual selected Coland checkout must be retained'
    $uiSources = Select-JointSourceFreezePaths -RepositoryPaths $allSources -RequiresInkson $true
    Assert-True ($uiSources.inkson -eq $other) 'a UI run must bind its actual Inkson source'

    $output = Join-Path $repo 'artifacts/guard'; $null = New-Item -ItemType Directory -Path $output -Force
    $before = Get-JointSourceFreezeState -RepositoryPaths $paths -ArtifactDirectory $output
    Set-Content -LiteralPath (Join-Path $output 'ignored.log') -Value 'runtime artifact'
    Set-Content -LiteralPath (Join-Path $other 'input.rs') -Value 'unselected checkout changed'
    $result = Complete-JointSourceFreeze -Before $before -RepositoryPaths $paths -ArtifactDirectory $output -ExitCode 0
    Assert-True ($result.source_stable -and $result.exit_code -eq 0) 'ignored outputs and an unselected checkout cannot invalidate the selected source'
    Assert-True ($result.source_coverage -eq 'partial') 'missing and nested sources must remain explicitly unknown'
    Assert-True ($result.recorded_repositories -eq 1) 'a nested directory must not borrow its parent HEAD'

    $input = Join-Path $repo 'input.rs'; $time = (Get-Item $input).LastWriteTimeUtc
    $private = 'synthetic-source-private-content-AAAABBBBCCCC'
    Set-Content -LiteralPath $input -Value $private
    (Get-Item $input).LastWriteTimeUtc = $time
    $result = Complete-JointSourceFreeze -Before $before -RepositoryPaths $paths -ArtifactDirectory $output -ExitCode 0
    Assert-True (-not $result.source_stable -and $result.exit_code -eq 1) 'same-mtime content changes must turn a successful browser exit into failure'
    $published = (Get-Content (Join-Path $output 'source-freeze.json') -Raw) + (Get-Content (Join-Path $output 'source-freeze-mismatch.json') -Raw)
    Assert-True (-not $published.Contains($private)) 'source provenance must never publish source contents'
    Assert-True (-not $published.Contains($root)) 'public source diagnostics must not disclose private absolute roots'
    $result = Complete-JointSourceFreeze -Before $before -RepositoryPaths $paths -ArtifactDirectory $output -ExitCode 101
    Assert-True ($result.exit_code -eq 101) 'an original nonzero test exit must be preserved'

    $null = Invoke-BuildInputGit -RepositoryRoot $repo -Arguments @('checkout', '--', 'input.rs')
    $before = Get-JointSourceFreezeState -RepositoryPaths $paths -ArtifactDirectory $output
    $null = Invoke-BuildInputGit -RepositoryRoot $repo -Arguments @('-c', 'user.name=Cotest Fixture', '-c', 'user.email=cotest@example.invalid', 'commit', '--allow-empty', '--quiet', '-m', 'new HEAD, identical source')
    $result = Complete-JointSourceFreeze -Before $before -RepositoryPaths $paths -ArtifactDirectory $output -ExitCode 0
    Assert-True (-not $result.source_stable -and $result.exit_code -eq 1) 'a changed HEAD invalidates provenance even with identical tracked bytes'

    $before = Get-JointSourceFreezeState -RepositoryPaths $paths -ArtifactDirectory $output
    Set-Content -LiteralPath (Join-Path $repo 'new-source.rs') -Value 'new source'
    $result = Complete-JointSourceFreeze -Before $before -RepositoryPaths $paths -ArtifactDirectory $output -ExitCode 0
    Assert-True (-not $result.source_stable) 'new nonignored source must be detected'
    $before = Get-JointSourceFreezeState -RepositoryPaths $paths -ArtifactDirectory $output
    $result = Complete-JointSourceFreeze -Before $before -RepositoryPaths $paths -ArtifactDirectory $output -ExitCode 0
    Assert-True ($result.source_stable) 'an unchanged qualified dirty checkout is a stable input'
    $null = Invoke-BuildInputGit -RepositoryRoot $repo -Arguments @('checkout', '--', 'input.rs')
    Move-Item -LiteralPath $repo -Destination (Join-Path $root 'removed-selected')
    $output = Join-Path $root 'removed-output'; $null = New-Item -ItemType Directory -Path $output
    $result = Complete-JointSourceFreeze -Before $before -RepositoryPaths $paths -ArtifactDirectory $output -ExitCode 0
    Assert-True (-not $result.source_stable -and $result.exit_code -eq 1) 'a disappearing selected repository must fail closed'
    $result = Complete-JointSourceFreeze -Before $null -RepositoryPaths $paths -ArtifactDirectory $output -ExitCode 0
    Assert-True (-not $result.source_stable -and $result.exit_code -eq 1) 'missing entry capture cannot authorize success'

    $calls = @($ast.FindAll({ param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Complete-JointSourceFreeze'
    }, $true))
    Assert-True ($calls.Count -eq 1) 'the actual runner must call the final source gate once'
    Assert-True ($ast.Extent.Text.Contains('$exitCode = $sourceFreezeReport.exit_code')) 'runner exit must consume the actual guard verdict'
    Assert-True ($ast.Extent.Text.Contains('source_stable = $sourceFreezeReport.source_stable')) 'summary must publish the guard verdict'
    Assert-True ($ast.Extent.Text.Contains('$sourceFreezeBefore = Get-JointSourceFreezeState')) 'runner must capture the original source before preparation'
    Write-Host 'joint-source-freeze.tests.ps1: PASS'
} finally {
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
