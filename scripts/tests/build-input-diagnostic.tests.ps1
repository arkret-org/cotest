$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../lib/build-freshness.ps1')

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('cotest-input-diagnostic-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $testRoot
try {
    $repo = Join-Path $testRoot 'source'
    $null = New-Item -ItemType Directory -Path $repo
    Invoke-BuildInputGit -RepositoryRoot $repo -Arguments @('init', '--quiet') | Out-Null
    $source = Join-Path $repo 'source.txt'
    Set-Content -LiteralPath $source -Value 'private source body before'
    Invoke-BuildInputGit -RepositoryRoot $repo -Arguments @('add', '.') | Out-Null
    Invoke-BuildInputGit -RepositoryRoot $repo -Arguments @('-c', 'user.name=Cotest', '-c', 'user.email=cotest@example.invalid', 'commit', '--quiet', '-m', 'input fixture') | Out-Null
    $artifact = Join-Path $testRoot 'artifact'
    $before = Get-RepositoryBuildInputState -RepositoryRoot $repo -BinaryPath $artifact
    $time = (Get-Item $source).LastWriteTimeUtc
    Set-Content -LiteralPath $source -Value 'private source body after'
    (Get-Item $source).LastWriteTimeUtc = $time
    $after = Get-RepositoryBuildInputState -RepositoryRoot $repo -BinaryPath $artifact
    $path = Join-Path $testRoot 'mismatch.json'
    $rejected = $false
    try { Assert-BuildInputStatesUnchanged -Before @($before) -After @($after) -DiagnosticPath $path }
    catch { $rejected = $_.Exception.Message -ceq 'Build inputs changed during the managed build; refusing to stamp the artifact' }
    Assert-True $rejected 'changed bytes must retain the exact strict rejection'
    $raw = Get-Content -LiteralPath $path -Raw
    $diagnostic = $raw | ConvertFrom-Json
    $beforeRecord = @($diagnostic.before[0].files | Where-Object path -CEQ 'source.txt')[0]
    $afterRecord = @($diagnostic.after[0].files | Where-Object path -CEQ 'source.txt')[0]
    Assert-True ($beforeRecord.sha256 -cne $afterRecord.sha256) 'both captured source digests must be retained despite unchanged mtime'
    Assert-True ($diagnostic.before[0].source_sha256 -ceq $before.SourceSha256) 'diagnostic must retain the actual original source digest'
    Assert-True ($diagnostic.after[0].source_sha256 -ceq $after.SourceSha256) 'diagnostic must retain the actual final source digest'
    Assert-True (-not $raw.Contains($testRoot) -and -not $raw.Contains('private source body')) 'absolute paths and source bodies must stay private'
    if (-not $IsWindows) {
        Assert-True ([IO.File]::GetUnixFileMode($path) -eq ([IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite)) 'diagnostic must be owner-only'
    }

    $unchangedPath = Join-Path $testRoot 'unchanged.json'
    Assert-BuildInputStatesUnchanged -Before @($after) -After @($after) -DiagnosticPath $unchangedPath
    Assert-True (-not (Test-Path $unchangedPath)) 'unchanged inputs must not create a mismatch report'
    $failedDiagnosticRejected = $false
    try { Assert-BuildInputStatesUnchanged -Before @($before) -After @($after) -DiagnosticPath (Join-Path $testRoot 'missing/diagnostic.json') }
    catch { $failedDiagnosticRejected = $_.Exception.Message -ceq 'Build inputs changed during the managed build; refusing to stamp the artifact' }
    Assert-True $failedDiagnosticRejected 'diagnostic I/O failure must never authorize the build'

    $privatePath = 'cargo_configuration:/private/credential-directory/config.toml'
    $privateTarget = '/private/credential-directory/link-target'
    $before.BuildInputFiles = @([ordered]@{ path = $privatePath; sha256 = 'a' * 64; target = $privateTarget; mode = 'UserRead' })
    $after.BuildInputFiles = @([ordered]@{ path = $privatePath; sha256 = 'a' * 64; target = '/private/other-target'; mode = 'UserRead' })
    try { Assert-BuildInputStatesUnchanged -Before @($before) -After @($after) -DiagnosticPath $path } catch { }
    $raw = Get-Content -LiteralPath $path -Raw
    $diagnostic = $raw | ConvertFrom-Json
    Assert-True (-not $raw.Contains('/private/') -and $diagnostic.before[0].files[0].path.StartsWith('external_cargo_configuration:')) 'external config and symlink paths must be opaque'
    Assert-True ($diagnostic.before[0].files[0].record_sha256 -cne $diagnostic.after[0].files[0].record_sha256) 'equal file bytes with changed link metadata must remain distinguishable'
    Write-Host 'PASS build-input diagnostics: exact before/after, privacy, unchanged inputs, I/O failure, metadata identity'
} finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force
}
