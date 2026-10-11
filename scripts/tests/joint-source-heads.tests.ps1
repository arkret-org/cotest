$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

. (Join-Path $PSScriptRoot "../lib/build-freshness.ps1")
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot "../run-joint-e2e.ps1"), [ref]$tokens, [ref]$parseErrors
)
Assert-True ($parseErrors.Count -eq 0) "joint runner must parse"
$function = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq "Get-JointSourceHeads"
}, $true)
Assert-True ($null -ne $function) "production source HEAD collector must exist"
Invoke-Expression $function.Extent.Text
Assert-True ($ast.Extent.Text.Contains('preflight-source-heads.json')) "runner must upload-address the source snapshot"
Assert-True ($ast.Extent.Text.Contains('preflight_source_heads = $preflightSourceHeads')) "summary must retain actual source snapshot"

$root = Join-Path ([System.IO.Path]::GetTempPath()) ("cotest-source-heads-" + [guid]::NewGuid())
$null = New-Item -ItemType Directory -Path $root
try {
    $repo = Join-Path $root "selected"
    $null = New-Item -ItemType Directory -Path $repo
    $null = Invoke-BuildInputGit -RepositoryRoot $repo -Arguments @("init", "--quiet")
    $null = Invoke-BuildInputGit -RepositoryRoot $repo -Arguments @("-c", "user.name=Cotest Fixture", "-c", "user.email=cotest@example.invalid", "commit", "--allow-empty", "--quiet", "-m", "fixture input")
    $head = (Invoke-BuildInputGit -RepositoryRoot $repo -Arguments @("rev-parse", "HEAD")).Trim()
    $nested = Join-Path $repo "not-a-sibling-repository"
    $null = New-Item -ItemType Directory -Path $nested
    $snapshot = Get-JointSourceHeads -RepositoryPaths ([ordered]@{
        selected = $repo
        nested = $nested
        missing = (Join-Path $root "absent")
        nongit = $root
        unspecified = $null
    })
    Assert-True ($snapshot.repository_heads.selected.head -eq $head) "must record the selected checkout's actual full HEAD"
    Assert-True ($snapshot.repository_heads.selected.status -eq "recorded") "actual HEAD must be explicit"
    foreach ($name in @("nested", "missing", "nongit", "unspecified")) {
        Assert-True ($null -eq $snapshot.repository_heads[$name].head) "$name must not inherit any other HEAD"
        Assert-True ($snapshot.repository_heads[$name].status -eq "unknown") "$name must remain unknown"
    }
    $json = $snapshot | ConvertTo-Json -Depth 5 | ConvertFrom-Json
    Assert-True ($json.repository_heads.selected.head -eq $head) "artifact JSON must retain safe full source identity"
    Write-Host "joint-source-heads.tests.ps1: PASS"
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force
}
