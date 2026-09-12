param(
    [string]$WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\.."))
)

$ErrorActionPreference = "Stop"
$rg = Get-Command rg -ErrorAction Stop
$sourceRoots = @(
    "arkret-rust-sdk\crates",
    "soland\crates",
    "inkson\src",
    "cotest\src",
    "coauth\crates",
    "garth\src",
    "chime\src"
) | ForEach-Object { Join-Path $WorkspaceRoot $_ } | Where-Object { Test-Path -LiteralPath $_ }

function Assert-NoRustMatch {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Pattern,
        [Parameter(Mandatory)][string[]]$Roots
    )

    $output = & $rg.Source -n -U $Pattern -g "*.rs" -g "!**/generated/event_kinds.rs" @Roots 2>&1
    if ($LASTEXITCODE -eq 0) {
        throw "$Name violated:`n$($output -join [Environment]::NewLine)"
    }
    if ($LASTEXITCODE -ne 1) {
        throw "$Name scan failed with rg exit code $LASTEXITCODE`n$($output -join [Environment]::NewLine)"
    }
}

Assert-NoRustMatch `
    -Name "raw Event plane equality" `
    -Pattern 'cbs_plane\(\)\s*(?:==|!=)' `
    -Roots $sourceRoots
Assert-NoRustMatch `
    -Name "exported Event descriptor plane access" `
    -Pattern '(?:descriptor\(\)[\s\S]{0,80}\.plane|descriptor\.plane)' `
    -Roots $sourceRoots
$generatedKinds = Join-Path $WorkspaceRoot "arkret-rust-sdk\crates\wire\src\generated\event_kinds.rs"
$generatedSource = Get-Content -Raw -LiteralPath $generatedKinds
foreach ($helper in @("cbs_plane", "is_data_plane", "is_control_plane")) {
    if ($generatedSource -notmatch "pub fn $helper\(") {
        throw "generated EventKind is missing $helper()"
    }
}

Write-Host "Event plane classification gate passed."
