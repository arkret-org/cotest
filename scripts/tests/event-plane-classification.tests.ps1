param(
    [string]$WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\.."))
)

$ErrorActionPreference = "Stop"
$rg = Get-Command rg -ErrorAction Stop
$sourceRoots = @(
    "arkret-rust-sdk\crates",
    "coland\crates",
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
    -Name "retired Event plane classification" `
    -Pattern '\b(?:cbs_plane|is_data_plane|is_control_plane)\s*\(' `
    -Roots $sourceRoots
Assert-NoRustMatch `
    -Name "exported Event descriptor plane access" `
    -Pattern '(?:descriptor\(\)[\s\S]{0,80}\.plane|descriptor\.plane)' `
    -Roots $sourceRoots
$generatedKinds = Join-Path $WorkspaceRoot "arkret-rust-sdk\crates\wire\src\generated\event_kinds.rs"
$generatedSource = Get-Content -Raw -LiteralPath $generatedKinds
foreach ($helper in @("product_class", "wire_scope", "is_reducer_input")) {
    if ($generatedSource -notmatch "pub fn $helper\(") {
        throw "generated EventKind is missing $helper()"
    }
}

Write-Host "Event registry classification gate passed."
