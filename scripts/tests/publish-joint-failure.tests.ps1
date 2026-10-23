$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$scratch = Join-Path ([IO.Path]::GetTempPath()) ("cotest-public-failure-" + [Guid]::NewGuid().ToString("n"))
try {
    $source = Join-Path $scratch "private"
    $services = Join-Path $source "run/services"
    $null = New-Item -ItemType Directory -Path $services -Force
    $raw = Join-Path $services "coland-server1-bootstrap.stderr.log"
    @(
        "Error: Permission denied while opening the private keystore"
        "Authorization: Bearer private-fixture-token"
        '{"signing_seed":"private-fixture-seed"}'
        '-----BEGIN PRIVATE KEY-----'
        'private-multiline-material'
        '-----END PRIVATE KEY-----'
    ) | Set-Content -LiteralPath $raw -Encoding utf8
    'COLAND_KEYSTORE_MASTER_KEY=must-not-be-exported' | Set-Content -LiteralPath (Join-Path $services "coland-server1-bootstrap.command.txt")
    $public = Join-Path $scratch "public"
    & (Join-Path $PSScriptRoot "../publish-joint-failure.ps1") -RunRoot $source -OutputDirectory $public
    $published = Get-Content -LiteralPath (Join-Path $public "run/services/coland-server1-bootstrap.stderr.log") -Raw
    if ($published -notmatch 'Permission denied' -or $published -match 'private-fixture-token|private-fixture-seed|private-multiline-material') {
        throw "Public evidence must retain the real error and remove private material"
    }
    if (@(Get-ChildItem -LiteralPath $public -Recurse -File | Where-Object Name -Like '*.command.txt').Count -ne 0) {
        throw "Command files must never be exported"
    }
    if ((Get-Content -LiteralPath $raw -Raw) -notmatch 'private-fixture-token') { throw "Raw owning evidence must remain untouched" }
    $missing = Join-Path $scratch "missing-public"
    & (Join-Path $PSScriptRoot "../publish-joint-failure.ps1") -RunRoot (Join-Path $scratch "no-run") -OutputDirectory $missing
    if (-not (Test-Path (Join-Path $missing "manifest.json"))) { throw "Early failures require an empty diagnostic manifest" }
    Write-Host "Public startup evidence regressions passed."
} finally {
    if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force }
}
