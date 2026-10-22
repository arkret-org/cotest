[CmdletBinding()]
param([string]$RepoRoot = (Join-Path $PSScriptRoot '../..'))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$runner = Join-Path $RepoRoot 'scripts/run-server-conformance.ps1'
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($runner, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Invalid runner syntax' }
$definitions = foreach ($name in @('Add-RawLogLine', 'ConvertTo-NativeCommandLineArgument', 'Invoke-CargoTestInvocation')) {
    $definition = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if (-not $definition) { throw "Missing production function $name" }
    $definition.Extent.Text
}
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
if (-not $tempRoot.StartsWith('D:\', [StringComparison]::OrdinalIgnoreCase) -and -not $tempRoot.StartsWith('D:/', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'This tool test requires an explicit D: TEMP'
}
$scratch = Join-Path $tempRoot ('cotest-native-invocation-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path (Join-Path $scratch 'scripts')
try {
    # Execute unmodified function extents from a real script directory. This
    # preserves automatic PSScriptRoot semantics without changing production
    # code or providing a configurable TLS-wrapper override.
    Copy-Item -LiteralPath (Join-Path $RepoRoot 'scripts/run-native-rust-tests.py') -Destination (Join-Path $scratch 'scripts/run-native-rust-tests.py')
    $body = @'
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$script:mockExit = 0
$script:mockStdout = "test selected_case ... ok`ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.01s`n"
$script:captured = @()
function Get-Command {
    param([string]$Name, [string]$CommandType, [string]$ErrorAction)
    if ($Name -notin @('cargo', 'python') -or $CommandType -ne 'Application') { throw 'Unexpected executable resolution' }
    # Return multiple PATH hits deterministically, with spaces in the selected
    # executable. No executable is launched: Start-Process below is a mock.
    [pscustomobject]@{ Source = (Join-Path $PSScriptRoot "tools with spaces/$Name.exe") }
    [pscustomobject]@{ Source = (Join-Path $PSScriptRoot "unselected/$Name.exe") }
}
function Start-Process {
    param($FilePath, $ArgumentList, $WorkingDirectory, [switch]$NoNewWindow, [switch]$PassThru, $RedirectStandardOutput, $RedirectStandardError)
    $script:captured += [pscustomobject]@{ file = $FilePath; arguments = $ArgumentList; directory = $WorkingDirectory }
    [IO.File]::WriteAllText($RedirectStandardOutput, $script:mockStdout)
    [IO.File]::WriteAllText($RedirectStandardError, 'mock compiler stderr')
    $process = [pscustomobject]@{ ExitCode = $script:mockExit }
    $process | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value {} -PassThru |
        Add-Member -MemberType ScriptMethod -Name Dispose -Value {} -PassThru
}
$cargoArgs = @('test', '--locked', '-p', 'cotest', '--test', 'fixture_target', 'selected_case', '--', '--exact', '--nocapture')
$log = Join-Path $PSScriptRoot 'raw.log'
$exit = Invoke-CargoTestInvocation -CargoArgs $cargoArgs -RawLog $log -Label 'positive selected case'
if ($exit -ne 0 -or $script:captured.Count -ne 1) { throw 'Nonempty actual-success exit was not preserved' }
$call = $script:captured[0]
$python = (Get-Command python -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$cargo = (Get-Command cargo -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$wrapper = Join-Path $PSScriptRoot 'run-native-rust-tests.py'
$expectedTokens = @('-B', $wrapper, $cargo) + $cargoArgs
$expectedArgs = (($expectedTokens | ForEach-Object { ConvertTo-NativeCommandLineArgument -Argument $_ }) -join ' ')
if ($call.file -cne $python -or $call.arguments -cne $expectedArgs) { throw ('Actual invocation lost native wrapper or changed original Cargo argv: actual=' + $call.arguments + '; expected=' + $expectedArgs + '; executable=' + $call.file + '; expected executable=' + $python) }
if ((Get-Content $log -Raw) -notmatch '1 passed; 0 failed;' -or (Get-Content $log -Raw) -notmatch 'mock compiler stderr') { throw 'File-backed stdout/stderr were discarded' }
$script:mockExit = 101
if ((Invoke-CargoTestInvocation -CargoArgs $cargoArgs -RawLog $log -Label 'real exit failure') -ne 101) { throw 'Actual nonzero child exit was hidden by a passing footer' }
$script:mockExit = 0
$script:mockStdout = "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0s`n"
if ((Invoke-CargoTestInvocation -CargoArgs $cargoArgs -RawLog $log -Label 'empty exact selection') -ne 1) { throw 'Empty exact native selection was accepted' }
$script:mockStdout = "test selected_case ... ignored`ntest result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0s`n"
if ((Invoke-CargoTestInvocation -CargoArgs $cargoArgs -RawLog $log -Label 'ignored only selection') -ne 1) { throw 'Ignored-only exact native selection was accepted' }
$priorCalls = $script:captured.Count
$hiddenWrapper = $wrapper + '.hidden'
Move-Item -LiteralPath $wrapper -Destination $hiddenWrapper
try {
    $rejected = $false
    try { $null = Invoke-CargoTestInvocation -CargoArgs $cargoArgs -RawLog $log -Label 'missing native wrapper' }
    catch { $rejected = $_.Exception.Message -like 'Native Rust TLS wrapper is missing:*' }
    if (-not $rejected -or $script:captured.Count -ne $priorCalls) { throw 'Missing native wrapper reached process execution' }
} finally { Move-Item -LiteralPath $hiddenWrapper -Destination $wrapper }
Write-Host 'native-conformance-invocation.tests.ps1: PASS (mocked process argv/real function/footer/exit boundaries only; no Cargo/TLS/business executed)'
'@
    $child = Join-Path $scratch 'scripts/mock-invocation.ps1'
    [IO.File]::WriteAllText($child, (($definitions -join "`n") + "`n" + $body))
    & (Get-Process -Id $PID).Path -NoProfile -File $child
    if ($LASTEXITCODE -ne 0) { throw 'Native invocation production-function regression failed' }
} finally {
    $resolved = [IO.Path]::GetFullPath($scratch)
    if (-not $resolved.StartsWith($tempRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Scratch cleanup escaped its D: TEMP' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
