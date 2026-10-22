param([string]$RegressionScript = (Join-Path $PSScriptRoot 'provision-default-stack.tests.ps1'))
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
# Full production-script control flow with mocked node/process observations.
# No Node, browser, provision bridge, Cargo, service or database is executed.
$tempRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')
if (-not $tempRoot.StartsWith('D:\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Use D: TEMP'}
$scratch=Join-Path $tempRoot ('provision-node-tool-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path "$scratch/scripts/tests","$scratch/e2e/node_modules/playwright"
$production=Join-Path $scratch 'scripts/tests/provision-default-stack.tests.ps1'
Copy-Item -LiteralPath $RegressionScript -Destination $production
[IO.File]::WriteAllText("$scratch/e2e/node_modules/playwright/cli.js",'// Never executed')
$binary=Join-Path $scratch 'cotest-provision.exe'
$bytes=[byte[]]::new(512)
[BitConverter]::GetBytes([uint32]128).CopyTo($bytes,0x3c)
[BitConverter]::GetBytes([uint32]0x4550).CopyTo($bytes,128)
[BitConverter]::GetBytes([uint16]0x20b).CopyTo($bytes,152)
[BitConverter]::GetBytes([uint64]1048576).CopyTo($bytes,224)
[IO.File]::WriteAllBytes($binary,$bytes)
$original=@{}
foreach($name in @('RUST_MIN_STACK','COTEST_PROVISION_BIN','COTEST_JOINT_RUN_DIR')) {$original[$name]=[Environment]::GetEnvironmentVariable($name,'Process')}
$global:r03ProvisionMock=@{calls=@();processQueries=0;leak=$false;nodeExit=0;junit=''}
function Get-Command {
    param([string]$Name,[string]$CommandType,[string]$ErrorAction)
    if ($Name -ne 'node' -or $CommandType -ne 'Application') {throw 'Unexpected executable lookup'}
    [pscustomobject]@{Source='Invoke-MockedNode'}
    [pscustomobject]@{Source='Unselected-Node-Path'}
}
function Get-Process {
    param([string]$Name,[string]$ErrorAction)
    if ($Name -ne 'cotest-provision') {throw 'Unexpected process query'}
    $global:r03ProvisionMock.processQueries++
    if ($global:r03ProvisionMock.leak -and $global:r03ProvisionMock.processQueries -gt 1) {[pscustomobject]@{Id=987654;Path=$binary}}
}
function Invoke-MockedNode {
    $global:r03ProvisionMock.calls+=,@($args)
    if (Test-Path Env:RUST_MIN_STACK) {throw 'Stack override reached the journey'}
    if ($env:COTEST_PROVISION_BIN -cne $binary) {throw 'Wrong binary supplied to journey'}
    $null=New-Item -ItemType Directory -Path $env:COTEST_JOINT_RUN_DIR
    if ($null -ne $global:r03ProvisionMock.junit) {[IO.File]::WriteAllText((Join-Path $env:COTEST_JOINT_RUN_DIR 'junit.xml'),$global:r03ProvisionMock.junit)}
    $global:LASTEXITCODE=$global:r03ProvisionMock.nodeExit
}
function Case([string]$Name,[string]$JUnit,[int]$Exit,[bool]$Leak,[bool]$ExpectedPass) {
    $global:r03ProvisionMock.calls=@();$global:r03ProvisionMock.processQueries=0;$global:r03ProvisionMock.junit=$JUnit;$global:r03ProvisionMock.nodeExit=$Exit;$global:r03ProvisionMock.leak=$Leak
    $env:RUST_MIN_STACK='marker-not-a-real-stack-size'
    $env:COTEST_PROVISION_BIN='original-binary-marker'
    $env:COTEST_JOINT_RUN_DIR='original-output-marker'
    $evidence=Join-Path $scratch $Name
    $threw=$false;$caseError=""
    try {& $production -BinaryPath $binary -EvidenceDirectory $evidence} catch {$threw=$true;$caseError=$_.Exception.Message}
    if (-not (Test-Path (Join-Path $evidence "result.json"))) {throw "${Name}: no result: $caseError"}
    $result=Get-Content (Join-Path $evidence 'result.json') -Raw | ConvertFrom-Json
    if ($result.passed -ne $ExpectedPass -or $threw -eq $ExpectedPass) {throw "${Name}: incorrect terminal result"}
    if ($global:r03ProvisionMock.calls.Count -ne 1) {throw "${Name}: Node was not selected exactly once"}
    $expected=@((Join-Path $scratch 'e2e/node_modules/playwright/cli.js'),'test','tests/harness/garth-client.spec.ts','--project=joint-api','--workers=1','--retries=0','--grep','Garth commits a two-member Realm, exchanges messages and resumes a rebuilt runtime')
    if (($global:r03ProvisionMock.calls[0] | ConvertTo-Json -Compress) -cne ($expected | ConvertTo-Json -Compress)) {throw "${Name}: changed journey arguments"}
    if ($env:RUST_MIN_STACK -cne 'marker-not-a-real-stack-size' -or $env:COTEST_PROVISION_BIN -cne 'original-binary-marker' -or $env:COTEST_JOINT_RUN_DIR -cne 'original-output-marker') {throw "${Name}: environment was not restored"}
}
try {
    $one='<testsuites><testsuite><testcase name="Garth commits a two-member Realm, exchanges messages and resumes a rebuilt runtime"/></testsuite></testsuites>'
    Case 'one-full-journey' $one 0 $false $true
    Case 'nonzero-despite-success-report' $one 1 $false $false
    Case 'missing-report' $null 0 $false $false
    Case 'skipped' '<testsuites><testsuite><testcase><skipped/></testcase></testsuite></testsuites>' 0 $false $false
    Case 'failed' '<testsuites><testsuite><testcase><failure/></testcase></testsuite></testsuites>' 0 $false $false
    Case 'empty-selection' '<testsuites><testsuite/></testsuites>' 0 $false $false
    Case 'two-cases' '<testsuites><testsuite><testcase/><testcase/></testsuite></testsuites>' 0 $false $false
    Case 'bridge-leaked' $one 0 $true $false
    $global:LASTEXITCODE=0
    Write-Host 'provision-default-stack-tools.tests.ps1: PASS (8 mocked full-script cases; no real journey or stack-runtime credit)'
} finally {
    foreach($name in $original.Keys) {[Environment]::SetEnvironmentVariable($name,$original[$name],'Process')}
    $resolved=[IO.Path]::GetFullPath($scratch)
    if (-not $resolved.StartsWith($tempRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {throw 'Cleanup outside owned D: scratch'}
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
