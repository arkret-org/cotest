$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repoRoot 'scripts/lib/build-freshness.ps1')
$tokens=$null; $parseErrors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repoRoot 'scripts/run-joint-e2e.ps1'),[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw 'runner parse failed'}
$function=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Prepare-JointPostNativeTools'},$true)
if($null -eq $function){throw 'production post-native tool finalizer missing'}
Invoke-Expression $function.Extent.Text
$toolCalls=@($ast.FindAll({param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Prepare-JointPostNativeTools'},$true))
$native=$ast.Find({param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$provisioningCommand'},$true)
$hook=$ast.Find({param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Start-ManagedCommand' -and $node.Extent.Text.Contains('prepare-post-provision')},$true)
if($toolCalls.Count -ne 1 -or $null -eq $native -or $null -eq $hook -or $toolCalls[0].Extent.StartOffset -le $native.Extent.EndOffset -or $toolCalls[0].Extent.EndOffset -ge $hook.Extent.StartOffset){throw 'normal product finalization must occur after native gates and before any post-provision business command'}
$finish=$ast.Find({param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$finishedAt'},$true)
$freeze=$ast.Find({param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Complete-JointSourceFreeze'},$true)
if($null -eq $finish -or $null -eq $freeze -or $finish.Extent.StartOffset -le $freeze.Extent.EndOffset){throw 'reported finish time must include final source and secret audits'}
function Assert-True([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
$parent=Join-Path ([System.IO.Path]::GetTempPath()) ('cotest-post-native-' + [guid]::NewGuid())
$fixture=Join-Path $parent 'fixture'
$null=New-Item -ItemType Directory -Path (Join-Path $fixture 'src/bin'),(Join-Path $fixture 'tests'),(Join-Path $fixture 'variant/src') -Force
try{
 Set-Content -LiteralPath (Join-Path $fixture '.gitignore') -Value '/target/'
 Set-Content -LiteralPath (Join-Path $fixture 'Cargo.toml') -Value @'
[package]
name = "cotest-test-support"
version = "0.1.0"
edition = "2021"
[dependencies]
variant = { path = "variant" }
[dev-dependencies]
variant = { path = "variant", features = ["integration"] }
'@
 Set-Content -LiteralPath (Join-Path $fixture 'variant/Cargo.toml') -Value @'
[package]
name = "variant"
version = "0.1.0"
edition = "2021"
[features]
integration = []
'@
 Set-Content -LiteralPath (Join-Path $fixture 'variant/src/lib.rs') -Value 'pub fn marker() -> &''static str { if cfg!(feature = "integration") { "fixture-integration" } else { "fixture-normal" } }'
 foreach($name in @('cotest-wire','cotest-provision')){
  Set-Content -LiteralPath (Join-Path $fixture "src/bin/$name.rs") -Value 'fn main() { println!("{}",variant::marker()); }'
 }
 Set-Content -LiteralPath (Join-Path $fixture 'tests/provisioning_live.rs') -Value @'
#[test]
fn actual_auto_binary_uses_test_feature_graph() {
 for path in [env!("CARGO_BIN_EXE_cotest-wire"),env!("CARGO_BIN_EXE_cotest-provision")] {
  let output=std::process::Command::new(path).output().unwrap();
  assert!(output.status.success());
  assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "fixture-integration");
 }
}
'@
 $cargo=(Get-Command cargo).Source
 Invoke-BuildInputNative -FilePath (Get-Command git).Source -WorkingDirectory $fixture -Arguments @('init','-q') | Out-Null
 Invoke-BuildInputNative -FilePath $cargo -WorkingDirectory $fixture -Arguments @('generate-lockfile','--offline') | Out-Null
 Invoke-BuildInputGit -RepositoryRoot $fixture -Arguments @('add','.') | Out-Null
 Invoke-BuildInputGit -RepositoryRoot $fixture -Arguments @('-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','fixture') | Out-Null
 $target=Join-Path $fixture 'target'
 $prepare=Join-Path $repoRoot 'scripts/prepare-cargo-artifact.ps1'
 $normal=@(Prepare-JointPostNativeTools -RepositoryRoot $fixture -TargetDirectory $target -PrepareScriptPath $prepare -DiagnosticPath (Join-Path $parent 'normal.json') -Jobs 1)
 Assert-True ($normal.Count -eq 2) 'both product tools must be reported'
 $testOutput=Invoke-BuildInputNative -FilePath $cargo -WorkingDirectory $fixture -Arguments @('test','--locked','--offline','--manifest-path',(Join-Path $fixture 'Cargo.toml'),'--target-dir',$target,'--test','provisioning_live','--jobs','1')
 Assert-True ($testOutput.Contains('1 passed; 0 failed')) 'integration gate must actually run and prove dev-feature tool variant'
 foreach($name in @('cotest-wire','cotest-provision')){
  $exe=if($IsWindows){"$name.exe"}else{$name};$path=Join-Path $target "debug/$exe"
  $states=@(Get-ArtifactBuildRepositoryStates -ArtifactPath $path -RepositoryRoots @($fixture))
  Assert-True (-not (Test-ArtifactBuildStamp -ArtifactPath $path -RepositoryStates $states).Matches) 'test Cargo overwritten bytes must fail the prior prepared stamp'
 }
 $restored=@(Prepare-JointPostNativeTools -RepositoryRoot $fixture -TargetDirectory $target -PrepareScriptPath $prepare -DiagnosticPath (Join-Path $parent 'restored.json') -Jobs 1)
 foreach($tool in $restored){
  $exe=if($IsWindows){"$($tool.name).exe"}else{$tool.name};$path=Join-Path $target "debug/$exe"
  Assert-True ((Invoke-BuildInputNative -FilePath $path -Arguments @()).Trim() -ceq 'fixture-normal') 'normal managed prepare must actually restore the non-test binary'
  Assert-True $tool.artifact_matches_stamp 'restored exact bytes and current source must match generated stamp'
 }
 $cached=@(Prepare-JointPostNativeTools -RepositoryRoot $fixture -TargetDirectory $target -PrepareScriptPath $prepare -DiagnosticPath (Join-Path $parent 'cached.json') -Jobs 1)
 foreach($tool in $cached){
  $previous=@($restored | Where-Object name -CEQ $tool.name)[0]
  Assert-True ($tool.cargo_fresh -and $tool.artifact_time_utc -eq $previous.artifact_time_utc -and $tool.artifact_sha256 -ceq $previous.artifact_sha256) 'actual unchanged Cargo verification must retain natural tool mtime and bytes'
  Assert-True ($tool.preparation_batch_timings.binary_count -eq 2 -and $tool.preparation_batch_timings.total_seconds -gt 0) 'both tools must share a measured preparation batch'
 }
 $paths=@($cached | ForEach-Object {Join-Path $target ("debug/" + $_.name + $(if($IsWindows){'.exe'}else{''}))})
 $stamp=Get-ArtifactBuildStampPath -ArtifactPath $paths[0]
 $originalStamp=(Get-FileHash -LiteralPath $stamp -Algorithm SHA256).Hash
 foreach($names in @(@('cotest-wire','missing-bin'),@('cotest-wire','cotest-wire'))){
  $rejected=$false
  try { & $prepare -ManifestPath (Join-Path $fixture 'Cargo.toml') -BinaryNames $names -TargetDirectory $target -Jobs 1 | Out-Null } catch { $rejected=$true }
  Assert-True $rejected 'missing or duplicate binaries must fail closed'
  Assert-True ((Get-FileHash -LiteralPath $stamp -Algorithm SHA256).Hash -ceq $originalStamp) 'rejected selection must not stamp an old executable'
 }
 # The first executable is normally excluded from its own snapshot. A batch
 # must reject it too if a caller makes that output a tracked source input.
 foreach($output in @($paths[0],(Get-ArtifactBuildStampPath -ArtifactPath $paths[1]))){
  Invoke-BuildInputGit -RepositoryRoot $fixture -Arguments @('add','-f','--',$output) | Out-Null
  $rejected=$false
  try { Prepare-JointPostNativeTools -RepositoryRoot $fixture -TargetDirectory $target -PrepareScriptPath $prepare -DiagnosticPath (Join-Path $parent 'rejected.json') -Jobs 1 | Out-Null } catch { $rejected=$_.Exception.Message -ceq 'Batch preparation cannot share inputs when an output or stamp is a Git input' }
  Assert-True $rejected 'tracked output or stamp must prevent shared source snapshots'
  Assert-True (-not (Test-Path -LiteralPath (Join-Path $parent 'rejected.json'))) 'rejected batch must not emit a success receipt'
  Assert-True ((Get-FileHash -LiteralPath $stamp -Algorithm SHA256).Hash -ceq $originalStamp) 'rejected source inventory must not overwrite stamps'
  Invoke-BuildInputGit -RepositoryRoot $fixture -Arguments @('reset','-q','HEAD','--',$output) | Out-Null
 }
 $tamper=Join-Path $parent 'tamper.ps1'
 $env:COTEST_FIXTURE_PREPARE=$prepare
 Set-Content -LiteralPath $tamper -Value @'
param($ManifestPath,$BinaryNames,$PackageName,$TargetDirectory,$Jobs,$RepositoryRoots)
$items=@(& $env:COTEST_FIXTURE_PREPARE @PSBoundParameters)
$file=$items[0].ArtifactPath
[IO.File]::WriteAllBytes($file,([IO.File]::ReadAllBytes($file) + [byte]0))
$items
'@
 $rejected=$false
 try { Prepare-JointPostNativeTools -RepositoryRoot $fixture -TargetDirectory $target -PrepareScriptPath $tamper -DiagnosticPath (Join-Path $parent 'tampered.json') -Jobs 1 | Out-Null } catch { $rejected=$_.Exception.Message -like 'Post-native tool artifact/stamp mismatch:*' }
 Assert-True $rejected 'a first tool changed after the batch must fail final byte verification'
 Assert-True (-not (Test-Path -LiteralPath (Join-Path $parent 'tampered.json'))) 'tampered tools must not receive a success receipt'
 Write-Host 'post-native tools fixture: PASS (shared build, test-feature overwrite/restoration, warm cache, invalid selection/source inventory and final-byte rejection)'
}finally{Remove-Item -LiteralPath $parent -Recurse -Force}
