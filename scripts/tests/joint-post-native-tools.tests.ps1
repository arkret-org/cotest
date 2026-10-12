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
 $testOutput=Invoke-BuildInputNative -FilePath $cargo -WorkingDirectory $fixture -Arguments @('test','--locked','--offline','--manifest-path',(Join-Path $fixture 'Cargo.toml'),'--test','provisioning_live','--jobs','1')
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
 }
 Write-Host 'post-native tools fixture: PASS (actual test overwrite, strict old-stamp rejection, actual normal restoration, natural-mtime cache verification)'
}finally{Remove-Item -LiteralPath $parent -Recurse -Force}
