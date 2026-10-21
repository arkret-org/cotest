param(
    [Parameter(Mandatory=$true)][string]$AdminUrl,
    [Parameter(Mandatory=$true)][string]$ToolsDirectory,
    [Parameter(Mandatory=$true)][string]$DataDirectory,
    [Parameter(Mandatory=$true)][string]$EvidenceDirectory
)
$ErrorActionPreference='Stop'
$PSNativeCommandUseErrorActionPreference=$false
function Invoke-NativeCapture {
    param([string]$FilePath,[string[]]$Arguments=@())
    & $FilePath @Arguments 2>&1
}
. (Join-Path $PSScriptRoot '../lib/joint-native-postgres.ps1')
function Assert-True([bool]$Value,[string]$Message) { if(-not $Value){throw $Message} }
function Assert-Refused([scriptblock]$Action,[string]$Message) {
    $refused=$false
    try{& $Action | Out-Null}catch{$refused=$true}
    Assert-True $refused $Message
}
New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
$first=$null
$second=$null
try {
    Assert-Refused {New-JointNativePostgresDatabase $AdminUrl $ToolsDirectory 'wrong-cluster' ($DataDirectory+'-wrong')} 'Wrong-cluster verification must fail before CREATE'
    $first=New-JointNativePostgresDatabase $AdminUrl $ToolsDirectory 'native-isolation' $DataDirectory
    $second=New-JointNativePostgresDatabase $AdminUrl $ToolsDirectory 'native-isolation' $DataDirectory
    Assert-True ($first.DatabaseName -cne $second.DatabaseName) 'Application databases must be distinct'
    $psql=Join-Path $ToolsDirectory $(if($IsWindows){'psql.exe'}else{'psql'})
    Invoke-JointPostgresSql $psql $first.Url 'CREATE TABLE isolation_probe (value integer); INSERT INTO isolation_probe VALUES (41)' | Out-Null
    Assert-Refused {Invoke-JointPostgresSql $psql $second.Url 'SELECT * FROM isolation_probe'} 'A second service must not share the first service schema'
    Invoke-JointPostgresSql $psql $second.Url 'CREATE TABLE isolation_probe (value integer); INSERT INTO isolation_probe VALUES (42)' | Out-Null
    $dump=Export-JointNativePostgresDump $first.ContainerName (Join-Path $EvidenceDirectory 'owned-database.sql')
    Assert-True ($null -ne $dump -and (Get-Content -LiteralPath $dump -Raw).Contains('(41)')) 'The actual durable store must be dumped before cleanup'
    Assert-Refused {Remove-JointNativePostgresDatabase 'native-postgres:postgres'} 'An administrative database is never owned by this run'
    Remove-JointNativePostgresDatabase $first.ContainerName
    Remove-JointNativePostgresDatabase $first.ContainerName
    $surviving=(Invoke-JointPostgresSql $psql $second.Url 'SELECT value FROM isolation_probe') -join ''
    Assert-True ($surviving.Trim() -ceq '42') 'Cleaning one database must preserve the other service'
    @{exit=0;databases=2;cluster_directory_verified=$true;isolated_schemas=$true;dump_before_cleanup=$true;unowned_drop_refused=$true;cleanup_idempotent=$true;surviving_service=$true} |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'result.json') -Encoding utf8
    Write-Output 'Native PostgreSQL: cluster anchor, two isolated stores, actual dump, owned/idempotent cleanup and surviving peer verified'
} finally {
    if($first){Remove-JointNativePostgresDatabase $first.ContainerName}
    if($second){Remove-JointNativePostgresDatabase $second.ContainerName}
}
