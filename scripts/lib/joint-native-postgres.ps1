# A run owns database names, never the caller's PostgreSQL cluster or service.
$script:jointNativePostgresDatabases = @{}

function Invoke-JointPostgresSql {
    param([string]$Psql, [string]$Url, [string]$Sql)
    $output = Invoke-NativeCapture -FilePath $Psql -Arguments @('--dbname', $Url, '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-c', $Sql)
    if ($LASTEXITCODE -ne 0) { throw "Native PostgreSQL command failed: $($output -join "`n")" }
    return $output
}

function New-JointNativePostgresDatabase {
    param([string]$AdminUrl, [string]$ToolsDirectory, [string]$NamePrefix, [Parameter(Mandatory=$true)][string]$ExpectedDataDirectory)
    $admin = [Uri]$AdminUrl
    if ($admin.Scheme -notin @('postgres', 'postgresql') -or $admin.AbsolutePath.Trim('/') -notin @('postgres', 'template1')) {
        throw 'Native PostgreSQL requires an explicit administrative database URL'
    }
    $suffix = if ($IsWindows) { '.exe' } else { '' }
    $psql = if ($ToolsDirectory) { Join-Path $ToolsDirectory "psql$suffix" } else { (Get-Command psql -ErrorAction Stop).Source }
    $dump = if ($ToolsDirectory) { Join-Path $ToolsDirectory "pg_dump$suffix" } else { (Get-Command pg_dump -ErrorAction Stop).Source }
    foreach ($tool in @($psql, $dump)) { if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw "Missing PostgreSQL tool: $tool" } }
    $actualDirectory = ((Invoke-JointPostgresSql $psql $AdminUrl 'SHOW data_directory') -join '').Trim().Replace('\','/').TrimEnd('/')
    $expectedDirectory = $ExpectedDataDirectory.Trim().Replace('\','/').TrimEnd('/')
    $comparison = if ($IsWindows) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
    if (-not [string]::Equals($actualDirectory,$expectedDirectory,$comparison)) { throw 'Native PostgreSQL data directory does not match the explicitly approved cluster' }
    $prefix = ($NamePrefix.ToLowerInvariant() -replace '[^a-z0-9_]', '_')
    if ($prefix.Length -gt 30) { $prefix = $prefix.Substring(0,30) }
    $database = 'cotest_' + $prefix + '_' + [Guid]::NewGuid().ToString('N').Substring(0,16)
    if ($database -notmatch '^cotest_[a-z0-9_]{1,55}$') { throw 'Invalid generated isolated database name' }
    $handle = "native-postgres:$database"
    $url = [UriBuilder]::new($AdminUrl)
    $url.Path = $database
    $url.Fragment = ''
    $url.Query = ($url.Query.TrimStart('?') + '&connect_timeout=5').TrimStart('&')
    $adminConnection = [UriBuilder]::new($AdminUrl)
    $adminConnection.Query = ($adminConnection.Query.TrimStart('?') + '&connect_timeout=5').TrimStart('&')
    $record = [pscustomobject]@{
        Database = $database; AdminUrl = $adminConnection.Uri.AbsoluteUri; Url = $url.Uri.AbsoluteUri
        Psql = $psql; PgDump = $dump; Active = $false
    }
    Invoke-JointPostgresSql $psql $record.AdminUrl "CREATE DATABASE `"$database`"" | Out-Null
    $record.Active = $true
    $script:jointNativePostgresDatabases.Add($handle, $record)
    try {
        $actual = (Invoke-JointPostgresSql $psql $record.Url 'SELECT current_database()') -join ''
        if ($actual.Trim() -cne $database) { throw 'Native PostgreSQL connected to another database' }
    } catch {
        Remove-JointNativePostgresDatabase $handle
        throw
    }
    return [pscustomobject]@{ ContainerName=$handle; Runtime='native'; DatabaseName=$database; HostPort=$admin.Port; Url=$record.Url }
}

function Test-JointNativePostgresHandle {
    param([string]$Name)
    if ($script:jointNativePostgresDatabases.ContainsKey($Name)) { return $true }
    if ($Name.StartsWith('native-postgres:',[StringComparison]::Ordinal)) { throw 'Unknown native PostgreSQL ownership handle' }
    return $false
}

function Remove-JointNativePostgresDatabase {
    param([string]$Name)
    if (-not (Test-JointNativePostgresHandle $Name)) { throw 'Not a native PostgreSQL ownership handle' }
    $record = $script:jointNativePostgresDatabases[$Name]
    if (-not $record.Active) { return }
    # Only a successful CREATE from this run can populate this ownership table.
    Invoke-JointPostgresSql $record.Psql $record.AdminUrl "DROP DATABASE `"$($record.Database)`" WITH (FORCE)" | Out-Null
    $record.Active = $false
}

function Export-JointNativePostgresDump {
    param([string]$Name, [string]$OutputPath)
    if (-not (Test-JointNativePostgresHandle $Name)) { throw 'Not a native PostgreSQL ownership handle' }
    $record = $script:jointNativePostgresDatabases[$Name]
    if (-not $record.Active) { Write-Warning 'Native PostgreSQL database was removed before its durable-store scan'; return $null }
    $dump = Invoke-NativeCapture -FilePath $record.PgDump -Arguments @('--dbname',$record.Url,'--column-inserts','--no-owner','--no-privileges')
    if ($LASTEXITCODE -ne 0) { Write-Warning 'Native PostgreSQL dump failed; durable-store scan is incomplete'; return $null }
    $parent = Split-Path -Parent $OutputPath
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $dump | Set-Content -LiteralPath $OutputPath -Encoding utf8
    return $OutputPath
}
