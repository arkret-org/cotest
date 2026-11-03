# Native suites own service databases independently, even on one PG server.
function Resolve-ConformancePython {
    param([AllowNull()][string]$ExplicitPath)
    $candidates = if ($ExplicitPath) { @($ExplicitPath) } else { @('python3', 'python', 'python3.14', 'python3.13', 'python3.12', 'python3.11') }
    foreach ($candidate in $candidates) {
        $command = Get-Command $candidate -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $command) { continue }
        & $command.Source -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' *> $null
        if ($LASTEXITCODE -eq 0) { return $command.Source }
    }
    throw 'Native conformance requires Python 3.11 or newer; set COTEST_PYTHON_BIN to a supported interpreter'
}

function Initialize-ConformancePython {
    param([string]$Python, [string]$SpecRoot, [string]$OutputDirectory)
    $imports = 'from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey; from jsonschema import Draft202012Validator; import yaml; from argon2 import PasswordHasher; import nacl.signing'
    & $Python -I -c $imports *> $null
    if ($LASTEXITCODE -eq 0) { return $Python }

    # Install missing reference-tool dependencies into a run-owned environment,
    # never into the selected system or user interpreter.
    $requirements = Join-Path $SpecRoot 'tools/requirements.txt'
    if (-not (Test-Path -LiteralPath $requirements -PathType Leaf)) { throw 'Spec tool requirements are unavailable' }
    $runtime = Join-Path $OutputDirectory 'python-runtime'
    $log = Join-Path $OutputDirectory 'python-runtime.log'
    & $Python -I -m venv --copies $runtime *> $log
    if ($LASTEXITCODE -ne 0) { throw "Could not create the conformance Python environment; see $log" }
    $prepared = Join-Path $runtime $(if ($IsWindows) { 'Scripts/python.exe' } else { 'bin/python' })
    & $prepared -I -m pip install --disable-pip-version-check -r $requirements *>> $log
    if ($LASTEXITCODE -ne 0) { throw "Could not prepare Spec tool dependencies; see $log" }
    & $prepared -I -c $imports *>> $log
    if ($LASTEXITCODE -ne 0) { throw "Spec tool dependencies are unusable; see $log" }
    return $prepared
}

function Resolve-ConformancePsql {
    param([AllowNull()][string]$ToolsDirectory)
    if ($ToolsDirectory) {
        $candidate = Join-Path $ToolsDirectory $(if ($IsWindows) { 'psql.exe' } else { 'psql' })
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { throw 'Selected PostgreSQL tools directory has no psql executable' }
        return (Get-Item -LiteralPath $candidate).FullName
    }
    return (Get-Command psql -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
}

function New-NativeConformanceDatabase {
    param([string]$AdminUrl, [string]$ExpectedDataDirectory, [string]$OutputDirectory, [string]$PostgresToolsDirectory)
    if (-not $ExpectedDataDirectory) { throw 'Native conformance requires an explicit PostgreSQL data directory' }
    $psql = Resolve-ConformancePsql -ToolsDirectory $PostgresToolsDirectory
    $actual = @(& $psql --dbname $AdminUrl -X -At -v ON_ERROR_STOP=1 -c 'SHOW data_directory' 2>$null)
    if ($LASTEXITCODE -ne 0) { throw 'Could not verify native conformance PostgreSQL ownership' }
    $comparison = if ($IsWindows) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
    if (-not [string]::Equals(($actual -join '').Trim().Replace('\','/').TrimEnd('/'), $ExpectedDataDirectory.Trim().Replace('\','/').TrimEnd('/'), $comparison)) {
        throw 'Native conformance PostgreSQL data directory does not match the explicitly selected cluster'
    }
    return New-ConformanceServiceDatabase -AdminUrl $AdminUrl -Service conformance -OutputDirectory $OutputDirectory -PostgresToolsDirectory $PostgresToolsDirectory
}

function New-ConformanceServiceDatabase {
    param([string]$AdminUrl, [string]$Service, [string]$Migration, [string]$OutputDirectory, [string]$PostgresToolsDirectory)
    $psql = Resolve-ConformancePsql -ToolsDirectory $PostgresToolsDirectory
    # Coauth's destructive-reset guard requires a separate test component.
    $name = 'cotest_test_' + $Service + '_' + [Guid]::NewGuid().ToString('N')
    if ($name -notmatch '^cotest_test_[a-z]+_[a-f0-9]{32}$') { throw 'Invalid owned database name' }
    $created = $false
    try {
        $log = Join-Path $OutputDirectory "$Service-database.log"
        & $psql --dbname $AdminUrl -X -v ON_ERROR_STOP=1 -c "CREATE DATABASE $name" *> $log
        if ($LASTEXITCODE -ne 0) { throw "Failed to create isolated $Service database; see $log" }
        $created = $true
        $url = [UriBuilder]::new($AdminUrl)
        $url.Path = "/$name"
        if ($Migration) {
            & $psql --dbname $url.Uri.AbsoluteUri -X -v ON_ERROR_STOP=1 -f $Migration *>> $log
            if ($LASTEXITCODE -ne 0) { throw "Failed to migrate isolated $Service database; see $log" }
        }
        return [pscustomobject]@{ Name = $name; AdminUrl = $AdminUrl; Url = $url.Uri.AbsoluteUri; Psql = $psql }
    } catch {
        if ($created) { Remove-ConformanceServiceDatabase ([pscustomobject]@{Name=$name; AdminUrl=$AdminUrl; Psql=$psql}) }
        throw
    }
}

function Remove-ConformanceServiceDatabase {
    param($Database)
    if ($Database.Name -notmatch '^cotest_test_[a-z]+_[a-f0-9]{32}$') { throw 'Invalid owned database cleanup' }
    & $Database.Psql --dbname $Database.AdminUrl -X -v ON_ERROR_STOP=1 -c "DROP DATABASE $($Database.Name) WITH (FORCE)" *> $null
    if ($LASTEXITCODE -ne 0) { Write-Warning "Could not remove owned database $($Database.Name)" }
}

function Assert-ConformanceDatabaseCapacity {
    param([string]$AdminUrl, [string]$PostgresToolsDirectory)
    $psql = Resolve-ConformancePsql -ToolsDirectory $PostgresToolsDirectory
    $locks = @(& $psql --dbname $AdminUrl -X -At -v ON_ERROR_STOP=1 -c 'SHOW max_locks_per_transaction' 2>$null)
    if ($LASTEXITCODE -ne 0) { throw 'Could not verify conformance PostgreSQL lock capacity' }
    if ([int](($locks -join '').Trim()) -lt 1024) {
        throw 'Parallel storage conformance requires max_locks_per_transaction >= 1024; select a suitably configured test cluster. The runner will not restart an external cluster.'
    }
}

function Get-ConformanceNativeRequirements {
    param([string]$Profile, [AllowNull()][string]$Package, [AllowNull()][string]$Target)
    $full = $Profile -in @('all', 'full-nightly') -and -not $Target
    $client = -not $Package -or $Package -eq 'cotest-inkson-client-tests'
    $aggregate = $Target -eq 'conformance_vectors'
    return [pscustomobject]@{
        Services = $Profile -in @('all', 'full-nightly', 'services-live', 'inkson-client-live')
        Sdk = $full -or $aggregate
        Binding = $full -or $Target -in @('agent_runtime_binding_live', 'agent_vectors_production') -or ($aggregate -and $client)
        Media = ($full -and $client) -or ($client -and ($aggregate -or $Target -in @('consent_current_production', 'consent_call_admission')))
        RouteEvidence = $full -or $aggregate -or $Target -eq 'sdk_precheck_production'
        Browser = $full -or $Target -in @('agent_provision_production', 'agent_vectors_production') -or ($aggregate -and $client)
        StorageLocks = $full -or $Target -eq 'key_backup_protocol'
    }
}
