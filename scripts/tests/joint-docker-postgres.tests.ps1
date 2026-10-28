param([string]$Image = "postgres:18-alpine")
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$runner = Join-Path $PSScriptRoot "../run-joint-e2e.ps1"
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($runner, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw "The joint runner must parse" }
foreach ($name in @("Invoke-NativeCapture", "Get-HarnessTcpPortRange", "Get-WindowsExcludedTcpPortRanges", "Test-TcpPortExcluded", "Test-TcpPortBindable", "Get-FreeTcpPort", "Start-EphemeralPostgres", "Stop-EphemeralPostgres", "Get-ContainerHostGatewayIpv4", "Convert-ToContainerReachableUrl")) {
    $definition = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true))
    if ($definition.Count -ne 1) { throw "Expected real helper $name" }
    . ([scriptblock]::Create($definition[0].Extent.Text))
}
function Test-JointNativePostgresHandle { param($Handle) return $false }
$PostgresAdminUrl = $null
$ColandRuntime = "docker"
$ColandImage = $Image
$script:ContainerHostGatewayIpv4 = $null
$script:AllocatedTcpPorts = [System.Collections.Generic.HashSet[int]]::new()
$script:TcpPortRange = $null
$script:NextTcpPortCandidate = $null
$script:WindowsExcludedTcpPortRanges = $null
$script:ContainerPostgresUrls = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
$database = $null
try {
    $database = Start-EphemeralPostgres -Image $Image -NamePrefix "cotest-pg-routing" -TimeoutSeconds 60
    $hostUri = [uri]$database.Url
    if ($hostUri.Host -ne "127.0.0.1") { throw "The host database URL must remain loopback" }
    $binding = (Invoke-NativeCapture -FilePath "docker" -Arguments @(
        "inspect", "--format", '{{(index .HostConfig.PortBindings "5432/tcp" 0).HostIp}}', $database.ContainerName
    ) | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $binding -ne "127.0.0.1") { throw "The database publication must remain loopback" }
    $containerUrl = Convert-ToContainerReachableUrl $database.Url
    if ([uri]$containerUrl -eq $hostUri -or ([uri]$containerUrl).Port -ne 5432) { throw "The owned database needs its bridge endpoint" }
    $result = Invoke-NativeCapture -FilePath "docker" -Arguments @(
        "run", "--rm", "--entrypoint", "psql", $Image, $containerUrl, "-Atc", "SELECT current_database()"
    )
    if ($LASTEXITCODE -ne 0 -or ($result | Out-String).Trim() -ne "arkret") { throw "A peer container cannot query the owned database" }
    $script:ContainerHostGatewayIpv4 = "192.0.2.1"
    $unowned = "postgresql://other:other@127.0.0.1:$($database.HostPort)/other"
    if (([uri](Convert-ToContainerReachableUrl $unowned)).Host -ne "192.0.2.1") { throw "An unowned URL must not acquire a database mapping" }
    Write-Host "Owned PostgreSQL bridge query passed; host publication remains loopback; unowned URL stays unmapped."
} finally {
    if ($database) { Stop-EphemeralPostgres $database.ContainerName }
}
