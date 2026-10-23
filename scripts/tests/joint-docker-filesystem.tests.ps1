param([string]$Image = "ubuntu:24.04")
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$runner = Join-Path $PSScriptRoot "../run-joint-e2e.ps1"
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($runner, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw "The joint runner must parse" }
foreach ($name in @("Invoke-NativeCapture", "Get-ManagedDockerIdentityArguments")) {
    $definition = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true))
    if ($definition.Count -ne 1) { throw "Expected real helper $name" }
    Invoke-Expression $definition[0].Extent.Text
}

$driverUid = (Invoke-NativeCapture -FilePath "id" -Arguments @("-u") | Out-String).Trim()
$driverGid = (Invoke-NativeCapture -FilePath "id" -Arguments @("-g") | Out-String).Trim()
if ($driverUid -eq "0") { throw "Run this regression as an unprivileged fixture driver" }
$scratch = Join-Path ([IO.Path]::GetTempPath()) ("cotest-docker-owner-" + [Guid]::NewGuid().ToString("n"))
$volume = "cotest-docker-owner-" + [Guid]::NewGuid().ToString("n")
$directories = @("objects", "state", "logs") | ForEach-Object { Join-Path $scratch $_ }
try {
    foreach ($directory in $directories) { $null = New-Item -ItemType Directory -Path $directory -Force }
    $identity = @(Get-ManagedDockerIdentityArguments -LinuxHost $true -Image $Image -MountDirectories $directories)
    Invoke-NativeCapture -FilePath "docker" -Arguments @("volume", "create", "--label", "cotest.runner=filesystem-regression", $volume) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Cannot create the owned Linux test volume" }
    $mount = "type=volume,source=$volume,target=/tmp/coland-state"
    # Keep a marker so Docker does not copy up an empty volume's root metadata
    # again. This native Linux filesystem avoids Desktop bind-mount emulation.
    $prepare = "touch /tmp/coland-state/.fixture-owner && chown ${driverUid}:${driverGid} /tmp/coland-state && chmod 755 /tmp/coland-state"
    Invoke-NativeCapture -FilePath "docker" -Arguments @("run", "--rm", "--network", "none", "--user", "0:0", "--mount", $mount, "--entrypoint", "/bin/sh", $Image, "-c", $prepare) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Cannot prepare Linux fixture ownership" }
    $write = 'umask 077; printf fixture > /tmp/coland-state/private-probe && stat -c "%u:%g %a" /tmp/coland-state/private-probe'
    $before = Invoke-NativeCapture -FilePath "docker" -Arguments @("run", "--rm", "--network", "none", "--user", "10001:10001", "--mount", $mount, "--entrypoint", "/bin/sh", $Image, "-c", $write)
    if ($LASTEXITCODE -eq 0) { throw "The original mismatched image user must be refused" }
    $after = Invoke-NativeCapture -FilePath "docker" -Arguments (@("run", "--rm", "--network", "none", "--mount", $mount, "--entrypoint", "/bin/sh") + $identity + @($Image, "-c", $write))
    if ($LASTEXITCODE -ne 0 -or ($after | Out-String).Trim() -ne "${driverUid}:${driverGid} 600") {
        throw "The actual helper must retain a private, driver-readable fixture: $after"
    }
    Write-Host "Linux Docker ownership regression passed: mismatched user refused; actual helper writes mode 0600."
} finally {
    & docker volume rm $volume 2>$null | Out-Null
    if (Test-Path $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force }
}
