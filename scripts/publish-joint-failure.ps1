param(
    [Parameter(Mandatory = $true)][string]$RunRoot,
    [Parameter(Mandatory = $true)][string]$OutputDirectory
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "lib/secret-scan.ps1")

$source = [IO.Path]::GetFullPath($RunRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
$destination = [IO.Path]::GetFullPath($OutputDirectory)
if ($destination -eq $source -or $destination.StartsWith($source + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Public diagnostics must be outside the private run root"
}
if (Test-Path -LiteralPath $destination) { throw "Public diagnostics directory already exists" }
$staging = $destination + ".staging-" + [Guid]::NewGuid().ToString("n")
$null = New-Item -ItemType Directory -Path $staging -Force
$manifest = [Collections.Generic.List[object]]::new()
try {
    if (Test-Path -LiteralPath $source) {
        foreach ($file in Get-ChildItem -LiteralPath $source -Recurse -File) {
            if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            $selected = $file.Name -in @("managed-service-failures.json", "managed-service-failures.md", "runner-error.log", "summary.md") -or
                $file.Name -match '^coland-server\d+(?:-bootstrap)?\.(?:stdout|stderr)\.log$'
            if (-not $selected) { continue }
            $relative = [IO.Path]::GetRelativePath($source, $file.FullName)
            if ($file.Length -gt 4MB) {
                $manifest.Add([pscustomobject]@{path = $relative; exported = $false; reason = "exceeds bounded startup diagnostic size"})
                continue
            }
            $safe = [Collections.Generic.Queue[string]]::new()
            $privateBlock = $false
            foreach ($line in [IO.File]::ReadAllLines($file.FullName)) {
                if ($line -match '-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----') { $privateBlock = $true }
                $redacted = if ($privateBlock) { "[redacted]" } else { ConvertTo-RedactedLine -Line $line }
                if ($line -match '-----END (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----') { $privateBlock = $false }
                $safe.Enqueue($redacted)
                if ($safe.Count -gt 200) { $null = $safe.Dequeue() }
            }
            $target = Join-Path $staging $relative
            $null = New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force
            [IO.File]::WriteAllLines($target, $safe.ToArray())
            $manifest.Add([pscustomobject]@{
                path = $relative; exported = $true
                source_sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                public_sha256 = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
            })
        }
    }
    $leaks = @(Find-SecretLeaks -ScanRoots @($staging))
    $scan = Get-SecretScanSummary -Leaks $leaks
    if ($scan.failing -ne 0) { throw "Startup diagnostics still contain forbidden private material" }
    ConvertTo-Json -InputObject @($manifest) -Depth 4 | Set-Content -LiteralPath (Join-Path $staging "manifest.json") -Encoding utf8
    Move-Item -LiteralPath $staging -Destination $destination
    Write-Host "Published $(@($manifest | Where-Object exported).Count) sanitized startup diagnostics."
} finally {
    if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
}
