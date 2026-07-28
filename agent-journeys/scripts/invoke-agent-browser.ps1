[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RunDir,
    [Parameter(Mandatory = $true)]
    [string]$Actor,
    [switch]$Sensitive,
    [Parameter(Mandatory = $true)]
    [string[]]$BrowserArgs
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$resolvedRunDir = (Resolve-Path -LiteralPath $RunDir).Path
$resultPath = Join-Path $resolvedRunDir "result.json"
$result = Get-Content -Raw -LiteralPath $resultPath | ConvertFrom-Json
$knownActors = @($result.actors | ForEach-Object { [string]$_.id })
if ($Actor -notin $knownActors) {
    throw "Unknown journey actor '$Actor'. Expected one of: $($knownActors -join ', ')"
}
if ($BrowserArgs.Count -eq 0) {
    throw "At least one agent-browser argument is required"
}

$sessionName = ("{0}-{1}" -f $result.run_id, $Actor) -replace '[^a-zA-Z0-9_-]', '-'
$profileDirectory = Join-Path $resolvedRunDir "profiles\$Actor"
$null = New-Item -ItemType Directory -Force -Path $profileDirectory
$startedAt = (Get-Date).ToUniversalTime()
$previousErrorActionPreference = $ErrorActionPreference
try {
    $ErrorActionPreference = "Continue"
    # Do not capture stdout in a PowerShell variable. The agent-browser daemon
    # inherits the capture pipe on Windows and can keep it open after the CLI
    # command has completed. Streaming output directly avoids that deadlock.
    & agent-browser --session $sessionName --profile $profileDirectory @BrowserArgs
    $exitCode = $LASTEXITCODE
}
finally {
    $ErrorActionPreference = $previousErrorActionPreference
}

$loggedArgs = @($BrowserArgs)
if ($Sensitive -and $loggedArgs.Count -gt 0) {
    $loggedArgs[$loggedArgs.Count - 1] = "<redacted>"
}
$record = [ordered]@{
    timestamp = $startedAt.ToString("o")
    duration_ms = [math]::Round(((Get-Date).ToUniversalTime() - $startedAt).TotalMilliseconds)
    actor = $Actor
    session = $sessionName
    profile = $profileDirectory
    arguments = $loggedArgs
    sensitive = [bool]$Sensitive
    exit_code = $exitCode
}
$record | ConvertTo-Json -Compress -Depth 5 | Add-Content -LiteralPath (Join-Path $resolvedRunDir "actions.ndjson") -Encoding UTF8
if ($exitCode -ne 0) {
    throw "agent-browser exited with code $exitCode"
}
