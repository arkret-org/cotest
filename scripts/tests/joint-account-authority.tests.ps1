$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$runnerPath = Join-Path $PSScriptRoot "../run-joint-e2e.ps1"
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $runnerPath, [ref]$tokens, [ref]$parseErrors
)
if ($parseErrors.Count) { throw "Joint runner has PowerShell parse errors" }
if ($ast.Extent.Text -match 'Get-DescribedServiceId -BaseUrl \$CoauthBaseUrl') {
    throw "Private Account Authority must not be queried as an independently described Station"
}
$requiredFunctions = @(
    "Quote-PsLiteral", "Write-DotEnvFile", "Get-ContainerHostGatewayIpv4", "Convert-ToContainerReachableUrl",
    "Build-SolandCommand", "Build-SolandDockerEnvironment", "Wait-HttpReady"
)
foreach ($name in $requiredFunctions) {
    $definition = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if ($definition.Count -ne 1) { throw "Expected exactly one runner function: $name" }
    Invoke-Expression $definition[0].Extent.Text
}

$testDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("cotest-authority-" + [guid]::NewGuid())
[void](New-Item -ItemType Directory -Path $testDirectory)
$configPath = Join-Path $testDirectory "soland.env"
$CoauthBaseUrl = "https://coauth.joint.example"
$StartCoauth = $true
$CoauthCommand = $null
$script:UseManagedCoauthAssertionKey = $true
$CoauthServiceId = $null
$CoauthEmbeddedWebvhRegistrationBearer = "test-registration-bearer"
$CoauthSessionGrantIntrospectionBearer = "test-introspection-bearer"
$CoauthOAuthClientId = "test-client"
$TeabayBaseUrl = $null
$WebvhDegradedNoWitnessMaxSecs = 60
$SolandContainerPort = 8008
$script:ContainerHostGatewayIpv4 = "192.0.2.1"
$solandChaosControlFile = Join-Path $testDirectory "chaos.json"
$processArguments = @{
    BinaryPath = "soland.exe"; ConfigPath = $configPath
    BaseUrl = "https://station.joint.example"; DatabaseUrl = "postgresql://localhost/test"
    ObjectsRoot = $testDirectory; StateRoot = $testDirectory; Port = 8008
    MetricsPort = 9001; LogFile = (Join-Path $testDirectory "trace.log")
    CorsAllowOrigin = "https://inkson.joint.example"; KeyStoreMasterKey = "test-key"
    NotarySigningKey = ""; FederationPeers = ""
}
$dockerArguments = @{
    BaseUrl = $processArguments.BaseUrl; DatabaseUrl = $processArguments.DatabaseUrl
    MetricsPort = 9001; LogFileName = "trace.log"
    CorsAllowOrigin = $processArguments.CorsAllowOrigin; KeyStoreMasterKey = "test-key"
    NotarySigningKey = ""; FederationPeers = ""
}
try {
    Build-SolandCommand @processArguments | Out-Null
    $bootstrapConfig = Get-Content -LiteralPath $configPath -Raw
    if ($bootstrapConfig -match "SOLAND_ACCOUNT_AUTHORITY_SERVICE_ID=") {
        throw "Identity bootstrap must not guess an Account Authority identity"
    }
    if ($bootstrapConfig -notmatch 'SOLAND_ACCOUNT_AUTHORITY_URL="https://coauth.joint.example"') {
        throw "Identity bootstrap must bind the managed Account Authority endpoint to its pinned key"
    }
    if ($bootstrapConfig -notmatch 'SOLAND_ACCOUNT_AUTHORITY_PUBLIC_KEY_MULTIBASE=') {
        throw "Station inception must preauthorize the deployment Account Authority public key"
    }
    # The runner fills CoauthCommand after generating its managed config.
    # That mutation must not erase the previously selected signing delegation.
    $CoauthCommand = "generated-managed-coauth-command"
    Build-SolandCommand @processArguments | Out-Null
    if ((Get-Content -LiteralPath $configPath -Raw) -notmatch 'SOLAND_ACCOUNT_AUTHORITY_PUBLIC_KEY_MULTIBASE=') {
        throw "Generated CoauthCommand must preserve the managed authority delegation"
    }
    $script:UseManagedCoauthAssertionKey = $false
    Build-SolandCommand @processArguments | Out-Null
    if ((Get-Content -LiteralPath $configPath -Raw) -match 'SOLAND_ACCOUNT_AUTHORITY_PUBLIC_KEY_MULTIBASE=') {
        throw "Caller-owned Coauth must not receive a fixture signing delegation"
    }
    $script:UseManagedCoauthAssertionKey = $true
    $bootstrapDocker = Build-SolandDockerEnvironment @dockerArguments
    if ($bootstrapDocker.SOLAND_ACCOUNT_AUTHORITY_URL -ne $CoauthBaseUrl) {
        throw "Docker identity bootstrap must bind the managed Account Authority endpoint to its pinned key"
    }

    $CoauthServiceId = "ak:did_core:web:station.joint.example"
    Build-SolandCommand @processArguments | Out-Null
    $boundConfig = Get-Content -LiteralPath $configPath -Raw
    if ($boundConfig -notmatch [regex]::Escape("SOLAND_ACCOUNT_AUTHORITY_SERVICE_ID=`"$CoauthServiceId`"")) {
        throw "Process config must pin the actual owning Station identity"
    }
    if ($boundConfig -notmatch 'SOLAND_ACCOUNT_AUTHORITY_URL="https://coauth.joint.example"') {
        throw "Bound process config must advertise the Account Authority endpoint"
    }
    $boundDocker = Build-SolandDockerEnvironment @dockerArguments
    if ($boundDocker.SOLAND_ACCOUNT_AUTHORITY_SERVICE_ID -ne $CoauthServiceId) {
        throw "Docker config must use the same owning Station identity"
    }
    if ($boundConfig -match "ENROLLMENT_DID" -or $boundDocker.Contains("SOLAND_ACCOUNT_AUTHORITY_ENROLLMENT_DID")) {
        throw "Retired independent enrollment identity must not be emitted"
    }
    $betaAuthorityUrl = "https://coauth-beta.joint.example"
    $betaStationId = "ak:did_core:web:station-beta.joint.example"
    Build-SolandCommand @processArguments -AccountAuthorityBaseUrl $betaAuthorityUrl -AccountAuthorityServiceId $betaStationId | Out-Null
    $betaConfig = Get-Content -LiteralPath $configPath -Raw
    if ($betaConfig -notmatch [regex]::Escape("SOLAND_ACCOUNT_AUTHORITY_SERVICE_ID=`"$betaStationId`"") -or
        $betaConfig -notmatch [regex]::Escape("SOLAND_ACCOUNT_AUTHORITY_URL=`"$betaAuthorityUrl`"")) {
        throw "Beta must use its own Station identity and Account Authority endpoint"
    }
    $betaDocker = Build-SolandDockerEnvironment @dockerArguments -AccountAuthorityBaseUrl $betaAuthorityUrl -AccountAuthorityServiceId $betaStationId
    if ($betaDocker.SOLAND_ACCOUNT_AUTHORITY_SERVICE_ID -ne $betaStationId -or $betaDocker.SOLAND_ACCOUNT_AUTHORITY_URL -ne $betaAuthorityUrl) {
        throw "Docker Beta authority must remain independent from Alpha"
    }

    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $rejected = $false
    try {
        Wait-HttpReady -Url "http://127.0.0.1:1/health" -TimeoutSeconds 30 -ManagedService @{
            Kind = "process"; Name = "exited-test-service"; Process = @{ HasExited = $true }
        }
    } catch {
        $rejected = $_.Exception.Message -match "exited before readiness"
    }
    if (-not $rejected -or $clock.Elapsed.TotalSeconds -ge 1) {
        throw "Exited managed service must fail readiness immediately"
    }
    Write-Output "Joint Account Authority config and early-exit assertions passed."
} finally {
    if (Test-Path -LiteralPath $configPath) { Remove-Item -LiteralPath $configPath }
    Remove-Item -LiteralPath $testDirectory
}
