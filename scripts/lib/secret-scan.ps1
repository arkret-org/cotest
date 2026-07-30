# Secret-scan primitives shared by run-cotest.ps1 and the synthetic-secret
# regression test (scripts/tests/secret-scan.tests.ps1). Dot-source this file;
# it defines functions only and has no side effects.
#
# Invariant: every pattern Find-SecretLeaks can match MUST have a matching
# redaction in ConvertTo-SecretPreview, so a real hit never lands verbatim in
# secret-scan.json/md (which are copied into a stable latest channel). The invariant
# is enforced by the synthetic-secret regression test, which run-cotest.ps1
# executes before every scan.
#
# `secret_b64u` is the exact field name key-management.md section 7.7.1
# forbids in logs, crash dumps, and telemetry. `credential` is listed so the
# JSON redaction also covers every field the did_in_token_field detector can
# match (token | push_key | credential).
#
# ## Two categories, two artifact classes
#
# A finding is not automatically a leak: it depends on what the artifact is.
#
#   * `recovery_private_material` — mnemonics, seeds, PRKs, private JWK members,
#     plaintext keybags, MLS private state. These are NEVER legitimate, in any
#     artifact. Always fail.
#   * `credential_exposure` — bearer tokens, JWS, signed links, authorization
#     fields. In a log or a telemetry stream these are a leak. In a durable
#     protocol store they are frequently the protocol evidence the spec requires
#     the server to persist: a PostgreSQL dump legitimately contains 55+ JWS and
#     authorization fields, and failing the gate on those either trains everyone
#     to ignore it or pushes someone to allowlist the whole scan — which would
#     also hide real recovery-material leaks.
#
# So the verdict is (category, artifact class):
#
#   | category                  | log_or_telemetry | durable_protocol_store |
#   | recovery_private_material | fail             | fail                   |
#   | credential_exposure       | fail             | allowed_by_artifact_class |
#
# Callers declare the class per scan root. The default is `log_or_telemetry`,
# the strict side, so a root added without thought fails closed.

$script:JsonSecretFieldNames = "authorization|access_token|token|push_key|invite_token|signed_link|jws|sig|password|secret|secret_b64u|private_key|seed|mnemonic|recovery_key|recovery_phrase|recovery_secret|root_seed|root_private_key|hkdf_prk|prk|credential|plaintext_keybag|keybag_secret|mls_secret|epoch_secret|application_secret|confirmation_key|membership_key|init_secret|joiner_secret|welcome_secret|private_state"
$script:QuerySecretFieldNames = "access_token|token|push_key|invite_token|signed_link|jws|sig|password|secret|secret_b64u|private_key|seed|mnemonic|recovery_key|recovery_phrase|recovery_secret|root_seed|root_private_key|hkdf_prk|prk|credential|plaintext_keybag|keybag_secret|mls_secret|epoch_secret|application_secret|confirmation_key|membership_key|init_secret|joiner_secret|welcome_secret|private_state"
$script:RecoveryPrivateMaterialFieldNames = "private_key|seed|mnemonic|recovery_key|recovery_phrase|recovery_secret|root_seed|root_private_key|hkdf_prk|prk|plaintext_keybag|keybag_secret|mls_secret|epoch_secret|application_secret|confirmation_key|membership_key|init_secret|joiner_secret|welcome_secret|private_state"
# Candidate shape only: a quoted string containing a run of 12+ short words.
# Surrounding prose and punctuation are allowed because logs commonly embed a
# mnemonic after text such as "recovery phrase:". Detection additionally
# requires 12 consecutive words from the BIP-39 English wordlist
# (Test-Bip39MnemonicCandidate), so ordinary long sentences do not trip the
# gate.
$script:Bip39SequencePattern = '(?i)"[^"\r\n]*(?:[a-z]{3,8}[ \t]+){11,}[a-z]{3,8}[^"\r\n]*"'
$script:Bip39WordSet = $null

# Structural detectors. Field-name matching alone misses private material that
# travels under a short, generic member name inside a well-known envelope:
#
#   * a JWK's `d` member is the private scalar for OKP / EC / RSA keys. The
#     cotest harness exports exactly this shape
#     (`ed25519PrivateKeySeedB64url` reads `jwk.d`), and no field-name list
#     containing `"d"` could be used on its own without matching every diff and
#     date field in the corpus. Binding it to a `kty` member on the same line
#     makes it unambiguous.
#   * a keybag object carrying raw `k` / `d` JWK members is a plaintext keybag
#     regardless of what the enclosing field is called.
#
# Both orders are matched because JSON member order is not guaranteed.
$script:JwkPrivateMemberPattern = '(?i)(?:"kty"\s*:\s*"(?:OKP|EC|RSA)"[^\r\n]{0,400}?"d"\s*:\s*"[A-Za-z0-9_\-+/=]{22,}"|"d"\s*:\s*"[A-Za-z0-9_\-+/=]{22,}"[^\r\n]{0,400}?"kty"\s*:\s*"(?:OKP|EC|RSA)")'
$script:PlaintextKeybagPattern = '(?i)"key_?bag"\s*:\s*[\{\[][^\r\n]{0,800}?"(?:k|d)"\s*:\s*"[A-Za-z0-9_\-+/=]{16,}"'

# Closed set of finding categories. See the file header for the verdict matrix.
$script:SecretCategoryPrivateMaterial = "recovery_private_material"
$script:SecretCategoryCredential = "credential_exposure"

# Closed set of artifact classes a scan root can be declared as.
$script:ArtifactClassLog = "log_or_telemetry"
$script:ArtifactClassDurableStore = "durable_protocol_store"

function Get-Bip39WordSet {
    if ($null -eq $script:Bip39WordSet) {
        $wordlistPath = Join-Path $PSScriptRoot "bip39-english.txt"
        $words = [System.IO.File]::ReadAllLines($wordlistPath)
        if ($words.Count -ne 2048) {
            throw "bip39-english.txt must contain exactly 2048 words, found $($words.Count)"
        }
        $set = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($word in $words) {
            [void]$set.Add($word)
        }
        $script:Bip39WordSet = $set
    }
    return $script:Bip39WordSet
}

# True when any quoted candidate run in the line contains 12 consecutive
# BIP-39 English words. 12 is the shortest standard mnemonic; requiring
# consecutive wordlist membership keeps natural-language sentences out.
function Test-Bip39MnemonicCandidate {
    param([Parameter(Mandatory = $true)][string]$Line)

    $wordSet = Get-Bip39WordSet
    foreach ($match in [regex]::Matches($Line, $script:Bip39SequencePattern)) {
        $run = 0
        foreach ($wordMatch in [regex]::Matches($match.Value, '(?i)(?<![a-z])[a-z]{3,8}(?![a-z])')) {
            $word = $wordMatch.Value.ToLowerInvariant()
            if ($wordSet.Contains($word)) {
                $run += 1
                if ($run -ge 12) {
                    return $true
                }
            } else {
                $run = 0
            }
        }
    }
    return $false
}

# Full-fidelity redaction of one line: every detectable pattern replaced by a
# marker, nothing truncated. `ConvertTo-SecretPreview` truncates this for the
# report; `Protect-SecretBearingFile` writes it back into the artifact, where
# truncation would destroy the surrounding diagnostic.
function ConvertTo-RedactedLine {
    param([Parameter(Mandatory = $true)][string]$Line)

    $preview = $Line
    $preview = $preview -replace '(?i)((?:^|\s)authorization\s*:\s*bearer\s+)(?!\[redacted\])\S+', '$1[redacted]'
    $preview = $preview -replace "(?i)(`"($script:JsonSecretFieldNames)`"\s*:\s*`")(?!\[redacted\])([^`"]+)(`")", '$1[redacted]$4'
    $preview = $preview -replace "(?i)((?:^|[?&\s])($script:QuerySecretFieldNames)=)(?!\[redacted\]|%5[Bb]redacted%5[Dd])([^&\s]+)", '$1[redacted]'
    $preview = $preview -replace "(?i)(\b($script:RecoveryPrivateMaterialFieldNames)\b\s*(?:=|:)\s*)(?!\[redacted\])(?:'[^']*'|`"[^`"]*`"|\S+)", '$1[redacted]'
    # Over-redacts non-mnemonic candidates on purpose: a preview may lose
    # harmless words but must never keep a real mnemonic.
    $preview = $preview -replace $script:Bip39SequencePattern, '"[redacted-mnemonic]"'
    # Same trade: any `"d"` / `"k"` member long enough to be key material is
    # blanked in previews. A preview that loses an unrelated `d` field costs a
    # diagnostic; one that keeps a private JWK scalar costs a key.
    $preview = $preview -replace '(?i)("(?:d|k)"\s*:\s*")(?!\[redacted\])[A-Za-z0-9_\-+/=]{16,}(")', '$1[redacted]$2'
    $preview = $preview -replace '-----BEGIN (RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[^\r\n]*-----END (RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----', '[redacted-private-key]'
    $preview = $preview -replace '-----BEGIN (RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----', '[redacted-private-key]'
    return $preview
}

function ConvertTo-SecretPreview {
    param([Parameter(Mandatory = $true)][string]$Line)

    $preview = ConvertTo-RedactedLine -Line $Line
    if ($preview.Length -gt 220) {
        return $preview.Substring(0, 220) + "...[truncated]"
    }
    return $preview
}

function Get-SecretLeakPatterns {
    @(
        [pscustomobject]@{ name = "authorization_header"; category = $script:SecretCategoryCredential; pattern = '(?i)(?:^|\s)authorization\s*:\s*bearer\s+(?!\[redacted\])\S+'; validate = $null },
        [pscustomobject]@{ name = "recovery_private_material_field"; category = $script:SecretCategoryPrivateMaterial; pattern = "(?i)`"($script:RecoveryPrivateMaterialFieldNames)`"\s*:\s*`"(?!\[redacted\])[^`"]+`""; validate = $null },
        [pscustomobject]@{ name = "recovery_private_material_assignment"; category = $script:SecretCategoryPrivateMaterial; pattern = "(?i)\b($script:RecoveryPrivateMaterialFieldNames)\b\s*(?:=|:)\s*(?!\[redacted\])(?:'[^']+'|`"[^`"]+`"|\S+)"; validate = $null },
        [pscustomobject]@{ name = "jwk_private_member"; category = $script:SecretCategoryPrivateMaterial; pattern = $script:JwkPrivateMemberPattern; validate = $null },
        [pscustomobject]@{ name = "plaintext_keybag_object"; category = $script:SecretCategoryPrivateMaterial; pattern = $script:PlaintextKeybagPattern; validate = $null },
        [pscustomobject]@{ name = "json_secret_field"; category = $script:SecretCategoryCredential; pattern = "(?i)`"($script:JsonSecretFieldNames)`"\s*:\s*`"(?!\[redacted\])[^`"]+`""; validate = $null },
        [pscustomobject]@{ name = "query_secret_field"; category = $script:SecretCategoryCredential; pattern = "(?i)(?:^|[?&\s])($script:QuerySecretFieldNames)=(?!\[redacted\]|%5[Bb]redacted%5[Dd])[^&\s]+"; validate = $null },
        [pscustomobject]@{ name = "bip39_mnemonic_sequence"; category = $script:SecretCategoryPrivateMaterial; pattern = $script:Bip39SequencePattern; validate = { param($line) Test-Bip39MnemonicCandidate -Line $line } },
        [pscustomobject]@{ name = "did_in_token_field"; category = $script:SecretCategoryCredential; pattern = '(?i)"(token|push_key|credential)"\s*:\s*"(did:[^"]+)"'; validate = $null },
        [pscustomobject]@{ name = "private_key_block"; category = $script:SecretCategoryPrivateMaterial; pattern = '-----BEGIN (RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'; validate = $null }
    )
}

# The verdict matrix from the file header, in one place.
#
# `recovery_private_material` fails everywhere. `credential_exposure` is
# tolerated only in a durable protocol store, where the spec requires the server
# to persist signed authorization evidence. Note that the private-material
# detectors fire independently of `json_secret_field`, so tolerating a
# credential finding in a store can never mask a mnemonic or a seed that
# happens to sit in a field the credential list also names.
function Get-SecretLeakVerdict {
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$ArtifactClass
    )

    if ($Category -eq $script:SecretCategoryPrivateMaterial) {
        return "fail"
    }
    if ($ArtifactClass -eq $script:ArtifactClassDurableStore) {
        return "allowed_by_artifact_class"
    }
    return "fail"
}

# Normalise a scan root given either as a bare path (strict default class) or
# as an object declaring its artifact class.
function ConvertTo-ScanRootDescriptor {
    param(
        [Parameter(Mandatory = $true)]$Root,
        [Parameter(Mandatory = $true)][string]$DefaultArtifactClass
    )

    if ($Root -is [string]) {
        return [pscustomobject]@{ path = $Root; artifact_class = $DefaultArtifactClass }
    }
    $path = $Root.path
    $class = if ($Root.PSObject.Properties.Name -contains "artifact_class" -and $Root.artifact_class) {
        $Root.artifact_class
    } else {
        $DefaultArtifactClass
    }
    if ($class -ne $script:ArtifactClassLog -and $class -ne $script:ArtifactClassDurableStore) {
        throw "unknown artifact class '$class' for scan root '$path'"
    }
    return [pscustomobject]@{ path = $path; artifact_class = $class }
}

function Add-SecretLeaksFromReader {
    param(
        [Parameter(Mandatory = $true)]$Reader,
        [Parameter(Mandatory = $true)][string]$DisplayPath,
        [Parameter(Mandatory = $true)][string]$ArtifactClass,
        [Parameter(Mandatory = $true)]$Patterns,
        [Parameter(Mandatory = $true)]$Leaks
    )

    $lineNo = 0
    while (-not $Reader.EndOfStream) {
        $line = $Reader.ReadLine()
        $lineNo += 1
        foreach ($pattern in $Patterns) {
            if ($line -match $pattern.pattern) {
                if ($pattern.validate -and -not (& $pattern.validate $line)) {
                    continue
                }
                $Leaks.Add([pscustomobject]@{
                        path           = $DisplayPath
                        line           = $lineNo
                        pattern        = $pattern.name
                        category       = $pattern.category
                        artifact_class = $ArtifactClass
                        verdict        = Get-SecretLeakVerdict -Category $pattern.category -ArtifactClass $ArtifactClass
                        preview        = ConvertTo-SecretPreview -Line $line
                    })
            }
        }
    }
}

# Scan every root and return one record per (file, line, pattern) hit.
#
# `ScanRoots` accepts bare paths or `{ path; artifact_class }` objects; a bare
# path takes `DefaultArtifactClass`, which is the strict `log_or_telemetry` so a
# root added without thought fails closed. Every returned record carries its
# category, the class of the artifact it came from, and the resulting verdict —
# callers gate on `verdict`, not on the record count.
function Find-SecretLeaks {
    param(
        [Parameter(Mandatory = $true)]$ScanRoots,
        [ValidateSet("log_or_telemetry", "durable_protocol_store")]
        [string]$DefaultArtifactClass = "log_or_telemetry"
    )

    $patterns = Get-SecretLeakPatterns
    $leaks = New-Object System.Collections.Generic.List[object]
    foreach ($rawRoot in @($ScanRoots)) {
        if (-not $rawRoot) {
            continue
        }
        $descriptor = ConvertTo-ScanRootDescriptor -Root $rawRoot -DefaultArtifactClass $DefaultArtifactClass
        $root = $descriptor.path
        $artifactClass = $descriptor.artifact_class
        if (-not $root -or -not (Test-Path $root)) {
            continue
        }
        $files = if ((Get-Item $root).PSIsContainer) {
            Get-ChildItem -Path $root -Recurse -File
        } else {
            @(Get-Item $root)
        }
        foreach ($file in $files) {
            if ($file.Extension -ieq ".zip") {
                try {
                    Add-Type -AssemblyName System.IO.Compression.FileSystem
                    $archive = [System.IO.Compression.ZipFile]::OpenRead($file.FullName)
                    try {
                        foreach ($entry in $archive.Entries) {
                            if ($entry.Length -eq 0 -or $entry.Length -gt 64MB) {
                                continue
                            }
                            $stream = $entry.Open()
                            $reader = New-Object System.IO.StreamReader($stream, $true)
                            try {
                                Add-SecretLeaksFromReader `
                                    -Reader $reader `
                                    -DisplayPath "$($file.FullName)!$($entry.FullName)" `
                                    -ArtifactClass $artifactClass `
                                    -Patterns $patterns `
                                    -Leaks $leaks
                            }
                            finally {
                                $reader.Dispose()
                                $stream.Dispose()
                            }
                        }
                    }
                    finally {
                        $archive.Dispose()
                    }
                }
                catch {
                    # A corrupt archive is covered by ordinary artifact
                    # integrity checks; keep scanning every other artifact.
                }
                continue
            }
            try {
                $stream = [System.IO.File]::OpenRead($file.FullName)
                $reader = New-Object System.IO.StreamReader($stream, $true)
                try {
                    Add-SecretLeaksFromReader `
                        -Reader $reader `
                        -DisplayPath $file.FullName `
                        -ArtifactClass $artifactClass `
                        -Patterns $patterns `
                        -Leaks $leaks
                }
                finally {
                    $reader.Dispose()
                    $stream.Dispose()
                }
            }
            catch {
                # Unreadable artifacts are covered by ordinary artifact
                # integrity checks; keep scanning every other artifact.
            }
        }
    }
    return $leaks
}

# Roll findings up into the shape the gate and the report both read.
function Get-SecretScanSummary {
    param([Parameter(Mandatory = $true)]$Leaks)

    $all = @($Leaks)
    $failing = @($all | Where-Object { $_.verdict -eq "fail" })
    return [pscustomobject]@{
        findings                  = $all.Count
        failing                   = $failing.Count
        allowed_by_artifact_class = @($all | Where-Object { $_.verdict -eq "allowed_by_artifact_class" }).Count
        recovery_private_material = @($all | Where-Object { $_.category -eq $script:SecretCategoryPrivateMaterial }).Count
        credential_exposure       = @($all | Where-Object { $_.category -eq $script:SecretCategoryCredential }).Count
    }
}

# Rewrite one text artifact so no detectable secret survives in it.
#
# Runs AFTER the scan, never before: the report keeps the file, line, pattern
# and category of every finding as evidence, while the artifact that is copied
# into the stable latest channel no longer carries the plaintext. Returns the
# number of lines that changed.
function Protect-SecretBearingFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return 0
    }
    $lines = [System.IO.File]::ReadAllLines($Path)
    $changed = 0
    for ($index = 0; $index -lt $lines.Count; $index++) {
        $redacted = ConvertTo-RedactedLine -Line $lines[$index]
        if ($redacted -ne $lines[$index]) {
            $lines[$index] = $redacted
            $changed += 1
        }
    }
    if ($changed -gt 0) {
        [System.IO.File]::WriteAllLines($Path, $lines)
    }
    return $changed
}

# Redact every plain-file artifact that produced a FAILING finding.
#
# Selection is by verdict, not by finding count. A durable protocol store's
# signed authorization evidence is `allowed_by_artifact_class`: rewriting it
# would destroy the very protocol record the store exists to hold, and a
# PostgreSQL dump with its JWS fields blanked is worthless for replay or
# forensics. Only artifacts that actually leaked get rewritten.
#
# When a file carries both -- a real private-material leak next to legitimate
# evidence -- the whole line is redacted. That file is not a trustworthy
# artifact regardless, so the strict side wins.
#
# Archive members (`<zip>!<entry>`) are reported as `not_redacted` rather than
# silently skipped: a secret inside a retained archive needs the archive
# dropped, and a silent skip would read as "handled".
function Protect-SecretBearingArtifacts {
    param([Parameter(Mandatory = $true)]$Leaks)

    $redacted = New-Object System.Collections.Generic.List[object]
    $notRedacted = New-Object System.Collections.Generic.List[string]
    $paths = @($Leaks | Where-Object { $_.verdict -eq "fail" } | ForEach-Object { $_.path } | Sort-Object -Unique)
    foreach ($path in $paths) {
        if ($path -like "*!*") {
            $notRedacted.Add($path)
            continue
        }
        $changed = Protect-SecretBearingFile -Path $path
        if ($changed -gt 0) {
            $redacted.Add([pscustomobject]@{ path = $path; redacted_lines = $changed })
        }
    }
    # Return arrays, not the accumulator lists: a `List[object]` surfaced on a
    # property makes the ordinary `@($result.redacted_files).Count` throw
    # "Argument types do not match" in PowerShell 7, which reads like a bug in
    # the caller rather than a container-type leak here.
    return [pscustomobject]@{
        redacted_files = $redacted.ToArray()
        not_redacted   = $notRedacted.ToArray()
    }
}
