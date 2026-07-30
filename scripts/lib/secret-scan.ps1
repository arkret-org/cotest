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

$script:JsonSecretFieldNames = "authorization|access_token|token|push_key|invite_token|signed_link|jws|sig|password|secret|secret_b64u|private_key|seed|mnemonic|recovery_key|recovery_phrase|recovery_secret|root_seed|root_private_key|hkdf_prk|prk|credential|plaintext_keybag|keybag_secret|mls_secret|epoch_secret|application_secret|confirmation_key|membership_key|init_secret|joiner_secret|welcome_secret|private_state"
$script:QuerySecretFieldNames = "access_token|token|push_key|invite_token|signed_link|jws|sig|password|secret|secret_b64u|private_key|seed|mnemonic|recovery_key|recovery_phrase|recovery_secret|root_seed|root_private_key|hkdf_prk|prk|credential|plaintext_keybag|keybag_secret|mls_secret|epoch_secret|application_secret|confirmation_key|membership_key|init_secret|joiner_secret|welcome_secret|private_state"
# Candidate shape only: a quoted string containing a run of 12+ short words.
# Surrounding prose and punctuation are allowed because logs commonly embed a
# mnemonic after text such as "recovery phrase:". Detection additionally
# requires 12 consecutive words from the BIP-39 English wordlist
# (Test-Bip39MnemonicCandidate), so ordinary long sentences do not trip the
# gate.
$script:Bip39SequencePattern = '(?i)"[^"\r\n]*(?:[a-z]{3,8}[ \t]+){11,}[a-z]{3,8}[^"\r\n]*"'
$script:Bip39WordSet = $null

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

function ConvertTo-SecretPreview {
    param([Parameter(Mandatory = $true)][string]$Line)

    $preview = $Line
    $preview = $preview -replace '(?i)((?:^|\s)authorization\s*:\s*bearer\s+)(?!\[redacted\])\S+', '$1[redacted]'
    $preview = $preview -replace "(?i)(`"($script:JsonSecretFieldNames)`"\s*:\s*`")(?!\[redacted\])([^`"]+)(`")", '$1[redacted]$4'
    $preview = $preview -replace "(?i)((?:^|[?&\s])($script:QuerySecretFieldNames)=)(?!\[redacted\]|%5[Bb]redacted%5[Dd])([^&\s]+)", '$1[redacted]'
    # Over-redacts non-mnemonic candidates on purpose: a preview may lose
    # harmless words but must never keep a real mnemonic.
    $preview = $preview -replace $script:Bip39SequencePattern, '"[redacted-mnemonic]"'
    $preview = $preview -replace '-----BEGIN (RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[^\r\n]*-----END (RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----', '[redacted-private-key]'
    $preview = $preview -replace '-----BEGIN (RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----', '[redacted-private-key]'
    if ($preview.Length -gt 220) {
        return $preview.Substring(0, 220) + "...[truncated]"
    }
    return $preview
}

function Get-SecretLeakPatterns {
    @(
        [pscustomobject]@{ name = "authorization_header"; pattern = '(?i)(?:^|\s)authorization\s*:\s*bearer\s+(?!\[redacted\])\S+'; validate = $null },
        [pscustomobject]@{ name = "json_secret_field"; pattern = "(?i)`"($script:JsonSecretFieldNames)`"\s*:\s*`"(?!\[redacted\])[^`"]+`""; validate = $null },
        [pscustomobject]@{ name = "query_secret_field"; pattern = "(?i)(?:^|[?&\s])($script:QuerySecretFieldNames)=(?!\[redacted\]|%5[Bb]redacted%5[Dd])[^&\s]+"; validate = $null },
        [pscustomobject]@{ name = "bip39_mnemonic_sequence"; pattern = $script:Bip39SequencePattern; validate = { param($line) Test-Bip39MnemonicCandidate -Line $line } },
        [pscustomobject]@{ name = "did_in_token_field"; pattern = '(?i)"(token|push_key|credential)"\s*:\s*"(did:[^"]+)"'; validate = $null },
        [pscustomobject]@{ name = "private_key_block"; pattern = '-----BEGIN (RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'; validate = $null }
    )
}

function Add-SecretLeaksFromReader {
    param(
        [Parameter(Mandatory = $true)]$Reader,
        [Parameter(Mandatory = $true)][string]$DisplayPath,
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
                        path    = $DisplayPath
                        line    = $lineNo
                        pattern = $pattern.name
                        preview = ConvertTo-SecretPreview -Line $line
                    })
            }
        }
    }
}

function Find-SecretLeaks {
    param([Parameter(Mandatory = $true)][string[]]$ScanRoots)

    $patterns = Get-SecretLeakPatterns
    $leaks = New-Object System.Collections.Generic.List[object]
    foreach ($root in $ScanRoots) {
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
