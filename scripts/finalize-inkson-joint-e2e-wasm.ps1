[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SourceWasm,
    [Parameter(Mandatory = $true)][string]$OutputDirectory
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$lockPath = Join-Path $OutputDirectory ".finalize.lock"
try {
    $finalizeLock = [System.IO.File]::Open(
        $lockPath,
        [System.IO.FileMode]::OpenOrCreate,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::None
    )
}
catch [System.IO.IOException] {
    throw "another Inkson WASM finalizer owns $OutputDirectory"
}

$loader = @'

globalThis.__wasm_split_main_initSync = initSync;

__wbg_init({module_or_path: new URL('inkson_bg.wasm', import.meta.url)}).then((wasm) => {
    globalThis.__dx_mainWasm = wasm;
    globalThis.__dx_mainInit = __wbg_init;
    globalThis.__dx_mainInitSync = initSync;
    globalThis.__dx___wbg_get_imports = __wbg_get_imports;

    if (wasm.__wbindgen_start == undefined) {
        wasm.main();
    }
});
'@

try {
    & wasm-bindgen `
        --target web `
        --out-dir $OutputDirectory `
        --out-name inkson `
        $SourceWasm
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    $javascriptPath = Join-Path $OutputDirectory "inkson.js"
    Add-Content -LiteralPath $javascriptPath -Value $loader -Encoding UTF8
    $javascript = Get-Content -LiteralPath $javascriptPath -Raw
    $loaderCount = [regex]::Matches(
        $javascript,
        [regex]::Escape("globalThis.__wasm_split_main_initSync = initSync;")
    ).Count
    if ($loaderCount -ne 1) {
        throw "Inkson WASM finalizer expected exactly one startup loader, found $loaderCount"
    }
}
finally {
    $finalizeLock.Dispose()
}
