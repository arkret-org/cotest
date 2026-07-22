[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SourceWasm,
    [Parameter(Mandatory = $true)][string]$OutputDirectory
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
& wasm-bindgen `
    --target web `
    --out-dir $OutputDirectory `
    --out-name inkson `
    $SourceWasm
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
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
Add-Content -LiteralPath (Join-Path $OutputDirectory "inkson.js") -Value $loader -Encoding UTF8
