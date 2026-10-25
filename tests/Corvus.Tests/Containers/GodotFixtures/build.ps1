# Rebuilds the Godot pack fixtures with the engine's PCKPacker. CORVUS_GODOT_RELEASES is a folder with one
# godot-<version> folder per Godot release holding its editor executable; 3.6.3, 4.3, 4.5.1 and 4.7.2 write pack
# formats 1, 2, 3 and 4, and 4.7.2 also writes an encrypted pack with a test key.
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$releases = $env:CORVUS_GODOT_RELEASES
if (-not $releases) { throw 'set CORVUS_GODOT_RELEASES to a folder of godot-<version> folders' }
function Engine([string]$version) {
    $exe = Get-ChildItem (Join-Path $releases "godot-$version") -File | Where-Object { $_.Name -like 'Godot_v*' -and $_.Extension -in '.exe', '.x86_64' } |
        Sort-Object { $_.Name -notlike '*_console*' } | Select-Object -First 1
    if (-not $exe) { throw "no Godot executable under godot-$version" }
    return $exe.FullName
}
$project = Join-Path ([IO.Path]::GetTempPath()) "corvus-godot-$PID"
New-Item -ItemType Directory -Force $project | Out-Null
New-Item -ItemType File -Force (Join-Path $project 'project.godot') | Out-Null
try {
    $null | & (Engine '3.6.3') --no-window --path $project --script (Join-Path $here 'pack3.gd') (Join-Path $here 'format-1.pck') 2>&1 | Out-Null
    foreach ($b in @(@('4.3', 'format-2.pck', $null), @('4.5.1', 'format-3.pck', $null), @('4.7.2', 'format-4.pck', $null),
                     @('4.7.2', 'format-4-encrypted.pck', ('0123456789abcdef' * 4)))) {
        $version, $name, $key = $b
        $packArgs = @('--headless', '--path', $project, '--script', (Join-Path $here 'pack4.gd'), '--', (Join-Path $here $name))
        if ($key) { $packArgs += $key }
        $null | & (Engine $version) @packArgs 2>&1 | Out-Null
    }
    foreach ($n in 'format-1.pck', 'format-2.pck', 'format-3.pck', 'format-4.pck', 'format-4-encrypted.pck') {
        if (-not (Test-Path (Join-Path $here $n))) { throw "$n was not written" }
    }
}
finally {
    Remove-Item -Recurse -Force $project -ErrorAction SilentlyContinue
}
