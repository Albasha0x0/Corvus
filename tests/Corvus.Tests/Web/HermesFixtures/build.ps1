# Rebuilds the Hermes bytecode fixtures from sample.js, features.js and metro.js with every Hermes compiler found.
# CORVUS_FIXTURE_HERMESC: a folder with one subfolder per Hermes release (the hermes-cli release archives, and react-native's
# sdks/hermesc for 0.69, 0.71, 0.72), each holding hermesc (or hermes, for releases before 0.7). Compiled from this folder,
# so the debug info names the source file only. Each output is <source>-v<bytecode version>.hbc; a compiler that rejects a
# source (features.js needs async functions, 0.8 and later) is skipped; metro.js is kept for the oldest and newest versions.
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$root = $env:CORVUS_FIXTURE_HERMESC
if (-not $root) { throw 'set CORVUS_FIXTURE_HERMESC to the folder of Hermes compilers' }
$compilers = Get-ChildItem $root -Recurse -File | Where-Object { $_.BaseName -in 'hermesc', 'hermes' } |
    Group-Object DirectoryName | ForEach-Object { $_.Group | Sort-Object { $_.BaseName -ne 'hermesc' } | Select-Object -First 1 }
$tmp = Join-Path ([IO.Path]::GetTempPath()) "corvus-hbc-$PID"
New-Item -ItemType Directory -Force $tmp | Out-Null
try {
    Push-Location $here
    foreach ($source in 'sample.js', 'features.js', 'metro.js') {
        $built = @{}
        foreach ($c in $compilers) {
            $out = Join-Path $tmp ([IO.Path]::GetRandomFileName())
            & $c.FullName -emit-binary -O -out $out $source 2>$null | Out-Null
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path $out)) { continue }
            $version = [BitConverter]::ToUInt32([IO.File]::ReadAllBytes($out), 8)
            $built[$version] = $out
        }
        $versions = $built.Keys | Sort-Object
        if ($source -eq 'metro.js') { $versions = @($versions | Select-Object -First 1) + @($versions | Select-Object -Last 1) }
        foreach ($v in $versions) { Copy-Item $built[$v] (Join-Path $here "$([IO.Path]::GetFileNameWithoutExtension($source))-v$v.hbc") -Force }
        Write-Host "$source -> versions $($versions -join ', ')"
    }
}
finally {
    Pop-Location
    Remove-Item -Recurse -Force $tmp
}
