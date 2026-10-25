# Rebuilds the Unreal fixtures: paks with repak (CORVUS_PAK_TOOL: repak.exe, 0.2.3 tested) and IoStore containers with
# retoc (CORVUS_IOSTORE_TOOL: retoc.exe, 0.1.5 tested). Input is generated: two text files in nested folders, plus zeros
# whose data spans several compression blocks. One pak per version and compression method the engine-built packs do not
# cover; IoStore containers hold the same files as ExternalFile chunks, with and without paths in the directory index.
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$pakTool = $env:CORVUS_PAK_TOOL
$ioTool = $env:CORVUS_IOSTORE_TOOL
if (-not $pakTool -or -not $ioTool) { throw 'set CORVUS_PAK_TOOL to repak.exe and CORVUS_IOSTORE_TOOL to retoc.exe' }
$tmp = Join-Path ([IO.Path]::GetTempPath()) "corvus-unreal-$PID"
$settings = "[Section]`nName=Ledger`nCount=3`n" * 40
$notes = "nested entry`n"
try {
    foreach ($set in 'stored', 'compressed') {
        $root = Join-Path $tmp "$set\content"
        New-Item -ItemType Directory -Force (Join-Path $root 'Config\Nested') | Out-Null
        [IO.File]::WriteAllText((Join-Path $root 'Config\Settings.ini'), $settings)
        [IO.File]::WriteAllText((Join-Path $root 'Config\Nested\notes.txt'), $notes)
        if ($set -eq 'compressed') { [IO.File]::WriteAllBytes((Join-Path $root 'zeros.bin'), [byte[]]::new(200000)) }
    }
    $builds = @(
        @('stored', 'V1', $null), @('stored', 'V2', $null), @('stored', 'V3', $null),
        @('compressed', 'V3', 'Zlib'), @('compressed', 'V4', 'Zlib'), @('compressed', 'V6', 'Zlib'),
        @('compressed', 'V10', 'Zlib'), @('compressed', 'V11', 'Gzip'), @('compressed', 'V11', 'Zstd'), @('compressed', 'V11', 'LZ4')
    )
    foreach ($b in $builds) {
        $set, $version, $method = $b
        $name = "$($version.ToLowerInvariant())$(if ($method) { '-' + $method.ToLowerInvariant() })"
        $packArgs = @('pack', '-q', '--version', $version, '-m', '../../../Fixture/')
        if ($method) { $packArgs += @('--compression', $method) }
        & $pakTool @packArgs (Join-Path $tmp "$set\content") (Join-Path $here "$name.pak")
        if ($LASTEXITCODE -ne 0) { throw "repak exit $LASTEXITCODE for $name" }
    }

    # IoStore: chunk ids 1-3 of type 7 (ExternalFile from TOC version 5, LoaderInitialLoadMeta before); 66,000 zeros
    # span two 64 KiB blocks in the one container that carries them.
    $containers = @(
        @('toc-v2', 'DirectoryIndex', $true, $false), @('toc-v5', 'PerfectHashWithOverflow', $true, $false),
        @('toc-v5-nopaths', 'PerfectHashWithOverflow', $false, $false), @('toc-v8', 'ReplaceIoChunkHashWithIoHash', $true, $true)
    )
    foreach ($c in $containers) {
        $name, $version, $indexed, $large = $c
        $raw = Join-Path $tmp "raw-$name"
        New-Item -ItemType Directory -Force (Join-Path $raw 'chunks') | Out-Null
        [IO.File]::WriteAllText((Join-Path $raw 'chunks\000000000000000100000007'), $settings)
        [IO.File]::WriteAllText((Join-Path $raw 'chunks\000000000000000200000007'), $notes)
        $paths = [ordered]@{
            '000000000000000100000007' = '../../../Fixture/Config/Settings.ini'
            '000000000000000200000007' = '../../../Fixture/Config/Nested/notes.txt'
        }
        if ($large) {
            [IO.File]::WriteAllBytes((Join-Path $raw 'chunks\000000000000000300000007'), [byte[]]::new(66000))
            $paths['000000000000000300000007'] = '../../../Fixture/zeros.bin'
        }
        $manifest = [ordered]@{ chunk_paths = $(if ($indexed) { $paths } else { @{} }); version = $version; mount_point = '../../../' }
        [IO.File]::WriteAllText((Join-Path $raw 'manifest.json'), ($manifest | ConvertTo-Json))
        & $ioTool pack-raw $raw (Join-Path $here "$name.utoc")
        if ($LASTEXITCODE -ne 0) { throw "retoc exit $LASTEXITCODE for $name" }
    }
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
