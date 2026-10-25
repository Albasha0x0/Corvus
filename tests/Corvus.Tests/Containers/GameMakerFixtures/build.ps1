# Rebuilds the GameMaker data file fixtures with the data file CLI (CORVUS_GAMEMAKER_TOOL: UndertaleModCli.exe,
# 0.9.2.0 tested): a blank data file, then features.csx adds code, an object, a 4x4 PNG texture page and an 8 kHz WAV
# sound. One file per bytecode version 14-17.
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$tool = $env:CORVUS_GAMEMAKER_TOOL
if (-not $tool) { throw 'set CORVUS_GAMEMAKER_TOOL to UndertaleModCli.exe' }
$tmp = Join-Path ([IO.Path]::GetTempPath()) "corvus-gamemaker-$PID"
New-Item -ItemType Directory -Force $tmp | Out-Null
try {
    # 4x4 RGBA PNG: rows of filter byte 0 and pixels, zlib-compressed into one IDAT chunk.
    $rows = [Collections.Generic.List[byte]]::new()
    foreach ($y in 0..3) { $rows.Add(0); foreach ($x in 0..3) { $rows.AddRange([byte[]]@(($x * 40), ($y * 60), 128, 255)) } }
    $z = [IO.MemoryStream]::new()
    $zs = [IO.Compression.ZLibStream]::new($z, [IO.Compression.CompressionLevel]::Optimal)
    $zs.Write($rows.ToArray(), 0, $rows.Count); $zs.Dispose()
    function Crc32([byte[]]$data) {
        $c = 0xFFFFFFFFu
        foreach ($b in $data) { $c = $c -bxor $b; foreach ($k in 1..8) { $c = if ($c -band 1) { 0xEDB88320u -bxor ($c -shr 1) } else { $c -shr 1 } } }
        return [uint32]($c -bxor 0xFFFFFFFFu)
    }
    function BigEndian([uint32]$v) { return [byte[]]((($v -shr 24) -band 255), (($v -shr 16) -band 255), (($v -shr 8) -band 255), ($v -band 255)) }
    function Chunk([string]$type, [byte[]]$data) {
        $body = [byte[]]([Text.Encoding]::ASCII.GetBytes($type) + $data)
        return [byte[]]((BigEndian $data.Length) + $body + (BigEndian (Crc32 $body)))
    }
    # IHDR: width 4, height 4, bit depth 8, colour type 6 (RGBA).
    $ihdr = [byte[]](0, 0, 0, 4, 0, 0, 0, 4, 8, 6, 0, 0, 0)
    $png = [byte[]](0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A) + (Chunk 'IHDR' $ihdr) + (Chunk 'IDAT' $z.ToArray()) + (Chunk 'IEND' ([byte[]]@()))
    [IO.File]::WriteAllBytes((Join-Path $tmp 'page.png'), $png)
    # 800 samples of 8-bit mono PCM at 8 kHz.
    $samples = [byte[]](0..799 | ForEach-Object { ($_ * 7) % 256 })
    $wav = [IO.MemoryStream]::new(); $w = [IO.BinaryWriter]::new($wav)
    $w.Write([Text.Encoding]::ASCII.GetBytes('RIFF')); $w.Write([int](36 + $samples.Length)); $w.Write([Text.Encoding]::ASCII.GetBytes('WAVEfmt '))
    $w.Write([int]16); $w.Write([int16]1); $w.Write([int16]1); $w.Write([int]8000); $w.Write([int]8000); $w.Write([int16]1); $w.Write([int16]8)
    $w.Write([Text.Encoding]::ASCII.GetBytes('data')); $w.Write([int]$samples.Length); $w.Write($samples); $w.Flush()
    [IO.File]::WriteAllBytes((Join-Path $tmp 'tone.wav'), $wav.ToArray())

    $blank = Join-Path $tmp 'blank.win'
    & $tool new -o $blank -f | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "new: exit $LASTEXITCODE" }
    $env:FIXTURE_INPUT = $tmp
    foreach ($v in 14..17) {
        $env:FIXTURE_BYTECODE = "$v"
        $out = Join-Path $here "bytecode-$v.win"
        # The CLI waits for a key after a script error; closed input ends it.
        $null | & $tool load $blank -s (Join-Path $here 'features.csx') -o $out -f | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $out)) { throw "bytecode $v`: exit $LASTEXITCODE" }
    }
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    Remove-Item env:FIXTURE_INPUT, env:FIXTURE_BYTECODE -ErrorAction SilentlyContinue
}
