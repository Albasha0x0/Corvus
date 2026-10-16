# Rebuilds the cabinet fixtures with makecab (Windows):  pwsh -File build-cab.ps1
# Three files (text, a deterministic mix of repeated text and pseudo-random bytes with E8 call bytes, a zip package) in
# one folder each of stored, MSZIP and LZX:21, and LZX:15 for the smallest window.
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$work = Join-Path ([IO.Path]::GetTempPath()) 'corvus-cab'
if (Test-Path $work) { Remove-Item -Recurse -Force $work }
New-Item -ItemType Directory $work | Out-Null
Set-Content -NoNewline -Path "$work\readme.txt" -Value ('cabinet test file ' * 40)
$rng = [Random]::new(1234)
$mix = [IO.MemoryStream]::new()
for ($i = 0; $i -lt 40; $i++) {
    $text = [Text.Encoding]::ASCII.GetBytes("block $i of mixed content: the quick brown fox jumps over the lazy dog. " * 20)
    $mix.Write($text, 0, $text.Length)
    $noise = [byte[]]::new(600); $rng.NextBytes($noise)
    for ($k = 0; $k -lt $noise.Length; $k += 37) { $noise[$k] = 0xE8 }
    $mix.Write($noise, 0, $noise.Length)
}
[IO.File]::WriteAllBytes("$work\mixed.bin", $mix.ToArray())
Compress-Archive -Path "$work\readme.txt" -DestinationPath "$work\setup.zip"
$kinds = @{ stored = @('off', 'MSZIP', $null); mszip = @('on', 'MSZIP', $null); lzx21 = @('on', 'LZX', 21); lzx15 = @('on', 'LZX', 15) }
foreach ($name in $kinds.Keys) {
    $compress, $type, $memory = $kinds[$name]
    $ddf = [Collections.Generic.List[string]]::new()
    $ddf.Add(".Set CabinetNameTemplate=$name.cab")
    $ddf.Add(".Set DiskDirectoryTemplate=$work")
    $ddf.Add('.Set Cabinet=on')
    $ddf.Add(".Set Compress=$compress")
    $ddf.Add(".Set CompressionType=$type")
    if ($memory) { $ddf.Add(".Set CompressionMemory=$memory") }
    $ddf.Add('.Set MaxDiskSize=0')
    $ddf.Add('.Set UniqueFiles=off')
    $ddf.Add("`"$work\readme.txt`" readme.txt")
    $ddf.Add("`"$work\mixed.bin`" data\mixed.bin")
    $ddf.Add("`"$work\setup.zip`" data\setup.zip")
    Set-Content -Path "$work\$name.ddf" -Value $ddf
    Push-Location $work
    $log = makecab /F "$name.ddf"
    Pop-Location
    if ($LASTEXITCODE -ne 0) { throw "makecab failed: $log" }
    $bytes = [IO.File]::ReadAllBytes((Join-Path $work "$name.cab"))
    $gz = [IO.File]::Create((Join-Path $here "$name.cab.gz"))
    $z = [IO.Compression.GZipStream]::new($gz, [IO.Compression.CompressionLevel]::SmallestSize)
    $z.Write($bytes, 0, $bytes.Length); $z.Dispose(); $gz.Dispose()
}
Remove-Item -Recurse -Force $work
