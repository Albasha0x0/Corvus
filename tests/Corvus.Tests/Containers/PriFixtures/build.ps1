# Rebuilds notes.pri from the notes folder and writes MakePri's detailed dump of it, notes.pri.xml, which PriFileTests
# compares the reader with. CORVUS_MAKEPRI is MakePri.exe from the Windows SDK (10.0.19041.0 x64 built these).
$ErrorActionPreference = 'Stop'
$makepri = $env:CORVUS_MAKEPRI
if (-not $makepri) { throw 'set CORVUS_MAKEPRI to MakePri.exe' }
# MakePri resolves the project and config paths from the current folder.
Push-Location $PSScriptRoot
try {
    & $makepri new /pr notes /cf priconfig.xml /of notes.pri /in SampleNotes /o | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "makepri new exit $LASTEXITCODE" }
    & $makepri dump /if notes.pri /of notes.pri.xml /dt detailed /o | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "makepri dump exit $LASTEXITCODE" }
}
finally { Pop-Location }
