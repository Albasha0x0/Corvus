# Regenerates powershell/*.ps1: one benign command transformed by Invoke-Obfuscation (github.com/danielbohannon/Invoke-Obfuscation,
# commit f20e7f8), three samples per technique (token, string concatenation / reorder / reverse, ASCII / hex / octal / binary /
# SecureString / BXOR / whitespace / special-character encodings, compression). Run under Windows PowerShell 5.1.
# CORVUS_FIXTURE_POWERSHELL_LAYERS: the folder holding Invoke-Obfuscation.psd1. The outputs are text only; nothing runs them.
$ErrorActionPreference = 'Stop'
$module = Join-Path $env:CORVUS_FIXTURE_POWERSHELL_LAYERS 'Invoke-Obfuscation.psd1'
if (-not (Test-Path $module)) { throw 'set CORVUS_FIXTURE_POWERSHELL_LAYERS to the Invoke-Obfuscation folder' }
Import-Module $module -Force
$out = Join-Path $PSScriptRoot 'powershell'
New-Item -ItemType Directory -Force $out | Out-Null
$sb = [ScriptBlock]::Create("`$u = 'http://api.example.com/v1/notes.txt'; `$wc = New-Object Net.WebClient; Write-Host 'corvus marker'; Write-Output `$u")
$cases = @(
    @{ n = 'token-all'; f = { Out-ObfuscatedTokenCommand -ScriptBlock $sb } },
    @{ n = 'string-concat'; f = { Out-ObfuscatedStringCommand -ScriptBlock $sb 1 } },
    @{ n = 'string-reorder'; f = { Out-ObfuscatedStringCommand -ScriptBlock $sb 2 } },
    @{ n = 'string-reverse'; f = { Out-ObfuscatedStringCommand -ScriptBlock $sb 3 } },
    @{ n = 'encoding-ascii'; f = { Out-EncodedAsciiCommand -ScriptBlock $sb -PassThru } },
    @{ n = 'encoding-hex'; f = { Out-EncodedHexCommand -ScriptBlock $sb -PassThru } },
    @{ n = 'encoding-octal'; f = { Out-EncodedOctalCommand -ScriptBlock $sb -PassThru } },
    @{ n = 'encoding-binary'; f = { Out-EncodedBinaryCommand -ScriptBlock $sb -PassThru } },
    @{ n = 'encoding-securestring'; f = { Out-SecureStringCommand -ScriptBlock $sb -PassThru } },
    @{ n = 'encoding-bxor'; f = { Out-EncodedBXORCommand -ScriptBlock $sb -PassThru } },
    @{ n = 'encoding-whitespace'; f = { Out-EncodedWhitespaceCommand -ScriptBlock $sb -PassThru } },
    @{ n = 'encoding-specialchar'; f = { Out-EncodedSpecialCharOnlyCommand -ScriptBlock $sb -PassThru } },
    @{ n = 'compress'; f = { Out-CompressedCommand -ScriptBlock $sb -PassThru } }
)
foreach ($c in $cases) {
    foreach ($i in 1..3) { Set-Content -Path (Join-Path $out "$($c.n)-$i.ps1") -Value (& $c.f) -Encoding UTF8 }
}
# launchers/*.cmd: the command lines of Out-PowerShellLauncher's twelve launch types (cmd, wmic, rundll32, environment
# variables, stdin, clipboard, mshta) around a second benign command; read as command lines, not batch files.
$launchers = Join-Path $PSScriptRoot 'launchers'
New-Item -ItemType Directory -Force $launchers | Out-Null
$sb = [ScriptBlock]::Create("Write-Host 'corvus marker'; `$u = 'http://api.example.com/v1/notes.txt'")
foreach ($n in 1..12) {
    $r = Out-PowerShellLauncher -ScriptBlock $sb -LaunchType $n -NoProfile -NonInteractive -WindowStyle Hidden
    Set-Content -Path (Join-Path $launchers ('launcher-{0:00}.cmd' -f $n)) -Value $r -Encoding UTF8
}
