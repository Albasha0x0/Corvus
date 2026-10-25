# Rebuilds the AutoIt fixtures: ledger.au3 (with notes.txt added by FileInstall) compiled to .a3x by Aut2Exe of AutoIt
# 3.2.4.9 (EA05), 3.2.6.0, 3.3.14.5 and 3.3.18.0 (EA06). CORVUS_AUTOIT_RELEASES is a folder of official releases,
# autoit-<version> each holding Aut2Exe\Aut2exe.exe. With -Executables, x86 and x64 executables are written to -Out
# instead (the reference test compiles them; they are not kept in the repo).
param([switch]$Executables, [string]$Out = $PSScriptRoot, [string[]]$Versions = @('3.2.4.9', '3.2.6.0', '3.3.14.5', '3.3.18.0'))
$ErrorActionPreference = 'Stop'
# pwsh -File passes a list as one comma-separated string.
$Versions = $Versions -split ','
$releases = $env:CORVUS_AUTOIT_RELEASES
if (-not $releases) { throw 'set CORVUS_AUTOIT_RELEASES to the folder of AutoIt releases' }
# The compiler records its input and temporary file paths. A substituted drive with its own temp and profile folders
# keeps those paths free of the build machine's folders.
$work = Join-Path ([IO.Path]::GetTempPath()) "corvus-autoit-$([guid]::NewGuid().ToString('n'))"
New-Item -ItemType Directory -Force (Join-Path $work 'tmp\AppData\Local') | Out-Null
Copy-Item (Join-Path $PSScriptRoot 'ledger.au3'), (Join-Path $PSScriptRoot 'notes.txt') $work
$letter = [char[]](75..90) | Where-Object { -not (Test-Path "$($_):\") } | Select-Object -First 1
subst "$($letter):" $work
try {
    foreach ($v in $Versions) {
        $aut2exe = Get-ChildItem (Join-Path $releases "autoit-$v") -Recurse -Filter 'Aut2exe.exe' | Select-Object -First 1 -ExpandProperty FullName
        $outputs = [Collections.Generic.List[string[]]]::new()
        # Releases before 3.2.10 have no x64 compiler.
        if ($Executables) { $outputs.Add(@("ledger-$v-x86.exe")); if ([version]$v -ge [version]'3.2.10') { $outputs.Add(@("ledger-$v-x64.exe", '/x64')) } }
        else { $outputs.Add(@("ledger-$v.a3x")) }
        foreach ($o in $outputs) {
            $psi = [Diagnostics.ProcessStartInfo]::new($aut2exe)
            foreach ($a in '/in', "$($letter):\ledger.au3", '/out', "$($letter):\$($o[0])", '/nopack') { $psi.ArgumentList.Add($a) }
            if ($o.Length -gt 1) { $psi.ArgumentList.Add($o[1]) }
            $psi.WorkingDirectory = "$($letter):\"
            $psi.UseShellExecute = $false
            $psi.Environment['TEMP'] = $psi.Environment['TMP'] = "$($letter):\tmp"
            # 3.3 writes its temporary files under the local application data folder; 3.2 stops when the profile moves.
            if ([version]$v -ge [version]'3.3') { $psi.Environment['USERPROFILE'] = "$($letter):\tmp" }
            $p = [Diagnostics.Process]::Start($psi)
            if (-not $p.WaitForExit(60000)) { $p.Kill(); throw "Aut2Exe $v did not finish" }
            if (-not (Test-Path "$($letter):\$($o[0])")) { throw "Aut2Exe $v wrote no $($o[0])" }
            Copy-Item "$($letter):\$($o[0])" (Join-Path $Out $o[0]) -Force
        }
    }
}
finally {
    subst "$($letter):" /d
    Remove-Item -Recurse -Force $work
}
