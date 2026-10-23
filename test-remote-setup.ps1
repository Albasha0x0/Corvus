# Prepares a Windows machine as a test host, from this machine over OpenSSH: the tools pinned in
# tests/Corvus.Tests/Support/remote-tools-assets.json (PowerShell 7, MinGit, Python, the JDK, Ghidra and the reference
# tools the real-data classes compare against) under
# ~/corvus-test-host/tools, Frida's pinned release in that Python, a clone of the repository, the .NET SDK global.json
# names with the runtimes the tests start programs on, and the Visual C++ build tools. Each step keeps what is already
# there, so a second run only fills gaps; -Check changes nothing and names what is missing (exit 1 when anything is).
# The .NET Framework 4.8 Developer Pack and a Microsoft Defender exclusion for the host folder are only named, with the
# command that adds them.
# The host needs OpenSSH Server and this machine's key authorized for an administrator account (the SDK, runtimes and
# build tools install machine-wide). Engine and live permits are the host's own (its temporary folder).
# Usage:  ./test-remote-setup.ps1 -Target user@host [-Check]
#         ./test-remote-setup.ps1 -Target user@host -Data [-Check]  # the real data, under ~/corvus-data there
#         ./test-remote-setup.ps1 -Target user@host -IdaDirectory <folder on the host>  # an IDA Pro 9+ install there
# On the host (run by the above):  powershell -File corvus-test-host\test-remote-setup.ps1 -OnHost -Repository <url> [-Check]
#Requires -Version 5.1
param(
    [string]$Target,
    [switch]$Check,
    [switch]$OnHost,
    [string]$Repository,
    # The host folder; the tests point it elsewhere.
    [string]$Base = (Join-Path $HOME 'corvus-test-host'),
    # Only the pinned tools, the clone and Frida, without touching the user or machine environment (the tests).
    [switch]$ToolsOnly,
    # Copy the folders and files the real-data variables name to the host instead, and set the variables there.
    [switch]$Data,
    # The host's IDA Pro 9+ folder, for CORVUS_IDA_DIR there; IDA is licensed per machine, so setup never installs it.
    [string]$IdaDirectory
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# OpenSSH's option strings: key auth only, no prompt (a new host's key is recorded), and a connect that fails fast.
$sshOptions = @('-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ConnectTimeout=10')
# The .NET runtimes the tests start programs on, beside the SDK's own: x64 and x86 majors.
$runtimesX64 = @(6, 7, 8, 9)
$runtimesX86 = @(8, 9, 10)
# The Visual C++ build tools: the release channel's bootstrapper (signed by Microsoft, checked before it runs) and the
# workload the session tests and NativeAOT builds use.
$buildToolsUrl = 'https://aka.ms/vs/17/release/vs_buildtools.exe'
$buildToolsArguments = @('--quiet', '--wait', '--norestart', '--nocache', '--add', 'Microsoft.VisualStudio.Workload.VCTools', '--includeRecommended')
$buildToolsComponent = 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64'
# The host folder under its user's home that holds the real data (-Data), and the free space a copy must leave there.
$dataFolder = 'corvus-data'
$dataMarginGB = 10
$hostFiles = @('test-remote-setup.ps1', 'tests/Corvus.Tests/Support/fetch-remote-tools.ps1', 'tests/Corvus.Tests/Support/remote-tools-assets.json')

# Runs ssh or scp (or the .ps1 script standing in for it in the tests); returns its output, sets $LASTEXITCODE.
function Invoke-Transport([string]$variable, [string]$program, [string[]]$arguments) {
    $command = [Environment]::GetEnvironmentVariable($variable)
    if (-not $command) { return & $program @arguments }
    & pwsh -NoProfile -File $command @arguments
}

# Runs $script on $target under Windows PowerShell, passed encoded so no shell between reparses it; progress records
# would reach the output as CLIXML.
function Invoke-HostScript([string]$target, [string]$script) {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("`$ProgressPreference = 'SilentlyContinue'`n$script"))
    Invoke-Transport 'CORVUS_TEST_SSH' 'ssh' ($sshOptions + @($target, "powershell -NoProfile -NonInteractive -EncodedCommand $encoded"))
}

# Copies what each real-data variable the host group needs names here (one existing folder or file of inputs, links
# followed; variables that name a program are left out) to ~/corvus-data/<variable>/ on $target and sets the variable there as a user variable. A copy whose recorded size and
# name still match is kept. Refuses when the host's drive would keep under $dataMarginGB free. Returns 0, or 1 when it
# refuses, a copy fails or (with -Check, which changes nothing) anything is left to copy.
function Copy-RealData([string]$target) {
    Import-Module (Join-Path $PSScriptRoot 'test-remote.psm1') -Force
    $items = @(foreach ($name in Get-RealDataVariables (Join-Path $PSScriptRoot 'tests/Corvus.Tests')) {
        $value = [Environment]::GetEnvironmentVariable($name)
        $item = if ($value -and $value -notmatch '[|;]') { Get-Item -LiteralPath $value -Force -ErrorAction SilentlyContinue }
        if (-not $item) { Write-Host "  not copied: $name ($(if ($value) { 'not one existing path here' } else { 'not set here' }))"; continue }
        # Il2CppDumper's DummyDll folder is read with the script.json and string files beside it: its parent travels.
        $from = if ($item.PSIsContainer -and (Test-Path -LiteralPath (Join-Path $item.Parent.FullName 'script.json'))) { $item.Parent } else { $item }
        $leaf = if ($from -ne $item) { "$($from.Name)\$($item.Name)" } else { $item.Name }
        $bytes = if ($from -is [IO.DirectoryInfo]) { [long](Get-ChildItem -LiteralPath $from.FullName -Recurse -File -Force -FollowSymlink | Measure-Object Length -Sum).Sum } else { $from.Length }
        [pscustomobject]@{ Name = $name; Path = $from.FullName; Leaf = $leaf; Bytes = $bytes; Marker = "$bytes $leaf" }
    })
    $tools = @(Get-RealDataVariables (Join-Path $PSScriptRoot 'tests/Corvus.Tests') -Tools)
    if ($tools) { Write-Host "  not copied, programs the host installs itself: $($tools -join ', ')" }
    $names = ($items | ForEach-Object { "'$($_.Name)'" }) -join ','
    $answer = Invoke-HostScript $target @"
`$d = Join-Path `$HOME '$dataFolder'
`$r = @{ Home = `$HOME; Free = (Get-PSDrive `$HOME.Substring(0, 1)).Free; Vars = @{} }
foreach (`$n in @($names)) {
    `$v = [Environment]::GetEnvironmentVariable(`$n, 'User'); `$m = Join-Path `$d "`$n.size"
    `$r.Vars[`$n] = @{ Value = `$v; Exists = [bool](`$v -and (Test-Path -LiteralPath `$v)); Marker = `$(if (Test-Path `$m) { (Get-Content `$m -Raw).Trim() } else { '' }) }
}
`$r | ConvertTo-Json -Compress -Depth 4
"@
    if ($LASTEXITCODE -ne 0) { throw "ssh $target failed (exit $LASTEXITCODE)." }
    $state = ($answer -join '') | ConvertFrom-Json
    $copies = @($items | Where-Object {
        $there = $state.Vars.($_.Name)
        -not ($there.Exists -and $there.Marker -eq $_.Marker -and $there.Value -eq (Join-Path $state.Home "$dataFolder\$($_.Name)\$($_.Leaf)"))
    })
    $need = [long]($copies | Measure-Object Bytes -Sum).Sum
    $kept = $items.Count - $copies.Count
    Write-Host ("Real data: {0} to copy ({1:N1} GB), {2} kept; {3:N1} GB free on {4}." -f $copies.Count, ($need / 1GB), $kept, ($state.Free / 1GB), $target)
    if ($state.Free - $need -lt $dataMarginGB * 1GB) { Write-Host "Refused: the copy would leave under $dataMarginGB GB free on $target." -ForegroundColor Red; return 1 }
    if ($Check) { $copies | ForEach-Object { Write-Host ("  missing: {0} ({1:N0} MB)" -f $_.Name, ($_.Bytes / 1MB)) }; return [int]($copies.Count -gt 0) }
    $failed = 0
    foreach ($copy in $copies) {
        $folder = "$dataFolder\$($copy.Name)"
        $null = Invoke-HostScript $target "`$t = Join-Path `$HOME '$folder'; Remove-Item `$t, (Join-Path `$HOME '$folder.size') -Recurse -Force -ErrorAction SilentlyContinue; New-Item -ItemType Directory -Force `$t | Out-Null"
        $null = Invoke-Transport 'CORVUS_TEST_SCP' 'scp' ($sshOptions + @('-r', '-q', $copy.Path, "${target}:$($folder.Replace('\', '/'))/"))
        if ($LASTEXITCODE -ne 0) { Write-Host "  copy failed: $($copy.Name) (scp exit $LASTEXITCODE)" -ForegroundColor Red; $failed++; continue }
        $leaf = $copy.Leaf.Replace("'", "''")
        $null = Invoke-HostScript $target "[Environment]::SetEnvironmentVariable('$($copy.Name)', (Join-Path `$HOME '$folder\$leaf'), 'User'); Set-Content (Join-Path `$HOME '$folder.size') '$($copy.Marker.Replace("'", "''"))'"
        Write-Host ("- copied {0} ({1:N0} MB)" -f $copy.Name, ($copy.Bytes / 1MB))
    }
    [int]($failed -gt 0)
}

if (-not $OnHost) {
    if (-not $Target) { throw 'Name the host: -Target user@host.' }
    if ($Data) { exit (Copy-RealData $Target) }
    if (-not $Repository) { $Repository = (git -C $PSScriptRoot remote get-url origin).Trim() }
    $null = Invoke-Transport 'CORVUS_TEST_SSH' 'ssh' ($sshOptions + @($Target, 'powershell -NoProfile -Command "New-Item -ItemType Directory -Force corvus-test-host | Out-Null"'))
    if ($LASTEXITCODE -ne 0) { throw "ssh $Target failed (exit $LASTEXITCODE): is OpenSSH Server running there, with this machine's key authorized?" }
    $null = Invoke-Transport 'CORVUS_TEST_SCP' 'scp' ($sshOptions + @($hostFiles | ForEach-Object { Join-Path $PSScriptRoot $_ }) + @("${Target}:corvus-test-host/"))
    if ($LASTEXITCODE -ne 0) { throw "Copying the setup files to $Target failed (exit $LASTEXITCODE)." }
    # The host's default shell splits at spaces and keeps single quotes, so the folder goes in double quotes.
    $idaArgument = if ($IdaDirectory) { ' -IdaDirectory "' + $IdaDirectory + '"' } else { '' }
    Invoke-Transport 'CORVUS_TEST_SSH' 'ssh' ($sshOptions + @($Target, "powershell -NoProfile -ExecutionPolicy Bypass -File corvus-test-host\test-remote-setup.ps1 -OnHost -Repository $Repository$(if ($Check) { ' -Check' })$idaArgument"))
    $code = $LASTEXITCODE
    if ($code -eq 0) { Write-Host "To send whole-suite runs there from this machine: setx CORVUS_TEST_REMOTE $Target" }
    exit $code
}

# On the host, under Windows PowerShell 5.1 or later.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$tools = Join-Path $Base 'tools'
$clone = Join-Path $Base 'repo'
$missing = [Collections.Generic.List[string]]::new()
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
# The host has the support files beside this script; a checkout has them in the test project.
$support = if (Test-Path (Join-Path $PSScriptRoot 'fetch-remote-tools.ps1')) { $PSScriptRoot } else { Join-Path $PSScriptRoot 'tests/Corvus.Tests/Support' }
$fetch = Join-Path $support 'fetch-remote-tools.ps1'
$table = (Get-Content (Join-Path $support 'remote-tools-assets.json') -Raw | ConvertFrom-Json).tools

# Runs $block with native commands' standard error as plain output: under Stop, Windows PowerShell 5.1 turns any line
# a native command writes there into a terminating error. Callers check $LASTEXITCODE.
function Invoke-Native([scriptblock]$block) {
    $ErrorActionPreference = 'Continue'
    & $block
}

function Step([string]$text) { Write-Host "- $text" }
function Need([string]$text) { $missing.Add($text); Write-Host "  missing: $text" }

# Sets a user environment variable (and this process's), unless -ToolsOnly.
function Set-UserVariable([string]$name, [string]$value) {
    [Environment]::SetEnvironmentVariable($name, $value, 'Process')
    if (-not $ToolsOnly) { [Environment]::SetEnvironmentVariable($name, $value, 'User') }
}

# Puts $folders first on this process's PATH and, unless -ToolsOnly, on the user's.
function Add-UserPath([string[]]$folders) {
    $user = @([Environment]::GetEnvironmentVariable('PATH', 'User') -split ';' | Where-Object { $_ })
    $env:PATH = (@($folders) + @($env:PATH -split ';' | Where-Object { $_ -and $_ -notin $folders })) -join ';'
    if (-not $ToolsOnly) { [Environment]::SetEnvironmentVariable('PATH', ((@($folders) + @($user | Where-Object { $_ -notin $folders })) -join ';'), 'User') }
}

# The newest release of a .NET major from Microsoft's release metadata, with its file of $rid and $kind (sdk/runtime).
function Get-DotnetFile([int]$major, [string]$kind, [string]$rid, [string]$version = '') {
    $releases = Invoke-RestMethod "https://builds.dotnet.microsoft.com/dotnet/release-metadata/$major.0/releases.json" -UseBasicParsing
    foreach ($release in $releases.releases) {
        $items = if ($kind -eq 'sdk') { @($release.sdks) } else { @($release.runtime) }
        foreach ($item in $items | Where-Object { $_ -and (-not $version -or $_.version -eq $version) }) {
            # A runtime's files also hold its apphost pack; only dotnet-<kind>-<rid>.zip is the runtime or SDK itself.
            $file = $item.files | Where-Object { $_.name -eq "dotnet-$kind-$rid.zip" } | Select-Object -First 1
            if ($file) { return [pscustomobject]@{ Version = $item.version; Url = $file.url; Hash = $file.hash } }
        }
    }
    throw ".NET $major $kind $version for $rid is not in the release metadata."
}

# Extracts a .NET zip over $root after checking its SHA-512 against the release metadata.
function Install-DotnetFile($file, [string]$root) {
    $zip = Join-Path $env:TEMP "corvus-dotnet-$([guid]::NewGuid().ToString('N')).zip"
    try {
        Invoke-WebRequest $file.Url -OutFile $zip -UseBasicParsing
        $sha = (Get-FileHash $zip -Algorithm SHA512).Hash
        if ($sha -ne $file.Hash) { throw "$($file.Url): SHA-512 $sha, expected $($file.Hash)" }
        New-Item -ItemType Directory -Force $root | Out-Null
        Expand-Archive $zip -DestinationPath $root -Force
    }
    finally { Remove-Item $zip -Force -ErrorAction SilentlyContinue }
}

# The majors of $root's shared .NET runtimes.
function Get-RuntimeMajors([string]$root) {
    @(Get-ChildItem (Join-Path $root 'shared\Microsoft.NETCore.App') -Directory -ErrorAction SilentlyContinue | ForEach-Object { [int]($_.Name -split '\.')[0] })
}

Write-Host "Test host $env:COMPUTERNAME ($env:USERNAME), folder $Base$(if ($Check) { ', check only' })"
if (-not $admin) { Need 'an administrator account (the SDK, runtimes and build tools install machine-wide)' }

Step 'Pinned tools'
if ($Check) { & $fetch -Destination $tools -Check | ForEach-Object { Need ($_ -replace '^missing ', '') } }
else {
    foreach ($line in & $fetch -Destination $tools) { $name, $value = $line -split '=', 2; Set-UserVariable $name $value }
}
$paths = @($table | Where-Object { $_.bin } | ForEach-Object { Join-Path (Join-Path $tools $_.folder) $_.bin })
$python = Join-Path $tools "$(($table | Where-Object name -eq 'python').folder)\tools\python.exe"
if (-not $Check) { Add-UserPath ($paths + @(Split-Path $python | Join-Path -ChildPath 'Scripts')) }
$git = Join-Path $tools "$(($table | Where-Object name -eq 'git').folder)\cmd\git.exe"

Step "Repository clone ($clone)"
if (Test-Path (Join-Path $clone '.git')) {
    if (-not $Check) { Invoke-Native { & $git -C $clone fetch --quiet origin 2>&1 | Out-Host }; if ($LASTEXITCODE -ne 0) { throw 'git fetch failed.' } }
}
elseif ($Check) { Need "the clone of $Repository" }
else {
    Invoke-Native { & $git clone --quiet -c core.longpaths=true $Repository $clone 2>&1 | Out-Host }
    if ($LASTEXITCODE -ne 0) { throw "Cloning $Repository failed." }
}

Step 'Frida'
# The release and wheel hash the server pins (FridaVersions.cs), so the host runs what the live tests are written against.
$versions = Join-Path $clone 'src\Corvus\Native\Providers\Live\FridaVersions.cs'
if (-not (Test-Path $versions)) { if ($Check) { Need 'frida (its pinned release comes with the clone)' } else { throw "The clone has no $versions." } }
else {
    $source = Get-Content $versions -Raw
    $pinned = [regex]::Match($source, 'Pinned = "([^"]+)"').Groups[1].Value
    $hash = [regex]::Match($source, '\["windows-x64"\] = \["([0-9a-f]{64})"').Groups[1].Value
    $have = if (Test-Path $python) { Invoke-Native { & $python -c "import importlib.metadata as m; print(m.version('frida'))" 2>$null } } else { $null }
    if ($have -ne $pinned) {
        if ($Check) { Need "frida $pinned in $python$(if ($have) { " (has $have)" })" }
        else {
            Invoke-Native { & $python -m ensurepip --upgrade 2>&1 | Out-Null }
            $requirements = Join-Path $Base 'frida-requirements.txt'
            Set-Content $requirements "frida==$pinned --hash=sha256:$hash" -Encoding ASCII
            Invoke-Native { & $python -m pip install --disable-pip-version-check --no-warn-script-location --require-hashes -r $requirements 2>&1 | Out-Host }
            if ($LASTEXITCODE -ne 0) { throw "Installing frida $pinned failed." }
        }
    }
    if (-not $Check) { Set-UserVariable 'CORVUS_FRIDA_PYTHON' $python }
}

if ($ToolsOnly) { Write-Host "`nTools only: $($missing.Count) missing."; exit ([int]($missing.Count -gt 0)) }

Step '.NET SDK and runtimes'
$x64 = Join-Path $env:ProgramFiles 'dotnet'
$x86 = Join-Path ${env:ProgramFiles(x86)} 'dotnet'
$globalJson = Join-Path $clone 'global.json'
if (Test-Path $globalJson) {
    $sdk = (Get-Content $globalJson -Raw | ConvertFrom-Json).sdk.version
    $band = $sdk.Substring(0, $sdk.LastIndexOf('.') + 2)
    $sdks = @(Get-ChildItem (Join-Path $x64 'sdk') -Directory -ErrorAction SilentlyContinue | ForEach-Object Name)
    if (-not ($sdks | Where-Object { $_.StartsWith($band) -and [version]$_ -ge [version]$sdk })) {
        if ($Check -or -not $admin) { Need ".NET SDK $sdk in $x64" }
        else { Install-DotnetFile (Get-DotnetFile ([int]$sdk.Split('.')[0]) 'sdk' 'win-x64' $sdk) $x64 }
    }
}
elseif ($Check) { Need '.NET SDK (global.json comes with the clone)' }
foreach ($pair in @(@($x64, 'win-x64', $runtimesX64), @($x86, 'win-x86', $runtimesX86))) {
    $root, $rid, $majors = $pair
    $have = Get-RuntimeMajors $root
    foreach ($major in $majors | Where-Object { $_ -notin $have }) {
        if ($Check -or -not $admin) { Need ".NET $major runtime ($rid) in $root" }
        else {
            Install-DotnetFile (Get-DotnetFile $major 'runtime' $rid) $root
            if ($major -notin (Get-RuntimeMajors $root)) { throw ".NET $major runtime ($rid) is still not in $root after its install." }
        }
    }
}
# An apphost finds the runtime through DOTNET_ROOT (DOTNET_ROOT(x86) in a 32-bit one), then the installer's
# InstallLocation key (32-bit registry view); a zip install writes neither, and a program started with a reduced
# environment then has no fallback.
foreach ($pair in @(@($x64, 'x64', 'DOTNET_ROOT'), @($x86, 'x86', 'DOTNET_ROOT(x86)'))) {
    $root, $arch, $variable = $pair
    if ([Environment]::GetEnvironmentVariable($variable, 'User') -ne $root) {
        if ($Check) { Need "$variable set to $root" } else { Set-UserVariable $variable $root }
    }
    $key = "HKLM:\SOFTWARE\WOW6432Node\dotnet\Setup\InstalledVersions\$arch"
    if ((Get-ItemProperty $key -Name InstallLocation -ErrorAction SilentlyContinue).InstallLocation -eq "$root\") { continue }
    if ($Check -or -not $admin) { Need "the .NET install location ($arch) registered as the installer does" }
    else { New-Item $key -Force | Out-Null; Set-ItemProperty $key -Name InstallLocation -Value "$root\" }
}
if (-not $Check -and $admin) {
    $machine = [Environment]::GetEnvironmentVariable('PATH', 'Machine')
    if (($machine -split ';') -notcontains $x64) { [Environment]::SetEnvironmentVariable('PATH', "$x64;$machine", 'Machine') }
    if (($env:PATH -split ';') -notcontains $x64) { $env:PATH = "$x64;$env:PATH" }
}

Step 'IDA'
# The folder given, else the one CORVUS_IDA_DIR or IDA's own ida-config.json names; a host without IDA leaves the IDA
# classes to the machine that has it.
$ida = if ($IdaDirectory) { $IdaDirectory } else { [Environment]::GetEnvironmentVariable('CORVUS_IDA_DIR', 'User') }
if (-not $ida) {
    $config = Join-Path $env:APPDATA 'Hex-Rays\IDA Pro\ida-config.json'
    if (Test-Path $config) { $ida = (Get-Content $config -Raw | ConvertFrom-Json).Paths.'ida-install-dir' }
}
if (-not $ida) { Write-Host '  none: the IDA classes stay on the machine that has IDA' }
elseif (-not ((Test-Path (Join-Path $ida 'idalib.dll')) -and (Test-Path (Join-Path $ida 'idalib\python\idapro\__init__.py')))) { Need "idalib in $ida (IDA Pro 9 or newer)" }
elseif ($Check) { Write-Host "  $ida" }
else { Set-UserVariable 'CORVUS_IDA_DIR' $ida; Write-Host "  CORVUS_IDA_DIR = $ida" }

Step 'Visual C++ build tools'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$found = if (Test-Path $vswhere) { & $vswhere -products * -requires $buildToolsComponent -property installationPath } else { $null }
if (-not $found) {
    if ($Check -or -not $admin) { Need "Visual C++ build tools ($buildToolsComponent)" }
    else {
        $installer = Join-Path $env:TEMP 'corvus-vs_buildtools.exe'
        Invoke-WebRequest $buildToolsUrl -OutFile $installer -UseBasicParsing
        $signature = Get-AuthenticodeSignature $installer
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw "The build tools installer is not signed by Microsoft ($($signature.Status))." }
        $process = Start-Process $installer -ArgumentList $buildToolsArguments -Wait -PassThru
        # 3010: installed, a restart pending.
        if ($process.ExitCode -notin 0, 3010) { throw "The build tools installer exited with $($process.ExitCode)." }
        if ($process.ExitCode -eq 3010) { Write-Host '  installed; restart the host before the first test run' }
    }
}

# The next two change the machine beyond the test folder, so setup only names them with the command that does it.
Step '.NET Framework 4.8 reference assemblies'
$framework48 = Join-Path ${env:ProgramFiles(x86)} 'Reference Assemblies\Microsoft\Framework\.NETFramework\v4.8\mscorlib.dll'
if (-not (Test-Path $framework48)) { Need '.NET Framework 4.8 Developer Pack; as administrator: winget install --id Microsoft.DotNet.Framework.DeveloperPack_4 --version 4.8 --exact' }

Step 'Microsoft Defender exclusion'
# Defender quarantines some of the benign script fixtures under $Base.
$defender = if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) { try { Get-MpComputerStatus } catch { $null } }
$exclusions = if ($defender) { @((Get-MpPreference).ExclusionPath | Where-Object { $_ }) } else { @() }
$excluded = $exclusions | Where-Object { $_ -notmatch '^N/A' -and "$($Base.TrimEnd('\'))\".StartsWith("$($_.TrimEnd('\'))\",[StringComparison]::OrdinalIgnoreCase) }
if (-not $defender) { Write-Host '  unknown: Defender reported no status' }
elseif ($excluded) { Write-Host "  excluded ($($excluded | Select-Object -First 1))" }
elseif ($exclusions -match '^N/A') { Write-Host "  unknown: the exclusions need an administrator to read; as administrator: Add-MpPreference -ExclusionPath '$Base'" }
elseif (-not $defender.RealTimeProtectionEnabled) { Write-Host "  real-time protection off; once it is on, as administrator: Add-MpPreference -ExclusionPath '$Base'" }
else { Need "a Defender exclusion for $Base; as administrator: Add-MpPreference -ExclusionPath '$Base'" }

Write-Host ''
if ($missing.Count) { Write-Host "Not ready: $($missing.Count) missing."; exit 1 }
Write-Host 'Ready.'
exit 0
