# Builds a framework-dependent release into ./publish (requires the .NET 10 runtime on the target machine).
# Usage:  ./publish.ps1            -> ./publish/NetDecompilerMcp.exe
#         ./publish.ps1 -SelfContained   -> single-folder build that does not need .NET installed
param([switch]$SelfContained)

$ErrorActionPreference = 'Stop'
$out = Join-Path $PSScriptRoot 'publish'
$project = Join-Path $PSScriptRoot 'src/NetDecompilerMcp/NetDecompilerMcp.csproj'

$publishArgs = @('publish', $project, '-c', 'Release', '-o', $out, '-r', 'win-x64', '--nologo')
if ($SelfContained) { $publishArgs += @('--self-contained', 'true') } else { $publishArgs += @('--self-contained', 'false') }

dotnet @publishArgs
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed" }
Write-Host "Published to $out"
