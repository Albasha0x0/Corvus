# Rebuilds the optical disc fixtures with the Windows image mastering API (IMAPI2FS), on Windows only:
#   pwsh -File build.ps1
# Each image holds a text file, a nested folder with a long-named file and a small zip package, one per file system
# choice: ISO 9660 only, ISO 9660 + Joliet, and UDF 1.02 only. The images are stored gzip-compressed.
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$tree = Join-Path ([IO.Path]::GetTempPath()) 'corvus-iso-tree'
if (Test-Path $tree) { Remove-Item -Recurse -Force $tree }
New-Item -ItemType Directory -Force (Join-Path $tree 'docs/a folder with a long name') | Out-Null
Set-Content -NoNewline -Path (Join-Path $tree 'readme.txt') -Value 'hello from the disc'
Set-Content -NoNewline -Path (Join-Path $tree 'docs/a folder with a long name/Quarterly Report (final).txt') -Value 'nested file'
Compress-Archive -Path (Join-Path $tree 'readme.txt') -DestinationPath (Join-Path $tree 'docs/setup.zip')

# the result image is a COM IStream: read in C#, where the cast is a QueryInterface
Add-Type -TypeDefinition @'
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices.ComTypes;
public static class ImageSaver
{
    public static void Save(object image, long size, string path)
    {
        var stream = (IStream)image;
        var bytes = new byte[size];
        stream.Read(bytes, (int)size, System.IntPtr.Zero);
        using var file = File.Create(path);
        using var gzip = new GZipStream(file, CompressionLevel.SmallestSize);
        gzip.Write(bytes, 0, bytes.Length);
    }
}
'@

function Write-Image([int]$systems, [string]$name) {
    $image = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
    $image.FileSystemsToCreate = $systems
    $image.VolumeName = 'CORVUS'
    $image.Root.AddTree($tree, $false)
    $result = $image.CreateResultImage()
    [ImageSaver]::Save($result.ImageStream, [long]$result.TotalBlocks * $result.BlockSize, (Join-Path $here "$name.iso.gz"))
}
Write-Image 1 'iso9660'
Write-Image 3 'joliet'
Write-Image 4 'udf'
Remove-Item -Recurse -Force $tree
