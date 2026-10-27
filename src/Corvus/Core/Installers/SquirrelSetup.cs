using System.Text;

namespace Corvus.Core.Installers;

/// <summary>Squirrel.Windows Setup.exe: the release zip in resource DATA/131, read as the zip reader reads it.</summary>
internal sealed class SquirrelSetupReader : IContainerReader
{
    private const string ResourceType = "DATA";
    private const uint ResourceId = 131;
    /// <summary>The stub's resource directory is looked for in this many leading bytes (the stream path's head).</summary>
    private const int HeadBytes = 1 << 20;

    public string Kind => "squirrel";

    public bool Accepts(ReadOnlySpan<byte> data, string name)
    {
        var head = data[..Math.Min(data.Length, HeadBytes)].ToArray();
        return PeImage.TryParse(head) is { } pe && !pe.IsDotNet(head) && InstallerPe.Resource(pe, head, InstallerPe.Of(head), ResourceType, ResourceId) != null;
    }

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Open(new MemoryStream(data, writable: false), name, allFiles, limits, ct)!;

    public ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var read = InstallerPe.Of(stream);
        var head = read(0, (int)Math.Min(stream.Length, HeadBytes))!;
        var pe = PeImage.TryParse(head) ?? throw new ToolError(ErrorCode.MalformedInput, $"{name}: not a PE image.");
        var (offset, size) = InstallerPe.Resource(pe, head, read, ResourceType, ResourceId)
            ?? throw new ToolError(ErrorCode.MalformedInput, $"{name}: no Squirrel release resource ({ResourceType}/{ResourceId}).");
        if (size > limits.MaxItemBytes) throw new ToolError(ErrorCode.LimitExceeded, $"{name}: the release zip is {size:N0} bytes, over the {limits.MaxItemBytes:N0}-byte item limit.");
        var zip = read(offset, size) ?? throw new ToolError(ErrorCode.MalformedInput, $"{name}: the release resource runs past the end of the file.");
        var inner = Containers.Open(zip, "Setup.zip", limits, ct, allFiles: allFiles);
        var notes = new List<string> { $"Squirrel Setup.exe: release zip of {size:N0} bytes in resource {ResourceType}/{ResourceId}." };
        notes.AddRange(Releases(zip));
        notes.AddRange(inner.Notes);
        return new ContainerContents("Squirrel installer", inner.Items, notes) { Entries = inner.Entries };
    }

    /// <summary>The RELEASES lines ("SHA1 file size") as notes; none from a zip too damaged to read it.</summary>
    private static List<string> Releases(byte[] zip)
    {
        var notes = new List<string>();
        try
        {
            using var archive = new System.IO.Compression.ZipArchive(new MemoryStream(zip, writable: false));
            if (archive.GetEntry("RELEASES") is not { Length: < 1 << 20 } entry) return notes;
            using var reader = new StreamReader(entry.Open(), Encoding.UTF8);
            while (reader.ReadLine() is { } line)
                if (line.Split(' ', StringSplitOptions.RemoveEmptyEntries) is [{ Length: 40 } sha, var file, var length] && long.TryParse(length, out var bytes))
                    notes.Add($"Release {file}: {bytes:N0} bytes, SHA-1 {sha.ToLowerInvariant()}.");
        }
        catch (InvalidDataException) { }
        return notes;
    }
}
