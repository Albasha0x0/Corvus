using System.Buffers.Binary;
using System.Text;
using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>A CPython runtime in a native image: the interpreter section and the Python C API exports.</summary>
internal sealed record EmbeddedPython(string? Section, int Exports, IReadOnlyList<string> Samples)
{
    private const string SectionPrefix = "PyRuntim";
    private const int MinExports = 50;
    private const int MaxExportWindow = 4 << 20;
    private const int MaxExportNames = 1 << 16;

    /// <summary>Bytes of the file head that cover the headers and the section table.</summary>
    public const int HeadSize = 1 << 16;

    /// <summary>True when the section table of a PE head names an interpreter section.</summary>
    public static bool HasSection(byte[] head) =>
        PeImage.TryParse(head) is { } pe && pe.Sections.Any(s => s.Name.StartsWith(SectionPrefix, StringComparison.Ordinal));

    /// <summary>The runtime facts of a whole PE image in memory; null when it has no interpreter section and fewer than 50 Py* exports or is not a PE.</summary>
    public static EmbeddedPython? Of(byte[] image) =>
        Of(image.AsSpan(0, Math.Min(image.Length, HeadSize)).ToArray(), (offset, count) =>
            offset >= image.Length ? [] : image.AsSpan((int)offset, (int)Math.Min(count, image.Length - offset)).ToArray());

    /// <summary>The runtime facts from a file head and a bounded reader at file offsets; null when it has no interpreter section and fewer than 50 Py* exports or is not a PE.</summary>
    public static EmbeddedPython? Of(byte[] head, Func<long, int, byte[]> readAt)
    {
        if (PeImage.TryParse(head) is not { } pe) return null;
        var section = pe.Sections.FirstOrDefault(s => s.Name.StartsWith(SectionPrefix, StringComparison.Ordinal))?.Name;
        var names = ExportNames(pe, head, readAt);
        if (section == null && names.Count < MinExports) return null;
        return new EmbeddedPython(section, names.Count, [.. names.Take(4)]);
    }

    // Reads the export name table from one bounded window of the section that holds it.
    private static List<string> ExportNames(PeImage pe, byte[] head, Func<long, int, byte[]> readAt)
    {
        var (dirRva, dirSize) = pe.Directory(head, 0);
        var home = pe.Sections.FirstOrDefault(s => dirRva >= s.VirtualAddress && dirRva < s.VirtualAddress + Math.Max(s.VirtualSize, s.RawSize));
        if (dirRva == 0 || dirSize < 40 || home == null) return [];
        long windowRva = home.VirtualAddress;
        var window = readAt(home.RawPointer, (int)Math.Min(home.RawSize, MaxExportWindow));
        long At(uint rva) => rva - windowRva;
        var dir = At(dirRva);
        if (dir < 0 || dir + 40 > window.Length) return [];
        uint count = BinaryPrimitives.ReadUInt32LittleEndian(window.AsSpan((int)dir + 24));
        uint table = BinaryPrimitives.ReadUInt32LittleEndian(window.AsSpan((int)dir + 32));
        var result = new List<string>();
        for (uint i = 0; i < Math.Min(count, MaxExportNames); i++)
        {
            long slot = At(table) + i * 4L;
            if (slot < 0 || slot + 4 > window.Length) break;
            long name = At(BinaryPrimitives.ReadUInt32LittleEndian(window.AsSpan((int)slot)));
            if (name < 0 || name >= window.Length) continue;
            int end = Array.IndexOf(window, (byte)0, (int)name);
            if (end < 0 || end - name > 256) continue;
            var text = Encoding.ASCII.GetString(window, (int)name, end - (int)name);
            if (text.StartsWith("Py", StringComparison.Ordinal) || text.StartsWith("_Py", StringComparison.Ordinal)) result.Add(text);
        }
        return result;
    }

    /// <summary>The section and the exports as a short phrase, without the leading label.</summary>
    public string Evidence() =>
        (Section != null ? $"interpreter section {Section}" : "no interpreter section")
        + (Exports > 0 ? $", {Exports:N0} Python C API exports ({string.Join(", ", Samples)}{(Exports > Samples.Count ? ", ..." : "")})" : ", no Python C API exports");

    /// <summary>One sentence naming the runtime, the section and the exports; the runtime is embedded only when the section is present.</summary>
    public string Describe() => (Section != null ? "Embedded CPython runtime: " : "CPython runtime exports: ") + Evidence() + ".";
}

