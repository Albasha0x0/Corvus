using System.IO.Compression;
using System.Text.Json;
using Corvus.Native.Elf;

namespace Corvus.Native;

/// <summary>A crate of a cargo-auditable dependency list: kind is "runtime" or "build"; dependencies index the package list.</summary>
public sealed record RustPackage(string Name, string Version, string Source, string Kind, bool Root, IReadOnlyList<int> Dependencies);

/// <summary>
/// The dependency list cargo-auditable embeds in a Rust binary: section .dep-v0 (ELF, PE) or __DATA,.dep-v0 (Mach-O),
/// zlib-compressed JSON {"packages":[{name, version, source, kind, dependencies, root}]}. Decompression is bounded.
/// </summary>
public sealed class RustAudit
{
    public const int MaxCompressed = 4 << 20, MaxJson = 16 << 20, MaxPackages = 20_000;

    public List<RustPackage> Packages { get; } = [];
    public List<string> Issues { get; } = [];
    public string Section { get; private init; } = "";
    public int CompressedSize { get; private init; }

    /// <summary>The image's dependency list, or null when it has no .dep-v0 section.</summary>
    public static RustAudit? Of(INativeImage image, ReadOnlySpan<byte> file)
    {
        byte[]? data = null;
        string name = "";
        if (image.Sections.FirstOrDefault(s => s.Name is ".dep-v0" or "__DATA,.dep-v0" or "__DATA_CONST,.dep-v0") is { } s)
        {
            name = s.Name;
            int size = (int)Math.Min(s.MappedSize, MaxCompressed);
            var buffer = new byte[size];
            data = buffer.AsSpan(0, image.Read(s.Rva, buffer)).ToArray();
        }
        else if (image is ElfFile elf && elf.SectionHeaders.FirstOrDefault(h => h.Name == ".dep-v0" && h.Type != 8) is { } h && h.Offset < (ulong)file.Length)
        {
            name = h.Name;
            data = file.Slice((int)h.Offset, (int)Math.Min(Math.Min(h.Size, (ulong)file.Length - h.Offset), MaxCompressed)).ToArray();
        }
        return data == null ? null : Parse(data, name);
    }

    /// <summary>Inflates and reads one section's bytes; a malformed list gives issues, never an exception.</summary>
    public static RustAudit Parse(byte[] compressed, string section = ".dep-v0")
    {
        var audit = new RustAudit { Section = section, CompressedSize = compressed.Length };
        byte[] json;
        try
        {
            using var z = new ZLibStream(new MemoryStream(compressed, writable: false), CompressionMode.Decompress);
            var buffer = new MemoryStream();
            var chunk = new byte[81920];
            int n;
            while ((n = z.Read(chunk)) > 0)
            {
                if (buffer.Length + n > MaxJson) { audit.Issues.Add($"decompressed list exceeds {MaxJson >> 20} MB; not read"); return audit; }
                buffer.Write(chunk, 0, n);
            }
            json = buffer.ToArray();
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException) { audit.Issues.Add($"not zlib data: {ex.Message}"); return audit; }
        try
        {
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 16 });
            if (doc.RootElement.ValueKind != JsonValueKind.Object || !doc.RootElement.TryGetProperty("packages", out var packages) || packages.ValueKind != JsonValueKind.Array)
            {
                audit.Issues.Add("no packages array");
                return audit;
            }
            foreach (var p in packages.EnumerateArray())
            {
                if (audit.Packages.Count >= MaxPackages) { audit.Issues.Add($"packages: the first {MaxPackages:N0} read"); break; }
                if (p.ValueKind != JsonValueKind.Object) continue;
                var deps = new List<int>();
                if (p.TryGetProperty("dependencies", out var d) && d.ValueKind == JsonValueKind.Array)
                    foreach (var i in d.EnumerateArray())
                        if (i.TryGetInt32(out int index) && index >= 0) deps.Add(index);
                audit.Packages.Add(new RustPackage(Text(p, "name"), Text(p, "version"), Text(p, "source"), Text(p, "kind") is { Length: > 0 } k ? k : "runtime",
                    p.TryGetProperty("root", out var root) && root.ValueKind == JsonValueKind.True, deps));
            }
        }
        catch (JsonException ex) { audit.Issues.Add($"malformed JSON: {ex.Message}"); }
        int count = audit.Packages.Count;
        if (audit.Packages.Any(p => p.Dependencies.Any(i => i >= count))) audit.Issues.Add("a dependency index is past the package list");
        return audit;
    }

    private static string Text(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
}
