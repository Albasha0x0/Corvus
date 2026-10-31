using System.Security.Cryptography;
using Corvus.Core;

namespace Corvus.Native.Dump;

/// <summary>A module image written from a dump: its file name, address, size, SHA-256 and the share of its pages the dump held.</summary>
/// <param name="Metadata">The metadata state of a .NET image (readable, partial or unreadable); omitted for a native image.</param>
/// <param name="MetadataReason">Why the metadata is not readable; omitted when it is readable.</param>
public sealed record ExportedModule(string File, string Base, uint Size, string Sha256, int CapturedPercent,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? Metadata = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? MetadataReason = null);

/// <summary>A module left out of the export, with the reason.</summary>
public sealed record SkippedModule(string Name, string Base, string Reason);

/// <summary>The images written to a folder and the modules left out.</summary>
public sealed record ModuleExport(string Folder, IReadOnlyList<ExportedModule> Written, IReadOnlyList<SkippedModule> Skipped);

/// <summary>Writes the module images of a minidump to a folder, rebuilt from the memory the dump captured.</summary>
public static class DumpModuleExport
{
    /// <summary>Largest image written, and most bytes written in all.</summary>
    public const long MaxImageBytes = 128L << 20, MaxTotalBytes = 1L << 30;

    /// <summary>Writes each module of the minidump at <paramref name="dump"/> into <paramref name="folder"/>, a new or empty folder; modules whose headers the dump lacks, or past a size limit, are listed as skipped.</summary>
    /// <remarks>File names are the module's own, made safe under the folder; a name taken by another module, or not a plain file name, gets the module's base address.</remarks>
    public static ModuleExport Write(string dump, string folder, CancellationToken ct)
    {
        using var file = MinidumpFile.Open(dump);
        var root = Path.GetFullPath(folder);
        Directory.CreateDirectory(root);
        var written = new List<ExportedModule>();
        var skipped = new List<SkippedModule>();
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long total = 0;
        foreach (var module in file.Modules)
        {
            ct.ThrowIfCancellationRequested();
            var at = $"0x{module.Base:X}";
            if (module.Size > MaxImageBytes)
            {
                skipped.Add(new SkippedModule(module.FileName, at, $"larger than {MaxImageBytes >> 20} MB"));
                continue;
            }
            var image = DumpImages.FromMemory(file, module, out ulong captured);
            if (image == null)
            {
                skipped.Add(new SkippedModule(module.FileName, at, "the dump does not hold the image headers"));
                continue;
            }
            var bytes = image.FileBytes;
            if (total + bytes.Length > MaxTotalBytes)
            {
                skipped.Add(new SkippedModule(module.FileName, at, $"past the {MaxTotalBytes >> 20} MB total limit"));
                continue;
            }
            var name = NameFor(module, used);
            SafeFile.WriteUnderRoot(root, name, bytes.Span, overwrite: false);
            total += bytes.Length;
            var metadata = DumpManagedMetadata.Inspect(image);
            written.Add(new ExportedModule(name, at, module.Size, Convert.ToHexStringLower(SHA256.HashData(bytes.Span)), (int)(captured * 100 / Math.Max(1u, module.Size)),
                metadata?.State, metadata?.Reason));
        }
        return new ModuleExport(root, written, skipped);
    }

    private static string NameFor(DumpModule module, HashSet<string> used)
    {
        var name = module.FileName;
        if (!InputFiles.IsPlainName(name) || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || name.EndsWith('.') || name.EndsWith(' ')) name = "module.bin";
        if (used.Add(name)) return name;
        var unique = $"{Path.GetFileNameWithoutExtension(name)}-{module.Base:X}{Path.GetExtension(name)}";
        for (int n = 2; !used.Add(unique); n++) unique = $"{Path.GetFileNameWithoutExtension(name)}-{module.Base:X}-{n}{Path.GetExtension(name)}";
        return unique;
    }
}
