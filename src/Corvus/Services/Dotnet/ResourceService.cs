using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Resources;
using Corvus.Core;

namespace Corvus.Services;

/// <summary>Lists and extracts manifest resources, including entries inside .resources containers.</summary>
public sealed class ResourceService
{
    /// <param name="FileOffset">Where the data starts in the file as loaded (absent once edits rewrote the image).</param>
    public sealed record ResourceInfo(string Name, string Kind, long? Size, bool IsPublic, int? EntryCount, long? FileOffset = null, string? Sha256 = null);

    public List<ResourceInfo> List(LoadedAssembly asm)
    {
        var list = new List<ResourceInfo>();
        long? directory = null;
        if (!asm.IsDirty && asm.Module.Metadata.ImageCor20Header.Resources is { VirtualAddress: var rva, Size: > 0 } && rva != 0)
            directory = (long)asm.Module.Metadata.PEImage.ToFileOffset(rva);
        foreach (var r in asm.Module.Resources)
        {
            switch (r)
            {
                case EmbeddedResource er:
                    int? entries = null;
                    if (er.Name.String.EndsWith(".resources", StringComparison.OrdinalIgnoreCase))
                        entries = TryReadSet(asm, er)?.ResourceElements.Count();
                    // Each entry is a 4-byte length, then the data.
                    list.Add(new ResourceInfo(er.Name, "embedded", er.Length, r.IsPublic, entries, directory + er.Offset + 4,
                        Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(er.CreateReader().ToArray()))));
                    break;
                case LinkedResource lr:
                    list.Add(new ResourceInfo(lr.Name, $"linked file '{lr.File?.Name}'", null, r.IsPublic, null));
                    break;
                case AssemblyLinkedResource al:
                    list.Add(new ResourceInfo(al.Name, $"in assembly '{al.Assembly?.FullName}'", null, r.IsPublic, null));
                    break;
            }
        }
        return list;
    }

    /// <summary>
    /// Returns a text rendering of a resource (or one entry of a .resources container) and,
    /// when <paramref name="outputPath"/> is set, writes the raw bytes there.
    /// </summary>
    public string Get(LoadedAssembly asm, string name, string? entry, string? outputPath, int previewBytes = 4096, Func<byte[], string?>? baml = null,
        bool overwrite = false)
    {
        var res = asm.Module.Resources.FirstOrDefault(r => r.Name == name)
                  ?? asm.Module.Resources.FirstOrDefault(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase))
                  ?? throw new ToolError(ErrorCode.NotFound, $"Resource '{name}' not found in {asm.Id}. Available: {string.Join(", ", asm.Module.Resources.Select(r => r.Name.String))}");
        if (res is not EmbeddedResource er)
            throw new ToolError(ErrorCode.Unsupported, $"Resource '{name}' is not embedded ({res.ResourceType}); it lives outside this assembly.");

        byte[] data = er.CreateReader().ToArray();
        var set = name.EndsWith(".resources", StringComparison.OrdinalIgnoreCase) ? TryReadSet(asm, er) : null;

        if (set != null && entry == null)
        {
            if (outputPath != null) outputPath = SafeFile.WriteAllBytes(outputPath, data, overwrite);
            var sb = new StringBuilder($"{er.Name}: .resources container with {set.ResourceElements.Count()} entries");
            if (outputPath != null) sb.Append($" (raw container saved to {outputPath})");
            sb.AppendLine().AppendLine("Pass entry=<name> to read or save one entry.").AppendLine();
            foreach (var el in set.ResourceElements.OrderBy(e => e.Name, StringComparer.Ordinal))
                sb.AppendLine($"  {el.Name}  [{DescribeType(el.ResourceData)}]  {Preview(el.ResourceData)}");
            return sb.ToString();
        }

        if (set != null && entry != null)
        {
            var el = set.ResourceElements.FirstOrDefault(e => e.Name == entry)
                     ?? set.ResourceElements.FirstOrDefault(e => string.Equals(e.Name, entry, StringComparison.OrdinalIgnoreCase))
                     ?? throw new ToolError(ErrorCode.NotFound, $"Entry '{entry}' not found in {name}.");
            var bytes = EntryBytes(el.ResourceData);
            if (outputPath != null)
            {
                if (bytes == null) throw new ToolError(ErrorCode.InvalidArgument, $"Entry '{entry}' is a {DescribeType(el.ResourceData)} value; nothing binary to save. Value: {Preview(el.ResourceData, 500)}");
                return $"Saved entry '{entry}' ({bytes.Length} bytes) to {SafeFile.WriteAllBytes(outputPath, bytes, overwrite)}";
            }
            // BAML (compiled WPF XAML) is shown decompiled to XAML.
            if (bytes != null && baml != null && entry.EndsWith(".baml", StringComparison.OrdinalIgnoreCase) && baml(bytes) is { } xaml)
                return $"<!-- {entry}: XAML decompiled from BAML ({bytes.Length} bytes; outputPath writes the raw BAML) -->{Environment.NewLine}{xaml}";
            return el.ResourceData is BuiltInResourceData { Data: string s }
                ? s
                : bytes != null ? Render(bytes, previewBytes) : Preview(el.ResourceData, 100_000);
        }

        if (outputPath != null)
        {
            return $"Saved {er.Name} ({data.Length} bytes) to {SafeFile.WriteAllBytes(outputPath, data, overwrite)}";
        }
        return $"{er.Name} ({data.Length} bytes)\n" + Render(data, previewBytes);
    }

    private static ResourceElementSet? TryReadSet(LoadedAssembly asm, EmbeddedResource er)
    {
        try { return ResourceReader.Read(asm.Module, er.CreateReader()); }
        catch { return null; }
    }

    private static byte[]? EntryBytes(IResourceData data) => data switch
    {
        BinaryResourceData b => b.Data,
        BuiltInResourceData { Data: byte[] bytes } => bytes,
        BuiltInResourceData { Data: string s } => Encoding.UTF8.GetBytes(s),
        _ => null,
    };

    private static string DescribeType(IResourceData data) => data switch
    {
        BinaryResourceData b => $"serialized {b.TypeName}",
        BuiltInResourceData bi => bi.Code.ToString(),
        _ => data.Code.ToString(),
    };

    private static string Preview(IResourceData data, int max = 80) => data switch
    {
        BuiltInResourceData { Data: string s } => Format.Literal(Format.Clip(s, max)),
        BuiltInResourceData { Data: byte[] b } => $"{b.Length} bytes",
        BuiltInResourceData bi => Format.Clip(Format.Literal(bi.Data), max),
        BinaryResourceData b => $"{b.Data.Length} bytes",
        _ => "",
    };

    /// <summary>Text if it looks like text (UTF-8/UTF-16 with BOM), otherwise a hex dump.</summary>
    internal static string Render(byte[] data, int previewBytes)
    {
        var text = TryDecodeText(data);
        if (text != null)
            return text;
        int n = Math.Min(data.Length, previewBytes);
        var sb = new StringBuilder($"[binary; hex dump of the first {n} bytes; outputPath extracts it]\n");
        for (int i = 0; i < n; i += 16)
        {
            sb.Append($"{i:X8}  ");
            for (int j = 0; j < 16; j++)
                sb.Append(i + j < n ? $"{data[i + j]:X2} " : "   ");
            sb.Append(' ');
            for (int j = 0; j < 16 && i + j < n; j++)
                sb.Append(data[i + j] is >= 32 and < 127 ? (char)data[i + j] : '.');
            sb.AppendLine();
        }
        return sb.ToString();
    }

    private static string? TryDecodeText(byte[] data)
    {
        if (data.Length >= 2 && ((data[0] == 0xFF && data[1] == 0xFE) || (data[0] == 0xFE && data[1] == 0xFF)))
            return Encoding.Unicode.GetString(data).TrimStart('﻿');
        try
        {
            var s = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(data).TrimStart('﻿');
            int control = s.Count(c => char.IsControl(c) && c is not ('\r' or '\n' or '\t'));
            return control <= s.Length / 100 ? s : null;
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
    }
}
