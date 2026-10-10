using System.Text;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Services;

/// <summary>Win32 resources of a native image, named TYPE/NAME/LANGUAGE as list_resources shows them.</summary>
public static class NativeResourceService
{
    public static string Key(PeResource r) => $"{r.TypeName}/{r.Name?.ToString() ?? "?"}/{r.Language}";

    public static string List(LoadedNative native)
    {
        if (native.Pe is not { } pe) return $"{native.Id} has no Win32 resources ({native.Image.Format} image).";
        if (pe.Resources.Count == 0) return $"{native.Id} has no Win32 resources.";
        var sb = new StringBuilder($"{native.Id}: {pe.Resources.Count} Win32 resource(s) (TYPE/NAME/LANGUAGE)\n");
        foreach (var r in pe.Resources)
            sb.AppendLine($"  {Key(r)}  {r.Size:N0} bytes at rva 0x{r.Rva:X}{(r.CodePage != 0 ? $", code page {r.CodePage}" : "")}");
        return sb.ToString();
    }

    /// <summary>
    /// Reads one resource: version info and string tables decoded, manifests and other text as text, binary as a hex
    /// preview; <paramref name="savePath"/> writes the raw bytes. The language may be omitted when only one matches.
    /// </summary>
    public static string Get(LoadedNative native, string name, string? savePath, int previewBytes = 4096, bool overwrite = false)
    {
        var pe = native.RequirePe("get_resource");
        // "VERSION/#1/1033", "VERSION/1" and "RT_VERSION/1" all name the same resource.
        static string Plain(string k) => k.Replace("#", "").ToUpperInvariant() is var u && u.StartsWith("RT_") ? u[3..] : k.Replace("#", "").ToUpperInvariant();
        var key = Plain(name.Trim());
        var matches = pe.Resources.Where(r => Plain(Key(r)) == key || Plain(Key(r)).StartsWith(key + "/", StringComparison.Ordinal)).ToList();
        if (matches.Count == 0)
            throw new ToolError(ErrorCode.NotFound, $"No resource '{name}' in {native.Id}.",
                $"list_resources lists them as TYPE/NAME/LANGUAGE, e.g. {(pe.Resources.Count > 0 ? Key(pe.Resources[0]) : "VERSION/1/1033")}");
        if (matches.Count > 1)
            throw new ToolError(ErrorCode.Ambiguous, $"'{name}' matches {matches.Count} resources: {string.Join(", ", matches.Take(10).Select(Key))}.", "add the language: TYPE/NAME/LANGUAGE");
        var r = matches[0];
        var bytes = pe.ReadResource(r) ?? throw new ToolError(ErrorCode.MalformedInput, $"The data of {Key(r)} is outside the mapped image.");
        if (savePath != null)
        {
            var full = SafeFile.WriteAllBytes(savePath, bytes, overwrite);
            return $"Saved {Key(r)} ({bytes.Length:N0} bytes) to {full}";
        }
        var head = $"{Key(r)}: {bytes.Length:N0} bytes\n";
        switch (r.Type.IsName ? 0u : r.Type.Id)
        {
            case PeFile.RtVersion when pe.VersionInfo is { } vi:
                var sb = new StringBuilder(head);
                if (vi.Fixed is { } fx) sb.AppendLine($"FileVersion {fx.FileVersionText}, ProductVersion {fx.ProductVersionText}, flags 0x{fx.FileFlags:X}, type {fx.FileType}");
                foreach (var table in vi.StringTables)
                {
                    sb.AppendLine($"[{table.Key}]");
                    foreach (var (k, v) in table.Strings) sb.AppendLine($"  {k}: {v}");
                }
                return sb.ToString();
            case PeFile.RtString:
                uint block = r.Name is { IsName: false } n ? n.Id : 0;
                var strings = pe.ResourceStrings.Where(s => s.Language == r.Language && (s.Id >> 4) + 1 == block).ToList();
                return head + string.Join("\n", strings.Select(s => $"  {s.Id}: {s.Text}"));
            case PeFile.RtManifest:
                return head + Text(bytes);
        }
        if (LooksLikeText(bytes)) return head + Text(bytes);
        var preview = bytes.AsSpan(0, Math.Min(bytes.Length, previewBytes));
        var hex = new StringBuilder(head);
        for (int i = 0; i < preview.Length; i += 16)
        {
            var row = preview.Slice(i, Math.Min(16, preview.Length - i));
            hex.Append($"{i:X6}  ").Append(string.Join(" ", row.ToArray().Select(b => b.ToString("X2"))).PadRight(48)).Append("  ")
               .AppendLine(new string(row.ToArray().Select(b => b is >= 0x20 and < 0x7F ? (char)b : '.').ToArray()));
        }
        if (bytes.Length > preview.Length) hex.AppendLine($"... {bytes.Length - preview.Length:N0} more bytes (savePath writes them all)");
        return hex.ToString();
    }

    private static string Text(byte[] bytes) =>
        bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE ? Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2)
        : bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF ? Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3)
        : Encoding.UTF8.GetString(bytes);

    private static bool LooksLikeText(byte[] bytes)
    {
        if (bytes.Length == 0) return false;
        int sample = Math.Min(bytes.Length, 2048), printable = 0;
        for (int i = 0; i < sample; i++)
            if (bytes[i] is 9 or 10 or 13 or (>= 0x20 and < 0x7F)) printable++;
        return printable >= sample * 0.95;
    }
}
