using System.Buffers.Binary;
using System.Text;
using System.Text.RegularExpressions;
using Corvus.Core.Archives;

namespace Corvus.Core.Documents;

/// <summary>OneNote sections (MS-ONESTORE): embedded files named in order, with the mentioned file names listed unpaired.</summary>
internal sealed class OneNoteReader : IContainerReader
{
    private static readonly Guid Section = new("7B5C52E4-D88C-4DA7-AEB1-5378D02996D3");
    private static readonly Guid TableOfContents = new("43FF2FA1-EFD9-4C76-9EE2-10EA5722765F");
    private static readonly byte[] StoreHeader = new Guid("BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC").ToByteArray();
    private static readonly byte[] StoreFooter = new Guid("71FBA722-0F79-4A0B-BB13-899256426B24").ToByteArray();

    public string Kind => "onenote";

    public static bool Looks(ReadOnlySpan<byte> b) => b.Length >= 16 && new Guid(b[..16]) is var g && (g == Section || g == TableOfContents);

    public bool Accepts(ReadOnlySpan<byte> data, string name) => Looks(data);

    /// <summary>The embedded files in file order, with their offsets.</summary>
    public static List<(long Offset, byte[] Data)> Files(byte[] data, long max, List<string> notes, CancellationToken ct)
    {
        var files = new List<(long, byte[])>();
        int at = 0;
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            int found = data.AsSpan(at).IndexOf(StoreHeader);
            if (found < 0) break;
            int start = at + found;
            at = start + 16;
            if (start + 36 > data.Length) break;
            long length = BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(start + 16));
            long body = start + 36;
            if (length < 0 || body + length > data.Length) { notes.Add($"embedded file at 0x{start:X}: {length:N0} bytes run past the file"); continue; }
            if (length > max) { notes.Add($"embedded file at 0x{start:X}: {length:N0} bytes, over the item limit"); continue; }
            long footer = (body + length + 7) / 8 * 8;
            if (footer + 16 > data.Length || !data.AsSpan((int)footer, 16).SequenceEqual(StoreFooter))
                notes.Add($"embedded file at 0x{start:X}: no footer after its data");
            files.Add((start, data.AsSpan((int)body, (int)length).ToArray()));
            at = (int)Math.Min(body + length, data.Length);
        }
        return files;
    }

    // NonBacktracking matches in linear time, so no match timeout.
    private static readonly Regex FileName = new(
        @"[\w\-. ()\[\]]{1,120}\.(?:exe|dll|scr|hta|bat|cmd|js|jse|vbs|vbe|wsf|wsh|ps1|lnk|chm|zip|rar|7z|iso|img|vhd|vhdx|msi|jar|docm|xlsm|pptm|doc|xls|pdf|one|url|reg|cpl|txt)\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    /// <summary>File names stored as UTF-16 in the section (the EmbeddedFileName property and others), in file order.</summary>
    public static List<string> Names(byte[] data)
    {
        var text = Encoding.Unicode.GetString(data, 0, data.Length & ~1);
        var names = new List<string>();
        foreach (Match m in FileName.Matches(text))
            if (!names.Contains(m.Value.Trim())) names.Add(m.Value.Trim());
        return names;
    }

    /// <summary>
    /// The name of each file: the stored name when the section names as many
    /// files as it embeds, else the content name; stored names are paired in order.
    /// </summary>
    public static List<string> FileNames(IReadOnlyList<byte[]> files, IReadOnlyList<string> stored)
    {
        var names = new List<string>();
        bool paired = stored.Count == files.Count;
        for (int i = 0; i < files.Count; i++)
            names.Add(paired && Path.GetFileName(stored[i]) is { Length: > 0 } stem ? stem : $"embedded_{i + 1}{Extension(files[i])}");
        return names;
    }

    /// <summary>An extension for embedded content from its first bytes.</summary>
    public static string Extension(byte[] b)
    {
        var kind = Blob.Identify(b);
        if (kind is "native PE" or ".NET assembly" or "NativeAOT executable") return PeImage.TryParse(b)?.IsDll == true ? ".dll" : ".exe";
        if (kind == "text")
        {
            var head = Encoding.UTF8.GetString(b, 0, Math.Min(b.Length, 512)).TrimStart().ToLowerInvariant();
            if (head.StartsWith("<hta", StringComparison.Ordinal) || head.Contains("<hta:", StringComparison.Ordinal) || head.StartsWith("<html", StringComparison.Ordinal)) return ".hta";
            if (head.StartsWith("@echo", StringComparison.Ordinal) || head.StartsWith("echo ", StringComparison.Ordinal)) return ".bat";
            var text = Encoding.UTF8.GetString(b, 0, Math.Min(b.Length, 8192));
            return Providers.Of<IScriptSniffer>().Select(s => s.Language(text)).FirstOrDefault(l => l != null) switch
            {
                "powershell" => ".ps1", "batch" => ".cmd", "vbscript" => ".vbs", "javascript" => ".js", _ => ".txt",
            };
        }
        return kind switch
        {
            "zip" => ".zip", "pdf" => ".pdf", "png" => ".png", "jpeg" => ".jpg", "gif" => ".gif", "ole (msi/doc/xls)" => ".ole", "lnk shortcut" => ".lnk", "cab" => ".cab", "7z" => ".7z",
            "rar" => ".rar", "gzip" => ".gz", _ => ".bin",
        };
    }

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var notes = new List<string>();
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        long total = 0;
        var files = Files(data, limits.MaxItemBytes, notes, ct);
        var names = Names(data);
        var fileNames = FileNames([.. files.Select(f => f.Data)], names);
        for (int i = 0; i < files.Count; i++)
            ArchiveItems.Take(items, entries, "OneNote embedded file", fileNames[i], files[i].Data, true, limits, ref total);
        int n = files.Count;
        if (names.Count > 0) notes.Add($"file names in the section: {string.Join(", ", names.Take(20))}");
        if (n == 0) notes.Add("no embedded files");
        return new ContainerContents(new Guid(data.AsSpan(0, 16)) == TableOfContents ? "OneNote table of contents" : "OneNote section", items, notes) { Entries = entries };
    }
}
