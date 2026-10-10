using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Native.Patching;

/// <summary>What an exported patch set is made of: the image, its patches and the bytes before and after (as save_native writes them).</summary>
public sealed record PatchExportSource(
    string Path,
    string Sha256,
    ulong ImageBase,
    NativeArch Arch,
    IReadOnlyList<NativePatch> Patches,
    byte[] Original,
    byte[] Output,
    long ChecksumOffset,
    Func<long, uint?> FileOffsetToRva);

/// <summary>An exported patch set: the file content and what it holds.</summary>
public sealed record PatchExportResult(byte[] Content, int Patches, int RelocationEdits, int ChangedBytes, int Records, bool ChecksumUpdated, List<string> Notes);

/// <summary>
/// Renders an image's byte patches for other tools: an IDAPython script (patches by RVA rebased to the database's image
/// base, each applied only where the database holds the original bytes), IDA's .dif (file offsets, one changed byte per
/// line), IPS / IPS32 (file offsets, records of changed bytes) and JSON (the whole patch set with original bytes and
/// relocation edits). Relocation-table edits and the recomputed PE checksum are byte changes of the file, so every
/// format carries them: applying a .dif or IPS to the original file gives exactly the bytes save_native writes.
/// </summary>
public static class PatchExport
{
    public enum Format { Ida, Dif, Ips, Ips32, Json }

    /// <summary>Highest offset an IPS record can start at (3-byte offsets).</summary>
    public const long IpsMaxOffset = 0xFFFFFF;
    /// <summary>The offset whose 3-byte big-endian encoding reads "EOF", IPS's end marker.</summary>
    public const long IpsEofOffset = 0x454F46;
    /// <summary>The offset whose 4-byte big-endian encoding reads "EEOF", IPS32's end marker.</summary>
    public const long Ips32EofOffset = 0x45454F46;
    private const int MaxRecord = 0xFFFE;
    private const int MergeGap = 4;

    public static Format ParseFormat(string? format) => (format ?? "json").Trim().ToLowerInvariant() switch
    {
        "ida" or "idapython" or "py" => Format.Ida,
        "dif" or "diff" => Format.Dif,
        "ips" => Format.Ips,
        "ips32" => Format.Ips32,
        "json" or "" => Format.Json,
        _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown format '{format}'.", "use ida, dif, ips, ips32 or json"),
    };

    public static string Name(Format format) => format.ToString().ToLowerInvariant();

    public static PatchExportResult Render(PatchExportSource source, Format format)
    {
        if (source.Output.Length != source.Original.Length)
            throw new ToolError(ErrorCode.InvalidArgument, "The patched file has a different length than the original; byte patch formats cannot express that.");
        var runs = Runs(source.Original, source.Output);
        int changed = runs.Sum(r => r.Length);
        bool checksum = source.ChecksumOffset >= 0 && source.ChecksumOffset + 4 <= source.Original.Length
            && !source.Original.AsSpan((int)source.ChecksumOffset, 4).SequenceEqual(source.Output.AsSpan((int)source.ChecksumOffset, 4));
        int edits = source.Patches.Sum(p => p.RelocationEdits.Count);
        var notes = new List<string>();
        byte[] content;
        int records;
        switch (format)
        {
            case Format.Ida:
                (content, records) = Ida(source, checksum);
                break;
            case Format.Dif:
                (content, records) = Dif(source, runs);
                break;
            case Format.Ips:
            case Format.Ips32:
                (content, records) = Ips(source, runs, format == Format.Ips32, notes);
                break;
            default:
                (content, records) = Json(source, checksum);
                break;
        }
        if (source.Patches.Count == 0) notes.Add("the image has no patches: the export is empty");
        return new PatchExportResult(content, source.Patches.Count, edits, changed, records, checksum, notes);
    }

    /// <summary>Maximal runs of differing bytes between two equal-length arrays.</summary>
    public static List<(long Offset, int Length)> Runs(byte[] a, byte[] b)
    {
        var runs = new List<(long, int)>();
        int n = Math.Min(a.Length, b.Length);
        for (int i = 0; i < n;)
        {
            int k = a.AsSpan(i, n - i).CommonPrefixLength(b.AsSpan(i, n - i));
            i += k;
            if (i >= n) break;
            int start = i;
            while (i < n && a[i] != b[i]) i++;
            runs.Add((start, i - start));
        }
        return runs;
    }

    // ---- IDAPython ----

    private static (byte[], int) Ida(PatchExportSource s, bool checksum)
    {
        var entries = new List<(string Label, uint Rva, byte[] Original, byte[] Replacement)>();
        int number = 1;
        foreach (var p in s.Patches)
        {
            entries.Add(($"#{number} {p.Description}", p.Rva, p.Original, p.Replacement));
            if (p.Stub is { } stub)
                entries.Add(($"#{number} relocation stub", stub.Rva, stub.Original, stub.Replacement));
            foreach (var e in p.RelocationEdits)
                entries.Add(($"#{number} relocation entry", e.SlotRva, U16(e.Original), U16(e.Replacement)));
            number++;
        }
        if (checksum && s.FileOffsetToRva(s.ChecksumOffset) is { } csRva)
            entries.Add(("PE checksum", csRva, s.Original[(int)s.ChecksumOffset..(int)(s.ChecksumOffset + 4)], s.Output[(int)s.ChecksumOffset..(int)(s.ChecksumOffset + 4)]));

        var sb = new StringBuilder();
        sb.Append("# IDAPython: apply native patches exported from NetDecompilerMcp.\n");
        sb.Append($"# Source: {Comment(System.IO.Path.GetFileName(s.Path))}  sha256 {s.Sha256}  preferred image base 0x{s.ImageBase:X}\n");
        sb.Append("# Each entry is applied at its RVA rebased to this database's image base, only when the database holds the\n");
        sb.Append("# original bytes there; entries already applied are skipped. Relocation-table and header entries are applied when\n");
        sb.Append("# those bytes are loaded in the database (IDA does not load .reloc or the PE header by default).\n");
        sb.Append("import idaapi, ida_bytes, ida_auto\n\n");
        sb.Append("PATCHES = [\n");
        sb.Append("    # (label, rva, original bytes, replacement bytes)\n");
        foreach (var (label, rva, orig, repl) in entries)
            sb.Append($"    ({Py(label)}, 0x{rva:X}, \"{Convert.ToHexString(orig)}\", \"{Convert.ToHexString(repl)}\"),\n");
        sb.Append("]\n\n");
        sb.Append("""
            def _loaded(ea, n):
                return all(ida_bytes.is_loaded(ea + i) for i in range(n))

            def apply_patches():
                base = idaapi.get_imagebase()
                applied = already = differ = missing = 0
                for label, rva, original, replacement in PATCHES:
                    ea = base + rva
                    orig = bytes.fromhex(original)
                    new = bytes.fromhex(replacement)
                    if not _loaded(ea, len(new)):
                        missing += 1
                        print("NetDecompilerMcp: %s at 0x%X: not loaded in the database, skipped" % (label, ea))
                        continue
                    found = ida_bytes.get_bytes(ea, len(new))
                    if found == new:
                        already += 1
                        continue
                    if found != orig:
                        differ += 1
                        print("NetDecompilerMcp: %s at 0x%X: original bytes differ (expected %s, found %s), skipped" % (label, ea, original, found.hex().upper() if found else "none"))
                        continue
                    ida_bytes.patch_bytes(ea, new)
                    ida_auto.plan_range(ea, ea + len(new))
                    applied += 1
                ida_auto.auto_wait()
                print("NetDecompilerMcp: %d applied, %d already applied, %d with different original bytes, %d not loaded (of %d)" % (applied, already, differ, missing, len(PATCHES)))
                return applied, already, differ, missing

            NDM_PATCH_RESULT = apply_patches()

            """.Replace("\r\n", "\n"));
        return (Encoding.UTF8.GetBytes(sb.ToString()), entries.Count);
    }

    // ---- IDA .dif ----

    private static (byte[], int) Dif(PatchExportSource s, List<(long Offset, int Length)> runs)
    {
        // As IDA writes it: a header line, a blank line, the file name, then "%016X: %02X %02X" per changed byte, LF line ends.
        var sb = new StringBuilder();
        sb.Append("This difference file was created by IDA\n\n");
        sb.Append(System.IO.Path.GetFileName(s.Path)).Append('\n');
        int lines = 0;
        foreach (var (offset, length) in runs)
            for (int i = 0; i < length; i++, lines++)
                sb.Append($"{offset + i:X16}: {s.Original[offset + i]:X2} {s.Output[offset + i]:X2}\n");
        return (Encoding.ASCII.GetBytes(sb.ToString()), lines);
    }

    // ---- IPS / IPS32 ----

    private static (byte[], int) Ips(PatchExportSource s, List<(long Offset, int Length)> runs, bool ips32, List<string> notes)
    {
        long eof = ips32 ? Ips32EofOffset : IpsEofOffset;
        long max = ips32 ? uint.MaxValue : IpsMaxOffset;
        // merge runs separated by a few unchanged bytes (a record header costs 5 or 6 bytes), then split to the record size
        var merged = new List<(long Offset, int Length)>();
        foreach (var r in runs)
        {
            if (merged.Count > 0 && r.Offset - (merged[^1].Offset + merged[^1].Length) <= MergeGap)
                merged[^1] = (merged[^1].Offset, (int)(r.Offset + r.Length - merged[^1].Offset));
            else merged.Add(r);
        }
        var records = new List<(long Offset, int Length)>();
        foreach (var (offset, length) in merged)
            for (int done = 0; done < length; done += MaxRecord)
                records.Add((offset + done, Math.Min(MaxRecord, length - done)));
        // a record starting at the end marker's offset would read as the end: start it one byte earlier (an unchanged or
        // equal byte, written with its patched value)
        int moved = 0;
        for (int i = 0; i < records.Count; i++)
            if (records[i].Offset == eof) { records[i] = (eof - 1, records[i].Length + 1); moved++; }
        if (moved > 0) notes.Add($"{moved} record(s) at offset 0x{eof:X} (the end marker read as an offset) start one byte earlier");
        if (records.FirstOrDefault(r => r.Offset > max) is { Length: > 0 } far)
            throw new ToolError(ErrorCode.InvalidArgument,
                $"A patch is at file offset 0x{far.Offset:X}, beyond IPS's 16 MB offset limit (0x{IpsMaxOffset:X}).",
                "use format=ips32 (4-byte offsets), dif or json");

        using var ms = new MemoryStream();
        ms.Write(Encoding.ASCII.GetBytes(ips32 ? "IPS32" : "PATCH"));
        Span<byte> head = stackalloc byte[6];
        foreach (var (offset, length) in records)
        {
            if (ips32)
            {
                BinaryPrimitives.WriteUInt32BigEndian(head, (uint)offset);
                BinaryPrimitives.WriteUInt16BigEndian(head[4..], (ushort)length);
                ms.Write(head);
            }
            else
            {
                head[0] = (byte)(offset >> 16); head[1] = (byte)(offset >> 8); head[2] = (byte)offset;
                BinaryPrimitives.WriteUInt16BigEndian(head[3..], (ushort)length);
                ms.Write(head[..5]);
            }
            ms.Write(s.Output, (int)offset, length);
        }
        ms.Write(Encoding.ASCII.GetBytes(ips32 ? "EEOF" : "EOF"));
        return (ms.ToArray(), records.Count);
    }

    // ---- JSON ----

    public const string JsonKind = "netdecompilermcp.native_patches";

    private static (byte[], int) Json(PatchExportSource s, bool checksum)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true }))
        {
            w.WriteStartObject();
            w.WriteString("kind", JsonKind);
            w.WriteNumber("version", 1);
            w.WriteStartObject("image");
            w.WriteString("path", s.Path);
            w.WriteString("fileName", System.IO.Path.GetFileName(s.Path));
            w.WriteString("sha256", s.Sha256);
            w.WriteString("arch", s.Arch.ToString().ToLowerInvariant());
            w.WriteString("imageBase", $"0x{s.ImageBase:X}");
            w.WriteNumber("fileSize", s.Original.Length);
            w.WriteString("patchedSha256", Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(s.Output)).ToLowerInvariant());
            w.WriteEndObject();
            w.WriteStartArray("patches");
            int number = 1;
            foreach (var p in s.Patches)
            {
                w.WriteStartObject();
                w.WriteNumber("number", number++);
                w.WriteString("rva", $"0x{p.Rva:X}");
                w.WriteString("fileOffset", $"0x{p.FileOffset:X}");
                w.WriteNumber("length", p.Length);
                w.WriteString("original", Convert.ToHexString(p.Original));
                w.WriteString("replacement", Convert.ToHexString(p.Replacement));
                w.WriteString("description", p.Description);
                w.WriteString("origin", p.Stub != null ? "stub" : p.Assembly != null ? "asm" : "bytes");
                if (p.Assembly != null) w.WriteString("assembly", p.Assembly); else w.WriteNull("assembly");
                if (p.Stub is { } stub)
                {
                    w.WriteStartObject("stub");
                    w.WriteString("mode", stub.Mode);
                    w.WriteString("placement", stub.Placement);
                    w.WriteString("rva", $"0x{stub.Rva:X}");
                    w.WriteString("fileOffset", $"0x{stub.FileOffset:X}");
                    w.WriteString("returnRva", $"0x{stub.ReturnRva:X}");
                    w.WriteString("original", Convert.ToHexString(stub.Original));
                    w.WriteString("replacement", Convert.ToHexString(stub.Replacement));
                    w.WriteEndObject();
                }
                else w.WriteNull("stub");
                w.WriteStartArray("relocationEdits");
                foreach (var e in p.RelocationEdits)
                {
                    w.WriteStartObject();
                    w.WriteString("slotRva", $"0x{e.SlotRva:X}");
                    w.WriteString("fileOffset", $"0x{e.FileOffset:X}");
                    w.WriteString("original", $"0x{e.Original:X4}");
                    w.WriteString("replacement", $"0x{e.Replacement:X4}");
                    w.WriteEndObject();
                }
                w.WriteEndArray();
                w.WriteStartArray("relocationChanges");
                foreach (var c in p.Relocations?.Changes ?? [])
                {
                    w.WriteStartObject();
                    w.WriteString("action", c.Action);
                    w.WriteString("targetRva", $"0x{c.TargetRva:X}");
                    w.WriteString("type", c.Type.ToString().ToLowerInvariant());
                    if (c.SlotRva is { } slot) w.WriteString("slotRva", $"0x{slot:X}"); else w.WriteNull("slotRva");
                    if (c.Note != null) w.WriteString("note", c.Note); else w.WriteNull("note");
                    w.WriteEndObject();
                }
                w.WriteEndArray();
                w.WriteEndObject();
            }
            w.WriteEndArray();
            if (checksum)
            {
                w.WriteStartObject("checksum");
                w.WriteString("fileOffset", $"0x{s.ChecksumOffset:X}");
                w.WriteString("original", Convert.ToHexString(s.Original, (int)s.ChecksumOffset, 4));
                w.WriteString("replacement", Convert.ToHexString(s.Output, (int)s.ChecksumOffset, 4));
                w.WriteEndObject();
            }
            else w.WriteNull("checksum");
            w.WriteEndObject();
        }
        return (ms.ToArray(), s.Patches.Count);
    }

    private static byte[] U16(ushort v) => [(byte)v, (byte)(v >> 8)];

    private static string Comment(string text) => text.Replace('\n', ' ').Replace('\r', ' ');

    private static string Py(string text)
    {
        var sb = new StringBuilder("\"");
        foreach (var c in text)
        {
            if (c is '\\' or '"') sb.Append('\\').Append(c);
            else if (c < 0x20 || c > 0x7E) sb.Append($"\\u{(int)c:x4}");
            else sb.Append(c);
        }
        return sb.Append('"').ToString();
    }
}
