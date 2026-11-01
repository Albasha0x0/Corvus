using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Documents;

/// <summary>One VBA module: its stream, kind (standard, class, form or document) and source text.</summary>
internal sealed record VbaModule(string Name, string Stream, string Type, string Source, bool SourceMissing)
{
    /// <summary>The compiled-code cache compared with the source, one of <see cref="VbaCompiledState"/>.</summary>
    public string CompiledCode { get; init; } = VbaCompiledState.Unverified;

    /// <summary>The basis or reason of <see cref="CompiledCode"/>; null when purged.</summary>
    public string? CompiledNote { get; init; }
}

/// <summary>The states of a module's compiled-code comparison.</summary>
internal static class VbaCompiledState
{
    /// <summary>The project holds no compiled code for the module.</summary>
    public const string Purged = "purged";

    /// <summary>Every source string is found in the compiled code; opcodes are not compared.</summary>
    public const string StringsMatch = "strings_match";

    /// <summary>Source strings are absent from the compiled code.</summary>
    public const string Differs = "differs";

    /// <summary>The comparison could not be made; the note names the reason.</summary>
    public const string Unverified = "unverified";
}

/// <summary>A VBA project (MS-OVBA), its module sources and, per module, the compiled-code comparison.</summary>
internal sealed class VbaProject
{
    public required string Storage { get; set; }
    public string? ProjectName { get; init; }
    public int CodePage { get; init; }

    /// <summary>The version in _VBA_PROJECT as 0xNNNN; null when absent or unreadable.</summary>
    public string? Version { get; init; }
    public required IReadOnlyList<VbaModule> Modules { get; init; }
    public required IReadOnlyList<string> References { get; init; }
    public required IReadOnlyList<string> Notes { get; init; }

    /// <summary>The storages holding a VBA project: the parent of each "VBA/dir" stream ("" for vbaProject.bin, "Macros/" in Word).</summary>
    public static IEnumerable<string> Roots(CompoundFile cf) =>
        cf.Entries.Where(e => !e.IsStorage && e.Path.EndsWith("VBA/dir", StringComparison.OrdinalIgnoreCase) && (e.Path.Length == 7 || e.Path[^8] == '/'))
            .Select(e => e.Path[..^7]);

    public static VbaProject Read(CompoundFile cf, string root, long max)
    {
        var notes = new List<string>();
        var dirEntry = cf.Find(root + "VBA/dir")!;
        var dir = Decompress(cf.Read(dirEntry, max), max) ?? throw new ToolError(ErrorCode.MalformedInput, $"{cf.Name}: {root}VBA/dir is not MS-OVBA compressed data.");
        var modules = new List<VbaModule>();
        var references = new List<string>();
        string? project = null;
        int codePage = 1252;
        Encoding enc = Encoding.Latin1;

        var projectCache = ReadProjectStream(cf, root, max);
        string? name = null, nameUnicode = null, stream = null, streamUnicode = null, type = null;
        uint offset = 0;
        void EndModule()
        {
            if (name == null && stream == null) return;
            var streamName = streamUnicode ?? stream ?? name!;
            var moduleName = nameUnicode ?? name ?? streamName;
            var entry = cf.Find(root + "VBA/" + streamName);
            string source = "";
            bool missing = false;
            byte[]? cache = null;
            string? problem = null;
            if (entry == null) { notes.Add($"module {moduleName}: stream VBA/{streamName} not found"); problem = "module stream not found"; }
            else
            {
                var data = cf.Read(entry, max);
                if (entry.Size > max) problem = LimitNote(max);
                else if (offset <= data.Length) cache = data[..(int)offset];
                else problem = "text offset past the module stream";
                if (offset > data.Length) { notes.Add($"module {moduleName}: text offset {offset} past the stream ({data.Length} bytes)"); missing = true; }
                else if (Decompress(data.AsSpan((int)offset), max) is { } text) source = enc.GetString(text);
                else { notes.Add($"module {moduleName}: no MS-OVBA compressed source at its text offset"); missing = true; }
            }
            var (state, detail) = Compare(cache, problem, projectCache, source, missing, enc);
            modules.Add(new VbaModule(moduleName, "VBA/" + streamName, type ?? "standard", source, missing) { CompiledCode = state, CompiledNote = detail });
            name = nameUnicode = stream = streamUnicode = type = null;
            offset = 0;
        }

        int pos = 0;
        string? lastReference = null;
        while (pos + 6 <= dir.Length)
        {
            int id = BinaryPrimitives.ReadUInt16LittleEndian(dir.AsSpan(pos));
            int size = BinaryPrimitives.ReadInt32LittleEndian(dir.AsSpan(pos + 2));
            pos += 6;
            // PROJECTVERSION: its size field reads 4 for 6 bytes of data.
            if (id == 0x0009) size = 6;
            if (size < 0 || pos + size > dir.Length) { notes.Add($"dir stream: record 0x{id:X4} runs past the end"); break; }
            var d = dir.AsSpan(pos, size);
            pos += size;
            switch (id)
            {
                case 0x0003 when size >= 2:
                    codePage = BinaryPrimitives.ReadUInt16LittleEndian(d);
                    enc = EncodingOf(codePage);
                    break;
                case 0x0004: project = enc.GetString(d); break;
                case 0x0016: lastReference = enc.GetString(d); break;
                case 0x003E: references.Add(Encoding.Unicode.GetString(d)); lastReference = null; break;
                case 0x000D or 0x000E or 0x002F or 0x0033:
                    if (lastReference != null) { references.Add(lastReference); lastReference = null; }
                    break;
                case 0x0019: EndModule(); name = enc.GetString(d); break;
                case 0x0047: nameUnicode = Encoding.Unicode.GetString(d); break;
                case 0x001A: stream = enc.GetString(d); break;
                case 0x0032: streamUnicode = Encoding.Unicode.GetString(d); break;
                case 0x0031 when size >= 4: offset = BinaryPrimitives.ReadUInt32LittleEndian(d); break;
                case 0x0021: type = "standard"; break;
                case 0x0022: type = "class"; break;
                case 0x002B: EndModule(); break;
                case 0x0010: pos = dir.Length; break;
            }
        }
        EndModule();
        // The PROJECT stream names document modules (Document=ThisDocument/&H00000000).
        if (cf.Find(root + "PROJECT") is { } projectStream)
        {
            var text = enc.GetString(cf.Read(projectStream, Math.Min(max, 1 << 20)));
            var kinds = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in text.Split('\n').Select(l => l.Trim()))
            {
                int eq = line.IndexOf('=');
                if (eq <= 0) continue;
                var kind = line[..eq].ToLowerInvariant() switch { "document" => "document", "class" => "class", "baseclass" => "form", "module" => "standard", _ => null };
                if (kind != null) kinds[line[(eq + 1)..].Split('/')[0]] = kind;
            }
            for (int i = 0; i < modules.Count; i++)
                if (kinds.TryGetValue(modules[i].Name, out var kind)) modules[i] = modules[i] with { Type = kind };
        }
        return new VbaProject { Storage = root, ProjectName = project, CodePage = codePage, Version = projectCache.Version, Modules = modules, References = references, Notes = notes };
    }

    private sealed record ProjectStream(string? Version, bool HasCache, string? Problem);

    private static string LimitNote(long max) => $"stream exceeds the {max >> 20} MiB part limit, which no parameter raises; read the module source with view=office";

    // _VBA_PROJECT holds 0x61CC, the version, 0x00 and a reserved word, then the cache.
    private static ProjectStream ReadProjectStream(CompoundFile cf, string root, long max)
    {
        if (cf.Find(root + "VBA/_VBA_PROJECT") is not { } entry) return new(null, false, "project stream missing or unreadable");
        var data = cf.Read(entry, max);
        if (data.Length < 7 || BinaryPrimitives.ReadUInt16LittleEndian(data) != 0x61CC) return new(null, false, "project stream missing or unreadable");
        int version = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(2));
        // A version of 0xFFFF or no bytes after the header marks a purged project.
        return new($"0x{version:X4}", version != 0xFFFF && data.Length > 7, entry.Size > max ? LimitNote(max) : null);
    }

    // Source strings absent from the cache stored before the source mean the source was replaced.
    private static (string State, string? Detail) Compare(byte[]? cache, string? problem, ProjectStream project, string source, bool sourceMissing, Encoding enc)
    {
        if (project.Problem != null) return (VbaCompiledState.Unverified, project.Problem);
        if (problem != null) return (VbaCompiledState.Unverified, problem);
        if (cache == null || cache.Length == 0 || !project.HasCache) return (VbaCompiledState.Purged, null);
        if (sourceMissing) return (VbaCompiledState.Unverified, "compiled code present, source unreadable");
        var literals = Literals(source, enc);
        if (literals.Count == 0) return (VbaCompiledState.Unverified, "no source string to compare");
        int absent = literals.Count(l => cache.AsSpan().IndexOf(l) < 0);
        return absent == 0
            ? (VbaCompiledState.StringsMatch, $"{literals.Count} source string(s) found in the compiled code; opcodes are not compared")
            : (VbaCompiledState.Differs, $"{absent} of {literals.Count} source string(s) not in the compiled code");
    }

    // Distinct literals of 3 or more characters; attributes, declarations, comments and #If blocks are skipped.
    private static List<byte[]> Literals(string source, Encoding enc)
    {
        var found = new List<byte[]>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        int conditional = 0;
        foreach (var raw in source.Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith("#If ", StringComparison.OrdinalIgnoreCase)) { conditional++; continue; }
            if (line.StartsWith("#End If", StringComparison.OrdinalIgnoreCase)) { if (conditional > 0) conditional--; continue; }
            if (conditional > 0) continue;
            if (line.StartsWith("Attribute ", StringComparison.OrdinalIgnoreCase) || line.StartsWith("Rem ", StringComparison.OrdinalIgnoreCase)
                || line.Contains("Declare ", StringComparison.OrdinalIgnoreCase)) continue;
            var text = new StringBuilder();
            bool inString = false;
            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];
                if (!inString)
                {
                    if (c == '\'') break;
                    if (c == ':' && line.AsSpan(i + 1).TrimStart().StartsWith("Rem ", StringComparison.OrdinalIgnoreCase)) break;
                    if (c == '"') { inString = true; text.Clear(); }
                }
                else if (c == '"')
                {
                    if (i + 1 < line.Length && line[i + 1] == '"') { text.Append('"'); i++; continue; }
                    inString = false;
                    var value = text.ToString();
                    if (value.Length >= 3 && seen.Add(value)) found.Add(enc.GetBytes(value));
                }
                else text.Append(c);
            }
        }
        return found;
    }

    private static Encoding EncodingOf(int cp)
    {
        try { return cp == 65001 ? Encoding.UTF8 : CodePagesEncodingProvider.Instance.GetEncoding(cp) ?? Encoding.GetEncoding(cp); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException) { return Encoding.Latin1; }
    }

    /// <summary>MS-OVBA 2.4.1 decompression of a CompressedContainer; null when it does not start with the signature byte.</summary>
    public static byte[]? Decompress(ReadOnlySpan<byte> src, long max)
    {
        if (src.Length == 0 || src[0] != 1) return null;
        var output = new List<byte>(src.Length * 2);
        int pos = 1;
        while (pos + 2 <= src.Length)
        {
            int header = BinaryPrimitives.ReadUInt16LittleEndian(src[pos..]);
            int chunkEnd = Math.Min(pos + (header & 0x0FFF) + 3, src.Length);
            bool compressed = (header & 0x8000) != 0;
            pos += 2;
            int chunkStart = output.Count;
            if (!compressed)
            {
                int n = Math.Min(4096, src.Length - pos);
                for (int i = 0; i < n; i++) output.Add(src[pos + i]);
                pos += n;
            }
            else
            {
                while (pos < chunkEnd)
                {
                    byte flags = src[pos++];
                    for (int bit = 0; bit < 8 && pos < chunkEnd; bit++)
                    {
                        if ((flags & (1 << bit)) == 0) { output.Add(src[pos++]); continue; }
                        if (pos + 2 > chunkEnd) { pos = chunkEnd; break; }
                        int token = BinaryPrimitives.ReadUInt16LittleEndian(src[pos..]);
                        pos += 2;
                        int difference = output.Count - chunkStart;
                        int bitCount = 4;
                        while ((1 << bitCount) < difference) bitCount++;
                        int lengthMask = 0xFFFF >> bitCount;
                        int length = (token & lengthMask) + 3;
                        int offset = (token >> (16 - bitCount)) + 1;
                        int from = output.Count - offset;
                        // A copy from before the chunk is damage: keep what was read.
                        if (from < chunkStart) return output.ToArray();
                        for (int i = 0; i < length; i++) output.Add(output[from + i]);
                    }
                }
            }
            if (output.Count > max) throw new ToolError(ErrorCode.LimitExceeded, $"VBA source decompresses past the {max:N0}-byte item limit.");
            pos = Math.Max(pos, chunkEnd);
        }
        return [.. output];
    }
}
