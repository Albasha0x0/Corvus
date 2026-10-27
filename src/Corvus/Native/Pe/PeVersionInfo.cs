using System.Buffers.Binary;
using System.Text;

namespace Corvus.Native.Pe;

/// <summary>VS_FIXEDFILEINFO; versions are (MS &lt;&lt; 32) | LS.</summary>
public sealed record PeFixedFileInfo(
    uint StructVersion,
    ulong FileVersion,
    ulong ProductVersion,
    uint FileFlagsMask,
    uint FileFlags,
    uint FileOs,
    uint FileType,
    uint FileSubtype,
    ulong FileDate)
{
    public string FileVersionText => Dotted(FileVersion);
    public string ProductVersionText => Dotted(ProductVersion);

    private static string Dotted(ulong v) => $"{v >> 48}.{(v >> 32) & 0xFFFF}.{(v >> 16) & 0xFFFF}.{v & 0xFFFF}";
}

/// <summary>A StringTable of StringFileInfo: its key (language and code page as 8 hex digits) and strings in order.</summary>
public sealed record PeVersionStringTable(string Key, IReadOnlyList<KeyValuePair<string, string>> Strings);

/// <summary>A decoded VS_VERSIONINFO resource.</summary>
public sealed record PeVersionInfo(PeFixedFileInfo? Fixed, IReadOnlyList<PeVersionStringTable> StringTables, IReadOnlyList<uint> Translations)
{
    /// <summary>The value of <paramref name="key"/> in the first string table that has it.</summary>
    public string? Get(string key)
    {
        foreach (var table in StringTables)
            foreach (var (k, v) in table.Strings)
                if (string.Equals(k, key, StringComparison.OrdinalIgnoreCase)) return v;
        return null;
    }

    private readonly record struct Block(int Start, int End, int ValueLength, int Type, string Key, int ValueStart, int ChildrenStart);

    /// <summary>Parses the version block tree; a damaged block ends its parent's walk and keeps what was read.</summary>
    internal static PeVersionInfo? Parse(byte[] b, IssueLog log)
    {
        int blocks = 0;
        if (!TryBlock(b, 0, b.Length, out var root))
        {
            log.Add("version resource has no readable VS_VERSIONINFO block");
            return null;
        }
        if (root.Key != "VS_VERSION_INFO") log.Add($"version resource root key is '{root.Key}', not VS_VERSION_INFO");
        PeFixedFileInfo? fixedInfo = null;
        if (root.ValueLength >= 52 && root.ValueStart + 52 <= root.End)
        {
            int v = root.ValueStart;
            uint U(int at) => BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(v + at));
            if (U(0) == 0xFEEF04BD)
                fixedInfo = new PeFixedFileInfo(U(4), (ulong)U(8) << 32 | U(12), (ulong)U(16) << 32 | U(20), U(24), U(28), U(32), U(36), U(40),
                    (ulong)U(44) << 32 | U(48));
            else log.Add($"VS_FIXEDFILEINFO signature is 0x{U(0):X8}, not 0xFEEF04BD");
        }

        var tables = new List<PeVersionStringTable>();
        var translations = new List<uint>();
        foreach (var child in Children(b, root, log, ref blocks))
        {
            if (child.Key == "StringFileInfo")
            {
                foreach (var table in Children(b, child, log, ref blocks))
                {
                    var strings = new List<KeyValuePair<string, string>>();
                    foreach (var s in Children(b, table, log, ref blocks))
                        strings.Add(new(s.Key, s.ValueLength == 0 ? "" : Utf16Z(b, s.ValueStart, s.End)));
                    tables.Add(new PeVersionStringTable(table.Key, strings));
                }
            }
            else if (child.Key == "VarFileInfo")
            {
                foreach (var v in Children(b, child, log, ref blocks))
                {
                    if (v.Key != "Translation") continue;
                    int end = Math.Min(v.ValueStart + v.ValueLength, v.End);
                    for (int at = v.ValueStart; at + 4 <= end; at += 4) translations.Add(BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(at)));
                }
            }
        }
        return new PeVersionInfo(fixedInfo, tables, translations);
    }

    private static List<Block> Children(byte[] b, Block parent, IssueLog log, ref int blocks)
    {
        var result = new List<Block>();
        int at = parent.ChildrenStart;
        while (at + 6 <= parent.End)
        {
            if (++blocks > PeLimits.MaxVersionBlocks)
            {
                if (blocks == PeLimits.MaxVersionBlocks + 1) log.Add($"more than {PeLimits.MaxVersionBlocks} version blocks; the rest are not read");
                break;
            }
            if (!TryBlock(b, at, parent.End, out var child))
            {
                log.Add($"damaged version block at offset 0x{at:X} inside '{parent.Key}'");
                break;
            }
            result.Add(child);
            at = Align4(child.End);
        }
        return result;
    }

    private static bool TryBlock(byte[] b, int at, int limit, out Block block)
    {
        block = default;
        if (at < 0 || at + 6 > limit) return false;
        int length = BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(at));
        if (length < 6) return false;
        int end = Math.Min(at + length, limit);
        int valueLength = BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(at + 2));
        int type = BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(at + 4));
        int keyStart = at + 6, keyEnd = keyStart;
        while (keyEnd + 2 <= end && (b[keyEnd] | b[keyEnd + 1]) != 0) keyEnd += 2;
        string key = Encoding.Unicode.GetString(b, keyStart, keyEnd - keyStart);
        int valueStart = Math.Min(Align4(keyEnd + 2), end);
        int valueBytes = type == 1 ? valueLength * 2 : valueLength;
        int childrenStart = Math.Min(Align4(valueStart + valueBytes), end);
        block = new Block(at, end, valueLength, type, key, valueStart, childrenStart);
        return true;
    }

    private static string Utf16Z(byte[] b, int start, int end)
    {
        int at = start;
        while (at + 2 <= end && (b[at] | b[at + 1]) != 0) at += 2;
        return Encoding.Unicode.GetString(b, start, at - start);
    }

    private static int Align4(int v) => (v + 3) & ~3;
}
