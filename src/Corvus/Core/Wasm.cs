using System.Text;

namespace Corvus.Core;

/// <summary>A WebAssembly import or export: module (imports), name and kind (func, table, memory, global, tag).</summary>
public sealed record WasmSymbol(string? Module, string Name, string Kind);

/// <summary>
/// A WebAssembly module's structure, read without running it: sections, imports, exports, memories, function counts,
/// custom sections (the name section's function names and the producers section's toolchain). Malformed input gives
/// issues and what was read before them, never an exception.
/// </summary>
public sealed class WasmModule
{
    public int Version { get; private set; }
    public List<(string Name, int Size)> Sections { get; } = [];
    public List<WasmSymbol> Imports { get; } = [];
    public List<WasmSymbol> Exports { get; } = [];
    public int DefinedFunctions { get; private set; }
    public int Globals { get; private set; }
    public List<(ulong Min, ulong? Max)> Memories { get; } = [];
    public int DataSegments { get; private set; }
    public Dictionary<uint, string> FunctionNames { get; } = [];
    /// <summary>producers section: field (language, processed-by, sdk) to "name version" values.</summary>
    public List<(string Field, string Value)> Producers { get; } = [];
    public List<string> Issues { get; } = [];

    private const int MaxItems = 100_000;

    public static bool IsWasm(ReadOnlySpan<byte> b) => b.Length >= 8 && b[..4].SequenceEqual("\0asm"u8);

    public static WasmModule Read(byte[] data)
    {
        var m = new WasmModule();
        if (!IsWasm(data)) { m.Issues.Add("no \\0asm magic"); return m; }
        m.Version = BitConverter.ToInt32(data, 4);
        int p = 8;
        while (p < data.Length)
        {
            int start = p;
            byte id = data[p++];
            if (!Leb(data, data.Length, ref p, out ulong size) || (ulong)(data.Length - p) < size) { m.Issues.Add($"section at 0x{start:X} runs past the end"); break; }
            int end = p + (int)size;
            try { m.Section(id, data, p, end); }
            catch (FormatException ex) { m.Issues.Add($"section {id} at 0x{start:X}: {ex.Message}"); }
            p = end;
        }
        return m;
    }

    private static readonly string[] Names = ["custom", "type", "import", "function", "table", "memory", "global", "export", "start", "element", "code", "data", "datacount", "tag"];
    private static string KindName(byte k) => k switch { 0 => "func", 1 => "table", 2 => "memory", 3 => "global", 4 => "tag", _ => $"kind {k}" };

    private void Section(byte id, byte[] d, int p, int end)
    {
        string name = id < Names.Length ? Names[id] : $"id {id}";
        if (id == 0)
        {
            name = Str(d, ref p, end);
            if (name == "name") NameSection(d, p, end);
            else if (name == "producers") ProducersSection(d, p, end);
        }
        Sections.Add((name, end - p));
        switch (id)
        {
            case 2:
                for (ulong i = 0, n = Count(d, ref p, end); i < n; i++)
                {
                    var module = Str(d, ref p, end);
                    var field = Str(d, ref p, end);
                    byte kind = Byte(d, ref p, end);
                    Imports.Add(new WasmSymbol(module, field, KindName(kind)));
                    SkipImportType(d, ref p, end, kind);
                }
                break;
            case 3: DefinedFunctions = (int)Count(d, ref p, end); break;
            case 5:
                for (ulong i = 0, n = Count(d, ref p, end); i < n; i++) Memories.Add(Limits(d, ref p, end));
                break;
            case 6: Globals = (int)Count(d, ref p, end); break;
            case 7:
                for (ulong i = 0, n = Count(d, ref p, end); i < n; i++)
                {
                    var field = Str(d, ref p, end);
                    byte kind = Byte(d, ref p, end);
                    U(d, ref p, end);
                    Exports.Add(new WasmSymbol(null, field, KindName(kind)));
                }
                break;
            case 11: DataSegments = (int)Count(d, ref p, end); break;
        }
    }

    private void NameSection(byte[] d, int p, int end)
    {
        while (p < end)
        {
            byte sub = Byte(d, ref p, end);
            int size = (int)U(d, ref p, end), next = p + size;
            if (next > end || next < p) throw new FormatException("name subsection runs past its section");
            if (sub == 1)
                for (ulong i = 0, n = Count(d, ref p, next); i < n; i++)
                {
                    uint index = (uint)U(d, ref p, next);
                    FunctionNames[index] = Str(d, ref p, next);
                }
            p = next;
        }
    }

    private void ProducersSection(byte[] d, int p, int end)
    {
        for (ulong i = 0, n = Count(d, ref p, end); i < n; i++)
        {
            var field = Str(d, ref p, end);
            for (ulong j = 0, m = Count(d, ref p, end); j < m; j++)
            {
                var name = Str(d, ref p, end);
                var version = Str(d, ref p, end);
                Producers.Add((field, version.Length > 0 ? $"{name} {version}" : name));
            }
        }
    }

    private static void SkipImportType(byte[] d, ref int p, int end, byte kind)
    {
        switch (kind)
        {
            case 0: U(d, ref p, end); break;                            // type index
            case 1: Byte(d, ref p, end); Limits(d, ref p, end); break;  // reftype, limits
            case 2: Limits(d, ref p, end); break;
            case 3: Byte(d, ref p, end); Byte(d, ref p, end); break;    // valtype, mutability
            case 4: Byte(d, ref p, end); U(d, ref p, end); break;       // attribute, type index
            default: throw new FormatException($"unknown import kind {kind}");
        }
    }

    private static (ulong, ulong?) Limits(byte[] d, ref int p, int end)
    {
        byte flags = Byte(d, ref p, end);
        ulong min = U(d, ref p, end);
        return (min, (flags & 1) != 0 ? U(d, ref p, end) : null);
    }

    private static ulong Count(byte[] d, ref int p, int end)
    {
        ulong n = U(d, ref p, end);
        if (n > MaxItems) throw new FormatException($"{n} items exceed the {MaxItems:N0} read");
        return n;
    }

    private static byte Byte(byte[] d, ref int p, int end) => p < end ? d[p++] : throw new FormatException("unexpected end");

    private static ulong U(byte[] d, ref int p, int end) =>
        p < end && Leb(d, end, ref p, out var v) ? v : throw new FormatException("bad LEB128");

    private static string Str(byte[] d, ref int p, int end)
    {
        int length = (int)U(d, ref p, end);
        if (length < 0 || length > end - p) throw new FormatException("string runs past its section");
        var s = Encoding.UTF8.GetString(d, p, length);
        p += length;
        return s;
    }

    private static bool Leb(byte[] d, int end, ref int p, out ulong value)
    {
        value = 0;
        for (int shift = 0; shift < 64 && p < end; shift += 7)
        {
            byte b = d[p++];
            value |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0) return true;
        }
        return false;
    }
}
