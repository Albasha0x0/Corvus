using System.Buffers.Binary;
using System.Text;

namespace Corvus.Tests.Accuracy;

/// <summary>Truth class of a function start; see <see cref="StartScore"/> for how each class is scored.</summary>
public enum TruthClass { Function, Chunk, Thunk }

public sealed record TruthFunction(uint Start, uint Size, string Name, TruthClass Class);

/// <summary>
/// Function truth from an unstripped ELF's .symtab, read here and not with the code under test: FUNC / IFUNC symbols
/// in executable sections (Thumb bit cleared), GCC <c>.cold</c> parts as chunks, PLT sections as thunk ranges.
/// Addresses are RVAs: virtual address minus the lowest PT_LOAD address.
/// </summary>
public sealed class ElfTruth
{
    public required string Arch { get; init; }
    public required ulong Base { get; init; }
    public required IReadOnlyList<TruthFunction> Functions { get; init; }
    public required IReadOnlyList<(uint Start, uint End)> Executable { get; init; }
    public required IReadOnlyList<(uint Start, uint End)> Plt { get; init; }
    /// <summary>PT_LOAD segments: RVA, file offset, file size.</summary>
    public required IReadOnlyList<(uint Rva, ulong Offset, ulong FileSize)> Loads { get; init; }

    /// <summary>File offset of an RVA, or -1 when it has no file bytes.</summary>
    public int FileOffset(uint rva)
    {
        foreach (var (start, offset, size) in Loads)
            if (rva >= start && rva < start + size) return (int)(offset + (rva - start));
        return -1;
    }

    public static ElfTruth Read(string path)
    {
        var d = File.ReadAllBytes(path);
        if (d.Length < 64 || d[0] != 0x7F || d[1] != (byte)'E' || d[2] != (byte)'L' || d[3] != (byte)'F' || d[5] != 1)
            throw new InvalidDataException($"{path}: not a little-endian ELF");
        bool is64 = d[4] == 2;
        ushort machine = U16(d, 18);
        string arch = machine switch { 3 => "x86", 62 => "x64", 183 => "arm64", 40 => "arm32", _ => machine.ToString() };
        ulong phoff = is64 ? U64(d, 32) : U32(d, 28), shoff = is64 ? U64(d, 40) : U32(d, 32);
        int phentsize = U16(d, is64 ? 54 : 42), phnum = U16(d, is64 ? 56 : 44);
        int shentsize = U16(d, is64 ? 58 : 46), shnum = U16(d, is64 ? 60 : 48), shstrndx = U16(d, is64 ? 62 : 50);

        ulong loadBase = ulong.MaxValue;
        var rawLoads = new List<(ulong Vaddr, ulong Offset, ulong FileSize)>();
        for (int i = 0; i < phnum; i++)
        {
            int o = (int)phoff + i * phentsize;
            if (U32(d, o) != 1) continue;
            ulong vaddr = is64 ? U64(d, o + 16) : U32(d, o + 8);
            ulong offset = is64 ? U64(d, o + 8) : U32(d, o + 4);
            ulong filesz = is64 ? U64(d, o + 32) : U32(d, o + 16);
            rawLoads.Add((vaddr, offset, filesz));
            loadBase = Math.Min(loadBase, vaddr);
        }
        if (loadBase == ulong.MaxValue) loadBase = 0;
        var loads = rawLoads.Select(l => ((uint)(l.Vaddr - loadBase), l.Offset, l.FileSize)).ToList();

        var sections = new List<(string Name, uint Type, ulong Flags, ulong Addr, ulong Offset, ulong Size, uint Link)>();
        for (int i = 0; i < shnum; i++)
        {
            int o = (int)shoff + i * shentsize;
            uint name = U32(d, o), type = U32(d, o + 4);
            ulong flags = is64 ? U64(d, o + 8) : U32(d, o + 8);
            ulong addr = is64 ? U64(d, o + 16) : U32(d, o + 12);
            ulong offset = is64 ? U64(d, o + 24) : U32(d, o + 16);
            ulong size = is64 ? U64(d, o + 32) : U32(d, o + 20);
            uint link = U32(d, o + (is64 ? 40 : 24));
            sections.Add((name.ToString(), type, flags, addr, offset, size, link));
        }
        var shstr = sections[shstrndx];
        for (int i = 0; i < sections.Count; i++)
            sections[i] = sections[i] with { Name = CStr(d, (int)shstr.Offset + int.Parse(sections[i].Name)) };

        const ulong ShfAlloc = 2, ShfExec = 4;
        var exec = sections.Where(s => (s.Flags & ShfExec) != 0 && (s.Flags & ShfAlloc) != 0 && s.Type != 8)
            .Select(s => ((uint)(s.Addr - loadBase), (uint)(s.Addr + s.Size - loadBase))).ToList();
        var plt = sections.Where(s => s.Name is ".plt" or ".plt.got" or ".plt.sec" or ".iplt" && s.Size > 0)
            .Select(s => ((uint)(s.Addr - loadBase), (uint)(s.Addr + s.Size - loadBase))).ToList();

        var funcs = new Dictionary<uint, TruthFunction>();
        foreach (var symtab in sections.Where(s => s.Type == 2))
        {
            var strtab = sections[(int)symtab.Link];
            int ent = is64 ? 24 : 16;
            for (ulong k = 0; k < symtab.Size / (ulong)ent; k++)
            {
                int o = (int)(symtab.Offset + k * (ulong)ent);
                uint nameOff = U32(d, o);
                byte info = is64 ? d[o + 4] : d[o + 12];
                ushort shndx = is64 ? U16(d, o + 6) : U16(d, o + 14);
                ulong value = is64 ? U64(d, o + 8) : U32(d, o + 4);
                ulong size = is64 ? U64(d, o + 16) : U32(d, o + 8);
                int type = info & 0xF;
                if (type is not (2 or 10) || shndx == 0) continue;
                if (arch == "arm32") value &= ~1UL;
                uint rva = (uint)(value - loadBase);
                if (!exec.Any(r => rva >= r.Item1 && rva < r.Item2)) continue;
                string name = CStr(d, (int)strtab.Offset + (int)nameOff);
                var cls = plt.Any(r => rva >= r.Item1 && rva < r.Item2) ? TruthClass.Thunk
                    : name.EndsWith(".cold", StringComparison.Ordinal) || name.Contains(".cold.", StringComparison.Ordinal) ? TruthClass.Chunk
                    : TruthClass.Function;
                var f = new TruthFunction(rva, (uint)size, name, cls);
                if (!funcs.TryGetValue(rva, out var cur) || (cur.Size == 0 && size > 0) || (cur.Class != TruthClass.Function && cls == TruthClass.Function))
                    funcs[rva] = f;
            }
        }
        if (funcs.Count == 0) throw new InvalidDataException($"{path}: no .symtab functions");
        return new ElfTruth { Arch = arch, Base = loadBase, Functions = [.. funcs.Values.OrderBy(f => f.Start)], Executable = exec, Plt = plt, Loads = loads };
    }

    private static ushort U16(byte[] d, int o) => BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(o));
    private static uint U32(byte[] d, int o) => BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(o));
    private static ulong U64(byte[] d, int o) => BinaryPrimitives.ReadUInt64LittleEndian(d.AsSpan(o));

    private static string CStr(byte[] d, int o)
    {
        int e = Array.IndexOf(d, (byte)0, o);
        return Encoding.UTF8.GetString(d, o, (e < 0 ? d.Length : e) - o);
    }
}
