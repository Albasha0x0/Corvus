using System.Buffers.Binary;
using System.Text;

namespace Corvus.Native.Dwarf;

/// <summary>A function or variable of a debug map object with its address in the linked image (and a function's size).</summary>
internal readonly record struct DebugMapSymbol(string Name, ulong Address, ulong Size);

/// <summary>One object file of a Mach-O debug map: its N_OSO path and time stamp, and its symbols' final addresses.</summary>
internal sealed record DebugMapObject(string Path, ulong ModTime, List<DebugMapSymbol> Symbols);

/// <summary>A Mach-O symbol table entry (nlist).</summary>
internal readonly record struct MachONlist(string Name, byte Type, byte Section, ulong Value)
{
    public bool IsStab => (Type & 0xE0) != 0;
    public bool IsDefinedInSection => !IsStab && (Type & 0x0E) == 0x0E;
}

/// <summary>The STABS debug map of a Mach-O image without a dSYM: each object file (N_OSO) and its symbols' final addresses.</summary>
internal static class MachODebugMap
{
    private const int MaxSymbols = 1 << 22;
    private const byte NGsym = 0x20, NFun = 0x24, NStsym = 0x26, NLcsym = 0x28, NSo = 0x64, NOso = 0x66;

    /// <summary>The LC_SYMTAB entries of a Mach-O file; empty when it has none.</summary>
    public static List<MachONlist> Symbols(DebugContainer file)
    {
        var result = new List<MachONlist>();
        if (file.Format != ImageFormat.MachO) return result;
        bool be = file.BigEndian, is64 = file.Is64;
        uint U32(byte[] b, int at) => at + 4 > b.Length ? 0 : be ? BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(at)) : BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(at));
        ulong U64(byte[] b, int at) => at + 8 > b.Length ? 0 : be ? BinaryPrimitives.ReadUInt64BigEndian(b.AsSpan(at)) : BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(at));
        var header = file.ReadAt(0, 32);
        int ncmds = (int)U32(header, 16), sizeofcmds = (int)Math.Min(U32(header, 20), 64u << 20);
        var cmds = file.ReadAt(is64 ? 32 : 28, sizeofcmds);
        for (int i = 0, at = 0; i < ncmds && at + 8 <= cmds.Length; i++)
        {
            uint cmd = U32(cmds, at), size = U32(cmds, at + 4);
            if (size < 8) break;
            if (cmd == 0x2 && size >= 24)
            {
                uint symoff = U32(cmds, at + 8), nsyms = Math.Min(U32(cmds, at + 12), MaxSymbols), stroff = U32(cmds, at + 16), strsize = U32(cmds, at + 20);
                int entry = is64 ? 16 : 12;
                var table = file.ReadAt(symoff, (int)Math.Min((long)nsyms * entry, int.MaxValue));
                var strings = file.ReadAt(stroff, (int)Math.Min(strsize, 256u << 20));
                for (int k = 0; (k + 1) * entry <= table.Length; k++)
                {
                    int e = k * entry;
                    int strx = (int)U32(table, e);
                    string name = "";
                    if (strx > 0 && strx < strings.Length)
                    {
                        int z = Array.IndexOf(strings, (byte)0, strx);
                        name = Encoding.UTF8.GetString(strings, strx, (z < 0 ? strings.Length : z) - strx);
                    }
                    result.Add(new MachONlist(name, table[e + 4], table[e + 5], is64 ? U64(table, e + 8) : U32(table, e + 8)));
                }
                break;
            }
            at += (int)size;
        }
        return result;
    }

    /// <summary>The debug map of <paramref name="image"/>: each object file and its symbols, in the order the linker wrote them.</summary>
    public static List<DebugMapObject> Read(DebugContainer image)
    {
        var symbols = Symbols(image);
        var defined = new Dictionary<string, ulong>(StringComparer.Ordinal);
        foreach (var s in symbols) if (s.IsDefinedInSection) defined.TryAdd(s.Name, s.Value);
        var objects = new List<DebugMapObject>();
        DebugMapObject? current = null;
        (string Name, ulong Address)? function = null;
        foreach (var s in symbols)
        {
            if (!s.IsStab) continue;
            switch (s.Type)
            {
                case NOso:
                    objects.Add(current = new DebugMapObject(s.Name, s.Value, []));
                    break;
                case NSo when s.Name.Length == 0:
                    current = null;
                    break;
                case NFun when current != null:
                    if (s.Name.Length > 0) function = (s.Name, s.Value);
                    else if (function is { } f) { current.Symbols.Add(new DebugMapSymbol(f.Name, f.Address, s.Value)); function = null; }
                    break;
                case NStsym or NLcsym when current != null && s.Name.Length > 0:
                    current.Symbols.Add(new DebugMapSymbol(s.Name, s.Value, 0));
                    break;
                case NGsym when current != null && s.Name.Length > 0:
                    ulong address = s.Value != 0 ? s.Value : defined.GetValueOrDefault(s.Name);
                    if (address != 0) current.Symbols.Add(new DebugMapSymbol(s.Name, address, 0));
                    break;
            }
        }
        return objects;
    }

    /// <summary>The object file of <paramref name="entry"/>: its recorded path, else by name beside the image; an archive member is not read.</summary>
    public static (string? Path, string? Problem) Find(DebugMapObject entry, string imagePath)
    {
        if (entry.Path.EndsWith(')') && entry.Path.Contains(".a(", StringComparison.Ordinal))
            return (null, $"{entry.Path}: an archive member (static library); not read");
        string? refused = null;
        var candidates = new List<string>();
        if (Corvus.Core.InputFiles.NamedProblem(entry.Path) is { } why) refused = $"{entry.Path}: {why}";
        else candidates.Add(entry.Path);
        var last = entry.Path.Replace('\\', '/').Split('/')[^1];
        if (Path.GetDirectoryName(imagePath) is { Length: > 0 } dir && Corvus.Core.InputFiles.IsPlainName(last)) candidates.Add(Path.Combine(dir, last));
        foreach (var c in candidates)
        {
            if (!File.Exists(c)) continue;
            ulong stamp = (ulong)new DateTimeOffset(File.GetLastWriteTimeUtc(c)).ToUnixTimeSeconds();
            if (entry.ModTime != 0 && stamp != entry.ModTime) return (null, $"{c}: modified after the link (time stamp {stamp}, the debug map records {entry.ModTime}); not read");
            return (c, null);
        }
        return (null, refused ?? $"{entry.Path}: not found");
    }
}

/// <summary>Maps one debug map object's addresses to image addresses, each symbol's extent moved to its final address.</summary>
internal sealed class DebugAddressMap
{
    private readonly (ulong From, ulong To, ulong Size)[] _forward, _back;

    private DebugAddressMap((ulong, ulong, ulong)[] forward)
    {
        _forward = forward;
        _back = [.. forward.Select(e => (e.Item2, e.Item1, e.Item3)).OrderBy(e => e.Item1)];
    }

    public int Count => _forward.Length;

    public static DebugAddressMap Build(DebugMapObject entry, IReadOnlyList<MachONlist> objectSymbols)
    {
        var local = objectSymbols.Where(s => s.IsDefinedInSection).GroupBy(s => s.Name, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.First().Value, StringComparer.Ordinal);
        var starts = local.Values.Distinct().Order().ToArray();
        var entries = new List<(ulong, ulong, ulong)>();
        foreach (var s in entry.Symbols)
        {
            if (!local.TryGetValue(s.Name, out ulong from)) continue;
            ulong size = s.Size;
            if (size == 0)
            {
                int i = Array.BinarySearch(starts, from);
                size = i >= 0 && i + 1 < starts.Length ? starts[i + 1] - from : 1;
            }
            entries.Add((from, s.Address, size));
        }
        return new DebugAddressMap([.. entries.OrderBy(e => e.Item1)]);
    }

    /// <summary>The image address of object address <paramref name="address"/>, or null outside every mapped symbol.</summary>
    public ulong? Forward(ulong address) => Find(_forward, address);

    /// <summary>The object address of image address <paramref name="address"/>, or null.</summary>
    public ulong? Back(ulong address) => Find(_back, address);

    private static ulong? Find((ulong From, ulong To, ulong Size)[] table, ulong address)
    {
        int lo = 0, hi = table.Length - 1, best = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (table[mid].From <= address) { best = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        return best >= 0 && address - table[best].From < Math.Max(table[best].Size, 1) ? table[best].To + (address - table[best].From) : null;
    }
}
