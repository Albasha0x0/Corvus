using Corvus.Core;
using Corvus.Core.Archives;
using System.Buffers.Binary;
using Corvus.Native.Elf;
using Corvus.Native.Pe;

namespace Corvus.Native.Diff;

/// <summary>A library function's object-file bytes, with the bytes its relocations rewrite masked out.</summary>
public sealed record LibraryFunction(string Name, string Member, byte[] Bytes, bool[] Fixed)
{
    /// <summary>Bytes no relocation rewrites: the ones a match compares.</summary>
    public int FixedCount { get; } = Fixed.Count(f => f);

    /// <summary>The relative calls and jumps the linker resolves in it.</summary>
    public IReadOnlyList<LibraryCall> Calls { get; init; } = [];

    /// <summary>Other names the object gives the same address.</summary>
    public IReadOnlyList<string> Aliases { get; init; } = [];
}

/// <summary>A rel32 call or jump: field offset, bytes from field end to its base, and the called name.</summary>
public readonly record struct LibraryCall(int Offset, int Extra, string Symbol);

/// <summary>The functions of a static library or object file, and what could not be read, with the reason.</summary>
public sealed record LibrarySignatureSet(string Path, NativeArch Arch, IReadOnlyList<LibraryFunction> Functions, int Members, IReadOnlyList<string> Notes);

/// <summary>A library function placed at a function start of an image.</summary>
public sealed record LibraryMatch(uint Rva, string Name, string Member, int Length, int FixedBytes);

/// <summary>A start left unnamed: several matches (ambiguous) or a call reaching another name (call_target_differs).</summary>
public sealed record LibraryAmbiguity(uint Rva, IReadOnlyList<string> Names, string Reason, string Code = "ambiguous");

/// <summary>Names statically linked library functions from .lib, .a or object files by their unrelocated bytes.</summary>
public static class LibrarySignatures
{
    /// <summary>Fewest fixed bytes a function needs before a match names it: shorter ones match too many places.</summary>
    public const int MinFixedBytes = 16;

    private const int MaxFunctions = 1 << 20;
    private const int KeyLength = 8;

    /// <summary>Every function of the file; skipped members are counted in the notes; throws when it is neither archive nor object.</summary>
    public static LibrarySignatureSet Read(string path, CancellationToken ct)
    {
        var info = new FileInfo(path);
        if (info.Length > PeLimits.MaxFileSize) throw new ToolError(ErrorCode.LimitExceeded, $"{path} is {info.Length:N0} bytes; at most {PeLimits.MaxFileSize:N0} are read.");
        var data = File.ReadAllBytes(path);
        var members = data.AsSpan().StartsWith("!<arch>\n"u8)
            ? ArReader.Members(data, Path.GetFileName(path), ct).Where(m => m.Name is not ("/" or "/SYM64/" or "__.SYMDEF" or "__.SYMDEF SORTED"))
                .Select(m => (m.Name, m.At, m.Size)).ToList()
            : [(Path.GetFileName(path), 0, data.Length)];
        var functions = new List<LibraryFunction>();
        var skipped = new Dictionary<string, int>(StringComparer.Ordinal);
        var arch = NativeArch.Unknown;
        foreach (var (name, at, size) in members)
        {
            ct.ThrowIfCancellationRequested();
            var bytes = data.AsSpan(at, size);
            string? reason;
            (NativeArch Arch, List<LibraryFunction>? Functions) read = (NativeArch.Unknown, null);
            if (bytes.StartsWith("\u007fELF"u8))
            {
                try
                {
                    var elf = ElfFile.FromBytes(bytes, name);
                    read = (elf.Arch, Functions(elf, name, out reason));
                }
                catch (ToolError) { reason = "a malformed ELF object"; }
            }
            else if (CoffObject.Read(bytes, out reason) is { } o) read = (o.Arch, [.. Functions(o, name)]);
            if (read.Functions != null)
            {
                if (arch == NativeArch.Unknown) arch = read.Arch;
                if (read.Arch != arch) reason = $"a {read.Arch} object in a {arch} library";
                else if (functions.Count < MaxFunctions) functions.AddRange(read.Functions);
            }
            if (reason != null) skipped[reason] = skipped.GetValueOrDefault(reason) + 1;
        }
        if (members.Count == 1 && functions.Count == 0 && skipped.Count == 1 && arch == NativeArch.Unknown)
            throw new ToolError(ErrorCode.Unsupported, $"{path} is not a static library or object file: {skipped.Keys.First()}.");
        var notes = skipped.OrderByDescending(s => s.Value).Select(s => $"{s.Value} member(s) skipped: {s.Key}").ToList();
        if (functions.Count >= MaxFunctions) notes.Add($"the first {MaxFunctions:N0} functions are read");
        return new LibrarySignatureSet(path, arch, functions, members.Count, notes);
    }

    // One code section of an object: its bytes, the symbols defined in it and the bytes the linker rewrites.
    private sealed record CodeSection(byte[] Data, List<CodeSymbol> Symbols, List<Fixup> Fixups, bool TrimPadding);

    // A symbol defined in a code section; Size null: up to the next symbol.
    private sealed record CodeSymbol(int Offset, int? Size, string Name, bool IsFunction, bool IsPreferred);

    // Bytes [Offset - Before, Offset - Before + Length) the linker rewrites; a rel32 call or jump also names its callee.
    private readonly record struct Fixup(int Offset, int Before, int Length, int? Extra, string? Callee);

    /// <summary>The functions of one COFF object: each function symbol's bytes to the next symbol in its section or the section end.</summary>
    internal static IEnumerable<LibraryFunction> Functions(CoffObject o, string member)
    {
        var bySymbol = o.Symbols.ToDictionary(y => y.Index);
        foreach (var section in o.Sections.Where(s => s.IsCode && s.Data.Length > 0))
        {
            var symbols = o.Symbols.Where(y => y.Section == section.Number && y.Value < section.Data.Length && y.StorageClass is 2 or 3 && !IsSectionName(y, section))
                .Select(y => new CodeSymbol((int)y.Value, null, Display(y.Name, o.Arch), y.IsFunction, y.IsExternal)).ToList();
            var fixups = section.Relocations.Select(r => new Fixup((int)r.Offset, 0, CoffObject.Width(o.Machine, r.Type), Extra(o.Arch, r.Type),
                bySymbol.TryGetValue(r.Symbol, out var callee) && Callable(callee) ? Display(callee!.Name, o.Arch) : null)).ToList();
            foreach (var f in Functions(new CodeSection(section.Data, symbols, fixups, o.Arch is NativeArch.X64 or NativeArch.X86), member))
                yield return f;
        }
    }

    // A function symbol's bytes (its size, else to the next symbol or the section end), relocated bytes unfixed.
    private static IEnumerable<LibraryFunction> Functions(CodeSection section, string member)
    {
        var starts = section.Symbols.GroupBy(y => y.Offset)
            .Select(g => (Offset: g.Key, First: g.OrderByDescending(y => y.IsFunction).ThenByDescending(y => y.IsPreferred).First(), All: g.ToList()))
            .OrderBy(g => g.Offset).ToList();
        for (int i = 0; i < starts.Count; i++)
        {
            var symbol = starts[i].First;
            if (!symbol.IsFunction) continue;
            int from = symbol.Offset, next = i + 1 < starts.Count ? starts[i + 1].Offset : section.Data.Length;
            int to = symbol.Size is > 0 and var size ? (int)Math.Min((long)from + size, section.Data.Length) : next;
            var mask = new bool[to - from];
            Array.Fill(mask, true);
            foreach (var r in section.Fixups)
                for (int b = r.Offset - r.Before; b < r.Offset - r.Before + r.Length; b++)
                    if (b >= from && b < to) mask[b - from] = false;
            // Alignment padding (int3 or nop) after the last instruction belongs to the section, not the function.
            int end = mask.Length;
            while (section.TrimPadding && end > 0 && mask[end - 1] && section.Data[from + end - 1] is 0xCC or 0x90) end--;
            if (end == 0) continue;
            var calls = section.Fixups.Where(r => r.Extra != null && r.Callee != null && r.Offset >= from && r.Offset + 4 <= from + end)
                .Select(r => new LibraryCall(r.Offset - from, r.Extra!.Value, r.Callee!)).ToList();
            var aliases = starts[i].All.Where(y => y != symbol && y.IsFunction).Select(y => y.Name).Where(n => n != symbol.Name).Distinct().ToList();
            yield return new LibraryFunction(symbol.Name, member, section.Data[from..(from + end)], mask[..end]) { Calls = calls, Aliases = aliases };
        }
    }

    /// <summary>The functions of a little-endian x86, x64 or AArch64 relocatable ELF object; null with <paramref name="reason"/> otherwise.</summary>
    internal static List<LibraryFunction>? Functions(ElfFile elf, string member, out string? reason)
    {
        reason = elf.Type != 1 ? $"an ELF {elf.TypeName}, not a relocatable object"
            : elf.BigEndian || elf.Arch is not (NativeArch.X64 or NativeArch.X86 or NativeArch.Arm64) ? $"an ELF object for {elf.MachineName} (not read)" : null;
        if (reason != null) return null;
        var file = elf.FileBytes;
        var data = file.Span;
        var symbols = elf.StaticSymbols;
        var relocations = elf.SectionHeaders.Where(h => h.Type is 4 or 9 && h.Info < elf.SectionHeaders.Count).ToLookup(h => (int)h.Info);
        var result = new List<LibraryFunction>();
        // SHT_PROGBITS with SHF_EXECINSTR.
        foreach (var section in elf.SectionHeaders.Where(h => h.Type == 1 && (h.Flags & 4) != 0 && h.Size > 0 && Within(h, file.Length)))
        {
            var bytes = data.Slice((int)section.Offset, (int)section.Size).ToArray();
            var defined = symbols.Where(y => y.SectionIndex == section.Index && y.Value < section.Size && y.Name.Length > 0
                && y.Type is ElfSymbol.TypeFunction or ElfSymbol.TypeIndirectFunction or ElfSymbol.TypeNone or ElfSymbol.TypeObject)
                .Select(y => new CodeSymbol((int)y.Value, y.IsFunction && y.Size > 0 ? (int)Math.Min(y.Size, section.Size) : null, y.Name, y.IsFunction,
                    y.Binding != ElfSymbol.BindLocal)).ToList();
            var fixups = new List<Fixup>();
            foreach (var table in relocations[section.Index])
                foreach (var (offset, type, symbolIndex, addend) in ElfRelocations(data, table, elf.Is64Bit))
                {
                    if (type == 0 || offset >= section.Size) continue;
                    var (before, length) = ElfRewrites(elf.Arch, type);
                    int at = (int)offset;
                    long a = addend ?? (at + 4 <= bytes.Length ? BitConverter.ToInt32(bytes, at) : 0);
                    var callee = symbolIndex > 0 && symbolIndex < symbols.Count && symbols[symbolIndex] is var y && y.Name.Length > 0
                        && (y.IsFunction || !y.IsDefined && y.Type == ElfSymbol.TypeNone) ? y.Name : null;
                    // R_X86_64_PC32, R_X86_64_PLT32, R_386_PC32, R_386_PLT32: S = P + field - A.
                    int? extra = elf.Arch is NativeArch.X64 or NativeArch.X86 && type is 2 or 4 ? (int)(-a - 4) : null;
                    fixups.Add(new Fixup(at, before, length, extra, callee));
                }
            result.AddRange(Functions(new CodeSection(bytes, defined, fixups, elf.Arch is NativeArch.X64 or NativeArch.X86), member));
        }
        return result;
    }

    // Named as the PDB layer names them: decorated names undecorated to their qualified name.
    private static string Display(string symbol, NativeArch arch)
    {
        var name = Pdb.PdbNaming.Display(symbol);
        // i386 C names carry a leading underscore the PDB and the image's own symbols drop.
        return name == symbol && arch == NativeArch.X86 && name.Length > 1 && name[0] == '_' ? name[1..] : name;
    }

    // A function name a call can reach: not a section, label or import address table slot.
    private static bool Callable(CoffSymbol y) => (y.IsExternal || y.IsFunction) && y.Name.Length > 0 && y.Name[0] is not ('.' or '$')
        && !y.Name.StartsWith("__imp_", StringComparison.Ordinal);

    // Bytes between a rel32 field's end and the address it is relative to; null for other relocations.
    // IMAGE_REL_AMD64_REL32 to REL32_5 (4-9) and IMAGE_REL_I386_REL32 (0x14).
    private static int? Extra(NativeArch arch, ushort type) => arch switch
    {
        NativeArch.X64 when type is >= 4 and <= 9 => type - 4,
        NativeArch.X86 when type == 0x14 => 0,
        _ => null,
    };

    // A section symbol (storage STATIC, value 0) carries its section's name.
    private static bool IsSectionName(CoffSymbol y, CoffSection s) => y.StorageClass == 3 && y.Value == 0 && !y.IsFunction && y.Name == s.Name;

    // Entries of a SHT_RELA (explicit addend) or SHT_REL table: offset, type, symbol index, addend (null: in the field).
    private static IEnumerable<(ulong Offset, uint Type, int Symbol, long? Addend)> ElfRelocations(ReadOnlySpan<byte> data, ElfSection table, bool is64)
    {
        bool rela = table.Type == 4;
        int least = (is64 ? 8 : 4) * (rela ? 3 : 2);
        int size = table.EntrySize is var e && e >= (ulong)least && e <= 64 ? (int)e : least;
        if (!Within(table, data.Length)) return [];
        var entries = new List<(ulong, uint, int, long?)>();
        var span = data.Slice((int)table.Offset, (int)table.Size);
        for (int at = 0; at + size <= span.Length; at += size)
        {
            if (is64)
            {
                ulong info = BinaryPrimitives.ReadUInt64LittleEndian(span[(at + 8)..]);
                entries.Add((BinaryPrimitives.ReadUInt64LittleEndian(span[at..]), (uint)info, (int)(info >> 32), rela ? BinaryPrimitives.ReadInt64LittleEndian(span[(at + 16)..]) : null));
            }
            else
            {
                uint info = BinaryPrimitives.ReadUInt32LittleEndian(span[(at + 4)..]);
                entries.Add((BinaryPrimitives.ReadUInt32LittleEndian(span[at..]), info & 0xFF, (int)(info >> 8), rela ? BinaryPrimitives.ReadInt32LittleEndian(span[(at + 8)..]) : null));
            }
        }
        return entries;
    }

    // The section's bytes lie in the file (no wrap past 2^64).
    private static bool Within(ElfSection h, int fileLength) => h.Offset <= (ulong)fileLength && h.Size <= (ulong)fileLength - h.Offset;

    // Bytes a relocation and the linker's relaxation of it rewrite: from Before bytes ahead of its field, Length bytes.
    // GOTPCRELX and TLS models let the linker rewrite opcodes ahead of the field (x86-64 and i386 psABI).
    private static (int Before, int Length) ElfRewrites(NativeArch arch, uint type) => arch switch
    {
        NativeArch.X64 => type switch
        {
            1 or 24 or 25 or 33 => (0, 8),
            12 or 13 => (0, 2),
            14 or 15 => (0, 1),
            // R_X86_64_TLSGD: the 16-byte call sequence; TLSLD: 12 bytes.
            19 => (4, 16),
            20 => (3, 12),
            // GOTTPOFF, GOTPC32_TLSDESC, REX_GOTPCRELX: REX, opcode and ModRM; GOTPCRELX: opcode and ModRM.
            22 or 34 or 42 => (3, 7),
            41 => (2, 6),
            35 => (0, 2),
            _ => (0, 4),
        },
        NativeArch.X86 => type switch
        {
            20 or 21 => (0, 2),
            22 or 23 => (0, 1),
            // R_386_TLS_GD: 12-byte sequence; TLS_LDM: 11; TLS_IE: opcode; TLS_GOTIE and GOT32X: opcode and ModRM.
            18 => (3, 12),
            19 => (2, 11),
            15 => (1, 5),
            16 or 43 => (2, 6),
            _ => (0, 4),
        },
        // AArch64: ABS64 and PREL64 are data; every other relocation rewrites its 4-byte instruction.
        _ => type switch { 257 or 260 => (0, 8), 259 or 262 => (0, 2), _ => (0, 4) },
    };

    /// <summary>Library functions at <paramref name="starts"/>; functions under <see cref="MinFixedBytes"/> or past the next start are unused; ambiguous matches and calls reaching another name are refused.</summary>
    public static (List<LibraryMatch> Matches, List<LibraryAmbiguity> Ambiguous) Match(LibrarySignatureSet set, INativeImage image, IEnumerable<uint> starts,
        Func<uint, string?>? nameAt, CancellationToken ct)
    {
        var usable = set.Functions.Where(f => f.FixedCount >= MinFixedBytes).ToList();
        // Functions whose first bytes are all fixed are found by those bytes; the rest are compared at every start.
        var keyed = new Dictionary<ulong, List<LibraryFunction>>();
        var unkeyed = new List<LibraryFunction>();
        foreach (var f in usable)
        {
            if (f.Bytes.Length >= KeyLength && f.Fixed.AsSpan(0, KeyLength).IndexOf(false) < 0)
                (keyed.TryGetValue(Key(f.Bytes), out var list) ? list : keyed[Key(f.Bytes)] = []).Add(f);
            else unkeyed.Add(f);
        }
        int longest = usable.Count == 0 ? 0 : usable.Max(f => f.Bytes.Length);
        var window = new byte[longest];
        var found = new Dictionary<uint, List<LibraryFunction>>();
        var sorted = starts.Distinct().Order().ToArray();
        for (int i = 0; i < sorted.Length; i++)
        {
            ct.ThrowIfCancellationRequested();
            uint rva = sorted[i];
            int read = image.Read(rva, window);
            // A function's bytes end before the next start: a longer one only shares this function's first bytes.
            if (i + 1 < sorted.Length && sorted[i + 1] - rva < (uint)read) read = (int)(sorted[i + 1] - rva);
            if (read < KeyLength) continue;
            var span = window.AsSpan(0, read);
            var candidates = keyed.TryGetValue(Key(span), out var list) ? list.Concat(unkeyed) : unkeyed;
            foreach (var f in candidates)
                if (Equal(f, span)) (found.TryGetValue(rva, out var at) ? at : found[rva] = []).Add(f);
        }
        var matches = new List<LibraryMatch>();
        var ambiguous = new List<LibraryAmbiguity>();
        var chosen = new Dictionary<uint, List<LibraryFunction>>();
        var sites = found.SelectMany(p => p.Value.Select(f => (f.Name, p.Key))).GroupBy(x => x.Name).ToDictionary(g => g.Key, g => g.Select(x => x.Key).Distinct().Count());
        foreach (var (rva, fs) in found.OrderBy(p => p.Key))
        {
            var names = fs.Select(f => f.Name).Distinct(StringComparer.Ordinal).ToList();
            if (names.Count > 1) { ambiguous.Add(new LibraryAmbiguity(rva, names, "several library functions have these bytes")); continue; }
            if (sites[names[0]] > 1) { ambiguous.Add(new LibraryAmbiguity(rva, names, $"the function's bytes are at {sites[names[0]]} starts")); continue; }
            var best = fs.MaxBy(f => f.FixedCount)!;
            matches.Add(new LibraryMatch(rva, best.Name, best.Member, best.Bytes.Length, best.FixedCount));
            chosen[rva] = fs;
        }
        // Masked call targets make functions that differ only in their callees look alike, so each call must reach a
        // function of its own name; image names are checked first, to a fixed point, then this set's placements.
        var canonical = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var f in set.Functions)
            foreach (var n in f.Aliases.Prepend(f.Name)) canonical.TryAdd(Spaceless(n), Spaceless(f.Name));
        string Canon(string name) => canonical.TryGetValue(Spaceless(name), out var c) ? c : Spaceless(name);
        var field = new byte[4];
        foreach (bool own in new[] { false, true })
        {
            for (bool changed = true; changed;)
            {
                changed = false;
                var byRva = matches.ToDictionary(m => m.Rva);
                string? Conflict(uint rva, LibraryCall c)
                {
                    if (image.Read(rva + (uint)c.Offset, field) < 4) return null;
                    uint target = rva + (uint)c.Offset + 4 + (uint)c.Extra + (uint)BitConverter.ToInt32(field);
                    var want = Canon(c.Symbol);
                    if (nameAt?.Invoke(target) is { } known && Canon(known) != want) return $"its call to '{c.Symbol}' reaches '{known}'";
                    // Only a named target is evidence: calls through PLT, IFUNC and import stubs reach other addresses.
                    if (!own) return null;
                    return byRva.TryGetValue(target, out var other) && Canon(other.Name) != want ? $"its call to '{c.Symbol}' reaches '{other.Name}'" : null;
                }
                foreach (var m in matches.ToList())
                {
                    ct.ThrowIfCancellationRequested();
                    // Objects can define one name with alike bytes (narrow and wide variants): one consistent variant keeps it.
                    var conflicts = chosen[m.Rva].Select(f => f.Calls.Select(c => Conflict(m.Rva, c)).FirstOrDefault(x => x != null)).ToList();
                    if (conflicts.Any(x => x == null)) continue;
                    matches.Remove(m);
                    ambiguous.Add(new LibraryAmbiguity(m.Rva, [m.Name], conflicts[0]!, "call_target_differs"));
                    changed = true;
                }
            }
        }
        return (matches, ambiguous);
    }

    // Demanglers differ in the spaces inside template argument lists.
    private static string Spaceless(string name) => name.Replace(" ", "", StringComparison.Ordinal);

    private static bool Equal(LibraryFunction f, ReadOnlySpan<byte> code)
    {
        if (code.Length < f.Bytes.Length) return false;
        for (int i = 0; i < f.Bytes.Length; i++)
            if (f.Fixed[i] && f.Bytes[i] != code[i]) return false;
        return true;
    }

    private static ulong Key(ReadOnlySpan<byte> bytes) => System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(bytes);
}
