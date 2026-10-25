using Corvus.Core;
using Corvus.Core.Archives;
using Corvus.Native.Pe;

namespace Corvus.Native.Diff;

/// <summary>
/// A library function as its object file holds it: its bytes up to the next function or the section end, with the
/// bytes its relocations rewrite masked out (the linker fills them per image).
/// </summary>
public sealed record LibraryFunction(string Name, string Member, byte[] Bytes, bool[] Fixed)
{
    /// <summary>Bytes no relocation rewrites: the ones a match compares.</summary>
    public int FixedCount { get; } = Fixed.Count(f => f);

    /// <summary>The relative calls and jumps the linker resolves in it.</summary>
    public IReadOnlyList<LibraryCall> Calls { get; init; } = [];

    /// <summary>Other names the object gives the same address.</summary>
    public IReadOnlyList<string> Aliases { get; init; } = [];
}

/// <summary>
/// A relative call or jump to a named function: the 32-bit field's offset in the function, the bytes between the
/// field's end and the address it is relative to, and the called name.
/// </summary>
public readonly record struct LibraryCall(int Offset, int Extra, string Symbol);

/// <summary>The functions of a static library or object file, and what could not be read, with the reason.</summary>
public sealed record LibrarySignatureSet(string Path, NativeArch Arch, IReadOnlyList<LibraryFunction> Functions, int Members, IReadOnlyList<string> Notes);

/// <summary>A library function placed at a function start of an image.</summary>
public sealed record LibraryMatch(uint Rva, string Name, string Member, int Length, int FixedBytes);

/// <summary>
/// A start no name is given to: more than one library function matches it or a library function matches several
/// starts (code ambiguous), or a call in the function reaches a function of another name (call_target_differs).
/// </summary>
public sealed record LibraryAmbiguity(uint Rva, IReadOnlyList<string> Names, string Reason, string Code = "ambiguous");

/// <summary>
/// Names statically linked library functions in an image from the library files themselves: a Microsoft librarian
/// archive (.lib), an ar archive of COFF objects, or one COFF object. A function matches a start when every byte its
/// relocations leave alone is equal and its length fits; ELF relocatable objects are reported as not read.
/// </summary>
public static class LibrarySignatures
{
    /// <summary>Fewest fixed bytes a function needs before a match names it: shorter ones match too many places.</summary>
    public const int MinFixedBytes = 16;

    private const int MaxFunctions = 1 << 20;
    private const int KeyLength = 8;

    /// <summary>
    /// Every function of the file at <paramref name="path"/>; members that are not COFF objects of one machine are
    /// counted in the notes with their reason. Throws <see cref="ToolError"/> when the file is neither an archive nor
    /// a COFF object.
    /// </summary>
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
            if (bytes.StartsWith("\u007fELF"u8)) reason = "an ELF relocatable object (not read)";
            else if (CoffObject.Read(bytes, out reason) is { } o)
            {
                if (arch == NativeArch.Unknown) arch = o.Arch;
                if (o.Arch != arch) reason = $"a {o.Arch} object in a {arch} library";
                else if (functions.Count < MaxFunctions) functions.AddRange(Functions(o, name));
            }
            if (reason != null) skipped[reason] = skipped.GetValueOrDefault(reason) + 1;
        }
        if (members.Count == 1 && functions.Count == 0 && skipped.Count == 1 && arch == NativeArch.Unknown)
            throw new ToolError(ErrorCode.Unsupported, $"{path} is not a static library or COFF object: {skipped.Keys.First()}.");
        var notes = skipped.OrderByDescending(s => s.Value).Select(s => $"{s.Value} member(s) skipped: {s.Key}").ToList();
        if (functions.Count >= MaxFunctions) notes.Add($"the first {MaxFunctions:N0} functions are read");
        return new LibrarySignatureSet(path, arch, functions, members.Count, notes);
    }

    /// <summary>The functions of one object: each function symbol's bytes to the next symbol in its section or the section end.</summary>
    internal static IEnumerable<LibraryFunction> Functions(CoffObject o, string member)
    {
        var bySymbol = o.Symbols.ToDictionary(y => y.Index);
        foreach (var section in o.Sections.Where(s => s.IsCode && s.Data.Length > 0))
        {
            var starts = o.Symbols.Where(y => y.Section == section.Number && y.Value < section.Data.Length && y.StorageClass is 2 or 3 && !IsSectionName(y, section))
                .GroupBy(y => y.Value).Select(g => g.OrderByDescending(y => y.IsFunction).ThenByDescending(y => y.IsExternal).First()).OrderBy(y => y.Value).ToList();
            for (int i = 0; i < starts.Count; i++)
            {
                if (!starts[i].IsFunction) continue;
                int from = (int)starts[i].Value, to = i + 1 < starts.Count ? (int)starts[i + 1].Value : section.Data.Length;
                var mask = new bool[to - from];
                Array.Fill(mask, true);
                foreach (var r in section.Relocations)
                {
                    int width = CoffObject.Width(o.Machine, r.Type);
                    for (int b = 0; b < width; b++)
                        if (r.Offset + b >= from && r.Offset + b < to) mask[r.Offset + b - from] = false;
                }
                // Alignment padding (int3 or nop) after the last instruction belongs to the section, not the function.
                int end = mask.Length;
                while (end > 0 && mask[end - 1] && section.Data[from + end - 1] is 0xCC or 0x90) end--;
                if (end == 0) continue;
                var calls = new List<LibraryCall>();
                foreach (var r in section.Relocations)
                    if (r.Offset >= from && r.Offset + 4 <= from + end && Extra(o.Arch, r.Type) is int extra && bySymbol.TryGetValue(r.Symbol, out var callee)
                        && Callable(callee))
                        calls.Add(new LibraryCall((int)r.Offset - from, extra, Display(callee.Name, o.Arch)));
                var aliases = o.Symbols.Where(y => y.Section == section.Number && y.Value == starts[i].Value && y != starts[i] && Callable(y))
                    .Select(y => Display(y.Name, o.Arch)).Distinct().ToList();
                yield return new LibraryFunction(Display(starts[i].Name, o.Arch), member, section.Data[from..(from + end)], mask[..end]) { Calls = calls, Aliases = aliases };
            }
        }
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

    /// <summary>
    /// The library functions found at <paramref name="starts"/> of <paramref name="image"/>. A start more than one name
    /// matches, and a function matching more than one start, are ambiguities and name nothing. Functions with fewer
    /// than <see cref="MinFixedBytes"/> fixed bytes are not used. A match is refused when a relative call in it reaches
    /// an address that this match set or <paramref name="nameAt"/> (the image's names; null: none) names otherwise.
    /// </summary>
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
        foreach (var rva in starts.Distinct())
        {
            ct.ThrowIfCancellationRequested();
            int read = image.Read(rva, window);
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
        // Masked call targets make functions that differ only in what they call look alike: each call must reach a
        // function of its own name wherever the name is known. The image's names are checked first, to a fixed point,
        // so a wrong placement in this set is refused before it can refuse its callers; then this set's own placements.
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
                var placed = matches.GroupBy(m => Canon(m.Name)).Where(g => g.Count() == 1).ToDictionary(g => g.Key, g => g.First().Rva, StringComparer.Ordinal);
                var byRva = matches.ToDictionary(m => m.Rva);
                string? Conflict(uint rva, LibraryCall c)
                {
                    if (image.Read(rva + (uint)c.Offset, field) < 4) return null;
                    uint target = rva + (uint)c.Offset + 4 + (uint)c.Extra + (uint)BitConverter.ToInt32(field);
                    var want = Canon(c.Symbol);
                    if (nameAt?.Invoke(target) is { } known && Canon(known) != want) return $"its call to '{c.Symbol}' reaches '{known}'";
                    if (!own) return null;
                    if (placed.TryGetValue(want, out var at) && at != target) return $"its call to '{c.Symbol}' reaches 0x{target:X}; the library places it at 0x{at:X}";
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
