using Corvus.Core;

namespace Corvus.Services;

/// <summary>
/// String literals of an Il2Cpp game, which dummy DLLs do not carry (their bodies are empty): the literal table from
/// stringliteral.json (or script.json's ScriptString), and the native functions that load each literal's slot, found by
/// scanning the game binary's code and mapped to dummy-DLL methods through their [Address] RVAs, or to script.json names
/// (generic instantiations) where no dummy method starts there. Built per dump on first use and kept until the dump's
/// files change or its assemblies are unloaded.
/// </summary>
public sealed class Il2CppStringService
{
    private readonly AssemblyWorkspace _workspace;
    private readonly Il2CppService _il2cpp;
    private readonly Dictionary<string, Il2CppStringIndex> _dumps = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Il2CppDumpFiles?> _located = new(StringComparer.OrdinalIgnoreCase);
    private int _locatedGeneration = -1;
    private long _locatedAt;
    private (int Generation, Dictionary<Il2CppStringIndex, MethodStarts> Maps) _methods = (-1, new());

    public Il2CppStringService(AssemblyWorkspace workspace, Il2CppService il2cpp)
    {
        _workspace = workspace;
        _il2cpp = il2cpp;
    }

    /// <summary>One function that loads a literal: its start RVA, the number of loads in it, and the dummy methods starting there.</summary>
    public sealed record LiteralUse(uint Function, int Sites, IReadOnlyList<Il2CppService.MethodAddress> Methods);

    /// <summary>A literal of a dump; <see cref="Uses"/> is null when the code references are unknown.</summary>
    public sealed record LiteralMatch(Il2CppStringIndex Dump, int Index, IReadOnlyList<LiteralUse>? Uses)
    {
        public string Value => Dump.Values[Index];
        public ulong Address => Dump.Addresses[Index];
    }

    /// <summary>The dumps of the Il2Cpp dummy assemblies in <paramref name="scope"/>, with the assemblies of each.</summary>
    public List<(Il2CppStringIndex Dump, List<LoadedAssembly> Assemblies)> DumpsFor(IReadOnlyList<LoadedAssembly> scope)
    {
        var byDump = new Dictionary<Il2CppStringIndex, List<LoadedAssembly>>();
        using (AssemblyWorkspace.Lock(_dumps))
        {
            // Dump files are looked for again after a workspace change, and at most a few seconds after the last look.
            if (_locatedGeneration != _workspace.Generation || Environment.TickCount64 - _locatedAt > 5_000)
            {
                _located.Clear();
                _locatedGeneration = _workspace.Generation;
                _locatedAt = Environment.TickCount64;
            }
            var live = new HashSet<Il2CppStringIndex>();
            foreach (var asm in _workspace.Assemblies)
            {
                if (DumpOf(asm) is not { } dump) continue;
                live.Add(dump);
                if (scope.Contains(asm)) (byDump.TryGetValue(dump, out var list) ? list : byDump[dump] = []).Add(asm);
            }
            foreach (var key in _dumps.Where(d => !live.Contains(d.Value)).Select(d => d.Key).ToList())
                _dumps.Remove(key); // no assembly of it is loaded any more
        }
        return byDump.Select(kv => (kv.Key, kv.Value)).ToList();
    }

    private Il2CppStringIndex? DumpOf(LoadedAssembly asm)
    {
        var dir = Path.GetDirectoryName(asm.FilePath);
        if (dir == null) return null;
        if (!_located.TryGetValue(dir, out var files))
            _located[dir] = files = Il2CppDumpFiles.Locate(dir);
        if (files == null || _il2cpp.GetIndex(asm).Count == 0) return null;
        if (!_dumps.TryGetValue(files.Directory, out var dump) || dump.Stamp != files.Stamp)
            _dumps[files.Directory] = dump = new Il2CppStringIndex(files);
        return dump;
    }

    /// <summary>
    /// Literals of the dumps in scope whose value matches. When the scope holds only some of a dump's loaded
    /// assemblies and the code references are known, only literals used by a method of the scope are returned.
    /// </summary>
    public List<LiteralMatch> Search(Func<string, bool> matcher, IReadOnlyList<LoadedAssembly> scope, CancellationToken ct)
    {
        var result = new List<LiteralMatch>();
        foreach (var (dump, assemblies) in DumpsFor(scope))
        {
            var values = dump.Values;
            var refs = dump.References;
            var methods = refs != null ? MethodsByRva(dump) : null;
            bool partial = refs != null && _workspace.Assemblies.Any(a => !assemblies.Contains(a) && DumpOfCached(a) == dump);
            var inScope = assemblies.ToHashSet();
            for (int i = 0; i < values.Length; i++)
            {
                if ((i & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
                if (!matcher(values[i])) continue;
                var uses = refs != null ? Uses(refs, methods!, i) : null;
                if (partial && !uses!.Any(u => u.Methods.Any(m => inScope.Contains(m.Assembly)))) continue;
                result.Add(new LiteralMatch(dump, i, uses));
            }
        }
        return result;
    }

    private Il2CppStringIndex? DumpOfCached(LoadedAssembly asm)
    {
        using (AssemblyWorkspace.Lock(_dumps)) return DumpOf(asm);
    }

    private static List<LiteralUse> Uses(Il2CppStringIndex.NativeReferences refs, MethodStarts methods, int literal)
    {
        var list = new List<LiteralUse>();
        for (int s = refs.LiteralFirst[literal]; s < refs.LiteralFirst[literal + 1];)
        {
            uint fn = refs.SiteFunctions[s];
            int n = 0;
            for (; s < refs.LiteralFirst[literal + 1] && refs.SiteFunctions[s] == fn; s++) n++;
            if (fn == Il2CppStringIndex.NoFunction) continue;
            list.Add(new LiteralUse(fn, n, methods.At(fn)));
        }
        return list;
    }

    /// <summary>The literals that the native function starting at <paramref name="function"/> loads, with the number of loads.</summary>
    public List<(int Literal, int Sites)> LiteralsUsedBy(Il2CppStringIndex dump, uint function)
    {
        var list = new List<(int, int)>();
        if (dump.References is not { } refs) return list;
        int i = Array.BinarySearch(refs.FunctionKeys, function);
        if (i < 0) return list;
        while (i > 0 && refs.FunctionKeys[i - 1] == function) i--;
        for (; i < refs.FunctionKeys.Length && refs.FunctionKeys[i] == function; i++)
        {
            int literal = refs.FunctionLiterals[i];
            if (list.Count > 0 && list[^1].Item1 == literal) list[^1] = (literal, list[^1].Item2 + 1);
            else list.Add((literal, 1));
        }
        return list;
    }

    /// <summary>The dummy methods by [Address] RVA, across the dump's loaded assemblies.</summary>
    public MethodStarts MethodsByRva(Il2CppStringIndex dump)
    {
        using (AssemblyWorkspace.Lock(_dumps))
        {
            if (_methods.Generation != _workspace.Generation) _methods = (_workspace.Generation, new());
            if (_methods.Maps.TryGetValue(dump, out var map)) return map;
            _methods.Maps[dump] = map = MethodStarts.Of(_workspace.Assemblies.Where(a => DumpOf(a) == dump).SelectMany(_il2cpp.GetIndex));
            return map;
        }
    }

    /// <summary>Dummy methods sorted by RVA, with what their [Address] values tell about the image.</summary>
    public sealed class MethodStarts(uint[] rvas, Il2CppService.MethodAddress[] methods)
    {
        private uint[]? _starts;
        private (ulong? Base, List<(ulong Low, ulong High, long Delta)> Ranges)? _layout;

        public int Count => rvas.Length;

        public static MethodStarts Of(IEnumerable<Il2CppService.MethodAddress> index)
        {
            var entries = index.Where(e => e.Rva is <= uint.MaxValue).OrderBy(e => e.Rva).ToArray(); // stable: load order within an RVA
            return new MethodStarts(entries.Select(e => (uint)e.Rva!.Value).ToArray(), entries);
        }

        /// <summary>Distinct method RVAs, ascending.</summary>
        public uint[] Starts => _starts ??= rvas.Distinct().ToArray();

        /// <summary>The image base the dumper used for VA (the most common VA - RVA), when the methods give VAs.</summary>
        public ulong? ImageBase => Layout.Base;

        /// <summary>
        /// The RVA of a file offset, from the methods' Offset and RVA values: each section has its own RVA - offset
        /// difference, so offsets between the first and last method of a section convert. Null outside those ranges.
        /// </summary>
        public ulong? OffsetToRva(ulong offset)
        {
            foreach (var (low, high, delta) in Layout.Ranges)
                if (offset >= low && offset <= high) return (ulong)((long)offset + delta);
            return null;
        }

        private (ulong? Base, List<(ulong Low, ulong High, long Delta)> Ranges) Layout => _layout ??= ComputeLayout();

        private (ulong?, List<(ulong, ulong, long)>) ComputeLayout()
        {
            var bases = new Dictionary<ulong, int>();
            var ranges = new Dictionary<long, (ulong Low, ulong High)>();
            foreach (var m in methods)
            {
                if (m.Va is { } va && va >= m.Rva!.Value) bases[va - m.Rva.Value] = bases.GetValueOrDefault(va - m.Rva.Value) + 1;
                if (m.Offset is { } off && off > 0)
                {
                    long delta = (long)m.Rva!.Value - (long)off;
                    ranges[delta] = ranges.TryGetValue(delta, out var r) ? (Math.Min(r.Low, off), Math.Max(r.High, off)) : (off, off);
                }
            }
            ulong? imageBase = bases.Count > 0 ? bases.MaxBy(kv => kv.Value).Key : null;
            return (imageBase is 0 ? null : imageBase, ranges.Select(kv => (kv.Value.Low, kv.Value.High, kv.Key)).ToList());
        }

        /// <summary>The methods starting at <paramref name="rva"/> (several when native code is shared).</summary>
        public ArraySegment<Il2CppService.MethodAddress> At(uint rva)
        {
            int i = Array.BinarySearch(rvas, rva);
            if (i < 0) return ArraySegment<Il2CppService.MethodAddress>.Empty;
            int start = i, end = i + 1;
            while (start > 0 && rvas[start - 1] == rva) start--;
            while (end < rvas.Length && rvas[end] == rva) end++;
            return new ArraySegment<Il2CppService.MethodAddress>(methods, start, end - start);
        }
    }
}

/// <summary>
/// The string literals of one Il2CppDumper dump and, when the game binary is present, the code that loads them; also
/// the dump's script.json index and binary sections, which <see cref="Il2CppNavigator"/> uses.
/// </summary>
public sealed class Il2CppStringIndex
{
    public const uint NoFunction = 0;

    // Built once per dump; a call waiting for another call's build stops when it is cancelled.
    private readonly Deferred<(string[] Values, ulong[] Addresses, Dictionary<ulong, int> BySlot)> _literals;
    private readonly Deferred<Il2CppScript?> _script;
    private readonly Deferred<NativeReferences?> _references;
    private readonly Deferred<(List<NativeCodeScanner.Section>, ulong)?> _binary;

    internal Il2CppStringIndex(Il2CppDumpFiles files)
    {
        Files = files;
        Stamp = files.Stamp;
        _literals = new(LoadLiterals);
        _script = new(() => Files.ScriptJson != null ? Il2CppScript.Load(Files.ScriptJson)
            : Files.Model != null ? Il2CppScript.FromModel(Il2CppRawLoader.Model(Files.Model), Files.Model) : null);
        _references = new(ScanReferences);
        _binary = new(() =>
        {
            if (Files.GameAssembly == null) return null;
            try { return (NativeCodeScanner.Sections(Files.GameAssembly), NativeCodeScanner.ImageBase(Files.GameAssembly)); }
            catch (Exception ex) when (ex is ToolError or IOException or UnauthorizedAccessException) { return null; }
        });
    }

    public Il2CppDumpFiles Files { get; }
    public string Stamp { get; }
    public TimeSpan LiteralLoadTime { get; private set; }

    /// <summary>Literal values, ordered by slot address.</summary>
    public string[] Values => _literals.Value.Values;
    /// <summary>Slot RVA of each literal.</summary>
    public ulong[] Addresses => _literals.Value.Addresses;

    public int? LiteralAt(ulong slot) => _literals.Value.BySlot.TryGetValue(slot, out var i) ? i : null;

    /// <summary>script.json function starts and names; null without script.json.</summary>
    public Il2CppScript? Script => _script.Value;

    /// <summary>Sections and preferred image base of the game binary; null without it or when it is not an x64 PE image.</summary>
    public (List<NativeCodeScanner.Section> Sections, ulong ImageBase)? Binary => _binary.Value;

    /// <summary>Code references from the game binary; null when it, or script.json for the function starts, is missing.</summary>
    public NativeReferences? References => _references.Value;

    /// <summary>Why <see cref="References"/> is null, or a problem found while scanning.</summary>
    public string? ReferenceProblem { get; private set; }

    /// <summary>
    /// Loads of literal slots by native code: sites grouped by literal (<see cref="LiteralFirst"/> indexes
    /// <see cref="Sites"/>, sites ascending), and the same loads ordered by function for the reverse lookup.
    /// </summary>
    public sealed record NativeReferences(int[] LiteralFirst, uint[] Sites, uint[] SiteFunctions, uint[] FunctionKeys, int[] FunctionLiterals,
        int Functions, int ReferencedLiterals, TimeSpan ScanTime);

    private (string[], ulong[], Dictionary<ulong, int>) LoadLiterals()
    {
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var list = new List<ScriptString>();
        var source = Files.StringLiteralJson ?? Files.ScriptJson ?? Files.Model!;
        try
        {
            if (Files.StringLiteralJson != null) list = ScriptJsonReader.ReadStringLiterals(source);
            else if (Files.ScriptJson != null) new ScriptJsonReader { String = list.Add }.Read(source);
            else
            {
                // Literals without a slot cannot be tied to code; the model lists them as unreadable items.
                var model = Il2CppRawLoader.Model(source);
                for (int i = 0; i < model.LiteralValues.Length; i++)
                    if (model.LiteralSlots[i] != 0) list.Add(new ScriptString(model.LiteralSlots[i], model.LiteralValues[i]));
            }
        }
        catch (Exception ex) when (ex is System.Text.Json.JsonException or IOException or UnauthorizedAccessException)
        {
            throw new ToolError(ErrorCode.IoError, $"Cannot read {source}: {ex.Message}");
        }
        list.Sort((a, b) => a.Address.CompareTo(b.Address));
        var values = list.Select(s => s.Value).ToArray();
        var addresses = list.Select(s => s.Address).ToArray();
        var bySlot = new Dictionary<ulong, int>(addresses.Length);
        for (int i = 0; i < addresses.Length; i++) bySlot.TryAdd(addresses[i], i);
        LiteralLoadTime = watch.Elapsed;
        return (values, addresses, bySlot);
    }

    private NativeReferences? ScanReferences()
    {
        if (Files.GameAssembly == null) { ReferenceProblem = "no game binary next to the dump"; return null; }
        var watch = System.Diagnostics.Stopwatch.StartNew();
        Il2CppScript? script;
        try { script = Script; }
        catch (Exception ex) when (ex is System.Text.Json.JsonException or IOException or UnauthorizedAccessException) { ReferenceProblem = $"cannot read {Files.ScriptSource}: {ex.Message}"; return null; }
        if (script == null) { ReferenceProblem = $"no {Il2CppDumpFiles.ScriptFileName} (function starts) next to the dump"; return null; }
        var addresses = Addresses;
        var bySlot = _literals.Value.BySlot;
        if (addresses.Length == 0) { ReferenceProblem = "the dump has no literals"; return null; }
        List<NativeCodeScanner.Section> sections;
        try { sections = NativeCodeScanner.Sections(Files.GameAssembly); }
        catch (Exception ex) when (ex is ToolError or IOException or UnauthorizedAccessException)
        {
            ReferenceProblem = Native.NativeImageLoader.DetectFile(Files.GameAssembly) is Native.NativeFileKind.Elf or Native.NativeFileKind.MachO or Native.NativeFileKind.MachOFat
                ? $"code loads of literal slots are scanned in x64 PE builds; on {Path.GetFileName(Files.GameAssembly)} load it, apply_il2cpp_names, then find_xrefs on a literal's slot"
                : ex.Message;
            return null;
        }
        ulong low = addresses[0], high = addresses[^1];
        if (high > uint.MaxValue || !sections.Any(s => !s.Executable && s.Contains(low)) || !sections.Any(s => !s.Executable && s.Contains(high)))
        {
            ReferenceProblem = $"the literal slots (0x{low:X}-0x{high:X}) are outside the data sections of {Il2CppDumpFiles.GameAssemblyFileName}: another build of the game?";
            return null;
        }

        var siteList = new List<uint>();
        var literalList = new List<int>();
        try
        {
            NativeCodeScanner.FindRipRelative(Files.GameAssembly, sections, (uint)low, (uint)high, (site, target) =>
            {
                if (!bySlot.TryGetValue(target, out var literal)) return;
                siteList.Add(site);
                literalList.Add(literal);
            }, default);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { ReferenceProblem = $"cannot read {Files.GameAssembly}: {ex.Message}"; return null; }

        // Group by literal (counting sort; sites ascend within each literal because the scan runs in address order).
        int count = addresses.Length;
        var first = new int[count + 1];
        foreach (var l in literalList) first[l + 1]++;
        for (int i = 0; i < count; i++) first[i + 1] += first[i];
        var sites = new uint[siteList.Count];
        var functions = new uint[siteList.Count];
        var next = first[..count];
        for (int k = 0; k < siteList.Count; k++)
        {
            int at = next[literalList[k]]++;
            sites[at] = siteList[k];
            functions[at] = script.FunctionContaining(siteList[k]) ?? NoFunction;
        }

        var keys = new List<uint>(sites.Length);
        var keyLiterals = new List<int>(sites.Length);
        int referenced = 0;
        for (int l = 0; l < count; l++)
        {
            if (first[l + 1] > first[l]) referenced++;
            for (int s = first[l]; s < first[l + 1]; s++)
                if (functions[s] != NoFunction) { keys.Add(functions[s]); keyLiterals.Add(l); }
        }
        var functionKeys = keys.ToArray();
        var functionLiterals = keyLiterals.ToArray();
        Array.Sort(functionKeys, functionLiterals); // literal order within a function is restored below
        for (int i = 0, j; i < functionKeys.Length; i = j)
        {
            for (j = i + 1; j < functionKeys.Length && functionKeys[j] == functionKeys[i]; j++) { }
            if (j - i > 1) Array.Sort(functionLiterals, i, j - i);
        }
        int distinctFunctions = 0;
        for (int i = 0; i < functionKeys.Length; i++)
            if (i == 0 || functionKeys[i] != functionKeys[i - 1]) distinctFunctions++;
        if (sites.Length == 0)
            ReferenceProblem = $"no code in {Il2CppDumpFiles.GameAssemblyFileName} loads a literal slot: packed or encrypted code, or another build of the game?";
        return new NativeReferences(first, sites, functions, functionKeys, functionLiterals, distinctFunctions, referenced, watch.Elapsed);
    }

    /// <summary>One line on where the literals and their references come from.</summary>
    public string Describe()
    {
        var source = Files.StringLiteralJson ?? Files.ScriptJson ?? (Files.Model != null ? $"the game's metadata (built-in reader, {Files.Model})" : null);
        var text = $"{Values.Length} literals from {source}";
        if (References is { } r)
            text += $"; code references from {Files.GameAssembly}: {r.Sites.Length} loads of {r.ReferencedLiterals} literals in {r.Functions} functions";
        if (ReferenceProblem != null) text += $"; {(References == null ? "code references unknown: " : "")}{ReferenceProblem}";
        return text;
    }
}
