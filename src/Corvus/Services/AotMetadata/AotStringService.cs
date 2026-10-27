using Corvus.Core;

namespace Corvus.Services;

/// <summary>
/// String literals of a build, which dummy assemblies do not carry, and the native functions that load each one; built
/// per dump on first use, kept until its files change or its assemblies unload.
/// </summary>
public sealed class AotStringService
{
    private readonly AssemblyWorkspace _workspace;
    private readonly AotMetadataService _aot;
    private readonly Dictionary<string, AotStringIndex> _dumps = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, AotDumpFiles?> _located = new(StringComparer.OrdinalIgnoreCase);
    private int _locatedGeneration = -1;
    private long _locatedAt;
    private (int Generation, Dictionary<AotStringIndex, MethodStarts> Maps) _methods = (-1, new());

    public AotStringService(AssemblyWorkspace workspace, AotMetadataService aot)
    {
        _workspace = workspace;
        _aot = aot;
    }

    /// <summary>One function that loads a literal: its start RVA, the number of loads in it, and the dummy methods starting there.</summary>
    public sealed record LiteralUse(uint Function, int Sites, IReadOnlyList<AotMetadataService.MethodAddress> Methods);

    /// <summary>A literal of a dump; <see cref="Uses"/> is null when the code references are unknown.</summary>
    public sealed record LiteralMatch(AotStringIndex Dump, int Index, IReadOnlyList<LiteralUse>? Uses)
    {
        public string Value => Dump.Values[Index];
        public ulong Address => Dump.Addresses[Index];
    }

    /// <summary>The dumps of the dummy assemblies in <paramref name="scope"/>, with the assemblies of each.</summary>
    public List<(AotStringIndex Dump, List<LoadedAssembly> Assemblies)> DumpsFor(IReadOnlyList<LoadedAssembly> scope)
    {
        var byDump = new Dictionary<AotStringIndex, List<LoadedAssembly>>();
        using (AssemblyWorkspace.Lock(_dumps))
        {
            // Dump files are looked for again after a workspace change, and at most a few seconds after the last look.
            if (_locatedGeneration != _workspace.Generation || Environment.TickCount64 - _locatedAt > 5_000)
            {
                _located.Clear();
                _locatedGeneration = _workspace.Generation;
                _locatedAt = Environment.TickCount64;
            }
            var live = new HashSet<AotStringIndex>();
            foreach (var asm in _workspace.Assemblies)
            {
                if (DumpOf(asm) is not { } dump) continue;
                live.Add(dump);
                if (scope.Contains(asm)) (byDump.TryGetValue(dump, out var list) ? list : byDump[dump] = []).Add(asm);
            }
            foreach (var key in _dumps.Where(d => !live.Contains(d.Value)).Select(d => d.Key).ToList())
                _dumps.Remove(key);
        }
        return byDump.Select(kv => (kv.Key, kv.Value)).ToList();
    }

    private AotStringIndex? DumpOf(LoadedAssembly asm)
    {
        var dir = Path.GetDirectoryName(asm.FilePath);
        if (dir == null) return null;
        if (!_located.TryGetValue(dir, out var files))
            _located[dir] = files = AotDumpFiles.Locate(dir);
        // A built-in read names its model; metadata read without the binary has no addresses but still has literals.
        if (files == null || (_aot.GetIndex(asm).Count == 0 && files.Model == null)) return null;
        if (!_dumps.TryGetValue(files.Directory, out var dump) || dump.Stamp != files.Stamp)
            _dumps[files.Directory] = dump = new AotStringIndex(files);
        return dump;
    }

    /// <summary>Matching literals of the dumps in scope; with a partial scope and known references, only those its methods use.</summary>
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

    private AotStringIndex? DumpOfCached(LoadedAssembly asm)
    {
        using (AssemblyWorkspace.Lock(_dumps)) return DumpOf(asm);
    }

    private static List<LiteralUse> Uses(AotStringIndex.NativeReferences refs, MethodStarts methods, int literal)
    {
        var list = new List<LiteralUse>();
        for (int s = refs.LiteralFirst[literal]; s < refs.LiteralFirst[literal + 1];)
        {
            uint fn = refs.SiteFunctions[s];
            int n = 0;
            for (; s < refs.LiteralFirst[literal + 1] && refs.SiteFunctions[s] == fn; s++) n++;
            if (fn == AotStringIndex.NoFunction) continue;
            list.Add(new LiteralUse(fn, n, methods.At(fn)));
        }
        return list;
    }

    /// <summary>The literals that the native function starting at <paramref name="function"/> loads, with the number of loads.</summary>
    public List<(int Literal, int Sites)> LiteralsUsedBy(AotStringIndex dump, uint function)
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
    public MethodStarts MethodsByRva(AotStringIndex dump)
    {
        using (AssemblyWorkspace.Lock(_dumps))
        {
            if (_methods.Generation != _workspace.Generation) _methods = (_workspace.Generation, new());
            if (_methods.Maps.TryGetValue(dump, out var map)) return map;
            _methods.Maps[dump] = map = MethodStarts.Of(_workspace.Assemblies.Where(a => DumpOf(a) == dump).SelectMany(_aot.GetIndex));
            return map;
        }
    }

    /// <summary>Dummy methods sorted by RVA, with what their [Address] values tell about the image.</summary>
    public sealed class MethodStarts(uint[] rvas, AotMetadataService.MethodAddress[] methods)
    {
        private uint[]? _starts;
        private (ulong? Base, List<(ulong Low, ulong High, long Delta)> Ranges)? _layout;

        public int Count => rvas.Length;

        public static MethodStarts Of(IEnumerable<AotMetadataService.MethodAddress> index)
        {
            // Stable sort: load order within an RVA.
            var entries = index.Where(e => e.Rva is <= uint.MaxValue).OrderBy(e => e.Rva).ToArray();
            return new MethodStarts(entries.Select(e => (uint)e.Rva!.Value).ToArray(), entries);
        }

        /// <summary>Distinct method RVAs, ascending.</summary>
        public uint[] Starts => _starts ??= rvas.Distinct().ToArray();

        /// <summary>The recorded image base (the most common VA - RVA); null when the methods give no VAs.</summary>
        public ulong? ImageBase => Layout.Base;

        /// <summary>The RVA of a file offset from the methods' per-section deltas; null outside a section's method range.</summary>
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
        public ArraySegment<AotMetadataService.MethodAddress> At(uint rva)
        {
            int i = Array.BinarySearch(rvas, rva);
            if (i < 0) return ArraySegment<AotMetadataService.MethodAddress>.Empty;
            int start = i, end = i + 1;
            while (start > 0 && rvas[start - 1] == rva) start--;
            while (end < rvas.Length && rvas[end] == rva) end++;
            return new ArraySegment<AotMetadataService.MethodAddress>(methods, start, end - start);
        }
    }
}

/// <summary>One dump's string literals, the code that loads them, its script.json index and binary sections.</summary>
public sealed class AotStringIndex
{
    public const uint NoFunction = 0;

    // Built once per dump; a call waiting for another call's build stops when it is cancelled.
    private readonly Deferred<(string[] Values, ulong[] Addresses, Dictionary<ulong, int> BySlot)> _literals;
    private readonly Deferred<AotScript?> _script;
    private readonly Deferred<NativeReferences?> _references;
    private readonly Deferred<(List<NativeCodeScanner.Section>, ulong)?> _binary;

    internal AotStringIndex(AotDumpFiles files)
    {
        Files = files;
        Stamp = files.Stamp;
        _literals = new(LoadLiterals);
        _script = new(() => Files.ScriptJson != null ? AotScript.Load(Files.ScriptJson)
            : Files.Model != null ? AotScript.FromModel(AotBuildLoader.Model(Files.Model), Files.Model) : null);
        _references = new(ScanReferences);
        _binary = new(() =>
        {
            if (Files.GameAssembly == null) return null;
            try { return (NativeCodeScanner.Sections(Files.GameAssembly), NativeCodeScanner.ImageBase(Files.GameAssembly)); }
            catch (Exception ex) when (ex is ToolError or IOException or UnauthorizedAccessException) { return null; }
        });
    }

    public AotDumpFiles Files { get; }
    public string Stamp { get; }
    public TimeSpan LiteralLoadTime { get; private set; }

    /// <summary>Literal values, ordered by slot address.</summary>
    public string[] Values => _literals.Value.Values;
    /// <summary>Slot RVA of each literal.</summary>
    public ulong[] Addresses => _literals.Value.Addresses;

    public int? LiteralAt(ulong slot) => _literals.Value.BySlot.TryGetValue(slot, out var i) ? i : null;

    /// <summary>script.json function starts and names; null without script.json.</summary>
    public AotScript? Script => _script.Value;

    /// <summary>Sections and preferred image base of the native binary; null without it or when it is not an x64 PE image.</summary>
    public (List<NativeCodeScanner.Section> Sections, ulong ImageBase)? Binary => _binary.Value;

    /// <summary>Code references from the native binary; null when it, or script.json for the function starts, is missing.</summary>
    public NativeReferences? References => _references.Value;

    /// <summary>Why <see cref="References"/> is null, or a problem found while scanning.</summary>
    public string? ReferenceProblem { get; private set; }

    /// <summary>Native loads of literal slots, grouped by literal and again by function for the reverse lookup.</summary>
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
                // Slotless literals cannot be tied to code, except without a binary, where all are kept at slot 0.
                var model = AotBuildLoader.Model(source);
                bool metadataOnly = model.BinaryPath.Length == 0;
                for (int i = 0; i < model.LiteralValues.Length; i++)
                    if (model.LiteralSlots[i] != 0 || metadataOnly) list.Add(new ScriptString(model.LiteralSlots[i], model.LiteralValues[i]));
            }
        }
        catch (Exception ex) when (ex is System.Text.Json.JsonException or IOException or UnauthorizedAccessException)
        {
            throw new ToolError(ErrorCode.IoError, $"Cannot read {source}: {ex.Message}");
        }
        // Stable sort: slotless literals keep metadata order.
        list = list.OrderBy(s => s.Address).ToList();
        var values = list.Select(s => s.Value).ToArray();
        var addresses = list.Select(s => s.Address).ToArray();
        var bySlot = new Dictionary<ulong, int>(addresses.Length);
        for (int i = 0; i < addresses.Length; i++) bySlot.TryAdd(addresses[i], i);
        LiteralLoadTime = watch.Elapsed;
        return (values, addresses, bySlot);
    }

    private NativeReferences? ScanReferences()
    {
        if (Files.GameAssembly == null) { ReferenceProblem = "the native binary was not found next to the dump"; return null; }
        var watch = System.Diagnostics.Stopwatch.StartNew();
        AotScript? script;
        try { script = Script; }
        catch (Exception ex) when (ex is System.Text.Json.JsonException or IOException or UnauthorizedAccessException) { ReferenceProblem = $"cannot read {Files.ScriptSource}: {ex.Message}"; return null; }
        if (script == null) { ReferenceProblem = $"no {AotDumpFiles.ScriptFileName} (function starts) next to the dump"; return null; }
        var addresses = Addresses;
        var bySlot = _literals.Value.BySlot;
        if (addresses.Length == 0) { ReferenceProblem = "the dump has no literals"; return null; }
        List<NativeCodeScanner.Section> sections;
        try { sections = NativeCodeScanner.Sections(Files.GameAssembly); }
        catch (Exception ex) when (ex is ToolError or IOException or UnauthorizedAccessException)
        {
            ReferenceProblem = Native.NativeImageLoader.DetectFile(Files.GameAssembly) is Native.NativeFileKind.Elf or Native.NativeFileKind.MachO or Native.NativeFileKind.MachOFat
                ? $"code loads of literal slots are scanned in x64 PE builds; on {Path.GetFileName(Files.GameAssembly)} load it, apply_metadata_names, then find_xrefs on a literal's slot"
                : ex.Message;
            return null;
        }
        ulong low = addresses[0], high = addresses[^1];
        if (high > uint.MaxValue || !sections.Any(s => !s.Executable && s.Contains(low)) || !sections.Any(s => !s.Executable && s.Contains(high)))
        {
            ReferenceProblem = $"the literal slots (0x{low:X}-0x{high:X}) are outside the data sections of {AotDumpFiles.GameAssemblyFileName}: another build?";
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
        // Literal order within a function is restored below.
        Array.Sort(functionKeys, functionLiterals);
        for (int i = 0, j; i < functionKeys.Length; i = j)
        {
            for (j = i + 1; j < functionKeys.Length && functionKeys[j] == functionKeys[i]; j++) { }
            if (j - i > 1) Array.Sort(functionLiterals, i, j - i);
        }
        int distinctFunctions = 0;
        for (int i = 0; i < functionKeys.Length; i++)
            if (i == 0 || functionKeys[i] != functionKeys[i - 1]) distinctFunctions++;
        if (sites.Length == 0)
            ReferenceProblem = $"no code in {AotDumpFiles.GameAssemblyFileName} loads a literal slot: packed or encrypted code, or another build?";
        return new NativeReferences(first, sites, functions, functionKeys, functionLiterals, distinctFunctions, referenced, watch.Elapsed);
    }

    /// <summary>One line on where the literals and their references come from.</summary>
    public string Describe()
    {
        var source = Files.StringLiteralJson ?? Files.ScriptJson ?? (Files.Model != null ? $"the build's metadata (built-in reader, {Files.Model})" : null);
        var text = $"{Values.Length} literals from {source}";
        if (References is { } r)
            text += $"; code references from {Files.GameAssembly}: {r.Sites.Length} loads of {r.ReferencedLiterals} literals in {r.Functions} functions";
        if (ReferenceProblem != null) text += $"; {(References == null ? "code references unknown: " : "")}{ReferenceProblem}";
        return text;
    }
}
