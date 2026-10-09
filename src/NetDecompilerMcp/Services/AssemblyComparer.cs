using System.Collections.Concurrent;
using System.Globalization;
using System.Runtime.CompilerServices;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using NetDecompilerMcp.Core;
using static NetDecompilerMcp.Services.MetadataUtil;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Compares two builds of an assembly: added, removed and renamed types and members, signature and body changes,
/// and Il2Cpp field-offset / address changes. Renamed or moved definitions are matched by content (IL shape,
/// string literals, field and member structure).
/// </summary>
public sealed class AssemblyComparer(AssemblyWorkspace workspace)
{
    public sealed record MemberChange(string Change, IMemberDef? Old, IMemberDef? New, string Detail);

    public sealed record TypeChange(string Change, TypeDef? Old, TypeDef? New, double Score, List<MemberChange> Members);

    public sealed record Comparison(
        LoadedAssembly Old, LoadedAssembly New, List<TypeChange> Types,
        IReadOnlyDictionary<TypeDef, TypeDef> TypeMap, IReadOnlyDictionary<IMemberDef, (IMemberDef New, string How)> MemberMap);

    private readonly ConditionalWeakTable<LoadedAssembly, ConditionalWeakTable<LoadedAssembly, CacheEntry>> _cache = new();

    private sealed record CacheEntry(long Key, Comparison Value);

    private const double TypeThreshold = 0.6;
    private const double MethodThreshold = 0.6;

    public Comparison Compare(LoadedAssembly oldAsm, LoadedAssembly newAsm, CancellationToken ct)
    {
        if (oldAsm == newAsm)
            throw new ToolError("Pick two different assemblies (load both builds; the second gets an id like Name#2).");
        long key = ((long)workspace.Generation << 32) | (uint)(oldAsm.Version * 65_537 + newAsm.Version);
        var inner = _cache.GetOrCreateValue(oldAsm);
        if (inner.TryGetValue(newAsm, out var cached) && cached.Key == key)
            return cached.Value;

        var oldInfo = Fingerprints(oldAsm, ct);
        var newInfo = Fingerprints(newAsm, ct);
        var typeMap = MatchTypes(oldInfo, newInfo, out var typeScores, ct);
        var memberMap = new Dictionary<IMemberDef, (IMemberDef, string)>();
        var changes = new List<TypeChange>();

        foreach (var (o, n) in typeMap)
        {
            ct.ThrowIfCancellationRequested();
            var members = CompareMembers(oldInfo, newInfo, o, n, memberMap);
            bool renamed = o.FullName != n.FullName;
            if (renamed || members.Count > 0)
                changes.Add(new TypeChange(renamed ? "renamed" : "changed", o, n, typeScores.GetValueOrDefault(o, 1.0), members));
        }
        foreach (var o in oldInfo.Types.Keys.Where(t => !typeMap.ContainsKey(t)))
            changes.Add(new TypeChange("removed", o, null, 0, []));
        var mappedNew = typeMap.Values.ToHashSet();
        foreach (var n in newInfo.Types.Keys.Where(t => !mappedNew.Contains(t)))
            changes.Add(new TypeChange("added", null, n, 0, []));

        var order = new Dictionary<string, int> { ["renamed"] = 0, ["changed"] = 1, ["removed"] = 2, ["added"] = 3 };
        changes.Sort((a, b) => order[a.Change] != order[b.Change] ? order[a.Change] - order[b.Change]
            : string.CompareOrdinal((a.Old ?? a.New)!.FullName, (b.Old ?? b.New)!.FullName));

        var result = new Comparison(oldAsm, newAsm, changes, typeMap, memberMap);
        inner.AddOrUpdate(newAsm, new CacheEntry(key, result));
        return result;
    }

    /// <summary>The counterpart of an old type or member in the new build.</summary>
    public (IMemberDef? Match, string How) FindCounterpart(Comparison comparison, IMemberDef oldMember)
    {
        if (oldMember is TypeDef t)
            return comparison.TypeMap.TryGetValue(t, out var nt) ? (nt, nt.FullName == t.FullName ? "same name" : "matched by content") : (null, "type not found in the new build");
        if (comparison.MemberMap.TryGetValue(oldMember, out var m))
            return (m.New, m.How);
        var declaring = oldMember.DeclaringType;
        return declaring != null && !comparison.TypeMap.ContainsKey(declaring)
            ? (null, $"its type {declaring.FullName} was not found in the new build")
            : (null, "removed in the new build (no match)");
    }

    /// <summary>
    /// Shape: opcodes and literals. Skeleton: opcodes and string literals only. Control-flow code transformers (Dotfuscator,
    /// ConfuserEx) plant random integer constants that change with every build, so only the skeleton survives a rebuild.
    /// </summary>
    private sealed record MethodPrint(MethodDef Method, string Signature, ulong Shape, ulong Skeleton, ulong Full, int Size, HashSet<string> Strings);

    /// <summary>RareShapes: method bodies that occur in at most two types of the build — boilerplate shared by many types is no evidence of identity.</summary>
    private sealed record TypePrint(TypeDef Type, string Kind, int Arity, string BaseName, List<string> FieldTypes, HashSet<ulong> Shapes,
        HashSet<ulong> Skeletons, HashSet<string> Strings)
    {
        public HashSet<ulong> RareShapes { get; set; } = [];

        /// <summary>Rare shapes of substantial methods (20+ instructions): one shared is already strong evidence.</summary>
        public HashSet<ulong> BigShapes { get; set; } = [];

        public HashSet<ulong> RareSkeletons { get; set; } = [];
        public HashSet<ulong> BigSkeletons { get; set; } = [];

        /// <summary>Strings (literals, constants, enum member names) that occur in at most two types of the build.</summary>
        public HashSet<string> RareStrings { get; set; } = [];
    }

    private sealed class Info
    {
        public required LoadedAssembly Assembly { get; init; }
        public Dictionary<TypeDef, TypePrint> Types { get; } = new();
        public Dictionary<MethodDef, MethodPrint> Methods { get; } = new();
    }

    private static Info Fingerprints(LoadedAssembly asm, CancellationToken ct)
    {
        var info = new Info { Assembly = asm };
        var methods = new ConcurrentDictionary<MethodDef, MethodPrint>();
        var types = asm.Module.GetTypes().Where(t => t.FullName != "<Module>").ToList();
        Parallel.ForEach(types, new ParallelOptions { CancellationToken = ct }, t =>
        {
            foreach (var m in t.Methods)
                methods[m] = MethodFingerprint(asm, m);
        });
        foreach (var (m, p) in methods) info.Methods[m] = p;
        foreach (var t in types)
        {
            var prints = t.Methods.Select(m => info.Methods[m]).ToList();
            info.Types[t] = new TypePrint(t, Format.Kind(t), t.GenericParameters.Count,
                t.BaseType?.FullName ?? "",
                t.Fields.Where(f => !f.IsLiteral).Select(f => Format.Type(f.FieldType)).OrderBy(x => x, StringComparer.Ordinal).ToList(),
                prints.Where(p => p.Size > 2).Select(p => p.Shape).ToHashSet(),
                prints.Where(p => p.Size > 2).Select(p => p.Skeleton).ToHashSet(),
                t.IsEnum ? t.Fields.Where(f => f.IsLiteral).Select(f => f.Name.String).ToHashSet()
                    : prints.SelectMany(p => p.Strings).Concat(ConstantValues(t)).ToHashSet());
        }
        var frequency = info.Types.Values.SelectMany(t => t.Shapes).GroupBy(x => x).ToDictionary(g => g.Key, g => g.Count());
        var skeletonFrequency = info.Types.Values.SelectMany(t => t.Skeletons).GroupBy(x => x).ToDictionary(g => g.Key, g => g.Count());
        var stringFrequency = info.Types.Values.SelectMany(t => t.Strings).GroupBy(x => x, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal);
        foreach (var t in info.Types.Values)
        {
            t.RareShapes = t.Shapes.Where(x => frequency[x] <= 2).ToHashSet();
            t.BigShapes = t.Type.Methods.Select(m => info.Methods[m]).Where(p => p.Size >= 20 && t.RareShapes.Contains(p.Shape)).Select(p => p.Shape).ToHashSet();
            t.RareSkeletons = t.Skeletons.Where(x => skeletonFrequency[x] <= 2).ToHashSet();
            t.BigSkeletons = t.Type.Methods.Select(m => info.Methods[m]).Where(p => p.Size >= 20 && t.RareSkeletons.Contains(p.Skeleton)).Select(p => p.Skeleton).ToHashSet();
            t.RareStrings = t.Strings.Where(x => stringFrequency[x] <= 2).ToHashSet(StringComparer.Ordinal);
        }
        return info;
    }

    /// <summary>Values of the type's constants (const fields): product names, keys, GUIDs, versions survive renaming.</summary>
    private static IEnumerable<string> ConstantValues(TypeDef t) =>
        t.Fields.Where(f => f.IsLiteral && f.Constant?.Value is not null)
            .Select(f => "c:" + Convert.ToString(f.Constant.Value, CultureInfo.InvariantCulture))
            .Where(v => v.Length > 4); // "c:0", "c:1": no evidence

    private static MethodPrint MethodFingerprint(LoadedAssembly asm, MethodDef m)
    {
        ulong shape = 14695981039346656037UL, full = shape, skeleton = shape;
        var strings = new HashSet<string>(StringComparer.Ordinal);
        int size = 0;
        foreach (var i in FastIlReader.Instructions(asm, m))
        {
            size++;
            var op = Canonical(i.OpCode.Code);
            shape = Mix(shape, (ulong)op);
            skeleton = Mix(skeleton, (ulong)op);
            full = Mix(full, (ulong)op);
            string? literal = i.Operand switch
            {
                string s => "s:" + s,
                int n => "i:" + n.ToString(CultureInfo.InvariantCulture),
                sbyte n => "i:" + n.ToString(CultureInfo.InvariantCulture),
                long n => "l:" + n.ToString(CultureInfo.InvariantCulture),
                float n => "f:" + n.ToString("R", CultureInfo.InvariantCulture),
                double n => "d:" + n.ToString("R", CultureInfo.InvariantCulture),
                _ when i.IsLdcI4() => "i:" + i.GetLdcI4Value().ToString(CultureInfo.InvariantCulture),
                _ => null,
            };
            if (literal != null)
            {
                shape = Mix(shape, Hash(literal));
                full = Mix(full, Hash(literal));
                if (i.Operand is string str)
                {
                    strings.Add(str);
                    skeleton = Mix(skeleton, Hash(literal));
                }
            }
            else if (AsMethod(i.Operand) is { } callee) full = Mix(full, Hash(Format.MemberLabel(callee)));
            else if (AsField(i.Operand) is { } field) full = Mix(full, Hash(Format.MemberLabel(field)));
            else if (i.Operand is ITypeDefOrRef type) full = Mix(full, Hash(type.FullName));
        }
        var signature = $"{(m.IsStatic ? "static " : "")}{Format.Type(m.ReturnType)}({Format.ParameterTypes(m.MethodSig)})";
        return new MethodPrint(m, signature, shape, skeleton, full, size, strings);
    }

    /// <summary>Short and long forms of an opcode count as the same instruction (compilers pick either).</summary>
    private static Code Canonical(Code c) => c switch
    {
        Code.Br_S => Code.Br, Code.Brtrue_S => Code.Brtrue, Code.Brfalse_S => Code.Brfalse,
        Code.Beq_S => Code.Beq, Code.Bne_Un_S => Code.Bne_Un, Code.Bge_S => Code.Bge, Code.Bgt_S => Code.Bgt,
        Code.Ble_S => Code.Ble, Code.Blt_S => Code.Blt, Code.Bge_Un_S => Code.Bge_Un, Code.Bgt_Un_S => Code.Bgt_Un,
        Code.Ble_Un_S => Code.Ble_Un, Code.Blt_Un_S => Code.Blt_Un, Code.Leave_S => Code.Leave,
        Code.Ldc_I4_S or Code.Ldc_I4_M1 or Code.Ldc_I4_0 or Code.Ldc_I4_1 or Code.Ldc_I4_2 or Code.Ldc_I4_3 or Code.Ldc_I4_4
            or Code.Ldc_I4_5 or Code.Ldc_I4_6 or Code.Ldc_I4_7 or Code.Ldc_I4_8 => Code.Ldc_I4,
        Code.Ldarg_S or Code.Ldarg_0 or Code.Ldarg_1 or Code.Ldarg_2 or Code.Ldarg_3 => Code.Ldarg,
        Code.Ldloc_S or Code.Ldloc_0 or Code.Ldloc_1 or Code.Ldloc_2 or Code.Ldloc_3 => Code.Ldloc,
        Code.Stloc_S or Code.Stloc_0 or Code.Stloc_1 or Code.Stloc_2 or Code.Stloc_3 => Code.Stloc,
        Code.Ldarga_S => Code.Ldarga, Code.Ldloca_S => Code.Ldloca, Code.Starg_S => Code.Starg,
        _ => c,
    };

    private static ulong Mix(ulong h, ulong v) => (h ^ v) * 1099511628211UL;

    private static ulong Hash(string s)
    {
        ulong h = 14695981039346656037UL;
        foreach (var ch in s) h = (h ^ ch) * 1099511628211UL;
        return h;
    }

    private static Dictionary<TypeDef, TypeDef> MatchTypes(Info oldInfo, Info newInfo, out Dictionary<TypeDef, double> scores, CancellationToken ct)
    {
        var map = new Dictionary<TypeDef, TypeDef>();
        scores = new Dictionary<TypeDef, double>();
        var newByName = newInfo.Types.Keys.GroupBy(t => t.FullName).Where(g => g.Count() == 1).ToDictionary(g => g.Key, g => g.First());
        foreach (var t in oldInfo.Types.Keys)
            if (newByName.TryGetValue(t.FullName, out var n))
                map[t] = n;

        // Top-level types first; nested types are matched only under matched parents.
        foreach (bool nested in new[] { false, true })
        {
            var mappedNew = map.Values.ToHashSet();
            var oldLeft = oldInfo.Types.Values.Where(p => !map.ContainsKey(p.Type) && (p.Type.DeclaringType != null) == nested).ToList();
            var newLeft = newInfo.Types.Values.Where(p => !mappedNew.Contains(p.Type) && (p.Type.DeclaringType != null) == nested).ToList();
            var candidates = new List<(TypePrint Old, TypePrint New, double Score)>();
            foreach (var group in oldLeft.GroupBy(p => (p.Kind, p.Arity)))
            {
                var pool = newLeft.Where(p => p.Kind == group.Key.Kind && p.Arity == group.Key.Arity).ToList();
                foreach (var o in group)
                {
                    ct.ThrowIfCancellationRequested();
                    var parent = nested ? map.GetValueOrDefault(o.Type.DeclaringType) : null;
                    if (nested && parent == null) continue;
                    var nearby = nested ? pool.Where(p => p.Type.DeclaringType == parent).ToList()
                        : pool.Count <= 400 ? pool
                        : pool.Where(p => Math.Abs(p.Type.Methods.Count - o.Type.Methods.Count) <= 2 && Math.Abs(p.FieldTypes.Count - o.FieldTypes.Count) <= 2).ToList();
                    foreach (var n in nearby)
                    {
                        double score = TypeScore(o, n);
                        if (score >= TypeThreshold) candidates.Add((o, n, score));
                    }
                }
            }
            var usedOld = new HashSet<TypeDef>();
            var usedNew = new HashSet<TypeDef>();
            foreach (var (o, n, score) in candidates.OrderByDescending(c => c.Score))
            {
                if (usedOld.Contains(o.Type) || usedNew.Contains(n.Type)) continue;
                usedOld.Add(o.Type);
                usedNew.Add(n.Type);
                map[o.Type] = n.Type;
                scores[o.Type] = score;
            }
        }
        return map;
    }

    /// <summary>
    /// 0..1 likelihood that two types with different full names are the same type. A type that moved namespace keeps
    /// its simple name; a renamed type must share real content (method bodies or string literals) or a very similar
    /// name — small look-alike types (a removed feature vs. a new one) must not pair up.
    /// </summary>
    private static double TypeScore(TypePrint o, TypePrint n)
    {
        bool rare = o.RareShapes.Count > 0 || n.RareShapes.Count > 0;
        // Bodies compared with and without numeric constants (see MethodPrint); the stronger match counts.
        double shapes = Math.Max(rare ? Jaccard(o.RareShapes, n.RareShapes) : 0.5 * Jaccard(o.Shapes, n.Shapes),
            o.RareSkeletons.Count > 0 || n.RareSkeletons.Count > 0 ? Jaccard(o.RareSkeletons, n.RareSkeletons) : 0.5 * Jaccard(o.Skeletons, n.Skeletons));
        double fields = MultisetJaccard(o.FieldTypes, n.FieldTypes);
        double strings = o.Strings.Count + n.Strings.Count == 0 ? fields : Jaccard(o.Strings, n.Strings);
        double rareStrings = o.RareStrings.Count + n.RareStrings.Count == 0 ? 0 : Jaccard(o.RareStrings, n.RareStrings);
        int sharedRareStrings = o.RareStrings.Count(n.RareStrings.Contains);
        double counts = 1.0 - Math.Min(1.0, Math.Abs(o.Type.Methods.Count - n.Type.Methods.Count) / (double)Math.Max(1, Math.Max(o.Type.Methods.Count, n.Type.Methods.Count)));
        double baseSame = o.BaseName == n.BaseName ? 1 : 0;
        double structural = 0.4 * Math.Max(shapes, rareStrings) + 0.2 * fields + 0.2 * strings + 0.1 * counts + 0.1 * baseSame;

        string oName = NormalizeName(o.Type.Name), nName = NormalizeName(n.Type.Name);
        if (oName == nName)
            return 0.6 + 0.4 * structural; // moved to another namespace (or generated name renumbered)

        int sharedShapes = Math.Max(o.RareShapes.Count(n.RareShapes.Contains), o.RareSkeletons.Count(n.RareSkeletons.Contains));
        int sharedStrings = o.Strings.Count(n.Strings.Contains);
        double nameSimilarity = Similarity(oName, nName);
        bool evidence = sharedShapes >= 2 || sharedStrings >= 2
                        || (sharedShapes >= 1 && sharedStrings >= 1)
                        || o.BigShapes.Overlaps(n.BigShapes) || o.BigSkeletons.Overlaps(n.BigSkeletons)
                        || (nameSimilarity >= 0.8 && structural >= 0.5);
        if (!evidence) return 0;
        // Content that only these two types share decides on its own: code transformers rename every type at each build,
        // so the names carry no evidence at all.
        bool strong = (sharedRareStrings >= 3 && rareStrings >= 0.6) || (sharedShapes >= 2 && shapes >= 0.6)
                      || (o.Type.IsEnum && sharedStrings >= 4 && strings >= 0.6); // an enum's member names, often kept by code transformers
        double score = 0.3 * nameSimilarity + 0.7 * structural;
        return strong ? Math.Max(score, structural) : score;
    }

    /// <summary>Simple name without generic arity and without compiler-generated numbering (&lt;&gt;c__DisplayClass154_0 -> &lt;&gt;c__DisplayClass_).</summary>
    private static string NormalizeName(string name)
    {
        var n = Format.StripArity(name);
        return n.StartsWith('<') ? new string(n.Where(c => !char.IsDigit(c)).ToArray()) : n;
    }

    /// <summary>Normalized Levenshtein similarity (1 = equal).</summary>
    private static double Similarity(string a, string b)
    {
        if (a.Length == 0 && b.Length == 0) return 1;
        var prev = new int[b.Length + 1];
        var cur = new int[b.Length + 1];
        for (int j = 0; j <= b.Length; j++) prev[j] = j;
        for (int i = 1; i <= a.Length; i++)
        {
            cur[0] = i;
            for (int j = 1; j <= b.Length; j++)
                cur[j] = Math.Min(Math.Min(cur[j - 1] + 1, prev[j] + 1), prev[j - 1] + (a[i - 1] == b[j - 1] ? 0 : 1));
            (prev, cur) = (cur, prev);
        }
        return 1.0 - prev[b.Length] / (double)Math.Max(a.Length, b.Length);
    }

    private static double Jaccard<T>(IReadOnlySet<T> a, IReadOnlySet<T> b)
    {
        if (a.Count == 0 && b.Count == 0) return 1;
        int inter = a.Count(b.Contains);
        return inter / (double)(a.Count + b.Count - inter);
    }

    private static double MultisetJaccard(List<string> a, List<string> b)
    {
        if (a.Count == 0 && b.Count == 0) return 1;
        var counts = a.GroupBy(x => x).ToDictionary(g => g.Key, g => g.Count());
        int inter = 0;
        foreach (var x in b)
            if (counts.TryGetValue(x, out int c) && c > 0) { inter++; counts[x] = c - 1; }
        return inter / (double)(a.Count + b.Count - inter);
    }

    private static List<MemberChange> CompareMembers(Info oldInfo, Info newInfo, TypeDef o, TypeDef n, Dictionary<IMemberDef, (IMemberDef, string)> memberMap)
    {
        var changes = new List<MemberChange>();

        // Methods: same name + signature, then same name (signature changed), then by content (renamed).
        var oldMethods = o.Methods.Select(m => oldInfo.Methods[m]).ToList();
        var newMethods = n.Methods.Select(m => newInfo.Methods[m]).ToList();
        var matched = new List<(MethodPrint Old, MethodPrint New, string How)>();
        void Take(Func<MethodPrint, MethodPrint, bool> rule, string how)
        {
            foreach (var om in oldMethods.ToList())
            {
                var candidates = newMethods.Where(nm => rule(om, nm)).ToList();
                if (candidates.Count != 1) continue;
                matched.Add((om, candidates[0], how));
                oldMethods.Remove(om);
                newMethods.Remove(candidates[0]);
            }
        }
        // Identical content outranks an identical name: code transformers hand out names (a, b, c...) afresh at each build, so
        // the method called r() in the new build may be another method than the old r().
        Take((a, b) => a.Method.Name == b.Method.Name && a.Signature == b.Signature && (a.Size <= 2 || a.Shape == b.Shape), "same name");
        Take((a, b) => a.Size > 2 && a.Shape == b.Shape && a.Signature == b.Signature, "identical body (renamed)");
        Take((a, b) => a.Size > 2 && a.Skeleton == b.Skeleton && a.Signature == b.Signature, "identical body but for numeric constants (renamed)");
        Take((a, b) => a.Method.Name == b.Method.Name && a.Signature == b.Signature, "same name");
        Take((a, b) => a.Method.Name == b.Method.Name, "same name, signature changed");
        Take((a, b) => a.Size > 2 && a.Shape == b.Shape, "identical body shape (renamed)");
        Take((a, b) => a.Size > 2 && a.Skeleton == b.Skeleton, "identical body shape but for numeric constants (renamed)");
        foreach (var om in oldMethods.ToList())
        {
            var best = newMethods.Select(nm => (nm, Score: MethodScore(om, nm))).Where(x => x.Score >= MethodThreshold).OrderByDescending(x => x.Score).FirstOrDefault();
            if (best.nm == null) continue;
            matched.Add((om, best.nm, $"similar content ({best.Score:P0})"));
            oldMethods.Remove(om);
            newMethods.Remove(best.nm);
        }

        foreach (var (om, nm, how) in matched)
        {
            memberMap[om.Method] = (nm.Method, how);
            if (om.Method.Name != nm.Method.Name)
                changes.Add(new MemberChange("renamed", om.Method, nm.Method, how));
            else if (om.Signature != nm.Signature)
                changes.Add(new MemberChange("signature", om.Method, nm.Method, $"{om.Signature} -> {nm.Signature}"));
            else if (om.Full != nm.Full && (om.Size > 0 || nm.Size > 0))
            {
                // Bodies that are not valid IL (e.g. encrypted) cannot be compared.
                bool oldBad = !oldInfo.Assembly.IsDirty && oldInfo.Assembly.BodyHealth.IsInvalid(om.Method);
                bool newBad = !newInfo.Assembly.IsDirty && newInfo.Assembly.BodyHealth.IsInvalid(nm.Method);
                var detail = oldBad || newBad
                    ? $"{(oldBad ? "old" : "")}{(oldBad && newBad ? " and " : "")}{(newBad ? "new" : "")} body not valid IL (encrypted?); not comparable"
                    : $"{om.Size} -> {nm.Size} instructions";
                changes.Add(new MemberChange("body", om.Method, nm.Method, detail));
            }
            var oldAddress = Il2CppService.CompactSummary(om.Method);
            var newAddress = Il2CppService.CompactSummary(nm.Method);
            if (oldAddress != null && newAddress != null && oldAddress != newAddress)
                changes.Add(new MemberChange("address", om.Method, nm.Method, $"{oldAddress} -> {newAddress}"));
        }
        changes.AddRange(oldMethods.Select(m => new MemberChange("removed", m.Method, null, m.Signature)));
        changes.AddRange(newMethods.Select(m => new MemberChange("added", null, m.Method, m.Signature)));

        // Fields: by name, then by type and position (renamed).
        var oldFields = o.Fields.ToList();
        var newFields = n.Fields.ToList();
        foreach (var of in o.Fields)
        {
            var nf = newFields.FirstOrDefault(f => f.Name == of.Name);
            if (nf == null) continue;
            oldFields.Remove(of);
            newFields.Remove(nf);
            memberMap[of] = (nf, "same name");
            if (Format.Type(of.FieldType) != Format.Type(nf.FieldType))
                changes.Add(new MemberChange("type", of, nf, $"{Format.Type(of.FieldType)} -> {Format.Type(nf.FieldType)}"));
            CompareOffsets(of, nf, changes);
        }
        foreach (var of in oldFields.ToList())
        {
            var sameType = newFields.Where(f => Format.Type(f.FieldType) == Format.Type(of.FieldType) && f.IsStatic == of.IsStatic).ToList();
            var nf = sameType.Count == 1 ? sameType[0]
                : sameType.FirstOrDefault(f => n.Fields.IndexOf(f) == o.Fields.IndexOf(of));
            if (nf == null) continue;
            oldFields.Remove(of);
            newFields.Remove(nf);
            memberMap[of] = (nf, "same type and position (renamed)");
            changes.Add(new MemberChange("renamed", of, nf, "same type and position"));
            CompareOffsets(of, nf, changes);
        }
        changes.AddRange(oldFields.Select(f => new MemberChange("removed", f, null, Format.Field(f))));
        changes.AddRange(newFields.Select(f => new MemberChange("added", null, f, Format.Field(f))));

        foreach (var op in o.Properties)
        {
            var np = n.Properties.FirstOrDefault(p => p.Name == op.Name);
            if (np != null) memberMap[op] = (np, "same name");
            else changes.Add(new MemberChange("removed", op, null, Format.Property(op)));
        }
        foreach (var np in n.Properties.Where(p => !o.Properties.Any(x => x.Name == p.Name)))
            changes.Add(new MemberChange("added", null, np, Format.Property(np)));
        foreach (var oe in o.Events)
            if (n.Events.FirstOrDefault(e => e.Name == oe.Name) is { } ne) memberMap[oe] = (ne, "same name");
        return changes;
    }

    private static double MethodScore(MethodPrint a, MethodPrint b)
    {
        if (a.Method.IsStatic != b.Method.IsStatic || ParamCount(a.Method) != ParamCount(b.Method)) return 0;
        double sig = a.Signature == b.Signature ? 1 : 0;
        double size = 1.0 - Math.Min(1.0, Math.Abs(a.Size - b.Size) / (double)Math.Max(1, Math.Max(a.Size, b.Size)));
        double strings = a.Strings.Count + b.Strings.Count == 0 ? size : Jaccard(a.Strings, b.Strings);
        return 0.45 * sig + 0.3 * size + 0.25 * strings;
    }

    private static void CompareOffsets(FieldDef of, FieldDef nf, List<MemberChange> changes)
    {
        var a = Il2CppService.CompactSummary(of);
        var b = Il2CppService.CompactSummary(nf);
        if (a != null && b != null && a != b)
            changes.Add(new MemberChange("offset", of, nf, $"{a} -> {b}"));
    }
}
