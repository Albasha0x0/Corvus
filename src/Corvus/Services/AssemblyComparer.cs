using System.Collections.Concurrent;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Corvus.Core;
using static Corvus.Core.MetadataUtil;

namespace Corvus.Services;

/// <summary>
/// Compares two builds of an assembly: added, removed and renamed types and members, signature and body changes,
/// and Il2Cpp field-offset / address changes. Renamed or moved definitions are matched by content (IL shape,
/// string literals, field and member structure).
///
/// Members are matched in tiers (full name and signature, matched type and name, normalized IL hash, body shape,
/// structure, similarity). A tier pairs two members only when its key is unique among the unmatched members on both
/// sides; a member whose key is shared at some tier and that no later tier pairs is reported as ambiguous with its
/// candidates instead of being guessed. Methods left over in every type are then paired across types (moved) by identical
/// bodies, under the same rule.
/// </summary>
public sealed partial class AssemblyComparer(AssemblyWorkspace workspace)
{
    /// <summary>One way a matched member changed. Kind: renamed, signature, type, body, metadata, address or offset.</summary>
    public sealed record ChangeDimension(string Kind, string Detail);

    /// <summary>Candidates: for "ambiguous", the new members that tie.</summary>
    public sealed record MemberChange(string Change, IMemberDef? Old, IMemberDef? New, string Detail, IReadOnlyList<IMemberDef>? Candidates = null)
    {
        /// <summary>Every change of a matched pair, the first being Change and Detail; a single entry otherwise.</summary>
        public IReadOnlyList<ChangeDimension> Dimensions { get; init; } = [new(Change, Detail)];

        public static MemberChange Of(IMemberDef old, IMemberDef @new, List<ChangeDimension> dimensions) =>
            new(dimensions[0].Kind, old, @new, dimensions[0].Detail) { Dimensions = dimensions };
    }

    public sealed record TypeChange(string Change, TypeDef? Old, TypeDef? New, double Score, List<MemberChange> Members, IReadOnlyList<IMemberDef>? Candidates = null);

    /// <summary>A pairing: How describes the evidence, Tier names the matching tier, Confidence is exact, strong or structural.</summary>
    public sealed record Match(IMemberDef New, string How, string Tier, string Confidence);

    /// <summary>An old member whose key is shared at <see cref="Tier"/> by several new members (and no later tier decided).</summary>
    public sealed record Ambiguity(string Tier, IReadOnlyList<IMemberDef> Candidates);

    public sealed record Comparison(
        LoadedAssembly Old, LoadedAssembly New, List<TypeChange> Types,
        IReadOnlyDictionary<TypeDef, TypeDef> TypeMap, IReadOnlyDictionary<IMemberDef, Match> MemberMap,
        IReadOnlyDictionary<IMemberDef, Ambiguity> Ambiguous)
    {
        /// <summary>Method bodies that are not valid IL in the old / new build: their bodies were not compared.</summary>
        public int OldSkippedBodies { get; init; }
        public int NewSkippedBodies { get; init; }
    }

    /// <summary>Result of <see cref="FindCounterpart"/>; Candidates is set when the match is ambiguous.</summary>
    public sealed record Counterpart(IMemberDef? Match, string How, string? Tier = null, string? Confidence = null, IReadOnlyList<IMemberDef>? Candidates = null)
    {
        public void Deconstruct(out IMemberDef? match, out string how) => (match, how) = (Match, How);
    }

    private readonly ConditionalWeakTable<LoadedAssembly, ConditionalWeakTable<LoadedAssembly, CacheEntry>> _cache = new();

    private sealed record CacheEntry(long Key, Comparison Value);

    private const double TypeThreshold = 0.6;
    private const double MethodThreshold = 0.6;
    private const int MinStructureSize = 8;

    public Comparison Compare(LoadedAssembly oldAsm, LoadedAssembly newAsm, CancellationToken ct)
    {
        if (oldAsm == newAsm)
            throw new ToolError(ErrorCode.InvalidArgument, "Pick two different assemblies (load both builds; the second gets an id like Name#2).");
        long key = ((long)workspace.Generation << 32) | (uint)(oldAsm.Version * 65_537 + newAsm.Version);
        var inner = _cache.GetOrCreateValue(oldAsm);
        if (inner.TryGetValue(newAsm, out var cached) && cached.Key == key)
            return cached.Value;

        var oldInfo = Fingerprints(oldAsm, ct);
        var newInfo = Fingerprints(newAsm, ct);
        var ambiguous = new Dictionary<IMemberDef, Ambiguity>();
        var typeMap = MatchTypes(oldInfo, newInfo, out var typeScores, ambiguous, ct);
        var memberMap = new Dictionary<IMemberDef, Match>();
        // Member changes by old type: matched types, and removed types (methods moved out of them).
        var members = new Dictionary<TypeDef, List<MemberChange>>();
        foreach (var (o, n) in typeMap)
        {
            ct.ThrowIfCancellationRequested();
            members[o] = CompareMembers(oldInfo, newInfo, typeMap, o, n, memberMap, ambiguous);
        }
        foreach (var o in oldInfo.Types.Keys.Where(t => !typeMap.ContainsKey(t) && !ambiguous.ContainsKey(t)))
            members[o] = [];
        var mappedNew = typeMap.Values.ToHashSet();
        var candidateNew = ambiguous.Where(a => a.Key is TypeDef).SelectMany(a => a.Value.Candidates).ToHashSet();
        var addedTypes = newInfo.Types.Keys.Where(t => !mappedNew.Contains(t) && !candidateNew.Contains(t)).ToList();
        MatchMoves(oldInfo, newInfo, typeMap, members, addedTypes, memberMap, ambiguous);
        MarkUnknown(oldInfo.Assembly, newInfo.Assembly, typeMap, members);

        var changes = new List<TypeChange>();
        foreach (var (o, n) in typeMap)
        {
            bool renamed = o.FullName != n.FullName;
            if (renamed || members[o].Count > 0)
                changes.Add(new TypeChange(renamed ? "renamed" : "changed", o, n, typeScores.GetValueOrDefault(o, 1.0), members[o]));
        }
        foreach (var o in oldInfo.Types.Keys.Where(t => !typeMap.ContainsKey(t)))
            changes.Add(ambiguous.TryGetValue(o, out var a)
                ? new TypeChange("ambiguous", o, null, 0, [], a.Candidates)
                : new TypeChange("removed", o, null, 0, members[o]));
        changes.AddRange(addedTypes.Select(n => new TypeChange("added", null, n, 0, [])));

        var order = new Dictionary<string, int> { ["renamed"] = 0, ["changed"] = 1, ["ambiguous"] = 2, ["removed"] = 3, ["added"] = 4 };
        changes.Sort((a, b) => order[a.Change] != order[b.Change] ? order[a.Change] - order[b.Change]
            : string.CompareOrdinal((a.Old ?? a.New)!.FullName, (b.Old ?? b.New)!.FullName));

        var result = new Comparison(oldAsm, newAsm, changes, typeMap, memberMap, ambiguous)
        {
            OldSkippedBodies = oldAsm.BodyHealth.Invalid,
            NewSkippedBodies = newAsm.BodyHealth.Invalid,
        };
        inner.AddOrUpdate(newAsm, new CacheEntry(key, result));
        return result;
    }

    /// <summary>The counterpart of an old type or member in the new build.</summary>
    public Counterpart FindCounterpart(Comparison comparison, IMemberDef oldMember)
    {
        if (comparison.Ambiguous.TryGetValue(oldMember, out var a))
            return new Counterpart(null, $"ambiguous: {a.Candidates.Count} candidates share the {a.Tier} key", a.Tier, null, a.Candidates);
        if (oldMember is TypeDef t)
        {
            if (!comparison.TypeMap.TryGetValue(t, out var nt)) return new Counterpart(null, "type not found in the new build");
            var (tier, confidence) = TypeTier(t, nt);
            return new Counterpart(nt, nt.FullName == t.FullName ? "same name" : "matched by content", tier, confidence);
        }
        if (comparison.MemberMap.TryGetValue(oldMember, out var m))
            return new Counterpart(m.New, m.How, m.Tier, m.Confidence);
        var declaring = oldMember.DeclaringType;
        return declaring != null && !comparison.TypeMap.ContainsKey(declaring)
            ? new Counterpart(null, $"its type {declaring.FullName} was not found in the new build")
            : new Counterpart(null, "removed in the new build (no match)");
    }

    /// <summary>
    /// One old type or member and where it went. Status: matched; removed; ambiguous (Candidates lists the tied new
    /// tokens); unknown (no counterpart, but the other build's bodies or signatures could not be read); type_unmatched
    /// (its type has no counterpart). BodyHashEqual: methods with a normalized IL hash on both sides.
    /// </summary>
    public sealed record TokenMapEntry(string Kind, string Old, string OldToken, string? New, string? NewToken, string Status,
        string? Tier, string? Confidence, bool? BodyHashEqual, IReadOnlyList<string>? Candidates);

    /// <summary>Every type and member of the old build (except &lt;Module&gt;), in token order.</summary>
    public static List<TokenMapEntry> TokenMap(Comparison cmp)
    {
        var changes = cmp.Types.SelectMany(t => t.Members).Where(m => m.Old != null).GroupBy(m => m.Old!).ToDictionary(g => g.Key, g => g.First());
        var entries = new List<TokenMapEntry>();
        foreach (var type in cmp.Old.Module.GetTypes().Where(t => t.FullName != "<Module>"))
        {
            Add(type);
            foreach (var m in type.Methods.Cast<IMemberDef>().Concat(type.Fields).Concat(type.Properties).Concat(type.Events)) Add(m);
        }
        return [.. entries.OrderBy(e => e.OldToken, StringComparer.Ordinal)];

        void Add(IMemberDef old)
        {
            string kind = old switch { TypeDef => "type", MethodDef => "method", FieldDef => "field", PropertyDef => "property", _ => "event" };
            if (cmp.Ambiguous.TryGetValue(old, out var a))
            {
                entries.Add(new(kind, Format.MemberLabel(old), Format.Token(old), null, null, "ambiguous", a.Tier, null, null,
                    a.Candidates.Select(Format.Token).ToList()));
                return;
            }
            IMemberDef? match = null;
            string? tier = null, confidence = null;
            if (old is TypeDef t && cmp.TypeMap.TryGetValue(t, out var nt))
            {
                match = nt;
                (tier, confidence) = TypeTier(t, nt);
            }
            else if (cmp.MemberMap.TryGetValue(old, out var m))
                (match, tier, confidence) = (m.New, m.Tier, m.Confidence);
            if (match == null)
            {
                var status = old is not TypeDef && old.DeclaringType is { } d && !cmp.TypeMap.ContainsKey(d) ? "type_unmatched"
                    : changes.TryGetValue(old, out var c) && c.Change == "unknown" ? "unknown" : "removed";
                entries.Add(new(kind, Format.MemberLabel(old), Format.Token(old), null, null, status, null, null, null, null));
                return;
            }
            bool? same = old is MethodDef om && match is MethodDef nm && IlHash.Of(cmp.Old, om) is { } oh && IlHash.Of(cmp.New, nm) is { } nh ? oh == nh : null;
            entries.Add(new(kind, Format.MemberLabel(old), Format.Token(old), Format.MemberLabel(match), Format.Token(match), "matched", tier, confidence, same, null));
        }
    }

    /// <summary>Tier and confidence of a type pairing.</summary>
    public static (string Tier, string Confidence) TypeTier(TypeDef o, TypeDef n) =>
        o.FullName == n.FullName ? ("full name", "exact")
        : NormalizeName(o.Name) == NormalizeName(n.Name) ? ("name (moved)", "strong")
        : ("content", "structural");

    /// <summary>
    /// Shape: opcodes and literals. Skeleton: opcodes and string literals only. Control-flow transformers plant random integer
    /// constants that change with every build, so only the skeleton survives a rebuild.
    /// </summary>
    /// <remarks>IlHash: <see cref="Services.IlHash"/> (null: no body or not valid IL). Structure: signature shape, size bucket,
    /// opcode histogram, call / field reference shape and exception region shape, for bodies too changed to share a shape.</remarks>
    private sealed record MethodPrint(MethodDef Method, string Signature, ulong Shape, ulong Skeleton, int Size, HashSet<string> Strings,
        string? IlHash, string Structure);

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
        ulong shape = 14695981039346656037UL, skeleton = shape;
        var strings = new HashSet<string>(StringComparer.Ordinal);
        int size = 0;
        var body = FastIlReader.Read(asm, m);
        var instructions = body?.Instructions ?? MetadataUtil.SafeInstructions(m);
        var histogram = new SortedDictionary<Code, int>();
        var references = new List<string>();
        foreach (var i in instructions)
        {
            size++;
            var op = Canonical(i.OpCode.Code);
            shape = Mix(shape, (ulong)op);
            skeleton = Mix(skeleton, (ulong)op);
            histogram[op] = histogram.GetValueOrDefault(op) + 1;
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
                if (i.Operand is string str)
                {
                    strings.Add(str);
                    skeleton = Mix(skeleton, Hash(literal));
                }
            }
            else if (AsMethod(i.Operand) is { } callee)
                references.Add($"m{(callee.MethodSig?.HasThis == true ? "i" : "s")}{callee.MethodSig?.Params.Count ?? 0}{(callee.MethodSig?.RetType?.ElementType == ElementType.Void ? "v" : "r")}");
            else if (AsField(i.Operand) is { } field)
                references.Add(i.OpCode.Code is Code.Ldsfld or Code.Stsfld or Code.Ldsflda ? "fs" : "fi");
        }
        var signature = $"{(m.IsStatic ? "static " : "")}{Format.Type(m.ReturnType)}({Format.ParameterTypes(m.MethodSig)})";
        // Instruction counts below 8 are kept exact, larger ones bucketed by 25% steps.
        int bucket = size < 8 ? size : 8 + (int)Math.Round(Math.Log(size / 8.0) / Math.Log(1.25));
        references.Sort(StringComparer.Ordinal);
        var structure = string.Join("|",
            $"{(m.IsStatic ? "s" : "i")}{ParamCount(m)}{(m.ReturnType?.ElementType == ElementType.Void ? "v" : "r")}",
            bucket.ToString(CultureInfo.InvariantCulture),
            string.Join(",", histogram.Select(h => $"{(int)h.Key:x}:{h.Value}")),
            string.Join(",", references),
            string.Join(",", body?.Regions.Select(r => r.Kind.ToString()) ?? []));
        return new MethodPrint(m, signature, shape, skeleton, size, strings, IlHash.Of(asm, m, body), structure);
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

    private static Dictionary<TypeDef, TypeDef> MatchTypes(Info oldInfo, Info newInfo, out Dictionary<TypeDef, double> scores,
        Dictionary<IMemberDef, Ambiguity> ambiguous, CancellationToken ct)
    {
        var map = new Dictionary<TypeDef, TypeDef>();
        scores = new Dictionary<TypeDef, double>();
        // Full names unique on both sides (duplicates occur only in transformed or merged images).
        var oldNames = oldInfo.Types.Keys.GroupBy(t => t.FullName).ToDictionary(g => g.Key, g => g.Count());
        var newByName = newInfo.Types.Keys.GroupBy(t => t.FullName).Where(g => g.Count() == 1).ToDictionary(g => g.Key, g => g.First());
        foreach (var t in oldInfo.Types.Keys)
            if (oldNames[t.FullName] == 1 && newByName.TryGetValue(t.FullName, out var n))
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
            // Best score first; a pair whose score another free pair with the same old or new type ties is not decided:
            // the old types involved are ambiguous and the tied new types stay unpaired.
            var usedOld = new HashSet<TypeDef>();
            var usedNew = new HashSet<TypeDef>();
            var ordered = candidates.OrderByDescending(c => c.Score).ToList();
            var byOld = ordered.ToLookup(c => c.Old.Type);
            var byNew = ordered.ToLookup(c => c.New.Type);
            bool Free((TypePrint Old, TypePrint New, double Score) c) => !usedOld.Contains(c.Old.Type) && !usedNew.Contains(c.New.Type);
            foreach (var (o, n, score) in ordered)
            {
                if (usedOld.Contains(o.Type) || usedNew.Contains(n.Type)) continue;
                var ties = byOld[o.Type].Where(c => c.Score == score && c.New.Type != n.Type && Free(c))
                    .Concat(byNew[n.Type].Where(c => c.Score == score && c.Old.Type != o.Type && Free(c))).ToList();
                if (ties.Count > 0)
                {
                    var olds = ties.Select(c => c.Old.Type).Append(o.Type).Distinct().ToList();
                    var news = ties.Select(c => c.New.Type).Append(n.Type).Distinct().ToList();
                    foreach (var ot in olds)
                        ambiguous[ot] = new Ambiguity("type content", byOld[ot].Where(c => c.Score == score && news.Contains(c.New.Type)).Select(c => (IMemberDef)c.New.Type).ToList());
                    usedOld.UnionWith(olds);
                    usedNew.UnionWith(news);
                    continue;
                }
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

    /// <summary>A member-matching tier: Key null means the member takes no part in this tier.</summary>
    private sealed record Tier<T>(string Name, string How, Func<T, string?> OldKey, Func<T, string?> NewKey, Func<T, T, string> Confidence);

    /// <summary>
    /// Pairs old and new members tier by tier; a key pairs two members only when exactly one unmatched old and one unmatched
    /// new member have it. Returns the pairs; old members whose key was shared at some tier get their first such tier and
    /// the tied new members in <paramref name="ties"/>.
    /// </summary>
    private static List<(T Old, T New, string How, string Tier, string Confidence)> MatchInTiers<T>(List<T> olds, List<T> news, IReadOnlyList<Tier<T>> tiers,
        Dictionary<T, (string Tier, List<T> Candidates)> ties) where T : notnull
    {
        var pairs = new List<(T, T, string, string, string)>();
        // Repeated while a pass pairs anything: a key shared at one pass can become unique once a later tier has paired
        // the others. The ties of the last pass are those of the members left over.
        for (int found = -1; found != pairs.Count;)
        {
            found = pairs.Count;
            ties.Clear();
            foreach (var tier in tiers)
            {
                if (olds.Count == 0 || news.Count == 0) break;
                var oldGroups = olds.Select(x => (x, Key: tier.OldKey(x))).Where(x => x.Key != null).GroupBy(x => x.Key!, x => x.x, StringComparer.Ordinal).ToList();
                var newGroups = news.Select(x => (x, Key: tier.NewKey(x))).Where(x => x.Key != null).GroupBy(x => x.Key!, x => x.x, StringComparer.Ordinal)
                    .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.Ordinal);
                foreach (var g in oldGroups)
                {
                    if (!newGroups.TryGetValue(g.Key, out var candidates)) continue;
                    var sameKey = g.ToList();
                    if (sameKey.Count == 1 && candidates.Count == 1)
                    {
                        pairs.Add((sameKey[0], candidates[0], tier.How, tier.Name, tier.Confidence(sameKey[0], candidates[0])));
                        olds.Remove(sameKey[0]);
                        news.Remove(candidates[0]);
                    }
                    else
                    {
                        foreach (var x in sameKey) ties.TryAdd(x, (tier.Name, candidates));
                    }
                }
            }
        }
        return pairs;
    }

    /// <summary>Every way a matched method changed: renamed, signature, body, metadata, Il2Cpp address.</summary>
    private static List<ChangeDimension> MethodChanges(Info oldInfo, Info newInfo, MethodPrint om, MethodPrint nm, string how)
    {
        static string Body(MethodPrint p) => p.IlHash ?? (p.Size <= 2 ? "small" : "?" + p.Shape.ToString(CultureInfo.InvariantCulture));
        var dimensions = new List<ChangeDimension>();
        if (om.Method.Name != nm.Method.Name)
            dimensions.Add(new("renamed", how));
        if (om.Signature != nm.Signature)
            dimensions.Add(new("signature", $"{om.Signature} -> {nm.Signature}"));
        if (Body(om) != Body(nm))
        {
            // Bodies that are not valid IL (e.g. encrypted) cannot be compared.
            bool oldBad = !oldInfo.Assembly.IsDirty && oldInfo.Assembly.BodyHealth.IsInvalid(om.Method);
            bool newBad = !newInfo.Assembly.IsDirty && newInfo.Assembly.BodyHealth.IsInvalid(nm.Method);
            dimensions.Add(new("body", oldBad || newBad
                ? $"{(oldBad ? "old" : "")}{(oldBad && newBad ? " and " : "")}{(newBad ? "new" : "")} body not valid IL (encrypted?); not comparable"
                : $"{om.Size} -> {nm.Size} instructions"));
        }
        if (MetadataDifference(om.Method, nm.Method) is { } metadata)
            dimensions.Add(new("metadata", metadata));
        var oldAddress = Il2CppService.CompactSummary(om.Method);
        var newAddress = Il2CppService.CompactSummary(nm.Method);
        if (oldAddress != null && newAddress != null && oldAddress != newAddress)
            dimensions.Add(new("address", $"{oldAddress} -> {newAddress}"));
        return dimensions;
    }

    /// <summary>
    /// Methods moved to another type. After the per-type matching, the methods left over (removed from a matched type or
    /// in a removed type; added to a matched type or in an added type) are paired across types by identical body (IL
    /// hash), then by identical body but for numeric constants, with the signature in both keys. Unique-only, like the
    /// per-type tiers; an old method listed as removed whose key is shared becomes ambiguous.
    /// </summary>
    private static void MatchMoves(Info oldInfo, Info newInfo, IReadOnlyDictionary<TypeDef, TypeDef> typeMap, Dictionary<TypeDef, List<MemberChange>> members,
        List<TypeDef> addedTypes, Dictionary<IMemberDef, Match> memberMap, Dictionary<IMemberDef, Ambiguity> ambiguous)
    {
        var listed = members.Values.SelectMany(l => l).Where(c => c.Change == "removed" && c.Old is MethodDef).Select(c => (MethodDef)c.Old!).ToHashSet();
        var olds = listed.Concat(members.Keys.Where(t => !typeMap.ContainsKey(t)).SelectMany(t => t.Methods)).Distinct().Select(m => oldInfo.Methods[m]).ToList();
        var news = members.Values.SelectMany(l => l).Where(c => c.Change == "added" && c.New is MethodDef).Select(c => (MethodDef)c.New!)
            .Concat(addedTypes.SelectMany(t => t.Methods)).Distinct().Select(m => newInfo.Methods[m]).ToList();
        if (olds.Count == 0 || news.Count == 0) return;
        var oldSig = olds.ToDictionary(p => p, p => NormalizedSignature(p.Method, t => typeMap.TryGetValue(t, out var nt) ? nt.FullName : t.FullName));
        var newSig = news.ToDictionary(p => p, p => NormalizedSignature(p.Method, t => t.FullName));
        var tiers = new List<Tier<MethodPrint>>
        {
            new("IL hash, other type", "identical body (moved)", p => p.Size > 2 && p.IlHash != null ? $"{oldSig[p]}|{p.IlHash}" : null,
                p => p.Size > 2 && p.IlHash != null ? $"{newSig[p]}|{p.IlHash}" : null, (_, _) => "strong"),
            // Without member references the skeleton is common among small bodies: substantial ones only.
            new("body shape, other type", "identical body but for numeric constants (moved)", p => p.Size >= MinStructureSize ? $"{oldSig[p]}|{p.Skeleton}" : null,
                p => p.Size >= MinStructureSize ? $"{newSig[p]}|{p.Skeleton}" : null, (_, _) => "structural"),
        };
        var ties = new Dictionary<MethodPrint, (string Tier, List<MethodPrint> Candidates)>();
        var pairs = MatchInTiers(olds, news, tiers, ties);
        var ownerOfNew = typeMap.ToDictionary(kv => kv.Value, kv => kv.Key);
        void Unlist(MethodDef added)
        {
            if (added.DeclaringType is { } t && ownerOfNew.TryGetValue(t, out var owner))
                members[owner].RemoveAll(c => c.Change == "added" && c.New == added);
        }
        foreach (var (op, np, how, tier, confidence) in pairs)
        {
            var (om, nm) = (op.Method, np.Method);
            memberMap[om] = new Match(nm, how, tier, confidence);
            var list = members[om.DeclaringType];
            list.RemoveAll(c => c.Change == "removed" && c.Old == om);
            Unlist(nm);
            list.Add(MemberChange.Of(om, nm, [new("moved", $"to {nm.DeclaringType.FullName}"), .. MethodChanges(oldInfo, newInfo, op, np, how)]));
        }
        foreach (var op in olds)
        {
            if (!listed.Contains(op.Method) || !ties.TryGetValue(op, out var tie)) continue;
            var candidates = tie.Candidates.Where(news.Contains).Select(c => (IMemberDef)c.Method).ToList();
            if (candidates.Count == 0) continue;
            ambiguous[op.Method] = new Ambiguity(tie.Tier, candidates);
            var list = members[op.Method.DeclaringType];
            list.RemoveAll(c => c.Change == "removed" && c.Old == op.Method);
            list.Add(new MemberChange("ambiguous", op.Method, null, $"{candidates.Count} candidates share the {tie.Tier} key", candidates));
            foreach (var c in candidates) Unlist((MethodDef)c);
        }
    }

    /// <summary>
    /// A method or field without a counterpart is "unknown" instead of removed or added when the evidence to pair it is
    /// missing: its own body is not valid IL or its signature is unreadable, most bodies of the other build are not valid
    /// IL, or the counterpart type has an unpaired member of the same kind with such a body or signature (it may be this
    /// member). The detail says which.
    /// </summary>
    private static void MarkUnknown(LoadedAssembly oldAsm, LoadedAssembly newAsm, IReadOnlyDictionary<TypeDef, TypeDef> typeMap,
        Dictionary<TypeDef, List<MemberChange>> members)
    {
        foreach (var o in typeMap.Keys)
        {
            var list = members[o];
            var removed = list.Where(c => c.Change == "removed").Select(c => c.Old!).ToList();
            var added = list.Where(c => c.Change == "added").Select(c => c.New!).ToList();
            for (int i = 0; i < list.Count; i++)
            {
                var c = list[i];
                if (c.Change is not ("removed" or "added") || (c.Old ?? c.New) is not (MethodDef or FieldDef)) continue;
                bool isOld = c.Change == "removed";
                var member = (c.Old ?? c.New)!;
                var (own, other, otherSide) = isOld ? (oldAsm, newAsm, "new") : (newAsm, oldAsm, "old");
                var suspect = (isOld ? added : removed).FirstOrDefault(x => x.GetType() == member.GetType() && Incomplete(other, x) != null);
                var reason = Incomplete(own, member) is { } self ? $"its {self}"
                    : member is MethodDef && other.BodyHealth.MostlyInvalid ? $"most method bodies of the {otherSide} build are not valid IL"
                    : suspect != null ? $"{Format.MemberLabel(suspect)} in the {otherSide} build has a {Incomplete(other, suspect)} and may be this member"
                    : null;
                if (reason != null)
                    list[i] = new MemberChange("unknown", c.Old, c.New, $"{c.Detail}; no counterpart in the {otherSide} build, not shown as {c.Change}: {reason}");
            }
        }
    }

    /// <summary>Why a member could not take part in content matching, or null.</summary>
    private static string? Incomplete(LoadedAssembly asm, IMemberDef m) => m switch
    {
        MethodDef md when !asm.IsDirty && asm.BodyHealth.IsInvalid(md) => "body that is not valid IL",
        MethodDef md when md.MethodSig is not { RetType: not null } sig || sig.Params.Any(p => p == null) => "signature that cannot be read",
        FieldDef f when f.FieldSig?.Type == null => "signature that cannot be read",
        _ => null,
    };

    private static List<MemberChange> CompareMembers(Info oldInfo, Info newInfo, IReadOnlyDictionary<TypeDef, TypeDef> typeMap, TypeDef o, TypeDef n,
        Dictionary<IMemberDef, Match> memberMap, Dictionary<IMemberDef, Ambiguity> ambiguous)
    {
        var changes = new List<MemberChange>();
        bool sameType = o.FullName == n.FullName;
        string NameConfidence() => sameType ? "exact" : "strong";
        string nameTier = sameType ? "full name + signature" : "type match + name + signature";

        // Methods. Signatures are compared with old types replaced by their counterparts, so a parameter whose type was
        // renamed still has the same signature.
        var oldMethods = o.Methods.Select(m => oldInfo.Methods[m]).ToList();
        var newMethods = n.Methods.Select(m => newInfo.Methods[m]).ToList();
        var oldSig = oldMethods.ToDictionary(p => p, p => NormalizedSignature(p.Method, t => typeMap.TryGetValue(t, out var nt) ? nt.FullName : t.FullName));
        var newSig = newMethods.ToDictionary(p => p, p => NormalizedSignature(p.Method, t => t.FullName));
        // Identical content outranks an identical name: code transformers hand out names (a, b, c...) afresh at each build, so
        // the method called r() in the new build may be another method than the old r(). The first tier therefore wants the
        // body shape as well; the name and signature alone count after the content tiers.
        var methodTiers = new List<Tier<MethodPrint>>
        {
            new(nameTier, "same name", p => p.Size <= 2 ? $"{p.Method.Name}|{oldSig[p]}" : $"{p.Method.Name}|{oldSig[p]}|{p.Shape}",
                p => p.Size <= 2 ? $"{p.Method.Name}|{newSig[p]}" : $"{p.Method.Name}|{newSig[p]}|{p.Shape}", (_, _) => NameConfidence()),
            new("IL hash", "identical body (renamed)", p => p.Size > 2 && p.IlHash != null ? $"{oldSig[p]}|{p.IlHash}" : null,
                p => p.Size > 2 && p.IlHash != null ? $"{newSig[p]}|{p.IlHash}" : null, (_, _) => "strong"),
            new("body shape", "identical body shape (renamed)", p => p.Size > 2 ? $"{oldSig[p]}|{p.Shape}" : null,
                p => p.Size > 2 ? $"{newSig[p]}|{p.Shape}" : null, (_, _) => "structural"),
            new("body shape", "identical body but for numeric constants (renamed)", p => p.Size > 2 ? $"{oldSig[p]}|{p.Skeleton}" : null,
                p => p.Size > 2 ? $"{newSig[p]}|{p.Skeleton}" : null, (_, _) => "structural"),
            new(nameTier, "same name", p => $"{p.Method.Name}|{oldSig[p]}", p => $"{p.Method.Name}|{newSig[p]}", (_, _) => NameConfidence()),
            new("generated name", "same compiler-generated name, renumbered", p => RenumberedName(p.Method.Name) is { } g ? $"{g}|{oldSig[p]}" : null,
                p => RenumberedName(p.Method.Name) is { } g ? $"{g}|{newSig[p]}" : null, (_, _) => "strong"),
            new("name", "same name, signature changed", p => p.Method.Name, p => p.Method.Name, (_, _) => "strong"),
            new("IL hash", "identical body, signature changed", p => p.Size > 2 ? p.IlHash : null, p => p.Size > 2 ? p.IlHash : null, (_, _) => "strong"),
            new("body shape", "identical body shape (renamed)", p => p.Size > 2 ? p.Shape.ToString(CultureInfo.InvariantCulture) : null,
                p => p.Size > 2 ? p.Shape.ToString(CultureInfo.InvariantCulture) : null, (_, _) => "structural"),
            new("body shape", "identical body shape but for numeric constants (renamed)", p => p.Size > 2 ? p.Skeleton.ToString(CultureInfo.InvariantCulture) : null,
                p => p.Size > 2 ? p.Skeleton.ToString(CultureInfo.InvariantCulture) : null, (_, _) => "structural"),
            // Small bodies share structure by chance: no evidence.
            new("structure", "same structure (renamed)", p => p.Size >= MinStructureSize ? p.Structure : null,
                p => p.Size >= MinStructureSize ? p.Structure : null, (_, _) => "structural"),
        };
        var methodTies = new Dictionary<MethodPrint, (string Tier, List<MethodPrint> Candidates)>();
        var matched = MatchInTiers(oldMethods, newMethods, methodTiers, methodTies);
        matched.AddRange(MatchBySimilarity(oldMethods, newMethods, methodTies));
        // A pair found by content that also has the same name and signature is a name match.
        for (int i = 0; i < matched.Count; i++)
            if (matched[i] is var (om, nm, _, _, _) && om.Method.Name == nm.Method.Name && oldSig[om] == newSig[nm])
                matched[i] = (om, nm, "same name", nameTier, NameConfidence());

        foreach (var (om, nm, how, tier, confidence) in matched)
        {
            memberMap[om.Method] = new Match(nm.Method, how, tier, confidence);
            var dimensions = MethodChanges(oldInfo, newInfo, om, nm, how);
            if (dimensions.Count > 0) changes.Add(MemberChange.Of(om.Method, nm.Method, dimensions));
        }
        // Old methods left over after a tie: ambiguous, with the tied new methods that are still unpaired.
        var tiedNew = new HashSet<MethodPrint>();
        foreach (var om in oldMethods.ToList())
        {
            if (!methodTies.TryGetValue(om, out var tie)) continue;
            var candidates = tie.Candidates.Where(newMethods.Contains).ToList();
            if (candidates.Count == 0) continue;
            oldMethods.Remove(om);
            tiedNew.UnionWith(candidates);
            ambiguous[om.Method] = new Ambiguity(tie.Tier, candidates.Select(c => (IMemberDef)c.Method).ToList());
            changes.Add(new MemberChange("ambiguous", om.Method, null, $"{candidates.Count} candidates share the {tie.Tier} key",
                candidates.Select(c => (IMemberDef)c.Method).ToList()));
        }
        changes.AddRange(oldMethods.Select(m => new MemberChange("removed", m.Method, null, m.Signature)));
        changes.AddRange(newMethods.Where(m => !tiedNew.Contains(m)).Select(m => new MemberChange("added", null, m.Method, m.Signature)));

        // Fields: by name, then by type when one field of that type is left on each side, then by type and position.
        var oldFields = o.Fields.ToList();
        var newFields = n.Fields.ToList();
        var oldFieldType = oldFields.ToDictionary(f => f, f => IlHash.TypeName(f.FieldType, t => typeMap.TryGetValue(t, out var nt) ? nt.FullName : t.FullName));
        var newFieldType = newFields.ToDictionary(f => f, f => IlHash.TypeName(f.FieldType, t => t.FullName));
        var fieldTiers = new List<Tier<FieldDef>>
        {
            new(sameType ? "full name" : "type match + name", "same name", f => f.Name, f => f.Name, (_, _) => NameConfidence()),
            new("initial data", "same initial data (renamed)", f => f.HasFieldRVA ? $"{oldFieldType[f]}|{InitialData(f)}" : null,
                f => f.HasFieldRVA ? $"{newFieldType[f]}|{InitialData(f)}" : null, (_, _) => "strong"),
            new("generated name", "same compiler-generated name, renumbered", f => RenumberedName(f.Name) is { } g ? $"{f.IsStatic}|{oldFieldType[f]}|{g}" : null,
                f => RenumberedName(f.Name) is { } g ? $"{f.IsStatic}|{newFieldType[f]}|{g}" : null, (_, _) => "strong"),
            new("field type", "same type (renamed)", f => $"{f.IsStatic}|{oldFieldType[f]}", f => $"{f.IsStatic}|{newFieldType[f]}", (_, _) => "structural"),
            new("field type + position", "same type and position (renamed)", f => $"{f.IsStatic}|{oldFieldType[f]}|{o.Fields.IndexOf(f)}",
                f => $"{f.IsStatic}|{newFieldType[f]}|{n.Fields.IndexOf(f)}", (_, _) => "structural"),
        };
        var fieldTies = new Dictionary<FieldDef, (string Tier, List<FieldDef> Candidates)>();
        foreach (var (of, nf, how, tier, confidence) in MatchInTiers(oldFields, newFields, fieldTiers, fieldTies))
        {
            memberMap[of] = new Match(nf, how, tier, confidence);
            var dimensions = new List<ChangeDimension>();
            if (of.Name != nf.Name)
                dimensions.Add(new("renamed", how.Replace(" (renamed)", "")));
            if (Format.Type(of.FieldType) != Format.Type(nf.FieldType))
                dimensions.Add(new("type", $"{Format.Type(of.FieldType)} -> {Format.Type(nf.FieldType)}"));
            if (MetadataDifference(of, nf) is { } metadata)
                dimensions.Add(new("metadata", metadata));
            var (oldOffset, newOffset) = (Il2CppService.CompactSummary(of), Il2CppService.CompactSummary(nf));
            if (oldOffset != null && newOffset != null && oldOffset != newOffset)
                dimensions.Add(new("offset", $"{oldOffset} -> {newOffset}"));
            if (dimensions.Count > 0) changes.Add(MemberChange.Of(of, nf, dimensions));
        }
        var tiedFields = new HashSet<FieldDef>();
        foreach (var of in oldFields.ToList())
        {
            if (!fieldTies.TryGetValue(of, out var tie)) continue;
            var candidates = tie.Candidates.Where(newFields.Contains).ToList();
            if (candidates.Count == 0) continue;
            oldFields.Remove(of);
            tiedFields.UnionWith(candidates);
            ambiguous[of] = new Ambiguity(tie.Tier, candidates.ToList<IMemberDef>());
            changes.Add(new MemberChange("ambiguous", of, null, $"{candidates.Count} candidates share the {tie.Tier} key", candidates.ToList<IMemberDef>()));
        }
        changes.AddRange(oldFields.Select(f => new MemberChange("removed", f, null, Format.Field(f))));
        changes.AddRange(newFields.Where(f => !tiedFields.Contains(f)).Select(f => new MemberChange("added", null, f, Format.Field(f))));

        foreach (var op in o.Properties)
        {
            var np = n.Properties.FirstOrDefault(p => p.Name == op.Name);
            if (np != null) memberMap[op] = new Match(np, "same name", sameType ? "full name" : "type match + name", NameConfidence());
            else changes.Add(new MemberChange("removed", op, null, Format.Property(op)));
        }
        foreach (var np in n.Properties.Where(p => !o.Properties.Any(x => x.Name == p.Name)))
            changes.Add(new MemberChange("added", null, np, Format.Property(np)));
        foreach (var oe in o.Events)
        {
            var ne = n.Events.FirstOrDefault(e => e.Name == oe.Name);
            if (ne != null) memberMap[oe] = new Match(ne, "same name", sameType ? "full name" : "type match + name", NameConfidence());
            else changes.Add(new MemberChange("removed", oe, null, Format.Event(oe)));
        }
        foreach (var ne in n.Events.Where(e => !o.Events.Any(x => x.Name == e.Name)))
            changes.Add(new MemberChange("added", null, ne, Format.Event(ne)));
        return changes;
    }

    /// <summary>
    /// Last tier: content similarity (signature, size, string literals). A pair is taken only when each is the other's
    /// single best candidate; equal best scores are ties.
    /// </summary>
    private static List<(MethodPrint Old, MethodPrint New, string How, string Tier, string Confidence)> MatchBySimilarity(
        List<MethodPrint> olds, List<MethodPrint> news, Dictionary<MethodPrint, (string Tier, List<MethodPrint> Candidates)> ties)
    {
        var pairs = new List<(MethodPrint, MethodPrint, string, string, string)>();
        while (olds.Count > 0 && news.Count > 0)
        {
            var scores = olds.SelectMany(a => news.Select(b => (Old: a, New: b, Score: MethodScore(a, b)))).Where(x => x.Score >= MethodThreshold).ToList();
            if (scores.Count == 0) break;
            var bestOld = scores.GroupBy(x => x.Old).ToDictionary(g => g.Key, g => g.Max(x => x.Score));
            var bestNew = scores.GroupBy(x => x.New).ToDictionary(g => g.Key, g => g.Max(x => x.Score));
            var taken = new List<(MethodPrint Old, MethodPrint New, double Score)>();
            foreach (var x in scores)
            {
                if (x.Score != bestOld[x.Old] || x.Score != bestNew[x.New]) continue;
                bool tied = scores.Any(y => y.Score == x.Score && ((y.Old == x.Old) != (y.New == x.New)));
                if (tied)
                {
                    ties.TryAdd(x.Old, ("similarity", scores.Where(y => y.Old == x.Old && y.Score == x.Score).Select(y => y.New).ToList()));
                    continue;
                }
                taken.Add(x);
            }
            if (taken.Count == 0) break;
            foreach (var (a, b, score) in taken)
            {
                pairs.Add((a, b, $"similar content ({score:P0})", "similarity", "structural"));
                olds.Remove(a);
                news.Remove(b);
            }
        }
        return pairs;
    }

    /// <summary>
    /// A compiler-generated name with the numbers that count methods or closures replaced (&lt;Run&gt;b__37_0 -> &lt;Run&gt;b__#_0,
    /// &lt;&gt;9__37_0 -> &lt;&gt;9__#_0); null for other names. Adding a method elsewhere in the type renumbers them.
    /// </summary>
    private static string? RenumberedName(string name) =>
        name.StartsWith('<') && GeneratedNumber().IsMatch(name) ? GeneratedNumber().Replace(name, "$1#") : null;

    [System.Text.RegularExpressions.GeneratedRegex(@"(__[A-Za-z]*|\|)\d+")]
    private static partial System.Text.RegularExpressions.Regex GeneratedNumber();

    /// <summary>SHA-256 of a field's RVA data (array initializers), or "?" when it cannot be read.</summary>
    private static string InitialData(FieldDef f)
    {
        try { return f.InitialValue is { } data ? Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(data)) : "?"; }
        catch { return "?"; }
    }

    /// <summary>Method signature with each type of this module written as <paramref name="name"/> gives it (token independent).</summary>
    private static string NormalizedSignature(MethodDef m, Func<TypeDef, string> name)
    {
        var sb = new StringBuilder(m.IsStatic ? "static " : "");
        sb.Append(IlHash.TypeName(m.ReturnType, name)).Append('(');
        var parameters = m.MethodSig?.Params ?? [];
        for (int i = 0; i < parameters.Count; i++)
            sb.Append(i > 0 ? "," : "").Append(IlHash.TypeName(parameters[i], name));
        sb.Append(')');
        if (m.MethodSig?.GenParamCount > 0) sb.Append('`').Append(m.MethodSig.GenParamCount);
        return sb.ToString();
    }

    /// <summary>Differences of flags, implementation flags and custom attributes, or null when there are none.</summary>
    private static string? MetadataDifference(IMemberDef a, IMemberDef b)
    {
        var parts = new List<string>();
        switch (a, b)
        {
            case (MethodDef x, MethodDef y):
                Flags("flags", x.Attributes, y.Attributes);
                Flags("impl", x.ImplAttributes, y.ImplAttributes);
                break;
            case (FieldDef x, FieldDef y):
                Flags("flags", x.Attributes, y.Attributes);
                break;
        }
        var oldAttributes = Attributes(a);
        var newAttributes = Attributes(b);
        var removed = oldAttributes.Except(newAttributes).ToList();
        var added = newAttributes.Except(oldAttributes).ToList();
        if (removed.Count > 0) parts.Add("attributes removed: " + string.Join(", ", removed.Select(x => Format.Clip(x, 100))));
        if (added.Count > 0) parts.Add("attributes added: " + string.Join(", ", added.Select(x => Format.Clip(x, 100))));
        return parts.Count == 0 ? null : string.Join("; ", parts);

        void Flags<TEnum>(string label, TEnum before, TEnum after) where TEnum : struct, Enum
        {
            if (before.Equals(after)) return;
            var x = before.ToString().Split(", ");
            var y = after.ToString().Split(", ");
            parts.Add(label + " " + string.Join(" ", x.Except(y).Select(f => "-" + f).Concat(y.Except(x).Select(f => "+" + f))));
        }
    }

    /// <summary>Custom attributes as type name and arguments; the compiler's NullableContext choice is left out.</summary>
    private static HashSet<string> Attributes(IMemberDef member) =>
        member is IHasCustomAttribute { CustomAttributes: var list }
            ? list.Where(ca => ca.TypeFullName != "System.Runtime.CompilerServices.NullableContextAttribute")
                .Select(ca => Format.StripArity(ca.AttributeType?.Name ?? "?") +
                              (ca.ConstructorArguments.Count > 0 ? "(" + string.Join(", ", ca.ConstructorArguments.Select(arg => ArgumentText(arg.Value))) + ")" : ""))
                .ToHashSet(StringComparer.Ordinal)
            : [];

    private static string ArgumentText(object? value) => value switch
    {
        null => "null",
        UTF8String s => "\"" + s.String + "\"",
        string s => "\"" + s + "\"",
        TypeSig t => "typeof(" + t.FullName + ")",
        IList<CAArgument> list => "[" + string.Join(", ", list.Select(x => ArgumentText(x.Value))) + "]",
        IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
        _ => value.ToString() ?? "",
    };

    private static double MethodScore(MethodPrint a, MethodPrint b)
    {
        if (a.Method.IsStatic != b.Method.IsStatic || ParamCount(a.Method) != ParamCount(b.Method)) return 0;
        double sig = a.Signature == b.Signature ? 1 : 0;
        double size = 1.0 - Math.Min(1.0, Math.Abs(a.Size - b.Size) / (double)Math.Max(1, Math.Max(a.Size, b.Size)));
        double strings = a.Strings.Count + b.Strings.Count == 0 ? size : Jaccard(a.Strings, b.Strings);
        return 0.45 * sig + 0.3 * size + 0.25 * strings;
    }
}
