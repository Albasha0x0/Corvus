using System.Diagnostics;
using System.Runtime.CompilerServices;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services.Simplify;

/// <summary>
/// Calls through static delegate fields of an assembly (<c>ldsfld F; args; Invoke</c>) and the method each field's
/// delegate calls, as the evaluator computes it from the field's type initializer (see
/// <see cref="MethodSimplifier"/>'s delegate pass). For navigation: the call graph, find_references and find_callees show
/// these calls as calls of the target. A field that is null during its own type's initialization still calls only that
/// target, so unlike the rewrite the index does not need the call site to run after the initialization. Computed once
/// per assembly version, within a time budget; fields it cannot resolve are left out.
/// </summary>
internal static class DelegateCalls
{
    public sealed record Site(MethodDef Caller, uint Offset, FieldDef Field, IMethod Target);

    /// <summary>Time all evaluations of one assembly may take; the remaining fields stay unresolved.</summary>
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(20);

    private sealed class Entry
    {
        public int Version = -1;
        public IReadOnlyList<Site> Sites = [];
        public ILookup<TypeDef, Site> ByType = Enumerable.Empty<Site>().ToLookup(s => s.Caller.DeclaringType);
    }

    private static readonly ConditionalWeakTable<LoadedAssembly, Entry> Cache = new();

    /// <summary>The resolved delegate-field call sites of <paramref name="asm"/>. Call under the workspace read lock.</summary>
    public static IReadOnlyList<Site> Of(LoadedAssembly asm, CancellationToken ct) => Current(asm, ct).Sites;

    /// <summary>The sites by the type of their calling method.</summary>
    public static ILookup<TypeDef, Site> ByType(LoadedAssembly asm, CancellationToken ct) => Current(asm, ct).ByType;

    private static Entry Current(LoadedAssembly asm, CancellationToken ct)
    {
        var entry = Cache.GetValue(asm, _ => new Entry());
        lock (entry)
        {
            if (entry.Version != asm.Version)
            {
                entry.Sites = Compute(asm, ct);
                entry.ByType = entry.Sites.ToLookup(s => s.Caller.DeclaringType);
                entry.Version = asm.Version;
            }
            return entry;
        }
    }

    private static List<Site> Compute(LoadedAssembly asm, CancellationToken ct)
    {
        var module = asm.Module;
        // Candidate sites first, from the raw IL: most assemblies have none, and then nothing is evaluated.
        var candidates = new List<(MethodDef Caller, uint Offset, FieldDef Field, int Arguments)>();
        foreach (var method in module.GetTypes().SelectMany(t => t.Methods))
        {
            ct.ThrowIfCancellationRequested();
            var code = FastIlReader.Instructions(asm, method);
            HashSet<Instruction>? branchTargets = null;
            for (int i = 0; i < code.Count; i++)
            {
                if (code[i] is not { OpCode.Code: Code.Call or Code.Callvirt, Operand: IMethod { Name.String: "Invoke", MethodSig: { HasThis: true } sig } invoke }) continue;
                branchTargets ??= code.SelectMany(BodyGraph.BranchTargets).ToHashSet();
                int producer = MethodSimplifier.Producer(code, branchTargets, i, sig.Params.Count);
                if (producer >= 0 && code[producer] is { OpCode.Code: Code.Ldsfld, Operand: FieldDef { IsStatic: true } field } && field.Module == module &&
                    field.FieldType.FullName == invoke.DeclaringType.FullName)
                    candidates.Add((method, code[i].Offset, field, sig.Params.Count));
            }
        }
        if (candidates.Count == 0) return [];

        var limits = new EvaluationLimits();
        var evaluator = new IlEvaluator(module, limits);
        var targets = new Dictionary<FieldDef, IMethod?>();
        var clock = Stopwatch.StartNew();
        var sites = new List<Site>();
        foreach (var (caller, offset, field, arguments) in candidates)
        {
            ct.ThrowIfCancellationRequested();
            if (!targets.TryGetValue(field, out var target))
            {
                target = clock.Elapsed < Budget ? Resolve(evaluator, limits, field, arguments) : null;
                targets[field] = target;
            }
            if (target != null) sites.Add(new Site(caller, offset, field, target));
        }
        return sites;
    }

    /// <summary>The method the field's delegate calls, or null when it is not known.</summary>
    private static IMethod? Resolve(IlEvaluator evaluator, EvaluationLimits limits, FieldDef field, int arguments)
    {
        evaluator.Meter = new MethodMeter(limits);
        try
        {
            if (evaluator.EvaluateSlice([new Instruction(OpCodes.Ldsfld, field)]) is not [DelegateObject d]) return null;
            return MethodSimplifier.DelegateCode(d, arguments, out _, out _) is { } code ? code.LastOrDefault(i => i.Operand is IMethod)?.Operand as IMethod : null;
        }
        catch (Exception ex) when (ex is EvaluationBailout or MethodTimeout)
        {
            return null;
        }
        finally
        {
            evaluator.Meter = null;
        }
    }
}
