using System.Diagnostics;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Corvus.Core;

namespace Corvus.Services.Simplify;

/// <summary>
/// A transformation layer of an assembly. State: restored (a simplify_methods dry run rewrites every site found), partial
/// (some sites are left, with their reason codes), unknown (no site can be rewritten, or the methods were not read), or
/// present (the layer is seen and counted; this reader does not restore it).
/// </summary>
public sealed record TransformLayer(string Layer, string State, int Sites, int Restored, IReadOnlyList<string> Reasons, string Evidence);

/// <summary>
/// The transformation layers of an assembly: constants, proxies and control flow from a dry run of simplify_methods over
/// every method (in memory, never applied); encoded bodies from the IL health of the image; assemblies loaded from bytes
/// at run time from the calls that load or resolve them. Reads only; a layer the reader could not see is reported
/// unknown. A constants site is a call of the module's own helper with a decoder shape, so plain string helpers of a clean
/// assembly add none.
/// </summary>
public static class TransformLayers
{
    /// <summary>The time the dry run may take; methods not reached by then make the layers partial and are counted.</summary>
    public static readonly TimeSpan TimeLimit = TimeSpan.FromSeconds(10);

    public const string Constants = "constants", Proxies = "proxies", ControlFlow = "control flow", EncodedBodies = "encoded bodies",
        LoadedAssemblies = "loaded assemblies";

    private const string CountedOnly = "counted-only";

    /// <summary>The layers seen, in a fixed order; empty when none is. Call under the workspace read lock.</summary>
    public static List<TransformLayer> Read(LoadedAssembly asm, CancellationToken ct, TimeSpan? limit = null)
    {
        var methods = asm.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody).ToList();
        var layers = new List<TransformLayer>();
        if (!asm.HasUnreadableBodies) layers.AddRange(DryRun(asm.Module, methods, ct, limit ?? TimeLimit));
        else
        {
            var (unreadable, total) = asm.BodyCensus;
            layers.AddRange(new[] { Constants, Proxies, ControlFlow }.Select(layer =>
                new TransformLayer(layer, "unknown", 0, 0, ["unreadable-bodies"], $"not read: {unreadable} of {total} method bodies are not IL")));
        }
        if (asm.BodyHealth is { Invalid: > 0 } health)
            layers.Add(new(EncodedBodies, "present", health.Invalid, 0, [CountedOnly], $"{health.Invalid} of {health.Bodies} method bodies are not valid IL"));
        if (Loads(methods) is { Count: > 0 } loads)
            layers.Add(new(LoadedAssemblies, "present", loads.Count, 0, [CountedOnly],
                string.Join("; ", loads.Take(3).Select(l => $"{l.Call} in {Format.MemberLabel(l.Method)}" + (l.FromResource ? " (bytes from a manifest resource)" : "")))
                + (loads.Count > 3 ? $"; +{loads.Count - 3} more" : "")));
        return layers;
    }

    /// <summary>
    /// The identified transformers whose evidence explains <paramref name="layer"/>, as "name (confidence): evidence", one
    /// per transformer; empty for a layer no identification evidence speaks to (proxies, control flow).
    /// </summary>
    public static List<string> Joined(TransformLayer layer, IEnumerable<Analysis.TransformerFinding> found)
    {
        string[] keys = layer.Layer switch
        {
            Constants => ["constants decoder", "string decoder"],
            EncodedBodies => ["anti-tamper", "without an IL body"],
            LoadedAssemblies => ["resource protection"],
            _ => [],
        };
        return [.. found.SelectMany(f => f.Evidence.Where(e => keys.Any(k => e.Contains(k, StringComparison.Ordinal))).Take(1)
            .Select(e => $"{f.Name} ({f.Confidence}): {e}"))];
    }

    /// <summary>
    /// Methods that load an assembly from bytes (Assembly.Load and AppDomain.Load with a byte array,
    /// AssemblyLoadContext.LoadFromStream) or register a resolve handler (AssemblyResolve, Resolving), one per method.
    /// </summary>
    private static List<(MethodDef Method, string Call, bool FromResource)> Loads(List<MethodDef> methods)
    {
        var found = new List<(MethodDef, string, bool)>();
        foreach (var m in methods)
        {
            IList<Instruction> code;
            try { code = m.Body.Instructions; }
            catch (Exception e) when (e is BadImageFormatException or InvalidMethodException or IndexOutOfRangeException) { continue; }
            var call = code.Select(i => i.Operand as IMethod).Select(LoadCall).FirstOrDefault(c => c != null);
            if (call == null) continue;
            bool resource = code.Any(i => i.Operand is IMethod { Name.String: "GetManifestResourceStream" });
            found.Add((m, call, resource));
        }
        return found;
    }

    private static string? LoadCall(IMethod? callee)
    {
        if (callee?.DeclaringType?.FullName is not { } type || callee.MethodSig is not { } sig) return null;
        bool bytes = sig.Params.Count > 0 && sig.Params[0].FullName == "System.Byte[]";
        return (type, callee.Name.String) switch
        {
            ("System.Reflection.Assembly", "Load") when bytes => "Assembly.Load(byte[])",
            ("System.AppDomain", "Load") when bytes => "AppDomain.Load(byte[])",
            ("System.Runtime.Loader.AssemblyLoadContext", "LoadFromStream") => "AssemblyLoadContext.LoadFromStream",
            ("System.AppDomain", "add_AssemblyResolve") => "an AssemblyResolve handler",
            ("System.Runtime.Loader.AssemblyLoadContext", "add_Resolving") => "a Resolving handler",
            _ => null,
        };
    }

    private static IEnumerable<TransformLayer> DryRun(ModuleDef module, List<MethodDef> methods, CancellationToken ct, TimeSpan limit)
    {
        var simplifier = new MethodSimplifier(module, new SimplifyOptions());
        var changes = new List<MethodChange>();
        var clock = Stopwatch.StartNew();
        int reached = 0;
        foreach (var m in methods)
        {
            if (clock.Elapsed > limit) break;
            changes.AddRange(simplifier.Run([m], ct));
            reached++;
        }
        int left = methods.Count - reached;
        var rejected = changes.Where(c => c.Rejected != null).GroupBy(c => SimplifyManifest.CodeOf(c.Rejected!.Reason))
            .Select(g => $"{g.Key}: {g.Count()} method(s) left whole").ToList();
        if (left > 0) rejected.Add($"time-limit: {left} method(s) not reached within {limit.TotalSeconds:0} s");

        TransformLayer? Layer(string name, int restored, IEnumerable<Fallback> skipped, string evidence)
        {
            var kept = skipped.ToList();
            int sites = restored + kept.Count;
            if (sites == 0 && left == 0) return null;
            var reasons = kept.GroupBy(f => SimplifyManifest.CodeOf(f.Reason)).OrderByDescending(g => g.Count()).Select(g => $"{g.Key}: {g.Count()}").Concat(sites > 0 ? rejected : rejected.Where(r => r.StartsWith("time-limit", StringComparison.Ordinal))).ToList();
            var state = sites == 0 ? "unknown" : restored == sites && reasons.Count == 0 ? "restored" : restored > 0 ? "partial" : "unknown";
            return new(name, state, sites, restored, reasons, sites == 0 ? "no site in the methods read" : evidence);
        }

        string First(Func<MethodChange, bool> has) => changes.FirstOrDefault(has) is { } c ? "first in " + Format.MemberLabel(c.Method) : "";
        var shapes = new Dictionary<MethodDef, bool>();
        bool Decoder(MethodDef? m) => m != null && DecoderShape(m, shapes, 2);
        var constants = Layer(Constants, changes.Sum(c => c.FoldedHelpers.Count(Decoder)), changes.SelectMany(c => c.Bailouts.Where(b => Decoder(b.Helper))),
            First(c => c.FoldedHelpers.Any(Decoder) || c.Bailouts.Any(b => Decoder(b.Helper))));
        var proxies = Layer(Proxies, changes.Sum(c => c.Inlined.Count + c.Delegates.Count), changes.SelectMany(c => c.Skipped.Where(f => f.Reason == FallbackReason.DelegateTarget)),
            First(c => c.Inlined.Count + c.Delegates.Count > 0 || c.Skipped.Any(f => f.Reason == FallbackReason.DelegateTarget)));
        var flow = Layer(ControlFlow, changes.Sum(c => c.Dispatchers + c.ConstantBranches), changes.SelectMany(c => c.Skipped.Where(f => f.Reason == FallbackReason.FlattenedShape)),
            First(c => c.Dispatchers + c.ConstantBranches > 0 || c.Skipped.Any(f => f.Reason == FallbackReason.FlattenedShape)));
        return new[] { constants, proxies, flow }.OfType<TransformLayer>();
    }

    // A decoder XORs, indexes an array or string in a loop, or calls a decoding API, itself or through the module's own
    // methods it calls, to the given depth.
    private static bool DecoderShape(MethodDef m, Dictionary<MethodDef, bool> seen, int depth)
    {
        if (seen.TryGetValue(m, out bool known)) return known;
        seen[m] = false;
        if (!m.HasBody) return false;
        var code = m.Body.Instructions;
        bool loop = code.Any(i => i.Operand is Instruction t && t.Offset < i.Offset);
        bool shape = code.Any(i =>
            i.OpCode.Code == Code.Xor
            || loop && (i.OpCode.Code is >= Code.Ldelem_I1 and <= Code.Ldelem_Ref or Code.Ldelem
                || i.Operand is IMethod { Name.String: "get_Chars", DeclaringType.FullName: "System.String" })
            || i.Operand is IMethod { Name.String: "GetString" or "FromBase64String" or "InitializeArray" or "GetManifestResourceStream" or "CreateDecryptor" }
            || depth > 0 && i.Operand is IMethod callee && Generics.Definition(callee) is MethodDef own && own.Module == m.Module && DecoderShape(own, seen, depth - 1));
        seen[m] = shape;
        return shape;
    }
}
