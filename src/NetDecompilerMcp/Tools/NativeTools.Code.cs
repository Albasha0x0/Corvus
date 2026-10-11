using System.ComponentModel;
using System.Text;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Calls;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[Description("A function ranked by call sites or size.")]
public sealed record RankedFunction(string Address, string Name, [property: Description("References to its start (most called) or bytes (largest).")] long Value);

[Description("The code as the built-in index sees it; present once the index is built (get_pe_info never waits for it).")]
public sealed record CodeOverview(
    int Functions,
    int Thunks,
    int NoReturn,
    [property: Description("Functions IDA recognized as library code.")] int Library,
    long Instructions,
    long Xrefs,
    int Strings,
    [property: Description("Percent of executable section bytes inside functions.")] double Coverage,
    int Exports,
    int TlsCallbacks,
    int SwitchTables,
    [property: Description("Indirect jumps the index could not resolve.")] int UnresolvedJumps,
    int VirtualCallSites,
    int VirtualExact,
    int VirtualPossible,
    int VirtualUnresolved,
    int RttiClasses,
    IReadOnlyList<RankedFunction> MostCalled,
    IReadOnlyList<RankedFunction> Largest);

[Description("A capability the imports imply.")]
public sealed record CapabilityEntry(
    [property: Description("files, registry, network, crypto, process_thread, ui, services, com, debug or dynamic_loading.")] string Group,
    [property: Description("Distinct APIs in the group.")] int Count,
    IReadOnlyList<string> Apis);

public sealed partial class NativeTools
{
    /// <summary>Capability groups from static imports, plus late-bound ones when the index is ready.</summary>
    internal static IReadOnlyList<ApiCapability> Capabilities(INativeImage image, NativeCodeIndex? index, CancellationToken ct)
    {
        var apis = image.Imports.Where(i => i.Name != null).Select(i => (i.Module, i.Name!)).ToList();
        if (index != null && CallAnalysis.Supports(index))
            apis.AddRange(CallAnalysis.For(index).DynamicImports(ct).Imports.Select(d => (d.Module ?? "", d.Name)));
        return ApiCapabilities.Classify(apis);
    }

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<NativeCodeIndex, Tuple<long, CodeOverview>> Overviews = new();

    /// <summary>The code statistics, computed once per index and name version.</summary>
    internal static CodeOverview Overview(NativeCodeIndex index)
    {
        long version = index.Sourced.Version;
        if (Overviews.TryGetValue(index, out var hit) && hit.Item1 == version) return hit.Item2;
        var overview = ComputeOverview(index);
        Overviews.AddOrUpdate(index, Tuple.Create(version, overview));
        return overview;
    }

    private static CodeOverview ComputeOverview(NativeCodeIndex index)
    {
        var image = index.Image;
        var s = index.Stats;
        string Va(uint r) => NativeAddress.Va(image, r);
        long executable = image.Sections.Where(x => (x.Access & SectionAccess.Execute) != 0).Sum(x => (long)x.VirtualSize);
        long inside = index.Functions.Sum(f => (long)f.Size);
        var called = index.Functions.Select(f => (f, n: index.CountRefsTo(f.Start))).Where(x => x.n > 0)
            .OrderByDescending(x => x.n).ThenBy(x => x.f.Start).Take(10).Select(x => new RankedFunction(Va(x.f.Start), index.NameAt(x.f.Start) ?? x.f.Name, x.n)).ToList();
        var largest = index.Functions.OrderByDescending(f => f.Size).ThenBy(f => f.Start).Take(10)
            .Select(f => new RankedFunction(Va(f.Start), index.NameAt(f.Start) ?? f.Name, f.Size)).ToList();
        var v = index.VirtualCalls.Stats;
        return new CodeOverview(s.Functions, s.Thunks, s.NoReturnFunctions, index.Functions.Count(f => EngineLibraryNames.IsLibrary(index, f.Start)), s.Instructions, s.Xrefs,
            s.Strings, executable == 0 ? 0 : Math.Round(Math.Min(100, 100.0 * inside / executable), 1), image.Exports.Count, image.TlsCallbackRvas.Count,
            s.ResolvedSwitches, s.UnresolvedJumps, v.Sites, v.Exact, v.Possible, v.Unresolved, v.RttiClasses, called, largest);
    }

    private static string CodeText(NativeCodeIndex? index, IReadOnlyList<ApiCapability> capabilities)
    {
        var sb = new StringBuilder();
        if (capabilities.Count > 0)
        {
            sb.AppendLine($"Capabilities (from {(index != null ? "static and late-bound" : "static")} imports):");
            foreach (var c in capabilities)
                sb.AppendLine($"  {c.Group,-16} {c.Count,4}  {string.Join(", ", c.Apis)}{(c.Count > c.Apis.Count ? ", ..." : "")}");
        }
        if (index == null)
        {
            sb.AppendLine("Code: the code index is still building (list_functions waits for it; get_pe_info shows this section once it is ready)");
            return sb.ToString();
        }
        if (index.Support == CodeSupport.DeclaredFunctionsOnly)
        {
            sb.AppendLine($"Code: {index.SupportNote ?? "instructions are not decoded for this architecture"}; {Plural(index.Functions.Count, "declared function")}");
            return sb.ToString();
        }
        var o = Overview(index);
        sb.AppendLine($"Code: {Plural(o.Functions, "function")} ({o.Thunks} thunks, {o.NoReturn} noreturn{(o.Library > 0 ? $", {o.Library} library" : "")}), " +
                      $"{o.Instructions:N0} instructions, {o.Xrefs:N0} references, {Plural(o.Strings, "string")}; {o.Coverage:0.#}% of executable bytes in functions");
        sb.AppendLine($"  entry points: {(index.Image.EntryPointRva != 0 ? "entry, " : "")}{Plural(o.Exports, "export")}, {Plural(o.TlsCallbacks, "TLS callback")}");
        sb.AppendLine($"  {Plural(o.SwitchTables, "switch table")}; {Plural(o.UnresolvedJumps, "unresolved indirect jump")} (get_cfg shows the reason; " +
                      "resolve_call_targets scope=image lists unresolved indirect calls)");
        if (o.VirtualCallSites > 0 || o.RttiClasses > 0)
            sb.AppendLine($"  virtual calls: {o.VirtualCallSites} sites ({o.VirtualExact} exact, {o.VirtualPossible} possible, {o.VirtualUnresolved} unresolved); {Plural(o.RttiClasses, "RTTI class")}");
        if (o.MostCalled.Count > 0) sb.AppendLine("  most referenced: " + string.Join(", ", o.MostCalled.Select(f => $"{f.Name} ({f.Value})")));
        if (o.Largest.Count > 0) sb.AppendLine("  largest: " + string.Join(", ", o.Largest.Select(f => $"{f.Name} ({f.Value:N0} bytes)")));
        return sb.ToString();
    }
}
