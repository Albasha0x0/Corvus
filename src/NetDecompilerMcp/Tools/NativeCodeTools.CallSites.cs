using System.Text;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;

namespace NetDecompilerMcp.Tools;

/// <summary>native_call_tree direction=both: one level of callers and callees with their call sites.</summary>
public sealed partial class NativeCodeTools
{
    /// <summary>"call, direct" and the like for an edge of the built-in index.</summary>
    internal static string SiteFlags(XrefKind kind) => kind switch
    {
        XrefKind.TailCall => "jump, direct",
        XrefKind.ImportCall => "call, indirect, external",
        XrefKind.ImportJump => "jump, indirect, external",
        XrefKind.VirtualExact => "call, indirect, virtual",
        XrefKind.VirtualPossible => "call, indirect, virtual (one of several)",
        _ => "call, direct",
    };

    private static string OurCallSites(NativeCodeIndex index, NativeFunction fn, CallEdgeFilter edges, CancellationToken ct)
    {
        string Va(uint r) => NativeAddress.Va(index.Image, r);
        string Where(uint from) => index.FunctionAt(from) is { } f ? $"{index.NameAt(f.Start) ?? f.Name}+0x{from - f.Start:X}" : "(no function)";
        var callers = index.Callers(fn, edges);
        var callees = index.Callees(fn, edges);
        ct.ThrowIfCancellationRequested();
        var sb = new StringBuilder($"; callers and callees of {index.NameAt(fn.Start) ?? fn.Name} at {Va(fn.Start)}, one level, by call site\n");
        sb.AppendLine($"callers ({callers.Count}):");
        foreach (var c in callers) sb.AppendLine($"  {Va(c.From)}  {Where(c.From)}  [{SiteFlags(c.Kind)}]");
        sb.AppendLine($"callees ({callees.Count}):");
        foreach (var c in callees)
        {
            var target = c.Import != null ? NativeCodeIndex.ImportName(c.Import) : c.Function != null ? index.NameAt(c.Function.Start) ?? c.Function.Name : Va(c.Target);
            sb.AppendLine($"  {Va(c.From)}  -> {target}{(c.Function != null ? $"  {Va(c.Function.Start)}" : "")}  [{SiteFlags(c.Kind)}]");
        }
        if (callers.Count + callees.Count == 0) sb.AppendLine("  (none)");
        return sb.ToString();
    }
}
