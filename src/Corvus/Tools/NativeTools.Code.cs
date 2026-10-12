using System.ComponentModel;
using System.Text;
using Corvus.Native;
using Corvus.Native.Calls;
using Corvus.Native.Code;

namespace Corvus.Tools;

[Description("A function ranked by call sites or size.")]
public sealed record RankedFunction(string Address, string Name, [property: Description("References to its start (most called) or bytes (largest).")] long Value);

[Description("The code as the built-in index sees it; get_pe_info leaves it empty (list_functions has these statistics).")]
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
    /// <summary>Capability groups from the static and delay-load imports. The code index is not consulted, so the answer never depends on whether it is built.</summary>
    internal static IReadOnlyList<ApiCapability> Capabilities(INativeImage image) =>
        ApiCapabilities.Classify(image.Imports.Where(i => i.Name != null).Select(i => (i.Module, i.Name!)).ToList());

    private static string CodeText(INativeImage image, IReadOnlyList<ApiCapability> capabilities)
    {
        var sb = new StringBuilder();
        if (capabilities.Count > 0)
        {
            sb.AppendLine("Capabilities (from static imports):");
            foreach (var c in capabilities)
                sb.AppendLine($"  {c.Group,-16} {c.Count,4}  {string.Join(", ", c.Apis)}{(c.Count > c.Apis.Count ? ", ..." : "")}");
        }
        sb.AppendLine(InstructionSets.For(image.Arch) is { Support: CodeSupport.DeclaredFunctionsOnly, Reason: var reason }
            ? $"Code: not decoded ({reason})"
            : "Code: list_functions gives the function statistics; list_imports includeDynamic=true adds the late-bound imports");
        return sb.ToString();
    }
}
