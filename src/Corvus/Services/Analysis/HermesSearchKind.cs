using System.Globalization;
using Corvus.Core;
using Corvus.Core.Hermes;
using Corvus.Services.Web;

namespace Corvus.Services.Analysis;

/// <summary>
/// search_container kind=hermes: the strings and function names of a React Native Hermes bytecode bundle (the file, or the
/// one inside an APK, AAB or .ipa), each with its id and how many instructions use it.
/// </summary>
internal sealed class HermesSearchKind : IContainerSearchKind
{
    public IReadOnlyList<string> Kinds => ["hermes"];

    public IEnumerable<ContainerMatch> Search(ContainerScope scope, string kind, Func<string, bool> matches, CancellationToken ct)
    {
        HermesBundle bundle;
        try
        {
            if (!HermesBundles.Applies(scope.Source)) yield break;
            bundle = HermesBundles.Open(scope.Source, ct);
        }
        catch (ToolError) { yield break; }
        var f = bundle.File;
        if (f.Opcodes == null) yield break;
        var path = bundle.Inner ?? Path.GetFileName(scope.Source);
        for (int i = 0; i < f.StringCount; i++)
        {
            if ((i & 4095) == 0) ct.ThrowIfCancellationRequested();
            if (f.String(i) is { } s && matches(s))
                yield return new ContainerMatch(path, s, "hermes")
                {
                    Detail = string.Create(CultureInfo.InvariantCulture, $"string #{i}{(f.IsIdentifier(i) ? " (identifier)" : "")}, {bundle.Index.StringRefs(i).Length} use(s)"),
                };
        }
        for (int i = 0; i < f.Functions.Count; i++)
            if (f.FunctionName(i) is { Length: > 0 } name && matches(name))
                yield return new ContainerMatch(path, name, "hermes")
                {
                    Detail = string.Create(CultureInfo.InvariantCulture, $"function #{i}{(bundle.Index.ModuleOf(i) is { } m ? $", Metro module {m.Id}" : "")}"),
                };
    }
}
