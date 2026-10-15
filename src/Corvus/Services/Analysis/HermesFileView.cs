using Corvus.Core.Hermes;
using Corvus.Services.Web;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=hermes: a React Native Hermes bytecode bundle (the file, or the one an APK, AAB or .ipa carries): bytecode version,
/// functions, strings and the Metro modules recovered from its global code; analyze_js reads its functions and code.
/// </summary>
internal sealed class HermesFileView : IFileSummaryView
{
    public string Name => "hermes";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        string? inner = null;
        byte[]? bytes = file.Kind == "zip" ? HermesBundles.FromPackage(file.Bytes, out inner) : HermesFile.Looks(file.Head) ? file.Bytes : null;
        if (bytes == null) return null;
        var hbc = HermesFile.Read(bytes);
        var index = hbc.Opcodes != null ? new HermesIndex(hbc, ct) : null;
        var notes = new List<string>(hbc.Issues);
        notes.Add("analyze_js path=<this file> lists functions and Metro modules, decompiles and disassembles them, and finds strings with their users.");
        var facts = new HermesFacts(hbc.Version, inner, hbc.Functions.Count, hbc.StringCount, index?.Modules.Count ?? 0, notes);
        var highlights = new List<string>
        {
            $"React Native Hermes bytecode{(inner != null ? $" ({inner})" : "")}: version {hbc.Version}, {hbc.Functions.Count:N0} functions, {hbc.StringCount:N0} strings" +
            (index != null ? $", {index.Modules.Count:N0} Metro modules" : "") + ".",
        };
        if (hbc.Opcodes == null) highlights.Add($"Version {hbc.Version} is outside the opcode tables (59–96): the header only.");
        return new FileView(facts, highlights);
    }
}
