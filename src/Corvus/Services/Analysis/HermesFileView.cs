using Corvus.Core.Hermes;
using Corvus.Services.Web;

namespace Corvus.Services.Analysis;

/// <summary>view=hermes: version, function and string counts and recovered Metro modules of a Hermes bundle, also inside an APK, AAB or .ipa.</summary>
internal sealed class HermesFileView : IFileSummaryView
{
    public string Name => "hermes";

    /// <summary>The entry names <see cref="HermesBundles.Entry"/> looks in.</summary>
    internal static bool IsBundleName(string name) =>
        name.EndsWith(".bundle", StringComparison.Ordinal) || name.EndsWith(".jsbundle", StringComparison.Ordinal) || name.EndsWith(".hbc", StringComparison.Ordinal);

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        string? inner = null;
        // A package is read whole only when its directory names a bundle.
        byte[]? bytes = file.Kind == "zip" ? file.HasZipEntry(IsBundleName) ? HermesBundles.FromPackage(file.Bytes, out inner) : null
            : HermesFile.Looks(file.Head) ? file.Bytes : null;
        if (bytes == null) return null;
        var hbc = HermesFile.Read(bytes);
        var index = hbc.Opcodes != null ? new HermesIndex(hbc, ct) : null;
        var notes = new List<string>(hbc.Issues);
        notes.Add("analyze_js path=<this file> lists, decompiles and disassembles functions and Metro modules, and finds string users.");
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
