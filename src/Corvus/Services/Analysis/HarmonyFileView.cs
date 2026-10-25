using Corvus.Core.Ark;

namespace Corvus.Services.Analysis;

/// <summary>An Ark bytecode file of a package: path, format version, classes, methods, code bytes, whether the checksum matches, and reading notes.</summary>
public sealed record ArkBytecodeFacts(string Path, string Version, int Classes, int Methods, long CodeBytes, bool ChecksumMatches, IReadOnlyList<string> Issues);

/// <summary>view=harmony: the modules of a HarmonyOS package and its Ark bytecode files; null lists mean none were found.</summary>
public sealed record HarmonyFacts(IReadOnlyList<HarmonyModule> Modules, IReadOnlyList<ArkBytecodeFacts> Bytecode, IReadOnlyList<string> Notes);

/// <summary>
/// view=harmony: a HarmonyOS module (.hap, .hsp), application bundle (.app) or Ark bytecode file (.abc): bundle,
/// version, API levels, abilities and what starts them, requested permissions, native libraries and each bytecode file.
/// </summary>
internal sealed class HarmonyFileView : IFileSummaryView
{
    public string Name => "harmony";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        var bytecode = new List<ArkBytecodeFacts>();
        var notes = new List<string>();
        IReadOnlyList<HarmonyModule> modules = [];
        if (file.Kind == "zip" && file.HasZipEntry(n => n is "module.json" or "config.json" or "pack.info"))
        {
            HarmonyPackage package;
            try
            {
                using var s = file.OpenRead();
                package = new HarmonyPackage(s, JsAnalysisLimit, (path, bytes) => bytecode.Add(Facts(path, bytes)));
            }
            catch (InvalidDataException) { return null; }
            if (package.Modules.Count == 0) return null;
            modules = package.Modules;
            notes.AddRange(package.Issues);
        }
        else if (ArkFile.Looks(file.Head)) bytecode.Add(Facts(System.IO.Path.GetFileName(file.Path), file.Bytes));
        else return null;
        notes.Add("analyze_js path=<this file> lists the bytecode's functions and disassembles them.");
        var highlights = new List<string>();
        foreach (var m in modules)
        {
            int exported = m.Abilities.Count(a => a.Exported);
            highlights.Add($"HarmonyOS {(m.Type ?? "module")} {m.Name}{(m.Path.Length > 0 ? $" ({m.Path})" : "")} of {m.Bundle} {m.VersionName}, {m.Model} model" +
                (m.MinApi != null ? $", API {m.MinApi}{(m.TargetApi != null && m.TargetApi != m.MinApi ? $"-{m.TargetApi}" : "")}" : "") +
                $": {m.Abilities.Count} abilities ({exported} exported), {m.Permissions.Count} permissions, {m.NativeLibraries.Count} native libraries.");
        }
        foreach (var b in bytecode)
            highlights.Add($"Ark bytecode {b.Path}: version {b.Version}, {b.Classes:N0} classes, {b.Methods:N0} methods, {b.CodeBytes:N0} bytes of code" +
                (b.ChecksumMatches ? "." : "; the checksum differs."));
        return new FileView(new HarmonyFacts(modules, bytecode, notes), highlights);
    }

    // Bytecode files are read whole, up to the size analyze_js reads.
    private const long JsAnalysisLimit = Web.JsAnalysis.MaxFileBytes;

    private static ArkBytecodeFacts Facts(string path, byte[] bytes)
    {
        try
        {
            var f = new ArkFile(bytes);
            long code = 0;
            foreach (var m in f.Classes.SelectMany(c => c.Methods))
                if (m.Code is { } at)
                    try { code += f.Code(at).Instructions.Length; }
                    catch (InvalidDataException) { }
            return new ArkBytecodeFacts(path, f.Version, f.Classes.Count, f.Classes.Sum(c => c.Methods.Count), code, f.ChecksumMatches, f.Issues);
        }
        catch (InvalidDataException ex) { return new ArkBytecodeFacts(path, "", 0, 0, 0, false, [$"not readable: {ex.Message}"]); }
    }
}
