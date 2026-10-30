using Corvus.Core;
using Corvus.Native.NativeAot;

namespace Corvus.Services.Analysis;

// The built-in summarize_file views (IFileSummaryView); the managed view and a loaded image's triage are built by InspectionService.

/// <summary>view=android: manifest facts, runtimes with evidence, ABIs, DEX, signature.</summary>
internal sealed class AndroidFileView : IFileSummaryView
{
    public string Name => "android";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (file.Kind != "zip" || !file.HasZipEntry(n => n is "AndroidManifest.xml" or "base/manifest/AndroidManifest.xml" || n.EndsWith(".apk", StringComparison.OrdinalIgnoreCase)))
            return null;
        using var package = file.OpenRead();
        return Mobile.AndroidPackageService.Facts(file.Path, package, ct) is { } facts ? new FileView(facts, facts.Highlights) : null;
    }
}

/// <summary>view=electron: versions, fuses, archive integrity, package.json entry, webPreferences values.</summary>
internal sealed class ElectronFileView : IFileSummaryView
{
    public string Name => "electron";

    public FileView? Inspect(FileInput file, CancellationToken ct) =>
        file.Kind is "asar" or "native PE" or "elf" or "mach-o" && ElectronInspector.Of(file.Path, file.Kind == "asar" ? file.Bytes : file.Image, ct) is { } facts ? new FileView(facts, [.. facts.Highlights()]) : null;
}

/// <summary>view=go: toolchain, main package and module, dependencies and build settings.</summary>
internal sealed class GoFileView : IFileSummaryView
{
    public string Name => "go";

    public FileView? Inspect(FileInput file, CancellationToken ct) =>
        Native.NativeImageLoader.Detect(file.Head) != Native.NativeFileKind.Unknown && InspectionService.GoBuildFacts.Of(file.Path, file.Image) is { } go ? new FileView(go, [go.Highlight()]) : null;
}

/// <summary>view=native: ELF / Mach-O facts, packers and protectors, NativeAOT recovery counts.</summary>
internal sealed class NativeFileView : IFileSummaryView
{
    public string Name => "native";

    public sealed record Facts(NativeImageFacts? Image, IReadOnlyList<Native.PackerFinding>? Packers, NativeAotSummary? NativeAot);

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        // Wasm has its own view.
        if (Native.NativeImageLoader.Detect(file.Head) is Native.NativeFileKind.Unknown or Native.NativeFileKind.Wasm) return null;
        var image = NativeImageFacts.Of(file.Path, file.Image);
        var packers = Native.PackerDetection.OfFile(file.Path, file.Image);
        var aot = NativeAot(file.Kind, file.Image, ct);
        var hits = file.Options.AllNetworkValues && file.Kind is "native PE" or "NativeAOT executable" or "elf" or "mach-o" ? IndicatorList.FromImageStrings("native", file.Image, ct) : [];
        if (image == null && packers.Count == 0 && aot == null && hits.Count == 0) return null;
        var highlights = new List<string>(image?.Highlights ?? []);
        foreach (var p in packers)
            highlights.Add(p.Kind == "suspicious" ? $"Possibly packed: {p.Evidence}." : $"Packed with {p.Name} ({p.Kind}): {p.Evidence}.");
        return new FileView(new Facts(image?.Facts, packers.Count > 0 ? packers : null, aot), highlights) { Findings = [.. packers.Select(FindingRules.ToFinding)], Indicators = hits };
    }

    private static NativeAotSummary? NativeAot(string kind, byte[] bytes, CancellationToken ct)
    {
        if (kind is not ("NativeAOT executable" or "elf" or "mach-o")) return null;
        try
        {
            var image = Native.NativeImageLoader.FromBytes(bytes);
            return kind == "NativeAOT executable" || NativeAotLocator.HasMarkers(image) ? NativeAotImage.Open(image, ct)?.Summary() : null;
        }
        catch (ToolError) { return null; }
    }
}
