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
        var packers = Native.PackerDetection.OfFile(file.Path, file.Image).ToList();
        var dieNote = AddDetectItEasy(file.Path, packers, ct);
        var aot = NativeAot(file.Kind, file.Image, ct);
        var hits = file.Options.AllNetworkValues && file.Kind is "native PE" or "NativeAOT executable" or "elf" or "mach-o" ? IndicatorList.FromImageStrings("native", file.Image, ct) : [];
        var hosted = HostEntries(file);
        // A PE too damaged to identify still gets the unavailable note.
        var isPe = file.Kind is "native PE" or "NativeAOT executable" || (file.Kind == "data" && Native.NativeImageLoader.Detect(file.Head) == Native.NativeFileKind.Pe);
        var pe = isPe ? PeHighlights(file.Image, ct) : [];
        var content = NativeEmbeddedContent.Highlights(file.Path, file.Image, ct);
        if (image == null && packers.Count == 0 && aot == null && hits.Count == 0 && hosted.Count == 0 && pe.Count == 0 && content.Count == 0 && dieNote == null) return null;
        var highlights = new List<string>(image?.Highlights ?? []);
        highlights.AddRange(pe);
        highlights.AddRange(content);
        if (dieNote != null) highlights.Add(dieNote);
        foreach (var p in packers)
            highlights.Add(p.Kind == "suspicious" ? $"Possibly packed: {p.Evidence}." : $"Packed with {p.Name} ({p.Kind}): {p.Evidence}.");
        return new FileView(new Facts(image?.Facts, packers.Count > 0 ? packers : null, aot), highlights) { Findings = [.. packers.Select(FindingRules.ToFinding), .. hosted], Indicators = hits };
    }

    /// <summary>Adds the packers Detect It Easy names when CORVUS_DIE is set, one diec run per call; returns why none were read, null when none is owed.</summary>
    private static string? AddDetectItEasy(string path, List<Native.PackerFinding> packers, CancellationToken ct)
    {
        if (!DetectItEasy.Configured()) return null;
        if (DetectItEasy.Find() is not { } die) return $"{Native.Providers.ExternalTools.Die.Variable} is set but Detect It Easy was not found there; set it to diec or its folder. The packers listed come from section names and headers only.";
        var result = DetectItEasy.Scan(die, path, ct);
        foreach (var d in result.Detections.Where(d => DetectItEasy.Category(d.Type) == "packing"))
            if (!packers.Any(p => PackerKey(p.Name) == PackerKey(d.Text)))
                packers.Add(new(d.Text, d.Type.Equals("protector", StringComparison.OrdinalIgnoreCase) || d.Type.Equals("protection", StringComparison.OrdinalIgnoreCase) ? "hardening tool" : "packing tool", "Detect It Easy"));
        return result.Problem == null ? null : $"{result.Problem} The packers listed come from section names and headers only.";
    }

    // Drops a "(version)" suffix and a "/alias" so "UPX(3.96)" matches "UPX".
    private static string PackerKey(string name)
    {
        var cut = name.IndexOfAny(['(', '/']);
        return (cut < 0 ? name : name[..cut]).Trim().ToUpperInvariant();
    }

    /// <summary>PE sections, mitigations, PDB path, TLS callbacks, import capabilities; one note when unreadable.</summary>
    private static List<string> PeHighlights(byte[] bytes, CancellationToken ct)
    {
        try
        {
            var pe = Native.Pe.PeFile.FromBytes(bytes);
            if (pe.Sections.Count == 0) return [$"PE highlights unavailable: the image has no readable section table ({pe.Issues.Count} issues)."];
            var (on, off) = Native.Pe.PeDescribe.Mitigations(pe);
            var lines = new List<string>
            {
                $"Sections ({pe.Sections.Count}): {string.Join(", ", pe.Sections.Take(12).Select(s => $"{s.Name} {Native.Pe.PeDescribe.Access(s.Access)}"))}" + (pe.Sections.Count > 12 ? $", ... ({pe.Sections.Count - 12} more)" : "") + ". get_pe_info lists sizes and entropy.",
                $"Mitigations on: {(on.Count > 0 ? string.Join(", ", on) : "none")}; off: {(off.Count > 0 ? string.Join(", ", off) : "none")}.",
            };
            if (pe.CodeView is { } cv) lines.Add($"PDB path: {cv.PdbPath}.");
            if (pe.TlsCallbackRvas.Count > 0)
                lines.Add($"TLS callbacks run before the entry point: {string.Join(", ", pe.TlsCallbackRvas.Take(8).Select(r => Native.NativeAddress.Va(pe, r)))}" + (pe.TlsCallbackRvas.Count > 8 ? $", ... ({pe.TlsCallbackRvas.Count - 8} more)" : "") + ".");
            ct.ThrowIfCancellationRequested();
            var capabilities = Native.Calls.ApiCapabilities.ForImports(pe);
            if (capabilities.Count > 0)
                lines.Add($"Import capabilities: {string.Join(", ", capabilities.Select(c => $"{c.Group} ({c.Count})"))}. list_imports shows the functions.");
            return lines;
        }
        catch (ToolError ex) { return [$"PE highlights unavailable: {ex.Message}"]; }
    }

    /// <summary>One review finding per PE export a host calls by name; empty for other images.</summary>
    private static List<Finding> HostEntries(FileInput file)
    {
        try
        {
            var image = Native.NativeImageLoader.FromBytes(file.Image);
            if (image.Format != Native.ImageFormat.Pe) return [];
            return [.. image.Exports.Where(e => e.ForwardedTo == null && EntryPoints.HostCallback(e.Name) != null)
                .Select(e => new Finding(FindingRules.Check("native/host-entry", FindingLevel.Review), "native/host-entry", "entry point", $"{e.Name}: {EntryPoints.HostCallback(e.Name)}", null, "native"))];
        }
        catch (ToolError) { return []; }
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
