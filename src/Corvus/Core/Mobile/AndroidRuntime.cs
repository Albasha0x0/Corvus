using System.Buffers.Binary;

namespace Corvus.Core.Mobile;

/// <summary>A runtime an Android package carries, with the entries that show it.</summary>
public sealed record AndroidRuntimeFamily(string Family, IReadOnlyList<string> Evidence, string? Note);

/// <summary>Runtime families decided from package content (native libraries, stores, metadata magic), not from file names alone.</summary>
public static class AndroidRuntime
{
    private const uint Il2CppMetadataMagic = 0xFAB11BAF;
    private static readonly byte[] HermesMagic = [0xC6, 0x1F, 0xBC, 0x03, 0xC1, 0x03, 0x19, 0x1F];

    public static IReadOnlyList<AndroidRuntimeFamily> Detect(AndroidPackage package)
    {
        var entries = package.Entries.ToList();
        var libs = entries.Where(e => e.StartsWith("lib/", StringComparison.Ordinal)).Select(e => (Path: e, File: System.IO.Path.GetFileName(e))).ToList();
        List<string> Libs(params string[] files) => [.. libs.Where(l => files.Contains(l.File, StringComparer.Ordinal)).Select(l => l.Path).Take(4)];
        var result = new List<AndroidRuntimeFamily>();

        var dotnet = Libs("libmonodroid.so", "libmonosgen-2.0.so", "libassembly-store.so", "libxamarin-app.so", "libnet-android.release.so", "libcoreclr.so");
        dotnet.AddRange(libs.Where(l => l.File.StartsWith("libassemblies.", StringComparison.Ordinal) && l.File.EndsWith(".blob.so", StringComparison.Ordinal)).Select(l => l.Path).Take(2));
        dotnet.AddRange(entries.Where(e => e.StartsWith("assemblies/", StringComparison.Ordinal)).Take(3));
        if (dotnet.Count > 0) result.Add(new("dotnet-android", dotnet, "Xamarin / .NET MAUI: unpack_container extracts the assemblies by name; map_java_dotnet links Java wrappers to .NET types"));

        var il2cpp = Libs("libil2cpp.so");
        const string Metadata = "assets/bin/Data/Managed/Metadata/global-metadata.dat";
        if (il2cpp.Count > 0 || package.Contains(Metadata))
        {
            string? note = null;
            if (package.Contains(Metadata))
            {
                il2cpp.Add(Metadata);
                var head = Head(package, Metadata, 4);
                note = head.Length == 4 && BinaryPrimitives.ReadUInt32LittleEndian(head) == Il2CppMetadataMagic
                    ? "Unity Il2Cpp: metadata header readable"
                    : "Unity Il2Cpp: the metadata does not start with 0xFAB11BAF (encrypted or tampered)";
            }
            result.Add(new("unity-il2cpp", il2cpp, note ?? "Unity Il2Cpp: no global-metadata.dat in this APK (an asset pack or split may hold it)"));
        }
        var mono = entries.Where(e => e.StartsWith("assets/bin/Data/Managed/", StringComparison.Ordinal) && e.EndsWith(".dll", StringComparison.Ordinal)).Take(4).ToList();
        if (mono.Count > 0) result.Add(new("unity-mono", mono, "Unity Mono: the Managed assemblies load directly"));

        var flutter = Libs("libflutter.so", "libapp.so");
        if (flutter.Any(l => l.EndsWith("libflutter.so", StringComparison.Ordinal))) result.Add(new("flutter", flutter, "Flutter: Dart AOT code in libapp.so"));

        var rn = Libs("libhermes.so", "libreactnativejni.so", "libreactnative.so", "libjsc.so");
        foreach (var bundle in new[] { "assets/index.android.bundle" }.Where(package.Contains))
        {
            rn.Add(bundle);
            var hermes = Head(package, bundle, 8).AsSpan().SequenceEqual(HermesMagic);
            result.Add(new("react-native", rn, hermes ? "React Native: Hermes bytecode bundle" : "React Native: JavaScript bundle"));
            rn = [];
        }
        if (rn.Count > 0) result.Add(new("react-native", rn, "React Native"));

        if (package.Contains("assets/www/index.html") || package.Contains("assets/public/index.html"))
            result.Add(new("web", [package.Contains("assets/www/index.html") ? "assets/www/index.html" : "assets/public/index.html"], "Cordova / Capacitor web app"));

        var dex = package.DexFiles;
        if (dex.Count > 0)
        {
            var kotlin = entries.Where(e => e.StartsWith("kotlin/", StringComparison.Ordinal) || e.EndsWith(".kotlin_module", StringComparison.Ordinal)).Take(2).ToList();
            result.Add(new(kotlin.Count > 0 ? "kotlin" : "java", [.. dex.Take(3), .. kotlin], $"{dex.Count} DEX file(s)"));
        }
        return result;
    }

    private static byte[] Head(AndroidPackage package, string entry, int count)
    {
        try { return package.Read(entry) is { } b ? b[..Math.Min(count, b.Length)] : []; }
        catch (ToolError) { return []; }
    }
}
