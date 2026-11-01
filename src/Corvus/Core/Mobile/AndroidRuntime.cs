using System.Buffers.Binary;

namespace Corvus.Core.Mobile;

/// <summary>A runtime an Android package carries, with the entries that show it.</summary>
public sealed record AndroidRuntimeFamily(string Family, IReadOnlyList<string> Evidence, string? Note);

/// <summary>Runtime families decided from package content (native libraries, stores, metadata magic), not from file names alone.</summary>
public static class AndroidRuntime
{
    private const uint AotMetadataMagic = 0xFAB11BAF;
    private const string Metadata = "assets/bin/Data/Managed/Metadata/global-metadata.dat";

    /// <summary>libil2cpp.so or global-metadata.dat: the entries that make a package an AOT build.</summary>
    public static bool IsAotEntry(string entry) =>
        entry == Metadata || (entry.StartsWith("lib/", StringComparison.Ordinal) && entry.EndsWith("/libil2cpp.so", StringComparison.Ordinal));

    public static bool IsMonoEntry(string entry) =>
        entry.StartsWith("assets/bin/Data/Managed/", StringComparison.Ordinal) && entry.EndsWith(".dll", StringComparison.Ordinal);

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

        var aot = Libs("libil2cpp.so");
        if (aot.Count > 0 || package.Contains(Metadata))
        {
            var notes = new List<string>();
            if (package.Contains(Metadata))
            {
                aot.Add(Metadata);
                var head = package.ReadHead(Metadata, 8);
                notes.Add(head.Length >= 4 && BinaryPrimitives.ReadUInt32LittleEndian(head) == AotMetadataMagic
                    ? "AOT: metadata header readable" + (head.Length == 8 ? $", version {BinaryPrimitives.ReadInt32LittleEndian(head.AsSpan(4))}" : "")
                    : "AOT: the metadata does not start with 0xFAB11BAF (encrypted or tampered)");
            }
            else notes.Add("AOT: no global-metadata.dat in this APK (an asset pack or split may hold it)");
            var abis = AotCodeAbis(package);
            if (abis.Count > 0)
            {
                var next = abis.FirstOrDefault(a => a.Confirmed).Abi ?? abis[0].Abi;
                notes.Add($"native code {string.Join(", ", abis.Select(a => a.Label))}; "
                    + $"load_assembly path={package.Path} slice={next} loads its library");
            }
            result.Add(new("aot", aot, string.Join("; ", notes)));
        }
        var mono = entries.Where(IsMonoEntry).Take(4).ToList();
        if (mono.Count > 0) result.Add(new("mono", mono, "Mono: the Managed assemblies load directly"));

        var flutter = Libs("libflutter.so", "libapp.so");
        if (flutter.Any(l => l.EndsWith("libflutter.so", StringComparison.Ordinal))) result.Add(new("flutter", flutter, "Flutter: Dart AOT code in libapp.so"));

        var rn = Libs("libhermes.so", "libreactnativejni.so", "libreactnative.so", "libjsc.so");
        foreach (var bundle in new[] { "assets/index.android.bundle" }.Where(package.Contains))
        {
            rn.Add(bundle);
            var head = package.ReadHead(bundle, 12);
            var note = head.Length >= 8 && BinaryPrimitives.ReadUInt64LittleEndian(head) == Hermes.HermesFile.Magic
                ? "React Native: Hermes bytecode bundle" + (Hermes.HermesFile.VersionOf(head) is { } version ? $" (version {version})" : "")
                  + "; analyze_js path=<the package> lists, decompiles and searches its functions"
                : "React Native: JavaScript bundle";
            result.Add(new("react-native", rn, note));
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

    // The ABI folder names the library; the ELF machine confirms it.
    // A mismatch or an unreadable header is labelled.
    private static List<(string Abi, string Label, bool Confirmed)> AotCodeAbis(
        AndroidPackage package) =>
    [
        .. package.Entries
            .Where(e => e.StartsWith("lib/", StringComparison.Ordinal)
                && e.EndsWith("/libil2cpp.so", StringComparison.Ordinal)
                && e.Count(c => c == '/') == 2)
            .Order(StringComparer.Ordinal)
            .Select(e =>
            {
                var abi = e.Split('/')[1];
                var machine = ElfMachine(package.ReadHead(e, 20));
                if (machine == null) return (abi, $"{abi} (header unreadable)", false);
                return machine == abi
                    ? (abi, abi, true)
                    : (abi, $"{abi} (ELF machine is {machine})", false);
            }),
    ];

    // Maps e_machine to the Android ABI name: 183 AArch64, 40 ARM, 62 x86-64, 3 x86.
    private static string? ElfMachine(byte[] head)
    {
        if (head.Length < 20 || head[0] != 0x7F || head[1] != (byte)'E'
            || head[2] != (byte)'L' || head[3] != (byte)'F') return null;
        return BinaryPrimitives.ReadUInt16LittleEndian(head.AsSpan(18)) switch
        {
            183 => "arm64-v8a",
            40 => "armeabi-v7a",
            62 => "x86_64",
            3 => "x86",
            var other => $"machine {other}",
        };
    }
}
