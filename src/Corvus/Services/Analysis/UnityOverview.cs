using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using dnlib.DotNet;
using Corvus.Core;
using Corvus.Native.Providers;

namespace Corvus.Services.Analysis;

/// <summary>
/// Overview of a Unity build from its layout and file headers: engine version (version resources, serialized-file and
/// bundle headers, cross-checked against the Il2Cpp metadata version), scripting backend with evidence, toolchain and
/// protection markers, platform, architecture, notable folders and next tool calls. Reads only directory listings, PE
/// headers, version resources and a few hundred header bytes per file (plus up to 16 MB of the Il2Cpp metadata string
/// heap, or Assembly-CSharp's type names for Mono); nothing is executed except Detect It Easy, when asked.
/// </summary>
public static class UnityOverview
{
    public sealed record Report(
        [property: Description("The path as given.")] string Input,
        [property: Description("The game folder (the one with the executable / UnityPlayer).")] string GameDirectory,
        [property: Description("The data folder (<Game>_Data, assets/bin/Data, Contents/Resources/Data); null when absent.")] string? DataDirectory,
        string? Executable,
        [property: Description("Company and product from <Data>/app.info; null when absent.")] string? Company,
        string? Product,
        [property: Description("windows, linux, macos, android, ios, webgl or unknown.")] string Platform,
        [property: Description("x64, x86, arm64, arm or unknown.")] string Architecture,
        [property: Description("Where architecture was read from.")] string? ArchitectureSource,
        EngineFacts Engine,
        BackendFacts Backend,
        [property: Description("Toolchain, protection and middleware markers.")] IReadOnlyList<MarkerFact> Markers,
        IReadOnlyList<FolderFact> Folders,
        [property: Description("Recommended tool calls, most useful first.")] IReadOnlyList<NextStep> NextSteps,
        IReadOnlyList<string> Notes);

    public sealed record EngineFacts(
        [property: Description("The engine version as the most specific source writes it (may carry a vendor suffix, e.g. 2020.3.13f1XD1.1); null when no source has it.")] string? Version,
        [property: Description("major.minor.patch plus release (2022.3.62f1); null when unknown.")] string? Normalized,
        [property: Description("agree (all sources give the same major.minor.patch), disagree, single_source or unknown.")] string Agreement,
        IReadOnlyList<VersionClaim> Claims,
        [property: Description("Unity versions that write this Il2Cpp metadata version (e.g. 2020.2 - 2021.1); null for Mono or unreadable metadata.")] string? MetadataRange,
        [property: Description("consistent (the version falls in metadataRange), inconsistent, or not_checked.")] string MetadataCheck);

    public sealed record VersionClaim(
        [property: Description("version_resource (PE FileVersion / ProductVersion), serialized_file (globalgamemanagers, mainData, level0 header) or bundle_header (data.unity3d).")] string Source,
        string File, string Version, string? Normalized);

    public sealed record BackendFacts(
        [property: Description("il2cpp, mono or unknown.")] string Kind,
        IReadOnlyList<string> Evidence,
        string? ManagedDirectory,
        [property: Description("DLLs in the Managed folder.")] int ManagedAssemblies,
        [property: Description("readable, encrypted (Assembly-CSharp.dll is not a readable .NET image), missing or not_applicable.")] string ManagedState,
        [property: Description("Mono runtime: mono-2.0-bdwgc (MonoBleedingEdge, .NET 4.x profile) or mono (legacy Mono, .NET 3.5 profile); null for Il2Cpp.")] string? MonoRuntime,
        [property: Description("API profile from mscorlib / netstandard in the Managed folder, e.g. \".NET 4.x (mscorlib 4.0.0.0), netstandard 2.1.0.0\".")] string? DotnetProfile,
        string? NativeBinary,
        string? Metadata,
        long? MetadataSize,
        [property: Description("The metadata header's version field as read (also when out of range).")] int? MetadataVersion,
        [property: Description("readable (built-in reader, versions 24-39), encrypted (no metadata magic), header_tampered (magic kept, header inconsistent), unsupported_version, truncated, missing or not_applicable.")] string MetadataState,
        string? MetadataStateReason,
        [property: Description("Assemblies listed in <Data>/ScriptingAssemblies.json (Unity 2019.3+); what survived code stripping.")] int? ScriptingAssemblies,
        [property: Description("Share (0..1) of identifiers that are unreadable or one or two characters long (Assembly-CSharp type names, or the Il2Cpp metadata string heap); null when not read.")] double? UnreadableNameRatio,
        [property: Description("Identifiers read for unreadableNameRatio.")] int NamesRead);

    public sealed record MarkerFact(
        [property: Description("anti_cheat, obfuscator, packer, encryption, mod_loader, build, middleware or toolchain.")] string Category,
        string Name, string Evidence,
        [property: Description("layout (file and folder names), pe_sections, assembly_markers, metadata_names or detect_it_easy.")] string Source);

    public sealed record FolderFact(
        [property: Description("managed, il2cpp_data, streaming_assets, addressables, plugins, mono_runtime, mod_loader or other.")] string Kind,
        string Path,
        [property: Description("Entries directly inside (files and folders), counted up to 10000.")] int Entries,
        string? Note);

    public sealed record NextStep(
        [property: Description("load_assembly, list_namespaces, apply_il2cpp_names, search_bytes, inspect_process, dump_from_memory, use_external_dumper or summarize_file.")] string Action,
        [property: Description("The tool to call; null when the step is outside this server.")] string? Tool,
        IReadOnlyDictionary<string, string> Arguments,
        string Reason);

    private const uint MetadataMagic = 0xFAB11BAF;
    private const int MaxEntries = 10_000;
    private const int MaxStringHeap = 16 << 20;
    private const int MaxTypeNames = 50_000;
    private static readonly TimeSpan DieTimeout = TimeSpan.FromSeconds(20);

    private static readonly string[] DataMarkers = ["globalgamemanagers", "data.unity3d", "mainData", "level0", "Managed", "il2cpp_data"];

    private static readonly string LookedFor =
        "a <Game>_Data folder (with globalgamemanagers, data.unity3d, mainData, level0, Managed or il2cpp_data), UnityPlayer.dll / UnityPlayer.so, " +
        "GameAssembly.dll with global-metadata.dat, assets/bin/Data (extracted Android APK), Contents/Resources/Data (macOS .app) or Data (iOS .app), " +
        "in the path or up to 4 folders above it";

    /// <summary>The overview of the Unity title at <paramref name="path"/>; ToolError (unsupported, reason not_a_unity_title) otherwise.</summary>
    public static Report Inspect(string path, bool detectItEasy, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ToolError(ErrorCode.InvalidArgument, "path is empty.", "pass a game folder, its executable, its *_Data folder, UnityPlayer.dll or GameAssembly.dll");
        string full;
        try { full = Path.GetFullPath(path.Trim().Trim('"')); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new ToolError(ErrorCode.InvalidArgument, $"Not a valid path: {path} ({ex.Message}).");
        }
        if (!File.Exists(full) && !Directory.Exists(full)) throw Targets.FileNotFound(full);
        string? die = null;
        if (detectItEasy)
            die = FindDie() ?? throw new ToolError(ErrorCode.ProviderUnavailable,
                "Detect It Easy (diec) was not found: looked at CORVUS_DIE (diec.exe or its folder) and for diec / diec.exe on PATH.",
                "set CORVUS_DIE to the Detect It Easy folder (or diec.exe), or call again with detectItEasy=false");

        string? package = null;
        var webNotes = new List<string>();
        if (UnityWebGl.Find(full) is { } web)
        {
            package = web.Data;
            full = UnityWebGl.Extract(web, Path.GetFullPath(Il2CppRawLoader.DefaultRoot), webNotes, ct);
        }
        else if (Il2CppPackages.IsUnityPackage(full))
        {
            // Packages and zipped titles: the game files the overview reads (binaries, metadata or assemblies, version files), in a short cache path.
            package = full;
            full = Il2CppPackages.Extract(full, null, ct: ct, anyBackend: true) ?? throw new ToolError(ErrorCode.Unsupported,
                $"{package} holds no Unity title (no Il2Cpp metadata, Managed assemblies or <Game>_Data folder): reason not_a_unity_title.",
                "pass the title's package, zip or folder");
        }
        var layout = Resolve(full, ct) ?? throw new ToolError(ErrorCode.Unsupported,
            $"{full} is not a Unity title (no UnityPlayer, libunity, GameAssembly or data folder in it or 4 folders above): reason not_a_unity_title.",
            "pass the game folder (the one with the executable), its <Game>_Data folder, UnityPlayer.dll or GameAssembly.dll")
        {
            Details = new { reason = "not_a_unity_title", path = full, lookedFor = LookedFor },
        };
        var notes = new List<string>(layout.Notes);
        notes.AddRange(webNotes);
        if (package != null) notes.Add($"Read from the game files of {package}, extracted to {full} (binaries, metadata or assemblies, and the data folder's version files).");
        var markers = new List<MarkerFact>();
        ct.ThrowIfCancellationRequested();
        var engine = Engine(layout, ct);
        ct.ThrowIfCancellationRequested();
        var backend = Backend(layout, markers, notes, ct);
        engine = CrossCheck(engine, backend);
        ct.ThrowIfCancellationRequested();
        LayoutMarkers(layout, backend, markers, ct);
        SectionMarkers(layout, backend, markers);
        if (die != null) DieMarkers(die, layout, backend, markers, notes, ct);
        else if (FindDie() is { } found) notes.Add($"Detect It Easy is available ({found}): detectItEasy=true adds its compiler / packer / protector detections.");
        var (arch, archSource) = Architecture(layout, backend);
        var folders = Folders(layout, ct);
        if (engine.Agreement == "disagree") notes.Add("The engine version sources disagree: the version resource is the player binary, the serialized files are the data; a patched or mixed install shows this.");
        var steps = NextSteps(layout, backend, markers);
        var (company, product) = AppInfo(layout.Data);
        return new Report(path, layout.Game, layout.Data, layout.Exe, company, product, layout.Platform, arch, archSource, engine, backend,
            markers, folders, steps, notes);
    }

    private sealed record Layout(string Game, string? Data, string? Exe, string Platform, string? UnityPlayer, List<string> Notes);

    private static Layout? Resolve(string full, CancellationToken ct)
    {
        string? exeHint = File.Exists(full) && IsExecutableName(full) ? full : null;
        var dir = File.Exists(full) ? Path.GetDirectoryName(full)! : full;
        for (int level = 0; level <= 4 && dir != null; level++, dir = Path.GetDirectoryName(dir))
        {
            ct.ThrowIfCancellationRequested();
            if (TryLayout(dir, exeHint) is { } layout) return layout;
        }
        return null;
    }

    private static Layout? TryLayout(string dir, string? exeHint)
    {
        var notes = new List<string>();
        // WebGL: the files UnityWebGl unpacked from the build's .data, laid out as Data/.
        if (File.Exists(Path.Combine(dir, UnityWebGl.Marker)))
            return new Layout(dir, Path.Combine(dir, "Data"), null, "webgl", null, notes);
        // Android (extracted APK): assets/bin/Data.
        var androidData = Path.Combine(dir, "assets", "bin", "Data");
        if (Directory.Exists(androidData))
            return new Layout(dir, androidData, null, "android", FirstExisting(Libs(dir, "libunity.so")), notes);
        // macOS: X.app/Contents/Resources/Data.
        var macData = Path.Combine(dir, "Contents", "Resources", "Data");
        if (Directory.Exists(macData))
            return new Layout(dir, macData, null, "macos", FirstExisting([Path.Combine(dir, "Contents", "Frameworks", "UnityPlayer.dylib")]), notes);
        // iOS: X.app/Data; the code is in Frameworks/UnityFramework.framework (2019.3+) or the app's executable.
        var iosData = Path.Combine(dir, "Data");
        if (dir.EndsWith(".app", StringComparison.OrdinalIgnoreCase) && IsDataFolder(iosData))
            return new Layout(dir, iosData, null, "ios", null, notes);

        if (Path.GetFileName(dir).EndsWith("_Data", StringComparison.OrdinalIgnoreCase) && IsDataFolder(dir))
            return Build(Path.GetDirectoryName(dir)!, dir, exeHint, notes);
        var datas = SafeList(() => Directory.EnumerateDirectories(dir, "*_Data").Where(IsDataFolder).Take(32).ToList());
        if (datas.Count > 0)
        {
            string? chosen = null;
            if (exeHint != null) chosen = datas.FirstOrDefault(d => Path.GetFileName(d).Equals(Path.GetFileNameWithoutExtension(exeHint) + "_Data", StringComparison.OrdinalIgnoreCase));
            chosen ??= datas.FirstOrDefault(d => ExecutableFor(dir, d) != null && HasSerializedHeader(d));
            chosen ??= datas.FirstOrDefault(HasSerializedHeader) ?? datas[0];
            if (datas.Count > 1)
                notes.Add($"Several data folders: {string.Join(", ", datas.Select(Path.GetFileName))}; reported {Path.GetFileName(chosen)} (the one beside the executable with serialized files).");
            return Build(dir, chosen, exeHint, notes);
        }
        bool player = File.Exists(Path.Combine(dir, "UnityPlayer.dll")) || File.Exists(Path.Combine(dir, "UnityPlayer.so"));
        bool il2cpp = File.Exists(Path.Combine(dir, "GameAssembly.dll")) && Il2CppGameFiles.MetadataIn(dir) != null;
        if (player || il2cpp)
        {
            notes.Add("No <Game>_Data folder: the overview is from the binaries alone.");
            return Build(dir, null, exeHint, notes);
        }
        return null;
    }

    private static Layout Build(string game, string? data, string? exeHint, List<string> notes)
    {
        var exe = exeHint != null && Path.GetDirectoryName(exeHint) == game && !IsEngineFile(exeHint) ? exeHint : data != null ? ExecutableFor(game, data) : null;
        exe ??= SafeList(() => Directory.EnumerateFiles(game, "*.exe").Where(f => !IsEngineFile(f)).Take(16).ToList()).FirstOrDefault();
        var player = FirstExisting([Path.Combine(game, "UnityPlayer.dll"), Path.Combine(game, "UnityPlayer.so")]);
        string platform = player?.EndsWith(".so", StringComparison.OrdinalIgnoreCase) == true || (exe != null && IsElf(exe)) ? "linux"
            : player != null || exe?.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) == true || File.Exists(Path.Combine(game, "GameAssembly.dll")) ? "windows"
            : "unknown";
        return new Layout(game, data, exe, platform, player, notes);
    }

    private static bool IsDataFolder(string dir) =>
        DataMarkers.Any(m => File.Exists(Path.Combine(dir, m)) || Directory.Exists(Path.Combine(dir, m)));

    private static bool HasSerializedHeader(string data) =>
        new[] { "globalgamemanagers", "data.unity3d", "mainData" }.Any(f => File.Exists(Path.Combine(data, f)));

    private static string? ExecutableFor(string game, string data)
    {
        var stem = Path.GetFileName(data)[..^"_Data".Length];
        return FirstExisting([Path.Combine(game, stem + ".exe"), Path.Combine(game, stem + ".x86_64"), Path.Combine(game, stem + ".x86"), Path.Combine(game, stem)]);
    }

    private static bool IsExecutableName(string path) =>
        path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || path.EndsWith(".x86_64", StringComparison.OrdinalIgnoreCase) || path.EndsWith(".x86", StringComparison.OrdinalIgnoreCase);

    private static bool IsEngineFile(string path) =>
        Path.GetFileName(path) is var n && (n.StartsWith("UnityCrashHandler", StringComparison.OrdinalIgnoreCase) || n.StartsWith("UnityPlayer", StringComparison.OrdinalIgnoreCase)
                                            || n.Equals("GameAssembly.dll", StringComparison.OrdinalIgnoreCase) || !IsExecutableName(path));

    private static IEnumerable<string> Libs(string apk, string name) =>
        SafeList(() => Directory.EnumerateDirectories(Path.Combine(apk, "lib")).Take(16).ToList()).Select(d => Path.Combine(d, name));

    private static readonly Regex VersionPattern = new(@"^(\d{1,4})\.(\d{1,2})\.(\d{1,3})(?:([abfpx])(\d{1,3}))?", RegexOptions.CultureInvariant);

    private static EngineFacts Engine(Layout layout, CancellationToken ct)
    {
        var claims = new List<VersionClaim>();
        foreach (var file in new[] { layout.UnityPlayer, layout.Exe }.OfType<string>())
            if (VersionResource(file) is { } v) claims.Add(new VersionClaim("version_resource", file, v, Normalize(v)));
        if (layout.Data != null)
        {
            ct.ThrowIfCancellationRequested();
            var serialized = FirstExisting([Path.Combine(layout.Data, "globalgamemanagers"), Path.Combine(layout.Data, "mainData"), Path.Combine(layout.Data, "level0")]);
            if (serialized != null && SerializedVersion(serialized) is { } s) claims.Add(new VersionClaim("serialized_file", serialized, s, Normalize(s)));
            var bundle = Path.Combine(layout.Data, "data.unity3d");
            if (File.Exists(bundle) && BundleVersion(bundle) is { } b) claims.Add(new VersionClaim("bundle_header", bundle, b, Normalize(b)));
        }
        claims = [.. claims.Where(c => c.Normalized != null)];
        // Most specific first: data headers carry the release suffix and vendor tags, then ProductVersion, then FileVersion.
        var best = claims.OrderBy(c => c.Source == "version_resource" ? 1 : 0).ThenByDescending(c => c.Version.Length).FirstOrDefault();
        var keys = claims.Select(c => Key(c.Normalized!)).Distinct().ToList();
        string agreement = claims.Count == 0 ? "unknown" : claims.Count == 1 ? "single_source" : keys.Count == 1 ? "agree" : "disagree";
        return new EngineFacts(best?.Version, best?.Normalized, agreement, claims, null, "not_checked");
    }

    /// <summary>"2022.3.62f1 (25971d727925)" or "2019.4.37.106033" from the PE version resource; null when absent.</summary>
    private static string? VersionResource(string file)
    {
        try
        {
            var info = FileVersionInfo.GetVersionInfo(file);
            foreach (var v in new[] { info.ProductVersion, info.FileVersion })
                if (v != null && VersionPattern.Match(v.Trim()) is { Success: true } m && int.Parse(m.Groups[1].Value) >= 3)
                    return v.Trim().Split(' ')[0];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FileNotFoundException) { }
        return null;
    }

    /// <summary>The engine version string in a serialized file's header (format 9 and later), or null.</summary>
    internal static string? SerializedVersion(string file)
    {
        var head = ReadHead(file, 256);
        if (head.Length < 24) return null;
        uint format = BinaryPrimitives.ReadUInt32BigEndian(head.AsSpan(8));
        int at = format is >= 9 and < 22 ? 20 : format is >= 22 and < 100 ? 48 : -1;
        return at < 0 ? null : CString(head, at) is { } s && VersionPattern.IsMatch(s) ? s : null;
    }

    /// <summary>The engine version in a UnityFS / UnityWeb / UnityRaw bundle header, or null.</summary>
    internal static string? BundleVersion(string file)
    {
        var head = ReadHead(file, 256);
        var sig = CString(head, 0);
        if (sig is not ("UnityFS" or "UnityWeb" or "UnityRaw")) return null;
        int at = sig.Length + 1 + 4;
        var player = CString(head, at);
        if (player == null) return null;
        return CString(head, at + player.Length + 1) is { } s && VersionPattern.IsMatch(s) ? s : null;
    }

    internal static string? Normalize(string version)
    {
        var m = VersionPattern.Match(version);
        if (!m.Success) return null;
        var core = $"{m.Groups[1].Value}.{m.Groups[2].Value}.{m.Groups[3].Value}";
        return m.Groups[4].Success ? core + m.Groups[4].Value + m.Groups[5].Value : core;
    }

    private static string Key(string normalized) => VersionPattern.Match(normalized) is var m ? $"{m.Groups[1].Value}.{m.Groups[2].Value}.{m.Groups[3].Value}" : normalized;

    /// <summary>Unity versions (major.minor, inclusive) that write each Il2Cpp metadata version.</summary>
    internal static (int Major, int Minor, int ToMajor, int ToMinor)? MetadataRange(int version) => version switch
    {
        16 => (5, 2, 5, 3),
        19 or 20 => (5, 3, 5, 3),
        21 => (5, 3, 5, 4),
        22 => (5, 5, 5, 5),
        23 => (5, 6, 2017, 1),
        24 => (2017, 1, 2020, 1),
        27 => (2020, 2, 2021, 1),
        29 => (2021, 2, 2023, 1),
        31 => (2022, 3, 9999, 99),
        _ => null,
    };

    private static EngineFacts CrossCheck(EngineFacts engine, BackendFacts backend)
    {
        if (backend.MetadataVersion is not { } v || backend.MetadataState is "encrypted" or "header_tampered" || MetadataRange(v) is not { } r) return engine;
        var range = r.ToMajor == 9999 ? $"{r.Major}.{r.Minor} and later" : $"{r.Major}.{r.Minor} - {r.ToMajor}.{r.ToMinor}";
        if (engine.Normalized == null || VersionPattern.Match(engine.Normalized) is not { Success: true } m) return engine with { MetadataRange = range };
        int major = int.Parse(m.Groups[1].Value), minor = int.Parse(m.Groups[2].Value);
        bool inside = (major, minor).CompareTo((r.Major, r.Minor)) >= 0 && (major, minor).CompareTo((r.ToMajor, r.ToMinor)) <= 0;
        return engine with { MetadataRange = range, MetadataCheck = inside ? "consistent" : "inconsistent" };
    }

    private static BackendFacts Backend(Layout layout, List<MarkerFact> markers, List<string> notes, CancellationToken ct)
    {
        var evidence = new List<string>();
        var game = layout.Game;
        var data = layout.Data;
        var binary = FirstExisting([Path.Combine(game, "GameAssembly.dll"), Path.Combine(game, "GameAssembly.so"),
            Path.Combine(game, "Contents", "Frameworks", "GameAssembly.dylib"), .. Libs(game, "libil2cpp.so"),
            .. layout.Platform == "ios" ? [Path.Combine(game, "Frameworks", "UnityFramework.framework", "UnityFramework"), Path.Combine(game, Path.GetFileNameWithoutExtension(game))] : Array.Empty<string>()]);
        string? metadata = data != null
            ? FirstExisting([Path.Combine(data, "il2cpp_data", "Metadata", "global-metadata.dat"), Path.Combine(data, "Managed", "Metadata", "global-metadata.dat")])
            : Il2CppGameFiles.MetadataIn(game);
        var managed = data != null && Directory.Exists(Path.Combine(data, "Managed")) ? Path.Combine(data, "Managed") : null;
        var managedDlls = managed != null ? SafeList(() => Directory.EnumerateFiles(managed, "*.dll").Take(MaxEntries).ToList()) : [];
        bool scripts = managedDlls.Any(f => Path.GetFileName(f) is var n && (n.StartsWith("Assembly-CSharp", StringComparison.OrdinalIgnoreCase) || n.StartsWith("UnityEngine", StringComparison.OrdinalIgnoreCase)));
        var mono = FirstExisting([Path.Combine(game, "MonoBleedingEdge", "EmbedRuntime", "mono-2.0-bdwgc.dll"), Path.Combine(game, "Mono", "EmbedRuntime", "mono.dll"),
            Path.Combine(game, "Mono", "mono.dll"), .. data != null ? new[] { Path.Combine(data, "Mono", "mono.dll"), Path.Combine(data, "Mono", "EmbedRuntime", "mono.dll") } : [],
            .. Libs(game, "libmonobdwgc-2.0.so"), .. Libs(game, "libmono.so")]);
        int? scriptingAssemblies = data != null ? ScriptingAssemblyCount(Path.Combine(data, "ScriptingAssemblies.json")) : null;

        string kind = binary != null || metadata != null ? "il2cpp" : scripts || mono != null ? "mono" : "unknown";
        if (binary != null) evidence.Add($"Il2Cpp native code: {binary}");
        if (metadata != null) evidence.Add($"Il2Cpp metadata: {metadata}");
        if (managed != null) evidence.Add($"Managed folder: {managedDlls.Count} DLL(s){(scripts ? " including Assembly-CSharp / UnityEngine" : "")}");
        if (mono != null) evidence.Add($"Mono runtime: {mono}");
        if (scriptingAssemblies is { } sa) evidence.Add($"ScriptingAssemblies.json lists {sa} assemblies");
        if (kind == "il2cpp" && scripts) notes.Add("An Il2Cpp build with IL assemblies in Managed: they may be leftovers or a second (Mono) build; the native binary is what runs.");
        if (kind == "unknown") notes.Add("Neither Il2Cpp files (GameAssembly + global-metadata.dat) nor Mono files (Managed with Assembly-CSharp / UnityEngine, a Mono runtime) were found.");

        string managedState = "not_applicable";
        string? profile = null;
        double? ratio = null;
        int namesRead = 0;
        if (kind == "mono")
        {
            profile = DotnetProfile(managed);
            var csharp = managed != null ? FirstExisting([Path.Combine(managed, "Assembly-CSharp.dll")]) : null;
            if (csharp == null) managedState = "missing";
            else
            {
                ct.ThrowIfCancellationRequested();
                (managedState, ratio, namesRead) = ManagedNames(csharp, markers);
                if (managedState == "encrypted")
                    markers.Add(new MarkerFact("encryption", "encrypted managed assembly", $"{csharp} is not a readable .NET image (decrypted by a modified runtime at load time)", "layout"));
            }
        }

        string state = "not_applicable";
        string? reason = null;
        int? version = null;
        long? size = null;
        if (kind == "il2cpp")
        {
            if (metadata == null) { state = "missing"; reason = "no global-metadata.dat in <Data>/il2cpp_data/Metadata: renamed, packed into another file or embedded in the binary"; }
            else
            {
                ct.ThrowIfCancellationRequested();
                (state, reason, version, size) = MetadataState(metadata);
                if (state == "readable")
                {
                    (ratio, namesRead) = MetadataNames(metadata, markers, ct);
                    if (layout.Platform is "unknown" && binary == null) reason = "header readable; the built-in reader needs the game binary (GameAssembly, libil2cpp.so or UnityFramework) beside it";
                }
                else if (state is "encrypted" or "header_tampered")
                    markers.Add(new MarkerFact("encryption", "encrypted Il2Cpp metadata", $"{state}: {reason}", "metadata_names"));
            }
        }
        if (ratio is >= 0.3 && namesRead >= 100 && !markers.Any(m => m.Category == "obfuscator"))
            markers.Add(new MarkerFact("obfuscator", "renamed identifiers", $"{Corvus.Core.Format.Percent(ratio.Value)} of {namesRead} identifiers are unreadable or one or two characters long", kind == "mono" ? "assembly_markers" : "metadata_names"));
        string? monoRuntime = mono == null ? null : Path.GetFileNameWithoutExtension(mono) is var n && n.Contains("bdwgc", StringComparison.OrdinalIgnoreCase)
            ? $"{n} (MonoBleedingEdge, .NET 4.x profile)" : $"{n} (legacy Mono, .NET 3.5 profile)";
        return new BackendFacts(kind, evidence, managed, managedDlls.Count, managedState, kind == "mono" ? monoRuntime : null, profile, binary, metadata, size, version,
            state, reason, scriptingAssemblies, ratio, namesRead);
    }

    /// <summary>The metadata's readability from its first 512 bytes: magic, version field and the header's offset / size pairs.</summary>
    internal static (string State, string? Reason, int? Version, long? Size) MetadataState(string metadata)
    {
        long size;
        try { size = new FileInfo(metadata).Length; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return ("missing", ex.Message, null, null); }
        var head = ReadHead(metadata, 512);
        if (head.Length < 64) return ("truncated", $"{head.Length} bytes: too small to be Il2Cpp metadata", null, size);
        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(head);
        int version = BinaryPrimitives.ReadInt32LittleEndian(head.AsSpan(4));
        if (magic != MetadataMagic)
            return ("encrypted", $"starts with 0x{magic:X8}, not the metadata magic 0x{MetadataMagic:X8} (encrypted or obfuscated; the running game holds it decrypted)", null, size);
        if (version is < 16 or > 64)
            return ("header_tampered", $"magic present but the version field is {version} (0x{version:X8}): the header after the magic is encrypted or scrambled", version, size);
        // The header is (offset, size) pairs, (offset, size, count) from version 38; the first section starts right after it.
        int stride = SectionStride(version);
        int headerSize = BinaryPrimitives.ReadInt32LittleEndian(head.AsSpan(8));
        if (headerSize is < 0x40 or > 0x200 || headerSize % 4 != 0 || headerSize > head.Length)
            return ("header_tampered", $"magic and version {version} present, but the first section offset 0x{headerSize:X} is not a header size", version, size);
        int bad = 0, pairs = (headerSize - 8) / stride;
        for (int i = 0; i < pairs; i++)
        {
            long offset = BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(8 + i * stride));
            long length = BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(12 + i * stride));
            if (length != 0 && (offset < headerSize || offset + length > size)) bad++;
        }
        if (bad > 0)
            return ("header_tampered", $"magic and version {version} present, but {bad} of {pairs} header sections lie outside the {size:N0}-byte file", version, size);
        if (version < Il2CppMetadataReader.MinVersion || version > Il2CppMetadataReader.MaxVersion)
            return ("unsupported_version", $"version {version}; the built-in reader handles {Il2CppMetadataReader.MinVersion}-{Il2CppMetadataReader.MaxVersion}", version, size);
        return ("readable", null, version, size);
    }

    private static int SectionStride(int version) => version >= 38 ? 12 : 8;

    /// <summary>Identifier statistics and marker names from the metadata string heap (header section 3, bounded).</summary>
    private static (double? Ratio, int Names) MetadataNames(string metadata, List<MarkerFact> markers, CancellationToken ct)
    {
        var head = ReadHead(metadata, 40);
        int at = 8 + 2 * SectionStride(BinaryPrimitives.ReadInt32LittleEndian(head.AsSpan(4)));
        uint offset = BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(at));
        int length = (int)Math.Min(BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(at + 4)), MaxStringHeap);
        byte[] heap;
        try
        {
            using var f = File.OpenHandle(metadata, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            heap = new byte[length];
            length = RandomAccess.Read(f, heap, offset);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { return (null, 0); }
        ct.ThrowIfCancellationRequested();
        var names = new List<string>();
        int start = 0;
        for (int i = 0; i < length; i++)
        {
            if (heap[i] != 0) continue;
            if (i > start) names.Add(Encoding.UTF8.GetString(heap, start, i - start));
            start = i + 1;
        }
        var identifiers = names.Where(n => n.Length > 0 && n[0] != '<' && !n.Contains('.') && !n.Contains('`')).ToList();
        if (names.Any(n => n.StartsWith("Beebyte.Obfuscator", StringComparison.Ordinal) || n == "Beebyte.Obfuscator"))
            markers.Add(new MarkerFact("obfuscator", "Beebyte Obfuscator", "Beebyte.Obfuscator namespace in the metadata strings", "metadata_names"));
        BeebyteStyle(identifiers, markers, "metadata_names");
        if (identifiers.Count == 0) return (null, 0);
        return (Math.Round((double)identifiers.Count(Markers.IsUnreadable) / identifiers.Count, 3), identifiers.Count);
    }

    /// <summary>Beebyte's default renaming: eleven capital letters (PDOGBNCJAEM).</summary>
    private static void BeebyteStyle(IReadOnlyCollection<string> identifiers, List<MarkerFact> markers, string source)
    {
        int styled = identifiers.Count(n => n.Length == 11 && n.All(char.IsAsciiLetterUpper));
        if (styled >= 50 && styled >= identifiers.Count / 50 && !markers.Any(m => m.Name == "Beebyte Obfuscator"))
            markers.Add(new MarkerFact("obfuscator", "Beebyte Obfuscator", $"{styled} of {identifiers.Count} identifiers are eleven capital letters (its default renaming)", source));
    }

    /// <summary>Assembly-CSharp: readable or not, marker types (survey markers), and the unreadable share of its type and method names.</summary>
    private static (string State, double? Ratio, int Names) ManagedNames(string path, List<MarkerFact> markers)
    {
        var head = ReadHead(path, 4096);
        if (PeImage.TryParse(head) is not { } pe || pe.Directory(head, PeImage.ComDescriptorDirectory).Size == 0) return ("encrypted", null, 0);
        try
        {
            using var module = ModuleDefMD.Load(path, new ModuleCreationOptions { TryToLoadPdbFromDisk = false });
            var full = new HashSet<string>(StringComparer.Ordinal);
            var identifiers = new List<string>();
            foreach (var t in module.GetTypes().Take(MaxTypeNames))
            {
                full.Add(t.FullName);
                identifiers.Add(t.Name.String);
                foreach (var m in t.Methods.Take(64)) if (!m.IsSpecialName && !m.IsRuntimeSpecialName) identifiers.Add(m.Name.String);
            }
            foreach (var ca in (module.Assembly?.CustomAttributes ?? []).Concat(module.CustomAttributes))
                if (ca.AttributeType?.FullName is { } n) full.Add(n);
            foreach (var tool in Markers.ToolsFromNames(full))
                markers.Add(new MarkerFact("obfuscator", tool, $"marker type or attribute in {Path.GetFileName(path)}", "assembly_markers"));
            identifiers = [.. identifiers.Where(n => n.Length > 0 && n[0] != '<' && !n.StartsWith("CS$", StringComparison.Ordinal))];
            BeebyteStyle(identifiers, markers, "assembly_markers");
            return ("readable", identifiers.Count == 0 ? null : Math.Round((double)identifiers.Count(Markers.IsUnreadable) / identifiers.Count, 3), identifiers.Count);
        }
        catch (Exception ex) when (ex is not OperationCanceledException and not OutOfMemoryException) { return ("encrypted", null, 0); }
    }

    private static string? DotnetProfile(string? managed)
    {
        if (managed == null) return null;
        var parts = new List<string>();
        if (AssemblyVersion(Path.Combine(managed, "mscorlib.dll")) is { } core)
            parts.Add((core.Major >= 4 ? ".NET 4.x" : ".NET 3.5") + $" (mscorlib {core})");
        if (AssemblyVersion(Path.Combine(managed, "netstandard.dll")) is { } ns) parts.Add($"netstandard {ns}");
        return parts.Count > 0 ? string.Join(", ", parts) : null;
    }

    private static Version? AssemblyVersion(string path)
    {
        if (!File.Exists(path)) return null;
        try { return System.Reflection.AssemblyName.GetAssemblyName(path).Version; }
        catch (Exception ex) when (ex is BadImageFormatException or IOException or UnauthorizedAccessException or ArgumentException) { return null; }
    }

    private static int? ScriptingAssemblyCount(string path)
    {
        if (!File.Exists(path)) return null;
        try
        {
            if (new FileInfo(path).Length > 4 << 20) return null;
            using var doc = JsonDocument.Parse(File.ReadAllBytes(path));
            return doc.RootElement.TryGetProperty("names", out var names) && names.ValueKind == JsonValueKind.Array ? names.GetArrayLength() : null;
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>(category, name, file or folder names, matched case-insensitively in the game folder, the data folder and Plugins).</summary>
    private static readonly (string Category, string Name, string[] Files)[] LayoutSignatures =
    [
        ("anti_cheat", "Easy Anti-Cheat", ["EasyAntiCheat", "start_protected_game.exe", "EasyAntiCheat_EOS_Setup.exe", "EasyAntiCheat_x64.dll", "EasyAntiCheat_EOS.sys"]),
        ("anti_cheat", "BattlEye", ["BattlEye", "BEService.exe", "BEService_x64.exe", "BEClient_x64.dll"]),
        ("anti_cheat", "nProtect GameGuard", ["GameGuard", "GameMon.des", "npggNT.des", "GameGuard.des"]),
        ("anti_cheat", "XIGNCODE3", ["XIGNCODE", "x3.xem", "xhunter1.sys"]),
        ("anti_cheat", "Anti-Cheat Expert (Tencent ACE)", ["AntiCheatExpert", "ACE-Base64.dll", "SGuard64.exe", "ACE-BASE.sys"]),
        ("anti_cheat", "mhyprot", ["mhyprot2.sys", "mhyprot3.sys"]),
        ("anti_cheat", "Denuvo Anti-Cheat", ["denuvo-anti-cheat.sys", "denuvo-anti-cheat-update-service.exe"]),
        ("mod_loader", "BepInEx", ["BepInEx", "winhttp.dll", "doorstop_config.ini"]),
        ("mod_loader", "MelonLoader", ["MelonLoader", "version.dll"]),
        ("build", "Burst", ["lib_burst_generated.dll", "lib_burst_generated.so"]),
        ("middleware", "Steamworks", ["steam_api64.dll", "steam_api.dll", "libsteam_api.so"]),
        ("middleware", "Epic Online Services", ["EOSSDK-Win64-Shipping.dll", "EOSSDK-Win32-Shipping.dll"]),
        ("middleware", "FMOD", ["fmodstudio.dll", "fmod.dll", "libfmodstudio.so"]),
        ("middleware", "Wwise", ["AkSoundEngine.dll", "libAkSoundEngine.so"]),
        ("middleware", "CRIWARE", ["cri_ware_unity.dll", "libcri_ware_unity.so"]),
        ("middleware", "CrashSight", ["CrashSight64.dll", "CrashSight.dll"]),
    ];

    /// <summary>Managed assembly name prefix (Managed folder or ScriptingAssemblies.json) -> marker.</summary>
    private static readonly (string Category, string Name, string Prefix)[] AssemblySignatures =
    [
        ("build", "Addressables", "Unity.Addressables"),
        ("build", "Burst", "Unity.Burst"),
        ("build", "Entities (DOTS)", "Unity.Entities"),
        ("middleware", "Photon", "Photon"),
        ("middleware", "Mirror", "Mirror"),
        ("middleware", "Netcode for GameObjects", "Unity.Netcode.Runtime"),
        ("middleware", "Odin Inspector", "Sirenix."),
        ("obfuscator", "Beebyte Obfuscator", "Beebyte"),
        ("mod_loader", "Harmony", "0Harmony"),
        ("toolchain", "xLua", "XLua"),
        ("toolchain", "HybridCLR (hot-update Il2Cpp interpreter)", "HybridCLR"),
    ];

    private static void LayoutMarkers(Layout layout, BackendFacts backend, List<MarkerFact> markers, CancellationToken ct)
    {
        var places = new List<string> { layout.Game };
        if (layout.Data != null)
        {
            places.Add(layout.Data);
            var plugins = Path.Combine(layout.Data, "Plugins");
            if (Directory.Exists(plugins))
            {
                places.Add(plugins);
                places.AddRange(SafeList(() => Directory.EnumerateDirectories(plugins).Take(16).ToList()));
            }
        }
        var entries = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var place in places)
        {
            ct.ThrowIfCancellationRequested();
            foreach (var e in SafeList(() => Directory.EnumerateFileSystemEntries(place).Take(MaxEntries).ToList()))
                entries.TryAdd(Path.GetFileName(e), e);
        }
        foreach (var (category, name, files) in LayoutSignatures)
        {
            var hits = files.Where(entries.ContainsKey).Select(f => entries[f]).ToList();
            // winhttp.dll / version.dll alone are common proxies, not proof of a loader.
            if (hits.Count == 0 || (category == "mod_loader" && hits.All(h => Path.GetExtension(h) is ".dll" or ".ini"))) continue;
            markers.Add(new MarkerFact(category, name, string.Join(", ", hits.Take(3)), "layout"));
        }
        var assemblies = new List<string>();
        if (backend.ManagedDirectory != null)
            assemblies.AddRange(SafeList(() => Directory.EnumerateFiles(backend.ManagedDirectory, "*.dll").Take(MaxEntries).Select(Path.GetFileNameWithoutExtension).OfType<string>().ToList()));
        if (layout.Data != null) assemblies.AddRange(ScriptingAssemblyNames(Path.Combine(layout.Data, "ScriptingAssemblies.json")));
        foreach (var (category, name, prefix) in AssemblySignatures)
        {
            if (markers.Any(m => m.Name == name)) continue;
            var hit = assemblies.FirstOrDefault(a => a.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
            if (hit != null) markers.Add(new MarkerFact(category, name, $"assembly {hit}", "layout"));
        }
        if (layout.Data != null && Directory.Exists(Path.Combine(layout.Data, "StreamingAssets", "aa")) && !markers.Any(m => m.Name == "Addressables"))
            markers.Add(new MarkerFact("build", "Addressables", Path.Combine(layout.Data, "StreamingAssets", "aa"), "layout"));
    }

    private static IEnumerable<string> ScriptingAssemblyNames(string path)
    {
        if (!File.Exists(path)) return [];
        try
        {
            if (new FileInfo(path).Length > 4 << 20) return [];
            using var doc = JsonDocument.Parse(File.ReadAllBytes(path));
            return doc.RootElement.TryGetProperty("names", out var names) && names.ValueKind == JsonValueKind.Array
                ? [.. names.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String).Select(e => Path.GetFileNameWithoutExtension(e.GetString()!))]
                : [];
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException) { return []; }
    }

    /// <summary>Packer section names (the survey_features rule) and code sections empty on disk, from PE headers.</summary>
    private static void SectionMarkers(Layout layout, BackendFacts backend, List<MarkerFact> markers)
    {
        var packer = new Regex(Features.PackerSectionNames, RegexOptions.CultureInvariant);
        foreach (var file in new[] { layout.Exe, layout.UnityPlayer, backend.NativeBinary }.Where(f => f != null).Distinct())
        {
            var head = ReadHead(file!, 4096);
            if (PeImage.TryParse(head) is not { } pe) continue;
            var named = pe.Sections.Where(s => packer.IsMatch(s.Name)).Select(s => s.Name).ToList();
            if (named.Count > 0)
                markers.Add(new MarkerFact("packer", PackerName(named[0]), $"{Path.GetFileName(file)}: section(s) {string.Join(", ", named)}", "pe_sections"));
            var hollow = pe.Sections.Where(s => s.RawSize == 0 && s.VirtualSize > 0x10000 && s.Name is ".text" or "" or ".code").ToList();
            if (hollow.Count > 0)
                markers.Add(new MarkerFact("packer", "code unpacked at run time", $"{Path.GetFileName(file)}: {string.Join(", ", hollow.Select(s => $"'{s.Name}' {s.VirtualSize:N0} bytes in memory, none on disk"))}", "pe_sections"));
        }
    }

    private static string PackerName(string section) => section.ToLowerInvariant() switch
    {
        var s when s.StartsWith("upx") => "UPX",
        var s when s.StartsWith(".vmp") => "VMProtect",
        ".themida" => "Themida",
        var s when s.StartsWith(".enigma") => "Enigma Protector",
        var s when s.StartsWith(".mpress") => "MPRESS",
        ".aspack" or ".adata" => "ASPack",
        _ => $"packer ({section})",
    };

    /// <summary>diec from CORVUS_DIE (the file or its folder) or PATH; null when absent.</summary>
    internal static string? FindDie()
    {
        var name = OperatingSystem.IsWindows() ? "diec.exe" : "diec";
        if (Environment.GetEnvironmentVariable("CORVUS_DIE") is { Length: > 0 } configured)
        {
            if (File.Exists(configured)) return Path.GetFullPath(configured);
            if (Directory.Exists(configured) && File.Exists(Path.Combine(configured, name))) return Path.GetFullPath(Path.Combine(configured, name));
        }
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            try { if (File.Exists(Path.Combine(dir.Trim('"'), name))) return Path.Combine(dir.Trim('"'), name); }
            catch (ArgumentException) { }
        }
        return null;
    }

    private static void DieMarkers(string die, Layout layout, BackendFacts backend, List<MarkerFact> markers, List<string> notes, CancellationToken ct)
    {
        var targets = new[] { layout.Exe, backend.NativeBinary, backend.ManagedDirectory != null ? Path.Combine(backend.ManagedDirectory, "Assembly-CSharp.dll") : null }
            .Where(f => f != null && File.Exists(f)).Distinct().ToList();
        foreach (var target in targets)
        {
            ct.ThrowIfCancellationRequested();
            var run = PythonLocator.RunCapture(die, ["-j", target!], DieTimeout);
            if (run.StartError != null || run.TimedOut)
            {
                notes.Add($"Detect It Easy on {Path.GetFileName(target)}: {(run.TimedOut ? $"no answer in {DieTimeout.TotalSeconds:0} s" : run.StartError)}.");
                continue;
            }
            try
            {
                using var doc = JsonDocument.Parse(run.Stdout);
                foreach (var detect in doc.RootElement.GetProperty("detects").EnumerateArray())
                    foreach (var value in detect.TryGetProperty("values", out var values) ? values.EnumerateArray() : default)
                    {
                        var type = value.TryGetProperty("type", out var t) ? t.GetString() ?? "" : "";
                        var text = value.TryGetProperty("string", out var s) ? s.GetString() ?? "" : "";
                        if (text.Length == 0) continue;
                        var category = type.ToLowerInvariant() switch
                        {
                            "packer" => "packer",
                            "protector" or "protection" => "packer",
                            "obfuscator" or "(heur)obfuscator" => "obfuscator",
                            "cryptor" => "encryption",
                            _ => "toolchain",
                        };
                        markers.Add(new MarkerFact(category, text, Path.GetFileName(target)!, "detect_it_easy"));
                    }
            }
            catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException)
            {
                notes.Add($"Detect It Easy on {Path.GetFileName(target)}: unreadable output ({ex.Message}).");
            }
        }
    }

    private static (string Arch, string? Source) Architecture(Layout layout, BackendFacts backend)
    {
        foreach (var file in new[] { layout.Exe, layout.UnityPlayer, backend.NativeBinary }.Where(f => f != null))
        {
            var head = ReadHead(file!, 4096);
            if (PeImage.TryParse(head) is { } pe)
                return (pe.Machine switch { 0x8664 => "x64", 0x14c => "x86", 0xaa64 => "arm64", 0x1c4 => "arm", _ => "unknown" }, file);
            if (head.Length >= 20 && head[0] == 0x7F && head[1] == 'E' && head[2] == 'L' && head[3] == 'F')
                return (BinaryPrimitives.ReadUInt16LittleEndian(head.AsSpan(18)) switch { 0x3E => "x64", 0x03 => "x86", 0xB7 => "arm64", 0x28 => "arm", _ => "unknown" }, file);
            if (MachOArchitecture(head) is { } macho) return (macho, file);
        }
        if (layout.Platform == "android")
            foreach (var abi in SafeList(() => Directory.EnumerateDirectories(Path.Combine(layout.Game, "lib")).Select(Path.GetFileName).OfType<string>().ToList()))
                if (abi switch { "arm64-v8a" => "arm64", "armeabi-v7a" => "arm", "x86_64" => "x64", "x86" => "x86", _ => null } is { } a)
                    return (a, Path.Combine(layout.Game, "lib", abi));
        return ("unknown", null);
    }

    /// <summary>The CPU of a thin Mach-O, or "universal (x64, arm64)" for a fat one; null when not Mach-O.</summary>
    internal static string? MachOArchitecture(byte[] head)
    {
        static string Cpu(uint type) => type switch { 0x01000007 => "x64", 7 => "x86", 0x0100000C => "arm64", 12 => "arm", _ => "unknown" };
        if (head.Length < 8) return null;
        if (BinaryPrimitives.ReadUInt32LittleEndian(head) is 0xFEEDFACF or 0xFEEDFACE) return Cpu(BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(4)));
        uint magic = BinaryPrimitives.ReadUInt32BigEndian(head), count = BinaryPrimitives.ReadUInt32BigEndian(head.AsSpan(4));
        if (magic is not (0xCAFEBABE or 0xCAFEBABF) || count is 0 or > 16) return null; // a Java class file shares 0xCAFEBABE with a large count
        int stride = magic == 0xCAFEBABF ? 32 : 20;
        var cpus = Enumerable.Range(0, (int)count).Where(i => 8 + i * stride + 4 <= head.Length)
            .Select(i => Cpu(BinaryPrimitives.ReadUInt32BigEndian(head.AsSpan(8 + i * stride))));
        return $"universal ({string.Join(", ", cpus)})";
    }

    private static List<FolderFact> Folders(Layout layout, CancellationToken ct)
    {
        var list = new List<FolderFact>();
        void Add(string kind, string path, string? note = null)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(path)) return;
            list.Add(new FolderFact(kind, path, SafeList(() => Directory.EnumerateFileSystemEntries(path).Take(MaxEntries).ToList()).Count, note));
        }
        if (layout.Data is { } data)
        {
            Add("managed", Path.Combine(data, "Managed"));
            Add("il2cpp_data", Path.Combine(data, "il2cpp_data"));
            Add("streaming_assets", Path.Combine(data, "StreamingAssets"));
            var aa = Path.Combine(data, "StreamingAssets", "aa");
            if (Directory.Exists(aa))
            {
                var catalogs = SafeList(() => Directory.EnumerateFiles(aa, "catalog*").Take(8).Select(Path.GetFileName).ToList()!);
                Add("addressables", aa, catalogs.Count > 0 ? $"catalog: {string.Join(", ", catalogs)}" : "no catalog file at the top level");
            }
            Add("plugins", Path.Combine(data, "Plugins"));
        }
        Add("mono_runtime", Path.Combine(layout.Game, "MonoBleedingEdge"));
        Add("mono_runtime", Path.Combine(layout.Game, "Mono"));
        Add("mod_loader", Path.Combine(layout.Game, "BepInEx"));
        Add("mod_loader", Path.Combine(layout.Game, "MelonLoader"));
        Add("other", Path.Combine(layout.Game, "Mods"));
        return list;
    }

    private static (string? Company, string? Product) AppInfo(string? data)
    {
        if (data == null) return (null, null);
        var path = Path.Combine(data, "app.info");
        if (!File.Exists(path)) return (null, null);
        var lines = Encoding.UTF8.GetString(ReadHead(path, 1024)).Split('\n', StringSplitOptions.TrimEntries);
        return (lines.Length > 0 && lines[0].Length > 0 ? lines[0] : null, lines.Length > 1 && lines[1].Length > 0 ? lines[1] : null);
    }

    private static List<NextStep> NextSteps(Layout layout, BackendFacts backend, List<MarkerFact> markers)
    {
        var steps = new List<NextStep>();
        var process = layout.Exe != null ? Path.GetFileName(layout.Exe) : "<the game's process>";
        Dictionary<string, string> Args(params (string Key, string Value)[] args) => args.ToDictionary(a => a.Key, a => a.Value);
        bool protectedBinary = markers.Any(m => m.Category == "packer" && backend.NativeBinary != null && m.Evidence.StartsWith(Path.GetFileName(backend.NativeBinary), StringComparison.OrdinalIgnoreCase));
        switch (backend.Kind)
        {
            case "mono" when backend.ManagedState == "encrypted":
                steps.Add(new NextStep("dump_from_memory", null, Args(("process", process)),
                    "Assembly-CSharp.dll is not a readable .NET image on disk (encrypted); the runtime decrypts it when loading. Dump the loaded image from the " +
                    "running game (a memory dumper hooking mono_image_open_from_data), then load_assembly the dump with the Managed folder beside it."));
                steps.Add(new NextStep("inspect_process", "inspect_process", Args(("process", process), ("sections", "modules")),
                    "Read-only view of the running game: confirms the Mono runtime module and where it is loaded."));
                break;
            case "mono" when backend.ManagedDirectory != null:
                var obfuscated = markers.Where(m => m.Category == "obfuscator").Select(m => m.Name).ToList();
                steps.Add(new NextStep("load_assembly", "load_assembly", Args(("path", backend.ManagedDirectory)),
                    "Mono build: the game's C# is IL in the Managed folder; loading it decompiles directly" +
                    (obfuscated.Count > 0 ? $" (names obfuscated: {string.Join(", ", obfuscated)}; rename_symbol as you go)." : ".")));
                steps.Add(new NextStep("list_namespaces", "list_namespaces", Args(("assembly", "Assembly-CSharp")), "The game's own code is in Assembly-CSharp (and Assembly-CSharp-firstpass)."));
                break;
            case "il2cpp" when backend.MetadataState == "readable" && backend.NativeBinary != null && !protectedBinary:
                steps.Add(new NextStep("load_assembly", "load_assembly", Args(("path", backend.Metadata!)),
                    $"Il2Cpp build with readable metadata v{backend.MetadataVersion}: the built-in reader builds dummy assemblies (addresses, field offsets, string literals) and loads {Path.GetFileName(backend.NativeBinary)} as a native image."));
                steps.Add(new NextStep("apply_il2cpp_names", "apply_il2cpp_names", Args(("image", backend.NativeBinary)),
                    $"Names {Path.GetFileName(backend.NativeBinary)}'s functions after the C# methods for the native tools (disassemble, find_xrefs, decompile_native)."));
                break;
            case "il2cpp" when backend.MetadataState == "readable" && backend.NativeBinary != null && protectedBinary:
                steps.Add(new NextStep("dump_from_memory", null, Args(("process", process), ("module", Path.GetFileName(backend.NativeBinary))),
                    "GameAssembly.dll is packed or protected on disk (see markers): dump it from the running game, put the dump beside the metadata as GameAssembly.dll, then load_assembly the metadata."));
                steps.Add(new NextStep("load_assembly", "load_assembly", Args(("path", backend.Metadata!)),
                    "After the dump: the built-in reader takes a memory dump of GameAssembly.dll too."));
                break;
            case "il2cpp" when backend.MetadataState is "readable" or "unsupported_version":
                steps.Add(new NextStep("use_external_dumper", null, Args(("metadata", backend.Metadata!), ("binary", backend.NativeBinary ?? "")),
                    backend.MetadataState == "readable"
                        ? "The game binary was not found beside the metadata: put it there (GameAssembly, libil2cpp.so or UnityFramework), or run Il2CppDumper or Cpp2IL and load_assembly its DummyDll folder."
                        : $"Metadata version {backend.MetadataVersion} is outside the built-in reader's 24-39: run Il2CppDumper or Cpp2IL, then load_assembly its DummyDll folder."));
                break;
            case "il2cpp" when backend.MetadataState is "encrypted" or "header_tampered":
                steps.Add(new NextStep("dump_from_memory", null, Args(("process", process), ("magic", "AF 1B B1 FA")),
                    $"Metadata {backend.MetadataState} ({backend.MetadataStateReason}). The running game holds it decrypted: dump the block starting with AF 1B B1 FA " +
                    "(the metadata magic, followed by a version 24-39) from its memory, save it as global-metadata.dat beside GameAssembly.dll, then load_assembly that file."));
                steps.Add(new NextStep("inspect_process", "inspect_process", Args(("process", process), ("sections", "regions"), ("regionFilter", "private")),
                    "Read-only view of the running game's private memory regions: the decrypted metadata is in one of them (tens of MB)."));
                break;
            case "il2cpp" when backend.MetadataState == "missing" && backend.NativeBinary != null:
                steps.Add(new NextStep("search_bytes", "search_bytes", Args(("image", backend.NativeBinary), ("pattern", "AF 1B B1 FA")),
                    "No global-metadata.dat: look for the metadata magic inside the binary (embedded metadata); otherwise dump it from the running game's memory."));
                break;
            case "il2cpp" when backend.MetadataState == "truncated":
                steps.Add(new NextStep("dump_from_memory", null, Args(("process", process)), $"The metadata file is truncated ({backend.MetadataStateReason}): reinstall or dump it from the running game."));
                break;
            default:
                if (layout.Exe != null)
                    steps.Add(new NextStep("summarize_file", "summarize_file", Args(("path", layout.Exe)), "Backend unknown: summarize the executable."));
                break;
        }
        return steps;
    }

    /// <summary>Up to <paramref name="count"/> bytes from the start of a file; empty when unreadable.</summary>
    internal static byte[] ReadHead(string path, int count)
    {
        try
        {
            using var f = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var buffer = new byte[(int)Math.Min(count, RandomAccess.GetLength(f))];
            int read = RandomAccess.Read(f, buffer, 0);
            return read == buffer.Length ? buffer : buffer[..read];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; }
    }

    private static string? CString(byte[] data, int at)
    {
        if (at < 0 || at >= data.Length) return null;
        int end = Array.IndexOf(data, (byte)0, at);
        if (end < 0 || end - at > 128) return null;
        var s = Encoding.ASCII.GetString(data, at, end - at);
        return s.All(c => c >= 0x20 && c < 0x7F) ? s : null;
    }

    private static bool IsElf(string path) => ReadHead(path, 4) is [0x7F, (byte)'E', (byte)'L', (byte)'F'];

    private static string? FirstExisting(IEnumerable<string> paths) => paths.FirstOrDefault(File.Exists);

    private static List<T> SafeList<T>(Func<List<T>> f)
    {
        try { return f(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { return []; }
    }
}
