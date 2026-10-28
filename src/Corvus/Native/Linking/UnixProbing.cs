using System.Text.Json;

namespace Corvus.Native.Linking;

/// <summary>The platform P/Invoke declarations bind on: OS (windows, linux, osx, android, ios), runtime identifier when known, and its source.</summary>
public sealed record TargetPlatform(string Os, string? Rid, string Source)
{
    public bool IsWindows => Os == "windows";
    public bool IsApple => Os is "osx" or "ios";

    /// <summary>The library suffix of the platform.</summary>
    public string Suffix => IsWindows ? ".dll" : IsApple ? ".dylib" : ".so";

    /// <summary>The architecture the runtime identifier names, or null.</summary>
    public NativeArch? Arch => (Rid?.Split('-') is { Length: > 1 } parts ? parts[^1] : null) switch
    {
        "x64" => NativeArch.X64,
        "x86" => NativeArch.X86,
        "arm64" => NativeArch.Arm64,
        "arm" => NativeArch.Arm,
        _ => null,
    };

    /// <summary>The runtime identifier fallback chain, most specific first (android-arm64, android, linux-arm64, linux, unix).</summary>
    public IReadOnlyList<string> RidChain
    {
        get
        {
            var chain = new List<string>();
            var arch = Rid?.Split('-') is { Length: > 1 } parts ? parts[^1] : null;
            void Add(string os)
            {
                if (arch != null) chain.Add($"{os}-{arch}");
                chain.Add(os);
            }
            if (Rid != null && !Rid.StartsWith(Os, StringComparison.Ordinal)) chain.Add(Rid); // linux-musl-x64 and similar
            Add(Os);
            if (Os == "android") Add("linux");
            if (Os == "ios") Add("osx");
            if (!IsWindows) chain.Add("unix");
            return [.. chain.Distinct()];
        }
    }
}

/// <summary>P/Invoke library probing off Windows: target platform, probing names and folders, and libraries shipped only for another platform.</summary>
public static class UnixProbing
{
    public static readonly string[] Platforms = ["auto", "windows", "linux", "osx", "android", "ios"];

    /// <summary>The target platform: <paramref name="requested"/>, else <paramref name="hint"/>, else deps.json, runtimes folders, libraries beside the app, then windows.</summary>
    public static TargetPlatform Detect(string appDirectory, string? requested, TargetPlatform? hint = null)
    {
        var deps = DepsRids(appDirectory);
        var folders = RuntimeFolders(appDirectory).Select(r => r.Rid).ToList();
        string? RidFor(string os) => deps.Concat(folders).FirstOrDefault(r => r == os || r.StartsWith(os + "-", StringComparison.Ordinal));
        if (requested is { Length: > 0 } r0 && !r0.Equals("auto", StringComparison.OrdinalIgnoreCase))
        {
            var os = r0.Trim().ToLowerInvariant() is "macos" ? "osx" : r0.Trim().ToLowerInvariant();
            if (!Platforms.Contains(os)) throw new Core.ToolError(Core.ErrorCode.InvalidArgument, $"Unknown platform '{requested}'.", $"use one of {string.Join(", ", Platforms)}");
            return new TargetPlatform(os, hint?.Os == os ? hint.Rid : RidFor(os), "requested");
        }
        if (hint != null) return hint;
        if (DepsRuntimeTarget(appDirectory) is { } target) return new TargetPlatform(OsOf(target), target, "deps.json runtime target");
        var oses = deps.Concat(folders).Select(OsOf).Distinct().ToList();
        if (oses.Count == 1) return new TargetPlatform(oses[0], deps.Concat(folders).FirstOrDefault(x => x.Contains('-', StringComparison.Ordinal)), "runtimes/<rid> of the app");
        var beside = Files(appDirectory);
        if (beside.Any(f => f.EndsWith(".dylib", StringComparison.OrdinalIgnoreCase))) return new TargetPlatform("osx", null, "native libraries beside the app");
        if (beside.Any(f => f.EndsWith(".so", StringComparison.OrdinalIgnoreCase) || f.Contains(".so.", StringComparison.OrdinalIgnoreCase)))
            return new TargetPlatform("linux", null, "native libraries beside the app");
        return new TargetPlatform("windows", RidFor("win"), oses.Count > 1 ? $"default (the app ships for {string.Join(", ", oses)})" : "default");
    }

    private static string OsOf(string rid)
    {
        var os = rid.Split('-')[0].ToLowerInvariant();
        return os switch
        {
            "win" => "windows",
            "osx" or "maccatalyst" => "osx",
            "ios" or "iossimulator" or "tvos" => "ios",
            "android" => "android",
            _ => "linux",
        };
    }

    /// <summary>The names .NET tries for <paramref name="module"/> on <paramref name="platform"/>, in order.</summary>
    public static IReadOnlyList<string> ProbeNames(string module, TargetPlatform platform)
    {
        var name = module.Trim();
        var suffix = platform.Suffix;
        bool hasSuffix = name.EndsWith(suffix, StringComparison.Ordinal) || (!platform.IsApple && name.Contains(".so.", StringComparison.Ordinal));
        bool hasPrefix = name.StartsWith("lib", StringComparison.Ordinal) || name.Contains('/', StringComparison.Ordinal);
        var names = new List<string>();
        if (hasSuffix) names.Add(name);
        if (!hasSuffix && !hasPrefix) names.Add("lib" + name + suffix);
        if (!hasSuffix) names.Add(name + suffix);
        if (!hasPrefix) names.Add("lib" + name);
        names.Add(name);
        return [.. names.Distinct(StringComparer.Ordinal)];
    }

    /// <summary>The library file for <paramref name="module"/> (null when not found), the folders searched, and matches shipped only for other platforms.</summary>
    public static (string? File, List<string> Searched, List<string> OtherPlatforms) Locate(string module, string appDirectory, TargetPlatform platform, IEnumerable<string>? extraFolders = null)
    {
        var searched = new List<string>();
        var names = ProbeNames(module, platform);
        if (Path.IsPathFullyQualified(module.Trim()))
        {
            if (Core.InputFiles.NamedProblem(module.Trim()) is { } why)
            {
                searched.Add($"{module.Trim()} ({why})");
                return (null, searched, []);
            }
            searched.Add(module.Trim());
            return (File.Exists(module.Trim()) ? module.Trim() : null, searched, []);
        }
        var folders = new List<string> { appDirectory };
        folders.AddRange(platform.RidChain.Select(r => Path.Combine(appDirectory, "runtimes", r, "native")));
        if (extraFolders != null) folders.AddRange(extraFolders);
        foreach (var folder in folders.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(folder)) continue;
            searched.Add(folder);
            foreach (var name in names)
            {
                var candidate = Path.Combine(folder, name);
                if (!Core.InputFiles.StaysUnder(name) && Core.InputFiles.NamedProblem(candidate) is { } why)
                {
                    searched.Add($"{candidate} ({why})");
                    continue;
                }
                if (File.Exists(candidate)) return (candidate, searched, []);
            }
        }
        // Shipped for another platform only: the same base name with any library suffix under runtimes/<other rid>/native.
        var bare = Path.GetFileNameWithoutExtension(names[^1]);
        var other = RuntimeFolders(appDirectory).Where(r => !platform.RidChain.Contains(r.Rid))
            .SelectMany(r => Files(r.Folder).Where(f => BaseName(f).Equals(bare, StringComparison.OrdinalIgnoreCase) || BaseName(f).Equals("lib" + bare, StringComparison.OrdinalIgnoreCase))
                .Select(f => $"runtimes/{r.Rid}/native/{Path.GetFileName(f)}")).ToList();
        return (null, searched, other);
    }

    private static string BaseName(string file)
    {
        var name = Path.GetFileName(file);
        int so = name.IndexOf(".so", StringComparison.Ordinal);
        if (so > 0 && (so + 3 == name.Length || name[so + 3] == '.')) return name[..so];
        return Path.GetFileNameWithoutExtension(name);
    }

    /// <summary>Libraries every Unix system has, which apps do not ship.</summary>
    private static readonly HashSet<string> SystemLibraries = new(StringComparer.Ordinal)
    {
        "c", "dl", "m", "pthread", "rt", "util", "stdc++", "c++", "c++_shared", "gcc_s", "z", "log", "android", "GLESv2", "GLESv3", "EGL", "OpenSLES", "jnigraphics",
        "mediandk", "vulkan", "System", "System.B", "objc", "icucore", "X11", "GL", "ssl", "crypto", "gssapi_krb5",
    };

    /// <summary>Whether <paramref name="module"/> names a library of the operating system (libc, libdl, liblog, libSystem, a framework, /usr/lib).</summary>
    public static bool IsSystemLibrary(string module)
    {
        var name = module.Trim();
        if (name.StartsWith("/usr/lib/", StringComparison.Ordinal) || name.StartsWith("/System/", StringComparison.Ordinal) || name.StartsWith("/lib", StringComparison.Ordinal)) return true;
        name = Path.GetFileName(name);
        if (name.StartsWith("lib", StringComparison.Ordinal)) name = name[3..];
        int dot = name.IndexOf(".so", StringComparison.Ordinal);
        if (dot > 0) name = name[..dot];
        if (name.EndsWith(".dylib", StringComparison.Ordinal)) name = name[..^6];
        return SystemLibraries.Contains(name);
    }

    /// <summary>The runtimes/&lt;rid&gt;/native folders of an app.</summary>
    private static List<(string Rid, string Folder)> RuntimeFolders(string appDirectory)
    {
        var runtimes = Path.Combine(appDirectory, "runtimes");
        try
        {
            return !Directory.Exists(runtimes) ? []
                : [.. Directory.EnumerateDirectories(runtimes).Select(d => (Rid: Path.GetFileName(d), Folder: Path.Combine(d, "native"))).Where(x => Directory.Exists(x.Folder))];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; }
    }

    private static List<string> Files(string folder)
    {
        try { return Directory.Exists(folder) ? [.. Directory.EnumerateFiles(folder)] : []; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; }
    }

    private static IEnumerable<JsonDocument> DepsFiles(string appDirectory)
    {
        foreach (var file in Files(appDirectory).Where(f => f.EndsWith(".deps.json", StringComparison.OrdinalIgnoreCase)).Take(4))
        {
            JsonDocument? doc = null;
            try
            {
                if (new FileInfo(file).Length <= 16 << 20) doc = JsonDocument.Parse(File.ReadAllBytes(file));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException) { }
            if (doc != null) yield return doc;
        }
    }

    /// <summary>The RID a self-contained or RID-specific app was built for (deps.json runtimeTarget name ".NETCoreApp,Version=v8.0/linux-x64").</summary>
    private static string? DepsRuntimeTarget(string appDirectory)
    {
        foreach (var doc in DepsFiles(appDirectory))
            using (doc)
                if (doc.RootElement.TryGetProperty("runtimeTarget", out var target) && target.TryGetProperty("name", out var name)
                    && name.GetString() is { } text && text.LastIndexOf('/') is var slash and > 0)
                    return text[(slash + 1)..];
        return null;
    }

    /// <summary>The RIDs a portable app's deps.json lists native assets for (runtimeTargets "runtimes/&lt;rid&gt;/native/...").</summary>
    private static List<string> DepsRids(string appDirectory)
    {
        var rids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var doc in DepsFiles(appDirectory))
            using (doc)
            {
                if (!doc.RootElement.TryGetProperty("targets", out var targets) || targets.ValueKind != JsonValueKind.Object) continue;
                foreach (var framework in targets.EnumerateObject())
                    foreach (var library in framework.Value.EnumerateObject())
                        if (library.Value.ValueKind == JsonValueKind.Object && library.Value.TryGetProperty("runtimeTargets", out var assets) && assets.ValueKind == JsonValueKind.Object)
                            foreach (var asset in assets.EnumerateObject())
                                if (asset.Value.TryGetProperty("assetType", out var type) && type.GetString() == "native"
                                    && asset.Value.TryGetProperty("rid", out var rid) && rid.GetString() is { } r)
                                    rids.Add(r);
            }
        return [.. rids.Order(StringComparer.Ordinal)];
    }
}
