using System.Runtime.CompilerServices;
using dnlib.DotNet;

namespace Corvus.Core;

/// <summary>
/// Locates installed .NET shared frameworks, reference packs, NuGet packages, .NET Framework 4 and Windows Runtime
/// metadata so references resolve against the framework version the requester targets, not the newest installed.
/// </summary>
internal static class Frameworks
{
    public sealed record Shared(string Name, Version Version, string Dir);

    private static readonly string[] SharedNames = ["Microsoft.NETCore.App", "Microsoft.WindowsDesktop.App", "Microsoft.AspNetCore.App"];

    /// <summary>Existing dotnet roots: DOTNET_ROOT, then default install locations.</summary>
    private static readonly Lazy<IReadOnlyList<string>> DotnetRoots = new(() => new[]
        {
            Environment.GetEnvironmentVariable("DOTNET_ROOT"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".dotnet"),
            "/usr/share/dotnet", "/usr/lib/dotnet", "/usr/local/share/dotnet", "/opt/homebrew/opt/dotnet/libexec",
        }.Where(r => !string.IsNullOrEmpty(r) && Directory.Exists(r)).Select(r => r!).Distinct(StringComparer.OrdinalIgnoreCase).ToList());

    /// <summary>NuGet global packages folder (NUGET_PACKAGES, else ~/.nuget/packages), if it exists.</summary>
    private static readonly Lazy<string?> NuGetRoot = new(() =>
    {
        var dir = Environment.GetEnvironmentVariable("NUGET_PACKAGES");
        if (string.IsNullOrEmpty(dir)) dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".nuget", "packages");
        return Directory.Exists(dir) ? dir : null;
    });

    /// <summary>Installed shared framework versions, newest first within each framework.</summary>
    public static readonly Lazy<IReadOnlyList<Shared>> All = new(() =>
    {
        var roots = DotnetRoots.Value;
        var list = new List<Shared>();
        foreach (var name in SharedNames)
            foreach (var root in roots)
            {
                var shared = Path.Combine(root!, "shared", name);
                if (!Directory.Exists(shared)) continue;
                try
                {
                    list.AddRange(Directory.EnumerateDirectories(shared)
                        .Select(d => (Dir: d, Version: Version.TryParse(Path.GetFileName(d).Split('-')[0], out var v) ? v : null))
                        .Where(x => x.Version != null)
                        .Select(x => new Shared(name, x.Version!, x.Dir)));
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
                break; // first root containing this framework wins
            }
        return list.OrderBy(s => Array.IndexOf(SharedNames, s.Name)).ThenByDescending(s => s.Version).ToList();
    });

    /// <summary>.NET Framework 4 directory and its WPF subfolder, if present (Windows only).</summary>
    public static readonly Lazy<IReadOnlyList<string>> NetFramework = new(() =>
    {
        var windir = Environment.GetEnvironmentVariable("WINDIR");
        if (string.IsNullOrEmpty(windir)) return [];
        var dirs = new List<string>();
        foreach (var bitness in new[] { "Framework64", "Framework" })
        {
            var dir = Path.Combine(windir, "Microsoft.NET", bitness, "v4.0.30319");
            if (!File.Exists(Path.Combine(dir, "mscorlib.dll"))) continue;
            dirs.Add(dir);
            if (Directory.Exists(Path.Combine(dir, "WPF"))) dirs.Add(Path.Combine(dir, "WPF"));
            break;
        }
        return dirs;
    });

    /// <summary>The current process's runtime directory; last resort when no shared framework is installed.</summary>
    private static readonly Lazy<string?> RuntimeDir = new(() =>
    {
        var dir = System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory();
        return !string.IsNullOrEmpty(dir) && File.Exists(Path.Combine(dir, "System.Runtime.dll")) ? dir : null;
    });

    /// <summary>
    /// Framework directories for a reference of <paramref name="version"/>. For 5.0+: the same major per shared
    /// framework, else its reference pack, else the nearest newer major. Otherwise the newest. .NET Framework
    /// requesters search the .NET Framework directory first.
    /// </summary>
    public static IEnumerable<string> DirectoriesFor(Version? version, bool netFramework)
    {
        var result = new List<string>();
        if (netFramework) result.AddRange(NetFramework.Value);
        foreach (var group in All.Value.GroupBy(s => s.Name))
        {
            var versions = group.ToList();
            Shared? pick = null;
            if (version is { Major: >= 5 } && !IsWildcard(version))
            {
                pick = versions.FirstOrDefault(s => s.Version.Major == version.Major);
                // Major not installed: its reference pack has the exact API and precedes a newer runtime.
                if (pick == null && ReferencePackDir(group.Key, version.Major) is { } pack) result.Add(pack);
                pick ??= versions.Where(s => s.Version.Major > version.Major).OrderBy(s => s.Version).FirstOrDefault();
            }
            pick ??= versions.FirstOrDefault();
            if (pick != null) result.Add(pick.Dir);
        }
        if (RuntimeDir.Value is { } runtime) result.Add(runtime);
        if (!netFramework) result.AddRange(NetFramework.Value); // last resort for .NET Framework-only assemblies
        return result.Distinct(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Targeting-pack directory for a shared framework major, from dotnet packs, the NuGet cache or the download cache
    /// (<c>packs/Microsoft.NETCore.App.Ref/6.0.x/ref/net6.0</c>); downloaded when none has it.
    /// </summary>
    public static string? ReferencePackDir(string framework, int major) =>
        InstalledReferencePackDir(framework, major) ?? ReferencePacks.Get(framework + ".Ref", major);

    private static string? InstalledReferencePackDir(string framework, int major)
    {
        var id = framework + ".Ref";
        var candidates = DotnetRoots.Value.Select(r => Path.Combine(r, "packs", id))
            .Concat(NuGetRoot.Value is { } nuget ? [Path.Combine(nuget, id.ToLowerInvariant())] : []);
        foreach (var packs in candidates)
        {
            if (!Directory.Exists(packs)) continue;
            try
            {
                var best = Directory.EnumerateDirectories(packs)
                    .Select(d => (Dir: d, Version: Version.TryParse(Path.GetFileName(d).Split('-')[0], out var v) ? v : null))
                    .Where(x => x.Version?.Major == major).OrderByDescending(x => x.Version)
                    .Select(x => Path.Combine(x.Dir, "ref", $"net{major}.0")).FirstOrDefault(Directory.Exists);
                if (best != null) return best;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        return null;
    }

    /// <summary>
    /// netstandard.dll reference assembly: 2.1 from the NETStandard.Library.Ref pack, 2.0 from the NETStandard.Library
    /// package. Preferred over runtime facades because it exposes the exact API.
    /// </summary>
    public static string? NetStandardFile(Version? version)
    {
        if (version is not { Major: 2 }) return null;
        if (version.Minor >= 1)
        {
            foreach (var root in DotnetRoots.Value)
                if (FirstExisting(Path.Combine(root, "packs", "NETStandard.Library.Ref"), d => Path.Combine(d, "ref", "netstandard2.1", "netstandard.dll")) is { } f)
                    return f;
            return NuGetRoot.Value is { } n ? FirstExisting(Path.Combine(n, "netstandard.library.ref"), d => Path.Combine(d, "ref", "netstandard2.1", "netstandard.dll")) : null;
        }
        return NuGetRoot.Value is { } nuget
            ? FirstExisting(Path.Combine(nuget, "netstandard.library"), d => Path.Combine(d, "build", "netstandard2.0", "ref", "netstandard.dll"))
            : null;
    }

    /// <summary>
    /// The facade of <paramref name="name"/> beside netstandard.dll (System.Runtime.InteropServices forwarding to
    /// netstandard) for a .NET Standard 2.x requester; null for other requesters or names outside the standard.
    /// </summary>
    public static string? NetStandardFacade(string name, string? requesterFramework)
    {
        if (name.Equals("netstandard", StringComparison.OrdinalIgnoreCase)
            || requesterFramework?.Split(",Version=v", 2) is not [var id, var ver]
            || !id.Equals(".NETStandard", StringComparison.OrdinalIgnoreCase) || !Version.TryParse(ver, out var v)
            || NetStandardFile(v) is not { } standard)
            return null;
        var facade = Path.Combine(Path.GetDirectoryName(standard)!, name + ".dll");
        return File.Exists(facade) ? facade : null;
    }

    /// <summary>The <paramref name="file"/> path in the newest version subfolder of <paramref name="dir"/> where it exists.</summary>
    private static string? FirstExisting(string dir, Func<string, string> file)
    {
        if (!Directory.Exists(dir)) return null;
        try
        {
            return Directory.EnumerateDirectories(dir)
                .OrderByDescending(d => Version.TryParse(Path.GetFileName(d).Split('-')[0], out var v) ? v : new Version(0, 0))
                .Select(file).FirstOrDefault(File.Exists);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    private static readonly string[] ModernTfms =
        ["net10.0", "net9.0", "net8.0", "net7.0", "net6.0", "net5.0", "netcoreapp3.1", "netcoreapp3.0", "netstandard2.1", "netstandard2.0",
         "netcoreapp2.1", "netstandard1.6", "netstandard1.3", "netstandard1.1", "netstandard1.0"];
    private static readonly string[] FrameworkTfms =
        ["net48", "net472", "net471", "net47", "net462", "net461", "net46", "net452", "net451", "net45", "net40", "netstandard2.0", "netstandard1.3", "net35", "net20"];

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, List<(string File, Version? Version, int Rank)>> NuGetIndex = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>The library of package <paramref name="name"/> (newest version) for a .NET Framework target: its best lib folder not newer than the target.</summary>
    public static string? NetFrameworkPackageFile(string name, string? framework)
    {
        if (NuGetRoot.Value is not { } root || name.Length == 0 || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) return null;
        int from = ShortName(framework) is { } target ? Array.IndexOf(FrameworkTfms, target) : -1;
        var tfms = from < 0 ? FrameworkTfms : FrameworkTfms[from..];
        return FirstExisting(Path.Combine(root, name.ToLowerInvariant()), d => tfms.Select(t => Path.Combine(d, "lib", t, name + ".dll")).FirstOrDefault(File.Exists) ?? "");
    }

    /// <summary>
    /// Assembly from the NuGet package of the same name, using the best compatible lib/TFM folder. Version preference:
    /// exact, lowest same-major at or above it, newest same-major, newest.
    /// </summary>
    public static string? NuGetFile(string name, Version? version, bool netFramework, string? requesterFramework = null)
    {
        if (NuGetRoot.Value is not { } root || name.Length == 0 || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) return null;
        var tfms = netFramework ? FrameworkTfms : CompatibleTfms(requesterFramework);
        var files = NuGetIndex.GetOrAdd(string.Join(",", tfms.Take(1)) + ":" + name, _ =>
        {
            var list = new List<(string, Version?, int)>();
            var package = Path.Combine(root, name.ToLowerInvariant());
            if (!Directory.Exists(package)) return list;
            try
            {
                foreach (var dir in Directory.EnumerateDirectories(package))
                    for (int rank = 0; rank < tfms.Length; rank++)
                    {
                        var file = Path.Combine(dir, "lib", tfms[rank], name + ".dll");
                        if (!File.Exists(file)) continue;
                        Version? v = null;
                        try { v = System.Reflection.AssemblyName.GetAssemblyName(file).Version; } catch { }
                        list.Add((file, v, rank));
                        break; // best TFM folder for this package version
                    }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            return list;
        });
        if (files.Count == 0) return null;
        var ordered = files.OrderBy(f => f.Rank).ThenByDescending(f => f.Version).ToList();
        if (version == null || IsWildcard(version)) return ordered[0].File;
        return ordered.FirstOrDefault(f => f.Version == version).File
               ?? files.Where(f => f.Version?.Major == version.Major && f.Version >= version).OrderBy(f => f.Version).ThenBy(f => f.Rank).Select(f => f.File).FirstOrDefault()
               ?? files.Where(f => f.Version?.Major == version.Major).OrderByDescending(f => f.Version).ThenBy(f => f.Rank).Select(f => f.File).FirstOrDefault()
               ?? ordered[0].File;
    }

    /// <summary>Existing Windows Kits 10 roots.</summary>
    private static readonly Lazy<IReadOnlyList<string>> WindowsKits = new(() =>
    {
        if (!OperatingSystem.IsWindows()) return [];
        return new[] { Environment.SpecialFolder.ProgramFilesX86, Environment.SpecialFolder.ProgramFiles }
            .Select(f => Path.Combine(Environment.GetFolderPath(f), "Windows Kits", "10"))
            .Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    });

    /// <summary>
    /// .winmd for a Windows Runtime API contract or <c>Windows</c>: the contract's own file (exact version, else newest),
    /// else the SDK union metadata <c>Windows.winmd</c>, which contains every Windows Runtime type.
    /// </summary>
    public static string? WindowsMetadataFile(string name, Version? version)
    {
        bool contract = name.StartsWith("Windows.", StringComparison.Ordinal) && name.EndsWith("Contract", StringComparison.Ordinal);
        if (!contract && name != "Windows") return null;
        foreach (var kit in WindowsKits.Value)
        {
            if (contract)
            {
                var sdks = SubDirectories(Path.Combine(kit, "References")).OrderByDescending(d => ParseVersion(Path.GetFileName(d))).ToList();
                var files = sdks.Select(sdk => Path.Combine(sdk, name)).Where(Directory.Exists)
                    .SelectMany(SubDirectories).Select(d => (File: Path.Combine(d, name + ".winmd"), Version: ParseVersion(Path.GetFileName(d))))
                    .Where(x => File.Exists(x.File)).ToList();
                var match = files.FirstOrDefault(x => version != null && x.Version == version).File
                            ?? files.OrderByDescending(x => x.Version).Select(x => x.File).FirstOrDefault();
                if (match != null) return match;
            }
            var union = SubDirectories(Path.Combine(kit, "UnionMetadata")).OrderByDescending(d => ParseVersion(Path.GetFileName(d)))
                .Select(d => Path.Combine(d, "Windows.winmd")).FirstOrDefault(File.Exists);
            if (union != null) return union;
        }
        return null;
    }

    private static readonly Lazy<IReadOnlyDictionary<string, string>> PackageMetadata = new(() =>
    {
        var map = new Dictionary<string, (string File, DateTime Written)>(StringComparer.OrdinalIgnoreCase);
        if (!OperatingSystem.IsWindows()) return new Dictionary<string, string>();
        foreach (var package in InstalledPackageFolders())
        {
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(package, "*.winmd").ToList(); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { continue; }
            foreach (var file in files)
            {
                // Several packages may ship the same component; keep the most recently written file.
                var name = Path.GetFileNameWithoutExtension(file);
                var written = File.GetLastWriteTimeUtc(file);
                if (!map.TryGetValue(name, out var known) || known.Written < written) map[name] = (file, written);
            }
        }
        return map.ToDictionary(kv => kv.Key, kv => kv.Value.File, StringComparer.OrdinalIgnoreCase);
    });

    /// <summary>
    /// Installed app package roots for the current user, read from the registry package repository because
    /// WindowsApps cannot be enumerated without elevation, while individual package folders are readable.
    /// </summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static IEnumerable<string> InstalledPackageFolders()
    {
        var folders = new List<string>();
        try
        {
            using var packages = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages");
            if (packages == null) return folders;
            foreach (var name in packages.GetSubKeyNames())
            {
                using var key = packages.OpenSubKey(name);
                if (key?.GetValue("PackageRootFolder") is string root && Directory.Exists(root)) folders.Add(root);
            }
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException) { }
        return folders;
    }

    /// <summary>A .winmd of this name shipped by an installed app package, if any.</summary>
    public static string? InstalledPackageMetadata(string name) => PackageMetadata.Value.GetValueOrDefault(name);

    private static Version ParseVersion(string s) => Version.TryParse(s.Split('-')[0], out var v) ? v : new Version(0, 0);

    private static IEnumerable<string> SubDirectories(string dir)
    {
        try { return Directory.Exists(dir) ? Directory.GetDirectories(dir) : []; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; }
    }

    /// <summary>
    /// NuGet lib TFMs usable by a modern requester, best first, excluding any newer than its target framework.
    /// All of them when the target framework is unknown.
    /// </summary>
    private static string[] CompatibleTfms(string? requesterFramework)
    {
        if (requesterFramework == null) return ModernTfms;
        var parts = requesterFramework.Split(",Version=v", 2);
        if (parts.Length != 2 || !Version.TryParse(parts[1], out var v)) return ModernTfms;
        if (parts[0].Equals(".NETStandard", StringComparison.OrdinalIgnoreCase))
            return ModernTfms.Where(t => t.StartsWith("netstandard", StringComparison.Ordinal) && Version.Parse(t["netstandard".Length..]) <= v).ToArray();
        if (!parts[0].Equals(".NETCoreApp", StringComparison.OrdinalIgnoreCase)) return ModernTfms;
        return ModernTfms.Where(t =>
            t.StartsWith("netstandard", StringComparison.Ordinal)
            || (t.StartsWith("netcoreapp", StringComparison.Ordinal) ? Version.Parse(t["netcoreapp".Length..]) : Version.Parse(t["net".Length..])) <= v).ToArray();
    }

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, IReadOnlyDictionary<string, HashSet<string>>> TypeIndex = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Public top-level type names (with `arity) per namespace in the framework <paramref name="targetFramework"/>
    /// compiles against, i.e. what a using directive brings into scope. Null when that framework is not installed.
    /// </summary>
    public static IReadOnlyDictionary<string, HashSet<string>>? PublicTypeNames(string? targetFramework)
    {
        List<string>? files = null;
        string key;
        if (NetCoreMajor(targetFramework) is { } major)
        {
            var dir = InstalledReferencePackDir("Microsoft.NETCore.App", major)
                      ?? All.Value.FirstOrDefault(s => s.Name == "Microsoft.NETCore.App" && s.Version.Major == major)?.Dir
                      ?? ReferencePacks.Get("Microsoft.NETCore.App.Ref", major);
            if (dir == null) return null;
            key = dir;
            files = SafeFiles(dir);
        }
        else if (targetFramework?.Split(",Version=v", 2) is [var id, var ver] && id.Equals(".NETStandard", StringComparison.OrdinalIgnoreCase)
                 && Version.TryParse(ver, out var v) && NetStandardFile(v) is { } netstandard)
        {
            key = netstandard;
            files = [netstandard];
        }
        else return null;

        return TypeIndex.GetOrAdd(key, _ =>
        {
            var index = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
            foreach (var file in files)
            {
                try
                {
                    using var stream = File.OpenRead(file);
                    using var pe = new System.Reflection.PortableExecutable.PEReader(stream);
                    if (!pe.HasMetadata) continue;
                    var reader = System.Reflection.Metadata.PEReaderExtensions.GetMetadataReader(pe);
                    foreach (var h in reader.TypeDefinitions)
                    {
                        var t = reader.GetTypeDefinition(h);
                        if ((t.Attributes & System.Reflection.TypeAttributes.VisibilityMask) != System.Reflection.TypeAttributes.Public) continue;
                        var ns = reader.GetString(t.Namespace);
                        if (!index.TryGetValue(ns, out var names)) index[ns] = names = new HashSet<string>(StringComparer.Ordinal);
                        names.Add(reader.GetString(t.Name));
                    }
                }
                catch (Exception) { }
            }
            return index;
        });
    }

    private static List<string> SafeFiles(string dir)
    {
        try { return Directory.GetFiles(dir, "*.dll").ToList(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; }
    }

    /// <summary>The TargetFrameworkAttribute value, e.g. ".NETCoreApp,Version=v8.0".</summary>
    public static string? TargetFrameworkOf(ModuleDef module) => Read(module)?.TargetFramework;

    /// <summary>
    /// The framework of an assembly without a TargetFrameworkAttribute, from the core assemblies it references:
    /// netstandard 2.x; System.Runtime 4.0 / 4.1 contracts (netstandard 1.x); mscorlib 2.0 (.NET Framework 3.5); mscorlib
    /// 4.0 next to netstandard or UnityEngine (the Unity .NET 4.x profile, close to .NET Framework 4.8). Null otherwise.
    /// </summary>
    public static string? InferTargetFramework(ModuleDef module) => Read(module) is { TargetFramework: null } f ? f.Inferred : null;

    /// <summary>
    /// The framework references are resolved for: the TargetFrameworkAttribute, else a .NET Standard framework inferred
    /// from the references (a netstandard1.x contract must not bind to the newest runtime's API, e.g. Volatile.Read(ref readonly)).
    /// </summary>
    public static string? RequesterFramework(ModuleDef module) => Read(module) is { } f
        ? f.TargetFramework ?? (f.Inferred?.StartsWith(".NETStandard", StringComparison.Ordinal) == true ? f.Inferred : null)
        : null;

    /// <summary>
    /// .NET Framework, or .NET Standard 1.x, whose contracts .NET Framework 4.5 implements: their references bind to .NET
    /// Framework, as the newest runtime's facades would change the API (Volatile.Read(ref T) read as ref readonly, shown as 'in').
    /// </summary>
    public static bool ResolvesAsNetFramework(ModuleDef module) =>
        TargetsNetFramework(module) || RequesterFramework(module)?.StartsWith(".NETStandard,Version=v1.", StringComparison.OrdinalIgnoreCase) == true;

    private static string? Infer(IReadOnlyDictionary<string, Version> refs, IEnumerable<string> names)
    {
        refs.TryGetValue("netstandard", out var standard);
        if (refs.TryGetValue("mscorlib", out var corlib))
        {
            if (corlib.Major == 2) return ".NETFramework,Version=v3.5";
            if (corlib.Major == 4 && (standard != null || names.Any(n => n.StartsWith("UnityEngine", StringComparison.OrdinalIgnoreCase))))
                return ".NETFramework,Version=v4.8";
            return null;
        }
        if (standard != null) return standard is { Major: 2, Minor: >= 1 } ? ".NETStandard,Version=v2.1" : ".NETStandard,Version=v2.0";
        if (refs.TryGetValue("System.Runtime", out var runtime) && runtime is { Major: 4, Minor: <= 1 })
            return ".NETStandard,Version=v" + (runtime.Minor == 1 ? "1.5" : runtime.Build switch { >= 20 => "1.3", >= 10 => "1.2", _ => "1.0" });
        return null;
    }

    /// <summary>The project file form of a framework name: ".NETStandard,Version=v1.0" -> netstandard1.0, ".NETFramework,Version=v4.8" -> net48.</summary>
    public static string? ShortName(string? targetFramework)
    {
        if (targetFramework?.Split(",Version=v", 2) is not [var id, var ver]) return null;
        return id.ToUpperInvariant() switch
        {
            ".NETSTANDARD" => "netstandard" + ver,
            ".NETFRAMEWORK" => "net" + ver.Replace(".", ""),
            ".NETCOREAPP" when Version.TryParse(ver, out var v) => v.Major >= 5 ? $"net{v.Major}.{v.Minor}" : "netcoreapp" + ver,
            _ => null,
        };
    }

    /// <summary>Whether a file lies in a .NET Framework directory (the runtime's, not a reference pack).</summary>
    public static bool InNetFrameworkDirectory(string file)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(file))?.TrimEnd(Path.DirectorySeparatorChar);
        return dir != null && NetFramework.Value.Any(d => string.Equals(Path.GetFullPath(d).TrimEnd(Path.DirectorySeparatorChar), dir, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>True for 0.0.x, 255.x (WinMD) and 65535.x versions ("any version"), which carry no framework information.</summary>
    public static bool IsWildcard(Version v) => v is { Major: 0, Minor: 0 } || v.Major is 255 or 65535;

    /// <param name="Inferred">See <see cref="InferTargetFramework"/>.</param>
    private sealed record ImageFacts(string? AssemblyName, string? TargetFramework, HashSet<string> References, string? Inferred);

    private static readonly ConditionalWeakTable<ModuleDef, ImageFacts> Facts = new();

    /// <summary>
    /// Reads via System.Reflection.Metadata rather than dnlib: this runs during dnlib assembly resolution, where
    /// enumerating custom attributes would re-enter a dnlib lock. Not cached on failure.
    /// </summary>
    private static ImageFacts? Read(ModuleDef module)
    {
        if (Facts.TryGetValue(module, out var known)) return known;
        if (module is not ModuleDefMD md) return null;
        try
        {
            var image = md.Metadata.PEImage.CreateReader().ToArray();
            using var pe = new System.Reflection.PortableExecutable.PEReader(new MemoryStream(image, writable: false));
            var reader = System.Reflection.Metadata.PEReaderExtensions.GetMetadataReader(pe);
            var versions = new Dictionary<string, Version>(StringComparer.OrdinalIgnoreCase);
            foreach (var h in reader.AssemblyReferences)
            {
                var r = reader.GetAssemblyReference(h);
                versions.TryAdd(reader.GetString(r.Name), r.Version);
            }
            var refs = versions.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase);
            string? name = null, tfm = null;
            if (reader.IsAssembly)
            {
                var asm = reader.GetAssemblyDefinition();
                name = reader.GetString(asm.Name);
                foreach (var h in asm.GetCustomAttributes())
                {
                    var ca = reader.GetCustomAttribute(h);
                    if (ca.Constructor.Kind != System.Reflection.Metadata.HandleKind.MemberReference) continue;
                    var parent = reader.GetMemberReference((System.Reflection.Metadata.MemberReferenceHandle)ca.Constructor).Parent;
                    if (parent.Kind != System.Reflection.Metadata.HandleKind.TypeReference) continue;
                    var type = reader.GetTypeReference((System.Reflection.Metadata.TypeReferenceHandle)parent);
                    if (reader.GetString(type.Name) != "TargetFrameworkAttribute" || reader.GetString(type.Namespace) != "System.Runtime.Versioning") continue;
                    var blob = reader.GetBlobReader(ca.Value);
                    if (blob.Length >= 3 && blob.ReadUInt16() == 1) tfm = blob.ReadSerializedString(); // 0x0001 prolog, then the framework name
                }
            }
            var facts = new ImageFacts(name, tfm, refs, tfm == null ? Infer(versions, refs) : null);
            Facts.AddOrUpdate(module, facts);
            return facts;
        }
        catch (Exception) { return null; }
    }

    /// <summary>
    /// True if the TargetFramework attribute says .NET Framework, or, without one, mscorlib is referenced without
    /// System.Runtime or netstandard.
    /// </summary>
    public static bool TargetsNetFramework(ModuleDef module)
    {
        if (Read(module) is not { } f) return false;
        if (f.TargetFramework != null) return f.TargetFramework.StartsWith(".NETFramework", StringComparison.OrdinalIgnoreCase);
        return f.References.Contains("mscorlib") && !f.References.Contains("System.Runtime") && !f.References.Contains("netstandard");
    }

    /// <summary>The shared framework that ships an assembly of this name, optionally for a given major version.</summary>
    public static string? SharedFrameworkOf(string name, int? major = null)
    {
        foreach (var group in All.Value.GroupBy(s => s.Name))
        {
            // With a major given, only that version's runtime or reference pack is checked.
            var dirs = major is { } m
                ? (group.FirstOrDefault(s => s.Version.Major == m)?.Dir ?? ReferencePackDir(group.Key, m)) is { } dir ? [dir] : []
                : group.Take(1).Select(s => s.Dir);
            if (dirs.Any(d => File.Exists(Path.Combine(d, name + ".dll")))) return group.Key;
        }
        // Target version unavailable: which framework owns an assembly name does not change between versions.
        return major != null ? SharedFrameworkOf(name) : null;
    }

    /// <summary>Major version of the shared framework directory containing the file, if any.</summary>
    public static int? SharedFrameworkMajor(string file)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(file));
        return All.Value.FirstOrDefault(s => string.Equals(Path.GetFullPath(s.Dir).TrimEnd(Path.DirectorySeparatorChar), dir, StringComparison.OrdinalIgnoreCase))?.Version.Major;
    }

    /// <summary>Major version of the targeting pack (&lt;Framework&gt;.Ref/&lt;version&gt;/ref/netN.0) containing the file, if any.</summary>
    public static int? ReferencePackMajor(string file)
    {
        var tfm = Path.GetDirectoryName(Path.GetFullPath(file));
        var refDir = Path.GetDirectoryName(tfm);
        var pack = Path.GetDirectoryName(Path.GetDirectoryName(refDir));
        if (pack == null || !string.Equals(Path.GetFileName(refDir), "ref", StringComparison.OrdinalIgnoreCase)
            || !SharedNames.Any(n => string.Equals(Path.GetFileName(pack), n + ".Ref", StringComparison.OrdinalIgnoreCase)))
            return null;
        var name = Path.GetFileName(tfm)!;
        return name.StartsWith("net", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".0", StringComparison.Ordinal)
               && int.TryParse(name.AsSpan(3, name.Length - 5), out var major) ? major : null;
    }

    /// <summary>Major version of the shared framework or targeting pack containing the file: a modern .NET copy, if any.</summary>
    public static int? ModernFrameworkMajor(string file) => SharedFrameworkMajor(file) ?? ReferencePackMajor(file);

    /// <summary>Major version of a ".NETCoreApp,Version=vX.Y" target framework, else null.</summary>
    public static int? NetCoreMajor(string? targetFramework) =>
        targetFramework?.Split(",Version=v", 2) is [var id, var ver] && id.Equals(".NETCoreApp", StringComparison.OrdinalIgnoreCase)
        && Version.TryParse(ver, out var v) ? v.Major : null;

    /// <summary>
    /// True for System.Private.CoreLib, a .NETCoreApp target framework, or a reference to System.Private.CoreLib or
    /// System.Runtime. Includes modern .NET facades such as mscorlib.
    /// </summary>
    public static bool IsModernNet(ModuleDef module)
    {
        if (Read(module) is not { } f) return false;
        if (f.AssemblyName == "System.Private.CoreLib") return true;
        if (f.TargetFramework != null) return f.TargetFramework.StartsWith(".NETCoreApp", StringComparison.OrdinalIgnoreCase);
        return f.References.Contains("System.Private.CoreLib") || f.References.Contains("System.Runtime");
    }

    public static string? NetFrameworkFile(string name) =>
        NetFramework.Value.Select(d => Path.Combine(d, name + ".dll")).FirstOrDefault(File.Exists);

    /// <summary>
    /// Reference assembly directories for a ".NETFramework,Version=vX.Y" target: the installed targeting pack, else the
    /// Microsoft.NETFramework.ReferenceAssemblies package. Null when neither is present.
    /// </summary>
    public static IReadOnlyList<string>? NetFrameworkReferenceDirs(string? targetFramework)
    {
        if (targetFramework?.Split(",Version=v", 2) is not [var id, var ver] || !id.Equals(".NETFramework", StringComparison.OrdinalIgnoreCase)) return null;
        var candidates = new List<string>
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Reference Assemblies", "Microsoft", "Framework", ".NETFramework", "v" + ver),
        };
        if (NuGetRoot.Value is { } nuget)
        {
            var package = Path.Combine(nuget, "microsoft.netframework.referenceassemblies.net" + ver.Replace(".", ""));
            if (FirstExisting(package, d => Path.Combine(d, "build", ".NETFramework", "v" + ver, "mscorlib.dll")) is { } mscorlib)
                candidates.Add(Path.GetDirectoryName(mscorlib)!);
        }
        var dir = candidates.FirstOrDefault(d => File.Exists(Path.Combine(d, "mscorlib.dll")));
        return dir == null ? null : [dir, Path.Combine(dir, "Facades")];
    }

    public static bool IsNetFrameworkAssembly(string name) => NetFramework.Value.Any(d => File.Exists(Path.Combine(d, name + ".dll")));
}
