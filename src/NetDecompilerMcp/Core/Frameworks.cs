using System.Runtime.CompilerServices;
using dnlib.DotNet;

namespace NetDecompilerMcp.Core;

/// <summary>
/// The installed .NET frameworks, for resolving framework references by version: every version of each shared
/// framework (Microsoft.NETCore.App, WindowsDesktop, AspNetCore) under the dotnet roots, and on Windows the .NET
/// Framework 4 directory. A reference is looked up in the framework of the same major version, so a net6.0 library is
/// read against .NET 6 and a .NET Framework app against .NET Framework (not against whatever is newest).
/// </summary>
internal static class Frameworks
{
    public sealed record Shared(string Name, Version Version, string Dir);

    private static readonly string[] SharedNames = ["Microsoft.NETCore.App", "Microsoft.WindowsDesktop.App", "Microsoft.AspNetCore.App"];

    /// <summary>The dotnet installation roots (DOTNET_ROOT, then the usual locations) that exist.</summary>
    private static readonly Lazy<IReadOnlyList<string>> DotnetRoots = new(() => new[]
        {
            Environment.GetEnvironmentVariable("DOTNET_ROOT"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".dotnet"),
            "/usr/share/dotnet", "/usr/lib/dotnet", "/usr/local/share/dotnet", "/opt/homebrew/opt/dotnet/libexec",
        }.Where(r => !string.IsNullOrEmpty(r) && Directory.Exists(r)).Select(r => r!).Distinct(StringComparer.OrdinalIgnoreCase).ToList());

    /// <summary>The NuGet global packages folder (NUGET_PACKAGES, else ~/.nuget/packages), when it exists.</summary>
    private static readonly Lazy<string?> NuGetRoot = new(() =>
    {
        var dir = Environment.GetEnvironmentVariable("NUGET_PACKAGES");
        if (string.IsNullOrEmpty(dir)) dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".nuget", "packages");
        return Directory.Exists(dir) ? dir : null;
    });

    /// <summary>Every installed shared framework version, newest first within each framework.</summary>
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
                break; // the first root that has this framework
            }
        return list.OrderBy(s => Array.IndexOf(SharedNames, s.Name)).ThenByDescending(s => s.Version).ToList();
    });

    /// <summary>The .NET Framework 4 directories (with WPF), when present (Windows).</summary>
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

    /// <summary>The runtime this process runs on (a last resort when no shared framework is installed).</summary>
    private static readonly Lazy<string?> RuntimeDir = new(() =>
    {
        var dir = System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory();
        return !string.IsNullOrEmpty(dir) && File.Exists(Path.Combine(dir, "System.Runtime.dll")) ? dir : null;
    });

    /// <summary>
    /// Framework directories to look in for a reference of <paramref name="version"/>: for .NET 5+ (major 5 and up)
    /// each shared framework's newest version of that major (else the nearest newer one, else the newest); for a
    /// .NET Framework app (<paramref name="netFramework"/>) the .NET Framework directory first; otherwise the newest.
    /// </summary>
    public static IEnumerable<string> DirectoriesFor(Version? version, bool netFramework)
    {
        var result = new List<string>();
        if (netFramework) result.AddRange(NetFramework.Value);
        foreach (var group in All.Value.GroupBy(s => s.Name))
        {
            var versions = group.ToList(); // newest first
            Shared? pick = null;
            if (version is { Major: >= 5 } && !IsWildcard(version))
            {
                pick = versions.FirstOrDefault(s => s.Version.Major == version.Major);
                // that major is not installed: its reference pack has the exact API, before a newer runtime
                if (pick == null && ReferencePackDir(group.Key, version.Major) is { } pack) result.Add(pack);
                pick ??= versions.Where(s => s.Version.Major > version.Major).OrderBy(s => s.Version).FirstOrDefault();
            }
            pick ??= versions.FirstOrDefault();
            if (pick != null) result.Add(pick.Dir);
        }
        if (RuntimeDir.Value is { } runtime) result.Add(runtime);
        if (!netFramework) result.AddRange(NetFramework.Value); // .NET Framework-only assemblies (System.Web, WindowsBase 4...) as a last resort
        return result.Distinct(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The reference assemblies of a shared framework's major version (targeting pack), from the dotnet roots' packs or
    /// the NuGet cache: <c>packs/Microsoft.NETCore.App.Ref/6.0.x/ref/net6.0</c>.
    /// </summary>
    public static string? ReferencePackDir(string framework, int major)
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
    /// The .NET Standard reference assembly for a netstandard reference (2.1 from the SDK's NETStandard.Library.Ref
    /// pack, 2.0 from the NETStandard.Library package): its exact API, not a newer runtime's facade, so a netstandard
    /// library decompiles against what it was built for.
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

    /// <summary>In the newest version folder under <paramref name="dir"/> that has it, the file <paramref name="file"/> names.</summary>
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

    /// <summary>
    /// A dependency from the NuGet global packages folder: the package named like the assembly, the assembly version
    /// asked for (else the lowest of the same major that is at least that version, else the newest of the major, else
    /// the newest), from the lib folder of the best target framework for a .NET Framework or a modern requester.
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
                        break; // the best framework folder of this package version
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

    /// <summary>The Windows SDK roots (Windows Kits 10) that exist.</summary>
    private static readonly Lazy<IReadOnlyList<string>> WindowsKits = new(() =>
    {
        if (!OperatingSystem.IsWindows()) return [];
        return new[] { Environment.SpecialFolder.ProgramFilesX86, Environment.SpecialFolder.ProgramFiles }
            .Select(f => Path.Combine(Environment.GetFolderPath(f), "Windows Kits", "10"))
            .Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    });

    /// <summary>
    /// The metadata of a Windows Runtime API contract (<c>Windows.Foundation.FoundationContract</c>, ...) or of
    /// <c>Windows</c> itself: the contract's own .winmd from the newest Windows SDK that has that version (else its
    /// newest), else the SDK's union metadata (<c>Windows.winmd</c>), which holds every Windows Runtime type.
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

    private static Version ParseVersion(string s) => Version.TryParse(s.Split('-')[0], out var v) ? v : new Version(0, 0);

    private static IEnumerable<string> SubDirectories(string dir)
    {
        try { return Directory.Exists(dir) ? Directory.GetDirectories(dir) : []; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; }
    }

    /// <summary>
    /// The lib folders a modern requester can use, best first: none newer than its own target framework
    /// (".NETCoreApp,Version=v8.0" takes net8.0 down to netstandard; ".NETStandard,Version=v2.0" only netstandard2.0
    /// and older). Without a known target framework, all of them.
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
    /// The public top-level type names (with `arity) per namespace of the framework a project of
    /// <paramref name="targetFramework"/> compiles against: the reference pack or runtime of that .NET major, or the
    /// .NET Standard reference assembly. What a using directive brings into scope at build time, beyond the
    /// assemblies the code itself references. Null when that framework is not on this machine.
    /// </summary>
    public static IReadOnlyDictionary<string, HashSet<string>>? PublicTypeNames(string? targetFramework)
    {
        List<string>? files = null;
        string key;
        if (NetCoreMajor(targetFramework) is { } major)
        {
            var dir = ReferencePackDir("Microsoft.NETCore.App", major)
                      ?? All.Value.FirstOrDefault(s => s.Name == "Microsoft.NETCore.App" && s.Version.Major == major)?.Dir;
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
                catch (Exception) { /* not a readable assembly */ }
            }
            return index;
        });
    }

    private static List<string> SafeFiles(string dir)
    {
        try { return Directory.GetFiles(dir, "*.dll").ToList(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; }
    }

    /// <summary>A module's TargetFramework attribute value (".NETCoreApp,Version=v8.0"), when it has one.</summary>
    public static string? TargetFrameworkOf(ModuleDef module) => Read(module)?.TargetFramework;

    /// <summary>0.0.0.0 and 255.255.255.255 (WinMD, "any version") say nothing about the framework.</summary>
    public static bool IsWildcard(Version v) => v is { Major: 0, Minor: 0 } || v.Major == 255;

    /// <summary>A module's target framework attribute and assembly references, read from its PE image.</summary>
    private sealed record ImageFacts(string? AssemblyName, string? TargetFramework, HashSet<string> References);

    private static readonly ConditionalWeakTable<ModuleDef, ImageFacts> Facts = new();

    /// <summary>
    /// Read with System.Reflection.Metadata from the module's own image, not through dnlib's lazy lists: this runs
    /// inside dnlib's assembly resolution, where enumerating custom attributes re-enters a lock dnlib already holds.
    /// Not cached when the image cannot be read.
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
            var refs = reader.AssemblyReferences.Select(h => reader.GetString(reader.GetAssemblyReference(h).Name)).ToHashSet(StringComparer.OrdinalIgnoreCase);
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
                    if (blob.Length >= 3 && blob.ReadUInt16() == 1) tfm = blob.ReadSerializedString(); // prolog, then the framework name
                }
            }
            var facts = new ImageFacts(name, tfm, refs);
            Facts.AddOrUpdate(module, facts);
            return facts;
        }
        catch (Exception) { return null; }
    }

    /// <summary>
    /// Whether a module targets .NET Framework: a TargetFramework attribute saying so, or (older compilers) a reference
    /// to mscorlib without System.Runtime / netstandard.
    /// </summary>
    public static bool TargetsNetFramework(ModuleDef module)
    {
        if (Read(module) is not { } f) return false;
        if (f.TargetFramework != null) return f.TargetFramework.StartsWith(".NETFramework", StringComparison.OrdinalIgnoreCase);
        return f.References.Contains("mscorlib") && !f.References.Contains("System.Runtime") && !f.References.Contains("netstandard");
    }

    /// <summary>
    /// The shared framework (runtime pack name) that ships an assembly of this name, if any: such references are part
    /// of the target framework, not files to reference.
    /// </summary>
    public static string? SharedFrameworkOf(string name, int? major = null)
    {
        foreach (var group in All.Value.GroupBy(s => s.Name))
        {
            // for a project of a given major: that version's framework (or its reference pack) decides
            var dirs = major is { } m
                ? group.Where(s => s.Version.Major == m).Select(s => s.Dir).Take(1)
                    .Concat(ReferencePackDir(group.Key, m) is { } pack ? [pack] : [])
                : group.Take(1).Select(s => s.Dir);
            if (dirs.Any(d => File.Exists(Path.Combine(d, name + ".dll")))) return group.Key;
        }
        return null;
    }

    /// <summary>The major version of the shared framework directory a file lies in (…/shared/Microsoft.NETCore.App/10.0.1/x.dll), if any.</summary>
    public static int? SharedFrameworkMajor(string file)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(file));
        return All.Value.FirstOrDefault(s => string.Equals(Path.GetFullPath(s.Dir).TrimEnd(Path.DirectorySeparatorChar), dir, StringComparison.OrdinalIgnoreCase))?.Version.Major;
    }

    /// <summary>The .NET major of a ".NETCoreApp,Version=v8.0" target framework, else null.</summary>
    public static int? NetCoreMajor(string? targetFramework) =>
        targetFramework?.Split(",Version=v", 2) is [var id, var ver] && id.Equals(".NETCoreApp", StringComparison.OrdinalIgnoreCase)
        && Version.TryParse(ver, out var v) ? v.Major : null;

    /// <summary>
    /// Whether a module belongs to modern .NET (Core): System.Private.CoreLib itself, a reference to it or to
    /// System.Runtime, or a .NETCoreApp target framework (facades like mscorlib 4.0 of .NET 10 included).
    /// </summary>
    public static bool IsModernNet(ModuleDef module)
    {
        if (Read(module) is not { } f) return false;
        if (f.AssemblyName == "System.Private.CoreLib") return true;
        if (f.TargetFramework != null) return f.TargetFramework.StartsWith(".NETCoreApp", StringComparison.OrdinalIgnoreCase);
        return f.References.Contains("System.Private.CoreLib") || f.References.Contains("System.Runtime");
    }

    /// <summary>The .NET Framework 4 file of an assembly of this name, if .NET Framework ships one.</summary>
    public static string? NetFrameworkFile(string name) =>
        NetFramework.Value.Select(d => Path.Combine(d, name + ".dll")).FirstOrDefault(File.Exists);

    /// <summary>Whether an assembly of this name is part of .NET Framework 4.</summary>
    public static bool IsNetFrameworkAssembly(string name) => NetFramework.Value.Any(d => File.Exists(Path.Combine(d, name + ".dll")));
}
