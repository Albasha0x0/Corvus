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

    /// <summary>Every installed shared framework version, newest first within each framework.</summary>
    public static readonly Lazy<IReadOnlyList<Shared>> All = new(() =>
    {
        var roots = new[]
        {
            Environment.GetEnvironmentVariable("DOTNET_ROOT"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".dotnet"),
            "/usr/share/dotnet", "/usr/lib/dotnet", "/usr/local/share/dotnet", "/opt/homebrew/opt/dotnet/libexec",
        }.Where(r => !string.IsNullOrEmpty(r)).Distinct(StringComparer.OrdinalIgnoreCase);
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
                pick = versions.FirstOrDefault(s => s.Version.Major == version.Major)
                       ?? versions.Where(s => s.Version.Major > version.Major).OrderBy(s => s.Version).FirstOrDefault();
            pick ??= versions.FirstOrDefault();
            if (pick != null) result.Add(pick.Dir);
        }
        if (RuntimeDir.Value is { } runtime) result.Add(runtime);
        if (!netFramework) result.AddRange(NetFramework.Value); // .NET Framework-only assemblies (System.Web, WindowsBase 4...) as a last resort
        return result.Distinct(StringComparer.OrdinalIgnoreCase);
    }

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
    public static string? SharedFrameworkOf(string name) =>
        All.Value.GroupBy(s => s.Name).Select(g => g.First())
            .FirstOrDefault(s => File.Exists(Path.Combine(s.Dir, name + ".dll")))?.Name;

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
