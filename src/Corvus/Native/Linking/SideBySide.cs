using System.Text.RegularExpressions;
using System.Xml;

namespace Corvus.Native.Linking;

/// <summary>Reads the side-by-side assemblies a PE manifest depends on and finds them in a component store.</summary>
internal static partial class SideBySide
{
    /// <summary>One dependent assembly: its identity as the manifest spells it.</summary>
    internal sealed record Dependency(string Name, string Version, string Architecture, string PublicKeyToken);

    /// <summary>The shared assemblies a manifest names: empty for null, and what precedes the error for malformed XML.</summary>
    public static IReadOnlyList<Dependency> Dependencies(string? manifest)
    {
        List<Dependency> found = [];
        if (string.IsNullOrEmpty(manifest)) return found;
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
        try
        {
            using var reader = XmlReader.Create(new StringReader(manifest), settings);
            var inside = false;
            while (reader.Read())
            {
                if (reader.LocalName == "dependentAssembly") inside = reader.NodeType == XmlNodeType.Element;
                else if (inside && reader.NodeType == XmlNodeType.Element && reader.LocalName == "assemblyIdentity"
                    && reader.GetAttribute("type") is null or "win32"
                    && Identity(reader) is { } dependency) found.Add(dependency);
            }
        }
        catch (XmlException) { }
        return found;
    }

    // The values come from the analyzed file and reach a path: only the store's own
    // spelling passes. A private assembly has no token and is not in the store.
    private static Dependency? Identity(XmlReader reader)
    {
        var name = reader.GetAttribute("name");
        var version = reader.GetAttribute("version");
        var token = reader.GetAttribute("publicKeyToken");
        var architecture = reader.GetAttribute("processorArchitecture") ?? "*";
        return name != null && version != null && token != null && AssemblyName().IsMatch(name) && Token().IsMatch(token)
            && System.Version.TryParse(version, out _) && Architecture().IsMatch(architecture)
            ? new Dependency(name, version, architecture, token)
            : null;
    }

    /// <summary>The store folder of the newest neutral servicing version of an assembly, as a publisher policy redirects to it; null when the store has none.</summary>
    public static string? Folder(string store, Dependency dependency, bool x86)
    {
        var wanted = Version.Parse(dependency.Version);
        var architecture = dependency.Architecture == "*" ? (x86 ? "x86" : "amd64") : dependency.Architecture;
        var prefix = $"{architecture}_{dependency.Name}_{dependency.PublicKeyToken}_".ToLowerInvariant();
        string? best = null;
        Version? bestVersion = null;
        try
        {
            foreach (var folder in Directory.EnumerateDirectories(store, $"{prefix}{wanted.Major}.{wanted.Minor}.*_none_*"))
            {
                var tail = Path.GetFileName(folder)[prefix.Length..];
                var end = tail.IndexOf('_');
                if (end > 0 && Version.TryParse(tail[..end], out var version) && version >= wanted && (bestVersion == null || version > bestVersion))
                    (best, bestVersion) = (folder, version);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { return null; }
        return best;
    }

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9.-]*\z")]
    private static partial Regex AssemblyName();

    [GeneratedRegex(@"^[0-9A-Fa-f]{16}\z")]
    private static partial Regex Token();

    [GeneratedRegex(@"^(\*|[A-Za-z0-9]+)\z")]
    private static partial Regex Architecture();
}
