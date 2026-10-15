using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Corvus.Core;

namespace Corvus.Native.Providers.Ghidra;

/// <summary>A Ghidra extension the user supplied: its module name, a hash of its content, and the zip or directory it came from.</summary>
public sealed record GhidraExtension(string Name, string Hash, string Source);

/// <summary>
/// Ghidra extensions (such as a NativeAOT analyzer built for this Ghidra) taken from the directory in
/// <see cref="GhidraOptions.ExtensionsVariable"/>: extension zips, or unpacked extension directories. They are
/// installed into the workers' private settings directory, never the user's, and their hashes are part of the profile
/// key, so adding or changing one analyzes images again. Nothing is downloaded.
/// </summary>
public static class GhidraExtensions
{
    private const string Marker = ".corvus-extension";

    // Migration only: the marker of extensions installed before the rename, so they are still managed.
    private const string LegacyMarker = ".ndm-extension";

    /// <summary>The extensions in <paramref name="directory"/> (none when null or empty); a missing directory or an unreadable zip is InvalidArgument.</summary>
    public static IReadOnlyList<GhidraExtension> Configured(string? directory)
    {
        if (string.IsNullOrWhiteSpace(directory)) return [];
        var dir = directory.Trim().Trim('"');
        if (!Directory.Exists(dir))
            throw new ToolError(ErrorCode.InvalidArgument, $"The extension directory {dir} ({GhidraOptions.ExtensionsVariable}) does not exist.",
                $"Set {GhidraOptions.ExtensionsVariable} to a directory of Ghidra extension zips built for this Ghidra, or unset it.");
        var list = new List<GhidraExtension>();
        foreach (var zip in Directory.EnumerateFiles(dir, "*.zip").Order(StringComparer.Ordinal))
            list.Add(new GhidraExtension(ZipModule(zip), Hash(File.ReadAllBytes(zip)), zip));
        foreach (var sub in Directory.EnumerateDirectories(dir).Order(StringComparer.Ordinal))
            if (File.Exists(Path.Combine(sub, "extension.properties")))
                list.Add(new GhidraExtension(Path.GetFileName(sub), DirectoryHash(sub), sub));
        var twice = list.GroupBy(e => e.Name, StringComparer.OrdinalIgnoreCase).FirstOrDefault(g => g.Count() > 1);
        if (twice != null)
            throw new ToolError(ErrorCode.InvalidArgument, $"Two extensions in {dir} are named {twice.Key}.", "Keep one of them.");
        return list;
    }

    /// <summary>The single top-level directory of an extension zip (its module), which must hold extension.properties.</summary>
    private static string ZipModule(string zip)
    {
        try
        {
            using var archive = ZipFile.OpenRead(zip);
            var tops = archive.Entries.Select(e => e.FullName.Replace('\\', '/').Split('/')[0]).Where(t => t.Length > 0).Distinct().ToList();
            if (tops.Count == 1 && archive.Entries.Any(e => e.FullName.Replace('\\', '/') == tops[0] + "/extension.properties")) return tops[0];
        }
        catch (InvalidDataException) { }
        throw new ToolError(ErrorCode.InvalidArgument, $"{zip} is not a Ghidra extension zip (one top-level directory holding extension.properties).",
            $"Put only extension zips built for this Ghidra in {GhidraOptions.ExtensionsVariable}.");
    }

    private static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes))[..16];

    private static string DirectoryHash(string dir)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
        {
            hash.AppendData(Encoding.UTF8.GetBytes(Path.GetRelativePath(dir, file).Replace('\\', '/') + "\n"));
            hash.AppendData(File.ReadAllBytes(file));
        }
        return Convert.ToHexStringLower(hash.GetHashAndReset())[..16];
    }

    /// <summary>
    /// Ghidra's user extension directory under the private settings directory: [settings]/[user]-ghidra/ghidra_[version]_[release]/Extensions,
    /// as Ghidra names it for a settings directory outside the user's home.
    /// </summary>
    public static string InstallDirectory(GhidraDirectories dirs, GhidraInstallation ghidra)
    {
        var properties = GhidraInstallation.ReadProperties(ghidra.PropertiesPath);
        var release = (properties?.GetValueOrDefault("application.release.name") ?? "PUBLIC").Replace(" ", "").ToUpperInvariant();
        var user = Environment.UserName.Replace(" ", "");
        user = user[(user.LastIndexOfAny(['\\', '/']) + 1)..];
        return Path.Combine(dirs.Settings, user + "-ghidra", $"ghidra_{ghidra.Version}_{release}", "Extensions");
    }

    /// <summary>
    /// Makes <paramref name="target"/> hold exactly <paramref name="wanted"/> among the extensions this server installed
    /// (each marked with its hash): new or changed ones are unpacked, ones no longer configured removed.
    /// </summary>
    public static void Install(IReadOnlyList<GhidraExtension> wanted, string target)
    {
        Directory.CreateDirectory(target);
        foreach (var dir in Directory.EnumerateDirectories(target))
            if ((File.Exists(Path.Combine(dir, Marker)) || File.Exists(Path.Combine(dir, LegacyMarker))) && !wanted.Any(w => w.Name.Equals(Path.GetFileName(dir), StringComparison.OrdinalIgnoreCase)))
                Directory.Delete(dir, recursive: true);
        foreach (var e in wanted)
        {
            var dest = Path.Combine(target, e.Name);
            var marker = Path.Combine(dest, Marker);
            if (File.Exists(marker) && File.ReadAllText(marker).Trim() == e.Hash) continue;
            var staging = Path.Combine(target, ".staging-" + Guid.NewGuid().ToString("N")[..8]);
            try
            {
                if (Directory.Exists(e.Source)) CopyDirectory(e.Source, Path.Combine(staging, e.Name));
                else ZipFile.ExtractToDirectory(e.Source, staging); // refuses entries outside the directory
                File.WriteAllText(Path.Combine(staging, e.Name, Marker), e.Hash);
                if (Directory.Exists(dest)) SafeFile.WhenReleased(() => Directory.Delete(dest, recursive: true));
                SafeFile.WhenReleased(() => Directory.Move(Path.Combine(staging, e.Name), dest));
            }
            finally
            {
                if (Directory.Exists(staging)) Directory.Delete(staging, recursive: true);
            }
        }
    }

    private static void CopyDirectory(string from, string to)
    {
        foreach (var file in Directory.EnumerateFiles(from, "*", SearchOption.AllDirectories))
        {
            var dest = Path.Combine(to, Path.GetRelativePath(from, file));
            Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
            File.Copy(file, dest);
        }
    }
}
