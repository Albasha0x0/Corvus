using System.Text.Json;
using System.Text.RegularExpressions;

namespace Corvus.Services.Web.Packages;

public static partial class PackageReview
{
    /// <summary>Script events Composer runs while installing or updating.</summary>
    private static readonly string[] ComposerInstallEvents = ["pre-install-cmd", "post-install-cmd", "pre-update-cmd", "post-update-cmd", "post-autoload-dump"];

    private static readonly Regex PhpCallback = R(@"^\\?[A-Za-z_][\w\\]*::[A-Za-z_]\w*$");

    private static PackageReport? Composer(PackageFiles files, CancellationToken ct)
    {
        var manifestPath = Root(files, "composer.json")!;
        var root = Folder(manifestPath);
        if (Json(files, manifestPath) is not { ValueKind: JsonValueKind.Object } pkg) return null;
        var findings = new List<PackageFinding>();
        var notes = new List<string>();
        var scripts = new List<PackageScript>();
        var psr4 = Psr4(pkg);
        if (pkg.TryGetProperty("scripts", out var s) && s.ValueKind == JsonValueKind.Object)
            foreach (var p in s.EnumerateObject())
            {
                var commands = p.Value.ValueKind == JsonValueKind.String ? [p.Value.GetString()!]
                    : p.Value.ValueKind == JsonValueKind.Array ? p.Value.EnumerateArray().Where(c => c.ValueKind == JsonValueKind.String).Select(c => c.GetString()!).ToList()
                    : [];
                bool atInstall = ComposerInstallEvents.Contains(p.Name, StringComparer.Ordinal);
                foreach (var command in commands)
                {
                    scripts.Add(new PackageScript(p.Name, command, atInstall));
                    if (!atInstall) continue;
                    // Composer runs only the root project's scripts, so the script
                    // alone is info; the code rules below set the level.
                    findings.Add(new PackageFinding("package/install-script", "info", "install script", $"{p.Name}: {Clip(command)}", manifestPath));
                    if (PhpCallback.IsMatch(command))
                    {
                        if (CallbackFile(files, root, psr4, command) is { } file && files.Text(file) is { } code)
                            findings.AddRange(Scan(file, code, install: true, ct));
                        else notes.Add($"{p.Name} calls {command}, whose file was not resolved in the package");
                        continue;
                    }
                    findings.AddRange(Scan(manifestPath + "#scripts." + p.Name, command, install: true, ct));
                    if (NetworkCommand.IsMatch(command))
                        findings.Add(new PackageFinding("package/install-network-tool", "noteworthy", "install script", $"{p.Name} runs a network tool: {Clip(command, 160)}", manifestPath));
                }
            }
        int requires = pkg.TryGetProperty("require", out var r) && r.ValueKind == JsonValueKind.Object ? r.EnumerateObject().Count() : 0;
        return new PackageReport("composer", Str(pkg, "name"), Str(pkg, "version"))
        {
            Description = Clip(Str(pkg, "description")), Scripts = scripts, Dependencies = requires, Findings = findings, Notes = notes,
        };
    }

    /// <summary>
    /// autoload.psr-4 as (namespace prefix, folders) pairs, longest prefix
    /// first.
    /// </summary>
    private static List<(string Prefix, List<string> Folders)> Psr4(JsonElement pkg)
    {
        var map = new List<(string, List<string>)>();
        if (pkg.TryGetProperty("autoload", out var a) && a.ValueKind == JsonValueKind.Object && a.TryGetProperty("psr-4", out var p) && p.ValueKind == JsonValueKind.Object)
            foreach (var e in p.EnumerateObject())
            {
                var folders = e.Value.ValueKind == JsonValueKind.String ? [e.Value.GetString()!]
                    : e.Value.ValueKind == JsonValueKind.Array ? e.Value.EnumerateArray().Where(f => f.ValueKind == JsonValueKind.String).Select(f => f.GetString()!).ToList()
                    : [];
                map.Add((e.Name, folders));
            }
        return [.. map.OrderByDescending(m => m.Item1.Length)];
    }

    /// <summary>
    /// The package file a Class::method callback names under autoload.psr-4, or
    /// null when the package does not hold it.
    /// </summary>
    private static string? CallbackFile(PackageFiles files, string root, List<(string Prefix, List<string> Folders)> psr4, string callback)
    {
        var type = callback[..callback.IndexOf("::", StringComparison.Ordinal)].TrimStart('\\');
        foreach (var (prefix, folders) in psr4)
        {
            if (!type.StartsWith(prefix, StringComparison.Ordinal)) continue;
            var rest = type[prefix.Length..].Replace('\\', '/') + ".php";
            foreach (var folder in folders)
                if (Resolve(root, folder.TrimEnd('/') + "/" + rest) is var file && files.Has(file)) return file;
        }
        return null;
    }
}
