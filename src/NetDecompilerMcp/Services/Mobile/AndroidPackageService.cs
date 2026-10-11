using System.ComponentModel;
using System.Text;
using System.Text.RegularExpressions;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Core.Mobile;

namespace NetDecompilerMcp.Services.Mobile;

public sealed record AndroidResourceList(IReadOnlyList<ResourceRow> Items, int Offset, int Total, bool Truncated,
    [property: Description("Resource types with their entry counts, for narrowing with type.")] IReadOnlyDictionary<string, int> Types);

/// <summary>An Android package at a glance, for summarize_file.</summary>
public sealed record AndroidPackageFacts(string Kind, string Package, string? VersionName, string? VersionCode, int? MinSdk, int? TargetSdk,
    [property: Description("Runtimes found in the package, each with its evidence.")] IReadOnlyList<AndroidRuntimeFamily> Runtimes,
    IReadOnlyList<string> Abis, int DexFiles, long DexBytes, int Permissions, int Components, int ExportedComponents,
    [property: Description("Signature verdict (verified, mismatch, unsigned, unsupported_algorithm) and schemes (v4 from the .idsig beside the file); an .aab has v1 only.")] string? Signature,
    [property: Description("One line per signer: scheme, certificate, SDK range, verdict with reasons, rotation lineage with capabilities.")] IReadOnlyList<string> Signers,
    IReadOnlyList<string> SplitApks, IReadOnlyList<string> Highlights);

/// <summary>Android packages: manifest, resources and package facts, read natively from .apk / .aab / split sets.</summary>
public sealed class AndroidPackageService(OutputPager pager, JavaDotNetMap? dotnet = null)
{
    /// <summary>The manifest summary; in a .NET for Android package each component names the .NET type that implements it.</summary>
    public AndroidManifestSummary Manifest(string path, CancellationToken ct = default)
    {
        AndroidManifestSummary summary;
        bool dotnetApp;
        using (var p = AndroidPackage.Open(path))
        {
            summary = AndroidManifestSummary.Of(p.Manifest, p.Resources);
            dotnetApp = AndroidRuntime.Detect(p).Any(r => r.Family == "dotnet-android");
        }
        if (dotnet == null || !dotnetApp) return summary;
        var types = dotnet.ComponentTypes(path, ct);
        if (types.Count == 0) return summary;
        return summary with { Components = [.. summary.Components.Select(c => types.TryGetValue(c.Name, out var t) ? c with { DotNetType = t } : c)] };
    }

    public AndroidResourceList Resources(string path, string? type, string? name, string? config, int offset, int limit)
    {
        using var p = AndroidPackage.Open(path);
        var table = p.Resources ?? throw new ToolError(ErrorCode.NotFound, $"{p.Path} has no resource table (resources.arsc / resources.pb).");
        var all = table.Rows.ToList();
        var types = all.GroupBy(r => r.Type).OrderBy(g => g.Key, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.Count());
        var namePattern = name is { Length: > 0 } ? Wildcard(name) : null;
        string? wanted = config?.Trim() is { Length: > 0 } c ? c.Equals("default", StringComparison.OrdinalIgnoreCase) ? "" : c : null;
        var rows = all.Where(r => (type is not { Length: > 0 } || r.Type.Equals(type.Trim().TrimStart('@'), StringComparison.Ordinal))
                                  && (namePattern == null || namePattern.IsMatch(r.Name))
                                  && (wanted == null || r.Config.Equals(wanted, StringComparison.OrdinalIgnoreCase)))
            .OrderBy(r => r.Id).ThenBy(r => r.Config, StringComparer.Ordinal).ToList();
        limit = Math.Clamp(limit, 1, 5_000);
        offset = Math.Max(0, offset);
        var page = rows.Skip(offset).Take(limit).ToList();
        return new AndroidResourceList(page, offset, rows.Count, offset + page.Count < rows.Count, types);
    }

    private static Regex Wildcard(string pattern) =>
        new("^" + Regex.Escape(pattern.Trim()).Replace(@"\*", ".*", StringComparison.Ordinal).Replace(@"\?", ".", StringComparison.Ordinal) + "$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeouts.Limit);

    /// <summary>A file entry (binary XML decoded) or a resource's values; savePath writes the entry's bytes.</summary>
    public string Resource(string path, string name, string? savePath, bool overwrite, int offset, int? maxChars)
    {
        using var p = AndroidPackage.Open(path);
        name = name.Trim();
        string entry;
        string? header = null;
        if (name.StartsWith('@') || name.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            var table = p.Resources ?? throw new ToolError(ErrorCode.NotFound, $"{p.Path} has no resource table.");
            var (id, rows) = Lookup(table, name);
            var files = rows.Where(r => r.ValueType == "file").Select(r => r.Value).Distinct().ToList();
            if (files.Count == 0 || savePath == null && rows.Any(r => r.ValueType != "file"))
            {
                var text = new StringBuilder($"{table.Name(id) ?? name} (0x{id:x8}): {rows.Count} value(s)\n");
                foreach (var r in rows) text.AppendLine($"  [{(r.Config.Length == 0 ? "default" : r.Config)}] {r.ValueType}: {r.Value}");
                if (files.Count > 0) text.AppendLine($"Files: {string.Join(", ", files)} (pass one as name to read it).");
                return pager.Page(text.ToString(), offset, maxChars);
            }
            entry = files[0];
            if (files.Count > 1) header = $"{table.Name(id)}: {files.Count} files by configuration ({string.Join(", ", files)}); showing {entry}.\n";
        }
        else entry = name.TrimStart('/');

        var bytes = p.Read(entry) ?? throw new ToolError(ErrorCode.NotFound, $"{entry} is not in {p.Path}.",
            "list_android_resources lists resources; get_android_manifest the manifest; use a path such as res/xml/network_security_config.xml or assets/...")
        {
            Details = new { similar = p.Entries.Where(e => e.Contains(Path.GetFileNameWithoutExtension(entry), StringComparison.OrdinalIgnoreCase)).Take(10).ToList() },
        };
        if (savePath != null)
        {
            var written = SafeFile.WriteAllBytes(savePath, bytes, overwrite);
            return $"Wrote {entry} ({bytes.Length:N0} bytes, SHA-256 {Blob.Sha256(bytes)}) to {written}.";
        }
        var res = p.Resources;
        string body;
        bool protoXml = p.Kind == "aab" && entry.EndsWith(".xml", StringComparison.OrdinalIgnoreCase) && (entry.StartsWith("res/", StringComparison.Ordinal) || entry == "AndroidManifest.xml");
        if (AxmlDocument.IsAxml(bytes) || protoXml)
        {
            var doc = protoXml ? AabProto.ReadXml(bytes) : AxmlDocument.Read(bytes);
            body = doc.ToXml(res == null ? null : res.Name) + string.Concat(doc.Issues.Select(i => $"<!-- issue: {i.Message} -->\n"));
        }
        else if (Blob.LooksLikeText(bytes)) body = Encoding.UTF8.GetString(bytes);
        else
        {
            var kind = Blob.Identify(bytes);
            body = $"{entry}: {bytes.Length:N0} bytes, {kind}, SHA-256 {Blob.Sha256(bytes)}; pass savePath to write it.\n" + Hex(bytes.AsSpan(0, Math.Min(256, bytes.Length)));
        }
        return pager.Page((header ?? "") + body, offset, maxChars);
    }

    private static (uint Id, List<ResourceRow> Rows) Lookup(IResourceTable table, string name)
    {
        uint id;
        if (name.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            if (!uint.TryParse(name[2..], System.Globalization.NumberStyles.HexNumber, null, out id))
                throw new ToolError(ErrorCode.InvalidArgument, $"'{name}' is not a resource id; use 0x7f010000 or @type/name.");
        }
        else
        {
            var body = name.TrimStart('@');
            if (body.Contains(':', StringComparison.Ordinal)) body = body[(body.IndexOf(':', StringComparison.Ordinal) + 1)..];
            var slash = body.IndexOf('/', StringComparison.Ordinal);
            if (slash <= 0) throw new ToolError(ErrorCode.InvalidArgument, $"'{name}' is not a resource name; use @type/name, e.g. @string/app_name.");
            id = table.Find(body[..slash], body[(slash + 1)..])
                 ?? throw new ToolError(ErrorCode.NotFound, $"no resource {name} in the package.", "list_android_resources with type and name (wildcards) finds it");
        }
        var rows = table.Rows.Where(r => r.Id == id).ToList();
        if (rows.Count == 0) throw new ToolError(ErrorCode.NotFound, $"no resource 0x{id:x8} in the package.");
        return (id, rows);
    }

    private static string Hex(ReadOnlySpan<byte> b)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < b.Length; i += 16)
        {
            var row = b.Slice(i, Math.Min(16, b.Length - i));
            sb.Append($"{i:x8}  ").AppendJoin(' ', row.ToArray().Select(x => x.ToString("x2", System.Globalization.CultureInfo.InvariantCulture))).Append('\n');
        }
        return sb.ToString();
    }

    private static byte[]? Idsig(string path)
    {
        try
        {
            var idsig = path + ".idsig";
            return File.Exists(idsig) && new FileInfo(idsig).Length <= 64 << 20 ? File.ReadAllBytes(idsig) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    internal static IReadOnlyList<string> Signers(ApkSignatureReport report)
    {
        static string Name(ApkCertificate c) => $"{c.Subject} (SHA-256 {c.Sha256[..16]}...)";
        var lines = new List<string>();
        foreach (var scheme in report.Schemes)
            for (int i = 0; i < scheme.Signers.Count; i++)
            {
                var s = scheme.Signers[i];
                var line = new StringBuilder($"{scheme.Scheme} signer {i + 1}");
                if (s.Extends != null) line.Append($" (for {s.Extends})");
                line.Append($": {(s.Certificates.FirstOrDefault() is { } c ? Name(c) : "no certificate")}");
                if (s.MinSdk != null) line.Append($", SDK {s.MinSdk}{(s.MaxSdk is { } max && max != int.MaxValue ? $"-{max}" : "+")}");
                if (s.RotationMinSdk != null) line.Append($", rotated signer from SDK {s.RotationMinSdk}");
                line.Append($", {s.Verdict}");
                if (s.Reasons.Count > 0) line.Append($" ({string.Join("; ", s.Reasons)})");
                if (s.Lineage.Count > 0)
                    line.Append("; lineage ").Append(string.Join(" -> ", s.Lineage.Select(n => $"{n.Certificate.Subject} [{string.Join(", ", n.Capabilities)}]")));
                lines.Add(line.ToString());
            }
        return lines;
    }

    /// <summary>Package facts for summarize_file; null when <paramref name="path"/> is not an Android package.</summary>
    public static AndroidPackageFacts? Facts(string path, byte[] bytes, CancellationToken ct)
    {
        AndroidPackage p;
        try { p = AndroidPackage.Open(path); }
        catch (ToolError) { return null; }
        using (p)
        {
            ct.ThrowIfCancellationRequested();
            AndroidManifestSummary? manifest = null;
            var highlights = new List<string>(p.Notes);
            try { manifest = AndroidManifestSummary.Of(p.Manifest, p.Resources); }
            catch (ToolError ex) { highlights.Add($"The manifest cannot be read: {ex.Message}"); }
            var dex = p.DexFiles;
            string? signature = null;
            IReadOnlyList<string> signers = [];
            if (p.Kind is "apk" or "aab")
            {
                bool bundle = p.Kind == "aab";
                var report = ApkSigning.Verify(bytes, bundle ? null : Idsig(path));
                var schemes = report.Schemes.Select(s => $"{s.Scheme} {s.Verdict}").ToList();
                if (bundle) schemes.Add("an app bundle is signed at upload with a JAR (v1) signature; the store signs the APKs it generates");
                signature = $"{report.Verdict} ({string.Join(bundle ? "; " : ", ", schemes)})";
                signers = Signers(report);
                if (report.Verdict != ApkSigning.Verified && !(bundle && report.Verdict == ApkSigning.Unsigned))
                    highlights.Add($"{(bundle ? "Bundle" : "APK")} signature: {signature}.");
                if (report.Schemes.SelectMany(s => s.Signers).SelectMany(s => s.Certificates).Any(c => c.Subject.Contains("CN=Android Debug", StringComparison.Ordinal)))
                    highlights.Add("Signed with the Android debug certificate.");
            }
            highlights.AddRange(manifest?.Highlights ?? []);
            return new AndroidPackageFacts(p.Kind, manifest?.Package ?? "", manifest?.VersionName, manifest?.VersionCode, manifest?.MinSdk, manifest?.TargetSdk,
                AndroidRuntime.Detect(p), p.Abis, dex.Count, dex.Sum(p.Length), manifest?.Permissions.Count ?? 0, manifest?.Components.Count ?? 0,
                manifest?.Components.Count(c => c.EffectiveExported) ?? 0, signature, signers, p.SplitApks, highlights);
        }
    }
}
