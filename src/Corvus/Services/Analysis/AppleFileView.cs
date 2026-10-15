using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Core.Mobile;
using Corvus.Native.MachO;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=apple: an Apple bundle, from an .ipa (Payload/X.app, read in memory) or from a Mach-O inside an .app, .appex or
/// .framework folder (summarize_file given the folder summarizes its main executable): what Info.plist declares, each
/// Mach-O with its role and a signature verdict per slice, the main executable's entitlements and the provisioning profile.
/// </summary>
internal sealed class AppleFileView : IFileSummaryView
{
    private const int MaxFiles = 50_000, MaxBinaries = 40;

    public sealed record Facts(string Bundle, string Kind, string? Identifier, string? Version, string? Build, string? Executable, string? MinimumOs,
        IReadOnlyList<string>? UrlSchemes, IReadOnlyList<string>? UsageDescriptions, IReadOnlyList<string>? BackgroundModes, bool? ArbitraryLoads,
        string? UpdateFeed, IReadOnlyList<Binary> Binaries, IReadOnlyList<string>? Entitlements, Profile? Provisioning, IReadOnlyList<string> Notes);

    /// <summary>A Mach-O of the bundle: its path inside it, its role and one signature verdict per slice.</summary>
    public sealed record Binary(string Path, string Role, IReadOnlyList<SliceSignature> Signatures);

    public sealed record SliceSignature(string Slice, string Verdict, string? Identifier, string? TeamId);

    /// <summary>embedded.mobileprovision / embedded.provisionprofile: its kind by devices and get-task-allow.</summary>
    public sealed record Profile(string? Name, string? Team, string Kind, string? Expires, int Devices);

    public string Name => "apple";

    /// <summary>The main executable of a bundle folder (.app, .appex, .framework), or null.</summary>
    public static string? MainExecutable(string folder)
    {
        var full = Path.GetFullPath(folder).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!Directory.Exists(full) || !IsBundleName(full)) return null;
        var source = Source.Folder(full);
        return source.Read(source.InfoPlist, 4 << 20) is { } plist && Plist.Read(plist).Root is PlistDict info && Str(info, "CFBundleExecutable") is { } exe
               && source.Executable(exe) is { } relative && File.Exists(Path.Combine(full, relative)) ? Path.Combine(full, relative) : null;
    }

    /// <summary>An .ipa's Info.plist and main executable (path in the app, bytes up to <paramref name="max"/>), or null.</summary>
    internal static (PlistDict Info, string Executable, byte[] Bytes)? IpaApp(byte[] ipa, long max)
    {
        if (Source.Ipa(ipa) is not { } source || source.Read(source.InfoPlist, 4 << 20) is not { } plist || Plist.Read(plist).Root is not PlistDict info
            || Str(info, "CFBundleExecutable") is not { } exe || source.Read(exe, max) is not { } bytes) return null;
        return (info, $"Payload/{source.Root}/{exe}", bytes);
    }

    /// <summary>The Info.plist of the .app, .appex or .framework folder a file sits in, or null.</summary>
    internal static PlistDict? BundleInfo(string path)
    {
        for (var dir = Path.GetDirectoryName(Path.GetFullPath(path)); dir != null; dir = Path.GetDirectoryName(dir))
            if (IsBundleName(dir))
            {
                var plist = new[] { Path.Combine(dir, "Info.plist"), Path.Combine(dir, "Contents", "Info.plist") }.FirstOrDefault(File.Exists);
                return plist != null && new FileInfo(plist).Length <= 4 << 20 && Plist.Read(File.ReadAllBytes(plist)).Root is PlistDict info ? info : null;
            }
        return null;
    }

    private static bool IsBundleName(string path) =>
        path.EndsWith(".app", StringComparison.OrdinalIgnoreCase) || path.EndsWith(".appex", StringComparison.OrdinalIgnoreCase) || path.EndsWith(".framework", StringComparison.OrdinalIgnoreCase);

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        Source? source = null;
        if (file.Kind == "zip") source = file.HasZipEntry(n => n.StartsWith("Payload/", StringComparison.Ordinal)) ? Source.Ipa(file.OpenRead()) : null;
        else if (file.Kind == "mach-o")
            for (var dir = Path.GetDirectoryName(file.Path); dir != null && source == null; dir = Path.GetDirectoryName(dir))
                if (IsBundleName(dir)) source = Source.Folder(dir);
        using var archive = source;
        if (source == null || source.Read(source.InfoPlist, 4 << 20) is not { } plistBytes || Plist.Read(plistBytes).Root is not PlistDict info) return null;
        var notes = new List<string>();
        var exe = Str(info, "CFBundleExecutable");
        var mainPath = exe != null ? source.Executable(exe) : null;
        var binaries = new List<Binary>();
        IReadOnlyList<string>? entitlements = null;
        int machO = 0;
        foreach (var path in source.Files)
        {
            ct.ThrowIfCancellationRequested();
            if (!Candidate(path, mainPath) || source.Read(path, 64) is not { } head || Blob.Identify(head) != "mach-o") continue;
            if (++machO > MaxBinaries) continue;
            if (source.Read(path, AnalysisLimits.Default.MaxItemBytes) is not { } bytes) { notes.Add($"{path}: too large to read"); continue; }
            bool main = path == mainPath;
            var signatures = new List<SliceSignature>();
            try
            {
                var slices = MachOFat.Read(bytes);
                foreach (var name in slices.Count > 0 ? slices.Select(s => (string?)s.Name) : [null])
                {
                    var image = MachOFile.FromBytes(bytes, path, name);
                    var verdict = SignatureVerdict.Of(image, main ? plistBytes : null);
                    signatures.Add(new SliceSignature(name ?? image.MachineName, verdict.Verdict, verdict.Identifier, verdict.TeamId));
                    if (main && entitlements == null && image.CodeSignature?.Entitlements is { } xml) entitlements = Entitlements(xml);
                }
            }
            catch (ToolError e) { notes.Add($"{path}: {e.Message}"); }
            binaries.Add(new Binary(path, main ? "main executable" : Role(path), signatures));
        }
        if (machO > MaxBinaries) notes.Add($"{machO} Mach-O files; the first {MaxBinaries} are listed");
        if (mainPath != null && !binaries.Any(b => b.Path == mainPath)) notes.Add($"the main executable {mainPath} is missing");
        var profile = source.Read(source.Ios ? "embedded.mobileprovision" : "Contents/embedded.provisionprofile", 4 << 20) is { } p ? ReadProfile(p) : null;
        var kind = (source.Root.EndsWith(".appex", StringComparison.OrdinalIgnoreCase) ? "app extension" : source.Root.EndsWith(".framework", StringComparison.OrdinalIgnoreCase) ? "framework" : "app")
                   is var k && source.Ios ? $"iOS {k}" : $"macOS {k}";
        var ats = (info["NSAppTransportSecurity"] as PlistDict)?["NSAllowsArbitraryLoads"] is PlistBool { Value: var b } ? b : (bool?)null;
        var facts = new Facts(source.Root, kind, Str(info, "CFBundleIdentifier"), Str(info, "CFBundleShortVersionString"), Str(info, "CFBundleVersion"), exe,
            Str(info, "MinimumOSVersion") ?? Str(info, "LSMinimumSystemVersion"),
            Strings((info["CFBundleURLTypes"] as PlistArray)?.Items.OfType<PlistDict>().SelectMany(t => (t["CFBundleURLSchemes"] as PlistArray)?.Items ?? [])),
            Nonempty(info.Entries.Where(e => e.Key.EndsWith("UsageDescription", StringComparison.Ordinal)).Select(e => e.Key).ToList()),
            Strings((info["UIBackgroundModes"] as PlistArray)?.Items), ats, Str(info, "SUFeedURL"), binaries, entitlements, profile, notes);
        return new FileView(facts, Highlights(facts));
    }

    private static List<string> Highlights(Facts f)
    {
        var h = new List<string> { $"{f.Kind} {f.Bundle}" + (f.Identifier != null ? $" ({string.Join(" ", new[] { f.Identifier, f.Version }.OfType<string>())}{(f.Build != null ? $", build {f.Build}" : "")})" : "") +
                                   $": {f.Binaries.Count} Mach-O file(s): {string.Join(", ", f.Binaries.GroupBy(b => b.Role.Split(' ')[0]).Select(g => g.Count() > 1 ? $"{g.Count()} {g.Key}" : g.Key))}." };
        if (f.Binaries.FirstOrDefault(b => b.Role == "main executable") is { Signatures: [var first, ..] }) h.Add($"Main executable signature: {first.Verdict}.");
        var damaged = f.Binaries.Where(b => b.Signatures.Any(s => s.Verdict.StartsWith("damaged", StringComparison.Ordinal))).Select(b => b.Path).ToList();
        if (damaged.Count > 0) h.Add($"Modified after signing: {string.Join(", ", damaged.Take(5))}.");
        var risky = f.Entitlements?.Where(e => e.StartsWith("get-task-allow=true", StringComparison.Ordinal) || e.StartsWith("com.apple.security.cs.", StringComparison.Ordinal)
                                               || e.StartsWith("com.apple.private.", StringComparison.Ordinal) || e.StartsWith("com.apple.security.get-task-allow=true", StringComparison.Ordinal)).ToList();
        if (risky is { Count: > 0 }) h.Add($"Entitlements of note: {string.Join("; ", risky.Take(6))}.");
        if (f.Kind.StartsWith("macOS app", StringComparison.Ordinal) && f.Entitlements != null && !f.Entitlements.Contains("com.apple.security.app-sandbox=true")) h.Add("Not sandboxed (no com.apple.security.app-sandbox).");
        if (f.ArbitraryLoads == true) h.Add("App Transport Security allows arbitrary loads (plain HTTP).");
        if (f.UpdateFeed != null) h.Add($"Sparkle update feed: {f.UpdateFeed}.");
        if (f.Provisioning is { } p) h.Add($"Provisioning profile: {p.Kind}" + (p.Team != null ? $", team {p.Team}" : "") + (p.Expires != null ? $", expires {p.Expires}" : "") + ".");
        return h;
    }

    /// <summary>Files that can be Mach-O: no extension or .dylib, outside resource folders; the main executable always.</summary>
    private static bool Candidate(string path, string? main)
    {
        if (path == main) return true;
        if (path.Contains("/Resources/", StringComparison.Ordinal) || path.Contains(".lproj/", StringComparison.Ordinal) || path.Contains("/_CodeSignature/", StringComparison.Ordinal)
            || path.Contains("/Versions/Current/", StringComparison.Ordinal) || path.Contains("/Headers/", StringComparison.Ordinal)) return false;
        var name = path[(path.LastIndexOf('/') + 1)..];
        return !name.Contains('.') || name.EndsWith(".dylib", StringComparison.Ordinal) || name.EndsWith(".so", StringComparison.Ordinal);
    }

    private static string Role(string path)
    {
        string Nested(string ext) => path.Split('/').First(s => s.EndsWith(ext, StringComparison.Ordinal))[..^ext.Length];
        if (path.Contains(".appex/", StringComparison.Ordinal)) return $"app extension {Nested(".appex")}";
        if (path.Contains("/XPCServices/", StringComparison.Ordinal) || path.StartsWith("XPCServices/", StringComparison.Ordinal)) return "XPC service";
        if (path.Contains("Library/LoginItems/", StringComparison.Ordinal)) return "login item";
        if (path.StartsWith("Watch/", StringComparison.Ordinal) || path.Contains("/Watch/", StringComparison.Ordinal)) return "watch app";
        if (path.Contains(".framework/", StringComparison.Ordinal)) return $"framework {Nested(".framework")}";
        if (path.EndsWith(".dylib", StringComparison.Ordinal) || path.EndsWith(".so", StringComparison.Ordinal)) return "library";
        if (path.Contains(".app/", StringComparison.Ordinal)) return $"helper app {Nested(".app")}";
        return "helper executable";
    }

    private static IReadOnlyList<string> Entitlements(string xml)
    {
        if (Plist.Read(Encoding.UTF8.GetBytes(xml)).Root is not PlistDict d) return [];
        return d.Entries.Select(e => $"{e.Key}={Value(e.Value)}").ToList();
    }

    private static string Value(PlistNode n) => n switch
    {
        PlistBool b => b.Value ? "true" : "false",
        PlistString s => Format.Clip(s.Value, 120),
        PlistInteger i => i.Value.ToString(),
        PlistArray a => "[" + Format.Clip(string.Join(", ", a.Items.Select(Value)), 160) + "]",
        PlistDict d => "{" + Format.Clip(string.Join(", ", d.Entries.Select(e => e.Key)), 160) + "}",
        _ => n.GetType().Name.Replace("Plist", "").ToLowerInvariant(),
    };

    private static Profile? ReadProfile(byte[] cms)
    {
        // a CMS envelope around an XML plist: the plist is read where it sits, the signature is not checked
        int start = cms.AsSpan().IndexOf("<?xml"u8), end = cms.AsSpan().IndexOf("</plist>"u8);
        if (start < 0 || end < start || Plist.Read(cms.AsSpan(start, end + 8 - start)).Root is not PlistDict p) return null;
        int devices = (p["ProvisionedDevices"] as PlistArray)?.Items.Count ?? 0;
        bool all = p["ProvisionsAllDevices"] is PlistBool { Value: true };
        bool debug = (p["Entitlements"] as PlistDict)?["get-task-allow"] is PlistBool { Value: true };
        var kind = all ? "enterprise (all devices)" : debug ? $"development ({devices} devices)" : devices > 0 ? $"ad hoc ({devices} devices)" : "distribution";
        return new Profile(Str(p, "Name"), Str(p, "TeamName"), kind, p["ExpirationDate"] is PlistDate d ? d.Value.ToString("yyyy-MM-dd") : null, devices);
    }

    private static string? Str(PlistDict d, string key) => d[key] is PlistString { Value: { Length: > 0 } s } ? s : null;

    private static IReadOnlyList<string>? Strings(IEnumerable<PlistNode>? items) => Nonempty(items?.OfType<PlistString>().Select(s => s.Value).Distinct().ToList());

    private static IReadOnlyList<string>? Nonempty(List<string>? list) => list is { Count: > 0 } ? list : null;

    /// <summary>A bundle's files by relative path ('/'), from a folder or an .ipa's Payload/X.app.</summary>
    private sealed class Source : IDisposable
    {
        public required string Root { get; init; }
        /// <summary>The .ipa's archive, open while the source is read.</summary>
        public IDisposable? Archive { get; init; }

        public void Dispose() => Archive?.Dispose();
        public required bool Ios { get; init; }
        public required IReadOnlyList<string> Files { get; init; }
        public required Func<string, long, byte[]?> Read { get; init; }

        public string InfoPlist => Ios ? "Info.plist" : "Contents/Info.plist";

        public string? Executable(string name) => Ios ? name : $"Contents/MacOS/{name}";

        public static Source Folder(string dir)
        {
            bool ios = !Directory.Exists(Path.Combine(dir, "Contents"));
            var files = Directory.EnumerateFiles(dir, "*", new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = FileAttributes.ReparsePoint })
                .Take(MaxFiles).Select(f => Path.GetRelativePath(dir, f).Replace('\\', '/')).ToList();
            return new Source
            {
                Root = Path.GetFileName(dir), Ios = ios, Files = files,
                Read = (relative, max) =>
                {
                    var full = Path.Combine(dir, relative);
                    if (!File.Exists(full)) return null;
                    using var s = File.OpenRead(full);
                    if (s.Length > max && max > 64) return null;
                    var buffer = new byte[Math.Min(s.Length, max)];
                    s.ReadExactly(buffer);
                    return buffer;
                },
            };
        }

        public static Source? Ipa(byte[] bytes) => Ipa(new MemoryStream(bytes));

        /// <summary>An .ipa read from a seekable stream (its directory, then the entries asked for); the source owns the stream.</summary>
        public static Source? Ipa(Stream stream)
        {
            ZipArchive zip;
            try { zip = new ZipArchive(stream, ZipArchiveMode.Read); }
            catch (InvalidDataException) { stream.Dispose(); return null; }
            var app = zip.Entries.Select(e => e.FullName).FirstOrDefault(n => n.StartsWith("Payload/", StringComparison.Ordinal) && n.EndsWith(".app/Info.plist", StringComparison.Ordinal)
                                                                             && n.Count(c => c == '/') == 2);
            if (app == null) { zip.Dispose(); return null; }
            var prefix = app[..^"Info.plist".Length];
            var entries = zip.Entries.Where(e => e.FullName.StartsWith(prefix, StringComparison.Ordinal) && e.FullName.Length > prefix.Length && !e.FullName.EndsWith('/'))
                .Take(MaxFiles).ToDictionary(e => e.FullName[prefix.Length..], StringComparer.Ordinal);
            return new Source
            {
                Root = prefix["Payload/".Length..^1], Ios = true, Files = [.. entries.Keys], Archive = zip,
                Read = (relative, max) =>
                {
                    if (!entries.TryGetValue(relative, out var e) || (e.Length > max && max > 64)) return null;
                    try
                    {
                        using var s = e.Open();
                        var buffer = new byte[Math.Min(e.Length, max)];
                        s.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);
                        return buffer;
                    }
                    catch (InvalidDataException) { return null; } // a damaged entry reads as a missing one
                },
            };
        }
    }
}
