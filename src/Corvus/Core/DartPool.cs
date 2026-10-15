using System.ComponentModel;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace Corvus.Core;

/// <summary>A string of a Dart AOT snapshot at its file offset (inside the AOT image).</summary>
public sealed record DartString(long Offset,
    [property: Description("package-uri, dart-uri or identifier.")] string Kind, string Value);

/// <summary>A package the snapshot's package: URIs name.</summary>
public sealed record DartPackage(string Name,
    [property: Description("app (holds main.dart), flutter (Flutter SDK) or pub.")] string Kind,
    [property: Description("From a pub cache path the snapshot carries; null when none does.")] string? Version,
    int Uris);

/// <summary>The strings of an isolate snapshot: distinct URIs and identifier tokens in file order, and the packages and dart: libraries they name.</summary>
public sealed record DartPool(long Start, long End, IReadOnlyList<DartString> Strings, IReadOnlyList<DartPackage> Packages, IReadOnlyList<string> Libraries,
    int PackageUris, int DartUris, int Identifiers,
    [property: Description("More distinct strings than the cap: the rest are counted, not kept.")] bool Capped);

/// <summary>
/// The string pool of a Dart AOT isolate snapshot. Strings are stored as a varint length ((length &lt;&lt; 1) | one-byte flag in
/// Dart 3, the plain length before) and their bytes; the scan takes printable runs between the snapshot's bounds, so it needs
/// no knowledge of the version's cluster layout. Runs whose last byte is the next string's length continuation are trimmed.
/// </summary>
public static partial class DartPoolScan
{
    public const int MaxStrings = 200_000;
    private const int MaxRun = 4096;

    private static readonly HashSet<string> FlutterPackages = new(StringComparer.Ordinal)
    {
        "flutter", "flutter_localizations", "flutter_web_plugins", "flutter_driver", "flutter_test", "integration_test", "sky_engine",
    };

    /// <summary>The isolate snapshot of an app image: the one _kDartIsolateSnapshotData names, else the second AOT snapshot (the first is the VM's).</summary>
    public static DartSnapshot? Isolate(IReadOnlyList<DartSnapshot> snapshots) =>
        snapshots.FirstOrDefault(s => s.Symbol == "kDartIsolateSnapshotData")
        ?? (snapshots.Count(s => s.Kind == "full-aot") > 1 ? snapshots.Where(s => s.Kind == "full-aot").ElementAt(1) : snapshots.LastOrDefault());

    public static DartPool Read(ReadOnlySpan<byte> data, DartSnapshot isolate, CancellationToken ct = default)
    {
        int start = (int)Math.Clamp(isolate.Offset, 0, data.Length);
        int end = (int)Math.Clamp(isolate.Offset + 4 + isolate.Length, start, data.Length);
        var seen = new HashSet<ulong>(); // 64-bit hashes of the bytes: a repeat is never decoded
        var strings = new List<DartString>();
        var packages = new Dictionary<string, int>(StringComparer.Ordinal);
        var versions = new Dictionary<string, string>(StringComparer.Ordinal);
        var libraries = new SortedSet<string>(StringComparer.Ordinal);
        string? app = null;
        int packageUris = 0, dartUris = 0, identifiers = 0;
        bool capped = false;

        void Add(int offset, string kind, ReadOnlySpan<byte> bytes)
        {
            if (!seen.Add(System.IO.Hashing.XxHash3.HashToUInt64(bytes))) return;
            var value = Encoding.ASCII.GetString(bytes);
            switch (kind)
            {
                case "package-uri":
                    packageUris++;
                    var name = value[8..value.IndexOf('/')];
                    packages[name] = packages.GetValueOrDefault(name) + 1;
                    if (value.EndsWith("/main.dart", StringComparison.Ordinal) && value.Count(c => c == '/') == 1) app ??= name;
                    break;
                case "dart-uri":
                    dartUris++;
                    libraries.Add("dart:" + LibraryName(value.AsSpan(5)));
                    break;
                default:
                    identifiers++;
                    break;
            }
            if (strings.Count < MaxStrings) strings.Add(new DartString(offset, kind, value));
            else capped = true;
        }

        int i = start, runs = 0;
        while (i < end)
        {
            if ((++runs & 0xFFFF) == 0) ct.ThrowIfCancellationRequested();
            int skip = data[i..end].IndexOfAnyInRange((byte)0x20, (byte)0x7E);
            if (skip < 0) break;
            int s = i + skip;
            int length = data[s..end].IndexOfAnyExceptInRange((byte)0x20, (byte)0x7E);
            i = length < 0 ? end : s + length;
            int stop = i;
            // A length of 64 or more takes two bytes: the first (< 0x80) may be printable and end this run.
            if (stop + 1 < end && data[stop] >= 0x80 && stop - s > 1)
            {
                int encoded = data[stop - 1] | ((data[stop] - 0x80) << 7);
                var next = data[(stop + 1)..Math.Min(end, stop + 2 + MaxRun)];
                int nextLength = next.IndexOfAnyExceptInRange((byte)0x20, (byte)0x7E) is var x and >= 0 ? x : next.Length;
                if (nextLength >= 64 && (encoded >> 1 == nextLength || encoded == nextLength)) stop--;
            }
            int n = stop - s;
            if (n < 2 || n > MaxRun) continue;
            var run = data[s..stop];
            if (run.IndexOfAny((byte)':', (byte)'.') < 0) { if (IsIdentifier(run) && (n >= 4 || LengthBefore(data, s, n))) Add(s, "identifier", run); }
            else if (run.IndexOf("package:"u8) is var p and >= 0) Uri(run, p, s, "package-uri", 8);
            else if (run.IndexOf("dart:"u8) is var dp and >= 0) Uri(run, dp, s, "dart-uri", 5);
            else if (run.IndexOf("pub."u8) >= 0) Version(run);
            else if (IsIdentifier(run) && (n >= 4 || LengthBefore(data, s, n))) Add(s, "identifier", run);
        }

        void Uri(ReadOnlySpan<byte> run, int at, int runStart, string kind, int prefix)
        {
            int e = at + prefix;
            while (e < run.Length && UriChar(run[e])) e++;
            var body = run[(at + prefix)..e];
            if (body.Length == 0 || !IsAsciiLetterOrUnderscore(body[0])) return;
            // a run may continue past the URI: cut after the last ".dart"
            if (body.LastIndexOf(".dart"u8) is var dot and >= 0 && dot + 5 < body.Length) body = body[..(dot + 5)];
            if (kind == "package-uri" && (body.IndexOf((byte)'/') is var slash && slash <= 0 || !PackageName(body[..slash]))) return;
            Add(runStart + at, kind, run.Slice(at, prefix + body.Length));
        }

        void Version(ReadOnlySpan<byte> run)
        {
            var text = Encoding.ASCII.GetString(run);
            foreach (Match m in PubPath().Matches(text)) versions.TryAdd(m.Groups[1].Value, m.Groups[2].Value);
        }

        foreach (var (name, version) in versions)
            if (!packages.ContainsKey(name)) packages[name] = 0;
        var list = packages.Select(kv => new DartPackage(kv.Key, kv.Key == app ? "app" : FlutterPackages.Contains(kv.Key) ? "flutter" : "pub",
                versions.GetValueOrDefault(kv.Key), kv.Value))
            .OrderBy(x => x.Kind switch { "app" => 0, "pub" => 1, _ => 2 }).ThenBy(x => x.Name, StringComparer.Ordinal).ToList();
        return new DartPool(start, end, strings, list, [.. libraries], packageUris, dartUris, identifiers, capped);
    }

    private static bool Printable(byte b) => b is >= 0x20 and <= 0x7E;

    private static bool UriChar(byte b) => b is (>= (byte)'a' and <= (byte)'z') or (>= (byte)'A' and <= (byte)'Z') or (>= (byte)'0' and <= (byte)'9')
        or (byte)'_' or (byte)'.' or (byte)'/' or (byte)'-' or (byte)'+' or (byte)'%';

    private static bool IsAsciiLetterOrUnderscore(byte b) => b is (>= (byte)'a' and <= (byte)'z') or (>= (byte)'A' and <= (byte)'Z') or (byte)'_';

    private static bool PackageName(ReadOnlySpan<byte> name)
    {
        if (name.Length == 0 || !IsAsciiLetterOrUnderscore(name[0])) return false;
        foreach (var b in name)
            if (!(b is (>= (byte)'a' and <= (byte)'z') or (>= (byte)'0' and <= (byte)'9') or (byte)'_' or (>= (byte)'A' and <= (byte)'Z'))) return false;
        return true;
    }

    private static string LibraryName(ReadOnlySpan<char> rest)
    {
        int n = 0;
        while (n < rest.Length && (char.IsAsciiLetterOrDigit(rest[n]) || rest[n] == '_')) n++;
        return rest[..n].ToString();
    }

    /// <summary>A Dart name: get:/set: accessors, letters, digits, _ and $, and the @key of a library-private name.</summary>
    private static bool IsIdentifier(ReadOnlySpan<byte> s)
    {
        if (s.StartsWith("get:"u8) || s.StartsWith("set:"u8)) s = s[4..];
        if (s.IndexOf((byte)'@') is var at and > 0)
        {
            var key = s[(at + 1)..];
            if (key.Length == 0) return false;
            foreach (var b in key)
                if (b is < (byte)'0' or > (byte)'9') return false;
            s = s[..at];
        }
        if (s.Length == 0 || !(IsAsciiLetterOrUnderscore(s[0]) || s[0] == '$')) return false;
        foreach (var b in s)
            if (!(b is (>= (byte)'a' and <= (byte)'z') or (>= (byte)'A' and <= (byte)'Z') or (>= (byte)'0' and <= (byte)'9') or (byte)'_' or (byte)'$')) return false;
        return true;
    }

    /// <summary>Whether the byte before a short run is its one-byte length (Dart 3: (n &lt;&lt; 1) | 1, earlier: n), which keeps 2- and 3-letter names out of the noise.</summary>
    private static bool LengthBefore(ReadOnlySpan<byte> data, int start, int n) =>
        start > 0 && (data[start - 1] == 0x80 + ((n << 1) | 1) || data[start - 1] == 0x80 + n);

    // ".pub-cache/hosted/pub.dev/http-1.2.1/lib/..." (pub.dartlang.org before 2023)
    [GeneratedRegex(@"pub\.(?:dev|dartlang\.org)/([a-z_][a-z0-9_]*)-(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-+]+)?)/")]
    private static partial Regex PubPath();

    /// <summary>
    /// The Dart AOT image of a file: the file itself, else an APK's lib/&lt;abi&gt;/libapp.so (arm64-v8a first) or an .ipa's
    /// Payload/X.app/Frameworks/App.framework/App; null when there is none. <paramref name="inner"/> names the entry.
    /// </summary>
    public static byte[]? AppImage(byte[] file, out string? inner, long maxBytes = 1L << 30)
    {
        inner = null;
        if (!Blob.StartsWith(file, "PK\x03\x04"u8)) return file;
        return AppImage(new MemoryStream(file, false), out inner, maxBytes);
    }

    /// <summary>The app image of an APK or .ipa read from a seekable stream: its directory, then that one entry.</summary>
    public static byte[]? AppImage(Stream package, out string? inner, long maxBytes = 1L << 30)
    {
        inner = null;
        try
        {
            using var zip = new ZipArchive(package, ZipArchiveMode.Read, leaveOpen: true);
            var entry = zip.Entries.Where(e => IsAppEntry(e.FullName)).OrderBy(e => e.FullName.Contains("arm64", StringComparison.Ordinal) ? 0 : 1)
                .ThenBy(e => e.FullName, StringComparer.Ordinal).FirstOrDefault();
            if (entry == null || entry.Length > maxBytes) return null;
            inner = entry.FullName;
            using var s = entry.Open();
            return Blob.ReadBounded(s, maxBytes);
        }
        catch (InvalidDataException) { return null; }
    }

    internal static bool IsAppEntry(string name) =>
        (name.StartsWith("lib/", StringComparison.Ordinal) && name.EndsWith("/libapp.so", StringComparison.Ordinal))
        || (name.StartsWith("Payload/", StringComparison.Ordinal) && name.EndsWith(".app/Frameworks/App.framework/App", StringComparison.Ordinal));
}
