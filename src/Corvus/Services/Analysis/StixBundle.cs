using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Corvus.Services.Analysis;

/// <summary>Writes a summarize_file result as a STIX 2.1 bundle: file and network observables and one malware-analysis object, no verdict.</summary>
public static class StixBundle
{
    public const string SpecVersion = "2.1";

    // The namespace STIX 2.1 section 2.9 fixes for observable ids; other objects must not use it.
    private static readonly Guid ObservableNamespace = new("00abedb4-aa42-466c-9c01-fed23315a9b7");

    // Corvus's own namespace, so its identity has one id in every bundle.
    private static readonly Guid CorvusNamespace = new("5b0e8c3a-2f4d-4c1e-9a6b-7d3f1e2c4b5a");

    // The identity is the same object in every bundle, so its timestamps are fixed.
    private const string IdentityCreated = "2026-10-24T00:00:00.000Z";

    private static readonly Dictionary<string, string> ValueTypes = new(StringComparer.Ordinal)
    {
        ["url"] = "url", ["domain"] = "domain-name", ["ipv4"] = "ipv4-addr", ["ipv6"] = "ipv6-addr", ["email"] = "email-addr",
    };

    // A custom observable: STIX 2.1 has no object for a TLS client fingerprint.
    private const string Fingerprint = "x-tls-fingerprint";

    private sealed record Observable(string Id, string Type, Dictionary<string, object> Properties, SortedSet<string> Locations);

    /// <summary>The bundle as UTF-8 JSON; observable ids are stable UUIDv5, the analysis and bundle ids are the given UUIDv4 values.</summary>
    public static byte[] Write(InspectionService.FileSummary summary, string toolVersion, DateTimeOffset timestamp, Guid analysis, Guid bundle)
    {
        var observables = new Dictionary<string, Observable>(StringComparer.Ordinal);
        var notes = new List<string>();
        var file = summary.File;
        int networkValues = 0;
        bool cut = false;
        // The STIX TLSH hash is the 70 digits without the "T1" version prefix.
        var sampleHashes = Hashes(("MD5", file.Md5), ("SHA-1", file.Sha1), ("SHA-256", file.Sha256), ("IMPHASH", file.Imphash), ("TLSH", file.Tlsh?[2..]));
        var sample = FileObject(sampleHashes, Path.GetFileName(file.Path), null);
        sample.Properties["size"] = file.Size;

        foreach (var a in summary.Assemblies)
        {
            if (!a.Sha256.Equals(file.Sha256, StringComparison.OrdinalIgnoreCase) && Hashes(("SHA-256", a.Sha256)) is { Count: > 0 } memberHashes)
                Add(observables, FileObject(memberHashes, Path.GetFileName(a.Path), a.Path));
            foreach (var c in a.Wrapping.Contents)
            {
                if (Hashes(("SHA-256", c.Sha256)) is not { Count: > 0 } contentHashes) continue;
                var content = FileObject(contentHashes, null, $"{a.Path}: {c.Source}");
                content.Properties["size"] = c.Size;
                content.Properties["x_corvus_kind"] = c.Kind;
                Add(observables, content);
            }
            // NetworkValues holds them all when the summary was read for a bundle; else only the summary's top values are known.
            foreach (var v in a.NetworkValues ?? a.Values.Top)
            {
                if (!ValueTypes.TryGetValue(v.Type, out var type)) continue;
                if (++networkValues > InspectionService.MaxNetworkValues) { cut = true; break; }
                var value = new Dictionary<string, object> { ["value"] = v.Value };
                IEnumerable<string> locations = v.Locations.Count == 0 ? [a.Path] : v.Locations.Select(l => $"{a.Path}: {l}");
                Add(observables, new Observable(ObservableId(type, value), type, value, new SortedSet<string>(locations, StringComparer.Ordinal)));
            }
            if (a.NetworkValues == null && a.Values.Total > a.Values.Top.Count)
                notes.Add($"{a.Path}: {a.Values.Top.Count} of {a.Values.Total} extracted values listed; extract_strings lists all.");
        }
        foreach (var h in summary.Views.OrderBy(v => v.Key, StringComparer.Ordinal).SelectMany(v => v.Value.Indicators))
        {
            if (++networkValues > InspectionService.MaxNetworkValues) { cut = true; break; }
            var where = h.Location == null ? h.Source : $"{h.Source}: {h.Location}";
            if (h.Type is "ja3" or "ja4")
            {
                var print = new Dictionary<string, object> { ["algorithm"] = h.Type.ToUpperInvariant(), ["value"] = h.Value };
                Add(observables, new Observable($"{Fingerprint}--{Uuid5(CorvusNamespace, Canonical(print))}", Fingerprint, print, new SortedSet<string>([where], StringComparer.Ordinal)));
            }
            else if (ValueTypes.TryGetValue(h.Type, out var type))
            {
                var value = new Dictionary<string, object> { ["value"] = h.Value };
                Add(observables, new Observable(ObservableId(type, value), type, value, new SortedSet<string>([where], StringComparer.Ordinal)));
            }
        }
        if (cut) notes.Add($"Partial: URLs, domains and IP addresses past the first {InspectionService.MaxNetworkValues:N0} are not listed.");
        if (summary.Assemblies.Count == 0 && !summary.Views.Values.Any(v => v.Indicators.Count > 0))
            notes.Add("URLs, domains and IP addresses not checked: summarize_file reads them from managed assemblies only.");

        var identity = $"identity--{Uuid5(CorvusNamespace, "corvus")}";
        var analysisId = $"malware-analysis--{analysis:D}";
        var stamp = timestamp.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
        var found = observables.Values.OrderBy(o => o.Type, StringComparer.Ordinal).ThenBy(o => o.Id, StringComparer.Ordinal).ToList();
        if (found.Count > 0) sample.Properties["contains_refs"] = found.Select(o => o.Id).ToList();

        using var stream = new MemoryStream();
        using (var w = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
        {
            w.WriteStartObject();
            w.WriteString("type", "bundle");
            w.WriteString("id", $"bundle--{bundle:D}");
            w.WriteStartArray("objects");

            w.WriteStartObject();
            w.WriteString("type", "identity");
            w.WriteString("spec_version", SpecVersion);
            w.WriteString("id", identity);
            w.WriteString("created", IdentityCreated);
            w.WriteString("modified", IdentityCreated);
            w.WriteString("name", "Corvus");
            w.WriteString("identity_class", "system");
            w.WriteString("description", "Static file reader; nothing it reads is executed.");
            w.WriteEndObject();

            w.WriteStartObject();
            w.WriteString("type", "malware-analysis");
            w.WriteString("spec_version", SpecVersion);
            w.WriteString("id", analysisId);
            w.WriteString("created_by_ref", identity);
            w.WriteString("created", stamp);
            w.WriteString("modified", stamp);
            w.WriteString("product", "corvus");
            w.WriteString("version", toolVersion);
            w.WriteString("analysis_ended", stamp);
            w.WriteString("description", string.Join(" ", notes.Prepend("summarize_file read the file statically; no verdict is given.")));
            w.WriteString("sample_ref", sample.Id);
            // The schema needs analysis_sco_refs or result; with nothing found, result says no verdict was reached.
            if (found.Count > 0)
            {
                w.WriteStartArray("analysis_sco_refs");
                foreach (var o in found) w.WriteStringValue(o.Id);
                w.WriteEndArray();
            }
            else w.WriteString("result", "unknown");
            w.WriteEndObject();

            WriteObservable(w, sample);
            foreach (var o in found) WriteObservable(w, o);
            w.WriteEndArray();
            w.WriteEndObject();
        }
        return stream.ToArray();
    }

    /// <summary>The non-empty hashes, lower case, by their STIX hash names.</summary>
    private static Dictionary<string, string> Hashes(params (string Name, string? Value)[] hashes) =>
        hashes.Where(h => !string.IsNullOrEmpty(h.Value)).ToDictionary(h => h.Name, h => h.Name == "TLSH" ? h.Value! : h.Value!.ToLowerInvariant(), StringComparer.Ordinal);

    private static Observable FileObject(Dictionary<string, string> hashes, string? name, string? location)
    {
        var properties = new Dictionary<string, object> { ["hashes"] = hashes };
        if (!string.IsNullOrEmpty(name)) properties["name"] = name;
        // Section 2.9: of several hashes only the first of MD5, SHA-1, SHA-256 contributes to the id.
        var chosen = new[] { "MD5", "SHA-1", "SHA-256" }.First(hashes.ContainsKey);
        var contributing = new Dictionary<string, object> { ["hashes"] = new Dictionary<string, string> { [chosen] = hashes[chosen] } };
        if (properties.TryGetValue("name", out var n)) contributing["name"] = n;
        var locations = new SortedSet<string>(StringComparer.Ordinal);
        if (location != null) locations.Add(location);
        return new Observable(ObservableId("file", contributing), "file", properties, locations);
    }

    private static void Add(Dictionary<string, Observable> observables, Observable o)
    {
        if (observables.TryGetValue(o.Id, out var known)) known.Locations.UnionWith(o.Locations);
        else observables[o.Id] = o;
    }

    private static void WriteObservable(Utf8JsonWriter w, Observable o)
    {
        w.WriteStartObject();
        w.WriteString("type", o.Type);
        w.WriteString("spec_version", SpecVersion);
        w.WriteString("id", o.Id);
        foreach (var (key, value) in o.Properties) { w.WritePropertyName(key); JsonSerializer.Serialize(w, value); }
        if (o.Locations.Count > 0)
        {
            w.WriteStartArray("x_corvus_locations");
            foreach (var l in o.Locations) w.WriteStringValue(l);
            w.WriteEndArray();
        }
        w.WriteEndObject();
    }

    /// <summary>The STIX id of an observable: its type, then UUIDv5 over the JCS form (RFC 8785) of its id contributing properties.</summary>
    internal static string ObservableId(string type, Dictionary<string, object> contributing) =>
        $"{type}--{Uuid5(ObservableNamespace, Canonical(contributing))}";

    /// <summary>RFC 8785 canonical JSON of string-keyed objects whose leaves are strings.</summary>
    private static string Canonical(object value)
    {
        var sb = new StringBuilder();
        void Write(object v)
        {
            if (v is string s) { Quote(sb, s); return; }
            // JCS orders keys by their UTF-16 code units.
            var entries = v switch
            {
                Dictionary<string, object> d => d.Select(e => (e.Key, Value: e.Value)),
                Dictionary<string, string> d => d.Select(e => (e.Key, Value: (object)e.Value)),
                _ => throw new ArgumentException($"no canonical form for {v.GetType().Name}"),
            };
            sb.Append('{');
            bool first = true;
            foreach (var (key, item) in entries.OrderBy(e => e.Key, StringComparer.Ordinal))
            {
                if (!first) sb.Append(',');
                first = false;
                Quote(sb, key);
                sb.Append(':');
                Write(item);
            }
            sb.Append('}');
        }
        Write(value);
        return sb.ToString();
    }

    private static void Quote(StringBuilder sb, string s)
    {
        sb.Append('"');
        foreach (var c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case < ' ': sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture)); break;
                default: sb.Append(c); break;
            }
        }
        sb.Append('"');
    }

    /// <summary>The RFC 9562 name-based (SHA-1) UUID of <paramref name="name"/>'s UTF-8 bytes in <paramref name="ns"/>.</summary>
    internal static Guid Uuid5(Guid ns, string name)
    {
        var input = new byte[16 + Encoding.UTF8.GetByteCount(name)];
        ns.TryWriteBytes(input, bigEndian: true, out _);
        Encoding.UTF8.GetBytes(name, input.AsSpan(16));
        var hash = SHA1.HashData(input);
        hash[6] = (byte)(hash[6] & 0x0F | 0x50);
        hash[8] = (byte)(hash[8] & 0x3F | 0x80);
        return new Guid(hash.AsSpan(0, 16), bigEndian: true);
    }
}
