using System.Text.Json;

namespace Corvus.Services.Analysis.Dependencies;

/// <summary>Writes a <see cref="DependencyFacts"/> inventory as a CycloneDX 1.6 JSON bill of materials.</summary>
public static class CycloneDx
{
    public const string SpecVersion = "1.6";

    /// <summary>
    /// The BOM as UTF-8 JSON: metadata names the tool and the file (with its SHA-256) as the subject; every component
    /// keeps its evidence (identity confidence and method, occurrences); dependencies hold the edges.
    /// </summary>
    public static byte[] Write(DependencyFacts facts, string filePath, string fileSha256, string toolVersion, DateTimeOffset timestamp, Guid serial)
    {
        using var stream = new MemoryStream();
        using (var w = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
        {
            w.WriteStartObject();
            w.WriteString("bomFormat", "CycloneDX");
            w.WriteString("specVersion", SpecVersion);
            w.WriteString("serialNumber", $"urn:uuid:{serial:D}");
            w.WriteNumber("version", 1);

            w.WriteStartObject("metadata");
            w.WriteString("timestamp", timestamp.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture));
            w.WriteStartObject("tools");
            w.WriteStartArray("components");
            w.WriteStartObject();
            w.WriteString("type", "application");
            w.WriteString("name", "corvus");
            w.WriteString("version", toolVersion);
            w.WriteEndObject();
            w.WriteEndArray();
            w.WriteEndObject();
            var subject = facts.Subject;
            var subjectRef = subject?.Ref ?? "file";
            w.WriteStartObject("component");
            w.WriteString("type", subject?.Type ?? "file");
            w.WriteString("bom-ref", subjectRef);
            w.WriteString("name", subject?.Name ?? Path.GetFileName(filePath));
            if (subject?.Version != null) w.WriteString("version", subject.Version);
            Hashes(w, [new ComponentHash("SHA-256", fileSha256.ToLowerInvariant())]);
            if (subject?.Purl != null) w.WriteString("purl", subject.Purl);
            Properties(w, [("corvus:file", Path.GetFileName(filePath)), .. subject != null ? [("corvus:source", subject.Source)] : Array.Empty<(string, string)>()]);
            w.WriteEndObject();
            w.WriteEndObject();

            w.WriteStartArray("components");
            foreach (var c in facts.All) Component(w, c);
            w.WriteEndArray();

            w.WriteStartArray("dependencies");
            var known = new HashSet<string>(facts.All.Select(c => c.Ref).Append(subjectRef), StringComparer.Ordinal);
            // Only components whose dependencies were read get an entry: CycloneDX reads an empty dependsOn as none.
            foreach (var e in facts.Edges.Where(e => known.Contains(e.From)))
            {
                w.WriteStartObject();
                w.WriteString("ref", e.From);
                w.WriteStartArray("dependsOn");
                foreach (var to in e.To.Where(known.Contains)) w.WriteStringValue(to);
                w.WriteEndArray();
                w.WriteEndObject();
            }
            w.WriteEndArray();
            w.WriteEndObject();
        }
        return stream.ToArray();
    }

    private static void Component(Utf8JsonWriter w, DependencyComponent c)
    {
        w.WriteStartObject();
        w.WriteString("type", c.Type);
        w.WriteString("bom-ref", c.Ref);
        w.WriteString("name", c.Name);
        if (c.Version != null) w.WriteString("version", c.Version);
        if (c.Scope != null) w.WriteString("scope", c.Scope);
        Hashes(w, c.Hashes);
        if (c.Purl != null) w.WriteString("purl", c.Purl);
        w.WriteStartObject("evidence");
        w.WriteStartArray("identity");
        w.WriteStartObject();
        w.WriteString("field", c.Purl != null ? "purl" : c.Version != null ? "version" : "name");
        w.WriteNumber("confidence", c.Confidence);
        w.WriteStartArray("methods");
        w.WriteStartObject();
        w.WriteString("technique", c.Technique);
        w.WriteNumber("confidence", c.Confidence);
        w.WriteString("value", c.Source);
        w.WriteEndObject();
        w.WriteEndArray();
        w.WriteEndObject();
        w.WriteEndArray();
        if (c.Locations.Count > 0)
        {
            w.WriteStartArray("occurrences");
            foreach (var l in c.Locations)
            {
                w.WriteStartObject();
                w.WriteString("location", l);
                w.WriteEndObject();
            }
            w.WriteEndArray();
        }
        w.WriteEndObject();
        Properties(w, [("corvus:ecosystem", c.Ecosystem), .. c.Version == null ? [("corvus:version", "unknown")] : Array.Empty<(string, string)>(),
            .. c.AssemblyVersion != null ? [("corvus:assemblyVersion", c.AssemblyVersion)] : Array.Empty<(string, string)>()]);
        w.WriteEndObject();
    }

    private static void Hashes(Utf8JsonWriter w, IReadOnlyList<ComponentHash> hashes)
    {
        if (hashes.Count == 0) return;
        w.WriteStartArray("hashes");
        foreach (var h in hashes)
        {
            w.WriteStartObject();
            w.WriteString("alg", h.Algorithm);
            w.WriteString("content", h.Value);
            w.WriteEndObject();
        }
        w.WriteEndArray();
    }

    private static void Properties(Utf8JsonWriter w, IReadOnlyList<(string Name, string Value)> properties)
    {
        if (properties.Count == 0) return;
        w.WriteStartArray("properties");
        foreach (var (name, value) in properties)
        {
            w.WriteStartObject();
            w.WriteString("name", name);
            w.WriteString("value", value);
            w.WriteEndObject();
        }
        w.WriteEndArray();
    }
}
