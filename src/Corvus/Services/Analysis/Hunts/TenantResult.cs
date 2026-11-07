using System.Globalization;
using System.Text;
using System.Text.Json;
using Corvus.Core;

namespace Corvus.Services.Analysis.Hunts;

/// <summary>What the tenant holds about one file: a signature seen on devices.</summary>
public sealed record TenantSignature(string Type, string? Signer, bool? Trusted, int Devices, string? FirstSeen, string? LastSeen);

/// <summary>Devices that wrote or started a file, from one table; zero devices is a count over the retention window, not absence.</summary>
public sealed record TenantReach(string Table, int Devices, string? FirstSeen, string? LastSeen, string Status);

/// <summary>The tenant facts joined to one file; a source with no row in the result is absent from the lists and unknown.</summary>
public sealed record TenantFacts(string Sha1, string ResultSaved, IReadOnlyList<TenantSignature> Signatures, IReadOnlyList<TenantReach> Reach, IReadOnlyList<string> Notes);

/// <summary>The outcome of reading a saved result: the joined facts, or null with a note why not; <see cref="Refused"/> names input that is not a result.</summary>
public sealed record TenantRead(TenantFacts? Facts, string? Refused, IReadOnlyList<string> Notes);

/// <summary>Writes the tenant query of a file by SHA-1 and reads the JSON result a person saved from running it.</summary>
public static class TenantResult
{
    /// <summary>The longest saved result read, in bytes.</summary>
    public const long MaxBytes = 16 << 20;

    /// <summary>Rows read from one result; more are counted in a note.</summary>
    public const int MaxRows = 1_000;

    /// <summary>Advanced hunting keeps 30 days of events.</summary>
    public const string Window = "30 days";

    /// <summary>The id prefix of the tenant query.</summary>
    public const string IdPrefix = "tenant-";

    private const string Certificates = "DeviceFileCertificateInfo";
    private const string FileEvents = "DeviceFileEvents";
    private const string ProcessEvents = "DeviceProcessEvents";
    private const int MaxText = 200;

    private static readonly string NotSeen = $"not seen in {Window} on onboarded devices";

    /// <summary>
    /// The read-only query of a file by <paramref name="sha1"/>: signature type, trust and signer, and the devices that
    /// wrote or started it. Each row names its table and the SHA-1 it was run for. Throws for a SHA-1 that is not 40 hex digits.
    /// </summary>
    public static Hunt Query(string sha1)
    {
        if (sha1.Length != 40 || !sha1.All(char.IsAsciiHexDigit)) throw new ArgumentException("The SHA-1 is not 40 hex digits.", nameof(sha1));
        sha1 = sha1.ToLowerInvariant();
        var hash = KqlHunts.Literal(sha1);
        string Branch(string table, string by) =>
            $"({table}\n| where SHA1 == {hash}\n| summarize Devices = dcount(DeviceId), FirstSeen = min(Timestamp), LastSeen = max(Timestamp){by}\n" +
            $"| extend Source = {KqlHunts.Literal(table)}, Queried = {hash})";
        var kql = "union\n" + string.Join(",\n", Branch(Certificates, " by SignatureType, IsTrusted, Signer"), Branch(FileEvents, ""), Branch(ProcessEvents, ""));
        return new Hunt($"{IdPrefix}{sha1[..8]}", $"Tenant facts of SHA-1 {sha1[..12]}", Certificates, kql, [$"{HuntKind.Sha1}:{sha1}"], IndicatorEvidence.Computed)
            { HuntingOnly = true };
    }

    /// <summary>
    /// Joins the JSON result of <see cref="Query"/> to the file with <paramref name="sha1"/>; <paramref name="saved"/> is when
    /// the result was saved. Never throws: bytes that are not a result set <see cref="TenantRead.Refused"/>, and a result for
    /// another SHA-1 or with no rows is not joined and says so in the notes.
    /// </summary>
    public static TenantRead Read(ReadOnlySpan<byte> bytes, string sha1, DateTimeOffset saved)
    {
        sha1 = sha1.ToLowerInvariant();
        JsonDocument doc;
        try { doc = InputJson.ParseDocument(bytes.ToArray()); }
        catch (JsonException e) { return new(null, $"The result is not valid JSON: {Clean(e.Message)}", []); }
        using var _ = doc;
        var root = doc.RootElement;
        JsonElement rows = default;
        bool found = root.ValueKind == JsonValueKind.Array;
        if (found) rows = root;
        else if (root.ValueKind == JsonValueKind.Object)
            foreach (var p in root.EnumerateObject())
                if (p.Name.Equals("results", StringComparison.OrdinalIgnoreCase) && p.Value.ValueKind == JsonValueKind.Array)
                {
                    rows = p.Value;
                    found = true;
                    break;
                }
        if (!found) return new(null, "The result has no results array: save the JSON a hunting query returns.", []);

        var notes = new List<string>();
        var queried = new HashSet<string>(StringComparer.Ordinal);
        var signatures = new List<TenantSignature>();
        var reach = new Dictionary<string, TenantReach>(StringComparer.Ordinal);
        int count = 0, other = 0, unnamed = 0;
        bool truncated = false;
        foreach (var row in rows.EnumerateArray())
        {
            if (row.ValueKind != JsonValueKind.Object) continue;
            if (count == MaxRows) { truncated = true; break; }
            count++;
            var source = Text(row, "Source");
            var hash = Text(row, "Queried")?.ToLowerInvariant();
            if (hash == null) unnamed++; else queried.Add(hash);
            var devices = Number(row, "Devices");
            var first = Text(row, "FirstSeen");
            var last = Text(row, "LastSeen");
            switch (source)
            {
                case Certificates:
                    if (devices > 0 || first != null)
                        signatures.Add(new(Text(row, "SignatureType") ?? "Unknown", Text(row, "Signer"), Flag(row, "IsTrusted"), devices, first, last));
                    break;
                case FileEvents or ProcessEvents:
                    reach[source] = new(source, devices, devices > 0 ? first : null, devices > 0 ? last : null, devices > 0 ? "seen" : NotSeen);
                    break;
                default: other++; break;
            }
        }
        if (truncated) notes.Add($"Only the first {MaxRows:N0} rows were read.");
        if (count == 0) return new(null, null, ["The result has no rows: not joined. The query returns a row for each event table, so this is not its result."]);
        if (unnamed > 0) return new(null, null, [$"{unnamed:N0} row(s) name no SHA-1 (Queried): not joined. Run the query Corvus wrote."]);
        if (queried.Any(q => q != sha1))
            return new(null, null, [$"The result is for SHA-1 {Clean(queried.First(q => q != sha1))}, not {sha1}: not joined."]);
        if (other > 0) notes.Add($"{other:N0} row(s) name a table the query does not read and were ignored.");
        foreach (var table in new[] { FileEvents, ProcessEvents })
            if (!reach.ContainsKey(table)) notes.Add($"{table}: no row in the result, so devices are unknown.");
        if (signatures.Count == 0) notes.Add($"{Certificates}: no row, so the signature is unknown: the file is unsigned or no device reported it in {Window}.");
        return new(new TenantFacts(sha1, saved.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture), signatures, [.. reach.Values.OrderBy(r => r.Table, StringComparer.Ordinal)], notes), null, []);
    }

    /// <summary>The signer of the signature seen on most devices, or null when no row names one.</summary>
    public static string? Signer(TenantFacts facts) =>
        facts.Signatures.Where(s => s.Signer != null).OrderByDescending(s => s.Devices).Select(s => s.Signer).FirstOrDefault();

    /// <summary>One line each for the signatures and the reach of <paramref name="facts"/>, with the time the result was saved.</summary>
    public static IReadOnlyList<string> Lines(TenantFacts facts)
    {
        var lines = new List<string>();
        foreach (var s in facts.Signatures)
            lines.Add($"Tenant (result saved {facts.ResultSaved}): {s.Type.ToLowerInvariant()} signature" + (s.Signer != null ? $" by {s.Signer}" : "")
                + (s.Trusted is { } t ? t ? ", trusted" : ", not trusted" : "") + $", {Devices(s.Devices)}.");
        foreach (var r in facts.Reach)
            lines.Add($"Tenant (result saved {facts.ResultSaved}): {r.Table} {(r.Devices > 0 ? $"{Devices(r.Devices)}, first {r.FirstSeen ?? "unknown"}, last {r.LastSeen ?? "unknown"}" : r.Status)}.");
        return lines;
    }

    private static string Devices(int n) => $"seen on {n:N0} device{(n == 1 ? "" : "s")}";

    private static string? Text(JsonElement row, string name)
    {
        foreach (var p in row.EnumerateObject())
        {
            if (!p.Name.Equals(name, StringComparison.OrdinalIgnoreCase)) continue;
            var text = p.Value.ValueKind switch
            {
                JsonValueKind.String => p.Value.GetString(),
                JsonValueKind.Number => p.Value.GetRawText(),
                _ => null,
            };
            return string.IsNullOrWhiteSpace(text) ? null : Clean(text);
        }
        return null;
    }

    private static int Number(JsonElement row, string name)
    {
        foreach (var p in row.EnumerateObject())
        {
            if (!p.Name.Equals(name, StringComparison.OrdinalIgnoreCase)) continue;
            if (p.Value.ValueKind == JsonValueKind.Number && p.Value.TryGetInt64(out var n)) return (int)Math.Clamp(n, 0, int.MaxValue);
            if (p.Value.ValueKind == JsonValueKind.String && long.TryParse(p.Value.GetString(), NumberStyles.None, CultureInfo.InvariantCulture, out n)) return (int)Math.Clamp(n, 0, int.MaxValue);
        }
        return 0;
    }

    private static bool? Flag(JsonElement row, string name)
    {
        foreach (var p in row.EnumerateObject())
        {
            if (!p.Name.Equals(name, StringComparison.OrdinalIgnoreCase)) continue;
            if (p.Value.ValueKind is JsonValueKind.True or JsonValueKind.False) return p.Value.GetBoolean();
            if (p.Value.ValueKind == JsonValueKind.String && bool.TryParse(p.Value.GetString(), out var b)) return b;
        }
        return null;
    }

    // A value of a saved result is data: control characters go and the text is cut.
    private static string Clean(string value)
    {
        var sb = new StringBuilder();
        foreach (var c in value.Trim())
        {
            if (sb.Length >= MaxText) { sb.Append("..."); break; }
            sb.Append(char.IsControl(c) || char.IsSurrogate(c) ? ' ' : c);
        }
        return sb.ToString();
    }
}
