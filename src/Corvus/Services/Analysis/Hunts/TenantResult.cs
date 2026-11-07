using System.Globalization;
using System.Text;
using System.Text.Json;
using Corvus.Core;

namespace Corvus.Services.Analysis.Hunts;

/// <summary>
/// What the tenant holds about one file: a signature seen on devices. A null count is unknown; a signer cut or
/// stripped on reading is marked <paramref name="SignerChanged"/> and never written into a query.
/// </summary>
public sealed record TenantSignature(string Type, string? Signer, bool? Trusted, int? Devices, string? FirstSeen, string? LastSeen, bool SignerChanged = false);

/// <summary>Devices that wrote, started or loaded a file, from one table; a null count is unknown, and zero is a count over the retention window, not absence.</summary>
public sealed record TenantReach(string Table, int? Devices, string? FirstSeen, string? LastSeen, string Status);

/// <summary>The tenant facts joined to one file; a source with no row in the result is absent from the lists and unknown.</summary>
public sealed record TenantFacts(string Sha1, string ResultSaved, IReadOnlyList<TenantSignature> Signatures, IReadOnlyList<TenantReach> Reach, IReadOnlyList<string> Notes);

/// <summary>The outcome of reading a saved result: the joined facts, or null with a note why not; <see cref="Refused"/> names input that is not a result.</summary>
public sealed record TenantRead(TenantFacts? Facts, string? Refused, IReadOnlyList<string> Notes);

/// <summary>Writes the tenant query of a file by SHA-1 and reads the JSON result a person saved from running it.</summary>
public static class TenantResult
{
    /// <summary>The id prefix of the tenant query.</summary>
    public const string IdPrefix = "tenant-";

    /// <summary>The longest saved result read, in bytes.</summary>
    public const long MaxBytes = 16 << 20;

    /// <summary>Rows a result may hold; a longer one is refused, since a row past the limit could name another file.</summary>
    public const int MaxRows = 1_000;

    /// <summary>Advanced hunting keeps 30 days of events.</summary>
    public const string Window = "30 days";

    private const string Certificates = "DeviceFileCertificateInfo";
    private const int MaxText = 200;

    // Each event table with the words a status uses for it.
    private static readonly (string Table, string Label)[] Events =
        [("DeviceFileEvents", "file events"), ("DeviceProcessEvents", "process events"), ("DeviceImageLoadEvents", "image load events")];

    /// <summary>
    /// The read-only query of a file by <paramref name="sha1"/>: signature type, trust and signer, and the devices that
    /// wrote, started or loaded it. Each row names its table and the SHA-1 it was run for. Throws for a SHA-1 that is not 40 hex digits.
    /// </summary>
    public static Hunt Query(string sha1)
    {
        if (sha1.Length != 40 || !sha1.All(char.IsAsciiHexDigit)) throw new ArgumentException("The SHA-1 is not 40 hex digits.", nameof(sha1));
        sha1 = sha1.ToLowerInvariant();
        var hash = KqlHunts.Literal(sha1);
        string Branch(string table, string by) =>
            $"({table}\n| where SHA1 == {hash}\n| summarize Devices = dcount(DeviceId), FirstSeen = min(Timestamp), LastSeen = max(Timestamp){by}\n" +
            $"| extend Source = {KqlHunts.Literal(table)}, Queried = {hash})";
        var branches = new[] { Branch(Certificates, " by SignatureType, IsTrusted, Signer") }.Concat(Events.Select(e => Branch(e.Table, "")));
        var kql = "union\n" + string.Join(",\n", branches);
        return new Hunt($"{IdPrefix}{sha1[..8]}", $"Tenant facts of SHA-1 {sha1[..12]}", Certificates, kql, [$"{HuntKind.Sha1}:{sha1}"], IndicatorEvidence.Computed)
            { HuntingOnly = true };
    }

    /// <summary>
    /// Joins the JSON result of <see cref="Query"/> to the file with <paramref name="sha1"/>; <paramref name="saved"/> is when
    /// the result was saved. Never throws: bytes that are not a result, or a result over <see cref="MaxRows"/> rows, set
    /// <see cref="TenantRead.Refused"/>, and a result for another SHA-1 or with no rows is not joined and says so in the notes.
    /// </summary>
    public static TenantRead Read(ReadOnlySpan<byte> bytes, string sha1, DateTimeOffset saved)
    {
        sha1 = sha1.ToLowerInvariant();
        JsonDocument doc;
        try { doc = InputJson.ParseDocument(bytes.ToArray()); }
        catch (JsonException e) { return new(null, $"The result is not valid JSON: {Clean(e.Message).Text}", []); }
        using var owner = doc;
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
        if (rows.GetArrayLength() > MaxRows) return new(null, $"The result has {rows.GetArrayLength():N0} rows, over {MaxRows:N0}: save the result of the tenant query.", []);

        var notes = new List<string>();
        var queried = new HashSet<string>(StringComparer.Ordinal);
        var signatures = new List<TenantSignature>();
        var reach = new Dictionary<string, TenantReach>(StringComparer.Ordinal);
        var duplicated = new HashSet<string>(StringComparer.Ordinal);
        int count = 0, other = 0, unnamed = 0;
        foreach (var row in rows.EnumerateArray())
        {
            if (row.ValueKind != JsonValueKind.Object) continue;
            count++;
            var source = Field(row, "Source").Text;
            var hash = Field(row, "Queried").Text?.ToLowerInvariant();
            if (hash == null) unnamed++; else queried.Add(hash);
            var devices = Number(row, "Devices");
            var first = Field(row, "FirstSeen").Text;
            var last = Field(row, "LastSeen").Text;
            if (source == Certificates)
            {
                var signer = Field(row, "Signer");
                var type = Field(row, "SignatureType").Text;
                if (type != null || signer.Text != null || devices != null)
                    signatures.Add(new(type ?? "Unknown", signer.Text, Flag(row, "IsTrusted"), devices, first, last, signer.Changed));
            }
            else if (Events.FirstOrDefault(e => e.Table == source) is { Table: not null } e)
            {
                var entry = new TenantReach(e.Table, devices, devices > 0 ? first : null, devices > 0 ? last : null,
                    devices == null ? "unknown" : devices > 0 ? "seen" : $"not seen in {e.Label} in {Window} on onboarded devices");
                // A count that is known and larger beats a later zero or an unknown value.
                if (reach.TryGetValue(e.Table, out var earlier))
                {
                    duplicated.Add(e.Table);
                    if ((earlier.Devices ?? -1) >= (entry.Devices ?? -1)) continue;
                }
                reach[e.Table] = entry;
            }
            else other++;
        }
        if (count == 0) return new(null, null, ["The result has no rows: not joined. The query returns a row for each event table, so this is not its result."]);
        if (unnamed > 0) return new(null, null, [$"{unnamed:N0} row(s) name no SHA-1 (Queried): not joined. Run the query Corvus wrote."]);
        if (queried.Any(q => q != sha1))
            return new(null, null, [$"The result is for SHA-1 {Clean(queried.First(q => q != sha1)).Text}, not {sha1}: not joined."]);
        if (other > 0) notes.Add($"{other:N0} row(s) name a table the query does not read and were ignored.");
        foreach (var table in duplicated.Order(StringComparer.Ordinal)) notes.Add($"{table}: more than one row; the larger count is kept.");
        foreach (var (table, _) in Events)
        {
            if (!reach.TryGetValue(table, out var r)) notes.Add($"{table}: no row in the result, so devices are unknown.");
            else if (r.Devices == null) notes.Add($"{table}: Devices is missing or is not a whole number, so devices are unknown.");
        }
        if (signatures.Count == 0) notes.Add($"{Certificates}: no row, so the signature is unknown: the file is unsigned or no device reported it in {Window}.");
        if (signatures.Any(s => s.Signer != null && s.Trusted != true))
            notes.Add("A signature row with a signer is not marked trusted: its signer is reported and not taken as the file's signer.");
        if (signatures.Any(s => s.SignerChanged))
            notes.Add("A signer was cut or had characters removed on reading: no signer query is written from it.");
        return new(new TenantFacts(sha1, saved.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture), signatures, [.. reach.Values.OrderBy(r => r.Table, StringComparer.Ordinal)], notes), null, []);
    }

    /// <summary>The signer of the trusted signature seen on most devices, or null when no trusted row names one or the name was changed on reading.</summary>
    public static string? Signer(TenantFacts facts) =>
        facts.Signatures.Where(s => s.Signer != null && s.Trusted == true && !s.SignerChanged)
            .OrderByDescending(s => s.Devices ?? -1).Select(s => s.Signer).FirstOrDefault();

    /// <summary>One line each for the signatures and the reach of <paramref name="facts"/>, with the time the result was saved; text is escaped for Markdown.</summary>
    public static IReadOnlyList<string> Lines(TenantFacts facts)
    {
        var head = $"Tenant (result saved {facts.ResultSaved}): ";
        var lines = new List<string>();
        foreach (var s in facts.Signatures)
            lines.Add(head + Format.EscapeMarkdown(s.Type.ToLowerInvariant()) + " signature" + (s.Signer != null ? $" by {Format.EscapeMarkdown(s.Signer)}" : "")
                + (s.Trusted is { } t ? t ? ", trusted" : ", not trusted" : ", trust unknown") + $", {Devices(s.Devices)}.");
        if (facts.Reach.Count == Events.Length && facts.Reach.All(r => r.Devices == 0))
            lines.Add(head + $"not seen in file, process or image load events in {Window} on onboarded devices.");
        else
            foreach (var r in facts.Reach)
                lines.Add(head + $"{r.Table} " + (r.Devices > 0 ? $"{Devices(r.Devices)}, first {Format.EscapeMarkdown(r.FirstSeen ?? "unknown")}, last {Format.EscapeMarkdown(r.LastSeen ?? "unknown")}" : r.Status) + ".");
        return lines;
    }

    private static string Devices(int? n) => n == null ? "devices unknown" : $"seen on {n:N0} device{(n == 1 ? "" : "s")}";

    // A value of a saved result is data: it is looked up without regard to case, and read as text only from a string or a number.
    private static (string? Text, bool Changed) Field(JsonElement row, string name)
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
            return string.IsNullOrWhiteSpace(text) ? (null, false) : Clean(text);
        }
        return (null, false);
    }

    // Only a whole number of zero or more is a count; anything else is unknown, never zero.
    private static int? Number(JsonElement row, string name)
    {
        foreach (var p in row.EnumerateObject())
        {
            if (!p.Name.Equals(name, StringComparison.OrdinalIgnoreCase)) continue;
            long n = -1;
            bool whole = p.Value.ValueKind == JsonValueKind.Number ? p.Value.TryGetInt64(out n)
                : p.Value.ValueKind == JsonValueKind.String && long.TryParse(p.Value.GetString(), NumberStyles.None, CultureInfo.InvariantCulture, out n);
            return whole && n >= 0 ? (int)Math.Min(n, int.MaxValue) : null;
        }
        return null;
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

    // Control and format characters (line breaks, bidi overrides, zero-width marks) go, an unpaired surrogate becomes U+FFFD
    // and the text is cut; Changed says any of that happened.
    private static (string Text, bool Changed) Clean(string value)
    {
        var sb = new StringBuilder();
        bool changed = false;
        value = value.Trim();
        for (int i = 0; i < value.Length; i++)
        {
            if (sb.Length >= MaxText) { sb.Append("..."); changed = true; break; }
            var c = value[i];
            if (char.IsHighSurrogate(c) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1])) { sb.Append(c).Append(value[++i]); continue; }
            if (char.IsSurrogate(c)) { sb.Append('�'); changed = true; continue; }
            if (char.GetUnicodeCategory(c) == UnicodeCategory.Format) { changed = true; continue; }
            if (char.IsControl(c)) { sb.Append(' '); changed = true; continue; }
            sb.Append(c);
        }
        return (sb.ToString(), changed);
    }
}
