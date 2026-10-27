using System.Globalization;
using System.Text.Json.Nodes;

namespace Corvus.Tools;

/// <summary>Observation records of a running program, checked by their named addresses: same image SHA-256, same name at each address.</summary>
public static partial class EvidenceBundle
{
    /// <summary>Tools whose saved records are observations of a running program.</summary>
    public static readonly IReadOnlySet<string> ObservationTools = new HashSet<string>(StringComparer.Ordinal)
    {
        "live_session", "live_break", "live_watch", "live_read", "live_events", "live_script", "live_coverage", "live_timeline", "live_console",
    };

    /// <summary>The field of an observation record that lists its named addresses.</summary>
    public const string NamedAddressesField = "namedAddresses";

    /// <summary>An address an observation named: the image by its SHA-256, the RVA in it and the name it had.</summary>
    public sealed record NamedAddress(string Image, string Sha256, uint Rva, string Name);

    /// <summary>What a named address is now: the SHA-256 of the image with that id (null when none is loaded) and the name at the RVA.</summary>
    public delegate (string? Sha256, string? Name) ResolveNamedAddress(NamedAddress address);

    /// <summary>The named addresses of an observation record; empty when it lists none or its record is not JSON.</summary>
    public static IReadOnlyList<NamedAddress> NamedAddresses(Record r)
    {
        if (r.Structured == null) return [];
        JsonNode? root;
        try { root = JsonNode.Parse(r.Structured); }
        catch (System.Text.Json.JsonException) { return []; }
        if (root?[NamedAddressesField] is not JsonArray list) return [];
        var result = new List<NamedAddress>();
        foreach (var item in list)
            if (item?["image"]?.GetValue<string>() is { } image && item["sha256"]?.GetValue<string>() is { } sha && item["rva"]?.GetValue<string>() is { } rva
                && item["name"]?.GetValue<string>() is { } name
                && uint.TryParse(rva.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? rva[2..] : rva, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out uint at))
                result.Add(new NamedAddress(image, sha, at, name));
        return result;
    }

    /// <summary>One observation record checked by its named addresses against the images loaded now.</summary>
    public static Check CheckObservation(Record r, ResolveNamedAddress resolve)
    {
        var addresses = NamedAddresses(r);
        if (addresses.Count == 0)
            return new(r.Id, r.Tool, false, "an observation of a running program cannot be repeated, and this record names no addresses to check");
        var differs = new List<string>();
        foreach (var a in addresses)
        {
            var (sha, name) = resolve(a);
            if (sha == null) differs.Add($"{a.Image} is not loaded here");
            else if (!string.Equals(sha, a.Sha256, StringComparison.OrdinalIgnoreCase)) differs.Add($"{a.Image} changed: SHA-256 {a.Sha256[..Math.Min(12, a.Sha256.Length)]}… then, {sha[..Math.Min(12, sha.Length)]}… now");
            else if (name != a.Name) differs.Add($"{a.Image} rva 0x{a.Rva:X} was {a.Name}, now {name ?? "unnamed"}");
        }
        return differs.Count == 0
            ? new(r.Id, r.Tool, true, $"{addresses.Count} named address{(addresses.Count == 1 ? "" : "es")} resolve to the same names in the same images")
            : new(r.Id, r.Tool, false, string.Join("; ", differs.Distinct().Take(10)) + (differs.Count > 10 ? $"; {differs.Count - 10} more" : ""));
    }
}
