using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Saved observation records are checked by their named addresses: same image hash, same name at each address.</summary>
public class ObservationRecordTests
{
    private const string Sha = "aa11bb22cc33dd44ee55ff6600778899aa11bb22cc33dd44ee55ff6600778899";

    private static EvidenceBundle.Record Record(string structured) =>
        new("r-0123456789ab", "live_break", "{}", [], "hash", "text", structured);

    private static readonly EvidenceBundle.Record Stop = Record(
        $$"""{"stop":"breakpoint","namedAddresses":[{"image":"app.exe","sha256":"{{Sha}}","rva":"0x1010","name":"Shop::Price"},{"image":"app.exe","sha256":"{{Sha}}","rva":"0x2040","name":"main"}]}""");

    [Fact]
    public void A_record_whose_names_still_resolve_matches()
    {
        var names = new Dictionary<uint, string> { [0x1010] = "Shop::Price", [0x2040] = "main" };
        var check = EvidenceBundle.CheckObservation(Stop, a => (Sha, names[a.Rva]));
        Assert.True(check.Matches, check.Detail);
        Assert.Equal("2 named addresses resolve to the same names in the same images", check.Detail);
    }

    [Fact]
    public void A_changed_image_another_name_or_a_missing_image_is_named()
    {
        Assert.Equal("app.exe is not loaded here", EvidenceBundle.CheckObservation(Stop, _ => (null, null)).Detail);
        Assert.StartsWith("app.exe changed: SHA-256 aa11bb22cc33… then, 000000000000… now", EvidenceBundle.CheckObservation(Stop, _ => (new string('0', 64), "x")).Detail);
        var renamed = EvidenceBundle.CheckObservation(Stop, a => (Sha, a.Rva == 0x1010 ? "Shop::Cost" : "main"));
        Assert.False(renamed.Matches);
        Assert.Equal("app.exe rva 0x1010 was Shop::Price, now Shop::Cost", renamed.Detail);
    }

    [Fact]
    public void A_record_without_named_addresses_cannot_be_checked()
    {
        var check = EvidenceBundle.CheckObservation(Record("""{"stop":"exit"}"""), _ => throw new InvalidOperationException());
        Assert.False(check.Matches);
        Assert.Contains("names no addresses", check.Detail);
    }
}
