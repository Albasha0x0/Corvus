using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>Fiddler .saz session archives: request and response heads per session; search_container kind=endpoint.</summary>
public sealed class SazTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _ws = new();
    public void Dispose() { _ws.Dispose(); _dir.Dispose(); }

    private static byte[] Archive(params (string Name, string Text)[] entries)
    {
        var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
            foreach (var (name, text) in entries)
            {
                using var s = zip.CreateEntry(name).Open();
                s.Write(Encoding.UTF8.GetBytes(text));
            }
        return ms.ToArray();
    }

    private static byte[] Sessions() => Archive(
        ("[Content_Types].xml", "<Types/>"),
        ("raw/01_c.txt", "GET https://api.example.com/users/42?token=secret HTTP/1.1\r\nHost: api.example.com\r\n\r\n"),
        ("raw/01_s.txt", "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\n\r\nbody"),
        ("raw/01_m.xml", "<Session/>"),
        ("raw/02_c.txt", "POST /v1/login HTTP/1.1\r\nHost: auth.example.com:443\r\nContent-Length: 2\r\n\r\n{}"),
        ("raw/02_s.txt", "HTTP/1.1 401 Unauthorized\r\n\r\n"),
        ("raw/10_c.txt", "CONNECT auth.example.com:443 HTTP/1.1\r\nHost: auth.example.com:443\r\n\r\n"),
        ("raw/03_c.txt", "GET https://api.example.com/users/7?token=other HTTP/1.1\r\nHost: api.example.com\r\n\r\n"),
        ("raw/03_s.txt", "HTTP/1.1 404 Not Found\r\n\r\n"));

    [Fact]
    public void Sessions_are_read_in_order_with_status_and_headers()
    {
        var bytes = Sessions();
        Assert.True(Saz.Looks(bytes));
        var r = Saz.Read(bytes);
        Assert.Equal(["GET https://api.example.com/users/42?token=secret 200", "POST https://auth.example.com/v1/login 401", "GET https://api.example.com/users/7?token=other 404",
            "CONNECT auth.example.com:443 0"], r.Select(x => $"{x.Method} {x.Url} {x.Status}"));
        Assert.Equal(("application/json", "gzip"), (r[0].MimeType, r[0].ContentEncoding));
    }

    [Fact]
    public void Endpoint_search_lists_saz_templates()
    {
        var path = _dir.File("capture.saz");
        File.WriteAllBytes(path, Sessions());
        var rows = new UnpackService(_ws).Search(path, "*", "endpoint", 100, AnalysisLimits.Default, default).Items.Select(m => $"{m.Name} | {m.Detail}").ToList();
        Assert.Contains("GET https://api.example.com/users/{n}?token=… | 2 request(s), status 200, 404", rows);
        Assert.Contains("POST https://auth.example.com/v1/login | 1 request(s), status 401", rows);
        Assert.Contains("CONNECT auth.example.com:443 | 1 request(s)", rows);
        Assert.DoesNotContain(rows, r => r.Contains("secret", StringComparison.Ordinal));
    }

    [Fact]
    public void Other_zips_are_not_saz() => Assert.False(Saz.Looks(Archive(("a.txt", "x"))));

    [Fact]
    public void Fuzzed_saz_never_throws()
    {
        var failures = FormatFuzz.Run(Sessions(), b => Saz.Read(b), 1500);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(5)));
    }
}
