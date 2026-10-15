using Corvus.Core;
using Corvus.Services.Analysis;
using Corvus.Services.Analysis.Endpoints;
using Corvus.Services.Web;

namespace Corvus.Tests;

/// <summary>analyze_js view=endpoints and view=secrets, and the JavaScript rows of search_container kind=endpoint joined to a capture.</summary>
public sealed class JsEndpointsTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private static JsProgram Program(string text) => JsProgram.Build("app.js", text, [], default)!;

    private static List<string> Endpoints(string text)
    {
        var rows = new List<CodeEndpoint>();
        JsEndpoints.Scan(Program(text), "app.js", rows, default);
        return rows.Select(r => $"{r.Verb} {r.Url} [{r.Client}]").ToList();
    }

    private const string Bundle = """
        const BASE = "https://api.example.com/v1";
        const api = axios.create({ baseURL: "https://api.example.com/v2" });
        function getJson(path) { return fetch(BASE + path).then(r => r.json()); }
        export async function load(id) {
          await fetch(`${BASE}/users/${id}`, { method: "PUT" });
          await api.get("/orders");
          const x = new XMLHttpRequest(); x.open("POST", BASE + "/upload");
          const ws = new WebSocket("wss://push.example.com/socket");
          navigator.sendBeacon("/metrics");
          getJson("/settings");
          cache.get("someKey");
          client.post("/api/items", {});
        }
        const Q = gql`query GetUser($id: ID!) { user(id: $id) { name } }`;
        const routes = [{ path: "/users/:id", element: h(User) }, { path: "/settings", component: Settings, name: "settings" }];
        const docs = "https://docs.example.com/guide";
        """;

    [Fact]
    public void Calls_constants_templates_and_wrappers_fold_into_endpoints()
    {
        var rows = Endpoints(Bundle);
        Assert.Contains("PUT https://api.example.com/v1/users/{id} [fetch]", rows);
        Assert.Contains("GET https://api.example.com/v2/orders [axios]", rows);
        Assert.Contains("POST https://api.example.com/v1/upload [xhr]", rows);
        Assert.Contains("GET wss://push.example.com/socket [websocket]", rows);
        Assert.Contains("POST /metrics [beacon]", rows);
        Assert.Contains("GET https://api.example.com/v1/settings [fetch via getJson]", rows);
        Assert.Contains("POST /api/items [http]", rows);
        Assert.Contains("POST {graphql}#query GetUser [graphql]", rows);
        Assert.Contains("ROUTE /users/:id [react-router]", rows);
        Assert.Contains("ROUTE /settings [vue-router]", rows);
        Assert.Contains("* https://docs.example.com/guide [url]", rows);
        Assert.DoesNotContain(rows, r => r.Contains("someKey") || r.Contains("{path}"));
    }

    [Fact]
    public void Next_build_manifest_routes()
    {
        var rows = Endpoints("""self.__BUILD_MANIFEST = { "/": ["a.js"], "/blog/[slug]": ["b.js"], sortedPages: [] };""");
        Assert.Equal(["ROUTE / [next]", "ROUTE /blog/[slug] [next]"], rows);
    }

    /// <summary>A script's endpoints joined to a HAR: code+capture, code, capture.</summary>
    [Fact]
    public void Script_endpoints_join_a_capture()
    {
        var js = _dir.File("app.js");
        File.WriteAllText(js, """const B = "https://api.example.com"; fetch(B + "/users/" + id); fetch(B + "/never");""");
        var har = _dir.File("capture.har");
        File.WriteAllText(har, """{"log":{"entries":[{"request":{"method":"GET","url":"https://api.example.com/users/42"},"response":{"status":200}},{"request":{"method":"GET","url":"https://cdn.example.com/x"},"response":{"status":200}}]}}""");
        using var ws = new AssemblyWorkspace();
        var rows = new UnpackService(ws).Search(js, "*", "endpoint", 100, AnalysisLimits.Default, default, capture: har).Items
            .Select(m => $"{m.Seen} {m.Name}").ToList();
        Assert.Contains("code+capture GET https://api.example.com/users/{id}", rows);
        Assert.Contains("code GET https://api.example.com/never", rows);
        Assert.Contains("capture GET https://cdn.example.com/x", rows);
    }

    [Fact]
    public void Secrets_by_provider_config_and_name_are_masked()
    {
        var found = JsSecrets.Find(Program("""
            const aws = "AKIAIOSFODNN7EXAMPLE";
            const firebaseConfig = { apiKey: "AIzaSyD-1234567890abcdefghijklmnopqrstu", authDomain: "x.firebaseapp.com", projectId: "x" };
            const clientSecret = "q8Zr2Lk9Vx4Tn7Wp1Ys6Hd3Fj5Gb0Mc";
            const password = "aaaaaaaaaaaaaaaaaaaa";
            """), default);
        var rows = found.Select(s => $"{s.Kind} {s.Name} {s.Masked}").ToList();
        Assert.Contains("aws-access-key  AKIA…LE", rows);
        Assert.Contains("google-api-key  AIza…tu", rows);
        Assert.Contains("firebase-config apiKey AIza…tu", rows);
        Assert.Contains("named clientSecret q8Zr…Mc", rows);
        Assert.DoesNotContain(found, s => s.Name == "password");
        Assert.DoesNotContain(found, s => s.Masked.Contains("IOSFODNN", StringComparison.Ordinal));
    }

    /// <summary>Endpoints of installed Electron apps' scripts: counts by client and time.</summary>
    [RequiresRealDataFact(RealData.ElectronApps)]
    [Trait("Speed", "Slow")]
    public void Real_app_endpoints()
    {
        foreach (var asar in Directory.EnumerateFiles(RealData.Path(RealData.ElectronApps), "app.asar", new EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 6 }))
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var items = ApiSurface.CodeItems(asar, [], AnalysisLimits.Default, default);
            var surface = ApiSurface.Read(items, default);
            var bytes = items.Sum(i => (long)i.Bytes.Length);
            Console.WriteLine($"{asar}: {bytes / 1e6:0.0} MB of script in {sw.Elapsed.TotalSeconds:0.00} s; " +
                              string.Join(", ", surface.Endpoints.GroupBy(e => e.Client.Split(' ')[0]).Select(g => $"{g.Count()} {g.Key}")));
            foreach (var e in surface.Endpoints.Where(e => e.Client != "url").Take(400)) Console.WriteLine($"    {e.Text} [{e.Client}] {e.File}:{e.Location}");
            foreach (var n in surface.Notes.Take(10)) Console.WriteLine("    note: " + n);
        }
    }

    [Fact]
    [FuzzEntry(typeof(JsEndpoints), typeof(JsSecrets))]
    public void Fuzzed_bundles_never_throw()
    {
        var failures = FormatFuzz.Run(System.Text.Encoding.UTF8.GetBytes(Bundle), b =>
        {
            if (JsProgram.Build("app.js", System.Text.Encoding.UTF8.GetString(b), [], default) is not { } p) return;
            JsEndpoints.Scan(p, "app.js", [], default);
            JsSecrets.Find(p, default);
        }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
