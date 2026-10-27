using System.Text.Json;
using Corvus.Core;
using Corvus.Services.Analysis;
using Corvus.Services.Analysis.Endpoints;
using Corvus.Tests.NativeFormats;

namespace Corvus.Tests;

/// <summary>search_container kind=endpoint on app code (DEX, .NET, Mach-O), embedded descriptors in code, and the join with a capture.</summary>
public sealed class ApiSurfaceTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _ws = new();
    public void Dispose() { _ws.Dispose(); _dir.Dispose(); }

    private const string Builder = "Ljava/lang/StringBuilder;";

    /// <summary>
    /// A Retrofit interface with its base URL, one whose annotation types R8 renamed (resolved through the parser method),
    /// an OkHttp URL built by a StringBuilder, a Java gRPC method name, and Java descriptorData split over two constants.
    /// </summary>
    private static byte[] AppDex()
    {
        var b = new DexBuilder();
        var api = b.Class("Lcom/app/Api;", 0x601);
        api.Method("user", "Lretrofit2/Call;", ["I"], 0x401).Annotations.Add(("Lretrofit2/http/GET;", 1, [("value", "users/{id}")]));
        b.Class("Lcom/app/Net;").Method("build", "V", [], 0x9,
            Asm.ConstString(0, "https://api.example.com/v1/"),
            Asm.NewInstance(1, "Lretrofit2/Retrofit$Builder;"),
            Asm.Invoke(0x6e, "Lretrofit2/Retrofit$Builder;->baseUrl(Ljava/lang/String;)Lretrofit2/Retrofit$Builder;", 1, 0),
            Asm.Op11x(0x0c, 1),
            Asm.Invoke(0x6e, "Lretrofit2/Retrofit$Builder;->build()Lretrofit2/Retrofit;", 1),
            Asm.Op11x(0x0c, 1),
            Asm.ConstClass(2, "Lcom/app/Api;"),
            Asm.Invoke(0x6e, "Lretrofit2/Retrofit;->create(Ljava/lang/Class;)Ljava/lang/Object;", 1, 2),
            Asm.ReturnVoid());

        var renamed = b.Class("Lc/d;", 0x601);
        renamed.Method("a", "Ljava/lang/Object;", [], 0x401).Annotations.Add(("La/b;", 1, [("value", "api/v1/statuses/{id}")]));
        b.Class("Le/f;").Method("p", "V", ["Ljava/lang/Object;"], 0x9,
            Asm.CheckCast(3, "La/b;"), Asm.ConstString(0, "GET"),
            Asm.CheckCast(3, "La/c;"), Asm.ConstString(0, "POST"),
            Asm.CheckCast(3, "La/e;"), Asm.ConstString(0, "PUT"),
            Asm.CheckCast(3, "La/g;"), Asm.ConstString(0, "DELETE"),
            Asm.ReturnVoid());

        var repo = b.Class("Lcom/app/Repo;").Method("load", "V", ["I"], 0x1,
            Asm.NewInstance(0, Builder),
            Asm.ConstString(1, "https://h.example/items/"),
            Asm.Invoke(0x70, $"{Builder}-><init>(Ljava/lang/String;)V", 0, 1),
            Asm.Invoke(0x6e, $"{Builder}->append(I){Builder}", 0, 4),
            Asm.Op11x(0x0c, 0),
            Asm.ConstString(1, "/detail"),
            Asm.Invoke(0x6e, $"{Builder}->append(Ljava/lang/String;){Builder}", 0, 1),
            Asm.Op11x(0x0c, 0),
            Asm.Invoke(0x6e, $"{Builder}->toString()Ljava/lang/String;", 0),
            Asm.Op11x(0x0c, 0),
            Asm.NewInstance(1, "Lokhttp3/Request$Builder;"),
            Asm.Invoke(0x6e, "Lokhttp3/Request$Builder;->url(Ljava/lang/String;)Lokhttp3/Request$Builder;", 1, 0),
            Asm.ReturnVoid());
        repo.Registers = 5;

        b.Class("Lcom/app/UsersGrpc;").Method("method", "V", [], 0x9,
            Asm.ConstString(0, "demo.v1.Users"), Asm.ConstString(1, "GetUser"),
            Asm.Invoke(0x71, "Lio/grpc/MethodDescriptor;->generateFullMethodName(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", 0, 1),
            Asm.ReturnVoid());

        var demo = ProtoWriter.Demo().Select(x => (char)x).ToArray();
        b.Class("Lcom/app/DemoProto;").Method("<clinit>", "V", [], 0x8,
            Asm.ConstString(0, new string(demo[..40])), Asm.ConstString(1, new string(demo[40..])), Asm.ReturnVoid());
        return b.Build();
    }

    private UnpackService.ContainerSearch Endpoints(string path, string? capture = null) =>
        new UnpackService(_ws).Search(path, "*", "endpoint", 1000, AnalysisLimits.Default, default, capture: capture);

    private static string Row(ContainerMatch m) => $"{m.Name} | {m.Detail} | {m.Member} {m.Location}";

    private static void Has(List<string> rows, string expected) => Assert.True(rows.Contains(expected), $"{expected}\nnot in\n{string.Join("\n", rows)}");

    [Fact]
    public void Retrofit_methods_get_their_base_url_and_renamed_annotation_types_their_http_method()
    {
        var path = _dir.File("app.dex");
        File.WriteAllBytes(path, AppDex());
        var rows = Endpoints(path).Items.Select(Row).ToList();
        Has(rows, "GET https://api.example.com/v1/users/{id} | retrofit, base https://api.example.com/v1/ | Lcom/app/Api;->user(I)Lretrofit2/Call; annotation");
        Has(rows, "GET /api/v1/statuses/{id} | retrofit | Lc/d;->a()Ljava/lang/Object; annotation");
        Has(rows, "* https://api.example.com/v1/ | retrofit-base | Lcom/app/Net;->build()V +0x4");
    }

    [Fact]
    public void Dex_url_built_by_a_string_builder_is_a_template_at_its_call()
    {
        var path = _dir.File("app.dex");
        File.WriteAllBytes(path, AppDex());
        var rows = Endpoints(path).Items.Select(Row).ToList();
        Has(rows, "* https://h.example/items/{}/detail | okhttp | Lcom/app/Repo;->load(I)V +0x17");
        Has(rows, "POST /demo.v1.Users/GetUser | grpc | Lcom/app/UsersGrpc;->method()V +0x4");
    }

    /// <summary>
    /// An app whose OkHttp, Ktor and Retrofit R8 renamed: OkHttp's url(String) known by its "ws:" / "wss:" rewrite, Ktor's URL
    /// parser by "mailto" and "@/\?#", a wrapper passing its String parameter on, and Retrofit's @Query type by its parser's
    /// instance-of order (Url, Path, Query, ... Field) with no annotation names left.
    /// </summary>
    private static byte[] RenamedDex()
    {
        var b = new DexBuilder();
        var ok = b.Class("Lo/a;");
        ok.Method("a", "Lo/a;", ["Ljava/lang/String;"], 1, Asm.ConstString(0, "ws:"), Asm.ConstString(0, "wss:"), Asm.ConstString(0, "http:"), Asm.Return(0x11, 1)).Registers = 3;
        b.Class("Lk/b;").Method("a", "Lk/c;", ["Lk/c;", "Ljava/lang/String;"], 9,
            Asm.ConstString(0, "mailto"), Asm.ConstString(0, "@/\\?#"), Asm.Return(0x11, 1)).Registers = 3;
        b.Class("Lcom/app/Http;").Method("get", "V", ["Ljava/lang/String;"], 9,
            Asm.NewInstance(0, "Lo/a;"), Asm.Invoke(0x6e, "Lo/a;->a(Ljava/lang/String;)Lo/a;", 0, 1), Asm.ReturnVoid()).Registers = 2;
        var feed = b.Class("Lcom/app/Feed;");
        feed.Method("load", "V", [], 1,
            Asm.NewInstance(0, "Lo/a;"), Asm.ConstString(1, "https://feed.example/v2/items"),
            Asm.Invoke(0x6e, "Lo/a;->a(Ljava/lang/String;)Lo/a;", 0, 1), Asm.ReturnVoid()).Registers = 3;
        feed.Method("more", "V", [], 1,
            Asm.ConstString(0, "https://feed.example/v2/more"), Asm.Invoke(0x71, "Lcom/app/Http;->get(Ljava/lang/String;)V", 0), Asm.ReturnVoid()).Registers = 2;
        feed.Method("ping", "V", [], 1,
            Asm.ConstString(1, "https://ktor.example/api/ping"), Asm.Invoke(0x71, "Lk/b;->a(Lk/c;Ljava/lang/String;)Lk/c;", 0, 1), Asm.ReturnVoid()).Registers = 3;

        string[] chain = ["Lr/u;", "Lr/p;", "Lr/q;", "Lr/n;", "Lr/m;", "Lr/h;", "Lr/i;", "Lr/f;", "Lr/g;", "Lr/t;"];
        foreach (var t in chain)
        {
            var a = b.Class(t, 0x2601);
            if (t is "Lr/p;" or "Lr/q;" or "Lr/f;" or "Lr/h;") a.Method("value", "Ljava/lang/String;", [], 0x401);
            if (t is "Lr/p;" or "Lr/q;" or "Lr/f;" or "Lr/n;" or "Lr/m;") a.Method("encoded", "Z", [], 0x401);
        }
        b.Class("Lr/z;").Method("a", "V", ["Ljava/lang/Object;"], 9, [.. chain.Select(t => Asm.InstanceOf(0, 1, t)), Asm.ReturnVoid()]).Registers = 2;
        b.Class("Le/f;").Method("p", "V", ["Ljava/lang/Object;"], 0x9,
            Asm.CheckCast(1, "La/b;"), Asm.ConstString(0, "GET"), Asm.CheckCast(1, "La/c;"), Asm.ConstString(0, "POST"),
            Asm.CheckCast(1, "La/e;"), Asm.ConstString(0, "PUT"), Asm.CheckCast(1, "La/g;"), Asm.ConstString(0, "DELETE"), Asm.ReturnVoid()).Registers = 2;
        var search = b.Class("Lc/d;", 0x601).Method("b", "Ljava/lang/Object;", ["Ljava/lang/String;", "Ljava/lang/String;", "I"], 0x401);
        search.Annotations.Add(("La/b;", 1, [("value", "items/{id}")]));
        search.ParameterAnnotations = [[("Lr/q;", 1, [("value", "term")])], [("Lr/p;", 1, [("value", "id")])], [("Lr/q;", 1, [("value", "page")])]];
        return b.Build();
    }

    [Fact]
    public void Renamed_okhttp_ktor_and_retrofit_query_are_recognized_by_their_code()
    {
        var path = _dir.File("app.apk");
        File.WriteAllBytes(path, ContainerFixtures.Zip(("classes.dex", RenamedDex())));
        var found = Endpoints(path);
        var rows = found.Items.Select(Row).ToList();
        Has(rows, "* https://feed.example/v2/items | okhttp (renamed) | Lcom/app/Feed;->load()V +0x4");
        Has(rows, "* https://feed.example/v2/more | okhttp (renamed) | Lcom/app/Feed;->more()V +0x2");
        Has(rows, "* https://ktor.example/api/ping | ktor (renamed) | Lcom/app/Feed;->ping()V +0x2");
        Has(rows, "GET /items/{id}?page=…&term=… | retrofit | Lc/d;->b(Ljava/lang/String;Ljava/lang/String;I)Ljava/lang/Object; annotation");
        Assert.DoesNotContain(rows, r => r.Contains("| url |", StringComparison.Ordinal));
        // The header counts the code read, not the (absent) assemblies.
        Assert.Equal(1, found.Searched);
        Assert.Contains("Code searched: 1 dex.", found.Notes);
    }

    [Fact]
    public void Java_descriptor_data_constants_are_read_as_one_descriptor_with_its_grpc_methods()
    {
        var surface = ApiSurface.Read([new ContainerItem("classes.dex", "dex", "file", AppDex())], default);
        var d = Assert.Single(surface.Descriptors);
        Assert.Equal(("demo.proto", "Latin-1 string constants", "Lcom/app/DemoProto;-><clinit>()V+0x0"), (d.File.Name, d.Encoding, d.Site));
        Assert.Contains(surface.Endpoints, e => e.Text == "POST /demo.v1.Users/Watch" && e.Client == "proto" && e.Member == "demo.proto service Users");
    }

    [Fact]
    public void Code_endpoints_join_a_capture_seen_in_code_capture_or_both()
    {
        var path = _dir.File("app.dex");
        File.WriteAllBytes(path, AppDex());
        var har = _dir.File("session.har");
        File.WriteAllBytes(har, JsonSerializer.SerializeToUtf8Bytes(new
        {
            log = new
            {
                entries = new[]
                {
                    new { request = new { method = "GET", url = "https://api.example.com/v1/users/42" }, response = new { status = 200 } },
                    new { request = new { method = "GET", url = "https://api.example.com/v1/users/7" }, response = new { status = 404 } },
                    new { request = new { method = "POST", url = "https://telemetry.example/v2/batch" }, response = new { status = 204 } },
                },
            },
        }));
        var rows = Endpoints(path, har).Items.ToDictionary(m => m.Name + " @ " + m.Member, m => (m.Seen, m.Detail));
        var user = rows["GET https://api.example.com/v1/users/{id} @ Lcom/app/Api;->user(I)Lretrofit2/Call;"];
        Assert.Equal("code+capture", user.Seen);
        Assert.Contains("captured as GET https://api.example.com/v1/users/{n} (2 request(s), status 200, 404)", user.Detail, StringComparison.Ordinal);
        Assert.Equal("code", rows["GET /api/v1/statuses/{id} @ Lc/d;->a()Ljava/lang/Object;"].Seen);
        Assert.Equal("capture", rows["POST https://telemetry.example/v2/batch @ "].Seen);
    }

    private const string DotNetSource = """
        using System;
        using System.Net.Http;
        using System.Threading.Tasks;
        namespace Refit
        {
            public sealed class GetAttribute(string path) : Attribute { public string Path => path; }
            public sealed class PostAttribute(string path) : Attribute { public string Path => path; }
            public static class RestService { public static T For<T>(string hostUrl) => default!; }
        }
        namespace Grpc.Core
        {
            public enum MethodType { Unary }
            public sealed class Marshaller<T> { }
            public sealed class Method<TRequest, TResponse>(MethodType type, string serviceName, string name, Marshaller<TRequest> request, Marshaller<TResponse> response) { }
        }
        namespace App
        {
            public interface IUsers
            {
                [Refit.Get("/users/{id}")] Task<string> Get(int id, string expand);
                [Refit.Post("/users")] Task Create();
            }
            public static class Clients
            {
                private const string Service = "demo.v1.Users";
                private static readonly HttpClient Http = new();
                private static readonly Grpc.Core.Method<string, string> GetUser = new(Grpc.Core.MethodType.Unary, Service, "GetUser", new(), new());
                public static IUsers Users() => Refit.RestService.For<IUsers>("https://api.example.com");
                public static Task<string> Item(int id) => Http.GetStringAsync($"https://api.example.com/items/{id}/detail");
                public static Task<HttpResponseMessage> Delete(string name) => Http.SendAsync(new HttpRequestMessage(HttpMethod.Delete, "https://api.example.com/tags/" + name));
                public static byte[] Descriptor() => Convert.FromBase64String(string.Concat("PART1", "PART2"));
            }
        }
        """;

    [Fact]
    public void Dotnet_refit_httpclient_grpc_and_base64_descriptors_are_found_by_member()
    {
        var b64 = Convert.ToBase64String(ProtoWriter.Demo());
        var source = DotNetSource.Replace("PART1", b64[..60], StringComparison.Ordinal).Replace("PART2", b64[60..], StringComparison.Ordinal);
        var path = _dir.File("App.dll");
        File.WriteAllBytes(path, Roslyn.Release("ApiSurfaceApp", source));
        var rows = Endpoints(path).Items.Select(m => $"{m.Name} | {m.Detail} | {m.Member}").ToList();
        Has(rows, "GET https://api.example.com/users/{id}?expand=… | refit, base https://api.example.com | App.IUsers::Get(int, string)");
        Has(rows, "POST https://api.example.com/users | refit, base https://api.example.com | App.IUsers::Create()");
        Has(rows, "GET https://api.example.com/items/{id}/detail | httpclient | App.Clients::Item(int)");
        Has(rows, "DELETE https://api.example.com/tags/{name} | httpclient | App.Clients::Delete(string)");
        Has(rows, "POST /demo.v1.Users/GetUser | grpc | App.Clients::.cctor()");
        Has(rows, "POST /demo.v1.Users/GetUser | proto | demo.proto service Users");
    }

    [Fact]
    public void Macho_url_strings_are_listed_with_the_function_that_loads_them()
    {
        var w = new MachOWriter
        {
            FileType = 2,
            // adrp x0, page of __cstring (+1 page); add x0, x0, #0; ret
            Text = [0x00, 0x00, 0x00, 0xB0, 0x00, 0x00, 0x00, 0x91, 0xC0, 0x03, 0x5F, 0xD6],
            Symbols = [new("_fetchUser", MachOWriter.TextOffset)],
            FunctionStarts = [MachOWriter.TextOffset],
            ExtraSections = [("__TEXT", "__cstring", 0x2000, [.. "https://api.example.com/v2/users/%@?lang=%s\0"u8], 2)],
        };
        var path = _dir.File("App");
        File.WriteAllBytes(path, w.Build());
        var row = Assert.Single(Endpoints(path).Items);
        Assert.Equal("* https://api.example.com/v2/users/{}?lang={} | url | _fetchUser 0x100001004", $"{row.Name} | {row.Detail} | {row.Member} {row.Location}");
    }
}
