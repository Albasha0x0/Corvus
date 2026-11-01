using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

[Collection(ProcessEnvironmentCollection.Name)]
public class OutputRedactionTests
{
    private const string Token = "ghp_0123456789abcdef0123456789abcdef0123";

    private static ServerOptions On() => ServerOptions.Parse([ServerOptions.RedactOutputOption, "--no-index", "--no-watch"]);

    private static ServerOptions Off() => ServerOptions.Parse(["--no-index", "--no-watch"]);

    private static CallToolResult Result(string text) => new() { Content = [new TextContentBlock { Text = text }] };

    private static string Text(CallToolResult r) => ((TextContentBlock)r.Content[0]).Text;

    [Fact]
    public void A_secret_named_assignment_is_masked_with_a_hash_of_its_value()
    {
        var text = Redaction.Output("db_password=hunter22\nother_password=hunter22\nthird_password=different");
        var lines = text.Split('\n');
        Assert.DoesNotContain("hunter22", text);
        Assert.StartsWith("db_password=[redacted:", lines[0]);
        Assert.Equal(lines[0].Split('=')[1], lines[1].Split('=')[1]);
        Assert.NotEqual(lines[0].Split('=')[1], lines[2].Split('=')[1]);
    }

    [Fact]
    public void A_token_shape_and_a_url_password_and_a_bearer_credential_are_masked()
    {
        var text = Redaction.Output($"key {Token}\nhttps://user:s3cretpass@host/x\nAuthorization: Bearer abcdefgh12345678");
        Assert.DoesNotContain(Token, text);
        Assert.DoesNotContain("s3cretpass", text);
        Assert.DoesNotContain("abcdefgh12345678", text);
    }

    [Fact]
    public void Masking_masked_text_leaves_it_unchanged()
    {
        var once = Redaction.Output("api_key=abc123def456 " + Token + "\nsecret_x = \"quoted one\"\nhttps://u:s3cretpass@h/\nBearer abcdefgh12345678");
        Assert.Equal(once, Redaction.Output(once));
        var record = JsonNode.Parse("{\"password\":\"hunter22\",\"items\":[\"token=abc123def456\"]}")!;
        Redaction.Output(record);
        var first = record.ToJsonString();
        Redaction.Output(record);
        Assert.Equal(first, record.ToJsonString());
    }

    [Fact]
    public void A_value_that_only_starts_like_a_mask_is_still_masked()
    {
        var text = Redaction.Output("password=[redactedSuperSecret1\n\"token\": \"[redacted-abc\"");
        Assert.DoesNotContain("SuperSecret1", text);
        Assert.DoesNotContain("-abc", text);
        var record = JsonNode.Parse("{\"password\":\"[redacted-abc\"}")!;
        Redaction.Output(record);
        Assert.DoesNotContain("-abc", record.ToJsonString());
    }

    [Fact]
    public void A_quoted_and_an_unquoted_value_get_the_same_mask()
    {
        var text = Redaction.Output("a_password=\"x1y2z3\"\nb_password=x1y2z3");
        var lines = text.Split('\n');
        Assert.Equal(lines[0].Split('=')[1], lines[1].Split('=')[1]);
    }

    [Fact]
    public void An_error_result_and_an_embedded_text_resource_are_masked()
    {
        var error = new CallToolResult { IsError = true, Content = [new TextContentBlock { Text = "bad line: password=hunter22" }] };
        Assert.DoesNotContain("hunter22", Text(Redaction.Result(On(), "decompile_member", error)));
        var resource = new CallToolResult
        {
            Content = [new EmbeddedResourceBlock { Resource = new TextResourceContents { Uri = "file:///x", Text = "password=hunter22" } }],
        };
        var masked = (EmbeddedResourceBlock)Redaction.Result(On(), "decompile_member", resource).Content[0];
        Assert.DoesNotContain("hunter22", ((TextResourceContents)masked.Resource).Text);
    }

    [Fact]
    public void The_plain_mask_covers_a_value_that_starts_like_a_mask()
    {
        Assert.Equal("password=[redacted]", Redaction.Text("password=[redactedx"));
    }

    [Fact]
    public async Task The_filter_masks_the_recent_call_and_the_server_keeps_masked_results()
    {
        var services = ServerHost.AddServices(new ServiceCollection(), On());
        using var provider = services.BuildServiceProvider();
        var request = new CallToolRequestParams { Name = "decompile_member" };
        await CallFilter.Run(request, null, provider, _ => ValueTask.FromResult(Result("password=hunter22")), default);
        Assert.DoesNotContain("hunter22", provider.GetRequiredService<RecentCalls>().Last(1)[0].Text);
        var store = provider.GetRequiredService<ResultStore>();
        Assert.DoesNotContain("hunter22", store.Read(store.Keep("password=hunter22", new KeptOrigin("decompile_member"))).Text);
    }

    [Fact]
    public void A_malformed_record_is_masked_as_text()
    {
        var store = new ResultStore(ResultCacheOptions.MemoryOnly) { Mask = Corvus.Mcp.Redaction.Kept };
        var id = store.Keep("x", new KeptOrigin("decompile_member"), "{password=hunter22");
        Assert.DoesNotContain("hunter22", store.Read(id).Record);
    }

    [Fact]
    public void A_symbol_that_names_a_token_type_is_not_masked()
    {
        const string symbol = "Ns.TokenReader::Read";
        Assert.Equal(symbol, Redaction.Output(symbol));
    }

    [Fact]
    public void A_long_run_of_name_characters_is_scanned_in_linear_time()
    {
        // Quadratic under backtracking: every start in the run scans to its end (regression of the backtracking matchers).
        var text = new string('A', 200_000) + "PASSWORD " + string.Concat(Enumerable.Repeat("bearer ", 20_000));
        var clock = System.Diagnostics.Stopwatch.StartNew();
        Redaction.Output(text);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(2));
    }

    [Fact]
    public void A_result_text_and_record_are_masked_when_the_option_is_on()
    {
        var result = Result("token=" + Token);
        result.StructuredContent = JsonSerializer.SerializeToElement(new { code = "password=hunter22", password = "hunter22" });
        var masked = Redaction.Result(On(), "decompile_member", result);
        Assert.DoesNotContain(Token, Text(masked));
        Assert.DoesNotContain("hunter22", masked.StructuredContent!.Value.GetRawText());
    }

    [Fact]
    public void An_off_switch_and_a_server_only_tool_leave_the_result_as_given()
    {
        var result = Result("token=" + Token);
        Assert.Same(result, Redaction.Result(Off(), "decompile_member", result));
        Assert.Same(result, Redaction.Result(On(), "server_status", result));
    }

    [Fact]
    public void A_kept_result_holds_the_masked_text_under_the_masked_id()
    {
        var store = new ResultStore(ResultCacheOptions.MemoryOnly) { Mask = Corvus.Mcp.Redaction.Kept };
        var id = store.Keep("api_key=abc123def456", new KeptOrigin("decompile_member"), "{\"code\":\"api_key=abc123def456\"}");
        var kept = store.Read(id);
        Assert.DoesNotContain("abc123def456", kept.Text);
        Assert.DoesNotContain("abc123def456", kept.Record);
        Assert.Equal(id, ResultStore.IdOf(kept.Text));
    }

    [Theory]
    [InlineData("1", true)]
    [InlineData("on", true)]
    [InlineData("0", false)]
    [InlineData("", false)]
    public void The_environment_variable_sets_whether_output_is_masked(string value, bool masked)
    {
        var name = ServerOptions.RedactOutputVariable;
        var before = Environment.GetEnvironmentVariable(name);
        try
        {
            Environment.SetEnvironmentVariable(name, value);
            Assert.Equal(masked, ServerOptions.Parse(["--no-index", "--no-watch"]).RedactOutput);
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, before);
        }
    }
}
