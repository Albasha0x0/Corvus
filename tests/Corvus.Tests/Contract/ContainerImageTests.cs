using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Corvus.Tests;

/// <summary>The container image: digest-pinned bases, a non-root user, and a server that works with a read-only root.</summary>
public sealed class ContainerImageTests(Xunit.Abstractions.ITestOutputHelper output)
{
    private static string Dockerfile => Path.Combine(DocsTests.RepoRoot(), "Dockerfile");

    [Fact]
    public void Every_base_image_is_pinned_by_digest_and_the_program_runs_as_a_non_root_user()
    {
        var lines = File.ReadAllLines(Dockerfile).Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith('#')).ToList();
        var bases = lines.Where(l => l.StartsWith("FROM ", StringComparison.Ordinal)).ToList();
        Assert.NotEmpty(bases);
        // Scratch is the empty image, with nothing to pin.
        Assert.All(bases, b => Assert.Matches(@"^FROM (scratch|\S+:\S+@sha256:[0-9a-f]{64})( AS \w+)?$", b));
        var user = lines.Last(l => l.StartsWith("USER ", StringComparison.Ordinal))["USER ".Length..].Trim();
        Assert.DoesNotMatch("^(0|root)(:|$)", user);
        Assert.True(lines.IndexOf("USER " + user) > lines.FindLastIndex(l => l.StartsWith("COPY ", StringComparison.Ordinal)), "USER comes after the last COPY");
    }

    /// <summary>CORVUS_CONTAINER_ENGINE builds the image and runs the server read-only: a tool call on a mounted file answers, and a kept result survives into the next container.</summary>
    [RequiresRealDataFact("CORVUS_CONTAINER_ENGINE")]
    [Trait("Speed", "Slow")]
    public async Task The_server_answers_tool_calls_in_a_read_only_container()
    {
        var engine = Environment.GetEnvironmentVariable("CORVUS_CONTAINER_ENGINE")!;
        using var dir = new TempDir();
        var publish = Path.Combine(dir.Path, "out");
        var (code, log) = Tools.Run(new ProcessStartInfo("dotnet",
            ["publish", Path.Combine(DocsTests.RepoRoot(), "src", "Corvus", "Corvus.csproj"), "-c", "Release", "-r", "linux-x64", "--self-contained", "true", "-o", publish, "--nologo"]));
        Assert.True(code == 0, log);
        var name = "corvus-test-" + Guid.NewGuid().ToString("N")[..12];
        try
        {
            (code, log) = Tools.Run(new ProcessStartInfo(engine, ["build", "-q", "-t", name, "-f", Dockerfile, publish]));
            Assert.True(code == 0, log);
            (code, log) = Tools.Run(new ProcessStartInfo(engine, ["image", "inspect", "-f", "{{.Config.User}}", name]));
            Assert.Equal("1654", log.Trim());

            var input = Path.Combine(dir.Path, "input");
            Directory.CreateDirectory(input);
            File.Copy(Env.FixturePath, Path.Combine(input, "fixture.dll"));
            var info = await CallAsync(engine, name, input, "get_assembly_info", """{"assembly":"/work/fixture.dll"}""");
            Assert.Contains(Path.GetFileNameWithoutExtension(Env.FixturePath), info);
            // A page keeps every value in the results cache under /data; a second container reads it back from the volume.
            var page = await CallAsync(engine, name, input, "extract_strings", """{"path":"/opt/corvus/corvus.dll","limit":1}""");
            var id = Regex.Match(page, @"read_result id=([A-Za-z0-9-]+)").Groups[1].Value;
            Assert.NotEmpty(id);
            var kept = await CallAsync(engine, name, input, "read_result", $$"""{"id":"{{id}}"}""");
            Assert.StartsWith($"[{id}: extract_strings result", kept);
            Assert.Contains("type,value,count,", kept);
        }
        finally
        {
            Tools.Run(new ProcessStartInfo(engine, ["volume", "rm", "-f", name]));
            Tools.Run(new ProcessStartInfo(engine, ["rmi", "-f", name]));
        }
    }

    // Read-only root, /tmp on tmpfs, input at /work read-only, data at /data, no network: initialize, then one tool call.
    private async Task<string> CallAsync(string engine, string image, string input, string tool, string arguments)
    {
        var run = new ProcessStartInfo(engine,
            ["run", "-i", "--rm", "--read-only", "--tmpfs", "/tmp", "-v", input + ":/work:ro", "-v", image + ":/data", "--network", "none", image])
        { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using var server = Process.Start(run)!;
        var stderr = server.StandardError.ReadToEndAsync();
        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        try
        {
            async Task<JsonElement> Request(int id, string method, string parameters)
            {
                await server.StandardInput.WriteLineAsync($$"""{"jsonrpc":"2.0","id":{{id}},"method":"{{method}}","params":{{parameters}}}""");
                await server.StandardInput.FlushAsync();
                while (await server.StandardOutput.ReadLineAsync(cts.Token) is { } line)
                    if (JsonDocument.Parse(line).RootElement is var m && m.TryGetProperty("id", out var i) && i.GetInt32() == id) return m.Clone();
                throw new InvalidOperationException("the server ended: " + await stderr);
            }
            await Request(1, "initialize", """{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}""");
            await server.StandardInput.WriteLineAsync("""{"jsonrpc":"2.0","method":"notifications/initialized"}""");
            var result = (await Request(2, "tools/call", $$"""{"name":"{{tool}}","arguments":{{arguments}}}""")).GetProperty("result");
            var text = result.GetProperty("content")[0].GetProperty("text").GetString()!;
            output.WriteLine($"{tool}: {text}");
            Assert.False(result.TryGetProperty("isError", out var e) && e.GetBoolean(), text);
            server.StandardInput.Close();
            Assert.True(server.WaitForExit(30_000), "the server kept running after its input closed");
            return text;
        }
        finally
        {
            if (!server.HasExited) server.Kill(entireProcessTree: true);
        }
    }
}
