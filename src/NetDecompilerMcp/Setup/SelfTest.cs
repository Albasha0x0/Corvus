using System.Diagnostics;
using System.Text.Json.Nodes;

namespace NetDecompilerMcp.Setup;

/// <summary>Starts the server the way a client would and completes an MCP handshake and tools/list.</summary>
internal static class SelfTest
{
    public sealed record Result(bool Ok, string Detail);

    public static Result Run(ServerLaunch launch, TimeSpan timeout)
    {
        var psi = new ProcessStartInfo(launch.Command)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var a in launch.Args) psi.ArgumentList.Add(a);
        var clock = Stopwatch.StartNew();
        Process p;
        try { p = Process.Start(psi)!; }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return new Result(false, $"cannot start {launch.Command}: {ex.Message}");
        }
        using (p)
        {
            var stderr = new System.Text.StringBuilder();
            p.ErrorDataReceived += (_, e) => { if (e.Data != null) lock (stderr) stderr.AppendLine(e.Data); };
            p.BeginErrorReadLine();
            try
            {
                Send(p, new JsonObject
                {
                    ["jsonrpc"] = "2.0", ["id"] = 1, ["method"] = "initialize",
                    ["params"] = new JsonObject
                    {
                        ["protocolVersion"] = "2025-06-18",
                        ["capabilities"] = new JsonObject(),
                        ["clientInfo"] = new JsonObject { ["name"] = "net-decompiler-check", ["version"] = Installation.Version },
                    },
                });
                var init = Receive(p, 1, timeout - clock.Elapsed);
                if (init == null) return Fail("no reply to initialize", stderr);
                var version = init["result"]?["serverInfo"]?["version"]?.GetValue<string>();
                Send(p, new JsonObject { ["jsonrpc"] = "2.0", ["method"] = "notifications/initialized" });
                Send(p, new JsonObject { ["jsonrpc"] = "2.0", ["id"] = 2, ["method"] = "tools/list" });
                var tools = Receive(p, 2, timeout - clock.Elapsed)?["result"]?["tools"]?.AsArray();
                if (tools == null) return Fail("no reply to tools/list", stderr);
                return new Result(true, $"version {version}, {tools.Count} tools, started in {clock.Elapsed.TotalSeconds:0.0} s");
            }
            catch (IOException ex) { return Fail(ex.Message, stderr); }
            finally
            {
                try { p.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            }
        }
    }

    private static Result Fail(string message, System.Text.StringBuilder stderr)
    {
        string log;
        lock (stderr) log = stderr.ToString().Trim();
        return new Result(false, log.Length > 0 ? $"{message}; server output: {log[..Math.Min(log.Length, 500)]}" : message);
    }

    private static void Send(Process p, JsonObject message)
    {
        p.StandardInput.WriteLine(message.ToJsonString());
        p.StandardInput.Flush();
    }

    private static JsonNode? Receive(Process p, int id, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + (timeout > TimeSpan.Zero ? timeout : TimeSpan.FromSeconds(1));
        while (DateTime.UtcNow < deadline)
        {
            var read = p.StandardOutput.ReadLineAsync();
            if (!read.Wait(deadline - DateTime.UtcNow) || read.Result == null) return null;
            JsonNode? node;
            try { node = JsonNode.Parse(read.Result); }
            catch (System.Text.Json.JsonException) { continue; }
            if (node?["id"] is JsonValue v && v.TryGetValue<int>(out var got) && got == id) return node;
        }
        return null;
    }
}
