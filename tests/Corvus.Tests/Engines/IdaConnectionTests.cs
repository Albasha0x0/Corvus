using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ida;

namespace Corvus.Tests;

/// <summary>
/// A database open in IDA, as corvus_connect.py serves it: a loopback listener that checks the token and answers
/// hello, attach and close; other ops fail as unsupported.
/// </summary>
internal sealed class ServedDatabase : IDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    public readonly ConcurrentQueue<(string Op, JsonObject Args)> Requests = new();
    public string Token { get; } = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
    public ulong ImageBase { get; init; } = 0x140000000;
    public string? RejectedToken;
    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public ServedDatabase()
    {
        _listener.Start();
        new Thread(Serve) { IsBackground = true }.Start();
    }

    /// <summary>Writes the connection file corvus_connect.py writes, for <paramref name="pid"/> (default: this process).</summary>
    public string WriteFile(string folder, string sha256, int? pid = null, string? token = null)
    {
        Directory.CreateDirectory(folder);
        var id = pid ?? Environment.ProcessId;
        var path = Path.Combine(folder, $"ida-{id}.json");
        File.WriteAllText(path, new JsonObject
        {
            ["protocol"] = 1, ["port"] = Port, ["token"] = token ?? Token, ["pid"] = id, ["sha256"] = sha256,
            ["idb"] = Path.Combine(folder, "served.i64"), ["imagebase"] = ImageBase,
        }.ToJsonString());
        return path;
    }

    private void Serve()
    {
        try
        {
            while (true)
            {
                using var client = _listener.AcceptTcpClient();
                using var stream = client.GetStream();
                using var reader = new StreamReader(stream, new UTF8Encoding(false));
                var first = JsonNode.Parse(reader.ReadLine() ?? "{}")!["token"]?.GetValue<string>();
                if (first != Token)
                {
                    RejectedToken = first;
                    continue;
                }
                void Send(JsonObject o)
                {
                    var bytes = Encoding.UTF8.GetBytes(o.ToJsonString() + "\n");
                    stream.Write(bytes);
                }
                Send(new JsonObject { ["event"] = "ready", ["protocol"] = 1 });
                while (reader.ReadLine() is { } line)
                {
                    var req = JsonNode.Parse(line)!.AsObject();
                    var op = req["op"]!.GetValue<string>();
                    var args = req["args"] as JsonObject ?? [];
                    Requests.Enqueue((op, (JsonObject)args.DeepClone()));
                    JsonNode? result = op switch
                    {
                        "hello" => new JsonObject { ["protocol"] = 1, ["version"] = "9.3.0", ["connected"] = true },
                        "attach" => new JsonObject
                        {
                            ["imagebase"] = ImageBase, ["bits"] = 64, ["processor"] = "metapc", ["functions"] = 1, ["decompiler"] = false,
                            ["reused"] = true, ["seconds"] = 0, ["warnings"] = new JsonArray(), ["analysis_complete"] = true,
                        },
                        "close" => new JsonObject { ["detached"] = true },
                        _ => null,
                    };
                    Send(result != null
                        ? new JsonObject { ["id"] = req["id"]!.DeepClone(), ["ok"] = true, ["result"] = result }
                        : new JsonObject { ["id"] = req["id"]!.DeepClone(), ["ok"] = false, ["error"] = new JsonObject { ["code"] = "unsupported", ["message"] = op } });
                    if (op == "close") break;
                }
            }
        }
        catch (Exception ex) when (ex is SocketException or IOException or ObjectDisposedException or InvalidOperationException) { }
    }

    public void Dispose() => _listener.Stop();
}

public sealed class IdaConnectionTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly string _image;
    private readonly string _sha;

    public IdaConnectionTests()
    {
        var pe = new PeBuilder { EntryPoint = 0x1000 };
        pe.Sections.Add(new PeBuilder.Section { Name = ".text", Rva = 0x1000, Data = [0xC3], VirtualSize = 1, Characteristics = 0x60000020 });
        _image = Path.Combine(_dir.Path, "served.exe");
        File.WriteAllBytes(_image, pe.Build());
        _sha = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(_image)));
    }

    private string Folder => Path.Combine(_dir.Path, "connect");

    private IdaProvider Provider() => new(new IdaProviderOptions
    {
        CacheRoot = Path.Combine(_dir.Path, "cache"), Connect = true, ConnectFolder = Folder,
        InstallDirectory = Path.Combine(_dir.Path, "no-ida"),
    });

    [Fact]
    public async Task A_database_open_in_IDA_is_attached_without_a_local_install()
    {
        using var served = new ServedDatabase();
        served.WriteFile(Folder, _sha);
        using var provider = Provider();
        Assert.True(provider.CheckAvailability().IsAvailable);
        await using var session = (IdaSession)await provider.OpenAsync(_image, null, new NativeOpenOptions { Symbols = SymbolMode.Off });
        Assert.Equal(Environment.ProcessId, session.ConnectedPid);
        Assert.Equal(0x140000000UL, session.ImageBase);
        Assert.Contains(served.Requests, r => r.Op == "attach" && r.Args["sha256"]?.GetValue<string>() == _sha);
    }

    [Fact]
    public async Task Closing_the_session_detaches_and_never_saves_or_opens()
    {
        using var served = new ServedDatabase();
        served.WriteFile(Folder, _sha);
        using var provider = Provider();
        var session = await provider.OpenAsync(_image, null, new NativeOpenOptions { Symbols = SymbolMode.Off });
        await session.DisposeAsync();
        var close = Assert.Single(served.Requests, r => r.Op == "close");
        Assert.False(close.Args["save"]?.GetValue<bool>() ?? false);
        Assert.DoesNotContain(served.Requests, r => r.Op is "open" or "save" or "rebase");
        Assert.True(File.Exists(Path.Combine(Folder, $"ida-{Environment.ProcessId}.json")));
    }

    [Fact]
    public async Task A_database_at_another_base_is_refused_not_rebased()
    {
        using var served = new ServedDatabase { ImageBase = 0x180000000 };
        served.WriteFile(Folder, _sha);
        using var provider = Provider();
        var e = await Assert.ThrowsAsync<ToolError>(() => provider.OpenAsync(_image, null, new NativeOpenOptions { Symbols = SymbolMode.Off }));
        Assert.Equal(ErrorCode.InvalidArgument, e.Code);
        Assert.Contains("0x180000000", e.Message);
        Assert.DoesNotContain(served.Requests, r => r.Op == "rebase");
    }

    [Fact]
    public async Task An_image_no_served_database_was_made_from_is_not_attached()
    {
        using var served = new ServedDatabase();
        served.WriteFile(Folder, new string('0', 64));
        using var provider = Provider();
        var e = await Assert.ThrowsAsync<ToolError>(() => provider.OpenAsync(_image, null, new NativeOpenOptions { Symbols = SymbolMode.Off }));
        Assert.Equal(ErrorCode.ProviderUnavailable, e.Code);
        Assert.Empty(served.Requests);
    }

    [Fact]
    public void Connection_files_of_exited_processes_are_left_out()
    {
        using var served = new ServedDatabase();
        using var exited = Process.Start(new ProcessStartInfo(OperatingSystem.IsWindows() ? "cmd.exe" : "true") { Arguments = OperatingSystem.IsWindows() ? "/c exit" : "", UseShellExecute = false })!;
        exited.WaitForExit();
        served.WriteFile(Folder, _sha, exited.Id);
        Assert.Empty(IdaConnection.List(Folder));
        served.WriteFile(Folder, _sha);
        Assert.Equal(Environment.ProcessId, Assert.Single(IdaConnection.List(Folder)).Pid);
    }

    [Fact]
    public async Task Without_the_opt_in_a_served_database_is_ignored()
    {
        using var served = new ServedDatabase();
        served.WriteFile(Folder, _sha);
        using var provider = new IdaProvider(new IdaProviderOptions
        {
            CacheRoot = Path.Combine(_dir.Path, "cache"), Connect = false, ConnectFolder = Folder, InstallDirectory = Path.Combine(_dir.Path, "no-ida"),
        });
        Assert.False(provider.CheckAvailability().IsAvailable);
        await Assert.ThrowsAsync<ToolError>(() => provider.OpenAsync(_image, null, new NativeOpenOptions { Symbols = SymbolMode.Off }));
        Assert.Empty(served.Requests);
    }

    [Fact]
    public void The_written_connect_script_imports_the_worker_beside_it()
    {
        var script = Corvus.Setup.ToolCli.WriteIdaScripts(Path.Combine(_dir.Path, "scripts"));
        Assert.Contains("import ida_worker", File.ReadAllText(script));
        Assert.Contains("def serve_connected(", File.ReadAllText(Path.Combine(Path.GetDirectoryName(script)!, "ida_worker.py")));
    }

    public void Dispose() => _dir.Dispose();
}
