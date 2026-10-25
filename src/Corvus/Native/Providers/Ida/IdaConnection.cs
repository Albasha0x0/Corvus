using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Corvus.Core;

namespace Corvus.Native.Providers.Ida;

/// <summary>
/// A database open in IDA that corvus_connect.py serves on 127.0.0.1, as its connection file in
/// &lt;IDA user directory&gt;/corvus names it: port, token, IDA's process id and the SHA-256 of the input it was made from.
/// </summary>
internal sealed record IdaConnection(string File, int Port, string Token, int Pid, string? Sha256, string? Database, ulong ImageBase)
{
    public const string Variable = "CORVUS_IDA_CONNECT";
    internal const string ScriptResource = "Corvus.Native.Providers.Ida.corvus_connect.py";

    /// <summary>Whether databases open in IDA are used: <paramref name="option"/>, else CORVUS_IDA_CONNECT=1. Off by default.</summary>
    public static bool Enabled(bool? option) => option ?? Environment.GetEnvironmentVariable(Variable) is "1" or "true";

    /// <summary>
    /// The connection files of running IDA processes in <paramref name="folder"/>, else in each IDA user directory's
    /// corvus folder, in IDA's order; unreadable files and those of exited processes are left out.
    /// </summary>
    public static IReadOnlyList<IdaConnection> List(string? folder = null)
    {
        var found = new List<IdaConnection>();
        foreach (var dir in folder != null ? [folder] : IdaInstallation.UserDirectories().Select(d => Path.Combine(d, "corvus")))
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var file in Directory.EnumerateFiles(dir, "ida-*.json").Order(StringComparer.Ordinal))
                if (Read(file) is { } c && Running(c.Pid)) found.Add(c);
        }
        return found;
    }

    /// <summary>The served database made from the input with this SHA-256, or null.</summary>
    public static IdaConnection? For(string? sha256, string? folder = null) =>
        sha256 == null ? null : List(folder).FirstOrDefault(c => string.Equals(c.Sha256, sha256, StringComparison.OrdinalIgnoreCase));

    /// <summary>The connection a file names, or null when it is not one.</summary>
    internal static IdaConnection? Read(string file)
    {
        try
        {
            using var doc = JsonDocument.Parse(System.IO.File.ReadAllText(file));
            var r = doc.RootElement;
            if (!r.TryGetProperty("port", out var port) || !r.TryGetProperty("token", out var token) || !r.TryGetProperty("pid", out var pid)) return null;
            return new IdaConnection(file, port.GetInt32(), token.GetString() ?? "", pid.GetInt32(),
                r.TryGetProperty("sha256", out var sha) ? sha.GetString() : null, r.TryGetProperty("idb", out var idb) ? idb.GetString() : null,
                r.TryGetProperty("imagebase", out var b) && b.ValueKind == JsonValueKind.Number ? b.GetUInt64() : 0);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException or FormatException) { return null; }
    }

    private static bool Running(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return !p.HasExited;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException) { return false; }
    }

    /// <summary>A worker connection to the served database; its first line is the token.</summary>
    public WorkerConnection Connect(TimeSpan timeout, WorkerConnectionOptions options)
    {
        var client = new TcpClient { NoDelay = true };
        try
        {
            if (!client.ConnectAsync(IPAddress.Loopback, Port).Wait(timeout))
                throw new ToolError(ErrorCode.Timeout, $"IDA (process {Pid}) did not accept a connection on port {Port} within {timeout.TotalSeconds:0} s.");
            var line = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { token = Token }) + "\n");
            client.GetStream().Write(line);
        }
        catch (Exception ex) when (ex is SocketException or IOException or AggregateException)
        {
            client.Dispose();
            throw new ToolError(ErrorCode.ProviderUnavailable, $"IDA (process {Pid}) refused the connection on port {Port}: {(ex as AggregateException)?.InnerException?.Message ?? ex.Message}",
                "run corvus_connect.py in IDA again (corvus ida-script writes it)");
        }
        catch
        {
            client.Dispose();
            throw;
        }
        return WorkerConnection.Attach(new SocketWorkerProcess(client, Pid), "IDA", IdaProvider.Remediation, options);
    }
}
