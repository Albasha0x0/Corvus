using System.Globalization;
using System.Text;
using System.Text.Json;
using Corvus.Core;
using Corvus.Native.Providers;

namespace Corvus.Native.Dump.Managed;

/// <summary>
/// The 32-bit decoder process (a .NET Framework x86 program beside the server) that loads a 32-bit DAC this 64-bit
/// process cannot. It opens the dump file itself, checks the DAC file's SHA-256 before loading it, and answers one
/// request line with one JSON line. A call that fails or times out ends the process; the decoder is then reopened.
/// </summary>
internal sealed class ClrHelperClient : IClrBackend
{
    public const string Folder = "clr32", FileName = "Corvus.Clr32.exe";
    /// <summary>Overrides the decoder's path (tests and custom layouts).</summary>
    public const string PathVariable = "NDM_CLR32";
    private static readonly TimeSpan StartTimeout = TimeSpan.FromMinutes(2), CallTimeout = TimeSpan.FromMinutes(10);
    private const long MemoryLimit = 3L << 30;

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly ChildProcess _process;
    private readonly StreamReader _output;
    private readonly StreamWriter _input;

    private ClrHelperClient(ChildProcess process)
    {
        _process = process;
        _output = new StreamReader(process.StandardOutput, new UTF8Encoding(false));
        _input = new StreamWriter(process.StandardInput, new UTF8Encoding(false)) { AutoFlush = true, NewLine = "\n" };
    }

    /// <summary>The decoder's executable: <see cref="PathVariable"/>, else clr32/ beside this server; null when absent.</summary>
    public static string? Locate()
    {
        if (Environment.GetEnvironmentVariable(PathVariable) is { Length: > 0 } custom) return File.Exists(custom) ? Path.GetFullPath(custom) : null;
        var beside = Path.Combine(AppContext.BaseDirectory, Folder, FileName);
        return File.Exists(beside) ? beside : null;
    }

    /// <summary>Starts the decoder on <paramref name="dump"/> with the verified DAC; throws when it cannot open the runtime.</summary>
    public static ClrHelperClient Start(string helper, string dump, string dac, string sha256, IReadOnlyList<string> imageDirectories)
    {
        var process = ChildProcess.Start(new ChildProcessStart(helper, [dump, dac, sha256, string.Join(';', imageDirectories)])
        {
            WorkingDirectory = Path.GetDirectoryName(helper),
            MemoryLimitBytes = MemoryLimit,
        });
        var client = new ClrHelperClient(process);
        try
        {
            client.Read(StartTimeout);
            return client;
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    public ManagedFacts Facts() => Call<ManagedFacts>("facts");

    public ManagedException? Exception(uint? threadId) => Call<ManagedException?>($"exception\t{(threadId is { } t ? t.ToString(CultureInfo.InvariantCulture) : "-")}");

    public IReadOnlyList<ManagedFrame> Frames(uint threadId, int maxFrames) =>
        Call<List<ManagedFrame>>(FormattableString.Invariant($"frames\t{threadId}\t{maxFrames}"));

    public HeapWalk Walk(string? type, ulong minSize, long maxObjects, int objectsFrom, int objectsTake, CancellationToken ct)
    {
        using var stop = ct.Register(Dispose);
        return Call<HeapWalk>(FormattableString.Invariant($"walk\t{Field(type)}\t{minSize}\t{maxObjects}\t{objectsFrom}\t{objectsTake}"));
    }

    public ObjectView? Object(ulong address, int depth, int maxFields, int maxArrayItems) =>
        Call<ObjectView?>(FormattableString.Invariant($"object\t{address}\t{depth}\t{maxFields}\t{maxArrayItems}"));

    /// <summary>A request field: tabs and line breaks never occur in type names, so they are dropped; "-" stands for none.</summary>
    private static string Field(string? value) => string.IsNullOrEmpty(value) ? "-" : value.Replace('\t', ' ').Replace('\n', ' ').Replace('\r', ' ');

    private T Call<T>(string request)
    {
        try { _input.WriteLine(request); }
        catch (IOException ex) { throw Exited(ex.Message); }
        var value = Read(CallTimeout);
        return value.ValueKind == JsonValueKind.Null ? default! : value.Deserialize<T>(Json)!;
    }

    /// <summary>The next response's value; an error response becomes a <see cref="ToolError"/>, a dead or silent process ends this client.</summary>
    private JsonElement Read(TimeSpan timeout)
    {
        var line = _output.ReadLineAsync();
        if (!line.Wait(timeout))
        {
            Dispose();
            throw new ToolError(ErrorCode.Timeout, $"the 32-bit .NET decoder did not answer within {timeout.TotalMinutes:0} minutes and was stopped.", "call again");
        }
        if (line.Result is not { } text) throw Exited("no answer");
        using var doc = JsonDocument.Parse(text);
        var root = doc.RootElement;
        if (!root.GetProperty("ok").GetBoolean())
            throw new ToolError(ErrorCode.ProviderUnavailable, $"the 32-bit .NET decoder: {root.GetProperty("error").GetString()}");
        return root.GetProperty("value").Clone();
    }

    private ToolError Exited(string why)
    {
        var stderr = "";
        try { stderr = new StreamReader(_process.StandardError).ReadToEnd(); }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
        Dispose();
        return new ToolError(ErrorCode.ProviderUnavailable, $"the 32-bit .NET decoder exited ({why}){(stderr.Length > 0 ? ": " + Format.Clip(stderr.Trim(), 500) : "")}.", "call again to restart it");
    }

    public void Dispose()
    {
        try { _input.WriteLine("exit"); }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
        _process.Dispose();
    }
}
