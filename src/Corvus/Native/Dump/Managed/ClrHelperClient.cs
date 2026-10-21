using System.Globalization;
using System.Text;
using System.Text.Json;
using Corvus.Core;
using Corvus.Native.Providers;

namespace Corvus.Native.Dump.Managed;

/// <summary>
/// The 32-bit decoder process (a .NET Framework x86 program beside the server) that loads a 32-bit DAC this 64-bit
/// process cannot. It opens the dump file or the running process itself, checks the DAC file's SHA-256 before loading
/// it, and answers one request line with one JSON line. A call that fails or times out ends the process; the decoder
/// is then reopened.
/// </summary>
internal sealed class ClrHelperClient : IClrBackend, ILiveClrReads
{
    public const string Folder = "clr32", FileName = "Corvus.Clr32.exe";
    /// <summary>Overrides the decoder's path (tests and custom layouts).</summary>
    public const string PathVariable = "CORVUS_CLR32";
    private static readonly TimeSpan StartTimeout = TimeSpan.FromMinutes(2), CallTimeout = TimeSpan.FromMinutes(10);
    /// <summary>A read of a running process serves a stop or a coverage sample: a slower one stops the decoder rather than the session.</summary>
    internal static TimeSpan LiveCallTimeout { get; set; } = TimeSpan.FromSeconds(15);
    private const long MemoryLimit = 3L << 30;

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly ChildProcess _process;
    private readonly StreamReader _output;
    private readonly StreamWriter _input;
    private readonly string _temp;

    private ClrHelperClient(ChildProcess process, string temp)
    {
        _process = process;
        _temp = temp;
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
    public static ClrHelperClient Start(string helper, string dump, string dac, string sha256, IReadOnlyList<string> imageDirectories) =>
        Start(helper, [dump, dac, sha256, string.Join(';', imageDirectories)]);

    /// <summary>Starts the decoder on running process <paramref name="pid"/> (never suspended) with the verified DAC.</summary>
    public static ClrHelperClient StartLive(string helper, int pid, string dac, string sha256) =>
        Start(helper, ["--pid", pid.ToString(CultureInfo.InvariantCulture), dac, sha256]);

    private static ClrHelperClient Start(string helper, string[] arguments)
    {
        // ClrMD creates its default symbol cache (%TEMP%\symbols) on every dump open: the decoder gets a temporary folder of its own
        var temp = Path.Combine(Path.GetTempPath(), "corvus-clr32", $"{Environment.ProcessId}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temp);
        ChildProcess process;
        try
        {
            process = ChildProcess.Start(new ChildProcessStart(helper, arguments)
            {
                WorkingDirectory = Path.GetDirectoryName(helper),
                Environment = new Dictionary<string, string?> { ["TMP"] = temp, ["TEMP"] = temp },
                MemoryLimitBytes = MemoryLimit,
            });
        }
        catch
        {
            DeleteTemp(temp);
            throw;
        }
        return Attach(process, temp);
    }

    /// <summary>The decoder running as <paramref name="process"/> (tests script one), once it answers its start.</summary>
    internal static ClrHelperClient Attach(ChildProcess process, string temp)
    {
        var client = new ClrHelperClient(process, temp);
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

    public void Refresh() => Call<object?>("refresh", LiveCallTimeout);

    public LiveMethod? MethodAt(ulong ip) => Call<LiveMethod?>(FormattableString.Invariant($"method_at\t{ip}"), LiveCallTimeout);

    public IReadOnlyList<ulong> Frames(uint thread, IReadOnlyDictionary<string, string> registers, int max) =>
        Call<List<ulong>>(FormattableString.Invariant($"live_frames\t{thread}\t{max}\t{string.Join(';', registers.Select(r => Field(r.Key) + "=" + Field(r.Value)))}"), LiveCallTimeout);

    public LiveCode? CodeOf(string path, int typeToken, int methodToken) =>
        Call<LiveCode?>(FormattableString.Invariant($"code_of\t{Field(path)}\t{typeToken}\t{methodToken}"), LiveCallTimeout);

    public LiveModuleImage? ModuleImage(string path) => Call<LiveModuleImage?>($"module_image\t{Field(path)}", LiveCallTimeout);

    public IReadOnlyList<uint> Prepared(string path) => Call<List<uint>>($"prepared\t{Field(path)}", LiveCallTimeout);

    /// <summary>A request field: tabs and line breaks never occur in type names, so they are dropped; "-" stands for none.</summary>
    private static string Field(string? value) => string.IsNullOrEmpty(value) ? "-" : value.Replace('\t', ' ').Replace('\n', ' ').Replace('\r', ' ');

    private T Call<T>(string request) => Call<T>(request, CallTimeout);

    private T Call<T>(string request, TimeSpan timeout)
    {
        try { _input.WriteLine(request); }
        catch (IOException ex) { throw Exited(ex.Message); }
        var value = Read(timeout);
        return value.ValueKind == JsonValueKind.Null ? default! : value.Deserialize<T>(Json)!;
    }

    /// <summary>The next response's value; an error response becomes a <see cref="ToolError"/>, a dead or silent process ends this client.</summary>
    private JsonElement Read(TimeSpan timeout)
    {
        var line = _output.ReadLineAsync();
        if (!line.Wait(timeout))
        {
            Dispose();
            throw new ToolError(ErrorCode.Timeout, $"the 32-bit .NET decoder did not answer within {timeout.TotalSeconds:0} s and was stopped.", "call again");
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

    /// <summary>The process was ended: this client answers no further call.</summary>
    public bool Ended { get; private set; }

    public void Dispose()
    {
        Ended = true;
        try { _input.WriteLine("exit"); }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
        _process.Dispose(); // waits for the exit, so the folder is free
        DeleteTemp(_temp);
    }

    private static void DeleteTemp(string temp)
    {
        try
        {
            Directory.Delete(temp, true);
            Directory.Delete(Path.GetDirectoryName(temp)!); // the shared parent, once no other decoder uses it
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }
}
