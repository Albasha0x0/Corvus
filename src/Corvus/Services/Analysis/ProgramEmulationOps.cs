using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native.Dump;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Worker;

namespace Corvus.Services.Analysis;

/// <summary>One API call of an emulated program: call site, module.function, arguments as the emulator shows them, return value (null: none).</summary>
public sealed record EmulatedApiCall(string Site, string Api, IReadOnlyList<string> Arguments, string? Returned);

/// <summary>A file the emulated program wrote in the emulator's virtual file system; SavedAs is null when the emulator kept no content.</summary>
public sealed record EmulatedFile(string Path, long Size, string? Sha256, string? SavedAs);

/// <summary>
/// A whole-program emulation: how it stopped (complete, or the emulator's error type such as unsupported_api or timeout,
/// with the address and the API or reason), the API calls in order, the files written, and the region-set manifest of
/// the program's own memory (its image, allocations and stack), or null when no region was kept.
/// </summary>
public sealed record ProgramEmulation(string Arch, string Stop, string? StoppedAt, string? Detail, string? ReturnValue,
    IReadOnlyList<EmulatedApiCall> ApiCalls, IReadOnlyList<EmulatedFile> FilesWritten, string? RegionSet, int Regions, long RegionBytes,
    double ElapsedSeconds, IReadOnlyList<string> Notes);

/// <summary>The worker op that runs the emulator (<see cref="ExternalTools.Emulator"/>) and reads its report; paths in, a record out.</summary>
internal sealed class ProgramEmulationOps : IWorkerOps
{
    public const string EmulateOp = "emulate_program";

    /// <summary>The emulator's report format this build reads (speakeasy 2.0.0b9 writes 5.0.0).</summary>
    public const int ReportFormat = 5;

    /// <summary>Largest report read; a run that keeps more memory is refused by name.</summary>
    public const long MaxReportBytes = 1L << 30;

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public IReadOnlyDictionary<string, WorkerOp> Ops => new Dictionary<string, WorkerOp> { [EmulateOp] = Emulate };

    /// <summary>
    /// Emulates <c>input</c> with the emulator at <c>emulator</c> (as raw code at <c>offset</c> for <c>arch</c> when
    /// <c>raw</c>, else from <c>entry</c> or the PE's entry point), bounded by <c>seconds</c>, <c>apis</c> and
    /// <c>instructions</c>, and writes the report, region files and written files under <c>output</c>.
    /// </summary>
    public static Task<JsonNode?> Emulate(JsonObject args, CancellationToken cancellationToken)
    {
        var emulator = Arg(args, "emulator");
        var input = Arg(args, "input");
        var output = Arg(args, "output");
        long seconds = Number(args, "seconds") ?? 10;
        Directory.CreateDirectory(output);
        var report = Path.Combine(output, "report.json");
        // speakeasy 2.0.0b9 mounts every file beside a PE into the emulated file system; a copy alone in its own folder
        // keeps the input's neighbours out of reach of the emulated program.
        var target = Path.Combine(output, "target", Path.GetFileName(input));
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        try { File.Copy(input, target, overwrite: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new ToolError(ErrorCode.IoError, $"{input} cannot be copied for the emulator: {ex.Message}");
        }
        var tool = ExternalTools.Emulator;
        var argv = ExternalTools.Arguments(tool, "run", ("input", target), ("seconds", seconds.ToString(CultureInfo.InvariantCulture)),
            ("apis", (Number(args, "apis") ?? 10000).ToString(CultureInfo.InvariantCulture)),
            ("instructions", (Number(args, "instructions") ?? 1_000_000).ToString(CultureInfo.InvariantCulture)));
        if ((bool?)args["raw"] == true)
            argv.AddRange(ExternalTools.Arguments(tool, "raw", ("offset", $"0x{Number(args, "offset") ?? 0:X}"), ("arch", Arg(args, "arch"))));
        else if (Number(args, "entry") is { } entry)
            argv.AddRange(ExternalTools.Arguments(tool, "entry", ("rva", $"0x{entry:X}")));
        argv.AddRange(ExternalTools.Arguments(tool, "report", ("report", report)));
        // The emulator stops itself at seconds and still writes its report; the extra minute covers its start and the write.
        var run = ExternalTools.Run(emulator, argv, TimeSpan.FromSeconds(seconds + 60), 1 << 20, cancellationToken, workingDirectory: output);
        if (run.StartError != null)
            throw new ToolError(ErrorCode.ProviderUnavailable, $"The emulator {emulator} cannot be started: {run.StartError}.", ExternalTools.Remediation(tool));
        if (!File.Exists(report))
        {
            var tail = string.Join(" | ", run.Stderr.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).TakeLast(3));
            throw run.TimedOut
                ? new ToolError(ErrorCode.Timeout, $"The emulator ran past {seconds + 60} s and wrote no report.", "a smaller timeoutSeconds or maxInstructions ends the run sooner")
                : new ToolError(ErrorCode.ProviderUnavailable, $"The emulator exited with {run.ExitCode?.ToString(CultureInfo.InvariantCulture) ?? "no code"} and wrote no report: {tail}",
                    ExternalTools.Remediation(tool));
        }
        return Task.FromResult<JsonNode?>(JsonSerializer.SerializeToNode(Read(report, output), Json));
    }

    /// <summary>Reads the emulator's report at <paramref name="report"/> and writes the region set and the written files under <paramref name="output"/>.</summary>
    internal static ProgramEmulation Read(string report, string output)
    {
        var size = new FileInfo(report).Length;
        if (size > MaxReportBytes)
            throw new ToolError(ErrorCode.LimitExceeded, $"The emulator's report is {size:N0} bytes; at most {MaxReportBytes:N0} are read.",
                "a smaller maxInstructions or timeoutSeconds keeps less memory");
        using var stream = File.OpenRead(report);
        JsonDocument doc;
        try { doc = JsonDocument.Parse(stream, new JsonDocumentOptions { MaxDepth = 256 }); }
        catch (JsonException ex) { throw new ToolError(ErrorCode.MalformedInput, $"The emulator's report is not JSON: {ex.Message}"); }
        using var owned = doc;
        var root = doc.RootElement;
        var version = Text(root, "report_version") ?? "unknown";
        if (!int.TryParse(version.Split('.')[0], NumberStyles.None, CultureInfo.InvariantCulture, out var major) || major != ReportFormat)
            throw new ToolError(ErrorCode.Unsupported, $"The emulator wrote report format {version}; this build reads format {ReportFormat}.x (speakeasy 2.0.0b9).",
                $"set {ExternalTools.Emulator.Variable} to speakeasy 2.0.0b9");
        var arch = Text(root, "arch") is "amd64" or "x64" ? "x64" : "x86";
        var elapsed = root.TryGetProperty("emulation_total_runtime", out var t) && t.TryGetDouble(out var s) ? s : 0;
        var data = root.TryGetProperty("data", out var d) && d.ValueKind == JsonValueKind.Object ? d : default;
        var notes = new List<string>();
        if (!root.TryGetProperty("entry_points", out var eps) || eps.ValueKind != JsonValueKind.Array || eps.GetArrayLength() == 0)
        {
            var why = root.TryGetProperty("errors", out var errs) && errs.ValueKind == JsonValueKind.Array && errs.GetArrayLength() > 0 ? errs[0] : default;
            return new ProgramEmulation(arch, why.ValueKind == JsonValueKind.Object ? Text(why, "type") ?? "error" : "no_entry", PcOf(why), Reason(why), null,
                [], [], null, 0, 0, elapsed, ["The emulator ran no entry point."]);
        }
        var ep = eps[0];
        var calls = new List<EmulatedApiCall>();
        if (ep.TryGetProperty("events", out var events) && events.ValueKind == JsonValueKind.Array)
            foreach (var e in events.EnumerateArray())
                if (Text(e, "event") == "api")
                    calls.Add(new EmulatedApiCall(e.TryGetProperty("pos", out var pos) && pos.TryGetProperty("pc", out var pc) && pc.TryGetUInt64(out var a) ? $"0x{a:X}" : "?",
                        Text(e, "api_name") ?? "?",
                        e.TryGetProperty("args", out var av) && av.ValueKind == JsonValueKind.Array
                            ? [.. av.EnumerateArray().Select(x => $"{Text(x, "name") ?? "?"}={Text(x, "display") ?? (x.TryGetProperty("value", out var v) ? v.ToString() : "?")}")]
                            : [],
                        Text(e, "ret_val")));
        var error = ep.TryGetProperty("error", out var er) && er.ValueKind == JsonValueKind.Object ? er : default;
        var stop = error.ValueKind == JsonValueKind.Object ? Text(error, "type") ?? "error" : "complete";

        var files = new List<EmulatedFile>();
        if (ep.TryGetProperty("dropped_files", out var dropped) && dropped.ValueKind == JsonValueKind.Array)
        {
            var folder = Path.Combine(output, "files");
            int n = 0;
            foreach (var f in dropped.EnumerateArray())
            {
                var path = Text(f, "path") ?? "?";
                var bytes = Blob(data, Text(f, "data_ref"));
                string? saved = null;
                if (bytes != null)
                {
                    Directory.CreateDirectory(folder);
                    saved = Path.Combine(folder, $"{n++:D3}-{SafeName(path)}");
                    File.WriteAllBytes(saved, bytes);
                }
                files.Add(new EmulatedFile(path, f.TryGetProperty("size", out var fs) && fs.TryGetInt64(out var l) ? l : bytes?.Length ?? 0, Text(f, "sha256"), saved));
            }
            if (files.Any(f => f.SavedAs == null)) notes.Add($"{files.Count(f => f.SavedAs == null)} written file(s) kept by name only: the emulator keeps the content of files up to 10 MB.");
        }

        var (manifest, regions, regionBytes, left, overlapping) = WriteRegions(root, ep, data, arch, output);
        if (overlapping > 0) notes.Add($"{overlapping} region(s) inside another region left out of the region set.");
        if (left > 0) notes.Add($"{left} region(s) of the emulator's own system modules and structures left out of the region set.");
        return new ProgramEmulation(arch, stop, PcOf(error), Reason(error), Text(ep, "ret_val"), calls, files, manifest, regions, regionBytes, elapsed, notes);
    }

    /// <summary>The program's image, its allocations and its stack as region files plus a region-set manifest; (null, 0, 0, left) when none was kept.</summary>
    private static (string? Manifest, int Regions, long Bytes, int Left, int Overlapping) WriteRegions(JsonElement root, JsonElement ep, JsonElement data, string arch, string output)
    {
        if (!ep.TryGetProperty("memory", out var memory) || !memory.TryGetProperty("layout", out var layout) || layout.ValueKind != JsonValueKind.Array) return (null, 0, 0, 0, 0);
        ulong imageBase = Hex(Text(root, "image_base")) ?? 0;
        JsonElement main = default;
        if (memory.TryGetProperty("modules", out var modules) && modules.ValueKind == JsonValueKind.Array)
            main = modules.EnumerateArray().FirstOrDefault(m => Hex(Text(m, "base")) == imageBase);
        ulong imageEnd = imageBase + (main.ValueKind == JsonValueKind.Object ? Hex(Text(main, "size")) ?? 0
            : root.TryGetProperty("size", out var sz) && sz.TryGetUInt64(out var u) ? u : 0);
        var folder = Path.Combine(output, "regions");
        var list = new JsonArray();
        long bytes = 0;
        int left = 0, overlapping = 0;
        var own = new List<(ulong Start, ulong Length, string Tag, string? Prot, string? Ref)>();
        foreach (var r in layout.EnumerateArray())
        {
            var tag = Text(r, "tag") ?? "";
            ulong start = Hex(Text(r, "address")) ?? 0, length = Hex(Text(r, "size")) ?? 0;
            if (!(tag.StartsWith("api.", StringComparison.Ordinal) || tag.StartsWith("emu.stack", StringComparison.Ordinal)
                  || start < imageEnd && start + length > imageBase)) { left++; continue; }
            if (length == 0 || r.TryGetProperty("is_free", out var free) && free.ValueKind == JsonValueKind.True) continue;
            own.Add((start, length, tag, Text(r, "prot"), Text(r, "data_ref")));
        }
        ulong end = 0;
        foreach (var (start, length, tag, prot, reference) in own.OrderBy(o => o.Start))
        {
            // A region set holds no overlapping regions; the emulator places small structures inside raw code's page.
            if (start < end) { overlapping++; continue; }
            if (Blob(data, reference) is not { } content) continue;
            end = start + length;
            Directory.CreateDirectory(folder);
            var file = $"regions/{start:X}.bin";
            File.WriteAllBytes(Path.Combine(output, file), content.Length > (long)length ? content[..(int)length] : content);
            bytes += Math.Min(content.Length, (long)length);
            var region = new JsonObject { ["file"] = file, ["base"] = $"0x{start:X}", ["size"] = $"0x{length:X}", ["tag"] = tag };
            // "???" is a protection the emulator does not know; the region set then reads it as unknown.
            if (prot?.Contains('?', StringComparison.Ordinal) != true) region["protect"] = Protect(prot);
            list.Add(region);
        }
        if (list.Count == 0) return (null, 0, 0, left, overlapping);
        var manifest = new JsonObject
        {
            ["format"] = RegionSetFile.Format, ["arch"] = arch, ["source"] = "speakeasy (emulate_native engine=speakeasy)", ["regions"] = list,
            ["modules"] = main.ValueKind == JsonValueKind.Object
                ? new JsonArray(new JsonObject { ["name"] = Text(main, "name"), ["base"] = $"0x{imageBase:X}", ["size"] = $"0x{imageEnd - imageBase:X}" })
                : new JsonArray(),
        };
        if (ProcessId(ep) is { } pid) manifest["processId"] = pid;
        var path = Path.Combine(output, "regions.json");
        File.WriteAllText(path, manifest.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        return (path, list.Count, bytes, left, overlapping);
    }

    /// <summary>The emulated process id: the entry point's, else its first event's; null when neither names one.</summary>
    private static uint? ProcessId(JsonElement ep) =>
        ep.TryGetProperty("pid", out var pid) && pid.TryGetUInt32(out var p) ? p
        : ep.TryGetProperty("events", out var events) && events.ValueKind == JsonValueKind.Array && events.GetArrayLength() > 0
          && events[0].TryGetProperty("pos", out var pos) && pos.TryGetProperty("pid", out var first) && first.TryGetUInt32(out p) ? p
        : null;

    /// <summary>A blob of the report's data table (zlib and base64, as the emulator stores them); null when absent or unreadable.</summary>
    private static byte[]? Blob(JsonElement data, string? reference)
    {
        if (reference == null || data.ValueKind != JsonValueKind.Object || !data.TryGetProperty(reference, out var blob) || Text(blob, "data") is not { } text) return null;
        try
        {
            var raw = Convert.FromBase64String(text);
            if (Text(blob, "compression") is not "zlib") return raw;
            using var z = new ZLibStream(new MemoryStream(raw), CompressionMode.Decompress);
            using var outBytes = new MemoryStream();
            z.CopyTo(outBytes);
            return outBytes.ToArray();
        }
        catch (Exception ex) when (ex is FormatException or InvalidDataException) { return null; }
    }

    private static string Protect(string? prot) => prot is { Length: 3 }
        ? (prot[0] == 'r' || prot[1] == 'w', prot[1] == 'w', prot[2] == 'x') switch
        {
            (false, false, false) => "none",
            (_, true, true) => "rwx",
            (_, false, true) => "rx",
            (_, true, false) => "rw",
            _ => "r",
        }
        : "none";

    private static string SafeName(string path)
    {
        var name = path.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries).LastOrDefault() ?? "file";
        var safe = new StringBuilder();
        foreach (var c in name) safe.Append(char.IsLetterOrDigit(c) || c is '.' or '-' or '_' ? c : '_');
        return safe.Length == 0 || safe.ToString().All(c => c == '.') ? "file" : safe.ToString();
    }

    private static string? PcOf(JsonElement error) => error.ValueKind == JsonValueKind.Object && Hex(Text(error, "pc")) is { } pc ? $"0x{pc:X}" : null;

    private static string? Reason(JsonElement error) => error.ValueKind != JsonValueKind.Object ? null : Text(error, "api_name") ?? Text(error, "context_summary");

    private static ulong? Hex(string? text) =>
        text is { } s && s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && ulong.TryParse(s.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v) ? v
        : ulong.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out v) ? v : null;

    private static string? Text(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) ? v.ValueKind switch
        {
            JsonValueKind.String => v.GetString(),
            JsonValueKind.Number => v.GetRawText(),
            _ => null,
        } : null;

    private static long? Number(JsonObject args, string name) =>
        args[name] is JsonValue v && v.GetValueKind() == JsonValueKind.Number && long.TryParse(v.ToJsonString(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var n)
            ? n : null;

    private static string Arg(JsonObject args, string name) =>
        args[name]?.GetValueKind() == JsonValueKind.String && args[name]!.GetValue<string>() is { Length: > 0 } value
            ? value
            : throw new ToolError(ErrorCode.InvalidArgument, $"{EmulateOp} needs '{name}'.");
}
