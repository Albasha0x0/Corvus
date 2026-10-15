using System.ComponentModel;
using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ghidra;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>Static p-code emulation of native code in the Ghidra worker.</summary>
[McpServerToolType]
public sealed class NativeEmulationTools(AssemblyWorkspace workspace, NativeEngineService engines, NativeCodeService? nativeCode = null, NativeNamePush? names = null)
{
    internal const int MaxScratchBytes = 1 << 20;
    internal const int MaxCandidates = 1000;

    [McpServerTool(Name = "emulate_native", Title = "Emulate native code", UseStructuredContent = true, OutputSchemaType = typeof(EmulationReport))]
    [Description("Emulates native code in Ghidra's p-code emulator: string decoders, hashes, computed constants. " +
                 "Memory: image, stack, given writes. Stops on return, stopAt or a budget. Calls run in the image or return stubs= " +
                 "values; an unmodelled call or unmapped read is an error. Reports return value, registers, written strings, reads, trace.")]
    public Task<string> EmulateNative(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string address,
        [Description("Per calling convention: integer, address, or pointer to 'text', u'text', buf:N (zeros) or hex:41A0.")] string? args = null,
        [Description("rcx=0x10, rdx='key' (values as args).")] string? registers = null,
        [Description("ADDR=VALUE: 'text', u'text', hex:.., zero:N, u32:5, ptr:..; outside the image va:0x10000000.")] string? memory = null,
        [Description("Addresses to stop at.")] string? stopAt = null,
        [Description("Calls not run: name=value (GetTickCount=5, kernel32!Sleep=0, 0x180001000=1; *=0 any call).")] string? stubs = null,
        [Description("Shown after the run: ADDR or register, space, length (rcx 64).")] string? read = null,
        [Description("Instruction budget (1-50000000).")] int maxInstructions = 1_000_000,
        [Description("Time budget, s (1-300).")] int timeoutSeconds = 10,
        [Description("Last instructions listed (0-2000).")] int trace = 0,
        [Description("Argument sets, ';'-separated, each as args; one timeoutSeconds covers all.")] string? candidates = null,
        [Description("auto or ghidra.")] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var id = string.IsNullOrWhiteSpace(engine) || engine.Trim().Equals("auto", StringComparison.OrdinalIgnoreCase) ? "ghidra" : engine.Trim().ToLowerInvariant();
        if (id != "ghidra")
            throw new ToolError(ErrorCode.Unsupported, $"emulate_native runs in Ghidra's p-code emulator, not in '{engine!.Trim()}'.",
                $"omit engine or pass engine=ghidra; Ghidra comes from {GhidraOptions.DirectoryVariable}");
        if (maxInstructions is < 1 or > 50_000_000) throw new ToolError(ErrorCode.InvalidArgument, $"maxInstructions must be 1-50000000, not {maxInstructions}.");
        if (timeoutSeconds is < 1 or > 300) throw new ToolError(ErrorCode.InvalidArgument, $"timeoutSeconds must be 1-300, not {timeoutSeconds}.");
        int seconds = timeoutSeconds;
        if (trace is < 0 or > 2000) throw new ToolError(ErrorCode.InvalidArgument, $"trace must be 0-2000, not {trace}.");
        engines.Provider("ghidra");
        var (native, startRva) = await Task.Run(() => NativeAnalysisTools.Resolve(workspace, nativeCode, image, address), cancellationToken);
        var session = await engines.Session(native, "ghidra", new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = $"Ghidra {p.Stage}" })), cancellationToken);
        EngineReport.Answered(new EngineChoice("ghidra", "the p-code emulator is Ghidra's"), engines, session);
        if (session is not GhidraSession ghidra)
            throw new ToolError(ErrorCode.Unsupported, "emulate_native needs a Ghidra session.", "omit engine or pass engine=ghidra");
        if (names != null) await names.EnsureAsync(native, session, cancellationToken);

        var parse = new Inputs(workspace, native, ghidra.ImageBase, nativeCode);
        var request = WorkerRows.Args(("start", Hex(ghidra.ImageBase + startRva)), ("max_instructions", maxInstructions),
            ("seconds", seconds), ("trace", trace));
        if (args != null && candidates != null) throw new ToolError(ErrorCode.InvalidArgument, "Pass args or candidates, not both.", "candidates takes argument sets separated by ';'");
        if (args != null) request["args"] = new JsonArray([.. Split(args).Select(parse.Value)]);
        var sets = candidates != null ? Split(candidates, ';') : null;
        if (sets is { Count: 0 or > MaxCandidates })
            throw new ToolError(ErrorCode.InvalidArgument, $"candidates holds {sets.Count} argument sets; pass 1-{MaxCandidates}.");
        if (sets != null) request["candidates"] = new JsonArray([.. sets.Select(set => (JsonNode)new JsonArray([.. Split(set).Select(parse.Value)]))]);
        if (registers != null) request["registers"] = new JsonArray([.. Split(registers).Select(item => (JsonNode)new JsonArray(Key(item, "registers"), parse.Value(After(item))))]);
        if (memory != null) request["memory"] = new JsonArray([.. Split(memory).Select(parse.Memory)]);
        if (stopAt != null) request["stops"] = new JsonArray([.. Split(stopAt).Select(s => (JsonNode)Hex(parse.Va(s)))]);
        if (stubs != null)
            request["stubs"] = new JsonArray([.. Split(stubs).Select(item => (JsonNode)new JsonArray(Key(item, "stubs"),
                Hex(Integer(After(item)) ?? throw new ToolError(ErrorCode.InvalidArgument, $"The stub value in '{item}' is not an integer."))))]);
        if (read != null) request["reads"] = new JsonArray([.. Split(read).Select(parse.Read)]);
        if (parse.ScratchBytes > MaxScratchBytes) throw new ToolError(ErrorCode.LimitExceeded, $"args and registers copy {parse.ScratchBytes} bytes; the scratch area holds {MaxScratchBytes}.");

        if (sets != null)
        {
            var batch = await ghidra.CallAsync("emulate_batch", request, cancellationToken, timeout: TimeSpan.FromSeconds(seconds + 30));
            var runs = batch.GetProperty("candidates").EnumerateArray().ToList();
            return Mcp.ToolOutput.Report(FormatBatch(native.Id, sets, runs), BatchReport(native.Id, sets, runs));
        }
        var r = await ghidra.CallAsync("emulate", request, cancellationToken, timeout: TimeSpan.FromSeconds(seconds + 30));
        var text = Format(native.Id, r, maxInstructions);
        var stop = r.GetProperty("stop").GetString();
        var where = At(r);
        var detail = r.GetProperty("detail").GetString();
        ToolError? error = stop switch
        {
            "unmodelled_call" => new ToolError(ErrorCode.Unsupported, $"Emulation stopped at {where}: {detail}.",
                "stubs=NAME=VALUE answers that call, stubs=*=0 every call") { Partial = text },
            "memory_fault" => new ToolError(ErrorCode.Failed, $"Emulation stopped at {where}: {detail}.",
                "memory= maps bytes there, or args / registers pass a pointer to a buffer (buf:N)") { Partial = text },
            "unmapped_execute" => new ToolError(ErrorCode.Failed, $"Emulation stopped at {where}: {detail}.", "the trace (trace=50) shows the jump") { Partial = text },
            "error" => new ToolError(ErrorCode.Unsupported, $"Emulation stopped at {where}: {detail}.",
                "an instruction the emulator does not model (system calls, segment bases, interrupts); stopAt= ends before it") { Partial = text },
            "cancelled" => new ToolError(ErrorCode.Cancelled, $"Emulation was cancelled at {where}.") { Partial = text },
            _ => null,
        };
        return error != null ? throw error : Mcp.ToolOutput.Report(text, Report(native.Id, r));
    });

    private static string At(JsonElement r) =>
        r.GetProperty("where").GetString() is { } w ? $"{r.GetProperty("pc").GetString()} ({w})" : r.GetProperty("pc").GetString() ?? "?";

    public sealed record EmulatedRegister(string Name, string Value);
    public sealed record EmulatedCall(string Site, string? Name, string Action, string? Value);
    public sealed record EmulatedMemory(string Va, long Length, string Bytes, string? Text);
    public sealed record EmulatedRead(string? Label, string Va, string? Bytes, string? Text, string? Error);

    /// <summary>One argument set of a candidates batch; Stop not_run when the time budget was spent before it.</summary>
    public sealed record EmulatedCandidate(int Index, string Args, string Stop, string? StoppedAt, string? ReturnValue, long Instructions,
        IReadOnlyList<EmulatedRead> Reads, string? Detail);

    public sealed record EmulationReport(string Image, string Engine, long Instructions, string Stop, string? StoppedAt, string? ReturnRegister, string? ReturnValue,
        IReadOnlyList<EmulatedRegister> Registers, int CallCount, IReadOnlyList<EmulatedCall> Calls, IReadOnlyList<EmulatedMemory> Written,
        IReadOnlyList<EmulatedRead> Reads, IReadOnlyList<IReadOnlyList<string>> Trace)
    {
        public double? ElapsedSeconds { get; init; }
        public IReadOnlyList<EmulatedCandidate>? Candidates { get; init; }
    }

    internal static EmulationReport BatchReport(string imageId, IReadOnlyList<string> sets, IReadOnlyList<JsonElement> runs)
    {
        var candidates = runs.Select((r, i) =>
        {
            var stop = r.GetProperty("stop").GetString() ?? "stopped";
            if (!r.TryGetProperty("instructions", out _)) return new EmulatedCandidate(i + 1, sets[i], stop, null, null, 0, [], null);
            var one = Report(imageId, r);
            return new EmulatedCandidate(i + 1, sets[i], one.Stop, one.StoppedAt, one.ReturnValue, one.Instructions, one.Reads,
                r.TryGetProperty("detail", out var d) && d.ValueKind == JsonValueKind.String ? d.GetString() : null);
        }).ToList();
        return new EmulationReport(imageId, "ghidra", candidates.Sum(c => c.Instructions), "batch", null, null, null, [], 0, [], [], [], [])
            { Candidates = candidates };
    }

    internal static string FormatBatch(string imageId, IReadOnlyList<string> sets, IReadOnlyList<JsonElement> runs)
    {
        var report = BatchReport(imageId, sets, runs);
        var sb = new StringBuilder();
        int returned = report.Candidates!.Count(c => c.Stop == "returned");
        sb.Append(CultureInfo.InvariantCulture, $"{imageId}: Ghidra p-code emulation of {ToolSupport.Plural(sets.Count, "argument set")}, {returned} returned, ")
            .Append(CultureInfo.InvariantCulture, $"{report.Instructions:N0} instructions\n");
        foreach (var c in report.Candidates!)
        {
            sb.Append(CultureInfo.InvariantCulture, $"  #{c.Index} ({c.Args}): ");
            sb.Append(c.Stop switch
            {
                "returned" => $"returned {c.ReturnValue}",
                "not_run" => "not run: the time budget was spent; raise timeoutSeconds",
                _ => c.Stop + (c.StoppedAt != null ? $" at {c.StoppedAt}" : "") + (c.Detail != null ? $": {c.Detail}" : ""),
            });
            if (c.Stop != "not_run") sb.Append(CultureInfo.InvariantCulture, $", {c.Instructions:N0} instructions");
            foreach (var x in c.Reads)
                sb.Append("; ").Append(x.Label ?? x.Va).Append(": ").Append(x.Error ?? x.Text ?? x.Bytes);
            sb.Append('\n');
        }
        return sb.ToString();
    }

    internal static EmulationReport Report(string imageId, JsonElement r)
    {
        string? S(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        var stop = S(r, "stop") ?? "stopped";
        return new EmulationReport(imageId, "ghidra", r.GetProperty("instructions").GetInt64(), stop, stop == "returned" ? null : At(r),
            stop == "returned" ? S(r, "return_register") : null, stop == "returned" ? S(r, "return_value") : null,
            [.. r.GetProperty("registers").EnumerateArray().Where(x => x[2].GetBoolean()).Select(x => new EmulatedRegister(x[0].GetString()!, x[1].GetString()!))],
            r.GetProperty("call_count").GetInt32(),
            [.. r.GetProperty("calls").EnumerateArray().Select(c => new EmulatedCall(S(c, "site") ?? "", S(c, "name") ?? S(c, "target"), S(c, "action") ?? "", S(c, "value")))],
            [.. r.GetProperty("written").EnumerateArray().Select(w =>
            {
                var bytes = Convert.FromHexString(S(w, "bytes") ?? "");
                return new EmulatedMemory(S(w, "va") ?? "", w.GetProperty("length").GetInt64(), Convert.ToHexString(bytes), Ascii(bytes) ?? Utf16(bytes));
            })],
            [.. r.GetProperty("reads").EnumerateArray().Select(x =>
            {
                var hex = S(x, "bytes");
                var bytes = hex != null ? Convert.FromHexString(hex) : null;
                return new EmulatedRead(S(x, "label"), S(x, "va") ?? "", hex, bytes != null ? Ascii(bytes) ?? Utf16(bytes) : null, S(x, "error"));
            })],
            [.. r.GetProperty("trace").EnumerateArray().Select(l => (IReadOnlyList<string>)[l[0].GetString() ?? "", l[1].GetString() ?? ""])])
            { ElapsedSeconds = r.TryGetProperty("seconds", out var s) ? Math.Round(s.GetDouble(), 3) : null };
    }

    internal static string Format(string imageId, JsonElement r, int maxInstructions)
    {
        var sb = new StringBuilder();
        long count = r.GetProperty("instructions").GetInt64();
        var stop = r.GetProperty("stop").GetString();
        string why = stop switch
        {
            "returned" => "returned to the caller",
            "stop_address" => "reached a stop address",
            "instruction_budget" => $"instruction budget ({maxInstructions:N0}) reached",
            "time_budget" => "time budget reached",
            _ => r.GetProperty("detail").GetString() ?? stop ?? "stopped",
        };
        sb.Append(CultureInfo.InvariantCulture, $"{imageId}: Ghidra p-code emulation ({r.GetProperty("language").GetString()}), ")
            .Append(CultureInfo.InvariantCulture, $"{count:N0} instructions\n");
        sb.Append("Stopped: ").Append(why);
        // a return stops on the sentinel return address, which says nothing
        if (stop != "returned") sb.Append(" at ").Append(At(r));
        sb.Append(stop switch
        {
            "instruction_budget" => "; raise maxInstructions to go further",
            "time_budget" => "; raise timeoutSeconds to go further",
            _ => "",
        }).Append('\n');
        if (r.GetProperty("return_register").GetString() is { } rr && stop == "returned")
        {
            var v = r.GetProperty("return_value").GetString()!;
            sb.Append("Return value: ").Append(rr).Append(" = ").Append(v);
            if (BigInteger.TryParse("0" + v[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var n) && n > 9) sb.Append(" (").Append(n).Append(')');
            sb.Append('\n');
        }
        var changed = r.GetProperty("registers").EnumerateArray().Where(x => x[2].GetBoolean()).Select(x => $"{x[0].GetString()}={x[1].GetString()}").ToList();
        sb.Append("Registers changed: ").Append(changed.Count == 0 ? "none" : string.Join(' ', changed)).Append('\n');
        var calls = r.GetProperty("calls");
        int callCount = r.GetProperty("call_count").GetInt32();
        if (callCount > 0)
        {
            sb.Append(CultureInfo.InvariantCulture, $"Calls ({callCount}{(callCount > calls.GetArrayLength() ? $", first {calls.GetArrayLength()}" : "")}):\n");
            foreach (var c in calls.EnumerateArray())
            {
                var name = c.GetProperty("name").GetString() ?? c.GetProperty("target").GetString();
                var action = c.GetProperty("action").GetString();
                sb.Append("  ").Append(c.GetProperty("site").GetString()).Append(" -> ").Append(name).Append(": ")
                    .Append(action == "into" ? "stepped in" : $"{(action == "stub" ? "stubbed" : "skipped")}, returned {c.GetProperty("value").GetString()}").Append('\n');
            }
        }
        var scratch = r.GetProperty("scratch");
        if (scratch.GetArrayLength() > 0)
            sb.Append("Scratch: ").Append(string.Join(", ", scratch.EnumerateArray().Select(s =>
                $"{s.GetProperty("label").GetString()} {s.GetProperty("va").GetString()} ({s.GetProperty("length").GetInt32()} bytes)"))).Append('\n');
        var written = r.GetProperty("written");
        int ranges = r.GetProperty("written_ranges").GetInt32();
        sb.Append(CultureInfo.InvariantCulture, $"Written memory: {ToolSupport.Plural(ranges, "range")}{(ranges > written.GetArrayLength() ? $" (first {written.GetArrayLength()})" : "")}, " +
                                                $"{r.GetProperty("stack_bytes_written").GetInt64()} stack bytes ({r.GetProperty("stack").GetString()})\n");
        foreach (var w in written.EnumerateArray())
        {
            var where = w.GetProperty("where").GetString();
            sb.Append("  ").Append(w.GetProperty("va").GetString()).Append(where != null ? $" ({where})" : "")
                .Append(CultureInfo.InvariantCulture, $" {w.GetProperty("length").GetInt64()} bytes: ")
                .Append(Show(Convert.FromHexString(w.GetProperty("bytes").GetString()!))).Append('\n');
        }
        var reads = r.GetProperty("reads");
        if (reads.GetArrayLength() > 0)
        {
            sb.Append("Reads:\n");
            foreach (var x in reads.EnumerateArray())
            {
                sb.Append("  ");
                if (x.TryGetProperty("label", out var label)) sb.Append(label.GetString()).Append(" -> ");
                sb.Append(x.GetProperty("va").GetString()).Append(": ");
                sb.Append(x.TryGetProperty("error", out var e) ? e.GetString() : Show(Convert.FromHexString(x.GetProperty("bytes").GetString()!))).Append('\n');
            }
        }
        var lines = r.GetProperty("trace");
        if (lines.GetArrayLength() > 0)
        {
            sb.Append(CultureInfo.InvariantCulture, $"Trace (last {lines.GetArrayLength()}):\n");
            foreach (var l in lines.EnumerateArray()) sb.Append("  ").Append(l[0].GetString()).Append("  ").Append(l[1].GetString()).Append('\n');
        }
        return sb.ToString();
    }

    /// <summary>Bytes as a quoted string when they read as ASCII or UTF-16LE text up to a NUL, with the hex of the first 64 bytes otherwise or after it.</summary>
    internal static string Show(byte[] bytes)
    {
        string? text = Ascii(bytes) ?? Utf16(bytes);
        var hex = Convert.ToHexString(bytes, 0, Math.Min(bytes.Length, 64));
        hex = string.Join(' ', Enumerable.Range(0, hex.Length / 2).Select(i => hex.Substring(i * 2, 2))) + (bytes.Length > 64 ? " ..." : "");
        return text != null ? $"{text} | {hex}" : hex;
    }

    private static string? Ascii(byte[] b)
    {
        int n = Array.IndexOf(b, (byte)0);
        if (n < 0) n = b.Length;
        if (n < 2 || b.Take(n).Any(c => c is < 0x20 and not (9 or 10 or 13) || c > 0x7E)) return null;
        return Quote(Encoding.ASCII.GetString(b, 0, Math.Min(n, 1024)), false);
    }

    private static string? Utf16(byte[] b)
    {
        int n = 0;
        while (n + 1 < b.Length && (b[n] | b[n + 1]) != 0) n += 2;
        if (n < 4) return null;
        var s = Encoding.Unicode.GetString(b, 0, Math.Min(n, 2048));
        return s.All(c => c >= 0x20 && !char.IsSurrogate(c) || c is '\t' or '\n' or '\r') ? Quote(s, true) : null;
    }

    private static string Quote(string s, bool wide) =>
        (wide ? "u\"" : "\"") + s.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal).Replace("\r", "\\r", StringComparison.Ordinal).Replace("\t", "\\t", StringComparison.Ordinal) + "\"";

    /// <summary>Items split at <paramref name="separator"/> outside single or double quotes; a backslash escapes the next character.</summary>
    internal static List<string> Split(string text, char separator = ',')
    {
        var items = new List<string>();
        var sb = new StringBuilder();
        char quote = '\0';
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (quote != '\0' && c == '\\' && i + 1 < text.Length) { sb.Append(c).Append(text[++i]); continue; }
            if (quote == '\0' && c is '"' or '\'') quote = c;
            else if (c == quote) quote = '\0';
            if (c == separator && quote == '\0')
            {
                if (sb.ToString().Trim() is { Length: > 0 } item) items.Add(item);
                sb.Clear();
                continue;
            }
            sb.Append(c);
        }
        if (quote != '\0') throw new ToolError(ErrorCode.InvalidArgument, $"Unterminated quote in '{text}'.");
        if (sb.ToString().Trim() is { Length: > 0 } last) items.Add(last);
        return items;
    }

    private static string Key(string item, string parameter)
    {
        int eq = item.IndexOf('=');
        if (eq <= 0) throw new ToolError(ErrorCode.InvalidArgument, $"'{item}' in {parameter} is not NAME=VALUE.");
        return item[..eq].Trim();
    }

    private static string After(string item) => item[(item.IndexOf('=') + 1)..].Trim();

    /// <summary>Decimal or 0x hex, negative as two's complement in 64 bits.</summary>
    internal static ulong? Integer(string text)
    {
        var t = text.Trim();
        if (!TypedValue.IsInteger(t)) return null;
        var bytes = TypedValue.Encode(t.StartsWith('-') ? "i64" : "u64", t, true);
        return BitConverter.ToUInt64(bytes);
    }

    private static string Hex(ulong v) => "0x" + v.ToString("x", CultureInfo.InvariantCulture);

    /// <summary>A string literal in single or double quotes: the text between them with \" \\ \n \t \r \0 unescaped, or null.</summary>
    internal static string? Literal(string text)
    {
        var t = text.Trim();
        if (t.Length < 2 || t[0] is not ('"' or '\'') || t[^1] != t[0]) return null;
        var sb = new StringBuilder();
        for (int i = 1; i < t.Length - 1; i++)
        {
            char c = t[i];
            if (c == '\\' && i + 1 < t.Length - 1)
            {
                c = t[++i];
                sb.Append(c switch { 'n' => '\n', 't' => '\t', 'r' => '\r', '0' => '\0', _ => c });
            }
            else sb.Append(c);
        }
        return sb.ToString();
    }

    /// <summary>Parses addresses and values against one image.</summary>
    private sealed class Inputs(AssemblyWorkspace workspace, LoadedNative native, ulong imageBase, NativeCodeService? code)
    {
        public long ScratchBytes { get; private set; }

        /// <summary>An address in the image (names, rva:, VA) or, outside it, a plain number (va: forces one).</summary>
        public ulong Va(string text)
        {
            var t = text.Trim();
            if (t.StartsWith("va:", StringComparison.OrdinalIgnoreCase) && Integer(t[3..]) is { } forced) return forced;
            try
            {
                return imageBase + workspace.Read(() => NativeAddress.Parse(native.Image, t, code?.Ready(native) is { } index ? index.AddressesOfName : null));
            }
            catch (ToolError) when (Integer(t) is { } raw)
            {
                return raw;
            }
        }

        /// <summary>A number, or bytes the worker copies to its scratch area and passes by address.</summary>
        public JsonNode Value(string text)
        {
            var t = text.Trim();
            byte[]? bytes = null;
            if (Literal(t) is { } ascii) bytes = [.. Encoding.UTF8.GetBytes(ascii), 0];
            else if (t.Length > 2 && t[0] is 'u' or 'U' && Literal(t[1..]) is { } wide)
                bytes = [.. Encoding.Unicode.GetBytes(wide), 0, 0];
            else if (t.StartsWith("buf:", StringComparison.OrdinalIgnoreCase))
                bytes = new byte[Count(t[4..], t)];
            else if (t.StartsWith("hex:", StringComparison.OrdinalIgnoreCase)) bytes = HexBytes(t[4..], t);
            if (bytes != null)
            {
                ScratchBytes += bytes.Length + 32;
                return new JsonObject { ["bytes"] = Convert.ToHexString(bytes) };
            }
            return new JsonObject { ["value"] = Hex(Integer(t) ?? Va(t)) };
        }

        public JsonNode Memory(string item)
        {
            var target = Va(Key(item, "memory"));
            var v = After(item);
            byte[] bytes;
            if (Literal(v) is { } ascii) bytes = [.. Encoding.UTF8.GetBytes(ascii), 0];
            else if (v.Length > 2 && v[0] is 'u' or 'U' && Literal(v[1..]) is { } wide) bytes = [.. Encoding.Unicode.GetBytes(wide), 0, 0];
            else if (v.StartsWith("hex:", StringComparison.OrdinalIgnoreCase)) bytes = HexBytes(v[4..], v);
            else if (v.StartsWith("zero:", StringComparison.OrdinalIgnoreCase)) bytes = new byte[Count(v[5..], v)];
            else if (v.IndexOf(':') is var colon and > 0)
            {
                var type = v[..colon].Trim();
                var value = v[(colon + 1)..].Trim();
                if (TypedValue.IsPointer(type) && !TypedValue.IsInteger(value)) value = Hex(Va(value));
                bytes = TypedValue.Encode(type, value, native.Image.Is64Bit);
            }
            else throw new ToolError(ErrorCode.InvalidArgument, $"Memory value '{v}' is not 'text', u'text', hex:..., zero:N or TYPE:VALUE.", "e.g. 0x10000000=u32:5");
            if (bytes.Length > MaxScratchBytes) throw new ToolError(ErrorCode.LimitExceeded, $"A memory write is limited to {MaxScratchBytes} bytes.");
            return new JsonObject { ["va"] = Hex(target), ["bytes"] = Convert.ToHexString(bytes) };
        }

        public JsonNode Read(string item)
        {
            var parts = item.Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            int length = 64;
            if (parts.Length > 1 && int.TryParse(parts[^1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var n)) { length = n; parts = parts[..^1]; }
            if (length is < 1 or > 65536) throw new ToolError(ErrorCode.InvalidArgument, $"A read length must be 1-65536, not {length}.");
            var where = string.Join(' ', parts);
            try
            {
                return new JsonObject { ["va"] = Hex(Va(where)), ["length"] = length };
            }
            catch (ToolError)
            {
                // not an address: a register the worker resolves
                return new JsonObject { ["register"] = where, ["length"] = length };
            }
        }

        private static int Count(string text, string item) =>
            Integer(text) is { } n && n <= MaxScratchBytes ? (int)n : throw new ToolError(ErrorCode.InvalidArgument, $"'{item}' needs a size up to {MaxScratchBytes}.");

        private static byte[] HexBytes(string text, string item)
        {
            var h = new string([.. text.Where(c => !char.IsWhiteSpace(c))]);
            if (h.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) h = h[2..];
            try { return Convert.FromHexString(h); }
            catch (FormatException) { throw new ToolError(ErrorCode.InvalidArgument, $"'{item}' is not hex bytes."); }
        }
    }
}
