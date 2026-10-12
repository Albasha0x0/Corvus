using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Protocol;
using Corvus.Core;

namespace Corvus.Mcp;

/// <summary>
/// The record of one tools/call (S14.1): an information line on stderr with the tool, outcome, milliseconds, estimated
/// tokens of the text and structured parts and the engine used, never argument values; and the --trace line when tracing.
/// </summary>
public sealed class CallLog
{
    public const string Template = "call tool={Tool} outcome={Outcome} ms={Ms} textTokens={TextTokens} structuredTokens={StructuredTokens} engine={Engine}";

    /// <summary>This server process's run, in server_status and every trace line.</summary>
    public static string RunId { get; } = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(6));

    private readonly CallToolRequestParams? _request;
    private readonly ILogger? _log;
    private readonly CallTrace? _trace;
    private readonly long _started = Stopwatch.GetTimestamp();
    private readonly Native.Providers.EngineUse.Record _engine;

    private CallLog(CallToolRequestParams? request, IServiceProvider? services)
    {
        _request = request;
        _log = services?.GetService<ILoggerFactory>()?.CreateLogger("Corvus.Calls") is { } l && l.IsEnabled(LogLevel.Information) ? l : null;
        _trace = CallTrace.For(services?.GetService<ServerOptions>());
        _engine = Native.Providers.EngineUse.Begin();
    }

    /// <summary>Starts the record on the call's flow (the engine record lives there).</summary>
    public static CallLog Begin(CallToolRequestParams? request, IServiceProvider? services) => new(request, services);

    public double Milliseconds => Stopwatch.GetElapsedTime(_started).TotalMilliseconds;

    /// <summary>The external engine (ida, ghidra) the call sent requests to, or null.</summary>
    public string? Engine => _engine.Engine;

    public void Cancelled() => Write("cancelled", null, 0, 0);

    public void Completed(CallToolResult result)
    {
        var (text, structured) = Tokens(result);
        Write(result.IsError == true ? CodeOf(result) : "ok", result, text, structured);
    }

    private void Write(string outcome, CallToolResult? result, long textTokens, long structuredTokens)
    {
        var ms = Milliseconds;
        _log?.LogInformation(Template, _request?.Name, outcome, (long)ms, textTokens, structuredTokens, Engine ?? "-");
        _trace?.Record(_request?.Name, _request?.Arguments, ms, outcome == "ok" ? null : outcome, result, textTokens, structuredTokens);
    }

    /// <summary>The error code of an error result, or "error".</summary>
    public static string CodeOf(CallToolResult result)
    {
        if (ErrorResult.JsonOf(result) is not { } json) return "error";
        try
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.TryGetProperty("code", out var code) && code.GetString() is { Length: > 0 } c ? c : "error";
        }
        catch (JsonException)
        {
            return "error";
        }
    }

    /// <summary>Estimated tokens of the text blocks and of the structured content.</summary>
    public static (long Text, long Structured) Tokens(CallToolResult result) =>
        (result.Content.OfType<TextContentBlock>().Sum(b => EstimateTokens(b.Text)),
         result.StructuredContent is { } s ? EstimateTokens(s.GetRawText()) : 0);

    /// <summary>
    /// Token estimate of S1.2 (letter runs /4, digit runs /3, symbols, newlines and non-ASCII 1 each, space runs /8); a
    /// local stand-in until the shared estimator lands.
    /// </summary>
    internal static long EstimateTokens(ReadOnlySpan<char> text)
    {
        long tokens = 0;
        int i = 0;
        while (i < text.Length)
        {
            char c = text[i];
            int start = i;
            if (char.IsAsciiLetter(c))
            {
                while (i < text.Length && char.IsAsciiLetter(text[i])) i++;
                tokens += (i - start + 3) / 4;
            }
            else if (char.IsAsciiDigit(c))
            {
                while (i < text.Length && char.IsAsciiDigit(text[i])) i++;
                tokens += (i - start + 2) / 3;
            }
            else if (c == ' ')
            {
                while (i < text.Length && text[i] == ' ') i++;
                tokens += (i - start + 7) / 8;
            }
            else
            {
                if (char.IsHighSurrogate(c) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1])) i++;
                i++;
                tokens++;
            }
        }
        return tokens;
    }
}
