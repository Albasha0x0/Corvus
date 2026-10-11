using System.Globalization;
using System.Text.RegularExpressions;

namespace NetDecompilerMcp.Services;

/// <summary>A stack frame as written in crash text: a native module and offset or address, or a managed method.</summary>
internal sealed record TextFrame(int Line, string Raw, string Format, string Kind)
{
    public string? Module { get; init; }
    public ulong? Offset { get; init; }
    public ulong? Address { get; init; }
    /// <summary>The name the text gives the frame (function, or Ns.Type.Method for managed frames).</summary>
    public string? Symbol { get; init; }
    /// <summary>Offset after the symbol (func+0x1a), or the NativeAOT method offset.</summary>
    public ulong? SymbolOffset { get; init; }
    public string? Type { get; init; }
    public string? Method { get; init; }
    public string? Args { get; init; }
    public Guid? Mvid { get; init; }
    public int? IlOffset { get; init; }
    public string? File { get; init; }
    public int? SourceLine { get; init; }
    /// <summary>Which exception of a chain the frame belongs to: 0 the outermost.</summary>
    public int? Segment { get; set; }
}

/// <summary>A module named with its load address (a crash log's module list), version or timestamp.</summary>
internal sealed record TextModule(string Name, ulong? Base, ulong? Size, string? Version, uint? TimeDateStamp);

/// <summary>An exception named in the text, with its inner chain.</summary>
internal sealed record TextException(string? Type, string? Message, uint? Code, IReadOnlyList<(string Type, string? Message)> Inner);

/// <summary>What the parser table made of a text.</summary>
internal sealed class ParsedStackText
{
    public List<TextFrame> Frames { get; } = [];
    public List<TextModule> Modules { get; } = [];
    public TextException? Exception { get; set; }
    public int Unrecognized { get; set; }
    public List<string> UnrecognizedSample { get; } = [];
    public Dictionary<string, int> Formats { get; } = [];
}

/// <summary>
/// The crash-text parser table: one entry per recognized line shape, tried in order on each line; a line no entry
/// takes is counted as unrecognized. Families: unity (Player.log / error.log native backtraces, module lists, Mono and
/// Il2Cpp managed lines), dotnet (exception text, NativeAOT), wer (Report.wer), eventlog (Application Error 1000 and
/// .NET Runtime 1026 text), windbg (k output, module!function+0x.., module+0x..).
/// </summary>
internal static class StackTextFormats
{
    public static readonly string[] Families = ["unity", "dotnet", "wer", "eventlog", "windbg"];
    private const RegexOptions Options = RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture;
    private static readonly TimeSpan Limit = TimeSpan.FromMilliseconds(200);

    private delegate bool Rule(Match m, int line, string raw, ParsedStackText into, State state);

    private sealed class State
    {
        public Dictionary<int, (string? Name, string? Value)> Sig { get; } = [];
        public Dictionary<string, string> Fields { get; } = new(StringComparer.OrdinalIgnoreCase);
        public int Depth { get; set; }
    }

    private sealed record Entry(string Family, Regex Pattern, Rule Apply);

    private static Regex R(string pattern) => new(pattern, Options, Limit);

    private static ulong Hex(Group g) => ulong.Parse(g.Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
    private static ulong? HexOrNull(Group g) => g.Success ? Hex(g) : null;
    private static int? IntOrNull(Group g) => g.Success && int.TryParse(g.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null;

    private static readonly Entry[] Table =
    [
        // Mono: at Ns.Type.Method (args) [0x0001a] in <0123...>:0 (Unity Mono Player.log)
        new("unity", R(@"^\s*at (?<sym>[^\s(][^(]*?) ?\((?<args>[^)]*)\) \[0x(?<il>[0-9a-fA-F]+)\] in (?:<(?<mvid>[0-9a-fA-F]{32})(?:#[0-9a-fA-F]+)?>|(?<file>[^<>]+?)):(?<line>\d+)\s*$"),
            (m, line, raw, into, s) => Add(into, Managed(line, raw, "unity", m.Groups["sym"].Value, m.Groups["args"].Value, s) with
            {
                Mvid = m.Groups["mvid"].Success ? Guid.ParseExact(m.Groups["mvid"].Value, "N") : null,
                IlOffset = (int)Hex(m.Groups["il"]),
                File = m.Groups["file"].Success ? m.Groups["file"].Value : null,
                SourceLine = m.Groups["file"].Success ? IntOrNull(m.Groups["line"]) : null,
            })),
        // Mono wrapper frames: at (wrapper managed-to-native) Ns.Type:Method (args)
        new("unity", R(@"^\s*at \((?<wrapper>wrapper [^)]+)\) (?<rest>.+)$"),
            (m, line, raw, into, _) => Add(into, new TextFrame(line, raw, "unity", "managed") { Symbol = $"({m.Groups["wrapper"].Value}) {m.Groups["rest"].Value.Trim()}" })),
        // NativeAOT without metadata: at App!<BaseAddress>+0x5a1b2c
        new("dotnet", R(@"^\s*at (?<module>[\w.-]+)!<BaseAddress>\+0x(?<off>[0-9a-fA-F]+)\s*$"),
            (m, line, raw, into, s) => Add(into, new TextFrame(line, raw, "dotnet", "native") { Module = m.Groups["module"].Value, Offset = Hex(m.Groups["off"]), Segment = s.Depth })),
        // .NET: at Ns.Type.Method(args) in file:line N | at Ns.Type.Method(args) + 0x2a (NativeAOT)
        new("dotnet", R(@"^\s*at (?<sym>[^\s(][^(]*?)\((?<args>[^)]*)\)(?: in (?<file>.+?):line (?<line>\d+))?(?: \+ ?0x(?<off>[0-9a-fA-F]+))?\s*$"),
            (m, line, raw, into, s) => Add(into, Managed(line, raw, "dotnet", m.Groups["sym"].Value, m.Groups["args"].Value, s) with
            {
                File = m.Groups["file"].Success ? m.Groups["file"].Value : null,
                SourceLine = IntOrNull(m.Groups["line"]),
                SymbolOffset = HexOrNull(m.Groups["off"]),
            })),
        // .NET Core puts each inner exception on its own line: " ---> Ns.Inner: message"
        new("dotnet", R(@"^\s*---> (?<text>.+)$"), (m, _, _, into, s) => Inner(into, s, m.Groups["text"].Value)),
        new("dotnet", R(@"^\s*--- End of inner exception stack trace ---\s*$"),
            (_, _, _, _, s) => { s.Depth = Math.Max(0, s.Depth - 1); return true; }),
        new("dotnet", R(@"^\s*--- End of stack trace from previous location( where exception was thrown)? ---\s*$"), (_, _, _, _, _) => true),
        // .NET Runtime event 1026: Exception Info: System.X
        new("eventlog", R(@"^\s*Exception Info: (?<type>[A-Za-z_][\w.`+]*)(?:: (?<msg>.*))?$"),
            (m, _, _, into, s) => Header(into, s, m.Groups["type"].Value + (m.Groups["msg"].Success ? ": " + m.Groups["msg"].Value : ""))),
        // Exception header: [Unhandled exception. ]Ns.SomeException: message ---> Ns.Inner: message
        new("dotnet", R(@"^\s*(?:Unhandled [Ee]xception\.?\s*|Unhandled exception: )?(?<text>(?:(?:[A-Za-z_][\w`]*\.)+[A-Za-z_][\w`+]*(?:Exception|Error|Failure)\w*|[A-Za-z_][\w`]*Exception)(?::.*)?)$"),
            (m, _, _, into, s) => Header(into, s, m.Groups["text"].Value)),
        // Unity native backtrace: 0x00007FFB12345678 (GameAssembly) [file:line] Symbol | (function-name not available)
        new("unity", R(@"^\s*(?:#\d+\s+)?\(?0x(?<addr>[0-9a-fA-F]{8,16})\)? \((?<module>[^)]+)\) (?<rest>.*)$"),
            (m, line, raw, into, _) => UnityNative(m, line, raw, into)),
        // Unity module list (error.log): C:\Game\GameAssembly.dll:GameAssembly.dll (00007FFB0C3F0000), size: 81616896 (...), fileVersion: 1.2.3.4
        new("unity", R(@"^(?<path>.*?):(?<name>[^:()\\/]+?) \((?<base>[0-9a-fA-F]{8,16})\), size: (?<size>\d+)(?:.*?fileVersion: (?<ver>[\d.]+))?"),
            (m, _, _, into, _) => Module(into, new TextModule(m.Groups["name"].Value.Trim(), Hex(m.Groups["base"]), ulong.Parse(m.Groups["size"].Value, CultureInfo.InvariantCulture),
                m.Groups["ver"].Success ? m.Groups["ver"].Value : null, null))),
        // Unity / Il2Cpp managed log line: Ns.Type:Method (args) (at Assets/File.cs:12)
        new("unity", R(@"^\s*(?<type>[A-Za-z_<][\w.<>`+/]*):(?<method>[A-Za-z_.<][\w.<>`|$]*) ?\((?<args>[^)]*)\)(?: \(at (?<file>.+?):(?<line>\d+)\))?\s*$"),
            (m, line, raw, into, s) => Add(into, new TextFrame(line, raw, "unity", "managed")
            {
                Symbol = $"{m.Groups["type"].Value}.{m.Groups["method"].Value}", Type = m.Groups["type"].Value.Replace('/', '+'), Method = m.Groups["method"].Value,
                Args = m.Groups["args"].Value, File = m.Groups["file"].Success ? m.Groups["file"].Value : null, SourceLine = IntOrNull(m.Groups["line"]),
            })),
        // WER Report.wer: Sig[n].Name / Sig[n].Value
        new("wer", R(@"^\s*Sig\[(?<i>\d+)\]\.(?<kind>Name|Value)=(?<v>.*)$"),
            (m, _, _, _, s) =>
            {
                int i = int.Parse(m.Groups["i"].Value, CultureInfo.InvariantCulture);
                var e = s.Sig.GetValueOrDefault(i);
                s.Sig[i] = m.Groups["kind"].Value == "Name" ? (m.Groups["v"].Value.Trim(), e.Value) : (e.Name, m.Groups["v"].Value.Trim());
                return true;
            }),
        new("wer", R(@"^\s*(?<k>AppName|AppPath|FriendlyEventName|EventType|NsAppName)=(?<v>.*)$"), (m, _, _, _, s) => { s.Fields["wer:" + m.Groups["k"].Value] = m.Groups["v"].Value.Trim(); return true; }),
        // Event Log 1000 (Application Error)
        new("eventlog", R(@"^\s*Faulting (?<what>application|module) name: (?<name>[^,]+), version: (?<ver>[^,]+), time stamp: 0x(?<ts>[0-9a-fA-F]+)"),
            (m, _, _, _, s) =>
            {
                string p = m.Groups["what"].Value;
                s.Fields[$"ev:{p}"] = m.Groups["name"].Value.Trim();
                s.Fields[$"ev:{p}:version"] = m.Groups["ver"].Value.Trim();
                s.Fields[$"ev:{p}:timestamp"] = m.Groups["ts"].Value;
                return true;
            }),
        new("eventlog", R(@"^\s*(?<k>Exception code|Fault offset|Faulting process id|Faulting module path|Faulting application path): (?<v>.+)$"),
            (m, _, _, _, s) => { s.Fields["ev:" + m.Groups["k"].Value] = m.Groups["v"].Value.Trim(); return true; }),
        // Debugger text: 00 000000a1`2b4ff6c8 00007ff6`1234abcd app!Crash+0x5 [c:\src\x.cpp @ 12]
        // The symbol starts like a name (decorated ?f@@, @f@8, <lambda_..>), so Unity's "Crash!!!" banner is no frame.
        new("windbg", R(@"^(?:\s*[0-9a-fA-F]{2,}\s+)?(?:[0-9a-fA-F`]{8,17}\s+){0,2}(?<module>[A-Za-z_][\w.-]*)!(?<sym>[A-Za-z_?@$<~][^\s+\[]*)(?:\+0x(?<off>[0-9a-fA-F]+))?(?:\s+\[(?<src>[^\]]+)\])?\s*$"),
            (m, line, raw, into, _) => Add(into, new TextFrame(line, raw, "windbg", "native")
            {
                Module = m.Groups["module"].Value, Symbol = m.Groups["sym"].Value, SymbolOffset = HexOrNull(m.Groups["off"]) ?? 0,
            })),
        new("windbg", R(@"^(?:\s*[0-9a-fA-F]{2,}\s+)?(?:[0-9a-fA-F`]{8,17}\s+){0,2}(?<module>[A-Za-z_][\w.-]*)\+0x(?<off>[0-9a-fA-F]+)\s*$"),
            (m, line, raw, into, _) => Add(into, new TextFrame(line, raw, "windbg", "native") { Module = m.Groups["module"].Value, Offset = Hex(m.Groups["off"]) })),
        // A bare address on its own line (resolved through moduleBases or a module list)
        new("windbg", R(@"^\s*(?:[0-9a-fA-F]{2}\s+)?0x(?<addr>[0-9a-fA-F]{6,16})\s*$"),
            (m, line, raw, into, _) => Add(into, new TextFrame(line, raw, "windbg", "native") { Address = Hex(m.Groups["addr"]) })),
    ];

    /// <summary>Parses <paramref name="text"/> with the families allowed by <paramref name="format"/> (auto: all).</summary>
    public static ParsedStackText Parse(string text, string format)
    {
        var allowed = format == "auto" ? Families.ToHashSet() : [format];
        if (format == "eventlog") allowed.Add("dotnet"); // event 1026 carries .NET exception text
        var entries = Table.Where(e => allowed.Contains(e.Family)).ToArray();
        var result = new ParsedStackText();
        var state = new State();
        int number = 0;
        foreach (var raw in text.Split('\n'))
        {
            number++;
            var line = raw.TrimEnd('\r');
            if (line.Trim().Length == 0) continue;
            bool taken = false;
            foreach (var e in entries)
            {
                Match m;
                try { m = e.Pattern.Match(line); }
                catch (RegexMatchTimeoutException) { continue; }
                if (!m.Success || !e.Apply(m, number, line.Trim(), result, state)) continue;
                result.Formats[e.Family] = result.Formats.GetValueOrDefault(e.Family) + 1;
                taken = true;
                break;
            }
            if (!taken)
            {
                result.Unrecognized++;
                if (result.UnrecognizedSample.Count < 5) result.UnrecognizedSample.Add(line.Length > 200 ? line[..200] + "..." : line);
            }
        }
        Finish(result, state);
        return result;
    }

    private static bool Add(ParsedStackText into, TextFrame frame)
    {
        into.Frames.Add(frame);
        return true;
    }

    private static bool Module(ParsedStackText into, TextModule module)
    {
        into.Modules.Add(module);
        return true;
    }

    private static TextFrame Managed(int line, string raw, string format, string symbol, string args, State s)
    {
        symbol = symbol.Trim();
        // Ns.Type.Method, Ns.Type..ctor, Ns.Outer+Inner.Method[T], Ns.Type:Method (Unity)
        int split = symbol.LastIndexOf("..", StringComparison.Ordinal) is var dd and > 0 ? dd : symbol.LastIndexOf('.');
        var method = split > 0 ? symbol[(split + 1)..] : symbol;
        var type = split > 0 ? symbol[..split] : null;
        int generic = method.IndexOfAny(['[', '<'], 1);
        if (generic > 0 && !method.StartsWith('<')) method = method[..generic];
        return new TextFrame(line, raw, format, "managed")
        {
            Symbol = symbol, Type = type?.Replace('/', '+'), Method = method, Args = args.Trim(), Segment = format == "dotnet" ? s.Depth : null,
        };
    }

    /// <summary>"Outer: message ---> Inner: message ---> ...": the first header starts the chain; frames that follow belong to the innermost.</summary>
    private static bool Header(ParsedStackText into, State s, string text)
    {
        if (into.Exception is { Type: not null }) return true; // the first header wins; later ones repeat it
        var parts = text.Split(" ---> ");
        (string Type, string? Message) Split(string p)
        {
            int colon = p.IndexOf(": ", StringComparison.Ordinal);
            return colon > 0 ? (p[..colon].Trim(), p[(colon + 2)..].Trim()) : (p.Trim().TrimEnd(':'), null);
        }
        var outer = Split(parts[0]);
        into.Exception = new TextException(outer.Type, outer.Message, into.Exception?.Code, parts.Skip(1).Select(Split).ToList());
        s.Depth = parts.Length - 1;
        return true;
    }

    private static bool Inner(ParsedStackText into, State s, string text)
    {
        if (into.Exception is not { Type: not null } e) return Header(into, s, text);
        var parts = text.Split(" ---> ").Select(p =>
        {
            int colon = p.IndexOf(": ", StringComparison.Ordinal);
            return colon > 0 ? (p[..colon].Trim(), (string?)p[(colon + 2)..].Trim()) : (p.Trim().TrimEnd(':'), null);
        });
        into.Exception = e with { Inner = [.. e.Inner, .. parts] };
        s.Depth = into.Exception.Inner.Count;
        return true;
    }

    private static bool UnityNative(Match m, int line, string raw, ParsedStackText into)
    {
        var module = m.Groups["module"].Value.Trim();
        var rest = m.Groups["rest"].Value.Trim();
        ulong address = Hex(m.Groups["addr"]);
        string? file = null;
        int? sourceLine = null;
        var src = Regex.Match(rest, @"^\[(?<file>[^\]]+?):(?<line>\d+)\]\s*(?<rest>.*)$", Options, Limit);
        if (src.Success)
        {
            file = src.Groups["file"].Value;
            sourceLine = IntOrNull(src.Groups["line"]);
            rest = src.Groups["rest"].Value;
        }
        if (module.Equals("Mono JIT Code", StringComparison.OrdinalIgnoreCase))
        {
            var managed = Regex.Match(rest, @"^\(?(?:wrapper [^)]+\) )?(?<type>[\w.<>`+/]+):(?<method>[\w.<>`|$]+) ?\((?<args>[^)]*)\)", Options, Limit);
            return Add(into, new TextFrame(line, raw, "unity", "managed")
            {
                Address = address, Symbol = managed.Success ? $"{managed.Groups["type"].Value}.{managed.Groups["method"].Value}" : rest,
                Type = managed.Success ? managed.Groups["type"].Value.Replace('/', '+') : null, Method = managed.Success ? managed.Groups["method"].Value : null,
                Args = managed.Success ? managed.Groups["args"].Value : null, File = file, SourceLine = sourceLine,
            });
        }
        string? symbol = rest.Length == 0 || rest.Contains("function-name not available", StringComparison.OrdinalIgnoreCase) ? null : rest;
        return Add(into, new TextFrame(line, raw, "unity", "native") { Module = module, Address = address, Symbol = symbol, File = file, SourceLine = sourceLine });
    }

    /// <summary>WER and Event Log fields become the faulting frame, its module and the exception code.</summary>
    private static void Finish(ParsedStackText result, State s)
    {
        var sig = s.Sig.Values.Where(v => v.Name != null && v.Value != null).ToDictionary(v => v.Name!, v => v.Value!, StringComparer.OrdinalIgnoreCase);
        string? module = sig.GetValueOrDefault("Fault Module Name") ?? s.Fields.GetValueOrDefault("ev:module");
        string? version = sig.GetValueOrDefault("Fault Module Version") ?? s.Fields.GetValueOrDefault("ev:module:version");
        string? stamp = sig.GetValueOrDefault("Fault Module Timestamp") ?? s.Fields.GetValueOrDefault("ev:module:timestamp");
        string? code = sig.GetValueOrDefault("Exception Code") ?? s.Fields.GetValueOrDefault("ev:Exception code");
        string? offset = sig.GetValueOrDefault("Exception Offset") ?? s.Fields.GetValueOrDefault("ev:Fault offset");
        string family = sig.Count > 0 ? "wer" : "eventlog";
        if (module != null)
        {
            uint? ts = ParseHex(stamp) is { } t and <= uint.MaxValue ? (uint)t : null;
            result.Modules.Add(new TextModule(module, null, null, version, ts));
            result.Frames.Insert(0, new TextFrame(0, $"{module}+{offset}", family, "native") { Module = module, Offset = ParseHex(offset) });
        }
        if (ParseHex(code) is { } c and <= uint.MaxValue)
            result.Exception = (result.Exception ?? new TextException(null, null, null, [])) with { Code = (uint)c };
    }

    private static ulong? ParseHex(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var t = text.Trim();
        if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) t = t[2..];
        return ulong.TryParse(t, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v) ? v : null;
    }
}
