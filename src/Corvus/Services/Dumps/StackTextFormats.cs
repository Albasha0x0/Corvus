using System.Globalization;
using System.Text.RegularExpressions;

namespace Corvus.Services;

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
    /// <summary>The module's GNU build id as the text gives it (Android tombstones), lower-case hex.</summary>
    public string? BuildId { get; init; }
    /// <summary>Which exception of a chain the frame belongs to: 0 the outermost.</summary>
    public int? Segment { get; set; }
    /// <summary>The module's version and time stamp as the same event or list entry gives them.</summary>
    public TextModule? Described { get; init; }
    /// <summary>The text says the fault is outside any module and gives an address.</summary>
    public bool Outside { get; init; }
    /// <summary>The text has a fault offset that is not a 64-bit hex value.</summary>
    public bool OffsetUnreadable { get; init; }
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
    public List<string> Notes { get; } = [];
}

/// <summary>The crash-text parser table, one entry per line shape tried in order; other lines count as unrecognized.
/// Families: mono (Player.log, error.log), dotnet, wer, eventlog, windbg, android.</summary>
internal static class StackTextFormats
{
    public static readonly string[] Families = ["mono", "dotnet", "wer", "eventlog", "windbg", "android"];
    /// <summary>Events resolved per text; further events are counted.</summary>
    public const int MaxEvents = 200;
    private const RegexOptions Options = RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture;

    private delegate bool Rule(Match m, int line, string raw, ParsedStackText into, State state);

    private sealed class State
    {
        public Dictionary<int, (string? Name, string? Value)> Sig { get; } = [];
        public Dictionary<string, string> Fields { get; private set; } = NewFields();
        public List<Dictionary<string, string>> Events { get; } = [];
        public int EventsSkipped { get; private set; }
        public int Depth { get; set; }

        private static Dictionary<string, string> NewFields() => new(StringComparer.OrdinalIgnoreCase);

        // A field seen twice starts the next event.
        public void Set(string key, string value)
        {
            if (key.StartsWith("ev:", StringComparison.Ordinal) && Fields.ContainsKey(key)) Flush();
            Fields[key] = value;
        }

        public void Flush()
        {
            if (!Fields.Keys.Any(k => k.StartsWith("ev:", StringComparison.Ordinal))) return;
            if (Events.Count < MaxEvents) Events.Add(Fields);
            else EventsSkipped++;
            Fields = NewFields();
        }
    }

    private sealed record Entry(string Family, Regex Pattern, Rule Apply);

    // NonBacktracking matches in linear time, so patterns over pasted text need no timeout.
    private static Regex R(string pattern) => new(pattern, Options | RegexOptions.NonBacktracking);

    private static ulong Hex(Group g) => ulong.Parse(g.Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
    private static ulong? HexOrNull(Group g) => g.Success ? Hex(g) : null;
    private static int? IntOrNull(Group g) => g.Success && int.TryParse(g.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null;

    private static readonly Entry[] Table =
    [
        // Mono: at Ns.Type.Method (args) [0x0001a] in <0123...>:0 (Player.log)
        new("mono", R(@"^\s*at (?<sym>[^\s(][^(]*?) ?\((?<args>[^)]*)\) \[0x(?<il>[0-9a-fA-F]+)\] in (?:<(?<mvid>[0-9a-fA-F]{32})(?:#[0-9a-fA-F]+)?>|(?<file>[^<>]+?)):(?<line>\d+)\s*$"),
            (m, line, raw, into, s) => Add(into, Managed(line, raw, "mono", m.Groups["sym"].Value, m.Groups["args"].Value, s) with
            {
                // An all-zero MVID carries no build identity.
                Mvid = m.Groups["mvid"].Success && Guid.ParseExact(m.Groups["mvid"].Value, "N") is var mvid && mvid != Guid.Empty ? mvid : null,
                IlOffset = (int)Hex(m.Groups["il"]),
                File = m.Groups["file"].Success ? m.Groups["file"].Value : null,
                SourceLine = m.Groups["file"].Success ? IntOrNull(m.Groups["line"]) : null,
            })),
        // Mono wrapper frames: at (wrapper managed-to-native) Ns.Type:Method (args)
        new("mono", R(@"^\s*at \((?<wrapper>wrapper [^)]+)\) (?<rest>.+)$"),
            (m, line, raw, into, _) => Add(into, new TextFrame(line, raw, "mono", "managed") { Symbol = $"({m.Groups["wrapper"].Value}) {m.Groups["rest"].Value.Trim()}" })),
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
        // Android tombstone / logcat: #00 pc 0000000000510134  /data/app/.../lib/arm64/libil2cpp.so (offset 0x1000) (sym+12) (BuildId: 3c5c...)
        // pc is the address in the ELF's own layout; an APK-embedded library reads base.apk!libil2cpp.so.
        // The symbol never starts "BuildId:": its proper prefixes, shortest first,
        // then a first difference, which NonBacktracking takes for a lookahead.
        new("android", R(@"^(?:.*?DEBUG\s*:)?\s*#\d+\s+pc\s+(?<pc>[0-9a-fA-F]+)\s+(?<path>[^\s(][^(]*?)(?:\s+\(offset 0x[0-9a-fA-F]+\))?(?:\s+\((?<sym>B|Bu|Bui|Buil|Build|BuildI|BuildId|(?:[^B\n]|B[^u\n]|Bu[^i\n]|Bui[^l\n]|Buil[^d\n]|Build[^I\n]|BuildI[^d\n]|BuildId[^:\n]).*?)(?:\+(?<off>\d+))?\))?(?:\s+\(BuildId: (?<id>[0-9a-fA-F]+)\))?\s*$"),
            (m, line, raw, into, _) =>
            {
                var path = m.Groups["path"].Value.Trim();
                var name = path[(path.LastIndexOfAny(['/', '!']) + 1)..];
                return Add(into, new TextFrame(line, raw, "android", "native")
                {
                    Module = name, Offset = Hex(m.Groups["pc"]), Symbol = m.Groups["sym"].Success ? m.Groups["sym"].Value : null,
                    SymbolOffset = m.Groups["off"].Success ? ulong.Parse(m.Groups["off"].Value, CultureInfo.InvariantCulture) : null,
                    BuildId = m.Groups["id"].Success ? m.Groups["id"].Value.ToLowerInvariant() : null,
                });
            }),
        // Player.log native backtrace: 0x00007FFB12345678 (GameAssembly) [file:line] Symbol | (function-name not available)
        new("mono", R(@"^\s*(?:#\d+\s+)?\(?0x(?<addr>[0-9a-fA-F]{8,16})\)? \((?<module>[^)]+)\) (?<rest>.*)$"),
            (m, line, raw, into, _) => MonoNative(m, line, raw, into)),
        // Module list (error.log): C:\App\GameAssembly.dll:GameAssembly.dll (00007FFB0C3F0000), size: 81616896 (...), fileVersion: 1.2.3.4
        new("mono", R(@"^(?<path>.*?):(?<name>[^:()\\/]+?) \((?<base>[0-9a-fA-F]{8,16})\), size: (?<size>\d+)(?:.*?fileVersion: (?<ver>[\d.]+))?"),
            (m, _, _, into, _) => Module(into, new TextModule(m.Groups["name"].Value.Trim(), Hex(m.Groups["base"]), ulong.Parse(m.Groups["size"].Value, CultureInfo.InvariantCulture),
                m.Groups["ver"].Success ? m.Groups["ver"].Value : null, null))),
        // Managed log line: Ns.Type:Method (args) (at Assets/File.cs:12)
        new("mono", R(@"^\s*(?<type>[A-Za-z_<][\w.<>`+/]*):(?<method>[A-Za-z_.<][\w.<>`|$]*) ?\((?<args>[^)]*)\)(?: \(at (?<file>.+?):(?<line>\d+)\))?\s*$"),
            (m, line, raw, into, s) => Add(into, new TextFrame(line, raw, "mono", "managed")
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
        new("wer", R(@"^\s*(?<k>AppName|AppPath|FriendlyEventName|EventType|NsAppName)=(?<v>.*)$"), (m, _, _, _, s) => { s.Set("wer:" + m.Groups["k"].Value, m.Groups["v"].Value.Trim()); return true; }),
        // Event Log 1000 (Application Error)
        new("eventlog", R(@"^\s*Faulting (?<what>application|module) name: (?<name>[^,]+)(?:, version: (?<ver>[^,]+), time stamp: 0x(?<ts>[0-9a-fA-F]+))?"),
            (m, _, _, _, s) =>
            {
                string p = m.Groups["what"].Value;
                s.Set($"ev:{p}", m.Groups["name"].Value.Trim());
                if (m.Groups["ver"].Success) s.Set($"ev:{p}:version", m.Groups["ver"].Value.Trim());
                if (m.Groups["ts"].Success) s.Set($"ev:{p}:timestamp", m.Groups["ts"].Value);
                return true;
            }),
        new("eventlog", R(@"^\s*(?<k>Exception code|Fault offset|Faulting process id|Faulting module path|Faulting application path|Faulting application start time|Report Id|Faulting package full name|Faulting package-relative application ID):(?:\s+(?<v>.*))?$"),
            (m, _, _, _, s) => { s.Set("ev:" + m.Groups["k"].Value, m.Groups["v"].Value.Trim()); return true; }),
        // Debugger text: 00 000000a1`2b4ff6c8 00007ff6`1234abcd app!Crash+0x5 [c:\src\x.cpp @ 12]
        // The symbol starts like a name (decorated ?f@@, @f@8, <lambda_..>), so a "Crash!!!" banner is no frame.
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
        if (allowed.Contains("eventlog")) text = EventText(text, result, state);
        foreach (var raw in text.Split('\n'))
        {
            number++;
            var line = raw.TrimEnd('\r');
            if (line.Trim().Length == 0) continue;
            bool taken = false;
            foreach (var e in entries)
            {
                var m = e.Pattern.Match(line);
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

    // Application Error EventData names as Windows 11 writes event 1000; the
    // same names appear at https://learn.microsoft.com/en-us/answers/questions/868473
    private static readonly Dictionary<string, string> EventDataFields = new(StringComparer.Ordinal)
    {
        ["AppName"] = "ev:application", ["AppVersion"] = "ev:application:version", ["AppTimeStamp"] = "ev:application:timestamp",
        ["ModuleName"] = "ev:module", ["ModuleVersion"] = "ev:module:version", ["ModuleTimeStamp"] = "ev:module:timestamp",
        ["ExceptionCode"] = "ev:Exception code", ["FaultingOffset"] = "ev:Fault offset",
    };

    private static readonly Regex EventDataItem = R(@"<Data\s+Name\s*=\s*(?:\\?""""?|\\?')(?<k>[A-Za-z]+)(?:\\?""""?|\\?')\s*>(?<v>[^<]*)</Data\s*>");
    private static readonly Regex RenderingInfo = new(@"<RenderingInfo\b.*?</RenderingInfo\s*>", Options | RegexOptions.Singleline | RegexOptions.NonBacktracking);
    private static readonly Regex XmlTag = R(@"</?(?:Event|EventData|System|RenderingInfo)(?:\s[^>]*)?>");
    private static readonly Regex DescriptionStart = R(@"Faulting (?:application|module) name: ");
    private const int EventValueLimit = 512;
    private static readonly Regex DescriptionLabel = R(@"[ \t]+(?<label>(?:Faulting (?:application|module) name|Exception code|Fault offset|Faulting process id|Faulting module path|Faulting application path): )");

    /// <summary>Reads EventData Data elements into fields and splits a description flattened to one line.</summary>
    private static string EventText(string text, ParsedStackText into, State s)
    {
        var items = EventDataItem.Matches(text);
        int read = 0;
        foreach (Match m in items)
        {
            if (!EventDataFields.TryGetValue(m.Groups["k"].Value, out var key)) continue;
            var v = System.Net.WebUtility.HtmlDecode(m.Groups["v"].Value).Trim();
            if (v.Length > EventValueLimit)
            {
                Skipped(into, $"EventData {m.Groups["k"].Value} over {EventValueLimit} characters");
                continue;
            }
            s.Set(key, key.EndsWith(":timestamp", StringComparison.Ordinal) && v.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? v[2..] : v);
            read++;
        }
        if (items.Count > 0)
        {
            into.Formats["eventlog"] = into.Formats.GetValueOrDefault("eventlog") + read;
            // The rendered message repeats the event the EventData gave; read twice, it would count as a second event.
            if (read > 0) text = RenderingInfo.Replace(text, "");
            text = XmlTag.Replace(EventDataItem.Replace(text, ""), "");
        }
        // Only a line that starts a description is split, so other text keeps its lines.
        return string.Join('\n', text.Split('\n').Select(l => DescriptionStart.IsMatch(l) ? DescriptionLabel.Replace(l, "\n${label}") : l));
    }

    private static void Skipped(ParsedStackText into, string what)
    {
        into.Unrecognized++;
        if (into.UnrecognizedSample.Count < 5) into.UnrecognizedSample.Add(what);
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
        // Ns.Type.Method, Ns.Type..ctor, Ns.Outer+Inner.Method[T], Ns.Type:Method
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

    private static readonly Regex MonoSource = R(@"^\[(?<file>[^\]]+?):(?<line>\d+)\]\s*(?<rest>.*)$");
    private static readonly Regex MonoManaged = R(@"^\(?(?:wrapper [^)]+\) )?(?<type>[\w.<>`+/]+):(?<method>[\w.<>`|$]+) ?\((?<args>[^)]*)\)");

    private static bool MonoNative(Match m, int line, string raw, ParsedStackText into)
    {
        var module = m.Groups["module"].Value.Trim();
        var rest = m.Groups["rest"].Value.Trim();
        ulong address = Hex(m.Groups["addr"]);
        string? file = null;
        int? sourceLine = null;
        var src = MonoSource.Match(rest);
        if (src.Success)
        {
            file = src.Groups["file"].Value;
            sourceLine = IntOrNull(src.Groups["line"]);
            rest = src.Groups["rest"].Value;
        }
        if (module.Equals("Mono JIT Code", StringComparison.OrdinalIgnoreCase))
        {
            var managed = MonoManaged.Match(rest);
            return Add(into, new TextFrame(line, raw, "mono", "managed")
            {
                Address = address, Symbol = managed.Success ? $"{managed.Groups["type"].Value}.{managed.Groups["method"].Value}" : rest,
                Type = managed.Success ? managed.Groups["type"].Value.Replace('/', '+') : null, Method = managed.Success ? managed.Groups["method"].Value : null,
                Args = managed.Success ? managed.Groups["args"].Value : null, File = file, SourceLine = sourceLine,
            });
        }
        string? symbol = rest.Length == 0 || rest.Contains("function-name not available", StringComparison.OrdinalIgnoreCase) ? null : rest;
        return Add(into, new TextFrame(line, raw, "mono", "native") { Module = module, Address = address, Symbol = symbol, File = file, SourceLine = sourceLine });
    }

    /// <summary>WER and Event Log fields become the faulting frames (one per event), their modules and the exception code.</summary>
    private static void Finish(ParsedStackText result, State s)
    {
        s.Flush();
        var sig = s.Sig.Values.Where(v => v.Name != null && v.Value != null).ToDictionary(v => v.Name!, v => v.Value!, StringComparer.OrdinalIgnoreCase);
        var events = s.Events.ToList();
        // The WER report is one event; the first event's fields fill what it lacks.
        var first = sig.Count > 0 ? events.FirstOrDefault() : null;
        if (sig.Count > 0 && events.Count > 0) events.RemoveAt(0);
        var frames = new List<TextFrame>();
        if (sig.Count > 0) Fault(result, frames, "wer", sig, first ?? []);
        foreach (var e in events) Fault(result, frames, "eventlog", [], e);
        result.Frames.InsertRange(0, frames);
        if (s.EventsSkipped > 0) result.Notes.Add($"{s.EventsSkipped} further events were not read: the limit is {MaxEvents} events.");
    }

    private static void Fault(ParsedStackText result, List<TextFrame> frames, string family, Dictionary<string, string> sig, Dictionary<string, string> fields)
    {
        string? module = sig.GetValueOrDefault("Fault Module Name") ?? fields.GetValueOrDefault("ev:module");
        string? version = sig.GetValueOrDefault("Fault Module Version") ?? fields.GetValueOrDefault("ev:module:version");
        string? stamp = sig.GetValueOrDefault("Fault Module Timestamp") ?? fields.GetValueOrDefault("ev:module:timestamp");
        string? code = sig.GetValueOrDefault("Exception Code") ?? fields.GetValueOrDefault("ev:Exception code");
        string? offset = sig.GetValueOrDefault("Exception Offset") ?? fields.GetValueOrDefault("ev:Fault offset");
        if (module != null)
        {
            uint? ts = ParseHex(stamp) is { } t and <= uint.MaxValue ? (uint)t : null;
            ulong? value = ParseHex(offset);
            bool unreadable = value == null && !string.IsNullOrWhiteSpace(offset);
            if (unreadable)
                result.Notes.Add($"Fault offset '{(offset!.Length > 40 ? offset[..40] + "..." : offset)}' of {module} is unreadable: it is not a hex value of at most 64 bits.");
            // Windows writes "unknown" with a zero stamp for a fault outside any module; the value is then an address.
            bool outside = module.Equals("unknown", StringComparison.OrdinalIgnoreCase) && ts is null or 0;
            var described = new TextModule(module, null, null, version, ts);
            if (!outside) result.Modules.Add(described);
            frames.Add(new TextFrame(0, $"{module}+{offset}", family, "native")
            {
                Module = outside ? null : module, Offset = outside ? null : value, Address = outside ? value : null,
                Outside = outside, OffsetUnreadable = unreadable, Described = outside ? null : described,
            });
        }
        if (result.Exception is not { Code: not null } && ParseHex(code) is { } c and <= uint.MaxValue)
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
