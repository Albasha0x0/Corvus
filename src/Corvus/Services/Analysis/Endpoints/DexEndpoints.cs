using System.Text;
using Corvus.Core.Mobile;
using Corvus.Core.Protobuf;

namespace Corvus.Services.Analysis.Endpoints;

/// <summary>
/// Endpoints and protobuf descriptors in an app's DEX files. Retrofit interface methods come from their HTTP annotations
/// (the annotation types named, or, when R8 renamed them, mapped back through Retrofit's own annotation parser, which tests
/// each type and then names its HTTP method); base URLs from Retrofit.Builder.baseUrl joined through create(Api.class).
/// Calls into OkHttp, Ktor, Volley, java.net.URL, WebView and gRPC are followed through one method's registers in code
/// order: const-string, StringBuilder chains, String.concat / format and Kotlin string templates fold to templates.
/// Absolute URL literals no call consumes are listed as client url. Java descriptorData (Latin-1 string constants in one
/// method) is read as FileDescriptorProto. Add every DEX of the app, then <see cref="Finish"/>.
/// </summary>
internal sealed class DexEndpoints
{
    private static readonly string[] Verbs = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

    private static readonly string[] Clients =
    [
        "Lokhttp3/", "okhttp", "Lcom/squareup/okhttp/", "okhttp", "Lio/ktor/", "ktor", "Lcom/android/volley/", "volley",
        "Lorg/apache/http/", "apache-http", "Ljava/net/URL;", "urlconnection", "Ljava/net/URI;", "urlconnection", "Landroid/webkit/WebView;", "webview",
        "Lio/grpc/", "grpc",
    ];

    private sealed record Annotated(string Type, IReadOnlyList<(string Name, DexValue Value)> Elements, string Member, string Interface, string File,
        IReadOnlyList<string> Query);

    private readonly List<Annotated> _annotated = [];
    private readonly Dictionary<string, string> _verbOfType = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _baseOfInterface = new(StringComparer.Ordinal);
    private readonly HashSet<string> _bases = new(StringComparer.Ordinal);
    private readonly List<CodeEndpoint> _rows = [];
    private readonly List<FoundDescriptor> _descriptors = [];

    /// <summary>A register's value: a string template, an int, a class, or a StringBuilder under construction.</summary>
    private sealed class Reg
    {
        public string? Text;
        public bool Literal;
        public long? Int;
        public string? Type;
        public StringBuilder? Builder;
        public bool BuilderLiteral;
        public int Const = -1; // offset of the const-string that loaded it
        public static readonly Reg Unknown = new() { Text = "{}" };
    }

    public void Add(DexFile dex, string file, CancellationToken ct)
    {
        var relevant = new bool[dex.StringCount];
        bool anyDescriptor = false;
        for (int i = 0; i < relevant.Length; i++)
        {
            var s = dex.String(i);
            bool descriptor = ProtoScan.StartsDescriptor(s);
            anyDescriptor |= descriptor;
            relevant[i] = descriptor || s.Contains('/', StringComparison.Ordinal) || Verbs.Contains(s) || s.Contains("://", StringComparison.Ordinal);
        }
        var sinks = new bool[dex.MethodCount];
        for (int i = 0; i < sinks.Length; i++)
        {
            var m = dex.Method(i);
            sinks[i] = m.Class.StartsWith("Lio/grpc/", StringComparison.Ordinal) || m.Name is "generateFullMethodName";
        }
        foreach (var c in dex.Classes)
        {
            ct.ThrowIfCancellationRequested();
            bool isInterface = (c.Access & 0x200) != 0;
            if (isInterface && c.AnnotationsOffset != 0) Annotations(dex, c, file);
            foreach (var em in dex.ClassData(c).Methods)
            {
                if (em.CodeOffset == 0 || dex.Code(em.CodeOffset) is not { } code) continue;
                if (!Interesting(code.Instructions, relevant, sinks)) continue;
                var instructions = Dalvik.Decode(code.Instructions);
                Method(dex, file, dex.Method(em.MethodIndex), instructions);
                if (anyDescriptor) Descriptors(dex, file, dex.Method(em.MethodIndex).Descriptor, instructions);
            }
        }
    }

    /// <summary>Whether a method loads a relevant string or calls a sink, read from the raw code units without decoding.</summary>
    private static bool Interesting(ushort[] code, bool[] strings, bool[] methods)
    {
        for (int at = 0; at < code.Length;)
        {
            ushort u = code[at];
            int op = u & 0xFF;
            if (op == 0 && (u >> 8) is 1 or 2 or 3)
            {
                if (Dalvik.DecodeOne(code, at) is not { } payload) return false;
                at += payload.Length;
                continue;
            }
            int units = Dalvik.Units(Dalvik.Ops[op].Format);
            if (at + units > code.Length) return false;
            if (op == 0x1a && code[at + 1] < strings.Length && strings[code[at + 1]]) return true;
            if (op == 0x1b && (code[at + 1] | code[at + 2] << 16) is var si && si >= 0 && si < strings.Length && strings[si]) return true;
            if (op is >= 0x6e and <= 0x72 or >= 0x74 and <= 0x78 && code[at + 1] < methods.Length && methods[code[at + 1]]) return true;
            at += units;
        }
        return false;
    }

    private void Annotations(DexFile dex, DexClass c, string file)
    {
        var a = dex.Annotations(c);
        foreach (var (methodIndex, set) in a.Methods)
            foreach (var an in set)
            {
                if (an.Visibility != "runtime") continue;
                bool path = an.Elements.Any(e => e.Name is "value" or "path" && e.Value.Kind == "string");
                if (!path) continue;
                var query = new List<string>();
                if (a.Parameters.TryGetValue(methodIndex, out var parameters))
                    foreach (var p in parameters)
                        foreach (var pa in p)
                            if (pa.Type == "Lretrofit2/http/Query;" && pa.Elements.FirstOrDefault(e => e.Name == "value").Value is { Kind: "string", Value: string q }) query.Add(q);
                _annotated.Add(new Annotated(an.Type, an.Elements, dex.Method(methodIndex).Descriptor, c.Descriptor, file, query));
            }
    }

    private void Method(DexFile dex, string file, DexMethodRef method, List<DalvikInstruction> instructions)
    {
        var regs = new Dictionary<int, Reg>();
        var consumed = new HashSet<int>();
        bool library = Client(method.Class) != null; // the HTTP library's own code calling itself
        Reg result = Reg.Unknown;
        string? lastType = null;
        var verbCandidates = new Dictionary<string, string>(StringComparer.Ordinal);
        var methodBases = new List<string>();
        var created = new List<string>();
        var ktorRows = new List<int>();
        var ktorVerbs = new HashSet<string>(StringComparer.Ordinal);
        Reg Get(int r) => regs.TryGetValue(r, out var v) ? v : Reg.Unknown;
        void Consume(Reg v) { if (v.Const >= 0) consumed.Add(v.Const); }
        void Row(string verb, Reg url, string client, int offset)
        {
            Consume(url);
            if (url.Text == null || !url.Literal || url.Text.Length > 2048) return;
            _rows.Add(new CodeEndpoint(verb, EndpointTemplates.Rooted(url.Text), client, file, method.Descriptor, $"+0x{offset:x}"));
        }

        foreach (var i in instructions)
        {
            switch (i.Opcode)
            {
                case 0x1a or 0x1b:
                    var text = dex.String(i.Index);
                    regs[i.A] = new Reg { Text = text, Literal = true, Const = i.Offset };
                    if (lastType != null && Verbs.Contains(text)) verbCandidates.TryAdd(lastType, text);
                    continue;
                case >= 0x12 and <= 0x14:
                    regs[i.A] = new Reg { Int = i.Literal, Text = "{}" };
                    continue;
                case 0x1c:
                    regs[i.A] = new Reg { Type = dex.Type(i.Index), Text = "{}" };
                    continue;
                case 0x1f or 0x20: // check-cast, instance-of
                    lastType = dex.Type(i.Index);
                    if (i.Opcode == 0x20) regs[i.A] = Reg.Unknown;
                    continue;
                case 0x07 or 0x08 or 0x09:
                    regs[i.A] = Get(i.B);
                    continue;
                case 0x0c:
                    regs[i.A] = result;
                    continue;
                case 0x22:
                    regs[i.A] = dex.Type(i.Index) == "Ljava/lang/StringBuilder;" ? new Reg { Builder = new StringBuilder(), Text = "{}" } : Reg.Unknown;
                    continue;
                case >= 0x52 and <= 0x6d: // iget / iput / sget / sput
                    if (i.IsFieldRead) regs[i.A] = new Reg { Text = "{" + dex.Field(i.Index).Name + "}" };
                    continue;
            }
            if (i.Ref != DalvikRef.Method || !i.IsInvoke)
            {
                // anything else that writes vA leaves it unknown
                if (i.Format is DalvikFormat.F12x or DalvikFormat.F11x or DalvikFormat.F22x or DalvikFormat.F21s or DalvikFormat.F23x or DalvikFormat.F22b
                    or DalvikFormat.F22s or DalvikFormat.F22c or DalvikFormat.F32x or DalvikFormat.F31i or DalvikFormat.F21c or DalvikFormat.F21h or DalvikFormat.F51l)
                    regs.Remove(i.A);
                continue;
            }
            var callee = dex.Method(i.Index);
            var args = Arguments(callee, i);
            result = Reg.Unknown;
            var cls = callee.Class;
            var name = callee.Name;
            if (cls == "Ljava/lang/StringBuilder;")
            {
                var sb = args.Count > 0 ? args[0] : Reg.Unknown;
                if (sb.Builder == null) continue;
                if (name == "<init>" && args.Count == 2 && callee.Proto.Parameters[0] == "Ljava/lang/String;") { Append(sb, args[1]); Consume(args[1]); }
                else if (name == "append" && args.Count == 2) { Append(sb, args[1]); Consume(args[1]); result = sb; }
                else if (name == "toString") result = new Reg { Text = sb.Builder.ToString(), Literal = sb.BuilderLiteral };
                continue;
            }
            if ((cls, name) is ("Ljava/lang/String;", "concat") or ("Lkotlin/jvm/internal/Intrinsics;", "stringPlus") && args.Count == 2)
            {
                Consume(args[0]);
                Consume(args[1]);
                result = new Reg { Text = (args[0].Text ?? "{}") + (args[1].Text ?? "{}"), Literal = args[0].Literal || args[1].Literal };
                continue;
            }
            if ((cls, name) is ("Ljava/lang/String;", "valueOf") && args.Count == 1) { result = args[0].Text != null ? args[0] : Reg.Unknown; continue; }
            if ((cls, name) is ("Ljava/lang/String;", "format") && args.Count >= 1)
            {
                var format = args[0].Literal ? args[0] : args.Count > 1 && args[1].Literal ? args[1] : null;
                if (format != null)
                {
                    Consume(format);
                    result = new Reg { Text = EndpointTemplates.FoldFormat(format.Text!), Literal = true };
                }
                continue;
            }
            switch (cls, name)
            {
                case ("Lretrofit2/Retrofit$Builder;", "baseUrl") when args.Count == 2 && args[1].Literal:
                    Consume(args[1]);
                    methodBases.Add(args[1].Text!);
                    _bases.Add(args[1].Text!);
                    _rows.Add(new CodeEndpoint("*", args[1].Text!, "retrofit-base", file, method.Descriptor, $"+0x{i.Offset:x}"));
                    continue;
                case ("Lretrofit2/Retrofit;", "create") when args.Count == 2 && args[1].Type != null:
                    created.Add(args[1].Type!);
                    continue;
                case ("Lio/grpc/MethodDescriptor;", "generateFullMethodName") when args.Count == 2:
                    Consume(args[0]);
                    Consume(args[1]);
                    if (args[0].Literal && args[1].Literal) _rows.Add(new CodeEndpoint("POST", $"/{args[0].Text}/{args[1].Text}", "grpc", file, method.Descriptor, $"+0x{i.Offset:x}"));
                    result = new Reg { Text = $"{args[0].Text}/{args[1].Text}", Literal = args[0].Literal || args[1].Literal };
                    continue;
                case ("Lio/ktor/http/HttpMethod$Companion;", _) when name.StartsWith("get", StringComparison.Ordinal) && Verbs.Contains(name[3..].ToUpperInvariant()):
                    ktorVerbs.Add(name[3..].ToUpperInvariant());
                    continue;
            }
            // volley: new XRequest(int method, String url, ...)
            if (cls.StartsWith("Lcom/android/volley/", StringComparison.Ordinal) && name == "<init>" && args.Count >= 3 && callee.Proto.Parameters is ["I", "Ljava/lang/String;", ..])
            {
                Row(args[1].Int is { } v and >= 0 and <= 7 ? VolleyVerbs[v] : "*", args[2], "volley", i.Offset);
                continue;
            }
            if (Client(cls) is { } client && !library)
            {
                var parameters = callee.Proto.Parameters;
                int first = args.Count - parameters.Count;
                for (int p = 0; p < parameters.Count; p++)
                    if (parameters[p] == "Ljava/lang/String;" && first + p < args.Count && args[first + p] is { Literal: true, Text: { } t } arg && LooksLikeUrl(t))
                    {
                        if (client == "ktor") ktorRows.Add(_rows.Count);
                        Row("*", arg, client, i.Offset);
                    }
            }
        }
        if (ktorVerbs.Count == 1)
            foreach (var r in ktorRows.Where(r => r < _rows.Count)) _rows[r] = _rows[r] with { Verb = ktorVerbs.First() };
        if (verbCandidates.Values.Distinct().Count() >= 4)
            foreach (var (type, verb) in verbCandidates) _verbOfType.TryAdd(type, verb);
        if (methodBases.Count == 1)
            foreach (var api in created) _baseOfInterface.TryAdd(api, methodBases[0]);
        foreach (var i in instructions)
            if (!library && i.Opcode is 0x1a or 0x1b && !consumed.Contains(i.Offset) && dex.String(i.Index) is var s && EndpointTemplates.IsLinkUrl(s))
                _rows.Add(new CodeEndpoint("*", s, "url", file, method.Descriptor, $"+0x{i.Offset:x}"));

        void Append(Reg sb, Reg value)
        {
            sb.Builder!.Append(value.Text is { } t && (value.Literal || t.StartsWith('{')) ? t : "{}");
            sb.BuilderLiteral |= value.Literal;
        }

        List<Reg> Arguments(DexMethodRef callee, DalvikInstruction i)
        {
            // registers per argument: this, then each parameter (long and double take two)
            var list = new List<Reg>();
            int r = 0;
            bool isStatic = i.Opcode is 0x71 or 0x77;
            if (!isStatic && i.Arguments.Count > 0) list.Add(Get(i.Arguments[r++]));
            foreach (var p in callee.Proto.Parameters)
            {
                if (r >= i.Arguments.Count) break;
                list.Add(Get(i.Arguments[r]));
                r += p is "J" or "D" ? 2 : 1;
            }
            return list;
        }
    }

    private static readonly string[] VolleyVerbs = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "PATCH"];

    private static string? Client(string cls)
    {
        for (int k = 0; k < Clients.Length; k += 2)
            if (cls.StartsWith(Clients[k], StringComparison.Ordinal)) return Clients[k + 1];
        return null;
    }

    /// <summary>An absolute URL, or a path from the root or after a computed base ("{}/v1/x"); not a header value like "okhttp/5.3".</summary>
    private static bool LooksLikeUrl(string t) =>
        !t.Contains(' ', StringComparison.Ordinal)
        && (EndpointTemplates.IsAbsoluteUrl(t) || (t.Length > 1 && t[0] is '/' or '{' && t.Contains('/', StringComparison.Ordinal) && t.Any(char.IsAsciiLetter)));

    /// <summary>Java descriptorData: a descriptor-start string constant and the constants after it in the same method, as bytes.</summary>
    private void Descriptors(DexFile dex, string file, string member, List<DalvikInstruction> instructions)
    {
        var strings = instructions.Where(i => i.Opcode is 0x1a or 0x1b).Select(i => (i.Offset, Text: dex.String(i.Index))).ToList();
        for (int k = 0; k < strings.Count; k++)
        {
            if (!ProtoScan.StartsDescriptor(strings[k].Text)) continue;
            int end = k + 1;
            while (end < strings.Count && strings[end].Text.All(c => c <= 0xFF) && !ProtoScan.StartsDescriptor(strings[end].Text)) end++;
            if (ProtoScan.Latin1(strings.Skip(k).Take(end - k).Select(x => x.Text)) is { } bytes && ProtoFile.Read(bytes) is { } proto)
                _descriptors.Add(new FoundDescriptor(proto, file, "Latin-1 string constants", strings[k].Offset, $"{member}+0x{strings[k].Offset:x}"));
            k = end - 1;
        }
    }

    /// <summary>The rows of every added DEX: Retrofit methods resolved through the annotation types seen in all of them.</summary>
    public void Finish(List<CodeEndpoint> endpoints, List<FoundDescriptor> descriptors)
    {
        foreach (var a in _annotated)
        {
            string? verb = a.Type.StartsWith("Lretrofit2/http/", StringComparison.Ordinal) ? a.Type[16..^1] : _verbOfType.GetValueOrDefault(a.Type);
            string? path;
            if (verb == "HTTP" || (verb == null && a.Elements.Any(e => e.Name == "method") && a.Elements.Any(e => e.Name == "path")))
            {
                verb = a.Elements.FirstOrDefault(e => e.Name == "method").Value?.Value as string;
                path = a.Elements.FirstOrDefault(e => e.Name == "path").Value?.Value as string;
            }
            else path = a.Elements.FirstOrDefault(e => e.Name == "value").Value?.Value as string;
            if (verb == null || !Verbs.Contains(verb) && verb.Any(c => !char.IsAsciiLetterUpper(c)) || path == null) continue;
            var baseUrl = _baseOfInterface.GetValueOrDefault(a.Interface);
            var url = baseUrl != null ? EndpointTemplates.Join(baseUrl, path) : EndpointTemplates.Rooted(path);
            if (a.Query.Count > 0) url += (url.Contains('?', StringComparison.Ordinal) ? "&" : "?") + string.Join("&", a.Query.Distinct().Order(StringComparer.Ordinal).Select(q => q + "=…"));
            endpoints.Add(new CodeEndpoint(verb, url, "retrofit", a.File, a.Member, "annotation") { Base = baseUrl });
        }
        endpoints.AddRange(_rows);
        descriptors.AddRange(_descriptors);
    }
}
