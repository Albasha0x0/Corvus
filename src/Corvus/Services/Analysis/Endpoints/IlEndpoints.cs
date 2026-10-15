using System.Globalization;
using System.Text;
using Corvus.Core;
using Corvus.Core.Protobuf;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Corvus.Services.Analysis.Endpoints;

/// <summary>
/// Endpoints and protobuf descriptors in a .NET module: Refit interface attributes (with RestService.For base URLs and the
/// query names unannotated parameters become), HttpClient / HttpRequestMessage / WebClient calls, generated gRPC client
/// methods (Grpc.Core.Method), absolute URL literals, and base64 descriptorData strings decoded to FileDescriptorProto.
/// String values are followed through one method body in IL order: ldstr, locals, string.Concat / Format and interpolated
/// string handlers fold to templates; arguments and fields become {name}, anything else {}.
/// </summary>
internal static class IlEndpoints
{
    /// <summary>A stack or local value: a string template, an int, an HTTP method, an array or a local's address.</summary>
    private sealed class Val
    {
        public string? Text;
        public bool Literal; // Text holds code-given characters, not only placeholders
        public int? Int;
        public string? Verb;
        public Val?[]? Array;
        public int Local = -1;
        public int Ldstr = -1; // instruction index of a plain ldstr
        public static readonly Val Unknown = new() { Text = "{}" };
        public static Val Of(string text, bool literal) => new() { Text = text, Literal = literal };
    }

    private static readonly Dictionary<string, string> RefitVerbs = new(StringComparer.Ordinal)
    {
        ["Refit.GetAttribute"] = "GET", ["Refit.PostAttribute"] = "POST", ["Refit.PutAttribute"] = "PUT", ["Refit.DeleteAttribute"] = "DELETE",
        ["Refit.PatchAttribute"] = "PATCH", ["Refit.HeadAttribute"] = "HEAD", ["Refit.OptionsAttribute"] = "OPTIONS",
    };

    private static readonly Dictionary<string, string> ClientVerbs = new(StringComparer.Ordinal)
    {
        ["GetAsync"] = "GET", ["GetStringAsync"] = "GET", ["GetByteArrayAsync"] = "GET", ["GetStreamAsync"] = "GET", ["PostAsync"] = "POST",
        ["PutAsync"] = "PUT", ["PatchAsync"] = "PATCH", ["DeleteAsync"] = "DELETE",
        ["GetFromJsonAsync"] = "GET", ["GetFromJsonAsAsyncEnumerable"] = "GET", ["PostAsJsonAsync"] = "POST", ["PutAsJsonAsync"] = "PUT",
        ["PatchAsJsonAsync"] = "PATCH", ["DeleteFromJsonAsync"] = "DELETE",
        ["DownloadString"] = "GET", ["DownloadData"] = "GET", ["DownloadFile"] = "GET", ["OpenRead"] = "GET", ["UploadString"] = "POST",
        ["UploadData"] = "POST", ["UploadValues"] = "POST", ["UploadFile"] = "POST",
    };

    public static void Scan(ModuleDef module, string file, List<CodeEndpoint> endpoints, List<FoundDescriptor> descriptors, CancellationToken ct)
    {
        var statics = new Dictionary<string, Val>(StringComparer.Ordinal);
        var bases = new Dictionary<string, string>(StringComparer.Ordinal); // Refit interface -> base URL
        var types = module.GetTypes().ToList();
        // static constructors first: their stsfld values feed the other methods
        var methods = types.SelectMany(t => t.Methods).Where(m => m.HasBody).OrderBy(m => m.IsStaticConstructor ? 0 : 1).ToList();
        var found = new List<CodeEndpoint>();
        foreach (var m in methods)
        {
            ct.ThrowIfCancellationRequested();
            IList<Instruction> body;
            try
            {
                body = m.Body.Instructions;
                if (!body.Any(i => i.OpCode.Code == Code.Ldstr)) continue;
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { continue; } // a body dnlib cannot read
            Method(m, body, file, statics, bases, found, descriptors);
        }
        foreach (var t in types.Where(t => t.IsInterface))
            foreach (var m in t.Methods)
                if (Refit(m, file, bases.GetValueOrDefault(t.FullName)) is { } row) found.Add(row);
        endpoints.AddRange(found);
    }

    private static CodeEndpoint? Refit(MethodDef m, string file, string? baseUrl)
    {
        foreach (var a in m.CustomAttributes)
        {
            if (!RefitVerbs.TryGetValue(a.AttributeType?.FullName ?? "", out var verb)) continue;
            var path = a.ConstructorArguments.Count > 0 && a.ConstructorArguments[0].Value is UTF8String s ? s.String : "";
            var query = new SortedSet<string>(StringComparer.Ordinal);
            foreach (var p in m.Parameters.Where(p => p.IsNormalMethodParameter))
            {
                var attrs = p.ParamDef?.CustomAttributes.Select(x => x.AttributeType?.FullName ?? "").ToList() ?? [];
                var alias = p.ParamDef?.CustomAttributes.FirstOrDefault(x => x.AttributeType?.FullName == "Refit.AliasAsAttribute")?.ConstructorArguments
                    .FirstOrDefault().Value is UTF8String al ? al.String : null;
                var name = alias ?? p.Name;
                if (path.Contains("{" + name + "}", StringComparison.Ordinal) || path.Contains("{**" + name + "}", StringComparison.Ordinal)) continue;
                var typeName = p.Type?.FullName ?? "";
                bool query1 = attrs.Contains("Refit.QueryAttribute")
                              || (attrs.All(x => !x.StartsWith("Refit.", StringComparison.Ordinal) || x == "Refit.AliasAsAttribute")
                                  && typeName != "System.Threading.CancellationToken" && !typeName.StartsWith("System.Net.Http.", StringComparison.Ordinal));
                if (query1) query.Add(name);
            }
            var url = (baseUrl != null ? EndpointTemplates.Join(baseUrl, path) : EndpointTemplates.Rooted(path))
                      + (query.Count > 0 ? (path.Contains('?', StringComparison.Ordinal) ? "&" : "?") + string.Join("&", query.Select(q => q + "=…")) : "");
            return new CodeEndpoint(verb, url, "refit", file, Format.MemberLabel(m), $"attribute {a.AttributeType!.Name}") { Base = baseUrl };
        }
        return null;
    }

    private static void Method(MethodDef m, IList<Instruction> body, string file, Dictionary<string, Val> statics, Dictionary<string, string> bases,
        List<CodeEndpoint> endpoints, List<FoundDescriptor> descriptors)
    {
        var stack = new List<Val>();
        var locals = new Dictionary<int, Val>();
        var consumed = new HashSet<int>();
        var member = Format.MemberLabel(m);
        bool returns = m.MethodSig?.RetType?.ElementType != ElementType.Void;
        Val Pop()
        {
            if (stack.Count == 0) return Val.Unknown;
            var v = stack[^1];
            stack.RemoveAt(stack.Count - 1);
            return v;
        }
        Val[] PopN(int n)
        {
            var a = new Val[n];
            for (int i = n - 1; i >= 0; i--) a[i] = Pop();
            return a;
        }
        void Consume(Val v) { if (v.Ldstr >= 0) consumed.Add(v.Ldstr); }
        void Row(string verb, Val url, string client, int index)
        {
            Consume(url);
            if (url.Text == null || !url.Literal) return;
            endpoints.Add(new CodeEndpoint(verb, EndpointTemplates.Rooted(url.Text), client, file, member, $"IL_{body[index].Offset:X4}"));
        }

        for (int index = 0; index < body.Count && index < 200_000; index++)
        {
            var ins = body[index];
            switch (ins.OpCode.Code)
            {
                case Code.Ldstr:
                    stack.Add(new Val { Text = (string)ins.Operand, Literal = true, Ldstr = index });
                    continue;
                case Code.Ldc_I4: case Code.Ldc_I4_S: case Code.Ldc_I4_0: case Code.Ldc_I4_1: case Code.Ldc_I4_2: case Code.Ldc_I4_3: case Code.Ldc_I4_4:
                case Code.Ldc_I4_5: case Code.Ldc_I4_6: case Code.Ldc_I4_7: case Code.Ldc_I4_8: case Code.Ldc_I4_M1:
                    stack.Add(new Val { Int = ins.GetLdcI4Value(), Text = "{}" });
                    continue;
                case Code.Dup:
                    var top = Pop();
                    stack.Add(top);
                    stack.Add(top);
                    continue;
                case Code.Ldarg: case Code.Ldarg_S: case Code.Ldarg_0: case Code.Ldarg_1: case Code.Ldarg_2: case Code.Ldarg_3:
                    var p = ins.GetParameter(m.Parameters);
                    stack.Add(Val.Of(p == null || p.IsHiddenThisParameter ? "{}" : "{" + p.Name + "}", false));
                    continue;
                case Code.Stloc: case Code.Stloc_S: case Code.Stloc_0: case Code.Stloc_1: case Code.Stloc_2: case Code.Stloc_3:
                    if (ins.GetLocal(m.Body.Variables) is { } sl) locals[sl.Index] = Pop(); else Pop();
                    continue;
                case Code.Ldloc: case Code.Ldloc_S: case Code.Ldloc_0: case Code.Ldloc_1: case Code.Ldloc_2: case Code.Ldloc_3:
                    stack.Add(ins.GetLocal(m.Body.Variables) is { } ll && locals.TryGetValue(ll.Index, out var lv) ? lv : Val.Unknown);
                    continue;
                case Code.Ldloca: case Code.Ldloca_S:
                    stack.Add(new Val { Local = ins.GetLocal(m.Body.Variables)?.Index ?? -1, Text = "{}" });
                    continue;
                case Code.Ldsfld:
                    var sf = (IField)ins.Operand;
                    stack.Add(statics.TryGetValue(sf.FullName, out var sv) ? sv : Val.Of("{" + sf.Name + "}", false));
                    continue;
                case Code.Ldfld:
                    Pop();
                    stack.Add(Val.Of("{" + ((IField)ins.Operand).Name + "}", false));
                    continue;
                case Code.Stsfld:
                    var stored = Pop();
                    if (m.IsStaticConstructor && stored.Text != null && stored.Literal) statics[((IField)ins.Operand).FullName] = stored;
                    continue;
                case Code.Newarr:
                    var length = Pop();
                    stack.Add(new Val { Array = new Val?[Math.Clamp(length.Int ?? 0, 0, 4096)], Text = "{}" });
                    continue;
                case Code.Stelem_Ref:
                    var item = Pop();
                    var at = Pop();
                    var array = Pop();
                    if (array.Array != null && at.Int is { } k && k >= 0 && k < array.Array.Length) array.Array[k] = item;
                    continue;
                case Code.Call: case Code.Callvirt: case Code.Newobj:
                    if (Call(ins, index)) continue;
                    break;
            }
            ins.CalculateStackUsage(returns, out int pushes, out int pops);
            if (pops < 0) stack.Clear();
            else PopN(pops);
            for (int i = 0; i < pushes; i++) stack.Add(Val.Unknown);
        }
        foreach (var (i, ins) in body.Index())
            if (ins.OpCode.Code == Code.Ldstr && !consumed.Contains(i) && ins.Operand is string s && EndpointTemplates.IsLinkUrl(s))
                endpoints.Add(new CodeEndpoint("*", s, "url", file, member, $"IL_{ins.Offset:X4}"));

        bool Call(Instruction ins, int index)
        {
            if (ins.Operand is not IMethod callee || callee.MethodSig is not { } sig) return false;
            var type = callee.DeclaringType?.FullName ?? "";
            var name = callee.Name.String;
            int args = sig.Params.Count + (sig.HasThis && ins.OpCode.Code != Code.Newobj ? 1 : 0);
            bool push = ins.OpCode.Code == Code.Newobj || sig.RetType.ElementType != ElementType.Void;
            switch (type)
            {
                case "System.String" when name == "Concat":
                {
                    var parts = PopN(args);
                    var flat = parts.Length == 1 && parts[0].Array is { } arr ? arr.Select(x => x ?? Val.Unknown).ToArray() : parts;
                    foreach (var x in flat) Consume(x);
                    stack.Add(Val.Of(string.Concat(flat.Select(x => x.Text ?? "{}")), flat.Any(x => x.Literal)));
                    return true;
                }
                case "System.String" when name == "Format" && sig.Params.Count >= 2:
                {
                    var parts = PopN(args);
                    int first = sig.Params[0].FullName == "System.String" ? 0 : 1;
                    var values = parts.Skip(first + 1).ToArray();
                    if (values.Length == 1 && values[0].Array is { } arr) values = [.. arr.Select(x => x ?? Val.Unknown)];
                    Consume(parts[first]);
                    foreach (var x in values) Consume(x);
                    var format = parts[first].Text ?? "{}";
                    var text = System.Text.RegularExpressions.Regex.Replace(format, @"\{(\d+)(,[^}]*)?(:[^}]*)?\}", mm =>
                        int.TryParse(mm.Groups[1].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) && n < values.Length ? values[n].Text ?? "{}" : "{}",
                        System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromMilliseconds(100));
                    stack.Add(Val.Of(text, parts[first].Literal));
                    return true;
                }
                case "System.Runtime.CompilerServices.DefaultInterpolatedStringHandler":
                {
                    var parts = PopN(args);
                    var handler = parts[0].Local;
                    if (handler < 0) { if (push) stack.Add(Val.Unknown); return true; }
                    var current = locals.GetValueOrDefault(handler) ?? Val.Of("", false);
                    switch (name)
                    {
                        case ".ctor": locals[handler] = Val.Of("", false); break;
                        case "AppendLiteral": Consume(parts[1]); locals[handler] = Val.Of(current.Text + parts[1].Text, true); break;
                        case "AppendFormatted":
                            var v = parts.Length > 1 ? parts[1] : Val.Unknown;
                            Consume(v);
                            locals[handler] = Val.Of(current.Text + (v.Literal ? v.Text : v.Text is { Length: > 0 } t && t.StartsWith('{') ? t : "{}"), current.Literal || v.Literal);
                            break;
                        case "ToStringAndClear": stack.Add(current); return true;
                    }
                    if (push) stack.Add(Val.Unknown);
                    return true;
                }
                case "System.Uri" when name == ".ctor" && sig.Params.Count >= 1:
                {
                    var parts = PopN(args);
                    if (sig.Params[0].FullName == "System.Uri" && parts.Length >= 2)
                    {
                        Consume(parts[1]);
                        stack.Add(Val.Of(parts[0].Literal ? EndpointTemplates.Join(parts[0].Text!, parts[1].Text ?? "") : (parts[1].Text ?? "{}"), parts[0].Literal || parts[1].Literal));
                    }
                    else stack.Add(parts[0].Array == null ? parts[0] : Val.Unknown);
                    return true;
                }
                case "System.Net.Http.HttpMethod":
                {
                    var parts = PopN(args);
                    if (name.StartsWith("get_", StringComparison.Ordinal)) stack.Add(new Val { Verb = name[4..].ToUpperInvariant(), Text = "{}" });
                    else if (name == ".ctor" && parts.Length == 1) { Consume(parts[0]); stack.Add(new Val { Verb = parts[0].Literal ? parts[0].Text : "*", Text = "{}" }); }
                    else if (push) stack.Add(Val.Unknown);
                    return true;
                }
                case "System.Net.Http.HttpRequestMessage" when name == ".ctor" && sig.Params.Count == 2:
                {
                    var parts = PopN(args);
                    Row(parts[0].Verb ?? "*", parts[1], "httpclient", index);
                    stack.Add(Val.Unknown);
                    return true;
                }
                case "System.Net.Http.HttpClient" when name == "set_BaseAddress":
                {
                    var parts = PopN(args);
                    Row("*", parts[1], "httpclient-base", index);
                    return true;
                }
                case "System.Net.Http.HttpClient" or "System.Net.Http.Json.HttpClientJsonExtensions" or "System.Net.WebClient" when ClientVerb(name) is { } verb && sig.Params.Count >= 1:
                {
                    var parts = PopN(args);
                    if (parts.Length > 1) Row(verb, parts[1], type == "System.Net.WebClient" ? "webclient" : "httpclient", index);
                    if (push) stack.Add(Val.Unknown);
                    return true;
                }
                case "System.Net.WebRequest" or "System.Net.HttpWebRequest" when name is "Create" or "CreateHttp":
                {
                    var parts = PopN(args);
                    if (parts.Length > 0) Row("*", parts[0], "webrequest", index);
                    stack.Add(Val.Unknown);
                    return true;
                }
                case "System.Convert" when name == "FromBase64String":
                {
                    var parts = PopN(args);
                    Consume(parts[0]);
                    if (parts[0].Literal && parts[0].Text is { } b64 && !b64.Contains('{', StringComparison.Ordinal) && ProtoScan.Base64(b64) is { } proto)
                        descriptors.Add(new FoundDescriptor(proto, file, "base64 string", body[index].Offset, $"{member} IL_{body[index].Offset:X4}"));
                    stack.Add(Val.Unknown);
                    return true;
                }
            }
            // generated gRPC clients: new Method<TRequest, TResponse>(type, serviceName, name, marshaller, marshaller)
            if (ins.OpCode.Code == Code.Newobj && name == ".ctor" && callee.DeclaringType is { } dt && dt.Namespace == "Grpc.Core" && dt.Name.String.StartsWith("Method`", StringComparison.Ordinal)
                && sig.Params.Count == 5)
            {
                var parts = PopN(args);
                Consume(parts[1]);
                Consume(parts[2]);
                if (parts[1].Literal && parts[2].Literal)
                    endpoints.Add(new CodeEndpoint("POST", $"/{parts[1].Text}/{parts[2].Text}", "grpc", file, member, $"IL_{ins.Offset:X4}"));
                stack.Add(Val.Unknown);
                return true;
            }
            // Refit: RestService.For<TApi>("https://host/")
            if (type == "Refit.RestService" && name == "For" && callee is MethodSpec spec && spec.GenericInstMethodSig?.GenericArguments.FirstOrDefault() is { } api)
            {
                var parts = PopN(args);
                if (parts.FirstOrDefault(x => x.Literal) is { } host)
                {
                    Consume(host);
                    bases[api.FullName] = host.Text!;
                }
                stack.Add(Val.Unknown);
                return true;
            }
            return false;
        }
    }

    /// <summary>The HTTP method of a client call by name (DownloadStringTaskAsync as DownloadString); null when it sends nothing.</summary>
    private static string? ClientVerb(string name) =>
        ClientVerbs.GetValueOrDefault(name)
        ?? (name.EndsWith("TaskAsync", StringComparison.Ordinal) ? ClientVerbs.GetValueOrDefault(name[..^9])
            : name.EndsWith("Async", StringComparison.Ordinal) ? ClientVerbs.GetValueOrDefault(name[..^5]) : null);
}
