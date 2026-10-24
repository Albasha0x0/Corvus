using System.Text;
using System.Text.RegularExpressions;
using Corvus.Core.Mobile;
using Corvus.Services.Mobile;

namespace Corvus.Services.Analysis;

/// <summary>
/// The "dex:" features of the mobile rules, evaluated in one pass over an app's DEX code. Forms: "call:PATTERN" (a call
/// whose target descriptor matches; '*' wildcards), optionally "#i=s:REGEX" (argument i is a string constant matching),
/// "#i=i:N" (an int constant) or "#i=literal" (bytes or chars from a literal: a string's bytes, base64, array data);
/// "field:PREFIX" (a field read); "str:REGEX" (a const-string); "class:PREFIX" (a class the app defines, counted as the
/// app's whatever package it is in); "check:trust-all" (an X509TrustManager whose checkServerTrusted returns without a
/// check) and "check:any-hostname" (a HostnameVerifier whose verify returns true). Methods are prefiltered on raw code
/// units; only those that touch a feature are decoded. Arguments are followed through one method in code order. Strings
/// that string decoder calls return (<see cref="DexStringFolding"/>) count as const-strings and string arguments at the call.
/// </summary>
internal sealed class DexRuleScan
{
    private const int MaxLocations = 5;
    private const int MaxStringChars = 512;

    /// <summary>The time decoder calls may take within a survey; a search or a later survey continues the pass.</summary>
    internal static readonly TimeSpan FoldTimeLimit = TimeSpan.FromSeconds(2);

    private sealed record CallFeature(string Feature, string Needle, Regex Target, int Arg, string? ArgKind, Regex? ArgText, long ArgInt);

    private sealed class Hits
    {
        public int App, Library;
        public readonly List<string> Locations = [], LibraryLocations = [];

        public void Add(bool library, string where)
        {
            if (library) { Library++; if (LibraryLocations.Count < MaxLocations && !LibraryLocations.Contains(where)) LibraryLocations.Add(where); }
            else { App++; if (Locations.Count < MaxLocations && !Locations.Contains(where)) Locations.Add(where); }
        }
    }

    /// <summary>Bytes or chars that came from a literal: where from, and how many.</summary>
    private sealed record Literal(string Origin, int Length);

    private readonly List<CallFeature> _calls = [];
    private readonly List<(string Feature, string Prefix)> _fields = [];
    private readonly List<(string Feature, Regex Regex)> _strings = [];
    private readonly List<(string Feature, string Prefix)> _classes = [];
    private readonly Dictionary<string, Hits> _hits = new(StringComparer.Ordinal);
    private readonly Func<string, bool> _isLibrary;
    private readonly DexIndex _index;
    private readonly DexStringFolding _folding;
    private readonly List<string> _notes = [];

    /// <summary>What the scan could not read: decoder calls left unevaluated by the time limit.</summary>
    public IReadOnlyList<string> Notes => _notes;

    /// <summary>Scans this thread built, and the methods they decoded (only those whose raw code touches a feature).</summary>
    [ThreadStatic]
    internal static int Scans, MethodsDecoded;

    public DexRuleScan(DexIndex index, IEnumerable<string> features, Func<string, bool> isLibrary, CancellationToken ct)
    {
        Scans++;
        _isLibrary = isLibrary;
        _index = index;
        _folding = DexStringFolding.For(index);
        foreach (var f in features.Distinct(StringComparer.Ordinal))
        {
            _hits[f] = new Hits();
            var body = f["dex:".Length..];
            int colon = body.IndexOf(':');
            var (kind, pattern) = (body[..colon], body[(colon + 1)..]);
            switch (kind)
            {
                case "call": _calls.Add(ParseCall(f, pattern)); break;
                case "field": _fields.Add((f, pattern)); break;
                case "str": _strings.Add((f, Features.RulePattern(pattern))); break;
                case "class": _classes.Add((f, pattern)); break;
                case "check": break;
                default: throw new InvalidOperationException($"Unknown dex feature: {f}");
            }
        }
        foreach (var file in index.Files)
        {
            ct.ThrowIfCancellationRequested();
            Scan(index, file, ct);
        }
        if (_strings.Count > 0) Recovered(ct);
    }

    /// <summary>str: features over the strings decoder calls return, at the call.</summary>
    private void Recovered(CancellationToken ct)
    {
        var folds = _folding.Package(ct, FoldTimeLimit);
        foreach (var site in folds.Sites)
        {
            if (site.Fold is not { Status: DexFoldStatus.Simplified, Value: { Length: > 0 and <= MaxStringChars } value }) continue;
            bool library = _isLibrary(site.Method[..Math.Max(0, site.Method.IndexOf("->", StringComparison.Ordinal))]);
            foreach (var (f, regex) in _strings)
                if (regex.IsMatch(value)) _hits[f].Add(library, $"{site.Method} +0x{site.Offset:x}: \"{Clip(value)}\" from {site.Decoder}");
        }
        if (folds.MethodsLeft > 0)
            _notes.Add($"{folds.MethodsLeft} method(s) with string decoder calls not evaluated within {FoldTimeLimit.TotalSeconds:0} s; the strings they return are unknown to the dex rules (search_dex kind=string continues the pass).");
    }

    /// <summary>The evidence of one feature, or null when nothing matched.</summary>
    public Evidence? Evidence(string feature)
    {
        if (!_hits.TryGetValue(feature, out var h) || h.App + h.Library == 0) return null;
        var locations = h.Locations.Concat(h.LibraryLocations.Take(Math.Max(0, MaxLocations - h.Locations.Count)).Select(l => "library " + l)).ToList();
        return new Evidence(feature, h.App, locations)
        {
            Library = h.Library > 0 ? h.Library : null,
            Basis = feature.StartsWith("dex:str:", StringComparison.Ordinal) ? "derived" : null,
        };
    }

    private static CallFeature ParseCall(string feature, string pattern)
    {
        int hash = pattern.LastIndexOf('#');
        string? argKind = null;
        Regex? text = null;
        long number = 0;
        int arg = -1;
        if (hash > 0 && pattern.IndexOf('=', hash) is var eq and > 0)
        {
            arg = int.Parse(pattern.AsSpan(hash + 1, eq - hash - 1), System.Globalization.CultureInfo.InvariantCulture);
            var value = pattern[(eq + 1)..];
            if (value.StartsWith("s:", StringComparison.Ordinal)) { argKind = "s"; text = Features.RulePattern(value[2..]); }
            else if (value.StartsWith("i:", StringComparison.Ordinal)) { argKind = "i"; number = long.Parse(value[2..], System.Globalization.CultureInfo.InvariantCulture); }
            else argKind = value;
            pattern = pattern[..hash];
        }
        var regex = new Regex("^" + Regex.Escape(pattern).Replace(@"\*", ".*"), RegexOptions.CultureInvariant);
        var needle = pattern.Split('*').MaxBy(p => p.Length) ?? "";
        return new CallFeature(feature, needle, regex, arg, argKind, text, number);
    }

    private void Scan(DexIndex index, DexFile dex, CancellationToken ct)
    {
        var callsOf = new List<CallFeature>?[dex.MethodCount];
        bool anyCall = false;
        if (_calls.Count > 0)
            for (int i = 0; i < callsOf.Length; i++)
            {
                var d = dex.Method(i).Descriptor;
                foreach (var c in _calls)
                    if (d.Contains(c.Needle, StringComparison.Ordinal) && c.Target.IsMatch(d)) { (callsOf[i] ??= []).Add(c); anyCall = true; }
            }
        var fieldsOf = new List<string>?[_fields.Count > 0 ? dex.FieldCount : 0];
        for (int i = 0; i < fieldsOf.Length; i++)
        {
            var d = dex.Field(i).Descriptor;
            foreach (var (f, prefix) in _fields)
                if (d.StartsWith(prefix, StringComparison.Ordinal)) (fieldsOf[i] ??= []).Add(f);
        }
        var stringsOf = new List<string>?[_strings.Count > 0 ? dex.StringCount : 0];
        for (int i = 0; i < stringsOf.Length; i++)
        {
            if ((i & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            var s = dex.String(i);
            if (s.Length is 0 or > MaxStringChars) continue;
            foreach (var (f, regex) in _strings)
                if (regex.IsMatch(s)) (stringsOf[i] ??= []).Add(f);
        }

        foreach (var c in dex.Classes)
        {
            ct.ThrowIfCancellationRequested();
            if (index.Classes.TryGetValue(c.Descriptor, out var first) && first.File != dex) continue;
            bool library = _isLibrary(c.Descriptor);
            foreach (var (f, prefix) in _classes)
                if (c.Descriptor.StartsWith(prefix, StringComparison.Ordinal)) _hits[f].Add(false, $"class {c.Descriptor}");
            foreach (var em in dex.ClassData(c).Methods)
            {
                if (em.CodeOffset == 0 || dex.Code(em.CodeOffset) is not { } code) continue;
                if (!Touches(code.Instructions, anyCall ? callsOf : null, fieldsOf, stringsOf)) continue;
                Method(dex, dex.Method(em.MethodIndex).Descriptor, code, library, callsOf, fieldsOf, stringsOf);
            }
        }
        if (_hits.ContainsKey("dex:check:trust-all") || _hits.ContainsKey("dex:check:any-hostname")) Overrides(index, dex);
    }

    /// <summary>Whether a method calls, reads or loads anything a feature names, from the raw code units.</summary>
    private static bool Touches(ushort[] code, List<CallFeature>?[]? calls, List<string>?[] fields, List<string>?[] strings)
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
            if (units == 0 || at + units > code.Length) return false;
            switch (op)
            {
                case 0x1a when code[at + 1] < strings.Length && strings[code[at + 1]] != null: return true;
                case 0x1b when (code[at + 1] | code[at + 2] << 16) is var si && si >= 0 && si < strings.Length && strings[si] != null: return true;
                case >= 0x52 and <= 0x58 or >= 0x60 and <= 0x66 when code[at + 1] < fields.Length && fields[code[at + 1]] != null: return true;
                case >= 0x6e and <= 0x72 or >= 0x74 and <= 0x78 when calls != null && code[at + 1] < calls.Length && calls[code[at + 1]] != null: return true;
            }
            at += units;
        }
        return false;
    }

    private void Method(DexFile dex, string method, DexCode code, bool library, List<CallFeature>?[] callsOf, List<string>?[] fieldsOf, List<string>?[] stringsOf)
    {
        MethodsDecoded++;
        var instructions = Dalvik.Decode(code.Instructions);
        var regs = new object?[Math.Max(code.Registers, 1)];
        object? result = null;
        IReadOnlyList<DexFoldSite>? folds = null;
        string Where(int offset) => $"{method} +0x{offset:x}";
        object? Reg(int r) => (uint)r < (uint)regs.Length ? regs[r] : null;
        void Set(int r, object? v) { if ((uint)r < (uint)regs.Length) regs[r] = v; }

        foreach (var i in instructions)
        {
            int op = i.Opcode;
            if (i.IsPayload) continue;
            switch (op)
            {
                case >= 0x12 and <= 0x15: Set(i.A, i.Literal); break;
                case 0x1a or 0x1b:
                {
                    var s = dex.String(i.Index);
                    Set(i.A, s);
                    if (i.Index < stringsOf.Length && stringsOf[i.Index] is { } fs)
                        foreach (var f in fs) _hits[f].Add(library, $"{Where(i.Offset)}: \"{Clip(s)}\"");
                    break;
                }
                case 0x01 or 0x02 or 0x03 or 0x07 or 0x08 or 0x09: Set(i.A, Reg(i.B)); break;
                case 0x0a or 0x0c: Set(i.A, result); result = null; break;
                case 0x23: Set(i.A, new Literal("new array", 0)); break;
                case 0x26:
                    if (instructions.FirstOrDefault(p => p.Offset == i.Target && p.Format == DalvikFormat.FillArrayPayload) is { } payload)
                        Set(i.A, new Literal("array data", Dalvik.ArrayData(code.Instructions, payload, out int width).Count * Math.Max(width, 1)));
                    break;
                case >= 0x52 and <= 0x58 or >= 0x60 and <= 0x66:
                    if (i.Index < fieldsOf.Length && fieldsOf[i.Index] is { } ff)
                        foreach (var f in ff) _hits[f].Add(library, $"{Where(i.Offset)}: reads {dex.Field(i.Index).Descriptor}");
                    if (op == 0x62 && _folding.IsTable(dex.Field(i.Index).Descriptor))
                        folds ??= _index.Methods.TryGetValue(method, out var entry) && entry.File == dex ? _folding.Method(entry) : [];
                    Set(i.A, null);
                    break;
                case 0x46:
                    Set(i.A, folds?.FirstOrDefault(s => s.Offset == i.Offset)?.Fold is { Status: DexFoldStatus.Simplified, Value: { } element } ? element : null);
                    break;
                case >= 0x6e and <= 0x72 or >= 0x74 and <= 0x78:
                {
                    var target = dex.Method(i.Index);
                    result = Transform(target, i.Arguments, Reg);
                    if (DexStringFolding.IsCall(op) && _folding.IsDecoder(target.Descriptor))
                    {
                        folds ??= _index.Methods.TryGetValue(method, out var entry) && entry.File == dex ? _folding.Method(entry) : [];
                        result = folds.FirstOrDefault(s => s.Offset == i.Offset)?.Fold is { Status: DexFoldStatus.Simplified, Value: { } value } ? value : null;
                    }
                    else if (DexStringFolding.IsCall(op) && _folding.IsArrayDecoder(target.Descriptor))
                        folds ??= _index.Methods.TryGetValue(method, out var entry) && entry.File == dex ? _folding.Method(entry) : [];
                    else if (folds?.FirstOrDefault(s => s.WrapperOffset == i.Offset) is { } wrapped)
                    {
                        var value = wrapped.Fold is { Status: DexFoldStatus.Simplified, Value: { } v } ? v : null;
                        // A String constructor leaves the string in its receiver; String.valueOf returns it.
                        if (target.Name == "<init>") { if (i.Arguments.Count > 0) Set(i.Arguments[0], value); }
                        else result = value;
                    }
                    if (i.Index < callsOf.Length && callsOf[i.Index] is { } cs)
                        foreach (var c in cs)
                            if (Argument(c, i.Arguments, Reg) is { } shown)
                                _hits[c.Feature].Add(library, $"{Where(i.Offset)}: {target.Class}->{target.Name}{shown}");
                    break;
                }
                case 0x04 or 0x05 or 0x06 or 0x0b or 0x0d or >= 0x16 and <= 0x19 or 0x1c or >= 0x20 and <= 0x22 or >= 0x44 and <= 0x4a or >= 0x7b and <= 0xe2:
                    Set(i.A, null);
                    break;
            }
        }
    }

    /// <summary>What a call returns when it turns a literal into bytes or chars: getBytes, toCharArray, Base64.decode.</summary>
    private static object? Transform(DexMethodRef target, IReadOnlyList<int> args, Func<int, object?> reg)
    {
        if (args.Count == 0) return null;
        if (target.Class == "Ljava/lang/String;" && target.Name is "getBytes" or "toCharArray" && reg(args[0]) is string s)
            return new Literal($"string literal \"{Clip(s)}\"", target.Name == "getBytes" ? Encoding.UTF8.GetByteCount(s) : s.Length);
        if (target.Name == "decode" && target.Class is "Landroid/util/Base64;" or "Ljava/util/Base64$Decoder;"
            && args.Select(reg).OfType<string>().FirstOrDefault() is { } b64)
        {
            try { return new Literal($"base64 literal \"{Clip(b64)}\"", Convert.FromBase64String(b64).Length); }
            catch (FormatException) { return null; }
        }
        return null;
    }

    /// <summary>The call's shown arguments when the feature's argument test passes (empty without one), else null.</summary>
    private static string? Argument(CallFeature c, IReadOnlyList<int> args, Func<int, object?> reg)
    {
        if (c.Arg < 0) return "(" + string.Join(", ", args.Select(reg).OfType<string>().Select(s => $"\"{Clip(s)}\"")) + ")";
        if (c.Arg >= args.Count) return null;
        var value = reg(args[c.Arg]);
        return c.ArgKind switch
        {
            "s" when value is string s && c.ArgText!.IsMatch(s) => $"(\"{Clip(s)}\")",
            "i" when value is long n && n == c.ArgInt => $"({n})",
            "literal" when value is Literal { Length: > 0 } l => $": {l.Origin}, {l.Length * 8} bits",
            _ => null,
        };
    }

    private static readonly string[] TrustManagers = ["Ljavax/net/ssl/X509TrustManager;", "Ljavax/net/ssl/X509ExtendedTrustManager;", "Ljavax/net/ssl/TrustManager;"];

    /// <summary>check:trust-all and check:any-hostname: framework overrides whose body accepts everything.</summary>
    private void Overrides(DexIndex index, DexFile dex)
    {
        foreach (var c in dex.Classes)
        {
            if (index.Classes.TryGetValue(c.Descriptor, out var first) && first.File != dex) continue;
            bool trust = _hits.ContainsKey("dex:check:trust-all") && Implements(index, c, TrustManagers);
            bool host = _hits.ContainsKey("dex:check:any-hostname") && Implements(index, c, ["Ljavax/net/ssl/HostnameVerifier;"]);
            if (!trust && !host) continue;
            foreach (var em in dex.ClassData(c).Methods)
            {
                var m = dex.Method(em.MethodIndex);
                if (em.CodeOffset == 0 || dex.Code(em.CodeOffset) is not { } code) continue;
                if (trust && m.Name == "checkServerTrusted" && m.Proto.ReturnType == "V" && Accepts(index, dex, code, returnsTrue: false, depth: 1))
                    _hits["dex:check:trust-all"].Add(_isLibrary(c.Descriptor), $"{m.Descriptor} +0x0: returns without checking the chain");
                if (host && m.Name == "verify" && m.Proto.Descriptor == "(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z" && Accepts(index, dex, code, returnsTrue: true, depth: 1))
                    _hits["dex:check:any-hostname"].Add(_isLibrary(c.Descriptor), $"{m.Descriptor} +0x0: returns true for any host");
            }
        }
    }

    /// <summary>Whether a class implements one of <paramref name="interfaces"/>, through superclasses the app defines.</summary>
    private static bool Implements(DexIndex index, DexClass c, string[] interfaces)
    {
        for (int depth = 0; c != null && depth < 16; depth++)
        {
            if (c.Interfaces.Any(interfaces.Contains) || (c.SuperClass != null && interfaces.Contains(c.SuperClass))) return true;
            if (c.SuperClass == null || !index.Classes.TryGetValue(c.SuperClass, out var super)) return false;
            c = super.Class;
        }
        return false;
    }

    /// <summary>
    /// A body that only returns (returnsTrue: a constant 1), around Kotlin parameter checks; or that calls one such method and
    /// returns its result (a desugared lambda), followed <paramref name="depth"/> levels.
    /// </summary>
    private static bool Accepts(DexIndex index, DexFile dex, DexCode code, bool returnsTrue, int depth)
    {
        var list = Dalvik.Decode(code.Instructions, 64);
        if (list.Count == 0 || list.Count >= 64) return false;
        bool delegated = false;
        int trueReg = -1;
        foreach (var i in list)
        {
            switch (i.Opcode)
            {
                case 0x00 or 0x1a or 0x1b: continue; // nop; parameter names for Kotlin's null checks
                case 0x0e: return !returnsTrue;
                case 0x0f: return returnsTrue && i.A == trueReg;
                case 0x12 or 0x13: trueReg = i.Literal == 1 ? i.A : (trueReg == i.A ? -1 : trueReg); continue;
                case 0x0a: if (delegated) trueReg = i.A; continue;
                case >= 0x6e and <= 0x72 or >= 0x74 and <= 0x78:
                {
                    var name = dex.Method(i.Index).Descriptor;
                    if (name.StartsWith("Lkotlin/jvm/internal/Intrinsics;->check", StringComparison.Ordinal)) continue;
                    if (depth == 0 || delegated || !index.Methods.TryGetValue(name, out var callee) || callee.Encoded.CodeOffset == 0
                        || callee.File.Code(callee.Encoded.CodeOffset) is not { } inner || !Accepts(index, callee.File, inner, returnsTrue, depth - 1)) return false;
                    delegated = true;
                    continue;
                }
                default: return false;
            }
        }
        return false;
    }

    private static string Clip(string s) => s.Length <= 60 ? s : s[..60] + "…";
}
