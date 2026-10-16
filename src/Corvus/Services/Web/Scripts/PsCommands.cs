using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using static Corvus.Services.Web.Scripts.PsConvert;

namespace Corvus.Services.Web.Scripts;

// Commands, members and methods of the PowerShell evaluator; the code-running ones peel layers.
internal sealed partial class PsInterpreter
{
    /// <summary>Cmdlets by their canonical spelling: a spelled-out or wildcard name resolves to one of these.</summary>
    private static readonly string[] Cmdlets =
    [
        "Invoke-Expression", "Invoke-Command", "Invoke-WebRequest", "Invoke-RestMethod", "Invoke-Item", "Invoke-WmiMethod", "Invoke-CimMethod",
        "New-Object", "Get-Variable", "Set-Variable", "New-Variable", "Remove-Variable", "Get-ChildItem", "Get-Item", "Set-Item", "New-Item",
        "Remove-Item", "Copy-Item", "Move-Item", "Rename-Item", "Get-ItemProperty", "Set-ItemProperty", "New-ItemProperty", "Test-Path",
        "Start-Process", "Stop-Process", "Get-Process", "Start-Sleep", "Start-Job", "Start-BitsTransfer", "Write-Host", "Write-Output",
        "Write-Verbose", "ForEach-Object", "Where-Object", "Select-Object", "Sort-Object", "Measure-Object", "Get-Content", "Set-Content",
        "Add-Content", "Out-File", "Out-Null", "Out-String", "Add-Type", "Set-Alias", "New-Alias", "Get-Alias", "Get-Command",
        "ConvertTo-SecureString", "ConvertFrom-SecureString", "Get-Random", "Join-Path", "Split-Path", "Resolve-Path", "Get-Location",
        "Set-Location", "Import-Module", "Expand-Archive", "Compress-Archive", "Get-WmiObject", "Get-CimInstance", "Register-ScheduledTask",
        "New-ScheduledTaskAction", "New-ScheduledTaskTrigger", "Set-MpPreference", "Add-MpPreference", "Get-Date", "Set-ExecutionPolicy",
        "Format-Table", "Out-Host", "Get-Member", "Get-Service", "New-Service", "Restart-Computer", "Stop-Computer", "Clear-History", "Get-Clipboard", "Set-Clipboard",
    ];

    private static readonly Dictionary<string, string> DefaultAliases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["iex"] = "Invoke-Expression", ["icm"] = "Invoke-Command", ["iwr"] = "Invoke-WebRequest", ["irm"] = "Invoke-RestMethod",
        ["curl"] = "Invoke-WebRequest", ["wget"] = "Invoke-WebRequest", ["ii"] = "Invoke-Item", ["%"] = "ForEach-Object",
        ["foreach"] = "ForEach-Object", ["?"] = "Where-Object", ["where"] = "Where-Object", ["select"] = "Select-Object",
        ["sort"] = "Sort-Object", ["sal"] = "Set-Alias", ["nal"] = "New-Alias", ["gal"] = "Get-Alias", ["sv"] = "Set-Variable",
        ["set"] = "Set-Variable", ["gv"] = "Get-Variable", ["nv"] = "New-Variable", ["rv"] = "Remove-Variable", ["gci"] = "Get-ChildItem",
        ["ls"] = "Get-ChildItem", ["dir"] = "Get-ChildItem", ["gi"] = "Get-Item", ["si"] = "Set-Item", ["ni"] = "New-Item",
        ["ri"] = "Remove-Item", ["rm"] = "Remove-Item", ["del"] = "Remove-Item", ["cp"] = "Copy-Item", ["copy"] = "Copy-Item",
        ["saps"] = "Start-Process", ["start"] = "Start-Process", ["spps"] = "Stop-Process", ["kill"] = "Stop-Process", ["gps"] = "Get-Process",
        ["ps"] = "Get-Process", ["sleep"] = "Start-Sleep", ["echo"] = "Write-Output", ["write"] = "Write-Output", ["gc"] = "Get-Content",
        ["cat"] = "Get-Content", ["type"] = "Get-Content", ["sc"] = "Set-Content", ["ac"] = "Add-Content", ["gcm"] = "Get-Command",
        ["measure"] = "Measure-Object", ["gwmi"] = "Get-WmiObject", ["ipmo"] = "Import-Module", ["cd"] = "Set-Location",
        ["sl"] = "Set-Location", ["gl"] = "Get-Location", ["pwd"] = "Get-Location", ["ft"] = "Format-Table", ["gm"] = "Get-Member",
        ["gsv"] = "Get-Service", ["sajb"] = "Start-Job", ["gp"] = "Get-ItemProperty", ["sp"] = "Set-ItemProperty", ["clhy"] = "Clear-History",
    };

    /// <summary>Commands not worth listing among the calls: plumbing a script uses to build values.</summary>
    private static readonly HashSet<string> Plumbing = new(StringComparer.OrdinalIgnoreCase)
    {
        "ForEach-Object", "Where-Object", "Select-Object", "Sort-Object", "Measure-Object", "Write-Output", "Write-Host", "Write-Verbose",
        "Out-Null", "Out-String", "Set-Variable", "Get-Variable", "New-Variable", "Get-Alias", "Set-Alias", "New-Alias", "Get-Command",
        "Get-ChildItem", "Get-Item", "Get-Random", "Get-Date", "Format-Table", "Out-Host", "Get-Member", "Invoke-Expression", "Start-Sleep",
        "Get-Location", "Join-Path", "Split-Path", "Resolve-Path", "Test-Path",
    };

    /// <summary>A command name as the shell resolves it: script functions, aliases, cmdlets, then Get-&lt;name&gt;.</summary>
    private string? Resolve(string name)
    {
        if (_functions.ContainsKey(name)) return name;
        for (int i = 0; i < 8 && _aliases.TryGetValue(name, out var target); i++) name = target;
        if (_functions.ContainsKey(name)) return name;
        if (DefaultAliases.TryGetValue(name, out var builtin)) return builtin;
        var stem = name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name[..^4] : name;
        stem = stem[(stem.LastIndexOfAny(['\\', '/']) + 1)..];
        if (Cmdlets.FirstOrDefault(c => c.Equals(stem, StringComparison.OrdinalIgnoreCase)) is { } cmdlet) return cmdlet;
        if (stem.ToLowerInvariant() is "powershell" or "pwsh" or "cmd") return stem.ToLowerInvariant();
        if (Cmdlets.FirstOrDefault(c => c.Equals("Get-" + stem, StringComparison.OrdinalIgnoreCase)) is { } get) return get;
        return null;
    }

    /// <summary>Commands whose names match a wildcard, as Get-Command lists them.</summary>
    private List<string> CommandsLike(string pattern) =>
        Cmdlets.Concat(DefaultAliases.Keys).Concat(_functions.Keys).Concat(_aliases.Keys)
            .Where(c => WildcardMatch(c, pattern, true)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    // --- pipelines and commands ---

    private object? Pipeline(PsPipeline p)
    {
        object? input = null;
        for (int i = 0; i < p.Elements.Count; i++)
        {
            var element = p.Elements[i];
            if (element is PsExpr e) input = i == 0 ? Eval(e) : PsUnknown.Value;
            else if (element is PsCommand c) input = Command(c, i > 0, input, i > 0 ? p.Start : c.Start);
        }
        return input;
    }

    private sealed record Bound(Dictionary<string, object?> Named, List<object?> Positional, List<PsArgument> Raw)
    {
        /// <summary>A named argument given by any unambiguous prefix of one of <paramref name="names"/>.</summary>
        public object? Get(params string[] names)
        {
            foreach (var (k, v) in Named)
                if (names.Any(n => n.StartsWith(k, StringComparison.OrdinalIgnoreCase))) return v;
            return null;
        }

        public bool Has(params string[] names) => Named.Keys.Any(k => names.Any(n => n.StartsWith(k, StringComparison.OrdinalIgnoreCase)));
    }

    private Bound Bind(PsCommand c, params string[] switches)
    {
        var named = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        var positional = new List<object?>();
        for (int i = 0; i < c.Args.Count; i++)
        {
            var a = c.Args[i];
            if (a.Parameter == null) { positional.Add(Argument(a.Value!)); continue; }
            if (a.Value != null) { named[a.Parameter] = Eval(a.Value); continue; }
            bool isSwitch = switches.Any(s => s.StartsWith(a.Parameter, StringComparison.OrdinalIgnoreCase));
            if (!isSwitch && i + 1 < c.Args.Count && c.Args[i + 1].Parameter == null)
            {
                named[a.Parameter] = Argument(c.Args[++i].Value!);
                continue;
            }
            named[a.Parameter] = true;
        }
        return new Bound(named, positional, c.Args);
    }

    /// <summary>A command argument; a computed one that folds to a plain word is written as a bare word.</summary>
    private object? Argument(PsExpr e)
    {
        var v = Eval(e);
        if (v is string s && e is not PsLiteral { Raw: true } && e is not PsVariable && _layer.Has(e.Start, e.End) && Regex.IsMatch(s, @"^[A-Za-z_][\w.\-]*$"))
            _layer.Override(e.Start, e.End, s);
        return v;
    }

    private object? Command(PsCommand c, bool piped, object? input, int siteStart)
    {
        string? name = null;
        object? target = null;
        if (c.Invocation == '\0' && c.Name is PsLiteral { Value: string bare })
        {
            name = bare;
            var source = _layer.Text.AsSpan(c.Name.Start, c.Name.End - c.Name.Start);
            if (source.IndexOfAny('`', '\'', '"') >= 0 && Resolve(bare) != null) _layer.Set(c.Name.Start, c.Name.End, Canonical(bare), weak: _fold);
        }
        else
        {
            target = c.Name is PsLiteral { Value: string word } ? word : Eval(c.Name);
            if (target is string s) name = s;
            else if (target is PsCommandInfo info) name = info.Name;
        }
        if (target is PsBlockValue block)
        {
            var bound = Bind(c);
            return _fold ? PsUnknown.Value : InvokeBlock(block, bound.Positional, piped ? input : null, piped, c.Invocation != '.');
        }
        if (name == null || Resolve(name) is not { } resolved)
        {
            if (name != null && c.Invocation == '\0') Record(name);
            Bind(c); // folds the arguments
            return PsUnknown.Value;
        }
        if (c.Invocation != '\0' && c.Name is not PsLiteral { Raw: false } && Regex.IsMatch(name, @"^[\w\-.]+$"))
            _layer.Set(c.Start, c.Name.End, Canonical(name), weak: _fold);
        if (_functions.TryGetValue(resolved, out var fn))
        {
            var bound = Bind(c);
            if (_fold) return PsUnknown.Value;
            return InvokeFunction(fn.Function, fn.Layer, bound, piped ? input : null, piped);
        }
        return Builtin(resolved, c, piped, input, siteStart);
    }

    /// <summary>The canonical spelling of a command name (cmdlet case restored, escapes gone), aliases kept as aliases.</summary>
    private static string Canonical(string name)
    {
        if (DefaultAliases.ContainsKey(name)) return name.ToLowerInvariant();
        return Cmdlets.FirstOrDefault(c => c.Equals(name, StringComparison.OrdinalIgnoreCase)) ?? name;
    }

    private void Record(string call)
    {
        if (!_fold && _ctx.Calls.Count < 200 && call.Length <= 200) _ctx.Calls.Add(call);
    }

    private object? Builtin(string name, PsCommand c, bool piped, object? input, int siteStart)
    {
        switch (name)
        {
            case "Invoke-Expression":
            {
                var b = Bind(c);
                var code = b.Get("Command") ?? (b.Positional.Count > 0 ? b.Positional[0] : piped ? input : null);
                if (code is object[] parts) code = Join(parts, "\n");
                if (!Known(code) || Str(code) is not { } text) { Record("Invoke-Expression"); return PsUnknown.Value; }
                return RunNested(text, "Invoke-Expression", siteStart, c.End, code);
            }
            case "ForEach-Object":
            {
                var b = Bind(c);
                if (_fold || !piped) return PsUnknown.Value;
                // several positional blocks: the first is Begin, and the last End when there are three or more
                var blocks = b.Positional.ToList();
                object? begin = b.Get("Begin"), end = b.Get("End");
                if (blocks.Count >= 2 && blocks.All(x => x is PsBlockValue))
                {
                    begin = blocks[0];
                    if (blocks.Count >= 3) { end = blocks[^1]; blocks = blocks.Skip(1).Take(blocks.Count - 2).ToList(); }
                    else blocks = blocks.Skip(1).ToList();
                }
                if (b.Get("Process") is { } named) blocks = [named];
                var output = new List<object?>();
                if (begin is PsBlockValue bb) Output(output, InvokeBlock(bb, [], null, false, newScope: false));
                foreach (var item in Items(input).ToList())
                {
                    Step();
                    if (!Known(item)) return PsUnknown.Value;
                    foreach (var process in blocks)
                    {
                        object? r;
                        if (process is PsBlockValue pb)
                        {
                            _scopes[^1]["_"] = item;
                            r = InvokeBlock(pb, [], null, false, newScope: false);
                        }
                        else if (Str(process) is { } member) r = b.Positional.Count > 1 ? Invoke(item, member, b.Positional.Skip(1).ToList(), null) : GetMember(item, member, false);
                        else return PsUnknown.Value;
                        if (!Known(r)) return PsUnknown.Value;
                        Output(output, r);
                        if (process is not PsBlockValue) break;
                    }
                }
                if (end is PsBlockValue eb) Output(output, InvokeBlock(eb, [], null, false, newScope: false));
                return Collapse(output, input);
            }
            case "Where-Object":
            {
                var b = Bind(c);
                if (_fold || !piped || (b.Get("FilterScript") ?? b.Positional.FirstOrDefault()) is not PsBlockValue filter) return PsUnknown.Value;
                var output = new List<object?>();
                foreach (var item in Items(input).ToList())
                {
                    _scopes[^1]["_"] = item;
                    var r = Bool(InvokeBlock(filter, [], null, false, newScope: false));
                    if (r == null) return PsUnknown.Value;
                    if (r == true) output.Add(item);
                }
                return Collapse(output, input);
            }
            case "Select-Object":
            {
                var b = Bind(c, "Unique");
                if (!piped || !Known(input)) return PsUnknown.Value;
                var items = Items(input).ToList();
                if (b.Get("ExpandProperty") is string prop)
                    return items.Select(i => GetMember(i, prop, false)).ToArray();
                if (Long(b.Get("Skip")) is { } skip && b.Has("Skip")) items = items.Skip((int)skip).ToList();
                if (b.Has("First") && Long(b.Get("First")) is { } first) items = items.Take((int)first).ToList();
                if (b.Has("Last") && Long(b.Get("Last")) is { } last) items = items.TakeLast((int)last).ToList();
                if (b.Has("Index") && Array(b.Get("Index")) is { } idx) items = idx.Select(i => Long(i) is { } n && n >= 0 && n < items.Count ? items[(int)n] : null).ToList();
                return items.Count == 1 ? items[0] : items.ToArray();
            }
            case "Sort-Object":
                Bind(c);
                return PsUnknown.Value;
            case "Write-Output":
            {
                var b = Bind(c);
                return piped ? input : b.Positional.Count == 1 ? b.Positional[0] : b.Positional.ToArray();
            }
            case "Out-String":
            {
                Bind(c);
                if (!piped || Array(input) is not { } items || Join(items, "\n") is not { } text) return PsUnknown.Value;
                return text + "\n";
            }
            case "Get-Clipboard":
                Bind(c);
                return _ctx.Clipboard ?? (object)PsUnknown.Value;
            case "Add-Type" when c.Args.All(a => a.Parameter == null || "assemblyname".StartsWith(a.Parameter.ToLowerInvariant(), StringComparison.Ordinal)):
                Bind(c);
                return PsVoid.Value; // loading a framework assembly by name
            case "Write-Host" or "Out-Null" or "Write-Verbose" or "Out-Host" or "Start-Sleep":
                Bind(c);
                return PsVoid.Value;
            case "Set-Variable" or "New-Variable":
            {
                var b = Bind(c, "PassThru", "Force");
                var vname = Str(b.Get("Name") ?? b.Positional.ElementAtOrDefault(0));
                var value = b.Has("Value") ? b.Get("Value") : b.Positional.Count > 1 ? b.Positional[1] : piped ? input : null;
                if (!_fold && vname != null) SetVar(vname, value);
                return PsVoid.Value;
            }
            case "Get-Variable":
            {
                var b = Bind(c, "ValueOnly");
                if (Str(b.Get("Name") ?? b.Positional.ElementAtOrDefault(0)) is not { } pattern) return PsUnknown.Value;
                var infos = VariablesLike(pattern);
                if (infos.Count == 0) return PsUnknown.Value;
                object? one(PsVariableInfo v) => b.Has("ValueOnly") ? v.Value : v;
                return infos.Count == 1 ? one(infos[0]) : infos.Select(one).ToArray();
            }
            case "Set-Item":
            {
                var b = Bind(c, "Force", "PassThru");
                var path = Str(b.Get("Path", "LiteralPath") ?? b.Positional.ElementAtOrDefault(0));
                var value = b.Has("Value") ? b.Get("Value") : b.Positional.Count > 1 ? b.Positional[1] : piped ? input : null;
                if (path != null && path.IndexOf(':') is var colon and > 0 && !_fold)
                {
                    var drive = path[..colon].ToLowerInvariant();
                    var item = path[(colon + 1)..].TrimStart('\\', '/');
                    if (drive == "variable") SetVar(item, value);
                    else if (drive == "env") SetVar("env:" + item, value);
                    else Record(name);
                }
                return PsVoid.Value;
            }
            case "Get-ChildItem" or "Get-Item":
            {
                var b = Bind(c, "Force", "Recurse");
                if (Str(b.Get("Path", "LiteralPath") ?? b.Positional.ElementAtOrDefault(0)) is not { } path) return PsUnknown.Value;
                var colon = path.IndexOf(':');
                if (colon <= 0) { Record(name); return PsUnknown.Value; }
                var drive = path[..colon].ToLowerInvariant();
                var pattern = path[(colon + 1)..].TrimStart('\\', '/');
                if (pattern.Length == 0) pattern = "*";
                List<PsVariableInfo> found = drive switch
                {
                    "variable" => VariablesLike(pattern),
                    "env" => ScriptEnvironment.Defaults.Keys.Concat(_ctx.Environment.Keys).Distinct(StringComparer.OrdinalIgnoreCase)
                        .Where(k => WildcardMatch(k, pattern, true)).Select(k => new PsVariableInfo(k, Env(k))).ToList(),
                    _ => [],
                };
                if (found.Count == 0) return PsUnknown.Value;
                return found.Count == 1 ? found[0] : found.Cast<object?>().ToArray();
            }
            case "Set-Alias" or "New-Alias":
            {
                var b = Bind(c, "Force", "PassThru");
                var alias = Str(b.Get("Name") ?? b.Positional.ElementAtOrDefault(0));
                var value = Str(b.Get("Value") ?? b.Positional.ElementAtOrDefault(1));
                if (!_fold && alias != null && value != null && Known(b.Get("Name") ?? b.Positional.ElementAtOrDefault(0))) _aliases[alias] = value;
                return PsVoid.Value;
            }
            case "Get-Alias":
            {
                var b = Bind(c);
                return Str(b.Get("Name") ?? b.Positional.ElementAtOrDefault(0)) is { } a && Resolve(a) is { } r ? new PsCommandInfo(r) : PsUnknown.Value;
            }
            case "Get-Command":
            {
                var b = Bind(c);
                if (Str(b.Get("Name") ?? b.Positional.ElementAtOrDefault(0)) is not { } pattern) return PsUnknown.Value;
                var found = CommandsLike(pattern).Select(n => Resolve(n) ?? n).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                return found.Count == 1 ? new PsCommandInfo(found[0]) : found.Count > 1 ? found.Select(f => (object?)new PsCommandInfo(f)).ToArray() : PsUnknown.Value;
            }
            case "New-Object":
            {
                var b = Bind(c, "Strict");
                if (b.Get("ComObject") is { } com) { Record("New-Object -ComObject " + Str(com)); return new PsOpaque(Str(com) ?? "COM"); }
                var type = Str(b.Get("TypeName") ?? b.Positional.ElementAtOrDefault(0));
                var args = Array(b.Get("ArgumentList") ?? (b.Positional.Count > 1 ? b.Positional[1] : null)) ?? [];
                if (b.Positional.Count > 1 && b.Positional[1] is not object[]) args = [b.Positional[1]];
                return type == null ? PsUnknown.Value : New(type, args.ToList());
            }
            case "ConvertTo-SecureString":
            {
                var b = Bind(c, "AsPlainText", "Force");
                var text = Str(b.Get("String") ?? b.Positional.ElementAtOrDefault(0) ?? (piped ? input : null));
                if (text == null) return PsUnknown.Value;
                if (b.Has("AsPlainText")) return new PsSecureString(text);
                var key = Bytes(Array(b.Get("Key") ?? b.Positional.ElementAtOrDefault(1)));
                if (key == null) { Record("ConvertTo-SecureString"); return PsUnknown.Value; }
                return SecureStringPlain(text, key) is { } plain ? new PsSecureString(TagStep(plain, "SecureString (AES)", text)) : PsUnknown.Value;
            }
            case "Invoke-Command":
            {
                var b = Bind(c);
                var sb = b.Get("ScriptBlock") ?? b.Positional.FirstOrDefault();
                if (b.Has("ComputerName", "Session")) Record("Invoke-Command -ComputerName");
                return sb is PsBlockValue block && !_fold ? InvokeBlock(block, Array(b.Get("ArgumentList"))?.ToList() ?? [], null, false, true) : PsUnknown.Value;
            }
            case "powershell": return Launcher(c, siteStart);
            case "cmd":
            {
                var b = Bind(c);
                Record("cmd.exe");
                var args = c.Args.Select(a => a.Value != null && Eval(a.Value) is string s ? s : _layer.Text[a.Start..a.End]).ToList();
                int at = args.FindIndex(a => a.Equals("/c", StringComparison.OrdinalIgnoreCase) || a.Equals("/k", StringComparison.OrdinalIgnoreCase) || a.Equals("/r", StringComparison.OrdinalIgnoreCase));
                if (_fold || at < 0 || at + 1 >= args.Count) return PsUnknown.Value;
                var command = string.Join(" ", args.Skip(at + 1));
                if (_peeled.Add((_layer, c.Start, c.End)) && _ctx.Peel("cmd", command, "cmd.exe /c", _layer.Depth + 1) is { } plain)
                    _layer.Set(c.Start, c.End, plain);
                return PsUnknown.Value;
            }
        }
        Bind(c);
        if (!Plumbing.Contains(name)) Record(name);
        return PsUnknown.Value;
    }

    /// <summary>Pipeline output as the shell hands it on: nothing, one item, or an array.</summary>
    private object? Collapse(List<object?> output, object? source) =>
        output.Count switch { 0 => null, 1 => output[0], _ => Tag(output.ToArray(), source) };

    private List<PsVariableInfo> VariablesLike(string pattern)
    {
        var names = AutomaticNames.Concat(_fold ? [] : _scopes.SelectMany(s => s.Keys)).Distinct(StringComparer.OrdinalIgnoreCase);
        return names.Where(n => WildcardMatch(n, pattern, true)).Select(n => new PsVariableInfo(n, GetVar(n))).ToList();
    }

    /// <summary>powershell.exe arguments: an encoded command (base64 of UTF-16LE) or a command line, peeled as a layer.</summary>
    private object? Launcher(PsCommand c, int siteStart)
    {
        Record("powershell.exe");
        var values = new List<(string? Param, object? Value)>();
        foreach (var a in c.Args) values.Add((a.Parameter, a.Value != null ? Eval(a.Value) : null));
        if (_fold) return PsUnknown.Value;
        for (int i = 0; i < values.Count; i++)
        {
            var p = values[i].Param?.ToLowerInvariant();
            if (p == null) continue;
            if (p is "e" or "ec" || p.Length >= 2 && "encodedcommand".StartsWith(p, StringComparison.Ordinal))
            {
                var arg = values[i].Value ?? (i + 1 < values.Count && values[i + 1].Param == null ? values[i + 1].Value : null);
                if (Str(arg) is { } b64 && ScriptText.FromBase64(b64) is { } bytes)
                {
                    var text = TagStep(Encoding.Unicode.GetString(bytes), "base64 > utf-16le", arg);
                    return RunNested(text, "powershell -EncodedCommand", siteStart, c.End, text);
                }
                return PsUnknown.Value;
            }
            if (p is "c" or "co" or "com" or "comm" or "comma" or "comman" or "command")
            {
                var rest = values.Skip(i + 1).Select(v => v.Param != null ? "-" + v.Param : Str(v.Value)).ToList();
                if (rest.Any(r => r == null)) return PsUnknown.Value;
                return RunNested(string.Join(" ", rest), "powershell -Command", siteStart, c.End, null);
            }
        }
        // no -Command: the first positional argument starts the command
        int first = values.FindIndex(v => v.Param == null);
        if (first < 0 || values.Skip(first).Any(v => v.Param == null && Str(v.Value) == null)) return PsUnknown.Value;
        return RunNested(string.Join(" ", values.Skip(first).Select(v => v.Param != null ? "-" + v.Param : Str(v.Value))), "powershell", siteStart, c.End, null);
    }

    /// <summary>ConvertTo-SecureString -Key: the shell's encrypted standard string (AES-CBC, UTF-16LE plain text).</summary>
    private static string? SecureStringPlain(string text, byte[] key)
    {
        try
        {
            if (key.Length is not (16 or 24 or 32)) return null;
            const string Header = "76492d1116743f0423413b16050a5345";
            if (!text.StartsWith(Header, StringComparison.OrdinalIgnoreCase)) return null;
            var inner = Encoding.Unicode.GetString(Convert.FromBase64String(text[Header.Length..])).Split('|');
            if (inner.Length != 3) return null;
            var iv = Convert.FromBase64String(inner[1]);
            var cipher = Convert.FromHexString(inner[2]);
            using var aes = Aes.Create();
            aes.Key = key;
            return Encoding.Unicode.GetString(aes.DecryptCbc(cipher, iv));
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or ArgumentException) { return null; }
    }

    // --- code layers ---

    /// <summary>Runs <paramref name="code"/> as a nested layer in the same session, replacing the site with its plain text.</summary>
    private object? RunNested(string code, string via, int siteStart, int siteEnd, object? source, bool asBlock = false)
    {
        var key = (_layer, siteStart, siteEnd);
        if (_fold && _peeled.Contains(key)) return PsUnknown.Value;
        var chain = Chain(source);
        if (_ctx.Layers.Count >= ScriptContext.MaxLayers)
        {
            _ctx.Note($"More than {ScriptContext.MaxLayers} layers: the rest are left as they are.");
            _ctx.Incomplete = true;
            return PsUnknown.Value;
        }
        if (++_callDepth > MaxCallDepth) { _callDepth--; return PsUnknown.Value; }
        try
        {
            bool first = _peeled.Add(key);
            int depth = _layer.Depth + 1;
            if (first) _ctx.Layers.Add(new ScriptLayer(depth, "powershell", chain.Length > 0 ? $"{via} of {chain}" : via, code));
            var outer = _layer;
            var plain = RunLayer(code, depth, out var outputs);
            if (first) outer.Set(siteStart, siteEnd, asBlock ? "{" + plain + "}" : plain.TrimEnd('\r', '\n'));
            return outputs.Count switch { 0 => PsVoid.Value, 1 => outputs[0], _ => outputs.ToArray() };
        }
        finally { _callDepth--; }
    }

    /// <summary>A script block made from text ([ScriptBlock]::Create, a cast, NewScriptBlock): read as a layer, shown in braces.</summary>
    private object? CodeBlock(string code, string via, int siteStart, int siteEnd, object? source)
    {
        var key = (_layer, siteStart, siteEnd);
        if (!_peeled.Contains(key))
        {
            var chain = Chain(source);
            int depth = _layer.Depth + 1;
            _peeled.Add(key);
            if (_ctx.Layers.Count < ScriptContext.MaxLayers)
            {
                _ctx.Layers.Add(new ScriptLayer(depth, "powershell", chain.Length > 0 ? $"{via} of {chain}" : via, code));
                var outer = _layer;
                bool fold = _fold;
                _fold = true; // the block runs when invoked; read it here for its text only
                try { outer.Set(siteStart, siteEnd, "{" + RunLayer(code, depth, out _).TrimEnd() + "}"); }
                finally { _fold = fold; }
            }
        }
        var layer = new PsLayerText(code, _layer.Depth + 1);
        return new PsBlockValue(PsParser.Parse(code, _budget), null, layer, code);
    }

    private object? InvokeBlock(PsBlockValue block, List<object?> args, object? input, bool piped, bool newScope)
    {
        if (_fold) return PsUnknown.Value;
        if (++_callDepth > MaxCallDepth) { _callDepth--; return PsUnknown.Value; }
        var saved = _layer;
        _layer = block.Layer;
        if (newScope) _scopes.Add(new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase));
        try
        {
            var scope = _scopes[^1];
            if (newScope)
            {
                var parameters = block.Parameters ?? [];
                for (int i = 0; i < parameters.Count; i++)
                    scope[parameters[i].Name] = i < args.Count ? args[i] : parameters[i].Default != null ? Eval(parameters[i].Default!) : null;
                scope["args"] = args.Skip(parameters.Count).ToArray();
                if (piped) scope["input"] = input;
            }
            var outputs = new List<object?>();
            try { ExecBody(block.Body, outputs); }
            catch (ReturnSignal) { }
            if (outputs.Any(o => !Known(o))) return PsUnknown.Value;
            return outputs.Count switch { 0 => PsVoid.Value, 1 => outputs[0], _ => outputs.ToArray() };
        }
        finally
        {
            if (newScope) _scopes.RemoveAt(_scopes.Count - 1);
            _layer = saved;
            _callDepth--;
        }
    }

    private object? InvokeFunction(PsFunction fn, PsLayerText layer, Bound bound, object? input, bool piped)
    {
        if (++_callDepth > MaxCallDepth) { _callDepth--; return PsUnknown.Value; }
        var saved = _layer;
        _layer = layer;
        var scope = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        _scopes.Add(scope);
        try
        {
            var positional = new Queue<object?>(bound.Positional);
            foreach (var p in fn.Parameters)
            {
                var named = bound.Named.FirstOrDefault(n => p.Name.StartsWith(n.Key, StringComparison.OrdinalIgnoreCase));
                scope[p.Name] = named.Key != null ? named.Value : positional.Count > 0 ? positional.Dequeue() : p.Default != null ? Eval(p.Default) : null;
            }
            scope["args"] = positional.ToArray();
            if (piped) { scope["input"] = input; scope["_"] = input; }
            var outputs = new List<object?>();
            try { ExecBody(fn.Body, outputs); }
            catch (ReturnSignal) { }
            if (outputs.Any(o => !Known(o))) return PsUnknown.Value;
            return outputs.Count switch { 0 => PsVoid.Value, 1 => outputs[0], _ => outputs.ToArray() };
        }
        finally
        {
            _scopes.RemoveAt(_scopes.Count - 1);
            _layer = saved;
            _callDepth--;
        }
    }

    // --- objects ---

    private object? New(string type, List<object?> args)
    {
        switch (TypeKey(type))
        {
            case "io.memorystream":
                return args.Count == 0 ? new PsStreamValue([]) : Bytes(Array(args[0])) is { } bytes ? Tag(new PsStreamValue(bytes), args[0]) : PsUnknown.Value;
            case "io.compression.deflatestream" or "io.compression.gzipstream":
            {
                if (args.Count == 0 || args[0] is not PsStreamValue s) return PsUnknown.Value;
                bool gzip = type.Contains("gzip", StringComparison.OrdinalIgnoreCase);
                return Inflate(s.Data, gzip) is { } data ? TagStep(new PsStreamValue(data), gzip ? "gzip" : "deflate", s) : PsUnknown.Value;
            }
            case "io.streamreader":
            {
                if (args.Count == 0 || args[0] is not PsStreamValue s) return PsUnknown.Value;
                var enc = args.Count > 1 && args[1] is PsEncodingValue e ? e.Encoding : null;
                string text;
                if (enc != null) text = enc.GetString(s.Data);
                else text = ScriptText.Decode(s.Data, out _);
                return new PsReaderValue(TagStep(text, null, s));
            }
            case "text.asciiencoding": return new PsEncodingValue(Encoding.ASCII, "ASCIIEncoding");
            case "text.utf8encoding": return new PsEncodingValue(new UTF8Encoding(false), "UTF8Encoding");
            case "text.unicodeencoding": return new PsEncodingValue(Encoding.Unicode, "UnicodeEncoding");
            case "string":
                if (args.Count == 1 && Array(args[0]) is { } chars && chars.All(x => x is char)) return JoinItems(chars, "");
                if (args.Count == 2 && Char(args[0]) is { } ch && Long(args[1]) is { } n && n >= 0 && n <= _budget.MaxChars) return new string(ch, (int)n);
                return PsUnknown.Value;
            case "management.automation.pscredential":
                return new PsOpaque("PSCredential") { Secret = args.Count > 1 && args[1] is PsSecureString ss ? ss.Plain : null };
            case "byte[]": return args.Count == 1 && Long(args[0]) is { } len && len is >= 0 and <= 1 << 24 ? new byte[len] : PsUnknown.Value;
        }
        Record("New-Object " + type);
        return new PsOpaque(type);
    }

    private byte[]? Inflate(byte[] data, bool gzip)
    {
        try
        {
            using var input = new MemoryStream(data);
            using Stream z = gzip ? new GZipStream(input, CompressionMode.Decompress) : new DeflateStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();
            var buffer = new byte[81920];
            int n;
            while ((n = z.Read(buffer, 0, buffer.Length)) > 0)
            {
                if (output.Length + n > _budget.MaxChars) return null;
                output.Write(buffer, 0, n);
            }
            return output.ToArray();
        }
        catch (InvalidDataException) { return null; }
    }

    private object? GetMember(object? target, string name, bool isStatic)
    {
        var n = name.ToLowerInvariant();
        if (isStatic && target is PsTypeValue t) return StaticMember(TypeKey(t.Name), n);
        switch (target)
        {
            case string s when n == "length": return (long)s.Length;
            case object[] a when n is "length" or "count": return (long)a.Length;
            case byte[] b when n is "length" or "count": return (long)b.Length;
            case PsVariableInfo v when n == "name": return v.Name;
            case PsVariableInfo v when n == "value": return v.Value;
            case PsCommandInfo c when n is "name" or "definition": return c.Name;
            case PsMatchValue m when n == "value": return m.Value;
            case PsMatchValue m when n == "index": return (long)m.Index;
            case PsHashValue h when n is "keys" or "values" or "count":
                return n == "count" ? h.Items.Count : n == "keys" ? h.Items.Keys.Cast<object?>().ToArray() : h.Items.Values.ToArray();
            case PsHashValue h: return h.Items.TryGetValue(name, out var hv) ? hv : null;
            case object[] a:
            {
                var each = a.Select(x => GetMember(x, name, false)).ToArray(); // member enumeration
                return each.All(Known) ? Tag(each, a) : PsUnknown.Value;
            }
            case PsOpaque { Type: "NetworkCredential", Secret: { } secret } when n == "password": return secret;
            case PsOpaque { Type: "ExecutionContext" } when n is "invokecommand" or "sessionstate": return new PsOpaque("ExecutionContext." + n);
            case PsOpaque { Type: "ExecutionContext.sessionstate" } when n == "psvariable": return new PsOpaque("PSVariable");
            case PsEncodingValue or PsStreamValue or PsReaderValue or string or PsBlockValue or PsOpaque or PsTypeValue: return new PsMethodGroup(target, name);
        }
        return PsUnknown.Value;
    }

    private object? StaticMember(string type, string name) => (type, name) switch
    {
        ("text.encoding", "utf8") => new PsEncodingValue(new UTF8Encoding(false), "UTF8Encoding"),
        ("text.encoding", "unicode") => new PsEncodingValue(Encoding.Unicode, "UnicodeEncoding"),
        ("text.encoding", "bigendianunicode") => new PsEncodingValue(Encoding.BigEndianUnicode, "UnicodeEncoding"),
        ("text.encoding", "ascii") => new PsEncodingValue(Encoding.ASCII, "ASCIIEncoding"),
        ("text.encoding", "utf32") => new PsEncodingValue(Encoding.UTF32, "UTF32Encoding"),
        ("text.encoding", "default") => new PsEncodingValue(Encoding.Latin1, "Encoding"),
        ("text.encoding", "utf7") => new PsEncodingValue(Encoding.ASCII, "UTF7Encoding"),
        ("string", "empty") => "",
        ("io.compression.compressionmode", _) => name,
        ("environment", "newline") => "\r\n",
        _ => new PsMethodGroup(new PsTypeValue(type), name), // a static method named as a member: .Invoke() calls it
    };

    private object? Invoke(object? target, string name, List<object?> args, PsInvoke? node)
    {
        var n = name.ToLowerInvariant();
        if (args.Any(a => !Known(a)) && !(target is PsOpaque)) return PsUnknown.Value;
        if (target is PsTypeValue t && (node == null || node.Member.Static)) return StaticCall(TypeKey(t.Name), t.Name, n, name, args, node);
        object? A(int i) => i < args.Count ? args[i] : null;
        switch (target)
        {
            case string s: return StringCall(s, n, args);
            case char ch: return StringCall(ch.ToString(), n, args);
            case PsEncodingValue e when n == "getstring":
            {
                if (Bytes(Array(A(0))) is not { } bytes) return PsUnknown.Value;
                if (args.Count == 3 && Long(A(1)) is { } off && Long(A(2)) is { } cnt && off >= 0 && cnt >= 0 && off + cnt <= bytes.Length) bytes = bytes[(int)off..(int)(off + cnt)];
                return TagStep(e.Encoding.GetString(bytes), EncodingStep(e), A(0));
            }
            case PsEncodingValue e when n == "getbytes": return Str(A(0)) is { } gs ? Tag(e.Encoding.GetBytes(gs), A(0)) : PsUnknown.Value;
            case PsReaderValue r when n == "readtoend": return r.Text;
            case PsStreamValue m when n == "toarray": return Tag(m.Data, m);
            case PsStreamValue m when n == "copyto" && A(0) is PsStreamValue to: to.Data = Tag(m.Data, m); return PsVoid.Value;
            case PsStreamValue m when n == "read" && A(0) is byte[] buf: return PsUnknown.Value;
            case PsBlockValue b when n is "invoke" or "invokereturnasis": return InvokeBlock(b, args, null, false, true);
            case PsBlockValue b when n == "tostring": return b.Text;
            case PsMethodGroup g when n is "invoke":
                return g.Target is PsTypeValue gt ? StaticCall(TypeKey(gt.Name), gt.Name, g.Name.ToLowerInvariant(), g.Name, args, node) : Invoke(g.Target, g.Name, args, node);
            case object[] a when n == "foreach" && A(0) is PsBlockValue fb:
            {
                var outputs = new List<object?>();
                foreach (var item in a)
                {
                    _scopes[^1]["_"] = item;
                    var r = InvokeBlock(fb, [], null, false, newScope: false);
                    if (!Known(r)) return PsUnknown.Value;
                    Output(outputs, r);
                }
                return Tag(outputs.ToArray(), a);
            }
            case object[] a when n == "tostring": return "System.Object[]";
            case object[] a when n == "contains": return a.Any(x => Compare("eq", x, A(0), true) is true);
            case object[] a when n == "clone": return a.ToArray();
            case PsOpaque { Type: "ExecutionContext.invokecommand" }:
            {
                if (n is "invokescript" && Str(A(0)) is { } code && node != null) return RunNested(code, "InvokeCommand.InvokeScript", node.Start, node.End, A(0));
                if (n is "newscriptblock" && Str(A(0)) is { } block && node != null) return CodeBlock(block, "InvokeCommand.NewScriptBlock", node.Start, node.End, A(0));
                if (n is "expandstring" && Str(A(0)) is { } x) return x;
                if (n is "getcommand" or "getcmdlet" or "getcmdlets" or "getcommandname" && Str(A(0)) is { } pattern)
                {
                    var found = CommandsLike(pattern).Select(c => Resolve(c) ?? c).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                    if (found.Count != 1) return found.Count == 0 ? PsUnknown.Value : found.Select(f => (object?)(n == "getcommandname" ? f : new PsCommandInfo(f))).ToArray();
                    return n == "getcommandname" ? found[0] : new PsCommandInfo(found[0]);
                }
                return PsUnknown.Value;
            }
            case PsOpaque { Type: "PSVariable" } when n is "getvalue" or "get" && Str(A(0)) is { } vn:
                return n == "get" ? new PsVariableInfo(vn, GetVar(vn)) : GetVar(vn);
            case PsOpaque { Type: "PSCredential" } cred when n == "getnetworkcredential":
                return cred.Secret != null ? new PsOpaque("NetworkCredential") { Secret = cred.Secret } : PsUnknown.Value;
            case PsOpaque o:
            {
                var shown = args.Select(a => a is string s ? ScriptText.SingleQuoted(s.Length > 120 ? s[..120] + "…" : s) : Known(a) && a is long or double ? Str(a) : "…");
                Record($"{o.Type}.{name}({string.Join(", ", shown)})");
                return PsUnknown.Value;
            }
        }
        return PsUnknown.Value;
    }

    private static string EncodingStep(PsEncodingValue e) => e.Name switch
    {
        "UnicodeEncoding" => "utf-16le",
        "UTF8Encoding" => "utf-8",
        "ASCIIEncoding" => "ascii",
        "UTF32Encoding" => "utf-32",
        _ => "text",
    };

    private object? StringCall(string s, string n, List<object?> args)
    {
        object? A(int i) => i < args.Count ? args[i] : null;
        string? S(int i) => Str(A(i));
        long? L(int i) => Long(A(i));
        try
        {
            switch (n)
            {
                case "replace":
                {
                    if (S(0) is not { } from || S(1) is not { } to || from.Length == 0) return PsUnknown.Value;
                    var r = s.Replace(from, to, StringComparison.Ordinal);
                    return r.Length > _budget.MaxChars ? PsUnknown.Value : TagStep(r, "replace", s);
                }
                case "tolower" or "tolowerinvariant": return s.ToLowerInvariant();
                case "toupper" or "toupperinvariant": return s.ToUpperInvariant();
                case "tostring": return s;
                case "trim": return args.Count == 0 ? s.Trim() : S(0) is { } tc ? s.Trim(tc.ToCharArray()) : PsUnknown.Value;
                case "trimstart": return args.Count == 0 ? s.TrimStart() : S(0) is { } ts ? s.TrimStart(ts.ToCharArray()) : PsUnknown.Value;
                case "trimend": return args.Count == 0 ? s.TrimEnd() : S(0) is { } te ? s.TrimEnd(te.ToCharArray()) : PsUnknown.Value;
                case "substring":
                    if (L(0) is not { } start) return PsUnknown.Value;
                    return args.Count > 1 ? (L(1) is { } len ? TagStep(s.Substring((int)start, (int)len), null, s) : PsUnknown.Value) : TagStep(s[(int)start..], null, s);
                case "remove": return L(0) is { } rs ? (args.Count > 1 && L(1) is { } rn ? s.Remove((int)rs, (int)rn) : s.Remove((int)rs)) : PsUnknown.Value;
                case "insert": return L(0) is { } ip && S(1) is { } iv ? s.Insert((int)ip, iv) : PsUnknown.Value;
                case "split":
                {
                    if (args.Count == 0) return s.Split((char[]?)null).Cast<object?>().ToArray();
                    var sep = A(0) is object[] seps ? string.Concat(seps.Select(Str)) : S(0);
                    if (sep == null) return PsUnknown.Value;
                    return TagStep(s.Split(sep.ToCharArray()).Cast<object?>().ToArray(), null, s);
                }
                case "tochararray": return Tag(s.ToCharArray().Select(c => (object?)c).ToArray(), s);
                case "indexof": return S(0) is { } io ? (long)s.IndexOf(io, StringComparison.Ordinal) : PsUnknown.Value;
                case "lastindexof": return S(0) is { } lo ? (long)s.LastIndexOf(lo, StringComparison.Ordinal) : PsUnknown.Value;
                case "contains": return S(0) is { } co ? s.Contains(co, StringComparison.Ordinal) : PsUnknown.Value;
                case "startswith": return S(0) is { } sw ? s.StartsWith(sw, StringComparison.Ordinal) : PsUnknown.Value;
                case "endswith": return S(0) is { } ew ? s.EndsWith(ew, StringComparison.Ordinal) : PsUnknown.Value;
                case "padleft": return L(0) is { } pl && pl <= _budget.MaxChars ? s.PadLeft((int)pl, args.Count > 1 && Char(A(1)) is { } pc ? pc : ' ') : PsUnknown.Value;
                case "padright": return L(0) is { } pr && pr <= _budget.MaxChars ? s.PadRight((int)pr, args.Count > 1 && Char(A(1)) is { } prc ? prc : ' ') : PsUnknown.Value;
                case "chars" or "get_chars": return L(0) is { } ci && ci >= 0 && ci < s.Length ? s[(int)ci] : PsUnknown.Value;
                case "normalize": return s.Normalize();
                case "equals": return S(0) is { } eq ? s.Equals(eq, StringComparison.Ordinal) : PsUnknown.Value;
            }
        }
        catch (ArgumentException) { }
        return PsUnknown.Value;
    }

    private object? StaticCall(string type, string typeName, string n, string name, List<object?> args, PsInvoke? node)
    {
        object? A(int i) => i < args.Count ? args[i] : null;
        string? S(int i) => Str(A(i));
        switch (type, n)
        {
            case ("convert", "frombase64string"):
                return S(0) is { } b64 && ScriptText.FromBase64(b64) is { } bytes ? TagStep(bytes, "base64", A(0)) : PsUnknown.Value;
            case ("convert", "tobase64string"): return Bytes(Array(A(0))) is { } tb ? Convert.ToBase64String(tb) : PsUnknown.Value;
            case ("convert", "fromhexstring"):
                try { return S(0) is { } hx ? TagStep(Convert.FromHexString(hx), "hex", A(0)) : PsUnknown.Value; }
                catch (FormatException) { return PsUnknown.Value; }
            case ("convert", "toint16" or "toint32" or "toint64" or "tobyte" or "touint16" or "touint32" or "tosbyte"):
            {
                if (args.Count == 2 && S(0) is { } digits && Long(A(1)) is { } radix && radix is 2 or 8 or 10 or 16)
                {
                    try
                    {
                        var step = radix switch { 2 => "binary", 8 => "octal", 16 => "hex", _ => null };
                        if (step != null && !_numericSteps.Contains(step)) _numericSteps.Add(step);
                        return Convert.ToInt64(digits.Trim(), (int)radix);
                    }
                    catch (Exception ex) when (ex is FormatException or OverflowException or ArgumentException) { return PsUnknown.Value; }
                }
                return Long(A(0)) is { } v ? v : PsUnknown.Value;
            }
            case ("convert", "tochar"): return Char(A(0)) is { } tc ? tc : PsUnknown.Value;
            case ("convert", "tostring"):
                if (args.Count == 2 && Long(A(0)) is { } num && Long(A(1)) is { } toBase && toBase is 2 or 8 or 10 or 16) return Convert.ToString(num, (int)toBase);
                return S(0) ?? (object)PsUnknown.Value;
            case ("string", "join"):
            {
                if (S(0) is not { } sep) return PsUnknown.Value;
                var items = args.Count == 2 ? Array(A(1)) : args.Skip(1).ToArray();
                return items == null ? PsUnknown.Value : JoinItems(items, sep);
            }
            case ("string", "concat"):
                return args.Count == 1 && A(0) is object[] parts ? JoinItems(parts, "") : JoinItems(args.ToArray(), "");
            case ("string", "format"): return args.Count > 0 ? Format(A(0), args.Count == 2 && A(1) is object[] ? A(1) : args.Skip(1).ToArray()) : PsUnknown.Value;
            case ("string", "new"): return New("string", args);
            case ("char", "convertfromutf32"):
                try { return Long(A(0)) is { } cp ? char.ConvertFromUtf32((int)cp) : PsUnknown.Value; }
                catch (ArgumentOutOfRangeException) { return PsUnknown.Value; }
            case ("char", "tostring"): return S(0) ?? (object)PsUnknown.Value;
            case ("array", "reverse"):
            {
                if (node?.Args.FirstOrDefault() is PsVariable v && A(0) is object[] arr && !_fold)
                {
                    var copy = arr.ToArray();
                    System.Array.Reverse(copy);
                    SetVar(v.Name, TagStep(copy, "reverse", arr));
                }
                return PsVoid.Value;
            }
            case ("regex", "matches"):
            {
                if (S(0) is not { } input || S(1) is not { } pattern) return PsUnknown.Value;
                var options = S(2) ?? "";
                bool rtl = options.Contains("RightToLeft", StringComparison.OrdinalIgnoreCase);
                if (SafeRegex(pattern, options.Contains("IgnoreCase", StringComparison.OrdinalIgnoreCase), rtl ? RegexOptions.RightToLeft : 0) is not { } rx) return PsUnknown.Value;
                try { return TagStep(rx.Matches(input).Select(m => (object?)new PsMatchValue(m.Value, m.Index)).ToArray(), rtl ? "reverse" : null, A(0)); }
                catch (RegexMatchTimeoutException) { return PsUnknown.Value; }
            }
            case ("regex", "replace"):
                return args.Count >= 3 ? Replace(A(0), new object?[] { A(1), A(2) }, ci: false) : PsUnknown.Value;
            case ("regex", "split"): return args.Count >= 2 ? Split(A(0), A(1), ci: false) : PsUnknown.Value;
            case ("regex", "unescape"): try { return S(0) is { } ue ? Regex.Unescape(ue) : PsUnknown.Value; } catch (ArgumentException) { return PsUnknown.Value; }
            case ("scriptblock" or "management.automation.scriptblock", "create"):
                return S(0) is { } code && node != null ? CodeBlock(code, "[ScriptBlock]::Create", node.Start, node.End, A(0)) : PsUnknown.Value;
            case ("web.httputility" or "uri" or "net.webutility", "urldecode" or "unescapedatastring" or "htmldecode"):
                return S(0) is { } enc ? TagStep(n == "htmldecode" ? System.Net.WebUtility.HtmlDecode(enc) : Uri.UnescapeDataString(enc.Replace('+', n == "urldecode" ? ' ' : '+')), "url encoding", A(0)) : PsUnknown.Value;
            case ("runtime.interopservices.marshal", "securestringtobstr" or "securestringtoglobalallocunicode" or "securestringtocotaskmemunicode" or "securestringtoglobalallocansi" or "securestringtocotaskmemansi"):
                return A(0) is PsSecureString ss ? ss : PsUnknown.Value;
            case ("runtime.interopservices.marshal", "ptrtostringauto" or "ptrtostringbstr" or "ptrtostringuni" or "ptrtostringansi"):
                return A(0) is PsSecureString ps ? ps.Plain : PsUnknown.Value;
            case ("environment", "getenvironmentvariable"): return S(0) is { } en && Env(en) is { } ev ? ev : PsUnknown.Value;
            case ("windows.clipboard" or "windows.forms.clipboard", "gettext"): return _ctx.Clipboard ?? (object)PsUnknown.Value;
            case ("windows.clipboard" or "windows.forms.clipboard", "clear" or "settext"): return PsVoid.Value;
            case ("text.encoding", "getencoding"):
            {
                var e = S(0)?.ToLowerInvariant();
                return e switch
                {
                    "utf-8" or "utf8" or "65001" => new PsEncodingValue(new UTF8Encoding(false), "UTF8Encoding"),
                    "ascii" or "us-ascii" or "20127" => new PsEncodingValue(Encoding.ASCII, "ASCIIEncoding"),
                    "unicode" or "utf-16" or "1200" => new PsEncodingValue(Encoding.Unicode, "UnicodeEncoding"),
                    "28591" or "iso-8859-1" or "1252" or "windows-1252" => new PsEncodingValue(Encoding.Latin1, "Encoding"),
                    _ => PsUnknown.Value,
                };
            }
            case ("int" or "long" or "short" or "byte", "parse"): return Long(S(0)) is { } pv ? pv : PsUnknown.Value;
        }
        if (n is "load" or "loadfile" or "loadfrom" or "loadwithpartialname" && type.EndsWith("reflection.assembly", StringComparison.Ordinal))
            Record("[Reflection.Assembly]::" + n switch { "load" => "Load", "loadfile" => "LoadFile", "loadfrom" => "LoadFrom", _ => "LoadWithPartialName" });
        else if (type is not ("math" or "console" or "char" or "string" or "int" or "convert"))
            Record($"[{typeName}]::{name}");
        return PsUnknown.Value;
    }
}
