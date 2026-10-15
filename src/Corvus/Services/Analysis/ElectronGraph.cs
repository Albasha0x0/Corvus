using Acornima.Ast;
using Corvus.Services.Web;

namespace Corvus.Services.Analysis;

/// <summary>
/// The Electron graph of an app's scripts, read on their syntax trees: names resolved through require, esbuild __require,
/// webpack module ids and export getters, destructuring and interop wrappers; windows with their preload; contextBridge
/// keys and the functions they expose; IPC channels with the sends and listeners of each paired across files (renderer to
/// main and main to renderer), through wrapper functions and bridge methods; child_process, fs and shell sinks; native
/// add-ons and the functions called on them. A script that does not parse is read by its call shapes (<see cref="ElectronSurface"/>).
/// </summary>
internal sealed class ElectronGraph
{
    private sealed class Row(string kind, string value, string site, string file, int start)
    {
        public string Kind = kind, Value = value, Site = site, File = file;
        public int Start = start;
        public string? Call, Role, Link;
        public bool Literal;
    }

    private sealed record Wrapper(int Index, string Kind, string Role, string Call);

    private sealed record BridgeMethod(string Name, string File, int Start, int End, string Site, Wrapper? Wrapper);

    /// <summary>A call through a global chain (window.api.open(...)): where it is and its literal arguments.</summary>
    private sealed record GlobalCall(string Chain, string Site, string File, int Start, string?[] Args);

    private static readonly HashSet<string> ChildProcess = new(StringComparer.Ordinal) { "child_process", "node:child_process" };
    private static readonly HashSet<string> Fs = new(StringComparer.Ordinal) { "fs", "node:fs", "fs/promises", "node:fs/promises", "original-fs", "fs-extra" };
    private static readonly HashSet<string> ProcessCalls = new(StringComparer.Ordinal) { "exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork" };
    private static readonly HashSet<string> FsWrites = new(StringComparer.Ordinal)
    {
        "writeFile", "writeFileSync", "appendFile", "appendFileSync", "unlink", "unlinkSync", "rm", "rmSync", "rmdir", "rmdirSync", "rename", "renameSync",
        "copyFile", "copyFileSync", "cp", "cpSync", "chmod", "chmodSync", "createWriteStream", "symlink", "symlinkSync", "outputFile", "remove", "removeSync",
    };
    private static readonly HashSet<string> CommonGlobals = new(StringComparer.Ordinal)
    {
        "console", "Math", "JSON", "Object", "Array", "document", "Promise", "Number", "String", "Date", "Reflect", "Symbol", "process", "require",
        "module", "exports", "location", "history", "localStorage", "sessionStorage", "Buffer", "Intl", "Error", "RegExp", "Map", "Set", "performance",
    };

    private readonly List<Row> _rows = [];
    private readonly List<BridgeMethod> _bridge = [];
    private readonly List<GlobalCall> _globals = [];

    /// <summary>Package names under node_modules that hold a .node add-on: a require of one is a native require.</summary>
    public IReadOnlySet<string> AddonPackages { get; init; } = new HashSet<string>();

    /// <summary>Whether an app-relative path is a file of the app (checks preload paths).</summary>
    public Func<string, bool>? Exists { get; init; }

    public int Parsed { get; private set; }
    public List<string> Notes { get; } = [];

    public void Add(string path, string text, CancellationToken ct)
    {
        var notes = new List<string>();
        var program = JsProgram.Build(path, text, notes, ct);
        if (program == null)
        {
            // over the parse budget or not parsable: the call shapes still name most rows
            var shaped = new List<ElectronRow>();
            ElectronSurface.Scan(text, path, shaped);
            _rows.AddRange(shaped.Select((r, i) => new Row(r.Kind, r.Value, r.Site, path, i)));
            if (notes.Count > 0) Notes.Add($"{path}: {notes[0]}; read by call shapes");
            return;
        }
        Parsed++;
        new FileWalk(this, program).Run(ct);
    }

    /// <summary>One file's walk: rows, bridge methods, wrapper functions and the calls that may reach them.</summary>
    private sealed class FileWalk(ElectronGraph graph, JsProgram p)
    {
        private readonly Dictionary<IFunction, Wrapper> _wrappers = [];
        private readonly Dictionary<Node, string> _names = [];
        private readonly List<(CallExpression Call, JsScope Scope)> _calls = [];

        public void Run(CancellationToken ct)
        {
            p.Walk(Visit, ct);
            for (int round = 0; round < 3 && _wrappers.Count > 0; round++)
            {
                var names = _wrappers.Keys.Select(f => _names.GetValueOrDefault((Node)f)).OfType<string>().ToHashSet(StringComparer.Ordinal);
                int before = _wrappers.Count;
                foreach (var (call, scope) in _calls)
                {
                    var callee = JsProgram.Unwrap(call.Callee);
                    var name = callee switch { Identifier i => i.Name, MemberExpression { Property: Identifier pi, Computed: false } => pi.Name, _ => null };
                    if (name == null || !names.Contains(name) || p.Eval(callee, scope) is not JsFunction f || !_wrappers.TryGetValue(f.Node, out var w)) continue;
                    if (w.Index >= call.Arguments.Count) continue;
                    Ipc(call, scope, call.Arguments[w.Index], w.Kind, w.Role, $"{w.Call} via {name}");
                }
                if (_wrappers.Count == before) break;
            }
        }

        private void Visit(Node node, JsScope scope)
        {
            switch (node)
            {
                case VariableDeclarator { Id: Identifier id, Init: FunctionExpression or ArrowFunctionExpression } d: _names[d.Init!] = id.Name; break;
                case FunctionDeclaration { Id: { } fid } fd: _names[fd] = fid.Name; break;
                case Property { Value: FunctionExpression or ArrowFunctionExpression } pr when JsProgram.KeyName(pr.Key) is { } pk: _names[pr.Value] = pk; break;
                case MethodDefinition { Value: var mv } md when JsProgram.KeyName(md.Key) is { } mk: _names[mv] = mk; break;
                case AssignmentExpression { Left: MemberExpression { Property: Identifier ap, Computed: false }, Right: FunctionExpression or ArrowFunctionExpression } ae: _names[ae.Right] = ap.Name; break;
                case CallExpression c: Call(c, scope); break;
                case NewExpression n: New(n, scope); break;
            }
        }

        private void Call(CallExpression c, JsScope scope)
        {
            var callee = JsProgram.Unwrap(c.Callee);
            if (callee is Identifier or MemberExpression && c.Arguments.Count > 0) _calls.Add((c, scope));
            if (c.Arguments.Count >= 1 && JsProgram.Literal(c.Arguments[0]) is not null && callee is Identifier or MemberExpression { Property: Identifier { Name: "dlopen" } }
                && p.Eval(c, scope) is JsRef { Path: "" } required && required.Module.Length > 0)
            {
                if (IsAddon(required.Module)) Add("native-require", required.Module, c, "require", literal: true);
                else if (ChildProcess.Contains(required.Module)) Add("sink-child_process", required.Module, c, "require", literal: true);
                return;
            }
            var target = p.Eval(callee, scope) as JsRef;
            var chain = target != null ? target.Path : JsProgram.Chain(callee);
            if (chain == null) return;
            if (target != null && target.Path.Length > 0 && IsAddon(target.Module))
            {
                Add("native-call", target.Path, c, "call", literal: true).Link = target.Module;
                return;
            }
            if (target != null && ChildProcess.Contains(target.Module) && ProcessCalls.Contains(target.Path))
            {
                Add("sink-child_process", Argument(c, 0, scope), c, "child_process." + target.Path, literal: false);
                return;
            }
            if (target != null && Fs.Contains(target.Module) && FsWrites.Contains(target.Path.Split('.')[^1]))
            {
                Add("sink-fs", Argument(c, 0, scope), c, "fs." + target.Path, literal: false);
                return;
            }
            if (target is { Module: "" } && chain.Split('.') is [var root, _, ..] && !CommonGlobals.Contains(root) && scope.Lookup(root) == null)
                graph._globals.Add(new GlobalCall(chain, p.Site(c), p.Path, c.Start, [.. c.Arguments.Take(4).Select(a => JsProgram.Literal(a))]));
            var parts = chain.Split('.');
            if (parts.Length < 2) return;
            var (obj, method) = (parts[^2], parts[^1]);
            switch (obj, method)
            {
                case ("ipcMain", "handle" or "handleOnce" or "on" or "once" or "addListener"):
                    if (c.Arguments.Count > 0) Ipc(c, scope, c.Arguments[0], "ipc-main", "listen-main", "ipcMain." + method);
                    break;
                case ("ipcRenderer", "invoke" or "send" or "sendSync" or "postMessage" or "sendToHost"):
                    if (c.Arguments.Count > 0) Ipc(c, scope, c.Arguments[0], "ipc-renderer", "send-main", "ipcRenderer." + method);
                    break;
                case ("ipcRenderer", "on" or "once" or "addListener"):
                    if (c.Arguments.Count > 0) Ipc(c, scope, c.Arguments[0], "ipc-renderer", "listen-renderer", "ipcRenderer." + method);
                    break;
                case ("webContents" or "sender", "send" or "postMessage"):
                    if (c.Arguments.Count > 0) Ipc(c, scope, c.Arguments[0], "ipc-main", "send-renderer", obj + "." + method);
                    break;
                case ("contextBridge", "exposeInMainWorld" or "exposeInIsolatedWorld"):
                    Bridge(c, scope, method == "exposeInIsolatedWorld" ? 1 : 0);
                    break;
                case ("shell", "openExternal" or "openPath"):
                    Add("sink-shell", Argument(c, 0, scope), c, "shell." + method, literal: false);
                    break;
            }
        }

        private void New(NewExpression n, JsScope scope)
        {
            var target = p.Eval(n.Callee, scope) as JsRef;
            if (target != null && target.Path.Length > 0 && IsAddon(target.Module))
            {
                Add("native-call", target.Path, n, "new", literal: true).Link = target.Module;
                return;
            }
            var chain = target?.Path ?? JsProgram.Chain(n.Callee);
            var type = chain?.Split('.')[^1];
            if (type is not ("BrowserWindow" or "BrowserView" or "WebContentsView")) return;
            var options = n.Arguments.Count > 0 ? p.Eval(n.Arguments[0], scope) : null;
            var prefs = p.Get(options, "webPreferences");
            string? preload = null;
            if (prefs is JsObject po)
            {
                var preloadNode = po.Node.Properties.OfType<Property>().FirstOrDefault(x => JsProgram.KeyName(x.Key) == "preload");
                var value = p.Get(prefs, "preload");
                if (value is JsString s) preload = Relative(s.Text);
                else if (preloadNode != null) preload = Clip(p.Text[preloadNode.Value.Start..preloadNode.Value.End]);
                if (preload != null)
                {
                    Node site = preloadNode != null ? preloadNode : n;
                    graph._rows.Add(new Row("preload", preload, p.Site(site), p.Path, site.Start) { Call = "webPreferences.preload", Literal = value is JsString, Link = Found(preload) });
                }
            }
            Add("window", preload ?? "(no preload)", n, "new " + type, literal: preload != null).Link = preload != null ? "preload " + preload + Found(preload) switch { null => "", var f => " (" + f + ")" } : null;
        }

        private string? Found(string preload) => graph.Exists == null || preload.Contains('{') ? null : graph.Exists(preload) ? "in the app" : "not found in the app";

        /// <summary>A path built from __dirname, made relative to the app root through the script's folder.</summary>
        private string Relative(string text)
        {
            const string dirname = "{__dirname}";
            if (!text.StartsWith(dirname, StringComparison.Ordinal)) return text;
            var dir = System.IO.Path.GetDirectoryName(p.Path)?.Replace('\\', '/') ?? "";
            var segments = dir.Split('/', StringSplitOptions.RemoveEmptyEntries).ToList();
            foreach (var seg in text[dirname.Length..].Split('/', StringSplitOptions.RemoveEmptyEntries))
                if (seg == "..") { if (segments.Count > 0) segments.RemoveAt(segments.Count - 1); }
                else if (seg != ".") segments.Add(seg);
            return string.Join('/', segments);
        }

        private void Bridge(CallExpression c, JsScope scope, int keyIndex)
        {
            if (c.Arguments.Count <= keyIndex + 1) return;
            var key = p.Eval(c.Arguments[keyIndex], scope) is JsString { Exact: true } k ? k.Text : Clip(Text(c.Arguments[keyIndex]));
            Add("bridge-key", key, c, "contextBridge.exposeIn" + (keyIndex == 0 ? "MainWorld" : "IsolatedWorld"), literal: true);
            if (p.Eval(c.Arguments[keyIndex + 1], scope) is JsObject api) Members(api, key, 0);
        }

        private void Members(JsObject obj, string prefix, int depth)
        {
            foreach (var prop in obj.Node.Properties.OfType<Property>())
            {
                if (prop.Computed || JsProgram.KeyName(prop.Key) is not { } key) continue;
                var name = prefix + "." + key;
                var value = prop.Value is FunctionExpression or ArrowFunctionExpression ? new JsFunction((IFunction)prop.Value, obj.Scope) : p.Eval(prop.Value, obj.Scope);
                if (value is JsFunction f)
                {
                    var node = (Node)f.Node;
                    graph._bridge.Add(new BridgeMethod(name, p.Path, node.Start, node.End, p.Site(prop), null));
                    _bridgeFunctions[f.Node] = graph._bridge.Count - 1;
                }
                else if (value is JsObject inner && depth < 2) Members(inner, name, depth + 1);
            }
        }

        private readonly Dictionary<IFunction, int> _bridgeFunctions = [];

        /// <summary>An IPC row; a channel that is a parameter of the enclosing function makes that function a wrapper.</summary>
        private void Ipc(CallExpression c, JsScope scope, Node arg, string kind, string role, string call)
        {
            var channelNode = arg is SpreadElement spread ? spread.Argument : arg;
            var value = p.Eval(channelNode, scope);
            if (value is JsString s)
            {
                var row = Add(kind, s.Text, c, call, s.Exact);
                row.Role = role;
                return;
            }
            if (channelNode is Identifier id && scope.Lookup(id.Name) is { ParamOf: { } fn, ParamIndex: var index })
            {
                var w = new Wrapper(index, kind, role, call);
                if (_wrappers.TryAdd(fn, w) && _bridgeFunctions.TryGetValue(fn, out var b))
                    graph._bridge[b] = graph._bridge[b] with { Wrapper = w };
                // a bridge method defined before contextBridge is called: matched by range at the end
                graph._pendingWrappers.Add((p.Path, ((Node)fn).Start, ((Node)fn).End, w));
                return;
            }
            Add(kind, Clip(Text(channelNode)), c, call, literal: false).Role = role;
        }

        private string Argument(CallExpression c, int index, JsScope scope) =>
            index >= c.Arguments.Count ? "" : p.Eval(c.Arguments[index], scope) is JsString s ? s.Text : Clip(Text(c.Arguments[index]));

        private string Text(Node n) => n.Start >= 0 && n.End <= p.Text.Length && n.End >= n.Start ? p.Text[n.Start..n.End] : "";

        private Row Add(string kind, string value, Node at, string call, bool literal)
        {
            var row = new Row(kind, value, p.Site(at), p.Path, at.Start) { Call = call, Literal = literal };
            graph._rows.Add(row);
            return row;
        }

        private bool IsAddon(string module) =>
            module.EndsWith(".node", StringComparison.OrdinalIgnoreCase) || module.StartsWith("bindings:", StringComparison.Ordinal) || graph.AddonPackages.Contains(module);
    }

    private readonly List<(string File, int Start, int End, Wrapper Wrapper)> _pendingWrappers = [];

    private static string Clip(string s)
    {
        s = s.Trim();
        return s.Length > 120 ? s[..117] + "..." : s;
    }

    /// <summary>The rows with their links: IPC pairs, bridge methods with the channels they send, bridge calls of the pages.</summary>
    public List<ElectronRow> Finish()
    {
        // bridge methods that are wrappers, and the global calls of them (window.api.invoke("ch"))
        for (int i = 0; i < _bridge.Count; i++)
            if (_bridge[i].Wrapper == null && _pendingWrappers.FirstOrDefault(w => w.File == _bridge[i].File && w.Start == _bridge[i].Start && w.End == _bridge[i].End) is { Wrapper: { } w })
                _bridge[i] = _bridge[i] with { Wrapper = w };
        var byName = _bridge.GroupBy(b => b.Name).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
        foreach (var g in _globals)
        {
            var chain = g.Chain;
            foreach (var prefix in new[] { "window.", "globalThis.", "self." })
                if (chain.StartsWith(prefix, StringComparison.Ordinal)) chain = chain[prefix.Length..];
            if (!byName.TryGetValue(chain, out var method)) continue;
            _rows.Add(new Row("bridge-call", chain, g.Site, g.File, g.Start) { Call = g.Chain, Literal = true });
            // the bridge forwards the channel; a call already read as an IPC row (window.ipcRenderer.send) is not repeated
            if (method.Wrapper is { } w && w.Index < g.Args.Length && g.Args[w.Index] is { } channel
                && !_rows.Any(r => r.File == g.File && r.Start == g.Start && r.Role != null))
                _rows.Add(new Row(w.Kind, channel, g.Site, g.File, g.Start) { Call = $"{w.Call} via {g.Chain}", Role = w.Role, Literal = true });
        }

        // IPC pairs: renderer sends with main listeners, main sends with renderer listeners
        var ipc = _rows.Where(r => r.Role != null && r.Literal).ToList();
        var byChannel = ipc.GroupBy(r => r.Value, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.ToList(), StringComparer.Ordinal);
        foreach (var r in ipc)
        {
            var other = r.Role switch
            {
                "send-main" => "listen-main",
                "listen-main" => "send-main",
                "send-renderer" => "listen-renderer",
                _ => "send-renderer",
            };
            var peers = byChannel[r.Value].Where(x => x.Role == other).ToList();
            r.Link = peers.Count > 0
                ? "paired with " + string.Join(", ", peers.Take(3).Select(x => $"{x.Call} at {x.Site}")) + (peers.Count > 3 ? $" (+{peers.Count - 3})" : "")
                : r.Role switch
                {
                    "send-main" => "unpaired: no ipcMain listener for this channel in the app",
                    "listen-main" => "unpaired: no renderer sends this channel",
                    "send-renderer" => "unpaired: no ipcRenderer listener for this channel in the app",
                    _ => "unpaired: main sends no message on this channel",
                };
        }
        foreach (var r in _rows.Where(r => r.Role != null && !r.Literal)) r.Link ??= "computed channel: not paired";

        // bridge methods with the channels sent inside them
        foreach (var b in _bridge)
        {
            var inside = _rows.Where(r => r.File == b.File && r.Start >= b.Start && r.Start < b.End && r.Role != null).ToList();
            var link = b.Wrapper is { } w ? $"forwards argument {w.Index + 1} as the channel of {w.Call}"
                : inside.Count > 0 ? string.Join(", ", inside.Take(4).Select(r => $"{r.Call} {r.Value}")) : null;
            _rows.Add(new Row("bridge-method", b.Name, b.Site, b.File, b.Start) { Call = "contextBridge", Link = link });
        }
        foreach (var call in _rows.Where(r => r.Kind == "bridge-call").ToList())
            if (_rows.FirstOrDefault(r => r.Kind == "bridge-method" && r.Value == call.Value) is { Link: { } l }) call.Link = l;

        return _rows.OrderBy(r => r.File, StringComparer.Ordinal).ThenBy(r => r.Start)
            .Take(ElectronSurface.MaxRows)
            .Select(r => new ElectronRow(r.Kind, r.Value, r.Site) { Call = r.Call, Link = r.Link }).ToList();
    }

    /// <summary>Literal channels and how many have both a sender and a listener.</summary>
    public static (int Channels, int Paired) Pairing(IReadOnlyList<ElectronRow> rows)
    {
        var channels = rows.Where(r => r.Kind is "ipc-main" or "ipc-renderer" && r.Link != null && !r.Link.StartsWith("computed", StringComparison.Ordinal))
            .GroupBy(r => r.Value, StringComparer.Ordinal).ToList();
        return (channels.Count, channels.Count(g => g.Any(r => r.Link!.StartsWith("paired", StringComparison.Ordinal))));
    }

    /// <summary>Packages under <paramref name="root"/>/node_modules holding a .node file (scoped packages too), bounded.</summary>
    public static HashSet<string> Addons(string root)
    {
        var found = new HashSet<string>(StringComparer.Ordinal);
        var modules = System.IO.Path.Combine(root, "node_modules");
        if (!Directory.Exists(modules)) return found;
        var options = new EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 6, AttributesToSkip = FileAttributes.ReparsePoint, IgnoreInaccessible = true };
        int seen = 0;
        try
        {
            foreach (var f in Directory.EnumerateFiles(modules, "*.node", options))
            {
                if (++seen > 2000) break;
                var rel = System.IO.Path.GetRelativePath(modules, f).Replace('\\', '/').Split('/');
                var name = rel[0].StartsWith('@') && rel.Length > 2 ? rel[0] + "/" + rel[1] : rel[0];
                found.Add(name);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return found;
    }
}
