using dnlib.DotNet;
using Corvus.Core;
using Corvus.Core.Unity;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=unity: a Unity serialized file (.assets, levelN, sharedassetsN, globalgamemanagers) or a UnityFS asset bundle,
/// with its MonoBehaviour assets and their script fields as "field = value". Each asset names its layout source: the
/// file's own type tree, the script's assembly from the Managed folder beside the file, or the Il2Cpp metadata a load
/// of the game read. A layout is kept only when it reads exactly the object's size; a field that cannot be laid out is
/// unknown with its reason. script= keeps one script class; offset= and limit= page the assets.
/// </summary>
internal sealed class UnityFileView : IFileSummaryView
{
    private const long MaxFile = 1L << 30, MaxBundleBytes = 1L << 30;
    private const int DefaultLimit = 20, MaxLimit = 200, MaxFields = 60, MaxScan = 200_000, MaxAncestors = 6;

    /// <summary>A MonoBehaviour asset: where it is, its name and script class, the layout source and state, and its fields.</summary>
    public sealed record ScriptAsset(string File, long PathId, string? Name, string? Script, string? Assembly, string Layout, string State, IReadOnlyList<string> Fields)
    {
        public string? Reason { get; init; }
    }

    /// <summary>A serialized file read: its name, format, engine version, whether it keeps type trees and its object and MonoBehaviour counts.</summary>
    public sealed record FileFacts(string Name, int Format, string? UnityVersion, bool TypeTrees, int Objects, int MonoBehaviours);

    /// <summary>What view=unity read: the container, its serialized files, MonoBehaviour and matched counts, the page, layouts by source, the assets and notes.</summary>
    public sealed record Facts(string Container, IReadOnlyList<FileFacts> Files, int MonoBehaviours, int Matched, int Offset, int Limit, int? Next,
        IReadOnlyDictionary<string, int> Layouts, IReadOnlyList<ScriptAsset> Assets, IReadOnlyList<string> Notes);

    public string Name => "unity";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        bool bundle = UnityFsBundle.IsBundle(file.Head);
        if (!bundle && !SerializedFile.IsSerializedFile(file.Head, file.Length)) return null;
        var notes = new List<string>();
        string kind = bundle ? "bundle" : "serialized file";
        // The overview reads no bundle blocks and no streamed file whole; view=unity does.
        if (!file.Options.Wants(Name) && (bundle || file.Streamed))
        {
            var version = bundle ? UnityFsBundle.VersionOf(file.Head) : SerializedFile.VersionOf(file.Head);
            return new FileView(new Facts(kind, [], 0, 0, 0, 0, null, new Dictionary<string, int>(), [], []),
                [$"Unity {kind} ({version ?? "unknown engine version"}); view=unity lists its MonoBehaviour assets and their script fields."]);
        }
        if (file.Length > MaxFile)
            return new FileView(new Facts(kind, [], 0, 0, 0, 0, null, new Dictionary<string, int>(), [],
                [$"the file is {file.Length:N0} bytes, over the {MaxFile:N0} byte limit of this view"]), []);
        var files = new List<SerializedFile>();
        if (bundle)
        {
            var b = UnityFsBundle.Read(file.Bytes, MaxBundleBytes);
            notes.AddRange(b.Issues);
            foreach (var e in b.Entries)
                if (SerializedFile.IsSerializedFile(e.Bytes, e.Bytes.Length)) files.Add(SerializedFile.Read(e.Bytes, e.Path));
        }
        else files.Add(SerializedFile.Read(file.Bytes, Path.GetFileName(file.Path)));
        foreach (var f in files) notes.AddRange(f.Issues.Select(i => $"{f.Name}: {i}"));
        var monos = files.SelectMany(f => f.Objects.Where(o => o.ClassId == SerializedFile.ClassMonoBehaviour).Select(o => (File: f, Object: o))).ToList();
        var fileFacts = files.Select(f => new FileFacts(f.Name, f.Format, f.UnityVersion, f.HasTypeTrees, f.Objects.Count,
            f.Objects.Count(o => o.ClassId == SerializedFile.ClassMonoBehaviour))).ToList();
        var highlights = new List<string>();
        var first = files.FirstOrDefault();
        highlights.Add($"Unity {kind}{(first != null ? $" (format {first.Format}, {first.UnityVersion ?? "unknown engine version"})" : "")}: " +
                       $"{files.Sum(f => f.Objects.Count):N0} objects, {monos.Count:N0} MonoBehaviour assets{(files.Count > 1 ? $" in {files.Count} files" : "")}" +
                       (first is { HasTypeTrees: false } ? "; no type trees, so script fields are laid out from the scripts' assemblies" : "") + ".");
        if (!file.Options.Wants(Name))
            return new FileView(new Facts(kind, fileFacts, monos.Count, 0, 0, 0, null, new Dictionary<string, int>(), [], notes), highlights);

        using var context = new Context(file.Path, files);
        var options = file.Options;
        if (monos.Count > MaxScan) notes.Add($"MonoBehaviours: the first {MaxScan:N0} of {monos.Count:N0} are read");
        var matched = new List<(SerializedFile File, UnityObject Object, Base Base)>();
        foreach (var (f, o) in monos.Take(MaxScan))
        {
            ct.ThrowIfCancellationRequested();
            var b = context.ReadBase(f, o);
            if (options.Script == null || b.Script is { } s && (s.ClassName.Equals(options.Script, StringComparison.OrdinalIgnoreCase)
                                                                  || s.FullName.Equals(options.Script, StringComparison.OrdinalIgnoreCase)))
                matched.Add((f, o, b));
        }
        if (options.Script != null && matched.Count == 0)
        {
            var classes = monos.Take(MaxScan).Select(m => context.ReadBase(m.File, m.Object).Script?.FullName).OfType<string>().Distinct().Order(StringComparer.Ordinal).Take(30).ToList();
            throw new ToolError(ErrorCode.NotFound, $"no MonoBehaviour in {Path.GetFileName(file.Path)} uses script '{options.Script}'.",
                classes.Count > 0 ? $"pass script as one of {string.Join(", ", classes)}" : "drop script= to list the assets");
        }
        int offset = (int)Math.Clamp(options.Offset, 0, matched.Count);
        int limit = Math.Clamp(options.Limit ?? DefaultLimit, 1, MaxLimit);
        var assets = new List<ScriptAsset>();
        foreach (var (f, o, b) in matched.Skip(offset).Take(limit))
        {
            ct.ThrowIfCancellationRequested();
            assets.Add(context.Fields(f, o, b));
        }
        notes.AddRange(context.Notes);
        var layouts = assets.GroupBy(a => a.Layout).OrderBy(g => g.Key, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.Count());
        int? next = offset + assets.Count < matched.Count ? offset + assets.Count : null;
        if (assets.Count > 0)
            highlights.Add($"Script fields of assets {offset + 1}-{offset + assets.Count} of {matched.Count:N0}: " +
                           string.Join(", ", new[] { "read", "partial", "unknown" }.Select(s => (s, n: assets.Count(a => a.State == s))).Where(x => x.n > 0).Select(x => $"{x.n} {x.s}")) +
                           $" (layout from {string.Join(", ", layouts.Select(l => $"{l.Key} {l.Value}"))}).");
        return new FileView(new Facts(kind, fileFacts, monos.Count, matched.Count, offset, limit, next, layouts, assets, notes), highlights);
    }

    /// <summary>
    /// Each MonoBehaviour of a serialized file that keeps type trees, read through its type tree and laid out from its
    /// script's assembly, to compare the two; <paramref name="path"/> places the file for the assembly lookup.
    /// </summary>
    internal static IEnumerable<(ScriptAsset Tree, ScriptAsset Laid)> BothLayouts(string path, byte[] bytes)
    {
        var files = new List<SerializedFile>();
        if (UnityFsBundle.IsBundle(bytes))
            files.AddRange(UnityFsBundle.Read(bytes, MaxBundleBytes).Entries.Where(e => SerializedFile.IsSerializedFile(e.Bytes, e.Bytes.Length)).Select(e => SerializedFile.Read(e.Bytes, e.Path)));
        else if (SerializedFile.IsSerializedFile(bytes, bytes.Length)) files.Add(SerializedFile.Read(bytes, Path.GetFileName(path)));
        using var context = new Context(path, files);
        foreach (var f in files.Where(f => f.HasTypeTrees))
            foreach (var o in f.Objects.Where(o => o.ClassId == SerializedFile.ClassMonoBehaviour && o.Type?.Tree is { Count: > 1 }))
            {
                var b = context.ReadBase(f, o);
                yield return (context.Fields(f, o, b), context.Fields(f, o, b, useTree: false));
            }
    }

    /// <summary>The base fields of a MonoBehaviour: its name, script pointer and the class the script names (null when not found, with the reason).</summary>
    private sealed record Base(string? Name, UnityPointer? Pointer, UnityScriptClass? Script, string? Problem);

    /// <summary>
    /// The files a view reads beside the one asked for: serialized files a script pointer names (other entries of the
    /// bundle, or files in the same folder), and the Managed or Il2Cpp dummy assemblies of the game.
    /// </summary>
    private sealed class Context(string path, IReadOnlyList<SerializedFile> files) : IDisposable
    {
        public readonly List<string> Notes = [];
        private readonly string _directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
        private readonly Dictionary<string, SerializedFile?> _others = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<(SerializedFile, long), Base> _bases = [];
        private readonly Dictionary<(SerializedFile, UnityPointer), (UnityScriptClass?, string?)> _scripts = [];
        private readonly Dictionary<string, (TypeDef?, string Source, string? Problem)> _types = new(StringComparer.Ordinal);
        private readonly Dictionary<string, ModuleDefMD?> _modules = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<UnityType, int> _basePrefix = [];
        private (string? Managed, string? Dummies)? _assemblies;
        private ModuleContext? _moduleContext;

        public Base ReadBase(SerializedFile f, UnityObject o)
        {
            if (_bases.TryGetValue((f, o.PathId), out var known)) return known;
            Base result;
            if (f.Data(o) is not { } r) result = new Base(null, null, null, "the object's data is outside the file");
            else
            {
                try
                {
                    var tree = o.Type?.Tree is { Count: > 1 } t ? t.Take(Prefix(o.Type, t)).ToList() : UnityMonoBehaviour.BaseTree(f.Format);
                    var values = UnityTreeReader.Read(tree, r).ToDictionary(v => v.Name, v => v.Value);
                    var name = UnityMonoBehaviour.ParseString(values.GetValueOrDefault("m_Name"));
                    var pointer = UnityMonoBehaviour.ParsePointer(values.GetValueOrDefault("m_Script"));
                    var (script, problem) = pointer is { } p ? Script(f, p) : (null, "the object has no script pointer");
                    result = new Base(name, pointer, script, problem);
                }
                catch (InvalidDataException e)
                {
                    result = new Base(null, null, null, e.Message);
                }
            }
            return _bases[(f, o.PathId)] = result;
        }

        /// <summary>The number of type tree nodes up to the end of the m_Name field, or the whole tree when it has none.</summary>
        private int Prefix(UnityType type, IReadOnlyList<UnityTypeNode> tree)
        {
            if (_basePrefix.TryGetValue(type, out int n)) return n;
            n = tree.Count;
            for (int i = 1; i < tree.Count; i++)
                if (tree[i].Level == 1 && tree[i].Name == "m_Name")
                {
                    int j = i + 1;
                    while (j < tree.Count && tree[j].Level > 1) j++;
                    n = j;
                    break;
                }
            return _basePrefix[type] = n;
        }

        private (UnityScriptClass?, string?) Script(SerializedFile f, UnityPointer p)
        {
            if (_scripts.TryGetValue((f, p), out var known)) return known;
            (UnityScriptClass?, string?) result;
            if (p.IsNull) result = (null, "the script pointer is null");
            else if (Target(f, p.FileId) is not var (target, problem)) result = (null, "the script pointer names no file");
            else if (target == null) result = (null, problem);
            else if (target.Find(p.PathId) is not { ClassId: SerializedFile.ClassMonoScript } script)
                result = (null, $"{target.Name} has no MonoScript with path id {p.PathId}");
            else result = UnityMonoBehaviour.ScriptClass(target, script) is { } c ? (c, null) : (null, $"the MonoScript {p.PathId} in {target.Name} does not read");
            return _scripts[(f, p)] = result;
        }

        /// <summary>The file a file id names: 0 is the file itself, n the n-th external, found in the bundle or beside the file.</summary>
        private (SerializedFile?, string?)? Target(SerializedFile f, int fileId)
        {
            if (fileId == 0) return (f, null);
            if (fileId < 0 || fileId > f.Externals.Count) return null;
            var name = Path.GetFileName(f.Externals[fileId - 1].Path.Replace('\\', '/'));
            if (files.FirstOrDefault(x => Path.GetFileName(x.Name.Replace('\\', '/')).Equals(name, StringComparison.OrdinalIgnoreCase)) is { } inBundle) return (inBundle, null);
            if (!_others.TryGetValue(name, out var other))
            {
                var full = Path.Combine(_directory, name);
                other = null;
                try
                {
                    if (name.Length > 0 && File.Exists(full) && new FileInfo(full).Length <= MaxFile)
                    {
                        var bytes = File.ReadAllBytes(full);
                        if (SerializedFile.IsSerializedFile(bytes, bytes.Length)) other = SerializedFile.Read(bytes, name);
                    }
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
                _others[name] = other;
            }
            return (other, other == null ? $"the MonoScript is in {f.Externals[fileId - 1].Path}, which was not found beside the file" : null);
        }

        public ScriptAsset Fields(SerializedFile f, UnityObject o, Base b, bool useTree = true)
        {
            var asset = new ScriptAsset(f.Name, o.PathId, b.Name, b.Script?.FullName, b.Script?.Assembly, "none", "unknown", []);
            if (f.Data(o) is not { } r) return asset with { Reason = "the object's data is outside the file" };
            if (useTree && o.Type?.Tree is { Count: > 1 } tree) return FromTree(asset with { Layout = "type tree" }, tree, r);
            if (b.Script is not { } script) return asset with { Reason = b.Problem ?? "the script class is not known" };
            var (type, source, problem) = Type(script);
            if (type == null) return asset with { Reason = problem };
            var layout = UnityScriptLayout.Build(type, f.Format, attributesKept: source == "assembly", f.UnityVersion);
            return FromLayout(asset with { Layout = source }, layout, r);
        }

        /// <summary>The fields through the file's own type tree; a field the data does not fit ends them, with the fields before it kept.</summary>
        private static ScriptAsset FromTree(ScriptAsset asset, IReadOnlyList<UnityTypeNode> tree, UnityBinary r)
        {
            var (values, field, failure) = UnityTreeReader.ReadUntilFailure(tree, r);
            int size = r.End - r.Start, read = r.Position - r.Start;
            if (field == null && read != size)
                return asset with { Reason = $"the type tree reads {read:N0} of the object's {size:N0} bytes, so its values are not shown" };
            var lines = Lines(values, field);
            return field == null
                ? asset with { State = "read", Fields = lines }
                : asset with { State = "partial", Fields = lines, Reason = $"the type tree does not read field {field} ({failure}); the fields before it are read without the size check" };
        }

        /// <summary>The fields through a layout built from an assembly, kept only when it reads exactly the object's size or ends at an unknown field.</summary>
        private static ScriptAsset FromLayout(ScriptAsset asset, UnityScriptLayout.Layout layout, UnityBinary r)
        {
            List<UnityFieldValue> values;
            try
            {
                values = UnityTreeReader.Read(layout.Tree, r);
            }
            catch (InvalidDataException e)
            {
                return asset with { Reason = $"the layout does not read the object's data: {e.Message}" };
            }
            int size = r.End - r.Start, read = r.Position - r.Start;
            if (layout.Unknown == null && read != size)
                return asset with { Reason = $"the layout reads {read:N0} of the object's {size:N0} bytes, so its values are not shown" };
            var lines = Lines(values, layout.UnknownField);
            return layout.Unknown == null
                ? asset with { State = "read", Fields = lines }
                : asset with { State = "partial", Fields = lines, Reason = $"the fields before {layout.Unknown}; they are read without the size check" };
        }

        private static List<string> Lines(List<UnityFieldValue> values, string? unknown)
        {
            var lines = values.Where(v => !UnityMonoBehaviour.BaseFields.Contains(v.Name)).Select(v => $"{v.Name} = {v.Value}").ToList();
            if (unknown != null) lines.Add($"{unknown} = unknown");
            return lines.Count > MaxFields ? [.. lines.Take(MaxFields), $"... {lines.Count - MaxFields} more fields"] : lines;
        }

        /// <summary>The script's class from the Managed folder beside the file, else from a cached Il2Cpp load of the game.</summary>
        private (TypeDef?, string Source, string? Problem) Type(UnityScriptClass script)
        {
            var key = $"{script.Assembly}|{script.FullName}";
            if (_types.TryGetValue(key, out var known)) return known;
            var (managed, dummies) = _assemblies ??= Assemblies();
            var assembly = script.Assembly.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? script.Assembly : script.Assembly + ".dll";
            (TypeDef?, string, string?) result = (null, "none",
                $"no assembly for {script.FullName}: {assembly} is not in a Managed folder beside the file, and no Il2Cpp metadata of the game was read (load_assembly the game folder reads it)");
            foreach (var (dir, source) in new[] { (managed, "assembly"), (dummies, "metadata") })
            {
                if (dir == null || Module(Path.Combine(dir, assembly)) is not { } module) continue;
                // UnityEngine.dll forwards most engine classes to the UnityEngine.*Module assemblies.
                var type = module.Find(script.FullName, isReflectionName: false)
                           ?? module.ExportedTypes.FirstOrDefault(e => e.FullName == script.FullName)?.Resolve()
                           ?? module.GetTypes().FirstOrDefault(t => t.Name == script.ClassName && (t.DeclaringType ?? t).Namespace == script.Namespace);
                result = type != null ? (type, source, null) : (null, source, $"{assembly} in the {(source == "assembly" ? "Managed folder" : "Il2Cpp metadata")} has no class {script.FullName}");
                if (type != null) break;
            }
            return _types[key] = result;
        }

        private ModuleDefMD? Module(string file)
        {
            if (_modules.TryGetValue(file, out var known)) return known;
            ModuleDefMD? module = null;
            try
            {
                if (File.Exists(file))
                {
                    if (_moduleContext == null)
                    {
                        _moduleContext = ModuleDef.CreateModuleContext();
                        var resolver = (AssemblyResolver)_moduleContext.AssemblyResolver;
                        resolver.UseGAC = false;
                        resolver.EnableTypeDefCache = true;
                        resolver.FindExactMatch = false;
                        foreach (var dir in new[] { _assemblies?.Managed, _assemblies?.Dummies }.OfType<string>()) resolver.PreSearchPaths.Add(dir);
                    }
                    module = ModuleDefMD.Load(File.ReadAllBytes(file), _moduleContext);
                    ((AssemblyResolver)_moduleContext.AssemblyResolver).AddToCache(module);
                }
            }
            catch (Exception e) when (e is BadImageFormatException or IOException or UnauthorizedAccessException)
            {
                Notes.Add($"{Path.GetFileName(file)} does not read as a .NET assembly ({e.Message})");
            }
            return _modules[file] = module;
        }

        /// <summary>The Managed folder in or above the file's folder, and the cached Il2Cpp dummy assemblies of the game there.</summary>
        private (string?, string?) Assemblies()
        {
            string? managed = null, dummies = null;
            var dir = _directory;
            for (int i = 0; dir != null && i < MaxAncestors && (managed == null || dummies == null); i++, dir = Path.GetDirectoryName(dir))
            {
                if (managed == null && Directory.Exists(Path.Combine(dir, "Managed")) && Directory.EnumerateFiles(Path.Combine(dir, "Managed"), "*.dll").Any())
                    managed = Path.Combine(dir, "Managed");
                if (dummies == null)
                {
                    try
                    {
                        if (Il2CppGameFiles.Find(dir) is { } game) dummies = Il2CppRawLoader.CachedDummies(game);
                    }
                    catch (ToolError) { }
                }
            }
            return (managed, dummies);
        }

        public void Dispose()
        {
            if (_moduleContext?.AssemblyResolver is AssemblyResolver resolver)
                foreach (var a in resolver.GetCachedAssemblies())
                    foreach (var m in a.Modules) (m as IDisposable)?.Dispose();
            foreach (var m in _modules.Values) m?.Dispose();
        }
    }
}
