using System.IO.Compression;
using Corvus.Core;
using Corvus.Core.Mobile;

namespace Corvus.Services.Mobile;

/// <summary>What a code reference does with its target.</summary>
public enum DexRefKind : byte { Call, Read, Write, String, Type }

/// <summary>A reference from one instruction: target and source method are keys of <see cref="DexIndex.Key"/>; offset in code units.</summary>
public readonly record struct DexRef(int Target, int From, int Offset, DexRefKind Kind, byte Opcode);

/// <summary>A numeric constant loaded by a const instruction.</summary>
public readonly record struct DexConst(long Value, int From, int Offset, byte Opcode);

/// <summary>A class defined in one of the package's DEX files.</summary>
public sealed record DexClassEntry(DexFile File, DexClass Class);

/// <summary>A method defined in the package, with its exact descriptor.</summary>
public sealed record DexMethodEntry(DexFile File, DexClass Class, DexEncodedMethod Encoded, DexMethodRef Ref)
{
    public string Descriptor => Ref.Descriptor;
}

/// <summary>
/// Every class of a package's DEX files (classes.dex, classes2.dex, ... in loading order: a class defined twice keeps the first),
/// with a code index built on first use: calls, field reads and writes, strings, types and constants per instruction.
/// Targets are exact descriptors, so overloads never merge.
/// </summary>
public sealed class DexIndex
{
    public string Path { get; }
    public IReadOnlyList<DexFile> Files { get; }
    public IReadOnlyDictionary<string, DexClassEntry> Classes => _classes;
    public IReadOnlyList<string> Notes => _notes;

    private readonly Dictionary<string, DexClassEntry> _classes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DexMethodEntry> _methods = new(StringComparer.Ordinal);
    private readonly List<string> _notes = [];
    private Task<(List<DexRef> Refs, List<DexConst> Consts)>? _code;
    private readonly object _codeLock = new();
    private readonly List<string> _keys = [];
    private readonly Dictionary<string, int> _keyIds = new(StringComparer.Ordinal);
    private readonly object _keyLock = new();

    private DexIndex(string path, List<DexFile> files)
    {
        Path = path;
        Files = files;
        foreach (var f in files)
        {
            foreach (var c in f.Classes)
                if (!_classes.TryAdd(c.Descriptor, new DexClassEntry(f, c)))
                    _notes.Add($"{c.Descriptor} is defined again in {f.Name}; the first definition ({_classes[c.Descriptor].File.Name}) is used.");
            foreach (var i in f.Issues) _notes.Add($"{f.Name}: {i.Message}.");
        }
        foreach (var (_, e) in _classes)
            foreach (var m in e.File.ClassData(e.Class).Methods)
            {
                var r = e.File.Method(m.MethodIndex);
                _methods.TryAdd(r.Descriptor, new DexMethodEntry(e.File, e.Class, m, r));
            }
        if (_notes.Count > 50) _notes.RemoveRange(50, _notes.Count - 50);
    }

    public IReadOnlyDictionary<string, DexMethodEntry> Methods => _methods;

    /// <summary>The id of a descriptor or string in the reference lists.</summary>
    public int Key(string s)
    {
        lock (_keyLock)
        {
            if (_keyIds.TryGetValue(s, out var id)) return id;
            _keyIds[s] = id = _keys.Count;
            _keys.Add(s);
            return id;
        }
    }

    public int? FindKey(string s) { lock (_keyLock) return _keyIds.TryGetValue(s, out var id) ? id : null; }

    public string KeyText(int id) { lock (_keyLock) return _keys[id]; }

    public IReadOnlyList<DexRef> Refs => Code(default).Refs;
    public IReadOnlyList<DexConst> Consts => Code(default).Consts;

    /// <summary>Builds the code index once (in the background) and waits for it; a cancelled wait leaves the build to the next caller.</summary>
    public void EnsureCode(CancellationToken ct) => Code(ct);

    private (List<DexRef> Refs, List<DexConst> Consts) Code(CancellationToken ct)
    {
        Task<(List<DexRef>, List<DexConst>)> task;
        lock (_codeLock) task = _code ??= Task.Run(BuildCode, CancellationToken.None);
        return task.IsCompletedSuccessfully ? task.Result : task.WaitAsync(ct).GetAwaiter().GetResult();
    }

    /// <summary>Opens the DEX files of an Android package, a .dex file, or a jar / zip holding classes*.dex.</summary>
    public static DexIndex Load(string path, AnalysisLimits limits, CancellationToken ct)
    {
        var full = InputFiles.RequireRegularFile(path, "Android package or DEX file");
        if (!File.Exists(full)) throw Targets.FileNotFound(full);
        var head = new byte[8];
        using (var s = File.OpenRead(full)) _ = s.ReadAtLeast(head, 8, throwOnEndOfStream: false);
        var files = new List<DexFile>();
        if (DexFile.IsDex([.. head, .. new byte[DexFile.HeaderSize]]))
        {
            if (new FileInfo(full).Length > limits.MaxItemBytes) throw new ToolError(ErrorCode.LimitExceeded, $"{full} is larger than {limits.MaxItemBytes} bytes.");
            files.Add(DexFile.Read(File.ReadAllBytes(full), System.IO.Path.GetFileName(full)));
            return new DexIndex(full, files);
        }
        if (!Blob.StartsWith(head, "PK\x03\x04"u8)) throw new ToolError(ErrorCode.MalformedInput, $"{full} is neither a DEX file nor a zip (APK, AAB, JAR).");
        IReadOnlyList<string> names;
        Func<string, byte[]?> read;
        AndroidPackage? package = null;
        ZipArchive? zip = null;
        try
        {
            try
            {
                package = AndroidPackage.Open(full, limits);
                names = package.DexFiles;
                read = package.Read;
            }
            catch (ToolError e) when (e.Code == ErrorCode.Unsupported)
            {
                zip = ZipFile.OpenRead(full); // closes the file when the archive is unreadable
                var entries = zip.Entries.Where(x => !x.FullName.Contains('/') && x.FullName.StartsWith("classes", StringComparison.Ordinal) && x.FullName.EndsWith(".dex", StringComparison.Ordinal))
                    .ToDictionary(x => x.FullName, StringComparer.Ordinal);
                names = [.. entries.Keys.OrderBy(n => n.Length).ThenBy(n => n, StringComparer.Ordinal)];
                read = n => { using var s = entries[n].Open(); return Blob.ReadBounded(s, limits.MaxItemBytes); };
            }
            if (names.Count == 0)
            {
                bool classFiles = zip?.Entries.Any(e => e.FullName.EndsWith(".class", StringComparison.Ordinal)) == true;
                throw new ToolError(ErrorCode.NotFound, $"{full} has no classes*.dex.", classFiles
                    ? $"a jar of Java .class files: decompile_java path={full} reads its classes by name"
                    : "a package with native code only, or a bundle split without code");
            }
            foreach (var n in names)
            {
                ct.ThrowIfCancellationRequested();
                var bytes = read(n) ?? throw new ToolError(ErrorCode.LimitExceeded, $"{n} is larger than {limits.MaxItemBytes} bytes.");
                files.Add(DexFile.Read(bytes, n));
            }
        }
        finally
        {
            package?.Dispose();
            zip?.Dispose();
        }
        return new DexIndex(full, files);
    }

    private (List<DexRef>, List<DexConst>) BuildCode()
    {
        var refs = new List<DexRef>();
        var consts = new List<DexConst>();
        foreach (var m in _methods.Values)
        {
            if (m.Encoded.CodeOffset == 0 || m.File.Code(m.Encoded.CodeOffset) is not { } code) continue;
            int from = Key(m.Descriptor);
            foreach (var i in Dalvik.Decode(code.Instructions))
            {
                var op = (byte)i.Opcode;
                switch (i.Ref)
                {
                    case DalvikRef.Method:
                        refs.Add(new(Key(m.File.Method(i.Index).Descriptor), from, i.Offset, DexRefKind.Call, op));
                        break;
                    case DalvikRef.Field:
                        refs.Add(new(Key(m.File.Field(i.Index).Descriptor), from, i.Offset, i.IsFieldWrite ? DexRefKind.Write : DexRefKind.Read, op));
                        break;
                    case DalvikRef.String:
                        refs.Add(new(Key(m.File.String(i.Index)), from, i.Offset, DexRefKind.String, op));
                        break;
                    case DalvikRef.Type:
                        refs.Add(new(Key(m.File.Type(i.Index)), from, i.Offset, DexRefKind.Type, op));
                        break;
                }
                if (op is >= 0x12 and <= 0x19) consts.Add(new(i.Literal, from, i.Offset, op));
            }
        }
        return (refs, consts);
    }

    /// <summary>"Lcom/a/B;", "com.a.B", "com/a/B", or "com.a.B.Inner" for com.a.B$Inner; null when not defined.</summary>
    public DexClassEntry? FindClass(string name) => ToDescriptor(name).Select(d => _classes.GetValueOrDefault(d)).FirstOrDefault(c => c != null);

    /// <summary>The descriptors a class name may mean, most likely first (dots after the package may be inner-class separators).</summary>
    public static IEnumerable<string> ToDescriptor(string name)
    {
        name = name.Trim();
        if (name.StartsWith('L') && name.EndsWith(';')) { yield return name; yield break; }
        var slashed = name.Replace('.', '/');
        yield return "L" + slashed + ";";
        for (int i = slashed.LastIndexOf('/'); i > 0; i = slashed.LastIndexOf('/', i - 1))
        {
            slashed = slashed[..i] + "$" + slashed[(i + 1)..];
            yield return "L" + slashed + ";";
        }
    }

    public ToolError ClassNotFound(string name)
    {
        var simple = name.Trim().TrimEnd(';').Split('/', '.', '$').Last();
        var similar = _classes.Keys.Where(k => k.TrimEnd(';').Split('/', '$').Last().Equals(simple, StringComparison.OrdinalIgnoreCase)).Take(10).ToList();
        return new ToolError(ErrorCode.NotFound, $"no class {name} in {Path}" + (similar.Count > 0 ? $"; same simple name: {string.Join(", ", similar)}" : "."),
            "list_dex_classes with query finds classes by name")
        { Details = new { similar } };
    }

    /// <summary>
    /// The method descriptors a spec names: an exact descriptor (Lpkg/C;->m(I)V), or Class::m / Class.m / Class->m, optionally with
    /// Java or descriptor parameters ("(int, String)" or "(ILjava/lang/String;)"). Methods only referenced (framework calls) count too.
    /// </summary>
    public List<string> FindMethods(string spec, CancellationToken ct = default)
    {
        spec = spec.Trim();
        var arrow = spec.IndexOf("->", StringComparison.Ordinal);
        if (arrow > 0 && spec.Contains('(', StringComparison.Ordinal) && spec.StartsWith('L')) return [spec];
        string owner, name, parameters = "";
        int open = spec.IndexOf('(', StringComparison.Ordinal);
        var head = open >= 0 ? spec[..open] : spec;
        if (open >= 0) parameters = spec[open..];
        int sep = arrow > 0 ? arrow : head.IndexOf("::", StringComparison.Ordinal) is var c and > 0 ? c : head.LastIndexOf('.');
        if (sep <= 0) throw new ToolError(ErrorCode.InvalidArgument, $"'{spec}' does not name a method; use Lpkg/Class;->name(descriptor) or pkg.Class::name.");
        owner = head[..sep];
        name = head[(sep + (head[sep] == '.' ? 1 : 2))..];
        var owners = ToDescriptor(owner).ToList();
        var candidates = _methods.Keys.Where(d => owners.Any(o => d.StartsWith(o + "->" + name + "(", StringComparison.Ordinal))).ToList();
        if (candidates.Count == 0)
        {
            EnsureCode(ct); // referenced-only methods are keys of the code index
            foreach (var o in owners)
            {
                var prefix = o + "->" + name + "(";
                lock (_keyLock) candidates = [.. _keys.Where(k => k.StartsWith(prefix, StringComparison.Ordinal))];
                if (candidates.Count > 0) break;
            }
        }
        if (parameters.Length > 0) candidates = [.. candidates.Where(d => ParametersMatch(d, parameters))];
        return [.. candidates.Distinct().Order(StringComparer.Ordinal)];
    }

    private static bool ParametersMatch(string descriptor, string parameters)
    {
        var inner = parameters.Trim().TrimStart('(');
        var close = inner.IndexOf(')');
        if (close >= 0) inner = inner[..close];
        var actual = descriptor[(descriptor.IndexOf('(') + 1)..descriptor.LastIndexOf(')')];
        if (!inner.Contains(',') && !inner.Contains(' ') && (inner.Length == 0 || inner.Contains(';') || inner.All(ch => "ZBSCIJFD[".Contains(ch))))
            return actual == inner;
        var wanted = inner.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        var types = SplitParameters(actual).Select(DexFile.JavaName).ToList();
        return wanted.Length == types.Count && wanted.Zip(types).All(p => p.Second == p.First || p.Second.EndsWith("." + p.First, StringComparison.Ordinal));
    }

    /// <summary>The parameter descriptors of a method descriptor's parameter list.</summary>
    public static List<string> SplitParameters(string list)
    {
        var result = new List<string>();
        for (int i = 0; i < list.Length;)
        {
            int start = i;
            while (i < list.Length && list[i] == '[') i++;
            if (i < list.Length && list[i] == 'L') i = list.IndexOf(';', i) is var e and >= 0 ? e + 1 : list.Length;
            else i++;
            result.Add(list[start..Math.Min(i, list.Length)]);
        }
        return result;
    }

    /// <summary>One method: exact, or a single overload; several overloads are an ambiguous error listing their descriptors.</summary>
    public string ResolveMethod(string spec, CancellationToken ct = default)
    {
        var found = FindMethods(spec, ct);
        return found.Count switch
        {
            1 => found[0],
            0 => throw new ToolError(ErrorCode.NotFound, $"no method {spec} in {Path}.", "get_dex_class lists a class's methods with their descriptors"),
            _ => throw new ToolError(ErrorCode.Ambiguous, $"{spec} has {found.Count} overloads: {string.Join(", ", found.Take(20))}.",
                "pass the exact descriptor, or the parameters: Class::name(int, String)") { Details = new { candidates = found.Take(50).ToList() } },
        };
    }

    /// <summary>Field descriptors a spec names: Lpkg/C;->f:I exactly, or Class::f / Class.f / Class->f.</summary>
    public List<string> FindFields(string spec, CancellationToken ct = default)
    {
        spec = spec.Trim();
        if (spec.StartsWith('L') && spec.Contains("->", StringComparison.Ordinal) && spec.Contains(':', StringComparison.Ordinal)) return [spec];
        int arrow = spec.IndexOf("->", StringComparison.Ordinal);
        int sep = arrow > 0 ? arrow : spec.IndexOf("::", StringComparison.Ordinal) is var c and > 0 ? c : spec.LastIndexOf('.');
        if (sep <= 0) return [];
        var name = spec[(sep + (spec[sep] == '.' ? 1 : 2))..];
        var result = new List<string>();
        EnsureCode(ct);
        foreach (var owner in ToDescriptor(spec[..sep]))
        {
            if (_classes.TryGetValue(owner, out var e))
                result.AddRange(e.File.ClassData(e.Class).Fields.Select(f => e.File.Field(f.FieldIndex)).Where(f => f.Name == name).Select(f => f.Descriptor));
            if (result.Count == 0) lock (_keyLock) result.AddRange(_keys.Where(k => k.StartsWith(owner + "->" + name + ":", StringComparison.Ordinal)));
            if (result.Count > 0) break;
        }
        return result;
    }
}
