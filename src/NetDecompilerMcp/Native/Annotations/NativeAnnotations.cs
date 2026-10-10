using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Providers;

namespace NetDecompilerMcp.Native.Annotations;

/// <summary>
/// The user's names and comments for one image, keyed by RVA. The authoritative in-memory copy for a session: it is
/// loaded from the sidecar when the image loads (by the image's load-time SHA-256, which stays the annotation key even
/// after in-memory patches) and written back atomically on every change. The code index mirrors it so names show up
/// in disassembly, list_functions and cross-references.
/// </summary>
public sealed class NativeAnnotations
{
    private readonly AnnotationStore _store;
    private readonly object _gate = new();
    private readonly Dictionary<uint, string> _names = new();
    private readonly Dictionary<uint, string> _comments = new();

    /// <summary>The SHA-256 the sidecar is keyed by (the file's hash when first loaded).</summary>
    public string Sha256 { get; }
    public string FilePath { get; }
    public ulong ImageBase { get; }

    /// <summary>Hashes of sidecars for the same path but a different file version, if any (set once at load).</summary>
    public IReadOnlyList<string> StaleSiblingHashes { get; }

    /// <summary>Set when the sidecar is left in place and must not be overwritten: changes stay in memory.</summary>
    public string? WriteBlocked { get; }

    private readonly Action<string>? _notify;
    private string? _lastSaveProblem;

    /// <param name="notify">Receives warnings about the sidecar (moved aside, left in place, a failed save).</param>
    public NativeAnnotations(AnnotationStore store, string filePath, string sha256, ulong imageBase, Action<string>? notify = null)
    {
        _store = store;
        _notify = notify;
        FilePath = filePath;
        Sha256 = sha256;
        ImageBase = imageBase;
        StaleSiblingHashes = store.FindOtherHashesForPath(filePath, sha256);
        var loaded = store.Open(sha256);
        if (loaded.Warning != null) notify?.Invoke(loaded.Warning);
        if (loaded.WriteBlocked) WriteBlocked = loaded.Warning;
        if (loaded.Document is { } doc)
        {
            foreach (var (k, v) in doc.Names) if (Rva(k) is { } r) _names[r] = v;
            foreach (var (k, v) in doc.Comments) if (Rva(k) is { } r) _comments[r] = v;
            _userTypes = UserTypesOf(doc);
        }
    }

    private static UserTypeLayer UserTypesOf(AnnotationDocument doc)
    {
        if (!doc.HasUserTypes) return UserTypeLayer.Empty;
        var types = new Dictionary<uint, string>();
        foreach (var (k, v) in doc.Types ?? []) if (Rva(k) is { } r && !string.IsNullOrWhiteSpace(v)) types[r] = v;
        var locals = new Dictionary<uint, IReadOnlyList<NativeLocalEdit>>();
        foreach (var (k, list) in doc.Locals ?? [])
            if (Rva(k) is { } f && list is { Count: > 0 })
                locals[f] = list.Where(e => e.Local.Length > 0).Select(e => new NativeLocalEdit(f, e.Local, e.Stack, e.Name, e.Type)).ToList();
        var stack = new Dictionary<uint, IReadOnlyList<NativeStackVarEdit>>();
        foreach (var (k, list) in doc.StackVars ?? [])
            if (Rva(k) is { } f && list is { Count: > 0 }) stack[f] = list.Select(e => new NativeStackVarEdit(f, e.Offset, e.Name, e.Type)).ToList();
        return new UserTypeLayer(doc.Declarations?.Where(d => !string.IsNullOrWhiteSpace(d)).ToList() ?? [], types, locals, stack);
    }

    private UserTypeLayer _userTypes = UserTypeLayer.Empty;

    /// <summary>The user's engine types (prototypes, global types, locals, stack members, declarations).</summary>
    public UserTypeLayer UserTypes { get { lock (_gate) return _userTypes; } }

    /// <summary>Replaces the user types with <paramref name="change"/>'s result and persists; returns the new layer.</summary>
    public UserTypeLayer ChangeUserTypes(Func<UserTypeLayer, UserTypeLayer> change)
    {
        lock (_gate)
        {
            var next = change(_userTypes);
            if (ReferenceEquals(next, _userTypes)) return next;
            _userTypes = next;
            Persist();
            return next;
        }
    }

    private static uint? Rva(string hex) => uint.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out var v) ? v : null;

    private static string Hex(uint rva) => rva.ToString("x", System.Globalization.CultureInfo.InvariantCulture);

    public int NameCount { get { lock (_gate) return _names.Count; } }
    public int CommentCount { get { lock (_gate) return _comments.Count; } }

    public string? NameAt(uint rva) { lock (_gate) return _names.GetValueOrDefault(rva); }
    public string? CommentAt(uint rva) { lock (_gate) return _comments.GetValueOrDefault(rva); }

    /// <summary>A snapshot of all (rva, name) pairs, sorted by RVA.</summary>
    public IReadOnlyList<(uint Rva, string Name)> Names()
    {
        lock (_gate) return _names.Select(kv => (kv.Key, kv.Value)).OrderBy(p => p.Key).ToList();
    }

    public IReadOnlyList<(uint Rva, string Comment)> Comments()
    {
        lock (_gate) return _comments.Select(kv => (kv.Key, kv.Value)).OrderBy(p => p.Key).ToList();
    }

    /// <summary>
    /// Validates and records a name at <paramref name="rva"/>; a null or empty name removes it. Refuses a name already
    /// used at another address unless <paramref name="allowDuplicate"/>. Persists on success.
    /// </summary>
    public void SetName(uint rva, string? name, bool allowDuplicate = false)
    {
        lock (_gate)
        {
            if (string.IsNullOrWhiteSpace(name)) { _names.Remove(rva); Persist(); return; }
            var valid = NativeName.Validate(name);
            if (!allowDuplicate)
                foreach (var (other, used) in _names)
                    if (other != rva && string.Equals(used, valid, StringComparison.Ordinal))
                        throw new ToolError(ErrorCode.Conflict, $"The name '{valid}' is already used at rva 0x{other:X}.",
                            "pass allowDuplicate=true to use it anyway, or pick another name");
            _names[rva] = valid;
            Persist();
        }
    }

    /// <summary>Records a comment at <paramref name="rva"/>; a null or empty text removes it. Persists on success.</summary>
    public void SetComment(uint rva, string? text)
    {
        lock (_gate)
        {
            var t = text?.Trim();
            if (string.IsNullOrEmpty(t)) _comments.Remove(rva);
            else _comments[rva] = t.Length > 4000 ? t[..4000] : t;
            Persist();
        }
    }

    /// <summary>Records validated names and comments in one change, persisted once (migrate_native_names).</summary>
    public void SetMany(IEnumerable<(uint Rva, string Name)> names, IEnumerable<(uint Rva, string Text)> comments)
    {
        lock (_gate)
        {
            foreach (var (rva, name) in names) _names[rva] = NativeName.Validate(name);
            foreach (var (rva, text) in comments)
            {
                var t = text.Trim();
                if (t.Length > 0) _comments[rva] = t.Length > 4000 ? t[..4000] : t;
            }
            Persist();
        }
    }

    private void Persist()
    {
        if (WriteBlocked != null) return;
        var doc = new AnnotationDocument { Path = FilePath, Sha256 = Sha256, ImageBase = ImageBase };
        foreach (var (r, n) in _names) doc.Names[r.ToString("x")] = n;
        foreach (var (r, c) in _comments) doc.Comments[r.ToString("x")] = c;
        var u = _userTypes;
        if (u.Declarations.Count > 0) doc.Declarations = [.. u.Declarations];
        if (u.Types.Count > 0) doc.Types = u.Types.ToDictionary(t => Hex(t.Key), t => t.Value);
        if (u.Locals.Count > 0)
            doc.Locals = u.Locals.ToDictionary(l => Hex(l.Key), l => l.Value.Select(e => new AnnotationDocument.LocalEntry { Local = e.Local, Stack = e.Stack, Name = e.Name, Type = e.Type }).ToList());
        if (u.StackVars.Count > 0)
            doc.StackVars = u.StackVars.ToDictionary(s => Hex(s.Key), s => s.Value.Select(e => new AnnotationDocument.StackVarEntry { Offset = e.Offset, Name = e.Name, Type = e.Type }).ToList());
        var problem = _store.Save(doc);
        // One notice per distinct problem, not one per change.
        if (problem != null && problem != _lastSaveProblem) _notify?.Invoke($"Annotations of {FilePath} could not be saved: {problem}");
        _lastSaveProblem = problem;
    }
}
