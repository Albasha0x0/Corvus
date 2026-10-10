using NetDecompilerMcp.Core;

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

    public NativeAnnotations(AnnotationStore store, string filePath, string sha256, ulong imageBase)
    {
        _store = store;
        FilePath = filePath;
        Sha256 = sha256;
        ImageBase = imageBase;
        StaleSiblingHashes = store.FindOtherHashesForPath(filePath, sha256);
        if (store.Load(sha256) is { } doc)
        {
            foreach (var (k, v) in doc.Names) if (Rva(k) is { } r) _names[r] = v;
            foreach (var (k, v) in doc.Comments) if (Rva(k) is { } r) _comments[r] = v;
        }
    }

    private static uint? Rva(string hex) => uint.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out var v) ? v : null;

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

    private void Persist()
    {
        var doc = new AnnotationDocument { Path = FilePath, Sha256 = Sha256, ImageBase = ImageBase };
        foreach (var (r, n) in _names) doc.Names[r.ToString("x")] = n;
        foreach (var (r, c) in _comments) doc.Comments[r.ToString("x")] = c;
        _store.Save(doc);
    }
}
