using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using dnlib.DotNet;
using dnlib.DotNet.Writer;
using ICSharpCode.Decompiler.Metadata;

namespace Corvus.Core;

/// <summary>A workspace assembly: a dnlib module and a decompiler PEFile over one in-memory image with shared tokens; the file is never locked.</summary>
public sealed class LoadedAssembly : IDisposable
{
    private readonly object _sync = new();
    private readonly byte[] _originalBytes;
    private PEFile? _peFile;
    private int _peFileVersion = -1;
    private byte[]? _editedBytes;
    private SaveReport? _editedReport;
    private int _editedBytesVersion = -1;
    private RawImage? _rawOriginal;
    private ModuleDefMD? _pristine;
    private LoadedAssembly? _originalView;
    private ModuleDefMD? _imageModule;
    private int _imageModuleVersion = -1;

    internal LoadedAssembly(string id, string filePath, byte[] bytes, ModuleDefMD module)
    {
        Id = id;
        FilePath = filePath;
        _originalBytes = bytes;
        _module = module;
    }

    /// <summary>Unique handle used in tool calls; the simple name, suffixed #n on collision.</summary>
    public string Id { get; }
    public string FilePath { get; }
    public ModuleDefMD Module
    {
        get
        {
            if (Shared) AssemblyWorkspace.RequireLock(this, "the module");
            return _module;
        }
        private set => _module = value;
    }

    private ModuleDefMD _module;

    /// <summary>In a workspace: its module and reader are read under the workspace lock (<see cref="AssemblyWorkspace.CheckLockScope"/>).</summary>
    internal bool Shared { get; init; }
    public string AssemblyName => Module.Assembly?.Name ?? Path.GetFileNameWithoutExtension(FilePath);
    public string FullAssemblyName => Module.Assembly?.FullName ?? Module.Name;

    /// <summary>Unsaved in-memory edits in application order.</summary>
    public List<EditRecord> Edits { get; } = new();
    public bool IsDirty => Edits.Count > 0;

    /// <summary>The image as loaded, before any edit.</summary>
    public byte[] OriginalBytes => _originalBytes;

    private string? _originalSha256;

    /// <summary>SHA-256 (lowercase hex) of the image as loaded; computed once.</summary>
    public string OriginalSha256 => _originalSha256 ??= Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(_originalBytes));

    /// <summary>SHA-256 of the image save_assembly last wrote over the original file: a later save may replace it.</summary>
    public string? SavedOverOriginalSha256 { get; set; }

    /// <summary>"SHA-256 &lt;hex&gt;, MVID &lt;guid&gt;": the build a result belongs to (metadata tokens are only valid within it).</summary>
    public string BuildIdentity => $"SHA-256 {OriginalSha256}, MVID {Module.Mvid?.ToString() ?? "none"}";

    private IlHealth.Result? _bodyHealth;

    /// <summary>Method bodies of the original image that are not valid IL (encrypted or dumped images); computed once.</summary>
    public IlHealth.Result BodyHealth => _bodyHealth ??= IlHealth.Assess(_originalBytes);

    /// <summary>Incremented on every module change; invalidates cached images and the decompiler view.</summary>
    public int Version { get; private set; }

    /// <summary>The number the last recorded edit got; numbers are never reused while the assembly is loaded.</summary>
    private int _lastEditNumber;

    /// <summary>Records an edit under the next number.</summary>
    internal EditRecord RecordEdit(EditRecord edit)
    {
        using (AssemblyWorkspace.Lock(_sync))
        {
            edit = edit with { Number = ++_lastEditNumber };
            Edits.Add(edit);
            Version++;
            // Renames and added types change the name lookup; toggling rebuilds dnlib's cache.
            Module.EnableTypeDefFindCache = false;
            Module.EnableTypeDefFindCache = true;
            return edit;
        }
    }

    /// <summary>Gives the last recorded edit <paramref name="number"/>: a replayed edit keeps the number it had.</summary>
    internal void Renumber(int number)
    {
        using (AssemblyWorkspace.Lock(_sync))
        {
            if (number <= 0 || Edits.Count == 0) return;
            Edits[^1] = Edits[^1] with { Number = number };
            _lastEditNumber = Math.Max(_lastEditNumber, number);
        }
    }

    /// <summary>Reloads the original image and clears edits, returning the previous state; needs the workspace write lock.</summary>
    internal (ModuleDefMD Module, List<EditRecord> Edits) ResetToOriginal(ModuleContext context)
    {
        using (AssemblyWorkspace.Lock(_sync))
        {
            var previous = (Module, Edits.ToList());
            var fresh = ModuleDefMD.Load(_originalBytes, context);
            fresh.Location = FilePath;
            fresh.EnableTypeDefFindCache = true;
            Module = fresh;
            Edits.Clear();
            Version++;
            return previous;
        }
    }

    internal void RestoreState(ModuleDefMD module, List<EditRecord> edits)
    {
        using (AssemblyWorkspace.Lock(_sync))
        {
            var discarded = Module;
            Module = module;
            Edits.Clear();
            Edits.AddRange(edits);
            Version++;
            if (!ReferenceEquals(discarded, module)) discarded.Dispose();
        }
    }

    /// <summary>A lazily loaded read-only view of the original image for diffs, outside the workspace, with the same tokens.</summary>
    internal LoadedAssembly GetOriginalView(ModuleContext context)
    {
        using (AssemblyWorkspace.Lock(_sync))
        {
            if (_originalView == null)
            {
                var module = ModuleDefMD.Load(_originalBytes, context);
                module.Location = FilePath;
                module.EnableTypeDefFindCache = true;
                _originalView = new LoadedAssembly(Id + " (original)", FilePath, _originalBytes, module);
            }
            return _originalView;
        }
    }

    /// <summary><see cref="GetImage"/> without the report.</summary>
    public byte[] GetImageBytes() => GetImage().Bytes;

    /// <summary>The current image and its write report, cached per <see cref="Version"/>; the original bytes and an empty report when unedited (<see cref="SurveyOriginal"/> lists what is invalid).</summary>
    public (byte[] Bytes, SaveReport Report) GetImage()
    {
        using (AssemblyWorkspace.Lock(_sync))
        {
            if (!IsDirty)
                return (_originalBytes, SaveReport.Empty);
            if (_editedBytes == null || _editedBytesVersion != Version)
            {
                using var ms = new MemoryStream();
                _editedReport = Write(ms);
                _editedBytes = ms.ToArray();
                _editedBytesVersion = Version;
            }
            return (_editedBytes, _editedReport!);
        }
    }

    /// <summary>What a save with no edits reports (see <see cref="FaithfulWriter.Survey"/>).</summary>
    public SaveReport SurveyOriginal()
    {
        using (AssemblyWorkspace.Lock(_sync))
        {
            try { return FaithfulWriter.Survey(Pristine(), RawOriginal); }
            catch (Exception ex) when (ex is BadImageFormatException or InvalidOperationException or ArgumentException)
            {
                return new SaveReport([new SaveIssue(SaveIssueReason.InvalidBody, 0, "module", $"the image's metadata cannot be read for a survey ({ex.Message}); it is written as it is")]);
            }
        }
    }

    internal RawImage RawOriginal
    {
        get { using (AssemblyWorkspace.Lock(_sync)) return _rawOriginal ??= new RawImage(_originalBytes); }
    }

    private (int Unreadable, int Total)? _bodyCensus;

    /// <summary>Unreadable and total IL bodies of the original; many unreadable ones mean bodies are restored at run time.</summary>
    internal (int Unreadable, int Total) BodyCensus
    {
        get
        {
            using (AssemblyWorkspace.Lock(_sync))
            {
                if (_bodyCensus is { } known) return known;
                int unreadable = 0, total = 0;
                try
                {
                    var raw = RawOriginal;
                    for (int rid = 1; rid <= raw.MethodCount; rid++)
                    {
                        var row = raw.Method(rid);
                        if (row.Rva == 0 || !row.IsIL) continue;
                        total++;
                        if (raw.ReadBody(row.Rva, out _) == null) unreadable++;
                    }
                }
                catch (Exception ex) when (ex is BadImageFormatException or InvalidOperationException or ArgumentException)
                {
                    // Metadata the reader rejects: no census (the loaders report it).
                }
                _bodyCensus = (unreadable, total);
                return (unreadable, total);
            }
        }
    }

    /// <summary>Whether the method bodies are not the code that runs: at least two, and a quarter of all IL bodies, cannot be read.</summary>
    internal bool HasUnreadableBodies => BodyCensus is var (unreadable, total) && unreadable >= 2 && unreadable * 4 >= total;

    /// <summary>A separate, never edited load of the original image: tells what edits changed.</summary>
    private ModuleDefMD Pristine()
    {
        using (AssemblyWorkspace.Lock(_sync)) return _pristine ??= ModuleDefMD.Load(_originalBytes);
    }

    /// <summary>A member's token in the current image; added members are found by name and signature in the written image.</summary>
    public uint ImageToken(IMDTokenProvider member)
    {
        if (member.MDToken.Rid != 0)
            return member.MDToken.Raw;
        using (AssemblyWorkspace.Lock(_sync))
        {
            if (_imageModule == null || _imageModuleVersion != Version)
            {
                _imageModule?.Dispose();
                _imageModule = ModuleDefMD.Load(GetImageBytes());
                _imageModule.EnableTypeDefFindCache = true;
                _imageModuleVersion = Version;
            }
            var counterpart = Counterpart(_imageModule, member)
                              ?? throw new Core.ToolError($"Could not locate {member} in the written image.");
            return counterpart.MDToken.Raw;
        }
    }

    private static IMDTokenProvider? Counterpart(ModuleDef image, IMDTokenProvider member)
    {
        static TypeDef? TypeOf(ModuleDef image, TypeDef? t) => t == null ? null : image.Find(t.FullName, isReflectionName: false);
        var comparer = new SigComparer(SigComparerOptions.DontCompareTypeScope);
        return member switch
        {
            TypeDef t => TypeOf(image, t),
            MethodDef m => TypeOf(image, m.DeclaringType)?.Methods.FirstOrDefault(x => x.Name == m.Name && comparer.Equals(x.MethodSig, m.MethodSig)),
            FieldDef f => TypeOf(image, f.DeclaringType)?.Fields.FirstOrDefault(x => x.Name == f.Name),
            PropertyDef p => TypeOf(image, p.DeclaringType)?.Properties.FirstOrDefault(x => x.Name == p.Name),
            EventDef e => TypeOf(image, e.DeclaringType)?.Events.FirstOrDefault(x => x.Name == e.Name),
            _ => null,
        };
    }

    /// <summary>The decompiler view of the image, or a dnlib-written copy when its metadata is unreadable (<see cref="DecompilerNote"/>).</summary>
    public PEFile GetPEFile()
    {
        if (Shared) AssemblyWorkspace.RequireLock(this, "the decompiler reader");
        using (AssemblyWorkspace.Lock(_sync))
        {
            if (_peFile == null || _peFileVersion != Version)
            {
                var old = _peFile;
                var image = GetImageBytes();
                // The reader refuses some metadata outright (unknown tables, a damaged duplicate stream): normalized like unreadable rows.
                PEFile? pe;
                string? problem;
                try
                {
                    pe = new PEFile(FilePath, new MemoryStream(image, writable: false), PEStreamOptions.PrefetchEntireImage, MetadataReaderOptions.None);
                    problem = MetadataProbe.Problem(pe.Metadata);
                }
                catch (BadImageFormatException ex)
                {
                    pe = null;
                    problem = ex.Message;
                }
                string? note = null;
                if (problem != null)
                {
                    try
                    {
                        var (copy, dropped) = MetadataNormalizer.Normalize(image);
                        var normalized = new PEFile(FilePath, new MemoryStream(copy, writable: false), PEStreamOptions.PrefetchEntireImage, MetadataReaderOptions.None);
                        pe?.Dispose();
                        pe = normalized;
                        var left = MetadataProbe.Problem(pe.Metadata);
                        note = $"// Note: the decompiler cannot read this assembly's metadata as stored ({problem}); it is decompiled from a copy normalized by dnlib, with the same tokens" +
                               (dropped.Length > 0 ? $" ({dropped})" : "") +
                               (left != null ? $"; still unreadable: {left}, so some members may not decompile" : "") + ".\n";
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        note = $"// Note: the decompiler cannot read this assembly's metadata as stored ({problem}), and normalizing it failed ({ex.Message}); some members will not decompile.\n";
                    }
                }
                if (pe == null)
                    throw new ToolError(ErrorCode.MalformedInput, $"The decompiler cannot read the metadata of {Id} ({problem}), and a normalized copy could not be made. " +
                        "Metadata issues: " + string.Join("; ", MetadataSurvey.Survey(image).Take(8).Select(i => $"{i.Code} at {i.Location}, file offset {i.FileOffset}: {i.Detail}")),
                        "get_il, get_type_info and the other metadata tools still work (they read the metadata leniently)");
                _peFile = pe;
                DecompilerNote = note ?? "";
                _peFileVersion = Version;
                old?.Dispose();
            }
            return _peFile;
        }
    }

    /// <summary>A comment line for decompiler output when <see cref="GetPEFile"/> is a normalized copy, else empty.</summary>
    public string DecompilerNote { get; private set; } = "";

    public byte[] WriteToBytes()
    {
        using var ms = new MemoryStream();
        Write(ms);
        return ms.ToArray();
    }

    /// <summary>Writes the module with tokens and untouched bytes kept; returns what could not be kept.</summary>
    public SaveReport Write(Stream output)
    {
        using (AssemblyWorkspace.Lock(_sync))
        {
            RawImage? original = null;
            string? unreadable = null;
            try { original = RawOriginal; }
            catch (Exception ex) when (ex is BadImageFormatException or InvalidOperationException or ArgumentException)
            {
                unreadable = ex.Message;
            }
            return FaithfulWriter.Write(Module, original, unreadable, Pristine, output);
        }
    }

    /// <summary>True once <see cref="Dispose"/> has run.</summary>
    internal bool IsDisposed { get; private set; }

    public void Dispose()
    {
        IsDisposed = true;
        lock (_sync)
        {
            _peFile?.Dispose();
            _peFile = null;
            _originalView?.Dispose();
            _originalView = null;
            _imageModule?.Dispose();
            _imageModule = null;
            _pristine?.Dispose();
            _pristine = null;
            _rawOriginal?.Dispose();
            _rawOriginal = null;
        }
        Module.Dispose();
    }

    public override string ToString() => Id;
}
