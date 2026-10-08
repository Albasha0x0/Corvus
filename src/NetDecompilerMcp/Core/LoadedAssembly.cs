using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using dnlib.DotNet;
using dnlib.DotNet.Writer;
using ICSharpCode.Decompiler.Metadata;

namespace NetDecompilerMcp.Core;

/// <summary>
/// A workspace assembly with two views of one in-memory image: a dnlib module (metadata, analysis, editing) and an
/// ICSharpCode PEFile (decompilation). The file on disk is never locked. Edits are written with PreserveAll so
/// metadata tokens stay identical across both views.
/// </summary>
public sealed class LoadedAssembly : IDisposable
{
    private readonly object _sync = new();
    private readonly byte[] _originalBytes;
    private PEFile? _peFile;
    private int _peFileVersion = -1;
    private byte[]? _editedBytes;
    private int _editedBytesVersion = -1;
    private LoadedAssembly? _originalView;
    private ModuleDefMD? _imageModule;
    private int _imageModuleVersion = -1;

    internal LoadedAssembly(string id, string filePath, byte[] bytes, ModuleDefMD module)
    {
        Id = id;
        FilePath = filePath;
        _originalBytes = bytes;
        Module = module;
    }

    /// <summary>Unique handle used in tool calls; the simple name, suffixed #n on collision.</summary>
    public string Id { get; }
    public string FilePath { get; }
    public ModuleDefMD Module { get; private set; }
    public string AssemblyName => Module.Assembly?.Name ?? Path.GetFileNameWithoutExtension(FilePath);
    public string FullAssemblyName => Module.Assembly?.FullName ?? Module.Name;

    /// <summary>Unsaved in-memory edits in application order.</summary>
    public List<EditRecord> Edits { get; } = new();
    public bool IsDirty => Edits.Count > 0;

    /// <summary>The image as loaded, before any edit.</summary>
    public byte[] OriginalBytes => _originalBytes;

    private Services.IlHealth.Result? _bodyHealth;

    /// <summary>Method bodies of the original image that are not valid IL (encrypted or dumped images); computed once.</summary>
    public Services.IlHealth.Result BodyHealth => _bodyHealth ??= Services.IlHealth.Assess(_originalBytes);

    /// <summary>Incremented on every module change; invalidates cached images and the decompiler view.</summary>
    public int Version { get; private set; }

    internal void RecordEdit(EditRecord edit)
    {
        lock (_sync)
        {
            Edits.Add(edit);
            Version++;
            // Renames and added types change the name lookup; toggling rebuilds dnlib's cache.
            Module.EnableTypeDefFindCache = false;
            Module.EnableTypeDefFindCache = true;
        }
    }

    /// <summary>
    /// Reloads the original image and clears edits. Returns the previous state for <see cref="RestoreState"/>.
    /// Caller must hold the workspace write lock.
    /// </summary>
    internal (ModuleDefMD Module, List<EditRecord> Edits) ResetToOriginal(ModuleContext context)
    {
        lock (_sync)
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
        lock (_sync)
        {
            var discarded = Module;
            Module = module;
            Edits.Clear();
            Edits.AddRange(edits);
            Version++;
            if (!ReferenceEquals(discarded, module)) discarded.Dispose();
        }
    }

    /// <summary>
    /// Lazily loaded read-only view of the original image, used for diffs. Not part of the workspace; original
    /// members have the same tokens in both views.
    /// </summary>
    internal LoadedAssembly GetOriginalView(ModuleContext context)
    {
        lock (_sync)
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

    /// <summary>The original bytes, or the edited module serialized and cached per <see cref="Version"/>.</summary>
    public byte[] GetImageBytes()
    {
        lock (_sync)
        {
            if (!IsDirty)
                return _originalBytes;
            if (_editedBytes == null || _editedBytesVersion != Version)
            {
                _editedBytes = WriteToBytes();
                _editedBytesVersion = Version;
            }
            return _editedBytes;
        }
    }

    /// <summary>
    /// Metadata token of a member in the current image. Members added by edits have rid 0 in dnlib's model, so they
    /// are looked up by name and signature in the written image.
    /// </summary>
    public uint ImageToken(IMDTokenProvider member)
    {
        if (member.MDToken.Rid != 0)
            return member.MDToken.Raw;
        lock (_sync)
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

    /// <summary>Decompiler view of <see cref="GetImageBytes"/>, rebuilt after edits.</summary>
    public PEFile GetPEFile()
    {
        lock (_sync)
        {
            if (_peFile == null || _peFileVersion != Version)
            {
                var old = _peFile;
                _peFile = new PEFile(FilePath, new MemoryStream(GetImageBytes(), writable: false),
                    PEStreamOptions.PrefetchEntireImage, MetadataReaderOptions.None);
                _peFileVersion = Version;
                old?.Dispose();
            }
            return _peFile;
        }
    }

    public byte[] WriteToBytes()
    {
        using var ms = new MemoryStream();
        Write(ms);
        return ms.ToArray();
    }

    public void Write(Stream output)
    {
        if (Module.IsILOnly)
        {
            var opts = new ModuleWriterOptions(Module) { Logger = DummyLogger.NoThrowInstance };
            opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
            Module.Write(output, opts);
        }
        else
        {
            // Mixed-mode image: the native writer preserves native code and sections.
            var opts = new NativeModuleWriterOptions(Module, optimizeImageSize: false) { Logger = DummyLogger.NoThrowInstance };
            opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
            Module.NativeWrite(output, opts);
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            _peFile?.Dispose();
            _peFile = null;
            _originalView?.Dispose();
            _originalView = null;
            _imageModule?.Dispose();
            _imageModule = null;
        }
        Module.Dispose();
    }

    public override string ToString() => Id;
}
