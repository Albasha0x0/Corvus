using dnlib.DotNet;
using dnlib.DotNet.Writer;
using ICSharpCode.Decompiler.Metadata;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

namespace NetDecompilerMcp.Core;

/// <summary>
/// One assembly in the workspace. Holds two views of the same image:
/// a dnlib module (metadata browsing, analysis, editing) and an ICSharpCode PEFile
/// (decompilation/disassembly). Both are built from an in-memory copy, so the file on
/// disk is never locked. Metadata tokens are shared between the two views, and edits are
/// written with PreserveAll so tokens stay stable after a rebuild of the decompiler view.
/// </summary>
public sealed class LoadedAssembly : IDisposable
{
    private readonly object _sync = new();
    private readonly byte[] _originalBytes;
    private PEFile? _peFile;
    private int _peFileVersion = -1;
    private byte[]? _editedBytes;
    private int _editedBytesVersion = -1;

    internal LoadedAssembly(string id, string filePath, byte[] bytes, ModuleDefMD module)
    {
        Id = id;
        FilePath = filePath;
        _originalBytes = bytes;
        Module = module;
    }

    /// <summary>Short unique handle used in tool calls (usually the assembly simple name).</summary>
    public string Id { get; }
    public string FilePath { get; }
    public ModuleDefMD Module { get; }
    public string AssemblyName => Module.Assembly?.Name ?? Path.GetFileNameWithoutExtension(FilePath);
    public string FullAssemblyName => Module.Assembly?.FullName ?? Module.Name;

    /// <summary>Human-readable log of in-memory edits not yet saved.</summary>
    public List<string> Edits { get; } = new();
    public bool IsDirty => Edits.Count > 0;

    /// <summary>Increments whenever the module is edited; invalidates the decompiler view.</summary>
    public int Version { get; private set; }

    internal void RecordEdit(string description)
    {
        lock (_sync)
        {
            Edits.Add(description);
            Version++;
            // Renames change type names: rebuild dnlib's name -> TypeDef cache.
            Module.EnableTypeDefFindCache = false;
            Module.EnableTypeDefFindCache = true;
        }
    }

    /// <summary>The current image: the original file bytes, or the edited module serialized (cached per edit version).</summary>
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

    /// <summary>The decompiler's view of <see cref="GetImageBytes"/>, rebuilt after edits.</summary>
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
            // Mixed-mode image: keep native code/sections intact.
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
        }
        Module.Dispose();
    }

    public override string ToString() => Id;
}
