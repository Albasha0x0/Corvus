using System.Globalization;
using System.Security.Cryptography;
using Corvus.Core;
using Corvus.Core.WebAssembly;
using Corvus.Native.Pe;

namespace Corvus.Native;

/// <summary>A WebAssembly module as a native image; addresses are file offsets, as wasm-objdump gives them.</summary>
/// <remarks>A function's address is its body's offset. Names come from the name section, exports, imports, then an
/// Emscripten symbol map beside the module (&lt;name&gt;.js.symbols).</remarks>
public sealed class WasmImage : INativeImage
{
    private readonly byte[] _data;

    public WasmBinary Module { get; }
    public ImageFormat Format => ImageFormat.Wasm;
    public string Path { get; }
    public string Sha256 { get; }
    public NativeArch Arch => NativeArch.Wasm;
    public bool Is64Bit => Module.Memories.Any(m => m.Is64) || Module.Imports.Any(i => i.Memory is { Is64: true });
    public string MachineName => "WebAssembly";
    public long FileSize { get; }
    public bool IsDll => true;
    public ulong ImageBase => 0;
    public uint EntryPointRva { get; }
    public uint SizeOfImage { get; }
    public IReadOnlyList<NativeSection> Sections { get; }
    public IReadOnlyList<NativeImport> Imports { get; }
    public IReadOnlyList<NativeExport> Exports { get; }
    public IReadOnlyList<RuntimeFunction> RuntimeFunctions => [];
    public IReadOnlyList<uint> RelocationRvas => [];
    public IReadOnlyList<uint> TlsCallbackRvas => [];
    public IReadOnlyList<ParseIssue> Issues { get; }
    public IReadOnlyList<ImageSymbol> Symbols { get; }
    public IReadOnlyList<DeclaredFunction> DeclaredFunctions { get; }

    /// <summary>The display name of each function index: a name-section, export, symbol-map or import name, else func_&lt;index&gt;.</summary>
    public IReadOnlyList<string> FunctionNames { get; }
    /// <summary>Where each function's name came from: name, export, symbols, import or index.</summary>
    public IReadOnlyList<string> NameSources { get; }

    public static WasmImage Open(string path)
    {
        var full = InputFiles.RequireRegularFile(path, "image file");
        var info = new FileInfo(full);
        if (info.Length > PeLimits.MaxFileSize)
            throw new ToolError(ErrorCode.LimitExceeded, $"{path} is {info.Length} bytes; images up to {PeLimits.MaxFileSize} bytes are read");
        byte[] bytes;
        try { bytes = File.ReadAllBytes(full); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { throw new ToolError(ErrorCode.IoError, $"cannot read {path}: {ex.Message}"); }
        return new WasmImage(bytes, full);
    }

    public WasmImage(byte[] bytes, string path)
    {
        if (!WasmBinary.Looks(bytes)) throw new ToolError(ErrorCode.MalformedInput, $"{path} is not a WebAssembly module.");
        Path = path;
        Sha256 = Convert.ToHexStringLower(SHA256.HashData(bytes));
        FileSize = bytes.Length;
        ParseIssue? component = null;
        if (WasmComponent.Looks(bytes))
        {
            // A component holds no code of its own; its largest core module is the program.
            var modules = WasmComponent.CoreModules(bytes);
            if (modules.Count > 0)
            {
                var main = modules.MaxBy(x => x.Length);
                bytes = bytes.AsSpan(main.Offset, main.Length).ToArray();
                component = new ParseIssue("wasm", $"a WebAssembly component of {modules.Count} core modules: this view is {main.Name} (file offset 0x{main.Offset:X}), " +
                                                   "addresses are offsets in it; unpack_container extracts each core module");
            }
        }
        _data = bytes;
        Module = WasmBinary.Read(bytes);
        var m = Module;
        SizeOfImage = (uint)bytes.Length;
        Issues = [.. component != null ? [component] : Array.Empty<ParseIssue>(), .. m.Issues.Select(i => new ParseIssue("wasm", i)),
            .. m.Unsupported != null ? [new ParseIssue("wasm", $"not modelled: {m.Unsupported}")] : Array.Empty<ParseIssue>()];
        Sections = [.. m.Sections.Select(s => new NativeSection(WasmBinary.Name(s.Id), (uint)s.Start, (uint)(s.End - s.Start), (uint)s.Start, (uint)(s.End - s.Start),
            s.Id == 10 ? SectionAccess.Read | SectionAccess.Execute | SectionAccess.Code : SectionAccess.Read, s.Id))];
        Imports = [.. m.Imports.Where(i => i.Kind == WasmExternal.Func).Select(i => new NativeImport(i.Module, i.Name, null, 0, (uint)i.Offset, false))];

        var symbols = SymbolMap(path, Math.Max(m.FunctionCount, m.ImportedFunctions + m.Bodies.Count));
        // A body without a declaration still gets a name.
        int count = Math.Max(m.FunctionCount, m.ImportedFunctions + m.Bodies.Count);
        var names = new string[count];
        var sources = new string[count];
        var exportNames = new Dictionary<uint, string>();
        foreach (var e in m.Exports) if (e.Kind == WasmExternal.Func) exportNames.TryAdd(e.Index, e.Name);
        for (uint f = 0; f < names.Length; f++)
        {
            if (m.Names.Functions.TryGetValue(f, out var n) && n.Length > 0) (names[f], sources[f]) = (n, "name");
            else if (exportNames.TryGetValue(f, out var x)) (names[f], sources[f]) = (x, "export");
            else if (f < m.ImportedFunctions && m.ImportAt(WasmExternal.Func, f) is { } imp) (names[f], sources[f]) = ($"{imp.Module}.{imp.Name}", "import");
            else if (symbols != null && symbols.TryGetValue(f, out var s)) (names[f], sources[f]) = (s, "symbols");
            else (names[f], sources[f]) = ("func_" + f.ToString(CultureInfo.InvariantCulture), "index");
        }
        FunctionNames = names;
        NameSources = sources;

        var exports = new List<NativeExport>();
        uint ordinal = 0;
        foreach (var e in m.Exports)
        {
            uint rva = e.Kind == WasmExternal.Func && m.BodyOf(e.Index) is { } body ? (uint)body.Start
                : e.Kind == WasmExternal.Func && e.Index < m.ImportedFunctions && m.ImportAt(WasmExternal.Func, e.Index) is { } fi ? (uint)fi.Offset
                : e.Kind == WasmExternal.Global ? GlobalAddress(e.Index) ?? (uint)e.Offset : (uint)e.Offset;
            exports.Add(new NativeExport(e.Name, ordinal++, rva, null));
        }
        Exports = exports;
        Symbols = [.. Enumerable.Range(0, m.Bodies.Count).Select(i => new ImageSymbol(names[m.ImportedFunctions + i], (uint)m.Bodies[i].Start,
            (ulong)(m.Bodies[i].End - m.Bodies[i].Start), ImageSymbolKind.Function, ImageSymbolBinding.Global, "code")).OrderBy(s => s.Rva)];
        DeclaredFunctions = [.. m.Bodies.Select(b => new DeclaredFunction((uint)b.Start, (uint)(b.End - b.Start), DeclaredSource.Symbol))];
        EntryPointRva = m.Start is { } start && m.BodyOf(start) is { } entry ? (uint)entry.Start : 0;
    }

    /// <summary>Linear memory addresses to file offsets, through the data segments.</summary>
    public WasmMemoryMap Memory => _memory ??= new WasmMemoryMap(Module);
    private WasmMemoryMap? _memory;

    /// <summary>A global's address: its import entry or its global section entry.</summary>
    public uint? GlobalAddress(uint index) =>
        index < Module.ImportedGlobals ? (uint?)Module.ImportAt(WasmExternal.Global, index)?.Offset
        : index - Module.ImportedGlobals < Module.Globals.Count ? (uint)Module.Globals[(int)(index - Module.ImportedGlobals)].Offset : null;

    /// <summary>The function index whose body starts at <paramref name="rva"/>, or null.</summary>
    public uint? FunctionAt(uint rva)
    {
        int lo = 0, hi = Module.Bodies.Count - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            var b = Module.Bodies[mid];
            if (rva < b.Start) hi = mid - 1;
            else if (rva >= b.End) lo = mid + 1;
            else return (uint)(Module.ImportedFunctions + mid);
        }
        return null;
    }

    /// <summary>An Emscripten symbol map ("index:name" lines) beside the module, or null.</summary>
    private static Dictionary<uint, string>? SymbolMap(string path, int count)
    {
        if (path.Length == 0) return null;
        try
        {
            var map = System.IO.Path.ChangeExtension(path, ".js.symbols");
            if (!File.Exists(map) || new FileInfo(map).Length > 64 << 20) return null;
            var names = new Dictionary<uint, string>();
            foreach (var line in File.ReadLines(map))
            {
                int colon = line.IndexOf(':');
                if (colon > 0 && uint.TryParse(line.AsSpan(0, colon), NumberStyles.None, CultureInfo.InvariantCulture, out var index) && index < count && colon + 1 < line.Length)
                    names.TryAdd(index, line[(colon + 1)..]);
            }
            return names;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { return null; }
    }

    public int Read(uint rva, Span<byte> destination)
    {
        if (rva >= _data.Length) return 0;
        int n = Math.Min(destination.Length, _data.Length - (int)rva);
        _data.AsSpan((int)rva, n).CopyTo(destination);
        return n;
    }

    public bool TryRvaToFileOffset(uint rva, out long fileOffset)
    {
        fileOffset = rva;
        return rva < _data.Length;
    }

    public bool TryFileOffsetToRva(long fileOffset, out uint rva)
    {
        rva = (uint)fileOffset;
        return fileOffset >= 0 && fileOffset < _data.Length;
    }

    public NativeSection? SectionAt(uint rva) => Sections.FirstOrDefault(s => s.Contains(rva));
}
