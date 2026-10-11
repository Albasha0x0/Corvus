using System.Diagnostics;
using System.Reflection;
using AssetRipper.Primitives;
using LibCpp2IL;
using LibCpp2IL.BinaryStructures;
using LibCpp2IL.Logging;
using LibCpp2IL.Metadata;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services;

/// <summary>
/// The built-in Il2Cpp reader: reads global-metadata.dat (versions 24 to 39) with the game binary (GameAssembly.dll,
/// libil2cpp.so, UnityFramework, GameAssembly.dylib/.so; see <see cref="Il2CppBinaryLayout"/>) through LibCpp2IL and
/// produces what Il2CppDumper would: dummy assemblies (written to a folder) and the script.json / stringliteral.json data
/// (<see cref="Il2CppGameModel"/>). A memory image of the binary (a process dump) is read with its sections at their
/// RVAs; 32-bit ARM code pointers lose their Thumb bit. When the Unity version is not known from the player or the data folder, each
/// sub-version of the metadata's version is tried and the first whose method pointers land in code is kept. Unreadable
/// metadata is a typed error (encrypted or obfuscated header, unsupported version, mismatched binary); unreadable single
/// items are listed in <see cref="Il2CppGameModel.Unreadables"/>. LibCpp2IL keeps one game in process-wide state, so
/// reads are serialized.
/// </summary>
public static class Il2CppMetadataReader
{
    public const int MinVersion = 24, MaxVersion = 39;
    private const uint Magic = 0xFAB11BAF;
    private static readonly object Gate = new();
    private const int MaxLibraryMessages = 50;

    /// <param name="BinaryIdentity">The binary's build id (ELF build-id, Mach-O UUID), else the SHA-256 of its file.</param>
    public sealed record Output(Il2CppGameModel Model, IReadOnlyList<string> Notes, TimeSpan WriteTime, string BinaryIdentity);

    /// <summary>The metadata header's magic and version; ToolError when the file is not readable metadata of a supported version.</summary>
    public static int CheckHeader(string metadataPath, byte[]? bytes = null)
    {
        Span<byte> head = stackalloc byte[8];
        if (bytes != null)
        {
            if (bytes.Length < 8) throw TooSmall(metadataPath);
            bytes.AsSpan(0, 8).CopyTo(head);
        }
        else
        {
            try
            {
                using var f = File.OpenHandle(metadataPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (RandomAccess.Read(f, head, 0) < 8) throw TooSmall(metadataPath);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { throw new ToolError(ErrorCode.IoError, $"Cannot read {metadataPath}: {ex.Message}"); }
        }
        uint magic = BitConverter.ToUInt32(head);
        int version = BitConverter.ToInt32(head[4..]);
        if (magic != Magic)
            throw new ToolError(ErrorCode.MalformedInput,
                $"{metadataPath} does not start with the Il2Cpp metadata magic 0x{Magic:X8} (found 0x{magic:X8}): reason encrypted_or_obfuscated — the game encrypts or " +
                "obfuscates its metadata, or this is not a global-metadata.dat.",
                "dump the decrypted metadata from the running game's memory (the runtime holds it decrypted, starting with AF 1B B1 FA) and load that file");
        if (version < MinVersion || version > MaxVersion)
            throw new ToolError(ErrorCode.Unsupported,
                $"{metadataPath} is Il2Cpp metadata version {version}: reason unsupported_version — the built-in reader handles versions {MinVersion} to {MaxVersion}" +
                (version is > 0 and < 1000 ? "" : " (a version this far off usually means a modified header)") + ".",
                "use Il2CppDumper or Cpp2IL output (load_assembly the DummyDll folder) for this game");
        return version;
    }

    private static ToolError TooSmall(string path) =>
        new(ErrorCode.MalformedInput, $"{path} is too small to be Il2Cpp metadata: reason truncated.", "load the complete global-metadata.dat");

    /// <summary>Reads the game and writes its dummy assemblies into <paramref name="dummyDirectory"/>.</summary>
    public static Output Read(Il2CppGameFiles files, string dummyDirectory, Action<string>? progress, CancellationToken ct)
    {
        var watch = Stopwatch.StartNew();
        byte[] metadata, binary;
        try
        {
            metadata = File.ReadAllBytes(InputFiles.RequireRegularFile(files.Metadata, "metadata file"));
            binary = File.ReadAllBytes(InputFiles.RequireRegularFile(files.Binary, "binary file"));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { throw new ToolError(ErrorCode.IoError, $"Cannot read the game files: {ex.Message}"); }
        int headerVersion = CheckHeader(files.Metadata, metadata);
        var sha = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(binary));
        var opened = Il2CppBinaryLayout.Open(binary, files.Binary, files.Slice);
        binary = opened.Bytes;
        var layout = opened.Layout;
        bool mapped = opened.MemoryImage;

        var notes = new List<string>();
        if (opened.Note != null) notes.Add(opened.Note);
        var tried = new List<string>();
        lock (Gate)
        {
            // The library writes to the console by default, which is the MCP channel.
            var log = new LibraryLog();
            LibLogger.Writer = log;
            LibCpp2IlMain.Settings.AllowManualMetadataAndCodeRegInput = false; // it would read the console
            LibCpp2IlMain.Settings.DisableMethodPointerMapping = true;
            try
            {
                var candidates = UnityVersions(files, headerVersion, notes);
                (UnityVersion Version, string Source)? chosen = null;
                foreach (var (version, source) in candidates)
                {
                    ct.ThrowIfCancellationRequested();
                    progress?.Invoke($"reading metadata v{headerVersion} as Unity {version}");
                    LibCpp2IlMain.Reset();
                    try
                    {
                        if (!LibCpp2IlMain.Initialize(binary, metadata, version)) { tried.Add($"Unity {version}: not initialized"); continue; }
                    }
                    catch (Exception ex) when (ex is not OutOfMemoryException and not OperationCanceledException)
                    {
                        tried.Add($"Unity {version}: {ex.GetType().Name}: {Clip(ex.Message)}");
                        continue;
                    }
                    double sane;
                    try { sane = CodeShare(layout); }
                    catch (Exception ex) when (ex is not (OutOfMemoryException or OperationCanceledException)) { tried.Add($"Unity {version}: method pointers unreadable: {Clip(ex.Message)}"); continue; }
                    if (sane < 0.5)
                    {
                        tried.Add($"Unity {version}: only {sane:P0} of the method pointers are in code");
                        continue;
                    }
                    chosen = (version, source);
                    break;
                }
                if (chosen is not { } c)
                {
                    LibCpp2IlMain.Reset();
                    bool registration = tried.Any(t => t.Contains("registration", StringComparison.OrdinalIgnoreCase));
                    if (layout.Arch == Native.NativeArch.Arm && !layout.Is64)
                        throw new ToolError(ErrorCode.MalformedInput,
                            $"The metadata (v{headerVersion}) could not be read with the 32-bit ARM {Path.GetFileName(files.Binary)}: reason " +
                            (registration ? "registration_not_found_armv7 — LibCpp2IL did not find the code/metadata registration in this armeabi-v7a build"
                                          : "armv7_unreadable — LibCpp2IL failed on this armeabi-v7a build") +
                            $". Tried: {string.Join("; ", tried)}",
                            "load the arm64-v8a build of the same game (the package with slice=arm64-v8a, or its lib/arm64-v8a/libil2cpp.so), or a memory dump of the library");
                    throw new ToolError(ErrorCode.MalformedInput,
                        $"The metadata (v{headerVersion}) could not be read with {Path.GetFileName(files.Binary)}: reason " +
                        (registration ? "binary_mismatch_or_protected — the code/metadata registration was not found in the binary: it was built from other metadata, or it is packed/protected on disk"
                                      : "unreadable_structures — no Unity sub-version's layout reads it") +
                        $". Tried: {string.Join("; ", tried)}",
                        registration ? "use the game binary of the same build, or a memory dump of it from the running game"
                                     : "check that both files come from the same build; Il2CppDumper/Cpp2IL output (DummyDll folder) can still be loaded");
                }
                if (tried.Count > 0) notes.Add($"Unity version {c.Version} ({c.Source}) after {tried.Count} other(s) failed: {string.Join("; ", tried)}");
                ct.ThrowIfCancellationRequested();
                Il2CppGameModel model;
                TimeSpan writeTime;
                try { model = Extract(files, binary, layout, mapped, headerVersion, c.Version.ToString(), c.Source, dummyDirectory, progress, notes, ct, out writeTime); }
                catch (Exception ex) when (ex is not (OutOfMemoryException or OperationCanceledException or ToolError or IOException or UnauthorizedAccessException))
                {
                    throw new ToolError(ErrorCode.MalformedInput, $"Reading the metadata (v{headerVersion}, Unity {c.Version}) failed: reason unreadable_structures — {ex.GetType().Name}: {Clip(ex.Message)} ({Where(ex)})",
                        "check that both files come from the same build; Il2CppDumper/Cpp2IL output (DummyDll folder) can still be loaded");
                }
                notes.AddRange(log.Messages.Take(10).Select(m => $"LibCpp2IL: {m}"));
                model.ReadTime = watch.Elapsed;
                return new Output(model, notes, writeTime, layout.BuildId ?? sha);
            }
            finally
            {
                LibCpp2IlMain.Reset();
                LibLogger.Writer = Silent;
            }
        }
    }

    /// <summary>The innermost frame of an exception, for reports.</summary>
    private static string Where(Exception ex) => ex.StackTrace?.Split('\n').FirstOrDefault()?.Trim() ?? "";

    private static string Clip(string s) => s.Length > 200 ? s[..200] + "…" : s;

    /// <summary>Where LibCpp2IL's messages go outside a read: nowhere (never the console).</summary>
    private static readonly LibraryLog Silent = new();

    static Il2CppMetadataReader() => LibLogger.Writer = Silent;

    private sealed class LibraryLog : LogWriter
    {
        public readonly List<string> Messages = [];
        private void Add(string m)
        {
            m = m.Trim();
            if (m.Length > 0 && Messages.Count < MaxLibraryMessages) Messages.Add(m);
        }
        public override void Info(string message) { }
        public override void Verbose(string message) { }
        public override void Warn(string message) => Add(message);
        public override void Error(string message) => Add(message);
    }

    /// <summary>The Unity versions to read the metadata as: the game's own when found, else every sub-version layout of the header version.</summary>
    private static List<(UnityVersion, string)> UnityVersions(Il2CppGameFiles files, int headerVersion, List<string> notes)
    {
        var list = new List<(UnityVersion, string)>();
        try
        {
            var v = LibCpp2IlMain.DetermineUnityVersion(files.UnityPlayer, files.DataDirectory);
            if (v.Major >= 2017) list.Add((v, files.DataDirectory != null ? "from the game data" : "from UnityPlayer.dll"));
        }
        catch (Exception ex) when (ex is not OutOfMemoryException) { notes.Add($"Unity version not read from the game files: {Clip(ex.Message)}"); }
        string[] fallback = headerVersion switch
        {
            24 => ["2019.4.21f1", "2019.4.15f1", "2019.3.7f1", "2019.1.0f1", "2018.4.34f1", "2018.3.0f1", "2017.1.0f1", "2020.1.11f1", "2020.1.0f1"],
            27 => ["2021.1.0f1", "2020.2.4f1", "2020.2.0f1"],
            29 => ["2022.1.0f1", "2021.3.0f1"],
            31 => ["2022.3.33f1", "2022.3.0f1"],
            > 31 => ["6000.3.0f1"], // read as the header version itself
            _ => ["2022.3.33f1"],
        };
        foreach (var f in fallback)
        {
            var v = UnityVersion.Parse(f);
            if (!list.Any(x => x.Item1.Equals(v))) list.Add((v, "assumed from the metadata version"));
        }
        return list;
    }

    /// <summary>The share of non-null method pointers that land in an executable section.</summary>
    private static double CodeShare(Il2CppBinaryLayout layout)
    {
        var bin = LibCpp2IlMain.Binary!;
        var meta = LibCpp2IlMain.TheMetadata!;
        int total = 0, inCode = 0;
        void Check(ulong p)
        {
            if (p == 0) return;
            total++;
            if (layout.InCode(p)) inCode++;
        }
        if (meta.MetadataVersion >= 24.2f)
        {
            foreach (var image in meta.imageDefinitions)
            {
                ulong[] pointers;
                try { pointers = ModulePointers(bin, image.Name); }
                catch (Exception ex) when (ex is not OutOfMemoryException) { continue; }
                foreach (var p in pointers.Take(2000)) Check(p);
            }
        }
        else
            foreach (var m in meta.methodDefs.Take(20000))
                if (m.methodIndex >= 0) Check(m.MethodPointer);
        return total == 0 ? 0 : (double)inCode / total;
    }

    private static ulong[] ModulePointers(Il2CppBinary bin, string? imageName)
    {
        if (imageName == null) return [];
        try
        {
            int index = bin.GetCodegenModuleIndexByName(imageName);
            return index >= 0 ? bin.GetCodegenModuleMethodPointers(index) ?? [] : [];
        }
        catch (KeyNotFoundException) { return []; }
    }

    /// <summary>
    /// Metadata 27+: the slots are found as Il2CppDumper finds them, by scanning the initialized data sections for
    /// pointer-aligned values that encode a usage ((kind &lt;&lt; 29 | index &lt;&lt; 1) + 1) with an index in range for the kind.
    /// </summary>
    private static void ScanEncodedUsages(byte[] binary, Il2CppBinaryLayout layout, Il2CppMetadata meta, Il2CppBinary bin,
        Action<uint, uint, uint> usage, CancellationToken ct)
    {
        int size = layout.Is64 ? 8 : 4;
        long[] limits = [0, bin.NumTypes, bin.NumTypes, meta.methodDefs.Length, meta.fieldRefs.Length, meta.stringLiterals.Length, bin.AllGenericMethodSpecs.Length];
        foreach (var section in layout.Areas)
        {
            if (!section.InitializedData) continue;
            long start = (long)section.RawOffset, end = Math.Min(binary.LongLength, start + section.RawSize);
            for (long at = start + ((size - start % size) % size); at + size <= end; at += size)
            {
                if (((at - start) & 0xFFFFF) == 0) ct.ThrowIfCancellationRequested();
                ulong value = size == 8 ? BitConverter.ToUInt64(binary, (int)at) : BitConverter.ToUInt32(binary, (int)at);
                if ((value & 1) == 0 || value >= uint.MaxValue) continue;
                uint encoded = (uint)value;
                uint kind = encoded >> 29;
                if (kind is 0 or > 6) continue;
                uint index = (encoded & 0x1FFFFFFE) >> 1;
                if (value != ((kind << 29) | (index << 1)) + 1 || index >= limits[kind]) continue;
                usage(kind, index, section.Rva + (uint)(at - start));
            }
        }
    }

    /// <summary>
    /// In a memory image of a running game, the runtime has replaced the type definition and generic parameter
    /// indexes of the binary's Il2CppType entries with pointers into the metadata it loaded. The metadata's base in
    /// that process is found from the types that describe their own definition (a definition's by-value type points at
    /// it), and every such pointer is turned back into an index. Returns how many entries were repaired and how many
    /// pointers could not be.
    /// </summary>
    private static (int Repaired, int Unresolved, string Layout) RepairTypeHandles(Il2CppMetadata meta, Il2CppBinary bin)
    {
        var header = meta.metadataHeader;
        int typeCount = meta.typeDefs.Length;
        var types = bin.AllTypes;
        if (typeCount == 0 || header.typeDefinitions.Size <= 0) return (0, 0, "");
        ulong typeSize = (ulong)header.typeDefinitions.Size / (ulong)typeCount;
        if (typeSize == 0) return (0, 0, "");
        var votes = new Dictionary<ulong, int>();
        for (int t = 0; t < typeCount; t++)
        {
            Il2CppType own;
            try { own = bin.GetType(meta.typeDefs[t].ByvalTypeIndex); }
            catch (Exception ex) when (ex is not OutOfMemoryException) { continue; }
            if (own.Type is not (Il2CppTypeEnum.IL2CPP_TYPE_CLASS or Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE) || own.Data.Dummy < (ulong)typeCount) continue;
            var candidate = own.Data.Dummy - (ulong)t * typeSize;
            votes[candidate] = votes.GetValueOrDefault(candidate) + 1;
        }
        if (votes.Count == 0) return (0, 0, "");
        var (typeBase, count) = votes.MaxBy(kv => kv.Value);
        if (count < 16) return (0, 0, "");
        ulong metadataBase = typeBase - (ulong)header.typeDefinitions.Offset;
        // Generic parameters: their table is at a known offset of the same metadata; the entry size is the common
        // divisor of the pointers' distances from its start (the header's count is not filled for every version).
        ulong parameterBase = metadataBase + (ulong)header.genericParameters.Offset;
        ulong parameterEnd = parameterBase + (ulong)Math.Max(0, header.genericParameters.Size);
        ulong parameterSize = 0;
        foreach (var type in types)
            if (type.Type is Il2CppTypeEnum.IL2CPP_TYPE_VAR or Il2CppTypeEnum.IL2CPP_TYPE_MVAR && type.Data.Dummy >= parameterBase && type.Data.Dummy < parameterEnd)
                parameterSize = Gcd(parameterSize, type.Data.Dummy - parameterBase);
        if (parameterSize is < 8 or > 64) parameterSize = 0; // not a plausible entry size
        int parameterCount = parameterSize > 0 ? (int)((parameterEnd - parameterBase) / parameterSize) : 0;
        int repaired = 0, unresolved = 0;
        foreach (var type in types)
        {
            ulong value = type.Data.Dummy;
            switch (type.Type)
            {
                case Il2CppTypeEnum.IL2CPP_TYPE_CLASS or Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE when value >= (ulong)typeCount:
                    if (value >= typeBase && (value - typeBase) % typeSize == 0 && (value - typeBase) / typeSize < (ulong)typeCount) { type.Data.Dummy = (value - typeBase) / typeSize; repaired++; }
                    else unresolved++;
                    break;
                case Il2CppTypeEnum.IL2CPP_TYPE_VAR or Il2CppTypeEnum.IL2CPP_TYPE_MVAR when parameterSize > 0 && value >= (ulong)parameterCount:
                    if (value >= parameterBase && (value - parameterBase) % parameterSize == 0 && (value - parameterBase) / parameterSize < (ulong)parameterCount) { type.Data.Dummy = (value - parameterBase) / parameterSize; repaired++; }
                    else unresolved++;
                    break;
            }
        }
        // LibCpp2IL indexes definitions by their types when it initializes; build that again over the repaired entries.
        var reflection = typeof(LibCpp2IL.Reflection.LibCpp2IlReflection);
        reflection.GetMethod("ResetCaches", BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static)?.Invoke(null, null);
        reflection.GetMethod("InitCaches", BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static)?.Invoke(null, null);
        return (repaired, unresolved, $"type definitions of {typeSize} bytes at 0x{typeBase:X}, generic parameters of {parameterSize} bytes");
    }

    private static ulong Gcd(ulong a, ulong b)
    {
        while (b != 0) (a, b) = (b, a % b);
        return a;
    }

    private static T? Private<T>(object target, string name) where T : class =>
        typeof(Il2CppBinary).GetField(name, BindingFlags.NonPublic | BindingFlags.Instance)?.GetValue(target) as T;

    private sealed class State(Il2CppMetadata meta, Il2CppBinary bin, Il2CppBinaryLayout layout)
    {
        public readonly Il2CppMetadata Meta = meta;
        public readonly Il2CppBinary Bin = bin;
        public readonly List<Il2CppGameModel.Unreadable> Unreadables = [];
        public readonly Dictionary<string, ulong[]> Pointers = new(StringComparer.Ordinal);

        public void Unreadable(string item, string reason, string detail) => Unreadables.Add(new(item, reason, Clip(detail)));

        /// <summary>The RVA of a data pointer into the image, or null.</summary>
        public uint? Rva(ulong pointer) => layout.Rva(pointer);

        /// <summary>The RVA of a code pointer (Thumb bit cleared), or null.</summary>
        public uint? CodeRva(ulong pointer) => layout.CodeRva(pointer);

        /// <summary>The offset of an RVA in the file as built (also for a memory image).</summary>
        public ulong Offset(uint rva) => layout.FileOffset(rva) ?? 0;

        public ulong ImageBase => layout.ImageBase;

        /// <summary>A method definition's code pointer as Il2CppDumper takes it (codegen module table by token; no shared generic code).</summary>
        public ulong Pointer(Il2CppMethodDefinition m, string imageName)
        {
            if (Meta.MetadataVersion >= 24.2f)
            {
                if (!Pointers.TryGetValue(imageName, out var table)) Pointers[imageName] = table = ModulePointers(Bin, imageName);
                long index = (m.token & 0x00FFFFFF) - 1L;
                return index >= 0 && index < table.Length ? table[index] : 0;
            }
            return m.methodIndex >= 0 ? m.MethodPointer : 0;
        }
    }

    private static Il2CppGameModel Extract(Il2CppGameFiles files, byte[] binary, Il2CppBinaryLayout layout, bool mapped, int headerVersion,
        string unityVersion, string unitySource, string dummyDirectory, Action<string>? progress, List<string> notes, CancellationToken ct, out TimeSpan writeTime)
    {
        var meta = LibCpp2IlMain.TheMetadata!;
        var bin = LibCpp2IlMain.Binary!;
        var s = new State(meta, bin, layout);
        var (repaired, unresolved, repairLayout) = RepairTypeHandles(meta, bin);
        if (repaired > 0)
            notes.Add($"repaired {repaired} type entries the running game had turned into pointers to its loaded metadata (a memory image after start-up; {repairLayout})");
        if (unresolved > 0)
            s.Unreadable($"{unresolved} type entries", "unresolved_type_handle", "pointers that are neither a type definition nor a generic parameter of this metadata");
        var names = new Il2CppDumperNames(meta, bin);
        var imageOfType = new string[meta.typeDefs.Length];
        foreach (var image in meta.imageDefinitions)
            for (long t = image.firstTypeIndex.Value; t < image.firstTypeIndex.Value + image.typeCount && t < imageOfType.Length; t++)
                imageOfType[t] = image.Name ?? "";

        // Method addresses, as the dummy assemblies carry them and as ScriptMethod entries.
        progress?.Invoke("method addresses");
        var methods = new List<Il2CppGameModel.Entry>();
        var addressOf = new Dictionary<Il2CppMethodDefinition, (uint, ulong, ulong)?>(ReferenceEqualityComparer.Instance);
        for (int t = 0; t < meta.typeDefs.Length; t++)
        {
            if ((t & 0xFF) == 0) ct.ThrowIfCancellationRequested();
            var d = meta.typeDefs[t];
            string? typeName = null;
            Il2CppMethodDefinition[] defs;
            try { defs = d.Methods ?? []; }
            catch (Exception ex) when (ex is not OutOfMemoryException) { s.Unreadable($"methods of type #{t}", "unreadable_type", $"{ex.Message} ({Where(ex)})"); continue; }
            foreach (var m in defs)
            {
                ulong pointer;
                try { pointer = s.Pointer(m, imageOfType[t]); }
                catch (Exception ex) when (ex is not OutOfMemoryException) { s.Unreadable($"method {d.FullName}::{m.Name}", "unreadable_pointer", ex.Message); continue; }
                if (pointer == 0) continue;
                if (s.CodeRva(pointer) is not { } rva)
                {
                    s.Unreadable($"method {d.FullName}::{m.Name}", "pointer_outside_image", $"code pointer 0x{pointer:X} is outside the image (base 0x{s.ImageBase:X})");
                    continue;
                }
                addressOf[m] = (rva, s.Offset(rva), s.ImageBase + rva);
                try { typeName ??= names.TypeDefName(d, true, true); }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    typeName = d.FullName ?? $"Type{t}";
                    s.Unreadable($"type {typeName}", "unreadable_type_name", $"{ex.Message} ({Where(ex)})");
                }
                methods.Add(new(rva, typeName + "$$" + m.Name, imageOfType[t], m.token));
            }
        }

        // Generic instantiations with code of their own (or shared), and the other function starts.
        progress?.Invoke("generic instantiations");
        var specs = bin.AllGenericMethodSpecs;
        var specPointers = new Dictionary<int, ulong>();
        var genericPointers = Private<ulong[]>(bin, "_genericMethodPointers");
        var tables = Private<Il2CppGenericMethodFunctionsDefinitions[]>(bin, "_genericMethodTables");
        if (genericPointers == null || tables == null)
            s.Unreadable("generic instantiations", "library_internals_changed", "LibCpp2IL's generic method table is not reachable; instantiations are not named");
        else
            foreach (var table in tables)
            {
                if (table.GenericMethodIndex < 0 || table.GenericMethodIndex >= specs.Length || table.Indices.methodIndex < 0 || table.Indices.methodIndex >= genericPointers.Length) continue;
                specPointers.TryAdd(table.GenericMethodIndex, genericPointers[table.Indices.methodIndex]);
            }
        int specCount = 0;
        foreach (var (specIndex, pointer) in specPointers.OrderBy(kv => kv.Key))
        {
            if ((++specCount & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            if (pointer == 0) continue;
            var spec = specs[specIndex];
            try
            {
                if (s.CodeRva(pointer) is not { } rva) { s.Unreadable($"generic instantiation #{specIndex}", "pointer_outside_image", $"code pointer 0x{pointer:X} is outside the image"); continue; }
                var (type, method) = names.MethodSpecName(spec, true);
                var definition = meta.methodDefs[spec.methodDefinitionIndex.Value];
                methods.Add(new(rva, type + "$$" + method, imageOfType[definition.declaringTypeIdx.Value], definition.token));
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                s.Unreadable($"generic instantiation #{specIndex}", "unreadable_generic_instance", ex.Message);
            }
        }
        var starts = new List<uint>();
        void AddStarts(IEnumerable<ulong>? pointers)
        {
            if (pointers == null) return;
            foreach (var p in pointers)
                if (p != 0 && s.CodeRva(p) is { } r) starts.Add(r);
        }
        AddStarts(genericPointers);
        if (Private<Il2CppCodeRegistration>(bin, "_codeRegistration") is { } registration)
        {
            void Table(ulong address, ulong count, string what)
            {
                if (address == 0 || count == 0 || count > 10_000_000) return;
                try { AddStarts(bin.ReadNUintArrayAtVirtualAddress(address, (long)count)); }
                catch (Exception ex) when (ex is not OutOfMemoryException) { s.Unreadable(what, "unreadable_table", ex.Message); }
            }
            Table(registration.invokerPointers, registration.invokerPointersCount, "invoker table");
            Table(registration.reversePInvokeWrappers, registration.reversePInvokeWrapperCount, "reverse P/Invoke wrapper table");
            Table(registration.unresolvedVirtualCallPointers, registration.unresolvedVirtualCallCount, "unresolved call table");
            Table(registration.unresolvedInstanceCallPointers, registration.unresolvedVirtualCallCount, "unresolved instance call table");
            Table(registration.unresolvedStaticCallPointers, registration.unresolvedVirtualCallCount, "unresolved static call table");
        }
        try { AddStarts(bin.AllCustomAttributeGenerators); }
        catch (Exception ex) when (ex is not OutOfMemoryException) { s.Unreadable("custom attribute generators", "unreadable_table", ex.Message); }

        // Metadata usages: string literal, type, method and field slots.
        progress?.Invoke("metadata slots");
        var literalSlots = new uint[meta.stringLiterals.Length];
        var slots = new List<ScriptMetadata>();
        var infos = new List<ScriptMetadataMethod>();
        void Usage(uint kind, uint index, uint rva)
        {
            try
            {
                switch (kind)
                {
                    case 1:
                    case 2:
                        var type = bin.GetType(Il2CppIndex.Of<Il2CppType>((int)index));
                        var name = names.TypeName(type, true, false);
                        slots.Add(kind == 1
                            ? new ScriptMetadata(rva, name + "_TypeInfo", type.Type is Il2CppTypeEnum.IL2CPP_TYPE_CLASS or Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE or Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST
                                ? Il2CppDumperNames.StructName(name) + "_c*" : "Il2CppClass*")
                            : new ScriptMetadata(rva, name + "_var", "Il2CppType*"));
                        break;
                    case 3:
                        var md = meta.methodDefs[index];
                        var td = meta.typeDefs[md.declaringTypeIdx.Value];
                        var pointer = s.Pointer(md, imageOfType[md.declaringTypeIdx.Value]);
                        infos.Add(new ScriptMetadataMethod(rva, "Method$" + names.TypeDefName(td, true, true) + "." + md.Name + "()", s.CodeRva(pointer) ?? 0));
                        break;
                    case 4:
                        var fieldRef = meta.fieldRefs[index];
                        var owner = bin.GetType(fieldRef.typeIndex);
                        var field = fieldRef.FieldDefinition;
                        slots.Add(new ScriptMetadata(rva, "Field$" + names.TypeName(owner, true, false) + "." + field?.Name, "FieldInfo*"));
                        break;
                    case 5:
                        if (literalSlots[index] == 0) literalSlots[index] = rva;
                        break;
                    case 6:
                        var spec = specs[index];
                        var (typeName, methodName) = names.MethodSpecName(spec, true);
                        infos.Add(new ScriptMetadataMethod(rva, "Method$" + typeName + "." + methodName + "()",
                            specPointers.TryGetValue((int)index, out var p) && s.CodeRva(p) is { } target ? target : 0));
                        break;
                }
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                s.Unreadable($"metadata slot at RVA 0x{rva:X}", "unreadable_usage", ex.Message);
            }
        }
        if (meta.MetadataVersion < 27f)
        {
            if (meta.metadataUsageDic is { } usages)
                foreach (var (kind, entries) in usages)
                    foreach (var (usageIndex, value) in entries)
                    {
                        ulong pointer;
                        try { pointer = bin.GetRawMetadataUsage(usageIndex); }
                        catch (Exception ex) when (ex is not OutOfMemoryException) { s.Unreadable($"metadata usage {usageIndex}", "unreadable_usage", ex.Message); continue; }
                        if (s.Rva(pointer) is { } rva) Usage(kind, value, rva);
                    }
        }
        else ScanEncodedUsages(binary, layout, meta, bin, Usage, ct);

        var literalValues = new string[meta.stringLiterals.Length];
        int withoutSlot = 0;
        for (int i = 0; i < literalValues.Length; i++)
        {
            try { literalValues[i] = meta.GetStringLiteralFromIndex((uint)i); }
            catch (Exception ex) when (ex is not OutOfMemoryException) { literalValues[i] = ""; s.Unreadable($"string literal #{i}", "unreadable_literal", ex.Message); }
            if (literalSlots[i] == 0) withoutSlot++;
        }
        if (withoutSlot > 0)
            s.Unreadable($"{withoutSlot} of {literalValues.Length} string literals", "literal_slot_not_found",
                (meta.MetadataVersion < 27f ? "no metadata usage names them"
                    : mapped ? "no slot holds their encoded index: in a memory image, the slots the game had already used hold its string objects instead"
                    : "no slot holds their encoded index (literals only reachable through generic or unused code have none)")
                + "; they are not in the literal table (the metadata's full list is in the model)");

        // Dummy assemblies.
        progress?.Invoke("dummy assemblies");
        var builder = new Il2CppDummyBuilder(meta, bin, (m, _) => addressOf.TryGetValue(m, out var a) ? a : null, s.Unreadable);
        var modules = builder.Build(ct);
        var write = Stopwatch.StartNew();
        progress?.Invoke($"writing {modules.Count} dummy assemblies");
        builder.Write(modules, dummyDirectory, ct);
        writeTime = write.Elapsed;

        return new Il2CppGameModel
        {
            BinaryPath = files.Binary, MetadataPath = files.Metadata, MetadataVersion = meta.MetadataVersion, HeaderVersion = headerVersion,
            UnityVersion = unityVersion, UnityVersionSource = unitySource, ImageBase = layout.ImageBase, MemoryImage = mapped,
            LiteralValues = literalValues, LiteralSlots = literalSlots, Methods = methods, Metadata = slots, MethodInfos = infos,
            Addresses = starts.Distinct().Order().ToArray(), Unreadables = s.Unreadables,
            Images = meta.imageDefinitions.Length, Types = builder.Types, MethodDefinitions = builder.Methods, Fields = builder.Fields,
            MethodsWithCode = builder.MethodsWithCode,
        };
    }
}
