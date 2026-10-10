using System.Buffers.Binary;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using NetDecompilerMcp.Native;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Test-only <see cref="INativeImage"/>: a PE file read with System.Reflection.PortableExecutable headers plus a
/// minimal directory parser (exports, imports, delay imports, relocations, TLS callbacks, .pdata), or a synthetic
/// image built from code and data bytes. The code analysis tests use it for synthetic images; real files go through PeFile
/// (NativeAdapterConsistencyTests checks that both give the same index).
/// </summary>
public sealed class CodeTestImage : INativeImage
{
    private readonly List<(NativeSection Section, byte[] Raw)> _sections = [];
    private readonly byte[] _headers;

    public string Path { get; private init; } = "";
    public string Sha256 { get; private init; } = "";
    public NativeArch Arch { get; private init; }
    public bool Is64Bit => Arch is NativeArch.X64 or NativeArch.Arm64;
    public bool IsDll { get; private init; }
    public ulong ImageBase { get; private init; }
    public uint EntryPointRva { get; private set; }
    public uint SizeOfImage { get; private set; }
    public IReadOnlyList<NativeSection> Sections => _sections.Select(s => s.Section).ToList();
    public IReadOnlyList<NativeImport> Imports { get; private set; } = [];
    public IReadOnlyList<NativeExport> Exports { get; private set; } = [];
    public IReadOnlyList<RuntimeFunction> RuntimeFunctions { get; private set; } = [];
    public IReadOnlyList<uint> RelocationRvas { get; private set; } = [];
    public IReadOnlyList<uint> TlsCallbackRvas { get; private set; } = [];
    public IReadOnlyList<ParseIssue> Issues { get; } = [];

    private CodeTestImage(byte[] headers) => _headers = headers;

    public static CodeTestImage Load(string path)
    {
        var bytes = File.ReadAllBytes(path);
        var headers = new PEHeaders(new MemoryStream(bytes));
        var pe = headers.PEHeader!;
        var image = new CodeTestImage(bytes.AsSpan(0, Math.Min(bytes.Length, pe.SizeOfHeaders)).ToArray())
        {
            Path = path,
            Sha256 = Convert.ToHexStringLower(SHA256.HashData(bytes)),
            Arch = headers.CoffHeader.Machine switch
            {
                Machine.I386 => NativeArch.X86,
                Machine.Amd64 => NativeArch.X64,
                Machine.Arm64 => NativeArch.Arm64,
                Machine.Arm or Machine.ArmThumb2 => NativeArch.Arm,
                _ => NativeArch.Unknown,
            },
            IsDll = (headers.CoffHeader.Characteristics & Characteristics.Dll) != 0,
            ImageBase = pe.ImageBase,
            EntryPointRva = (uint)pe.AddressOfEntryPoint,
            SizeOfImage = (uint)pe.SizeOfImage,
        };
        foreach (var s in headers.SectionHeaders)
        {
            var c = s.SectionCharacteristics;
            var access = SectionAccess.None;
            if ((c & SectionCharacteristics.MemRead) != 0) access |= SectionAccess.Read;
            if ((c & SectionCharacteristics.MemWrite) != 0) access |= SectionAccess.Write;
            if ((c & SectionCharacteristics.MemExecute) != 0) access |= SectionAccess.Execute;
            if ((c & SectionCharacteristics.ContainsCode) != 0) access |= SectionAccess.Code;
            long rawStart = Math.Min(s.PointerToRawData, bytes.Length);
            long rawLength = Math.Min(s.SizeOfRawData, bytes.Length - rawStart);
            var section = new NativeSection(s.Name, (uint)s.VirtualAddress, (uint)s.VirtualSize, (uint)s.PointerToRawData, (uint)s.SizeOfRawData, access, (uint)c);
            image._sections.Add((section, bytes.AsSpan((int)rawStart, (int)rawLength).ToArray()));
        }
        image.ParseDirectories(pe);
        return image;
    }

    /// <summary>
    /// A synthetic image: .text (execute, read) at 0x1000 holding <paramref name="code"/> and .data (read, write)
    /// at <see cref="SyntheticDataRva"/> holding <paramref name="data"/>.
    /// </summary>
    public static CodeTestImage Synthetic(NativeArch arch, byte[] code, byte[]? data = null, IEnumerable<NativeImport>? imports = null,
        IEnumerable<RuntimeFunction>? pdata = null, IEnumerable<uint>? relocations = null, uint entry = 0, IEnumerable<NativeExport>? exports = null)
    {
        var image = new CodeTestImage(new byte[0x400])
        {
            Path = "synthetic",
            Arch = arch,
            IsDll = true,
            ImageBase = arch == NativeArch.X64 ? 0x140000000UL : 0x10000000UL,
        };
        image._sections.Add((new NativeSection(".text", SyntheticCodeRva, (uint)code.Length, 0x400, (uint)code.Length,
            SectionAccess.Read | SectionAccess.Execute | SectionAccess.Code, 0x60000020), code));
        data ??= new byte[0x100];
        image._sections.Add((new NativeSection(".data", SyntheticDataRva, (uint)data.Length, 0x400 + (uint)code.Length, (uint)data.Length,
            SectionAccess.Read | SectionAccess.Write, 0xC0000040), data));
        image.SizeOfImage = SyntheticDataRva + (uint)((data.Length + 0xFFF) & ~0xFFF);
        image.EntryPointRva = entry;
        image.Imports = imports?.ToList() ?? [];
        image.Exports = exports?.ToList() ?? [];
        image.RuntimeFunctions = pdata?.OrderBy(r => r.BeginRva).ToList() ?? [];
        image.RelocationRvas = relocations?.Order().ToList() ?? [];
        return image;
    }

    public const uint SyntheticCodeRva = 0x1000;
    public const uint SyntheticDataRva = 0x80000;

    public int Read(uint rva, Span<byte> destination)
    {
        int done = 0;
        while (done < destination.Length)
        {
            uint at = rva + (uint)done;
            if (at < rva) break;
            int n = ReadChunk(at, destination[done..]);
            if (n <= 0) break;
            done += n;
        }
        return done;
    }

    private int ReadChunk(uint rva, Span<byte> destination)
    {
        if (rva < _headers.Length && (_sections.Count == 0 || rva < _sections[0].Section.Rva))
        {
            int n = Math.Min(destination.Length, _headers.Length - (int)rva);
            _headers.AsSpan((int)rva, n).CopyTo(destination);
            return n;
        }
        foreach (var (s, raw) in _sections)
        {
            if (!s.Contains(rva)) continue;
            uint offset = rva - s.Rva;
            int n = (int)Math.Min((uint)destination.Length, s.MappedSize - offset);
            int fromRaw = offset < raw.Length ? Math.Min(n, raw.Length - (int)offset) : 0;
            if (fromRaw > 0) raw.AsSpan((int)offset, fromRaw).CopyTo(destination);
            destination[fromRaw..n].Clear();
            return n;
        }
        return 0;
    }

    public bool TryRvaToFileOffset(uint rva, out long fileOffset)
    {
        foreach (var (s, raw) in _sections)
            if (s.Contains(rva) && rva - s.Rva < raw.Length) { fileOffset = s.RawOffset + (rva - s.Rva); return true; }
        fileOffset = 0;
        return false;
    }

    public bool TryFileOffsetToRva(long fileOffset, out uint rva)
    {
        foreach (var (s, raw) in _sections)
            if (fileOffset >= s.RawOffset && fileOffset < s.RawOffset + raw.Length) { rva = s.Rva + (uint)(fileOffset - s.RawOffset); return true; }
        rva = 0;
        return false;
    }

    public NativeSection? SectionAt(uint rva)
    {
        foreach (var (s, _) in _sections) if (s.Contains(rva)) return s;
        return null;
    }

    // ---- directories ----

    private uint U32(uint rva) { Span<byte> b = stackalloc byte[4]; return Read(rva, b) == 4 ? BinaryPrimitives.ReadUInt32LittleEndian(b) : 0; }
    private ulong U64(uint rva) { Span<byte> b = stackalloc byte[8]; return Read(rva, b) == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(b) : 0; }
    private ushort U16(uint rva) { Span<byte> b = stackalloc byte[2]; return Read(rva, b) == 2 ? BinaryPrimitives.ReadUInt16LittleEndian(b) : (ushort)0; }

    private string? AsciiZ(uint rva, int max = 512)
    {
        var buffer = new byte[max];
        int n = Read(rva, buffer);
        int len = Array.IndexOf(buffer, (byte)0, 0, n);
        return len < 0 ? null : Encoding.ASCII.GetString(buffer, 0, len);
    }

    private void ParseDirectories(PEHeader pe)
    {
        var exportDir = pe.ExportTableDirectory;
        if (exportDir.Size > 0) Exports = ParseExports((uint)exportDir.RelativeVirtualAddress, (uint)exportDir.Size);
        var imports = new List<NativeImport>();
        if (pe.ImportTableDirectory.Size > 0) ParseImports((uint)pe.ImportTableDirectory.RelativeVirtualAddress, imports);
        if (pe.DelayImportTableDirectory.Size > 0) ParseDelayImports((uint)pe.DelayImportTableDirectory.RelativeVirtualAddress, imports);
        Imports = imports;
        if (pe.BaseRelocationTableDirectory.Size > 0) RelocationRvas = ParseRelocations((uint)pe.BaseRelocationTableDirectory.RelativeVirtualAddress, (uint)pe.BaseRelocationTableDirectory.Size);
        if (pe.ThreadLocalStorageTableDirectory.Size > 0) TlsCallbackRvas = ParseTls((uint)pe.ThreadLocalStorageTableDirectory.RelativeVirtualAddress);
        if (pe.ExceptionTableDirectory.Size > 0 && Arch is NativeArch.X64 or NativeArch.Arm64)
            RuntimeFunctions = ParsePdata((uint)pe.ExceptionTableDirectory.RelativeVirtualAddress, (uint)pe.ExceptionTableDirectory.Size);
    }

    private List<NativeExport> ParseExports(uint dir, uint size)
    {
        var result = new List<NativeExport>();
        uint baseOrdinal = U32(dir + 16), functions = U32(dir + 20), names = U32(dir + 24);
        uint addressTable = U32(dir + 28), nameTable = U32(dir + 32), ordinalTable = U32(dir + 36);
        var nameOf = new Dictionary<uint, string>();
        for (uint i = 0; i < Math.Min(names, 100_000); i++)
        {
            ushort index = U16(ordinalTable + i * 2);
            if (AsciiZ(U32(nameTable + i * 4)) is { } name) nameOf.TryAdd(index, name);
        }
        for (uint i = 0; i < Math.Min(functions, 100_000); i++)
        {
            uint rva = U32(addressTable + i * 4);
            if (rva == 0) continue;
            string? forward = rva >= dir && rva < dir + size ? AsciiZ(rva) : null;
            result.Add(new NativeExport(nameOf.GetValueOrDefault(i), baseOrdinal + i, rva, forward));
        }
        return result;
    }

    private void ParseImports(uint dir, List<NativeImport> result)
    {
        int ptr = Is64Bit ? 8 : 4;
        for (uint d = dir; ; d += 20)
        {
            uint lookup = U32(d), name = U32(d + 12), iat = U32(d + 16);
            if (name == 0 && iat == 0) break;
            string module = AsciiZ(name) ?? "?";
            uint table = lookup != 0 ? lookup : iat;
            for (uint i = 0; i < 65536; i++)
            {
                ulong entry = ptr == 8 ? U64(table + i * 8) : U32(table + i * 4);
                if (entry == 0) break;
                result.Add(Entry(module, entry, iat + i * (uint)ptr, ptr, false));
            }
        }
    }

    private void ParseDelayImports(uint dir, List<NativeImport> result)
    {
        int ptr = Is64Bit ? 8 : 4;
        for (uint d = dir; ; d += 32)
        {
            uint attributes = U32(d), name = U32(d + 4), iat = U32(d + 12), lookup = U32(d + 16);
            if (name == 0) break;
            // attribute bit 0 clear: old descriptors hold VAs instead of RVAs
            uint Fix(uint v) => (attributes & 1) != 0 || v == 0 ? v : (uint)(v - ImageBase);
            name = Fix(name); iat = Fix(iat); lookup = Fix(lookup);
            string module = AsciiZ(name) ?? "?";
            for (uint i = 0; i < 65536; i++)
            {
                ulong entry = ptr == 8 ? U64(lookup + i * 8) : U32(lookup + i * 4);
                if (entry == 0) break;
                if ((attributes & 1) == 0 && (entry >> (ptr * 8 - 1)) == 0) entry -= ImageBase;
                result.Add(Entry(module, entry, iat + i * (uint)ptr, ptr, true));
            }
        }
    }

    private NativeImport Entry(string module, ulong entry, uint slot, int ptr, bool delay)
    {
        bool byOrdinal = (entry >> (ptr * 8 - 1)) != 0;
        if (byOrdinal) return new NativeImport(module, null, (ushort)entry, 0, slot, delay);
        uint hintName = (uint)entry;
        return new NativeImport(module, AsciiZ(hintName + 2), null, U16(hintName), slot, delay);
    }

    private List<uint> ParseRelocations(uint dir, uint size)
    {
        var result = new List<uint>();
        uint end = dir + size;
        for (uint block = dir; block + 8 <= end;)
        {
            uint page = U32(block), blockSize = U32(block + 4);
            if (blockSize < 8) break;
            for (uint e = block + 8; e + 2 <= block + blockSize; e += 2)
            {
                ushort v = U16(e);
                int type = v >> 12;
                if (type is 3 or 10) result.Add(page + (uint)(v & 0xFFF));
            }
            block += blockSize;
        }
        result.Sort();
        return result;
    }

    private List<uint> ParseTls(uint dir)
    {
        var result = new List<uint>();
        ulong callbacks = Is64Bit ? U64(dir + 24) : U32(dir + 12);
        if (callbacks < ImageBase) return result;
        uint at = (uint)(callbacks - ImageBase);
        for (int i = 0; i < 256; i++)
        {
            ulong va = Is64Bit ? U64(at + (uint)i * 8) : U32(at + (uint)i * 4);
            if (va == 0 || va < ImageBase) break;
            result.Add((uint)(va - ImageBase));
        }
        return result;
    }

    private List<RuntimeFunction> ParsePdata(uint dir, uint size)
    {
        var result = new List<RuntimeFunction>();
        if (Arch == NativeArch.X64)
        {
            for (uint e = dir; e + 12 <= dir + size; e += 12)
            {
                uint begin = U32(e), end = U32(e + 4), unwind = U32(e + 8);
                if (begin == 0 && end == 0) break;
                result.Add(new RuntimeFunction(begin, end, unwind));
            }
        }
        else
        {
            for (uint e = dir; e + 8 <= dir + size; e += 8)
            {
                uint begin = U32(e), unwind = U32(e + 4);
                if (begin == 0) break;
                uint length = (unwind & 3) != 0 ? ((unwind >> 2) & 0x7FF) * 4 : (U32(unwind) & 0x3FFFF) * 4;
                result.Add(new RuntimeFunction(begin, begin + length, unwind));
            }
        }
        result.Sort((a, b) => a.BeginRva.CompareTo(b.BeginRva));
        return result;
    }
}
