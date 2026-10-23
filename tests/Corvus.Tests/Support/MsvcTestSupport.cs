using System.Buffers.Binary;
using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Corvus.Native;

namespace Corvus.Tests;

/// <summary>DbgHelp's UnDecorateSymbolName, the reference undecorator (Windows only; calls are serialized, DbgHelp is not thread-safe).</summary>
internal static class DbgHelp
{
    public const int Complete = 0x0000;
    public const int NameOnly = 0x1000;
    public const int NoPtr64 = 0x20000;

    private static readonly object Gate = new();

    public static bool IsAvailable => OperatingSystem.IsWindows();

    [DllImport("dbghelp.dll", EntryPoint = "UnDecorateSymbolNameW", CharSet = CharSet.Unicode)]
    private static extern uint UnDecorateSymbolNameW(string name, [Out] char[] output, uint maxLength, uint flags);

    public static string? Undecorate(string name, int flags)
    {
        var buffer = new char[16 * 1024];
        lock (Gate)
        {
            uint n = UnDecorateSymbolNameW(name, buffer, (uint)buffer.Length, (uint)flags);
            return n == 0 ? null : new string(buffer, 0, (int)n);
        }
    }

    /// <summary>
    /// Formatting-insensitive form for comparing undecorators: whitespace is dropped except between two identifier
    /// characters ("char const *" and "char const*" agree, "unsigned int" stays).
    /// </summary>
    public static string Normalize(string text)
    {
        var sb = new StringBuilder(text.Length);
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (c != ' ')
            {
                sb.Append(c);
                continue;
            }
            int j = i;
            while (j < text.Length && text[j] == ' ') j++;
            if (sb.Length > 0 && j < text.Length && IsIdent(sb[^1]) && IsIdent(text[j]))
                sb.Append(' ');
            i = j - 1;
        }
        return sb.ToString();
    }

    private static bool IsIdent(char c) => char.IsAsciiLetterOrDigit(c) || c is '_' or '$';
}

/// <summary>Decorated names found on this machine: DLL exports under the Windows directory and symbols in SDK / MSVC import libraries.</summary>
internal static class MsvcCorpus
{
    public static IEnumerable<string> SystemDirectories()
    {
        foreach (var folder in new[] { Environment.SpecialFolder.System, Environment.SpecialFolder.SystemX86 })
        {
            var dir = Environment.GetFolderPath(folder);
            if (dir.Length > 0 && Directory.Exists(dir)) yield return dir;
        }
    }

    public static IEnumerable<string> SystemDlls(int max = int.MaxValue) =>
        SystemDirectories().Distinct(StringComparer.OrdinalIgnoreCase)
            .SelectMany(d => SafeFiles(d, "*.dll")).Take(max);

    public static IEnumerable<string> SafeFiles(string dir, string pattern, bool recursive = false)
    {
        try
        {
            return Directory.EnumerateFiles(dir, pattern, new EnumerationOptions
            {
                RecurseSubdirectories = recursive, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint,
            }).ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; }
    }

    /// <summary>Export names of a PE file (empty when it is not one).</summary>
    public static List<string> ExportNames(string path)
    {
        var names = new List<string>();
        try
        {
            var image = File.ReadAllBytes(path);
            using var pe = new PEReader(new MemoryStream(image));
            var dir = pe.PEHeaders.PEHeader?.ExportTableDirectory;
            if (dir == null || dir.Value.Size == 0) return names;
            var h = pe.PEHeaders;
            int Offset(int rva)
            {
                foreach (var s in h.SectionHeaders)
                    if (rva >= s.VirtualAddress && rva < s.VirtualAddress + Math.Max(s.VirtualSize, s.SizeOfRawData))
                        return rva - s.VirtualAddress + s.PointerToRawData;
                return -1;
            }
            int e = Offset(dir.Value.RelativeVirtualAddress);
            if (e < 0 || e + 40 > image.Length) return names;
            int count = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(e + 24));
            int namesOffset = Offset(BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(e + 32)));
            if (namesOffset < 0 || count < 0 || count > 1_000_000) return names;
            for (int i = 0; i < count && namesOffset + 4 * i + 4 <= image.Length; i++)
            {
                int n = Offset(BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(namesOffset + 4 * i)));
                if (n < 0) continue;
                int end = Array.IndexOf(image, (byte)0, n);
                if (end > n) names.Add(Encoding.Latin1.GetString(image, n, end - n));
            }
        }
        catch (Exception ex) when (ex is BadImageFormatException or IOException or UnauthorizedAccessException or ArgumentException) { }
        return names;
    }

    /// <summary>Public symbol names from the first linker member of a COFF archive (.lib).</summary>
    public static List<string> ArchiveSymbols(string path)
    {
        var names = new List<string>();
        try
        {
            using var stream = File.OpenRead(path);
            var header = new byte[8 + 60];
            if (stream.Read(header) != header.Length || Encoding.ASCII.GetString(header, 0, 8) != "!<arch>\n") return names;
            var memberName = Encoding.ASCII.GetString(header, 8, 16).TrimEnd();
            if (memberName != "/") return names;
            if (!long.TryParse(Encoding.ASCII.GetString(header, 8 + 48, 10).Trim(), out long size) || size < 4 || size > 512 << 20) return names;
            var data = new byte[size];
            stream.ReadExactly(data);
            int count = BinaryPrimitives.ReadInt32BigEndian(data);
            int p = 4 + 4 * count;
            for (int i = 0; i < count && p < data.Length; i++)
            {
                int end = Array.IndexOf(data, (byte)0, p);
                if (end < 0) break;
                names.Add(Encoding.Latin1.GetString(data, p, end - p));
                p = end + 1;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or EndOfStreamException) { }
        return names;
    }

    /// <summary>Import libraries of the Windows SDK and of every Visual C++ toolset vswhere reports.</summary>
    public static IEnumerable<string> ImportLibraries()
    {
        var roots = new List<string>();
        var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        if (pf86.Length > 0)
        {
            var kits = Path.Combine(pf86, "Windows Kits", "10", "Lib");
            if (Directory.Exists(kits))
                roots.AddRange(Directory.GetDirectories(kits).OrderDescending().Take(1));
        }
        foreach (var vs in VisualStudio.Installations())
        {
            var msvc = Path.Combine(vs, "VC", "Tools", "MSVC");
            if (Directory.Exists(msvc))
                roots.AddRange(Directory.GetDirectories(msvc).OrderDescending().Take(1).Select(v => Path.Combine(v, "lib")));
        }
        return roots.Where(Directory.Exists).SelectMany(r => SafeFiles(r, "*.lib", recursive: true)).Distinct(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Every distinct decorated C++ name ("?..."): exports of the system DLLs plus import library symbols (__imp_ stripped).</summary>
    public static HashSet<string> DecoratedNames()
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        foreach (var dll in SystemDlls())
            foreach (var n in ExportNames(dll))
                if (n.StartsWith('?')) set.Add(n);
        foreach (var lib in ImportLibraries())
            foreach (var raw in ArchiveSymbols(lib))
            {
                var n = raw.StartsWith("__imp_", StringComparison.Ordinal) ? raw[6..] : raw;
                if (n.StartsWith('?')) set.Add(n);
            }
        return set;
    }
}

/// <summary>Visual Studio installations with the C++ toolset, located through vswhere.</summary>
internal static class VisualStudio
{
    public static List<string> Installations()
    {
        var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var vswhere = Path.Combine(pf86, "Microsoft Visual Studio", "Installer", "vswhere.exe");
        if (pf86.Length == 0 || !File.Exists(vswhere)) return [];
        var (code, output) = Tools.Run(new ProcessStartInfo(vswhere,
            "-all -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath"), 60_000);
        if (code != 0) return [];
        return output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Where(Directory.Exists).ToList();
    }

    /// <summary>
    /// A stand-in for vcvarsall.bat of the newest installation that has one, or null without one: it applies the
    /// environment vcvarsall set for x64 or x86, read once per run, and calls vcvarsall itself for other targets.
    /// </summary>
    public static string? VcVarsAll() => SavedVcVars.Value;

    /// <summary>True when an installation has vcvarsall.bat; reads vswhere only, so a skip check stays cheap.</summary>
    public static bool HasVcVars => FoundVcVars.Value != null;

    private static readonly Lazy<string?> FoundVcVars = new(() =>
        Installations().Select(i => Path.Combine(i, "VC", "Auxiliary", "Build", "vcvarsall.bat")).FirstOrDefault(File.Exists));

    // A vcvarsall call took minutes on a loaded machine, and parallel sample builds that each made one passed their
    // 300 s limit; one call per target per run keeps that cost out of every build.
    private static readonly Lazy<string?> SavedVcVars = new(() =>
    {
        if (FoundVcVars.Value is not { } vcvarsall) return null;
        var dir = LeakGuard.DeleteAtEnd(Directory.CreateTempSubdirectory("corvus-test-vcvars-").FullName);
        Parallel.ForEach(["x64", "x86"], arch => SaveEnvironment(vcvarsall, arch, Path.Combine(dir, arch + ".env")));
        var standIn = Path.Combine(dir, "vcvarsall.bat");
        File.WriteAllText(standIn, "@echo off\r\n"
            + "if not exist \"%~dp0%~1.env\" goto vcvarsall\r\n"
            + "for /f \"usebackq delims=\" %%v in (\"%~dp0%~1.env\") do set \"%%v\"\r\n"
            + "exit /b 0\r\n"
            + ":vcvarsall\r\n"
            + $"call \"{vcvarsall}\" %*\r\n");
        return standIn;
    });

    // Writes the variables vcvarsall sets for arch as name=value lines. Writes nothing when it fails or a line is too
    // long for cmd's for /f, so that target calls vcvarsall itself.
    private static void SaveEnvironment(string vcvarsall, string arch, string path)
    {
        var psi = new ProcessStartInfo("cmd.exe", $"/s /c \"\"{vcvarsall}\" {arch} >nul && set\"");
        psi.Environment["VSCMD_SKIP_SENDTELEMETRY"] = "1";
        var (code, output) = Tools.Run(psi, 900_000);
        if (code != 0) return;
        var before = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (System.Collections.DictionaryEntry e in Environment.GetEnvironmentVariables()) before[(string)e.Key] = e.Value as string;
        var changed = new List<string>();
        foreach (var line in output.Split('\n').Select(l => l.TrimEnd('\r')))
        {
            var eq = line.IndexOf('=');
            // Not a variable: stderr lines vcvarsall wrote, and cmd's per-drive "=C:" entries.
            if (eq <= 0 || line[..eq].Any(char.IsWhiteSpace) || line.Contains('"')) continue;
            if (before.TryGetValue(line[..eq], out var old) && old == line[(eq + 1)..]) continue;
            if (line.Length > 8000) return;
            changed.Add(line);
        }
        File.WriteAllLines(path, changed);
    }
}

/// <summary>
/// Test-only <see cref="INativeImage"/>: headers and sections through System.Reflection.PortableExecutable, the file
/// held in memory, base relocations (optional) from the relocation directory. Imports, exports and .pdata are not read.
/// The RTTI tests use it to read an image without its relocations; real files otherwise go through PeFile.
/// </summary>
internal sealed class MsvcTestImage : INativeImage
{
    private readonly byte[] file;
    private readonly int headerSize;

    private MsvcTestImage(string path, byte[] file, PEHeaders h, bool withRelocations)
    {
        Path = path;
        this.file = file;
        Sha256 = Convert.ToHexStringLower(SHA256.HashData(file));
        Arch = h.CoffHeader.Machine switch
        {
            Machine.I386 => NativeArch.X86,
            Machine.Amd64 => NativeArch.X64,
            Machine.Arm64 => NativeArch.Arm64,
            Machine.ArmThumb2 or Machine.Arm => NativeArch.Arm,
            _ => NativeArch.Unknown,
        };
        var pe = h.PEHeader!;
        Is64Bit = pe.Magic == PEMagic.PE32Plus;
        IsDll = (h.CoffHeader.Characteristics & Characteristics.Dll) != 0;
        ImageBase = pe.ImageBase;
        EntryPointRva = (uint)pe.AddressOfEntryPoint;
        SizeOfImage = (uint)pe.SizeOfImage;
        headerSize = (int)Math.Min(pe.SizeOfHeaders, file.Length);
        Sections = h.SectionHeaders.Select(s =>
        {
            var c = s.SectionCharacteristics;
            var access = SectionAccess.None;
            if ((c & SectionCharacteristics.MemRead) != 0) access |= SectionAccess.Read;
            if ((c & SectionCharacteristics.MemWrite) != 0) access |= SectionAccess.Write;
            if ((c & SectionCharacteristics.MemExecute) != 0) access |= SectionAccess.Execute;
            if ((c & SectionCharacteristics.ContainsCode) != 0) access |= SectionAccess.Code;
            return new NativeSection(s.Name, (uint)s.VirtualAddress, (uint)s.VirtualSize, (uint)s.PointerToRawData, (uint)s.SizeOfRawData, access, (uint)c);
        }).ToList();
        if (withRelocations)
            RelocationRvas = ReadRelocations(pe.BaseRelocationTableDirectory);
    }

    /// <summary>HIGHLOW (3) and DIR64 (10) entries of the base relocation blocks.</summary>
    private List<uint> ReadRelocations(DirectoryEntry dir)
    {
        var result = new List<uint>();
        if (dir.Size == 0) return result;
        var table = new byte[dir.Size];
        if (Read((uint)dir.RelativeVirtualAddress, table) != table.Length) return result;
        int p = 0;
        while (p + 8 <= table.Length)
        {
            uint page = BinaryPrimitives.ReadUInt32LittleEndian(table.AsSpan(p));
            int size = BinaryPrimitives.ReadInt32LittleEndian(table.AsSpan(p + 4));
            if (size < 8 || p + size > table.Length) break;
            for (int e = p + 8; e + 2 <= p + size; e += 2)
            {
                ushort entry = BinaryPrimitives.ReadUInt16LittleEndian(table.AsSpan(e));
                if (entry >> 12 is 3 or 10) result.Add(page + (uint)(entry & 0xFFF));
            }
            p += size;
        }
        result.Sort();
        return result;
    }

    public static MsvcTestImage? TryLoad(string path, bool withRelocations = true)
    {
        try
        {
            var bytes = File.ReadAllBytes(path);
            using var pe = new PEReader(new MemoryStream(bytes));
            var h = pe.PEHeaders;
            return h.PEHeader == null ? null : new MsvcTestImage(path, bytes, h, withRelocations);
        }
        catch (Exception ex) when (ex is BadImageFormatException or IOException or UnauthorizedAccessException or InvalidOperationException) { return null; }
    }

    public string Path { get; }
    public string Sha256 { get; }
    public NativeArch Arch { get; }
    public bool Is64Bit { get; }
    public bool IsDll { get; }
    public ulong ImageBase { get; }
    public uint EntryPointRva { get; }
    public uint SizeOfImage { get; }
    public IReadOnlyList<NativeSection> Sections { get; }
    public IReadOnlyList<NativeImport> Imports => [];
    public IReadOnlyList<NativeExport> Exports => [];
    public IReadOnlyList<RuntimeFunction> RuntimeFunctions => [];
    public IReadOnlyList<uint> RelocationRvas { get; } = [];
    public IReadOnlyList<uint> TlsCallbackRvas => [];
    public IReadOnlyList<ParseIssue> Issues => [];

    public int Read(uint rva, Span<byte> destination)
    {
        int done = 0;
        while (done < destination.Length)
        {
            uint at = rva + (uint)done;
            if (at < rva) break; // wrapped
            var s = SectionAt(at);
            if (s == null)
            {
                if (at >= headerSize || Sections.Count > 0 && at >= Sections[0].Rva) break;
                int n = (int)Math.Min(destination.Length - done, headerSize - at);
                file.AsSpan((int)at, n).CopyTo(destination[done..]);
                done += n;
                continue;
            }
            uint inSection = at - s.Rva;
            int chunk = (int)Math.Min((uint)(destination.Length - done), s.MappedSize - inSection);
            // raw bytes, then zero fill past the raw data or the end of the file
            long rawLeft = Math.Min((long)s.RawSize - inSection, file.Length - (s.RawOffset + (long)inSection));
            int copy = (int)Math.Clamp(rawLeft, 0, chunk);
            file.AsSpan((int)(s.RawOffset + inSection), copy).CopyTo(destination[done..]);
            destination.Slice(done + copy, chunk - copy).Clear();
            done += chunk;
        }
        return done;
    }

    public bool TryRvaToFileOffset(uint rva, out long fileOffset)
    {
        var s = SectionAt(rva);
        fileOffset = s != null && rva - s.Rva < s.RawSize ? s.RawOffset + (rva - s.Rva) : -1;
        return fileOffset >= 0;
    }

    public bool TryFileOffsetToRva(long fileOffset, out uint rva)
    {
        foreach (var s in Sections)
            if (fileOffset >= s.RawOffset && fileOffset < s.RawOffset + s.RawSize)
            {
                rva = (uint)(s.Rva + (fileOffset - s.RawOffset));
                return true;
            }
        rva = 0;
        return false;
    }

    public NativeSection? SectionAt(uint rva)
    {
        foreach (var s in Sections)
            if (s.Contains(rva)) return s;
        return null;
    }
}
