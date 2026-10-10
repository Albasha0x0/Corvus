using System.Buffers.Binary;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Native.Dump;

/// <summary>Outcome of looking for a module's image file: the file checked, and whether its header matches the dump's module.</summary>
public sealed record LocalImageCheck(string? Path, bool Exists, bool Matches, uint? TimeDateStamp, uint? SizeOfImage, bool? IsDotNet, string Detail);

/// <summary>Module images for a dump: the matching file on disk (header check) or the image rebuilt from captured memory.</summary>
public static class DumpImages
{
    /// <summary>Largest module image rebuilt from dump memory.</summary>
    public const uint MaxMemoryImage = 512u << 20;

    /// <summary>
    /// Looks for the module's file: its recorded path, then each of <paramref name="directories"/> with its file name. A
    /// file matches when its header's TimeDateStamp and SizeOfImage are the module's. Only the first 4 KB are read.
    /// </summary>
    public static LocalImageCheck Find(DumpModule module, IReadOnlyList<string> directories, NativeArch arch = NativeArch.Unknown)
    {
        LocalImageCheck? firstMismatch = null;
        foreach (var candidate in Candidates(module, directories, arch))
        {
            var check = Check(candidate, module);
            if (check.Matches) return check;
            if (check.Exists) firstMismatch ??= check;
        }
        return firstMismatch ?? new LocalImageCheck(null, false, false, null, null, null, "not found on this machine");
    }

    private static IEnumerable<string> Candidates(DumpModule module, IReadOnlyList<string> directories, NativeArch arch)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string recorded = module.Path;
        // a 32-bit process sees SysWOW64 as System32: its recorded system paths name the 32-bit files
        if (arch == NativeArch.X86 && Environment.Is64BitOperatingSystem && Wow64Path(recorded) is { } wow && seen.Add(wow)) yield return wow;
        if (IsUsablePath(recorded) && seen.Add(recorded)) yield return recorded;
        string name = module.FileName;
        if (name.Length == 0 || name.IndexOfAny(System.IO.Path.GetInvalidFileNameChars()) >= 0) yield break;
        foreach (var dir in directories)
        {
            string p;
            try { p = System.IO.Path.Combine(dir, name); }
            catch (ArgumentException) { continue; }
            if (seen.Add(p)) yield return p;
        }
    }

    private static string? Wow64Path(string path)
    {
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var wow = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);
        if (system.Length == 0 || wow.Length == 0 || system.Equals(wow, StringComparison.OrdinalIgnoreCase)) return null;
        var prefix = system.TrimEnd('\\') + "\\";
        return path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ? System.IO.Path.Combine(wow, path[prefix.Length..]) : null;
    }

    private static bool IsUsablePath(string path)
    {
        try { return path.Length > 0 && System.IO.Path.IsPathFullyQualified(path) && path.IndexOfAny(System.IO.Path.GetInvalidPathChars()) < 0; }
        catch (ArgumentException) { return false; }
    }

    /// <summary>Reads the header of <paramref name="path"/> and compares it with the module.</summary>
    public static LocalImageCheck Check(string path, DumpModule module)
    {
        byte[] head = new byte[4096];
        int n;
        try
        {
            if (!File.Exists(path)) return new LocalImageCheck(path, false, false, null, null, null, "file not found");
            using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            n = RandomAccess.Read(handle, head, 0);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return new LocalImageCheck(path, false, false, null, null, null, $"cannot read: {ex.Message}");
        }
        if (!TryHeader(head.AsSpan(0, n), out uint stamp, out uint size, out bool dotNet))
            return new LocalImageCheck(path, true, false, null, null, null, "not a PE file");
        bool matches = stamp == module.TimeDateStamp && size == module.Size;
        string detail = matches ? "timestamp and size match" :
            $"different build: file timestamp 0x{stamp:X8} size 0x{size:X}, dump module timestamp 0x{module.TimeDateStamp:X8} size 0x{module.Size:X}";
        return new LocalImageCheck(path, true, matches, stamp, size, dotNet, detail);
    }

    /// <summary>TimeDateStamp, SizeOfImage and whether there is a CLR header, from the first bytes of a PE file or mapped image.</summary>
    public static bool TryHeader(ReadOnlySpan<byte> b, out uint timeDateStamp, out uint sizeOfImage, out bool isDotNet)
    {
        timeDateStamp = sizeOfImage = 0;
        isDotNet = false;
        if (b.Length < 0x40 || b[0] != 'M' || b[1] != 'Z') return false;
        uint lfanew = BinaryPrimitives.ReadUInt32LittleEndian(b[0x3C..]);
        if (lfanew > b.Length - 24 || BinaryPrimitives.ReadUInt32LittleEndian(b[(int)lfanew..]) != 0x00004550) return false;
        int coff = (int)lfanew + 4, opt = coff + 20;
        timeDateStamp = BinaryPrimitives.ReadUInt32LittleEndian(b[(coff + 4)..]);
        if (opt + 60 > b.Length) return false;
        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(b[opt..]);
        sizeOfImage = BinaryPrimitives.ReadUInt32LittleEndian(b[(opt + 56)..]);
        int dirs = opt + (magic == 0x20B ? 112 : 96);
        if (dirs - 4 + 4 <= b.Length)
        {
            uint count = BinaryPrimitives.ReadUInt32LittleEndian(b[(dirs - 4)..]);
            if (count > 14 && dirs + 15 * 8 <= b.Length) isDotNet = BinaryPrimitives.ReadUInt32LittleEndian(b[(dirs + 14 * 8)..]) != 0;
        }
        return true;
    }

    /// <summary>Debug directory entries point at their data by file offset: in the rebuilt layout that is the RVA.</summary>
    private static void PatchDebugDirectory(byte[] image, int optional)
    {
        if (optional + 2 > image.Length) return;
        bool pe32Plus = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(optional)) == 0x20B;
        int dir = optional + (pe32Plus ? 112 : 96) + 6 * 8;
        if (dir + 8 > image.Length) return;
        uint rva = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(dir)), size = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(dir + 4));
        for (long at = rva; size > 0 && at + 28 <= Math.Min((long)rva + size, image.Length) && at - rva < 28 * 64; at += 28)
        {
            var entry = image.AsSpan((int)at, 28);
            BinaryPrimitives.WriteUInt32LittleEndian(entry[24..], BinaryPrimitives.ReadUInt32LittleEndian(entry[20..]));
        }
    }

    /// <summary>
    /// The module's image rebuilt from process memory (full-memory dumps, dumps with module headers and code, a live process):
    /// the mapped layout with each section header pointing at its own virtual address, so it reads as a file. Missing
    /// pages read as zero. Null when the headers are not captured. <paramref name="captured"/> counts the bytes present.
    /// </summary>
    public static PeFile? FromMemory(IProcessMemory dump, DumpModule module, out ulong captured)
    {
        captured = 0;
        var head = new byte[0x1000];
        if (dump.ReadMemory(module.Base, head) < 0x200) return null;
        if (!TryHeader(head, out _, out uint size, out _)) return null;
        // the module list's size is what was mapped; only the captured part is allocated
        size = Math.Min(module.Size != 0 ? module.Size : size, MaxMemoryImage);
        ulong extent = dump.ReadableExtent(module.Base, size);
        size = (uint)Math.Min(size, (extent + 0xFFF) & ~0xFFFUL);
        if (size < 0x200) return null;
        var image = new byte[size];
        for (uint page = 0; page < size; page += 0x1000)
        {
            int want = (int)Math.Min(0x1000u, size - page);
            int got = dump.ReadMemory(module.Base + page, image.AsSpan((int)page, want));
            captured += (ulong)got;
        }
        uint lfanew = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(0x3C));
        int coff = (int)lfanew + 4;
        if (coff + 20 > image.Length) return null;
        ushort sections = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(coff + 2));
        ushort optSize = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(coff + 16));
        long table = coff + 20L + optSize;
        for (int i = 0; i < sections && i < PeLimits.MaxSections; i++)
        {
            long at = table + i * 40L;
            if (at + 40 > image.Length) break;
            var h = image.AsSpan((int)at, 40);
            uint vsize = BinaryPrimitives.ReadUInt32LittleEndian(h[8..]);
            uint va = BinaryPrimitives.ReadUInt32LittleEndian(h[12..]);
            uint raw = BinaryPrimitives.ReadUInt32LittleEndian(h[16..]);
            uint mapped = Math.Max(vsize, raw);
            if (va >= size) mapped = 0;
            else mapped = Math.Min(mapped, size - va);
            BinaryPrimitives.WriteUInt32LittleEndian(h[16..], mapped);
            BinaryPrimitives.WriteUInt32LittleEndian(h[20..], mapped == 0 ? 0 : va);
        }
        PatchDebugDirectory(image, coff + 20);
        try { return PeFile.FromBytes(image, $"{module.FileName} ({(dump is MinidumpFile ? "dump" : "process")} memory)"); }
        catch (ToolError) { return null; }
    }
}
