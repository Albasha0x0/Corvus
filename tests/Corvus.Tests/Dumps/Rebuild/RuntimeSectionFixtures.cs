using System.Buffers.Binary;
using System.Text;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>A dump and the file of the same build; <paramref name="SectionRva"/> is the RVA of the section under test.</summary>
internal sealed record RuntimeSectionImage(string DumpPath, string ImageDir, uint SectionRva, ulong Base, string ModuleName);

/// <summary>Builds images whose sections are written in memory after the loader mapped them.</summary>
internal static class RuntimeSectionFixtures
{
    private const int Page = 0x1000;
    private const uint Executable = 0x20000020;
    private const uint Readable = 0x40000000;
    private const uint Writable = 0x80000000;
    private const uint InitializedData = 0x40;
    private const uint UninitializedData = 0x80;

    /// <summary>
    /// Returns a dump and its file where <paramref name="section"/> has SizeOfRawData 0 in the file and holds
    /// <paramref name="memoryBytes"/> in the dump; page indexes (RVA / 4 KB) in <paramref name="uncapturedPages"/>
    /// are left out. Throws on empty <paramref name="memoryBytes"/>.
    /// </summary>
    public static RuntimeSectionImage NoRawData(TempDir dir, bool is64, string section, byte[] memoryBytes,
        bool executable, bool writable, IReadOnlyList<int>? uncapturedPages = null) =>
        Create(dir, is64, section, [], memoryBytes, executable, writable, uncapturedPages);

    /// <summary>
    /// Returns a dump and its file where <paramref name="section"/> has <paramref name="rawBytes"/> as raw data and a
    /// virtual size that also covers <paramref name="memoryBytes"/>; the dump holds the file bytes followed by the
    /// written tail. Page indexes (RVA / 4 KB) in <paramref name="uncapturedPages"/> are left out. Throws on empty
    /// raw data or an empty tail.
    /// </summary>
    public static RuntimeSectionImage ShortRawData(TempDir dir, bool is64, string section, byte[] rawBytes,
        byte[] memoryBytes, bool executable = true, bool writable = false, IReadOnlyList<int>? uncapturedPages = null)
    {
        if (rawBytes.Length == 0) throw new ArgumentException("Raw data is empty.", nameof(rawBytes));
        return Create(dir, is64, section, rawBytes, memoryBytes, executable, writable, uncapturedPages);
    }

    private static RuntimeSectionImage Create(TempDir dir, bool is64, string section, byte[] raw, byte[] tail,
        bool executable, bool writable, IReadOnlyList<int>? uncaptured)
    {
        if (tail.Length == 0) throw new ArgumentException("No bytes in memory.", nameof(tail));
        bool noRaw = raw.Length == 0;
        uint characteristics = Readable
            | (executable ? Executable : noRaw ? UninitializedData : InitializedData)
            | (writable ? Writable : 0);
        var spec = new PeSpec(is64,
        [
            new SectionSpec(".text", 0x60000020, [0xC3]),
            new SectionSpec(section, characteristics, new byte[raw.Length + tail.Length]),
        ]);
        var file = RebuildFixtures.Pe(spec);
        uint rva = PeFile.FromBytes(file).Sections.First(s => s.Name == section).Rva;
        raw.CopyTo(file.AsSpan((int)RawOffset(file, section)));
        SetRawData(file, section, (uint)raw.Length, spec.FileAlignment);

        var mapped = RebuildFixtures.Mapped(file);
        raw.CopyTo(mapped, (int)rva);
        tail.CopyTo(mapped, (int)rva + raw.Length);

        const string name = "runtime.dll";
        string imageDir = dir.File("image-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(imageDir);
        File.WriteAllBytes(Path.Combine(imageDir, name), file);

        uint stamp = BinaryPrimitives.ReadUInt32LittleEndian(
            file.AsSpan(BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(0x3C)) + 8));
        var builder = new MinidumpBuilder { ProcessorArchitecture = is64 ? (ushort)9 : (ushort)0 };
        builder.Modules.Add(new MinidumpBuilder.Module(spec.Base, (uint)mapped.Length, stamp, name));
        var left = (uncaptured ?? []).ToHashSet();
        int pages = (mapped.Length + Page - 1) / Page;
        int start = -1;
        for (int p = 0; p <= pages; p++)
        {
            bool present = p < pages && !left.Contains(p);
            if (present && start < 0) start = p;
            if (!present && start >= 0)
            {
                var chunk = new byte[(p - start) * Page];
                mapped.AsSpan(start * Page, Math.Min(chunk.Length, mapped.Length - start * Page)).CopyTo(chunk);
                builder.Memory.Add((spec.Base + (ulong)start * Page, chunk));
                start = -1;
            }
        }
        string dump = dir.File($"runtime-{Guid.NewGuid():N}.dmp");
        File.WriteAllBytes(dump, builder.Build());
        return new RuntimeSectionImage(dump, imageDir, rva, spec.Base, name);
    }

    private static int Header(byte[] file, string section)
    {
        int nt = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(0x3C));
        int count = BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(nt + 6));
        int table = nt + 24 + BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(nt + 20));
        for (int i = 0; i < count; i++)
        {
            int h = table + 40 * i;
            if (Encoding.ASCII.GetString(file, h, 8).TrimEnd('\0') == section) return h;
        }
        throw new ArgumentException("Section not found.", nameof(section));
    }

    private static uint RawOffset(byte[] file, string section) =>
        BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(Header(file, section) + 20));

    // Sets SizeOfRawData (rounded to the file alignment); 0 also clears the pointer.
    private static void SetRawData(byte[] file, string section, uint rawSize, uint fileAlignment)
    {
        int h = Header(file, section);
        uint aligned = (rawSize + fileAlignment - 1) / fileAlignment * fileAlignment;
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(h + 16), aligned);
        if (rawSize == 0) BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(h + 20), 0);
    }
}
