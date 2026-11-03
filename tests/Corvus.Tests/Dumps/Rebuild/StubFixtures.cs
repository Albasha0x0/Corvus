using System.Buffers.Binary;

namespace Corvus.Tests;

/// <summary>How a stub transfers control to its target.</summary>
public enum StubForm
{
    X64MovJmp,
    X64JmpRip,
    X64PushRet,
    X86Jmp32,
    X86PushRet,
    X86JmpAbs,
    Arm64LdrBr,
    Arm64B,
}

/// <summary>
/// A dump of a main image patched to jump through stubs in an unbacked region, the image files, and the addresses to
/// assert; <paramref name="Export"/> is the provider's export the last stub reaches.
/// </summary>
internal sealed record StubDump(
    string DumpPath,
    string ImageFolder,
    ulong MainBase,
    ulong PatchSite,
    IReadOnlyList<ulong> Stubs,
    ulong Export,
    ulong Region);

/// <summary>A dump whose code section holds stubs of one shape, with the stub and target addresses.</summary>
internal sealed record RepeatedDump(
    string DumpPath,
    string ImageFolder,
    ulong ImageBase,
    IReadOnlyList<ulong> Stubs,
    IReadOnlyList<ulong> Targets);

/// <summary>Builds dumps of code patched to jump through stubs, chains of stubs, loops and repeated stubs.</summary>
internal static class StubFixtures
{
    /// <summary>The offset of the patched function start in the main image's code section.</summary>
    public const uint SiteRva = 0x1010;

    /// <summary>The export RVA in the provider image.</summary>
    public const uint ExportRva = 0x1020;

    /// <summary>The distance between stubs in the unbacked region.</summary>
    public const uint StubSpacing = 0x40;

    /// <summary>The offset of the first stub in the repeated-stub image.</summary>
    public const uint RepeatedRva = 0x1000;

    /// <summary>The distance between repeated stubs.</summary>
    public const uint RepeatedSpacing = 0x10;

    private const ushort X64 = 0x8664, X86 = 0x14C, Arm64 = 0xAA64;
    private const uint ImageRegion = 0x1000000, Rx = 0x20;

    /// <summary>
    /// A function start patched with a jump to a stub, then <paramref name="hops"/> (1 or 2) stubs to the export.
    /// Throws when the form does not belong to the machine or the hop count is out of range.
    /// </summary>
    public static StubDump Chain(TempDir dir, ushort machine, StubForm form, int hops)
    {
        if (hops is < 1 or > 2) throw new ArgumentOutOfRangeException(nameof(hops), "A chain has 1 or 2 stubs.");
        var (main, provider, region) = Place(machine, form);
        return Build(dir, machine, form, main, provider, region, hops, loop: false);
    }

    /// <summary>
    /// A function start patched with a jump to a stub, and two stubs that jump to each other.
    /// Throws when the form does not belong to the machine.
    /// </summary>
    public static StubDump Loop(TempDir dir, ushort machine, StubForm form)
    {
        var (main, provider, region) = Place(machine, form);
        return Build(dir, machine, form, main, provider, region, 2, loop: true);
    }

    /// <summary>
    /// An image whose code section holds <paramref name="count"/> jumps by rel32 with different displacements,
    /// written in memory over zeros in the file. Throws when the count is outside 1 to 128.
    /// </summary>
    public static RepeatedDump Repeated(TempDir dir, bool is64, int count)
    {
        if (count is < 1 or > 128) throw new ArgumentOutOfRangeException(nameof(count), "The count is 1 to 128.");
        ulong baseAddress = is64 ? 0x140000000UL : 0x10000000UL;
        var spec = new PeSpec(is64, [new SectionSpec(".text", 0x60000020, new byte[0x1000])], ImageBase: baseAddress);
        var file = RebuildFixtures.Pe(spec);
        var mapped = RebuildFixtures.Mapped(file);
        var stubs = new List<ulong>();
        var targets = new List<ulong>();
        for (int i = 0; i < count; i++)
        {
            uint site = RepeatedRva + (uint)i * RepeatedSpacing;
            uint target = 0x1800 + (uint)i * 0x20;
            mapped[(int)site] = 0xE9;
            BinaryPrimitives.WriteInt32LittleEndian(mapped.AsSpan((int)site + 1), (int)target - (int)(site + 5));
            stubs.Add(baseAddress + site);
            targets.Add(baseAddress + target);
        }

        string folder = Folder(dir);
        File.WriteAllBytes(Path.Combine(folder, "main.dll"), file);
        var builder = new MinidumpBuilder { ProcessorArchitecture = is64 ? (ushort)9 : (ushort)0 };
        AddImage(builder, "main.dll", file, mapped, baseAddress);
        string path = dir.File($"repeated-{Guid.NewGuid():N}.dmp");
        File.WriteAllBytes(path, builder.Build());
        return new RepeatedDump(path, folder, baseAddress, stubs, targets);
    }

    private static (ulong Main, ulong Provider, ulong Region) Place(ushort machine, StubForm form)
    {
        bool valid = form switch
        {
            StubForm.X64MovJmp or StubForm.X64JmpRip or StubForm.X64PushRet => machine == X64,
            StubForm.X86Jmp32 or StubForm.X86PushRet or StubForm.X86JmpAbs => machine == X86,
            _ => machine == Arm64,
        };
        if (!valid) throw new ArgumentException($"Form {form} does not belong to machine 0x{machine:X}.", nameof(form));
        // A push of a 32-bit immediate reaches only addresses below 2 GB in 64-bit code.
        bool low = machine == X86 || form == StubForm.X64PushRet;
        return low ? (0x10000000UL, 0x20000000UL, 0x30000000UL) : (0x140000000UL, 0x141000000UL, 0x142000000UL);
    }

    private static StubDump Build(TempDir dir, ushort machine, StubForm form, ulong main, ulong provider, ulong region, int hops, bool loop)
    {
        bool is64 = machine != X86;
        byte[] nop = machine == Arm64 ? [0x1F, 0x20, 0x03, 0xD5] : [0x90];
        byte[] ret = machine == Arm64 ? [0xC0, 0x03, 0x5F, 0xD6] : [0xC3];
        var mainCode = Filled(nop, 0x100);
        var providerCode = Filled(nop, 0x100);
        ret.CopyTo(providerCode, (int)(ExportRva - 0x1000));

        var mainSpec = new PeSpec(is64, [new SectionSpec(".text", 0x60000020, mainCode)], ImageBase: main);
        var providerSpec = new PeSpec(is64, [new SectionSpec(".text", 0x60000020, providerCode)], ImageBase: provider,
            Exports: [new ExportSpec("Target", ExportRva)]);
        var mainFile = SetMachine(RebuildFixtures.Pe(mainSpec), machine);
        var providerFile = SetMachine(RebuildFixtures.Pe(providerSpec), machine);
        var mainMapped = RebuildFixtures.Mapped(mainFile);
        var providerMapped = RebuildFixtures.Mapped(providerFile);

        ulong site = main + SiteRva;
        ulong export = provider + ExportRva;
        var stubs = new List<ulong>();
        for (int i = 0; i < hops; i++) stubs.Add(region + (ulong)i * StubSpacing);

        var regionBytes = new byte[0x1000];
        Encode(form, site, stubs[0], mainMapped.AsSpan((int)SiteRva));
        for (int i = 0; i < hops; i++)
        {
            ulong next = i + 1 < hops ? stubs[i + 1] : loop ? stubs[0] : export;
            Encode(form, stubs[i], next, regionBytes.AsSpan(i * (int)StubSpacing));
        }

        string folder = Folder(dir);
        File.WriteAllBytes(Path.Combine(folder, "main.dll"), mainFile);
        File.WriteAllBytes(Path.Combine(folder, "provider.dll"), providerFile);
        var builder = new MinidumpBuilder { ProcessorArchitecture = machine == X86 ? (ushort)0 : machine == Arm64 ? (ushort)12 : (ushort)9 };
        AddImage(builder, "main.dll", mainFile, mainMapped, main);
        AddImage(builder, "provider.dll", providerFile, providerMapped, provider);
        builder.Memory.Add((region, regionBytes));
        builder.Regions.Add(new MinidumpBuilder.Region(region, 0x1000, Rx));
        builder.Memory.Sort((a, b) => a.Start.CompareTo(b.Start));
        builder.Regions.Sort((a, b) => a.Base.CompareTo(b.Base));
        string path = dir.File($"stubs-{Guid.NewGuid():N}.dmp");
        File.WriteAllBytes(path, builder.Build());
        return new StubDump(path, folder, main, site, stubs, export, region);
    }

    // Writes the instruction of a form at an address; data it reads follows the code.
    private static void Encode(StubForm form, ulong at, ulong target, Span<byte> into)
    {
        switch (form)
        {
            case StubForm.X64MovJmp:
                into[0] = 0x48;
                into[1] = 0xB8;
                BinaryPrimitives.WriteUInt64LittleEndian(into[2..], target);
                into[10] = 0xFF;
                into[11] = 0xE0;
                break;
            case StubForm.X64JmpRip:
                into[0] = 0xFF;
                into[1] = 0x25;
                BinaryPrimitives.WriteUInt32LittleEndian(into[2..], 0);
                BinaryPrimitives.WriteUInt64LittleEndian(into[6..], target);
                break;
            case StubForm.X64PushRet:
            case StubForm.X86PushRet:
                into[0] = 0x68;
                BinaryPrimitives.WriteUInt32LittleEndian(into[1..], checked((uint)target));
                into[5] = 0xC3;
                break;
            case StubForm.X86Jmp32:
                into[0] = 0xE9;
                BinaryPrimitives.WriteInt32LittleEndian(into[1..], (int)(target - (at + 5)));
                break;
            case StubForm.X86JmpAbs:
                into[0] = 0xFF;
                into[1] = 0x25;
                BinaryPrimitives.WriteUInt32LittleEndian(into[2..], checked((uint)at + 6));
                BinaryPrimitives.WriteUInt32LittleEndian(into[6..], checked((uint)target));
                break;
            case StubForm.Arm64LdrBr:
                BinaryPrimitives.WriteUInt32LittleEndian(into, 0x58000050);
                BinaryPrimitives.WriteUInt32LittleEndian(into[4..], 0xD61F0200);
                BinaryPrimitives.WriteUInt64LittleEndian(into[8..], target);
                break;
            case StubForm.Arm64B:
                long words = ((long)target - (long)at) / 4;
                BinaryPrimitives.WriteUInt32LittleEndian(into, 0x14000000 | ((uint)words & 0x03FFFFFF));
                break;
        }
    }

    private static void AddImage(MinidumpBuilder builder, string name, byte[] file, byte[] mapped, ulong baseAddress)
    {
        int nt = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(0x3C));
        uint stamp = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(nt + 8));
        builder.Modules.Add(new MinidumpBuilder.Module(baseAddress, (uint)mapped.Length, stamp, name));
        builder.Memory.Add((baseAddress, mapped));
        builder.Regions.Add(new MinidumpBuilder.Region(baseAddress, (ulong)mapped.Length, Rx, Type: ImageRegion));
    }

    private static byte[] SetMachine(byte[] file, ushort machine)
    {
        int nt = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(0x3C));
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(nt + 4), machine);
        return file;
    }

    private static string Folder(TempDir dir) => Directory.CreateDirectory(dir.File($"images-{Guid.NewGuid():N}")).FullName;

    private static byte[] Filled(byte[] unit, int length)
    {
        var bytes = new byte[length];
        for (int i = 0; i < length; i++) bytes[i] = unit[i % unit.Length];
        return bytes;
    }
}
