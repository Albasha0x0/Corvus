using System.Buffers.Binary;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>A module whose import directory is zeroed and a second module whose exports its slots point at.</summary>
internal static class ImportScanFixtures
{
    public const ulong AppBase = 0x140000000UL;
    public const ulong LibBase = 0x180000000UL;

    /// <summary>Builds both modules in one dump; with <paramref name="iatDirectory"/> the app keeps data directory 12.</summary>
    public static (MinidumpFile Dump, PeBuilt App) Build(TempDir dir, IReadOnlyList<string> functions, bool iatDirectory)
    {
        var lib = RebuildFixtures.Build(new PeSpec(true, [new SectionSpec(".text", 0x60000020, new byte[0x40])],
            Exports: [new ExportSpec("Alpha", 0x1000), new ExportSpec("Beta", 0x1008)]));
        var built = RebuildFixtures.Build(new PeSpec(true, [new SectionSpec(".text", 0x60000020, new byte[0x40])],
            Imports: [new ImportSpec("lib.dll", functions)]));
        var bytes = (byte[])built.Bytes.Clone();
        int nt = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3C));
        int dirs = nt + 24 + 112;
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(dirs + 8), 0);
        if (iatDirectory)
        {
            uint first = built.IatSlots.Values.Min();
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(dirs + 12 * 8), first);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(dirs + 12 * 8 + 4), (uint)(8 * functions.Count));
        }
        var app = new PeBuilt(bytes, built.IatSlots);
        var dump = RebuildFixtures.Dump(dir, new Placed("app.exe", app, AppBase), new Placed("lib.dll", lib, LibBase));
        return (dump, app);
    }

    /// <summary>Reads the whole module of <paramref name="dump"/> as a fully captured mapped image.</summary>
    public static CapturedImage Capture(MinidumpFile dump, string name)
    {
        var module = dump.Modules.First(m => m.FileName == name);
        var image = new byte[module.Size];
        dump.ReadMemory(module.Base, image);
        return new CapturedImage(RebuildTarget.Of(module), image, Enumerable.Repeat(true, (image.Length + 0xFFF) / 0x1000).ToArray(), "mapped");
    }
}
