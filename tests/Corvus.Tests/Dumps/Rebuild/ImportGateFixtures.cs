using System.Buffers.Binary;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>An app whose address table holds two library pointers and a pointer into itself, next to its own file.</summary>
internal static class ImportGateFixtures
{
    public const ulong AppBase = 0x140000000UL;
    public const ulong LibBase = 0x180000000UL;

    /// <summary>
    /// Builds the dump with the import directory zeroed in memory and a folder holding the app file:
    /// <paramref name="fileDirectory"/> keeps the file's import directory, else the file has none.
    /// </summary>
    public static (MinidumpFile Dump, string Folder) Build(TempDir dir, bool fileDirectory)
    {
        var lib = RebuildFixtures.Build(new PeSpec(true, [new SectionSpec(".text", 0x60000020, new byte[0x40])],
            Exports: [new ExportSpec("Alpha", 0x1000), new ExportSpec("Beta", 0x1008)]));
        var built = RebuildFixtures.Build(new PeSpec(true, [new SectionSpec(".text", 0x60000020, new byte[0x40])],
            Exports: [new ExportSpec("Self", 0x1000)], Imports: [new ImportSpec("lib.dll", ["Alpha", "Beta", "Gamma"])]));
        var memory = (byte[])built.Bytes.Clone();
        ZeroDirectory(memory);
        var file = fileDirectory ? built.Bytes : memory;

        string folder = Directory.CreateDirectory(dir.File("bin")).FullName;
        File.WriteAllBytes(Path.Combine(folder, "app.exe"), file);
        var values = new Dictionary<string, ulong> { ["lib.dll!Gamma"] = AppBase + 0x1000 };
        var app = new PeBuilt(memory, built.IatSlots);
        var dump = RebuildFixtures.Dump(dir, new Placed("app.exe", app, AppBase, IatValues: values), new Placed("lib.dll", lib, LibBase));
        return (dump, folder);
    }

    private static void ZeroDirectory(byte[] bytes)
    {
        int nt = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3C));
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(nt + 24 + 112 + 8), 0);
    }
}
