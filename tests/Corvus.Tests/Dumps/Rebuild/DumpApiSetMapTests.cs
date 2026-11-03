using System.Buffers.Binary;
using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>The API set map a minidump holds is found through a thread TEB and the PEB.</summary>
public sealed class DumpApiSetMapTests : IDisposable
{
    private const ulong AppBase = 0x140000000UL, LibBase = 0x180000000UL;
    private const ulong Peb = 0x7FFD0000UL, MapAt = 0x7FFE0000UL;
    private const string Contract = "api-ms-win-core-synch-l1-2-0.dll";

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    // The builder gives thread 1 the TEB 0x7FF000000000 + 1 * 0x2000.
    private static ulong Teb => 0x7FF000002000UL;

    private static PeSpec Spec(IReadOnlyList<ImportSpec>? imports = null, IReadOnlyList<ExportSpec>? exports = null) => new(true,
        [new SectionSpec(".text", 0x60000020, [0x90, 0xC3, 0xCC, 0xCC])], Imports: imports, Exports: exports);

    // Copies the placed images into a dump that also holds a thread, its
    // TEB, the PEB and a map.
    private MinidumpFile Dump(bool withTeb, bool wide = true, string host = "lib.dll")
    {
        var lib = RebuildFixtures.Build(Spec(exports: [new ExportSpec("InitOnceComplete", 0x1000)]));
        var app = RebuildFixtures.Build(Spec([new ImportSpec(Contract, ["InitOnceComplete"])]));
        var values = new Dictionary<string, ulong> { [Contract + "!InitOnceComplete"] = LibBase + 0x1000 };
        using var placed = RebuildFixtures.Dump(_dir, new Placed("app.exe", app, AppBase, IatValues: values), new Placed("lib.dll", lib, LibBase));

        var builder = new MinidumpBuilder { ProcessorArchitecture = wide ? (ushort)9 : (ushort)0 };
        foreach (var module in placed.Modules)
        {
            builder.Modules.Add(new MinidumpBuilder.Module(module.Base, module.Size, module.TimeDateStamp, module.FileName));
            var bytes = new byte[module.Size];
            placed.ReadMemory(module.Base, bytes);
            builder.Memory.Add((module.Base, bytes));
        }
        builder.Threads.Add(new MinidumpBuilder.Thread(1, 0, MinidumpBuilder.ContextX64(0, 0)));
        if (withTeb)
        {
            var teb = new byte[0x1000];
            if (wide) BinaryPrimitives.WriteUInt64LittleEndian(teb.AsSpan(0x60), Peb);
            else BinaryPrimitives.WriteUInt32LittleEndian(teb.AsSpan(0x30), (uint)Peb);
            builder.Memory.Add((Teb, teb));
        }
        var peb = new byte[0x1000];
        if (wide) BinaryPrimitives.WriteUInt64LittleEndian(peb.AsSpan(0x68), MapAt);
        else BinaryPrimitives.WriteUInt32LittleEndian(peb.AsSpan(0x38), (uint)MapAt);
        builder.Memory.Add((Peb, peb));
        builder.Memory.Add((MapAt, ImportRedirectsApiSetTests.MapBytes(Contract, host)));
        builder.Memory.Sort((a, b) => a.Start.CompareTo(b.Start));
        string path = _dir.File($"env-{Guid.NewGuid():N}.dmp");
        File.WriteAllBytes(path, builder.Build());
        return MinidumpFile.Open(path);
    }

    private static IReadOnlyList<ImportRedirect> Find(MinidumpFile dump, ApiSetSchema? map)
    {
        var module = dump.Modules.First(m => m.FileName == "app.exe");
        var mapped = new byte[module.Size];
        dump.ReadMemory(module.Base, mapped);
        var captured = new CapturedImage(RebuildTarget.Of(module), mapped, Enumerable.Repeat(true, mapped.Length / 0x1000).ToArray(), "mapped");
        return ImportRedirects.Find(mapped, captured, new ExportMap(dump), dump, map);
    }

    [Fact]
    public void A_thread_TEB_leads_to_the_API_set_map_of_the_PEB()
    {
        using var dump = Dump(withTeb: true);

        Assert.Equal(MapAt, ProcessEnvironment.ApiSetMapAddress(dump, out var reason));
        Assert.Null(reason);
    }

    [Fact]
    public void A_32_bit_dump_reads_the_32_bit_TEB_and_PEB_offsets()
    {
        using var dump = Dump(withTeb: true, wide: false);

        Assert.Equal(MapAt, ProcessEnvironment.ApiSetMapAddress(dump, out _));
    }

    [Fact]
    public void A_contract_slot_resolves_through_the_map_the_dump_holds()
    {
        using var dump = Dump(withTeb: true, host: "absent.dll");
        var map = ImportRedirects.ReadApiSetMap(dump, ProcessEnvironment.ApiSetMapAddress(dump, out _)!.Value);

        var row = Assert.Single(Find(dump, map));

        Assert.Equal("dump", row.Via);
        Assert.Contains("absent.dll is not a loaded module", row.Reason);
    }

    [Fact]
    public void A_dump_without_the_TEB_page_names_the_missing_page_and_has_no_address()
    {
        using var dump = Dump(withTeb: false);

        Assert.Null(ProcessEnvironment.ApiSetMapAddress(dump, out var reason));
        Assert.Contains("TEB", reason);
    }

    [Fact]
    public void A_dump_without_the_TEB_page_resolves_contracts_through_the_system_map()
    {
        using var dump = Dump(withTeb: false);

        var row = Assert.Single(Find(dump, null));

        Assert.Equal("system", row.Via);
    }
}
