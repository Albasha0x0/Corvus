using System.Buffers.Binary;
using System.Text;
using Corvus.Native;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Import slots bound through API set contracts, forwarded exports and ordinals.</summary>
public sealed class ImportRedirectsApiSetTests : IDisposable
{
    private const ulong AppBase = 0x140000000UL, LibBase = 0x180000000UL, TargetBase = 0x190000000UL;
    private const string Contract = "api-ms-win-core-synch-l1-2-0.dll";

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static PeSpec Spec(IReadOnlyList<ImportSpec>? imports = null, IReadOnlyList<ExportSpec>? exports = null) => new(true,
        [new SectionSpec(".text", 0x60000020, [0x90, 0xC3, 0xCC, 0xCC])], Imports: imports, Exports: exports);

    // A version 6 map with one contract: name, host, no per-importer values.
    private static ApiSetSchema Map(string contract, string host)
    {
        string name = Path.GetFileNameWithoutExtension(contract);
        var text = new List<byte>();
        int namesAt = 28 + 24 + 20;
        int Add(string s)
        {
            int at = namesAt + text.Count;
            text.AddRange(Encoding.Unicode.GetBytes(s));
            return at;
        }
        int nameAt = Add(name), hostAt = Add(host);
        var map = new byte[namesAt + text.Count];
        void W(int at, int value) => BinaryPrimitives.WriteInt32LittleEndian(map.AsSpan(at), value);
        W(0, 6);
        W(4, map.Length);
        W(12, 1);
        W(16, 28);
        W(28 + 4, nameAt);
        W(28 + 8, name.Length * 2);
        W(28 + 12, name[..name.LastIndexOf('-')].Length * 2);
        W(28 + 16, 28 + 24);
        W(28 + 20, 1);
        W(52 + 4, 0);
        W(52 + 12, hostAt);
        W(52 + 16, host.Length * 2);
        text.CopyTo(map, namesAt);
        return ApiSetSchema.Parse(map)!;
    }

    private IReadOnlyList<ImportRedirect> Run(PeBuilt app, IReadOnlyDictionary<string, ulong> values, ApiSetSchema? map, params Placed[] others)
    {
        using var dump = RebuildFixtures.Dump(_dir, [new Placed("app.exe", app, AppBase, IatValues: values), .. others]);
        var module = dump.Modules.First(m => m.FileName == "app.exe");
        var mapped = new byte[module.Size];
        dump.ReadMemory(module.Base, mapped);
        var captured = new CapturedImage(RebuildTarget.Of(module), mapped, Enumerable.Repeat(true, mapped.Length / 0x1000).ToArray(), "mapped");
        return ImportRedirects.Find(mapped, captured, new ExportMap(dump), dump, map);
    }

    private static PeBuilt Lib() => RebuildFixtures.Build(Spec(exports: [new ExportSpec("InitOnceComplete", 0x1000)]));

    private static PeBuilt ContractApp() => RebuildFixtures.Build(Spec([new ImportSpec(Contract, ["InitOnceComplete"])]));

    [Fact]
    public void A_slot_holding_the_host_export_through_a_contract_is_not_reported()
    {
        var app = ContractApp();
        var values = new Dictionary<string, ulong> { [Contract + "!InitOnceComplete"] = LibBase + 0x1000 };

        Assert.Empty(Run(app, values, Map(Contract, "lib.dll"), new Placed("lib.dll", Lib(), LibBase)));
    }

    [Fact]
    public void A_slot_pointing_elsewhere_through_a_contract_is_a_redirect_into_the_module_it_points_at()
    {
        var other = RebuildFixtures.Build(Spec(exports: [new ExportSpec("Hook", 0x1000)]));
        var app = ContractApp();
        var values = new Dictionary<string, ulong> { [Contract + "!InitOnceComplete"] = TargetBase + 0x1000 };

        var row = Assert.Single(Run(app, values, Map(Contract, "lib.dll"), new Placed("lib.dll", Lib(), LibBase), new Placed("target.dll", other, TargetBase)));

        Assert.Equal("redirected", row.State);
        Assert.Equal(LibBase + 0x1000, row.Expected);
        Assert.Equal("target.dll!Hook", row.Target);
        Assert.Equal("dump", row.Via);
    }

    [Fact]
    public void A_contract_missing_from_the_map_stays_unknown_with_the_reason()
    {
        var app = ContractApp();
        var values = new Dictionary<string, ulong> { [Contract + "!InitOnceComplete"] = LibBase + 0x1000 };

        var row = Assert.Single(Run(app, values, Map("api-ms-win-core-other-l1-1-0.dll", "lib.dll"), new Placed("lib.dll", Lib(), LibBase)));

        Assert.Equal("unknown", row.State);
        Assert.Contains("is not in the dump api set map", row.Reason);
        Assert.Equal("dump", row.Via);
    }

    [Fact]
    public void A_contract_whose_host_is_not_loaded_names_the_host()
    {
        var app = ContractApp();
        var values = new Dictionary<string, ulong> { [Contract + "!InitOnceComplete"] = LibBase + 0x1000 };

        var row = Assert.Single(Run(app, values, Map(Contract, "absent.dll")));

        Assert.Equal("unknown", row.State);
        Assert.Contains("absent.dll is not a loaded module", row.Reason);
    }

    [Fact]
    public void A_forwarded_export_is_followed_to_the_module_that_holds_it()
    {
        var target = RebuildFixtures.Build(Spec(exports: [new ExportSpec("omega", 0x1000)]));
        var lib = RebuildFixtures.Build(Spec(exports: [new ExportSpec("alpha", 0x1000), new ExportSpec("target.omega", 0x1000)]));
        lib = PeEdit.ForwardExport(lib, "alpha", "target.omega");
        var app = RebuildFixtures.Build(Spec([new ImportSpec("lib.dll", ["alpha"])]));
        var held = new Dictionary<string, ulong> { ["lib.dll!alpha"] = TargetBase + 0x1000 };
        var moved = new Dictionary<string, ulong> { ["lib.dll!alpha"] = LibBase + 0x1000 };

        Assert.Empty(Run(app, held, null, new Placed("lib.dll", lib, LibBase), new Placed("target.dll", target, TargetBase)));
        var row = Assert.Single(Run(app, moved, null, new Placed("lib.dll", lib, LibBase), new Placed("target.dll", target, TargetBase)));
        Assert.Equal(TargetBase + 0x1000, row.Expected);
    }

    [Fact]
    public void An_import_by_ordinal_is_checked_against_the_export_with_that_ordinal()
    {
        var lib = RebuildFixtures.Build(Spec(exports: [new ExportSpec("alpha", 0x1000)]));
        var app = RebuildFixtures.Build(Spec([new ImportSpec("lib.dll", ["alpha"])]));
        app = PeEdit.ImportByOrdinal(app, "lib.dll!alpha", 1);
        var held = new Dictionary<string, ulong> { ["lib.dll!alpha"] = LibBase + 0x1000 };
        var moved = new Dictionary<string, ulong> { ["lib.dll!alpha"] = LibBase + 0x1001 };

        Assert.Empty(Run(app, held, null, new Placed("lib.dll", lib, LibBase)));
        var row = Assert.Single(Run(app, moved, null, new Placed("lib.dll", lib, LibBase)));
        Assert.Equal("lib.dll!#1", row.Import);
        Assert.Equal(LibBase + 0x1000, row.Expected);
    }
}

/// <summary>Byte edits of a built synthetic PE for cases the builder does not describe.</summary>
internal static class PeEdit
{
    private static int Offset(byte[] pe, uint rva)
    {
        int nt = BinaryPrimitives.ReadInt32LittleEndian(pe.AsSpan(0x3C));
        int count = BinaryPrimitives.ReadUInt16LittleEndian(pe.AsSpan(nt + 6));
        int table = nt + 24 + BinaryPrimitives.ReadUInt16LittleEndian(pe.AsSpan(nt + 20));
        for (int i = 0; i < count; i++)
        {
            var s = pe.AsSpan(table + 40 * i);
            uint at = BinaryPrimitives.ReadUInt32LittleEndian(s[12..]), raw = BinaryPrimitives.ReadUInt32LittleEndian(s[16..]);
            if (rva >= at && rva < at + raw) return (int)(BinaryPrimitives.ReadUInt32LittleEndian(s[20..]) + rva - at);
        }
        throw new ArgumentException($"RVA {rva:X} is in no section.");
    }

    private static uint U32(byte[] pe, uint rva) => BinaryPrimitives.ReadUInt32LittleEndian(pe.AsSpan(Offset(pe, rva)));

    /// <summary>Makes export <paramref name="name"/> forward to the text of export <paramref name="textName"/>.</summary>
    public static PeBuilt ForwardExport(PeBuilt built, string name, string textName)
    {
        var pe = (byte[])built.Bytes.Clone();
        int nt = BinaryPrimitives.ReadInt32LittleEndian(pe.AsSpan(0x3C));
        uint dir = BinaryPrimitives.ReadUInt32LittleEndian(pe.AsSpan(nt + 24 + 112));
        uint functions = U32(pe, dir + 28), names = U32(pe, dir + 32), ordinals = U32(pe, dir + 36), count = U32(pe, dir + 24);
        uint textRva = 0;
        int index = -1;
        for (uint i = 0; i < count; i++)
        {
            uint nameRva = U32(pe, names + 4 * i);
            string text = Encoding.ASCII.GetString(pe, Offset(pe, nameRva), textName.Length + 1);
            string found = Encoding.ASCII.GetString(pe, Offset(pe, nameRva), name.Length + 1);
            if (text == textName + "\0") textRva = nameRva;
            if (found == name + "\0") index = BinaryPrimitives.ReadUInt16LittleEndian(pe.AsSpan(Offset(pe, ordinals + 2 * i)));
        }
        if (textRva == 0 || index < 0) throw new ArgumentException("Export not found.");
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(Offset(pe, functions + 4 * (uint)index)), textRva);
        return built with { Bytes = pe };
    }

    /// <summary>Rewrites the lookup entry of a single-function module to import by <paramref name="ordinal"/>.</summary>
    public static PeBuilt ImportByOrdinal(PeBuilt built, string key, ushort ordinal)
    {
        var pe = (byte[])built.Bytes.Clone();
        uint lookup = built.IatSlots[key] - 16;
        BinaryPrimitives.WriteUInt64LittleEndian(pe.AsSpan(Offset(pe, lookup)), 1UL << 63 | ordinal);
        return built with { Bytes = pe };
    }
}
