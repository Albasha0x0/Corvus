using System.Buffers.Binary;
using System.Text;
using Corvus.Native;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Import slots whose forwarder names a contract, and ordinal imports across an ordinal base.</summary>
public sealed class ImportRedirectsForwardedContractTests : IDisposable
{
    private const ulong AppBase = 0x140000000UL, ABase = 0x180000000UL, BBase = 0x190000000UL;
    private const string Contract = "api-ms-x-l1-1-0";

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static PeSpec Spec(IReadOnlyList<ImportSpec>? imports = null, IReadOnlyList<ExportSpec>? exports = null) => new(true,
        [new SectionSpec(".text", 0x60000020, [0x90, 0xC3, 0xCC, 0xCC])], Imports: imports, Exports: exports);

    // A version 6 map with one contract and its value entries in order.
    private static ApiSetSchema Map(params (string Importer, string Host)[] values)
    {
        var text = new List<byte>();
        int namesAt = 28 + 24 + 20 * values.Length;
        int Add(string s)
        {
            int at = namesAt + text.Count;
            text.AddRange(Encoding.Unicode.GetBytes(s));
            return at;
        }
        int nameAt = Add(Contract);
        var placed = values.Select(v => (v.Importer.Length == 0 ? 0 : Add(v.Importer), Add(v.Host))).ToArray();
        var map = new byte[namesAt + text.Count];
        void W(int at, int value) => BinaryPrimitives.WriteInt32LittleEndian(map.AsSpan(at), value);
        W(0, 6);
        W(4, map.Length);
        W(12, 1);
        W(16, 28);
        W(28 + 4, nameAt);
        W(28 + 8, Contract.Length * 2);
        W(28 + 12, Contract[..Contract.LastIndexOf('-')].Length * 2);
        W(28 + 16, 28 + 24);
        W(28 + 20, values.Length);
        for (int i = 0; i < values.Length; i++)
        {
            int at = 52 + 20 * i;
            W(at + 4, placed[i].Item1);
            W(at + 8, values[i].Importer.Length * 2);
            W(at + 12, placed[i].Item2);
            W(at + 16, values[i].Host.Length * 2);
        }
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

    private static PeBuilt Forwarding() => PeEdit.ForwardExport(
        RebuildFixtures.Build(Spec(exports: [new ExportSpec("F", 0x1000), new ExportSpec(Contract + ".F", 0x1000)])), "F", Contract + ".F");

    private static PeBuilt Holder() => RebuildFixtures.Build(Spec(exports: [new ExportSpec("F", 0x1000)]));

    private static PeBuilt App() => RebuildFixtures.Build(Spec([new ImportSpec("a.dll", ["F"])]));

    private static Dictionary<string, ulong> Slot(ulong value) => new() { ["a.dll!F"] = value };

    [Fact]
    public void A_forwarder_to_a_contract_resolves_through_the_exception_entry_of_the_forwarding_module()
    {
        var map = Map(("", "a.dll"), ("a.dll", "b.dll"));

        Assert.Empty(Run(App(), Slot(BBase + 0x1000), map, new Placed("a.dll", Forwarding(), ABase), new Placed("b.dll", Holder(), BBase)));
    }

    [Fact]
    public void A_forwarder_to_a_contract_that_hosts_back_uses_the_next_host_of_the_entry()
    {
        var map = Map(("", "a.dll"), ("other.dll", "b.dll"));

        Assert.Empty(Run(App(), Slot(BBase + 0x1000), map, new Placed("a.dll", Forwarding(), ABase), new Placed("b.dll", Holder(), BBase)));
    }

    [Fact]
    public void A_contract_that_only_hosts_back_to_the_forwarding_module_stays_unknown()
    {
        var map = Map(("", "a.dll"));

        var row = Assert.Single(Run(App(), Slot(BBase + 0x1000), map, new Placed("a.dll", Forwarding(), ABase)));

        Assert.Equal("unknown", row.State);
        Assert.Equal("the contract resolves back to a.dll", row.Reason);
    }

    [Fact]
    public void An_ordinal_import_is_matched_across_a_non_one_ordinal_base()
    {
        var lib = PeEdit.OrdinalBase(Holder(), 270);
        var app = PeEdit.ImportByOrdinal(App(), "a.dll!F", 270);

        Assert.Empty(Run(app, Slot(ABase + 0x1000), null, new Placed("a.dll", lib, ABase)));
        var row = Assert.Single(Run(app, Slot(ABase + 0x1001), null, new Placed("a.dll", lib, ABase)));
        Assert.Equal("a.dll!#270", row.Import);
        Assert.Equal(ABase + 0x1000, row.Expected);
    }

    [Fact]
    public void An_ordinal_import_of_a_named_forwarded_export_follows_the_forwarder()
    {
        var map = Map(("", "a.dll"), ("a.dll", "b.dll"));
        var app = PeEdit.ImportByOrdinal(App(), "a.dll!F", 1);

        Assert.Empty(Run(app, Slot(BBase + 0x1000), map, new Placed("a.dll", Forwarding(), ABase), new Placed("b.dll", Holder(), BBase)));
    }
}
