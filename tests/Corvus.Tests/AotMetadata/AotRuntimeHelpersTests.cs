using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Pe;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>Runtime helpers of a small x64 image: exported entries that jump to internal functions, and methods that share first and null-check calls.</summary>
public sealed class AotRuntimeHelpersTests : IDisposable
{
    private const uint ObjectNew = 0x1000, ClassInit = 0x1010, Raise = 0x1020, ObjectInit = 0x1030, SameTarget = 0x1040, Indirect = 0x1050;
    private static readonly (uint Start, uint First)[] ThreeMethods = [(0x1800, 0x1400), (0x1820, 0x1400), (0x1840, 0x1400)];
    private static readonly (string, uint)[] NewAndInit = [("il2cpp_object_new", ObjectNew), ("il2cpp_runtime_class_init", ClassInit)];
    private static readonly (string, uint)[] WithRaise = [.. NewAndInit, ("il2cpp_raise_exception", Raise)];

    private readonly TempDir _dir = new();
    private readonly Env _env = new();

    public void Dispose()
    {
        _env.Dispose();
        _dir.Dispose();
    }

    private static byte[] Rel(uint from, uint to) => BitConverter.GetBytes((int)(to - from));

    /// <summary>
    /// A .text section at 0x1000 of 0x1000 bytes and an export table of <paramref name="exports"/>. The wrappers
    /// at 0x1000-0x1050 jump to 0x1200 (object new), 0x1220 (class init), 0x1240 (raise), call 0x1260 then jump to
    /// 0x1280 (object init), jump to 0x1200 again, and jump through memory. Each method calls its first target,
    /// the helper at 0x1380 (a lower address than the usual first target), then the thrower at 0x1500, which
    /// calls 0x1240 and does not return.
    /// </summary>
    internal static byte[] Image(IReadOnlyList<(string Name, uint Rva)> exports, IReadOnlyList<(uint Start, uint First)> methods, IReadOnlyList<uint>? secondThrowerCallers = null)
    {
        var b = new PeBuilder { ImageBase = 0x180000000 };
        var code = Enumerable.Repeat((byte)0xCC, 0x1000).ToArray();
        void Put(uint rva, params byte[] bytes) => bytes.CopyTo(code, (int)(rva - 0x1000));
        Put(ObjectNew, [0xE9, .. Rel(0x1005, 0x1200)]);
        Put(ClassInit, [0xE9, .. Rel(0x1015, 0x1220)]);
        Put(Raise, [0xE9, .. Rel(0x1025, 0x1240)]);
        Put(ObjectInit, [0xE8, .. Rel(0x1035, 0x1260), 0xE9, .. Rel(0x103A, 0x1280)]);
        Put(SameTarget, [0xE9, .. Rel(0x1045, 0x1200)]);
        Put(Indirect, [0xFF, 0x25, 0, 0, 0, 0]);
        foreach (var fn in new uint[] { 0x1200, 0x1220, 0x1240, 0x1260, 0x1280, 0x1380, 0x1400, 0x1420 })
            Put(fn, 0xC3);
        Put(0x1500, [0xE8, .. Rel(0x1505, 0x1240)]);
        foreach (var (start, first) in methods)
            Put(start, [0xE8, .. Rel(start + 5, first), 0xE8, .. Rel(start + 10, 0x1380), 0xE8, .. Rel(start + 15, 0x1500), 0xC3]);
        if (secondThrowerCallers != null)
        {
            Put(0x1520, [0xE8, .. Rel(0x1525, 0x1240)]);
            foreach (var start in secondThrowerCallers)
                Put(start, [0xE8, .. Rel(start + 5, 0x1520), 0xC3]);
        }
        var text = b.Add(".text", code, 0x60000020);
        b.EntryPoint = text.Rva;
        uint table = 0, tableSize = 0;
        b.Add(".rdata", rva =>
        {
            var blob = new PeBlob(rva);
            table = blob.Zero(40);
            uint dll = blob.Ascii("synth.dll");
            blob.Align(4);
            uint eat = blob.U32(exports[0].Rva);
            foreach (var e in exports.Skip(1)) blob.U32(e.Rva);
            var nameRvas = exports.Select(e => blob.Ascii(e.Name)).ToList();
            blob.Align(4);
            uint names = blob.U32(nameRvas[0]);
            foreach (var n in nameRvas.Skip(1)) blob.U32(n);
            uint ordinals = blob.U16(0);
            for (int i = 1; i < exports.Count; i++) blob.U16((ushort)i);
            blob.Patch32(table + 12, dll);
            blob.Patch32(table + 16, 1);
            blob.Patch32(table + 20, (uint)exports.Count);
            blob.Patch32(table + 24, (uint)exports.Count);
            blob.Patch32(table + 28, eat);
            blob.Patch32(table + 32, names);
            blob.Patch32(table + 36, ordinals);
            tableSize = blob.Here - table;
            return blob.ToArray();
        });
        b.Directories[PeDirectory.Export] = (table, tableSize);
        return b.Build();
    }

    private NativeCodeIndex Open(out INativeImage image, (string, uint)[] exports, (uint, uint)[]? methods = null, uint[]? secondThrowerCallers = null)
    {
        var path = _dir.File("helpers.dll");
        File.WriteAllBytes(path, Image(exports, methods ?? [], secondThrowerCallers));
        image = _env.Workspace.LoadAny(path).Native!.Image;
        return NativeCodeIndex.Build(image);
    }

    private static HashSet<uint> Named(IEnumerable<(uint Start, uint First)> methods) => methods.Select(m => m.Start).ToHashSet();

    [Fact]
    public void A_function_behind_an_exported_runtime_entry_is_named_for_its_role()
    {
        var index = Open(out var image, NewAndInit);
        var helpers = AotRuntimeHelpers.Find(image, index, new HashSet<uint>());
        Assert.Equal([(0x1200u, "Runtime_ObjectNew"), (0x1220u, "Runtime_ClassInit")], helpers.Select(h => (h.Rva, h.Name)));
        Assert.Contains("object allocation; behind export il2cpp_object_new", helpers[0].Evidence);
        Assert.Contains("runs the static constructor once", helpers[1].Evidence);
    }

    [Fact]
    public void An_address_already_named_is_not_named_again()
    {
        var index = Open(out var image, NewAndInit);
        var helpers = AotRuntimeHelpers.Find(image, index, new HashSet<uint> { 0x1200 });
        Assert.Equal(0x1220u, Assert.Single(helpers).Rva);
    }

    [Fact]
    public void An_export_wrapper_with_two_direct_calls_names_nothing()
    {
        var index = Open(out var image, [("il2cpp_runtime_object_init", ObjectInit)]);
        Assert.Empty(AotRuntimeHelpers.Find(image, index, new HashSet<uint>()));
    }

    [Fact]
    public void An_export_wrapper_that_jumps_through_memory_names_nothing()
    {
        var index = Open(out var image, [("il2cpp_object_new", Indirect)]);
        Assert.Empty(AotRuntimeHelpers.Find(image, index, new HashSet<uint>()));
    }

    [Fact]
    public void Two_exports_forwarding_to_one_function_name_it_for_the_first_table_entry()
    {
        var index = Open(out var image, [("il2cpp_object_new", ObjectNew), ("il2cpp_runtime_object_init", SameTarget)]);
        var helper = Assert.Single(AotRuntimeHelpers.Find(image, index, new HashSet<uint>()));
        Assert.Equal((0x1200u, "Runtime_ObjectNew"), (helper.Rva, helper.Name));
    }

    [Fact]
    public void The_function_most_named_methods_call_first_is_the_metadata_initializer()
    {
        var index = Open(out var image, NewAndInit, ThreeMethods);
        var init = Assert.Single(AotRuntimeHelpers.Find(image, index, Named(ThreeMethods)), h => h.Name == "Runtime_InitMetadata");
        Assert.Equal(0x1400u, init.Rva);
        Assert.Contains("3 of 3 named functions", init.Evidence);
    }

    [Fact]
    public void The_first_call_site_decides_the_initializer_when_a_later_call_has_a_lower_target()
    {
        // Every method calls 0x1380 second; ordering by target would pick it over 0x1400.
        var index = Open(out var image, NewAndInit, ThreeMethods);
        var helpers = AotRuntimeHelpers.Find(image, index, Named(ThreeMethods));
        Assert.DoesNotContain(helpers, h => h.Rva == 0x1380);
    }

    [Fact]
    public void Fewer_than_three_callers_name_no_metadata_initializer()
    {
        var index = Open(out var image, NewAndInit, ThreeMethods);
        Assert.DoesNotContain(AotRuntimeHelpers.Find(image, index, Named(ThreeMethods.Take(2))), h => h.Name == "Runtime_InitMetadata");
    }

    [Fact]
    public void A_first_callee_shared_by_three_of_eight_named_methods_names_no_initializer()
    {
        // First callees split 3, 3 and 2: none reaches half of the eight.
        (uint, uint)[] methods = [.. Enumerable.Range(0, 8).Select(i => (0x1800u + (uint)i * 0x20, i < 3 ? 0x1400u : i < 6 ? 0x1420u : 0x1380u))];
        var index = Open(out var image, NewAndInit, methods);
        Assert.DoesNotContain(AotRuntimeHelpers.Find(image, index, Named(methods)), h => h.Name == "Runtime_InitMetadata");
    }

    [Fact]
    public void A_function_that_only_raises_and_is_called_by_three_methods_is_the_null_reference_throw()
    {
        var index = Open(out var image, WithRaise, ThreeMethods);
        var helpers = AotRuntimeHelpers.Find(image, index, Named(ThreeMethods));
        var thrower = Assert.Single(helpers, h => h.Name == "Runtime_ThrowNullReference");
        Assert.Equal(0x1500u, thrower.Rva);
        Assert.Contains("called by 3 named functions", thrower.Evidence);
        Assert.Contains(helpers, h => h is { Rva: 0x1240, Name: "Runtime_RaiseException" });
    }

    // FT-298 M26: a bounds throw has the same shape as the null throw, so only one is named.
    [Fact]
    public void A_second_function_that_only_raises_with_as_many_callers_stays_unnamed()
    {
        uint[] second = [0x1900, 0x1920, 0x1940];
        var index = Open(out var image, WithRaise, ThreeMethods, second);
        var named = Named(ThreeMethods).Concat(second).ToHashSet();
        var helpers = AotRuntimeHelpers.Find(image, index, named);
        Assert.Equal(0x1500u, Assert.Single(helpers, h => h.Name == "Runtime_ThrowNullReference").Rva);
        Assert.DoesNotContain(helpers, h => h.Rva == 0x1520);
    }

    [Fact]
    public void Without_the_exported_raise_no_null_reference_throw_is_named()
    {
        var index = Open(out var image, NewAndInit, ThreeMethods);
        Assert.DoesNotContain(AotRuntimeHelpers.Find(image, index, Named(ThreeMethods)), h => h.Name == "Runtime_ThrowNullReference");
    }

    [Fact]
    public void Fewer_than_three_callers_name_no_null_reference_throw()
    {
        var index = Open(out var image, WithRaise, ThreeMethods);
        Assert.DoesNotContain(AotRuntimeHelpers.Find(image, index, Named(ThreeMethods.Take(2))), h => h.Name == "Runtime_ThrowNullReference");
    }

    [Fact]
    public void A_cancelled_token_stops_the_search()
    {
        var index = Open(out var image, WithRaise, ThreeMethods);
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.Throws<OperationCanceledException>(() => AotRuntimeHelpers.Find(image, index, Named(ThreeMethods), cts.Token));
    }
}
