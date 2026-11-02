using System.Text.Json;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Diff;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Shape matchers run on images a compiler built from translated_shapes.cpp (build.ps1).</summary>
public sealed class CompilerFixtureTests
{
    private static string Dir => Path.Combine(AppContext.BaseDirectory, "AotMetadata", "CompilerFixtures");

    // Every committed image is one of MSVC PE x64, clang PE x64, clang ELF x64
    // or clang ELF AArch64.
    private static IEnumerable<string> AllBuilds() =>
        Directory.GetFiles(Dir, "shapes-*").Select(Path.GetFileName).OfType<string>().Order(StringComparer.Ordinal);

    private const string Arm64Reason = "collapse=runtime applies to x86 and x64 images only";
    private const string Arm64SlotReason = "slot notes read x64 code only";
    private static bool Arm64(string build) => build.Contains("-arm64", StringComparison.Ordinal);

    // Images a matcher is not run on, each with its reason; the theory of the
    // matcher leaves them out.
    private static string? Exempt(string matcher, string build) => matcher switch
    {
        nameof(Collapse) when Arm64(build) => Arm64Reason,
        nameof(Slots) when Arm64(build) => Arm64SlotReason,
        _ => null,
    };

    private static TheoryData<string> Matcher(string matcher)
    {
        var data = new TheoryData<string>();
        foreach (var name in AllBuilds())
            if (Exempt(matcher, name) == null) data.Add(name);
        return data;
    }

    public static TheoryData<string> Builds() => Matcher("All");

    public static TheoryData<string> Collapse() => Matcher(nameof(Collapse));

    public static TheoryData<string> Slots() => Matcher(nameof(Slots));

    [Fact]
    public void The_build_set_covers_each_compiler_level_and_target()
    {
        string[] levels = ["O0", "O1", "O2"];
        string[] targets = ["x64.dll", "x64.elf", "arm64.elf"];
        var expected = new[] { "shapes-msvc-Od.dll", "shapes-msvc-O1.dll", "shapes-msvc-O2.dll" }
            .Concat(levels.SelectMany(l => targets.Select(t => $"shapes-clang-{l}-{t}")))
            .Order(StringComparer.Ordinal);
        Assert.Equal(expected, AllBuilds());
    }

    [Fact]
    public void The_exempt_images_are_the_arm64_builds_for_slots_and_collapse()
    {
        string[] arm64 = ["shapes-clang-O0-arm64.elf", "shapes-clang-O1-arm64.elf", "shapes-clang-O2-arm64.elf"];
        Assert.Equal(arm64, AllBuilds().Where(n => Exempt(nameof(Collapse), n) != null));
        Assert.Equal(arm64, AllBuilds().Where(n => Exempt(nameof(Slots), n) != null));
        Assert.DoesNotContain(AllBuilds(), n => Exempt("All", n) != null);
    }

    private sealed record Built(string Name, INativeImage Image, NativeCodeIndex Index, Dictionary<string, uint> Methods)
    {
        public IReadOnlySet<uint> MethodRvas => Methods.Values.ToHashSet();

        public bool Elf => Image.Format == ImageFormat.Elf;

        // The slot harness lays the text out from RVA 0x1000.
        public uint Shift(uint rva) => rva - Image.Sections.Single(s => s.Name == ".text").Rva + 0x1000;
    }

    private static Built Load(string name)
    {
        var image = NativeImageLoader.Open(Path.Combine(Dir, name));
        var methods = image.Exports.Where(e => e.Name?.StartsWith("M_", StringComparison.Ordinal) == true).ToDictionary(e => e.Name![2..], e => e.Rva);
        return new Built(name, image, NativeCodeIndex.Build(image), methods);
    }

    private static Dictionary<string, uint> Helpers(Built b) =>
        AotRuntimeHelpers.Find(b.Image, b.Index, b.MethodRvas).ToDictionary(h => h.Name, h => h.Rva);

    // The shapes are from MSVC 19.44 at /Od, /O1 and /O2.
    [Theory, MemberData(nameof(Builds))]
    public void Every_runtime_helper_in_the_build_is_named(string build)
    {
        // RT-319, RT-329.
        var b = Load(build);
        var names = Helpers(b).Keys.Order(StringComparer.Ordinal).ToArray();
        // The class setup and the wrapped null-reference throw are matched in x64 code only.
        string[] expected = Arm64(build)
            ? ["Runtime_ClassInit", "Runtime_InitMetadata", "Runtime_RaiseException"]
            : ["Runtime_ClassInit", "Runtime_ClassSetup", "Runtime_InitMetadata", "Runtime_RaiseException", "Runtime_ThrowNullReference"];
        Assert.Equal(expected, names);
    }

    private const string Receiver = "Fixture.Native.Host";

    private static IEnumerable<KeyValuePair<string, uint>> SlotFunctions(Built b) =>
        b.Methods.Where(m => m.Key.StartsWith("Slot", StringComparison.Ordinal) || m.Key.StartsWith("Setup", StringComparison.Ordinal));

    // A metadata model with one type whose slots 3 and 5 name methods, and one instance method at each fixture function.
    private static (string Source, string Script) Metadata(Built b)
    {
        var methods = SlotFunctions(b).ToList();
        var source = """
            using System;
            namespace Il2CppDummyDll
            {
                public class AddressAttribute : Attribute { public string RVA; public string Offset; public string VA; public string Slot; }
            }
            namespace Fixture.Native
            {
                using Il2CppDummyDll;
                public class Host
                {
                    [Address(Slot = "3")] public virtual int Dispatch() { return 0; }
                    [Address(Slot = "5")] public virtual int Other() { return 0; }

            """ + string.Concat(methods.Select(m =>
                $"        [Address(RVA = \"0x{b.Shift(m.Value):X}\", Offset = \"0x{b.Shift(m.Value) - 0x1000 + 0x400:X}\", VA = \"0x{0x180000000UL + b.Shift(m.Value):X}\")] public void {m.Key}() {{ }}\n"))
            + "    }\n}\n";
        var script = JsonSerializer.Serialize(new
        {
            ScriptMethod = methods.Select(m => new { Address = b.Shift(m.Value), Name = $"{Receiver}$${m.Key}" }),
            ScriptMetadata = Array.Empty<object>(),
        });
        return (source, script);
    }

    // The .text bytes at their RVAs, from the first byte of the section.
    private static byte[] Text(Built b)
    {
        var text = b.Image.Sections.Single(s => s.Name == ".text");
        var bytes = new byte[text.VirtualSize];
        Assert.Equal(bytes.Length, b.Image.Read(text.Rva, bytes));
        return bytes;
    }

    private static Dictionary<string, List<AotSlotNotes.SlotCall>> SlotCalls(AotFieldNotesTests host, Built b) => host.CallsOf(Text(b), Metadata(b), SlotFunctions(b).ToDictionary(m => m.Key, m => b.Shift(m.Value)), b.Elf);

    [Theory, MemberData(nameof(Slots))]
    public void A_slot_call_through_memory_or_a_register_names_the_method_in_the_slot(string build)
    {
        // RT-319, RT-329.
        using var host = new AotFieldNotesTests();
        var calls = SlotCalls(host, Load(build));
        // The compiler loads each entry into a register first, so every call is a register form.
        Assert.Equal("Host::Dispatch (slot 3)", Assert.Single(calls["SlotMemory"]).Note);
        Assert.Equal("Host::Dispatch (slot 3)", Assert.Single(calls["SlotTail"]).Note);
        Assert.Equal("Host::Other (slot 5)", Assert.Single(calls["SlotRegister"]).Note);
        foreach (var setup in new[] { "Setup", "SetupB", "SetupC" })
            Assert.Equal("Host::Dispatch (slot 3)", Assert.Single(calls[setup]).Note);
    }

    private static Dictionary<uint, RuntimeCollapse.Run> Runs(Built b, string method)
    {
        var helpers = Helpers(b);
        var names = helpers.ToDictionary(h => h.Value, h => h.Key);
        var fn = b.Index.FunctionByStart(b.Methods[method])!;
        var lines = b.Index.DisassembleFunction(fn, 400, out _).Where(e => e.Line != null).Select(e => e.Line!).ToList();
        var calls = lines.Where(l => l.Facts.Flow == FlowKind.Call && l.Facts.BranchTarget is { } t && names.ContainsKey(t))
            .ToDictionary(l => l.Rva, l => names[l.Facts.BranchTarget!.Value]);
        return RuntimeCollapse.Find(b.Index, fn, lines, r => $"0x{b.Image.ImageBase + r:X}", calls);
    }

    [Theory, MemberData(nameof(Collapse))]
    public void A_flag_check_around_one_or_two_initializer_calls_is_one_lazy_initialization(string build)
    {
        // RT-319.
        var b = Load(build);
        Assert.Contains(Runs(b, "LazyOne").Values, r => r.Note.Contains("lazy initialization of", StringComparison.Ordinal));
        var two = Runs(b, "LazyTwo").Values.Where(r => r.Note.Contains("lazy initialization of", StringComparison.Ordinal)).ToList();
        // Both calls, the fence and the flag store are inside the run.
        var run = Assert.Single(two);
        Assert.True(run.Count >= 6, run.Note);
    }

    [Theory, MemberData(nameof(Collapse))]
    public void A_class_flag_check_before_the_class_init_call_is_one_class_initialization(string build)
    {
        // RT-319.
        var b = Load(build);
        Assert.Contains(Runs(b, "SlotMemory").Values, r => r.Note.Contains("class initialization", StringComparison.Ordinal));
    }

    [Theory, MemberData(nameof(Collapse))]
    public void An_inlined_card_table_update_is_one_write_barrier(string build)
    {
        // RT-319.
        var b = Load(build);
        Assert.Contains(Runs(b, "Store").Values, r => r.Note.StartsWith("collapsed: write barrier", StringComparison.Ordinal));
        Assert.Contains(Runs(b, "StoreTwo").Values, r => r.Note.StartsWith("collapsed: write barrier", StringComparison.Ordinal));
    }

    [Theory, MemberData(nameof(Collapse))]
    public void A_flag_loaded_before_other_work_and_tested_later_is_one_lazy_initialization(string build)
    {
        // Regression 0bf3610b2.
        var b = Load(build);
        Assert.Contains(Runs(b, "LazyMoved").Values, r => r.Note.Contains("lazy initialization of", StringComparison.Ordinal));
    }

    [Theory, MemberData(nameof(Collapse))]
    public void A_class_flag_checked_after_other_work_is_one_class_initialization(string build)
    {
        // Regression 0bf3610b2.
        var b = Load(build);
        Assert.Contains(Runs(b, "ClassInitMoved").Values, r => r.Note.Contains("class initialization", StringComparison.Ordinal));
    }

    [Theory, MemberData(nameof(Collapse))]
    public void A_card_table_update_with_other_work_before_it_is_one_write_barrier(string build)
    {
        // Regression 0bf3610b2.
        var b = Load(build);
        Assert.Contains(Runs(b, "StoreMoved").Values, r => r.Note.StartsWith("collapsed: write barrier", StringComparison.Ordinal));
    }

    [Theory, MemberData(nameof(Builds))]
    public void Helper_callees_and_the_card_mask_are_left_out_of_similarity(string build)
    {
        // RT-319.
        var b = Load(build);
        var prints = ImagePrints.Build(b.Index, default);
        var helpers = Helpers(b);
        prints.NameHelpers(helpers.Values);
        var ignored = prints.IgnoredCallees;
        foreach (var (name, rva) in helpers)
            Assert.True(ignored[prints.ByStart[rva]], $"{name} is scored as a shared callee");
        foreach (var method in new[] { "Store", "StoreTwo" })
            Assert.DoesNotContain(0x3FFUL, prints.Functions[prints.ByStart[b.Methods[method]]].Constants);
    }
}
