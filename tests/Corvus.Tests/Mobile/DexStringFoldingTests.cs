using System.Diagnostics;
using System.Text;
using Corvus.Core.Mobile;
using Corvus.Services.Mobile;
using static Corvus.Tests.AndroidSamples;

namespace Corvus.Tests;

/// <summary>String decoder calls of DEX code evaluated by DalvikEvaluator, shown by disassemble_dex and search_dex, on built DEX files.</summary>
public sealed class DexStringFoldingTests : IDisposable
{
    private const string Dec = "Lp/Dec;", Main = "Lp/Main;", Tab = "Lp/Tab;", Util = "Lp/Util;", Bad = "Lp/Bad;", Cnt = "Lp/Cnt;", Cfg = "Lp/Cfg;";
    private const string S = "Ljava/lang/String;", Sb = "Ljava/lang/StringBuilder;";
    private const int Key = 0x5a, ByteKey = 0x11;
    private const string Wide = "héllo";

    private readonly TempDir _dir = new();
    private readonly DexService _dex = new();
    private readonly byte[] _bytes = Fixture();
    private readonly string _path;

    public DexStringFoldingTests() => _path = Save(_dir, "app.dex", _bytes);

    public void Dispose() => _dir.Dispose();

    private static DexInsn NewArray(int a, int size, string type) =>
        new(p => [(ushort)(0x23 | (a | size << 4) << 8), (ushort)p.Type(type)], [], [type], [], []);

    private static DexInsn FilledNewArray(string type, params int[] regs)
    {
        int[] r = [.. regs, 0, 0, 0, 0, 0];
        return new(p => [(ushort)(0x24 | (regs.Length << 4 | r[4]) << 8), (ushort)p.Type(type), (ushort)(r[0] | r[1] << 4 | r[2] << 8 | r[3] << 12)], [], [type], [], []);
    }

    private static DexInsn Op22t(int op, int a, int b, int offset) => Asm.Raw((ushort)(op | (a | b << 4) << 8), (ushort)offset);

    private static DexInsn Op22b(int op, int a, int b, int literal) => Asm.Raw((ushort)(op | a << 8), (ushort)(b | (byte)literal << 8));

    private static void Method(DexBuilder.ClassDef c, string name, string[] parameters, int registers, params DexInsn[] code) =>
        c.Method(name, S, parameters, 9, code).Registers = registers;

    /// <summary>
    /// Decoders of five shapes and four refused ones, with a caller per decoder passing constants, and a caller passing
    /// its own parameter.
    /// </summary>
    private static byte[] Fixture()
    {
        var b = new DexBuilder();
        var dec = b.Class(Dec);
        // x([C, I): XOR each element with the key in place, then new String(char[]).
        Method(dec, "x", ["[C", "I"], 5,
            Asm.Const4(0, 0), Asm.Op12x(0x21, 1, 3), Op22t(0x35, 0, 1, 11), Asm.Op23x(0x49, 2, 3, 0), Asm.Op12x(0xb7, 2, 4), Asm.Op12x(0x8e, 2, 2),
            Asm.Op23x(0x50, 2, 3, 0), Asm.AddIntLit8(0, 0, 1), Asm.Goto(-10), Asm.NewInstance(0, S), Asm.Invoke(0x70, S + "-><init>([C)V", 0, 3), Asm.Return(0x11, 0));
        // b(String): Base64.decode, XOR each byte, new String(bytes, UTF_8).
        Method(dec, "b", [S], 5,
            Asm.Const4(0, 0), Asm.Invoke(0x71, "Landroid/util/Base64;->decode(Ljava/lang/String;I)[B", 4, 0), Asm.Op11x(0x0c, 1), Asm.Const4(0, 0),
            Asm.Op12x(0x21, 2, 1), Op22t(0x35, 0, 2, 12), Asm.Op23x(0x48, 3, 1, 0), Op22b(0xdf, 3, 3, ByteKey), Asm.Op12x(0x8d, 3, 3), Asm.Op23x(0x4f, 3, 1, 0),
            Asm.AddIntLit8(0, 0, 1), Asm.Goto(-11), Asm.Static(0x62, 2, "Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;"),
            Asm.NewInstance(0, S), Asm.Invoke(0x70, S + "-><init>([BLjava/nio/charset/Charset;)V", 0, 1, 2), Asm.Return(0x11, 0));
        // r(String): new StringBuilder(s).reverse().toString().
        Method(dec, "r", [S], 2,
            Asm.NewInstance(0, Sb), Asm.Invoke(0x70, Sb + "-><init>(Ljava/lang/String;)V", 0, 1), Asm.Invoke(0x6e, Sb + "->reverse()Ljava/lang/StringBuilder;", 0),
            Asm.Op11x(0x0c, 0), Asm.Invoke(0x6e, Sb + "->toString()Ljava/lang/String;", 0), Asm.Op11x(0x0c, 0), Asm.Return(0x11, 0));
        // n(String): a nested helper of another class shifts each character by one.
        Method(dec, "n", [S], 2, Asm.Const4(0, 1), Asm.Invoke(0x71, Util + "->rot(Ljava/lang/String;I)Ljava/lang/String;", 1, 0), Asm.Op11x(0x0c, 0), Asm.Return(0x11, 0));

        var util = b.Class(Util);
        Method(util, "rot", [S, "I"], 6,
            Asm.Invoke(0x6e, S + "->toCharArray()[C", 4), Asm.Op11x(0x0c, 0), Asm.Const4(1, 0), Asm.Op12x(0x21, 2, 0), Op22t(0x35, 1, 2, 12), Asm.Op23x(0x49, 3, 0, 1),
            Asm.Op23x(0x91, 3, 3, 5), Asm.Op12x(0x8e, 3, 3), Asm.Op23x(0x50, 3, 0, 1), Asm.AddIntLit8(1, 1, 1), Asm.Goto(-11),
            Asm.Invoke(0x71, S + "->valueOf([C)Ljava/lang/String;", 0), Asm.Op11x(0x0c, 0), Asm.Return(0x11, 0));

        // Tab: a table its static initializer fills, read by t([I) through indexes.
        var tab = b.Class(Tab).Field("T", "[C", 0x18);
        tab.Method("<clinit>", "V", [], 8, Asm.Const4(0, 5), NewArray(0, 0, "[C"), Asm.FillArrayData(0, 7), Asm.Static(0x69, 0, Tab + "->T:[C"), Asm.ReturnVoid(),
            Asm.Nop(), Asm.ArrayPayload(2, 'd', 'l', 'o', 'r', 'w')).Registers = 1;
        Method(tab, "t", ["[I"], 6,
            Asm.NewInstance(0, Sb), Asm.Invoke(0x70, Sb + "-><init>()V", 0), Asm.Static(0x62, 4, Tab + "->T:[C"), Asm.Const4(1, 0), Asm.Op12x(0x21, 2, 5),
            Op22t(0x35, 1, 2, 12), Asm.Op23x(0x44, 3, 5, 1), Asm.Op23x(0x49, 3, 4, 3), Asm.Invoke(0x6e, Sb + "->append(C)Ljava/lang/StringBuilder;", 0, 3),
            Asm.AddIntLit8(1, 1, 1), Asm.Goto(-11), Asm.Invoke(0x6e, Sb + "->toString()Ljava/lang/String;", 0), Asm.Op11x(0x0c, 0), Asm.Return(0x11, 0));
        // m(I): adds the argument to each table element in place, so the table differs on the next call.
        Method(tab, "m", ["I"], 5,
            Asm.Static(0x62, 3, Tab + "->T:[C"), Asm.Const4(0, 0), Asm.Op12x(0x21, 1, 3), Op22t(0x35, 0, 1, 11), Asm.Op23x(0x49, 2, 3, 0), Asm.Op12x(0xb0, 2, 4),
            Asm.Op12x(0x8e, 2, 2), Asm.Op23x(0x50, 2, 3, 0), Asm.AddIntLit8(0, 0, 1), Asm.Goto(-10), Asm.NewInstance(0, S), Asm.Invoke(0x70, S + "-><init>([C)V", 0, 3),
            Asm.Return(0x11, 0));

        var bad = b.Class(Bad);
        Method(bad, "refl", [S], 1, Asm.Invoke(0x71, "Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;", 0), Asm.Return(0x11, 0));
        Method(bad, "spin", [S], 1, Asm.Nop(), Asm.Goto(-1));
        // Cnt.c(String): appends a static counter it increments, so a second call returns another string.
        var cnt = b.Class(Cnt).Field("n", "I", 0x8);
        Method(cnt, "c", [S], 2,
            Asm.Static(0x60, 0, Cnt + "->n:I"), Asm.AddIntLit8(0, 0, 1), Asm.Static(0x67, 0, Cnt + "->n:I"), Asm.Invoke(0x71, S + "->valueOf(I)Ljava/lang/String;", 0),
            Asm.Op11x(0x0c, 0), Asm.Invoke(0x6e, S + "->concat(Ljava/lang/String;)Ljava/lang/String;", 1, 0), Asm.Op11x(0x0c, 0), Asm.Return(0x11, 0));
        // Cfg.g(String): appends a static field that Main.setup writes at run time.
        var cfg = b.Class(Cfg).Field("name", S, 0x8);
        Method(cfg, "g", [S], 2, Asm.Static(0x62, 0, Cfg + "->name:Ljava/lang/String;"), Asm.Invoke(0x6e, S + "->concat(Ljava/lang/String;)Ljava/lang/String;", 1, 0),
            Asm.Op11x(0x0c, 0), Asm.Return(0x11, 0));

        var main = b.Class(Main);
        main.Method("setup", "V", [], 9, Asm.ConstString(0, "y"), Asm.Static(0x69, 0, Cfg + "->name:Ljava/lang/String;"), Asm.ReturnVoid()).Registers = 1;
        Method(main, "xor", [], 2,
            Asm.Const4(0, 3), NewArray(0, 0, "[C"), Asm.FillArrayData(0, 11), Asm.Const16(1, Key), Asm.Invoke(0x71, Dec + "->x([CI)Ljava/lang/String;", 0, 1),
            Asm.Op11x(0x0c, 0), Asm.Return(0x11, 0), Asm.Nop(), Asm.ArrayPayload(2, 'a' ^ Key, 'b' ^ Key, 'c' ^ Key));
        var encoded = Convert.ToBase64String([.. Encoding.UTF8.GetBytes(Wide).Select(x => (byte)(x ^ ByteKey))]);
        Method(main, "base64", [], 1, Asm.ConstString(0, encoded), Asm.Invoke(0x71, Dec + "->b(Ljava/lang/String;)Ljava/lang/String;", 0), Asm.Op11x(0x0c, 0), Asm.Return(0x11, 0));
        Method(main, "reverse", [], 1, Asm.ConstString(0, "olleh"), Asm.Invoke(0x71, Dec + "->r(Ljava/lang/String;)Ljava/lang/String;", 0), Asm.Op11x(0x0c, 0), Asm.Return(0x11, 0));
        Method(main, "nested", [], 1, Asm.ConstString(0, "ifmmp"), Asm.Invoke(0x71, Dec + "->n(Ljava/lang/String;)Ljava/lang/String;", 0), Asm.Op11x(0x0c, 0), Asm.Return(0x11, 0));
        Method(main, "table", [], 4,
            Asm.Const4(0, 4), Asm.Const4(1, 2), Asm.Const4(2, 3), Asm.Const4(3, 0), FilledNewArray("[I", 0, 1, 2, 3), Asm.Op11x(0x0c, 0),
            Asm.Invoke(0x71, Tab + "->t([I)Ljava/lang/String;", 0), Asm.Op11x(0x0c, 0), Asm.Return(0x11, 0));
        // The argument is the caller's own parameter: not a constant.
        Method(main, "use", [S], 1, Asm.Invoke(0x71, Dec + "->r(Ljava/lang/String;)Ljava/lang/String;", 0), Asm.Op11x(0x0c, 0), Asm.Return(0x11, 0));
        main.Method("bad", "V", [], 9, Asm.ConstString(0, "x"), Asm.Invoke(0x71, Bad + "->refl(Ljava/lang/String;)Ljava/lang/String;", 0),
            Asm.Invoke(0x71, Cnt + "->c(Ljava/lang/String;)Ljava/lang/String;", 0), Asm.Invoke(0x71, Bad + "->spin(Ljava/lang/String;)Ljava/lang/String;", 0),
            Asm.Invoke(0x71, Cfg + "->g(Ljava/lang/String;)Ljava/lang/String;", 0), Asm.Static(0x62, 0, Cfg + "->name:Ljava/lang/String;"),
            Asm.Invoke(0x71, Dec + "->r(Ljava/lang/String;)Ljava/lang/String;", 0), Asm.ReturnVoid()).Registers = 1;
        return b.Build();
    }

    private IReadOnlyList<DexFoldSite> Sites(string method)
    {
        var index = DexIndex.Load(_path, Core.AnalysisLimits.Default, default);
        return DexStringFolding.For(index).Method(index.Methods[index.ResolveMethod(Main + "->" + method)]);
    }

    private static string Value(DexFoldSite site) => site.Fold.Status == DexFoldStatus.Simplified ? site.Fold.Value! : $"{site.Fold.Status}: {site.Fold.Reason}";

    [Fact]
    public void A_xor_decoder_over_a_char_array_literal_is_simplified()
    {
        var site = Assert.Single(Sites("xor"));
        Assert.Equal("abc", Value(site));
        Assert.Equal((8, Dec + "->x([CI)Ljava/lang/String;"), (site.Offset, site.Decoder));
    }

    [Fact]
    public void A_base64_decoder_with_a_key_reads_utf8_through_a_standard_charset() => Assert.Equal(Wide, Value(Assert.Single(Sites("base64"))));

    [Fact]
    public void A_reversing_string_builder_decoder_is_simplified() => Assert.Equal("hello", Value(Assert.Single(Sites("reverse"))));

    [Fact]
    public void A_nested_helper_of_another_class_is_evaluated() => Assert.Equal("hello", Value(Assert.Single(Sites("nested"))));

    [Fact]
    public void A_table_the_static_initializer_fills_is_read_by_index() => Assert.Equal("word", Value(Assert.Single(Sites("table"))));

    [Fact]
    public void A_parameter_passed_on_is_not_a_constant() =>
        Assert.Equal("Unknown: not-constant: argument 1 (v0) is not a constant in the call's block", Value(Assert.Single(Sites("use"))));

    [Fact]
    public void Reflection_a_static_counter_an_endless_loop_and_a_static_written_at_run_time_are_refused()
    {
        var clock = Stopwatch.StartNew();
        var sites = Sites("bad");
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(1), $"the refusals took {clock.Elapsed}");
        Assert.Equal(
        [
            "Unknown: unsupported-call: Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;",
            "Unknown: cache-dependent: called again on the static state the first call left, it returns another string",
            $"Partial: instruction-budget: more than {DalvikEvaluator.MaxSteps:N0} instructions",
            $"Unknown: mutable-static: {Cfg}->name:Ljava/lang/String; is also written by {Main}->setup()V",
            "Unknown: not-constant: argument 1 (v0) is not a constant in the call's block",
        ], sites.Select(Value));
    }

    [Fact]
    public void A_call_after_one_that_changed_static_state_starts_from_the_initializer_state()
    {
        var evaluator = new DalvikEvaluator(new OneFile(DexFile.Read(_bytes, "app.dex")));
        var fold = evaluator.Fold(Tab + "->m(I)Ljava/lang/String;", [1]);
        Assert.StartsWith("cache-dependent:", fold.Reason);
        Assert.True(evaluator.TryReadStatic(Tab + "->T:[C", out var table));
        Assert.Equal("dlorw", string.Concat(Enumerable.Range(0, 5).Select(k => (char)(int)((DalvikArray)table!)[k]!)));
    }

    [Fact]
    public void Disassembly_shows_each_decoder_call_result_after_the_call_and_counts_them()
    {
        var text = _dex.Disassemble(_path, Main, annotated: false, default, simplified: true);
        Assert.Contains("# string decoder calls: 5 simplified, 1 partial, 3 unknown, 2 with arguments that are not constants\n", text);
        Assert.Contains($"    invoke-static {{v0, v1}}, {Dec}->x([CI)Ljava/lang/String;\n    # simplified: \"abc\"\n", text);
        Assert.Contains("    # simplified: \"h\\u00e9llo\"\n", text);
        Assert.Contains("    # not simplified: not-constant: argument 1 (v0) is not a constant in the call's block\n", text);
        Assert.DoesNotContain("# simplified", _dex.Disassemble(_path, Main, annotated: false, default));
    }

    [Fact]
    public void String_search_labels_decoder_results_as_recovered_with_decoder_and_call_site()
    {
        var r = _dex.Search(_path, "string", "hello", 0, 10, default);
        Assert.Equal(
        [
            ("recovered", "hello", Main + "->nested()Ljava/lang/String;", "invoke-static " + Dec + "->n(Ljava/lang/String;)Ljava/lang/String;"),
            ("recovered", "hello", Main + "->reverse()Ljava/lang/String;", "invoke-static " + Dec + "->r(Ljava/lang/String;)Ljava/lang/String;"),
        ], r.Items.Select(h => (h.Kind, h.Value, h.Method!, h.Opcode!)));
        Assert.Equal("2 matching string(s) recovered from string decoder calls; 4 call(s) with constant arguments not simplified (disassemble_dex format=simplified says why).",
            Assert.Single(r.Notes, n => n.Contains("recovered", StringComparison.Ordinal)));
        var literal = Assert.Single(_dex.Search(_path, "string", "olleh", 0, 10, default).Items);
        Assert.Equal(("string", "const-string"), (literal.Kind, literal.Opcode));
    }

    /// <summary>Six random bytes of the fixture changed per round; every decoder is folded with constant arguments.</summary>
    [Fact]
    [FuzzEntry(typeof(DalvikEvaluator))]
    public void Damaged_decoders_end_with_a_value_or_a_reason_without_crashing()
    {
        var random = new Random(23);
        (string Decoder, object?[] Args)[] calls =
        [
            (Dec + "->r(Ljava/lang/String;)Ljava/lang/String;", ["olleh"]),
            (Dec + "->n(Ljava/lang/String;)Ljava/lang/String;", ["ifmmp"]),
            (Tab + "->t([I)Ljava/lang/String;", [Ints(4, 2, 3, 0)]),
            (Dec + "->b(Ljava/lang/String;)Ljava/lang/String;", ["AAAA"]),
        ];
        var clock = Stopwatch.StartNew();
        for (int n = 0; n < 200; n++)
        {
            var bytes = (byte[])_bytes.Clone();
            for (int k = 0; k < 6; k++) bytes[random.Next(DexFile.HeaderSize, bytes.Length)] = (byte)random.Next(256);
            var evaluator = new DalvikEvaluator(new OneFile(DexFile.Read(bytes, "x.dex")));
            foreach (var (decoder, args) in calls)
            {
                var fold = evaluator.Fold(decoder, args);
                Assert.True(fold.Status == DexFoldStatus.Simplified ? fold.Value != null : fold.Reason != null, $"round {n}: {decoder}");
            }
        }
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(30), $"200 rounds took {clock.Elapsed}");
    }

    private static DalvikArray Ints(params int[] values)
    {
        var a = new DalvikArray("[I", values.Length);
        for (int k = 0; k < values.Length; k++) a[k] = values[k];
        return a;
    }

    private sealed class OneFile(DexFile file) : IDexProgram
    {
        public (DexFile File, DexClass Class, DexEncodedMethod Method)? FindMethod(string descriptor)
        {
            foreach (var c in file.Classes)
                foreach (var m in file.ClassData(c).Methods)
                    if (file.Method(m.MethodIndex).Descriptor == descriptor) return (file, c, m);
            return null;
        }

        public (DexFile File, DexClass Class)? FindClass(string descriptor) => file.Classes.FirstOrDefault(c => c.Descriptor == descriptor) is { } c ? (file, c) : null;

        public IReadOnlyList<string> StaticWriters(string field) =>
        [
            .. file.Classes.SelectMany(c => file.ClassData(c).Methods.Where(m => m.CodeOffset != 0)
                .Where(m => Dalvik.Decode(file.Code(m.CodeOffset)?.Instructions ?? []).Any(i => i.Opcode is >= 0x67 and <= 0x6d && file.Field(i.Index).Descriptor == field))
                .Select(m => file.Method(m.MethodIndex).Descriptor)),
        ];
    }
}
