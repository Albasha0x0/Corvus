using Corvus.Core;
using Corvus.Core.Mobile;
using Corvus.Services.Mobile;
using static Corvus.Tests.AndroidSamples;

namespace Corvus.Tests;

/// <summary>The DEX reader, the Dalvik decoder and the DEX tools (classes, members, search, references) on synthetic DEX files.</summary>
public sealed class DexTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly DexService _dex = new();
    private readonly string _apk;

    public DexTests() => _apk = Save(_dir, "app.apk", Apk(30, ("classes.dex", Dex())));

    public void Dispose() => _dir.Dispose();

    [Fact]
    public void Reader_pools_class_data_code_annotations_and_debug_info()
    {
        var f = DexFile.Read(Dex(), "classes.dex");
        Assert.Empty(f.Issues);
        Assert.Equal(35, f.Version);
        // Sorted by type index.
        Assert.Equal([Helper, "Lcom/example/app/Main$Inner;", Main, Link], f.Classes.Select(c => c.Descriptor));
        var main = f.Classes.Single(c => c.Descriptor == Main);
        Assert.Equal(("Landroid/app/Activity;", "Main.java"), (main.SuperClass, main.SourceFile));
        var (fields, methods) = f.ClassData(main);
        Assert.Equal(["COUNT", "name"], fields.Select(x => f.Field(x.FieldIndex).Name));
        Assert.Equal("int 0x7", $"{f.StaticValues(main).Single().Kind} {f.StaticValues(main).Single()}");
        var onCreate = methods.Single(m => f.Method(m.MethodIndex).Name == "onCreate");
        var code = f.Code(onCreate.CodeOffset)!;
        Assert.Equal((3, 2), (code.Registers, code.Ins));
        Assert.Equal(["invoke-super", "const-string", "iput-object", "invoke-static", "return-void"], Dalvik.Decode(code.Instructions).Select(i => i.Name));
        var (lines, names) = f.Debug(code.DebugInfoOffset);
        Assert.Equal([(0, 10), (3, 11), (5, 12), (7, 13)], lines);
        Assert.Equal(["savedInstanceState"], names);
        var guarded = f.Code(methods.Single(m => f.Method(m.MethodIndex).Name == "guarded").CodeOffset)!;
        var t = Assert.Single(guarded.Tries);
        Assert.Equal((0, 3), (t.Start, t.Count));
        Assert.Equal([("Ljava/lang/Exception;", 4), (null, 4)], t.Handlers);
        Assert.Equal("Ldalvik/annotation/MemberClasses;", f.Annotations(main).Class.Single().Type);
        Assert.Null(methods.Single(m => f.Method(m.MethodIndex).Name == "abstractLike").CodeOffset is 0 ? null : "code");
    }

    [Fact]
    public void Decoder_every_format_reads_operands_and_lengths()
    {
        DalvikInstruction One(params ushort[] u) => Dalvik.DecodeOne(u, 0)!;
        Assert.Equal((-1L, 1), (One(0xF012).Literal, One(0xF012).Length));                                   // const/4 v0, -1
        Assert.Equal(0x3f800000L, One(0x0015, 0x3f80).Literal);                                              // const/high16
        Assert.Equal(unchecked((long)0x4000000000000000), One(0x0019, 0x4000).Literal);                      // const-wide/high16
        Assert.Equal(0x0123456789ABCDEFL, One(0x0018, 0xCDEF, 0x89AB, 0x4567, 0x0123).Literal);             // const-wide
        Assert.Equal((-2L, 3, 4), (One(0x03d8, 0xFE04).Literal, One(0x03d8, 0xFE04).A, One(0x03d8, 0xFE04).B)); // add-int/lit8 v3, v4, -2
        var invoke = One(0x546e, 0x0007, 0x3210);                                                             // invoke-virtual {v0..v3, v4}
        Assert.Equal([0, 1, 2, 3, 4], invoke.Arguments);
        Assert.Equal((7, DalvikRef.Method), (invoke.Index, invoke.Ref));
        var range = One(0x0374, 0x0009, 0x0010);                                                              // invoke-virtual/range {v16..v18}
        Assert.Equal([16, 17, 18], range.Arguments);
        var poly = One(0x21fa, 0x0002, 0x0010, 0x0005);                                                       // invoke-polymorphic {v0, v1}, meth, proto
        Assert.Equal((2, 5, 4), (poly.Index, poly.Index2, poly.Length));
        Assert.Equal(-3, One(0xFD28).Target);                                                                // goto -3
        Assert.Equal(0x10000, One(0x002a, 0x0000, 0x0001).Target);                                          // goto/32
        Assert.Equal(8, One(0x0100, 0x0002, 0, 0, 1, 0, 2, 0).Length);                                       // packed payload: 4 + 2 * 2 units
        Assert.Equal(DalvikFormat.FillArrayPayload, One(0x0300, 4, 3, 0, 0, 0, 0, 0, 0, 0).Format);
        Assert.Null(Dalvik.DecodeOne([0x0018, 1], 0));                                                       // truncated const-wide
        Assert.Equal("unused-3e", One(0x003e).Name);
        Assert.All(Enumerable.Range(0, 256), op => Assert.NotNull(Dalvik.Ops[op].Name));
    }

    [Fact]
    public void List_and_get_class_give_exact_method_ids_inner_classes_and_values()
    {
        var list = _dex.ListClasses(_apk, null, null, 0, 100, default);
        Assert.Equal(4, list.Total);
        Assert.Equal(["Lcom/example/app/Main$Inner;", Main], _dex.ListClasses(_apk, "Main", "com.example", 0, 100, default).Items.Select(c => c.Descriptor));
        Assert.Equal([Link], _dex.ListClasses(_apk, "crc64*.Link*", null, 0, 100, default).Items.Select(c => c.Descriptor));

        var main = _dex.GetClass(_apk, "com.example.app.Main", default);
        Assert.Equal(["Lcom/example/app/Main$Inner;"], main.InnerClasses);
        Assert.Contains(ComputeInt, main.Methods.Select(m => m.Id));
        Assert.Contains(ComputeString, main.Methods.Select(m => m.Id));
        Assert.Equal("public int compute(java.lang.String)", main.Methods.Single(m => m.Id == ComputeString).Signature);
        Assert.Equal(["savedInstanceState"], main.Methods.Single(m => m.Name == "onCreate").ParameterNames);
        Assert.Null(main.Methods.Single(m => m.Name == "abstractLike").CodeUnits);
        Assert.Equal("0x7", main.Fields.Single(f => f.Name == "COUNT").Value);
        Assert.Equal("public static final", main.Fields.Single(f => f.Name == "COUNT").Access);
        Assert.Equal("com.example.app.Main$Inner", _dex.GetClass(_apk, "com.example.app.Main.Inner", default).JavaName);
        Assert.StartsWith("class; names: Lcom/example/app/Helper;, log", _dex.GetClass(_apk, Helper, default).Kotlin);
        var missing = Assert.Throws<ToolError>(() => _dex.GetClass(_apk, "org.Main", default));
        Assert.Equal(ErrorCode.NotFound, missing.Code);
        Assert.Contains(Main, missing.Message);
    }

    [Fact]
    public void Search_finds_strings_types_members_constants_and_opcodes()
    {
        var s = _dex.Search(_apk, "string", "api.example", 0, 10, default).Items.Single();
        Assert.Equal(("https://api.example.com/v1", Main + "->onCreate(Landroid/os/Bundle;)V", 3, "const-string"), (s.Value, s.Method, s.Offset, s.Opcode));
        Assert.Contains("not loaded by code", _dex.Search(_apk, "string", "savedInstance", 0, 10, default).Notes.Single());
        Assert.Contains(_dex.Search(_apk, "type", "*.Main", 0, 10, default).Items, h => h.Kind == "class" && h.Value == Main);
        var compute = _dex.Search(_apk, "method", "compute", 0, 10, default);
        Assert.Equal([ComputeInt, ComputeString], compute.Items.Select(h => h.Value));
        Assert.Equal(1, _dex.Search(_apk, "method", "*util/Log;->d(*", 0, 10, default).Items.Single().Uses);
        Assert.Equal(2, _dex.Search(_apk, "field", "name", 0, 10, default).Items.Single().Uses);
        Assert.Equal(Main + "->pick(I)I", _dex.Search(_apk, "const", "1.0", 0, 10, default).Items.Single().Method);
        Assert.Single(_dex.Search(_apk, "const", "-1", 0, 10, default).Items);
        Assert.Equal(3, _dex.Search(_apk, "opcode", "invoke-static", 0, 10, default).Total);
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => _dex.Search(_apk, "const", "x", 0, 10, default)).Code);
    }

    [Fact]
    public void References_keep_overloads_apart_and_name_field_reads_writes_and_callees()
    {
        var callers = _dex.References(_apk, Log, null, null, 0, 10, default);
        Assert.Equal(("method", Log), (callers.TargetKind, callers.Target));
        Assert.Equal([Main + "->guarded()V", Main + "->onCreate(Landroid/os/Bundle;)V"], callers.Items.Select(r => r.Method));

        var ambiguous = Assert.Throws<ToolError>(() => _dex.References(_apk, "com.example.app.Main::compute", null, null, 0, 10, default));
        Assert.Equal(ErrorCode.Ambiguous, ambiguous.Code);
        Assert.Contains(ComputeInt, ambiguous.Message);
        Assert.Equal(ComputeString, _dex.References(_apk, "com.example.app.Main::compute(String)", null, "from", 0, 10, default).Target);
        Assert.Equal(ComputeInt, _dex.References(_apk, "Lcom/example/app/Main;->compute(I)I", null, "from", 0, 10, default).Target);

        var field = _dex.References(_apk, "com.example.app.Main::name", null, null, 0, 10, default);
        Assert.Equal(("field", NameField), (field.TargetKind, field.Target));
        Assert.Equal([("read", ComputeInt, 6), ("write", Main + "->onCreate(Landroid/os/Bundle;)V", 5)], field.Items.Select(r => (r.Kind, r.Method, r.Offset)));

        var from = _dex.References(_apk, ComputeInt, null, "from", 0, 10, default);
        Assert.Equal([("read", CountField), ("read", NameField)], from.Items.Select(r => (r.Kind, r.Target)));
        var framework = _dex.References(_apk, "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I", null, null, 0, 10, default);
        Assert.Equal(Log, framework.Items.Single().Method);
        Assert.Equal(Log, _dex.References(_apk, "\"Example\"", null, null, 0, 10, default).Items.Single().Method);
        var cls = _dex.References(_apk, Helper, null, null, 0, 10, default);
        // Two calls to Helper.log and the write of Helper.level.
        Assert.Equal(("class", 3), (cls.TargetKind, cls.Total));
        Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => _dex.References(_apk, "com.example.app.Main::nope", null, null, 0, 10, default)).Code);
    }

    [Fact]
    public void References_to_a_dotted_framework_class_equal_its_descriptor()
    {
        var byDescriptor = _dex.References(_apk, "Landroid/util/Log;", null, null, 0, 10, default);
        var dotted = _dex.References(_apk, "android.util.Log", null, null, 0, 10, default);
        Assert.Equal(("class", "Landroid/util/Log;"), (dotted.TargetKind, dotted.Target));
        Assert.Equal(1, dotted.Total);
        Assert.Equal(byDescriptor.Items, dotted.Items);
        Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => _dex.References(_apk, "android.util.Nope", null, null, 0, 10, default)).Code);
    }

    [Fact]
    public void DEX_files_jars_and_bundles_read_and_other_files_are_refused()
    {
        var dex = Save(_dir, "classes.dex", Dex());
        Assert.Equal(4, _dex.ListClasses(dex, null, null, 0, 10, default).Total);
        var jar = Save(_dir, "lib.jar", ContainerFixtures.Zip(("classes.dex", Dex()), ("META-INF/MANIFEST.MF", [1])));
        Assert.Equal(4, _dex.ListClasses(jar, null, null, 0, 10, default).Total);
        var aab = Save(_dir, "app.aab", ContainerFixtures.Zip(("base/manifest/AndroidManifest.xml", [1]), ("base/dex/classes.dex", Dex())));
        Assert.Equal(4, _dex.ListClasses(aab, null, null, 0, 10, default).Total);
        var classJar = Save(_dir, "classes.jar", ContainerFixtures.Zip(("p/A.class", [0xCA, 0xFE, 0xBA, 0xBE])));
        Assert.Contains("decompile_java", Assert.Throws<ToolError>(() => _dex.ListClasses(classJar, null, null, 0, 10, default)).Remediation);
        var none = Save(_dir, "none.apk", Apk());
        Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => _dex.ListClasses(none, null, null, 0, 10, default)).Code);
        Assert.Equal(ErrorCode.MalformedInput, Assert.Throws<ToolError>(() => _dex.ListClasses(Env.FixturePath, null, null, 0, 10, default)).Code);
    }

    /// <summary>A caller waiting for the code index stops at its cancellation; the build goes on for the next caller.</summary>
    [Fact]
    public void Code_index_wait_is_cancellable()
    {
        var b = new DexBuilder();
        for (int c = 0; c < 400; c++)
        {
            var cls = b.Class($"Lp/C{c};", 1);
            for (int m = 0; m < 10; m++)
                cls.Method($"m{m}", "V", [], 9, [.. Enumerable.Range(0, 40).Select(i => Asm.ConstString(0, $"s{c}.{m}.{i}")), Asm.ReturnVoid()]).Registers = 1;
        }
        var index = DexIndex.Load(Save(_dir, "big.dex", b.Build()), AnalysisLimits.Default, default);
        Assert.ThrowsAny<OperationCanceledException>(() => index.EnsureCode(new CancellationToken(true)));
        index.EnsureCode(default);
        Assert.Equal(400 * 10 * 40, index.Refs.Count);
    }

    [Fact]
    [FuzzEntry(typeof(Core.Mobile.DexFile))]
    public void Damaged_DEX_never_throws()
    {
        var good = Dex();
        var random = new Random(11);
        for (int n = 0; n < 400; n++)
        {
            var bytes = (byte[])good.Clone();
            for (int k = 0; k < 6; k++) bytes[random.Next(8, bytes.Length)] = (byte)random.Next(256);
            if (n % 3 == 0) bytes = bytes[..random.Next(DexFile.HeaderSize, bytes.Length)];
            var f = DexFile.Read(bytes, "x.dex");
            foreach (var c in f.Classes)
            {
                var (fields, methods) = f.ClassData(c);
                _ = f.Annotations(c);
                _ = f.StaticValues(c).Select(v => v.ToString()).ToList();
                foreach (var x in fields) _ = f.Field(x.FieldIndex).Descriptor;
                foreach (var m in methods)
                {
                    _ = f.Method(m.MethodIndex).Descriptor;
                    if (f.Code(m.CodeOffset) is { } code)
                    {
                        _ = Dalvik.Decode(code.Instructions);
                        _ = f.Debug(code.DebugInfoOffset);
                    }
                }
            }
        }
    }
}
