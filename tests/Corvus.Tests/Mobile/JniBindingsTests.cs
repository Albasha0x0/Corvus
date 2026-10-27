using System.Buffers.Binary;
using System.Text;
using Corvus.Core;
using Corvus.Services.Mobile;
using Corvus.Tests.NativeFormats;

namespace Corvus.Tests;

/// <summary>JNI bindings of a test-built APK: Java_ exports (short and overload names), RegisterNatives tables and the methods left unbound.</summary>
public class JniBindingsTests
{
    private const string Native = "Lcom/example/jni/Native;", Other = "Lcom/example/jni/Other;", Third = "Lcom/example/jni/Third;", Nested = "Lcom/example/my_pkg/Na$Inner;";

    internal static byte[] Dex(Action<DexBuilder>? more = null)
    {
        var b = new DexBuilder();
        var n = b.Class(Native);
        n.Method("hello", "Ljava/lang/String;", [], 0x109);
        n.Method("add", "I", ["I", "I"], 0x109);
        n.Method("add", "J", ["J", "J"], 0x109);
        n.Method("reg", "V", ["I"], 0x109);
        n.Method("missing", "V", [], 0x109);
        b.Class(Other).Method("init", "V", [], 0x109);
        b.Class(Third).Method("init", "V", [], 0x109);
        b.Class(Nested).Method("do_it", "V", ["Ljava/lang/String;", "[I"], 0x101);
        more?.Invoke(b);
        return b.Build();
    }

    /// <summary>ADRP + ADD of <paramref name="target"/> into x<paramref name="reg"/> at <paramref name="pc"/>.</summary>
    private static uint[] Address(uint pc, uint target, int reg)
    {
        long pages = ((long)target >> 12) - (pc >> 12);
        uint adrp = 0x90000000u | (uint)(pages & 3) << 29 | (uint)((pages >> 2) & 0x7FFFF) << 5 | (uint)reg;
        uint add = 0x91000000u | (target & 0xFFF) << 10 | (uint)reg << 5 | (uint)reg;
        return [adrp, add];
    }

    internal static byte[] Library(string soName = "libnative.so", string dataSection = ".data.rel.ro")
    {
        const uint Data = ElfWriter.DataRva, Text = ElfWriter.TextRva;
        var data = new byte[0x400];
        var strings = new Dictionary<string, uint>();
        uint at = 0;
        foreach (var s in new[] { "reg", "(I)V", "init", "()V", "com/example/jni/Third", "not a name" })
        {
            strings[s] = Data + at;
            Encoding.ASCII.GetBytes(s).CopyTo(data, (int)at);
            at += (uint)s.Length + 1;
        }
        uint table1 = Data + 0x100, table2 = Data + 0x200, junk = Data + 0x300;
        var relocations = new List<ElfWriter.Reloc>();
        void Ptr(uint slot, uint target) => relocations.Add(new(slot, 1027, Addend: target));
        // Table 1: reg(I)V, unique in the DEX code; table 2: init()V, declared by two classes.
        Ptr(table1, strings["reg"]); Ptr(table1 + 8, strings["(I)V"]); Ptr(table1 + 16, Text + 0x40);
        Ptr(table2, strings["init"]); Ptr(table2 + 8, strings["()V"]); Ptr(table2 + 16, Text + 0x48);
        // Not a table: the name pointer is not a Java identifier.
        Ptr(junk, strings["not a name"]); Ptr(junk + 8, strings["()V"]); Ptr(junk + 16, Text + 0x48);

        // JNI_OnLoad: x1 = "com/example/jni/Third", x2 = table 2 (FindClass, RegisterNatives); then the native functions.
        var code = new List<uint>();
        code.AddRange(Address(Text, strings["com/example/jni/Third"], 1));
        code.AddRange(Address(Text + 8, table2, 2));
        code.Add(0xD65F03C0);
        while (code.Count < 0x60 / 4) code.Add(0xD65F03C0);
        var text = new byte[code.Count * 4];
        for (int i = 0; i < code.Count; i++) BinaryPrimitives.WriteUInt32LittleEndian(text.AsSpan(i * 4), code[i]);
        return new ElfWriter
        {
            Text = text,
            Data = data,
            DataSectionName = dataSection,
            Relocations = relocations,
            SoName = soName,
            Symbols =
            [
                new("JNI_OnLoad", Text, 0x10),
                new("Java_com_example_jni_Native_hello", Text + 0x20, 4),
                new("Java_com_example_jni_Native_add__II", Text + 0x24, 4),
                new("Java_com_example_jni_Native_add__JJ", Text + 0x28, 4),
                new("Java_com_example_my_1pkg_Na_00024Inner_do_1it", Text + 0x2C, 4),
                new("Java_com_example_jni_Gone_x", Text + 0x30, 4),
            ],
        }.Build();
    }

    /// <summary>A table's class found through the code index is kept per library, so paging calls do not rebuild the index.</summary>
    [Fact]
    public void Table_owners_from_the_code_index_are_kept_per_library()
    {
        using var dir = new TempDir();
        var library = Library($"lib{Guid.NewGuid():N}.so");
        var path = AndroidSamples.Save(dir, "jni.apk", AndroidSamples.Apk(30, ("classes.dex", Dex()), ("lib/arm64-v8a/libnative.so", library)));
        var jni = new JniBindings(new DexService());
        const uint table2 = ElfWriter.DataRva + 0x200;
        Assert.False(JniBindings.OwnerCached(library, table2));
        string Owner() => jni.List(path, null, null, "registered", 0, 100, default).Items.Single(i => i.JavaMethod == $"{Third}->init()V").Confidence!;
        Assert.Equal("class_string", Owner());
        Assert.True(JniBindings.OwnerCached(library, table2));
        Assert.Equal("class_string", Owner());
    }

    /// <summary>Relocation, symbol and unwind sections are not scanned for tables: in an AOT library they are most of the data and hold none.</summary>
    [Fact]
    public void Tables_are_read_from_data_sections_only()
    {
        using var dir = new TempDir();
        int Tables(string section)
        {
            var path = AndroidSamples.Save(dir, $"jni{section}.apk", AndroidSamples.Apk(30, ("classes.dex", Dex()), ("lib/arm64-v8a/libnative.so", Library(dataSection: section))));
            return new JniBindings(new DexService()).List(path, null, null, null, 0, 100, default).Libraries.Single().RegisterNativesTables;
        }
        Assert.Equal(2, Tables(".data.rel.ro"));
        Assert.Equal(0, Tables(".eh_frame"));
    }

    /// <summary>The owner search reads references and strings: virtual call resolution, 40-50 % of a large ARM32 library's index, is skipped.</summary>
    [Fact]
    public void The_owner_index_skips_virtual_call_resolution() => Assert.False(JniBindings.IndexOptions.ResolveVirtualCalls);

    [Theory]
    [InlineData("Lcom/example/my_pkg/Na$Inner;", "do_it", "Java_com_example_my_1pkg_Na_00024Inner_do_1it")]
    [InlineData("Lp/C;", "mé", "Java_p_C_m_000e9")]
    public void Short_names_are_mangled(string cls, string method, string expected) => Assert.Equal(expected, JniBindings.ShortName(cls, method));

    [Fact]
    public void Long_names_mangle_the_parameters() =>
        Assert.Equal("Java_p_C_f__Ljava_lang_String_2_3I_3_3J", JniBindings.LongName("Lp/C;", "f", "(Ljava/lang/String;[I[[J)V"));

    [Fact]
    public void Exports_tables_and_unbound_methods_are_paired()
    {
        using var dir = new TempDir();
        var plain = new ElfWriter { Text = new byte[0x20], SoName = "libplain.so", Symbols = [new("plain_function", ElfWriter.TextRva, 4)] }.Build();
        var path = AndroidSamples.Save(dir, "jni.apk", AndroidSamples.Apk(30, ("classes.dex", Dex()), ("lib/arm64-v8a/libnative.so", Library()),
            ("lib/arm64-v8a/libplain.so", plain), ("lib/x86_64/libnative.so", Library())));
        var jni = new JniBindings(new DexService());
        var r = jni.List(path, null, null, null, 0, 100, default);
        string Row(JniBinding b) => $"{b.Kind} {b.JavaMethod} {b.Symbol} {b.Address} {b.Confidence}";
        var rows = r.Items.Select(Row).ToList();

        var lib = Assert.Single(r.Libraries);
        Assert.Equal(("lib/arm64-v8a/libnative.so", 5, true, 2, 2), (lib.Library, lib.JavaExports, lib.HasJniOnLoad, lib.RegisterNativesTables, lib.RegisteredMethods));
        Assert.Contains(r.Notes, n => n.Contains("abi=all"));
        // A library without JNI content is counted, not listed (.NET for Android ships hundreds of them).
        Assert.Contains(r.Notes, n => n.StartsWith("1 of 2 libraries have no Java_ export"));
        Assert.Contains($"static_export {Native}->hello()Ljava/lang/String; Java_com_example_jni_Native_hello 0x1020 ", rows);
        Assert.Contains($"static_export {Native}->add(II)I Java_com_example_jni_Native_add__II 0x1024 ", rows);
        Assert.Contains($"static_export {Native}->add(JJ)J Java_com_example_jni_Native_add__JJ 0x1028 ", rows);
        Assert.Contains($"static_export {Nested}->do_it(Ljava/lang/String;[I)V Java_com_example_my_1pkg_Na_00024Inner_do_1it 0x102C ", rows);
        Assert.Contains("export_only  Java_com_example_jni_Gone_x 0x1030 ", rows);
        Assert.Contains($"registered {Native}->reg(I)V  0x1040 name_and_signature", rows);
        Assert.Contains($"registered {Third}->init()V  0x1048 class_string", rows);
        Assert.Equal("0x20A00", r.Items.Single(i => i.JavaMethod == $"{Third}->init()V").Table);
        Assert.Contains($"unresolved {Native}->missing()V   ", rows);
        Assert.Contains($"unresolved {Other}->init()V   ", rows);
        Assert.Equal(9, r.Total);

        Assert.Equal(2, jni.List(path, "all", null, null, 0, 100, default).Libraries.Count);
        Assert.All(jni.List(path, null, "com.example.jni.Native", "static_export", 0, 100, default).Items, i => Assert.StartsWith(Native, i.JavaMethod));
        Assert.Equal(3, jni.List(path, null, "com.example.jni.Native", "static_export", 0, 100, default).Total);
        var page = jni.List(path, null, null, null, 2, 3, default);
        Assert.Equal((3, 9), (page.Items.Count, page.Total));
        Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => jni.List(path, "mips", null, null, 0, 10, default)).Code);
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => jni.List(path, null, null, "dynamic", 0, 10, default)).Code);
    }

    /// <summary>The .NET for Android runtime library (a real NDK build) with the Java side of its runtime class declared in a test-built DEX.</summary>
    [Fact]
    [Trait("Speed", "Slow")]
    public void Real_runtime_library_exports_bind_their_Java_methods()
    {
        const string Runtime = "Lmono/android/Runtime;";
        var b = new DexBuilder();
        var runtime = b.Class(Runtime);
        runtime.Method("register", "V", ["Ljava/lang/String;", "Ljava/lang/Class;", "Ljava/lang/String;"], 0x109);
        runtime.Method("notifyTimeZoneChanged", "V", [], 0x109);
        runtime.Method("propagateUncaughtException", "V", ["Ljava/lang/Thread;", "Ljava/lang/Throwable;"], 0x109);
        runtime.Method("dumpTimingData", "V", [], 0x109);
        b.Class("Lnet/dot/android/crypto/DotnetProxyTrustManager;").Method("verifyRemoteCertificate", "Z", ["J"], 0x109);
        var so = File.ReadAllBytes(RealPackages.File("Microsoft.Android.Runtime.35.android-arm64", "35.0.105", "runtimes", "android-arm64", "native", "libmono-android.release.so"));
        using var dir = new TempDir();
        var path = AndroidSamples.Save(dir, "runtime.apk", AndroidSamples.Apk(30, ("classes.dex", b.Build()), ("lib/arm64-v8a/libmonodroid.so", so)));
        var r = new JniBindings(new DexService()).List(path, null, null, null, 0, 200, default);
        var lib = Assert.Single(r.Libraries);
        Assert.True(lib.HasJniOnLoad);
        Assert.True(lib.JavaExports >= 6, $"{lib.JavaExports} Java_ exports");
        foreach (var m in new[] { "register", "notifyTimeZoneChanged", "propagateUncaughtException", "dumpTimingData" })
        {
            var row = r.Items.Single(i => i.JavaMethod?.StartsWith($"{Runtime}->{m}(", StringComparison.Ordinal) == true);
            Assert.Equal(("static_export", $"Java_mono_android_Runtime_{m}"), (row.Kind, row.Symbol));
            Assert.StartsWith("0x", row.Address);
        }
        // Imported from another library, not exported here.
        Assert.Contains(r.Items, i => i is { Kind: "unresolved", JavaMethod: "Lnet/dot/android/crypto/DotnetProxyTrustManager;->verifyRemoteCertificate(J)Z" });
        // init and initInternal are not declared in this DEX.
        Assert.Contains(r.Items, i => i is { Kind: "export_only", Symbol: "Java_mono_android_Runtime_initInternal" });
    }

    [Fact]
    public void Package_without_libraries_lists_every_native_method_as_unresolved()
    {
        using var dir = new TempDir();
        var path = AndroidSamples.Save(dir, "plain.apk", AndroidSamples.Apk(30, ("classes.dex", Dex())));
        var r = new JniBindings(new DexService()).List(path, null, null, null, 0, 100, default);
        Assert.Equal(8, r.Total);
        Assert.All(r.Items, i => Assert.Equal("unresolved", i.Kind));
        Assert.Contains(r.Notes, n => n.Contains("no native libraries"));
    }
}
