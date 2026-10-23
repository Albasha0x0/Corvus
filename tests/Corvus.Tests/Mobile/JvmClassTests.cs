using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Core.Mobile;
using Corvus.Native.Providers;

namespace Corvus.Tests;

/// <summary>The class-file reader's listing against <c>javap -c -p</c> of a JDK 23+ (its javap reads through the ClassFile API).</summary>
public sealed class JvmClassTests(Xunit.Abstractions.ITestOutputHelper output)
{
    /// <summary>Jars from NuGet packages: the Android API (stubs), Guava for Android (Java 8) and the Kotlin standard library (kotlinc output).</summary>
    public static IEnumerable<object[]> RealJars() =>
    [
        ["mono.android"], ["guava"], ["kotlin-stdlib"],
    ];

    private static string Jar(string name, string folder) => name switch
    {
        "mono.android" => RealPackages.File("Microsoft.Android.Ref.35", "35.0.105", "ref", "net9.0", "mono.android.jar"),
        "guava" => FromAar(RealPackages.File("Xamarin.Google.Guava", "33.6.0.1", "lib", "net9.0-android35.0", "Xamarin.Google.Guava.aar"), folder),
        "kotlin-stdlib" => FromAar(RealPackages.File("Xamarin.Kotlin.StdLib", "2.3.21", "lib", "net9.0-android35.0", "Xamarin.Kotlin.StdLib.aar"), folder),
        _ => throw new ArgumentException(name),
    };

    /// <summary>The largest jar in an .aar (a binding package keeps it under libs/ by hash).</summary>
    private static string FromAar(string aar, string folder)
    {
        using var zip = ZipFile.OpenRead(aar);
        var entry = zip.Entries.Where(e => e.FullName.EndsWith(".jar", StringComparison.Ordinal)).MaxBy(e => e.Length)!;
        var path = Path.Combine(folder, Path.GetFileNameWithoutExtension(aar) + ".jar");
        entry.ExtractToFile(path, overwrite: true);
        return path;
    }

    [Permit("reference-tool")]
    [Trait("Speed", "Slow")]
    [JavapTheory]
    [MemberData(nameof(RealJars))]
    public void Listing_equals_javap(string name)
    {
        using var dir = new TempDir();
        var (classes, differing, first) = Compare(Jar(name, dir.Path), dir.Path);
        output.WriteLine($"{name}: {classes} classes, {differing} differ");
        Assert.True(differing == 0, first);
        Assert.True(classes > 100);
    }

    /// <summary>Jars of a local corpus (CORVUS_JAVA_JARS, a folder searched three levels deep): shaded and transformed builds.</summary>
    [Permit("reference-tool")]
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact(JavaJars)]
    public void Listing_equals_javap_on_the_local_corpus()
    {
        Assert.True(JavapTheoryAttribute.Jdk != null, "No JDK 23+ (JAVA_HOME or PATH) for javap.");
        var jars = Directory.EnumerateFiles(RealData.Get(JavaJars)!, "*.jar", new EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 3 }).ToList();
        Assert.NotEmpty(jars);
        foreach (var jar in jars)
        {
            using var dir = new TempDir();
            var (classes, differing, first) = Compare(jar, dir.Path);
            output.WriteLine($"{Path.GetFileName(jar)}: {classes} classes, {differing} differ");
            Assert.True(differing == 0, first);
        }
    }

    public const string JavaJars = "CORVUS_JAVA_JARS";

    /// <summary>
    /// p/Shape: a field, a constructor, a static method with a tableswitch and a string with a newline, and two overloads of m.
    /// </summary>
    internal static byte[] Shape()
    {
        var pool = new List<byte[]>();
        int Add(params byte[] entry) { pool.Add(entry); return pool.Count; }
        int Utf(string s) { var b = Encoding.UTF8.GetBytes(s); return Add([1, (byte)(b.Length >> 8), (byte)b.Length, .. b]); }
        byte[] U2(int v) => [(byte)(v >> 8), (byte)v];
        int Class(string name) => Add([7, .. U2(Utf(name))]);
        int self = Class("p/Shape"), obj = Class("java/lang/Object");
        int init = Utf("<init>"), voidDesc = Utf("()V");
        int nat = Add([12, .. U2(init), .. U2(voidDesc)]);
        int objInit = Add([10, .. U2(obj), .. U2(nat)]);
        int text = Add([8, .. U2(Utf("a\nb"))]);
        int code = Utf("Code"), source = Utf("SourceFile"), sourceName = Utf("Shape.java");
        int size = Utf("size"), intDesc = Utf("I"), pick = Utf("pick"), pickDesc = Utf("(I)Ljava/lang/Object;"), m = Utf("m"), mInt = Utf("(I)V"), mString = Utf("(Ljava/lang/String;)V");
        byte[] Code(int stack, int locals, byte[] body) =>
            [.. U2(code), .. BitConverter.GetBytes(System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(12 + body.Length)), .. U2(stack), .. U2(locals),
             .. BitConverter.GetBytes(System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(body.Length)), .. body, 0, 0, 0, 0];
        byte[] Method(int access, int name, int desc, byte[] body) => [.. U2(access), .. U2(name), .. U2(desc), 0, 1, .. Code(2, 2, body)];
        // iload_0; tableswitch (padded to 4; targets relative to 1) 0 -> 24 ldc, 1 and default -> 27 aconst_null; areturn
        byte[] Switch = [0x1a, 0xaa, 0, 0, 0, 0, 0, 0x1a, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0x17, 0, 0, 0, 0x1a, 0x12, (byte)text, 0xb0, 0x01, 0xb0];
        var file = new List<byte>([0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52]);
        file.AddRange(U2(pool.Count + 1));
        foreach (var e in pool) file.AddRange(e);
        file.AddRange([0, 0x21, .. U2(self), .. U2(obj), 0, 0]);
        file.AddRange([0, 1, 0, 2, .. U2(size), .. U2(intDesc), 0, 0]);
        file.AddRange(U2(4));
        file.AddRange(Method(1, init, voidDesc, [0x2a, 0xb7, .. U2(objInit), 0xb1]));
        file.AddRange(Method(9, pick, pickDesc, Switch));
        file.AddRange(Method(1, m, mInt, [0xb1]));
        file.AddRange(Method(1, m, mString, [0xb1]));
        file.AddRange([0, 1, .. U2(source), 0, 0, 0, 2, .. U2(sourceName)]);
        return [.. file];
    }

    /// <summary>module-info of module m@1: requires java.base, uses p.S, and two provides (p.S with p.A, p.B; p.T with p.C).</summary>
    internal static byte[] ModuleInfo()
    {
        var pool = new List<byte[]>();
        int Add(params byte[] entry) { pool.Add(entry); return pool.Count; }
        int Utf(string s) { var b = Encoding.UTF8.GetBytes(s); return Add([1, (byte)(b.Length >> 8), (byte)b.Length, .. b]); }
        byte[] U2(int v) => [(byte)(v >> 8), (byte)v];
        int Class(string name) => Add([7, .. U2(Utf(name))]);
        int Module(string name) => Add([19, .. U2(Utf(name))]);
        int self = Class("module-info"), source = Utf("SourceFile"), sourceName = Utf("module-info.java"), moduleAttr = Utf("Module");
        int m = Module("m"), version = Utf("1"), javaBase = Module("java.base");
        int s = Class("p/S"), t = Class("p/T"), a = Class("p/A"), b = Class("p/B"), c = Class("p/C");
        byte[] body = [.. U2(m), 0, 0, .. U2(version),
            0, 1, .. U2(javaBase), 0x80, 0, 0, 0,
            0, 0, 0, 0,
            0, 1, .. U2(s),
            0, 2, .. U2(s), 0, 2, .. U2(a), .. U2(b), .. U2(t), 0, 1, .. U2(c)];
        var file = new List<byte>([0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 53]);
        file.AddRange(U2(pool.Count + 1));
        foreach (var e in pool) file.AddRange(e);
        file.AddRange([0x80, 0, .. U2(self), 0, 0, 0, 0, 0, 0, 0, 0]);
        file.AddRange([0, 2, .. U2(source), 0, 0, 0, 2, .. U2(sourceName)]);
        file.AddRange([.. U2(moduleAttr), .. BitConverter.GetBytes(System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(body.Length)), .. body]);
        return [.. file];
    }

    [Fact]
    public void Module_info_with_several_provides_lists_as_javap_does()
    {
        Assert.Equal("""
            Compiled from "module-info.java"
            module m@1 {
              requires java.base;
              uses p.S;
              provides  p.S with
                p.A,
                p.B;
              provides  p.T with
                p.C;
            }

            """, JvmListing.Class(JvmClass.Read(ModuleInfo())));
    }

    [Fact]
    public void Disassemble_dex_lists_a_jar_of_class_files_as_javap_does()
    {
        using var dir = new TempDir();
        var jar = AndroidSamples.Save(dir, "lib.jar", ContainerFixtures.Zip(("p/Shape.class", Shape())));
        var dex = new Corvus.Services.Mobile.DexService();
        var text = dex.Disassemble(jar, "p.Shape", false, default);
        output.WriteLine(text);
        Assert.Equal("""
            Compiled from "Shape.java"
            public class p.Shape {
              private int size;

              public p.Shape();
                Code:
                     0: aload_0
                     1: invokespecial #8                  // Method java/lang/Object."<init>":()V
                     4: return

              public static java.lang.Object pick(int);
                Code:
                     0: iload_0
                     1: tableswitch   { // 0 to 1
                                   0: 24
                                   1: 27
                             default: 27
                        }
                    24: ldc           #10                 // String a\nb
                    26: areturn
                    27: aconst_null
                    28: areturn

              public void m(int);
                Code:
                     0: return

              public void m(java.lang.String);
                Code:
                     0: return
            }

            """, text);
        Assert.Equal("""
              public void m(int);
                Code:
                     0: return

            """, dex.Disassemble(jar, "Lp/Shape;->m(I)V", false, default));
        Assert.StartsWith("  public void m(java.lang.String);", dex.Disassemble(jar, "p.Shape::m(String)", false, default));
        Assert.Equal(ErrorCode.Ambiguous, Assert.Throws<ToolError>(() => dex.Disassemble(jar, "p.Shape::m", false, default)).Code);
        Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => dex.Disassemble(jar, "p.Other", false, default)).Code);
        var single = AndroidSamples.Save(dir, "Shape.class", Shape());
        Assert.Equal(text, dex.Disassemble(single, "p.Shape", false, default));
    }

    [Fact]
    [FuzzEntry(typeof(JvmClass), typeof(JvmListing))]
    public void Mutated_class_files_fail_only_as_malformed()
    {
        var failures = FormatFuzz.Run(Shape(), b =>
        {
            try { JvmListing.Class(JvmClass.Read(b)); }
            catch (InvalidDataException) { }
        }, 3000);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    [Fact]
    public void Numbers_print_as_Java_does()
    {
        Assert.Equal("1.0", JavaNumbers.Double(1));
        Assert.Equal("-0.0", JavaNumbers.Double(-0.0));
        Assert.Equal("0.001", JavaNumbers.Double(0.001));
        Assert.Equal("1.0E-4", JavaNumbers.Double(0.0001));
        Assert.Equal("1234567.0", JavaNumbers.Double(1234567));
        Assert.Equal("1.0E7", JavaNumbers.Double(1e7));
        Assert.Equal("1.7976931348623157E308", JavaNumbers.Double(double.MaxValue));
        Assert.Equal("4.9E-324", JavaNumbers.Double(double.Epsilon));
        Assert.Equal("0.1", JavaNumbers.Float(0.1f));
        Assert.Equal("3.4028235E38", JavaNumbers.Float(float.MaxValue));
        Assert.Equal("NaN", JavaNumbers.Float(float.NaN));
    }

    [Fact]
    public void Names_that_are_not_binary_names_are_quoted()
    {
        Assert.Equal("java/lang/String", JvmListing.CheckName("java/lang/String"));
        Assert.Equal("\"<init>\"", JvmListing.CheckName("<init>"));
        Assert.Equal("\"[Ljava/lang/String;\"", JvmListing.CheckName("[Ljava/lang/String;"));
        Assert.Equal("\"box-impl\"", JvmListing.CheckName("box-impl"));
    }

    /// <summary>Every class of <paramref name="jar"/> listed by us and by javap; the count that differ and the first difference.</summary>
    private (int Classes, int Differing, string First) Compare(string jar, string work)
    {
        var root = Path.Combine(work, "classes");
        var files = new List<string>();
        var names = new Dictionary<string, string>(StringComparer.Ordinal);
        Directory.CreateDirectory(root);
        using (var zip = ZipFile.OpenRead(jar))
            foreach (var e in zip.Entries.Where(e => e.FullName.EndsWith(".class", StringComparison.Ordinal) && !e.FullName.StartsWith("META-INF/", StringComparison.Ordinal)))
            {
                // Numbered: entries that differ only in case would collide on a case-insensitive file system.
                var path = Path.Combine(root, $"{files.Count}.class");
                e.ExtractToFile(path, overwrite: true);
                files.Add(path);
                names[path] = e.FullName;
            }
        var expected = JavapOracle.Run(files, work);
        int differing = 0;
        var first = "";
        var watch = System.Diagnostics.Stopwatch.StartNew();
        foreach (var file in files)
        {
            string ours;
            try { ours = JvmListing.Class(JvmClass.Read(File.ReadAllBytes(file))); }
            catch (InvalidDataException ex) { ours = "error: " + ex.Message; }
            // javap 24+ prints a diagnostic line before a member whose flags carry a bit the JVMS leaves unassigned there (ACC_ENUM on a
            // scalac method), then lists the member: the diagnostic is not part of the listing
            var theirs = string.Join('\n', expected[file].Split('\n').Where(l => !l.StartsWith("Error: Access Flags: Unmatched bit position ", StringComparison.Ordinal)));
            if (ours == theirs) continue;
            if (differing++ == 0) first = $"{names[file]}\n{FirstDifference(theirs, ours)}";
        }
        output.WriteLine($"listed {files.Count} classes in {watch.ElapsedMilliseconds} ms");
        if (differing > 0) output.WriteLine(first);
        return (files.Count, differing, first);
    }

    private static string FirstDifference(string expected, string actual)
    {
        var a = expected.Split('\n');
        var b = actual.Split('\n');
        for (int i = 0; i < Math.Max(a.Length, b.Length); i++)
        {
            var x = i < a.Length ? a[i] : "<end>";
            var y = i < b.Length ? b[i] : "<end>";
            if (x != y) return $"line {i + 1}\njavap: {x}\nours:  {y}";
        }
        return "equal lines";
    }
}

/// <summary>Runs javap in one JVM over many class files (its ToolProvider), its output is raw UTF-16, so lone surrogates in constants survive.</summary>
internal static class JavapOracle
{
    private const string Source = """
        import java.io.*;
        import java.nio.charset.StandardCharsets;
        import java.nio.file.*;
        import java.util.spi.ToolProvider;

        public class JavapAll {
            public static void main(String[] args) throws Exception {
                var javap = ToolProvider.findFirst("javap").orElseThrow();
                try (var out = new DataOutputStream(new BufferedOutputStream(Files.newOutputStream(Path.of(args[1]))))) {
                    for (var file : Files.readAllLines(Path.of(args[0]), StandardCharsets.UTF_8)) {
                        var text = new StringWriter();
                        var pw = new PrintWriter(text);
                        javap.run(pw, pw, "-c", "-p", file);
                        pw.flush();
                        out.writeChars("\u0001" + file + "\n" + text.toString().replace("\r", ""));
                    }
                }
            }
        }
        """;

    public static Dictionary<string, string> Run(IReadOnlyList<string> files, string work)
    {
        var java = Path.Combine(JavapTheoryAttribute.Jdk!.Home, "bin", OperatingSystem.IsWindows() ? "java.exe" : "java");
        var program = Path.Combine(work, "JavapAll.java");
        File.WriteAllText(program, Source);
        var list = Path.Combine(work, "classes.txt");
        File.WriteAllLines(list, files, new UTF8Encoding(false));
        var result = Path.Combine(work, "javap.txt");
        var (code, text) = Tools.Run(new System.Diagnostics.ProcessStartInfo(java) { ArgumentList = { program, list, result } });
        Assert.True(code == 0, text);
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        var bytes = File.ReadAllBytes(result);
        var chars = new char[bytes.Length / 2];
        for (int i = 0; i < chars.Length; i++) chars[i] = (char)((bytes[2 * i] << 8) | bytes[2 * i + 1]);
        foreach (var block in new string(chars).Split('\u0001', StringSplitOptions.RemoveEmptyEntries))
        {
            int nl = block.IndexOf('\n');
            map[block[..nl]] = block[(nl + 1)..];
        }
        return map;
    }
}

/// <summary>
/// Runs when a JDK 23+ is found (JAVA_HOME, PATH), checked when a test runs (java -version); its javap reads through
/// the ClassFile API, the layout matched.
/// </summary>
[Xunit.Sdk.XunitTestCaseDiscoverer(RunTimeSkips.TheoryDiscoverer, RunTimeSkips.Assembly)]
public sealed class JavapTheoryAttribute : TheoryAttribute, IRunTimeSkip
{
    public static Native.Providers.Ghidra.JavaRuntime? Jdk => Found.Value;
    private static readonly Lazy<Native.Providers.Ghidra.JavaRuntime?> Found = new(() => Native.Providers.Ghidra.JavaRuntime.Locate(null, 23, null, []));

    public string? RunTimeSkip() => Jdk == null ? "No JDK 23+ (JAVA_HOME or PATH)." : null;
}
