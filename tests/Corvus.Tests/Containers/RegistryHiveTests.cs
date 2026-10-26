using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Corvus.Core;
using Corvus.Core.Registry;
using Corvus.Services.Analysis;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Registry hive files: keys, values, large data, deleted keys, and the Offline Registry Library as reference.</summary>
public sealed class RegistryHiveTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static readonly byte[] Big = [.. Enumerable.Range(0, 40_000).Select(i => (byte)(i * 7))];

    /// <summary>Software\Sample with one value of each type, a class name, a large value and a key named in Cyrillic.</summary>
    private static HiveSamples.Node Sample()
    {
        var sample = new HiveSamples.Node("Sample") { Class = "SampleClass" };
        sample.Values.AddRange(
        [
            new("", 1, HiveSamples.Utf16("default\0")),
            new("Text", 1, HiveSamples.Utf16("hello\0")),
            new("Path", 2, HiveSamples.Utf16("%SystemRoot%\\x\0")),
            new("List", 7, HiveSamples.Utf16("a\0b\0\0")),
            new("Count", 4, HiveSamples.U32(0x12345678)),
            new("Order", 5, [0x12, 0x34, 0x56, 0x78]),
            new("Size", 11, BitConverter.GetBytes(0x1122334455667788UL)),
            new("Blob", 3, [1, 2, 3, 4, 5, 6]),
            new("Large", 3, Big),
            new("Значение", 1, HiveSamples.Utf16("юникод\0")),
        ]);
        var software = new HiveSamples.Node("Software");
        software.Children.Add(sample);
        software.Children.Add(new HiveSamples.Node("Ключ"));
        software.Children.Add(new HiveSamples.Node("alpha"));
        var root = new HiveSamples.Node("ROOT");
        root.Children.Add(software);
        root.Children.Add(new HiveSamples.Node("Environment") { Values = { new("TEMP", 2, HiveSamples.Utf16("%USERPROFILE%\\Temp\0")) } });
        return root;
    }

    private RegistryFileView.Facts View(byte[] hive, string? table = null, long offset = 0, int? limit = null)
    {
        var path = Path.Combine(_dir.Path, "hive.dat");
        File.WriteAllBytes(path, hive);
        var f = FileInput.Open(path);
        f.Options = new FileViewOptions("registry", table, Offset: offset, Limit: limit);
        return (RegistryFileView.Facts)new RegistryFileView().Inspect(f, default)!.Detail;
    }

    [Fact]
    public void A_hive_lists_its_keys_and_values_by_type()
    {
        var root = View(new HiveSamples().Build(Sample()));
        Assert.Equal(("\\??\\C:\\work\\sample.dat", 1, 5, false, true), (root.Header.FileName, root.Header.Major, root.Header.Minor, root.Header.Dirty, root.Header.ChecksumValid));
        Assert.Equal((6L, 11L), (root.Keys, root.Values));
        Assert.Equal(["Environment", "Software"], root.SubkeyPage.Select(k => k.Name));
        Assert.Equal(0, root.RecoveredKeys);

        var sample = View(new HiveSamples().Build(Sample()), "ROOT\\software\\SAMPLE");
        Assert.Equal(("ROOT\\software\\SAMPLE", "SampleClass", 10), (sample.Path, sample.Class, sample.KeyValues));
        var values = sample.ValuePage.ToDictionary(v => v.Name);
        Assert.Equal("default", values["(Default)"].Data);
        Assert.Equal(("REG_SZ", "hello"), (values["Text"].Type, values["Text"].Data));
        Assert.Equal("%SystemRoot%\\x", values["Path"].Data);
        Assert.Equal(["a", "b"], (string[])values["List"].Data);
        Assert.Equal(0x12345678u, values["Count"].Data);
        Assert.Equal(0x12345678u, values["Order"].Data);
        Assert.Equal(0x1122334455667788UL, values["Size"].Data);
        Assert.Equal("010203040506", values["Blob"].Data);
        Assert.Equal(40_000, values["Large"].Size);
        Assert.Equal("юникод", values["Значение"].Data);

        var software = View(new HiveSamples().Build(Sample()), "Software");
        Assert.Equal(["alpha", "Sample", "Ключ"], software.SubkeyPage.Select(k => k.Name));
    }

    [Fact]
    public void Large_values_read_through_their_segments_and_whole_in_old_formats()
    {
        foreach (int minor in new[] { 5, 3 })
        {
            var hive = RegistryHive.Read(new HiveSamples { Minor = minor }.Build(Sample()));
            var large = hive.Values(hive.Find("Software\\Sample")!).Single(v => v.Name == "Large");
            Assert.Equal(Big, large.Data);
            Assert.Empty(hive.Notes);
        }
    }

    [Fact]
    public void Index_root_lists_and_pages_read_in_order()
    {
        var root = new HiveSamples.Node("ROOT");
        for (int i = 0; i < 10; i++) root.Children.Add(new HiveSamples.Node($"key{i:D2}"));
        var bytes = new HiveSamples { SplitAbove = 3 }.Build(root);
        var first = View(bytes, limit: 4);
        Assert.Equal(["key00", "key01", "key02", "key03"], first.SubkeyPage.Select(k => k.Name));
        Assert.Equal(4L, first.Next);
        var rest = View(bytes, offset: 4);
        Assert.Equal(6, rest.SubkeyPage.Count);
        Assert.Null(rest.Next);
    }

    [Fact]
    public void Deleted_keys_and_values_are_recovered_from_free_cells()
    {
        var gone = new HiveSamples.Node("Gone") { Values = { new("Secret", 1, HiveSamples.Utf16("left behind\0")) } };
        var facts = View(new HiveSamples { Deleted = { gone } }.Build(Sample()));
        Assert.Equal((6L, 1, 1), (facts.Keys, facts.RecoveredKeys, facts.RecoveredValues));
        Assert.Equal(("Gone", 1), (facts.RecoveredKeyList[0].Path, facts.RecoveredKeyList[0].Values));
        Assert.Equal(("Secret", "left behind"), (facts.RecoveredValueList[0].Name, facts.RecoveredValueList[0].Data));
    }

    [Fact]
    public void A_dirty_or_cut_hive_is_read_with_notes()
    {
        var dirty = View(new HiveSamples { Sequence2 = 2 }.Build(Sample()));
        Assert.True(dirty.Header.Dirty);
        Assert.Contains(dirty.Notes, n => n.StartsWith("the sequence numbers differ (1, 2)", StringComparison.Ordinal));

        var bytes = new HiveSamples().Build(Sample());
        var cut = bytes[..(bytes.Length - 3000)];
        var hive = RegistryHive.Read(cut);
        foreach (var (_, k) in hive.Walk(default)) hive.Values(k);
        Assert.Contains(hive.Notes, n => n.Contains("the file holds", StringComparison.Ordinal));

        Assert.Throws<InvalidDataException>(() => RegistryHive.Read([.. "regf"u8, 0, 0]));
        var path = Path.Combine(_dir.Path, "bad.dat");
        File.WriteAllBytes(path, [.. "regf"u8, .. new byte[5000]]);
        var f = FileInput.Open(path);
        f.Options = new FileViewOptions("registry");
        Assert.Equal(ErrorCode.MalformedInput, Assert.Throws<ToolError>(() => new RegistryFileView().Inspect(f, default)).Code);
    }

    [Fact]
    [FuzzEntry(typeof(RegistryHive), typeof(RegistryFileView))]
    public void Fuzzed_hives_never_throw()
    {
        var gone = new HiveSamples.Node("Gone") { Values = { new("Secret", 1, HiveSamples.Utf16("x\0")) } };
        var sample = new HiveSamples { SplitAbove = 1, Deleted = { gone } }.Build(Sample());
        var failures = FormatFuzz.Run(sample, b =>
        {
            RegistryHive hive;
            try { hive = RegistryHive.Read(b); }
            catch (InvalidDataException) { return; }
            foreach (var (_, k) in hive.Walk(default))
                foreach (var v in hive.Values(k)) RegistryHive.Render(v.Type, v.Data);
            hive.Recover(default);
            hive.Find("Software\\Sample");
            var file = new FileInput("fuzz.dat", b, "registry hive") { Options = new FileViewOptions("registry", "Software\\Sample") };
            try { new RegistryFileView().Inspect(file, default); }
            catch (ToolError e) when (e.Code == ErrorCode.MalformedInput) { }
        }, 200);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    /// <summary>Every key (path, class, last write) and value (path, name, type, data hash) depth first, as read here.</summary>
    private static List<string> Mine(string path)
    {
        var hive = RegistryHive.Read(File.ReadAllBytes(path));
        var lines = new List<string>();
        foreach (var (p, k) in hive.Walk(default))
        {
            lines.Add(KeyLine(p, k.Class, k.LastWritten?.ToFileTimeUtc() ?? 0));
            lines.AddRange(hive.Values(k).Select(v => ValueLine(p, v.Name, v.Type, v.Data)));
        }
        Assert.True(hive.Notes.Count == 0, string.Join("\n", hive.Notes));
        return lines;
    }

    private static string KeyLine(string path, string? className, long written) => $"K {path} | {className} | {written}";

    private static string ValueLine(string path, string name, int type, byte[] data) => $"V {path} | {name} | {type} | {data.Length} {Convert.ToHexString(SHA256.HashData(data))[..16]}";

    /// <summary>The same listing through the Offline Registry Library (offreg.dll), which reads hive files as the registry does.</summary>
    private static List<string> Theirs(string path)
    {
        Check(Offreg.OROpenHive(path, out var hive));
        var lines = new List<string>();
        try { Walk(hive, "", lines); }
        finally { Check(Offreg.ORCloseHive(hive)); }
        return lines;
    }

    private static void Walk(IntPtr key, string path, List<string> lines)
    {
        var className = new char[256];
        uint classLength = (uint)className.Length, subkeys, values, maxName, maxData;
        long written;
        int error;
        // ERROR_MORE_DATA: the class name needs a larger buffer.
        while ((error = Offreg.ORQueryInfoKey(key, className, ref classLength, out subkeys, out _, out _, out values, out maxName, out maxData, out _, out written)) == 234)
            classLength = (uint)(className = new char[className.Length * 4]).Length;
        Check(error);
        lines.Add(KeyLine(path, classLength > 0 ? new string(className, 0, (int)classLength) : null, written));
        for (uint i = 0; i < values; i++)
        {
            var name = new char[maxName + 2];
            uint nameLength = maxName + 2, size = maxData;
            var data = new byte[Math.Max(1, maxData)];
            Check(Offreg.OREnumValue(key, i, name, ref nameLength, out uint type, data, ref size));
            lines.Add(ValueLine(path, new string(name, 0, (int)nameLength), (int)type, data[..(int)size]));
        }
        for (uint i = 0; i < subkeys; i++)
        {
            var buffer = new char[256];
            uint nameLength = 256;
            Check(Offreg.OREnumKey(key, i, buffer, ref nameLength, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero));
            var name = new string(buffer, 0, (int)nameLength);
            Check(Offreg.OROpenKey(key, name, out var child));
            try { Walk(child, path.Length == 0 ? name : path + "\\" + name, lines); }
            finally { Check(Offreg.ORCloseKey(child)); }
        }
    }

    private static void Check(int error) => Assert.True(error == 0, $"offreg error {error}");

    private void Compare(string label, string path)
    {
        var mine = Mine(path);
        var theirs = Theirs(path);
        int i = 0;
        while (i < mine.Count && i < theirs.Count && mine[i] == theirs[i]) i++;
        Assert.True(mine.Count == theirs.Count && i == mine.Count,
            $"{label}: {mine.Count} lines vs offreg {theirs.Count}; first difference at {i}: {(i < mine.Count ? mine[i] : "(end)")} | {(i < theirs.Count ? theirs[i] : "(end)")}");
        output.WriteLine($"{label}: {mine.Count:N0} keys and values match");
    }

    // The Offline Registry Library ships with Windows (System32\offreg.dll).
    [WindowsFact]
    public void Built_hives_read_as_the_offline_registry_library_reads_them()
    {
        foreach (var (label, writer) in new[] { ("lh lists", new HiveSamples()), ("ri lists", new HiveSamples { SplitAbove = 2 }), ("format 1.3", new HiveSamples { Minor = 3 }) })
        {
            var path = Path.Combine(_dir.Path, $"{label}.dat");
            File.WriteAllBytes(path, writer.Build(Sample()));
            Compare(label, path);
        }
        // A hive the library writes itself: 2,000 subkeys (ri lists), a 100 KB value (db cells), class names, every type.
        Check(Offreg.ORCreateHive(out var hive));
        try
        {
            Check(Offreg.ORCreateKey(hive, "Software", null, 0, IntPtr.Zero, out var software, out _));
            Check(Offreg.ORCreateKey(software, "Wide", "WideClass", 0, IntPtr.Zero, out var wide, out _));
            Check(Offreg.ORCloseKey(software));
            for (int i = 0; i < 2000; i++)
            {
                Check(Offreg.ORCreateKey(wide, $"k{i:D4}-Ключ", i % 3 == 0 ? $"c{i}" : null, 0, IntPtr.Zero, out var k, out _));
                Check(Offreg.ORSetValue(k, i % 2 == 0 ? "" : "v", (uint)(i % 12), BitConverter.GetBytes(i), 4));
                Check(Offreg.ORCloseKey(k));
            }
            var large = new byte[100_000];
            new Random(5).NextBytes(large);
            Check(Offreg.ORSetValue(wide, "Large", 3, large, (uint)large.Length));
            Check(Offreg.ORCloseKey(wide));
            foreach (var (major, minor) in new[] { (6u, 1u), (5u, 1u) })
            {
                var path = Path.Combine(_dir.Path, $"offreg-{major}.{minor}.dat");
                Check(Offreg.ORSaveHive(hive, path, major, minor));
                Compare($"saved for Windows {major}.{minor}", path);
            }
        }
        finally { Check(Offreg.ORCloseHive(hive)); }
    }

    /// <summary>CORVUS_REGISTRY_HIVES: a folder of hive files (searched recursively), each compared with the Offline Registry Library.</summary>
    [RequiresRealDataFact("CORVUS_REGISTRY_HIVES")]
    [Trait("Speed", "Slow")]
    public void Real_hives_read_as_the_offline_registry_library_reads_them()
    {
        Assert.True(OperatingSystem.IsWindows(), "the Offline Registry Library is a Windows library");
        var failures = new List<string>();
        int hives = 0;
        foreach (var path in Directory.EnumerateFiles(Environment.GetEnvironmentVariable("CORVUS_REGISTRY_HIVES")!, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
        {
            var head = new byte[4];
            using (var s = File.OpenRead(path)) if (s.Read(head) < 4 || !RegistryHive.Looks(head)) continue;
            try { Compare(Path.GetFileName(Path.GetDirectoryName(path)) + "/" + Path.GetFileName(path), path); }
            catch (Exception ex) when (ex is Xunit.Sdk.XunitException or InvalidDataException) { failures.Add(ex.Message); }
            var (keys, values) = RegistryHive.Read(File.ReadAllBytes(path)).Recover(default);
            output.WriteLine($"  {keys.Count:N0} deleted keys, {values.Count:N0} deleted values recovered");
            hives++;
        }
        Assert.True(hives > 0, "no hive files");
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    private static class Offreg
    {
        [DllImport("offreg.dll", CharSet = CharSet.Unicode)]
        public static extern int ORCreateHive(out IntPtr hive);

        [DllImport("offreg.dll", CharSet = CharSet.Unicode)]
        public static extern int OROpenHive(string path, out IntPtr hive);

        [DllImport("offreg.dll", CharSet = CharSet.Unicode)]
        public static extern int ORCloseHive(IntPtr hive);

        [DllImport("offreg.dll", CharSet = CharSet.Unicode)]
        public static extern int ORSaveHive(IntPtr hive, string path, uint major, uint minor);

        [DllImport("offreg.dll", CharSet = CharSet.Unicode)]
        public static extern int ORCreateKey(IntPtr key, string subkey, string? className, uint options, IntPtr security, out IntPtr result, out uint disposition);

        [DllImport("offreg.dll", CharSet = CharSet.Unicode)]
        public static extern int OROpenKey(IntPtr key, string subkey, out IntPtr result);

        [DllImport("offreg.dll", CharSet = CharSet.Unicode)]
        public static extern int ORCloseKey(IntPtr key);

        [DllImport("offreg.dll", CharSet = CharSet.Unicode)]
        public static extern int ORSetValue(IntPtr key, string name, uint type, byte[] data, uint size);

        [DllImport("offreg.dll", CharSet = CharSet.Unicode)]
        public static extern int ORQueryInfoKey(IntPtr key, [Out] char[]? className, ref uint classLength, out uint subkeys, out uint maxSubkeyLength,
            out uint maxClassLength, out uint values, out uint maxValueNameLength, out uint maxValueLength, out uint securityLength, out long lastWritten);

        [DllImport("offreg.dll", CharSet = CharSet.Unicode)]
        public static extern int OREnumKey(IntPtr key, uint index, [Out] char[] name, ref uint nameLength, IntPtr className, IntPtr classLength, IntPtr lastWritten);

        [DllImport("offreg.dll", CharSet = CharSet.Unicode)]
        public static extern int OREnumValue(IntPtr key, uint index, [Out] char[] name, ref uint nameLength, out uint type, [Out] byte[] data, ref uint size);
    }
}
