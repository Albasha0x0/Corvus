using System.Buffers.Binary;
using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests.NativeFormats;

/// <summary>Dart AOT snapshot headers and the Dart VM version string; summarize_file view=flutter.</summary>
[Collection(nameof(SerialTimingTests))] // the pool scan has a CPU budget
public sealed class FlutterViewTests
{
    private const string Hash = "0123456789abcdef0123456789abcdef";
    private const string Features = "product no-code_comments no-dwarf_stack_traces_mode dedup_instructions no-tsan arm64 android compressed-pointers";

    private static byte[] Snapshot(long kind = 3, string hash = Hash, string features = Features)
    {
        var b = new byte[52 + features.Length + 1 + 11];
        BinaryPrimitives.WriteUInt32LittleEndian(b, 0xdcdcf5f5);
        BinaryPrimitives.WriteInt64LittleEndian(b.AsSpan(4), 0x4000);
        BinaryPrimitives.WriteInt64LittleEndian(b.AsSpan(12), kind);
        Encoding.ASCII.GetBytes(hash).CopyTo(b, 20);
        Encoding.ASCII.GetBytes(features).CopyTo(b, 52);
        return b;
    }

    private static byte[] App()
    {
        var vm = Snapshot();
        var data = new byte[0x200];
        vm.CopyTo(data, 0);
        vm.CopyTo(data, 0x100);
        return new ElfWriter
        {
            Data = data,
            Symbols = [new("_kDartVmSnapshotData", ElfWriter.DataRva, 0x100, Type: 1), new("_kDartIsolateSnapshotData", ElfWriter.DataRva + 0x100, 0x100, Type: 1)],
        }.Build();
    }

    private static FileView? View(byte[] bytes, string path = "libapp.so") => new FlutterFileView().Inspect(new FileInput(path, bytes, Blob.Identify(bytes)), default);

    [Fact]
    public void App_snapshots_give_hash_features_and_symbol_names()
    {
        var view = View(App())!;
        var f = (FlutterFileView.Facts)view.Detail;
        Assert.Equal(["kDartVmSnapshotData", "kDartIsolateSnapshotData"], f.Snapshots.Select(s => s.Symbol));
        var s = f.Snapshots[0];
        Assert.Equal(("full-aot", Hash, Features), (s.Kind, s.Hash, s.Features));
        Assert.Equal(("product", "arm64", "android"), (s.Mode, s.Architecture, s.Os));
        Assert.Contains($"version hash {Hash}, arm64 android, product mode", view.Highlights[0]);
    }

    [Fact]
    public void Older_features_name_the_abi()
    {
        var s = DartScan.Snapshots(Snapshot(features: "product no-asserts x64-sysv")).Single();
        Assert.Equal("x64", s.Architecture);
        Assert.Null(s.Os);
    }

    [Fact]
    public void Magic_without_a_valid_header_is_not_a_snapshot()
    {
        Assert.Empty(DartScan.Snapshots(Snapshot(hash: "0123456789ABCDEF0123456789ABCDEF")));
        Assert.Empty(DartScan.Snapshots(Snapshot(kind: 9)));
        Assert.Empty(DartScan.Snapshots(Snapshot().AsSpan(0, 60)));
    }

    [Fact]
    public void Engine_gives_the_dart_version()
    {
        var text = "\0io/flutter/embedding/engine/FlutterJNI\0" + "3.5.4 (stable) (Wed Oct 16 16:27:51 2024 +0000) on \"android_arm64\"\0";
        var data = new byte[0x200];
        Encoding.ASCII.GetBytes(text).CopyTo(data, 0);
        var view = View(new ElfWriter { Data = data }.Build(), "libflutter.so")!;
        var f = (FlutterFileView.Facts)view.Detail;
        Assert.Equal("Flutter engine", f.Role);
        Assert.Equal("3.5.4 (stable) (Wed Oct 16 16:27:51 2024 +0000) on \"android_arm64\"", f.DartVersion);
    }

    [Fact]
    public void Other_images_do_not_apply() => Assert.Null(View(new ElfWriter().Build(), "libc.so"));

    [Fact]
    [FuzzEntry(typeof(FlutterFileView), typeof(DartPoolScan))]
    public void Fuzzed_snapshot_image_never_throws()
    {
        var failures = FormatFuzz.Run([App(), PoolApp()], 1500, 11, b => View(b));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(5)));
    }

    /// <summary>A Dart 3 string as the snapshot stores it: varint((length &lt;&lt; 1) | 1), last byte with the high bit set, then the bytes.</summary>
    private static void DartString(List<byte> to, string s)
    {
        for (uint v = (uint)(s.Length << 1) | 1; ; v >>= 7)
            if (v <= 127) { to.Add((byte)(v + 128)); break; }
            else to.Add((byte)(v & 127));
        to.AddRange(Encoding.ASCII.GetBytes(s));
    }

    private static readonly string Long = "LongName" + new string('z', 92); // 100 characters: its length takes two bytes, the first an 'I'

    /// <summary>An app whose isolate snapshot holds URIs, a pub cache path, identifiers and noise.</summary>
    private static byte[] PoolApp()
    {
        var pool = new List<byte>();
        foreach (var s in new[]
                 {
                     "package:myapp/main.dart", "package:myapp/src/home.dart", "package:http/http.dart", "package:http/src/client.dart",
                     "package:flutter/material.dart", "dart:core", "dart:async", "dart:core-patch/array.dart",
                     "/home/u/.pub-cache/hosted/pub.dev/http-1.2.1/lib/http.dart", "MyHomePage", "_counter@1234", "get:title", "ab", "build", Long,
                 })
        {
            DartString(pool, s);
            pool.AddRange([0, 1]);
        }
        pool.AddRange([0, (byte)'x', (byte)'y', 0]); // two letters without their length: noise
        var vm = Snapshot();
        var isolate = Snapshot();
        BinaryPrimitives.WriteInt64LittleEndian(isolate.AsSpan(4), isolate.Length + pool.Count);
        var data = new byte[0x100 + isolate.Length + pool.Count];
        vm.CopyTo(data, 0);
        isolate.CopyTo(data, 0x100);
        pool.CopyTo(data, 0x100 + isolate.Length);
        return new ElfWriter
        {
            Data = data,
            Symbols = [new("_kDartVmSnapshotData", ElfWriter.DataRva, 0x100, Type: 1), new("_kDartIsolateSnapshotData", ElfWriter.DataRva + 0x100, (uint)(data.Length - 0x100), Type: 1)],
        }.Build();
    }

    [Fact]
    public void Isolate_pool_gives_packages_with_versions_libraries_and_identifiers()
    {
        var view = View(PoolApp())!;
        var pool = ((FlutterFileView.Facts)view.Detail).StringPool!;
        Assert.Equal([("myapp", "app", null, 2), ("http", "pub", "1.2.1", 2), ("flutter", "flutter", null, 1)],
            pool.Packages.Select(p => (p.Name, p.Kind, p.Version, p.Uris)));
        Assert.Equal(["dart:async", "dart:core"], pool.Libraries);
        Assert.Contains("app myapp; 1 from pub (http 1.2.1)", view.Highlights[1]);
        var app = PoolApp();
        var strings = DartPoolScan.Read(app, DartPoolScan.Isolate(DartScan.Snapshots(app))!).Strings;
        var identifiers = strings.Where(s => s.Kind == "identifier").Select(s => s.Value).ToList();
        Assert.Equal(["MyHomePage", "_counter@1234", "get:title", "ab", "build", Long], identifiers);
        Assert.Equal("dart:core-patch/array.dart", strings.Single(s => s.Value.StartsWith("dart:core-", StringComparison.Ordinal)).Value);
    }

    [Fact]
    public void Apk_and_ipa_read_their_app_image()
    {
        var apk = ContainerFixtures.Zip(("lib/armeabi-v7a/libapp.so", App()), ("lib/arm64-v8a/libapp.so", PoolApp()));
        var f = (FlutterFileView.Facts)new FlutterFileView().Inspect(new FileInput("app.apk", apk, "zip"), default)!.Detail;
        Assert.Equal(("lib/arm64-v8a/libapp.so", 3), (f.Image, f.StringPool!.Packages.Count));
        var ipa = ContainerFixtures.Zip(("Payload/Runner.app/Frameworks/App.framework/App", PoolApp()));
        Assert.Equal("Payload/Runner.app/Frameworks/App.framework/App", ((FlutterFileView.Facts)new FlutterFileView().Inspect(new FileInput("app.ipa", ipa, "zip"), default)!.Detail).Image);
        Assert.Null(new FlutterFileView().Inspect(new FileInput("other.zip", ContainerFixtures.Zip(("a.txt", [1])), "zip"), default));
    }

    [Fact]
    public void Search_container_kind_dart_pages_the_pool()
    {
        using var dir = new TempDir();
        var path = dir.File("app.apk");
        File.WriteAllBytes(path, ContainerFixtures.Zip(("lib/arm64-v8a/libapp.so", PoolApp())));
        using var ws = new AssemblyWorkspace();
        var found = new UnpackService(ws).Search(path, "package:http*", "dart", 1, AnalysisLimits.Default, default);
        Assert.Equal(2, found.Total);
        var row = Assert.Single(found.Items);
        Assert.Equal(("lib/arm64-v8a/libapp.so", "package:http/http.dart"), (row.Path, row.Name));
        Assert.StartsWith("package-uri at 0x", row.Detail);
        Assert.Equal(6, new UnpackService(ws).Search(path, "identifier", "dart", 100, AnalysisLimits.Default, default).Total);
    }

    /// <summary>
    /// An app whose string objects sit after the clustered data in the data image, as older ARM32 snapshots keep them: header
    /// (class id at bit 12, size tag at bit 8), hash, Smi length, characters; 8-byte aligned. One repeats a clustered string.
    /// </summary>
    private static byte[] ImageApp(bool bits32)
    {
        const uint oneByte = 94;
        var features = bits32 ? "product arm android no-compressed-pointers" : "product arm64 android no-compressed-pointers";
        int align = bits32 ? 8 : 16, dataAt = bits32 ? 12 : 16;
        var texts = Enumerable.Range(0, 20).Select(i => $"Value not in range {i}").Append("MyHomePage").Append("line one\nline two").ToList();
        byte[] Build(int pad)
        {
            var pool = new List<byte>();
            DartString(pool, "MyHomePage");
            var isolate = Snapshot(features: features);
            BinaryPrimitives.WriteInt64LittleEndian(isolate.AsSpan(4), isolate.Length - 4 + pool.Count);
            var image = new List<byte>(new byte[pad]);
            void Object(uint cid, byte[] chars, int n)
            {
                int size = (dataAt + chars.Length + align - 1) / align;
                var header = new byte[dataAt];
                BinaryPrimitives.WriteUInt32LittleEndian(header, cid << 12 | (uint)size << 8 | 2);
                if (bits32) { BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(4), 0x1234); BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(8), (uint)n << 1); }
                else BinaryPrimitives.WriteInt64LittleEndian(header.AsSpan(8), (long)n << 1);
                image.AddRange(header);
                image.AddRange(chars);
                while ((image.Count - pad) % align != 0) image.Add(0);
            }
            foreach (var t in texts) Object(oneByte, Encoding.Latin1.GetBytes(t), t.Length);
            Object(oneByte + 1, Encoding.Unicode.GetBytes("✓ done"), 6);
            Object(oneByte + 7, Encoding.ASCII.GetBytes("other class"), 11); // not a string class
            var data = new byte[0x100 + isolate.Length + pool.Count + image.Count];
            Snapshot().CopyTo(data, 0);
            isolate.CopyTo(data, 0x100);
            pool.CopyTo(data, 0x100 + isolate.Length);
            image.CopyTo(data, 0x100 + isolate.Length + pool.Count);
            return new ElfWriter
            {
                Data = data,
                Symbols = [new("_kDartVmSnapshotData", ElfWriter.DataRva, 0x100, Type: 1), new("_kDartIsolateSnapshotData", ElfWriter.DataRva + 0x100, (uint)(data.Length - 0x100), Type: 1)],
            }.Build();
        }
        // place the image at an aligned file offset: the data section's offset is known after a first build
        var first = Build(0);
        var isolateAt = DartScan.Snapshots(first)[1].Offset;
        var imageAt = isolateAt + Snapshot(features: features).Length + 11;
        return Build((int)((align - imageAt % align) % align));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Strings_only_in_the_data_image_are_found_as_string_objects(bool bits32)
    {
        var app = ImageApp(bits32);
        var view = View(app)!;
        var pool = ((FlutterFileView.Facts)view.Detail).StringPool!;
        Assert.Equal(22, pool.ImageStrings);
        Assert.Contains(view.Highlights, h => h.StartsWith("22 strings only as string objects", StringComparison.Ordinal));
        var isolate = DartPoolScan.Isolate(DartScan.Snapshots(app))!;
        var strings = DartPoolScan.Read(app, isolate, default, FlutterFileView.Images(app, "libapp.so", isolate)).Strings;
        Assert.Equal(("text", "data image"), strings.Where(s => s.Value == "Value not in range 7").Select(s => (s.Kind, s.Image)).Single());
        Assert.Null(Assert.Single(strings, s => s.Value == "MyHomePage").Image); // the clustered copy only
        Assert.Contains(strings, s => s.Value == "line one\nline two");
        Assert.Contains(strings, s => s.Value == "✓ done");
        Assert.DoesNotContain(strings, s => s.Value == "other class");

        using var dir = new TempDir();
        var path = dir.File("app.apk");
        File.WriteAllBytes(path, ContainerFixtures.Zip(("lib/arm64-v8a/libapp.so", app)));
        using var ws = new AssemblyWorkspace();
        var row = Assert.Single(new UnpackService(ws).Search(path, "Value not in range 3", "dart", 10, AnalysisLimits.Default, default).Items);
        Assert.Matches("^text at 0x[0-9a-f]+ in the data image$", row.Detail);
    }

    /// <summary>The pool scan of a 100 MB isolate snapshot dense with strings.</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public void Pool_scan_of_100_MB_is_fast()
    {
        var unit = new List<byte>();
        for (int i = 0; unit.Count < 1 << 20; i++)
        {
            DartString(unit, $"package:pkg{i % 50}/src/file{i}.dart");
            DartString(unit, $"identifier{i}");
            unit.AddRange([0, 0x17, 0xFF, 0x41, 0x42, 0x00]);
        }
        var data = new byte[100 << 20];
        var header = Snapshot();
        header.CopyTo(data, 0);
        BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(4), data.Length - 4);
        for (int at = header.Length; at + unit.Count <= data.Length; at += unit.Count) unit.CopyTo(0, data, at, unit.Count);
        var snapshot = DartScan.Snapshots(data).Single();
        var cpu = ThreadCpuClock.Now();
        var pool = DartPoolScan.Read(data, snapshot);
        var took = ThreadCpuClock.Now() - cpu;
        Assert.Equal(50, pool.Packages.Count);
        // the target is 1 s in a Release build (about 0.5 s measured); the Debug test build runs about 3x slower
        PerfBudget.Check(took < TimeSpan.FromSeconds(3), $"{took.TotalMilliseconds:0} ms of CPU");
    }
}
