using System.Buffers.Binary;
using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests.NativeFormats;

/// <summary>Dart AOT snapshot headers and the Dart VM version string; summarize_file view=flutter.</summary>
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
    public void Fuzzed_snapshot_image_never_throws()
    {
        var failures = FormatFuzz.Run([App()], 1500, 11, b => View(b));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(5)));
    }
}
