using System.Buffers.Binary;
using System.Text;
using Corvus.Core;
using Corvus.Native.MachO;
using Corvus.Services.Analysis;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>summarize_file view=nib: a NIBArchive's outlets and actions, actions resolved to their implementation in the app's executable.</summary>
public sealed class NibViewTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    /// <summary>A NIBArchive: objects as (class, fields); a field value is string (stored as an NSString object), long, or int (an object reference).</summary>
    private static byte[] Nib(params (string Class, (string Key, object Value)[] Fields)[] objects)
    {
        var all = objects.ToList();
        var keys = new List<string>();
        var classes = new List<string>();
        var values = new MemoryStream();
        int valueCount = 0;
        var rows = new List<(int Class, int Start, int Count)>();
        int Key(string k) { if (!keys.Contains(k)) keys.Add(k); return keys.IndexOf(k); }
        int Class(string c) { if (!classes.Contains(c)) classes.Add(c); return classes.IndexOf(c); }
        void Varint(Stream s, int v) { do { byte b = (byte)(v & 0x7F); v >>= 7; s.WriteByte(v == 0 ? (byte)(b | 0x80) : b); } while (v != 0); }
        for (int i = 0; i < all.Count; i++)
        {
            int start = valueCount;
            foreach (var (k, v) in all[i].Fields)
            {
                Varint(values, Key(k));
                if (v is string s)
                {
                    all.Add(("NSString", [("NS.bytes", Encoding.UTF8.GetBytes(s))]));
                    values.WriteByte(10);
                    values.Write(BitConverter.GetBytes(all.Count - 1));
                }
                else if (v is byte[] data) { values.WriteByte(8); Varint(values, data.Length); values.Write(data); }
                else if (v is int reference) { values.WriteByte(10); values.Write(BitConverter.GetBytes(reference)); }
                else { values.WriteByte(3); values.Write(BitConverter.GetBytes((long)v)); }
                valueCount++;
            }
            rows.Add((Class(all[i].Class), start, valueCount - start));
        }
        var objectTable = new MemoryStream();
        foreach (var (c, s, n) in rows) { Varint(objectTable, c); Varint(objectTable, s); Varint(objectTable, n); }
        var keyTable = new MemoryStream();
        foreach (var k in keys) { Varint(keyTable, Encoding.UTF8.GetByteCount(k)); keyTable.Write(Encoding.UTF8.GetBytes(k)); }
        var classTable = new MemoryStream();
        foreach (var c in classes) { Varint(classTable, c.Length + 1); Varint(classTable, 0); classTable.Write(Encoding.UTF8.GetBytes(c + "\0")); }
        var header = new byte[50];
        "NIBArchive"u8.CopyTo(header);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(10), 1);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(14), 9);
        uint at = 50;
        uint[] fields = [(uint)rows.Count, at, (uint)keys.Count, at += (uint)objectTable.Length, (uint)valueCount, at += (uint)keyTable.Length, (uint)classes.Count, at += (uint)values.Length];
        for (int i = 0; i < fields.Length; i++) BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(18 + 4 * i), fields[i]);
        return [.. header, .. objectTable.ToArray(), .. keyTable.ToArray(), .. values.ToArray(), .. classTable.ToArray()];
    }

    [Fact]
    public void Actions_resolve_to_their_implementation_in_the_app()
    {
        var exe = RealPackages.File("Microsoft.macOS.Runtime.osx-arm64", "14.2.8078", "runtimes", "osx-arm64", "native", "libxamarin-dotnet.dylib");
        var target = AppleObjcMetadata.Read(MachOFile.Open(exe)).Classes.First(c => c.Methods.Any(m => !m.IsClassMethod && m.Selector.EndsWith(':')));
        var selector = target.Methods.First(m => !m.IsClassMethod && m.Selector.EndsWith(':'));
        output.WriteLine($"-[{target.Name} {selector.Selector}] at 0x{selector.Imp:X}");

        var app = _dir.File("Demo.app");
        Directory.CreateDirectory(Path.Combine(app, "Base.lproj"));
        File.WriteAllText(Path.Combine(app, "Info.plist"), "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleExecutable</key><string>Demo</string></dict></plist>");
        File.Copy(exe, Path.Combine(app, "Demo"));
        var nib = Path.Combine(app, "Base.lproj", "Main.nib");
        // 0 owner proxy, 1 button, 2 the target's object, 3 an action to it, 4 an outlet from the owner
        File.WriteAllBytes(nib, Nib(
            ("UIProxyObject", [("UIProxiedObjectIdentifier", "IBFilesOwner")]),
            ("UIButton", []),
            (target.Name, []),
            ("UIRuntimeEventConnection", [("UILabel", selector.Selector), ("UISource", 1), ("UIDestination", 2), ("UIEventMask", 64L)]),
            ("UIRuntimeOutletConnection", [("UILabel", "button"), ("UISource", 0), ("UIDestination", 1)])));

        var bytes = File.ReadAllBytes(nib);
        var view = new NibFileView().Inspect(new FileInput(nib, bytes, Blob.Identify(bytes)), default)!;
        var facts = (NibFileView.Facts)view.Detail;
        output.WriteLine(view.Highlights[0]);
        Assert.Equal(new NibFileView.Connection("button", "proxy IBFilesOwner", "UIButton", null), Assert.Single(facts.Outlets));
        var action = Assert.Single(facts.Actions);
        Assert.Equal((selector.Selector, "UIButton", target.Name), (action.Name, action.Source, action.Destination));
        Assert.Equal($"0x{selector.Imp:X} -[{target.Name} {selector.Selector}]", action.Implementation);
    }

    [Fact]
    [FuzzEntry(typeof(NibFileView), typeof(Core.Mobile.NibArchive))]
    public void Fuzzed_nibs_never_crash()
    {
        var nib = Nib(("UIButton", [("UILabel", "go:"), ("UITag", 3L)]), ("UIRuntimeEventConnection", [("UILabel", "go:"), ("UISource", 0), ("UIDestination", 0)]));
        var failures = FormatFuzz.Run(nib, b => new NibFileView().Inspect(new FileInput("x.nib", b, "data"), default), 500);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
