namespace Corvus.Tests;

/// <summary>read_bytes: bytes with no file data behind them (virtual size past raw size, .bss) show as ?? with a gap list; typed reads say uninitialized.</summary>
public class ReadBytesUninitializedTests
{
    /// <summary>.data: 16 bytes of file data (raw size 0x200) in a 0x1000-byte section; .bss: no file data at all.</summary>
    private static string Image(TempDir dir)
    {
        var b = new PeBuilder();
        var text = b.Add(".text", [0xC3], 0x60000020);
        b.EntryPoint = text.Rva;
        b.Add(".data", Enumerable.Range(1, 16).Select(i => (byte)i).ToArray(), 0xC0000040, virtualSize: 0x1000);
        var bss = b.Add(".bss", [], 0xC0000080, virtualSize: 0x100);
        bss.RawSize = 0;
        var path = dir.File("bss.dll");
        File.WriteAllBytes(path, b.Build());
        return path;
    }

    [Fact]
    public async Task Bytes_past_the_raw_data_are_marked_with_a_gap_list()
    {
        using var dir = new TempDir();
        var path = Image(dir);
        using var h = new NativeToolHarness();
        // The raw size is rounded to the file alignment: file data ends at 0x2200.
        var dump = await h.Native.ReadBytes(path, "rva:0x21F0", 0x20);
        Assert.Contains("1400021F0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", dump);
        Assert.Contains("140002200  ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??  ????????????????", dump);
        Assert.Contains("?? uninitialized (no file data; zero at load, run-time values in a process): 0x140002200-0x140002210 (16 bytes, .data)", dump);

        var bss = await h.Native.ReadBytes(path, "rva:0x3000", 8);
        Assert.Contains("140003000  ?? ?? ?? ?? ?? ?? ?? ??", bss);
        Assert.Contains("0x140003000-0x140003008 (8 bytes, .bss)", bss);

        var backed = await h.Native.ReadBytes(path, "rva:0x2000", 16);
        Assert.Contains("140002000  01 02 03 04", backed);
        Assert.DoesNotContain("uninitialized", backed);
    }

    [Fact]
    public async Task Typed_reads_there_say_uninitialized()
    {
        using var dir = new TempDir();
        var path = Image(dir);
        using var h = new NativeToolHarness();
        var values = await h.Native.ReadBytes(path, "rva:0x21FC", 3, type: "u32");
        var first = values.Split('\n')[1];
        Assert.StartsWith("1400021FC  0", first);
        Assert.DoesNotContain("uninitialized", first);
        Assert.Contains("140002200  ?? uninitialized", values);
        Assert.Contains("140002204  ?? uninitialized", values);
        var partial = await h.Native.ReadBytes(path, "rva:0x21FE", 1, type: "u32");
        Assert.Contains("[?? uninitialized]", partial);
        Assert.Contains("140003000  ?? uninitialized", await h.Native.ReadBytes(path, "rva:0x3000", 1, type: "cstr"));
    }
}
