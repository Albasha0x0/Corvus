using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;
using Corvus.Tests.NativeFormats;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Two cpio firmware images that hold ELF files: changed files and function counts per binary.</summary>
public sealed class FirmwareImageCompareTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    /// <summary>newc cpio with the files in order, then the trailer.</summary>
    private static byte[] Cpio(params (string Name, byte[] Bytes)[] files)
    {
        var o = new MemoryStream();
        void Entry(string n, byte[] b, uint mode)
        {
            var header = $"070701{0:X8}{mode:X8}{0:X8}{0:X8}{1:X8}{0:X8}{b.Length:X8}{0:X8}{0:X8}{0:X8}{0:X8}{n.Length + 1:X8}{0:X8}";
            o.Write(Encoding.ASCII.GetBytes(header));
            o.Write(Encoding.ASCII.GetBytes(n + "\0"));
            while (o.Length % 4 != 0) o.WriteByte(0);
            o.Write(b);
            while (o.Length % 4 != 0) o.WriteByte(0);
        }
        foreach (var (name, bytes) in files) Entry(name, bytes, 0x81A4);
        Entry("TRAILER!!!", [], 0);
        return o.ToArray();
    }

    /// <summary>x64 ELF with functions one and two; two returns 2 (mov eax, 2) or, when <paramref name="two"/> is 3, 0 (xor eax, eax).</summary>
    private static byte[] Elf(byte two) => new ElfWriter
    {
        Machine = ElfWriter.EmX64, Type = 3, Entry = ElfWriter.TextRva,
        Text = [0xB8, 1, 0, 0, 0, 0xC3, 0xCC, 0xCC, .. (two == 2 ? (byte[])[0xB8, 2, 0, 0, 0, 0xC3] : [0x31, 0xC0, 0x90, 0x90, 0x90, 0xC3]), 0xCC, 0xCC],
        Symbols = [new("one", ElfWriter.TextRva, 6), new("two", ElfWriter.TextRva + 8, 6)],
    }.Build();

    private string Image(string name, params (string Name, byte[] Bytes)[] files)
    {
        var path = _dir.File(name);
        File.WriteAllBytes(path, Cpio(files));
        return path;
    }

    private static FolderCompare.Comparison Compare(string a, string b, int limit = 100) =>
        FolderTools.CompareWith(new FolderCompare(), new FileWork.CompareFoldersArgs(a, b, "changed", null, null, 1000, 0, limit, true), null, default).Comparison;

    private static readonly byte[] Config = Encoding.ASCII.GetBytes("name=router\n");

    [Fact]
    public void Two_images_differing_in_one_function_name_the_changed_file_and_count_one_changed_function()
    {
        var old = Image("old.cpio", ("etc/conf", Config), ("bin/httpd", Elf(2)));
        var @new = Image("new.cpio", ("etc/conf", Config), ("bin/httpd", Elf(3)));
        var result = Compare(old, @new);
        var changed = Assert.Single(result.Entries);
        Assert.Equal("modified", changed.Change);
        Assert.Equal("bin/httpd", changed.NewPath);
        Assert.Equal("elf", changed.Kind);
        Assert.Single(result.Notes, n => n == "bin/httpd: 2 matched, 1 identical, 1 changed, 0 removed, 0 added");
    }

    [Fact]
    public void Two_identical_images_report_no_changed_binaries()
    {
        var old = Image("old.cpio", ("etc/conf", Config), ("bin/httpd", Elf(2)));
        var same = Image("same.cpio", ("etc/conf", Config), ("bin/httpd", Elf(2)));
        var result = Compare(old, same);
        Assert.Empty(result.Entries);
        Assert.Equal(0, result.Counts.Modified);
        Assert.Equal(2, result.Counts.Unchanged);
        Assert.DoesNotContain(result.Notes, n => n.Contains(" matched, "));
    }

    [Fact]
    public void The_binary_limit_is_named_when_more_binaries_changed()
    {
        var old = Image("old.cpio", ("bin/a", Elf(2)), ("bin/b", Elf(2)));
        var @new = Image("new.cpio", ("bin/a", Elf(3)), ("bin/b", Elf(3)));
        var result = Compare(old, @new, limit: 1);
        Assert.Single(result.Notes, n => n.StartsWith("bin/a: ", StringComparison.Ordinal));
        Assert.DoesNotContain(result.Notes, n => n.StartsWith("bin/b: ", StringComparison.Ordinal));
        Assert.Contains(result.Notes, n => n.Contains("binary limit reached: 1 of 2 changed binaries were not compared (at most 1 per call"));
    }

    [Fact]
    public void Added_and_removed_files_are_listed_without_function_counts()
    {
        var old = Image("old.cpio", ("bin/old", Elf(2)));
        var @new = Image("new.cpio", ("bin/new", Elf(2)));
        var result = Compare(old, @new);
        Assert.Equal(["added", "removed"], result.Entries.Select(e => e.Change).Order().ToArray());
        Assert.DoesNotContain(result.Notes, n => n.Contains(" matched, "));
    }

    [Fact]
    public void Two_folders_with_a_changed_binary_carry_its_function_counts()
    {
        foreach (var (side, value) in new[] { ("a", (byte)2), ("b", (byte)3) })
        {
            Directory.CreateDirectory(_dir.File(side));
            File.WriteAllBytes(Path.Combine(_dir.File(side), "httpd"), Elf(value));
        }
        var result = Compare(_dir.File("a"), _dir.File("b"));
        Assert.Single(result.Notes, n => n == "httpd: 2 matched, 1 identical, 1 changed, 0 removed, 0 added");
    }
}
