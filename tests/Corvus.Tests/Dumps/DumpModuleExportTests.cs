using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native.Dump;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>batch --file --dump-modules: the module images of a minidump written to a folder.</summary>
public sealed class DumpModuleExportTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private string Dump(Action<MinidumpBuilder>? change = null)
    {
        var b = SyntheticCrash.Builder();
        change?.Invoke(b);
        var path = _dir.File("crash.dmp");
        File.WriteAllBytes(path, b.Build());
        return path;
    }

    [Fact]
    public void Each_module_image_is_written_under_its_own_name_as_a_PE_file()
    {
        var export = DumpModuleExport.Write(Dump(), _dir.File("modules"), default);
        var written = Assert.Single(export.Written);
        Assert.Equal("synth.dll", written.File);
        Assert.Equal($"0x{SyntheticCrash.Base:X}", written.Base);
        Assert.Equal(100, written.CapturedPercent);
        var bytes = File.ReadAllBytes(Path.Combine(export.Folder, "synth.dll"));
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(bytes)), written.Sha256);
        Assert.Equal((uint)SyntheticCrash.Image().Length, PeFile.FromBytes(bytes).SizeOfImage);
        Assert.Empty(export.Skipped);
    }

    [Fact]
    public void A_module_whose_headers_the_dump_lacks_is_skipped_with_the_reason()
    {
        var export = DumpModuleExport.Write(Dump(b => b.Memory.RemoveAll(m => m.Start == SyntheticCrash.Base)), _dir.File("modules"), default);
        Assert.Empty(export.Written);
        var skipped = Assert.Single(export.Skipped);
        Assert.Equal("synth.dll", skipped.Name);
        Assert.Equal("the dump does not hold the image headers", skipped.Reason);
        Assert.Empty(Directory.GetFiles(export.Folder));
    }

    [Fact]
    public void Modules_with_one_name_or_an_unsafe_name_get_distinct_safe_file_names()
    {
        var export = DumpModuleExport.Write(Dump(b =>
        {
            var image = SyntheticCrash.Image();
            b.Modules.Add(new MinidumpBuilder.Module(0x7FF7_0000_0000, (uint)image.Length, 0, @"Z:\other\synth.dll"));
            b.Memory.Add((0x7FF7_0000_0000, image));
            b.Modules.Add(new MinidumpBuilder.Module(0x7FF8_0000_0000, (uint)image.Length, 0, @"Z:\other\con.dll"));
            b.Memory.Add((0x7FF8_0000_0000, image));
        }), _dir.File("modules"), default);
        Assert.Equal(["module.bin", "synth-7FF700000000.dll", "synth.dll"], export.Written.Select(w => w.File).Order(StringComparer.Ordinal));
        Assert.All(export.Written, w => Assert.True(File.Exists(Path.Combine(export.Folder, w.File))));
    }

    [Fact]
    [FuzzEntry(typeof(DumpModuleExport))]
    public void Mutated_dumps_never_throw_from_the_export()
    {
        var seed = File.ReadAllBytes(Dump());
        int n = 0;
        var failures = FormatFuzz.Run(seed, bytes =>
        {
            var path = _dir.File("fuzz.dmp");
            File.WriteAllBytes(path, bytes);
            try { DumpModuleExport.Write(path, _dir.File($"export{n++}"), default); }
            catch (ToolError) { }
        }, 250);
        Assert.Empty(failures);
    }

    [Fact]
    public async Task The_batch_command_writes_the_images_and_lists_them_in_the_document()
    {
        var folder = _dir.File("images");
        var (code, output, _) = await ToolCliTests.Run("batch", "--file", Dump(), "--dump-modules", folder, "--json", "--no-index");
        Assert.True(code is 0, output);
        var written = Assert.Single(JsonNode.Parse(output)!["dumpModules"]!["written"]!.AsArray());
        Assert.Equal("synth.dll", (string?)written!["file"]);
        Assert.True(File.Exists(Path.Combine(folder, "synth.dll")));
    }

    [Fact]
    public async Task The_batch_command_refuses_a_folder_that_is_not_empty_and_a_file_that_is_not_a_dump()
    {
        var (code, output, _) = await ToolCliTests.Run("batch", "--file", Dump(), "--dump-modules", _dir.Path, "--json", "--no-index");
        Assert.Equal(2, code);
        Assert.Empty(output);
        File.WriteAllText(_dir.File("notes.txt"), "text");
        (code, output, _) = await ToolCliTests.Run("batch", "--file", _dir.File("notes.txt"), "--dump-modules", _dir.File("out"), "--json", "--no-index");
        Assert.Equal(2, code);
        Assert.Empty(output);
    }
}
