using System.Security.Cryptography;
using Corvus.Core;

namespace Corvus.Tests;

public class LoadedSetRecordTests
{
    private static ToolError Lost(AssemblyWorkspace ws, string id) => Assert.Throws<ToolError>(() => ws.Get(id));

    private static string Sha256(string path) => Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));

    [Fact]
    public void A_restarted_workspace_names_the_recorded_path_for_an_old_id_and_loading_restores_it()
    {
        using var dir = new TempDir();
        var file = dir.File("loaded-set.json");
        var copy = dir.File("TestFixture.dll");
        File.Copy(Env.FixturePath, copy);
        using (var first = new AssemblyWorkspace(new ServerOptions { LoadedSetFile = file }))
            Assert.Equal("TestFixture", first.Load(copy).Id);

        using var second = new AssemblyWorkspace(new ServerOptions { LoadedSetFile = file });
        var error = Lost(second, "TestFixture");
        Assert.Equal(ErrorCode.NotLoaded, error.Code);
        Assert.Equal($"load_assembly path={copy}", error.Remediation);
        Assert.Equal("TestFixture", second.Load(copy).Id);
    }

    [Fact]
    public void An_unloaded_id_is_dropped_from_the_record()
    {
        using var dir = new TempDir();
        var file = dir.File("loaded-set.json");
        using var ws = new AssemblyWorkspace(new ServerOptions { LoadedSetFile = file });
        ws.Unload(ws.Load(Env.FixturePath));

        Assert.Equal("load_assembly path=TestFixture", Lost(ws, "TestFixture").Remediation);
        Assert.Null(new LoadedSetRecord(file).Find("TestFixture"));
    }

    [Fact]
    public void The_record_keeps_the_sha256_of_the_file_bytes()
    {
        using var dir = new TempDir();
        var file = dir.File("loaded-set.json");
        using var ws = new AssemblyWorkspace(new ServerOptions { LoadedSetFile = file });
        ws.Load(Env.FixturePath);

        Assert.Equal(Sha256(Env.FixturePath), new LoadedSetRecord(file).Find("testfixture")?.Sha256);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("[{\"Id\":1}]")]
    public void An_unreadable_record_gives_the_plain_next(string content)
    {
        using var dir = new TempDir();
        var file = dir.File("loaded-set.json");
        File.WriteAllText(file, content);
        using var ws = new AssemblyWorkspace(new ServerOptions { LoadedSetFile = file });

        Assert.Equal("load_assembly path=TestFixture", Lost(ws, "TestFixture").Remediation);
    }

    [Fact]
    public void A_record_without_a_file_keeps_nothing()
    {
        using var ws = new AssemblyWorkspace(new ServerOptions());
        ws.Unload(ws.Load(Env.FixturePath));

        Assert.Equal("load_assembly path=TestFixture", Lost(ws, "TestFixture").Remediation);
        Assert.Null(new LoadedSetRecord(null).Find("TestFixture"));
    }

    [Fact]
    public void A_recorded_file_that_is_gone_gives_the_plain_next()
    {
        using var dir = new TempDir();
        var file = dir.File("loaded-set.json");
        var copy = dir.File("TestFixture.dll");
        File.Copy(Env.FixturePath, copy);
        using (var first = new AssemblyWorkspace(new ServerOptions { LoadedSetFile = file }))
            first.Load(copy);
        File.Delete(copy);

        using var second = new AssemblyWorkspace(new ServerOptions { LoadedSetFile = file });
        Assert.Equal("load_assembly path=TestFixture", Lost(second, "TestFixture").Remediation);
    }

    [Fact]
    public void A_recorded_file_that_changed_is_named_in_the_next()
    {
        using var dir = new TempDir();
        var file = dir.File("loaded-set.json");
        var copy = dir.File("TestFixture.dll");
        File.Copy(Env.FixturePath, copy);
        using (var first = new AssemblyWorkspace(new ServerOptions { LoadedSetFile = file }))
            first.Load(copy);
        File.AppendAllText(copy, "x");

        using var second = new AssemblyWorkspace(new ServerOptions { LoadedSetFile = file });
        Assert.Contains("differs from the one loaded as TestFixture", Lost(second, "TestFixture").Remediation);
    }

    [Fact]
    public void A_reload_records_the_new_bytes()
    {
        using var dir = new TempDir();
        var file = dir.File("loaded-set.json");
        var copy = dir.File("TestFixture.dll");
        File.Copy(Env.FixturePath, copy);
        using var ws = new AssemblyWorkspace(new ServerOptions { LoadedSetFile = file });
        var asm = ws.Load(copy);
        ws.Reload(asm);

        Assert.Equal(Sha256(copy), new LoadedSetRecord(file).Find("TestFixture")?.Sha256);
    }

    [Fact]
    public void A_folder_load_records_every_file_in_one_write()
    {
        using var dir = new TempDir();
        var file = dir.File("loaded-set.json");
        var folder = dir.File("bin");
        Directory.CreateDirectory(folder);
        File.Copy(Env.FixturePath, Path.Combine(folder, "TestFixture.dll"));
        File.Copy(Env.ConsumerPath, Path.Combine(folder, "Consumer.dll"));
        using var ws = new AssemblyWorkspace(new ServerOptions { LoadedSetFile = file });
        var report = ws.LoadDirectory(folder, recursive: false);

        var record = new LoadedSetRecord(file);
        Assert.Equal(2, report.Loaded.Count);
        Assert.All(report.Loaded, a => Assert.NotNull(record.Find(a.Id)));
    }

    [Fact]
    public void The_record_trims_ids_in_every_call_and_refuses_a_blank_id()
    {
        using var dir = new TempDir();
        var file = dir.File("loaded-set.json");
        var record = new LoadedSetRecord(file);
        record.Add(new LoadedSetEntry(" A ", Env.FixturePath, "00"));
        record.Remove("A");
        record.Flush();

        Assert.Null(record.Find("a"));
        Assert.Null(record.Find("  "));
    }

    [Fact]
    public void A_bare_file_name_is_written_without_failing()
    {
        var name = "loaded-set-" + Guid.NewGuid().ToString("N") + ".json";
        try
        {
            var record = new LoadedSetRecord(name);
            record.Add(new LoadedSetEntry("A", Env.FixturePath, "00"));
            record.Flush();

            Assert.NotNull(new LoadedSetRecord(name).Find("A"));
        }
        finally { File.Delete(name); }
    }

    [Fact]
    public void Parse_leaves_the_loaded_set_file_unset()
    {
        Assert.Null(ServerOptions.Parse([]).LoadedSetFile);
    }

    [WindowsFact]
    public void A_native_image_id_is_recorded_and_named_after_a_restart()
    {
        using var dir = new TempDir();
        var file = dir.File("loaded-set.json");
        var copy = dir.File("kernel32.dll");
        File.Copy(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "kernel32.dll"), copy);
        using (var first = new AssemblyWorkspace(new ServerOptions { LoadedSetFile = file }))
            Assert.Equal("kernel32.dll", first.LoadAny(copy).Native!.Id);

        using var second = new AssemblyWorkspace(new ServerOptions { LoadedSetFile = file });
        var error = Assert.Throws<ToolError>(() => second.GetNative("kernel32.dll"));
        Assert.Equal($"load_assembly path={copy}", error.Remediation);
    }
}
