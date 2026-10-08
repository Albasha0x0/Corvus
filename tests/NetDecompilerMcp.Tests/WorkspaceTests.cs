using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Tests;

public class WorkspaceTests
{
    [Fact]
    public void DirectoryLoadSkipsNonDotNetAndDoesNotLockFiles()
    {
        using var dir = new TempDir();
        var copy = dir.File("TestFixture.dll");
        File.Copy(Env.FixturePath, copy);
        File.WriteAllText(dir.File("native.dll"), "not a PE file");
        Directory.CreateDirectory(dir.File("sub"));
        File.Copy(Env.ConsumerPath, dir.File("sub/TestFixture.Consumer.dll"));

        using var ws = new AssemblyWorkspace();
        var progress = new List<int>();
        var report = ws.LoadDirectory(dir.Path, recursive: false, (done, _, _) => progress.Add(done));
        Assert.Single(report.Loaded);
        Assert.Single(report.Skipped);
        Assert.Equal([0, 1], progress);
        Assert.Same(report.Loaded[0], ws.Load(copy)); // idempotent
        File.Copy(Env.FixturePath, copy, overwrite: true); // not locked

        var recursive = ws.LoadDirectory(dir.Path, recursive: true);
        Assert.Contains(recursive.Loaded, a => a.Id == "TestFixture.Consumer");
    }

    [Fact]
    public void DuplicateNamesGetDistinctIdsAndAmbiguityIsReported()
    {
        using var dir = new TempDir();
        var copy = dir.File("TestFixture.dll");
        File.Copy(Env.FixturePath, copy);
        using var ws = new AssemblyWorkspace();
        var a = ws.Load(Env.FixturePath);
        var b = ws.Load(copy);
        Assert.Equal("TestFixture", a.Id);
        Assert.Equal("TestFixture#2", b.Id);
        Assert.Throws<ToolError>(() => ws.Read(() => SymbolResolver.ResolveOne(ws, null, "Account", SymbolKind.Type)));
        Assert.Same(b, ws.Read(() => SymbolResolver.ResolveOne(ws, "TestFixture#2", "Account", SymbolKind.Type)).Assembly);
        Assert.Same(b, ws.Get(copy)); // by full path
        Assert.Throws<ToolError>(() => ws.Get("TestFixture.dll")); // file name matches both
    }

    [Fact]
    public void GetByIdFileNameAndPath()
    {
        using var ws = new AssemblyWorkspace();
        var a = ws.Load(Env.FixturePath);
        Assert.Same(a, ws.Get("testfixture"));
        Assert.Same(a, ws.Get("TestFixture.dll"));
        Assert.Same(a, ws.Get(Env.FixturePath));
        Assert.Throws<ToolError>(() => ws.Get(" "));
    }

    [Fact]
    public void ErrorsForMissingAndInvalidInput()
    {
        using var ws = new AssemblyWorkspace();
        Assert.Contains("No assemblies are loaded", Assert.Throws<ToolError>(() => ws.Get("x")).Message);
        Assert.Contains("No assemblies are loaded", Assert.Throws<ToolError>(() => ws.Scope(null)).Message);
        Assert.Contains("File not found", Assert.Throws<ToolError>(() => ws.Load(@"C:\nope\missing.dll")).Message);
        Assert.Throws<ToolError>(() => ws.LoadDirectory(@"C:\nope\missing", false));
        Assert.Throws<ToolError>(() => ws.AddSearchDirectory(@"C:\nope\missing"));
        using var dir = new TempDir();
        File.WriteAllText(dir.File("bad.dll"), "garbage");
        Assert.Contains("Not a loadable .NET assembly", Assert.Throws<ToolError>(() => ws.Load(dir.File("bad.dll"))).Message);
    }

    [Fact]
    public void UnloadAndGenerationInvalidation()
    {
        using var ws = new AssemblyWorkspace();
        var a = ws.Load(Env.FixturePath);
        int generation = ws.Generation;
        ws.Load(Env.ConsumerPath);
        Assert.True(ws.Generation > generation);
        ws.Unload(a);
        Assert.Single(ws.Assemblies);
    }

    [Fact]
    public void ResolvesReferencesFromSearchPathAndRuntime()
    {
        using var ws = new AssemblyWorkspace();
        ws.Load(Env.ConsumerPath); // TestFixture is next to it -> found via the auto-added search directory
        Assert.NotNull(ws.FindAssemblyFile("TestFixture"));
        Assert.NotNull(ws.FindAssemblyFile("System.Runtime")); // runtime directory fallback
        Assert.Null(ws.FindAssemblyFile("Definitely.Not.Here"));
    }

    [Fact]
    public void PagerSplitsOnLinesCachesAndPagesRows()
    {
        var pager = new OutputPager(new ServerOptions { MaxOutputChars = 2_000 });
        var text = string.Join("\n", Enumerable.Range(0, 500).Select(i => $"line {i:D4}"));
        var first = pager.Page(text);
        Assert.Contains("Call again with offset=", first);
        int next = int.Parse(System.Text.RegularExpressions.Regex.Match(first, @"offset=(\d+)").Groups[1].Value);
        Assert.Equal('\n', text[next - 1]);
        Assert.StartsWith($"[Continuing from offset {next}]", pager.Page(text, next));
        Assert.Throws<ToolError>(() => pager.Page(text, text.Length + 5));
        Assert.Equal("short", pager.Page("short"));

        int calls = 0;
        pager.GetOrCreate("k", () => { calls++; return "v"; });
        pager.GetOrCreate("k", () => { calls++; return "v"; });
        Assert.Equal(1, calls);

        var rows = Enumerable.Range(0, 10).Select(i => $"row{i}").ToList();
        var page = pager.PageRows(rows, 2, 3, "row");
        Assert.Contains("10 rows (showing 3-5)", page);
        Assert.Contains("offset=5", page);
    }

    [Fact]
    public void ServerOptionsParsing()
    {
        var o = ServerOptions.Parse(["--load", "a.dll", "--load", "b", "--search-dir", "c", "--max-output", "5000", "--timeout", "30"]);
        Assert.Equal(["a.dll", "b"], o.Preload.Take(2));
        Assert.Equal(["c"], o.SearchDirectories);
        Assert.Equal(5000, o.MaxOutputChars);
        Assert.Equal(30, o.TimeoutSeconds);
        Assert.Throws<ArgumentException>(() => ServerOptions.Parse(["--bogus"]));
        Assert.Throws<ArgumentException>(() => ServerOptions.Parse(["--load"]));
    }
}
