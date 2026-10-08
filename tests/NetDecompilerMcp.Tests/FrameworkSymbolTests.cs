using NetDecompilerMcp.Tools;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Tools that look for users of a symbol accept framework / dependency types and members the loaded code only
/// references (System.IDisposable, Process.Start), matched by name across the files they come from.
/// </summary>
public class FrameworkSymbolTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private const string Source = """
        using System;
        using System.Diagnostics;
        using System.IO;
        public sealed class Resource : IDisposable { public void Dispose() { } }
        public sealed class Explicit : IDisposable { void IDisposable.Dispose() { } }
        public sealed class Counting : Stream
        {
            public override bool CanRead => true; public override bool CanSeek => false; public override bool CanWrite => false;
            public override long Length => 0; public override long Position { get; set; }
            public override void Flush() { }
            public override int Read(byte[] buffer, int offset, int count) => 0;
            public override long Seek(long offset, SeekOrigin origin) => 0;
            public override void SetLength(long value) { }
            public override void Write(byte[] buffer, int offset, int count) { }
        }
        public static class Launcher
        {
            public static void Open(string url) => Process.Start(url);
            public static void Run() => Open("https://example.com");
            public static void Close(IDisposable d) => d.Dispose();
        }
        """;

    private Env Load()
    {
        var path = _dir.File("Users.dll");
        File.WriteAllBytes(path, ReferenceResolutionTests.Compile("Users", Source));
        return new Env(path);
    }

    [Fact]
    public async Task FrameworkTypesAndMembers_CanBeTargets()
    {
        using var env = Load();
        var refs = new ReferenceTools(env.Workspace, env.References, env.Pager);

        var overrides = await refs.FindOverrides("System.IDisposable::Dispose");
        Assert.Contains("Resource::Dispose()", overrides);
        Assert.Contains("Explicit::System.IDisposable.Dispose()", overrides);
        Assert.Contains("(reference)", overrides); // says where the base method comes from

        var callers = await refs.FindReferences("System.Diagnostics.Process::Start(string)");
        Assert.Contains("Launcher::Open(string)", callers);

        var hierarchy = await new BrowseTools(env.Workspace, env.References, env.Pager).GetTypeHierarchy("System.IO.Stream");
        Assert.Contains("Counting", hierarchy);

        var paths = await new CallGraphTools(env.Workspace, new NetDecompilerMcp.Services.CallGraphService(env.Workspace), env.Pager).FindCallPaths("System.Diagnostics.Process::Start(string)");
        Assert.Contains("Launcher::Run()", paths);
        Assert.Contains("Launcher::Open(string)", paths);

        // loaded types still win, and unknown names still fail clearly
        Assert.Contains("not found", (await Assert.ThrowsAsync<NetDecompilerMcp.Core.ToolError>(() => refs.FindOverrides("System.NoSuchType::Dispose"))).Message);
    }

    [Fact]
    public async Task NetFrameworkAndModernCopies_AreOneApi()
    {
        using var env = Load(); // System.Private.CoreLib
        env.Workspace.Load(RealPackages.Lib("Newtonsoft.Json", "13.0.1", "net45", "Newtonsoft.Json.dll")); // mscorlib
        var overrides = await new ReferenceTools(env.Workspace, env.References, env.Pager).FindOverrides("System.IDisposable::Dispose", limit: 1000);
        Assert.Contains("[Users]", overrides);
        Assert.Contains("[Newtonsoft.Json]", overrides);
    }
}
