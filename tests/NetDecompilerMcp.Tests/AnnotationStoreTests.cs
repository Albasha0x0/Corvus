using System.Text.Json;
using NetDecompilerMcp.Native.Annotations;

namespace NetDecompilerMcp.Tests;

/// <summary>Annotation sidecars: an unusable sidecar is never silently replaced; writes are atomic and concurrent writers never tear the file.</summary>
public class AnnotationStoreTests : IDisposable
{
    private const string Sha = "ab12";
    private readonly TempDir _dir = new();
    private readonly List<string> _notices = [];
    public void Dispose() => _dir.Dispose();

    private string Root => _dir.File("ann");
    private string Sidecar => Path.Combine(Root, Sha + ".json");

    private NativeAnnotations Open(AnnotationStore? store = null) =>
        new(store ?? new AnnotationStore(Root), _dir.File("image.dll"), Sha, 0x180000000, n => { lock (_notices) _notices.Add(n); });

    private void WriteSidecar(string text)
    {
        Directory.CreateDirectory(Root);
        File.WriteAllText(Sidecar, text);
    }

    private static JsonElement Parse(string file) => JsonDocument.Parse(File.ReadAllText(file)).RootElement;

    [Fact]
    public void CorruptSidecar_IsMovedAside_AndReported()
    {
        WriteSidecar("{ \"names\": { \"1000\": \"Kept\" ");
        var ann = Open();
        var notice = Assert.Single(_notices);
        Assert.Contains("moved to", notice);
        Assert.Null(ann.WriteBlocked);

        ann.SetName(0x2000, "Fresh");
        var aside = Assert.Single(Directory.GetFiles(Root, Sha + ".json.corrupt-*"));
        Assert.Equal("{ \"names\": { \"1000\": \"Kept\" ", File.ReadAllText(aside));
        Assert.Contains(aside, notice);
        Assert.Equal("Fresh", Parse(Sidecar).GetProperty("names").GetProperty("2000").GetString());
    }

    [Fact]
    public void LockedSidecar_IsLeftUntouched_AndWritesAreBlocked()
    {
        WriteSidecar("{\"sha256\":\"ab12\",\"names\":{\"1000\":\"Original\"},\"comments\":{}}");
        var before = File.ReadAllBytes(Sidecar);
        NativeAnnotations ann;
        using (new FileStream(Sidecar, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            ann = Open();
            ann.SetName(0x3000, "InMemory");
        }
        Assert.Equal("InMemory", ann.NameAt(0x3000));
        Assert.Single(_notices);
        if (OperatingSystem.IsWindows())
        {
            Assert.NotNull(ann.WriteBlocked);
            Assert.Contains("left untouched", _notices[0]);
            Assert.Equal(before, File.ReadAllBytes(Sidecar));
        }
        else
        {
            // POSIX locks do not stop a rename: the sidecar is moved aside intact instead.
            var kept = Directory.GetFiles(Root, Sha + ".json*").Select(File.ReadAllBytes);
            Assert.Contains(kept, b => b.AsSpan().SequenceEqual(before));
        }
    }

    [Fact]
    public void SidecarWithoutFormatVersion_Loads_AndIsRewrittenWithIt()
    {
        WriteSidecar("{\"path\":\"x\",\"sha256\":\"ab12\",\"imageBase\":0,\"names\":{\"1000\":\"Legacy\"},\"comments\":{\"1000\":\"note\"}}");
        var ann = Open();
        Assert.Empty(_notices);
        Assert.Equal("Legacy", ann.NameAt(0x1000));
        Assert.Equal("note", ann.CommentAt(0x1000));
        ann.SetComment(0x1000, "changed");
        var doc = Parse(Sidecar);
        Assert.Equal(1, doc.GetProperty("formatVersion").GetInt32());
        Assert.Equal("Legacy", doc.GetProperty("names").GetProperty("1000").GetString());
    }

    [Fact]
    public void UserTypes_RoundTrip_AsVersion2_AndWithoutThemTheFileStaysVersion1()
    {
        var ann = Open();
        ann.ChangeUserTypes(l => l.WithDeclarations("struct S { int a; };").WithType(0x1000, "int __fastcall f(S *s)")
            .WithLocal(new(0x1000, "v3", null, "count", null)).WithLocal(new(0x1000, "count", 0x28, null, "unsigned int"))
            .WithStackVar(new(0x1000, 0x20, "buffer", "char[16]")));
        Assert.Equal(2, Parse(Sidecar).GetProperty("formatVersion").GetInt32());

        var again = Open().UserTypes;
        Assert.Equal(["struct S { int a; };"], again.Declarations);
        Assert.Equal("int __fastcall f(S *s)", again.Types[0x1000]);
        // the second edit names the variable by its new name: one edit, identity kept
        Assert.Equal(new NetDecompilerMcp.Native.Providers.NativeLocalEdit(0x1000, "v3", 0x28, "count", "unsigned int"), Assert.Single(again.Locals[0x1000]));
        Assert.Equal(new NetDecompilerMcp.Native.Providers.NativeStackVarEdit(0x1000, 0x20, "buffer", "char[16]"), Assert.Single(again.StackVars[0x1000]));
        Assert.Equal(ann.UserTypes.Stamp, again.Stamp);

        ann.ChangeUserTypes(_ => UserTypeLayer.Empty);
        ann.SetName(0x1000, "kept");
        Assert.Equal(1, Parse(Sidecar).GetProperty("formatVersion").GetInt32());
        Assert.False(Parse(Sidecar).TryGetProperty("locals", out _));
    }

    [Fact]
    public void Export_CarriesUserTypes_InTheIdaScriptAndJson()
    {
        var ann = Open();
        ann.SetName(0x1000, "Parse");
        ann.ChangeUserTypes(l => l.WithDeclarations("struct S { int a; };").WithType(0x1000, "int __fastcall Parse(S *s)")
            .WithLocal(new(0x1000, "v3", 0x28, "count", null)).WithStackVar(new(0x1000, 0x20, null, "char[16]")));
        var ida = AnnotationExport.Render(ann, AnnotationExport.Format.Ida);
        Assert.Contains("ndm_declare(\"struct S { int a; };\")", ida);
        Assert.Contains("ndm_type(0x1000, \"int __fastcall Parse(S *s)\")", ida);
        Assert.Contains("ndm_stack(0x1000, 32, None, \"char[16]\")", ida);
        Assert.Contains("ndm_local(0x1000, \"v3\", 40, \"count\", None)", ida);
        Assert.Contains("1 name(s), 0 comment(s) and 4 user type(s)", ida);
        var python = NetDecompilerMcp.Native.Providers.PythonLocator.Find([], []);
        if (python != null)
        {
            var script = _dir.File("apply.py");
            File.WriteAllText(script, ida);
            var check = NetDecompilerMcp.Native.Providers.PythonLocator.RunCapture(python.Executable,
                ["-I", "-c", "import sys; compile(open(sys.argv[1]).read(), sys.argv[1], 'exec')", script], TimeSpan.FromSeconds(30));
            Assert.True(check.ExitCode == 0, check.Stderr);
        }

        var json = JsonDocument.Parse(AnnotationExport.Render(ann, AnnotationExport.Format.Json)).RootElement;
        Assert.Equal("struct S { int a; };", json.GetProperty("declarations")[0].GetString());
        Assert.Equal("count", json.GetProperty("locals")[0].GetProperty("name").GetString());
        Assert.Equal(32, json.GetProperty("stackVars")[0].GetProperty("offset").GetInt32());
        Assert.Contains("IDA and JSON exports only", AnnotationExport.Render(ann, AnnotationExport.Format.Ghidra));
    }

    [Fact]
    public void NewerFormatVersion_IsLeftUntouched()
    {
        var text = "{\"formatVersion\":99,\"sha256\":\"ab12\",\"names\":{\"1000\":\"Future\"},\"comments\":{}}";
        WriteSidecar(text);
        var ann = Open();
        Assert.NotNull(ann.WriteBlocked);
        ann.SetName(0x1000, "Mine");
        Assert.Equal(text, File.ReadAllText(Sidecar));
    }

    [Fact]
    public async Task ConcurrentWriters_NeverTearTheFile_AndTheLastWriterKeepsItsEntries()
    {
        var a = Open(new AnnotationStore(Root));
        var b = Open(new AnnotationStore(Root));
        using var stop = new CancellationTokenSource();
        int reads = 0;
        var reader = Task.Run(() =>
        {
            while (!stop.IsCancellationRequested)
            {
                try
                {
                    using var fs = new FileStream(Sidecar, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    JsonDocument.Parse(fs).Dispose(); // a torn file would throw here
                    Interlocked.Increment(ref reads);
                }
                catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException) { }
                Thread.Sleep(1); // an open reader blocks a rename over the file on Windows; real readers are occasional
            }
        });
        Parallel.Invoke(
            () => { for (uint i = 0; i < 20; i++) a.SetName(0x1000 + i * 16, $"A_{i}"); },
            () => { for (uint i = 0; i < 20; i++) b.SetName(0x8000 + i * 16, $"B_{i}"); });
        a.SetComment(0x1000, "last");
        SpinWait.SpinUntil(() => Volatile.Read(ref reads) > 0, TimeSpan.FromSeconds(10)); // the reader may start late on a busy pool
        stop.Cancel();
        await reader;

        Assert.True(_notices.Count == 0, string.Join('\n', _notices));
        Assert.True(Volatile.Read(ref reads) > 0);
        var names = Parse(Sidecar).GetProperty("names");
        for (uint i = 0; i < 20; i++) Assert.Equal($"A_{i}", names.GetProperty((0x1000 + i * 16).ToString("x")).GetString());
        Assert.Empty(Directory.GetFiles(Root, "*.tmp"));
        Assert.Empty(Directory.GetFiles(Root, "*.corrupt-*"));
    }
}
