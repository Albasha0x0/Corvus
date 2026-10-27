using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Corvus.Core;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>save_assembly keeps what no edit touched byte for byte and reports each member it cannot keep, with the reason.</summary>
public sealed class SaveFidelityTests(ITestOutputHelper output)
{
    public static TheoryData<InvalidShape> Shapes => new(Enum.GetValues<InvalidShape>());

    private sealed class Case : IDisposable
    {
        private readonly TempDir _dir = new();
        public string Input { get; }
        public byte[] Original { get; }
        public Env Env { get; }

        public Case(byte[] image)
        {
            Input = _dir.File("Fidelity.dll");
            File.WriteAllBytes(Input, image);
            Original = image;
            Env = new Env(Input);
        }

        public string Output => _dir.File("Fidelity.saved.dll");
        public string Dir => _dir.Path;

        public string Save(bool strict = false) => Env.Edits.Save(Env.Fixture, Output, overwrite: true, strict);

        public uint Token(string member) => ((IMDTokenProvider)Env.One(member).Member).MDToken.Raw;

        public void Edit() => Env.Edit(() => Env.Edits.StubMethod(Env.One(SaveFidelity.EditTarget), "42"));

        public void Dispose()
        {
            Env.Dispose();
            _dir.Dispose();
        }
    }

    /// <summary>The report line of a member: it names the member and ends with the reason code.</summary>
    private static string Line(string report, string member, string code)
    {
        var line = report.Split('\n').FirstOrDefault(l => l.Contains(member + "(", StringComparison.Ordinal));
        Assert.True(line != null, $"{member} is not listed in:\n{report}");
        Assert.EndsWith($"[{code}]", line!.TrimEnd());
        return line;
    }

    [Theory, MemberData(nameof(Shapes))]
    public void Unmodified_save_writes_the_original_bytes_and_lists_the_shape(InvalidShape shape)
    {
        using var c = new Case(SaveFidelity.Build(shape));
        var result = c.Save();
        output.WriteLine(result);
        Assert.Equal(c.Original, File.ReadAllBytes(c.Output));
        Line(result, SaveFidelity.Method(shape), SaveFidelity.Code(shape, edited: false));
        Assert.DoesNotContain("Changed by the writer", result);
    }

    [Theory, MemberData(nameof(Shapes))]
    public void Edited_save_keeps_the_shape_and_everything_else_no_edit_touched(InvalidShape shape)
    {
        using var c = new Case(SaveFidelity.Build(shape));
        uint target = c.Token(SaveFidelity.EditTarget), method = c.Token(SaveFidelity.Method(shape));
        c.Edit();
        var result = c.Save();
        output.WriteLine(result);
        var written = File.ReadAllBytes(c.Output);
        var (image, report) = c.Env.Fixture.GetImage();
        Assert.Equal(image, written);

        var line = Line(result, SaveFidelity.Method(shape), SaveFidelity.Code(shape, edited: true));
        Assert.Contains(report.Issues, i => i.Token == method && SaveManifest.CodeOf(i.Reason) == SaveFidelity.Code(shape, edited: true));

        // The edit is in the image; every other body and signature is the original's, unless reported as changed.
        var differ = SaveFidelity.Differences(c.Original, written);
        Assert.Contains(target, differ);
        differ.Remove(target);
        var unexplained = differ.Except(SaveFidelity.Listed(report, changesBytes: true)).ToList();
        Assert.True(unexplained.Count == 0, $"differ without a report entry: {string.Join(", ", unexplained.Select(t => $"0x{t:X8}"))}\n{result}");
        if (shape == InvalidShape.UnreadableBody)
            Assert.Contains("written", line); // what was written instead
        else
            Assert.DoesNotContain(method, differ); // the invalid shape itself is kept byte-for-byte

        using var reloaded = ModuleDefMD.Load(written);
        var stub = reloaded.Types.Single(t => t.FullName == SaveFidelity.Type).Methods.Single(m => m.Name == "Target");
        Assert.Equal([Code.Ldc_I4, Code.Ret], stub.Body.Instructions.Select(i => i.OpCode.Code == Code.Ldc_I4_S ? Code.Ldc_I4 : i.OpCode.Code));
        Assert.Equal(42, stub.Body.Instructions[0].GetLdcI4Value());
    }

    [Fact]
    public void Mixed_module_keeps_every_invalid_shape_next_to_an_edit()
    {
        var shapes = Enum.GetValues<InvalidShape>();
        using var c = new Case(SaveFidelity.Build(shapes));
        uint target = c.Token(SaveFidelity.EditTarget);
        c.Env.Edit(() => c.Env.Edits.PatchMethodIL(c.Env.One(SaveFidelity.EditTarget), "ldc.i4 1234\nret", "replace", false));
        var result = c.Save();
        output.WriteLine(result);
        var written = File.ReadAllBytes(c.Output);
        var (_, report) = c.Env.Fixture.GetImage();

        foreach (var shape in shapes) Line(result, SaveFidelity.Method(shape), SaveFidelity.Code(shape, edited: true));
        var differ = SaveFidelity.Differences(c.Original, written);
        Assert.Contains(target, differ);
        differ.Remove(target);
        Assert.Equal([c.Token(SaveFidelity.Method(InvalidShape.UnreadableBody))], differ.Order());
        Assert.Equal(differ, SaveFidelity.Listed(report, changesBytes: true));
        // Valid methods (calls, string literals, locals, exception handlers) are untouched: same bytes.
        foreach (var valid in new[] { "Lab.P::Valid", "Lab.P::Text", "Lab.P::Guarded" }) Assert.DoesNotContain(c.Token(valid), differ);
        Assert.Contains(1234, ModuleDefMD.Load(written).Types.Single(t => t.FullName == SaveFidelity.Type).Methods.Single(m => m.Name == "Target")
            .Body.Instructions.Where(i => i.IsLdcI4()).Select(i => i.GetLdcI4Value()));
    }

    [Fact]
    public void Edited_valid_module_is_kept_except_the_edit_and_still_runs()
    {
        using var c = new Case(SaveFidelity.Build());
        uint target = c.Token(SaveFidelity.EditTarget);
        c.Edit();
        var result = c.Save();
        Assert.DoesNotContain("Changed by the writer", result);
        Assert.DoesNotContain("Kept byte-for-byte", result);
        var written = File.ReadAllBytes(c.Output);
        Assert.Equal([target], SaveFidelity.Differences(c.Original, written));

        using var run = new IlLab.LabRunner(written);
        Assert.Equal(42, run.Call(SaveFidelity.Type, "Target").Value);
        Assert.Equal(9, run.Call(SaveFidelity.Type, "Valid", 9).Value);
        Assert.Equal("hello you", run.Call(SaveFidelity.Type, "Text", "you").Value);
    }

    [Fact]
    public void Unmodified_save_writes_the_original_bytes()
    {
        using var dir = new TempDir();
        foreach (var path in new[] { Env.FixturePath, RealPackages.Lib("newtonsoft.json", "13.0.4", "netstandard2.0", "Newtonsoft.Json.dll") })
        {
            using var env = new Env(path);
            var target = dir.File(Path.GetFileName(path));
            var result = env.Edits.Save(env.Fixture, target, overwrite: false);
            Assert.Equal(File.ReadAllBytes(path), File.ReadAllBytes(target));
            Assert.Contains("no edits: the original bytes", result);
        }
    }

    [Fact]
    public void Strict_save_fails_with_the_same_list_and_writes_nothing()
    {
        using var c = new Case(SaveFidelity.Build(InvalidShape.UnreadableBody, InvalidShape.EmptyBody));
        c.Edit();
        var error = Assert.Throws<ToolError>(() => c.Save(strict: true)).Message;
        output.WriteLine(error);
        Assert.Contains("Nothing was written", error);
        Assert.False(File.Exists(c.Output));
        Assert.Equal([Path.GetFileName(c.Input)], Directory.GetFiles(c.Dir).Select(Path.GetFileName));

        // Same list as the default save, which goes ahead.
        var saved = c.Save();
        var list = (string s) => s[s.IndexOf("\n\nChanged by the writer", StringComparison.Ordinal)..];
        Assert.Equal(list(saved), list(error));
        Line(saved, SaveFidelity.Method(InvalidShape.UnreadableBody), "unreadable-body");
        Line(saved, SaveFidelity.Method(InvalidShape.EmptyBody), "invalid-body");
    }

    [Fact]
    public void Strict_save_accepts_invalid_shapes_kept_byte_for_byte()
    {
        var kept = Enum.GetValues<InvalidShape>().Where(s => s != InvalidShape.UnreadableBody).ToArray();
        using var c = new Case(SaveFidelity.Build(kept));
        c.Edit();
        var result = c.Save(strict: true);
        foreach (var shape in kept) Line(result, SaveFidelity.Method(shape), SaveFidelity.Code(shape, edited: true));
        Assert.True(File.Exists(c.Output));
    }

    [Fact]
    public void Edits_refuse_a_method_whose_signature_cannot_be_read()
    {
        using var c = new Case(SaveFidelity.Build(InvalidShape.MalformedSignature));
        var method = c.Env.One(SaveFidelity.Method(InvalidShape.MalformedSignature));
        var error = Assert.Throws<ToolError>(() => c.Env.Edit(() => c.Env.Edits.StubMethod(method, null))).Message;
        Assert.Contains("signature that cannot be read", error);
        Assert.Throws<ToolError>(() => c.Env.Edit(() => c.Env.Edits.PatchMethodIL(method, "ret", "replace", false)));
        Assert.False(c.Env.Fixture.IsDirty);
    }

    /// <summary>Loads, edits and saves a damaged image: each step works or refuses with a <see cref="ToolError"/>, and a saved file reports every difference.</summary>
    private static string Survive(byte[] image)
    {
        using var dir = new TempDir();
        var input = dir.File("Damaged.dll");
        var target = dir.File("Damaged.saved.dll");
        File.WriteAllBytes(input, image);
        void NothingLeftBehind() => Assert.Equal(["Damaged.dll", .. File.Exists(target) ? new[] { "Damaged.saved.dll" } : []],
            Directory.GetFiles(dir.Path).Select(Path.GetFileName).Order());

        Env env;
        try { env = new Env(input); }
        catch (ToolError e) { return "load refused: " + e.Message.Split('\n')[0]; }
        using (env)
        {
            uint edited = 0;
            try
            {
                var symbol = env.One(SaveFidelity.EditTarget);
                edited = ((IMDTokenProvider)symbol.Member).MDToken.Raw;
                env.Edit(() => env.Edits.StubMethod(symbol, "42"));
            }
            catch (Exception ex) when (ex is ToolError || ex.GetType().Namespace?.StartsWith("dnlib", StringComparison.Ordinal) == true)
            {
                // Editing damaged metadata may fail; the save of the resulting state is what is checked.
                edited = 0;
            }

            string result;
            try { result = env.Edits.Save(env.Fixture, target, overwrite: false); }
            catch (ToolError e)
            {
                Assert.False(File.Exists(target));
                NothingLeftBehind();
                return "save refused: " + e.Message.Split('\n')[0];
            }
            NothingLeftBehind();
            var written = File.ReadAllBytes(target);
            if (!env.Fixture.IsDirty)
            {
                Assert.Equal(image, written);
                return "saved unmodified";
            }
            var (bytes, report) = env.Fixture.GetImage();
            Assert.Equal(bytes, written);
            if (report.Changed.Any(i => i.Token == 0)) return "saved, module-level change reported: " + report.Changed.First(i => i.Token == 0).Detail;
            HashSet<uint> differ;
            try { differ = SaveFidelity.Differences(image, written); }
            catch (BadImageFormatException e) { Assert.Fail($"the original cannot be compared ({e.Message}) but the report has no module-level entry:\n{result}"); throw; }
            differ.Remove(edited);
            var unexplained = differ.Except(SaveFidelity.Listed(report, changesBytes: true)).ToList();
            Assert.True(unexplained.Count == 0, $"differ without a report entry: {string.Join(", ", unexplained.Select(t => $"0x{t:X8}"))}\n{result}");
            return $"saved, {report.Changed.Count()} change(s) and {report.Kept.Count()} kept member(s) reported";
        }
    }

    [Fact]
    public void Truncated_images_are_refused_or_saved_with_everything_reported()
    {
        var image = SaveFidelity.Build(Enum.GetValues<InvalidShape>());
        foreach (int length in new[] { 64, 512, image.Length / 2, image.Length - 600, image.Length - 1 })
            output.WriteLine($"truncated to {length} bytes: {Survive(image[..length])}");
    }

    [Fact]
    public void Corrupted_metadata_is_refused_or_saved_with_everything_reported()
    {
        var image = SaveFidelity.Build(Enum.GetValues<InvalidShape>());
        using var pe = new System.Reflection.PortableExecutable.PEReader(new MemoryStream(image.ToArray()));
        var md = System.Reflection.Metadata.PEReaderExtensions.GetMetadataReader(pe);
        int metadata = pe.PEHeaders.MetadataStartOffset;
        int Heap(System.Reflection.Metadata.Ecma335.HeapIndex h) => metadata + System.Reflection.Metadata.Ecma335.MetadataReaderExtensions.GetHeapMetadataOffset(md, h);
        int Table(System.Reflection.Metadata.Ecma335.TableIndex t) => metadata + System.Reflection.Metadata.Ecma335.MetadataReaderExtensions.GetTableMetadataOffset(md, t);
        var cases = new (string Name, int Offset, byte[] Bytes)[]
        {
            ("blob heap overwritten", Heap(System.Reflection.Metadata.Ecma335.HeapIndex.Blob) + 1, Enumerable.Repeat((byte)0xFF, 24).ToArray()),
            ("strings heap overwritten", Heap(System.Reflection.Metadata.Ecma335.HeapIndex.String) + 1, Enumerable.Repeat((byte)0xFF, 32).ToArray()),
            ("user strings heap overwritten", Heap(System.Reflection.Metadata.Ecma335.HeapIndex.UserString) + 1, Enumerable.Repeat((byte)0xEE, 8).ToArray()),
            ("member reference class out of range", Table(System.Reflection.Metadata.Ecma335.TableIndex.MemberRef), [0xFF, 0xFF]),
            ("method row signature out of range", Table(System.Reflection.Metadata.Ecma335.TableIndex.MethodDef) + 10, [0xFF, 0x7F]),
            ("metadata signature damaged", metadata, [0, 0, 0, 0]),
            ("table stream header damaged", Table(System.Reflection.Metadata.Ecma335.TableIndex.Module) - 16, Enumerable.Repeat((byte)0xFF, 8).ToArray()),
        };
        foreach (var (name, offset, bytes) in cases)
        {
            var damaged = image.ToArray();
            bytes.CopyTo(damaged, offset);
            output.WriteLine($"{name}: {Survive(damaged)}");
        }
    }

    [Fact]
    public void Random_damage_is_refused_or_saved_with_everything_reported()
    {
        var image = SaveFidelity.Build(Enum.GetValues<InvalidShape>());
        int count = int.TryParse(Environment.GetEnvironmentVariable("CORVUS_FUZZ_COUNT"), out int n) ? n : 60;
        var outcomes = new Dictionary<string, int>();
        for (int seed = 1; seed <= count; seed++)
        {
            var random = new Random(seed);
            var damaged = image.ToArray();
            for (int k = random.Next(1, 9); k > 0; k--) damaged[random.Next(0x80, damaged.Length)] = (byte)random.Next(256);
            string outcome;
            try { outcome = Survive(damaged); }
            catch (Exception ex) { throw new Xunit.Sdk.XunitException($"[save fuzz] seed {seed}: {ex}"); }
            var kind = outcome.StartsWith("save refused", StringComparison.Ordinal)
                ? "save refused: " + System.Text.RegularExpressions.Regex.Replace(outcome.Split(": ", 3)[^1], "0x[0-9A-F]+|[0-9]+", "#")
                : outcome.Split(':', ',')[0];
            outcomes[kind] = outcomes.GetValueOrDefault(kind) + 1;
        }
        foreach (var (kind, times) in outcomes.OrderByDescending(p => p.Value)) output.WriteLine($"{times,4}  {kind}");
    }

    [Fact]
    public void ReadyToRun_image_with_full_headers_is_written_as_IL_only_and_reported()
    {
        var path = RealPackages.File("Microsoft.NETCore.App.Runtime.osx-arm64", "10.0.11", "runtimes", "osx-arm64", "lib", "net10.0", "System.Linq.dll");
        var (written, report) = Rewrite(path);
        Assert.Contains(report.Issues, i => i.Reason == SaveIssueReason.PrecompiledCodeDropped);
        using (var pe = new System.Reflection.PortableExecutable.PEReader(new MemoryStream(written)))
        {
            var cor = pe.PEHeaders.CorHeader!;
            Assert.Equal(System.Reflection.PortableExecutable.CorFlags.ILOnly, cor.Flags & (System.Reflection.PortableExecutable.CorFlags.ILOnly | System.Reflection.PortableExecutable.CorFlags.ILLibrary));
            Assert.Equal(0, cor.ManagedNativeHeaderDirectory.Size);
            Assert.Equal(System.Reflection.PortableExecutable.Machine.Arm64, pe.PEHeaders.CoffHeader.Machine);
        }
        Assert.Empty(SaveFidelity.Differences(File.ReadAllBytes(path), written).Except(SaveFidelity.Listed(report, changesBytes: true)));

        // On Linux and macOS the host's own System.Linq has full headers too: the IL-only rewrite runs.
        var (own, ownReport) = Rewrite(typeof(Enumerable).Assembly.Location);
        if (!ownReport.Issues.Any(i => i.Reason == SaveIssueReason.PrecompiledCodeDropped)) return;
        var context = new System.Runtime.Loader.AssemblyLoadContext("il-only", isCollectible: true);
        try
        {
            var range = context.LoadFromStream(new MemoryStream(own)).GetType("System.Linq.Enumerable")!.GetMethod("Range")!;
            Assert.Equal(new[] { 1, 2, 3 }, (IEnumerable<int>)range.Invoke(null, [1, 3])!);
        }
        finally { context.Unload(); }

        static (byte[], SaveReport) Rewrite(string path)
        {
            using var workspace = new AssemblyWorkspace(new ServerOptions { BackgroundIndexing = false, WatchFiles = false });
            var asm = workspace.Load(path);
            using var ms = new MemoryStream();
            var report = workspace.Read(() => asm.Write(ms));
            return (ms.ToArray(), report);
        }
    }

    [Fact]
    public void Report_codes_follow_the_manifest()
    {
        Assert.Equal(Enum.GetValues<SaveIssueReason>().Length, SaveManifest.Reasons.Count);
        Assert.Equal(SaveManifest.Reasons.Count, SaveManifest.Reasons.Select(r => r.Code).Distinct().Count());
        var issue = new SaveIssue(SaveIssueReason.UnreadableBody, 0x06000001, "N.T::M() [0x06000001]", "why");
        Assert.True(issue.ChangesBytes);
        Assert.Equal("N.T::M() [0x06000001]: why [unreadable-body]", issue.ToString());
        Assert.False(new SaveIssue(SaveIssueReason.InvalidBody, 0, "m", "d").ChangesBytes);
    }

    [Fact]
    public void Saving_doc_is_up_to_date()
    {
        var root = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(root, "Corvus.slnx"))) root = Path.GetDirectoryName(root) ?? throw new InvalidOperationException("repository root not found");
        var path = Path.Combine(root, "docs", "saving.md");
        var expected = SaveManifest.Markdown().ReplaceLineEndings("\n");
        if (Environment.GetEnvironmentVariable("CORVUS_UPDATE_DOCS") == "1")
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, expected);
        }
        Assert.True(File.Exists(path) && File.ReadAllText(path).ReplaceLineEndings("\n") == expected,
            "docs/saving.md is out of date: run the tests once with CORVUS_UPDATE_DOCS=1");
    }
}
