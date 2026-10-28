using System.Diagnostics;
using System.Xml.Linq;
using Corvus.Core;
using Corvus.Core.Pri;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>Package resource index files: resource names, candidates, qualifiers and values, as MakePri.exe dumps them.</summary>
public sealed class PriFileTests : IDisposable
{
    private const string MakePri = "CORVUS_MAKEPRI";
    private const string PriFiles = "CORVUS_PRI_FILES";

    private static readonly string Fixtures = Path.Combine(AppContext.BaseDirectory, "Containers", "PriFixtures");

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static PriFile Notes() => PriFile.Read(File.ReadAllBytes(Path.Combine(Fixtures, "notes.pri")));

    private PriFileView.Facts View(byte[] bytes, string? table = null, long offset = 0, int? limit = null)
    {
        var path = _dir.File("resources.pri");
        File.WriteAllBytes(path, bytes);
        var f = FileInput.Open(path);
        f.Options = new FileViewOptions("pri", table, Offset: offset, Limit: limit);
        return (PriFileView.Facts)new PriFileView().Inspect(f, default)!.Detail;
    }

    // notes.pri.xml is MakePri's detailed dump of notes.pri (PriFixtures/build.ps1).
    [Fact]
    public void A_built_file_reads_as_makepri_dumped_it()
    {
        int resources = 0;
        Assert.Null(Compare(Path.Combine(Fixtures, "notes.pri"), XDocument.Load(Path.Combine(Fixtures, "notes.pri.xml"), LoadOptions.PreserveWhitespace), ref resources));
        Assert.Equal(10, resources);
    }

    [Fact]
    public void Names_values_and_qualifiers_keep_their_exact_text()
    {
        var map = Assert.Single(Notes().Maps);
        Assert.Equal(("SampleNotes", "ms-appx://SampleNotes/", true), (map.Name, map.UniqueName, map.Primary));
        string Value(string name, string language) =>
            map.Resources.Single(r => r.Name == name).Candidates.Single(c => c.Qualifiers.Any(q => q.Name == "Language" && q.Value == language)).Text!;
        Assert.Equal("Größe", Value("Resources/Größe", "de-DE"));
        // The .resw is XML, so MakePri stores its CR LF as LF.
        Assert.Equal("一行目\n二行目", Value("Resources/Footer", "ja-JP"));
        Assert.Equal("  ", Value("Resources/Spacer", "en-US"));
        Assert.Equal("保存", Value("Resources/Save/Content", "ja-JP"));
        var logo = map.Resources.Single(r => r.Name == "Files/Assets/Logo.png").Candidates;
        Assert.Equal(["Assets\\Logo.scale-100.png", "Assets\\Logo.scale-200.png", "Assets\\Logo.scale-400.png"], logo.Select(c => c.Text!).Order(StringComparer.Ordinal));
        Assert.All(logo, c => Assert.Equal(("Path", "Scale"), (c.Type, Assert.Single(c.Qualifiers).Name)));
    }

    [Fact]
    public void The_view_pages_resources_and_filters_them_by_name()
    {
        var bytes = File.ReadAllBytes(Path.Combine(Fixtures, "notes.pri"));
        var all = View(bytes, limit: 4);
        Assert.Equal(("mrm_pri2", 10, 4, (long?)4), (all.Format, all.Matching, all.Resources.Count, all.Next));
        Assert.Equal(["de-DE", "en-US", "ja-JP"], all.Qualifiers["Language"]);
        Assert.Equal(["HIGH", "STANDARD"], all.Qualifiers["Contrast"]);
        Assert.Contains("offset=4 lists the next resources", all.Notes);
        var greeting = Assert.Single(View(bytes, table: "greet").Resources);
        Assert.Equal("Resources/Greeting", greeting.Name);
        Assert.Contains(greeting.Candidates, c => c is { Qualifiers: "Language=de-DE", Type: "String", Value: "Hallo" });
    }

    [Fact]
    public void A_file_that_is_no_index_is_refused_with_its_reason()
    {
        var bytes = File.ReadAllBytes(Path.Combine(Fixtures, "notes.pri"));
        var cut = bytes.AsSpan(0, 40).ToArray();
        cut[16] = 0xFF;
        var e = Assert.Throws<ToolError>(() => View(cut));
        Assert.Equal(ErrorCode.MalformedInput, e.Code);
        Assert.Contains("table of contents", e.Message);
        Assert.Equal("package resource index", Blob.Identify(bytes));
    }

    // Regression: a schema's entry count of 0x7FFFFFFF reserved a 700 MB list
    // before its first row was read.
    [Fact]
    public void A_schema_entry_count_past_its_section_is_noted_before_it_is_allocated()
    {
        var bytes = File.ReadAllBytes(Path.Combine(Fixtures, "notes.pri"));
        var schema = PriFile.Read(bytes).Sections.First(s => s.Identifier.StartsWith("[mrm_hschema", StringComparison.Ordinal));
        int body = (int)schema.Offset + 32;
        int U16(int at) => System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(at));
        int entries = body + 8 + (schema.Identifier == "[mrm_hschemaex]" ? 16 : 0) + 20 + 2 * U16(body + 2) + 2 * U16(body + 4) + 6;
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(entries), int.MaxValue);
        long before = GC.GetAllocatedBytesForCurrentThread();
        var pri = PriFile.Read(bytes);
        Assert.True(GC.GetAllocatedBytesForCurrentThread() - before < 64 << 20);
        Assert.Contains(pri.Notes, n => n.Contains("run past the section", StringComparison.Ordinal));
    }

    [Fact]
    [FuzzEntry(typeof(PriFile), typeof(PriFileView))]
    public void Fuzzed_indexes_never_throw()
    {
        var failures = FormatFuzz.Run(File.ReadAllBytes(Path.Combine(Fixtures, "notes.pri")), b =>
        {
            try { PriFile.Read(b); }
            catch (InvalidDataException) { return; }
            var file = new FileInput("fuzz.pri", b, "package resource index") { Options = new FileViewOptions("pri", "a") };
            try { new PriFileView().Inspect(file, default); }
            catch (ToolError e) when (e.Code == ErrorCode.MalformedInput) { }
        }, 200);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    // MakePri (CORVUS_MAKEPRI) dumps each .pri under CORVUS_PRI_FILES; compared: every named resource's candidates, in
    // order, with their type, qualifiers and value.
    [RequiresRealDataFact(MakePri, PriFiles)]
    [Trait("Speed", "Slow")]
    public void Real_files_read_as_makepri_dumps_them()
    {
        var files = Directory.EnumerateFiles(Environment.GetEnvironmentVariable(PriFiles)!, "*.pri", SearchOption.AllDirectories).Order(StringComparer.Ordinal).ToList();
        Assert.NotEmpty(files);
        var failures = new List<string>();
        int resources = 0;
        foreach (var file in files)
        {
            var xml = _dir.File(Path.GetRandomFileName() + ".xml");
            var psi = new ProcessStartInfo(Environment.GetEnvironmentVariable(MakePri)!) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var a in new[] { "dump", "/if", file, "/of", xml, "/dt", "detailed", "/o" }) psi.ArgumentList.Add(a);
            using (var p = Process.Start(psi)!)
            {
                p.StandardOutput.ReadToEnd();
                p.WaitForExit();
            }
            var problem = File.Exists(xml) ? Compare(file, XDocument.Load(xml, LoadOptions.PreserveWhitespace), ref resources) : "MakePri wrote no dump";
            if (problem != null) failures.Add($"{file}: {problem}");
            File.Delete(xml);
        }
        Assert.True(failures.Count == 0, $"{failures.Count} of {files.Count} files differ:\n" + string.Join("\n", failures.Take(20)));
        Assert.True(resources > 0);
    }

    /// <summary>Null when the reader and MakePri's <paramref name="dump"/> agree on <paramref name="file"/>, else the first difference.</summary>
    private static string? Compare(string file, XDocument dump, ref int resources)
    {
        var expected = dump.Descendants("NamedResource").Select(r => ((string)r.Attribute("uri")!, r.Elements("Candidate").Select(c =>
            $"{(string)c.Attribute("type")!} {string.Join(",", c.Element("QualifierSet")!.Elements("Qualifier").Select(q => $"{(string)q.Attribute("name")!}={(string)q.Attribute("value")!}").Order(StringComparer.Ordinal))} " +
            (c.Element("Base64Value") is { } b64 ? string.Concat(((string)b64).Where(ch => !char.IsWhiteSpace(ch))) : (string?)c.Element("Value"))).ToList())).ToList();
        PriFile pri;
        try { pri = PriFile.Read(File.ReadAllBytes(file)); }
        catch (InvalidDataException ex) { return $"not read: {ex.Message}"; }
        if (pri.Notes.Count > 0) return "notes: " + string.Join("; ", pri.Notes);
        var actual = pri.Maps.SelectMany(m => m.Resources.Select(r => (Uri: $"ms-resource://{m.Name}/{r.Name}", Candidates: r.Candidates.Select(Shown).ToList()))).ToList();
        if (actual.Count != expected.Count) return $"{actual.Count} resources, MakePri {expected.Count}";
        var byUri = expected.ToDictionary(e => e.Item1, e => e.Item2, StringComparer.Ordinal);
        foreach (var (uri, candidates) in actual)
        {
            if (!byUri.TryGetValue(uri, out var want)) return $"{uri} is not in MakePri's dump";
            if (!candidates.SequenceEqual(want)) return $"{uri}: [{string.Join(" | ", candidates)}], MakePri [{string.Join(" | ", want)}]";
            resources++;
        }
        return null;
    }

    private static string Shown(PriFile.Candidate c) =>
        $"{c.Type} {string.Join(",", c.Qualifiers.Select(q => $"{q.Name}={q.Value}").Order(StringComparer.Ordinal))} " +
        // XML reads a CR LF in the dump as LF.
        (c.Data != null ? Convert.ToBase64String(c.Data) : (c.Text ?? c.Note)?.Replace("\r\n", "\n").Replace('\r', '\n'));
}
