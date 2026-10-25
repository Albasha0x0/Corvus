using System.Diagnostics;
using System.Text.RegularExpressions;
using Corvus.Core.Ark;
using Corvus.Native.Providers;
using Corvus.Core;
using Corvus.Services.Analysis;
using Corvus.Services.Web;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>The Ark bytecode fixtures es2abc builds from features.ts and helper.ts (ArkFixtures/build.ps1).</summary>
internal static class ArkFixtures
{
    public static string Path(string name) => System.IO.Path.Combine(AppContext.BaseDirectory, "Mobile", "ArkFixtures", name);

    public static byte[] Features => File.ReadAllBytes(Path("features.abc"));
}

/// <summary>Ark bytecode (.abc): header, records, methods and the disassembly of each method body.</summary>
public sealed partial class ArkBytecodeTests(ITestOutputHelper output)
{
    /// <summary>
    /// A listing in ark_disasm's form: per function, its instructions with jump and try labels replaced by the index of
    /// the instruction they name.
    /// </summary>
    internal static Dictionary<string, List<string>> Listing(string text)
    {
        var functions = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        // Lines end as the first one does (CRLF from a Windows build); any other carriage return is string text, and NUL
        // prints as its MUTF-8 bytes.
        string end = text.IndexOf('\n') is > 0 and var nl && text[nl - 1] == '\r' ? "\r\n" : "\n";
        var lines = text.Split(end).Select(l => l.Replace("\r", "\\r", StringComparison.Ordinal).Replace("��", "\\0", StringComparison.Ordinal)).ToList();
        for (int i = 0; i < lines.Count; i++)
        {
            var header = FunctionHeader().Match(lines[i]);
            if (!header.Success) continue;
            var body = new List<string>();
            var labels = new Dictionary<string, int>(StringComparer.Ordinal);
            for (i++; i < lines.Count && lines[i] != "}"; i++)
            {
                var l = lines[i];
                if (l.StartsWith(".catch", StringComparison.Ordinal) || LabelLine().IsMatch(l))
                {
                    if (l[0] != '.') labels[l[..^1]] = body.Count;
                    continue;
                }
                // ark_disasm prints string text raw, so a line break inside a string continues the instruction; a blank
                // line is string text when more string text follows it.
                if (l.Length == 0 && !Continues(lines, i + 1)) continue;
                if (!l.StartsWith('\t') && body.Count > 0) { body[^1] += "\\n" + l; continue; }
                body.Add(l.Trim());
            }
            functions[header.Groups[1].Value] = [.. body.Select(b => LabelOperand().Replace(b, m => labels.TryGetValue(m.Value, out var at) ? $"@{at}" : m.Value))];
        }
        return functions;
    }

    private static bool Continues(List<string> lines, int i)
    {
        while (i < lines.Count && lines[i].Length == 0) i++;
        return i < lines.Count && lines[i] != "}" && !lines[i].StartsWith('\t') && !lines[i].StartsWith(".catch", StringComparison.Ordinal) && !LabelLine().IsMatch(lines[i]);
    }

    /// <summary>The same listing from Corvus's decoder: every method with code, jumps as the index of their target.</summary>
    internal static Dictionary<string, List<string>> Ours(ArkFile file)
    {
        var functions = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var m in file.Classes.SelectMany(c => c.Methods))
        {
            if (m.Code is not { } at) continue;
            var code = file.Code(at);
            var list = ArkOpcodes.Decode(code.Instructions, out int stopped);
            var index = list.Select((ins, n) => (ins.Offset, n)).ToDictionary(x => x.Offset, x => x.n);
            var body = list.Select(ins =>
            {
                var text = ArkBundles.Text(file, m, ins, code.Arguments, code.Registers);
                return ins.Operation.IsJump && index.TryGetValue(ins.Offset + (int)ins.Values[0], out var target)
                    ? $"{ins.Operation.Name} @{target}" : text;
            }).ToList();
            if (stopped >= 0) body.Add($"<stopped at 0x{stopped:x}>");
            functions[m.FullName] = body;
        }
        return functions;
    }

    [GeneratedRegex(@"^\.function \S+ (\S+?)\(")]
    private static partial Regex FunctionHeader();

    [GeneratedRegex(@"^(jump_label_\d+|try_begin_label_\d+|try_end_label_\d+|handler_begin_label_\d+_\d+):$")]
    private static partial Regex LabelLine();

    [GeneratedRegex(@"\b(jump_label_\d+|try_begin_label_\d+|try_end_label_\d+|handler_begin_label_\d+_\d+)\b")]
    private static partial Regex LabelOperand();

    internal static List<string> Differences(Dictionary<string, List<string>> theirs, Dictionary<string, List<string>> ours)
    {
        var problems = new List<string>();
        foreach (var (name, body) in theirs)
        {
            if (!ours.TryGetValue(name, out var mine)) { problems.Add($"{name}: missing"); continue; }
            for (int i = 0; i < Math.Max(body.Count, mine.Count); i++)
            {
                string a = i < body.Count ? body[i] : "<end>", b = i < mine.Count ? mine[i] : "<end>";
                if (a == b) continue;
                // A long line is shown from just before its first difference.
                int at = 0;
                while (at < a.Length && at < b.Length && a[at] == b[at]) at++;
                int from = Math.Max(0, at - 40);
                problems.Add($"{name} [{i}] at {at}: ark_disasm '{a[from..Math.Min(a.Length, at + 80)]}', Corvus '{b[from..Math.Min(b.Length, at + 80)]}'");
                break;
            }
        }
        foreach (var name in ours.Keys.Except(theirs.Keys)) problems.Add($"{name}: not in the listing");
        return problems;
    }

    [Fact]
    public void Each_method_of_the_fixture_disassembles_as_ark_disasm_lists_it()
    {
        var file = new ArkFile(ArkFixtures.Features);
        var theirs = Listing(File.ReadAllText(ArkFixtures.Path("features.txt")));
        var problems = Differences(theirs, Ours(file));
        foreach (var p in problems) output.WriteLine(p);
        Assert.Empty(problems);
        Assert.True(theirs.Count >= 15, $"{theirs.Count} functions");
    }

    // ark_disasm lists each file into a temporary file.
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_ARK_DIR", "CORVUS_ARK_DISASSEMBLER")]
    public void Real_bytecode_disassembles_as_ark_disasm_lists_it()
    {
        var tool = ExternalTools.Locate(ExternalTools.ArkDisassembler)!.Value.Path;
        var files = Directory.EnumerateFiles(RealData.Path("CORVUS_ARK_DIR"), "*.abc", SearchOption.AllDirectories).Order(StringComparer.Ordinal).ToList();
        Assert.NotEmpty(files);
        using var dir = new TempDir();
        var problems = new List<string>();
        long functions = 0, instructions = 0;
        foreach (var file in files)
        {
            var listing = dir.File(Path.GetFileNameWithoutExtension(file) + ".txt");
            var run = ExternalTools.Run(tool, ExternalTools.Arguments(ExternalTools.ArkDisassembler, "list", ("file", file), ("output", listing)), TimeSpan.FromMinutes(10), 1 << 16, default);
            Assert.True(run.ExitCode == 0, $"{file}: ark_disasm exit {run.ExitCode}: {run.Text}");
            var sw = Stopwatch.StartNew();
            var ours = Ours(new ArkFile(File.ReadAllBytes(file)));
            var elapsed = sw.Elapsed;
            var theirs = Listing(File.ReadAllText(listing));
            functions += theirs.Count;
            instructions += theirs.Values.Sum(b => b.Count);
            problems.AddRange(Differences(theirs, ours).Select(p => $"{Path.GetFileName(file)}: {p}"));
            output.WriteLine($"{Path.GetFileName(file)}: {new FileInfo(file).Length:N0} bytes, {theirs.Count:N0} functions, read and decoded in {elapsed.TotalMilliseconds:N0} ms");
        }
        output.WriteLine($"{files.Count} files, {functions:N0} functions, {instructions:N0} instructions compared");
        foreach (var p in problems.Take(60)) output.WriteLine(p);
        Assert.Empty(problems);
    }

    [Fact]
    public void The_header_names_the_version_and_the_checksum_matches()
    {
        var file = new ArkFile(ArkFixtures.Features);
        Assert.Equal("13.0.1.0", file.Version);
        Assert.True(file.ChecksumMatches);
        Assert.Empty(file.Issues);
        Assert.Contains(file.Classes, c => c.Name == "features" && c.Fields.Any(f => f.Name == "moduleRecordIdx"));
    }
}

/// <summary>analyze_js on Ark bytecode: a bare .abc and the one inside a HarmonyOS module.</summary>
public sealed class ArkToolTests(ITestOutputHelper output)
{
    [Fact]
    public void Analyze_js_reads_an_abc_file_and_the_one_in_a_module()
    {
        var tools = new WebTools(new OutputPager(new ServerOptions()));
        string abc = ArkFixtures.Path("features.abc");
        string Run(string path, string view, string? query = null) => tools.AnalyzeJs(path, view, query: query);
        Assert.StartsWith("features.abc: Ark bytecode version 13.0.1.0, 5 classes, 15 methods (15 with code)", Run(abc, "summary"), StringComparison.Ordinal);
        Assert.Contains("#9 features.#~@0=#Ledger  4 args", Run(abc, "functions", "Ledger"), StringComparison.Ordinal);
        var listing = Run(abc, "disassemble", "classify");
        output.WriteLine(listing);
        Assert.Contains("lda.str \"zero\"", listing, StringComparison.Ordinal);
        Assert.Contains("strictnoteq 0x0, a3", listing, StringComparison.Ordinal);
        Assert.Contains("\"total\"  used by #4 features.#*#summary+0x", Run(abc, "search", "total"), StringComparison.Ordinal);
        Assert.Contains("method #7 features.#~@0>#total", Run(abc, "search", "total"), StringComparison.Ordinal);
        Assert.Contains("#8 features.func_main_0+0x", Run(abc, "xrefs", "#3"), StringComparison.Ordinal);
        Assert.Contains("#10 features.#*#loadTotals+0x", Run(abc, "xrefs", "next"), StringComparison.Ordinal);
        Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => Run(abc, "disassemble", "nothing")).Code);
        using var dir = new TempDir();
        var hap = dir.File("entry.hap");
        File.WriteAllBytes(hap, HarmonyPackageTests.StageModule(ArkFixtures.Features));
        Assert.StartsWith("entry.hap!ets/modules.abc: Ark bytecode version 13.0.1.0", Run(hap, "summary"), StringComparison.Ordinal);
    }

    [Fact]
    [FuzzEntry(typeof(ArkFile), typeof(HarmonyPackage), typeof(HarmonyFileView))]
    public void Fuzzed_bytecode_and_modules_never_throw_unexpectedly()
    {
        var seed = ArkFixtures.Features;
        var failures = FormatFuzz.Run(seed, b =>
        {
            ArkFile f;
            try { f = new ArkFile(b); }
            catch (InvalidDataException) { return; }
            foreach (var m in f.Classes.SelectMany(c => c.Methods))
            {
                if (m.Code is not { } at) continue;
                ArkCode code;
                try { code = f.Code(at); }
                catch (InvalidDataException) { continue; }
                foreach (var ins in ArkOpcodes.Decode(code.Instructions, out _)) ArkBundles.Text(f, m, ins, code.Arguments, code.Registers);
            }
            new HarmonyFileView().Inspect(new FileInput("x.abc", b, Blob.Identify(b)), default);
        }, 600);
        var hap = HarmonyPackageTests.StageModule(seed);
        failures.AddRange(FormatFuzz.Run(hap, b =>
        {
            try { _ = new HarmonyPackage(new MemoryStream(b), 1 << 20, (_, _) => { }); }
            catch (InvalidDataException) { }
            new HarmonyFileView().Inspect(new FileInput("x.hap", b, Blob.Identify(b)), default);
        }, 300));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
