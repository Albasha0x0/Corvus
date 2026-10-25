using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Corvus.Core;
using Corvus.Core.AutoIt;
using Corvus.Native.Providers;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Compiled AutoIt scripts of ledger.au3 from Aut2Exe 3.2.4.9 (EA05) to 3.3.18.0 (EA06): records, script, files.</summary>
public sealed class AutoItScriptTests(ITestOutputHelper output)
{
    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Containers", "AutoItFixtures", name);

    private static ContainerContents Open(byte[] data, string name) => Containers.Open(data, name, AnalysisLimits.Default, default, allFiles: true);

    private static string Text(ContainerContents c, string item) => Encoding.UTF8.GetString(c.Items.Single(i => i.Name == item).Bytes);

    [Theory]
    [InlineData("3.2.6.0", "- 1")]
    [InlineData("3.3.14.5", "+ -1")]
    [InlineData("3.3.18.0", "+ -1")]
    public void An_ea06_script_is_rebuilt_from_its_tokens_with_its_installed_file(string version, string minusOne)
    {
        var data = File.ReadAllBytes(Fixture($"ledger-{version}.a3x"));
        Assert.Equal("autoit script", Blob.Identify(data));
        var c = Open(data, "ledger.a3x");
        Assert.StartsWith("AutoIt compiled script (EA06, AutoIt 3.2.6 or later) at 0x0: ", c.Notes[0]);
        Assert.EndsWith("1 FileInstall file(s); the script is rebuilt from tokens, without its comments and layout.", c.Notes[0]);
        string script = Text(c, "script.au3");
        // User names keep the compiler's upper case; built-in names take the vendor's spelling.
        Assert.Contains($"Func TOTAL(ByRef $ALIST)\r\n\tLocal $FSUM = 0\r\n\tFor $I = 0 To UBound($ALIST) {minusOne}\r\n\t\t$FSUM += $ALIST[$I][0]\r\n\tNext\r\n", script);
        Assert.Contains("Switch UBound($AENTRIES)\r\n\tCase 0\r\n\t\t$SREPORT &= \"no entries\"\r\n", script);
        Assert.Contains("@AutoItVersion & \" 'quoted' \"\"double\"\"\" & @CRLF)", script);
        Assert.Contains("[12.5, \"paper\"]", script);
        Assert.Equal("Shipping notes for the ledger sample.", Text(c, "files/notes.txt").TrimEnd());
        Assert.Contains(c.Entries!, e => e.Path == "files/notes.txt" && e.Detail!.Contains("stored as K:\\notes.txt", StringComparison.Ordinal));
    }

    [Fact]
    public void An_ea05_script_keeps_its_source_text()
    {
        var c = Open(File.ReadAllBytes(Fixture("ledger-3.2.4.9.a3x")), "ledger.a3x");
        Assert.StartsWith("AutoIt compiled script (EA05, AutoIt 3.2.4 or earlier) at 0x0: 2 record(s), 1 FileInstall file(s).", c.Notes[0]);
        string script = Text(c, "script.au3");
        Assert.Contains("; <AUT2EXE VERSION: 3.2.4.9>", script);
        Assert.Contains("For $i = 0 To UBound($aList) - 1", script);
        Assert.Equal("Shipping notes for the ledger sample.", Text(c, "files/notes.txt").TrimEnd());
    }

    [Fact]
    public void A_script_inside_an_executable_is_found_after_the_interpreter()
    {
        // The interpreter's own copy of the marker is not followed by AU3!EA0x; only the script data's is.
        var script = File.ReadAllBytes(Fixture("ledger-3.3.18.0.a3x"));
        var host = new byte[0x3000];
        "MZ"u8.CopyTo(host);
        new byte[] { 0xA3, 0x48, 0x4B, 0xBE, 0x98, 0x6C, 0x4A, 0xA9, 0x99, 0x4C, 0x53, 0x0A, 0x86, 0xD6, 0x48, 0x7D, 1, 1, 1, 1 }.CopyTo(host, 0x400);
        script.CopyTo(host, 0x1000);
        Assert.Equal(0x1000, AutoItScript.Find(host));
        var (layout, records) = AutoItScript.Read(host, 0x1000, 1 << 20);
        Assert.Equal("EA06", layout);
        Assert.Equal([">>>AUTOIT NO CMDEXECUTE<<<", ">>>AUTOIT SCRIPT<<<", "notes.txt"], records.Select(r => r.Type));
    }

    [Fact]
    public void A_damaged_record_fails_its_checksum_as_malformed_input()
    {
        var data = File.ReadAllBytes(Fixture("ledger-3.3.18.0.a3x"));
        // The installed file's stored data ends before the 16-byte trailer.
        data[^20] ^= 0xFF;
        Assert.Equal(ErrorCode.MalformedInput, Assert.Throws<ToolError>(() => Open(data, "x.a3x")).Code);
    }

    [Fact]
    [FuzzEntry(typeof(AutoItScript))]
    public void Fuzzed_scripts_never_throw_past_a_tool_error()
    {
        var failures = new List<string>();
        foreach (var seed in new[] { "ledger-3.2.4.9.a3x", "ledger-3.3.18.0.a3x" })
            failures.AddRange(FormatFuzz.Run(File.ReadAllBytes(Fixture(seed)), b => { try { Open(b, seed); } catch (ToolError) { } }, 400));
        // The token reader is reached only past the checksum, so it is fuzzed on its own.
        var tokens = AutoItScript.Read(File.ReadAllBytes(Fixture("ledger-3.3.18.0.a3x")), 0, 1 << 20).Records.Single(r => r.Type == ">>>AUTOIT SCRIPT<<<").Data!;
        failures.AddRange(FormatFuzz.Run(tokens, b => AutoItScript.Render(AutoItScript.Detokenize(b).Lines), 400));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    // The fixtures, executables compiled from ledger.au3 by each release under CORVUS_AUTOIT_RELEASES (x86 and, from
    // 3.2.10, x64), and each file under CORVUS_AUTOIT_SCRIPTS are read by AutoIt-Ripper (CORVUS_AUTOIT_REFERENCE).
    // Compared: each installed file by name and SHA-256; a source script by text; a token script line by line and token
    // by token, with the reference's unsigned integers read as signed and its spacing ignored.
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_AUTOIT_REFERENCE")]
    public void Scripts_and_installed_files_equal_the_reference_extraction()
    {
        string reference = RealData.Path("CORVUS_AUTOIT_REFERENCE");
        var files = Directory.GetFiles(Path.GetDirectoryName(Fixture("x"))!, "*.a3x").Order(StringComparer.Ordinal).ToList();
        string? built = null;
        if (Environment.GetEnvironmentVariable("CORVUS_AUTOIT_RELEASES") is { Length: > 0 } releases)
        {
            built = Path.Combine(Path.GetTempPath(), "corvus-autoit-" + Guid.NewGuid().ToString("n"));
            Directory.CreateDirectory(built);
            var versions = Directory.GetDirectories(releases, "autoit-*").Select(d => Path.GetFileName(d)["autoit-".Length..]).Where(v => Version.TryParse(v, out _)).ToArray();
            var run = ExternalTools.Run(BundleTests.FindOnPath(OperatingSystem.IsWindows() ? "pwsh.exe" : "pwsh")!, ["-NoProfile", "-File", Fixture("build.ps1"), "-Executables", "-Out", built, "-Versions", string.Join(',', versions)],
                TimeSpan.FromMinutes(10), 1 << 20, default, new Dictionary<string, string?> { ["CORVUS_AUTOIT_RELEASES"] = releases });
            Assert.True(run.ExitCode == 0, run.Text + run.Stderr + run.StartError);
            files.AddRange(Directory.GetFiles(built).Order(StringComparer.Ordinal));
        }
        if (Environment.GetEnvironmentVariable("CORVUS_AUTOIT_SCRIPTS") is { Length: > 0 } dir)
            files.AddRange(Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal));
        string python = BundleTests.FindOnPath(OperatingSystem.IsWindows() ? "python.exe" : "python3") ?? throw new InvalidOperationException("python is not on PATH");
        var problems = new List<string>();
        int scripts = 0, lines = 0, installed = 0;
        try
        {
            foreach (var file in files)
            {
                var data = File.ReadAllBytes(file);
                int at = AutoItScript.Find(data);
                if (at < 0) continue;
                string name = Path.GetFileName(file);
                var run = ExternalTools.Run(python, ["-I", Fixture("reference.py"), reference, file], TimeSpan.FromMinutes(2), 1 << 26, default);
                var theirs = JsonSerializer.Deserialize<List<List<string?>>>(run.Text) ?? [];
                var (_, records) = AutoItScript.Read(data, at, 1 << 28);
                scripts++;
                foreach (var r in records.Where(r => r.Data != null))
                {
                    if (r.Type is ">>>AUTOIT SCRIPT<<<" or ">AUTOIT UNICODE SCRIPT<" or ">AUTOIT SCRIPT<")
                    {
                        var their = theirs.FirstOrDefault(t => t[0] == "script.au3");
                        if (their == null) { problems.Add($"{name}: the reference recovers no script"); continue; }
                        if (r.Type == ">>>AUTOIT SCRIPT<<<")
                        {
                            var ours = AutoItScript.Detokenize(r.Data!);
                            if (ours.Problem != null) problems.Add($"{name}: {ours.Problem}");
                            var refLines = their[2]!.Split("\r\n").Where(l => l.Length > 0).Select(ReferenceTokens).ToList();
                            lines += ours.Lines.Count;
                            if (refLines.Count != ours.Lines.Count) problems.Add($"{name}: {ours.Lines.Count} lines, the reference {refLines.Count}");
                            for (int i = 0; i < Math.Min(refLines.Count, ours.Lines.Count); i++)
                                if (!refLines[i].SequenceEqual(ours.Lines[i], TokenComparer.Instance)) { problems.Add($"{name}: line {i + 1}: reference [{string.Join(' ', refLines[i])}], Corvus [{string.Join(' ', ours.Lines[i])}]"); break; }
                        }
                        else
                        {
                            string text = r.Type == ">AUTOIT UNICODE SCRIPT<" ? Encoding.Unicode.GetString(r.Data!).TrimStart('\uFEFF') : Encoding.Latin1.GetString(r.Data!);
                            if (text != their[2]) problems.Add($"{name}: the source script differs from the reference");
                        }
                        continue;
                    }
                    installed++;
                    string hash = Convert.ToHexStringLower(SHA256.HashData(r.Data!));
                    if (!theirs.Any(t => t[0] == r.Type && t[1] == hash)) problems.Add($"{name}: installed file {r.Type} differs from the reference");
                }
            }
        }
        finally { if (built != null) Directory.Delete(built, true); }
        output.WriteLine($"{scripts} compiled scripts: {lines} token lines and {installed} installed files equal to the reference");
        foreach (var p in problems.Take(40)) output.WriteLine(p);
        Assert.Empty(problems);
        Assert.True(scripts > 0);
    }

    // The reference joins tokens with spaces; a string token is quoted with doubled quotes inside.
    private static List<string> ReferenceTokens(string line)
    {
        var tokens = new List<string>();
        var s = line.Trim();
        for (int i = 0; i < s.Length;)
        {
            if (s[i] == ' ') { i++; continue; }
            int start = i;
            if (s[i] == '"')
            {
                for (i++; i < s.Length; i++)
                    if (s[i] == '"') { if (i + 1 < s.Length && s[i + 1] == '"') i++; else { i++; break; } }
            }
            else while (i < s.Length && s[i] != ' ') i++;
            tokens.Add(s[start..i]);
        }
        return tokens;
    }

    // Names compare without case (the two keep different spelling tables); numbers by value, the reference's integers
    // being unsigned.
    private sealed class TokenComparer : IEqualityComparer<string>
    {
        public static readonly TokenComparer Instance = new();

        public bool Equals(string? theirs, string? ours)
        {
            if (theirs == null || ours == null) return theirs == ours;
            if (theirs.StartsWith('"')) return theirs == ours;
            if (ulong.TryParse(theirs, out var u) && long.TryParse(ours, out var l))
                return u == (ulong)l || (u <= uint.MaxValue && l is >= int.MinValue and < 0 && u == (uint)(int)l);
            if (double.TryParse(theirs, System.Globalization.CultureInfo.InvariantCulture, out var a) && double.TryParse(ours, System.Globalization.CultureInfo.InvariantCulture, out var b)) return a == b;
            return string.Equals(theirs, ours, StringComparison.OrdinalIgnoreCase);
        }

        public int GetHashCode(string s) => 0;
    }
}
