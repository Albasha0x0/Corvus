using System.Text;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Core.Lua;
using Corvus.Native.Providers;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Lua 5.1-5.4 chunks and LuaJIT 2.0 / 2.1 dumps of ledger.lua: functions, instructions, constants, stripping.</summary>
public sealed class LuaBytecodeTests(ITestOutputHelper output)
{
    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Containers", "LuaFixtures", name);

    private static ContainerContents Open(byte[] data, string name) => Containers.Open(data, name, AnalysisLimits.Default, default, allFiles: true);

    [Theory]
    [InlineData("lua5.1.luac", "Lua 5.1", "lua bytecode")]
    [InlineData("lua5.2.luac", "Lua 5.2", "lua bytecode")]
    [InlineData("lua5.3.luac", "Lua 5.3", "lua bytecode")]
    [InlineData("lua5.4.luac", "Lua 5.4", "lua bytecode")]
    [InlineData("luajit2.0.ljbc", "LuaJIT 2.0", "luajit bytecode")]
    [InlineData("luajit2.1.ljbc", "LuaJIT 2.1", "luajit bytecode")]
    public void Each_version_lists_the_five_functions_and_their_constants(string fixture, string version, string kind)
    {
        var data = File.ReadAllBytes(Fixture(fixture));
        Assert.Equal(kind, Blob.Identify(data));
        var c = Open(data, fixture);
        Assert.StartsWith($"{version} bytecode (", c.Notes[0]);
        Assert.Contains(": 5 function(s), ", c.Notes[0]);
        Assert.EndsWith("; source ledger.lua.", c.Notes[0]);
        // main and Ledger.new, Ledger:add, Ledger:total and label, each named with its source lines.
        Assert.Equal(5, c.Entries!.Count);
        Assert.Contains(c.Entries, e => e.Path.EndsWith("function ledger.lua:5-7", StringComparison.Ordinal));
        var strings = Encoding.UTF8.GetString(c.Items.Single(i => i.Name == "strings.txt").Bytes).Split('\n');
        Assert.Contains("%s: %.2f (%d extra)", strings);
        Assert.Contains("cash", strings);
        Assert.Contains("\"setmetatable\"", Encoding.UTF8.GetString(c.Items.Single(i => i.Name == "listing.txt").Bytes));
    }

    [Theory]
    [InlineData("lua5.1-stripped.luac")]
    [InlineData("lua5.4-stripped.luac")]
    [InlineData("luajit2.1-stripped.ljbc")]
    public void A_stripped_chunk_is_named_stripped_and_keeps_its_code(string fixture)
    {
        var c = Open(File.ReadAllBytes(Fixture(fixture)), fixture);
        Assert.EndsWith("; debug information stripped (no source names, lines or locals).", c.Notes[0]);
        Assert.Equal(5, c.Entries!.Count);
    }

    [Fact]
    public void A_count_past_the_chunk_is_malformed_input()
    {
        var data = File.ReadAllBytes(Fixture("lua5.3.luac"));
        // The main function's code count follows its source name, two line numbers and three bytes.
        int at = Array.IndexOf(data, (byte)'@') + "@ledger.lua".Length + 4 + 4 + 3;
        BitConverter.GetBytes(0x0FFF_FFFF).CopyTo(data, at);
        Assert.Equal(ErrorCode.MalformedInput, Assert.Throws<ToolError>(() => Open(data, "x.luac")).Code);
    }

    [Fact]
    [FuzzEntry(typeof(LuaBytecode))]
    [FuzzEntry(typeof(LuaJitBytecode))]
    [FuzzEntry(typeof(LuaContents))]
    public void Fuzzed_chunks_never_throw_past_a_tool_error()
    {
        var failures = new List<string>();
        foreach (var seed in new[] { "lua5.1.luac", "lua5.4.luac", "luajit2.1.ljbc" })
            failures.AddRange(FormatFuzz.Run(File.ReadAllBytes(Fixture(seed)), b => { try { Open(b, seed); } catch (ToolError) { } }, 400));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    // The fixtures and each chunk under CORVUS_LUA_CHUNKS are listed by the luac of their version (luac -l -l) or by luajit
    // -bl. Compared per function: luac's two header lines, each instruction's opcode and line, and the constants; for
    // LuaJIT the prototype's name and line range and each opcode.
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_LUA_TOOLS")]
    public void Functions_instructions_and_constants_equal_the_reference_listings()
    {
        string tools = RealData.Path("CORVUS_LUA_TOOLS");
        var files = Directory.GetFiles(Path.GetDirectoryName(Fixture("x"))!).Where(f => f.EndsWith(".luac", StringComparison.Ordinal) || f.EndsWith(".ljbc", StringComparison.Ordinal)).Order(StringComparer.Ordinal).ToList();
        if (Environment.GetEnvironmentVariable("CORVUS_LUA_CHUNKS") is { Length: > 0 } dir)
            files.AddRange(Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal));
        var problems = new List<string>();
        int chunks = 0, functions = 0, instructions = 0;
        foreach (var file in files)
        {
            var data = File.ReadAllBytes(file);
            string name = Path.GetFileName(file);
            List<string> theirs, ours;
            if (LuaBytecode.Looks(data))
            {
                var chunk = LuaBytecode.Read(data);
                string folder = Directory.GetDirectories(tools, $"lua-{chunk.Version}.*").Single();
                var run = ExternalTools.Run(Tool(Path.Combine(folder, "src"), "luac"), ["-l", "-l", "-p", file], TimeSpan.FromMinutes(2), 1 << 26, default);
                theirs = LuacLines(run.Text);
                var all = new List<LuaFunction>();
                void Walk(LuaFunction f) { all.Add(f); foreach (var c in f.Children) Walk(c); }
                Walk(chunk.Main);
                ours = all.SelectMany(f => OurLines(chunk, f)).ToList();
                functions += all.Count;
                instructions += all.Sum(f => f.Code.Length);
            }
            else if (LuaJitBytecode.Looks(data))
            {
                var (chunk, protos) = LuaJitBytecode.Read(data);
                string src = Path.Combine(tools, chunk.Version == "LuaJIT 2.0" ? "luajit-2.0" : "luajit-2.1", "src");
                var run = ExternalTools.Run(Tool(src, "luajit"), ["-bl", file], TimeSpan.FromMinutes(2), 1 << 26, default, workingDirectory: src);
                theirs = run.Text.Replace("\r", "").Split('\n').Select(JitLine).Where(l => l != null).Select(l => l!).ToList();
                ours = protos.SelectMany(f => new[] { $"-- {(chunk.Stripped ? "" : LuaContents.Display(f.Source))}:{f.Line}-{f.LastLine}" }
                    .Concat(f.Code.Select(i => LuaJitBytecode.OpcodeName(chunk.Version, i)))).ToList();
                // A stripped dump names no chunk; luajit shows the file name instead.
                if (chunk.Stripped) theirs = theirs.Select(l => l.StartsWith("-- ", StringComparison.Ordinal) ? "-- " + l[(l.LastIndexOf(':') - 0)..].TrimStart() : l).ToList();
                if (chunk.Stripped) ours = ours.Select(l => l.StartsWith("-- ", StringComparison.Ordinal) ? "-- " + l[l.LastIndexOf(':')..] : l).ToList();
                functions += protos.Count;
                instructions += protos.Sum(f => f.Code.Length);
            }
            else continue;
            chunks++;
            int first = Enumerable.Range(0, Math.Min(theirs.Count, ours.Count)).FirstOrDefault(i => theirs[i] != ours[i], -1);
            if (first >= 0 || theirs.Count != ours.Count)
            {
                int at = first >= 0 ? first : Math.Min(theirs.Count, ours.Count);
                problems.Add($"{name}: line {at}: reference [{theirs.ElementAtOrDefault(at)}], Corvus [{ours.ElementAtOrDefault(at)}] ({theirs.Count} vs {ours.Count} lines)");
            }
        }
        output.WriteLine($"{chunks} chunks: {functions} functions, {instructions} instructions equal to the reference listings");
        foreach (var p in problems.Take(40)) output.WriteLine(p);
        Assert.Empty(problems);
        Assert.True(chunks > 0);
    }

    private static string Tool(string folder, string name) =>
        Directory.GetFiles(folder, name + "*").First(f => Path.GetFileNameWithoutExtension(f) == name && Path.GetExtension(f) is ".exe" or "");

    // luac -l -l: header lines without the address, then per instruction "line OPCODE", then each constant's value.
    private static List<string> LuacLines(string text)
    {
        var lines = new List<string>();
        string section = "";
        foreach (var raw in text.Replace("\r", "").Split('\n'))
        {
            var m = Regex.Match(raw, @"^((?:main|function) <.*>) \((\d+ instructions?)(?:, \d+ bytes)? at [0-9A-Fa-fx]+\)$");
            if (m.Success) { lines.Add($"{m.Groups[1].Value} ({m.Groups[2].Value})"); section = "head"; continue; }
            if (section == "head") { lines.Add(raw); section = "code"; continue; }
            if (raw.StartsWith("constants (", StringComparison.Ordinal)) { section = "k"; continue; }
            if (raw.StartsWith("locals (", StringComparison.Ordinal) || raw.StartsWith("upvalues (", StringComparison.Ordinal)) { section = ""; continue; }
            var cols = raw.Split('\t');
            if (section == "code" && cols.Length >= 4 && cols[0] == "")
                lines.Add($"{cols[2].Trim('[', ']')} {cols[3].Trim()}");
            else if (section == "k" && cols.Length >= 3 && cols[0] == "")
                // 5.4 adds a type column before the value; earlier versions number from 1.
                lines.Add("k " + (cols.Length >= 4 ? string.Join('\t', cols[3..]) : string.Join('\t', cols[2..])));
        }
        return lines;
    }

    private static IEnumerable<string> OurLines(LuaChunk chunk, LuaFunction f)
    {
        yield return LuaContents.Header(chunk, f);
        yield return LuaContents.Counts(f, false);
        var ops = LuaBytecode.Opcodes(chunk.Version);
        int mask = chunk.Version == "5.4" ? 0x7F : 0x3F;
        for (int pc = 0; pc < f.Code.Length; pc++)
            yield return $"{(f.Lines != null && pc < f.Lines.Length ? f.Lines[pc].ToString() : "-")} {ops[f.Code[pc] & mask].Name}";
        foreach (var k in f.Constants) yield return "k " + k.Text;
    }

    // luajit -bl: "-- BYTECODE -- name:first-last" and "0001    OPCODE ..." (a "=>" marks a jump target).
    private static string? JitLine(string raw)
    {
        if (raw.StartsWith("-- BYTECODE -- ", StringComparison.Ordinal)) return "-- " + raw["-- BYTECODE -- ".Length..];
        var m = Regex.Match(raw, @"^\d{4} (?:=>| {2}) ?(\w+)");
        return m.Success ? m.Groups[1].Value : null;
    }
}
