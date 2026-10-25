using System.Text;
using Corvus.Core;
using Corvus.Native.Providers;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>GameMaker data files: chunk inventory, GEN8 header, code entries, strings, textures and audio, bytecode 14-17.</summary>
public sealed class GameMakerDataTests(ITestOutputHelper output)
{
    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Containers", "GameMakerFixtures", name);

    private static ContainerContents Open(byte[] data, string name = "data.win") => Containers.Open(data, name, AnalysisLimits.Default, default, allFiles: true);

    [Theory]
    [InlineData(14)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(17)]
    public void Each_bytecode_version_lists_code_strings_and_embedded_files(int bytecode)
    {
        var data = File.ReadAllBytes(Fixture($"bytecode-{bytecode}.win"));
        Assert.Equal("gamemaker data", Blob.Identify(data));
        var c = Open(data);
        Assert.Equal(GameMakerData.Kind, c.Kind);
        Assert.StartsWith($"GameMaker data file, bytecode version {bytecode}, declared version {(bytecode >= 17 ? 2 : 0)}.0.0.0: \"Ledger\" (\"Ledger Fixture\"), " +
                          "configuration \"Default\"; 3 code entries, 2 scripts, 1 objects, 1 rooms, 0 sprites, 0 sounds, ", c.Notes[0]);
        Assert.EndsWith("strings, 1 textures, 1 audio.", c.Notes[0]);
        Assert.StartsWith("Chunks: GEN8 (", c.Notes[1]);
        var code = c.Entries!.Where(e => e.Path.StartsWith("code/", StringComparison.Ordinal)).ToDictionary(e => e.Path[5..], e => e.Detail);
        Assert.Equal(["gml_Object_obj_counter_Create_0", "gml_Script_ledger_label", "gml_Script_ledger_total"], code.Keys.Order(StringComparer.Ordinal));
        // From bytecode 15 on, entries carry their argument and local counts: total, i and the compiler's arguments.
        if (bytecode >= 15) Assert.Equal("bytecode, 0 argument(s), 3 local(s)", code["gml_Script_ledger_total"]);
        var strings = Encoding.UTF8.GetString(Assert.Single(c.Items, i => i.Name == "strings.txt").Bytes).Split('\n');
        Assert.Contains("ledger: ", strings);
        Assert.Contains("obj_counter", strings);
        var page = Assert.Single(c.Items, i => i.Name == "textures/0.png").Bytes;
        // IHDR width and height, big-endian, at 16 and 20.
        Assert.Equal(new byte[] { 0, 0, 0, 4, 0, 0, 0, 4 }, page[16..24]);
        var sound = Assert.Single(c.Items, i => i.Name == "audio/0.wav").Bytes;
        Assert.Equal(844, sound.Length);
    }

    [Fact]
    public void A_data_file_with_an_empty_code_chunk_is_named_as_native_code()
    {
        var data = File.ReadAllBytes(Fixture("bytecode-16.win"));
        int code = IndexOf(data, "CODE"u8);
        // Shrink CODE to an empty chunk and give the freed bytes to a filler chunk, keeping every later offset.
        int size = BitConverter.ToInt32(data, code + 4);
        BitConverter.GetBytes(0).CopyTo(data, code + 4);
        "PADD"u8.CopyTo(data.AsSpan(code + 8));
        BitConverter.GetBytes(size - 8).CopyTo(data, code + 12);
        var c = Open(data);
        Assert.Contains("code compiled to native code (YYC), no bytecode", c.Notes[0]);
        Assert.DoesNotContain(c.Entries!, e => e.Path.StartsWith("code/", StringComparison.Ordinal));
    }

    [Fact]
    public void A_list_pointing_past_the_file_is_malformed_input()
    {
        var data = File.ReadAllBytes(Fixture("bytecode-16.win"));
        int strg = IndexOf(data, "STRG"u8);
        BitConverter.GetBytes(0x7FFF_FFF0).CopyTo(data, strg + 12);
        var e = Assert.Throws<ToolError>(() => Open(data));
        Assert.Equal(ErrorCode.MalformedInput, e.Code);
    }

    [Fact]
    [FuzzEntry(typeof(GameMakerData))]
    public void Fuzzed_data_files_never_throw_unexpectedly()
    {
        var failures = new List<string>();
        foreach (var seed in new[] { "bytecode-14.win", "bytecode-17.win" })
            failures.AddRange(FormatFuzz.Run(File.ReadAllBytes(Fixture(seed)), b => { try { Open(b); } catch (ToolError) { } }, 300));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    // The fixtures and each data file under CORVUS_GAMEMAKER_DATA (data.win, game.unx, game.ios, game.droid) are dumped by
    // UndertaleModCli: the code entry names, the string table and the texture page count are compared.
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_GAMEMAKER_TOOL")]
    public void Code_strings_and_textures_equal_what_the_data_file_cli_dumps()
    {
        var tool = ExternalTools.Locate(ExternalTools.GameMakerTool)!.Value.Path;
        var files = Enumerable.Range(14, 4).Select(v => Fixture($"bytecode-{v}.win")).ToList();
        if (Environment.GetEnvironmentVariable("CORVUS_GAMEMAKER_DATA") is { Length: > 0 } dir)
            files.AddRange(Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories)
                .Where(f => Path.GetExtension(f).ToLowerInvariant() is ".win" or ".unx" or ".ios" or ".droid").Order(StringComparer.Ordinal));
        var problems = new List<string>();
        int compared = 0, codeEntries = 0;
        foreach (var file in files)
        {
            using var temp = new TempDir();
            var run = ExternalTools.Run(tool, ExternalTools.Arguments(ExternalTools.GameMakerTool, "dump", ("file", file), ("output", temp.Path)), TimeSpan.FromMinutes(5), 1 << 24, default);
            string strings = Path.Combine(temp.Path, "strings.txt");
            if (run.ExitCode != 0 || !File.Exists(strings)) { problems.Add($"{file}: dump exit {run.ExitCode}: {run.Text[..Math.Min(400, run.Text.Length)]}"); continue; }
            var c = Open(File.ReadAllBytes(file), Path.GetFileName(file));
            string name = Path.GetFileName(file);
            var theirCode = Directory.Exists(Path.Combine(temp.Path, "CodeEntries"))
                ? Directory.GetFiles(Path.Combine(temp.Path, "CodeEntries"), "*.gml").Select(Path.GetFileNameWithoutExtension).Order(StringComparer.Ordinal).ToList() : [];
            var ourCode = c.Entries!.Where(e => e.Path.StartsWith("code/", StringComparison.Ordinal) && e.Detail?.StartsWith("function in ", StringComparison.Ordinal) != true)
                .Select(e => e.Path[5..]).Order(StringComparer.Ordinal).ToList();
            if (!theirCode.SequenceEqual(ourCode)) problems.Add($"{name}: code entries differ: {theirCode.Count} dumped, {ourCode.Count} listed");
            var theirStrings = File.ReadAllText(strings).Replace("\r\n", "\n").TrimEnd('\n');
            var ourStrings = Encoding.UTF8.GetString(c.Items.Single(i => i.Name == "strings.txt").Bytes);
            if (theirStrings != ourStrings) problems.Add($"{name}: string tables differ");
            int theirTextures = Directory.Exists(Path.Combine(temp.Path, "EmbeddedTextures")) ? Directory.GetFiles(Path.Combine(temp.Path, "EmbeddedTextures")).Length : 0;
            int ourTextures = c.Entries!.Count(e => e.Path.StartsWith("textures/", StringComparison.Ordinal) && e.Size > 0);
            if (theirTextures != ourTextures) problems.Add($"{name}: {theirTextures} texture pages dumped, {ourTextures} read");
            compared++;
            codeEntries += ourCode.Count;
        }
        output.WriteLine($"{compared} data files: {codeEntries} code entries, string tables and texture pages equal to the dump");
        foreach (var p in problems.Take(40)) output.WriteLine(p);
        Assert.Empty(problems);
    }

    private static int IndexOf(byte[] data, ReadOnlySpan<byte> tag)
    {
        int i = data.AsSpan().IndexOf(tag);
        Assert.True(i > 0);
        return i;
    }
}
