using System.Buffers.Binary;
using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Modules saved from a running test program, compared with their files.</summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
[Permit("live")]
public sealed class LiveSaveModulesRealTests(ITestOutputHelper output) : LiveToolCalls(output), IDisposable
{
    private const uint ExecuteSection = 0x20000000;

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [LiveTargetFact("win-x64")]
    public async Task Modules_saved_from_a_running_program_match_their_files()
    {
        var target = LiveTarget.WinX64;
        var exe = target.Build(_dir, "orders", LivePrograms.Orders);
        await using var server = await Server();

        var pid = await Spawn(server, exe, "live-1", "400", "20");
        // The stop point lets the loader finish, so every module is mapped when
        // they are saved.
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "AddLine" });
        var stop = await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 60 });
        Assert.Contains("stopped at s1", stop);

        // A stop point patches the code it sits on; clear it so the image holds
        // the program's own bytes.
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "clear", ["stopPoint"] = "s1" });
        var saved = _dir.File("saved");
        var report = await Ok(server, "live_session", new()
        {
            ["action"] = "save_modules", ["session"] = "live-1", ["outputPath"] = saved, ["modules"] = "all", ["base"] = "preferred",
        });
        Assert.DoesNotContain(" failed:", report);

        var rows = Regex.Matches(report, @"^  (?<name>[^:\r\n]+): (?<file>[^\r\n(]+?) \((?<read>\d+)% read", RegexOptions.Multiline);
        Assert.NotEmpty(rows);
        var compared = new List<string>();
        foreach (Match row in rows)
        {
            var name = row.Groups["name"].Value;
            var rebuilt = Path.Combine(saved, row.Groups["file"].Value);
            // The program is its own build; system modules come from the system
            // folder.
            var original = name.Equals(target.Exe("orders"), StringComparison.OrdinalIgnoreCase) ? exe : Path.Combine(Environment.SystemDirectory, name);
            if (!File.Exists(original) || !File.Exists(rebuilt) || !SameBuild(File.ReadAllBytes(original), File.ReadAllBytes(rebuilt))) continue;
            compared.Add(name);
            var differences = CodeDifferences(File.ReadAllBytes(rebuilt), File.ReadAllBytes(original));
            if (differences.Count > 0) Assert.True(differences.Count == 0, $"{name}: code differs from its file at {string.Join(", ", differences)}");
            if (name.Equals(target.Exe("orders"), StringComparison.OrdinalIgnoreCase))
            {
                var fromFile = await Functions(server, original);
                var fromImage = await Functions(server, rebuilt);
                Assert.NotEmpty(fromFile);
                Assert.Equal(fromFile, fromImage);
            }
        }
        Assert.Contains(target.Exe("orders"), compared);
        Assert.True(compared.Count > 1, $"only {string.Join(", ", compared)} had a file to compare");

        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
        await UntilExited(server, "live-1");
        await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
        Ended(pid);
    }

    private async Task<string> Functions(InProcessServer server, string path)
    {
        var rows = new List<string>();
        for (int offset = 0; ;)
        {
            var text = await Ok(server, "list_functions", new() { ["image"] = path, ["engine"] = "ours", ["offset"] = offset }, log: false);
            // The first line names the file; notices and page markers are not
            // rows.
            rows.AddRange(text.Split('\n').Skip(1).Select(l => l.TrimEnd()).Where(l => l.Length > 0 && !l.StartsWith('[')));
            var more = Regex.Match(text, @"\[More: offset=(\d+)\]");
            if (!more.Success) return string.Join("\n", rows);
            offset = int.Parse(more.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
        }
    }

    // A module loaded from another folder has the same name but its own build.
    // The saved image may append sections, so its size is not below the file's.
    private static bool SameBuild(byte[] file, byte[] saved)
    {
        int x = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(0x3C)), y = BinaryPrimitives.ReadInt32LittleEndian(saved.AsSpan(0x3C));
        return file.AsSpan(x + 8, 4).SequenceEqual(saved.AsSpan(y + 8, 4))
            && BinaryPrimitives.ReadUInt32LittleEndian(saved.AsSpan(y + 80)) >= BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(x + 80));
    }

    /// <summary>
    /// The rvas where an executable section of <paramref name="saved"/> differs from <paramref name="file"/> other than
    /// a jump the session's agent wrote over a function entry and the nops that pad the displaced instructions; empty
    /// when the code matches.
    /// </summary>
    private static List<string> CodeDifferences(byte[] saved, byte[] file)
    {
        var y = Executable(file);
        // The saved image may mark more sections executable or append some;
        // each executable section of the file must be there at its address.
        var x = Executable(saved).Where(s => y.Any(t => t.Rva == s.Rva)).ToList();
        var found = new List<string>();
        if (y.Count == 0 || x.Count != y.Count) return ["sections differ"];
        uint imageSize = BinaryPrimitives.ReadUInt32LittleEndian(saved.AsSpan(BinaryPrimitives.ReadInt32LittleEndian(saved.AsSpan(0x3C)) + 80));
        for (int i = 0; i < x.Count; i++)
        {
            if (x[i].Rva != y[i].Rva) return ["section addresses differ"];
            int length = Math.Min(x[i].Size, y[i].Size);
            if (x[i].At + length > saved.Length || y[i].At + length > file.Length) return ["section is cut short"];
            for (int k = 0; k < length; k++)
            {
                if (saved[x[i].At + k] == file[y[i].At + k]) continue;
                // The agent's jump: E9 and a displacement that leaves the
                // image, padded with filler.
                if (saved[x[i].At + k] == 0xE9 && k + 5 <= length && (uint)(x[i].Rva + k + 5 + BinaryPrimitives.ReadInt32LittleEndian(saved.AsSpan(x[i].At + k + 1))) >= imageSize)
                {
                    k += 4;
                    while (k + 1 < length && saved[x[i].At + k + 1] != file[y[i].At + k + 1])
                    {
                        int pad = saved[x[i].At + k + 1] == 0xCC ? 1 : NopLength(saved.AsSpan(x[i].At + k + 1, Math.Min(8, length - k - 1)));
                        if (pad == 0) break;
                        k += pad;
                    }
                    continue;
                }
                found.Add($"0x{x[i].Rva + k:X} {file[y[i].At + k]:X2}>{saved[x[i].At + k]:X2}");
                if (found.Count == 8) return found;
            }
        }
        return found;
    }

    // The length of the nop at the start of the code, or 0: [66] 90, or 0F 1F
    // with a modrm operand.
    private static int NopLength(ReadOnlySpan<byte> code)
    {
        int p = 0;
        while (p < code.Length && code[p] == 0x66) p++;
        if (p < code.Length && code[p] == 0x90) return p + 1;
        if (p + 3 > code.Length || code[p] != 0x0F || code[p + 1] != 0x1F) return 0;
        byte modrm = code[p + 2];
        int length = p + 3, mod = modrm >> 6;
        if (modrm >> 6 != 3 && (modrm & 7) == 4) length++;
        length += mod == 1 ? 1 : mod == 2 ? 4 : 0;
        return length <= code.Length ? length : 0;
    }

    private static List<(uint Rva, int At, int Size)> Executable(byte[] image)
    {
        var sections = new List<(uint, int, int)>();
        int pe = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(0x3C));
        int count = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(pe + 6));
        int table = pe + 24 + BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(pe + 20));
        for (int i = 0; i < count; i++)
        {
            var h = image.AsSpan(table + i * 40, 40);
            if ((BinaryPrimitives.ReadUInt32LittleEndian(h[36..]) & ExecuteSection) == 0) continue;
            sections.Add((BinaryPrimitives.ReadUInt32LittleEndian(h[12..]), (int)BinaryPrimitives.ReadUInt32LittleEndian(h[20..]), (int)BinaryPrimitives.ReadUInt32LittleEndian(h[16..])));
        }
        return sections;
    }
}
