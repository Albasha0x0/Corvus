using System.IO.Compression;
using Corvus.Core;
using Corvus.Native.Providers;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// Real firmware images opened level by level; every filesystem level found inside (squashfs, UBI, UBIFS, JFFS2, ext, FAT,
/// cramfs, cpio, FIT) is listed and extracted by its reference tool too (FirmwareFixtures/reference.sh) and compared file by
/// file: path, size, SHA-256, link target and mode; each dynamically linked ELF program inside opens at its architecture and
/// lists its imports. Opt-in: CORVUS_FIRMWARE_IMAGES names a folder of images (.gz ones are
/// ungzipped first) and CORVUS_FS_REFERENCE the program that runs the script as root: sh on Linux, wsl.exe on Windows.
/// </summary>
public sealed class FirmwareComparisonTests(ITestOutputHelper output)
{
    /// <summary>Reader kinds and the script's format names.</summary>
    private static readonly Dictionary<string, string> Formats = new(StringComparer.Ordinal)
    {
        ["squashfs"] = "squashfs", ["UBI"] = "ubi", ["UBIFS"] = "ubifs", ["jffs2"] = "jffs2", ["ext2"] = "ext", ["ext3"] = "ext", ["ext4"] = "ext",
        ["FAT12"] = "fat", ["FAT16"] = "fat", ["FAT32"] = "fat",
        ["cramfs"] = "cramfs", ["cpio"] = "cpio", ["FIT"] = "fit",
    };

    private static readonly AnalysisLimits Limits = new() { MaxItems = 200_000 };

    /// <summary>One file or link: size, SHA-256 (files), target (links), permission bits when known.</summary>
    private sealed record Row(long Size, string? Sha, string? Target, string? Mode);

    [Fact]
    public void Real_firmware_filesystems_match_their_reference_tools()
    {
        if (Environment.GetEnvironmentVariable("CORVUS_FIRMWARE_IMAGES") is not { Length: > 0 } root || !Directory.Exists(root)
            || Environment.GetEnvironmentVariable("CORVUS_FS_REFERENCE") is not { Length: > 0 } runner) return;
        var script = Path.Combine(FirmwareFilesystemTests.FixtureDir, "reference.sh");
        long rows = 0, agreed = 0;
        var programs = new SortedDictionary<string, (int Linked, int WithImports)>(StringComparer.Ordinal);
        var failures = new List<string>();
        foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
        {
            var data = File.ReadAllBytes(file);
            if (file.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)) data = Gunzip(data);
            int levels = 0;
            string? top = null;
            Walk(data, Path.GetFileName(file), Path.GetFileName(file), 0);
            if (levels == 0) output.WriteLine($"{Path.GetFileName(file)}: no filesystem level (read as {top})");

            void Walk(byte[] bytes, string name, string where, int depth)
            {
                if (depth > 6) return;
                ContainerContents c;
                try { c = Containers.Open(bytes, name, Limits, default, allFiles: true); }
                catch (ToolError ex) { output.WriteLine($"{where}: {ex.Message}"); return; }
                top ??= c.Kind;
                if (Formats.TryGetValue(c.Kind, out var format))
                {
                    levels++;
                    var (total, same, differences) = Compare(runner, script, format, bytes, c);
                    rows += total;
                    agreed += same;
                    var line = $"{where} ({c.Kind}): {same:N0} of {total:N0} agree" + (differences.Count > 0 ? "\n    " + string.Join("\n    ", differences.Take(12)) : "");
                    output.WriteLine(line);
                    if (same < total) failures.Add(line);
                    // a filesystem's files are not opened further, the volumes of UBI and the images of a FIT are
                    if (format is not ("ubi" or "fit"))
                    {
                        Programs(c, where, programs, failures);
                        return;
                    }
                }
                foreach (var item in c.Items) Walk(item.Bytes, item.Name, $"{where} > {item.Name}", depth + 1);
            }
        }
        output.WriteLine($"agreement: {agreed:N0} of {rows:N0} rows ({(rows == 0 ? 0 : 100.0 * agreed / rows):F2} %)");
        foreach (var (machine, (linked, withImports)) in programs) output.WriteLine($"programs {machine}: {withImports:N0} of {linked:N0} dynamically linked ones list imports");
        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    /// <summary>Each ELF program of a filesystem opens at its architecture; one linked to libraries lists its imports.</summary>
    private static void Programs(ContainerContents c, string where, SortedDictionary<string, (int Linked, int WithImports)> programs, List<string> failures)
    {
        foreach (var item in c.Items.Where(i => Blob.Identify(i.Bytes) == "elf"))
        {
            var elf = Corvus.Native.Elf.ElfFile.FromBytes(item.Bytes, item.Name);
            if (elf.Dependencies.Count == 0) continue;
            var (linked, withImports) = programs.GetValueOrDefault(elf.MachineName);
            bool imports = elf.Imports.Count > 0;
            programs[elf.MachineName] = (linked + 1, withImports + (imports ? 1 : 0));
            if (!imports) failures.Add($"{where} > {item.Name}: {elf.MachineName}, linked to {string.Join(", ", elf.Dependencies)}, lists no imports");
        }
    }

    /// <summary>Our rows against the reference tool's, by path: the count compared, the count equal, and the differences.</summary>
    private (int Total, int Same, List<string> Differences) Compare(string runner, string script, string format, byte[] image, ContainerContents c)
    {
        using var work = new TempDir();
        var imagePath = work.File("image");
        File.WriteAllBytes(imagePath, image);
        bool wsl = Path.GetFileNameWithoutExtension(runner).Equals("wsl", StringComparison.OrdinalIgnoreCase);
        List<string> args = wsl ? ["-u", "root", "-e", "sh", LinuxPath(script), format, LinuxPath(imagePath)] : [script, format, imagePath];
        var run = ExternalTools.Run(runner, args, TimeSpan.FromMinutes(10), 256L << 20, default);
        Assert.True(run.StartError == null && !run.TimedOut && !run.Truncated && run.ExitCode == 0, $"reference {format}: {run.StartError ?? run.Stderr}");
        var reference = Reference(run.Text);
        var ours = Ours(c);
        var differences = new List<string>();
        int same = 0;
        foreach (var path in reference.Keys.Union(ours.Keys).Order(StringComparer.Ordinal))
        {
            var r = reference.GetValueOrDefault(path);
            var o = ours.GetValueOrDefault(path);
            if (r == null) differences.Add($"only ours: {path} {o}");
            else if (o == null) differences.Add($"only reference: {path} {r}");
            else if (r.Size != o.Size || r.Sha != o.Sha || r.Target != o.Target || o.Mode is { } mode && mode != r.Mode) differences.Add($"differs: {path} ours {o}, reference {r}");
            else same++;
        }
        return (reference.Keys.Union(ours.Keys).Count(), same, differences);
    }

    /// <summary>The script's f and l lines by path (directories are left out: the readers list files and links).</summary>
    private static Dictionary<string, Row> Reference(string text)
    {
        var rows = new Dictionary<string, Row>(StringComparer.Ordinal);
        foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var f = line.Split(' ', 5);
            if (f.Length < 5 || f[0] is not ("f" or "l")) continue;
            if (f[0] == "f") rows[f[4]] = new Row(long.Parse(f[2]), f[3], null, f[1]);
            else if (f[4].IndexOf(" -> ", StringComparison.Ordinal) is var arrow and > 0) rows[f[4][..arrow]] = new Row(long.Parse(f[2]), null, f[4][(arrow + 4)..], f[1]);
        }
        return rows;
    }

    private static Dictionary<string, Row> Ours(ContainerContents c)
    {
        var bytes = c.Items.GroupBy(i => i.Name).ToDictionary(g => g.Key, g => g.First().Bytes, StringComparer.Ordinal);
        var rows = new Dictionary<string, Row>(StringComparer.Ordinal);
        foreach (var e in c.Entries ?? [])
            rows[e.Path] = e.Detail is { } d && d.StartsWith("symbolic link to ", StringComparison.Ordinal)
                ? new Row(e.Size, null, d["symbolic link to ".Length..], e.Mode)
                : new Row(e.Size, bytes.TryGetValue(e.Path, out var b) ? Blob.Sha256(b) : e.Size == 0 ? Blob.Sha256([]) : null, null, e.Mode);
        return rows;
    }

    /// <summary>A Windows path as WSL mounts it (/mnt/d/...).</summary>
    private static string LinuxPath(string path) =>
        path.Length > 2 && path[1] == ':' ? $"/mnt/{char.ToLowerInvariant(path[0])}{path[2..].Replace('\\', '/')}" : path;

    private static byte[] Gunzip(byte[] data)
    {
        using var z = new GZipStream(new MemoryStream(data), CompressionMode.Decompress);
        var o = new MemoryStream();
        z.CopyTo(o);
        return o.ToArray();
    }
}
