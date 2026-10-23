using System.Diagnostics;
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
[Trait("Speed", "Slow")]
[Permit("reference-tool")]
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

    /// <summary>Classes the signature images are taken by; each takes a reference-tool permit of its own.</summary>
    public const int SignatureParts = 2;

    public sealed class Signatures1(ITestOutputHelper output) : SignatureScan(output);
    public sealed class Signatures2(ITestOutputHelper output) : SignatureScan(output);

    /// <summary>
    /// Signature hits of each image against the scanner's (binwalk) by offset, and the sizes both state. A part takes the
    /// next image whenever it is free and adds its counts to totals all parts share; each part waits for the images still
    /// being scanned and checks the totals, so the check covers every image whether one part runs or all do.
    /// </summary>
    [Trait("Speed", "Slow")]
    public abstract class SignatureScan(ITestOutputHelper output)
    {
        private static readonly object Gate = new();
        private static Queue<string>? _pending;
        private static int _scanning, _ours, _theirs, _common, _inside, _sized, _sameSize;

        [Fact]
        public void Firmware_signatures_match_the_scanners()
        {
            if (Environment.GetEnvironmentVariable("CORVUS_FIRMWARE_IMAGES") is not { Length: > 0 } root || !Directory.Exists(root)
                || Environment.GetEnvironmentVariable("CORVUS_FS_REFERENCE") is not { Length: > 0 } runner) return;
            var script = Path.Combine(FirmwareFilesystemTests.FixtureDir, "reference.sh");
            lock (Gate) _pending ??= new(Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal));
            while (true)
            {
                string file;
                lock (Gate)
                {
                    if (!_pending.TryDequeue(out file!)) break;
                    _scanning++;
                }
                try { Scan(file, runner, script); }
                finally { lock (Gate) _scanning--; }
            }
            // An image another part is scanning still counts toward the totals.
            var waited = Stopwatch.StartNew();
            while (Volatile.Read(ref _scanning) > 0 && waited.Elapsed < TimeSpan.FromMinutes(20)) Thread.Sleep(500);
            Assert.True(Volatile.Read(ref _scanning) == 0, "another part's image was still being scanned after 20 min");
            output.WriteLine($"signatures: ours {_ours:N0}, scanner {_theirs:N0}, at the same offset {_common:N0}, scanner hits inside our sized regions {_inside:N0}; sizes stated by both {_sized:N0}, equal {_sameSize:N0}");
            Assert.Equal(_sized, _sameSize);
            Assert.True(_common + _inside >= _theirs * 0.99, $"{_theirs - _common - _inside} scanner hits outside every region we found");
        }

        private void Scan(string file, string runner, string script)
        {
            int ours = 0, theirs = 0, common = 0, inside = 0, sized = 0, sameSize = 0;
            using var work = new TempDir();
            var data = File.ReadAllBytes(file);
            if (file.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)) data = Gunzip(data);
            var hits = Corvus.Core.Firmware.FirmwareSignatures.Scan(data, 2000, default).ToDictionary(h => h.Offset);
            var reference = Run(runner, script, "signatures", data, work).Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Select(l => l.Split(' ', 2)).GroupBy(f => long.Parse(f[0])).ToDictionary(g => g.Key, g => g.First()[1]);
            ours += hits.Count;
            theirs += reference.Count;
            var differences = new List<string>();
            foreach (var at in hits.Keys.Union(reference.Keys).Order())
            {
                if (!reference.TryGetValue(at, out var description)) { differences.Add($"only ours: 0x{at:X} {hits[at].Format} ({hits[at].Size})"); continue; }
                if (!hits.TryGetValue(at, out var hit))
                {
                    // a hit inside a region we sized (a file of a filesystem, a stream of a kernel) is that region's reader's to find
                    if (hits.Values.Any(h => h.Offset < at && at < h.Offset + (h.Size ?? 0))) inside++;
                    else differences.Add($"only scanner: 0x{at:X} {description}");
                    continue;
                }
                common++;
                if (System.Text.RegularExpressions.Regex.Match(description, @"(?<![a-z] )size: (\d+) bytes") is { Success: true } m && hit.Size is { } size)
                {
                    sized++;
                    if (long.Parse(m.Groups[1].Value) == size) sameSize++;
                    else differences.Add($"size: 0x{at:X} {hit.Format} ours {size}, scanner {m.Groups[1].Value}: {description}");
                }
            }
            output.WriteLine($"{Path.GetFileName(file)}: ours {hits.Count}, scanner {reference.Count}, both {hits.Keys.Intersect(reference.Keys).Count()}"
                             + (differences.Count > 0 ? "\n    " + string.Join("\n    ", differences.Take(15)) : ""));
            Interlocked.Add(ref _ours, ours);
            Interlocked.Add(ref _theirs, theirs);
            Interlocked.Add(ref _common, common);
            Interlocked.Add(ref _inside, inside);
            Interlocked.Add(ref _sized, sized);
            Interlocked.Add(ref _sameSize, sameSize);
        }
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
        var reference = Reference(Run(runner, script, format, image, work));
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

    /// <summary>The script's output for <paramref name="image"/>, written to <paramref name="work"/> first.</summary>
    private static string Run(string runner, string script, string format, byte[] image, TempDir work)
    {
        var imagePath = work.File("image");
        File.WriteAllBytes(imagePath, image);
        bool wsl = Path.GetFileNameWithoutExtension(runner).Equals("wsl", StringComparison.OrdinalIgnoreCase);
        List<string> args = wsl ? ["-u", "root", "-e", "sh", LinuxPath(script), format, LinuxPath(imagePath)] : [script, format, imagePath];
        var run = ExternalTools.Run(runner, args, TimeSpan.FromMinutes(10), 256L << 20, default);
        Assert.True(run.StartError == null && !run.TimedOut && !run.Truncated && run.ExitCode == 0, $"reference {format}: {run.StartError ?? run.Stderr}");
        return run.Text;
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
