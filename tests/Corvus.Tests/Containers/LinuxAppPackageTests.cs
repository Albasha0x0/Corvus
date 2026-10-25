using System.Security.Cryptography;
using System.Text;
using Corvus.Core;
using Corvus.Native.Providers;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>AppImages (an ELF runtime stub before a squashfs image) and a snap built by build.sh from one ledger tree.</summary>
public sealed class LinuxAppPackageTests(ITestOutputHelper output)
{
    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Containers", "LinuxAppFixtures", name);

    [Theory]
    [InlineData("gzip")]
    [InlineData("zstd")]
    public void An_AppImage_names_its_runtime_update_information_and_desktop_entry(string compressor)
    {
        var c = Containers.Open(File.ReadAllBytes(Fixture($"ledger-{compressor}.AppImage")), "ledger.AppImage", AnalysisLimits.Default, default);
        Assert.Equal("AppImage", c.Kind);
        Assert.Equal("AppImage type 2: a 64-bit runtime of 2,401 bytes, squashfs at 0x961; update information gh-releases-zsync|example|ledger|latest|Ledger-*x86_64.AppImage.zsync; " +
            "not signed; desktop entry ledger.desktop: Ledger (command ledger, icon ledger, version 1.2.0).", c.Notes[0]);
        var entries = c.Entries!.ToDictionary(e => e.Path);
        Assert.Equal("755", entries["usr/bin/ledger"].Mode);
        Assert.Equal("symbolic link to ledger.png", entries[".DirIcon"].Detail);
        // Without allFiles only the desktop entry is extracted: the scripts are neither binaries nor packages.
        Assert.Equal(["ledger.desktop"], c.Items.Select(i => i.Name));
    }

    [Fact]
    public void A_snap_names_its_package_fields_and_apps()
    {
        var c = Containers.Open(File.ReadAllBytes(Fixture("ledger_1.2.0_amd64.snap")), "ledger.snap", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("snap package", c.Kind);
        Assert.Equal("snap ledger 1.2.0: Ledger sample package; base core22; grade stable; confinement strict; apps ledger, ledger-report.", c.Notes[0]);
        Assert.Equal("#!/bin/sh\necho ledger 1.2.0\n", Encoding.UTF8.GetString(c.Items.Single(i => i.Name == "bin/ledger").Bytes));
    }

    [Fact]
    public void A_plain_squashfs_image_stays_squashfs()
    {
        var data = File.ReadAllBytes(Fixture("ledger-gzip.AppImage"))[2401..];
        var c = Containers.Open(data, "ledger.squashfs", AnalysisLimits.Default, default);
        Assert.Equal("squashfs", c.Kind);
        Assert.Contains(c.Entries!, e => e.Path == "usr/share/ledger/notes.txt");
    }

    [Fact]
    public void An_ELF_without_a_squashfs_image_after_its_section_headers_is_no_AppImage()
    {
        var data = File.ReadAllBytes(Fixture("ledger-gzip.AppImage"))[..2401];
        Assert.NotEqual("AppImage", Containers.Open(data, "ledger", AnalysisLimits.Default, default).Kind);
    }

    [Fact]
    [FuzzEntry(typeof(Corvus.Core.Archives.LinuxAppPackages))]
    public void Fuzzed_AppImages_and_snaps_never_throw_past_a_tool_error()
    {
        var failures = new List<string>();
        foreach (var seed in new[] { "ledger-gzip.AppImage", "ledger_1.2.0_amd64.snap" })
            failures.AddRange(FormatFuzz.Run(File.ReadAllBytes(Fixture(seed)), b =>
            {
                try { Containers.Open(b, seed, AnalysisLimits.Default, default, allFiles: true); } catch (ToolError) { }
            }, 400));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    // The fixtures and each AppImage and snap under CORVUS_LINUX_APPS are read by unsquashfs through reference.sh, run by
    // CORVUS_FS_REFERENCE (sh on Linux, wsl.exe on Windows). Compared: the squashfs offset, each regular file's size,
    // mode and SHA-256, and each symbolic link's target.
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_FS_REFERENCE")]
    public void Files_and_links_equal_what_unsquashfs_reads()
    {
        string runner = RealData.Path("CORVUS_FS_REFERENCE");
        static bool Wanted(string f) => f.EndsWith(".AppImage", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".snap", StringComparison.OrdinalIgnoreCase);
        var files = Directory.GetFiles(Path.GetDirectoryName(Fixture("x"))!).Where(Wanted).Order(StringComparer.Ordinal).ToList();
        if (Environment.GetEnvironmentVariable("CORVUS_LINUX_APPS") is { Length: > 0 } dir)
            files.AddRange(Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories).Where(Wanted).Order(StringComparer.Ordinal));
        bool wsl = Path.GetFileNameWithoutExtension(runner).Equals("wsl", StringComparison.OrdinalIgnoreCase);
        var limits = AnalysisLimits.Default with { MaxItems = 1_000_000, MaxItemBytes = 1L << 31, MaxTotalBytes = 1L << 33 };
        var problems = new List<string>();
        int packages = 0, contents = 0, links = 0;
        foreach (var file in files)
        {
            string name = Path.GetFileName(file);
            List<string> args = wsl ? ["-e", "sh", LinuxPath(Fixture("reference.sh")), LinuxPath(file)] : [Fixture("reference.sh"), file];
            var run = ExternalTools.Run(runner, args, TimeSpan.FromMinutes(10), 1 << 28, default);
            if (run.ExitCode != 0) { problems.Add($"{name}: reference exit {run.ExitCode}: {run.Stderr}"); continue; }
            var c = Containers.Open(File.ReadAllBytes(file), name, limits, default, allFiles: true);
            var entries = c.Entries!.GroupBy(e => e.Path).ToDictionary(g => g.Key, g => g.First());
            var items = c.Items.GroupBy(i => i.Name).ToDictionary(g => g.Key, g => g.First());
            packages++;
            foreach (var line in run.Text.Replace("\r", "").Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var f = line.Split('\t');
                switch (f[0])
                {
                    case "O":
                        if (f[1] != "0" && !c.Notes[0].Contains($"squashfs at 0x{long.Parse(f[1]):X};", StringComparison.Ordinal)) problems.Add($"{name}: offset {f[1]}, Corvus: {c.Notes[0]}");
                        break;
                    case "L":
                        if (!entries.TryGetValue(f[1], out var e)) { problems.Add($"{name}: {f[1]} is not listed"); break; }
                        if (e.Size != long.Parse(f[3]) || e.Mode != f[2]) problems.Add($"{name}: {f[1]}: unsquashfs {f[2]} {f[3]}, Corvus {e.Mode} {e.Size}");
                        break;
                    case "S":
                        links++;
                        if (!entries.TryGetValue(f[1], out var l) || l.Detail != $"symbolic link to {f[2]}") problems.Add($"{name}: link {f[1]} -> {f[2]} differs");
                        break;
                    case "C":
                        contents++;
                        if (!items.TryGetValue(f[1], out var item) || Convert.ToHexStringLower(SHA256.HashData(item.Bytes)) != f[2]) problems.Add($"{name}: {f[1]} differs");
                        break;
                }
            }
        }
        output.WriteLine($"{packages} packages: {contents} files and {links} links equal to unsquashfs");
        foreach (var p in problems.Take(40)) output.WriteLine(p);
        Assert.Empty(problems);
        Assert.True(packages > 0);
    }

    /// <summary>A Windows path as WSL mounts it (/mnt/d/...).</summary>
    private static string LinuxPath(string path) =>
        path.Length > 2 && path[1] == ':' ? $"/mnt/{char.ToLowerInvariant(path[0])}{path[2..].Replace('\\', '/')}" : path;
}
