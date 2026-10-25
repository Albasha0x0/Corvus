using System.Security.Cryptography;
using System.Text;
using Corvus.Core;
using Corvus.Native.Providers;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>rpm packages of ledger-tools.spec built by rpmbuild 4.17: header fields, file list, payload and scriptlets.</summary>
public sealed class RpmReaderTests(ITestOutputHelper output)
{
    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Containers", "RpmFixtures", name);

    private static ContainerContents Open(byte[] data, string name) => Containers.Open(data, name, AnalysisLimits.Default, default, allFiles: true);

    [Theory]
    // A payload other than gzip adds an rpmlib(PayloadIs...) requirement.
    [InlineData("gzip", 8)]
    [InlineData("bzip2", 9)]
    [InlineData("xz", 9)]
    [InlineData("zstd", 9)]
    public void A_binary_package_lists_its_header_files_and_extracts_its_payload(string compressor, int requires)
    {
        var c = Open(File.ReadAllBytes(Fixture($"ledger-tools-{compressor}.rpm")), "ledger.rpm");
        Assert.Equal("rpm package", c.Kind);
        Assert.Equal("binary rpm ledger-tools-1.2.0-3.noarch: Ledger sample package; license MIT; built on fixture.build at 2026-01-01 00:00:00 UTC; " +
            $"7 file(s) (1 not in the payload), payload cpio compressed with {compressor}; requires {requires}, provides 3; source package ledger-tools-1.2.0-3.src.rpm; " +
            "signature header: SHA-1, SHA-256, MD5.", c.Notes[0]);
        var entries = c.Entries!.ToDictionary(e => e.Path);
        Assert.Equal("755", entries["usr/bin/ledger"].Mode);
        Assert.StartsWith("root:root; SHA-256 c14406743dc18f54", entries["usr/bin/ledger"].Detail);
        Assert.Equal("root:root; symbolic link to ledger", entries["usr/bin/ledger-report"].Detail);
        Assert.Equal("root:root; directory", entries["usr/share/ledger/archive"].Detail);
        Assert.EndsWith("configuration file", entries["etc/ledger.conf"].Detail);
        Assert.EndsWith("not in the payload (%ghost)", entries["var/log/ledger.log"].Detail);
        Assert.Equal("Shipping notes for the ledger sample.\n", Encoding.UTF8.GetString(c.Items.Single(i => i.Name == "usr/share/ledger/notes.txt").Bytes));
        Assert.Equal("echo \"installing ledger\"", Encoding.UTF8.GetString(c.Items.Single(i => i.Name == "scripts/preinstall").Bytes).TrimEnd('\n'));
        Assert.Contains(c.Items, i => i.Name == "scripts/postinstall" && i.Origin == "postinstall scriptlet (/bin/sh)");
    }

    [Fact]
    public void A_source_package_is_named_source_and_holds_its_spec()
    {
        var c = Open(File.ReadAllBytes(Fixture("ledger-tools.src.rpm")), "ledger.src.rpm");
        Assert.StartsWith("source rpm ledger-tools-1.2.0-3.src: Ledger sample package;", c.Notes[0]);
        Assert.Contains("Name:           ledger-tools", Encoding.UTF8.GetString(c.Items.Single(i => i.Name == "ledger-tools.spec").Bytes));
    }

    [Fact]
    public void A_header_past_the_file_is_malformed_input()
    {
        var data = File.ReadAllBytes(Fixture("ledger-tools-gzip.rpm"))[..200];
        Assert.Equal(ErrorCode.MalformedInput, Assert.Throws<ToolError>(() => Open(data, "x.rpm")).Code);
    }

    [Fact]
    [FuzzEntry(typeof(Corvus.Core.Archives.RpmReader))]
    public void Fuzzed_packages_never_throw_past_a_tool_error()
    {
        var failures = new List<string>();
        foreach (var seed in new[] { "ledger-tools-gzip.rpm", "ledger-tools.src.rpm" })
            failures.AddRange(FormatFuzz.Run(File.ReadAllBytes(Fixture(seed)), b => { try { Open(b, seed); } catch (ToolError) { } }, 400));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    // The fixtures and each package under CORVUS_RPM_PACKAGES are read by rpm through reference.sh, run by
    // CORVUS_FS_REFERENCE (sh on Linux, wsl.exe on Windows). Compared: the package name, each header file's size, mode,
    // owner, link target and digest, each scriptlet's body and each payload file's SHA-256.
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_FS_REFERENCE")]
    public void Header_files_payload_and_scriptlets_equal_what_rpm_reads()
    {
        string runner = RealData.Path("CORVUS_FS_REFERENCE");
        var files = Directory.GetFiles(Path.GetDirectoryName(Fixture("x"))!, "*.rpm").Order(StringComparer.Ordinal).ToList();
        if (Environment.GetEnvironmentVariable("CORVUS_RPM_PACKAGES") is { Length: > 0 } dir)
            files.AddRange(Directory.EnumerateFiles(dir, "*.rpm", SearchOption.AllDirectories).Order(StringComparer.Ordinal));
        bool wsl = Path.GetFileNameWithoutExtension(runner).Equals("wsl", StringComparison.OrdinalIgnoreCase);
        var problems = new List<string>();
        int packages = 0, rows = 0, contents = 0;
        foreach (var file in files)
        {
            string name = Path.GetFileName(file);
            List<string> args = wsl ? ["-e", "sh", LinuxPath(Fixture("reference.sh")), LinuxPath(file)] : [Fixture("reference.sh"), file];
            var run = ExternalTools.Run(runner, args, TimeSpan.FromMinutes(5), 1 << 26, default);
            if (run.ExitCode != 0) { problems.Add($"{name}: reference exit {run.ExitCode}: {run.Stderr}"); continue; }
            var c = Open(File.ReadAllBytes(file), name);
            var entries = c.Entries!.GroupBy(e => e.Path).ToDictionary(g => g.Key, g => g.First());
            var items = c.Items.GroupBy(i => i.Name).ToDictionary(g => g.Key, g => g.First());
            packages++;
            foreach (var line in run.Text.Replace("\r", "").Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var f = line.Split('\t');
                switch (f[0])
                {
                    case "P":
                        if (!c.Notes[0].Contains($"rpm {f[1]}", StringComparison.Ordinal)) problems.Add($"{name}: package {f[1]}, Corvus: {c.Notes[0]}");
                        break;
                    case "F":
                        rows++;
                        string path = f[1].TrimStart('/');
                        if (!entries.TryGetValue(path, out var e)) { problems.Add($"{name}: {path} is not listed"); break; }
                        string mode = Convert.ToString(Convert.ToInt64(f[3], 8) & 0xFFF, 8);
                        var detail = e.Detail ?? "";
                        if (e.Size != long.Parse(f[2]) || e.Mode != mode || !detail.StartsWith($"{f[4]}:{f[5]}", StringComparison.Ordinal)
                            || (f[6].Length > 0 && !detail.Contains($"symbolic link to {f[6]}", StringComparison.Ordinal))
                            || (f[7].Length > 0 && !detail.Contains(f[7], StringComparison.Ordinal)))
                            problems.Add($"{name}: {path}: rpm [{string.Join(' ', f[2..])}], Corvus [{e.Size} {e.Mode} {detail}]");
                        break;
                    case "X":
                        string script = items.TryGetValue("scripts/" + f[1], out var s) ? Hash(Encoding.UTF8.GetString(s.Bytes).TrimEnd('\n')) : "missing";
                        if (script != f[2]) problems.Add($"{name}: scriptlet {f[1]} differs");
                        break;
                    case "C":
                        contents++;
                        if (!items.TryGetValue(f[1], out var item) || Convert.ToHexStringLower(SHA256.HashData(item.Bytes)) != f[2]) problems.Add($"{name}: payload file {f[1]} differs");
                        break;
                }
            }
        }
        output.WriteLine($"{packages} packages: {rows} header files and {contents} payload files equal to rpm");
        foreach (var p in problems.Take(40)) output.WriteLine(p);
        Assert.Empty(problems);
        Assert.True(packages > 0);
    }

    private static string Hash(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    /// <summary>A Windows path as WSL mounts it (/mnt/d/...).</summary>
    private static string LinuxPath(string path) =>
        path.Length > 2 && path[1] == ':' ? $"/mnt/{char.ToLowerInvariant(path[0])}{path[2..].Replace('\\', '/')}" : path;
}
