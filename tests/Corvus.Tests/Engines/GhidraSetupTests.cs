using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ghidra;

namespace Corvus.Tests;

/// <summary>Ghidra install and JDK discovery, the option table and the worker command line, on fake installs.</summary>
public class GhidraSetupTests
{
    /// <summary>A directory shaped like a Ghidra release: properties, launcher jars, optionally the native decompiler.</summary>
    internal static string FakeInstall(TempDir tmp, string version = "12.1.4", bool decompiler = true, string? javaMax = null)
    {
        var dir = tmp.File("ghidra_" + version);
        Directory.CreateDirectory(Path.Combine(dir, "Ghidra"));
        File.WriteAllText(Path.Combine(dir, "Ghidra", "application.properties"),
            $"#comment\napplication.name=Ghidra\napplication.version={version}\napplication.revision.ghidra=abc123\napplication.java.min=21\napplication.java.max={javaMax}\n");
        foreach (var jar in new[] { Path.Combine("Ghidra", "Framework", "Utility", "lib", "Utility.jar"), Path.Combine("support", "LaunchSupport.jar"),
                     Path.Combine("Ghidra", "Features", "Base", "lib", "Base.jar") })
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.Combine(dir, jar))!);
            File.WriteAllText(Path.Combine(dir, jar), "");
        }
        if (decompiler)
        {
            var os = Path.Combine(dir, "Ghidra", "Features", "Decompiler", "os", GhidraInstallation.PlatformName);
            Directory.CreateDirectory(os);
            File.WriteAllText(Path.Combine(os, OperatingSystem.IsWindows() ? "decompile.exe" : "decompile"), "");
        }
        return dir;
    }

    internal static string FakeJdk(TempDir tmp, string name, string version, bool javac = true)
    {
        var home = tmp.File(name);
        var bin = Path.Combine(home, "bin");
        Directory.CreateDirectory(bin);
        var exe = OperatingSystem.IsWindows() ? ".exe" : "";
        File.WriteAllText(Path.Combine(bin, "java" + exe), "");
        if (javac) File.WriteAllText(Path.Combine(bin, "javac" + exe), "");
        File.WriteAllText(Path.Combine(home, "release"), $"IMPLEMENTOR=\"Test\"\nJAVA_VERSION=\"{version}\"\n");
        return home;
    }

    [Fact]
    public void Install_detection_reports_what_is_missing()
    {
        using var tmp = new TempDir();
        Assert.Null(GhidraInstallation.Locate(tmp.File("absent"), out var reason, out var fix));
        Assert.Contains("does not exist", reason);
        Assert.Contains(GhidraOptions.DirectoryVariable, fix);

        Assert.Null(GhidraInstallation.Locate(tmp.Path, out reason, out _));
        Assert.Contains("application.properties", reason);

        Assert.Null(GhidraInstallation.Locate(FakeInstall(tmp, "11.4"), out reason, out _));
        Assert.Contains("too old", reason);

        var dir = FakeInstall(tmp);
        File.Delete(Path.Combine(dir, "support", "LaunchSupport.jar"));
        Assert.Null(GhidraInstallation.Locate(dir, out reason, out _));
        Assert.Contains("LaunchSupport.jar", reason);
    }

    [Fact]
    public void Install_reads_version_java_range_and_decompiler()
    {
        using var tmp = new TempDir();
        var g = GhidraInstallation.Locate(FakeInstall(tmp, javaMax: "25"), out _, out _)!;
        Assert.Equal("12.1.4", g.Version);
        Assert.Equal("abc123", g.Revision);
        Assert.Equal(21, g.JavaMin);
        Assert.Equal(25, g.JavaMax);
        Assert.Equal("configured", g.Source);
        Assert.NotNull(g.DecompilerPath);
        Assert.Contains(g.CompileClasspath(), j => j.EndsWith("Base.jar", StringComparison.Ordinal));

        var bare = GhidraInstallation.Locate(FakeInstall(tmp, "12.0", decompiler: false), out _, out _)!;
        Assert.Null(bare.JavaMax);
        Assert.Null(bare.DecompilerPath);
        Assert.Contains(GhidraInstallation.PlatformName, bare.DecompilerRemediation);
    }

    [Theory]
    [InlineData("24.0.1", 24)]
    [InlineData("21", 21)]
    [InlineData("1.8.0_292", 8)]
    [InlineData("25-ea", 25)]
    public void Java_versions_parse_to_the_feature_release(string text, int major) => Assert.Equal(major, JavaRuntime.FeatureVersion(text));

    [Fact]
    public void Jdk_is_found_from_home_bin_or_executable_and_must_have_javac()
    {
        using var tmp = new TempDir();
        var home = FakeJdk(tmp, "jdk-24", "24.0.1");
        foreach (var path in new[] { home, Path.Combine(home, "bin"), Path.Combine(home, "bin", OperatingSystem.IsWindows() ? "java.exe" : "java") })
        {
            var jdk = JavaRuntime.Probe(path, "test", out var problem);
            Assert.True(jdk != null, problem);
            Assert.Equal(24, jdk.Major);
            Assert.Equal(Path.GetFullPath(home), jdk.Home);
        }
        Assert.Null(JavaRuntime.Probe(FakeJdk(tmp, "jre-24", "24", javac: false), "test", out var why));
        Assert.Contains("javac", why);

        var log = new List<string>();
        JavaRuntime.Locate(FakeJdk(tmp, "jdk-17", "17.0.2"), 21, null, log);
        Assert.Contains("outside", log[0]);
    }

    [Fact]
    public void Profiles_set_the_measured_options()
    {
        Assert.Equal(GhidraAnalysisProfile.Standard, GhidraOptions.Profile(null));
        Assert.Equal(GhidraAnalysisProfile.Full, GhidraOptions.Profile(" Full "));
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => GhidraOptions.Profile("fast")).Code);

        var standard = GhidraOptions.AnalyzerOptions(GhidraAnalysisProfile.Standard, SymbolMode.Default, null);
        Assert.Contains(standard, o => o.Key == "Decompiler Parameter ID.Analysis Decompiler Timeout (sec)" && o.Value == "10");
        Assert.Contains(standard, o => o.Key == "WindowsResourceReference" && o.Value == "false");
        // stack analysis waits for the completion pass, when one follows
        Assert.DoesNotContain(standard, o => o.Key == "Stack");
        Assert.Contains(GhidraOptions.AnalyzerOptions(GhidraAnalysisProfile.Standard, SymbolMode.Default, null, completion: true), o => o.Key == "Stack" && o.Value == "false");
        Assert.Empty(GhidraOptions.AnalyzerOptions(GhidraAnalysisProfile.Full, SymbolMode.Default, null));
        Assert.Contains(GhidraOptions.AnalyzerOptions(GhidraAnalysisProfile.Full, SymbolMode.Off, null), o => o.Key == "PDB Universal" && o.Value == "false");
        Assert.Contains(GhidraOptions.AnalyzerOptions(GhidraAnalysisProfile.Minimal, SymbolMode.Default, null), o => o.Key == "Decompiler Switch Analysis" && o.Value == "false");

        Assert.Contains(GhidraOptions.LoaderArguments(GhidraAnalysisProfile.Standard), a => a.Key == "-loader-ordinalLookup" && a.Value == "false");
        Assert.DoesNotContain(GhidraOptions.LoaderArguments(GhidraAnalysisProfile.Full), a => a.Key == "-loader-ordinalLookup");
    }

    [Fact]
    public void Extra_options_and_heap_size_are_validated()
    {
        var extra = GhidraOptions.ParseExtra(" Stack = false ;Decompiler Parameter ID.Analysis Decompiler Timeout (sec)=5;");
        Assert.Equal([new("Stack", "false"), new("Decompiler Parameter ID.Analysis Decompiler Timeout (sec)", "5")], extra);
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => GhidraOptions.ParseExtra("Stack")).Code);
        Assert.Equal("Stack", GhidraOptions.AnalyzerOptions(GhidraAnalysisProfile.Standard, SymbolMode.Default, "Stack=false")[^1].Key);

        Assert.Equal("4G", GhidraOptions.MaxMemory(null, 1 << 20));
        Assert.Equal("8G", GhidraOptions.MaxMemory("", 60L << 20));
        Assert.Equal("6g", GhidraOptions.MaxMemory("6g", 1));
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => GhidraOptions.MaxMemory("lots", 1)).Code);
    }

    [Fact]
    public void Profile_key_is_stable_and_changes_with_each_input()
    {
        using var tmp = new TempDir();
        var g = GhidraInstallation.Locate(FakeInstall(tmp), out _, out _)!;
        var loader = GhidraOptions.LoaderArguments(GhidraAnalysisProfile.Standard);
        var options = GhidraOptions.AnalyzerOptions(GhidraAnalysisProfile.Standard, SymbolMode.Default, null);
        var key = GhidraOptions.ProfileKey(g, GhidraAnalysisProfile.Standard, loader, options);
        Assert.Equal(16, key.Length);
        Assert.Equal("44469fa82bf02958", key); // a change here re-analyzes every cached image: bump on purpose only
        Assert.NotEqual(key, GhidraOptions.ProfileKey(g with { Version = "12.1.5" }, GhidraAnalysisProfile.Standard, loader, options));
        Assert.NotEqual(key, GhidraOptions.ProfileKey(g, GhidraAnalysisProfile.Full, loader, options));
        Assert.NotEqual(key, GhidraOptions.ProfileKey(g, GhidraAnalysisProfile.Standard, [.. loader, new(GhidraOptions.ElfImageBaseArgument, "0")], options));
        Assert.NotEqual(key, GhidraOptions.ProfileKey(g, GhidraAnalysisProfile.Standard, loader,
            GhidraOptions.AnalyzerOptions(GhidraAnalysisProfile.Standard, SymbolMode.Off, null)));
    }

    [Fact]
    public void Worker_command_keeps_every_ghidra_directory_private()
    {
        using var tmp = new TempDir();
        var g = GhidraInstallation.Locate(FakeInstall(tmp), out _, out _)!;
        var dirs = new GhidraDirectories(tmp.File("cache"));
        var args = GhidraLaunch.Arguments(g, ["-Djava.system.class.loader=ghidra.GhidraClassLoader"], "4G", dirs, "boot.jar", "worker.jar");
        Assert.Equal("-Djava.system.class.loader=ghidra.GhidraClassLoader", args[0]);
        foreach (var property in new[] { "user.home", "application.settingsdir", "application.cachedir", "application.tempdir", "java.io.tmpdir" })
            Assert.Contains(args, a => a.StartsWith($"-D{property}={dirs.Root}", StringComparison.Ordinal));
        Assert.Contains("-Xmx4G", args);
        Assert.Contains("-Dcorvus.worker.jar=worker.jar", args);
        Assert.Equal(["ghidra.Ghidra", GhidraLaunch.BootClass], args.TakeLast(2));
        Assert.Equal(g.UtilityJar + Path.PathSeparator + "boot.jar", args[^3]);
    }
}
