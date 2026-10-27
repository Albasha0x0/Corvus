using System.IO.Compression;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ghidra;

namespace Corvus.Tests;

/// <summary>Ghidra extensions from CORVUS_GHIDRA_EXTENSIONS: discovery, installation into the private settings and the profile key.</summary>
public class GhidraExtensionTests
{
    /// <summary>An extension zip: one top-level module directory with extension.properties, Module.manifest and a jar.</summary>
    internal static string ExtensionZip(string dir, string name, string version, string jarContent = "probe")
    {
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, name + ".zip");
        File.Delete(path);
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        void Text(string entry, string text)
        {
            using var w = new StreamWriter(zip.CreateEntry(entry).Open());
            w.Write(text);
        }
        Text($"{name}/extension.properties", $"name={name}\ndescription=test extension\nauthor=\ncreatedOn=\nversion={version}\n");
        Text($"{name}/Module.manifest", "");
        using var jar = new MemoryStream();
        using (var j = new ZipArchive(jar, ZipArchiveMode.Create, leaveOpen: true))
        {
            using var w = new StreamWriter(j.CreateEntry("META-INF/MANIFEST.MF").Open());
            w.Write("Manifest-Version: 1.0\r\nX-Probe: " + jarContent + "\r\n\r\n");
        }
        using (var s = zip.CreateEntry($"{name}/lib/{name}.jar").Open()) s.Write(jar.ToArray());
        return path;
    }

    [Fact]
    public void Extensions_are_found_by_module_name_and_content_hash()
    {
        using var tmp = new TempDir();
        Assert.Empty(GhidraExtensions.Configured(null));
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => GhidraExtensions.Configured(tmp.File("absent"))).Code);

        var dir = tmp.File("ext");
        var zip = ExtensionZip(dir, "NativeAOT", "12.1.4");
        Directory.CreateDirectory(Path.Combine(dir, "Unpacked"));
        File.WriteAllText(Path.Combine(dir, "Unpacked", "extension.properties"), "name=Unpacked\nversion=12.1.4\n");
        Directory.CreateDirectory(Path.Combine(dir, "not-an-extension"));
        var found = GhidraExtensions.Configured(dir);
        Assert.Equal(["NativeAOT", "Unpacked"], found.Select(e => e.Name));
        Assert.Equal(zip, found[0].Source);
        Assert.Equal(16, found[0].Hash.Length);
        ExtensionZip(dir, "NativeAOT", "12.1.4", "rebuilt");
        Assert.NotEqual(found[0].Hash, GhidraExtensions.Configured(dir)[0].Hash);

        using (var bad = ZipFile.Open(Path.Combine(dir, "bad.zip"), ZipArchiveMode.Create)) bad.CreateEntry("readme.txt");
        var e = Assert.Throws<ToolError>(() => GhidraExtensions.Configured(dir));
        Assert.Equal(ErrorCode.InvalidArgument, e.Code);
        Assert.Contains("bad.zip", e.Message);
    }

    [Fact]
    public void Install_unpacks_replaces_changed_ones_and_removes_its_own_stale_ones()
    {
        using var tmp = new TempDir();
        var dir = tmp.File("ext");
        ExtensionZip(dir, "NativeAOT", "12.1.4");
        ExtensionZip(dir, "Other", "12.1.4");
        var target = tmp.File("settings-extensions");
        Directory.CreateDirectory(Path.Combine(target, "UserOwn")); // not installed by the server: left alone
        GhidraExtensions.Install(GhidraExtensions.Configured(dir), target);
        Assert.True(File.Exists(Path.Combine(target, "NativeAOT", "lib", "NativeAOT.jar")));
        Assert.True(File.Exists(Path.Combine(target, "Other", "extension.properties")));
        var stamp = File.GetLastWriteTimeUtc(Path.Combine(target, "NativeAOT", "extension.properties"));

        // Unchanged: not unpacked again.
        GhidraExtensions.Install(GhidraExtensions.Configured(dir), target);
        Assert.Equal(stamp, File.GetLastWriteTimeUtc(Path.Combine(target, "NativeAOT", "extension.properties")));

        // Changed and removed.
        ExtensionZip(dir, "NativeAOT", "12.1.4", "rebuilt");
        File.Delete(Path.Combine(dir, "Other.zip"));
        GhidraExtensions.Install(GhidraExtensions.Configured(dir), target);
        using (var jar = ZipFile.OpenRead(Path.Combine(target, "NativeAOT", "lib", "NativeAOT.jar")))
        using (var r = new StreamReader(jar.GetEntry("META-INF/MANIFEST.MF")!.Open()))
            Assert.Contains("rebuilt", r.ReadToEnd());
        Assert.False(Directory.Exists(Path.Combine(target, "Other")));
        Assert.True(Directory.Exists(Path.Combine(target, "UserOwn")));
        Assert.DoesNotContain(Directory.GetDirectories(target), d => Path.GetFileName(d).StartsWith(".staging", StringComparison.Ordinal));
    }

    [Fact]
    public void Extensions_are_part_of_the_profile_key_and_install_under_the_private_settings()
    {
        using var tmp = new TempDir();
        var g = GhidraInstallation.Locate(GhidraSetupTests.FakeInstall(tmp), out _, out _)!;
        var loader = GhidraOptions.LoaderArguments(GhidraAnalysisProfile.Standard);
        var options = GhidraOptions.AnalyzerOptions(GhidraAnalysisProfile.Standard, SymbolMode.Default, null);
        var key = GhidraOptions.ProfileKey(g, GhidraAnalysisProfile.Standard, loader, options);
        Assert.Equal(key, GhidraOptions.ProfileKey(g, GhidraAnalysisProfile.Standard, loader, options, []));
        GhidraExtension[] one = [new("NativeAOT", "0123456789abcdef", "x.zip")];
        var withOne = GhidraOptions.ProfileKey(g, GhidraAnalysisProfile.Standard, loader, options, one);
        Assert.NotEqual(key, withOne);
        Assert.NotEqual(withOne, GhidraOptions.ProfileKey(g, GhidraAnalysisProfile.Standard, loader, options, [one[0] with { Hash = "fedcba9876543210" }]));

        var dirs = new GhidraDirectories(tmp.File("cache"));
        var install = GhidraExtensions.InstallDirectory(dirs, g);
        Assert.StartsWith(dirs.Settings + Path.DirectorySeparatorChar, install);
        Assert.EndsWith(Path.Combine("ghidra_12.1.4_PUBLIC", "Extensions"), install);
    }

    [Fact]
    public void A_bad_extension_directory_makes_the_provider_unavailable_with_the_variable_named()
    {
        using var tmp = new TempDir();
        var java = GhidraSetupTests.FakeJdk(tmp, "jdk", "21.0.2");
        using var provider = new GhidraProvider(new GhidraProviderOptions
        {
            InstallDirectory = GhidraSetupTests.FakeInstall(tmp), JavaHome = java, CacheRoot = tmp.File("cache"), ExtensionsDirectory = tmp.File("absent"),
        });
        var a = provider.CheckAvailability();
        Assert.False(a.IsAvailable);
        Assert.Contains(GhidraOptions.ExtensionsVariable, a.Reason);
    }
}
