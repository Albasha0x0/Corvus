using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>summarize_file view=apple on a macOS .app folder and an .ipa: roles, Info.plist facts, signatures per slice, the profile.</summary>
public sealed class AppleBundleViewTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static byte[] Dylib(string name) =>
        File.ReadAllBytes(RealPackages.File("Microsoft.NETCore.App.Runtime.osx-arm64", "10.0.11", "runtimes", "osx-arm64", "native", name));

    private static string Plist(params (string Key, string Xml)[] entries) =>
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict>" + string.Concat(entries.Select(e => $"<key>{e.Key}</key>{e.Xml}")) + "</dict></plist>";

    private AppleFileView.Facts View(string path)
    {
        var bytes = File.ReadAllBytes(path);
        var view = new AppleFileView().Inspect(new FileInput(path, bytes, Blob.Identify(bytes)), default)!;
        foreach (var h in view.Highlights) output.WriteLine(h);
        return (AppleFileView.Facts)view.Detail;
    }

    [Fact]
    public void A_macOS_app_folder_lists_roles_and_signatures()
    {
        var app = Directory.CreateDirectory(_dir.File("Tool.app")).FullName;
        void Put(string relative, byte[] bytes)
        {
            var full = Path.Combine(app, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            File.WriteAllBytes(full, bytes);
        }
        Put("Contents/Info.plist", Encoding.UTF8.GetBytes(Plist(("CFBundleExecutable", "<string>Tool</string>"), ("CFBundleIdentifier", "<string>org.example.tool</string>"),
            ("CFBundleShortVersionString", "<string>1.2</string>"), ("SUFeedURL", "<string>https://example.org/appcast.xml</string>"))));
        Put("Contents/MacOS/Tool", Dylib("libclrjit.dylib"));
        Put("Contents/Frameworks/Sparkle.framework/Versions/B/Sparkle", Dylib("libhostfxr.dylib"));
        Put("Contents/Frameworks/libextra.dylib", Dylib("libhostpolicy.dylib"));
        Put("Contents/Resources/notes", Dylib("libhostpolicy.dylib"));

        var main = AppleFileView.MainExecutable(app);
        Assert.Equal(Path.Combine(app, "Contents/MacOS/Tool"), main);
        var facts = View(main!);
        Assert.Equal(("macOS app", "org.example.tool", "https://example.org/appcast.xml"), (facts.Kind, facts.Identifier, facts.UpdateFeed));
        Assert.Equal(["Contents/Frameworks/Sparkle.framework/Versions/B/Sparkle framework Sparkle", "Contents/Frameworks/libextra.dylib library", "Contents/MacOS/Tool main executable"],
            facts.Binaries.Select(b => $"{b.Path} {b.Role}").Order(StringComparer.Ordinal));
        Assert.All(facts.Binaries, b => Assert.Contains("code pages match", Assert.Single(b.Signatures).Verdict));
    }

    [Fact]
    public void An_ipa_names_its_profile_and_frameworks()
    {
        var ipa = _dir.File("Bar.ipa");
        using (var zip = ZipFile.Open(ipa, ZipArchiveMode.Create))
        {
            void Put(string name, byte[] bytes)
            {
                using var s = zip.CreateEntry("Payload/Bar.app/" + name).Open();
                s.Write(bytes);
            }
            Put("Info.plist", Encoding.UTF8.GetBytes(Plist(("CFBundleExecutable", "<string>Bar</string>"), ("CFBundleIdentifier", "<string>org.example.bar</string>"),
                ("CFBundleURLTypes", "<array><dict><key>CFBundleURLSchemes</key><array><string>bar</string></array></dict></array>"),
                ("NSCameraUsageDescription", "<string>scan codes</string>"))));
            Put("Bar", Dylib("libclrjit.dylib"));
            Put("Frameworks/Lib.framework/Lib", Dylib("libhostfxr.dylib"));
            // A CMS envelope's bytes around the profile's plist.
            Put("embedded.mobileprovision", [0x30, 0x80, .. Encoding.UTF8.GetBytes(Plist(("Name", "<string>Bar Dev</string>"), ("TeamName", "<string>Example</string>"),
                ("ProvisionedDevices", "<array><string>a</string><string>b</string></array>"), ("Entitlements", "<dict><key>get-task-allow</key><true/></dict>"))), 0, 0]);
        }
        var facts = View(ipa);
        Assert.Equal(("iOS app", "Bar.app"), (facts.Kind, facts.Bundle));
        Assert.Equal(["bar"], facts.UrlSchemes);
        Assert.Equal(["NSCameraUsageDescription"], facts.UsageDescriptions);
        Assert.Equal("development (2 devices)", facts.Provisioning?.Kind);
        Assert.Contains(facts.Binaries, b => b.Role == "framework Lib");
    }
}
