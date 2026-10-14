using ModelContextProtocol.Protocol;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>verify_native_imports on a Mach-O image: @rpath through @loader_path resolves beside it, and reports the load unresolved when the library is gone.</summary>
public sealed class MachOLinkCheckTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static string Native(string name) => RealPackages.File("Microsoft.NETCore.App.Runtime.osx-arm64", "10.0.11", "runtimes", "osx-arm64", "native", name);

    private async Task<string> Verify(string folder)
    {
        await using var server = await InProcessServer.StartAsync();
        await server.Client.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = Path.Combine(folder, "libmscordbi.dylib") });
        var r = await server.Client.CallToolAsync("verify_native_imports", new Dictionary<string, object?> { ["assembly"] = "libmscordbi.dylib" });
        var text = string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));
        output.WriteLine(text);
        return text;
    }

    [Fact]
    public async Task An_rpath_dependency_resolves_beside_the_image_or_is_unresolved()
    {
        var whole = Directory.CreateDirectory(_dir.File("whole")).FullName;
        File.Copy(Native("libmscordbi.dylib"), Path.Combine(whole, "libmscordbi.dylib"));
        File.Copy(Native("libmscordaccore.dylib"), Path.Combine(whole, "libmscordaccore.dylib"));
        var text = await Verify(whole);
        Assert.Matches(@"verified \(resolved\)  @rpath/libmscordaccore\.dylib  -> .*libmscordaccore\.dylib: \d+ symbol\(s\) bound, all exported", text);
        Assert.Contains("not_checked (system_library)  /usr/lib/libSystem.B.dylib", text);

        var broken = Directory.CreateDirectory(_dir.File("broken")).FullName;
        File.Copy(Native("libmscordbi.dylib"), Path.Combine(broken, "libmscordbi.dylib"));
        Assert.Contains("unresolved (dll_not_found)  @rpath/libmscordaccore.dylib: searched", await Verify(broken));
    }
}
