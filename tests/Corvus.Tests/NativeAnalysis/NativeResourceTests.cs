using Microsoft.Extensions.DependencyInjection;
using Corvus.Core;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>corvus://native/{image}/segments, /entrypoints and /type/{name}.</summary>
public sealed class NativeResourceTests
{
    [Fact]
    public async Task Segments_entrypoints_and_types_of_a_loaded_image()
    {
        using var dir = new TempDir();
        using var env = new Env();
        var path = dir.File("sink.dll");
        File.WriteAllBytes(path, NativePeTests.KitchenSink(is64: true));
        var native = env.Workspace.LoadAny(path).Native!;
        using var services = new ServiceCollection().AddSingleton(env.Workspace).BuildServiceProvider();
        var resources = new NativeResources(env.Workspace, services);

        var segments = resources.Segments("sink.dll");
        var text = native.Image.Sections.First(s => s.IsExecutable);
        Assert.Contains($"{text.Name}\t0x{native.Image.ImageBase + text.Rva:X}-0x{native.Image.ImageBase + text.Rva + text.VirtualSize:X}\t0x{text.VirtualSize:X}\tr-x", segments);

        var entries = resources.EntryPoints("sink.dll");
        var first = native.Image.Exports.First(e => e.Name == "First");
        // The address is the export's VA and the ordinal is its own column.
        Assert.Contains($"0x{native.Image.ImageBase + first.Rva:X}\texport\tFirst\t#{first.Ordinal}", entries);
        if (native.Image.EntryPointRva != 0) Assert.StartsWith($"0x{native.Image.ImageBase + native.Image.EntryPointRva:X}\tentry", entries);
        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => resources.Type("sink.dll", "NoSuchType", default))).Code);
        Assert.Throws<ToolError>(() => resources.Segments("missing.dll"));
    }
}
