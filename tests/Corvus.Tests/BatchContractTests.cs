using Corvus.Core;
using Corvus.Mcp;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Batch tools (S6.5): one good and one bad target succeed with failed=1 and a per-item error; all bad is an error.</summary>
public class BatchContractTests
{
    private static (TempDir Dir, string Path, string Va) Image()
    {
        var dir = new TempDir();
        var path = dir.File("batch.dll");
        var b = new PeBuilder();
        var text = b.Add(".text", [0x55, 0x48, 0x89, 0xE5, 0x5D, 0xC3, 0xCC, 0xCC], 0x60000020);
        b.EntryPoint = text.Rva;
        File.WriteAllBytes(path, b.Build());
        return (dir, path, $"0x{b.ImageBase + text.Rva:X}");
    }

    private static void OneFailed<T>(IReadOnlyList<BatchItem<T>>? items, int? failed, string badTarget)
    {
        Assert.NotNull(items);
        Assert.Equal(1, failed);
        var bad = Assert.Single(items!, i => i.Error != null);
        Assert.Equal(badTarget, bad.Target);
        Assert.False(string.IsNullOrEmpty(bad.Error!.Next));
        Assert.Null(bad.Value);
        Assert.Contains(items!, i => i.Error == null && i.Value != null);
    }

    [Fact]
    public async Task ResolveAddressSearchBytesAndFindXrefsReportEachFailedItem()
    {
        var (dir, path, va) = Image();
        using var _ = dir;
        using var h = new NativeToolHarness();

        var collector = ToolOutput.Collect();
        await h.Native.ResolveAddress(path, addresses: [va, "no_such_name"]);
        var resolved = Assert.IsType<AddressInfo>(collector.Value);
        OneFailed(resolved.Results, resolved.Failed, "no_such_name");
        Assert.Equal(va, resolved.Results![0].Value!.Va);

        await h.Native.SearchBytes(path, patterns: ["48 89 E5", "?? ??"]);
        var hits = Assert.IsType<NativeTools.ByteSearch>(collector.Value);
        OneFailed(hits.Patterns, hits.Failed, "?? ??");
        Assert.Equal("invalid_argument", hits.Patterns![1].Error!.Code);

        await h.CodeTools.FindXrefs(path, addresses: [va, "no_such_name"]);
        var xrefs = Assert.IsType<XrefList>(collector.Value);
        OneFailed(xrefs.Targets, xrefs.Failed, "no_such_name");
        Assert.DoesNotContain(xrefs.Items, e => e.Kind == "error");

        await Assert.ThrowsAsync<ToolError>(() => h.Native.ResolveAddress(path, addresses: ["nope1", "nope2"]));
        await Assert.ThrowsAsync<ToolError>(() => h.Native.SearchBytes(path, patterns: ["??", "zz"]));
        await Assert.ThrowsAsync<ToolError>(() => h.CodeTools.FindXrefs(path, addresses: ["nope1", "nope2"]));
    }

    [Fact]
    public void AnItemErrorIsCutAt8000Characters()
    {
        var error = BatchError.From(new ToolError(ErrorCode.InvalidArgument, new string('x', 20_000), "fix it"));
        Assert.True(error.Message.Length <= BatchError.MaxMessageChars);
        Assert.EndsWith("chars, cut)", error.Message);
    }
}
