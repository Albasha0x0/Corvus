using System.Buffers.Binary;
using Corvus.Core;
using Corvus.Native;
using Corvus.Services.Analysis;
using Corvus.Services.Analysis.Hunts;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>compare_native_images view=review over two self-built builds: what the new build adds and the pass or hold verdict.</summary>
public sealed class UpdateReviewTests
{
    private const uint Name = 0x1000, Other = 0x1040, Injected = 0x1080, OldStamp = 0x5F8A1B2C;

    // The second build can add a function, an import, a host and a PE image.
    private static byte[] Image(uint stamp, bool function = false, bool import = false, bool host = false, byte[]? inner = null, string importName = "Go", bool grow = false)
    {
        (string, string[])[] imports = import
            ? [("kernel32.dll", ["ExitProcess"]), (importName == "Go" ? "added-lib.dll" : "kernel32.dll", [importName])]
            : [("kernel32.dll", ["ExitProcess"])];
        var image = LinkedImages.Build("host.dll", [], imports, _ =>
        {
            var code = Enumerable.Repeat((byte)0xCC, 0xC0).ToArray();
            byte[] first = grow ? [0x31, 0xC0, 0x85, 0xC9, 0x74, 0x03, 0x83, 0xC0, 0x05, 0xC3] : [0x31, 0xC0, 0x83, 0xC0, 0x05, 0xC3];
            first.CopyTo(code, 0);
            new byte[] { 0xB8, 0x01, 0, 0, 0, 0x83, 0xC0, 0x22, 0xC3 }.CopyTo(code, 0x40);
            if (function) new byte[] { 0x31, 0xC0, 0x83, 0xC0, 0x09, 0x83, 0xE8, 0x02, 0xC3 }.CopyTo(code, 0x80);
            return code;
        }, (blob, _) =>
        {
            blob.Ascii(@"\\.\pipe\shared-pipe");
            if (host) blob.Ascii("http://added.example.net/update");
            if (inner != null) { blob.Align(16); blob.Bytes(inner); }
            return [];
        });
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(PeBuilder.PeOffset + 8), stamp);
        return image;
    }

    private static async Task<(NativeDiffTools.NativeComparison Record, string Text)> Compare(byte[] before, byte[] after, string? reviewPath = null, bool injected = false)
    {
        using var h = new NativeBuildUpdateTests.Harness();
        var (o, oi) = await h.Load(before, "old.dll", [Name, Other]);
        var (n, ni) = await h.Load(after, "new.dll", injected ? [Name, Other, Injected] : [Name, Other]);
        foreach (var (native, index) in new[] { (o, oi), (n, ni) })
        {
            h.Code.Annotations(native).SetMany([(Name, "Grown"), (Other, "Steady")], []);
            index.SetUserName(Name, "Grown");
            index.SetUserName(Other, "Steady");
        }
        var tools = new NativeDiffTools(h.Env.Workspace, h.Code, inspection: new InspectionService(h.Env.Workspace));
        return await BuildToolCalls.Collected<NativeDiffTools.NativeComparison>(() => tools.CompareNativeImages(o.Id, n.Id, view: "review", reviewPath: reviewPath));
    }

    [Fact]
    public async Task An_added_function_import_and_host_are_named_and_the_verdict_is_hold()
    {
        var (record, text) = await Compare(Image(OldStamp), Image(OldStamp + 1, function: true, import: true, host: true), injected: true);
        var review = record.Review!;
        Assert.Equal("hold", review.Verdict);
        Assert.Contains(review.Added, f => f.NewAddress!.EndsWith("1080", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(review.Imports, i => i.Name == "added-lib.dll!Go" && i.Concern == null);
        Assert.Contains(review.Hosts, x => x.Value == "added.example.net");
        Assert.Contains(review.Holds, x => x.Id == "new_network_host");
        Assert.DoesNotContain(review.Holds, x => x.Id is "new_process_import" or "new_signer" or "signature_lost");
        Assert.Contains("Verdict: hold.", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_rebuild_with_only_a_new_time_stamp_passes_with_no_added_or_changed_function()
    {
        var (record, text) = await Compare(Image(OldStamp), Image(OldStamp + 1));
        var review = record.Review!;
        Assert.Equal("pass", review.Verdict);
        Assert.Empty(review.Holds);
        Assert.Equal((0, 0), (review.AddedTotal, review.ChangedTotal));
        Assert.Empty(review.Imports);
        Assert.Contains("this does not show the update is safe", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_build_with_its_signature_removed_is_a_hold()
    {
        var (record, _) = await Compare(SideloadTests.Signed(Image(OldStamp)), Image(OldStamp));
        var review = record.Review!;
        Assert.Equal("hold", review.Verdict);
        Assert.Equal(["signature_lost"], review.Holds.Select(x => x.Id));
        Assert.Equal("signature_lost", review.Signer.Change);
    }

    [Fact]
    public async Task An_added_PE_image_is_a_hold_with_its_offset_and_SHA256()
    {
        var inner = LinkedImages.Build("inner.dll", [], [("kernel32.dll", ["ExitProcess"])], _ => Enumerable.Repeat((byte)0xCC, 0x40).ToArray());
        var (record, _) = await Compare(Image(OldStamp), Image(OldStamp, inner: inner));
        var embedded = Assert.Single(record.Review!.Embedded);
        Assert.Equal(Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(inner)), embedded.Sha256);
        Assert.Contains(record.Review.Holds, x => x.Id == "new_embedded_executable");
    }

    [Fact]
    public async Task A_changed_function_carries_a_diff_reference_with_its_old_address()
    {
        var (record, _) = await Compare(Image(OldStamp), Image(OldStamp, grow: true));
        var changed = Assert.Single(record.Review!.Changed);
        Assert.EndsWith("1000", changed.OldAddress, StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith("address=" + changed.OldAddress, changed.Diff, StringComparison.Ordinal);
        Assert.StartsWith("diff_function oldImage=", changed.Diff, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReviewPath_writes_Markdown_and_a_json_extension_writes_JSON()
    {
        using var dir = new TempDir();
        var (md, json) = (dir.File("review.md"), dir.File("review.json"));
        var (record, _) = await Compare(Image(OldStamp), Image(OldStamp + 1, host: true), md);
        await Compare(Image(OldStamp), Image(OldStamp + 1, host: true), json);
        var text = File.ReadAllText(md);
        Assert.StartsWith("# Update review:", text, StringComparison.Ordinal);
        Assert.Contains("new_network_host", text, StringComparison.Ordinal);
        Assert.Equal("hold", System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(json))!["Review"]!["Verdict"]!.GetValue<string>());
        Assert.Contains(record.Notes, n => n.Contains("Review written to " + md, StringComparison.Ordinal));
    }

    [Fact]
    public void A_new_import_of_a_process_creation_or_injection_function_is_marked()
    {
        NativeImport I(string module, string name) => new(module, name, null, 0, 0, false);
        var added = UpdateReviewer.AddedImports([I("kernel32.dll", "ExitProcess")],
            [I("kernel32.dll", "ExitProcess"), I("KERNEL32.dll", "CreateProcessW"), I("kernel32.dll", "WriteProcessMemory"), I("user32.dll", "MessageBoxW")]);
        Assert.Equal([("KERNEL32.dll!CreateProcessW", "process creation"), ("kernel32.dll!WriteProcessMemory", "injection"), ("user32.dll!MessageBoxW", null)],
            added.Select(x => (x.Name, x.Concern)));
    }

    [Fact]
    public void A_different_signer_is_new_and_the_same_signer_with_a_renewed_certificate_is_not()
    {
        var a = new CertificateInfo(true, "Vendor A", Thumbprint: "11", DigestMatches: true);
        Assert.Equal("new_signer", UpdateReviewer.Signer(a, a with { Signer = "Vendor B" }).Change);
        var renewed = UpdateReviewer.Signer(a, a with { Thumbprint = "22" });
        Assert.Equal("same_signer", renewed.Change);
        Assert.Contains("thumbprint", renewed.Detail, StringComparison.Ordinal);
        Assert.Equal("signature_lost", UpdateReviewer.Signer(a, a with { DigestMatches = false }).Change);
        Assert.Equal("signed", UpdateReviewer.Signer(new CertificateInfo(false), a).Change);
    }

    [Fact]
    public void An_unreadable_signature_or_a_missing_PE_is_unknown_not_unsigned()
    {
        Assert.Equal("unknown", UpdateReviewer.Signer(new CertificateInfo(true, Problem: "signature unreadable: x"), new CertificateInfo(false)).Change);
        Assert.Equal("unknown", UpdateReviewer.Signer(null, new CertificateInfo(false)).Change);
    }

    [Fact]
    public void A_build_that_is_not_a_PE_image_holds_on_each_unread_section()
    {
        var review = UpdateReviewer.Review(new ReviewSources("a", "b", null, null, [], [], [], [], [], [], null, null, []), default);
        Assert.Equal("hold", review.Verdict);
        Assert.All(review.Holds, h => Assert.Equal("unread_section", h.Id));
        Assert.Equal(3, review.Holds.Count);
        Assert.Equal(["embedded files", "imports", "signer", "version resource"], review.Sections.Where(x => x.Contains(": unknown", StringComparison.Ordinal)).Select(x => x[..x.IndexOf(':')]).Order());
    }

    [Fact]
    public void A_streamed_build_is_unknown_for_hosts()
    {
        var streamed = new[] { "The image is streamed (70,000,000 bytes): its version resource, imports and strings were not read." };
        var review = UpdateReviewer.Review(new ReviewSources("a", "b", null, null, [], [], [], [], [], streamed, null, null, []), default);
        Assert.Contains(review.Sections, x => x.StartsWith("hosts: unknown", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ReviewPath_without_view_review_is_refused()
    {
        using var h = new NativeBuildUpdateTests.Harness();
        var tools = new NativeDiffTools(h.Env.Workspace, h.Code, inspection: new InspectionService(h.Env.Workspace));
        var ex = await Assert.ThrowsAsync<ToolError>(() => tools.CompareNativeImages("a", "b", reviewPath: "x.md"));
        Assert.Contains("applies to view=review", ex.Message, StringComparison.Ordinal);
    }
}
