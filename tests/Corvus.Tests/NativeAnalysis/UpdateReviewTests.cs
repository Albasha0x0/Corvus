using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Pe;
using Corvus.Services.Analysis;
using Corvus.Services.Analysis.Hunts;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>compare_native_images view=review over two self-built builds: what the new build adds and the pass or hold verdict.</summary>
public sealed class UpdateReviewTests
{
    private const uint Name = 0x1000, Other = 0x1040, Injected = 0x1080, OldStamp = 0x5F8A1B2C;

    private static readonly (string, string[])[] Basic = [("kernel32.dll", ["ExitProcess"])];

    private sealed record Options
    {
        public bool Function { get; init; }
        public bool Grow { get; init; }
        public (string, string[])[] Imports { get; init; } = Basic;
        public string[] Strings { get; init; } = [];
        public int Filler { get; init; }
        public string? Wide { get; init; }
        public int WidePad { get; init; }
        public byte[]? Inner { get; init; }
        public byte[]? Random { get; init; }
    }

    private static byte[] Image(uint stamp, Options? o = null)
    {
        o ??= new Options();
        var image = LinkedImages.Build("host.dll", [], o.Imports, _ =>
        {
            var code = Enumerable.Repeat((byte)0xCC, 0xC0).ToArray();
            byte[] first = o.Grow ? [0x31, 0xC0, 0x85, 0xC9, 0x74, 0x03, 0x83, 0xC0, 0x05, 0xC3] : [0x31, 0xC0, 0x83, 0xC0, 0x05, 0xC3];
            first.CopyTo(code, 0);
            new byte[] { 0xB8, 0x01, 0, 0, 0, 0x83, 0xC0, 0x22, 0xC3 }.CopyTo(code, 0x40);
            if (o.Function) new byte[] { 0x31, 0xC0, 0x83, 0xC0, 0x09, 0x83, 0xE8, 0x02, 0xC3 }.CopyTo(code, 0x80);
            return code;
        }, (blob, _) =>
        {
            blob.Ascii(@"\\.\pipe\shared-pipe");
            for (int i = 0; i < o.Filler; i++) blob.Ascii($"filler{i:D5}.zz");
            foreach (var s in o.Strings) blob.Ascii(s);
            if (o.Wide != null) { blob.Align(2); blob.Zero(o.WidePad); blob.Utf16(o.Wide); blob.U16(0); }
            if (o.Random != null) { blob.Align(16); blob.Bytes(o.Random); }
            if (o.Inner != null) { blob.Align(16); blob.Bytes(o.Inner); }
            return [];
        });
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(PeBuilder.PeOffset + 8), stamp);
        return image;
    }

    private static (string, string[])[] Imports(params (string Module, string Name)[] added) =>
        [.. Basic, .. added.GroupBy(a => a.Module).Select(g => (g.Key, g.Select(a => a.Name).ToArray()))];

    private static byte[] RandomWith(string text)
    {
        var data = new byte[16_384];
        new Random(7).NextBytes(data);
        System.Text.Encoding.ASCII.GetBytes(text).CopyTo(data, 8_192);
        return data;
    }

    private static async Task<(NativeDiffTools.NativeComparison Record, string Text)> Compare(byte[] before, byte[] after, string? reviewPath = null, bool injected = false)
    {
        using var h = new NativeBuildUpdateTests.Harness();
        var (o, oi) = await h.Load(before, "old.dll", [Name, Other]);
        var (n, ni) = await h.Load(after, "new.dll", (injected ? [Name, Other, Injected] : [Name, Other]));
        foreach (var (native, index) in new[] { (o, oi), (n, ni) })
        {
            h.Code.Annotations(native).SetMany([(Name, "Grown"), (Other, "Steady")], []);
            index.SetUserName(Name, "Grown");
            index.SetUserName(Other, "Steady");
        }
        var tools = new NativeDiffTools(h.Env.Workspace, h.Code, inspection: new InspectionService(h.Env.Workspace));
        return await BuildToolCalls.Collected<NativeDiffTools.NativeComparison>(() => tools.CompareNativeImages(o.Id, n.Id, view: "review", reviewPath: reviewPath));
    }

    private static UpdateReview Of(NativeDiffTools.NativeComparison record) => record.Review!;

    [Fact]
    public async Task An_added_function_import_and_host_are_named_and_the_verdict_is_hold()
    {
        var (record, text) = await Compare(Image(OldStamp),
            Image(OldStamp + 1, new Options { Function = true, Imports = Imports(("added-lib.dll", "Go")), Strings = ["http://added.example.net/update"] }), injected: true);
        var review = Of(record);
        Assert.Equal("hold", review.Verdict);
        Assert.Contains(review.Added, f => f.NewAddress!.EndsWith("1080", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(review.Imports, i => i.Name == "added-lib.dll!Go" && i.Concern == null);
        Assert.Contains(review.Hosts, x => x.Value == "added.example.net");
        Assert.Contains(review.Holds, x => x.Id == "new_network_host");
        Assert.DoesNotContain(review.Holds, x => x.Id is "new_process_import" or "new_signer" or "signature_lost");
        Assert.Contains("Verdict: hold.", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_rebuild_with_only_a_new_time_stamp_passes_and_the_pass_line_names_what_it_does_not_cover()
    {
        var (record, text) = await Compare(Image(OldStamp), Image(OldStamp + 1));
        var review = Of(record);
        Assert.Equal("pass", review.Verdict);
        Assert.Empty(review.Holds);
        Assert.Equal((0, 0), (review.AddedTotal, review.ChangedTotal));
        Assert.Empty(review.Imports);
        Assert.Contains("this does not show the update is safe", text, StringComparison.Ordinal);
        Assert.Contains("an added or changed function does not hold", text, StringComparison.Ordinal);
        Assert.Contains("encoded or compressed inside the build are not read", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_build_with_its_signature_removed_is_a_hold()
    {
        var (record, _) = await Compare(SideloadTests.Signed(Image(OldStamp)), Image(OldStamp));
        var review = Of(record);
        Assert.Equal("hold", review.Verdict);
        Assert.Equal(["signature_lost"], review.Holds.Select(x => x.Id));
        Assert.Equal("signature_lost", review.Signer.Change);
    }

    [Fact]
    public async Task Two_byte_identical_signed_builds_pass()
    {
        var signed = SideloadTests.Signed(Image(OldStamp));
        var (record, _) = await Compare(signed, signed);
        Assert.Equal("pass", Of(record).Verdict);
        Assert.Equal("same_signer", Of(record).Signer.Change);
    }

    [Fact]
    public async Task An_added_PE_image_is_a_hold_with_its_offset_and_SHA256()
    {
        var inner = LinkedImages.Build("inner.dll", [], Basic, _ => Enumerable.Repeat((byte)0xCC, 0x40).ToArray());
        var (record, _) = await Compare(Image(OldStamp), Image(OldStamp, new Options { Inner = inner }));
        var embedded = Assert.Single(Of(record).Embedded);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(inner)), embedded.Sha256);
        Assert.Contains(Of(record).Holds, x => x.Id == "new_embedded_executable");
    }

    [Fact]
    public async Task An_embedded_PE_image_that_differs_only_in_time_stamp_and_checksum_is_not_new()
    {
        var inner = LinkedImages.Build("inner.dll", [], Basic, _ => Enumerable.Repeat((byte)0xCC, 0x40).ToArray());
        var rebuilt = (byte[])inner.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(rebuilt.AsSpan(PeBuilder.PeOffset + 8), 0x12345678);
        BinaryPrimitives.WriteUInt32LittleEndian(rebuilt.AsSpan(PeBuilder.PeOffset + 24 + 64), 0x0BADF00D);
        var (record, _) = await Compare(Image(OldStamp, new Options { Inner = inner }), Image(OldStamp + 1, new Options { Inner = rebuilt }));
        Assert.Empty(Of(record).Embedded);
        Assert.Equal("pass", Of(record).Verdict);
    }

    [Fact]
    public async Task An_image_nested_in_an_added_image_is_listed_too()
    {
        var deep = LinkedImages.Build("deep.dll", [], Basic, _ => Enumerable.Repeat((byte)0xCC, 0x40).ToArray());
        var outer = LinkedImages.Build("outer.dll", [], Basic, _ => Enumerable.Repeat((byte)0xCC, 0x40).ToArray(), (blob, _) => { blob.Align(16); blob.Bytes(deep); return []; });
        var (record, _) = await Compare(Image(OldStamp), Image(OldStamp, new Options { Inner = outer }));
        Assert.Equal(2, Of(record).Embedded.Count);
        Assert.Contains(Of(record).Embedded, e => e.Sha256 == Convert.ToHexStringLower(SHA256.HashData(deep)));
    }

    [Fact]
    public void A_scan_stopped_at_the_image_bound_makes_embedded_files_partial_and_holds_when_the_old_build_was_not()
    {
        var inner = LinkedImages.Build("inner.dll", [], Basic, _ => Enumerable.Repeat((byte)0xCC, 0x40).ToArray());
        var many = Image(OldStamp, new Options { Inner = [.. inner, .. inner, .. LinkedImages.Build("two.dll", [], Basic, _ => Enumerable.Repeat((byte)0xCC, 0x50).ToArray())] });
        var plain = Image(OldStamp);
        var (o, n) = (PeFile.FromBytes(plain, "o.dll"), PeFile.FromBytes(many, "n.dll"));
        var review = UpdateReviewer.Review(Sources(UpdateReviewer.Read(o, plain, [], 0, 0, default), UpdateReviewer.Read(n, many, [], 0, 0, default, maxImages: 1)), default);
        Assert.Contains(review.Sections, x => x.StartsWith("embedded files: partial", StringComparison.Ordinal));
        Assert.Contains(review.Holds, h => h.Id == "unread_section" && h.Evidence.StartsWith("embedded files", StringComparison.Ordinal));
    }

    private static ReviewSources Sources(BuildReading old, BuildReading current, int matched = 1) => new("old", "new", old, current, matched, [], [], []);

    [Fact]
    public async Task A_changed_function_carries_a_diff_reference_with_its_old_address()
    {
        var (record, _) = await Compare(Image(OldStamp), Image(OldStamp, new Options { Grow = true }));
        var changed = Assert.Single(Of(record).Changed);
        Assert.EndsWith("1000", changed.OldAddress, StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith("address=" + changed.OldAddress, changed.Diff, StringComparison.Ordinal);
        Assert.StartsWith("diff_function oldImage=", changed.Diff, StringComparison.Ordinal);
        Assert.Equal("pass", Of(record).Verdict);
    }

    [Fact]
    public void No_matched_function_pair_is_unknown_and_holds()
    {
        var pe = Image(OldStamp);
        var file = PeFile.FromBytes(pe, "a.dll");
        var read = UpdateReviewer.Read(file, pe, [], 0, 0, default);
        var review = UpdateReviewer.Review(Sources(read, read, matched: 0), default);
        Assert.Equal("hold", review.Verdict);
        Assert.Contains(review.Sections, x => x.StartsWith("functions: unknown", StringComparison.Ordinal));
        Assert.Equal("pass", UpdateReviewer.Review(Sources(read, read), default).Verdict);
    }

    [Fact]
    public async Task ReviewPath_writes_Markdown_and_a_json_extension_writes_JSON()
    {
        using var dir = new TempDir();
        var (md, json) = (dir.File("review.md"), dir.File("review.json"));
        var host = new Options { Strings = ["http://added.example.net/update"] };
        var (record, _) = await Compare(Image(OldStamp), Image(OldStamp + 1, host), md);
        await Compare(Image(OldStamp), Image(OldStamp + 1, host), json);
        var text = File.ReadAllText(md);
        Assert.StartsWith("# Update review:", text, StringComparison.Ordinal);
        Assert.Contains("new_network_host", text, StringComparison.Ordinal);
        Assert.Equal("hold", System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(json))!["Review"]!["Verdict"]!.GetValue<string>());
        Assert.Contains(record.Notes, n => n.Contains("Review written to " + md, StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_host_after_thousands_of_earlier_strings_is_still_found()
    {
        var (record, _) = await Compare(Image(OldStamp, new Options { Filler = 5_100 }),
            Image(OldStamp + 1, new Options { Filler = 5_100, Strings = ["http://late.example.net/x"] }));
        Assert.Contains(Of(record).Hosts, h => h.Value == "late.example.net");
        Assert.Equal("hold", Of(record).Verdict);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public async Task A_UTF16_host_is_found_at_either_file_offset_parity_after_many_ASCII_strings(int pad)
    {
        var (record, _) = await Compare(Image(OldStamp, new Options { Filler = 5_100 }),
            Image(OldStamp + 1, new Options { Filler = 5_100, Wide = "http://wide.example.org/x", WidePad = pad }));
        Assert.Contains(Of(record).Hosts, h => h.Value == "wide.example.org");
    }

    [Fact]
    public async Task A_host_in_a_high_entropy_region_only_the_new_build_has_holds_as_a_partial_read()
    {
        var (record, _) = await Compare(Image(OldStamp, new Options { Random = RandomWith("") }), Image(OldStamp + 1, new Options { Random = RandomWith("http://hidden.example.net/p") }));
        var review = Of(record);
        Assert.Equal("hold", review.Verdict);
        Assert.Contains(review.Holds, h => h.Id == "unread_section" && h.Evidence.StartsWith("hosts is partial", StringComparison.Ordinal));
    }

    [Fact]
    public async Task The_same_high_entropy_region_in_both_builds_is_a_note_and_a_rebuild_still_passes()
    {
        var region = new Options { Random = RandomWith("http://hidden.example.net/p") };
        var (record, _) = await Compare(Image(OldStamp, region), Image(OldStamp + 1, region));
        Assert.Equal("pass", Of(record).Verdict);
        Assert.Contains(Of(record).Sections, x => x.StartsWith("hosts: partial", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("kernel32.dll", "CreateProcessW", "new_process_import")]
    [InlineData("msvcrt.dll", "system", "new_process_import")]
    [InlineData("msvcrt.dll", "_wspawnlp", "new_process_import")]
    [InlineData("ntdll.dll", "NtCreateThreadEx", "new_process_import")]
    [InlineData("ntdll.dll", "NtMapViewOfSection", "new_process_import")]
    [InlineData("kernel32.dll", "VirtualProtectEx", "new_process_import")]
    [InlineData("ordlib.dll", "#17", "new_unnamed_import")]
    public async Task A_new_process_or_injection_or_ordinal_import_holds_through_the_view(string module, string import, string hold)
    {
        var (record, _) = await Compare(Image(OldStamp), Image(OldStamp + 1, new Options { Imports = Imports((module, import)) }));
        Assert.Equal("hold", Of(record).Verdict);
        Assert.Contains(Of(record).Holds, h => h.Id == hold);
    }

    [Fact]
    public async Task A_new_GetProcAddress_import_is_listed_as_a_concern_without_a_hold()
    {
        var (record, _) = await Compare(Image(OldStamp), Image(OldStamp + 1, new Options { Imports = Imports(("kernel32.dll", "GetProcAddress")) }));
        Assert.Contains(Of(record).Imports, i => i.Concern == "dynamic resolution");
        Assert.Equal("pass", Of(record).Verdict);
    }

    [Fact]
    public async Task A_function_moving_to_a_forwarder_library_is_not_a_new_import()
    {
        var (record, _) = await Compare(Image(OldStamp, new Options { Imports = Imports(("kernel32.dll", "CreateProcessW")) }),
            Image(OldStamp + 1, new Options { Imports = Imports(("api-ms-win-core-processthreads-l1-1-0.dll", "CreateProcessW")) }));
        Assert.Empty(Of(record).Imports);
        Assert.Equal("pass", Of(record).Verdict);
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
    public void A_different_subject_or_issuer_is_a_new_signer_and_a_renewed_certificate_is_not()
    {
        var a = new CertificateInfo(true, "Vendor A", "CA One", Thumbprint: "11", DigestMatches: true, SignatureValid: true);
        Assert.Equal("new_signer", UpdateReviewer.Signer(a, a with { Signer = "Vendor B" }).Change);
        var issuer = UpdateReviewer.Signer(a, a with { Issuer = "Vendor A" });
        Assert.Equal("new_signer", issuer.Change);
        Assert.Contains("issuer changed", issuer.Detail, StringComparison.Ordinal);
        var renewed = UpdateReviewer.Signer(a, a with { Thumbprint = "22" });
        Assert.Equal("same_signer", renewed.Change);
        Assert.Contains("renewed", renewed.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void A_new_signature_that_does_not_verify_or_has_no_digest_result_is_signature_lost()
    {
        var a = new CertificateInfo(true, "Vendor A", "CA One", Thumbprint: "11", DigestMatches: true, SignatureValid: true);
        Assert.Equal("signature_lost", UpdateReviewer.Signer(a, a with { SignatureValid = false }).Change);
        Assert.Equal("signature_lost", UpdateReviewer.Signer(a, a with { DigestMatches = false }).Change);
        Assert.Equal("signature_lost", UpdateReviewer.Signer(a, a with { DigestMatches = null }).Change);
    }

    [Fact]
    public void An_unsigned_build_that_gains_a_signature_with_a_bad_digest_is_signature_lost_and_a_shared_defect_is_a_note()
    {
        var bad = new CertificateInfo(true, "Vendor A", "CA One", Thumbprint: "11", DigestMatches: false, SignatureValid: true);
        Assert.Equal("signature_lost", UpdateReviewer.Signer(new CertificateInfo(false), bad).Change);
        var both = UpdateReviewer.Signer(bad, bad);
        Assert.Equal("same_signer", both.Change);
        Assert.Contains("in both builds", both.Detail, StringComparison.Ordinal);
        var good = bad with { DigestMatches = true };
        Assert.Equal("signed", UpdateReviewer.Signer(new CertificateInfo(false), good).Change);
    }

    [Fact]
    public void An_unreadable_signature_or_a_missing_PE_is_unknown_not_unsigned()
    {
        Assert.Equal("unknown", UpdateReviewer.Signer(new CertificateInfo(true, Problem: "signature unreadable: x"), new CertificateInfo(false)).Change);
        Assert.Equal("unknown", UpdateReviewer.Signer(null, new CertificateInfo(false)).Change);
    }

    [Fact]
    public async Task The_CRL_and_time_stamp_URLs_of_a_new_signature_are_not_a_new_host()
    {
        var plain = Image(OldStamp);
        var (record, _) = await Compare(plain, SignedWithCrl(plain));
        Assert.Empty(Of(record).Hosts);
        Assert.DoesNotContain(Of(record).Holds, h => h.Id == "new_network_host");
    }

    private static byte[] SignedWithCrl(byte[] image)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=test signer", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension(["http://crl.example.net/a.crl"]));
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var cms = new SignedCms(new ContentInfo(image));
        cms.ComputeSignature(new CmsSigner(cert) { IncludeOption = X509IncludeOption.EndCertOnly });
        var blob = cms.Encode();
        int at = (image.Length + 7) & ~7, length = (8 + blob.Length + 7) & ~7;
        var result = new byte[at + length];
        image.CopyTo(result, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(at), (uint)(8 + blob.Length));
        BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(at + 4), 0x0200);
        BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(at + 6), 2);
        blob.CopyTo(result, at + 8);
        int entry = PeImage.TryParse(image)!.DirectoryEntryOffset(PeImage.SecurityDirectory);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(entry), (uint)at);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(entry + 4), (uint)length);
        Assert.Contains("crl.example.net", System.Text.Encoding.ASCII.GetString(result), StringComparison.Ordinal);
        return result;
    }

    [Fact]
    public void A_build_that_is_not_a_PE_image_holds_on_each_unread_section()
    {
        var none = UpdateReviewer.Read(null, null, [], 0, 0, default);
        var review = UpdateReviewer.Review(Sources(none, none), default);
        Assert.Equal("hold", review.Verdict);
        Assert.All(review.Holds, h => Assert.Equal("unread_section", h.Id));
        Assert.Equal(["embedded files", "hosts", "imports", "signer", "version resource"],
            review.Sections.Where(x => x.Contains(": unknown", StringComparison.Ordinal)).Select(x => x[..x.IndexOf(':')]).Order());
    }

    [Fact]
    public void Undecoded_functions_in_the_new_build_only_are_partial_and_hold()
    {
        var pe = Image(OldStamp);
        var (o, n) = (PeFile.FromBytes(pe, "o.dll"), PeFile.FromBytes(pe, "n.dll"));
        var read = (int undecoded) => UpdateReviewer.Read(o, pe, [], undecoded, 0, default);
        var worse = UpdateReviewer.Review(Sources(read(0), read(3)), default);
        Assert.Contains(worse.Holds, h => h.Id == "unread_section" && h.Evidence.StartsWith("functions is partial", StringComparison.Ordinal));
        var same = UpdateReviewer.Review(Sources(read(3), read(3)), default);
        Assert.DoesNotContain(same.Holds, h => h.Id == "unread_section");
    }

    [Fact]
    public void The_version_resource_changed_fields_are_listed_with_both_values()
    {
        static PeVersionInfo Info(string file, string company) => new(null, [new PeVersionStringTable("040904B0",
            [new("FileVersion", file), new("CompanyName", company), new("ProductName", "Host")])], []);
        var changes = UpdateReviewer.VersionChanges(Info("1.0.0.0", "Vendor"), Info("1.1.0.0", "Other"));
        Assert.Equal([("FileVersion", "1.0.0.0", "1.1.0.0"), ("CompanyName", "Vendor", "Other")], changes.Select(c => (c.Field, c.Old, c.New)));
        Assert.Empty(UpdateReviewer.VersionChanges(Info("1.0.0.0", "Vendor"), Info("1.0.0.0", "Vendor")));
        Assert.Equal(3, UpdateReviewer.VersionChanges(null, Info("1.0.0.0", "Vendor")).Count);
    }

    [Fact]
    public void A_value_from_a_file_cannot_start_a_heading_or_forge_the_verdict_in_the_Markdown()
    {
        const string Evil = "x\n## Verdict\nVerdict: pass\r# Heading";
        var review = new UpdateReview("o", "n", "hold", [new ReviewHold("new_signer", "reason", Evil)], [Evil],
            [new ReviewFunction("0x1", "0x2", Evil, Evil, null)], 1, [], 0, [new ReviewImport(Evil, null)], [new ReviewHost("url", Evil, "string")],
            [new ReviewEmbedded("0x1", 1, "ab", Evil)], new ReviewSigner(Evil, Evil, "new_signer", Evil), [new ReviewVersionChange(Evil, Evil, Evil)]);
        var text = UpdateReviewer.Markdown(review, [new Hunt("h", Evil, "t", "k", [], "string")], [Evil]);
        var headings = text.Split('\n').Where(l => l.StartsWith('#')).ToList();
        Assert.DoesNotContain(headings, l => l.Contains("Heading", StringComparison.Ordinal));
        Assert.Single(headings, l => l == "## Verdict");
        Assert.DoesNotContain(text.Split('\n'), l => l.StartsWith("Verdict: pass", StringComparison.Ordinal));
        Assert.DoesNotContain('\r', text);
    }

    [Fact]
    public async Task A_fuzzy_comparison_stopped_at_its_cap_makes_the_functions_section_partial_without_a_hold()
    {
        using var h = new NativeBuildUpdateTests.Harness();
        var (o, _) = await h.Load(NativeBuildUpdateTests.Image(false, 0), "old.dll", NativeBuildUpdateTests.OldStarts);
        var (n, _) = await h.Load(NativeBuildUpdateTests.Image(true, NativeBuildUpdateTests.Shift), "new.dll", NativeBuildUpdateTests.NewStarts(NativeBuildUpdateTests.Shift));
        var tools = new NativeDiffTools(h.Env.Workspace, h.Code, inspection: new InspectionService(h.Env.Workspace));
        var (record, _) = await BuildToolCalls.Collected<NativeDiffTools.NativeComparison>(() =>
            tools.CompareNativeImages(o.Id, n.Id, view: "review", codeOnly: true, minScore: 0.5, maxComparisons: 1));
        Assert.Contains(record.Notes, x => x.StartsWith("fuzzy matching stopped", StringComparison.Ordinal));
        Assert.Contains(Of(record).Sections, x => x.StartsWith("functions: partial", StringComparison.Ordinal) && x.Contains("fuzzy matching stopped", StringComparison.Ordinal));
        Assert.DoesNotContain(Of(record).Holds, x => x.Evidence.StartsWith("functions", StringComparison.Ordinal));
    }

    [Fact]
    public void Facts_read_in_part_make_the_hunts_section_partial_with_the_reason_and_no_hold()
    {
        var pe = Image(OldStamp);
        var file = PeFile.FromBytes(pe, "a.dll");
        var read = UpdateReviewer.Read(file, pe, [], 0, 0, default);
        var limits = UpdateHunts.PartialReads(false, true);
        var review = UpdateReviewer.Review(Sources(read, read) with { HuntLimits = limits }, default);
        Assert.Contains(review.Sections, x => x.StartsWith("hunts: partial", StringComparison.Ordinal) && x.Contains("new build's facts are partial", StringComparison.Ordinal));
        Assert.Equal("pass", review.Verdict);
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
