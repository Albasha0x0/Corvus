using Corvus.Core;
using Corvus.Native.Diff;
using Corvus.Tools;
using static Corvus.Tests.NativeBuildUpdateTests;

namespace Corvus.Tests;

/// <summary>One reason vocabulary for the build tools: published, and the same code for the same case from every tool.</summary>
public class MigrationReasonTests
{
    [Fact]
    public void ReasonDocumentIsCurrent()
    {
        var path = Path.Combine(DocsTests.RepoRoot(), "docs", "migration-reasons.md");
        var expected = MigrationReasons.Markdown();
        if (Environment.GetEnvironmentVariable("CORVUS_UPDATE_DOCS") == "1") File.WriteAllText(path, expected);
        Assert.True(File.Exists(path) && File.ReadAllText(path).ReplaceLineEndings("\n") == expected,
            "docs/migration-reasons.md is out of date: run the tests once with CORVUS_UPDATE_DOCS=1");
        Assert.Equal(MigrationReasons.All.Count, MigrationReasons.All.Select(r => r.Code).Distinct().Count());
    }

    [Theory]
    [InlineData("original_bytes_differ: the bytes at 0x10 are 90", ErrorCode.Conflict, "original_bytes_differ")]
    [InlineData("The relocation slot at 0x10 is used by patch #1.", ErrorCode.Conflict, "relocation_slot_unavailable")]
    [InlineData("0x10 is in the middle of an instruction.", ErrorCode.InvalidArgument, "mid_instruction")]
    [InlineData("Patch #2 covers 0x10.", ErrorCode.Conflict, "conflicts_with_existing_patch")]
    [InlineData("nonsense_code: something", ErrorCode.InvalidArgument, "cannot_prepare")]
    public void Patch_refusals_take_one_code(string message, ErrorCode code, string reason) =>
        Assert.Equal(reason, MigrationReasons.PatchRefusal(new ToolError(code, message)));

    [Fact]
    public async Task Names_carry_with_the_same_codes_from_both_tools_and_comments_keep_their_kind()
    {
        using var h = new Harness();
        var (oldN, oldIdx) = await h.Load(Image(false, 0), "old.dll", OldStarts);
        var (newN, _) = await h.Load(Image(true, Shift), "new.dll", NewStarts(Shift));
        var ann = h.Code.Annotations(oldN);
        ann.Apply([(F1, "ReadGlobal"), (F2, "Second"), (F4, "Fourth"), (F5, "Removed")], [(F1 + 6, "adds the bias"), (F2, "boxed note")],
            [(F1, "decompiler note")], kinds: [(F2, "plate")]);
        foreach (var (rva, name) in ann.Names()) oldIdx.SetUserName(rva, name);
        var newAnn = h.Code.Annotations(newN);
        newAnn.SetName(F2 + Shift, "Second");
        newAnn.SetName(F6 + Shift, "Fourth");

        var diff = new NativeDiffTools(h.Env.Workspace, h.Code);
        var migrated = (await diff.CarryNames(oldN.Id, newN.Id, true, 5, 0, null, false, false, default, default)).Items.Select(e => (e.Kind, e.OldAddress, e.Reason)).Order().ToList();
        var updated = (await h.Tools.UpdateToNewBuild(oldN.Id, newN.Id, include: "names")).Items.Where(i => i.Category == "names")
            .Select(i => (i.Kind, i.OldAddress, i.Reason)).Order().ToList();
        Assert.Equal(migrated, updated);
        Assert.All(migrated, m => Assert.True(MigrationReasons.IsKnown(m.Reason), m.Reason));
        Assert.Contains(("name", Va(F2), "same_name"), migrated);
        Assert.Contains(("name", Va(F4), "name_in_use"), migrated);
        Assert.Contains(("name", Va(F5), "function_not_matched"), migrated);

        await diff.CarryNames(oldN.Id, newN.Id, false, 5, 0, null, false, false, default, default);
        Assert.Equal(("boxed note", "plate"), (newAnn.CommentAt(F2 + Shift), newAnn.CommentKindAt(F2 + Shift)));
        Assert.Equal(("adds the bias", null), (newAnn.CommentAt(F1 + Shift + 6), newAnn.CommentKindAt(F1 + Shift + 6)));
        Assert.Equal("decompiler note", newAnn.PseudoCommentAt(F1 + Shift));
    }
}
