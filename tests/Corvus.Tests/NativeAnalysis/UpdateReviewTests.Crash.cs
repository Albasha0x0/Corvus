using Corvus.Core;
using Corvus.Services;
using Corvus.Services.Analysis;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>compare_native_images view=review with crash text: each native frame is placed in the new build as changed, added, unchanged or unknown.</summary>
public sealed partial class UpdateReviewTests
{
    private const uint NewStamp = OldStamp + 1, Padding = 0x10B0;

    private static string Event(string module, uint stamp, uint offset) =>
        $"Faulting application name: app.exe, version: 1.0.0.0, time stamp: 0x{stamp:x8}\n" +
        $"Faulting module name: {module}, version: 1.0.0.0, time stamp: 0x{stamp:x8}\n" +
        "Exception code: 0xc0000005\n" + $"Fault offset: 0x{offset:x16}\n";

    // The old build has Grown (0x1000, 6 bytes) and Steady (0x1040); the new build grows the first and adds a function at 0x1080.
    private static Task<(NativeDiffTools.NativeComparison Record, string Text)> Crash(string crash, uint oldStamp = OldStamp, uint newStamp = NewStamp) =>
        Compare(Image(oldStamp), Image(newStamp, new Options { Grow = true, Function = true }), injected: true, crashText: crash);

    private static IReadOnlyList<CrashFrame> FramesOf(NativeDiffTools.NativeComparison record) => Of(record).Crash!.Frames;

    [Fact]
    public async Task Ten_crash_points_in_a_changed_function_are_each_named_and_marked_changed()
    {
        var (record, _) = await Crash(string.Concat(Enumerable.Range(0, 10).Select(i => Event("new.dll", NewStamp, 0x1000 + (uint)i))));
        var frames = FramesOf(record);
        Assert.Equal(10, frames.Count);
        for (int i = 0; i < 10; i++)
        {
            Assert.Equal("changed", frames[i].Class);
            Assert.Equal(i == 0 ? "Grown+0x0" : $"Grown+0x{i:X}", frames[i].Function);
            Assert.Equal(".text", frames[i].Section);
        }
        Assert.Equal("0xC0000005", Of(record).Crash!.ExceptionCode);
    }

    [Fact]
    public async Task A_crash_in_a_function_the_update_left_alone_is_marked_unchanged()
    {
        var (record, _) = await Crash(Event("new.dll", NewStamp, 0x1044));
        var frame = Assert.Single(FramesOf(record));
        Assert.Equal(("unchanged", "Steady+0x4"), (frame.Class, frame.Function));
    }

    [Fact]
    public async Task A_crash_in_a_function_only_the_new_build_has_is_marked_added()
    {
        var (record, _) = await Crash(Event("new.dll", NewStamp, 0x1084));
        var frame = Assert.Single(FramesOf(record));
        Assert.Equal("added", frame.Class);
        Assert.Equal(0x1084u, Convert.ToUInt32(frame.Offset, 16));
    }

    [Fact]
    public async Task Crash_text_from_a_third_build_is_unknown_and_names_both_time_stamps()
    {
        var (record, _) = await Crash(Event("new.dll", 0x12345678, 0x1004));
        var frame = Assert.Single(FramesOf(record));
        Assert.Equal("unknown", frame.Class);
        Assert.Null(frame.Function);
        Assert.Contains("0x12345678", frame.Detail, StringComparison.Ordinal);
        Assert.Contains($"0x{NewStamp:X8}", frame.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Crash_text_from_the_old_build_is_unknown_and_says_so()
    {
        var (record, _) = await Crash(Event("old.dll", OldStamp, 0x1004));
        var frame = Assert.Single(FramesOf(record));
        Assert.Equal("unknown", frame.Class);
        Assert.Contains("the text is from the old build", frame.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Builds_with_one_time_stamp_cannot_be_told_apart_so_a_frame_is_unknown()
    {
        var (record, _) = await Crash(Event("new.dll", OldStamp, 0x1004), newStamp: OldStamp);
        var frame = Assert.Single(FramesOf(record));
        Assert.Equal("unknown", frame.Class);
        Assert.Contains("the same time stamp", frame.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_offset_in_padding_between_functions_is_unknown_and_names_the_section()
    {
        var (record, _) = await Crash(Event("new.dll", NewStamp, Padding));
        var frame = Assert.Single(FramesOf(record));
        Assert.Equal(("unknown", ".text", null), (frame.Class, frame.Section, frame.Function));
        Assert.Contains("outside any known function", frame.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_offset_in_a_data_section_is_unknown_and_not_code()
    {
        var (record, _) = await Crash(Event("new.dll", NewStamp, 0x2004));
        var frame = Assert.Single(FramesOf(record));
        Assert.Equal(("unknown", ".rdata"), (frame.Class, frame.Section));
        Assert.Contains("not code", frame.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_offset_past_the_end_of_the_image_is_unknown()
    {
        var (record, _) = await Crash(Event("new.dll", NewStamp, 0x7FFF0000));
        var frame = Assert.Single(FramesOf(record));
        Assert.Equal("unknown", frame.Class);
        Assert.Contains("past the end", frame.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_frame_in_a_module_with_no_build_given_is_unknown_and_names_the_module()
    {
        var (record, _) = await Crash(Event("other.dll", NewStamp, 0x1004));
        var frame = Assert.Single(FramesOf(record));
        Assert.Equal(("unknown", "other.dll"), (frame.Class, frame.Module));
        Assert.Contains("no build given for other.dll", frame.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_frame_without_a_time_stamp_in_the_text_is_unknown_and_not_resolved()
    {
        var (record, _) = await Crash("00 000000a1`2b4ff6c8 00007ff6`1234abcd new+0x1004\n");
        var frame = Assert.Single(FramesOf(record));
        Assert.Equal("unknown", frame.Class);
        Assert.Null(frame.Function);
        Assert.Contains("no time stamp", frame.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Frames_of_mixed_classes_are_counted_in_a_crash_section_that_leaves_the_verdict_alone()
    {
        var (record, text) = await Crash(Event("new.dll", NewStamp, 0x1004) + Event("new.dll", NewStamp, 0x1044) + Event("new.dll", NewStamp, 0x1084) + Event("new.dll", 1, 0x1004));
        var review = Of(record);
        Assert.Contains("crash: read, 4 frame(s): 1 changed, 1 added, 1 unchanged, 1 unknown", string.Join('\n', review.Sections), StringComparison.Ordinal);
        Assert.Contains("crash changed: new.dll+0x1004 Grown+0x4", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_saved_report_lists_the_crash_frames()
    {
        using var dir = new TempDir();
        var md = dir.File("review.md");
        await Compare(Image(OldStamp), Image(NewStamp, new Options { Grow = true }), md, crashText: Event("new.dll", NewStamp, 0x1004));
        Assert.Contains("## Crash frames (1)", File.ReadAllText(md), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_module_name_with_a_line_separator_reads_as_one_escaped_line_in_the_head_and_the_report()
    {
        using var dir = new TempDir();
        var md = dir.File("review.md");
        var (_, head) = await Compare(Image(OldStamp), Image(NewStamp), md, crashText: Event("a\u2028<b>.dll", NewStamp, 0x1004));
        Assert.DoesNotContain('\u2028', head);
        Assert.Contains("a <b>.dll", head, StringComparison.Ordinal);
        var report = File.ReadAllText(md);
        Assert.DoesNotContain('\u2028', report);
        Assert.Contains(@"a \<b\>.dll", report, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Crash_text_over_the_limit_is_refused_with_the_limit()
    {
        using var h = new NativeBuildUpdateTests.Harness();
        var tools = new NativeDiffTools(h.Env.Workspace, h.Code, inspection: new InspectionService(h.Env.Workspace));
        var ex = await Assert.ThrowsAsync<ToolError>(() => tools.CompareNativeImages("a", "b", view: "review", crashText: new string('x', StackTextService.MaxTextChars + 1)));
        Assert.Equal(ErrorCode.LimitExceeded, ex.Code);
        Assert.Contains("crashText", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("review", "x", "y", "not both")]
    [InlineData("pairs", "x", null, "apply to view=review")]
    [InlineData("review", "just some words\nand a line\n", null, "no native frame")]
    [InlineData("review", "   at App.Program.Main() in Program.cs:line 3\n", null, "managed frames only")]
    public async Task Bad_crash_input_is_refused_before_the_builds_are_matched(string view, string? text, string? path, string message)
    {
        using var h = new NativeBuildUpdateTests.Harness();
        var tools = new NativeDiffTools(h.Env.Workspace, h.Code, inspection: new InspectionService(h.Env.Workspace));
        var ex = await Assert.ThrowsAsync<ToolError>(() => tools.CompareNativeImages("a", "b", view: view, crashText: text, crashPath: path));
        Assert.Equal(ErrorCode.InvalidArgument, ex.Code);
        Assert.Contains(message, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_review_with_crash_text_has_the_verdict_and_holds_of_the_same_review_without_it()
    {
        var host = new Options { Strings = ["http://added.example.net/update"] };
        var (plain, _) = await Compare(Image(OldStamp), Image(NewStamp, host));
        var (withCrash, _) = await Compare(Image(OldStamp), Image(NewStamp, host), crashText: Event("new.dll", NewStamp, 0x1000));
        Assert.Equal("hold", Of(plain).Verdict);
        Assert.Equal(Of(plain).Verdict, Of(withCrash).Verdict);
        Assert.Equal(Of(plain).Holds, Of(withCrash).Holds);
        Assert.Null(Of(plain).Crash);
    }

    [Fact]
    public async Task Frames_past_the_cap_are_counted_and_the_section_says_how_many_were_placed()
    {
        var (record, text) = await Crash(string.Concat(Enumerable.Repeat("new+0x1004\n", CrashLocatorCap + 50)));
        var crash = Of(record).Crash!;
        Assert.Equal((CrashLocatorCap + 50, CrashLocatorCap), (crash.Total, crash.Frames.Count));
        var section = Assert.Single(Of(record).Sections, x => x.StartsWith("crash:", StringComparison.Ordinal));
        Assert.Contains($"crash: partial, {CrashLocatorCap + 50} frame(s), first {CrashLocatorCap} placed: 0 changed, 0 added, 0 unchanged, {CrashLocatorCap} unknown", section, StringComparison.Ordinal);
        Assert.Contains(crash.Notes, n => n.Contains($"the limit is {CrashLocatorCap} frames", StringComparison.Ordinal));
        Assert.Contains("first 200 placed", text, StringComparison.Ordinal);
    }

    private const int CrashLocatorCap = 200;

    [Fact]
    public async Task A_crash_file_over_8_MiB_is_read_from_its_tail()
    {
        using var dir = new TempDir();
        var file = dir.File("crash.txt");
        var line = new string('x', 1023) + "\n";
        File.WriteAllText(file, string.Concat(Enumerable.Repeat(line, 9 * 1024)) + Event("new.dll", NewStamp, 0x1004));
        var (record, _) = await Compare(Image(OldStamp), Image(NewStamp, new Options { Grow = true }), crashPath: file);
        var crash = Of(record).Crash!;
        Assert.Equal("changed", Assert.Single(crash.Frames).Class);
        Assert.Contains(crash.Notes, n => n.Contains("only its last 8 MiB were read", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("0x5F8A1B2D", "1004")]
    [InlineData("0x5f8a1b2d", "0x1004")]
    [InlineData("0x00005f8a1b2d", "0X1004")]
    public async Task A_time_stamp_in_any_case_or_with_leading_zeros_and_an_offset_with_or_without_0x_are_the_same_numbers(string stamp, string offset)
    {
        var raw = $"Faulting application name: app.exe, version: 1.0.0.0, time stamp: {stamp}\nFaulting module name: new.dll, version: 1.0.0.0, time stamp: {stamp}\nException code: 0xc0000005\nFault offset: {offset}\n";
        var (record, _) = await Crash(raw);
        var frame = Assert.Single(FramesOf(record));
        Assert.Equal(("changed", "Grown+0x4"), (frame.Class, frame.Function));
    }

    [Fact]
    public async Task A_zero_time_stamp_is_no_time_stamp()
    {
        var (record, _) = await Crash(Event("new.dll", 0, 0x1004));
        var frame = Assert.Single(FramesOf(record));
        Assert.Equal("unknown", frame.Class);
        Assert.Contains("no time stamp of its own", frame.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_stack_frame_does_not_take_the_time_stamp_of_an_event_in_the_same_text()
    {
        // The last frame is a return address at the end of Steady; it is not placed in Steady or anywhere else.
        var (record, _) = await Crash(Event("new.dll", NewStamp, 0x1004) + "00 000000a1`2b4ff6c8 00007ff6`1234abcd new+0x1004\n01 000000a1`2b4ff6c8 00007ff6`1234abcd new+0x1049\n");
        var frames = FramesOf(record);
        Assert.Equal(["changed", "unknown", "unknown"], frames.Select(f => f.Class));
        Assert.All(frames.Skip(1), f =>
        {
            Assert.Null(f.Function);
            Assert.Contains("no time stamp of its own", f.Detail, StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task An_empty_crashText_is_refused_even_with_a_crashPath()
    {
        using var h = new NativeBuildUpdateTests.Harness();
        var tools = new NativeDiffTools(h.Env.Workspace, h.Code, inspection: new InspectionService(h.Env.Workspace));
        var ex = await Assert.ThrowsAsync<ToolError>(() => tools.CompareNativeImages("a", "b", view: "review", crashText: "", crashPath: "x.txt"));
        Assert.Equal(ErrorCode.InvalidArgument, ex.Code);
        Assert.Contains("crashText is empty", ex.Message, StringComparison.Ordinal);
    }
}
