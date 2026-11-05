using System.Buffers.Binary;
using Corvus.Core;
using Corvus.Native.Code;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>Application Error event 1000 resolved to a function in the build named by its module time stamp.</summary>
public sealed class EventLogCrashTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _ws = new();
    private readonly NativeCodeService _code;

    public EventLogCrashTests()
    {
        _code = new NativeCodeService(_ws, new ServerOptions { BackgroundIndexing = false }, annotations: new Native.Annotations.AnnotationStore(_dir.File("ann")));
    }

    public void Dispose()
    {
        _ws.Dispose();
        _dir.Dispose();
    }

    // The same image with its PE time stamp replaced.
    private string Build(string name, uint? stamp)
    {
        var bytes = SyntheticCrash.FileImage();
        if (stamp is { } s)
        {
            int pe = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3C));
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(pe + 8), s);
        }
        var path = _dir.File(name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private Task<StackTextService.SymbolizedStack> Run(string text) =>
        new StackTextService(_ws, _code).Symbolize(text, null, "eventlog", null, null, 0, 50, default);

    private static string Description(string stamp) => $"""
        Faulting application name: app.exe, version: 1.0.0.0, time stamp: 0x65000000
        Faulting module name: synth.dll, version: 1.2.3.4, time stamp: 0x{stamp}
        Exception code: 0xc0000005
        Fault offset: 0x0000000000001085
        """;

    private static string EventData(string stamp) => $"""
        <EventData>
          <Data Name="AppName">app.exe</Data>
          <Data Name="AppVersion">1.0.0.0</Data>
          <Data Name="AppTimeStamp">65000000</Data>
          <Data Name="ModuleName">synth.dll</Data>
          <Data Name="ModuleVersion">1.2.3.4</Data>
          <Data Name="ModuleTimeStamp">{stamp}</Data>
          <Data Name="ExceptionCode">c0000005</Data>
          <Data Name="FaultingOffset">0000000000001085</Data>
          <Data Name="ProcessId">0x1a2b</Data>
        </EventData>
        """;

    [Fact]
    public async Task A_fault_offset_resolves_to_its_function_in_the_same_build()
    {
        _ws.LoadAny(Build("synth.dll", null));
        var stamp = _ws.Read(() => _ws.Natives.Single().Pe!.Coff.TimeDateStamp);
        var f = Assert.Single((await Run(Description($"{stamp:x8}"))).Items);
        Assert.Equal("Big+0x5", f.Resolved);
        Assert.Equal("match", f.BuildCheck);
        Assert.Equal("same build; function starts at 0x1080, offset 0x5", f.BuildDetail);
    }

    [Fact]
    public async Task A_rebuilt_copy_is_reported_as_a_different_build_with_both_stamps()
    {
        _ws.LoadAny(Build("synth.dll", 0x11223344));
        var f = Assert.Single((await Run(Description("55667788"))).Items);
        Assert.Equal("Big+0x5", f.Resolved);
        Assert.Equal("mismatch", f.BuildCheck);
        Assert.StartsWith("different build", f.BuildDetail);
        Assert.Contains("0x55667788", f.BuildDetail);
        Assert.Contains("0x11223344", f.BuildDetail);
    }

    [Fact]
    public async Task A_module_without_a_loaded_image_is_reported_as_not_loaded()
    {
        var f = Assert.Single((await Run(Description("11223344"))).Items);
        Assert.Equal("module not loaded", f.BuildDetail);
        Assert.Null(f.Resolved);
    }

    [Fact]
    public async Task EventData_gives_the_result_of_the_rendered_description()
    {
        _ws.LoadAny(Build("synth.dll", 0x11223344));
        var text = await Run(Description("11223344"));
        var xml = await Run(EventData("11223344"));
        var a = Assert.Single(text.Items);
        var b = Assert.Single(xml.Items);
        Assert.Equal(a.Resolved, b.Resolved);
        Assert.Equal(a.BuildDetail, b.BuildDetail);
        Assert.Equal(text.Exception!.Code, xml.Exception!.Code);
    }

    // Rendered XML (wevtutil /f:RenderedXml) holds the EventData and the
    // description of the same event.
    [Fact]
    public async Task Rendered_XML_with_EventData_and_its_message_is_one_event()
    {
        _ws.LoadAny(Build("synth.dll", 0x11223344));
        var xml = $"<Event>{EventData("11223344")}<RenderingInfo Culture='en-US'><Message>{Description("11223344")}</Message></RenderingInfo></Event>";
        var f = Assert.Single((await Run(xml)).Items);
        Assert.Equal("Big+0x5", f.Resolved);
    }

    [Fact]
    public async Task A_description_flattened_to_one_line_is_read()
    {
        _ws.LoadAny(Build("synth.dll", 0x11223344));
        var flat = string.Join(' ', Description("11223344").Split('\n').Select(l => l.Trim()));
        var f = Assert.Single((await Run(flat)).Items);
        Assert.Equal("Big+0x5", f.Resolved);
        Assert.Equal("same build; function starts at 0x1080, offset 0x5", f.BuildDetail);
    }

    [Fact]
    public async Task Function_ranges_are_exact_and_half_open()
    {
        _ws.LoadAny(Build("synth.dll", 0x11223344));
        var native = _ws.Read(() => _ws.Natives.Single());
        var index = await _code.Index(native, null, default);
        var ranges = FunctionRanges.Of(native, index, ["Big", "Crash", "Missing"]);
        Assert.Equal(2, ranges.Count);
        Assert.Equal(new FunctionRange("synth.dll", 0x11223344, "Big", 0x1080, 0x10A4), ranges[0]);
        Assert.Equal(new FunctionRange("synth.dll", 0x11223344, "Crash", 0x1000, 0x100D), ranges[1]);
    }

    [Fact]
    public async Task A_missing_module_time_stamp_is_labelled_an_unknown_build()
    {
        _ws.LoadAny(Build("synth.dll", 0x11223344));
        var xml = EventData("11223344").Replace("<Data Name=\"ModuleTimeStamp\">11223344</Data>", "");
        var f = Assert.Single((await Run(xml)).Items);
        Assert.Equal("Big+0x5", f.Resolved);
        Assert.StartsWith("unknown build", f.BuildDetail);
    }

    [Fact]
    public async Task An_offset_past_the_image_names_the_build_and_both_stamps()
    {
        _ws.LoadAny(Build("synth.dll", 0x11223344));
        var text = Description("55667788").Replace("0000000000001085", "000000007FFF0000");
        var f = Assert.Single((await Run(text)).Items);
        Assert.Equal("mismatch", f.BuildCheck);
        Assert.StartsWith("different build", f.BuildDetail);
        Assert.Contains("0x55667788", f.BuildDetail);
        Assert.Contains("0x11223344", f.BuildDetail);
    }

    [Fact]
    public async Task EventData_entities_are_decoded_and_a_0x_time_stamp_is_read()
    {
        _ws.LoadAny(Build("a&b.dll", 0x11223344));
        var xml = EventData("0x11223344").Replace("synth.dll", "a&amp;b.dll");
        var f = Assert.Single((await Run(xml)).Items);
        Assert.Equal("Big+0x5", f.Resolved);
        Assert.StartsWith("same build", f.BuildDetail);
    }

    [Fact]
    public async Task Each_event_of_a_text_is_resolved()
    {
        _ws.LoadAny(Build("synth.dll", 0x11223344));
        string Event(string offset) => Description("11223344").Replace("0000000000001085", offset);
        var text = await Run(Event("0000000000001085") + "\n\n" + Event("0000000000001005") + "\n\n" + Event("0000000000001020"));
        Assert.Equal(["Big+0x5", "Crash+0x5", "Outer"], text.Items.Select(i => i.Resolved));
        Assert.Equal(0, text.UnrecognizedLines);
        var xml = await Run(EventData("11223344") + "\n" + EventData("11223344").Replace("0000000000001085", "0000000000001005"));
        Assert.Equal(["Big+0x5", "Crash+0x5"], xml.Items.Select(i => i.Resolved));
        Assert.Equal(0, xml.UnrecognizedLines);
    }

    [Fact]
    public async Task Events_past_the_limit_are_counted_in_a_note()
    {
        _ws.LoadAny(Build("synth.dll", 0x11223344));
        var one = Description("11223344");
        var result = await Run(string.Join("\n\n", Enumerable.Repeat(one, StackTextFormats.MaxEvents + 3)));
        Assert.Equal(StackTextFormats.MaxEvents, result.Frames);
        Assert.Contains(result.Notes, n => n.StartsWith("3 further events", StringComparison.Ordinal));
    }

    // Field test 5: the x86 event resolved against the x64 image of the same name.
    [Fact]
    public async Task The_image_with_the_events_time_stamp_is_preferred_among_images_of_one_name()
    {
        Directory.CreateDirectory(_dir.File("x64"));
        Directory.CreateDirectory(_dir.File("x86"));
        _ws.LoadAny(Build(Path.Combine("x64", "synth.dll"), 0x11223344));
        _ws.LoadAny(Build(Path.Combine("x86", "synth.dll"), 0x55667788));
        var second = _ws.Read(() => _ws.Natives.Last().Id);
        var f = Assert.Single((await Run(Description("55667788"))).Items);
        Assert.Equal(second, f.Image);
        Assert.Equal("match", f.BuildCheck);
    }

    // Field test 6: single quotes, spaces and JSON or CSV escaped quotes were not read.
    [Theory]
    [InlineData("<Data Name='{0}'>{1}</Data>")]
    [InlineData("<Data  Name = \"{0}\" >{1}</Data >")]
    [InlineData("<Data Name=\\\"{0}\\\">{1}</Data>")]
    [InlineData("<Data Name=\"\"{0}\"\">{1}</Data>")]
    public async Task EventData_quoting_variants_are_read(string item)
    {
        _ws.LoadAny(Build("synth.dll", 0x11223344));
        var data = new[] { ("AppName", "app.exe"), ("ModuleName", "synth.dll"), ("ModuleVersion", "1.2.3.4"), ("ModuleTimeStamp", "11223344"), ("ExceptionCode", "c0000005"), ("FaultingOffset", "0000000000001085") };
        var f = Assert.Single((await Run("<EventData>" + string.Concat(data.Select(d => string.Format(item, d.Item1, d.Item2))) + "</EventData>")).Items);
        Assert.Equal("Big+0x5", f.Resolved);
        Assert.Equal("match", f.BuildCheck);
    }

    // Field test 7: a data offset with a matching time stamp was named as the nearest function.
    [Fact]
    public async Task A_fault_offset_in_a_data_section_names_no_function()
    {
        _ws.LoadAny(Build("synth.dll", 0x11223344));
        var f = Assert.Single((await Run(Description("11223344").Replace("0000000000001085", "0000000000002010"))).Items);
        Assert.Null(f.Resolved);
        Assert.Contains(".rdata, not code", f.BuildDetail);
        Assert.Equal("match", f.BuildCheck);
    }

    // Field test 8: a fault outside any module has the module name unknown and an address.
    [Fact]
    public async Task A_fault_outside_any_module_is_reported_as_an_address()
    {
        var text = """
            Faulting application name: app.exe, version: 1.0.0.0, time stamp: 0x65000000
            Faulting module name: unknown, version: 0.0.0.0, time stamp: 0x00000000
            Exception code: 0xc0000005
            Fault offset: 0x000001e5a3b01000
            """;
        var result = await Run(text);
        var f = Assert.Single(result.Items);
        Assert.Contains("outside any loaded module", f.BuildDetail);
        Assert.Contains("address, not an offset", f.BuildDetail);
        Assert.Equal("0x1E5A3B01000", f.Address);
        Assert.DoesNotContain("unknown", f.NextStep ?? "");
        Assert.Empty(result.ModulesMissing);
    }

    // Field test 16a: a matching stamp with an offset past the image read "mismatch" and "same build".
    [Fact]
    public async Task An_offset_past_the_image_with_the_same_time_stamp_is_not_called_a_mismatch()
    {
        _ws.LoadAny(Build("synth.dll", 0x11223344));
        var f = Assert.Single((await Run(Description("11223344").Replace("0000000000001085", "000000007FFF0000"))).Items);
        Assert.Equal("unknown", f.BuildCheck);
        Assert.Contains("past the end", f.BuildDetail);
        Assert.DoesNotContain("same build", f.BuildDetail);
    }

    // Field test 16b: a different-build row sent the reader to decompile the loaded image.
    [Fact]
    public async Task A_different_build_row_points_at_the_build_to_load()
    {
        _ws.LoadAny(Build("synth.dll", 0x11223344));
        var f = Assert.Single((await Run(Description("55667788"))).Items);
        Assert.Equal("mismatch", f.BuildCheck);
        Assert.StartsWith("load_assembly", f.NextStep);
        Assert.Contains("0x55667788", f.NextStep);
    }

    // Field test 16c: module names went unchanged into the next step.
    [Fact]
    public async Task A_module_name_is_made_safe_in_the_next_step()
    {
        var result = await Run(Description("11223344").Replace("synth.dll", "..\\a\"<b>'.dll"));
        var next = Assert.Single(result.Items).NextStep!;
        Assert.DoesNotContain("<", next);
        Assert.DoesNotContain("\"", next);
        Assert.DoesNotContain("\\", next);
        Assert.DoesNotContain("'", next);
    }

    // Field test 16d: an overflowing offset was accepted silently.
    [Fact]
    public async Task An_unreadable_fault_offset_is_noted()
    {
        _ws.LoadAny(Build("synth.dll", 0x11223344));
        var result = await Run(Description("11223344").Replace("0x0000000000001085", "0xFFFFFFFFFFFFFFFFFFFF"));
        Assert.Contains(result.Notes, n => n.Contains("unreadable", StringComparison.Ordinal));
        Assert.Contains("unreadable", Assert.Single(result.Items).BuildDetail);
    }

    // Field test 16e: a module line without version and time stamp dropped the event.
    [Fact]
    public async Task A_module_line_without_version_and_time_stamp_is_read()
    {
        _ws.LoadAny(Build("synth.dll", 0x11223344));
        var text = "Faulting application name: app.exe\nFaulting module name: synth.dll\nException code: 0xc0000005\nFault offset: 0x1085";
        var f = Assert.Single((await Run(text)).Items);
        Assert.Equal("Big+0x5", f.Resolved);
        Assert.StartsWith("unknown build", f.BuildDetail);
    }

    // Field test 16f: the remaining lines of event 1000 were counted as unrecognized.
    [Fact]
    public async Task The_other_lines_of_an_event_are_recognized()
    {
        var text = Description("11223344") + """

            Faulting process id: 0x10624
            Faulting application start time: 0x1DD6D07B4AA7AB7
            Faulting application path: C:\App\app.exe
            Faulting module path: C:\App\synth.dll
            Report Id: bb338ecc-efe7-412d-8b93-cca184977544
            Faulting package full name:
            Faulting package-relative application ID:
            """;
        Assert.Equal(0, (await Run(text)).UnrecognizedLines);
    }

    [Fact]
    public async Task Function_lookup_names_why_a_name_has_no_range()
    {
        _ws.LoadAny(Build("synth.dll", 0x11223344));
        var native = _ws.Read(() => _ws.Natives.Single());
        var index = await _code.Index(native, null, default);
        var lookup = FunctionRanges.Lookup(native, index, ["Big", "Missing"]);
        Assert.Equal("found", lookup[0].Status);
        Assert.Equal("absent", lookup[1].Status);
        Assert.Null(lookup[1].Range);
    }
}
