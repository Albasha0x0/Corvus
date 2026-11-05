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
}
