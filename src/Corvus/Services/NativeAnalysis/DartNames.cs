using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;

namespace Corvus.Services;

/// <summary>
/// The <see cref="NativeNameSource.Dart"/> layer of a Dart AOT image (libapp.so, App.framework/App, a dart compile
/// aot-snapshot output): code named from the snapshot's Function and Class objects, set when the code index is built
/// (no tool call needed; see <see cref="DartProgramReader"/> for the layouts read). Cheap to rebuild, so not saved.
/// </summary>
public static class DartNames
{
    /// <summary>Set to 0 to turn off naming Dart AOT images from their snapshot.</summary>
    public const string AutoVariable = "CORVUS_AUTO_DART_NAMES";

    /// <summary>
    /// The program of an image whose symbols name a program snapshot (kDartSnapshotData, kDartSnapshotText) or VM and
    /// isolate snapshots (kDartVmSnapshotData, kDartIsolateSnapshotData, kDartIsolateSnapshotInstructions), with the RVA of
    /// the instructions its code offsets count from; null for other images.
    /// </summary>
    public static (DartProgram Program, uint TextRva)? Read(INativeImage image, CancellationToken ct = default)
    {
        var symbols = new Dictionary<string, uint>(StringComparer.Ordinal);
        foreach (var (name, rva) in image.Exports.Where(e => e.Name != null).Select(e => (e.Name!, e.Rva)).Concat(image.Symbols.Select(s => (s.Name, s.Rva))))
            symbols.TryAdd(name.TrimStart('_'), rva);
        var bytes = Native.Dwarf.DwarfLocator.FileBytes(image).Span;
        if (symbols.TryGetValue("kDartSnapshotText", out var text) && Header(image, bytes, symbols, "kDartSnapshotData") is { } program)
            return (DartProgramReader.Read(bytes, program, ct), text);
        if (symbols.TryGetValue("kDartIsolateSnapshotInstructions", out var isolateText) && Header(image, bytes, symbols, "kDartIsolateSnapshotData") is { } isolate)
            return (DartProgramReader.Read(bytes, Header(image, bytes, symbols, "kDartVmSnapshotData"), isolate, ct), isolateText);
        return null;
    }

    private static DartSnapshot? Header(INativeImage image, ReadOnlySpan<byte> bytes, Dictionary<string, uint> symbols, string symbol) =>
        symbols.TryGetValue(symbol, out var rva) && image.TryRvaToFileOffset(rva, out long offset) && DartScan.HeaderAt(bytes, offset) is { } h
            ? h with { Symbol = symbol } : null;

    /// <summary>On the index build thread: sets the dart layer and returns the code starts it names; null for other images or when turned off.</summary>
    public static IReadOnlyCollection<uint>? AutoApply(LoadedNative native, NativeCodeService code, CancellationToken ct)
    {
        if (Environment.GetEnvironmentVariable(AutoVariable) == "0" || Read(native.Image, ct) is not var (program, textRva)) return null;
        if (program.Unsupported != null) return null;
        var names = new Dictionary<uint, string>();
        foreach (var c in program.Code) names.TryAdd(textRva + c.Offset, c.Name);
        NativeNameLayers.Of(native).Set(new NativeNameLayers.Layer(NativeNameSource.Dart, names, new Dictionary<uint, string>(),
            $"Dart AOT snapshot ({program.Functions} functions, {names.Count} code objects named)"), code.Ready(native));
        return names.Keys;
    }
}
