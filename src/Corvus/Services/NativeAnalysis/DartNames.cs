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
    /// The program of an image whose symbols name a snapshot (kDartSnapshotData) and its instructions (kDartSnapshotText),
    /// with the instructions' RVA; null for other images.
    /// </summary>
    public static (DartProgram Program, uint TextRva)? Read(INativeImage image, CancellationToken ct = default)
    {
        uint? data = null, text = null;
        foreach (var (name, rva) in image.Exports.Where(e => e.Name != null).Select(e => (e.Name!, e.Rva)).Concat(image.Symbols.Select(s => (s.Name, s.Rva))))
            switch (name.TrimStart('_'))
            {
                case "kDartSnapshotData": data ??= rva; break;
                case "kDartSnapshotText": text ??= rva; break;
            }
        if (data is not { } dataRva || text is not { } textRva || !image.TryRvaToFileOffset(dataRva, out long offset)) return null;
        var bytes = Native.Dwarf.DwarfLocator.FileBytes(image).Span;
        if (DartScan.HeaderAt(bytes, offset) is not { } header) return null;
        return (DartProgramReader.Read(bytes, header with { Symbol = "kDartSnapshotData" }, ct), textRva);
    }

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
