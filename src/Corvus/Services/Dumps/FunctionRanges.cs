using Corvus.Core;
using Corvus.Native.Code;

namespace Corvus.Services;

/// <summary>A function's half-open RVA range [Start, End) in one build, named by module and PE time stamp.</summary>
public sealed record FunctionRange(string Module, uint? TimeDateStamp, string Name, uint Start, uint End);

/// <summary>RVA ranges of named functions in one loaded build.</summary>
public static class FunctionRanges
{
    /// <summary>
    /// Returns the range of each name that resolves to one function in <paramref name="index"/>; a name that is
    /// absent, ambiguous or without a known extent is left out. The time stamp is null for a non-PE image.
    /// </summary>
    public static IReadOnlyList<FunctionRange> Of(LoadedNative native, NativeCodeIndex index, IEnumerable<string> names)
    {
        var module = Path.GetFileName(native.FilePath);
        var stamp = native.Pe?.Coff.TimeDateStamp;
        var result = new List<FunctionRange>();
        foreach (var name in names)
        {
            if (index.AddressesOfName(name) is not [var one] || index.FunctionAt(one.Rva) is not { } f || f.Start != one.Rva) continue;
            result.Add(new FunctionRange(module, stamp, name, f.Start, f.End));
        }
        return result;
    }
}
