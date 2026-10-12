using Corvus.Core;
using Corvus.Native.Code;
using Corvus.Native.MachO;

namespace Corvus.Services;

/// <summary>
/// The <see cref="NativeNameSource.ObjC"/> and <see cref="NativeNameSource.Swift"/> name layers of a Mach-O image,
/// built from its Objective-C and Swift runtime metadata when the code index is first built (no tool call needed;
/// see <see cref="AppleObjcNames"/> and <see cref="AppleSwiftNames"/> for the naming). Cheap to rebuild, so not saved.
/// </summary>
public static class AppleNames
{
    /// <summary>Set to 0 to turn off naming Mach-O images from their ObjC / Swift metadata.</summary>
    public const string AutoVariable = "CORVUS_AUTO_APPLE_NAMES";

    private sealed class Holder
    {
        public readonly object Gate = new();
        public bool Done;
        public AppleObjcMetadata? Objc;
        public AppleSwiftMetadata? Swift;
    }

    /// <summary>The ObjC and Swift metadata of <paramref name="native"/>'s current image, read once; nulls for other images or none present.</summary>
    public static (AppleObjcMetadata? Objc, AppleSwiftMetadata? Swift) Metadata(LoadedNative native, CancellationToken ct = default)
    {
        if (native.Image is not MachOFile image) return (null, null);
        var holder = native.GetAnalysis(_ => new Holder());
        lock (holder.Gate)
        {
            if (!holder.Done)
            {
                var objc = AppleObjcMetadata.Read(image, ct);
                var swift = AppleSwiftMetadata.Read(image, ct);
                holder.Objc = objc.IsEmpty ? null : objc;
                holder.Swift = swift.IsEmpty ? null : swift;
                holder.Done = true;
            }
            return (holder.Objc, holder.Swift);
        }
    }

    /// <summary>
    /// On the index build thread: sets the objc and swift layers of a Mach-O image and returns the function starts they
    /// name (method implementations, metadata accessors, vtable entries); null for other images or when turned off.
    /// </summary>
    public static IReadOnlyCollection<uint>? AutoApply(LoadedNative native, NativeCodeService code, CancellationToken ct)
    {
        if (Environment.GetEnvironmentVariable(AutoVariable) == "0" || native.Image is not MachOFile image) return null;
        var (objc, swift) = Metadata(native, ct);
        var layers = NativeNameLayers.Of(native);
        var starts = new List<uint>();
        if (objc != null)
        {
            var built = AppleObjcNames.Build(image, objc);
            layers.Set(new NativeNameLayers.Layer(NativeNameSource.ObjC, built.Names, built.Comments,
                $"Objective-C metadata ({built.Classes} classes, {built.Methods} method implementations)"), code.Ready(native));
            starts.AddRange(built.FunctionStarts);
        }
        if (swift != null)
        {
            var built = AppleSwiftNames.Build(image, swift);
            layers.Set(new NativeNameLayers.Layer(NativeNameSource.Swift, built.Names, built.Comments,
                $"Swift metadata ({built.Classes} types, {built.Methods} vtable methods named)"), code.Ready(native));
            starts.AddRange(built.FunctionStarts);
        }
        return starts;
    }
}
