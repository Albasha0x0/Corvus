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

    /// <summary>
    /// list_cpp_classes lines for a Mach-O image: ObjC classes (superclass, Swift name, counts, protocols), categories and
    /// protocols, then Swift types (superclass, fields, vtable, conformances); with <paramref name="slots"/> the methods
    /// and vtable entries with their implementations. Empty for images without the metadata.
    /// </summary>
    public static List<string> ClassLines(LoadedNative native, string? filter, bool slots, Func<uint, string?> nameAt, CancellationToken ct)
    {
        var lines = new List<string>();
        var (objc, swift) = Metadata(native, ct);
        ulong imageBase = native.Image.ImageBase;
        bool Match(params string?[] names) => filter == null || names.Any(n => n != null && n.Contains(filter, StringComparison.OrdinalIgnoreCase));
        string Va(ulong va) => $"0x{va:X}";
        void Methods(string owner, IReadOnlyList<ObjcMethod> methods)
        {
            if (!slots) return;
            foreach (var m in methods)
                lines.Add($"    {(m.IsClassMethod ? '+' : '-')}[{owner} {m.Selector}]{(m.Imp != 0 ? "  " + Va(m.Imp) : "")}{(m.Optional ? "  (optional)" : "")}");
        }
        if (objc != null)
        {
            lines.Add($"Objective-C: {objc.Classes.Count} classes, {objc.Categories.Count} categories, {objc.Protocols.Count} protocols");
            foreach (var c in objc.Classes.Where(c => Match(c.Name, c.SwiftName)))
            {
                lines.Add($"objc class {c.Name}{(c.Superclass != null ? " : " + c.Superclass : "")}{(c.SwiftName != null ? $"  (Swift {c.SwiftName})" : c.IsSwift ? "  (Swift)" : "")}  " +
                          $"{c.Methods.Count} methods, {c.Ivars.Count} ivars, {c.Properties.Count} properties, size {c.InstanceSize}" +
                          (c.Protocols.Count > 0 ? "  <" + string.Join(", ", c.Protocols) + ">" : "") + $"  at {Va(c.Va)}");
                Methods(c.Name, c.Methods);
            }
            foreach (var c in objc.Categories.Where(c => Match(c.Name, c.ClassName)))
            {
                lines.Add($"objc category {c.ClassName}({c.Name})  {c.Methods.Count} methods{(c.ClassExternal ? ", class in another image" : "")}  at {Va(c.Va)}");
                Methods($"{c.ClassName}({c.Name})", c.Methods);
            }
            foreach (var p in objc.Protocols.Where(p => Match(p.Name)))
            {
                lines.Add($"objc protocol {p.Name}  {p.Methods.Count} methods{(p.Protocols.Count > 0 ? "  <" + string.Join(", ", p.Protocols) + ">" : "")}");
                Methods(p.Name, p.Methods);
            }
        }
        if (swift != null)
        {
            lines.Add($"Swift: {swift.Types.Count} types, {swift.Protocols.Count} protocols, {swift.Conformances.Count} conformances");
            var conformances = swift.Conformances.GroupBy(c => c.Type).ToDictionary(g => g.Key, g => g.Select(c => c.Protocol).Distinct().ToList());
            foreach (var t in swift.Types.Concat(swift.Protocols).Where(t => Match(t.Name)))
            {
                lines.Add($"swift {t.Kind} {t.Name}{(t.Superclass != null ? " : " + t.Superclass : "")}{(t.IsGeneric ? "  (generic)" : "")}  " +
                          $"{t.Fields.Count} {(t.Kind == "enum" ? "cases" : "fields")}{(t.Methods.Count > 0 ? $", vtable {t.Methods.Count}" : "")}" +
                          (conformances.TryGetValue(t.Name, out var protocols) ? "  <" + string.Join(", ", protocols) + ">" : "") + $"  at {Va(t.DescriptorVa)}");
                if (!slots) continue;
                for (int i = 0; i < t.Methods.Count; i++)
                {
                    var m = t.Methods[i];
                    string? name = m.Impl >= imageBase && m.Impl != 0 ? nameAt((uint)(m.Impl - imageBase)) : null;
                    lines.Add($"    [{i}] {(m.IsInstance ? "" : "static ")}{m.Kind}{(m.Impl != 0 ? "  " + Va(m.Impl) : "")}{(name != null ? "  " + name : "")}");
                }
            }
        }
        return lines;
    }
}
