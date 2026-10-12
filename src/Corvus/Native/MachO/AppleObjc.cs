using Corvus.Native.Swift;

namespace Corvus.Native.MachO;

/// <summary>An Objective-C method: selector, type encoding and implementation (0 when it has none or lies outside the image).</summary>
public sealed record ObjcMethod(string Selector, string? Types, ulong Imp, bool IsClassMethod, bool Optional = false);

/// <summary>An instance variable; <see cref="Offset"/> is read from its offset variable at <see cref="OffsetVa"/>.</summary>
public sealed record ObjcIvar(string Name, string? Type, ulong OffsetVa, uint? Offset, uint Size, uint Alignment);

public sealed record ObjcProperty(string Name, string? Attributes);

/// <summary>
/// A class from __objc_classlist. <see cref="SwiftName"/> is the demangled name of a Swift class ("_TtC..." runtime
/// names); <see cref="Superclass"/> is named from the bind when the superclass lives in another image.
/// </summary>
public sealed record ObjcClass(ulong Va, string Name, string? SwiftName, ulong MetaclassVa, string? Superclass, ulong SuperclassVa, bool SuperclassExternal,
    ulong RoVa, ulong MetaRoVa, uint Flags, uint InstanceStart, uint InstanceSize, bool IsSwift,
    IReadOnlyList<ObjcMethod> Methods, IReadOnlyList<ObjcIvar> Ivars, IReadOnlyList<ObjcProperty> Properties, IReadOnlyList<string> Protocols)
{
    /// <summary>The name to show: the Swift name for Swift classes, else the ObjC name.</summary>
    public string DisplayName => SwiftName ?? Name;
}

/// <summary>A category from __objc_catlist; <see cref="ClassExternal"/> when it extends a class of another image (a bind).</summary>
public sealed record ObjcCategory(ulong Va, string Name, string ClassName, ulong ClassVa, bool ClassExternal,
    IReadOnlyList<ObjcMethod> Methods, IReadOnlyList<ObjcProperty> Properties, IReadOnlyList<string> Protocols);

public sealed record ObjcProtocol(ulong Va, string Name, IReadOnlyList<string> Protocols, IReadOnlyList<ObjcMethod> Methods, IReadOnlyList<ObjcProperty> Properties);

/// <summary>A slot of __objc_selrefs, __objc_classrefs, __objc_superrefs or __objc_protorefs and what it names.</summary>
public sealed record ObjcReference(ulong Va, string Kind, string Name, ulong Target, bool External);

/// <summary>
/// The Objective-C runtime metadata of a Mach-O image: classes and metaclasses, categories (also on classes of other
/// images, named through their binds), protocols, methods (classic and relative method lists) with implementation
/// addresses, ivars with offsets, properties, and the selector, class, superclass and protocol references.
/// Malformed records are skipped and counted in <see cref="Issues"/>.
/// </summary>
public sealed class AppleObjcMetadata
{
    private const int MaxListCount = 1 << 16;
    private const int MaxRecords = 1 << 18;

    public IReadOnlyList<ObjcClass> Classes { get; }
    public IReadOnlyList<ObjcCategory> Categories { get; }
    public IReadOnlyList<ObjcProtocol> Protocols { get; }
    public IReadOnlyList<ObjcReference> References { get; }
    public IReadOnlyList<string> Issues { get; }
    public bool IsEmpty => Classes.Count == 0 && Categories.Count == 0 && Protocols.Count == 0 && References.Count == 0;

    private AppleObjcMetadata(List<ObjcClass> classes, List<ObjcCategory> categories, List<ObjcProtocol> protocols, List<ObjcReference> references, List<string> issues)
    {
        Classes = classes;
        Categories = categories;
        Protocols = protocols;
        References = references;
        Issues = issues;
    }

    /// <summary>Reads the metadata of <paramref name="image"/>; empty for images without Objective-C sections.</summary>
    public static AppleObjcMetadata Read(MachOFile image, CancellationToken ct = default) => new Reader(new AppleObjcImage(image), ct).Run();

    private sealed class Reader(AppleObjcImage view, CancellationToken ct)
    {
        private readonly List<string> issues = [];
        private readonly Dictionary<ulong, string?> classNames = [];
        private readonly Dictionary<ulong, ObjcProtocol?> protocolCache = [];
        private int records;
        private int P => view.PointerSize;

        private void Issue(string text)
        {
            if (issues.Count < 100) issues.Add(text);
        }

        private IEnumerable<ulong> Slots(string section)
        {
            foreach (var s in view.Sections(section))
                for (ulong at = s.Address; at + (ulong)P <= s.Address + s.Size; at += (ulong)P)
                {
                    ct.ThrowIfCancellationRequested();
                    if (++records > MaxRecords) yield break;
                    yield return at;
                }
        }

        public AppleObjcMetadata Run()
        {
            var classes = new List<ObjcClass>();
            foreach (var slot in Slots("__objc_classlist"))
            {
                var p = view.Ptr(slot);
                if (p.Symbol != null || p.Target == 0) continue;
                if (ReadClass(p.Target) is { } c) classes.Add(c);
            }
            var categories = new List<ObjcCategory>();
            foreach (var section in new[] { "__objc_catlist", "__objc_catlist2" })
                foreach (var slot in Slots(section))
                {
                    var p = view.Ptr(slot);
                    if (p.Symbol != null || p.Target == 0) continue;
                    if (ReadCategory(p.Target) is { } c) categories.Add(c);
                }
            var protocols = new List<ObjcProtocol>();
            var seen = new HashSet<ulong>();
            foreach (var slot in Slots("__objc_protolist"))
            {
                var p = view.Ptr(slot);
                if (p.Symbol != null || p.Target == 0 || !seen.Add(p.Target)) continue;
                if (ReadProtocol(p.Target) is { } proto) protocols.Add(proto);
            }
            var references = new List<ObjcReference>();
            foreach (var slot in Slots("__objc_selrefs"))
            {
                var p = view.Ptr(slot);
                if (p.Target != 0 && view.CString(p.Target) is { Length: > 0 } sel) references.Add(new ObjcReference(slot, "selector", sel, p.Target, false));
            }
            foreach (var (section, kind) in new[] { ("__objc_classrefs", "class"), ("__objc_superrefs", "superclass") })
                foreach (var slot in Slots(section))
                {
                    var p = view.Ptr(slot);
                    if (p.Symbol != null) references.Add(new ObjcReference(slot, kind, ExternalClassName(p.Symbol), 0, true));
                    else if (p.Target != 0 && ClassName(p.Target) is { } name) references.Add(new ObjcReference(slot, kind, name, p.Target, false));
                }
            foreach (var slot in Slots("__objc_protorefs"))
            {
                var p = view.Ptr(slot);
                if (p.Symbol != null) references.Add(new ObjcReference(slot, "protocol", ExternalProtocolName(p.Symbol), 0, true));
                else if (p.Target != 0 && view.CString(view.Ptr(p.Target + (ulong)P).Target) is { Length: > 0 } name)
                    references.Add(new ObjcReference(slot, "protocol", name, p.Target, false));
            }
            return new AppleObjcMetadata(classes, categories, protocols, references, issues);
        }

        private static string ExternalClassName(string symbol)
        {
            foreach (var prefix in new[] { "OBJC_CLASS_$_", "OBJC_METACLASS_$_" })
                if (symbol.StartsWith(prefix, StringComparison.Ordinal)) return symbol[prefix.Length..];
            return symbol;
        }

        private static string ExternalProtocolName(string symbol) =>
            symbol.StartsWith("OBJC_PROTOCOL_$_", StringComparison.Ordinal) ? symbol["OBJC_PROTOCOL_$_".Length..] : symbol;

        /// <summary>class_t.data with the Swift and flag bits cleared.</summary>
        private ulong DataPointer(ulong cls) => view.Ptr(cls + 4 * (ulong)P).Target & (P == 8 ? ~7UL : ~3UL);

        /// <summary>The ObjC name of the class at <paramref name="cls"/> (from its class_ro_t), cached.</summary>
        private string? ClassName(ulong cls)
        {
            if (classNames.TryGetValue(cls, out var known)) return known;
            classNames[cls] = null;
            ulong ro = DataPointer(cls);
            string? name = ro != 0 ? view.CString(view.Ptr(ro + RoName).Target) : null;
            classNames[cls] = name;
            return name;
        }

        private ulong RoName => P == 8 ? 24UL : 16UL;
        private ulong RoMethods => P == 8 ? 32UL : 20UL;
        private ulong RoProtocols => P == 8 ? 40UL : 24UL;
        private ulong RoIvars => P == 8 ? 48UL : 28UL;
        private ulong RoProperties => P == 8 ? 64UL : 36UL;

        private ObjcClass? ReadClass(ulong cls)
        {
            ulong ro = DataPointer(cls);
            if (ro == 0 || !view.Has(ro, (int)RoProperties + P))
            {
                Issue($"class at 0x{cls:X}: class_ro_t pointer 0x{ro:X} is outside the image");
                return null;
            }
            var name = ClassName(cls);
            if (string.IsNullOrEmpty(name))
            {
                Issue($"class at 0x{cls:X}: no readable name");
                return null;
            }
            uint flags = view.U32(ro), instanceStart = view.U32(ro + 4), instanceSize = view.U32(ro + 8);
            ulong rawData = view.Ptr(cls + 4 * (ulong)P).Target;
            bool swift = (rawData & 3) != 0;

            var superPtr = view.Ptr(cls + (ulong)P);
            string? superName = superPtr.Symbol != null ? ExternalClassName(superPtr.Symbol) : superPtr.Target != 0 ? ClassName(superPtr.Target) : null;

            var methods = new List<ObjcMethod>();
            ReadMethodList(view.Ptr(ro + RoMethods).Target, false, false, methods);
            var meta = view.Ptr(cls);
            ulong metaRo = 0;
            if (meta.Symbol == null && meta.Target != 0)
            {
                metaRo = DataPointer(meta.Target);
                if (metaRo != 0 && view.Has(metaRo, (int)RoProperties + P)) ReadMethodList(view.Ptr(metaRo + RoMethods).Target, true, false, methods);
                else metaRo = 0;
            }
            var ivars = ReadIvars(view.Ptr(ro + RoIvars).Target);
            var properties = ReadProperties(view.Ptr(ro + RoProperties).Target);
            var protocols = ReadProtocolNames(view.Ptr(ro + RoProtocols).Target);
            string? swiftName = name.StartsWith("_Tt", StringComparison.Ordinal) ? SwiftDemangler.Demangle(name) : null;
            return new ObjcClass(cls, name, swiftName, meta.Symbol == null ? meta.Target : 0, superName, superPtr.Target, superPtr.Symbol != null,
                ro, metaRo, flags, instanceStart, instanceSize, swift || swiftName != null, methods, ivars, properties, protocols);
        }

        private ObjcCategory? ReadCategory(ulong cat)
        {
            if (!view.Has(cat, 6 * P))
            {
                Issue($"category at 0x{cat:X} is outside the image");
                return null;
            }
            var name = view.CString(view.Ptr(cat).Target);
            if (string.IsNullOrEmpty(name))
            {
                Issue($"category at 0x{cat:X}: no readable name");
                return null;
            }
            var cls = view.Ptr(cat + (ulong)P);
            string className = cls.Symbol != null ? ExternalClassName(cls.Symbol) : cls.Target != 0 ? ClassName(cls.Target) ?? $"class_{cls.Target:X}" : "?";
            var methods = new List<ObjcMethod>();
            ReadMethodList(view.Ptr(cat + 2 * (ulong)P).Target, false, false, methods);
            ReadMethodList(view.Ptr(cat + 3 * (ulong)P).Target, true, false, methods);
            var protocols = ReadProtocolNames(view.Ptr(cat + 4 * (ulong)P).Target);
            var properties = ReadProperties(view.Ptr(cat + 5 * (ulong)P).Target);
            return new ObjcCategory(cat, name, className, cls.Target, cls.Symbol != null, methods, properties, protocols);
        }

        private ObjcProtocol? ReadProtocol(ulong proto)
        {
            if (protocolCache.TryGetValue(proto, out var known)) return known;
            protocolCache[proto] = null;
            if (!view.Has(proto, 8 * P))
            {
                Issue($"protocol at 0x{proto:X} is outside the image");
                return null;
            }
            var name = view.CString(view.Ptr(proto + (ulong)P).Target);
            if (string.IsNullOrEmpty(name))
            {
                Issue($"protocol at 0x{proto:X}: no readable name");
                return null;
            }
            var methods = new List<ObjcMethod>();
            ReadMethodList(view.Ptr(proto + 3 * (ulong)P).Target, false, false, methods);
            ReadMethodList(view.Ptr(proto + 4 * (ulong)P).Target, true, false, methods);
            ReadMethodList(view.Ptr(proto + 5 * (ulong)P).Target, false, true, methods);
            ReadMethodList(view.Ptr(proto + 6 * (ulong)P).Target, true, true, methods);
            var result = new ObjcProtocol(proto, name, ReadProtocolNames(view.Ptr(proto + 2 * (ulong)P).Target), methods, ReadProperties(view.Ptr(proto + 7 * (ulong)P).Target));
            protocolCache[proto] = result;
            return result;
        }

        /// <summary>
        /// method_list_t: classic entries (SEL, types, IMP pointers) or, with the high bit of entsize set, relative
        /// entries (three 32-bit offsets: selector reference, or the selector itself when flagged direct; types; IMP).
        /// </summary>
        private void ReadMethodList(ulong list, bool classMethods, bool optional, List<ObjcMethod> into)
        {
            if (list == 0) return;
            uint entsizeAndFlags = view.U32(list), count = view.U32(list + 4);
            bool small = (entsizeAndFlags & 0x80000000) != 0, direct = (entsizeAndFlags & 0x40000000) != 0;
            uint entsize = entsizeAndFlags & 0xFFFC;
            if (count > MaxListCount || entsize == 0 || !view.Has(list + 8, (int)Math.Min(entsize * (ulong)count, int.MaxValue)))
            {
                Issue($"method list at 0x{list:X}: {count} entries of {entsize} bytes do not fit the image");
                return;
            }
            for (uint i = 0; i < count; i++)
            {
                ulong m = list + 8 + i * (ulong)entsize;
                string? selector, types;
                ulong imp;
                if (small)
                {
                    ulong nameField = view.Relative(m);
                    selector = direct ? view.CString(nameField) : view.CString(view.Ptr(nameField).Target);
                    types = view.CString(view.Relative(m + 4));
                    imp = view.Relative(m + 8);
                }
                else
                {
                    selector = view.CString(view.Ptr(m).Target);
                    types = view.CString(view.Ptr(m + (ulong)P).Target);
                    imp = view.Ptr(m + 2 * (ulong)P).Target;
                }
                if (string.IsNullOrEmpty(selector))
                {
                    Issue($"method {i} of the list at 0x{list:X}: no readable selector");
                    continue;
                }
                into.Add(new ObjcMethod(selector, types, imp != 0 && view.Has(imp, 1) ? imp : 0, classMethods, optional));
            }
        }

        private List<ObjcIvar> ReadIvars(ulong list)
        {
            var result = new List<ObjcIvar>();
            if (list == 0) return result;
            uint entsize = view.U32(list), count = view.U32(list + 4);
            if (count > MaxListCount || entsize < 3 * (uint)P + 8 || !view.Has(list + 8, (int)Math.Min(entsize * (ulong)count, int.MaxValue)))
            {
                Issue($"ivar list at 0x{list:X}: {count} entries of {entsize} bytes do not fit the image");
                return result;
            }
            for (uint i = 0; i < count; i++)
            {
                ulong e = list + 8 + i * (ulong)entsize;
                var name = view.CString(view.Ptr(e + (ulong)P).Target);
                if (string.IsNullOrEmpty(name)) continue;
                ulong offsetVa = view.Ptr(e).Target;
                uint? offset = offsetVa != 0 && view.Has(offsetVa, 4) ? view.U32(offsetVa) : null;
                uint alignRaw = view.U32(e + 3 * (ulong)P), size = view.U32(e + 3 * (ulong)P + 4);
                result.Add(new ObjcIvar(name, view.CString(view.Ptr(e + 2 * (ulong)P).Target), offsetVa, offset, size, alignRaw == uint.MaxValue ? 8 : alignRaw < 32 ? 1u << (int)alignRaw : 0));
            }
            return result;
        }

        private List<ObjcProperty> ReadProperties(ulong list)
        {
            var result = new List<ObjcProperty>();
            if (list == 0) return result;
            uint entsize = view.U32(list), count = view.U32(list + 4);
            if (count > MaxListCount || entsize < 2 * (uint)P || !view.Has(list + 8, (int)Math.Min(entsize * (ulong)count, int.MaxValue)))
            {
                Issue($"property list at 0x{list:X}: {count} entries of {entsize} bytes do not fit the image");
                return result;
            }
            for (uint i = 0; i < count; i++)
            {
                ulong e = list + 8 + i * (ulong)entsize;
                var name = view.CString(view.Ptr(e).Target);
                if (!string.IsNullOrEmpty(name)) result.Add(new ObjcProperty(name, view.CString(view.Ptr(e + (ulong)P).Target)));
            }
            return result;
        }

        /// <summary>protocol_list_t: a pointer-sized count, then protocol pointers (binds name protocols of other images).</summary>
        private List<string> ReadProtocolNames(ulong list)
        {
            var result = new List<string>();
            if (list == 0) return result;
            ulong count = view.Word(list);
            if (count > MaxListCount || !view.Has(list + (ulong)P, (int)(count * (ulong)P)))
            {
                Issue($"protocol list at 0x{list:X}: {count} entries do not fit the image");
                return result;
            }
            for (ulong i = 0; i < count; i++)
            {
                var p = view.Ptr(list + (ulong)P * (i + 1));
                if (p.Symbol != null) result.Add(ExternalProtocolName(p.Symbol));
                else if (p.Target != 0 && view.CString(view.Ptr(p.Target + (ulong)P).Target) is { Length: > 0 } name) result.Add(name);
            }
            return result;
        }
    }
}
