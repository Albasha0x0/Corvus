namespace Corvus.Native.MachO;

/// <summary>Names, comments and function starts of a metadata name layer, by RVA.</summary>
public sealed record AppleNameSet(Dictionary<uint, string> Names, Dictionary<uint, string> Comments, uint[] FunctionStarts, int Methods, int Classes);

/// <summary>Objective-C names for implementations ("-[Class sel]"), class objects, ivars and reference slots; duplicates get "_&lt;RVA hex&gt;".</summary>
public static class AppleObjcNames
{
    public static AppleNameSet Build(MachOFile image, AppleObjcMetadata objc)
    {
        var names = new Dictionary<uint, string>();
        var comments = new Dictionary<uint, string>();
        var used = new Dictionary<string, uint>(StringComparer.Ordinal);
        var starts = new List<uint>();
        int methods = 0;
        bool Add(ulong va, string name, string? comment = null)
        {
            if (va == 0 || !image.TryVaToRva(va, out uint rva) || names.ContainsKey(rva)) return false;
            if (!used.TryAdd(name, rva))
            {
                name = $"{name}_{rva:X}";
                used.TryAdd(name, rva);
            }
            names[rva] = name;
            if (comment != null) comments[rva] = comment;
            return true;
        }
        void Methods(string owner, string what, IReadOnlyList<ObjcMethod> list)
        {
            foreach (var m in list)
            {
                if (m.Imp == 0) continue;
                string name = $"{(m.IsClassMethod ? '+' : '-')}[{owner} {m.Selector}]";
                if (Add(m.Imp, name, $"ObjC {(m.IsClassMethod ? "class" : "instance")} method of {what}{(m.Types != null ? "; types " + m.Types : "")}"))
                {
                    methods++;
                    if (image.TryVaToRva(m.Imp, out uint rva)) starts.Add(rva);
                }
            }
        }

        foreach (var c in objc.Classes)
        {
            string what = c.SwiftName != null ? $"{c.Name} (Swift class {c.SwiftName})" : c.Name;
            Methods(c.Name, what, c.Methods);
            string super = c.Superclass != null ? " : " + (c.Superclass.StartsWith("_Tt", StringComparison.Ordinal) ? Swift.SwiftDemangler.Demangle(c.Superclass) ?? c.Superclass : c.Superclass) : "";
            Add(c.Va, "_OBJC_CLASS_$_" + c.Name, $"ObjC class {what}{super}; {c.Methods.Count} methods, {c.Ivars.Count} ivars, instance size {c.InstanceSize}");
            Add(c.MetaclassVa, "_OBJC_METACLASS_$_" + c.Name, $"ObjC metaclass of {what}");
            Add(c.RoVa, "__OBJC_CLASS_RO_$_" + c.Name);
            Add(c.MetaRoVa, "__OBJC_METACLASS_RO_$_" + c.Name);
            foreach (var v in c.Ivars)
                Add(v.OffsetVa, $"_OBJC_IVAR_$_{c.Name}.{v.Name}", $"offset of ivar {c.Name}.{v.Name}{(v.Type is { Length: > 0 } t ? " (" + t + ")" : "")}: {v.Offset}");
        }
        foreach (var cat in objc.Categories)
        {
            Methods($"{cat.ClassName}({cat.Name})", $"category {cat.Name} on {cat.ClassName}", cat.Methods);
            Add(cat.Va, $"__OBJC_$_CATEGORY_{cat.ClassName}_$_{cat.Name}", $"ObjC category {cat.Name} on {(cat.ClassExternal ? "external " : "")}class {cat.ClassName}");
        }
        foreach (var p in objc.Protocols) Add(p.Va, "_OBJC_PROTOCOL_$_" + p.Name, $"ObjC protocol {p.Name}");
        foreach (var r in objc.References)
        {
            string prefix = r.Kind switch { "selector" => "selRef_", "class" => "classRef_", "superclass" => "superRef_", _ => "protocolRef_" };
            Add(r.Va, prefix + r.Name.Replace(':', '_'), r.External ? $"{r.Kind} {r.Name} (another image)" : null);
        }
        return new AppleNameSet(names, comments, [.. starts.Distinct().Order()], methods, objc.Classes.Count);
    }
}
