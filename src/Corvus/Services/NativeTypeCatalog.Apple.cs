using Corvus.Native.MachO;

namespace Corvus.Services;

public sealed partial class NativeTypeCatalog
{
    private const int MethodsListed = 40;

    /// <summary>ObjC classes and protocols ("objc:Name", Swift classes also by their Swift name) and Swift types ("swift:Module.Type") of a Mach-O image.</summary>
    private static void CollectApple(Context c, Func<string, bool> match, List<Hit> hits, CancellationToken ct)
    {
        if (!c.Uses(ObjC) && !c.Uses(Swift)) return;
        var (objc, swift) = AppleNames.Metadata(c.Native, ct);
        if (c.Uses(ObjC) && objc != null)
        {
            foreach (var cls in objc.Classes.Where(x => match(x.Name) || x.SwiftName != null && match(x.SwiftName)))
            {
                if (hits.Count >= MaxCandidates) return;
                var k = cls;
                hits.Add(new Hit(new NativeTypeCandidate(ObjC + ":" + cls.Name, cls.Name, "class", cls.InstanceSize, ObjC), () => ObjcView(c, k)));
            }
            foreach (var p in objc.Protocols.Where(x => match(x.Name)))
            {
                if (hits.Count >= MaxCandidates) return;
                var k = p;
                hits.Add(new Hit(new NativeTypeCandidate(ObjC + ":" + p.Name, p.Name, "protocol", -1, ObjC), () => ObjcProtocolView(k)));
            }
        }
        if (c.Uses(Swift) && swift != null)
            foreach (var t in swift.Types.Concat(swift.Protocols).Where(x => match(x.Name)))
            {
                if (hits.Count >= MaxCandidates) return;
                var k = t;
                hits.Add(new Hit(new NativeTypeCandidate(Swift + ":" + t.Name, t.Name, t.Kind, -1, Swift), () => SwiftView(c, k, swift)));
            }
    }

    private static NativeTypeView? AppleView(Context c, string prefix, string rest, CancellationToken ct)
    {
        var (objc, swift) = AppleNames.Metadata(c.Native, ct);
        if (prefix == ObjC)
        {
            if (objc?.Classes.FirstOrDefault(x => x.Name == rest) is { } cls) return ObjcView(c, cls);
            return objc?.Protocols.FirstOrDefault(x => x.Name == rest) is { } p ? ObjcProtocolView(p) : null;
        }
        return swift?.Types.Concat(swift.Protocols).FirstOrDefault(x => x.Name == rest) is { } t ? SwiftView(c, t, swift) : null;
    }

    private static List<string> MethodNotes(string owner, IReadOnlyList<ObjcMethod> methods, Func<ulong, string> va)
    {
        var notes = methods.Take(MethodsListed).Select(m =>
            $"{(m.IsClassMethod ? '+' : '-')}[{owner} {m.Selector}]{(m.Optional ? " (optional)" : "")}{(m.Imp != 0 ? " at " + va(m.Imp) : "")}{(m.Types != null ? "; types " + m.Types : "")}").ToList();
        if (methods.Count > MethodsListed) notes.Add($"+{methods.Count - MethodsListed} more methods");
        return notes;
    }

    private static NativeTypeView ObjcView(Context c, ObjcClass cls)
    {
        long pointer = PointerSize(c.Native);
        var fields = new List<NativeTypeField> { new(0, pointer, "isa", "Class", null, "header", null, null, null) };
        foreach (var v in cls.Ivars.OrderBy(v => v.Offset ?? uint.MaxValue))
            fields.Add(new NativeTypeField(v.Offset is { } o ? o : -1, v.Size, v.Name, ObjcTypeEncoding.ToC(v.Type), null, "member", null, null,
                (v.Type is { Length: > 0 } t ? "encoding " + t + "; " : "") + $"offset variable at {VaText(v.OffsetVa)}"));
        var bases = cls.Superclass is { } super
            ? new List<NativeTypeBase> { new(0, super, cls.SuperclassExternal ? null : ObjC + ":" + super, false) }
            : [];
        var notes = new List<string> { $"class object at {VaText(cls.Va)}, metaclass at {VaText(cls.MetaclassVa)}{(cls.SuperclassExternal ? $"; superclass {cls.Superclass} is in another image" : "")}" };
        if (cls.SwiftName != null) notes.Add($"Swift class {cls.SwiftName}: id {Swift}:{cls.SwiftName}");
        else if (cls.IsSwift) notes.Add("a Swift class exposed to Objective-C");
        if (cls.Protocols.Count > 0) notes.Add("protocols: " + string.Join(", ", cls.Protocols));
        notes.AddRange(cls.Properties.Select(p => $"@property {p.Name} ({p.Attributes})"));
        notes.AddRange(MethodNotes(cls.Name, cls.Methods, VaText));
        return Empty(ObjC + ":" + cls.Name, cls.Name, "class", ObjC, cls.InstanceSize) with
        {
            Fields = fields, TotalFields = fields.Count, Bases = bases, Alignment = pointer, Notes = notes,
        };
    }

    private static NativeTypeView ObjcProtocolView(ObjcProtocol p)
    {
        var notes = new List<string>();
        if (p.Protocols.Count > 0) notes.Add("inherits " + string.Join(", ", p.Protocols));
        notes.AddRange(p.Properties.Select(x => $"@property {x.Name} ({x.Attributes})"));
        notes.AddRange(MethodNotes(p.Name, p.Methods, VaText));
        return Empty(ObjC + ":" + p.Name, p.Name, "protocol", ObjC, -1) with { Notes = notes };
    }

    private static NativeTypeView SwiftView(Context c, SwiftType t, AppleSwiftMetadata swift)
    {
        var fields = t.Fields.Select(f => new NativeTypeField(-1, -1, f.Name, f.Type ?? "", f.Type != null && swift.Types.Any(x => x.Name == f.Type) ? Swift + ":" + f.Type : null,
            "member", null, null, (t.Kind == "enum" ? "case" : f.IsVar ? "var" : "let") + (f.IsIndirect ? ", indirect" : "") + (f.MangledType is { } m ? "; mangled " + m : ""))).ToList();
        var bases = t.Superclass is { } super ? new List<NativeTypeBase> { new(0, super, swift.Types.Any(x => x.Name == super) ? Swift + ":" + super : null, false) } : [];
        var vftables = new List<NativeVftable>();
        if (t.Methods.Count > 0)
            vftables.Add(new NativeVftable(VaText(t.Methods[0].DescriptorVa), 0, t.Methods.Count, t.Methods.Select((m, i) => new NativeVftableSlot(i, i,
                m.Impl != 0 ? VaText(m.Impl) : "", m.Impl != 0 && m.Impl >= c.Native.Image.ImageBase ? c.Index?.NameAt((uint)(m.Impl - c.Native.Image.ImageBase)) ?? m.Kind : m.Kind))
                .Skip(c.SlotOffset).Take(c.SlotLimit).ToList()));
        var notes = new List<string> { $"descriptor at {VaText(t.DescriptorVa)}" + (t.AccessorVa != 0 ? $", metadata accessor at {VaText(t.AccessorVa)}" : "") };
        if (t.Kind != "protocol" && t.Fields.Count > 0) notes.Add("field offsets are set in the type metadata at run time; the descriptor lists names and types");
        if (t.IsGeneric) notes.Add("generic: the layout depends on the arguments");
        if (vftables.Count > 0) notes.Add("vtable: method descriptors in the class descriptor (slot offsets are entry indexes)");
        var conforms = swift.Conformances.Where(x => x.Type == t.Name).Select(x => x.Protocol).Distinct().ToList();
        if (conforms.Count > 0) notes.Add("conforms to " + string.Join(", ", conforms));
        return Empty(Swift + ":" + t.Name, t.Name, t.Kind, Swift, -1) with
        {
            Fields = fields, TotalFields = fields.Count, Bases = bases, Vftables = vftables, Notes = notes,
        };
    }

    private static string VaText(ulong va) => $"0x{va:X}";
}
