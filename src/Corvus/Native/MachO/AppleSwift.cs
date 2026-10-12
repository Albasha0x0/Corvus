using Corvus.Native.Swift;
using K = Corvus.Native.Swift.SwiftNodeKind;

namespace Corvus.Native.MachO;

/// <summary>A stored property or enum case; <see cref="Type"/> is the demangled field type (null for payload-less cases).</summary>
public sealed record SwiftField(string Name, string? Type, string? MangledType, bool IsVar, bool IsIndirect);

/// <summary>
/// A vtable entry of a Swift class: kind (method, init, getter, setter, modify, read), instance or static, and the
/// implementation (0 when it has none). <see cref="DescriptorVa"/> is the method descriptor's own address.
/// </summary>
public sealed record SwiftMethod(ulong DescriptorVa, string Kind, bool IsInstance, bool IsAsync, ulong Impl);

/// <summary>
/// A nominal type (class, struct, enum) or protocol from __swift5_types / __swift5_protos. <see cref="Name"/> is
/// qualified ("Module.Outer.Inner"); <see cref="Symbol"/> is the type's mangled entity ("12StripeUICore4ViewC")
/// when its context nests only modules and nominal types.
/// </summary>
public sealed record SwiftType(ulong DescriptorVa, string Kind, string Name, string Module, string? Symbol, bool IsGeneric, ulong AccessorVa, ulong FieldDescriptorVa,
    string? Superclass, IReadOnlyList<SwiftField> Fields, IReadOnlyList<SwiftMethod> Methods);

/// <summary>A protocol conformance record; <see cref="ProtocolExternal"/> when the protocol lives in another image (a bind).</summary>
public sealed record SwiftConformance(ulong Va, string Type, string? TypeSymbol, string Protocol, string? ProtocolSymbol, bool ProtocolExternal, ulong WitnessTableVa);

/// <summary>
/// The Swift reflection metadata of a Mach-O image: nominal types with their fields (types demangled, symbolic
/// references resolved to the types they point at, in this image or through binds), class vtables, protocols and
/// conformances. Malformed records are skipped and counted in <see cref="Issues"/>.
/// </summary>
public sealed class AppleSwiftMetadata
{
    private const int MaxRecords = 1 << 18;
    private const int MaxFields = 1 << 14;

    public IReadOnlyList<SwiftType> Types { get; }
    public IReadOnlyList<SwiftType> Protocols { get; }
    public IReadOnlyList<SwiftConformance> Conformances { get; }
    public IReadOnlyList<string> Issues { get; }
    public bool IsEmpty => Types.Count == 0 && Protocols.Count == 0 && Conformances.Count == 0;

    private AppleSwiftMetadata(List<SwiftType> types, List<SwiftType> protocols, List<SwiftConformance> conformances, List<string> issues)
    {
        Types = types;
        Protocols = protocols;
        Conformances = conformances;
        Issues = issues;
    }

    public static AppleSwiftMetadata Read(MachOFile image, CancellationToken ct = default) => new Reader(new AppleObjcImage(image), ct).Run();

    private sealed class Reader(AppleObjcImage view, CancellationToken ct)
    {
        private readonly List<string> issues = [];
        private readonly Dictionary<ulong, SwiftNode?> contextNodes = [];
        private readonly HashSet<ulong> building = [];
        private int records;

        private void Issue(string text)
        {
            if (issues.Count < 100) issues.Add(text);
        }

        private IEnumerable<ulong> Entries(string section)
        {
            foreach (var s in view.Sections(section))
                for (ulong at = s.Address; at + 4 <= s.Address + s.Size; at += 4)
                {
                    ct.ThrowIfCancellationRequested();
                    if (++records > MaxRecords) yield break;
                    yield return at;
                }
        }

        public AppleSwiftMetadata Run()
        {
            var types = new List<SwiftType>();
            foreach (var entry in Entries("__swift5_types"))
            {
                int raw = view.I32(entry);
                if (raw == 0) continue;
                ulong target = unchecked(entry + (ulong)(long)(raw & ~3));
                ulong descriptor = (raw & 3) == 1 ? view.Ptr(target).Target : target;
                if (descriptor == 0) continue;
                if (ReadType(descriptor) is { } t) types.Add(t);
            }
            var protocols = new List<SwiftType>();
            foreach (var entry in Entries("__swift5_protos"))
            {
                var p = view.RelativeIndirectable(entry);
                if (p.Symbol != null || p.Target == 0) continue;
                if (ReadType(p.Target) is { Kind: "protocol" } proto) protocols.Add(proto);
            }
            var conformances = new List<SwiftConformance>();
            foreach (var entry in Entries("__swift5_proto"))
            {
                ulong descriptor = view.Relative(entry);
                if (descriptor != 0 && ReadConformance(descriptor) is { } c) conformances.Add(c);
            }
            return new AppleSwiftMetadata(types, protocols, conformances, issues);
        }

        private static string KindName(uint kind) => kind switch { 16 => "class", 17 => "struct", 18 => "enum", 3 => "protocol", _ => "other" };

        private SwiftType? ReadType(ulong d)
        {
            if (!view.Has(d, 20))
            {
                Issue($"type descriptor at 0x{d:X} is outside the image");
                return null;
            }
            uint flags = view.U32(d), kind = flags & 0x1F;
            if (kind is not (16 or 17 or 18 or 3))
            {
                Issue($"descriptor at 0x{d:X} has kind {kind}, not a nominal type");
                return null;
            }
            var node = ContextNode(d);
            string? name = node != null ? PrintContext(node) : null;
            if (name == null)
            {
                Issue($"type descriptor at 0x{d:X}: no readable name");
                return null;
            }
            string module = ModuleOf(node!);
            bool generic = (flags & 0x80) != 0;
            if (kind == 3) return new SwiftType(d, "protocol", name, module, Mangle(node!), generic, 0, 0, null, [], []);
            ulong accessor = view.Relative(d + 12), fieldDescriptor = view.Relative(d + 16);
            string? superclass = null;
            var methods = new List<SwiftMethod>();
            if (kind == 16)
            {
                ulong superName = view.Relative(d + 20);
                if (superName != 0) superclass = TypeName(superName);
                if (!generic) ReadVtable(d, flags, methods);
            }
            var fields = fieldDescriptor != 0 ? ReadFields(fieldDescriptor) : [];
            return new SwiftType(d, KindName(kind), name, module, Mangle(node!), generic, accessor, fieldDescriptor, superclass, fields, methods);
        }

        /// <summary>
        /// The vtable of a non-generic class: after the 44-byte descriptor come the resilient superclass (4 bytes when
        /// flagged), the metadata initialization record (singleton 12 bytes, foreign 4), then the vtable header and
        /// method descriptors (flags, relative implementation).
        /// </summary>
        private void ReadVtable(ulong d, uint flags, List<SwiftMethod> into)
        {
            uint kindFlags = flags >> 16;
            if ((kindFlags & 0x8000) == 0) return;
            ulong at = d + 44;
            if ((kindFlags & 0x2000) != 0) at += 4;
            at += (kindFlags & 3) switch { 1 => 12UL, 2 => 4UL, _ => 0UL };
            uint size = view.U32(at + 4);
            if (size > MaxFields || !view.Has(at + 8, (int)size * 8))
            {
                Issue($"class descriptor at 0x{d:X}: vtable of {size} entries does not fit the image");
                return;
            }
            for (uint i = 0; i < size; i++)
            {
                ulong m = at + 8 + i * 8UL;
                uint mf = view.U32(m);
                string kind = (mf & 0xF) switch { 0 => "method", 1 => "init", 2 => "getter", 3 => "setter", 4 => "modify", 5 => "read", _ => "other" };
                into.Add(new SwiftMethod(m, kind, (mf & 0x10) != 0, (mf & 0x40) != 0, view.Relative(m + 4)));
            }
        }

        /// <summary>A field descriptor: header (mangled type, superclass, kind, record size, count), then records (flags, mangled type, name).</summary>
        private List<SwiftField> ReadFields(ulong fd)
        {
            var result = new List<SwiftField>();
            ushort recordSize = view.U16(fd + 10);
            uint count = view.U32(fd + 12);
            if (count == 0) return result;
            if (count > MaxFields || recordSize < 12 || !view.Has(fd + 16, (int)(count * recordSize)))
            {
                Issue($"field descriptor at 0x{fd:X}: {count} records of {recordSize} bytes do not fit the image");
                return result;
            }
            for (uint i = 0; i < count; i++)
            {
                ulong r = fd + 16 + i * (ulong)recordSize;
                uint flags = view.U32(r);
                ulong typeName = view.Relative(r + 4);
                var name = view.CString(view.Relative(r + 8));
                if (string.IsNullOrEmpty(name)) continue;
                var mangled = typeName != 0 ? view.MangledName(typeName) : null;
                result.Add(new SwiftField(name, typeName != 0 ? TypeName(typeName) : null, mangled != null ? Printable(mangled) : null, (flags & 2) != 0, (flags & 1) != 0));
            }
            return result;
        }

        private SwiftConformance? ReadConformance(ulong c)
        {
            if (!view.Has(c, 16))
            {
                Issue($"conformance descriptor at 0x{c:X} is outside the image");
                return null;
            }
            uint flags = view.U32(c + 12);
            var proto = view.RelativeIndirectable(c);
            SwiftNode? protoNode = null;
            if (proto.Symbol != null) protoNode = SymbolEntity(proto.Symbol, K.ProtocolDescriptor);
            else if (proto.Target != 0) protoNode = ContextNode(proto.Target);
            if (protoNode == null)
            {
                Issue($"conformance at 0x{c:X}: unreadable protocol");
                return null;
            }
            ulong typeRef = c + 4;
            SwiftNode? typeNode = null;
            string? typeName = null;
            switch ((flags >> 3) & 7)
            {
                case 0:
                    if (view.Relative(typeRef) is var direct and not 0) typeNode = ContextNode(direct);
                    break;
                case 1:
                {
                    ulong slot = view.Relative(typeRef);
                    var p = slot != 0 ? view.Ptr(slot) : default;
                    typeNode = p.Symbol != null ? SymbolEntity(p.Symbol, K.NominalTypeDescriptor) : p.Target != 0 ? ContextNode(p.Target) : null;
                    break;
                }
                case 2:
                    typeName = view.CString(view.Relative(typeRef));
                    break;
                case 3:
                {
                    ulong slot = view.Relative(typeRef);
                    var p = slot != 0 ? view.Ptr(slot) : default;
                    typeName = p.Symbol is { } s && s.StartsWith("OBJC_CLASS_$_", StringComparison.Ordinal) ? s["OBJC_CLASS_$_".Length..] : p.Symbol;
                    break;
                }
            }
            typeName ??= typeNode != null ? PrintContext(typeNode) : null;
            if (typeName == null)
            {
                Issue($"conformance at 0x{c:X}: unreadable conforming type");
                return null;
            }
            return new SwiftConformance(c, typeName, typeNode != null ? Mangle(typeNode) : null, PrintContext(protoNode) ?? "?", Mangle(protoNode), proto.Symbol != null,
                view.Relative(c + 8));
        }

        /// <summary>The entity of a demangled descriptor symbol of another image ("$s7SwiftUI4ViewMp" -> SwiftUI.View).</summary>
        private static SwiftNode? SymbolEntity(string symbol, K descriptorKind)
        {
            try
            {
                var global = SwiftDemangler.DemangleSymbolAsNode(symbol, null);
                if (global?.First is { } d && d.Kind == descriptorKind && d.First is { } type) return type.Kind == K.Type ? type : null;
            }
            catch (SwiftDemangler.TooComplex) { }
            catch (InsufficientExecutionStackException) { }
            return null;
        }

        /// <summary>
        /// The demangling node of the context descriptor at <paramref name="d"/>, wrapped in a Type node as the runtime
        /// builds it for symbolic references: modules, nominal types and protocols nested by their parents, extensions
        /// of their extended type; anonymous contexts as their parent.
        /// </summary>
        private SwiftNode? ContextNode(ulong d)
        {
            if (contextNodes.TryGetValue(d, out var known)) return known;
            if (!building.Add(d) || building.Count > 64) return null;
            SwiftNode? result = null;
            try
            {
                if (!view.Has(d, 8)) return null;
                uint kind = view.U32(d) & 0x1F;
                var parentPtr = view.RelativeIndirectable(d + 4);
                SwiftNode? Parent()
                {
                    if (parentPtr.Symbol != null) return SymbolContext(parentPtr.Symbol);
                    return parentPtr.Target != 0 ? Unwrap(ContextNode(parentPtr.Target)) : null;
                }
                switch (kind)
                {
                    case 0:
                        if (view.CString(view.Relative(d + 8)) is { Length: > 0 } moduleName) result = new SwiftNode(K.Module) { Text = moduleName };
                        break;
                    case 1:
                    {
                        var extended = view.Relative(d + 8);
                        var text = extended != 0 ? view.MangledName(extended) : null;
                        if (text == null || Unwrap(SafeTypeNode(text, extended)) is not { } extendedType || Parent() is not { } module) break;
                        result = new SwiftNode(K.Extension);
                        result.Add(module);
                        result.Add(extendedType);
                        break;
                    }
                    case 2:
                        result = Parent();
                        break;
                    case 3 or 16 or 17 or 18:
                    {
                        var name = view.CString(view.Relative(d + 8));
                        var parent = Parent();
                        if (string.IsNullOrEmpty(name) || parent == null) break;
                        var nominal = new SwiftNode(kind switch { 3 => K.Protocol, 16 => K.Class, 17 => K.Structure, _ => K.Enum });
                        nominal.Add(parent);
                        // ObjC-imported names carry a related-entity tail after a NUL; the name is the first part
                        nominal.Add(new SwiftNode(K.Identifier) { Text = name });
                        result = nominal;
                        break;
                    }
                }
                if (result != null && result.Kind != K.Module && result.Kind != K.Type)
                {
                    var type = new SwiftNode(K.Type);
                    type.Add(result);
                    result = type;
                }
                return result;
            }
            finally
            {
                building.Remove(d);
                contextNodes[d] = result;
            }
        }

        private static SwiftNode? Unwrap(SwiftNode? n) => n is { Kind: K.Type } ? n.First : n;

        /// <summary>A parent context in another image named by a bind ("$s10Foundation4DataVMn"); modules by module descriptor symbols.</summary>
        private static SwiftNode? SymbolContext(string symbol) => Unwrap(SymbolEntity(symbol, K.NominalTypeDescriptor) ?? SymbolEntity(symbol, K.ProtocolDescriptor));

        private SwiftNode? SafeTypeNode(string mangled, ulong va)
        {
            try { return SwiftDemangler.DemangleTypeAsNode(mangled, Resolver(va)); }
            catch (Exception e) when (e is SwiftDemangler.TooComplex or InsufficientExecutionStackException or NullReferenceException or ArgumentOutOfRangeException
                                           or IndexOutOfRangeException or InvalidOperationException)
            {
                return null;
            }
        }

        /// <summary>Resolves symbolic references in the mangled name stored at <paramref name="va"/>.</summary>
        private SymbolicResolver Resolver(ulong va) => (kind, direct, value, offset) =>
        {
            ulong target = unchecked(va + (ulong)offset + (ulong)(long)value);
            if (kind is SymbolicReferenceKind.Context)
            {
                if (direct) return ContextNode(target);
                var p = view.Ptr(target);
                return p.Symbol != null ? SymbolEntity(p.Symbol, K.NominalTypeDescriptor) ?? SymbolEntity(p.Symbol, K.ProtocolDescriptor)
                    : p.Target != 0 ? ContextNode(p.Target) : null;
            }
            if (kind is SymbolicReferenceKind.ObjectiveCProtocol && view.CString(view.Ptr(target + (ulong)view.PointerSize).Target) is { Length: > 0 } name)
            {
                var proto = new SwiftNode(K.Protocol);
                proto.Add(new SwiftNode(K.Module) { Text = "__C" });
                proto.Add(new SwiftNode(K.Identifier) { Text = name });
                var type = new SwiftNode(K.Type);
                type.Add(proto);
                return type;
            }
            return null;
        };

        /// <summary>The demangled text of the metadata type name at <paramref name="va"/>, or a placeholder when it does not demangle.</summary>
        private string TypeName(ulong va)
        {
            var mangled = view.MangledName(va);
            if (mangled == null) return "?";
            return SwiftDemangler.DemangleType(mangled, Resolver(va)) ?? Printable(mangled);
        }

        /// <summary>A mangled name with symbolic references shown as "&lt;ref&gt;".</summary>
        private static string Printable(string mangled)
        {
            var sb = new System.Text.StringBuilder();
            for (int i = 0; i < mangled.Length; i++)
            {
                char c = mangled[i];
                if (c is >= '\u0001' and <= '\u0017') { sb.Append("<ref>"); i += 4; }
                else if (c is >= '\u0018' and <= '\u001F') { sb.Append("<ref>"); i += 8; }
                else sb.Append(c);
            }
            return sb.ToString();
        }

        private static string? PrintContext(SwiftNode node) => SwiftDemangler.Print(node, SwiftDemangler.PrintOptions.Default);

        private static string ModuleOf(SwiftNode node)
        {
            var n = node;
            while (n != null && n.Kind != K.Module) n = n.First;
            return n?.Text ?? "";
        }

        /// <summary>
        /// The mangled entity of a nominal type or protocol whose contexts are modules and nominal types only
        /// ("7Combine16ObservableObjectP"); null otherwise.
        /// </summary>
        private static string? Mangle(SwiftNode node)
        {
            var n = Unwrap(node);
            var parts = new List<string>();
            while (n != null)
            {
                switch (n.Kind)
                {
                    case K.Module:
                        parts.Add(n.Text switch { "Swift" => "s", "__C" => "So", "__C_Synthesized" => "SC", _ => Identifier(n.Text!) ?? "" });
                        n = null;
                        break;
                    case K.Class or K.Structure or K.Enum or K.Protocol when n[1] is { Kind: K.Identifier } id && Identifier(id.Text!) is { } ident:
                        parts.Add(ident + n.Kind switch { K.Class => "C", K.Structure => "V", K.Enum => "O", _ => "P" });
                        n = n[0];
                        break;
                    default:
                        return null;
                }
            }
            if (parts.Any(p => p.Length == 0)) return null;
            parts.Reverse();
            return string.Concat(parts);
        }

        private static string? Identifier(string name) =>
            name.Length > 0 && !char.IsAsciiDigit(name[0]) && name.All(c => char.IsAsciiLetterOrDigit(c) || c == '_') ? name.Length + name : null;
    }
}
