using System.ComponentModel;
using dnlib.DotNet;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Tools;

// Structured content of the list, search and info tools that agents chain together. The text block keeps the readable
// form; these records carry the same facts with names, tokens and addresses as separate fields. Lists are paged: items
// from offset, total counts every match, truncated says items stop before the end (page on with offset + items.Count).

/// <summary>A type or member: what other tools take as symbol (label or token, with assembly).</summary>
public sealed record SymbolRef(
    [property: Description("type, method, field, property or event.")] string Kind,
    [property: Description("Ns.Type or Ns.Type::Member(params).")] string Label,
    [property: Description("Assembly id.")] string Assembly,
    [property: Description("Metadata token, 0x06000001.")] string Token)
{
    public static SymbolRef Of(LoadedAssembly asm, IMemberDef member) =>
        new(MemberKind(member), Format.MemberLabel(member), asm.Id, Format.Token(member));

    public static SymbolRef Of(ResolvedSymbol s) => Of(s.Assembly, s.Member);

    public static string MemberKind(IMemberDef m) => m switch
    {
        TypeDef => "type",
        MethodDef => "method",
        FieldDef => "field",
        PropertyDef => "property",
        EventDef => "event",
        _ => "member",
    };
}

public sealed record NamespaceEntry(string Assembly, [property: Description("'' for the global namespace.")] string Namespace, int Types);

public sealed record NamespaceList(IReadOnlyList<NamespaceEntry> Items, int Offset, int Total, bool Truncated);

public sealed record TypeEntry(string Assembly, string Token, [property: Description("class, struct, interface, enum, delegate (with modifiers).")] string Kind, string FullName);

public sealed record TypeList(IReadOnlyList<TypeEntry> Items, int Offset, int Total, bool Truncated)
{
    [Description(SearchDoc.NotEvaluated)] public int NotEvaluated { get; init; }
}

public sealed record MemberEntry(
    string Token,
    string Name,
    [property: Description("Declaration as C#.")] string Signature,
    [property: Description("Il2Cpp RVA / offset from the dummy DLL's attributes.")] string? Il2Cpp,
    [property: Description("Methods: IL instruction count; null without a body.")] int? IlInstructions);

public sealed record TypeOutline(
    SymbolRef Type,
    string FullName,
    [property: Description("Declaration line: modifiers, kind, name, base types.")] string Declaration,
    string? DeclaringType,
    IReadOnlyList<string> Attributes,
    IReadOnlyList<MemberEntry> NestedTypes,
    IReadOnlyList<MemberEntry> Fields,
    IReadOnlyList<MemberEntry> Properties,
    IReadOnlyList<MemberEntry> Events,
    IReadOnlyList<MemberEntry> Methods,
    [property: Description("Compiler-generated members left out (includeCompilerGenerated=false).")] bool CompilerGeneratedHidden,
    [property: Description("A member list was cut at 2000 entries.")] bool Truncated);

public sealed record SymbolMatch(string Kind, string Label, string Assembly, string Token, [property: Description("Declaration, when asked for.")] string? Signature);

public sealed record SymbolList(IReadOnlyList<SymbolMatch> Items, int Offset, int Total, bool Truncated)
{
    [Description(SearchDoc.NotEvaluated)] public int NotEvaluated { get; init; }
}

public sealed record OverrideList(SymbolRef Method, IReadOnlyList<SymbolMatch> Items, int Offset, int Total, bool Truncated);

public sealed record StringEntry(
    [property: Description("The literal (clipped at 2000 characters).")] string Value,
    [property: Description("il (ldstr), constant (const field), il2cpp (the dump's string literal table).")] string Source,
    [property: Description("Method or field using it (il, constant).")] SymbolRef? Owner,
    int? IlOffset,
    [property: Description("Il2Cpp: RVA of the literal's slot.")] string? SlotRva,
    [property: Description("Il2Cpp: functions loading it (methods by label, else RVAs), up to usesPerLiteral.")] IReadOnlyList<string>? LoadedBy);

public sealed record StringList(IReadOnlyList<StringEntry> Items, int Offset, int Total, bool Truncated)
{
    [Description(SearchDoc.NotEvaluated)] public int NotEvaluated { get; init; }
}

public sealed record ConstantEntry(SymbolRef Owner, int? IlOffset, [property: Description("Where it appears: ldc.i4, const field, enum member, attribute, array initializer.")] string Kind, string Value);

public sealed record ConstantList(string Value, IReadOnlyList<ConstantEntry> Items, int Offset, int Total, bool Truncated);

public sealed record IlMatchEntry(SymbolRef Method, int IlOffset, [property: Description("Matched instructions (first 24).")] IReadOnlyList<string> Instructions);

public sealed record IlMatchList(IReadOnlyList<IlMatchEntry> Items, int Offset, int Total, bool Truncated);

public sealed record ReferenceEntry(
    [property: Description("Method, type or member containing the reference.")] SymbolRef Where,
    int? IlOffset,
    [property: Description("call, read, write, base type, attribute, ...")] string Kind,
    string? Detail,
    [property: Description("Native targets: the P/Invoke declaration the call goes through.")] string? Via);

public sealed record ReferenceList(
    [property: Description("What was searched: Ns.Type::Member, or the native export.")] string Target,
    IReadOnlyList<ReferenceEntry> Items,
    [property: Description("Native call sites in loaded images, as text rows.")] IReadOnlyList<string> NativeCallSites,
    int Offset, int Total, bool Truncated);

public sealed record CalleeEntry(
    int? IlOffset,
    string? OpCode,
    [property: Description("call, read, write, address, new, cast, string, ...")] string Kind,
    string Target,
    [property: Description("Assembly defining the target, when loaded.")] string? TargetAssembly,
    [property: Description("Native code a P/Invoke target binds to.")] string? Native,
    [property: Description("Uses collapsed into this entry (distinct=true), else 1.")] int Count);

public sealed record CalleeList(
    string Method,
    IReadOnlyList<CalleeEntry> Items,
    [property: Description("Native code below (P/Invoke methods, native symbols), as indented text lines.")] IReadOnlyList<string> NativeLines,
    int Offset, int Total, bool Truncated);

public sealed record CallTree(
    string Root,
    [property: Description("callers or callees.")] string Direction,
    int Depth,
    [property: Description("Nodes in tree order (depth-first).")] IReadOnlyList<Services.CallGraphService.TreeNode> Items,
    int Total,
    [property: Description("maxNodes stopped the walk, or items were cut to fit the response.")] bool Truncated);

public sealed record PathStepEntry(SymbolRef Method, [property: Description("Reached by virtual dispatch through this base/interface method.")] string? Via);

public sealed record CallPathEntry(IReadOnlyList<PathStepEntry> Steps, int VirtualHops, [property: Description("Native targets: the final P/Invoke -> native hop.")] string? NativeHop);

public sealed record CallPathList(string Target, string? From, IReadOnlyList<CallPathEntry> Items, int Total, bool Truncated);

public sealed record ResourceEntry(
    string Name,
    [property: Description("Embedded, .resources, linked, or a Win32 resource type.")] string Kind,
    long? Size,
    [property: Description(".resources: entry count.")] int? Entries,
    bool? Public);

public sealed record ResourceList(string Assembly, IReadOnlyList<ResourceEntry> Items, int Total, bool Truncated);

public sealed record ImportEntry(
    [property: Description("VA of the IAT slot code calls through (dynamic: the pointer global or the GetProcAddress call).")] string Address,
    string Module,
    [property: Description("Function name, or #ordinal.")] string Name,
    [property: Description("API set name: the DLL it resolves to on this system.")] string? ApiSetHost,
    bool Delay,
    [property: Description("Late-bound (GetProcAddress) rather than in the import table.")] bool Dynamic,
    [property: Description("bind=true: the export it reaches, or why not.")] string? Binding,
    [property: Description("Dynamic: where it is resolved, confidence, how.")] string? Detail);

public sealed record ImportList(string Image, IReadOnlyList<ImportEntry> Items, int Offset, int Total, bool Truncated,
    [property: Description("bind=true: counts of bound / not loaded / unresolved.")] string? Bindings);

public sealed record ExportEntry(int Ordinal, [property: Description("VA; null for a forwarder.")] string? Address, string? Name, string? Demangled, string? ForwardedTo);

public sealed record ExportList(string Image, IReadOnlyList<ExportEntry> Items, int Offset, int Total, bool Truncated);

public sealed record FunctionEntry(
    string Address,
    int Size,
    string Name,
    [property: Description("thunk, noreturn, unresolved jumps, invalid code, truncated, funclet, ...")] IReadOnlyList<string> Flags,
    [property: Description("How it was found.")] string Sources,
    [property: Description("Call sites and other references reaching it.")] int References);

public sealed record FunctionList(string Image,
    [property: Description("Functions in the image (before the filter).")] int Functions,
    IReadOnlyList<FunctionEntry> Items, int Offset, int Total, bool Truncated,
    [property: Description("What the index does not cover.")] string? Coverage,
    [property: Description(EngineDoc.Engine)] string Engine,
    [property: Description(EngineDoc.Note)] string? EngineNote);

public sealed record XrefEntry(
    [property: Description("Another loaded image the reference is in (imports of an export), else null.")] string? Image,
    [property: Description("VA of the referencing instruction or data.")] string? Address,
    [property: Description("Call, Jump, Read, Write, Address, CallReg, Resolve, DynCall, ...")] string? Kind,
    [property: Description("function+offset containing it.")] string? Function,
    [property: Description("Recovered call arguments, the import it goes through, or the whole row when it has no address.")] string? Detail);

public sealed record XrefList(string Image, string Target, IReadOnlyList<XrefEntry> Items, int Offset, int Total, bool Truncated,
    [property: Description("An import slot: the export it is bound to.")] string? BoundTo,
    [property: Description(EngineDoc.Engine)] string Engine,
    [property: Description(EngineDoc.Note)] string? EngineNote);

internal static class SearchDoc
{
    public const string NotEvaluated = "Inputs the regex timed out on (1 s limit each), left out of the results: non-zero means they are incomplete.";
}

/// <summary>Descriptions of the engine fields of native code results.</summary>
internal static class EngineDoc
{
    public const string Engine = "Which analysis produced the result: ours (the built-in index), ida (IDA's analysis through idalib) or ghidra (Ghidra's analysis).";
    public const string Note = "Why that engine answered (the engine parameter or server default, and for auto whether an engine's analysis of the image was complete).";
}

public sealed record NativeStringEntry(string Address, [property: Description("ascii, utf16, il2cpp (a string literal slot) or nativeaot (a frozen String object).")] string Encoding,
    [property: Description("Text (clipped at 400 characters).")] string Text, int References, string? FirstFunction);

public sealed record NativeStringList(string Image, IReadOnlyList<NativeStringEntry> Items, int Offset, int Total, bool Truncated)
{
    [Description(SearchDoc.NotEvaluated)] public int NotEvaluated { get; init; }
}

public sealed record AddressInfo(
    string Image,
    string Rva,
    string Va,
    [property: Description("File offset; null in zero fill or outside the file.")] string? FileOffset,
    string? Section,
    [property: Description("rwx of the section.")] string? Access,
    string? Name,
    [property: Description("user, pdb, il2cpp, ...")] string? NameSource,
    [property: Description("An IAT slot: module!name.")] string? Import,
    string? BoundTo,
    [property: Description("The export at the address, or the nearest before it as name+0xN.")] string? Export,
    [property: Description("Everything the text says, line by line.")] IReadOnlyList<string> Lines)
{
    [Description("Containing function as name+0xN (code index built).")] public string? Function { get; init; }
    [Description("decoded, mid_instruction, data, not_in_function, unmapped, outside_image or invalid (x86 / x64, code index built).")] public string? Status { get; init; }
    [Description("mid_instruction: the instruction covering the address.")] public string? ContainingInstruction { get; init; }
    [Description("The data item covering the address, as kind: text.")] public string? DataItem { get; init; }
    public string? Comment { get; init; }
    [Description("Cross-references to the address by kind.")] public IReadOnlyDictionary<string, int>? ReferencesTo { get; init; }
}

public sealed record SectionEntry(string Name, string Rva, string VirtualSize, string RawOffset, string RawSize, string Access, double Entropy, IReadOnlyList<string> Characteristics);

public sealed record PeSummary(
    string Image,
    string Path,
    string Machine,
    [property: Description("dll or exe.")] string Kind,
    [property: Description("PE32 or PE32+.")] string Format,
    string Subsystem,
    long FileSize,
    string Sha256,
    string ImageBase,
    [property: Description("VA; null when there is none.")] string? EntryPoint,
    string Timestamp,
    bool DotNet,
    IReadOnlyList<string> MitigationsOn,
    IReadOnlyList<string> MitigationsOff,
    IReadOnlyList<SectionEntry> Sections,
    int ImportModules,
    int ImportFunctions,
    int DelayImportModules,
    int Exports,
    int TlsCallbacks,
    string? PdbPath,
    string? PdbGuid,
    int? PdbAge,
    string? Signer,
    [property: Description("Stored checksum matches the computed one; null when none is stored.")] bool? ChecksumMatches,
    long? OverlaySize,
    [property: Description("Malformed parts found while parsing.")] int Issues,
    [property: Description("Capability groups the imports imply (late-bound imports included once the code index is ready).")] IReadOnlyList<CapabilityEntry>? Capabilities = null,
    CodeOverview? Code = null);
