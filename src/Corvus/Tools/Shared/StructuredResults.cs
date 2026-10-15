using System.ComponentModel;
using dnlib.DotNet;
using Corvus.Core;

namespace Corvus.Tools;

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

public sealed record ExportEntry(int Ordinal, [property: Description("VA; null for a forwarder.")] string? Address, string? Name, string? Demangled, string? ForwardedTo,
    [property: Description("ELF symbol version: @@VERSION (default) or @VERSION.")] string? Version = null);

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
    [property: Description("Recovered call arguments, the import it goes through, or the whole row when it has no address.")] string? Detail)
{
    [Description("direction=from: VA of the referenced target; null for a reference to the address.")]
    public string? Target { get; init; }

    [Description("With addresses: the target (as given) of this row's section.")]
    public string? Of { get; init; }
}

public sealed record XrefList(string Image, string Target, IReadOnlyList<XrefEntry> Items, int Offset, int Total, bool Truncated,
    [property: Description("An import slot: the export it is bound to.")] string? BoundTo,
    [property: Description(EngineDoc.Engine)] string Engine,
    [property: Description(EngineDoc.Note)] string? EngineNote)
{
    [Description("With addresses: one item per target, in order, with its reference count or its error.")]
    public IReadOnlyList<BatchItem<XrefTargetCount>>? Targets { get; init; }

    [Description("With addresses: how many targets failed.")]
    public int? Failed { get; init; }
}

/// <summary>A find_xrefs batch target: the target as resolved and its reference count.</summary>
public sealed record XrefTargetCount(string Resolved, int Total);

/// <summary>
/// The record of a text tool (code or a long text paged by characters): the page and where the next one starts (D3).
/// The call filter fills it from the tool's page.
/// </summary>
public sealed record TextPageRecord(
    [property: Description("The page of text.")] string Code,
    int Offset,
    [property: Description("Character offset of the next page; absent on the last.")] int? NextOffset,
    int TotalChars);

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

public sealed record NativeStringEntry(string Address, [property: Description("ascii, utf16, il2cpp (a string literal slot), nativeaot (a frozen String object) or engine:type (e.g. ghidra:unicode).")] string Encoding,
    [property: Description("Text, clipped at maxLength.")] string Text, int References, string? FirstFunction)
{
    [Description("The full length in characters when Text is clipped.")] public int? Length { get; init; }
    [Description("nativeaot: the String MethodTable the object points to.")] public string? MethodTable { get; init; }
}

public sealed record NativeStringList(string Image, IReadOnlyList<NativeStringEntry> Items, int Offset, int Total, bool Truncated)
{
    [Description(SearchDoc.NotEvaluated)] public int NotEvaluated { get; init; }
}

public sealed record AddressInfo(
    string Image,
    string? Rva,
    string? Va,
    [property: Description("File offset; null in zero fill or outside the file.")] string? FileOffset,
    string? Section,
    [property: Description("rwx of the section.")] string? Access,
    string? Name,
    [property: Description("user, pdb, il2cpp, ...")] string? NameSource,
    [property: Description("An IAT slot: module!name.")] string? Import,
    string? BoundTo,
    [property: Description("The export at the address, or the nearest before it as name+0xN.")] string? Export)
{
    [Description("Containing function as name+0xN (code index built).")] public string? Function { get; init; }
    [Description("decoded, mid_instruction, data, not_in_function, unmapped, outside_image or invalid (x86 / x64, code index built).")] public string? Status { get; init; }
    [Description("mid_instruction: the instruction covering the address.")] public string? ContainingInstruction { get; init; }
    [Description("The data item covering the address, as kind: text.")] public string? DataItem { get; init; }
    public string? Comment { get; init; }
    [Description("Cross-references to the address by kind.")] public IReadOnlyDictionary<string, int>? ReferencesTo { get; init; }
    [Description("With addresses: one item per address, in order, with its record or its error.")] public IReadOnlyList<BatchItem<AddressInfo>>? Results { get; init; }
    [Description("With addresses: how many failed.")] public int? Failed { get; init; }
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
