using System.ComponentModel;
using Corvus.Native;

namespace Corvus.Tools;

// Records of the .NET read tools; the call filter adds limit, totalExact, hasMore and nextOffset to lists.

internal static class DotnetDoc
{
    public const string Assembly = "Assembly id; only when several assemblies are listed.";
    public const string Basis = "observed (the code names it) or derived (through a base or interface declaration, or a delegate field).";
}

public sealed record NamespaceEntry([property: Description("'' for the global namespace.")] string Namespace, int Types)
{
    [Description(DotnetDoc.Assembly)] public string? Assembly { get; init; }
}

public sealed record NamespaceList(IReadOnlyList<NamespaceEntry> Items, int Offset, int Total);

public sealed record TypeEntry(string Token, [property: Description("Full name.")] string Name)
{
    [Description("struct, interface, enum, delegate, static class ... (with modifiers); absent: class.")] public string? Kind { get; init; }
    [Description(DotnetDoc.Assembly)] public string? Assembly { get; init; }
}

public sealed record TypeList(IReadOnlyList<TypeEntry> Items, int Offset, int Total)
{
    [Description(SearchDoc.NotEvaluated)] public int NotEvaluated { get; init; }
    public bool? TotalExact { get; init; }
}

public sealed record MemberEntry(
    string Token,
    [property: Description("Declaration as C#.")] string Signature)
{
    [Description("nested, field, property, event or method (section summary and all).")] public string? Kind { get; init; }
    [Description("RVA / offset from the dummy assembly's attributes.")] public string? Address { get; init; }
    [Description("Methods: IL instruction count; absent without a body.")] public int? Il { get; init; }
}

/// <summary>A member in a list row: what other tools take as symbol (label or token, with assembly).</summary>
public sealed record MemberRow(string Label, string Token)
{
    [Description(DotnetDoc.Assembly)] public string? Assembly { get; init; }
}

public sealed record TypeOutline(
    SymbolRef Type,
    [property: Description("Declaration line: modifiers, kind, name, base types.")] string Declaration,
    [property: Description("Members per kind.")] IReadOnlyDictionary<string, int> Counts,
    [property: Description("The section listed in items.")] string Section,
    IReadOnlyList<MemberEntry> Items,
    int Offset,
    int Total)
{
    public string? DeclaringType { get; init; }
    public IReadOnlyList<string>? Attributes { get; init; }
    [Description("Compiler-generated members left out (includeCompilerGenerated=false).")] public bool CompilerGeneratedHidden { get; init; }
    [Description("A FieldRVA field's data; items are its 16-byte rows.")] public FieldDataInfo? InitialData { get; init; }
}

public sealed record FieldDataInfo(string Rva, string? FileOffset, [property: Description("File bytes equal the declared data.")] bool Verified, int Size, string Sha256)
{
    public string? ElementType { get; init; }
    [Description("The first ones.")] public IReadOnlyList<string>? Elements { get; init; }
    public IReadOnlyList<string>? ReadBy { get; init; }
}

public sealed record TypeHierarchy(
    SymbolRef Type,
    [property: Description("Base types, nearest first.")] IReadOnlyList<string> BaseChain,
    IReadOnlyList<string> Interfaces,
    [property: Description("Types deriving from it directly (implementing it, for an interface).")] IReadOnlyList<MemberRow> Items,
    int Offset,
    int Total);

public sealed record AttributeEntry(
    [property: Description("type, method, field, property, event, param:<name>, return, assembly or module.")] string Target,
    [property: Description("The attribute with its arguments, as C#.")] string Attribute)
{
    [Description("The member carrying it, on its first row; absent for assembly and module.")] public string? Owner { get; init; }
    [Description("Constructor arguments, then named ones.")] public IReadOnlyList<AttributeArgumentEntry>? Arguments { get; init; }
    public string? Token { get; init; }
    public string? Assembly { get; init; }
}

public sealed record AttributeArgumentEntry(string Type, [property: Description("As C#.")] string Value)
{
    [Description("Named arguments only.")] public string? Name { get; init; }
}

/// <summary>get_attributes: rows, or with format=csharp the assembly attributes as a code page (code, offset, nextOffset, totalChars).</summary>
public sealed record AttributeList(IReadOnlyList<AttributeEntry>? Items, int Offset, int? Total)
{
    [Description("format=csharp: the decompiled attributes.")] public string? Code { get; init; }
    public int? NextOffset { get; init; }
    public int? TotalChars { get; init; }
}

public sealed record SymbolMatch(string Kind, string Label, string Assembly, string Token)
{
    [Description("Declaration as C#.")] public string? Signature { get; init; }
}

public sealed record SymbolList(IReadOnlyList<SymbolMatch> Items, int Offset, int Total)
{
    [Description(SearchDoc.NotEvaluated)] public int NotEvaluated { get; init; }
    public bool? TotalExact { get; init; }
}

/// <summary>A code page: decompiled C#, IL or native code from offset, with the symbols it shows.</summary>
public sealed record CodePage(
    [property: Description("csharp, il or asm.")] string Language,
    string Code,
    int Offset,
    [property: Description("Character offset of the next page; absent on the last.")] int? NextOffset,
    int TotalChars)
{
    [Description("The members shown.")] public IReadOnlyList<SymbolRef>? Symbols { get; init; }
    [Description("get_il: each method's normalized IL hash and raw IL SHA-256 (docs/il-hash.md).")] public IReadOnlyList<IlMethodHash>? Methods { get; init; }
    [Description("get_r2r_code: the compiled bodies.")] public IReadOnlyList<R2rBody>? Bodies { get; init; }
}

public sealed record IlMethodHash(string Token, string? IlHash, string? RawSha256);

public sealed record StringEntry(
    [property: Description("The literal (clipped at 200 characters).")] string Value,
    [property: Description("il (ldstr), constant (const field), metadata (stringliteral.json or script.json).")] string Source)
{
    [Description("Method or field using it (il, constant).")] public SymbolRef? Owner { get; init; }
    public int? IlOffset { get; init; }
    [Description("Value was clipped.")] public bool? Clipped { get; init; }
    [Description("Metadata literals: RVA of the slot.")] public string? SlotRva { get; init; }
    [Description("Metadata literals: functions loading it, up to usesPerLiteral.")] public IReadOnlyList<string>? LoadedBy { get; init; }
}

public sealed record StringList(IReadOnlyList<StringEntry> Items, int Offset, int Total)
{
    [Description(SearchDoc.NotEvaluated)] public int NotEvaluated { get; init; }
    public bool? TotalExact { get; init; }
}

public sealed record ConstantEntry([property: Description("The member using it.")] string Owner, string Token, string Assembly,
    [property: Description("Where it appears: ldc.i4, const field, enum member, attribute, array initializer.")] string Kind, string Value)
{
    public int? IlOffset { get; init; }
}

public sealed record ConstantList(string Value, IReadOnlyList<ConstantEntry> Items, int Offset, int Total);

public sealed record IlMatchEntry(SymbolRef Method, int IlOffset, [property: Description("Matched instructions (up to context).")] IReadOnlyList<string> Instructions);

public sealed record IlMatchList(IReadOnlyList<IlMatchEntry> Items, int Offset, int Total);

public sealed record ReferenceEntry(
    [property: Description("call, read, write, base type, attribute, override, native call, ...")] string Kind,
    [property: Description(DotnetDoc.Basis)] string Basis)
{
    [Description("Member containing the reference (kind=overrides: the override); absent: the previous row's.")] public string? Where { get; init; }
    public string? Token { get; init; }
    public string? Assembly { get; init; }
    public int? IlOffset { get; init; }
    public string? Detail { get; init; }
    [Description("Native targets: the P/Invoke declaration the call goes through.")] public string? Via { get; init; }
}

public sealed record ReferenceList(
    [property: Description("What was searched: Ns.Type::Member, or the native export.")] string Target,
    IReadOnlyList<ReferenceEntry> Items, int Offset, int Total);

public sealed record CalleeEntry(
    [property: Description("call, read, write, address, new, cast, string, ...; native rows: the edge.")] string Kind,
    string Target)
{
    public int? IlOffset { get; init; }
    public string? OpCode { get; init; }
    [Description("Assembly defining the target, when loaded.")] public string? TargetAssembly { get; init; }
    [Description("Native code a P/Invoke target binds to.")] public string? Native { get; init; }
    [Description("Uses collapsed into this entry (distinct=true).")] public int? Count { get; init; }
    [Description("Native rows: the node of the native call tree.")] public NativeTreeNode? Node { get; init; }
}

public sealed record CalleeList(string Method, IReadOnlyList<CalleeEntry> Items, int Offset, int Total);

/// <summary>A get_call_tree row: rows are in tree order, so a row's parent is the nearest row above it one level up.</summary>
public sealed record CallTreeRow([property: Description("Method label, external call, or native function or import.")] string Name)
{
    [Description("Levels below the root (1: direct callers or callees); absent: the row above's.")] public int? Depth { get; init; }
    [Description("Managed: metadata token.")] public string? Token { get; init; }
    [Description("Assembly or image id when it differs from the root's.")] public string? Assembly { get; init; }
    [Description("Native: VA.")] public string? Address { get; init; }
    [Description("virtual, delegate, external, pinvoke, native, import, ...; absent: direct call.")] public string? Edge { get; init; }
    [Description("repeated, recursive, more, unresolved, not-loaded.")] public IReadOnlyList<string>? Flags { get; init; }
    [Description("xN, via Base::Method, expanded under ..., binding details.")] public string? Note { get; init; }
    [Description("derived: via a base or interface method, delegate field or virtual target; else observed.")] public string? Basis { get; init; }
}

public sealed record CallTree(
    string Root,
    [property: Description("callers or callees.")] string Direction,
    int Depth,
    IReadOnlyList<CallTreeRow> Items,
    int Offset,
    int Total)
{
    public bool? TotalExact { get; init; }
}

public sealed record PathStepEntry([property: Description("Method label or native function.")] string Name)
{
    [Description("Managed: metadata token; native: VA.")] public string? Token { get; init; }
    [Description("Assembly or image id, when it differs from the previous step's.")] public string? Assembly { get; init; }
    [Description("Reached by virtual dispatch through this base/interface method.")] public string? Via { get; init; }
    [Description("Native steps: the call site (VA) in the previous step.")] public string? Site { get; init; }
    [Description("Native: call, tail, import, virtual_exact, virtual_possible, pointer or pinvoke.")] public string? Edge { get; init; }
    [Description("derived: via virtual dispatch, an engine reference, a virtual target or a pointer; else observed.")] public string? Basis { get; init; }
}

public sealed record CallPathEntry(IReadOnlyList<PathStepEntry> Steps, int VirtualHops)
{
    [Description("Native targets: the final P/Invoke -> native hop.")] public string? NativeHop { get; init; }
    [Description("Native: why the first step is a start (entry point, export, TLS callback, address taken, no callers, from).")] public string? Root { get; init; }
}

public sealed record CallPathList(string Target, IReadOnlyList<CallPathEntry> Items, int Offset, int Total)
{
    public string? From { get; init; }
    public bool? TotalExact { get; init; }
    /// <summary>The search stopped at the page end: more paths may follow (the call filter turns it into hasMore).</summary>
    public bool Truncated { get; init; }
    [Description(EngineDoc.Engine)] public string? Engine { get; init; }
}

public sealed record ResourceEntry(
    string Name,
    [property: Description("Embedded, .resources, linked, or a Win32 resource type.")] string Kind)
{
    public long? Size { get; init; }
    [Description(".resources: entry count.")] public int? Entries { get; init; }
    public bool? Public { get; init; }
    [Description("Win32: where the data is.")] public string? Rva { get; init; }
    [Description("File offset of the data.")] public string? FileOffset { get; init; }
    [Description("Win32: end of the data in the file (exclusive); absent if past the file.")] public string? FileEnd { get; init; }
    [Description("Win32: the code page, when not 0.")] public int? CodePage { get; init; }
    [Description("SHA-256 of the data.")] public string? Sha256 { get; init; }
    [Description("Win32 icon groups: the RT_ICON ids.")] public IReadOnlyList<int>? Icons { get; init; }
    [Description("Win32 icon groups: each entry with its stated size and RT_ICON resource (absent: missing).")] public IReadOnlyList<IconRef>? IconEntries { get; init; }
    [Description("Win32 icons: the groups naming them.")] public IReadOnlyList<string>? IconGroups { get; init; }
    [Description("Win32 icons, cursors, bitmaps: the decoded header (png 256x256, dib 32x32 32bpp).")] public string? Image { get; init; }
}

/// <summary>An icon group entry: its RT_ICON id, the size and depth the group states, and that icon's TYPE/NAME/LANGUAGE.</summary>
public sealed record IconRef(int Id, int Width, int Height, int BitCount, string? Resource);

public sealed record ResourceList(string Assembly, IReadOnlyList<ResourceEntry> Items, int Offset, int Total);

/// <summary>get_resource: a text or hex page of one resource.</summary>
public sealed record ResourcePage(
    string Name,
    [property: Description("text, xaml, hex, entries or image.")] string Kind,
    string Code,
    int Offset,
    int? NextOffset,
    int TotalChars)
{
    [Description("outputPath: where the bytes were written.")] public string? SavedTo { get; init; }
    public long? Size { get; init; }
}

public sealed record R2rBody(string Label, string EntryVa, int Size, [property: Description("Code ranges: hot, funclets, cold.")] int Ranges)
{
    [Description("Disassembled on this page (else only listed: maxBodies).")] public bool Disassembled { get; init; }
}

public sealed record R2rMethod(string Label, string EntryVa, int Size)
{
    public string? Token { get; init; }
    [Description("Assembly id, or the composite component holding it.")] public string? Assembly { get; init; }
}

/// <summary>find_r2r_method: what a native address of ReadyToRun code is.</summary>
public sealed record R2rLookup(
    string Address,
    [property: Description("The file holding the code.")] string File,
    [property: Description("method (main, funclet or cold code) or import_cell.")] string Kind)
{
    public string? Begin { get; init; }
    public string? End { get; init; }
    [Description("Offset of the address from Begin.")] public string? Offset { get; init; }
    [Description("The methods whose code it is (several when code is shared).")] public IReadOnlyList<R2rMethod>? Methods { get; init; }
    public string? Instruction { get; init; }
    [Description("An import cell: what it resolves to.")] public string? ImportCell { get; init; }
}

/// <summary>export_project's outcome.</summary>
public sealed record ExportOutcome(
    [property: Description("The export completed and is in outputDirectory.")] bool Applied,
    [property: Description("The assembly id or package file exported.")] string Source,
    string OutputDirectory,
    [property: Description("Files written.")] int Files,
    [property: Description(".csproj, or the Gradle build file of a package.")] string? ProjectFile,
    [property: Description("Types the decompiler failed on; their files hold the error.")] IReadOnlyList<string> FailedTypes)
{
    [Description("A previous export in the directory was replaced (overwrite=true).")] public bool Replaced { get; init; }
    [Description("Renamed references; package source notes.")] public IReadOnlyList<string>? Notes { get; init; }
}
