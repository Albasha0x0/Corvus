namespace Corvus.Native.Dump.Managed;

// Plain data of a decoded CLR, shared with the 32-bit decoder process (which returns it as JSON).

/// <summary>A managed frame: a method (with token and IL offset when the runtime has them) or a runtime transition frame.</summary>
public sealed record ManagedFrame(ulong Ip, ulong Sp, bool IsMethod, string Name, int? Token, int? IlOffset, string? ModulePath, Guid? Mvid, ulong? MethodStart);

/// <summary>A managed exception object with its stack and inner chain.</summary>
public sealed record ManagedException(string Type, string? Message, int HResult, ulong Address, uint? ThreadId, IReadOnlyList<ManagedFrame> Stack, ManagedException? Inner);

/// <summary>Heap facts: whether objects can be walked, and why not.</summary>
public sealed record ManagedHeapState(bool Walkable, int Segments, ulong Bytes, string? Reason);

/// <summary>App domains, managed threads and heap facts.</summary>
public sealed record ManagedFacts(int AppDomains, int Threads, ManagedHeapState Heap);

/// <summary>A managed type and the module that defines it (path, MVID read from dump memory, TypeDef token).</summary>
public sealed record ManagedType(string Name, string? ModulePath, Guid? Mvid, int Token);

/// <summary>One type's share of the heap.</summary>
public sealed record HeapTypeStat(ManagedType Type, long Count, ulong TotalSize);

/// <summary>One heap object; strings carry their (clipped) value.</summary>
public sealed record HeapObject(ulong Address, string Type, ulong Size, string? Value);

/// <summary>A bounded heap walk: statistics by type, the requested page of matching objects, and how far the walk went.</summary>
public sealed record HeapWalk(IReadOnlyList<HeapTypeStat> Stats, IReadOnlyList<HeapObject> Objects, long Matched, long Walked, bool Stopped);

/// <summary>A field (or array element) of an object, flattened: nested fields of expanded references and structs carry a dotted path.</summary>
public sealed record ObjectField(string Path, int Depth, string? Type, int? Offset, string? Value, ulong? Address);

/// <summary>An object's contents: its fields, string value or array elements, bounded.</summary>
public sealed record ObjectView(ulong Address, ManagedType Type, ulong Size, string? Value, int? Length, IReadOnlyList<ObjectField> Fields, bool Truncated);
