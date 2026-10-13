using System.ComponentModel;

namespace Corvus.Native;

/// <summary>
/// One node of a native call tree, flat in tree order (a node, then its children): native_call_tree's rows, and the native rows of find_callees and
/// get_call_tree. A node with <see cref="Flags"/> "more" was not expanded; passing its address as the root continues there.
/// </summary>
public sealed record NativeTreeNode(
    [property: Description("Node id, 0 for the root.")] int Id,
    [property: Description("Parent node id; absent on the root.")] int? Parent,
    [property: Description("Levels below the root.")] int Depth,
    [property: Description("Function, import (module!name) or managed method.")] string Name,
    [property: Description("VA of the function or import slot; absent when unresolved.")] string? Address,
    [property: Description("Image id when it differs from the root's.")] string? Image,
    [property: Description("How the parent reaches it: call, import, virtual, virtual?, dynamic, pinvoke, native (a managed method's native body), managed.")] string? Edge,
    [property: Description("repeated (expanded elsewhere), more (children not expanded), unresolved, not-loaded.")] IReadOnlyList<string>? Flags)
{
    [Description("Binding or edge detail: the provider of an import, the candidate count of a virtual call.")]
    public string? Note { get; init; }
}
