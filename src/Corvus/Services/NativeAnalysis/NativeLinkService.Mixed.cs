using System.Runtime.CompilerServices;
using System.Text;
using dnlib.DotNet;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Linking;

namespace Corvus.Services;

/// <summary>
/// Mixed-mode (C++/CLI) assemblies: methods with native bodies, VTableFixups slots native code calls managed methods
/// through, and the reverse lookup from native code to the managed methods bound to it.
/// </summary>
public sealed partial class NativeLinkService
{
    private readonly ConditionalWeakTable<LoadedAssembly, Tuple<int, MixedModeMap>> _mixed = new();
    private (string Key, Dictionary<(LoadedNative, uint), List<ManagedLink>> Map)? _managedAt;

    /// <summary>The managed/native seams of a loaded assembly (empty for IL-only assemblies).</summary>
    public MixedModeMap Mixed(LoadedAssembly asm)
    {
        if (_mixed.TryGetValue(asm, out var hit) && hit.Item1 == asm.Version) return hit.Item2;
        var map = MixedModeMap.Build(asm.Module);
        _mixed.AddOrUpdate(asm, Tuple.Create(asm.Version, map));
        return map;
    }

    /// <summary>The native body of a method in a mixed-mode image (bound to the assembly's native view), or null.</summary>
    private ManagedLink? NativeBody(LoadedAssembly asm, MethodDef method)
    {
        if (!MixedModeMap.IsMixedMode(asm.Module) || !Mixed(asm).Bodies.TryGetValue(method, out var rva)) return null;
        var view = workspace.NativeViewOf(asm);
        var hop = new LinkHop(asm.FilePath, method.Name, 0, rva, null, "native body");
        var link = new LinkResult(NativeLinker.Resolved, Path.GetFileName(asm.FilePath), asm.FilePath, [hop], "native body");
        var b = view != null ? new Binding(link, Bound, view, rva) : new Binding(link, NotLoaded, null, null);
        return new ManagedLink(asm, method, FollowThunks(b), "C++/CLI native body");
    }

    /// <summary>Managed methods whose native code (P/Invoke target, native body, thunk-followed hops) is <paramref name="rva"/> of <paramref name="native"/>.</summary>
    public IReadOnlyList<ManagedLink> ManagedLinksAt(LoadedNative native, uint rva, CancellationToken ct = default)
    {
        var assemblies = workspace.Assemblies;
        var key = string.Join("|", assemblies.Select(a => $"{RuntimeHelpers.GetHashCode(a)}.{a.Version}"))
                  + "/" + string.Join("|", workspace.Natives.Select(n => $"{RuntimeHelpers.GetHashCode(n.Image)}.{code.Ready(n) != null}"));
        Dictionary<(LoadedNative, uint), List<ManagedLink>> map;
        lock (_sync)
        {
            if (_managedAt is { } cached && cached.Key == key) map = cached.Map;
            else
            {
                map = [];
                foreach (var asm in assemblies)
                    foreach (var type in asm.Module.GetTypes())
                        foreach (var m in type.Methods)
                        {
                            ct.ThrowIfCancellationRequested();
                            if (m.ImplMap == null && !(m.RVA != 0 && (m.IsNative || m.IsUnmanaged))) continue;
                            if (NativeOf(m) is not { } link) continue;
                            foreach (var hop in link.Binding.Link.Hops)
                                if (hop.Rva is { } r && LoadedAt(hop.File) is { } image)
                                {
                                    if (!map.TryGetValue((image, r), out var list)) map[(image, r)] = list = [];
                                    if (!list.Contains(link)) list.Add(link);
                                }
                        }
                _managedAt = (key, map);
            }
        }
        return map.TryGetValue((native, rva), out var found) ? found : [];
    }

    /// <summary>Managed methods native code of a mixed-mode view reaches through VTableFixups slots from <paramref name="fn"/>.</summary>
    private IEnumerable<(uint Slot, MethodDef Method)> ManagedCallees(LoadedNative view, NativeCodeIndex index, NativeFunction fn)
    {
        if (view.ManagedView is not { } asm) yield break;
        var map = Mixed(asm);
        if (map.Slots.Count == 0) yield break;
        foreach (var x in index.RefsFrom(fn))
            if (map.Slots.TryGetValue(x.To, out var method))
                yield return (x.To, method);
    }

    /// <summary>Leaves for a native callee tree: managed methods entered through VTableFixups slots.</summary>
    private void AddManagedCallees(List<TreeNode> result, TreeNode node, NativeCodeIndex index)
    {
        var seen = new HashSet<MethodDef>();
        foreach (var (slot, method) in ManagedCallees(node.Image, index, node.Function!))
            if (seen.Add(method))
                result.Add(new TreeNode(node.Image, null,
                    $"managed: {Format.MemberLabel(method)}  [{node.Image.ManagedView!.Id}]  (through vtfixup slot {NativeAddress.Va(node.Image.Image, slot)})")
                    { Name = Format.MemberLabel(method), Rva = slot, Edge = "managed", Note = $"[{node.Image.ManagedView!.Id}] through the vtfixup slot" });
    }

    /// <summary>Leaves for a native caller tree: managed methods bound to the function (P/Invoke declarations, C++/CLI native bodies).</summary>
    private void AddManagedCallers(List<TreeNode> result, TreeNode node, CancellationToken ct)
    {
        foreach (var link in ManagedLinksAt(node.Image, node.Function!.Start, ct))
            result.Add(new TreeNode(node.Image, null,
                $"managed: {Format.MemberLabel(link.Method)}  [{link.Assembly.Id}]  ({link.Kind}; get_call_tree lists its managed callers)")
                { Name = Format.MemberLabel(link.Method), Edge = link.Kind == "P/Invoke" ? "pinvoke" : "managed", Note = $"[{link.Assembly.Id}] {link.Kind}" });
    }

    /// <summary>Functions of a mixed-mode view that reference the VTableFixups slots of <paramref name="method"/>, with the slot.</summary>
    private List<(LoadedNative View, NativeCodeIndex Index, NativeFunction Function, uint Slot, CodeXref Ref)> SlotUsers(MethodDef method)
    {
        var result = new List<(LoadedNative, NativeCodeIndex, NativeFunction, uint, CodeXref)>();
        if (workspace.FindByModule(method.Module) is not { } asm || workspace.NativeViewOf(asm) is not { } view || code.Ready(view) is not { } index)
            return result;
        foreach (var slot in Mixed(asm).SlotsOf(method))
            foreach (var x in index.RefsTo(slot))
                if (index.FunctionAt(x.From) is { } f)
                    result.Add((view, index, f, slot, x));
        return result;
    }

    /// <summary>
    /// Lines for a callers tree of a managed method that native code calls (through its VTableFixups slots): each
    /// native function using a slot at <paramref name="indent"/>, then its native callers for the remaining levels.
    /// <paramref name="rows"/>, when given, receives the same lines as <see cref="NativeTreeNode"/> rows under <paramref name="parent"/>.
    /// </summary>
    public string NativeCallers(MethodDef method, int levels, int indent, int maxNodes, CancellationToken ct, List<NativeTreeNode>? rows = null, int? parent = null)
    {
        if (levels < 1) return "";
        var users = SlotUsers(method);
        if (users.Count == 0)
        {
            if (workspace.FindByModule(method.Module) is { } asm && Mixed(asm).SlotsOf(method).Count > 0 && workspace.NativeViewOf(asm) is { } v && code.Ready(v) == null)
                return $"{new string(' ', indent * 2)}native: (the code index of {v.Id} is still being built: repeat for native callers)\n";
            return "";
        }
        var sb = new StringBuilder();
        foreach (var (view, _, f, slot, _) in users.DistinctBy(u => u.Function))
        {
            sb.Append(new string(' ', indent * 2)).AppendLine($"native: {FunctionLabel(view, f, null)}  (through vtfixup slot {NativeAddress.Va(view.Image, slot)})");
            int? id = null;
            if (rows != null)
            {
                id = rows.Count;
                rows.Add(new NativeTreeNode(rows.Count, parent, indent, f.Name, NativeAddress.Va(view.Image, f.Start), view.Id, "managed", null)
                    { Note = "through vtfixup slot " + NativeAddress.Va(view.Image, slot) });
            }
            if (levels > 1) AppendTree(sb, view, f, callers: true, levels - 1, maxNodes, indent + 1, withRoot: false, ct, rows: rows, parent: id);
        }
        return sb.ToString();
    }

    /// <summary>Native code calling a managed method through its VTableFixups slots, and the callers of jump thunks among them.</summary>
    public List<string> NativeCallSitesOf(MethodDef method, CancellationToken ct)
    {
        var rows = new List<string>();
        foreach (var (view, index, f, slot, x) in SlotUsers(method))
        {
            ct.ThrowIfCancellationRequested();
            bool thunk = f.InstructionCount <= 2 && x.From == f.Start;
            rows.Add($"[{view.Id}] {NativeAddress.Va(view.Image, x.From)}  {x.Kind,-10} {f.Name}+0x{x.From - f.Start:X}  " +
                     $"({(thunk ? "jump thunk" : "call")} through vtfixup slot {NativeAddress.Va(view.Image, slot)})");
            if (!thunk) continue;
            foreach (var c in index.Callers(f))
                rows.Add($"[{view.Id}] {NativeAddress.Va(view.Image, c.From)}  {c.Kind,-10} {(c.Caller is { } g ? $"{g.Name}+0x{c.From - g.Start:X}" : "(no function)")}  calls the thunk {f.Name}");
            rows.AddRange(ImportCallSites(view, f.Start, ct));
        }
        return rows;
    }

    /// <summary>What a native address is on the managed side: native body, vtfixup slot, or P/Invoke target of managed methods.</summary>
    public IEnumerable<string> DescribeManaged(LoadedNative native, uint rva)
    {
        if (native.ManagedView is { } asm)
        {
            var map = Mixed(asm);
            foreach (var m in map.MethodsWithBody(rva)) yield return $"native body of managed method {Format.MemberLabel(m)} [{asm.Id}]";
            if (map.Slots.TryGetValue(rva, out var entered)) yield return $"vtfixup slot entering managed method {Format.MemberLabel(entered)} [{asm.Id}]";
        }
        foreach (var link in ManagedLinksAt(native, rva))
            if (link.Kind != "C++/CLI native body" || link.Assembly != native.ManagedView)
                yield return $"{link.Kind} target of {Format.MemberLabel(link.Method)} [{link.Assembly.Id}]";
    }
}
