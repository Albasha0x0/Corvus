using dnlib.DotNet;

namespace Corvus.Native.Linking;

/// <summary>
/// The managed / native seams of a mixed-mode (C++/CLI) module: methods whose body is native code at their RVA
/// (IJW: "pinvokeimpl native unmanaged" with no ImplMap; managed calls to them run the native function), and the
/// VTableFixups slots the runtime fills with native-callable entry points of managed methods (native code calls a
/// managed method through its slot, directly or from a "jmp [slot]" thunk; exported managed functions are such thunks).
/// </summary>
public sealed class MixedModeMap
{
    private const int MaxSlots = 1 << 20;

    private readonly Dictionary<MethodDef, uint> _bodies = [];
    private readonly Dictionary<uint, List<MethodDef>> _byBody = [];
    private readonly Dictionary<uint, MethodDef> _slots = [];
    private readonly Dictionary<MethodDef, List<uint>> _slotsOf = [];

    /// <summary>Methods with a native body, by method.</summary>
    public IReadOnlyDictionary<MethodDef, uint> Bodies => _bodies;
    /// <summary>VTableFixups slots (RVA) and the managed method each one enters.</summary>
    public IReadOnlyDictionary<uint, MethodDef> Slots => _slots;
    public int VTables { get; private set; }
    /// <summary>Slots whose token does not resolve to a method of this module.</summary>
    public int UnresolvedSlots { get; private set; }

    public IReadOnlyList<MethodDef> MethodsWithBody(uint rva) => _byBody.TryGetValue(rva, out var list) ? list : [];

    public IReadOnlyList<uint> SlotsOf(MethodDef method) => _slotsOf.TryGetValue(method, out var list) ? list : [];

    /// <summary>
    /// Whether a module carries native code of its own (C++/CLI). The IL-only flag alone does not tell: ReadyToRun images
    /// clear it too (IL library flag, managed native header), and their precompiled code belongs to the R2R tools.
    /// </summary>
    public static bool IsMixedMode(ModuleDef module) =>
        !module.IsILOnly && (module.Cor20HeaderFlags & dnlib.DotNet.MD.ComImageFlags.ILLibrary) == 0
        && !(module is ModuleDefMD md && md.Metadata.ImageCor20Header.ManagedNativeHeader.VirtualAddress != 0);

    /// <summary>The map of a module; empty unless it is mixed-mode. Never throws on malformed metadata.</summary>
    public static MixedModeMap Build(ModuleDef module, CancellationToken ct = default)
    {
        var map = new MixedModeMap();
        if (!IsMixedMode(module)) return map;
        try
        {
            foreach (var type in module.GetTypes())
                foreach (var m in type.Methods)
                {
                    ct.ThrowIfCancellationRequested();
                    if (m.RVA == 0 || m.ImplMap != null || !(m.IsNative || m.IsUnmanaged)) continue;
                    uint rva = (uint)m.RVA;
                    map._bodies[m] = rva;
                    if (!map._byBody.TryGetValue(rva, out var list)) map._byBody[rva] = list = [];
                    list.Add(m);
                }
            if (module is ModuleDefMD md && md.VTableFixups is { } fixups)
                foreach (var table in fixups)
                {
                    map.VTables++;
                    uint size = table.Is64Bit ? 8u : 4u;
                    for (int i = 0; i < table.Methods.Count && map._slots.Count < MaxSlots; i++)
                    {
                        ct.ThrowIfCancellationRequested();
                        uint slot = (uint)table.RVA + (uint)i * size;
                        var entry = table.Methods[i];
                        var method = entry as MethodDef;
                        if (method == null && entry != null)
                            try { method = entry.ResolveMethodDef(); }
                            catch (Exception ex) when (ex is not OperationCanceledException) { method = null; }
                        if (method != null)
                        {
                            map._slots[slot] = method;
                            if (!map._slotsOf.TryGetValue(method, out var list)) map._slotsOf[method] = list = [];
                            list.Add(slot);
                        }
                        else map.UnresolvedSlots++;
                    }
                }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Damaged metadata: keep what was read.
        }
        return map;
    }
}
