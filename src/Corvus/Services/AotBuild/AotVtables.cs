using LibCpp2IL.Metadata;

namespace Corvus.Services;

/// <summary>Reads the vtable of every type from the metadata's vtable method table.</summary>
internal static class AotVtables
{
    private const uint MethodDefKind = 3;

    /// <summary>Reads each type's vtable and the images it names; reports bad slots in aggregate.</summary>
    public static (string[] Images, List<AotBuildModel.Vtable> Vtables) Read(
        Il2CppMetadata meta, Action<string, string, string> unreadable, CancellationToken ct)
    {
        var images = new List<string>();
        var imageIndex = new Dictionary<string, int>(StringComparer.Ordinal);
        int Image(string name)
        {
            if (!imageIndex.TryGetValue(name, out var i)) { imageIndex[name] = i = images.Count; images.Add(name); }
            return i;
        }
        var imageOfType = new int[meta.typeDefs.Length];
        Array.Fill(imageOfType, -1);
        foreach (var image in meta.imageDefinitions)
            for (long t = image.firstTypeIndex.Value; t < image.firstTypeIndex.Value + image.typeCount && t < imageOfType.Length; t++)
                imageOfType[t] = Image(image.Name ?? "");

        int ImageOf(int type) => imageOfType[type] >= 0 ? imageOfType[type] : Image("");
        var vtables = new List<AotBuildModel.Vtable>();
        int genericTypes = 0, genericSlots = 0, badTypes = 0, badSlots = 0;
        for (int t = 0; t < meta.typeDefs.Length; t++)
        {
            if ((t & 0xFF) == 0) ct.ThrowIfCancellationRequested();
            var d = meta.typeDefs[t];
            if (d.VtableCount == 0) continue;
            try
            {
                var slots = new AotBuildModel.SlotRef[d.VtableCount];
                int generic = 0, bad = 0;
                for (int k = 0; k < slots.Length; k++)
                {
                    long at = (long)d.VtableStart + k;
                    if (at < 0 || at >= meta.VTableMethodIndices.Length) { bad++; continue; }
                    // Kind in bits 29-31, 3 a method definition, 0 an empty slot. From
                    // metadata v27 bit 0 is a flag and the index sits in bits 1-28.
                    uint encoded = meta.VTableMethodIndices[at];
                    uint index = meta.MetadataVersion >= 27 ? (encoded & 0x1FFFFFFE) >> 1 : encoded & 0x1FFFFFFF;
                    if (encoded >> 29 == 0 && index == 0) continue;
                    if (encoded >> 29 != MethodDefKind) { generic++; continue; }
                    if (index >= meta.methodDefs.Length) { bad++; continue; }
                    var method = meta.methodDefs[index];
                    int declaring = method.declaringTypeIdx.Value;
                    if (declaring < 0 || declaring >= imageOfType.Length) { bad++; continue; }
                    slots[k] = new AotBuildModel.SlotRef(ImageOf(declaring), method.token);
                }
                vtables.Add(new AotBuildModel.Vtable(ImageOf(t), d.Token, slots));
                if (generic > 0) { genericTypes++; genericSlots += generic; }
                if (bad > 0) { badTypes++; badSlots += bad; }
            }
            catch (Exception ex) when (ex is not (OutOfMemoryException or OperationCanceledException))
            {
                unreadable($"vtable of type #{t}", "unreadable_vtable", ex.Message);
            }
        }
        if (genericSlots > 0)
            unreadable($"{genericSlots} vtable slots of {genericTypes} types", "vtable_slot_not_a_definition",
                "the slots hold instantiated generic methods; they keep their place with no method");
        if (badSlots > 0)
            unreadable($"{badSlots} vtable slots of {badTypes} types", "vtable_slot_bad_index",
                "the slots point outside the vtable or method table; they keep their place with no method");
        return ([.. images], vtables);
    }
}
