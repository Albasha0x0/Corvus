using dnlib.DotNet;

namespace NetDecompilerMcp.Core;

/// <summary>
/// A copy of an image that the decompiler's reader can read: loaded by dnlib (which reads malformed metadata leniently)
/// into a private module, cleaned of what dnlib cannot write validly either, and written with PreserveAll so tokens are
/// unchanged. Only for viewing: saving always writes from the workspace module.
/// </summary>
public static class MetadataNormalizer
{
    /// <summary>The normalized image, and what was dropped (empty when nothing).</summary>
    public static (byte[] Image, string Dropped) Normalize(byte[] image)
    {
        using var module = ModuleDefMD.Load(image);
        int dropped = 0;
        void Clean(IHasCustomAttribute? owner)
        {
            if (owner == null) return;
            var attributes = owner.CustomAttributes;
            for (int i = attributes.Count - 1; i >= 0; i--)
            {
                // A constructor that does not resolve (toolchain junk) is written as an invalid coded index.
                if (attributes[i]?.Constructor == null)
                {
                    attributes.RemoveAt(i);
                    dropped++;
                }
            }
        }

        Clean(module);
        Clean(module.Assembly);
        foreach (var type in module.GetTypes())
        {
            Clean(type);
            foreach (var g in type.GenericParameters) Clean(g);
            foreach (var m in type.Methods)
            {
                Clean(m);
                foreach (var p in m.ParamDefs) Clean(p);
                foreach (var g in m.GenericParameters) Clean(g);
            }
            foreach (var f in type.Fields) Clean(f);
            foreach (var p in type.Properties) Clean(p);
            foreach (var e in type.Events) Clean(e);
        }

        using var ms = new MemoryStream();
        FaithfulWriter.WritePlain(module, ms);
        return (ms.ToArray(), dropped == 0 ? "" : $"{dropped} custom attribute(s) whose constructor does not resolve were left out");
    }
}
