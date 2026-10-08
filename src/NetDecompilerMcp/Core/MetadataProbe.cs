using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;

namespace NetDecompilerMcp.Core;

/// <summary>
/// Whether System.Reflection.Metadata (the decompiler's reader) can read every row of an image: names, coded indexes and
/// signature blobs. Protectors leave out-of-range string offsets and coded indexes that dnlib reads leniently but the
/// decompiler throws on, deep inside a decompilation. Reading each row once up front finds them.
/// </summary>
public static class MetadataProbe
{
    /// <summary>The first row that cannot be read, as "table row: message", or null when every row reads.</summary>
    public static string? Problem(MetadataReader md)
    {
        string where = "header";
        try
        {
            where = "Module"; _ = md.GetString(md.GetModuleDefinition().Name);
            if (md.IsAssembly) { where = "Assembly"; var a = md.GetAssemblyDefinition(); _ = md.GetString(a.Name); _ = md.GetString(a.Culture); }
            foreach (var h in md.AssemblyReferences) { where = Row(h); var r = md.GetAssemblyReference(h); _ = md.GetString(r.Name); _ = md.GetString(r.Culture); }
            foreach (var h in md.TypeReferences) { where = Row(h); var t = md.GetTypeReference(h); _ = md.GetString(t.Name); _ = md.GetString(t.Namespace); _ = t.ResolutionScope; }
            foreach (var h in md.TypeDefinitions)
            {
                where = Row(h);
                var t = md.GetTypeDefinition(h);
                _ = md.GetString(t.Name); _ = md.GetString(t.Namespace); _ = t.BaseType; _ = t.GetDeclaringType();
                foreach (var i in t.GetInterfaceImplementations()) _ = md.GetInterfaceImplementation(i).Interface;
                foreach (var g in t.GetGenericParameters()) Generic(md, g);
            }
            foreach (var h in md.MethodDefinitions)
            {
                where = Row(h);
                var m = md.GetMethodDefinition(h);
                _ = md.GetString(m.Name); Blob(md, m.Signature);
                foreach (var p in m.GetParameters()) _ = md.GetString(md.GetParameter(p).Name);
                foreach (var g in m.GetGenericParameters()) Generic(md, g);
            }
            foreach (var h in md.FieldDefinitions) { where = Row(h); var f = md.GetFieldDefinition(h); _ = md.GetString(f.Name); Blob(md, f.Signature); }
            foreach (var h in md.PropertyDefinitions) { where = Row(h); var p = md.GetPropertyDefinition(h); _ = md.GetString(p.Name); Blob(md, p.Signature); }
            foreach (var h in md.EventDefinitions) { where = Row(h); var e = md.GetEventDefinition(h); _ = md.GetString(e.Name); _ = e.Type; }
            foreach (var h in md.MemberReferences) { where = Row(h); var r = md.GetMemberReference(h); _ = md.GetString(r.Name); _ = r.Parent; Blob(md, r.Signature); }
            foreach (var h in md.CustomAttributes) { where = Row(h); var c = md.GetCustomAttribute(h); _ = c.Parent; _ = c.Constructor; Blob(md, c.Value); }
            foreach (var h in md.DeclarativeSecurityAttributes) { where = Row(h); var d = md.GetDeclarativeSecurityAttribute(h); _ = d.Parent; Blob(md, d.PermissionSet); }
            foreach (var h in md.ExportedTypes) { where = Row(h); var t = md.GetExportedType(h); _ = md.GetString(t.Name); _ = md.GetString(t.Namespace); _ = t.Implementation; }
            foreach (var h in md.ManifestResources) { where = Row(h); var r = md.GetManifestResource(h); _ = md.GetString(r.Name); _ = r.Implementation; }
            for (int rid = 1; rid <= md.GetTableRowCount(TableIndex.TypeSpec); rid++)
            {
                var h = MetadataTokens.TypeSpecificationHandle(rid);
                where = Row(h); Blob(md, md.GetTypeSpecification(h).Signature);
            }
            for (int rid = 1; rid <= md.GetTableRowCount(TableIndex.MethodSpec); rid++)
            {
                var h = MetadataTokens.MethodSpecificationHandle(rid);
                where = Row(h); var s = md.GetMethodSpecification(h); _ = s.Method; Blob(md, s.Signature);
            }
            for (int rid = 1; rid <= md.GetTableRowCount(TableIndex.StandAloneSig); rid++)
            {
                var h = MetadataTokens.StandaloneSignatureHandle(rid);
                where = Row(h); Blob(md, md.GetStandaloneSignature(h).Signature);
            }
            return null;
        }
        catch (BadImageFormatException ex)
        {
            return $"{where}: {ex.Message}";
        }
    }

    private static void Generic(MetadataReader md, GenericParameterHandle h)
    {
        var g = md.GetGenericParameter(h);
        _ = md.GetString(g.Name); _ = g.Parent;
        foreach (var c in g.GetConstraints()) _ = md.GetGenericParameterConstraint(c).Type;
    }

    private static void Blob(MetadataReader md, BlobHandle h)
    {
        if (!h.IsNil) _ = md.GetBlobReader(h).Length;
    }

    private static string Row(EntityHandle h) => $"{h.Kind} 0x{MetadataTokens.GetToken(h):X8}";

    private static string Row(Handle h) => Row((EntityHandle)h);
}
