using System.Text;
using System.Text.Json;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Native.Annotations;

/// <summary>Renders the saved names and comments of an image as an IDAPython / Ghidra script or JSON. Addresses are
/// RVAs, rebased to the database's own image base at run time, so the script applies regardless of where the image
/// is loaded.</summary>
public static class AnnotationExport
{
    private static readonly JsonSerializerOptions IndentedJson = new() { WriteIndented = true };

    public enum Format { Ida, Ghidra, Json }

    public static Format ParseFormat(string? format) => (format ?? "json").Trim().ToLowerInvariant() switch
    {
        "ida" or "idapython" or "idc" => Format.Ida,
        "ghidra" => Format.Ghidra,
        "json" or "" => Format.Json,
        _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown format '{format}'.", "use ida, ghidra or json"),
    };

    public static string Render(NativeAnnotations ann, Format format) => format switch
    {
        Format.Ida => Ida(ann),
        Format.Ghidra => Ghidra(ann),
        _ => Json(ann),
    };

    public static string Extension(Format format) => format switch { Format.Ida => ".py", Format.Ghidra => ".java", _ => ".json" };

    private static string Ida(NativeAnnotations ann)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# IDAPython: apply names and comments exported from NetDecompilerMcp.");
        sb.AppendLine($"# Source: {ann.FilePath}  sha256 {ann.Sha256}");
        sb.AppendLine("import idaapi, idc");
        sb.AppendLine("base = idaapi.get_imagebase()");
        foreach (var (rva, name) in ann.Names())
            sb.AppendLine($"idc.set_name(base + 0x{rva:X}, {Py(name)}, idc.SN_NOWARN)");
        foreach (var (rva, comment) in ann.Comments())
            sb.AppendLine($"idc.set_cmt(base + 0x{rva:X}, {Py(comment)}, 0)");
        sb.AppendLine($"print('NetDecompilerMcp: applied {ann.NameCount} name(s) and {ann.CommentCount} comment(s)')");
        return sb.ToString();
    }

    private static string Ghidra(NativeAnnotations ann)
    {
        var sb = new StringBuilder();
        sb.AppendLine("// Ghidra script: apply names and comments exported from NetDecompilerMcp.");
        sb.AppendLine($"// Source: {ann.FilePath}  sha256 {ann.Sha256}");
        sb.AppendLine("// @category NetDecompilerMcp");
        sb.AppendLine("import ghidra.app.script.GhidraScript;");
        sb.AppendLine("import ghidra.program.model.address.Address;");
        sb.AppendLine("import ghidra.program.model.symbol.SourceType;");
        sb.AppendLine("public class ApplyAnnotations extends GhidraScript {");
        sb.AppendLine("  public void run() throws Exception {");
        sb.AppendLine("    Address base = currentProgram.getImageBase();");
        foreach (var (rva, name) in ann.Names())
            sb.AppendLine($"    createLabel(base.add(0x{rva:X}L), {Java(name)}, true, SourceType.USER_DEFINED);");
        foreach (var (rva, comment) in ann.Comments())
            sb.AppendLine($"    setPlateComment(base.add(0x{rva:X}L), {Java(comment)});");
        sb.AppendLine($"    println(\"NetDecompilerMcp: applied {ann.NameCount} name(s) and {ann.CommentCount} comment(s)\");");
        sb.AppendLine("  }");
        sb.AppendLine("}");
        return sb.ToString();
    }

    private static string Json(NativeAnnotations ann)
    {
        var doc = new
        {
            path = ann.FilePath,
            sha256 = ann.Sha256,
            imageBase = ann.ImageBase,
            names = ann.Names().Select(n => new { rva = n.Rva, name = n.Name }),
            comments = ann.Comments().Select(c => new { rva = c.Rva, comment = c.Comment }),
        };
        return JsonSerializer.Serialize(doc, IndentedJson);
    }

    private static string Py(string s) => "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "") + "\"";
    private static string Java(string s) => Py(s);
}
