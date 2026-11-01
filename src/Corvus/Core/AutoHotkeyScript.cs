using System.Text;
using Corvus.Native.Pe;

namespace Corvus.Core;

/// <summary>Compiled AutoHotkey executables, whose script is an RCDATA resource.</summary>
public static class AutoHotkeyScript
{
    /// <summary>The container kind named in notes and overview lines.</summary>
    public const string Kind = "AutoHotkey compiled script";
    private static readonly string[] ResourceNames = [">AUTOHOTKEY SCRIPT<", "E4847ED08866458F8DD35F94B37001C0"];
    private static readonly byte[][] EncodedNames = ResourceNames.Select(Encoding.Unicode.GetBytes).ToArray();
    private const uint RtRcData = 10;

    /// <summary>The script resource of a PE image; null when absent or unparsable.</summary>
    public static (PeFile Pe, PeResource Resource)? Find(byte[] image)
    {
        // Prefilter on the UTF-16 names so unrelated images are never parsed.
        if (!EncodedNames.Any(n => image.AsSpan().IndexOf(n) >= 0)) return null;
        PeFile pe;
        try { pe = PeFile.FromBytes(image); }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentException or ToolError) { return null; }
        var resource = pe.Resources.FirstOrDefault(r => r.Type.Id == RtRcData && !r.Type.IsName
            && r.Name is { Name: { } n } && ResourceNames.Contains(n, StringComparer.Ordinal));
        return resource == null ? null : (pe, resource);
    }

    /// <summary>The script as the member script.ahk; null when the image has no script.</summary>
    public static ContainerContents? Open(byte[] image, AnalysisLimits limits)
    {
        if (Find(image) is not var (pe, resource)) return null;
        var notes = new List<string>();
        var items = new List<ExtractedItem>();
        string detail = $"resource {resource.Name} ({resource.Size:N0} bytes)";
        if (resource.Size > limits.MaxItemBytes)
        {
            notes.Add(AnalysisLimits.Reached(
                "item", $"{limits.MaxItemBytes:N0}-byte", 1, "script.ahk"));
            return Unread(items, notes, resource, detail);
        }
        var bytes = pe.ReadResource(resource, (int)limits.MaxItemBytes);
        if (bytes == null)
        {
            notes.Add($"{Kind}: {detail} is not mapped in the image; its content is unknown.");
            return Unread(items, notes, resource, detail);
        }
        bool utf16 = bytes.Length >= 2 && (bytes[0], bytes[1]) is (0xFF, 0xFE) or (0xFE, 0xFF);
        string nul = !utf16 && Array.IndexOf(bytes, (byte)0) >= 0 ? " The bytes contain NUL; kept as stored." : "";
        notes.Add($"{Kind}: {detail}.{nul}");
        items.Add(new ExtractedItem("script.ahk", bytes, "script resource"));
        return new ContainerContents(Kind, items, notes)
        {
            Entries = [new ContainerEntry("script.ahk", bytes.Length, detail)],
        };
    }

    private static ContainerContents Unread(
        List<ExtractedItem> items, List<string> notes, PeResource resource, string detail) =>
        new(Kind, items, notes) { Entries = [new ContainerEntry("script.ahk", resource.Size, detail)] };
}
