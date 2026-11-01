namespace Corvus.Core.Documents;

/// <summary>An OLE class a document can embed or link: its class id, ProgID, display name and whether opening it runs code.</summary>
internal sealed record OleClass(Guid Clsid, string ProgId, string Name, bool Active);

/// <summary>The OLE classes read from a document, by ProgID or class id; the table that document readers extend.</summary>
internal static class OleClasses
{
    // Equation.3 as named in Microsoft KB 4055535; the Package class ids as
    // registered under HKEY_CLASSES_ROOT\CLSID by Windows (OLE 1.0 and Packager).
    private static readonly OleClass[] Table =
    [
        new(new("0002CE02-0000-0000-C000-000000000046"), "Equation.3", "Equation Editor 3.0", true),
        new(new("0002CE03-0000-0000-C000-000000000046"), "Equation.3", "Equation Editor 3.0", true),
        new(new("0003000C-0000-0000-C000-000000000046"), "Package", "OLE Package", true),
        new(new("F20DA720-C02F-11CE-927B-0800095AE340"), "Package", "OLE Package", true),
        new(new("25336920-03F9-11CF-8FD0-00AA00686F13"), "htmlfile", "HTML document", true),
    ];

    // The Microsoft Forms 2.0 HTML controls register consecutive class ids from
    // 5512D110 to 5512D12F under one base.
    private static readonly OleClass FormsHtml = new(Guid.Empty, "Forms.HTML", "HTML form control", true);

    /// <summary>The class registered under <paramref name="progId"/>, ignoring case; null when it is not in the table; any "Forms.HTML:" ProgID names the form control, whatever its class id.</summary>
    public static OleClass? FromProgId(string progId) =>
        progId.Trim().StartsWith("Forms.HTML:", StringComparison.OrdinalIgnoreCase) ? FormsHtml
        : Table.FirstOrDefault(c => string.Equals(c.ProgId, progId.Trim(), StringComparison.OrdinalIgnoreCase));

    /// <summary>The class with class id <paramref name="clsid"/>; null when it is not in the table.</summary>
    public static OleClass? FromClsid(Guid clsid) =>
        IsFormsHtml(clsid) ? FormsHtml : Table.FirstOrDefault(c => c.Clsid == clsid);

    /// <summary>The Forms.HTML class id with first field <paramref name="first"/> under the shared base.</summary>
    internal static Guid FormsHtmlId(uint first) =>
        new(first, 0x5CC6, 0x11CF, 0x8D, 0x67, 0x00, 0xAA, 0x00, 0xBD, 0xCE, 0x1D);

    private static bool IsFormsHtml(Guid clsid)
    {
        uint first = BitConverter.ToUInt32(clsid.ToByteArray());
        return first is >= 0x5512D110 and <= 0x5512D12F && FormsHtmlId(first) == clsid;
    }
}
