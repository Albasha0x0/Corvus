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
        new(new("0003000C-0000-0000-C000-000000000046"), "Package", "OLE Package", true),
        new(new("F20DA720-C02F-11CE-927B-0800095AE340"), "Package", "OLE Package", true),
    ];

    /// <summary>The class registered under <paramref name="progId"/>, ignoring case; null when it is not in the table.</summary>
    public static OleClass? FromProgId(string progId) =>
        Table.FirstOrDefault(c => string.Equals(c.ProgId, progId.Trim(), StringComparison.OrdinalIgnoreCase));

    /// <summary>The class with class id <paramref name="clsid"/>; null when it is not in the table.</summary>
    public static OleClass? FromClsid(Guid clsid) => Table.FirstOrDefault(c => c.Clsid == clsid);
}
