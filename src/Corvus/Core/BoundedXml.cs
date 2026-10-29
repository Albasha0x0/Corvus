using System.Xml;
using System.Xml.Linq;

namespace Corvus.Core;

/// <summary>
/// XML trees read with a nesting bound. XContainer.AddNodeSkipNotify walks to the root for each node it adds, so
/// XDocument.Load takes time quadratic in depth: 40,000 nested elements take about 28 s.
/// Workaround for dotnet/runtime#136658, tested on .NET 8.0.33, 9.0.22 and 10.0.14; no fix released yet.
/// </summary>
internal static class BoundedXml
{
    public const int MaxDepth = 256;

    /// <summary>The document, as <see cref="XDocument.Parse(string)"/>; throws <see cref="XmlException"/> when malformed or nested past <see cref="MaxDepth"/>.</summary>
    public static XDocument Parse(string text)
    {
        Check(XmlReader.Create(new StringReader(text), Settings()));
        return XDocument.Parse(text);
    }

    /// <summary>The root element, as <see cref="XElement.Load(Stream)"/>; throws <see cref="XmlException"/> when malformed or nested past <see cref="MaxDepth"/>.</summary>
    public static XElement Load(byte[] data)
    {
        Check(XmlReader.Create(new MemoryStream(data, writable: false), Settings()));
        return XElement.Load(new MemoryStream(data, writable: false));
    }

    /// <summary>Whether no element of <paramref name="data"/> is nested past <see cref="MaxDepth"/>; throws <see cref="XmlException"/> when malformed.</summary>
    public static bool WithinDepth(byte[] data, XmlReaderSettings settings)
    {
        using var reader = XmlReader.Create(new MemoryStream(data, writable: false), settings);
        while (reader.Read())
            if (reader.Depth > MaxDepth) return false;
        return true;
    }

    private static void Check(XmlReader reader)
    {
        using (reader)
            while (reader.Read())
                if (reader.Depth > MaxDepth) throw new XmlException($"elements nest deeper than {MaxDepth} levels.", null, ((IXmlLineInfo)reader).LineNumber, ((IXmlLineInfo)reader).LinePosition);
    }

    // The settings XDocument.Parse and XElement.Load use with LoadOptions.None.
    private static XmlReaderSettings Settings() =>
        new() { IgnoreWhitespace = true, DtdProcessing = DtdProcessing.Parse, MaxCharactersFromEntities = 10_000_000 };
}
