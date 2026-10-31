namespace Corvus.Services.Analysis;

/// <summary>Hosts that are not indicators: XML namespaces, parser feature names and certificate infrastructure.</summary>
public static class BenignHosts
{
    /// <summary>True for a host in the table, compared case-insensitively.</summary>
    public static bool Contains(string host) => Hosts.Contains(host);

    private static readonly HashSet<string> Hosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "schemas.microsoft.com", "www.w3.org", "w3.org", "schemas.xmlsoap.org", "schemas.openxmlformats.org", "purl.org",
        "ns.adobe.com", "json-schema.org", "docs.oasis-open.org", "www.xml.org", "xml.org", "tempuri.org", "schema.org",
        "schemas.android.com", "xmlpull.org", "java.sun.com", "xml.apache.org", "apache.org", "www.apple.com",

        // AIA, CRL and OCSP hosts: Microsoft Learn, "Azure Certificate Authority details".
        "cacerts.digicert.com", "cacerts.digicert.cn", "cacerts.geotrust.com", "caissuers.microsoft.com",
        "crl3.digicert.com", "crl4.digicert.com", "crl.digicert.cn",
        "ocsp.digicert.com", "ocsp.digicert.cn", "oneocsp.microsoft.com",

        // RFC 3161 timestamp server: Microsoft Learn, "SignTool" examples.
        "timestamp.digicert.com",
    };
}
