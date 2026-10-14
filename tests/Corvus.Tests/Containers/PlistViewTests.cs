using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>summarize_file view=plist: an XML keyed archive (CF$UID references) is decoded into its object graph.</summary>
public sealed class PlistViewTests
{
    [Fact]
    public void A_keyed_archive_is_decoded()
    {
        var xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <plist version="1.0"><dict>
            <key>$archiver</key><string>NSKeyedArchiver</string>
            <key>$version</key><integer>100000</integer>
            <key>$top</key><dict><key>root</key><dict><key>CF$UID</key><integer>1</integer></dict></dict>
            <key>$objects</key><array>
              <string>$null</string>
              <dict><key>$class</key><dict><key>CF$UID</key><integer>3</integer></dict><key>title</key><dict><key>CF$UID</key><integer>2</integer></dict></dict>
              <string>Quarterly report</string>
              <dict><key>$classname</key><string>Document</string><key>$classes</key><array><string>Document</string><string>NSObject</string></array></dict>
            </array>
            </dict></plist>
            """;
        var bytes = Encoding.UTF8.GetBytes(xml);
        var view = new PlistFileView().Inspect(new FileInput("doc.plist", bytes, Blob.Identify(bytes)), default)!;
        var facts = (PlistFileView.Facts)view.Detail;
        Assert.True(facts.KeyedArchive);
        Assert.Contains("Quarterly report", facts.Json);
        Assert.Contains("Document", facts.Json);
        Assert.Contains("NSKeyedArchiver archive decoded", view.Highlights[0]);
    }
}
