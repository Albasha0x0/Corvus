using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace Corvus.Services.Analysis.Hunts;

/// <summary>Writes an App Control policy in audit mode that denies the Authenticode hashes of a file whose hash fact the proof kept, and allows every other file.</summary>
public static class AuditPolicy
{
    private const string Namespace = "urn:schemas-microsoft-com:sipolicy";

    // The platform ID of the sample policies in the Windows schemas folder.
    private const string PlatformId = "{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}";

    private const int MaxNameChars = 100;

    private static readonly string[] Options =
    [
        "Enabled:Unsigned System Integrity Policy",
        "Enabled:Audit Mode",
        "Enabled:UMCI",
        "Enabled:Update Policy No Reboot",
        "Disabled:Script Enforcement",
    ];

    private static readonly string[] Comment =
    [
        "Audit policy. Option 3 (Enabled:Audit Mode) logs a match as event 3076 and blocks nothing.",
        "Deny rules name the Authenticode SHA-1 and SHA-256 hashes of the file; Allow rules for every file keep all other files allowed.",
        "Without the Allow rules, every file the policy does not list would be logged as a match.",
        "Option 11 (Disabled:Script Enforcement) is set: script enforcement acts in audit mode too and would block MSHTA and MSXML code.",
        "Gaps: signer rules need the PCA TBS hash and page hash rules need page hashes; Corvus reads neither.",
    ];

    /// <summary>
    /// The policy of <paramref name="set"/>, or null with the reason in the note when none is written: the file hash fact
    /// was not kept, or the input has no PE image to take Authenticode hashes from. Throws InvalidArgument for a set with no proof.
    /// </summary>
    public static (byte[]? Xml, string Note) Write(HuntSet set)
    {
        var (kept, withheld) = AuditFacts.Of(set);
        if (set.Image is not { } image)
            return (null, "No policy written: Authenticode hashes come from the file, and the input is a saved set of queries.");
        if (!kept.Any(k => k.Kind == HuntKind.Sha1 && k.Value == image.Sha1))
        {
            var why = withheld.FirstOrDefault(w => w.Fact == $"{HuntKind.Sha1}:{image.Sha1}")?.Reason ?? "no query reads it";
            return (null, $"No policy written: the file hash fact was not kept ({why}).");
        }
        if (image.AuthenticodeSha1 == null || image.AuthenticodeSha256 == null)
            return (null, $"No policy written: Authenticode hashes are unknown, {image.Unread}.");
        var name = Name(image.FileName);
        var id = PolicyId(image.AuthenticodeSha1, image.AuthenticodeSha256);
        using var stream = new MemoryStream();
        var settings = new XmlWriterSettings { Indent = true, Encoding = new UTF8Encoding(false), CheckCharacters = true };
        using (var w = XmlWriter.Create(stream, settings))
        {
            w.WriteStartDocument();
            foreach (var line in Comment) w.WriteComment(" " + line + " ");
            w.WriteStartElement("SiPolicy", Namespace);
            w.WriteAttributeString("PolicyType", "Base Policy");
            w.WriteElementString("VersionEx", "1.0.0.0");
            w.WriteElementString("PolicyID", id);
            w.WriteElementString("BasePolicyID", id);
            w.WriteElementString("PlatformID", PlatformId);
            w.WriteStartElement("Rules");
            foreach (var option in Options)
            {
                w.WriteStartElement("Rule");
                w.WriteElementString("Option", option);
                w.WriteEndElement();
            }
            w.WriteEndElement();
            w.WriteElementString("EKUs", "");
            w.WriteStartElement("FileRules");
            Deny(w, "ID_DENY_D_1", $"{name} Hash Sha1", image.AuthenticodeSha1);
            Deny(w, "ID_DENY_D_2", $"{name} Hash Sha256", image.AuthenticodeSha256);
            Allow(w, "ID_ALLOW_A_1");
            Allow(w, "ID_ALLOW_A_2");
            w.WriteEndElement();
            w.WriteElementString("Signers", "");
            w.WriteStartElement("SigningScenarios");
            Scenario(w, "131", "ID_SIGNINGSCENARIO_DRIVERS_1", "Drivers", "ID_ALLOW_A_1");
            Scenario(w, "12", "ID_SIGNINGSCENARIO_WINDOWS", "Windows", "ID_ALLOW_A_2");
            w.WriteEndElement();
            w.WriteElementString("UpdatePolicySigners", "");
            w.WriteElementString("CiSigners", "");
            w.WriteElementString("HvciOptions", "0");
            w.WriteStartElement("Settings");
            w.WriteStartElement("Setting");
            w.WriteAttributeString("Provider", "PolicyInfo");
            w.WriteAttributeString("Key", "Information");
            w.WriteAttributeString("ValueName", "Name");
            w.WriteStartElement("Value");
            w.WriteElementString("String", $"Audit {name}");
            w.WriteEndElement();
            w.WriteEndElement();
            w.WriteEndElement();
            w.WriteEndElement();
            w.WriteEndDocument();
        }
        return (stream.ToArray(), "");
    }

    /// <summary>The note naming the file <see cref="Write"/> saved to <paramref name="path"/>.</summary>
    public static string Written(string path) => $"App Control policy in audit mode written to {path}: 2 deny rules (Authenticode SHA-1 and SHA-256) and allow rules for all other files.";

    private static void Deny(XmlWriter w, string id, string name, string hash)
    {
        w.WriteStartElement("Deny");
        w.WriteAttributeString("ID", id);
        w.WriteAttributeString("FriendlyName", name);
        w.WriteAttributeString("Hash", hash.ToUpperInvariant());
        w.WriteEndElement();
    }

    private static void Allow(XmlWriter w, string id)
    {
        w.WriteStartElement("Allow");
        w.WriteAttributeString("ID", id);
        w.WriteAttributeString("FileName", "*");
        w.WriteEndElement();
    }

    // Both scenarios list the allow rule and the deny rules, so a deny rule
    // applies in each.
    private static void Scenario(XmlWriter w, string value, string id, string name, string allow)
    {
        w.WriteStartElement("SigningScenario");
        w.WriteAttributeString("Value", value);
        w.WriteAttributeString("ID", id);
        w.WriteAttributeString("FriendlyName", name);
        w.WriteStartElement("ProductSigners");
        w.WriteStartElement("FileRulesRef");
        foreach (var rule in new[] { allow, "ID_DENY_D_1", "ID_DENY_D_2" })
        {
            w.WriteStartElement("FileRuleRef");
            w.WriteAttributeString("RuleID", rule);
            w.WriteEndElement();
        }
        w.WriteEndElement();
        w.WriteEndElement();
        w.WriteEndElement();
    }

    // A file name is outside text: characters XML 1.0 forbids become U+FFFD,
    // and the name is cut.
    private static string Name(string fileName)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < fileName.Length && sb.Length < MaxNameChars; i++)
        {
            var c = fileName[i];
            if (char.IsHighSurrogate(c) && i + 1 < fileName.Length && char.IsLowSurrogate(fileName[i + 1])) { sb.Append(c).Append(fileName[++i]); continue; }
            sb.Append(XmlConvert.IsXmlChar(c) ? c : '�');
        }
        return sb.Length == 0 ? "file" : sb.ToString();
    }

    // The same hashes give the same policy id.
    private static string PolicyId(string sha1, string sha256)
    {
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes("audit\0" + sha1 + "\0" + sha256));
        return "{" + new Guid(hash.AsSpan(0, 16)).ToString().ToUpperInvariant() + "}";
    }
}
