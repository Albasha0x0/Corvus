namespace Corvus.Core.Mobile;

/// <summary>One network security config scope; trust anchors are certificates src values.</summary>
public sealed record NetworkSecurityScope(string Scope, IReadOnlyList<string> Domains, bool? CleartextPermitted, IReadOnlyList<string> TrustAnchors,
    IReadOnlyList<string> Pins, string? PinExpiration);

/// <summary>An Android network security config (res/xml/..., referenced by android:networkSecurityConfig), read from its compiled XML.</summary>
public sealed record AndroidNetworkSecurityConfig(IReadOnlyList<NetworkSecurityScope> Scopes)
{
    private const int MaxScopes = 4096;

    /// <summary>The scopes of a compiled document; references (a raw certificate) are named through <paramref name="resolve"/>.</summary>
    public static AndroidNetworkSecurityConfig Of(AxmlDocument doc, Func<uint, string?>? resolve = null)
    {
        var scopes = new List<NetworkSecurityScope>();
        if (doc.Root is not { Name: "network-security-config" } root) return new(scopes);
        string? Attr(AxmlElement e, string name) => e.Attributes.FirstOrDefault(a => a.Name == name) is { } a ? doc.Text(a, resolve) : null;
        bool? Bool(AxmlElement e, string name) => Attr(e, name) switch { "true" => true, "false" => false, _ => null };
        List<string> Anchors(AxmlElement e) =>
            [.. e.Elements("trust-anchors").SelectMany(t => t.Elements("certificates")).Select(c => Attr(c, "src")).OfType<string>()];

        void Add(AxmlElement e, string scope, bool? inheritedCleartext, int depth)
        {
            if (scopes.Count >= MaxScopes || depth > 32) return;
            var cleartext = Bool(e, "cleartextTrafficPermitted") ?? inheritedCleartext;
            var pinSet = e.Elements("pin-set").FirstOrDefault();
            var pins = pinSet?.Elements("pin").Select(p => $"{Attr(p, "digest") ?? "SHA-256"}/{p.Text?.Trim()}").ToList() ?? [];
            var domains = e.Elements("domain").Select(d => (d.Text?.Trim() ?? "") + (Bool(d, "includeSubdomains") == true ? " (and subdomains)" : "")).ToList();
            scopes.Add(new NetworkSecurityScope(scope, domains, cleartext, Anchors(e), pins, pinSet != null ? Attr(pinSet, "expiration") : null));
            foreach (var nested in e.Elements("domain-config")) Add(nested, "domain-config", cleartext, depth + 1);
        }

        foreach (var e in root.Children)
            switch (e.Name)
            {
                case "base-config": Add(e, "base-config", null, 0); break;
                case "domain-config": Add(e, "domain-config", null, 0); break;
                case "debug-overrides": Add(e, "debug-overrides", null, 0); break;
            }
        return new(scopes);
    }
}
