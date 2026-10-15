using System.Text.RegularExpressions;
using Acornima.Ast;

namespace Corvus.Services.Web;

/// <summary>analyze_js view=secrets: a key-like literal, masked; Kind is the provider rule or named (a secret-named, high-entropy value).</summary>
public sealed record JsSecret(string Kind, string? Name, string Masked, int Length, double Entropy, int Line, int Column, string? Module);

/// <summary>Key-like literals of a parsed file: provider patterns, cloud config objects, and named high-entropy values.</summary>
internal static partial class JsSecrets
{
    public const int MaxRows = 2000;

    private static readonly (string Kind, Regex Pattern)[] Rules =
    [
        ("aws-access-key", Aws()), ("google-api-key", Google()), ("stripe-secret", StripeSecret()), ("stripe-publishable", StripePublic()),
        ("github-token", GitHub()), ("slack-token", Slack()), ("slack-webhook", SlackHook()), ("sendgrid-key", SendGrid()),
        ("twilio-key", Twilio()), ("mailgun-key", Mailgun()), ("anthropic-key", Anthropic()), ("openai-key", OpenAi()), ("jwt", Jwt()),
        ("private-key", Pem()), ("google-oauth-client", OAuthClient()), ("sentry-dsn", Sentry()),
    ];

    public static List<JsSecret> Find(JsProgram p, CancellationToken ct)
    {
        var found = new List<JsSecret>();
        var seen = new HashSet<(string, string)>();
        void Add(string kind, string? name, string value, Node at)
        {
            if (found.Count >= MaxRows || !seen.Add((kind, value))) return;
            var module = p.Modules.LastOrDefault(m => m.Start <= at.Start && at.End <= m.End)?.Id;
            found.Add(new JsSecret(kind, name, Mask(value), value.Length, Math.Round(Entropy(value), 2), at.Location.Start.Line, at.Location.Start.Column + 1, module));
        }
        p.Walk((node, _) =>
        {
            switch (node)
            {
                case StringLiteral s when s.Value.Length >= 16:
                    foreach (var (kind, rule) in Rules)
                        if (rule.Match(s.Value) is { Success: true } m) Add(kind, null, m.Value, s);
                    break;
                case ObjectExpression o:
                    Config(o, Add);
                    break;
                case VariableDeclarator { Id: Identifier id, Init: StringLiteral v }:
                    Named(id.Name, v, Add);
                    break;
                case Property { Value: StringLiteral pv } pr when !pr.Computed && JsProgram.KeyName(pr.Key) is { } key:
                    Named(key, pv, Add);
                    break;
                case AssignmentExpression { Left: MemberExpression { Property: Identifier ap, Computed: false }, Right: StringLiteral av }:
                    Named(ap.Name, av, Add);
                    break;
            }
        }, ct);
        return found;
    }

    /// <summary>Firebase web configs (apiKey with authDomain / projectId / appId) and AWS credentials objects.</summary>
    private static void Config(ObjectExpression o, Action<string, string?, string, Node> add)
    {
        var props = o.Properties.OfType<Property>().Where(x => !x.Computed && JsProgram.KeyName(x.Key) != null)
            .GroupBy(x => JsProgram.KeyName(x.Key)!).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
        if (props.TryGetValue("apiKey", out var api) && api.Value is StringLiteral key && (props.ContainsKey("authDomain") || props.ContainsKey("projectId") || props.ContainsKey("messagingSenderId")))
            add("firebase-config", "apiKey", key.Value, api);
        if (props.TryGetValue("secretAccessKey", out var secret) && secret.Value is StringLiteral sv && props.ContainsKey("accessKeyId"))
            add("aws-credentials", "secretAccessKey", sv.Value, secret);
    }

    private static void Named(string name, StringLiteral value, Action<string, string?, string, Node> add)
    {
        var v = value.Value;
        if (v.Length is < 16 or > 512 || v.Any(char.IsWhiteSpace) || !SecretName().IsMatch(name) || Entropy(v) < 3.5) return;
        if (Rules.Any(r => r.Pattern.IsMatch(v))) return; // the provider rule names it
        if (v.StartsWith("http", StringComparison.Ordinal) || v.Contains("${", StringComparison.Ordinal)) return;
        add("named", name, v, value);
    }

    /// <summary>Shannon entropy in bits per character.</summary>
    internal static double Entropy(string s)
    {
        if (s.Length == 0) return 0;
        var counts = new Dictionary<char, int>();
        foreach (var c in s) counts[c] = counts.GetValueOrDefault(c) + 1;
        return -counts.Values.Sum(n => (double)n / s.Length * Math.Log2((double)n / s.Length));
    }

    internal static string Mask(string v) => v.Length <= 8 ? new string('*', v.Length) : $"{v[..4]}…{v[^2..]}";

    [GeneratedRegex(@"(?i)(secret|token|api_?key|apikey|passw(or)?d|private_?key|access_?key|credential|auth_?key|client_?key|signing_?key)")] private static partial Regex SecretName();
    [GeneratedRegex(@"\b(AKIA|ASIA)[0-9A-Z]{16}\b")] private static partial Regex Aws();
    [GeneratedRegex(@"AIza[0-9A-Za-z_\-]{35}")] private static partial Regex Google();
    [GeneratedRegex(@"\b(sk|rk)_live_[0-9A-Za-z]{24,}")] private static partial Regex StripeSecret();
    [GeneratedRegex(@"\bpk_live_[0-9A-Za-z]{24,}")] private static partial Regex StripePublic();
    [GeneratedRegex(@"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})")] private static partial Regex GitHub();
    [GeneratedRegex(@"\bxox[abprs]-[A-Za-z0-9-]{10,}")] private static partial Regex Slack();
    [GeneratedRegex(@"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")] private static partial Regex SlackHook();
    [GeneratedRegex(@"\bSG\.[\w-]{22}\.[\w-]{43}")] private static partial Regex SendGrid();
    [GeneratedRegex(@"\bSK[0-9a-f]{32}\b")] private static partial Regex Twilio();
    [GeneratedRegex(@"\bkey-[0-9a-f]{32}\b")] private static partial Regex Mailgun();
    [GeneratedRegex(@"\bsk-ant-[A-Za-z0-9_-]{20,}")] private static partial Regex Anthropic();
    [GeneratedRegex(@"\bsk-(proj-)?[A-Za-z0-9]{20,}[A-Za-z0-9_-]*")] private static partial Regex OpenAi();
    [GeneratedRegex(@"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")] private static partial Regex Jwt();
    [GeneratedRegex(@"-----BEGIN ([A-Z]+ )?PRIVATE KEY-----")] private static partial Regex Pem();
    [GeneratedRegex(@"\b[0-9]{6,}-[0-9a-z]{32}\.apps\.googleusercontent\.com")] private static partial Regex OAuthClient();
    [GeneratedRegex(@"https://[0-9a-f]{32}@[A-Za-z0-9.-]+/[0-9]+")] private static partial Regex Sentry();
}
