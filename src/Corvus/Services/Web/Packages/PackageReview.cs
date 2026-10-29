using System.ComponentModel;
using System.Text.RegularExpressions;
using Corvus.Services.Analysis;
using Corvus.Services.Web.Scripts;

namespace Corvus.Services.Web.Packages;

/// <param name="Rule">The rule id in <see cref="FindingRules"/>.</param>
/// <param name="Level">noteworthy (look before installing), review (expected in some packages) or info; a level above the rule's row throws.</param>
/// <param name="Category">install script, network, process, dynamic code, credentials, host details, exfiltration, persistence, publishing, transformed code, binary, name, permission, activation, remote code, hidden text, agent configuration, repository hook, build step, rule match (GuardDog), provenance.</param>
/// <param name="Line">1-based line in <paramref name="Path"/>, when the finding has one.</param>
public sealed record PackageFinding(string Rule, string Level, string Category, string Detail, string? Path = null, int? Line = null)
{
    public string Level { get; init; } = FindingRules.Check(Rule, Level);

    /// <summary>The finding as the shared record, located at path:line.</summary>
    public Finding ToFinding() => new(Level, Rule, Category, Detail, Line is { } line ? $"{Path}:{line}" : Path, "package");
}

/// <param name="AtInstall">True when the package manager runs it while installing.</param>
public sealed record PackageScript(string Name, string Command, bool AtInstall);

public sealed record PackageEntryPoint(string Kind, string Name, string? Target);

/// <summary>A browser extension's content script: the pages it runs in and its files.</summary>
public sealed record ContentScript(IReadOnlyList<string> Matches, IReadOnlyList<string> Files, string? RunAt, bool AllFrames);

/// <summary>A package reviewed before installing: identity, install scripts, entry points, permissions, files and findings.</summary>
public sealed record PackageReport(string Ecosystem, string? Name, string? Version)
{
    public string? Publisher { get; init; }
    public string? Description { get; init; }
    public IReadOnlyList<PackageScript> Scripts { get; init; } = [];
    public IReadOnlyList<PackageEntryPoint> EntryPoints { get; init; } = [];
    public IReadOnlyList<string>? Permissions { get; init; }
    public IReadOnlyList<string>? HostPermissions { get; init; }
    public IReadOnlyList<ContentScript>? ContentScripts { get; init; }
    public int Dependencies { get; init; }
    public int Files { get; init; }
    public IReadOnlyList<string>? Binaries { get; init; }

    [Description("A .crx: format version, extension id and key proofs verified.")]
    public CrxHeader? Signature { get; init; }

    [Description("A wheel's RECORD: files whose sha256 matches, differs, or is not listed.")]
    public string? Record { get; init; }

    [Description("Files the review did not read, named with the limit that stopped each; null when it read every file.")]
    public string? Partial { get; init; }

    [Description("noteworthy, worth reviewing, or none: the strongest finding.")]
    public string Review { get; init; } = "none";

    [Description("What runs unprompted, at file and line: agent files, hooks, MCP servers, tasks, git hooks, build steps.")]
    public IReadOnlyList<AgentEntry>? Agents { get; init; }

    [Description("Sigstore, npm or PyPI provenance beside the file: digest, signature, chain and log entry, checked offline.")]
    public IReadOnlyList<PackageAttestation>? Provenance { get; init; }

    public IReadOnlyList<PackageFinding> Findings { get; init; } = [];
    public IReadOnlyList<string> Notes { get; init; } = [];

    /// <summary>Hosts the package's code files name in URLs, for comparing two versions; null when not read.</summary>
    internal IReadOnlyList<string>? Hosts { get; init; }
}

/// <summary>Reviews npm, PyPI, RubyGems, VSIX and browser extension packages and agent configuration without installing or running them.</summary>
/// <summary>
/// Reviews npm, PyPI, NuGet, Composer, VSIX and browser extension packages and
/// agent configuration without installing or running them.
/// </summary>
public static partial class PackageReview
{
    public static PackageReport? Review(string path, CancellationToken ct) => Review(path, ct, hosts: false);

    /// <summary>The review of <paramref name="path"/>; with <paramref name="hosts"/>, also the hosts its code files name.</summary>
    internal static PackageReport? Review(string path, CancellationToken ct, bool hosts)
    {
        var files = PackageFiles.Open(path, ct);
        // A folder always gets a report, so an empty one says nothing runs rather than that the folder was not read.
        bool folder = Directory.Exists(path);
        if (files == null || files.Count == 0 && !folder) return null;
        PackageReport? report = files.Container == "gem" ? RubyGems(files, ct)
            : files.Crx != null || ManifestJson(files) != null && Root(files, "manifest.json") is { } m && IsExtensionManifest(files, m) ? Extension(files, ct)
            : Root(files, "extension.vsixmanifest") != null || files.Has("extension/package.json") ? Vsix(files, ct)
            : Nuspec(files) != null ? Nuget(files, ct)
            : Root(files, "package.json") != null ? Npm(files, ct)
            : files.Paths.Any(p => p.EndsWith(".dist-info/METADATA", StringComparison.Ordinal) || IsSdistFile(p)) ? Python(files, ct)
            : GemSpecPath(files) != null ? RubyGems(files, ct)
            : Root(files, "composer.json") != null ? Composer(files, ct)
            : null;
        if (report != null)
        {
            var assetNotes = new List<string>();
            var assets = AssetTrailingData(files, report, assetNotes, ct);
            if (assets.Count > 0 || assetNotes.Count > 0) report = report with { Findings = [.. report.Findings, .. assets], Notes = [.. report.Notes, .. assetNotes] };
        }
        // A source tree with no package manifest is reviewed for its agent configuration alone.
        // A PHP project often carries a frontend package.json; its Composer
        // scripts join the npm review, which keeps its ecosystem.
        if (report is { Ecosystem: "npm" } && Root(files, "composer.json") != null && Composer(files, ct) is { } php)
            report = report with
            {
                Scripts = [.. report.Scripts, .. php.Scripts], Findings = [.. report.Findings, .. php.Findings],
                Notes = [.. report.Notes, "also composer.json: its install-time scripts are listed and reviewed", .. php.Notes],
            };
        var agent = AgentConfig(files, standalone: report == null, ct);
        var hooks = RepositoryHooks(files, ct);
        if (report == null && agent == null && hooks == null && !folder) return null;
        report ??= new PackageReport("repository", null, null);
        foreach (var found in new[] { agent, hooks }.OfType<AgentReview>())
            report = report with { Agents = [.. report.Agents ?? [], .. found.Entries], Findings = [.. report.Findings, .. found.Findings], Notes = [.. report.Notes, .. found.Notes] };
        if (report.Agents is { Count: 0 }) report = report with { Agents = null };
        var (rules, ruleNote) = GuardDogRules.Scan(path, report.Ecosystem, ct);
        if (rules.Count > 0 || ruleNote != null) report = report with { Findings = [.. report.Findings, .. rules], Notes = ruleNote != null ? [.. report.Notes, ruleNote] : report.Notes };
        if (!folder)
        {
            var (attestations, provenanceNotes) = PackageProvenance.Read(path, ct);
            if (attestations.Count > 0 || provenanceNotes.Count > 0)
                report = report with
                {
                    Provenance = attestations.Count > 0 ? attestations : null,
                    Findings = [.. report.Findings, .. attestations.SelectMany(ProvenanceFindings)],
                    Notes = [.. report.Notes, .. provenanceNotes],
                };
        }
        var findings = report.Findings.Distinct().OrderBy(f => f.Level == "noteworthy" ? 0 : 1).ThenBy(f => f.Category, StringComparer.Ordinal).ToList();
        var review = findings.Any(f => f.Level == "noteworthy") ? "noteworthy" : findings.Any(f => f.Level == "review") ? "worth reviewing" : "none";
        return report with
        {
            Findings = findings, Review = review, Files = files.Count, Notes = [.. files.Notes, .. report.Notes], Hosts = hosts ? Hosts(files, ct) : null,
            Partial = Partial(files),
        };
    }

    /// <summary>The files a review did not read, the first few named; null when it read them all.</summary>
    private static string? Partial(PackageFiles files)
    {
        var notRead = files.NotRead.Distinct().ToList();
        if (notRead.Count == 0 && files.Unlisted == 0) return null;
        var parts = new List<string>();
        if (notRead.Count > 0) parts.Add($"{notRead.Count} not read: {string.Join("; ", notRead.Take(5))}{(notRead.Count > 5 ? "; …" : "")}");
        if (files.Unlisted > 0) parts.Add($"{files.Unlisted:N0} past the first {PackageFiles.MaxEntries:N0} files neither listed nor read");
        return string.Join("; ", parts);
    }

    // An sdist holds one top folder; some archives carry setup.py at their root.
    private static bool IsSdistFile(string p) => Regex.IsMatch(p, @"^[^/]+/(setup\.py|pyproject\.toml|PKG-INFO|setup\.cfg)$|^(setup\.py|PKG-INFO)$", RegexOptions.NonBacktracking);

    /// <summary>The shallowest path ending in <paramref name="name"/> (a package's root folder may be named anything).</summary>
    internal static string? Root(PackageFiles files, string name) =>
        files.Paths.Where(p => p == name || p.EndsWith("/" + name, StringComparison.Ordinal))
            .Where(p => !p.Contains("node_modules/", StringComparison.Ordinal))
            .OrderBy(p => p.Count(c => c == '/')).ThenBy(p => p, StringComparer.Ordinal).FirstOrDefault();

    private static string? ManifestJson(PackageFiles files) => Root(files, "manifest.json");

    private static string Folder(string path) => path.Contains('/') ? path[..(path.LastIndexOf('/') + 1)] : "";

    // --- code rules ---

    private sealed record Rule(string Id, string Category, string Level, Func<string, bool> IsMatch, string What)
    {
        public Rule(string id, string category, string level, Regex pattern, string what) : this(id, category, level, pattern.IsMatch, what) { }
    }

    /// <summary>A rule level: noteworthy at install or beside credentials, host details, processes or decoded code; else review.</summary>
    private const string Paired = "paired";

    /// <summary>A rule level: noteworthy in a hand-sized file that runs at install, else review (bundles encode their own endpoints).</summary>
    private const string Small = "small";

    /// <summary>A rule level: noteworthy in a file that runs at install, else review; one heuristic alone is review.</summary>
    private const string Install = "install";

    // NonBacktracking matches in linear time, so whole-file rules take no match timeout.
    private static Regex R(string pattern) => new(pattern, RegexOptions.NonBacktracking | RegexOptions.CultureInvariant);

    /// <summary>What code reaches, by pattern: each rule names what it found. Levels are raised by the install-time context.</summary>
    private static readonly Rule[] CodeRules =
    [
        new("package/child-process", "process", "review", R(@"\bchild_process\b|\bexecSync\s*\(|\bspawnSync?\s*\(|\bexecFile(?:Sync)?\s*\("), "starts processes (child_process)"),
        new("package/python-process", "process", "review", R(@"\bsubprocess\.(?:Popen|run|call|check_output|check_call)\b|\bos\.(?:system|popen|exec[lv]p?e?)\s*\(|\bpty\.spawn\b"), "starts processes (subprocess / os.system)"),
        new("package/network", "network", "review", R(@"require\(\s*['""](?:node:)?(?:https?|net|dns|dgram|tls)['""]\s*\)|\bfetch\s*\(\s*['""`]https?:|\bXMLHttpRequest\b|\bnew\s+WebSocket\s*\(|\bhttps?\.(?:request|get)\s*\(|require\(\s*['""](?:axios|node-fetch|got|undici)['""]\s*\)|\bawait\s+fetch\s*\(|\baxios\.(?:get|post|request)\s*\("), "opens network connections"),
        new("package/python-network", "network", "review", R(@"\b(?:urllib\.request|urllib2|requests\.(?:get|post|put)|http\.client|socket\.socket|urlopen)\b"), "opens network connections (Python)"),
        new("package/download-tool", "network", "review", R(@"\b(?:curl|wget)\s+(?:-[\w-]+\s+)*['""]?https?://|\bInvoke-WebRequest\b|\biwr\s+https?:|\bbitsadmin\b|\bcertutil\s+-urlcache"), "downloads with a command-line tool"),
        new("package/eval", "dynamic code", "review", R(@"\beval\s*\((?:[^'""`]|\z)|\bnew\s+Function\s*\(|\bvm\.runIn(?:This|New)Context\b"), "evaluates code built at run time (eval / Function)"),
        new("package/exec-decoded", "dynamic code", "noteworthy", R(@"\bexec\s*\(\s*(?:base64\.\w*decode|zlib\.decompress|marshal\.loads|codecs\.decode|bytes\.fromhex|__import__\(\s*['""](?:base64|zlib|marshal|codecs))|\bexec\s*\(\s*['""][^'""]*['""]\s*\.decode\(\s*['""](?:base64|hex|rot13|rot_13)|\bexec\s*\([^\n]{0,300}?\b(?:b64decode|b32decode|b85decode|a85decode|decompress|marshal\.loads|unhexlify|fromhex)\s*\("), "executes decoded code (exec of base64 / zlib / marshal)"),
        new("package/exec-download", "dynamic code", "noteworthy", R(@"\b(?:exec|eval)\s*\([^\n]{0,40}?\w*urlopen\s*\(|\b(?:exec|eval)\s*\(\s*requests\.get\s*\("), "executes code it downloads (exec of urlopen / requests)"),
        new("package/eval-response", "dynamic code", "noteworthy", R(@"\beval\s*\(\s*\w+\.(?:data|body|responseText)\b[\w.]*\s*\)|\bnew\s+Function\s*\(\s*['""]require['""](?:\s*,\s*['""]\w+['""])*\s*,\s*[\w.]+\s*\)"), "runs code from a response (eval of response data, a Function given require)"),
        new("package/file-host-program", "process", "noteworthy", R(@"https?://(?:dl\.dropbox(?:usercontent)?\.com|cdn\.discordapp\.com/attachments|files\.catbox\.moe|transfer\.sh|github\.com/[\w.-]+/[\w.-]+/raw)/[^\s'""]*?\.(?:exe|sh|bat|cmd|ps1|vbs|scr|msi)\b"), "downloads a program from a file-sharing host"),
        new("package/download-and-run", "process", "noteworthy", R(@"\bcurl(?:\.exe)?\s+[^\n]{0,60}?https?://[^\s'""]+\.(?:exe|scr|msi)\b|\b(?:curl|wget)\b[^\n]{0,200}?&&\s*chmod\s+\+x|\burlretrieve\s*\([\s\S]{0,600}?(?:\bPopen\s*\(|\bos\.(?:system|startfile)\s*\(|\bchmod\s*\()|\[\s*['""]node['""]\s*,\s*['""]-e['""]\s*,\s*\w+\.stdout"), "downloads a program or script and runs it"),
        new("package/download-and-start", "process", "noteworthy", DownloadsAndStarts, "downloads a program to a file and starts it"),
        new("package/decoded-command", "process", "noteworthy", R(@"\b(?:os\.system|os\.popen|subprocess\.(?:Popen|run|call|check_output|check_call))\s*\(\s*\w*(?:b64d\w*|b64decode|decode|unhexlify|fromhex)\s*\(|(?:^|[^.\w$])(?:exec|execSync)\s*\(\s*(?:atob|Buffer\.from)\s*\("), "runs a decoded command"),
        new("package/account-listing", "host details", "noteworthy", R(@"(?:^|[^.\w$])(?:exec|execSync|spawnSync|check_output|getoutput|popen|system)\s*\(\s*['""`](?:net\s+user|net\s+localgroup|whoami\s+/(?:priv|all|groups)|cat\s+/etc/passwd)\b"), "runs account and privilege listing commands"),
        new("package/credential-files", "credentials", "noteworthy", R(@"\.npmrc\b|[/\\]\.ssh[/\\]|\bid_rsa\b|\.aws[/\\]credentials|\.git-credentials|\.bash_history|/etc/(?:shadow|passwd)\b|\bLogin Data\b|Local Storage[/\\]+leveldb|\bwallet\.dat\b|\bdiscord(?:app)?\b.{0,40}\btoken|\bkeychain-db\b|\bbrowser_cookie3\b|\.pypirc\b|" + PublishTokenRead), "reads credential files or publish tokens (npmrc, pypirc, ssh keys, cloud or browser stores)"),
        new("package/environment-dump", "credentials", "review", R(@"JSON\.stringify\(\s*process\.env\s*\)|Object\.(?:keys|entries|assign)\(\s*(?:\{\}\s*,\s*)?process\.env\s*\)|json\.dumps\(\s*(?:dict\()?os\.environ|dict\(\s*os\.environ\s*\)|os\.environ\.copy\(\)"), "collects all environment variables"),
        new("package/host-details", "host details", "review", R(@"\bos\.(?:hostname|userInfo|networkInterfaces|homedir)\(\)|\bsocket\.gethostname\(\)|\bgetpass\.getuser\(\)|\bplatform\.node\(\)|\bwhoami\b|\$\(hostname\)|\b(?:ip-api\.com|ipinfo\.io|api\.ipify\.org|ifconfig\.me|icanhazip\.com|checkip\.amazonaws\.com)\b"), "reads host and user details"),
        // URLs only: a list of suffixes (a public suffix table) names these domains without sending anything to them
        new("package/collection-url", "exfiltration", "noteworthy", R(@"https?://pastebin\.com/raw|https?://[\w.-]+\.ngrok(?:-free)?\.(?:io|app|dev)\b|https?://[\w.-]+\.(?:oast\.(?:fun|me|pro|live|site|online)|interact\.sh|burpcollaborator\.net|oastify\.com|beeceptor\.com|dnslog\.cn|ceye\.io|requestcatcher\.com)\b|https?://(?:[\w-]+\.)*(?:requestbin\.(?:com|net)|pipedream\.net|webhook\.site)\b"), "sends to a collection endpoint (paste site, tunnel, request catcher)"),
        // chat bots and raw addresses have ordinary uses (notification integrations, documentation): noteworthy beside other behaviour
        new("package/chat-webhook", "exfiltration", Paired, R(@"https?://(?:[\w-]+\.)?discord(?:app)?\.com/api/webhooks|https?://api\.telegram\.org/bot"), "sends to a chat webhook (Discord, Telegram)"),
        new("package/raw-address-url", "exfiltration", Paired, RawAddressUrl(), "sends to a raw address"),
        new("package/raw-address-socket", "exfiltration", Install, RawAddressSocket(), "opens a socket to a raw address"),
        new("package/reverse-shell", "process", "noteworthy", R(@"bash\s+-i\s*>&\s*/dev/tcp/|/dev/tcp/[\w.-]+/\d+|\bnc(?:at)?\s+(?:-\w+\s+)*-e\s+/bin/|\bos\.dup2\(\s*\w+\.fileno\(\)|\bpty\.spawn\(\s*['""]/bin/(?:ba)?sh"), "hands a shell to a network connection (reverse shell)"),
        new("package/download-to-shell", "process", "noteworthy", R(@"(?:curl|wget)\b[^\n|;]{0,300}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\bsh\s+-c\s+['""]?\$\((?:curl|wget)\b|(?i:\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b[^\n]{0,300}(?:\|\s*iex\b|Invoke-Expression))"), "runs a downloaded script (download piped to a shell)"),
        new("package/hidden-powershell", "process", "noteworthy", HiddenPowerShell(), "runs a hidden or encoded PowerShell command"),
        new("package/logon-start", "persistence", "noteworthy", R(@"Start Menu['""\\/, ]+Programs['""\\/, ]+Startup|CurrentVersion\\+Run\b|\bcrontab\s+-|/etc/cron\.|Library/LaunchAgents|\.config/autostart|\.config/systemd/user"), "writes to a location that starts programs at logon"),
        new("package/string-array", "transformed code", Install, StringArrayNames, "obfuscator.io-style transformed code"),
        new("package/escaped-call", "transformed code", "noteworthy", R(@"\b(?:eval|exec|compile|getattr|__import__)\s*\(\s*['""](?:\\(?:x[0-9a-fA-F]{2}|[0-7]{3})){4,}['""]"), "calls functions named by escaped strings"),
        new("package/eval-decoded", "transformed code", "noteworthy", R(@"\beval\s*\(\s*(?:atob|unescape|Buffer\.from|String\.fromCharCode|function\s*\(p,a,c,k,e,[dr]\))"), "evaluates decoded code"),
        new("package/long-base64", "transformed code", "review", R(@"['""][A-Za-z0-9+/]{2000,}={0,2}['""]"), "a base64 literal over 2,000 characters"),
        new("package/hidden-url", "transformed code", Small, R(@"['""`](?:aHR0cHM6Ly|aHR0cDovL|68747470733a2f2f|687474703a2f2f)[A-Za-z0-9+/=]{8,}['""`]"), "a URL hidden in base64 or hex"),
        new("package/exec-char-codes", "transformed code", "noteworthy", R(@"\b(?:exec|eval)\s*\(\s*['""]{2}\.join\(\s*map\(\s*chr\s*,|\b(?:exec|eval)\s*\(\s*bytes\(\s*\[\s*\d"), "executes code built from character codes"),
        new("package/pyobfuscate", "transformed code", "noteworthy", R(@"\(https://pyobfuscate\.com\)|\bimport\s+(?:marshal|zlib|base64)\s+as\s+_{3,}"), "pyobfuscate-style transformed code"),
        new("package/space-run", "transformed code", Install, R(@"[!-~][ \t]{300,}[!-~]"), "code placed after hundreds of spaces on one line (out of view in an editor)"),
    ];

    /// <summary>Findings for one file; <paramref name="install"/>: runs at install, <paramref name="entry"/>: loaded first, <paramref name="peel"/>: read through layers.</summary>
    internal static IEnumerable<PackageFinding> Scan(string path, string text, bool install, CancellationToken ct, bool entry = false, bool peel = true)
    {
        var plain = text;
        var language = ScriptReader.Detect(path, text);
        if (peel && language != null && text.Length <= 4 << 20 && Transformed.IsMatch(text.Length > 200_000 ? text[..200_000] : text))
        {
            var reading = ScriptReader.Read(text, language, ct, milliseconds: ScriptBudget.OverviewMilliseconds);
            // Decoded layers and obfuscator machinery count; ordinary eval does not.
            bool transformed = reading.Recovered.Any(r => r is "obfuscator.io string array" or "control-flow flattening")
                               || reading.Layers.Any(l => l.Via.Contains(" of ", StringComparison.Ordinal) || l.Via.Contains("EncodedCommand", StringComparison.Ordinal));
            if (transformed)
            {
                plain = text + "\n" + reading.Plain;
                yield return new PackageFinding("package/peeled-layers", install ? "noteworthy" : "review", "transformed code",
                    $"transformation layers peeled ({string.Join(", ", reading.Layers.Select(l => l.Via).Concat(reading.Recovered).Distinct().Take(4))}); summarize_file view=script reads the file", path);
            }
        }
        var matched = new List<Rule>();
        foreach (var rule in CodeRules)
            if (rule.IsMatch(plain)) matched.Add(rule);
        var hits = matched.Select(r => r.Category).ToHashSet(StringComparer.Ordinal);
        bool context = install || hits.Overlaps(["credentials", "host details", "process", "dynamic code", "transformed code"]);
        foreach (var rule in matched)
        {
            var level = rule.Level switch
            {
                Paired => context ? "noteworthy" : "review",
                Small => install && plain.Length <= 64 << 10 ? "noteworthy" : "review",
                Install => install ? "noteworthy" : "review",
                _ => rule.Level,
            };
            if (install && rule.Category == "network") level = "review";
            // Tools read credential paths for their own work; only at install are they noteworthy.
            if (!install && rule.Category == "credentials") level = "review";
            yield return new PackageFinding(rule.Id, level, rule.Category, (install ? "at install: " : "") + rule.What, path);
        }
        if (install && BundledProgram.IsMatch(plain))
            yield return new PackageFinding("package/install-bundled-program", "noteworthy", "process", "at install: runs a program the package carries (.exe, .bat, .ps1)", path);
        if (install && CompiledEval().IsMatch(plain))
            yield return new PackageFinding("package/install-compiled-eval", "noteworthy", "dynamic code", "at install: evaluates code compiled from a string (eval(compile(...)))", path);
        // A collector host outside a URL (request options, dns.lookup), at install or beside connections.
        if ((install || hits.Contains("network")) && CollectorHost.IsMatch(plain))
            yield return new PackageFinding("package/collector-host", "noteworthy", "exfiltration", (install ? "at install: " : "") + "contacts a collection endpoint (request catcher, out-of-band test host)", path);
        // Install-time code that reaches the network and collects host details or secrets, or runs decoded code.
        var with = hits.Where(h => h is "credentials" or "host details" or "transformed code").ToList();
        if (install && (hits.Contains("network") || with.Contains("host details") && FormattedUrl.IsMatch(plain))
            && (with.Count > 0 || plain.Contains("exec(", StringComparison.Ordinal) && hits.Contains("dynamic code")))
            yield return new PackageFinding("package/install-network-collect", "noteworthy", "install script", $"install-time code reaches the network and {(with.Count > 0 ? string.Join(", ", with) : "runs decoded code")}", path);
        else if (install && hits.Contains("network") && Launch.IsMatch(plain))
            yield return new PackageFinding("package/install-network-launch", "noteworthy", "install script", "install-time code reaches the network and launches a shell or a background process", path);
        if (ReverseShell().IsMatch(plain))
            yield return new PackageFinding("package/socket-shell", "noteworthy", "process", "pipes a socket into a spawned shell (reverse shell)", path);
        if (install && Detached.IsMatch(plain))
            yield return new PackageFinding("package/install-detached", "noteworthy", "process", "at install: starts a background process that outlives the install", path);
        if (install && XorDecode.IsMatch(plain))
            yield return new PackageFinding("package/install-xor", "noteworthy", "transformed code", "at install: decodes its strings with XOR", path);
        if (hits.Contains("network") && InterpreterStdin.IsMatch(plain))
            yield return new PackageFinding("package/stdin-remote-code", "noteworthy", "remote code", "runs code it fetches through an interpreter's standard input", path);
        if (ChatWebhook.IsMatch(plain) && (WebhookSecret.IsMatch(plain) || WalletSecret.IsMatch(plain)))
            yield return new PackageFinding("package/webhook-secrets", "noteworthy", "exfiltration", "sends passwords, keys, tokens or wallet secrets to a chat webhook", path);
        // A beacon at load: host identity or the environment sent from entry code.
        if (entry && hits.Contains("network") && LoadBeacon.IsMatch(plain))
            yield return new PackageFinding("package/load-beacon", "noteworthy", "host details", "sends host identity or the environment when loaded", path);
        if (SelfPublish.IsMatch(plain) && plain.Contains("package.json", StringComparison.Ordinal))
            yield return new PackageFinding("package/self-publish", "noteworthy", "publishing", "rewrites package.json and runs npm publish from its own code", path);
        if (CiConfigWritten(plain) is { } ci)
            yield return new PackageFinding("package/ci-config-write", install ? "noteworthy" : "review", "build step",
                $"{(install ? "at install: " : "")}opens a CI pipeline file for writing: {Clip(ci, 160)}", path);
        if (install && ShellTokenRead.IsMatch(plain))
            yield return new PackageFinding("package/credential-files", "noteworthy", "credentials", "at install: reads a publish token variable ($NPM_TOKEN, %TWINE_PASSWORD%)", path);
        if (ClipboardAddress(plain) is { } swap)
            yield return new PackageFinding("package/clipboard-address", install ? "noteworthy" : "review", "clipboard",
                $"{(install ? "at install: " : "")}reads and writes the clipboard ({swap.Pair}) beside a {swap.Kind} address pattern", path);
    }

    /// <summary>Clipboard read and write calls, as pairs a file must hold both of.</summary>
    private static readonly (string Pair, Regex Read, Regex Write)[] ClipboardPairs =
    [
        ("navigator.clipboard readText and writeText", R(@"\bclipboard\.readText\s*\("), R(@"\bclipboard\.writeText\s*\(")),
        ("execCommand paste and copy", R(@"\bexecCommand\s*\(\s*['""]paste['""]"), R(@"\bexecCommand\s*\(\s*['""]copy['""]")),
        ("pyperclip paste and copy", R(@"\bpyperclip\.paste\s*\("), R(@"\bpyperclip\.copy\s*\(")),
        ("clipboard paste and copy", R(@"\bclipboard\.paste\s*\("), R(@"\bclipboard\.copy\s*\(")),
        ("clipboardy read and write", R(@"\bclipboardy\.read(?:Sync)?\s*\("), R(@"\bclipboardy\.write(?:Sync)?\s*\(")),
    ];

    /// <summary>Address kinds, each by the shape of a regular expression that matches its addresses.</summary>
    private static readonly (string Kind, Regex Shape)[] AddressShapes =
    [
        ("Bitcoin", R(@"(?:\[13\]|\(\?:1\|3\)|\(1\|3\))[^\n'""`]{0,60}\{2[5-9],3[0-9]\}|\bbc1[^\n'""`]{0,40}\{[0-9]{2}(?:,[0-9]{2})?\}")),
        ("Ethereum", R(@"0x\[[0-9a-fA-F-]{3,12}\]\{40\}")),
        ("Tron", R(@"\bT\[[1-9A-Za-z-]{5,20}\]\{33\}")),
        ("Litecoin", R(@"\[LM3?\]\[[1-9A-Za-z-]{5,20}\]\{2[5-9],3[0-9]\}")),
        ("Solana", R(@"\[1-9A-HJ-NP-Za-km-z\]\{3[2-3],4[3-4]\}")),
    ];

    /// <summary>The first clipboard pair and address kind a file holds together, or null when it lacks either.</summary>
    private static (string Pair, string Kind)? ClipboardAddress(string text)
    {
        if (!text.Contains("clipboard", StringComparison.OrdinalIgnoreCase) && !text.Contains("execCommand", StringComparison.Ordinal)
            && !text.Contains("pyperclip", StringComparison.Ordinal)) return null;
        var pair = ClipboardPairs.FirstOrDefault(p => p.Read.IsMatch(text) && p.Write.IsMatch(text)).Pair;
        var kind = pair == null ? null : AddressShapes.FirstOrDefault(a => a.Shape.IsMatch(text)).Kind;
        return kind == null ? null : (pair!, kind);
    }

    private static readonly Regex ShellTokenRead = R($@"\$\{{?(?:{PublishTokens})\b|%(?:{PublishTokens})%");

    private const string PublishTokens = "NPM_TOKEN|NODE_AUTH_TOKEN|TWINE_PASSWORD|PYPI_TOKEN|PYPI_API_TOKEN";

    // Reads of the npm and PyPI publish token variables from JavaScript or Python.
    private const string PublishTokenRead = $@"\bprocess\.env(?:\.(?:{PublishTokens})\b|\[\s*['""`](?:{PublishTokens})['""`]\s*\])|\bos\.(?:environ(?:\.get\(|\[)|getenv\()\s*['""](?:{PublishTokens})['""]";

    private const string CiPath = @"[^'""`\n]*(?:\.github/workflows/|\.gitlab-ci\.yml|azure-pipelines\.yml|\.circleci/config\.yml|Jenkinsfile)[^'""`\n]*";

    // A join with '.github' then 'workflows' as adjacent literal segments, or a pathlib '/' join of them.
    private static readonly Regex CiJoin = R(@"\b(?:path\.(?:join|resolve)|os\.path\.join)\s*\([^()\n]{0,200}?['""`]\.github['""`]\s*,\s*['""`]workflows['""`][^()\n]{0,200}\)|\bPath\s*\([^()\n]{0,200}?['""]\.github['""]\s*(?:,|\)\s*/)\s*['""]workflows['""][^\n]{0,120}");
    private static readonly Regex JoinWrite = R(@"\b(?:writeFile(?:Sync)?|appendFile(?:Sync)?|createWriteStream|open)\s*\(\s*$|\.write_(?:text|bytes)\(|\bshutil\.copy(?:file|2)?\s*\([^,\n]{1,200},\s*$");
    private static readonly Regex JoinAssign = R(@"(?:^|[\s;(])(?<v>[A-Za-z_$][\w$]*)\s*=\s*$");

    /// <summary>The CI pipeline path a write call opens: a literal, or a join written in the same statement or through a variable within five lines; else null.</summary>
    private static string? CiConfigWritten(string text)
    {
        if (CiConfigWrite.Match(text) is { Success: true } literal) return literal.Groups["p"].Value;
        foreach (Match join in CiJoin.Matches(text))
        {
            int lineStart = text.LastIndexOf('\n', Math.Max(0, join.Index - 1)) + 1, lineEnd = text.IndexOf('\n', join.Index + join.Length) is var e and >= 0 ? e : text.Length;
            var before = text[lineStart..join.Index];
            // Same statement: a write call opened just before the join, or a pathlib write right after it.
            if (JoinWrite.IsMatch(before) || join.Value.StartsWith("Path", StringComparison.Ordinal) && JoinWrite.IsMatch(text[join.Index..lineEnd])) return join.Value;
            if (JoinAssign.Match(before) is not { Success: true } assign) continue;
            var name = Regex.Escape(assign.Groups["v"].Value);
            var next = string.Join('\n', text[lineEnd..].Split('\n', 7).Skip(1).Take(5));
            if (Regex.IsMatch(next, $@"\b(?:writeFile(?:Sync)?|appendFile(?:Sync)?|createWriteStream|open)\s*\(\s*(?:(?:path\.(?:join|resolve)|os\.path\.join)\s*\(\s*)?{name}\b|(?:^|[^\w$.]){name}\s*(?:/\s*['""][^'""\n]*['""]\s*)?\.write_(?:text|bytes)\(|\bshutil\.copy(?:file|2)?\s*\([^,\n]{{1,200}},\s*{name}\b", RegexOptions.NonBacktracking))
                return join.Value;
        }
        return null;
    }

    // A write call whose own arguments carry a CI pipeline path literal; group p is the literal.
    private static readonly Regex CiConfigWrite = R($@"\b(?:writeFile(?:Sync)?|appendFile(?:Sync)?|createWriteStream)\s*\(\s*(?:[\w$.]+\s*\(\s*)?['""`](?<p>{CiPath})['""`]"
        + $@"|\bopen\s*\(\s*['""](?<p>{CiPath})['""]\s*,\s*(?:mode\s*=\s*)?['""][wax]b?\+?['""]"
        + $@"|\bPath\s*\(\s*['""](?<p>{CiPath})['""]\s*\)\s*\.(?:write_text|write_bytes|open\(\s*['""][wax])"
        + $@"|\bshutil\.copy(?:file|2)?\s*\([^,\n]{{1,200}},\s*['""](?<p>{CiPath})['""]");

    // A binary installer runs its own executable; these start a shell or outlive the installer.
    private static readonly Regex Launch = R(@"\bdetached\s*:\s*true|\.unref\(\)|\b(?:spawn|exec|execSync|execFile)\s*\(\s*['""`](?:cmd(?:\.exe)?|powershell(?:\.exe)?|/bin/(?:ba)?sh|sh|bash|start)\b|\bshell\s*=\s*True|\bos\.(?:system|startfile|popen)\s*\(|\bsubprocess\.Popen\s*\(");
    private const string Socket = @"\bnew\s+net\.Socket\b|\bnet\.(?:connect|createConnection)\s*\(|\bsocket\.socket\s*\(";
    private static readonly Regex Detached = R(@"\bdetached\s*:\s*(?:true|!0)|\bstart_new_session\s*=\s*True|\bDETACHED_PROCESS\b|\bnohup\s");
    private static readonly Regex XorDecode = R(@"\bfromCharCode\s*\([^()\n]{0,80}\^|\bchr\s*\([^()\n]{0,60}\^");
    private static readonly Regex InterpreterStdin = R(@"\bspawn\s*\(\s*['""](?:node|python3?|sh|bash)['""][\s\S]{0,300}?\.stdin\.(?:write|end)\s*\((?:[^'""`]|\z)");
    private static readonly Regex ChatWebhook = R(@"https?://(?:[\w-]+\.)?discord(?:app)?\.com/api/webhooks/|https?://api\.telegram\.org/bot");
    private static readonly Regex WebhookSecret = R(@"(?i)\b\w*webhook\w*\s*\([^()\n]{0,200}?\b(?:password|passwd|api[_ ]?key|token|secret|cookies?)\b");
    private static readonly Regex WalletSecret = R(@"(?i)\bprivate_?keys?\b|\bmnemonic\b|\bseed_?phrase\b");
    private const string Shell = @"\b(?:spawn|exec|Popen|call|run)\s*\(\s*\[?\s*['""](?:/bin/(?:ba|z)?sh|sh|bash|cmd(?:\.exe)?|powershell(?:\.exe)?)['""]";
    // A socket near a spawned shell or a child piped to it; bounded gaps keep work per start constant, so no match timeout.
    [GeneratedRegex($@"(?:{Socket})[\s\S]{{0,1500}}?(?:{Shell}|\.pipe\(\s*[\w$.]+\.stdin\s*\)[\s\S]{{0,300}}?\.stdout\.pipe\()|(?:{Shell})[\s\S]{{0,1500}}?(?:{Socket})", RegexOptions.CultureInvariant)]
    private static partial Regex ReverseShell();
    private static readonly Regex LoadBeacon = R(@"\b(?:os\.(?:hostname|userInfo|networkInterfaces)\(\)|socket\.gethostname\(\)|getpass\.getuser\(\)|platform\.node\(\))[\s\S]{0,600}?\b(?:os\.(?:hostname|userInfo|networkInterfaces|homedir)\(\)|socket\.gethostname\(\)|getpass\.getuser\(\)|platform\.node\(\)|process\.cwd\(\)|os\.getcwd\(\)|__dirname)|JSON\.stringify\(\s*process\.env\s*\)|json\.dumps\(\s*(?:dict\()?os\.environ");
    private static readonly Regex BundledProgram = R(@"\.(?:run|call|Popen|check_call|check_output|system|startfile)\(\s*\[?\s*(?:os\.path\.abspath\(\s*)?['""][^'""\n]*\.(?:exe|bat|cmd|ps1|vbs|scr)['""]|\.(?:run|call|Popen|check_call)\(\s*\[\s*exe_path\b");
    private static readonly Regex FormattedUrl = R(@"['""]https?://[^\s'""]*(?:\{\w*\}|%s|\$\{)");
    // Excludes compile(f.read(), ...), which setup.py uses to read its version module; no match timeout needed.
    [GeneratedRegex(@"\b(?:eval|exec)\s*\(\s*compile\s*\(\s*(?![\w.]*\.read\(|open\()", RegexOptions.CultureInvariant)]
    private static partial Regex CompiledEval();
    private static readonly Regex CollectorHost = R(@"['""`/.@](?:[\w-]+\.)*(?:oast\.(?:fun|me|pro|live|site|online)|interact\.sh|burpcollaborator\.net|oastify\.com|dnslog\.cn|ceye\.io|requestcatcher\.com|pipedream\.net|webhook\.site)['""`/]");
    private static readonly Regex SelfPublish = R(@"\bexec(?:Sync)?\s*\(\s*['""`]npm\s+publish\b");

    // Lookaheads read a bounded stretch per start, so no match timeout.
    [GeneratedRegex(@"https?://(?!(?:127|0|10)\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.)(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/", RegexOptions.CultureInvariant)]
    private static partial Regex RawAddressUrl();

    [GeneratedRegex(@"\.connect\(\s*\(\s*['""](?!(?:127|0|10)\.|192\.168\.)(?:\d{1,3}\.){3}\d{1,3}['""]\s*,\s*\d+\s*\)|\b(?:net\.connect|createConnection|\.connect)\(\s*\d+\s*,\s*['""](?!(?:127|0|10)\.|192\.168\.)(?:\d{1,3}\.){3}\d{1,3}['""]", RegexOptions.CultureInvariant)]
    private static partial Regex RawAddressSocket();

    [GeneratedRegex(@"(?i:powershell(?:\.exe)?\b[^\n]{0,120}(?:-w(?:indowstyle)?\s+hidden(?![^\n]{0,40}-Verb\s+runAs)|-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{40}))", RegexOptions.CultureInvariant)]
    private static partial Regex HiddenPowerShell();

    private static readonly Regex HexName = R(@"\b_0x[0-9a-f]{4,6}\b");

    /// <summary>Whether nine obfuscator.io names (_0x1a2b) follow each other on one line, each within 400 characters.</summary>
    private static bool StringArrayNames(string text)
    {
        // Consecutive names are the closest pair, so a run of them decides it;
        // one regex of nested bounded gaps backtracks combinatorially instead.
        int run = 0, end = -1;
        foreach (var m in HexName.EnumerateMatches(text))
        {
            run = end >= 0 && m.Index - end <= 400 && !text.AsSpan(end, m.Index - end).Contains('\n') ? run + 1 : 1;
            if (run >= 9) return true;
            end = m.Index + m.Length;
        }
        return false;
    }

    private static readonly Regex Downloader = R(@"\b(?:curl|wget|Invoke-WebRequest|iwr)\b");
    private static readonly Regex DownloadSource = R(@"https?://|%\w*URL\w*%|\$\{?\w*URL");
    private static readonly Regex SavedTo = R(@"\s-(?:o|O|OutFile)\s+['""]?(?<f>%\w+%|\$?\{\w+\}|\$\w+|[^\s'""]+\.(?:exe|scr|msi|bat|cmd|ps1|sh|bin))['""]?");
    private static readonly Regex Starter = R(@"(?m)(?:^|[\s&;(|'""])(?:start|Start-Process|call|chmod\s+\+x)\b");

    /// <summary>Whether a URL download saves to a file that a start, call or chmod +x names within 3,000 characters.</summary>
    private static bool DownloadsAndStarts(string text)
    {
        // Each step is a linear match; one regex with a backreference to the
        // saved file backtracks over every line pair instead.
        foreach (var tool in Downloader.EnumerateMatches(text))
        {
            int from = tool.Index + tool.Length, lineEnd = text.IndexOf('\n', from) is var n and >= 0 ? n : text.Length;
            if (!DownloadSource.IsMatch(text.AsSpan(from, lineEnd - from))) continue;
            for (var saved = SavedTo.Match(text, from, lineEnd - from); saved.Success; saved = saved.NextMatch())
            {
                var file = saved.Groups["f"].Value;
                int after = saved.Index + saved.Length;
                for (var start = Starter.Match(text, after); start.Success && start.Index <= after + 3000; start = start.NextMatch())
                {
                    int at = start.Index + start.Length, end = text.IndexOf('\n', at) is var e and >= 0 ? e : text.Length;
                    if (text.AsSpan(at, end - at).Contains(file, StringComparison.Ordinal)) return true;
                }
            }
        }
        return false;
    }

    /// <summary>Findings in the entry files, then noteworthy findings only in other scripts within a bound.</summary>
    internal static IEnumerable<PackageFinding> ScanLoaded(PackageFiles files, string root, IEnumerable<string> entries, CancellationToken ct)
    {
        var entryFiles = entries.Distinct().ToList();
        foreach (var entry in entryFiles)
            if (files.Text(entry) is { } code)
                foreach (var f in Scan(entry, code, install: false, ct, entry: true))
                    if (f.Level == "noteworthy" || f.Category is "transformed code" or "credentials" or "build step" or "clipboard") yield return f;
        var sources = files.Paths.Where(p => p.StartsWith(root, StringComparison.Ordinal) && LoadedSource.IsMatch(p)
                                             && !p.Contains("node_modules/", StringComparison.Ordinal) && !entryFiles.Contains(p))
            .OrderBy(p => p.Count(c => c == '/')).ThenBy(p => p, StringComparer.Ordinal).ToList();
        files.NotRead.AddRange(sources.Where(p => files.Size(p) > MaxScannedSourceBytes && files.Bytes(p) != null)
            .Select(p => $"{p} (source over {MaxScannedSourceBytes >> 20} MiB)"));
        foreach (var other in Capped(files, [.. sources.Where(p => files.Size(p) <= MaxScannedSourceBytes)]))
            if (files.Text(other) is { } code)
                foreach (var f in Scan(other, code, install: false, ct, entry: Folder(other) == root, peel: false))
                    if (f.Level == "noteworthy") yield return f;
    }

    private static readonly Regex LoadedSource = R(@"\.(?:c|m)?js$|\.(?:bat|cmd|ps1|sh)$");

    /// <summary>Signs of a transformation layer worth reading through: string arrays, eval / exec of decoded text, packers, encoded commands.</summary>
    private static readonly Regex Transformed = R(@"\b_0x[0-9a-f]{4,6}\b.{0,200}\b_0x[0-9a-f]{4,6}\b|\beval\s*\(\s*(?:atob|unescape|Buffer\.from|String\.fromCharCode|decodeURIComponent|function\s*\(p,a,c,k)|\bFunction\s*\(\s*(?:atob|unescape|String\.fromCharCode)|(?i:\b(?:iex|invoke-expression)\b|-enc(?:odedcommand)?\s+[A-Za-z0-9+/]{40})|\bExecute(?:Global)?\s*\(?\s*(?:Chr|StrReverse)");

    private static readonly Regex UrlHost = R(@"\b(?:https?|wss?|ftp)://([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+|\[[0-9A-Fa-f:]+\])");
    private static readonly HashSet<string> CodeExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".py", ".sh", ".ps1", ".bat", ".cmd", ".vbs", ".rb", ".pl", ".php", ".lua", ".go", ".rs", ".cs", ".java", ".kt",
    };
    private const int MaxHosts = 1000;
    private const long MaxHostText = 64L << 20;

    /// <summary>Hosts named in URLs in the code files (and install scripts of package.json), at most <see cref="MaxHosts"/>, over the first 64 MiB of code.</summary>
    private static List<string> Hosts(PackageFiles files, CancellationToken ct)
    {
        var hosts = new SortedSet<string>(StringComparer.Ordinal);
        long read = 0;
        foreach (var path in files.Paths.Where(p => CodeExtensions.Contains(Path.GetExtension(p)) || p == "package.json" || p.EndsWith("/package.json", StringComparison.Ordinal))
                     .Where(p => !p.Contains("node_modules/", StringComparison.Ordinal)).Order(StringComparer.Ordinal))
        {
            ct.ThrowIfCancellationRequested();
            if (read > MaxHostText || hosts.Count >= MaxHosts) break;
            if (files.Text(path) is not { } text) continue;
            read += text.Length;
            foreach (Match m in UrlHost.Matches(text))
                if (hosts.Count < MaxHosts) hosts.Add(m.Groups[1].Value.ToLowerInvariant());
        }
        return [.. hosts];
    }

    /// <summary>Native and executable files a package carries.</summary>
    internal static List<string> Binaries(PackageFiles files) =>
        files.Paths.Where(p => Regex.IsMatch(p, @"\.(node|so|dylib|dll|exe|pyd|wasm|jar|bin|msi|scr|com)$", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking)
                               || files.Bytes(p) is { Length: >= 4 } b && (b[0] == 'M' && b[1] == 'Z' || b[0] == 0x7F && b[1] == 'E' && b[2] == 'L' && b[3] == 'F'))
            .Order(StringComparer.Ordinal).Take(200).ToList();

    // --- commands named like system commands ---

    /// <summary>System and toolchain commands a package command can take the place of on PATH.</summary>
    private static readonly HashSet<string> SystemCommands = new(StringComparer.OrdinalIgnoreCase)
    {
        "node", "npm", "npx", "yarn", "pnpm", "git", "python", "python3", "pip", "pip3", "sh", "bash", "ls", "cat",
        "curl", "wget", "ssh", "scp", "sudo", "docker", "kubectl", "dotnet", "java", "go", "cargo", "code",
    };

    /// <summary>Commands shipped by a package of another name: npm installs npx, pip installs pip3.</summary>
    private static readonly Dictionary<string, string> CommandOwners = new(StringComparer.OrdinalIgnoreCase) { ["npx"] = "npm", ["pip3"] = "pip" };

    /// <summary>One finding per bin, console_scripts, gui_scripts or wheel script named like a system command, except in the package that owns it; empty when none.</summary>
    internal static IEnumerable<PackageFinding> CommandNames(string? package, IEnumerable<PackageEntryPoint> entries, bool atInstall, string? path)
    {
        foreach (var e in entries.Where(e => e.Kind is "bin" or "console_scripts" or "gui_scripts" or "script"))
        {
            // npm names a string bin after the package without its scope.
            var command = e.Name[(e.Name.LastIndexOf('/') + 1)..];
            if (!SystemCommands.Contains(command) || string.Equals(package, CommandOwners.GetValueOrDefault(command, command), StringComparison.OrdinalIgnoreCase)) continue;
            yield return new PackageFinding("package/command-name", atInstall ? "noteworthy" : "review", "name",
                $"{e.Kind} '{e.Name}' ({Clip(e.Target, 120)}) installs a program named like the system command {command}", path);
        }
    }

    // --- names close to popular packages ---

    /// <summary>A popular name that <paramref name="name"/> is one or two edits (or a separator) away from, else null.</summary>
    internal static string? CloseTo(string name, IReadOnlyCollection<string> popular)
    {
        var bare = Normalize(name);
        if (popular.Contains(name, StringComparer.OrdinalIgnoreCase)) return null;
        foreach (var p in popular)
        {
            // A scope is owned by its publisher: @swc/core is no copy of cors.
            if (name.StartsWith('@') && !p.StartsWith('@')) continue;
            var q = Normalize(p);
            if (q == bare) return p;
            if (Math.Abs(q.Length - bare.Length) > 2 || q.Length < 4) continue;
            int d = Distance(bare, q);
            if (d == 1 || d == 2 && q.Length >= 8) return p;
        }
        return null;
    }

    /// <summary><paramref name="version"/> when its major version is 99 or higher, else null; a year or date major (2000 to 2099) is a calendar version.</summary>
    internal static string? HighVersion(string? version) =>
        version != null && LeadingNumber.Match(version) is { Success: true } m && long.Parse(m.Groups[1].Value) is >= 99 and not (>= 2000 and <= 2099 or >= 20000101 and <= 20991231)
            ? Clip(version, 40) : null;

    // A PEP 440 epoch (N!) comes before the major version.
    private static readonly Regex LeadingNumber = R(@"^\s*[vV=]?(?:\d+!)?0*(\d{1,12})");

    private static string Normalize(string name)
    {
        // The scope stays: @swc/core and @babel/core are different names.
        return Regex.Replace(name.ToLowerInvariant(), @"[-_.@/]", "", RegexOptions.NonBacktracking);
    }

    /// <summary>Optimal string alignment distance (adjacent transpositions count once).</summary>
    private static int Distance(string a, string b)
    {
        var d = new int[a.Length + 1, b.Length + 1];
        for (int i = 0; i <= a.Length; i++) d[i, 0] = i;
        for (int j = 0; j <= b.Length; j++) d[0, j] = j;
        for (int i = 1; i <= a.Length; i++)
            for (int j = 1; j <= b.Length; j++)
            {
                int cost = a[i - 1] == b[j - 1] ? 0 : 1;
                d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);
                if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1]) d[i, j] = Math.Min(d[i, j], d[i - 2, j - 2] + 1);
            }
        return d[a.Length, b.Length];
    }

    // A check that failed is noteworthy: the file differs from what was signed, or the signature does not hold.
    private static IEnumerable<PackageFinding> ProvenanceFindings(PackageAttestation a) =>
        new[] { ("digest", a.Digest), ("signature", a.Signature), ("certificate chain", a.Chain), ("log entry", a.Log) }
            .Where(c => c.Item2.StartsWith("failed", StringComparison.Ordinal))
            .Select(c => new PackageFinding("package/provenance-failed", "noteworthy", "provenance", $"{a.Format} {c.Item1} {c.Item2}", a.File));
}
