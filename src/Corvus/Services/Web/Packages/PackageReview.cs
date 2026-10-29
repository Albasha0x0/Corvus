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
            assets.AddRange(AgentSettingsHooks(files));
            if (assets.Count > 0 || assetNotes.Count > 0) report = report with { Findings = [.. report.Findings, .. assets], Notes = [.. report.Notes, .. assetNotes] };
            var filler = files.CommentFiller.Select(p => new PackageFinding("package/comment-filler", "review", "transformed code",
                $"a code file over {PackageFiles.MaxFile >> 20} MiB padded with NUL bytes or archive data inside /* */ comments; its code outside them was read", p));
            report = report with { Findings = [.. report.Findings, .. filler] };
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

    /// <summary>A rule level: noteworthy in a hand-sized file, review in a bundle (bundles encode their own endpoints).</summary>
    private const string Small = "small";

    // NonBacktracking matches in linear time, so whole-file rules take no match timeout.
    private static Regex R(string pattern) => new(pattern, RegexOptions.NonBacktracking | RegexOptions.CultureInvariant);

    private static readonly Regex LongBase64 = R(@"['""][A-Za-z0-9+/]{2000,}={0,2}['""]");

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
        new("package/eval-response", "dynamic code", "noteworthy", R(@"(?:^|[^.\w$])eval\s*\(\s*\w+\.(?:data|body|responseText)\b[\w.]*\s*\)|(?:\bnew\s+)?\(?\s*(?:\bFunction(?:\.constructor)?|\.constructor(?:\.constructor)?)\s*\)?\s*\(\s*['""]require['""](?:\s*,\s*['""]\w+['""])*\s*,\s*[\w.]+\s*\)|"
            + ResponseCallback + "(?:" + DecodedRunInBlock + "|" + DecodedRunInExpression + ")"),
            "runs code from a response (eval of response data or its base64 decode, a Function given require)"),
        new("package/file-host-program", "process", "noteworthy", R(@"https?://(?:dl\.dropbox(?:usercontent)?\.com|cdn\.discordapp\.com/attachments|files\.catbox\.moe|transfer\.sh|github\.com/[\w.-]+/[\w.-]+/raw)/[^\s'""]*?\.(?:exe|sh|bat|cmd|ps1|vbs|scr|msi)\b"), "downloads a program from a file-sharing host"),
        new("package/download-and-run", "process", "noteworthy", R(@"\bcurl(?:\.exe)?\s+[^\n]{0,60}?https?://[^\s'""]+\.(?:exe|scr|msi)\b|\b(?:curl|wget)\b[^\n]{0,200}?&&\s*chmod\s+\+x|\burlretrieve\s*\([\s\S]{0,600}?(?:\bPopen\s*\(|\bos\.(?:system|startfile)\s*\(|\bchmod\s*\()|\[\s*['""]node['""]\s*,\s*['""]-e['""]\s*,\s*\w+\.stdout"), "downloads a program or script and runs it"),
        new("package/download-and-start", "process", "noteworthy", DownloadsAndStarts, "downloads a program to a file and starts it"),
        new("package/decoded-file-run", "process", "noteworthy", WritesDecodedAndRuns, DecodedFileRun),
        new("package/decoded-command", "process", "noteworthy", R(@"\b(?:os\.system|os\.popen|subprocess\.(?:Popen|run|call|check_output|check_call))\s*\(\s*\w*(?:b64d\w*|b64decode|decode|unhexlify|fromhex)\s*\(|(?:^|[^.\w$])(?:exec|execSync)\s*\(\s*(?:atob|Buffer\.from)\s*\("), "runs a decoded command"),
        new("package/account-listing", "host details", "noteworthy", R(@"(?:^|[^.\w$])(?:exec|execSync|spawnSync|check_output|getoutput|popen|system)\s*\(\s*['""`](?:net\s+user|net\s+localgroup|whoami\s+/(?:priv|all|groups)|cat\s+/etc/passwd)\b"), "runs account and privilege listing commands"),
        new("package/credential-files", "credentials", "noteworthy", R(@"\.npmrc\b|[/\\]\.ssh[/\\]|\bid_rsa\b|\.aws[/\\]credentials|\.git-credentials|\.bash_history|/etc/(?:shadow|passwd)\b|\bLogin Data\b|Local Storage[/\\]+leveldb|\bwallet\.dat\b|\bdiscord(?:app)?\b.{0,40}\btoken|\bkeychain-db\b|\bbrowser_cookie3\b|\.pypirc\b|" + PublishTokenRead), "reads credential files or publish tokens (npmrc, pypirc, ssh keys, cloud or browser stores)"),
        new("package/environment-dump", "credentials", "review", R(@"JSON\.stringify\(\s*process\.env\s*\)|Object\.(?:keys|entries|assign)\(\s*(?:\{\}\s*,\s*)?process\.env\s*\)|json\.dumps\(\s*(?:dict\()?os\.environ|dict\(\s*os\.environ\s*\)|os\.environ\.copy\(\)"), "collects all environment variables"),
        new("package/host-details", "host details", "review", ReadsHostDetails, "reads host and user details"),
        // URLs only: a list of suffixes (a public suffix table) names these domains without sending anything to them
        new("package/collection-url", "exfiltration", "noteworthy", R(@"https?://pastebin\.com/raw|https?://[\w.-]+\.ngrok(?:-free)?\.(?:io|app|dev)\b|https?://[\w.-]+\.(?:oast\.(?:fun|me|pro|live|site|online)|interact\.sh|burpcollaborator\.net|oastify\.com|beeceptor\.com|dnslog\.cn|ceye\.io|requestcatcher\.com)\b|https?://(?:[\w-]+\.)*(?:requestbin\.(?:com|net)|pipedream\.net|webhook\.site)\b"), "sends to a collection endpoint (paste site, tunnel, request catcher)"),
        // chat bots and raw addresses have ordinary uses (notification integrations, documentation): noteworthy beside other behaviour
        new("package/chat-webhook", "exfiltration", Paired, R(@"https?://(?:[\w-]+\.)?discord(?:app)?\.com/api/webhooks|https?://api\.telegram\.org/bot"), "sends to a chat webhook (Discord, Telegram)"),
        new("package/raw-address-url", "exfiltration", Paired, RawAddressUrl(), "sends to a raw address"),
        new("package/raw-address-socket", "exfiltration", "noteworthy", RawAddressSocket(), "opens a socket to a raw address"),
        new("package/reverse-shell", "process", "noteworthy", R(@"bash\s+-i\s*>&\s*/dev/tcp/|/dev/tcp/[\w.-]+/\d+|\bnc(?:at)?\s+(?:-\w+\s+)*-e\s+/bin/|\bos\.dup2\(\s*\w+\.fileno\(\)|\bpty\.spawn\(\s*['""]/bin/(?:ba)?sh"), "hands a shell to a network connection (reverse shell)"),
        new("package/download-to-shell", "process", "noteworthy", R(@"(?:curl|wget)\b[^\n|;]{0,300}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\bsh\s+-c\s+['""]?\$\((?:curl|wget)\b|(?i:\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b[^\n]{0,300}(?:\|\s*iex\b|Invoke-Expression))"), "runs a downloaded script (download piped to a shell)"),
        new("package/hidden-powershell", "process", "noteworthy", HiddenPowerShell(), "runs a hidden or encoded PowerShell command"),
        new("package/logon-start", "persistence", "noteworthy", R(@"Start Menu['""\\/, ]+Programs['""\\/, ]+Startup|CurrentVersion\\+Run\b|\bcrontab\s+-|/etc/cron\.|Library/LaunchAgents|\.config/autostart|\.config/systemd/user"), "writes to a location that starts programs at logon"),
        new("package/access-persistence", "persistence", "noteworthy", AddsAuthorizedKey, "appends a public key to authorized_keys"),
        new("package/string-array", "transformed code", "noteworthy", StringArrayNames, "obfuscator.io-style transformed code"),
        new("package/escaped-call", "transformed code", "noteworthy", R(@"\b(?:eval|exec|compile|getattr|__import__)\s*\(\s*['""](?:\\(?:x[0-9a-fA-F]{2}|[0-7]{3})){4,}['""]"), "calls functions named by escaped strings"),
        new("package/eval-decoded", "transformed code", "noteworthy", R(@"\beval\s*\(\s*(?:atob|unescape|Buffer\.from|String\.fromCharCode|function\s*\(p,a,c,k,e,[dr]\))"), "evaluates decoded code"),
        new("package/eval-inflated", "dynamic code", Small, RunsDecodedContent, "evaluates inflated or image-decoded content (eval / Function)"),
        new("package/long-base64", "transformed code", "review", R(@"['""][A-Za-z0-9+/]{2000,}={0,2}['""]"), "a base64 literal over 2,000 characters"),
        new("package/long-base64", "transformed code", "review", LongBase64, "a base64 literal over 2,000 characters"),
        new("package/hidden-url", "transformed code", Small, R(@"['""`](?:aHR0cHM6Ly|aHR0cDovL|68747470733a2f2f|687474703a2f2f)[A-Za-z0-9+/=]{8,}['""`]"), "a URL hidden in base64 or hex"),
        new("package/exec-char-codes", "transformed code", "noteworthy", ExecutesCharCodes, "executes code built from character codes"),
        new("package/pyobfuscate", "transformed code", "noteworthy", R(@"\(https://pyobfuscate\.com\)|\bimport\s+(?:marshal|zlib|base64)\s+as\s+_{3,}"), "pyobfuscate-style transformed code"),
        new("package/space-run", "transformed code", "noteworthy", CodeAfterBlankRun, "code placed after hundreds of columns of spaces or tabs on one line (out of view in an editor)"),
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
                Small => plain.Length <= 64 << 10 ? "noteworthy" : "review",
                _ => rule.Level,
            };
            if (install && rule.Category == "network") level = "review";
            // Tools read credential paths for their own work; only at install are they noteworthy.
            if (!install && rule.Category == "credentials") level = "review";
            yield return new PackageFinding(rule.Id, level, rule.Category, (install ? "at install: " : "") + rule.What, path);
        }
        if (path.EndsWith(".py", StringComparison.OrdinalIgnoreCase) && NormalizedExec(plain) is { } name)
            yield return new PackageFinding("package/normalized-exec", "noteworthy", "transformed code",
                $"{(install ? "at install: " : "")}calls {name} under a non-ASCII name that normalizes to it", path);
        if (install && BundledProgram.IsMatch(plain))
            yield return new PackageFinding("package/install-bundled-program", "noteworthy", "process", "at install: runs a program the package carries (.exe, .bat, .ps1)", path);
        if (install && (BundledProgram.IsMatch(plain) || RunsNamedProgram(plain)))
            yield return new PackageFinding("package/install-bundled-program", "noteworthy", "process", "at install: runs a program the package carries (.exe, .bat, .ps1, .sh)", path);
        if (install && CompiledEval().IsMatch(plain))
            yield return new PackageFinding("package/install-compiled-eval", "noteworthy", "dynamic code", "at install: evaluates code compiled from a string (eval(compile(...)))", path);
        // A collector host outside a URL (request options, dns.lookup), at install or beside connections.
        if ((install || hits.Contains("network")) && CollectorHost.IsMatch(plain))
            yield return new PackageFinding("package/collector-host", "noteworthy", "exfiltration", (install ? "at install: " : "") + "contacts a collection endpoint (request catcher, out-of-band test host)", path);
        // An encoded label or host details carry data; a constant lookup
        // counts only at install.
        bool carried = hits.Contains("host details") || hits.Contains("credentials");
        if (DnsName(plain) is { } dns && (dns != "constant" || install))
            yield return dns == "constant"
                ? new PackageFinding("package/dns-send", carried ? "noteworthy" : "review", "exfiltration", "at install: looks up a constant host name", path)
                : new PackageFinding("package/dns-send", dns == "encoded" || carried || install ? "noteworthy" : "review", "exfiltration",
                    (install ? "at install: " : "") + "looks up a host name whose leftmost label is built from values (data sent in the DNS name)", path);
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
        // A detached self-start is ordinary (update checks, daemons); it is
        // noteworthy only in entry code beside network, credentials, host
        // details or transformed code.
        if (!install && LoadedDetached.IsMatch(plain))
            yield return new PackageFinding("package/loaded-detached",
                entry && hits.Overlaps(["network", "credentials", "host details", "transformed code"]) ? "noteworthy" : "review",
                "process", "starts node or a file in its own folder as a background process that outlives the caller", path);
        if (install && XorDecode.IsMatch(plain))
            yield return new PackageFinding("package/install-xor", "noteworthy", "transformed code", "at install: decodes its strings with XOR", path);
        // The package manager links a package's own commands; install code that
        // edits files under the global prefix replaces commands it does not own.
        if (install && ReplacesGlobalCommand(plain))
            yield return new PackageFinding("package/command-replace", "noteworthy", "install script",
                "at install: deletes, links, copies over or writes a command file under the global npm prefix", path);
        if (hits.Contains("network") && InterpreterStdin.IsMatch(plain))
            yield return new PackageFinding("package/stdin-remote-code", "noteworthy", "remote code", "runs code it fetches through an interpreter's standard input", path);
        if (ChatWebhook.IsMatch(plain) && (WebhookSecret.IsMatch(plain) || WalletSecret.IsMatch(plain)))
            yield return new PackageFinding("package/webhook-secrets", "noteworthy", "exfiltration", "sends passwords, keys, tokens or wallet secrets to a chat webhook", path);
        // A beacon at load: host identity or the environment sent from entry code.
        if (entry && hits.Contains("network") && SendsLoadBeacon(plain))
        // A beacon at load: host identity or the environment sent from entry code,
        // or host identity POSTed from a small source file outside test folders.
        if (hits.Contains("network") && (entry && LoadBeacon.IsMatch(plain)
            || plain.Length <= 64 << 10 && !NotLoaded.IsMatch(path) && IdentityPosted(plain)))
            yield return new PackageFinding("package/load-beacon", "noteworthy", "host details", "sends host identity or the environment when loaded", path);
        if (entry && RedirectsWithAddress(path, plain))
            yield return new PackageFinding("package/redirect-entry", "noteworthy", "redirect", "entry code sends the browser to a fixed URL that carries an email address", path);
        if (SelfPublish.IsMatch(plain) && plain.Contains("package.json", StringComparison.Ordinal))
            yield return new PackageFinding("package/self-publish", "noteworthy", "publishing", "rewrites package.json and runs npm publish from its own code", path);
        if (CiConfigWritten(plain) is { } ci)
            yield return new PackageFinding("package/ci-config-write", install ? "noteworthy" : "review", "build step",
                $"{(install ? "at install: " : "")}opens a CI pipeline file for writing: {Clip(ci, 160)}", path);
        // Hook managers and scanners set it on the user's command; only at install is it noteworthy.
        if (GlobalHooksPath.IsMatch(plain))
            yield return new PackageFinding("package/global-hooks-path", install ? "noteworthy" : "review", "persistence",
                $"{(install ? "at install: " : "")}sets a global git hooks path (git config --global core.hooksPath)", path);
        if (install && ShellTokenRead.IsMatch(plain))
            yield return new PackageFinding("package/credential-files", "noteworthy", "credentials", "at install: reads a publish token variable ($NPM_TOKEN, %TWINE_PASSWORD%)", path);
        if (NestedInstall(path, plain, install) is { } nested)
            yield return new PackageFinding("package/nested-install", "noteworthy", "dependency", (install ? "at install: " : "") + nested, path);
        if (ClipboardAddress(plain) is { } swap)
            yield return new PackageFinding("package/clipboard-address", install ? "noteworthy" : "review", "clipboard",
                $"{(install ? "at install: " : "")}reads and writes the clipboard ({swap.Pair}) beside a {swap.Kind} address pattern", path);
        if (NetworkOverride.Match(plain) is { Success: true } hook && !FetchGuard.IsMatch(plain) && WalletTarget(plain) is { } target)
            yield return new PackageFinding("package/network-override", "noteworthy", "exfiltration",
                $"replaces {(hook.Value.Contains("fetch", StringComparison.Ordinal) ? "fetch" : "an XMLHttpRequest method")} beside {target}", path);
    }

    private static readonly HashSet<string> ExecNames = new(StringComparer.Ordinal) { "exec", "eval", "compile", "__import__", "getattr" };

    /// <summary>The builtin a non-ASCII name called outside strings and comments reads as after NFKC; null when none.</summary>
    // Python folds identifiers with NFKC, so a name in mathematical
    // letters calls the builtin.
    private static string? NormalizedExec(string text)
    {
        if (!text.Any(c => c > 0x7F)) return null;
        int n = text.Length;
        for (int i = 0; i < n;)
        {
            char c = text[i];
            if (c == '#')
            {
                while (i < n && text[i] != '\n') i++;
            }
            else if (c is '\'' or '"')
            {
                bool triple = i + 2 < n && text[i + 1] == c && text[i + 2] == c;
                i += triple ? 3 : 1;
                while (i < n && !(triple ? i + 2 < n && text[i] == c && text[i + 1] == c && text[i + 2] == c : text[i] == c || text[i] == '\n'))
                    i += text[i] == '\\' ? 2 : 1;
                i += triple ? 3 : 1;
            }
            else if (IsNameChar(c))
            {
                int start = i;
                bool wide = false;
                while (i < n && IsNameChar(text[i])) wide |= text[i++] > 0x7F;
                int j = i;
                while (j < n && text[j] is ' ' or '\t') j++;
                if (wide && j < n && text[j] == '(')
                {
                    string name;
                    // A lone surrogate does not normalize.
                    try { name = text[start..i].Normalize(System.Text.NormalizationForm.FormKC); }
                    catch (ArgumentException) { continue; }
                    if (ExecNames.Contains(name)) return name;
                }
            }
            else i++;
        }
        return null;
    }

    // Letter numbers and connector punctuation also fold to ASCII name
    // characters.
    private static bool IsNameChar(char c) =>
        c == '_' || char.IsLetterOrDigit(c) || char.IsSurrogate(c) || char.GetUnicodeCategory(c) is
            System.Globalization.UnicodeCategory.LetterNumber or System.Globalization.UnicodeCategory.ConnectorPunctuation
            or System.Globalization.UnicodeCategory.NonSpacingMark or System.Globalization.UnicodeCategory.SpacingCombiningMark;

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

    // The browser's location by its object, or a bare name opening a statement.
    private static readonly Regex LocationAssign = R(@"(?:\b(?:window|document|top|self|parent)\.|(?:^|[;{}\n]\s*))location(?:\.href)?\s*=[^=>]");
    private static readonly Regex UrlLiteral = R(@"['""`]https?://[\w.-]+");
    private const string Address = @"[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}";
    // A quote, or a query or fragment mark; '/' and ':' stay out, so user@host
    // URLs and DSNs do not match.
    private static readonly Regex AddressInUrl = R(@"(?:['""`]#?|[?&#=])" + Address + @"['""`&]");
    private static readonly Regex AddressVariable = R(@"\b([A-Za-z_$][\w$]*)\s*[:=]\s*['""`]" + Address + @"['""`]");
    private static readonly Regex Identifier = R(@"[A-Za-z_$][\w$]*");
    private static readonly Regex BrowserScript = R(@"\.(?:[cm]?js|html?)$");

    /// <summary>True when a script assigns the browser's location a URL literal whose expression carries an email address literal or a variable holding one.</summary>
    private static bool RedirectsWithAddress(string path, string text)
    {
        if (!BrowserScript.IsMatch(path.ToLowerInvariant()) || !text.Contains("location", StringComparison.Ordinal) || !text.Contains('@')) return false;
        HashSet<string>? holders = null;
        foreach (Match m in LocationAssign.Matches(text))
        {
            var start = m.Index + m.Length - 1;
            var end = text.IndexOfAny([';', '\n'], start);
            var expression = text.Substring(start, Math.Min(end < 0 ? text.Length : end, start + 300) - start);
            if (!UrlLiteral.IsMatch(expression)) continue;
            if (AddressInUrl.IsMatch(expression)) return true;
            var known = holders ??= AddressVariable.Matches(text).Select(v => v.Groups[1].Value).ToHashSet(StringComparer.Ordinal);
            if (Identifier.Matches(expression).Any(i => known.Contains(i.Value))) return true;
        }
        return false;
    }

    /// <summary>The first clipboard pair and address kind a file holds together, or null when it lacks either.</summary>
    private static (string Pair, string Kind)? ClipboardAddress(string text)
    {
        if (!text.Contains("clipboard", StringComparison.OrdinalIgnoreCase) && !text.Contains("execCommand", StringComparison.Ordinal)
            && !text.Contains("pyperclip", StringComparison.Ordinal)) return null;
        var pair = ClipboardPairs.FirstOrDefault(p => p.Read.IsMatch(text) && p.Write.IsMatch(text)).Pair;
        var kind = pair == null ? null : AddressShapes.FirstOrDefault(a => a.Shape.IsMatch(text)).Kind;
        return kind == null ? null : (pair!, kind);
    }

    // A global fetch assigned a function, or XMLHttpRequest.prototype.open or
    // send assigned; a bare fetch counts only at column 0 or after a semicolon.
    private static readonly Regex NetworkOverride = R($@"(?:^|\n|;[ \t]*)fetch[ \t]*={Wrapper}"
        + $@"|\b(?:window|globalThis|self|global)\.fetch[ \t]*={Wrapper}"
        + @"|\bXMLHttpRequest(?:\.prototype|\[[ \t]*['""]prototype['""][ \t]*\])"
        + @"(?:\.(?:open|send)\b|\[[ \t]*['""](?:open|send)['""][ \t]*\])[ \t]*=[^=]");

    private const string Wrapper = @"[ \t]*(?:async[ \t]*)?(?:function\b|\([^)\n]{0,80}\)[ \t]*=>|\w+[ \t]*=>)";

    // A polyfill assigns fetch only under a check that it is absent.
    private static readonly Regex FetchGuard = R(@"\bif[ \t]*\([ \t]*!(?:(?:window|globalThis|self|global)\.)?fetch\b");

    /// <summary>A cryptocurrency address pattern or a window.ethereum reference a file holds, named for the finding; null when it holds neither.</summary>
    private static string? WalletTarget(string text) =>
        AddressShapes.FirstOrDefault(a => a.Shape.IsMatch(text)).Kind is { } kind ? $"a {kind} address pattern"
        : text.Contains("window.ethereum", StringComparison.Ordinal) ? "window.ethereum" : null;
    // A package manager install of a named package; group n is the name.
    private const string NamedInstall = @"(?:(?:npm|pnpm)\s+(?:i|install|add)|yarn\s+add|pip3?\s+install)(?:\s+(?:--[\w-]+(?:=[^\s'""`]+)?|-[gDSEUq]))*\s+(?<n>[@\w][\w@./^~=<>-]{0,213})";
    private const string ParentFolder = @"\bcd\s+\.\.(?:[/\\]\.\.)*[/\\]?\s*(?:&&|;)\s*";
    private static readonly Regex ParentInstall = R(ParentFolder + NamedInstall);
    private static readonly Regex OutsideRequire = R(@"\brequire\(\s*['""`](?:\.\./){2,}(?<t>(?:@[\w.-]+/)?[\w.-]+)");
    private static readonly Regex CallInstall = R(@"\b(?:exec|execSync|spawn|spawnSync|system|run|call|Popen|check_call|check_output)\s*\(\s*['""`](?<up>" + ParentFolder + ")?" + NamedInstall);

    /// <summary>What a nested install does: a named install after cd .. in an install script or a process call, or one whose package the file loads from outside its root; else null.</summary>
    private static string? NestedInstall(string path, string text, bool install)
    {
        // Install script commands only; message text in code is not a command.
        if (install && path.Contains("#scripts.", StringComparison.Ordinal) && ParentInstall.Match(text) is { Success: true } script)
            return $"changes to the parent folder and installs '{script.Groups["n"].Value}' with a package manager";
        HashSet<string>? outside = null;
        foreach (Match call in CallInstall.Matches(text))
        {
            var name = call.Groups["n"].Value;
            if (call.Groups["up"].Success) return $"runs a package manager in the parent folder to install '{name}'";
            int at = name.IndexOf('@', 1);
            var bare = (at > 0 ? name[..at] : name).Split('=', '<', '>', '^', '~')[0];
            outside ??= OutsideRequire.Matches(text).Select(m => m.Groups["t"].Value).ToHashSet(StringComparer.Ordinal);
            if (outside.Contains(bare))
                return $"runs a package manager to install '{name}' and loads it from outside the package root";
        }
        return null;
    }

    private static readonly Regex ShellTokenRead = R($@"\$\{{?(?:{PublishTokens})\b|%(?:{PublishTokens})%");

    private const string PublishTokens = "NPM_TOKEN|NODE_AUTH_TOKEN|TWINE_PASSWORD|PYPI_TOKEN|PYPI_API_TOKEN";

    // Reads of the npm and PyPI publish token variables from JavaScript or Python.
    private const string PublishTokenRead = $@"\bprocess\.env(?:\.(?:{PublishTokens})\b|\[\s*['""`](?:{PublishTokens})['""`]\s*\])|\bos\.(?:environ(?:\.get\(|\[)|getenv\()\s*['""](?:{PublishTokens})['""]";

    // A .then callback or a response 'end' handler, up to its body.
    private const string ResponseCallback = @"\.(?:then\s*\(\s*(?:async\s+)?(?:(?:\(\s*[\w{}\s,]*\)|\w+)\s*=>|function\s*\w*\s*\(\s*[\w{}\s,]*\))|on\s*\(\s*['""]end['""]\s*,\s*(?:\(\s*\)\s*=>|function\s*\(\s*\)))";

    private const string Base64Decode = @"Buffer\.from\s*\(\s*\w+\s*,\s*['""]base64['""]";

    private const string RunsDecoded = @"(?:eval|Function)\s*\(\s*(?:atob\s*\(|" + Base64Decode + ")";

    // Stops at the block's first '}'; skips member calls such as client.eval.
    private const string DecodedRunInBlock = @"\s*\{(?:[^}]{0,200}?[^.\w$}])?(?:" + RunsDecoded + @"|\b" + Base64Decode + @"\s*\)(?:[^}]{0,120}?[^.\w$}])?eval\s*\()";

    // Stops at the first ';' or '}', where an expression body ends.
    private const string DecodedRunInExpression = @"(?:[^;}]{0,200}?[^.\w$;}])?(?:" + RunsDecoded + @"|\b" + Base64Decode + @"\s*\)(?:[^;}]{0,120}?[^.\w$;}])?eval\s*\()";

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

    /// <summary>One spawn, fork, execFile or Popen call whose first argument is
    /// node, process.execPath or a path built from __dirname, __filename or
    /// __file__, with a detached option inside the call.</summary>
    private static readonly Regex LoadedDetached = R(@"\b(?:spawn|fork|execFile|Popen)\s*\(\s*(?:['""`]node['""`]|process\.execPath|\[?[^,;\n]{0,120}?(?:__dirname|__filename|__file__))[^;]{0,400}?(?:\bdetached\s*:\s*(?:true|!0)|\bstart_new_session\s*=\s*True|\bDETACHED_PROCESS\b)");
    private static readonly Regex XorDecode = R(@"\bfromCharCode\s*\([^()\n]{0,80}\^|\bchr\s*\([^()\n]{0,60}\^");
    // The global npm prefix: an environment read, a destructured read or the
    // npm command that prints it.
    private static readonly Regex GlobalPrefix = R(@"\bprocess\.env(?:\.(?:npm_config_prefix|PREFIX)\b|\[\s*['""](?:npm_config_prefix|PREFIX)['""]\s*\])|\bnpm\s+(?:prefix|root|bin)\s+-g\b"
        + @"|\{[^{}]{0,80}\bnpm_config_prefix\b[^{}]{0,80}\}\s*=\s*process\.env");
    private static readonly Regex PrefixRename = R(@"\bnpm_config_prefix\s*:\s*(?<v>[A-Za-z_$][\w$]*)");
    private static readonly Regex Declaration = R(@"\b(?:const|let|var)\s+(?<v>[A-Za-z_$][\w$]*)\s*=\s*(?<e>[^;\n]{1,300})");
    private static readonly Regex CommandCall = R(@"(?:\b(?:fs|fsp|promises)\.(?:rm|unlink|symlink|link|rename|copyFile|cp|writeFile)|\b(?:rm|unlink|symlink|link|rename|copyFile|cp|writeFile)Sync)\s*\(\s*(?<a>[^;\n]{1,300})");
    private static readonly Regex CommandSegment = R(@"['""`](?:bin(?:[/\\][\w.-]+)?|[\w.-]+\.(?:cmd|ps1))['""`]");

    /// <summary>True when an fs call deletes, links, copies or writes a path built from the global npm prefix with a bin segment or a .cmd or .ps1 name.</summary>
    private static bool ReplacesGlobalCommand(string text)
    {
        if (!GlobalPrefix.IsMatch(text)) return false;
        var prefixNames = new HashSet<string>(StringComparer.Ordinal) { "npm_config_prefix" };
        foreach (Match m in PrefixRename.Matches(text)) prefixNames.Add(m.Groups["v"].Value);
        bool Prefixed(string code) => GlobalPrefix.IsMatch(code) || Identifier.Matches(code).Any(m => prefixNames.Contains(m.Value));
        // Declarations are read in source order, so a name holding the prefix
        // is known before a later path join uses it.
        var pathNames = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match d in Declaration.Matches(text))
        {
            var e = d.Groups["e"].Value;
            if (CommandSegment.IsMatch(e) && Prefixed(e)) pathNames.Add(d.Groups["v"].Value);
            // Only a direct prefix read names the prefix, so a flag derived from it does not.
            else if (GlobalPrefix.IsMatch(e)) prefixNames.Add(d.Groups["v"].Value);
        }
        foreach (Match c in CommandCall.Matches(text))
        {
            var args = c.Groups["a"].Value;
            if (Identifier.Matches(args).Any(m => pathNames.Contains(m.Value)) || CommandSegment.IsMatch(args) && Prefixed(args)) return true;
        }
        return false;
    }
    private static readonly Regex InterpreterStdin = R(@"\bspawn\s*\(\s*['""](?:node|python3?|sh|bash)['""][\s\S]{0,300}?\.stdin\.(?:write|end)\s*\((?:[^'""`]|\z)");
    private static readonly Regex ChatWebhook = R(@"https?://(?:[\w-]+\.)?discord(?:app)?\.com/api/webhooks/|https?://api\.telegram\.org/bot");
    private static readonly Regex WebhookSecret = R(@"(?i)\b\w*webhook\w*\s*\([^()\n]{0,200}?\b(?:password|passwd|api[_ ]?key|token|secret|cookies?)\b");
    private static readonly Regex WalletSecret = R(@"(?i)\bprivate_?keys?\b|\bmnemonic\b|\bseed_?phrase\b");
    private const string Shell = @"\b(?:spawn|exec|Popen|call|run)\s*\(\s*\[?\s*['""](?:/bin/(?:ba|z)?sh|sh|bash|cmd(?:\.exe)?|powershell(?:\.exe)?)['""]";
    // A socket near a spawned shell or a child piped to it; bounded gaps keep work per start constant, so no match timeout.
    [GeneratedRegex($@"(?:{Socket})[\s\S]{{0,1500}}?(?:{Shell}|\.pipe\(\s*[\w$.]+\.stdin\s*\)[\s\S]{{0,300}}?\.stdout\.pipe\()|(?:{Shell})[\s\S]{{0,1500}}?(?:{Socket})", RegexOptions.CultureInvariant)]
    private static partial Regex ReverseShell();
    private static readonly Regex LoadBeacon = R($@"(?:{HostIdentity})[\s\S]{{0,600}}?(?:{BeaconSecond})|JSON\.stringify\(\s*process\.env\s*\)|json\.dumps\(\s*(?:dict\()?os\.environ");
    private static readonly Regex BeaconSecondRegex = R(BeaconSecond);
    private const string BeaconSecond = HostIdentity + @"|\bos\.homedir\(\)|\bprocess\.cwd\(\)|\bos\.getcwd\(\)|\b__dirname";

    /// <summary>Whether code sends host identity twice in a row, or the environment; bare calls count only for names taken from os.</summary>
    private static bool SendsLoadBeacon(string text)
    {
        if (LoadBeacon.IsMatch(text)) return true;
        var calls = OsHostCalls(text);
        foreach (var end in calls)
        {
            if (calls.Exists(e => e > end && e - end <= 600)) return true;
            if (BeaconSecondRegex.IsMatch(text.AsSpan(end, Math.Min(600, text.Length - end)))) return true;
        }
        return false;
    }

    private static readonly Regex LoginName = R(@"\b(?:os\.(?:userInfo|getlogin)|getpass\.getuser)\(");
    private static readonly Regex HostName = R(@"\b(?:os\.hostname|socket\.gethostname|platform\.node)\(");
    private static readonly Regex EchoRequest = R(@"https?://(?:checkip\.amazonaws\.com|api\d?\.ipify\.org|ifconfig\.me|icanhazip\.com|ipinfo\.io)\b");
    private static readonly Regex OsObject = R(@"\{[^{}]{1,800}\}");
    private static readonly Regex OsField = R(@"\b(?:os|platform|socket|getpass)\.\w+\(");
    private static readonly Regex PostCall = R(@"\b(?:requests|httpx|axios)\.post\s*\(|\bmethod\s*[:=]\s*['""`]POST['""`]");
    // A named host with a letter top-level label, so localhost and
    // loopback addresses do not count.
    private static readonly Regex LiteralUrl = R(@"['""`]https?://[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}\b");
    private static readonly Regex NotLoaded = R(@"(?:^|/)(?:tests?|__tests__|testing|examples?|scripts?|docs?|benchmarks?)/");

    /// <summary>Whether a POST call has a literal URL and host identity near it.</summary>
    private static bool IdentityPosted(string text)
    {
        foreach (var post in PostCall.EnumerateMatches(text))
        {
            int from = Math.Max(0, post.Index - 1500), to = Math.Min(text.Length, post.Index + post.Length + 800);
            var near = text.AsSpan(from, to - from);
            if (!LiteralUrl.IsMatch(near)) continue;
            // Two kinds of identity: login name, host name, public address.
            int kinds = (LoginName.IsMatch(near) ? 1 : 0) + (HostName.IsMatch(near) ? 1 : 0) + (EchoRequest.IsMatch(near) ? 1 : 0);
            if (kinds >= 2) return true;
            // An object of three or more OS fields, one of them the host or user name.
            foreach (var o in OsObject.EnumerateMatches(near))
            {
                var obj = near.Slice(o.Index, o.Length);
                if ((HostName.IsMatch(obj) || LoginName.IsMatch(obj)) && OsField.Count(obj) >= 3) return true;
            }
        }
        return false;
    }
    private static readonly Regex BundledProgram = R(@"\.(?:run|call|Popen|check_call|check_output|system|startfile)\(\s*\[?\s*(?:os\.path\.abspath\(\s*)?['""][^'""\n]*\.(?:exe|bat|cmd|ps1|vbs|scr)['""]|\.(?:run|call|Popen|check_call)\(\s*\[\s*exe_path\b"
        + @"|" + SpawnCall + @"\(\s*" + JoinedProgram);
    private const string SpawnCall = @"\b(?:spawn|spawnSync|execFile|execFileSync|exec|execSync)";
    // A path.join or path.resolve call whose last argument names a .exe or .bin file.
    private const string JoinedProgram = @"(?:require\(\s*['""](?:node:)?path['""]\s*\)|\w+)\.(?:join|resolve)\([^\n;]{0,200}['""](?:[^'""\n]*/)?[\w-][\w.-]*\.(?:exe|bin)['""]\s*\)";
    private static readonly Regex LocalProgram = R(@"\.(?:run|call|Popen|check_call|check_output|system)\(\s*\[?\s*['""]\./([\w-]+|[\w.-]+\.sh)['""]");
    // The conventional build entry points an sdist runs to compile a bundled library.
    private const string BuildEntryPoint = @"configure|autogen\.sh|bootstrap|bootstrap\.sh|gradlew|make";
    private static readonly HashSet<string> BuildEntryPoints = [.. BuildEntryPoint.Replace(@"\.", ".", StringComparison.Ordinal).Split('|')];
    private static readonly Regex BuildEntryPointVariable = R(@"\b(\w+)\s*=\s*os\.path\.join\([^\n;]{0,200}['""](?:" + BuildEntryPoint + @")['""]\s*\)");
    private static readonly Regex JoinedProgramVariable = R(@"\b(\w+)\s*=\s*" + JoinedProgram);
    private static readonly Regex SpawnedVariable = R(SpawnCall + @"\(\s*(\w+)\s*[,)]");
    private static readonly Regex ChmodExecVariable = R(@"\bos\.chmod\(\s*(\w+)\s*,\s*(?:0o?[57][0-7]{2}\b|[\w.]*S_I(?:X\w*|EXEC|RWX[UGO])|\w+\.st_mode\s*\|)");
    private static readonly Regex SubprocessVariable = R(@"\bsubprocess\.(?:run|call|Popen|check_call|check_output)\(\s*\[?\s*(\w+)\s*[,\])]");
    private static readonly Regex ScriptFolder = R(@"\bos\.path\.dirname\(\s*(?:os\.path\.(?:abspath|realpath)\(\s*)?__file__");

    /// <summary>True when code runs a local file other than a build entry point, starts a variable bound to a joined .exe or .bin path, or starts one it made executable beside its own folder.</summary>
    private static bool RunsNamedProgram(string code)
    {
        static HashSet<string> Names(Regex pattern, string text) => pattern.Matches(text).Select(m => m.Groups[1].Value).ToHashSet(StringComparer.Ordinal);
        if (!Names(LocalProgram, code).IsSubsetOf(BuildEntryPoints)) return true;
        if (Names(JoinedProgramVariable, code).Overlaps(Names(SpawnedVariable, code))) return true;
        if (!ScriptFolder.IsMatch(code)) return false;
        var chmodded = Names(ChmodExecVariable, code);
        chmodded.ExceptWith(Names(BuildEntryPointVariable, code));
        return chmodded.Overlaps(Names(SubprocessVariable, code));
    }
    private static readonly Regex FormattedUrl = R(@"['""]https?://[^\s'""]*(?:\{\w*\}|%s|\$\{)");
    // Excludes compile(f.read(), ...), which setup.py uses to read its version module; no match timeout needed.
    [GeneratedRegex(@"\b(?:eval|exec)\s*\(\s*compile\s*\(\s*(?![\w.]*\.read\(|open\()", RegexOptions.CultureInvariant)]
    private static partial Regex CompiledEval();
    private static readonly Regex CollectorHost = R(@"['""`/.@](?:[\w-]+\.)*(?:oast\.(?:fun|me|pro|live|site|online)|interact\.sh|burpcollaborator\.net|oastify\.com|dnslog\.cn|ceye\.io|requestcatcher\.com|pipedream\.net|webhook\.site)['""`/]");
    // A Node dns or Python socket lookup; group a is the rest of the statement.
    private static readonly Regex DnsCall = R(@"\b(?:dns\.(?:promises\.)?(?:lookup|resolve\w*)|socket\.(?:gethostbyname(?:_ex)?|getaddrinfo))\s*\(\s*(?<a>[^\n;]{1,200})");
    // A value label before a literal domain label: a template, an
    // f-string, a join or a format string.
    private static readonly Regex BuiltName = R(@"^`\$\{[^}`\n]+\}[\w-]*\.[\w-]|^f['""]\{[^}'""\n]+\}[\w-]*\.[\w-]|^[\w.()\[\]'""=]+\s*\+\s*['""]\.[\w-]+(?:\.[\w-]+)*\.[A-Za-z][\w-]*['""]|^['""](?:\{\w*\}|%s)[\w-]*(?:\.[\w-]+)+['""]\s*(?:\.format\(|%)");
    private static readonly Regex ConstantName = R(@"^(?:'[\w-]+(?:\.[\w-]+)*\.[A-Za-z][\w-]*'|""[\w-]+(?:\.[\w-]+)*\.[A-Za-z][\w-]*""|`[\w-]+(?:\.[\w-]+)*\.[A-Za-z][\w-]*`)");
    private static readonly Regex LocalName = R(@"\.(?:local|localhost|localdomain|internal)['""`]");
    private static readonly Regex Encoder = R(@"\b(?:b32encode|b64encode|hexlify|Buffer\.from)\b|\.hex\(\)|toString\(\s*['""](?:hex|base64)");
    private static readonly Regex LeadingIdentifier = R(@"^[A-Za-z_$][\w$]*\s*[,)]");

    /// <summary>"encoded" or "built" when a DNS lookup takes a name built from values, "constant" for a constant non-local host name, else null.</summary>
    private static string? DnsName(string text)
    {
        if (!text.Contains("dns.", StringComparison.Ordinal) && !text.Contains("gethostbyname", StringComparison.Ordinal)
            && !text.Contains("getaddrinfo", StringComparison.Ordinal)) return null;
        string? found = null;
        foreach (Match call in DnsCall.Matches(text).Take(20))
        {
            var arg = call.Groups["a"].Value;
            // Calls in comments are usage examples (declarations, docstrings).
            if (InComment(text, call.Index)) continue;
            // A bare name reads through its first assignment in the file.
            if (LeadingIdentifier.Match(arg) is { Success: true } id)
            {
                var name = Regex.Escape(id.Value.TrimEnd(',', ')', ' ', '\t'));
                var assign = Regex.Match(text, $@"(?:^|[^\w$.]){name}\s*=\s*(?<e>[^=\n;][^\n;]{{0,199}})", RegexOptions.NonBacktracking);
                if (!assign.Success) continue;
                arg = assign.Groups["e"].Value.Trim();
            }
            if (BuiltName.IsMatch(arg))
            {
                if (LocalName.IsMatch(arg)) continue;
                if (Encoder.IsMatch(arg)) return "encoded";
                found = "built";
            }
            else if (found is null && ConstantName.Match(arg) is { Success: true } constant && !LocalName.IsMatch(constant.Value))
                found = "constant";
        }
        return found;
    }

    /// <summary>True when index lies on a comment or doctest line, in an open block comment or in a triple-quoted string.</summary>
    private static bool InComment(string text, int index)
    {
        var line = text[(text.LastIndexOf('\n', index) + 1)..index].TrimStart();
        if (line.StartsWith('*') || line.StartsWith('#') || line.StartsWith("//", StringComparison.Ordinal)
            || line.StartsWith("/*", StringComparison.Ordinal) || line.StartsWith(">>>", StringComparison.Ordinal)) return true;
        if (text.LastIndexOf("/*", index, StringComparison.Ordinal) > text.LastIndexOf("*/", index, StringComparison.Ordinal)) return true;
        var before = text.AsSpan(0, index);
        return before.Count("\"\"\"".AsSpan()) % 2 == 1 || before.Count("'''".AsSpan()) % 2 == 1;
    }

    private static readonly Regex SelfPublish = R(@"\bexec(?:Sync)?\s*\(\s*['""`]npm\s+publish\b");

    // Lookaheads read a bounded stretch per start, so no match timeout.
    [GeneratedRegex(@"https?://(?!(?:127|0|10)\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.)(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/", RegexOptions.CultureInvariant)]
    private static partial Regex RawAddressUrl();

    [GeneratedRegex(@"\.connect\(\s*\(\s*['""](?!(?:127|0|10)\.|192\.168\.)(?:\d{1,3}\.){3}\d{1,3}['""]\s*,\s*\d+\s*\)|\b(?:net\.connect|createConnection|\.connect)\(\s*\d+\s*,\s*['""](?!(?:127|0|10)\.|192\.168\.)(?:\d{1,3}\.){3}\d{1,3}['""]", RegexOptions.CultureInvariant)]
    private static partial Regex RawAddressSocket();

    [GeneratedRegex(@"(?i:powershell(?:\.exe)?\b[^\n]{0,120}(?:-w(?:indowstyle)?\s+hidden(?![^\n]{0,40}-Verb\s+runAs)|-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{40}))", RegexOptions.CultureInvariant)]
    private static partial Regex HiddenPowerShell();

    private static readonly Regex HexName = R(@"\b_0x[0-9a-f]{4,6}\b");

    /// <summary>Whether code follows code on one line after spaces and tabs at least 300 columns wide.</summary>
    private static bool CodeAfterBlankRun(string text)
    {
        // A tab counts as 4 columns, the default tab size in common editors.
        int width = 0;
        bool code = false;
        foreach (char c in text)
        {
            if (c is ' ' or '\t')
            {
                if (code) width += c == '\t' ? 4 : 1;
                continue;
            }
            bool printable = c is >= '!' and <= '~';
            if (printable && width >= 300) return true;
            code = printable;
            width = 0;
        }
        return false;
    }

    private static readonly Regex PythonCharCodes = R(@"\b(?:exec|eval)\s*\(\s*['""]{2}\.join\(\s*map\(\s*chr\s*,|\b(?:exec|eval)\s*\(\s*bytes\(\s*\[\s*\d");

    // An array as the argument of eval or Function: direct, through a call
    // or an inline decoder.
    private static readonly Regex ScriptCharCodes = R(@"(?:^|[^.\w$])(?:eval|Function)\s*\(\s*(?:[\w$.]{1,40}\s*\(\s*|\(?\s*(?:function\s*\([\w$,\s]{0,40}\)|\(?[\w$,\s]{0,40}\)?\s*=>)\s*\{?[^\n]{0,400}?\bfromCharCode\b[^\n]{0,400}?\(\s*)?\[");

    /// <summary>True when Python exec or eval runs chr / bytes output, or eval or Function takes an array of 200 integers.</summary>
    private static bool ExecutesCharCodes(string text)
    {
        if (PythonCharCodes.IsMatch(text)) return true;
        foreach (var m in ScriptCharCodes.EnumerateMatches(text))
            if (LeadingIntegers(text.AsSpan(m.Index + m.Length), 200) >= 200) return true;
        return false;
    }

    /// <summary>The count of leading comma-separated integers (decimal up to five digits, hex up to four) in <paramref name="s"/>, stopping at <paramref name="limit"/>.</summary>
    private static int LeadingIntegers(ReadOnlySpan<char> s, int limit)
    {
        int count = 0, i = 0;
        while (count < limit)
        {
            while (i < s.Length && char.IsWhiteSpace(s[i])) i++;
            bool hex = i + 1 < s.Length && s[i] == '0' && s[i + 1] is 'x' or 'X';
            if (hex) i += 2;
            int start = i;
            while (i < s.Length && (hex ? char.IsAsciiHexDigit(s[i]) : char.IsAsciiDigit(s[i]))) i++;
            if (i == start || i - start > (hex ? 4 : 5)) break;
            count++;
            while (i < s.Length && char.IsWhiteSpace(s[i])) i++;
            if (i >= s.Length || s[i] != ',') break;
            i++;
        }
        return count;
    }

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

    private static readonly Regex DecodeCall = R(@"\b(?:inflate(?:Raw)?Sync|unzipSync|gunzipSync|brotliDecompressSync)\s*\(|\b(?:pako|fflate|zlib)\.(?:inflate|ungzip)(?:Raw)?\s*\(|\bjsQR\s*\(");

    // Member calls (client.eval) run a server script, and eval of a string
    // literal is a bundler's module wrapper; neither takes decoded content.
    private static readonly Regex RunCall = R(@"(?:^|[^.\w$])eval\s*\(\s*(?:[^\s'""`]|\z)|\bnew\s+Function\s*\(");

    /// <summary>Whether an inflate or jsQR call and an eval or new Function call lie within 1,500 characters of each other.</summary>
    private static bool RunsDecodedContent(string text)
    {
        // The window stands in for one function body; image data alone
        // (getImageData) is no decode, since drawing code reads it too.
        var runs = new List<int>();
        foreach (var m in RunCall.EnumerateMatches(text)) runs.Add(m.Index);
        if (runs.Count == 0) return false;
        foreach (var m in DecodeCall.EnumerateMatches(text))
        {
            int i = runs.BinarySearch(m.Index);
            if (i < 0) i = ~i;
            if (i < runs.Count && runs[i] - m.Index <= 1500 || i > 0 && m.Index - runs[i - 1] <= 1500) return true;
        }
        return false;
    }

    // Home directory reads are cache and config paths, not identity: only the
    // os receiver form keeps them.
    private const string HostIdentity = @"\bos\.(?:hostname|userInfo|networkInterfaces|getlogin)\(\)|require\(\s*['""](?:node:)?os['""]\s*\)\.(?:hostname|userInfo|networkInterfaces)\(|\bsocket\.gethostname\(\)|\bgetpass\.getuser\(\)|\bplatform\.node\(\)";
    // Identity commands match only in their reading form, a string that ends
    // after the key; setting a name passes a value after it.
    private static readonly Regex HostDetailsCall = R(HostIdentity + @"|\bos\.homedir\(\)|\bwhoami\b|\$\(hostname\)|['""`]git\s+config\s+(?:--global\s+)?(?:--get\s+)?user\.(?:email|name)['""`]|['""`]ssh\s+-T\s+git@[\w.-]+['""`]|\b(?:ip-api\.com|ipinfo\.io|api\.ipify\.org|ifconfig\.me|icanhazip\.com|checkip\.amazonaws\.com)\b");
    private static readonly Regex OsDestructure = R(@"\{(?<names>[\w\s,:$]{1,200})\}\s*=\s*require\(\s*['""](?:node:)?os['""]\s*\)");
    private static readonly Regex OsImport = R(@"\bimport\s*\{(?<names>[\w\s,$]{1,200})\}\s*from\s*['""](?:node:)?os['""]");
    private static readonly Regex BareCall = R(@"(?:^|[^.\w$])(?<name>[\w$]+)\s*\(\s*\)");
    private static readonly HashSet<string> OsHostKeys = new(StringComparer.Ordinal) { "hostname", "userInfo", "networkInterfaces" };

    /// <summary>Whether code reads host or user details: an os call, an identity command, or a name taken from os and called bare.</summary>
    private static bool ReadsHostDetails(string text) => HostDetailsCall.IsMatch(text) || OsHostCalls(text).Count > 0;

    /// <summary>End offsets of bare calls to identity names destructured or imported from os, under their local alias; empty when there are none.</summary>
    private static List<int> OsHostCalls(string text)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var list in new[] { OsDestructure, OsImport })
            for (var m = list.Match(text); m.Success; m = m.NextMatch())
                foreach (var entry in m.Groups["names"].Value.Split(','))
                {
                    // Entries read "key", "key: local" or "key as local".
                    var parts = entry.Split([':', ' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length > 0 && OsHostKeys.Contains(parts[0])) names.Add(parts[^1]);
                }
        var ends = new List<int>();
        if (names.Count == 0) return ends;
        for (var m = BareCall.Match(text); m.Success; m = m.NextMatch())
            if (names.Contains(m.Groups["name"].Value)) ends.Add(m.Index + m.Length);
        return ends;
    }

    private static readonly Regex Downloader = R(@"\b(?:curl|wget|Invoke-WebRequest|iwr)\b");
    private static readonly Regex DownloadSource = R(@"https?://|%\w*URL\w*%|\$\{?\w*URL");
    // A value must follow the key: a bare git config --global core.hooksPath reads it.
    private static readonly Regex GlobalHooksPath = R(@"--global['""]?\s*,?\s*['""]?core\.hooksPath\b['""`]?[ \t]*(?:,\s*)?(?:['""`]?[ \t]*\+|['""`]?[^\s'""`,)+&;|])");
    private static readonly Regex AuthorizedKeysWrite = R(@"\b(?:appendFile|writeFile)(?:Sync)?\s*\([^\n;]{0,200}authorized_keys|>>\s*['""]?[^\s'"";|&]{0,200}authorized_keys|\bopen\s*\([^\n]{0,200}authorized_keys[^\n]{0,40}['""]a");
    private static readonly Regex KeyLiteral = R(@"\bssh-(?:rsa|ed25519)\s+AAAA[A-Za-z0-9+/]{16,}");

    /// <summary>Whether code writes to an authorized_keys path and holds a public key literal.</summary>
    private static bool AddsAuthorizedKey(string text) => AuthorizedKeysWrite.IsMatch(text) && KeyLiteral.IsMatch(text);

    private static readonly Regex SavedTo = R(@"\s-(?:o|O|OutFile)\s+['""]?(?<f>%\w+%|\$?\{\w+\}|\$\w+|[^\s'""]+\.(?:exe|scr|msi|bat|cmd|ps1|sh|bin))['""]?");
    private static readonly Regex Starter = R(@"(?m)(?:^|[\s&;(|'""])(?:start|Start-Process|call|chmod\s+\+x)\b");
    private static readonly Regex BareCommand = R(@"(?:&&|[;|])\s*['""]?(?<c>[^\s'""&;|]+)");
    private static readonly Regex BareRunnable = R(@"(?i:\.(?:bat|cmd|ps1|exe))$|^%\w+%$");

    private static readonly Regex DecodedWriteThenRun = R(@"(?:(?:\.write|\bwrite_bytes)\s*\(\s*(?:base64\.)?(?:urlsafe_)?b64decode\s*\(|\b(?:urlsafe_)?b64decode\s*\([\s\S]{0,300}?(?:\.write|\bwrite_bytes)\s*\()[\s\S]{0,600}?\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\(\s*\[\s*(?:sys\.executable|['""]python(?:w|[\d.]*)(?:\.exe)?['""])\s*,\s*(?:[A-Za-z_]|['""][^'""-])");
    private const string DecodedFileRun = "writes a decoded base64 literal to a file and runs it with Python";

    /// <summary>Whether a base64 literal over 2,000 characters sits beside a b64decode whose output is written to a file and passed as the first argument of a Python process.</summary>
    private static bool WritesDecodedAndRuns(string text) => DecodedWriteThenRun.IsMatch(text) && LongBase64.IsMatch(text);

    /// <summary>Whether a URL download saves to a file that a start, call or chmod +x names within 3,000 characters.</summary>
    /// <summary>Whether a URL download saves to a file that a start, call or chmod +x names within 3,000 characters, or that its line runs as a bare command.</summary>
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
                if (RunsBare(text, saved.Groups["f"].Index, after, lineEnd)) return true;
                for (var start = Starter.Match(text, after); start.Success && start.Index <= after + 3000; start = start.NextMatch())
                {
                    int at = start.Index + start.Length, end = text.IndexOf('\n', at) is var e and >= 0 ? e : text.Length;
                    if (text.AsSpan(at, end - at).Contains(file, StringComparison.Ordinal)) return true;
                }
            }
        }
        return false;
    }

    /// <summary>Whether the whole saved path, a script, a program or a %VAR%, is the first token after a later &amp;&amp;, ; or | on its line.</summary>
    private static bool RunsBare(string text, int path, int after, int lineEnd)
    {
        int stop = path;
        while (stop < lineEnd && !char.IsWhiteSpace(text[stop]) && text[stop] is not ('\'' or '"' or '&' or ';' or '|')) stop++;
        var saved = text.AsSpan(path, stop - path);
        if (!BareRunnable.IsMatch(saved)) return false;
        saved = FromCurrentFolder(saved);
        int scan = Math.Max(after, stop);
        for (var run = BareCommand.Match(text, scan, lineEnd - scan); run.Success; run = run.NextMatch())
            if (FromCurrentFolder(run.Groups["c"].ValueSpan).SequenceEqual(saved)) return true;
        return false;
    }

    /// <summary>The path without a leading .\ or ./, which PowerShell and sh need to run a file in the current folder.</summary>
    private static ReadOnlySpan<char> FromCurrentFolder(ReadOnlySpan<char> path) =>
        path is ['.', '\\' or '/', ..] ? path[1..].TrimStart("\\/") : path;

    /// <summary>Findings in the entry files, then noteworthy findings only in other scripts within a bound;
    /// <paramref name="extension"/> adds the editor extension checks to every file read.</summary>
    internal static IEnumerable<PackageFinding> ScanLoaded(PackageFiles files, string root, IEnumerable<string> entries, CancellationToken ct, bool extension = false)
    {
        var entryFiles = entries.Distinct().ToList();
        foreach (var entry in entryFiles)
            if (files.Text(entry) is { } code)
            {
                foreach (var f in Scan(entry, code, install: false, ct, entry: true))
                    if (f.Level == "noteworthy" || f.Category is "transformed code" or "credentials" or "build step" or "clipboard") yield return f;
                if (extension && Sideload(entry, code) is { } s) yield return s;
            }
        var sources = files.Paths.Where(p => p.StartsWith(root, StringComparison.Ordinal) && LoadedSource.IsMatch(p)
                                             && !p.Contains("node_modules/", StringComparison.Ordinal) && !entryFiles.Contains(p))
            .OrderBy(p => p.Count(c => c == '/')).ThenBy(p => p, StringComparer.Ordinal).ToList();
        files.NotRead.AddRange(sources.Where(p => files.Size(p) > MaxScannedSourceBytes && files.Bytes(p) != null)
            .Select(p => $"{p} (source over {MaxScannedSourceBytes >> 20} MiB)"));
        foreach (var other in Capped(files, [.. sources.Where(p => files.Size(p) <= MaxScannedSourceBytes)]))
            if (files.Text(other) is { } code)
            {
                foreach (var f in Scan(other, code, install: false, ct, entry: Folder(other) == root, peel: false))
                    if (f.Level == "noteworthy") yield return f;
                if (extension && Sideload(other, code) is { } s) yield return s;
            }
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
                               || files.Head(p) is { Length: >= 4 } h && PackageFiles.ImageKind(h) != null)
            .Order(StringComparer.Ordinal).Take(200).ToList();

    private static readonly Regex HookEvent = R(@"['""`](?:UserPromptSubmit|PreToolUse|PostToolUse|SessionStart|SessionEnd|PreCompact|SubagentStop)['""`]");
    private static readonly Regex SettingsFile = R(@"['""`]\.claude['""`]\s*,\s*['""`]settings(?:\.local)?\.json['""`]|\.claude/settings(?:\.local)?\.json");
    private static readonly Regex SettingsWrite = R(@"\b(?:writeFile(?:Sync)?|Bun\.write|Deno\.writeTextFile(?:Sync)?)\s*\(");
    private static readonly Regex TranscriptFolder = R(@"['""`]\.claude['""`]\s*,\s*['""`]projects['""`]|\.claude/projects/");

    /// <summary>One finding per compiled program whose embedded script writes hook events into an agent settings file and reads its transcript folder; empty when none.</summary>
    private static IEnumerable<PackageFinding> AgentSettingsHooks(PackageFiles files) =>
        files.Embedded.Where(e => HookEvent.IsMatch(e.Value) && SettingsFile.IsMatch(e.Value) && SettingsWrite.IsMatch(e.Value) && TranscriptFolder.IsMatch(e.Value))
            .Select(e => new PackageFinding("package/agent-settings-hook", "review", "agent configuration",
                "the script compiled into this program writes hook events to an agent settings file and reads the agent's transcript folder", e.Key));

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
