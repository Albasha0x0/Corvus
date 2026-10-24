using System.ComponentModel;
using System.Text.RegularExpressions;
using Corvus.Services.Web.Scripts;

namespace Corvus.Services.Web.Packages;

/// <param name="Level">noteworthy (worth a close look before installing) or review (expected in some packages, worth a look).</param>
/// <param name="Category">install script, network, process, dynamic code, credentials, host details, exfiltration, persistence, publishing, transformed code, binary, name, permission, activation, remote code, hidden text, agent configuration.</param>
/// <param name="Line">1-based line in <paramref name="Path"/>, when the finding has one.</param>
public sealed record PackageFinding(string Level, string Category, string Detail, string? Path = null, int? Line = null);

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

    [Description("noteworthy, worth reviewing, or none: the strongest finding.")]
    public string Review { get; init; } = "none";

    [Description("Agent configuration: instruction files, Claude Code hooks, MCP servers and tasks run on folder open, at file and line.")]
    public IReadOnlyList<AgentEntry>? Agents { get; init; }

    public IReadOnlyList<PackageFinding> Findings { get; init; } = [];
    public IReadOnlyList<string> Notes { get; init; } = [];
}

/// <summary>
/// Reviews npm, PyPI, VS Code (VSIX) and browser extension packages without installing or running them: install-time
/// scripts and what their code reaches (network, processes, dynamic code, credential files), entry points, permissions,
/// native binaries, transformed code (its layers peeled by the script readers) and names close to popular packages; and
/// the agent configuration a package or repository carries (hidden text in instruction files, hooks, MCP servers, tasks).
/// </summary>
public static partial class PackageReview
{
    public static PackageReport? Review(string path, CancellationToken ct)
    {
        var files = PackageFiles.Open(path, ct);
        if (files == null || files.Count == 0) return null;
        PackageReport? report = files.Crx != null || ManifestJson(files) != null && Root(files, "manifest.json") is { } m && IsExtensionManifest(files, m) ? Extension(files, ct)
            : Root(files, "extension.vsixmanifest") != null || files.Has("extension/package.json") ? Vsix(files, ct)
            : Root(files, "package.json") != null ? Npm(files, ct)
            : files.Paths.Any(p => p.EndsWith(".dist-info/METADATA", StringComparison.Ordinal) || IsSdistFile(p)) ? Python(files, ct)
            : null;
        // A source tree with no package manifest is reviewed for its agent configuration alone.
        var agent = AgentConfig(files, standalone: report == null, ct);
        if (report == null && agent == null) return null;
        report ??= new PackageReport("repository", null, null);
        if (agent != null)
            report = report with { Agents = agent.Entries.Count > 0 ? agent.Entries : null, Findings = [.. report.Findings, .. agent.Findings], Notes = [.. report.Notes, .. agent.Notes] };
        var findings = report.Findings.Distinct().OrderBy(f => f.Level == "noteworthy" ? 0 : 1).ThenBy(f => f.Category, StringComparer.Ordinal).ToList();
        var review = findings.Any(f => f.Level == "noteworthy") ? "noteworthy" : findings.Count > 0 ? "worth reviewing" : "none";
        return report with { Findings = findings, Review = review, Files = files.Count, Notes = [.. files.Notes, .. report.Notes] };
    }

    // an sdist holds one top folder; some archives carry setup.py at their root
    private static bool IsSdistFile(string p) => Regex.IsMatch(p, @"^[^/]+/(setup\.py|pyproject\.toml|PKG-INFO|setup\.cfg)$|^(setup\.py|PKG-INFO)$");

    /// <summary>The shallowest path ending in <paramref name="name"/> (a package's root folder may be named anything).</summary>
    internal static string? Root(PackageFiles files, string name) =>
        files.Paths.Where(p => p == name || p.EndsWith("/" + name, StringComparison.Ordinal))
            .Where(p => !p.Contains("node_modules/", StringComparison.Ordinal))
            .OrderBy(p => p.Count(c => c == '/')).ThenBy(p => p, StringComparer.Ordinal).FirstOrDefault();

    private static string? ManifestJson(PackageFiles files) => Root(files, "manifest.json");

    private static string Folder(string path) => path.Contains('/') ? path[..(path.LastIndexOf('/') + 1)] : "";

    // --- code rules ---

    private sealed record Rule(string Category, string Level, Func<string, bool> IsMatch, string What)
    {
        public Rule(string category, string level, Regex pattern, string what) : this(category, level, pattern.IsMatch, what) { }
    }

    /// <summary>A rule level: noteworthy at install or beside credentials, host details, processes or decoded code; else review.</summary>
    private const string Paired = "paired";

    /// <summary>A rule level: noteworthy in a hand-sized file, review in a bundle (bundles encode their own endpoints).</summary>
    private const string Small = "small";

    // Rules run over whole files, bundles included: NonBacktracking matches in
    // linear time, so they take no match timeout. Patterns that need lookarounds
    // are generated regexes with bounded work per start, or code.
    private static Regex R(string pattern) => new(pattern, RegexOptions.NonBacktracking | RegexOptions.CultureInvariant);

    /// <summary>What code reaches, by pattern: each rule names what it found. Levels are raised by the install-time context.</summary>
    private static readonly Rule[] CodeRules =
    [
        new("process", "review", R(@"\bchild_process\b|\bexecSync\s*\(|\bspawnSync?\s*\(|\bexecFile(?:Sync)?\s*\("), "starts processes (child_process)"),
        new("process", "review", R(@"\bsubprocess\.(?:Popen|run|call|check_output|check_call)\b|\bos\.(?:system|popen|exec[lv]p?e?)\s*\(|\bpty\.spawn\b"), "starts processes (subprocess / os.system)"),
        new("network", "review", R(@"require\(\s*['""](?:node:)?(?:https?|net|dns|dgram|tls)['""]\s*\)|\bfetch\s*\(\s*['""`]https?:|\bXMLHttpRequest\b|\bnew\s+WebSocket\s*\(|\bhttps?\.(?:request|get)\s*\(|require\(\s*['""](?:axios|node-fetch|got|undici)['""]\s*\)|\bawait\s+fetch\s*\(|\baxios\.(?:get|post|request)\s*\("), "opens network connections"),
        new("network", "review", R(@"\b(?:urllib\.request|urllib2|requests\.(?:get|post|put)|http\.client|socket\.socket|urlopen)\b"), "opens network connections (Python)"),
        new("network", "review", R(@"\b(?:curl|wget)\s+(?:-[\w-]+\s+)*['""]?https?://|\bInvoke-WebRequest\b|\biwr\s+https?:|\bbitsadmin\b|\bcertutil\s+-urlcache"), "downloads with a command-line tool"),
        new("dynamic code", "review", R(@"\beval\s*\((?:[^'""`]|\z)|\bnew\s+Function\s*\(|\bvm\.runIn(?:This|New)Context\b"), "evaluates code built at run time (eval / Function)"),
        new("dynamic code", "noteworthy", R(@"\bexec\s*\(\s*(?:base64\.\w*decode|zlib\.decompress|marshal\.loads|codecs\.decode|bytes\.fromhex|__import__\(\s*['""](?:base64|zlib|marshal|codecs))|\bexec\s*\(\s*['""][^'""]*['""]\s*\.decode\(\s*['""](?:base64|hex|rot13|rot_13)|\bexec\s*\([^\n]{0,300}?\b(?:b64decode|b32decode|b85decode|a85decode|decompress|marshal\.loads|unhexlify|fromhex)\s*\("), "executes decoded code (exec of base64 / zlib / marshal)"),
        new("dynamic code", "noteworthy", R(@"\b(?:exec|eval)\s*\([^\n]{0,40}?\w*urlopen\s*\(|\b(?:exec|eval)\s*\(\s*requests\.get\s*\("), "executes code it downloads (exec of urlopen / requests)"),
        new("dynamic code", "noteworthy", R(@"\beval\s*\(\s*\w+\.(?:data|body|responseText)\b[\w.]*\s*\)|\bnew\s+Function\s*\(\s*['""]require['""](?:\s*,\s*['""]\w+['""])*\s*,\s*[\w.]+\s*\)"), "runs code from a response (eval of response data, a Function given require)"),
        new("process", "noteworthy", R(@"https?://(?:dl\.dropbox(?:usercontent)?\.com|cdn\.discordapp\.com/attachments|files\.catbox\.moe|transfer\.sh|github\.com/[\w.-]+/[\w.-]+/raw)/[^\s'""]*?\.(?:exe|sh|bat|cmd|ps1|vbs|scr|msi)\b"), "downloads a program from a file-sharing host"),
        new("process", "noteworthy", R(@"\bcurl(?:\.exe)?\s+[^\n]{0,60}?https?://[^\s'""]+\.(?:exe|scr|msi)\b|\b(?:curl|wget)\b[^\n]{0,200}?&&\s*chmod\s+\+x|\burlretrieve\s*\([\s\S]{0,600}?(?:\bPopen\s*\(|\bos\.(?:system|startfile)\s*\(|\bchmod\s*\()|\[\s*['""]node['""]\s*,\s*['""]-e['""]\s*,\s*\w+\.stdout"), "downloads a program or script and runs it"),
        new("process", "noteworthy", DownloadsAndStarts, "downloads a program to a file and starts it"),
        new("process", "noteworthy", R(@"\b(?:os\.system|os\.popen|subprocess\.(?:Popen|run|call|check_output|check_call))\s*\(\s*\w*(?:b64d\w*|b64decode|decode|unhexlify|fromhex)\s*\(|(?:^|[^.\w$])(?:exec|execSync)\s*\(\s*(?:atob|Buffer\.from)\s*\("), "runs a decoded command"),
        new("host details", "noteworthy", R(@"(?:^|[^.\w$])(?:exec|execSync|spawnSync|check_output|getoutput|popen|system)\s*\(\s*['""`](?:net\s+user|net\s+localgroup|whoami\s+/(?:priv|all|groups)|cat\s+/etc/passwd)\b"), "runs account and privilege listing commands"),
        new("credentials", "noteworthy", R(@"\.npmrc\b|[/\\]\.ssh[/\\]|\bid_rsa\b|\.aws[/\\]credentials|\.git-credentials|\.bash_history|/etc/(?:shadow|passwd)\b|\bLogin Data\b|Local Storage[/\\]+leveldb|\bwallet\.dat\b|\bdiscord(?:app)?\b.{0,40}\btoken|\bkeychain-db\b|\bbrowser_cookie3\b"), "reads credential files (npmrc, ssh keys, cloud or browser stores)"),
        new("credentials", "review", R(@"JSON\.stringify\(\s*process\.env\s*\)|Object\.(?:keys|entries|assign)\(\s*(?:\{\}\s*,\s*)?process\.env\s*\)|json\.dumps\(\s*(?:dict\()?os\.environ|dict\(\s*os\.environ\s*\)|os\.environ\.copy\(\)"), "collects all environment variables"),
        new("host details", "review", R(@"\bos\.(?:hostname|userInfo|networkInterfaces|homedir)\(\)|\bsocket\.gethostname\(\)|\bgetpass\.getuser\(\)|\bplatform\.node\(\)|\bwhoami\b|\$\(hostname\)|\b(?:ip-api\.com|ipinfo\.io|api\.ipify\.org|ifconfig\.me|icanhazip\.com|checkip\.amazonaws\.com)\b"), "reads host and user details"),
        // URLs only: a list of suffixes (a public suffix table) names these domains without sending anything to them
        new("exfiltration", "noteworthy", R(@"https?://pastebin\.com/raw|https?://[\w.-]+\.ngrok(?:-free)?\.(?:io|app|dev)\b|https?://[\w.-]+\.(?:oast\.(?:fun|me|pro|live|site|online)|interact\.sh|burpcollaborator\.net|oastify\.com|beeceptor\.com|dnslog\.cn|ceye\.io|requestcatcher\.com)\b|https?://(?:[\w-]+\.)*(?:requestbin\.(?:com|net)|pipedream\.net|webhook\.site)\b"), "sends to a collection endpoint (paste site, tunnel, request catcher)"),
        // chat bots and raw addresses have ordinary uses (notification integrations, documentation): noteworthy beside other behaviour
        new("exfiltration", Paired, R(@"https?://(?:[\w-]+\.)?discord(?:app)?\.com/api/webhooks|https?://api\.telegram\.org/bot"), "sends to a chat webhook (Discord, Telegram)"),
        new("exfiltration", Paired, RawAddressUrl(), "sends to a raw address"),
        new("exfiltration", "noteworthy", RawAddressSocket(), "opens a socket to a raw address"),
        new("process", "noteworthy", R(@"bash\s+-i\s*>&\s*/dev/tcp/|/dev/tcp/[\w.-]+/\d+|\bnc(?:at)?\s+(?:-\w+\s+)*-e\s+/bin/|\bos\.dup2\(\s*\w+\.fileno\(\)|\bpty\.spawn\(\s*['""]/bin/(?:ba)?sh"), "hands a shell to a network connection (reverse shell)"),
        new("process", "noteworthy", R(@"(?:curl|wget)\b[^\n|;]{0,300}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\bsh\s+-c\s+['""]?\$\((?:curl|wget)\b|(?i:\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b[^\n]{0,300}(?:\|\s*iex\b|Invoke-Expression))"), "runs a downloaded script (download piped to a shell)"),
        new("process", "noteworthy", HiddenPowerShell(), "runs a hidden or encoded PowerShell command"),
        new("persistence", "noteworthy", R(@"Start Menu['""\\/, ]+Programs['""\\/, ]+Startup|CurrentVersion\\+Run\b|\bcrontab\s+-|/etc/cron\.|Library/LaunchAgents|\.config/autostart|\.config/systemd/user"), "writes to a location that starts programs at logon"),
        new("transformed code", "noteworthy", StringArrayNames, "obfuscator.io-style transformed code"),
        new("transformed code", "noteworthy", R(@"\b(?:eval|exec|compile|getattr|__import__)\s*\(\s*['""](?:\\(?:x[0-9a-fA-F]{2}|[0-7]{3})){4,}['""]"), "calls functions named by escaped strings"),
        new("transformed code", "noteworthy", R(@"\beval\s*\(\s*(?:atob|unescape|Buffer\.from|String\.fromCharCode|function\s*\(p,a,c,k,e,[dr]\))"), "evaluates decoded code"),
        new("transformed code", "review", R(@"['""][A-Za-z0-9+/]{2000,}={0,2}['""]"), "a base64 literal over 2,000 characters"),
        new("transformed code", Small, R(@"['""`](?:aHR0cHM6Ly|aHR0cDovL|68747470733a2f2f|687474703a2f2f)[A-Za-z0-9+/=]{8,}['""`]"), "a URL hidden in base64 or hex"),
        new("transformed code", "noteworthy", R(@"\b(?:exec|eval)\s*\(\s*['""]{2}\.join\(\s*map\(\s*chr\s*,|\b(?:exec|eval)\s*\(\s*bytes\(\s*\[\s*\d"), "executes code built from character codes"),
        new("transformed code", "noteworthy", R(@"\(https://pyobfuscate\.com\)|\bimport\s+(?:marshal|zlib|base64)\s+as\s+_{3,}"), "pyobfuscate-style transformed code"),
        new("transformed code", "noteworthy", R(@"[!-~][ \t]{300,}[!-~]"), "code placed after hundreds of spaces on one line (out of view in an editor)"),
    ];

    /// <summary>
    /// Findings for one file's text; <paramref name="install"/> marks code the package manager runs at install time,
    /// <paramref name="entry"/> the file a program loads first; <paramref name="peel"/> reads transformed code through its layers.
    /// </summary>
    internal static IEnumerable<PackageFinding> Scan(string path, string text, bool install, CancellationToken ct, bool entry = false, bool peel = true)
    {
        var plain = text;
        var language = ScriptReader.Detect(path, text);
        // transformed scripts: read through their layers so the rules see the plain text
        if (peel && language != null && text.Length <= 4 << 20 && Transformed.IsMatch(text.Length > 200_000 ? text[..200_000] : text))
        {
            var reading = ScriptReader.Read(text, language, ct, milliseconds: ScriptBudget.OverviewMilliseconds);
            // decoded layers and obfuscator machinery, not ordinary eval or object-of-functions code
            bool transformed = reading.Recovered.Any(r => r is "obfuscator.io string array" or "control-flow flattening")
                               || reading.Layers.Any(l => l.Via.Contains(" of ", StringComparison.Ordinal) || l.Via.Contains("EncodedCommand", StringComparison.Ordinal));
            if (transformed)
            {
                plain = text + "\n" + reading.Plain;
                yield return new PackageFinding(install ? "noteworthy" : "review", "transformed code",
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
            if (!install && rule.Category == "credentials") level = "review"; // tools read these paths for their own work; at install they are a reason to look
            yield return new PackageFinding(level, rule.Category, (install ? "at install: " : "") + rule.What, path);
        }
        if (install && BundledProgram.IsMatch(plain))
            yield return new PackageFinding("noteworthy", "process", "at install: runs a program the package carries (.exe, .bat, .ps1)", path);
        if (install && CompiledEval().IsMatch(plain))
            yield return new PackageFinding("noteworthy", "dynamic code", "at install: evaluates code compiled from a string (eval(compile(...)))", path);
        // a collector's host name outside a URL (https.request options, dns.lookup, HTTPSConnection), at install or beside connections
        if ((install || hits.Contains("network")) && CollectorHost.IsMatch(plain))
            yield return new PackageFinding("noteworthy", "exfiltration", (install ? "at install: " : "") + "contacts a collection endpoint (request catcher, out-of-band test host)", path);
        // install-time code that reaches the network (or builds a URL from values) and collects host details or secrets, or runs decoded code
        var with = hits.Where(h => h is "credentials" or "host details" or "transformed code").ToList();
        if (install && (hits.Contains("network") || with.Contains("host details") && FormattedUrl.IsMatch(plain))
            && (with.Count > 0 || plain.Contains("exec(", StringComparison.Ordinal) && hits.Contains("dynamic code")))
            yield return new PackageFinding("noteworthy", "install script", $"install-time code reaches the network and {(with.Count > 0 ? string.Join(", ", with) : "runs decoded code")}", path);
        else if (install && hits.Contains("network") && Launch.IsMatch(plain))
            yield return new PackageFinding("noteworthy", "install script", "install-time code reaches the network and launches a shell or a background process", path);
        if (ReverseShell().IsMatch(plain))
            yield return new PackageFinding("noteworthy", "process", "pipes a socket into a spawned shell (reverse shell)", path);
        if (install && Detached.IsMatch(plain))
            yield return new PackageFinding("noteworthy", "process", "at install: starts a background process that outlives the install", path);
        if (install && XorDecode.IsMatch(plain))
            yield return new PackageFinding("noteworthy", "transformed code", "at install: decodes its strings with XOR", path);
        if (hits.Contains("network") && InterpreterStdin.IsMatch(plain))
            yield return new PackageFinding("noteworthy", "remote code", "runs code it fetches through an interpreter's standard input", path);
        if (ChatWebhook.IsMatch(plain) && (WebhookSecret.IsMatch(plain) || WalletSecret.IsMatch(plain)))
            yield return new PackageFinding("noteworthy", "exfiltration", "sends passwords, keys, tokens or wallet secrets to a chat webhook", path);
        // a beacon at load: host identity or every environment variable sent from the code a program loads
        if (entry && hits.Contains("network") && LoadBeacon.IsMatch(plain))
            yield return new PackageFinding("noteworthy", "host details", "sends host identity or the environment when loaded", path);
        if (SelfPublish.IsMatch(plain) && plain.Contains("package.json", StringComparison.Ordinal))
            yield return new PackageFinding("noteworthy", "publishing", "rewrites package.json and runs npm publish from its own code", path);
    }

    // a binary installer runs its own executable; these start a shell or outlive the installer
    private static readonly Regex Launch = R(@"\bdetached\s*:\s*true|\.unref\(\)|\b(?:spawn|exec|execSync|execFile)\s*\(\s*['""`](?:cmd(?:\.exe)?|powershell(?:\.exe)?|/bin/(?:ba)?sh|sh|bash|start)\b|\bshell\s*=\s*True|\bos\.(?:system|startfile|popen)\s*\(|\bsubprocess\.Popen\s*\(");
    private const string Socket = @"\bnew\s+net\.Socket\b|\bnet\.(?:connect|createConnection)\s*\(|\bsocket\.socket\s*\(";
    private static readonly Regex Detached = R(@"\bdetached\s*:\s*(?:true|!0)|\bstart_new_session\s*=\s*True|\bDETACHED_PROCESS\b|\bnohup\s");
    private static readonly Regex XorDecode = R(@"\bfromCharCode\s*\([^()\n]{0,80}\^|\bchr\s*\([^()\n]{0,60}\^");
    private static readonly Regex InterpreterStdin = R(@"\bspawn\s*\(\s*['""](?:node|python3?|sh|bash)['""][\s\S]{0,300}?\.stdin\.(?:write|end)\s*\((?:[^'""`]|\z)");
    private static readonly Regex ChatWebhook = R(@"https?://(?:[\w-]+\.)?discord(?:app)?\.com/api/webhooks/|https?://api\.telegram\.org/bot");
    private static readonly Regex WebhookSecret = R(@"(?i)\b\w*webhook\w*\s*\([^()\n]{0,200}?\b(?:password|passwd|api[_ ]?key|token|secret|cookies?)\b");
    private static readonly Regex WalletSecret = R(@"(?i)\bprivate_?keys?\b|\bmnemonic\b|\bseed_?phrase\b");
    private const string Shell = @"\b(?:spawn|exec|Popen|call|run)\s*\(\s*\[?\s*['""](?:/bin/(?:ba|z)?sh|sh|bash|cmd(?:\.exe)?|powershell(?:\.exe)?)['""]";
    // a socket near a spawned shell, or near a child whose stdin and stdout it is piped to (the shell named by a variable); bundles hold both apart
    // Bounded gaps keep the work per start constant, so no match timeout.
    [GeneratedRegex($@"(?:{Socket})[\s\S]{{0,1500}}?(?:{Shell}|\.pipe\(\s*[\w$.]+\.stdin\s*\)[\s\S]{{0,300}}?\.stdout\.pipe\()|(?:{Shell})[\s\S]{{0,1500}}?(?:{Socket})", RegexOptions.CultureInvariant)]
    private static partial Regex ReverseShell();
    private static readonly Regex LoadBeacon = R(@"\b(?:os\.(?:hostname|userInfo|networkInterfaces)\(\)|socket\.gethostname\(\)|getpass\.getuser\(\)|platform\.node\(\))[\s\S]{0,600}?\b(?:os\.(?:hostname|userInfo|networkInterfaces|homedir)\(\)|socket\.gethostname\(\)|getpass\.getuser\(\)|platform\.node\(\)|process\.cwd\(\)|os\.getcwd\(\)|__dirname)|JSON\.stringify\(\s*process\.env\s*\)|json\.dumps\(\s*(?:dict\()?os\.environ");
    private static readonly Regex BundledProgram = R(@"\.(?:run|call|Popen|check_call|check_output|system|startfile)\(\s*\[?\s*(?:os\.path\.abspath\(\s*)?['""][^'""\n]*\.(?:exe|bat|cmd|ps1|vbs|scr)['""]|\.(?:run|call|Popen|check_call)\(\s*\[\s*exe_path\b");
    private static readonly Regex FormattedUrl = R(@"['""]https?://[^\s'""]*(?:\{\w*\}|%s|\$\{)");
    // not compile(f.read(), ...): setup.py files read their version module that way
    // The lookahead reads one name per start, so no match timeout.
    [GeneratedRegex(@"\b(?:eval|exec)\s*\(\s*compile\s*\(\s*(?![\w.]*\.read\(|open\()", RegexOptions.CultureInvariant)]
    private static partial Regex CompiledEval();
    private static readonly Regex CollectorHost = R(@"['""`/.@](?:[\w-]+\.)*(?:oast\.(?:fun|me|pro|live|site|online)|interact\.sh|burpcollaborator\.net|oastify\.com|dnslog\.cn|ceye\.io|requestcatcher\.com|pipedream\.net|webhook\.site)['""`/]");
    private static readonly Regex SelfPublish = R(@"\bexec(?:Sync)?\s*\(\s*['""`]npm\s+publish\b");

    // Rules that need a lookahead to exclude private addresses or an elevated
    // start read a bounded stretch per start, so no match timeout.
    [GeneratedRegex(@"https?://(?!(?:127|0|10)\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.)(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/", RegexOptions.CultureInvariant)]
    private static partial Regex RawAddressUrl();

    [GeneratedRegex(@"\.connect\(\s*\(\s*['""](?!(?:127|0|10)\.|192\.168\.)(?:\d{1,3}\.){3}\d{1,3}['""]\s*,\s*\d+\s*\)|\b(?:net\.connect|createConnection|\.connect)\(\s*\d+\s*,\s*['""](?!(?:127|0|10)\.|192\.168\.)(?:\d{1,3}\.){3}\d{1,3}['""]", RegexOptions.CultureInvariant)]
    private static partial Regex RawAddressSocket();

    [GeneratedRegex(@"(?i:powershell(?:\.exe)?\b[^\n]{0,120}(?:-w(?:indowstyle)?\s+hidden(?![^\n]{0,40}-Verb\s+runAs)|-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{40}))", RegexOptions.CultureInvariant)]
    private static partial Regex HiddenPowerShell();

    private static readonly Regex HexName = R(@"\b_0x[0-9a-f]{4,6}\b");

    /// <summary>
    /// Whether nine obfuscator.io names (_0x1a2b) follow each other on one line, each within 400 characters of the
    /// last.
    /// </summary>
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

    /// <summary>
    /// Whether a download command on a line naming a URL saves to a file (-o, -O, -OutFile) that a start, call or
    /// chmod +x line names within the next 3,000 characters.
    /// </summary>
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

    /// <summary>
    /// Code a package runs when loaded: the entry files in full (noteworthy findings, transformed code and credential
    /// reads), then its other script and shell files within a bound, noteworthy findings only.
    /// </summary>
    internal static IEnumerable<PackageFinding> ScanLoaded(PackageFiles files, string root, IEnumerable<string> entries, CancellationToken ct)
    {
        var entryFiles = entries.Distinct().ToList();
        foreach (var entry in entryFiles)
            if (files.Text(entry) is { } code)
                foreach (var f in Scan(entry, code, install: false, ct, entry: true))
                    if (f.Level == "noteworthy" || f.Category is "transformed code" or "credentials") yield return f;
        var others = files.Paths.Where(p => p.StartsWith(root, StringComparison.Ordinal) && LoadedSource.IsMatch(p)
                                            && !p.Contains("node_modules/", StringComparison.Ordinal) && !entryFiles.Contains(p) && files.Size(p) <= 16 << 20)
            .OrderBy(p => p.Count(c => c == '/')).ThenBy(p => p, StringComparer.Ordinal).Take(MaxScannedSources);
        foreach (var other in others)
            if (files.Text(other) is { } code)
                foreach (var f in Scan(other, code, install: false, ct, entry: Folder(other) == root, peel: false))
                    if (f.Level == "noteworthy") yield return f;
    }

    private static readonly Regex LoadedSource = R(@"\.(?:c|m)?js$|\.(?:bat|cmd|ps1|sh)$");

    /// <summary>Signs of a transformation layer worth reading through: string arrays, eval / exec of decoded text, packers, encoded commands.</summary>
    private static readonly Regex Transformed = R(@"\b_0x[0-9a-f]{4,6}\b.{0,200}\b_0x[0-9a-f]{4,6}\b|\beval\s*\(\s*(?:atob|unescape|Buffer\.from|String\.fromCharCode|decodeURIComponent|function\s*\(p,a,c,k)|\bFunction\s*\(\s*(?:atob|unescape|String\.fromCharCode)|(?i:\b(?:iex|invoke-expression)\b|-enc(?:odedcommand)?\s+[A-Za-z0-9+/]{40})|\bExecute(?:Global)?\s*\(?\s*(?:Chr|StrReverse)");

    /// <summary>Native and executable files a package carries.</summary>
    internal static List<string> Binaries(PackageFiles files) =>
        files.Paths.Where(p => Regex.IsMatch(p, @"\.(node|so|dylib|dll|exe|pyd|wasm|jar|bin|msi|scr|com)$", RegexOptions.IgnoreCase)
                               || files.Bytes(p) is { Length: >= 4 } b && (b[0] == 'M' && b[1] == 'Z' || b[0] == 0x7F && b[1] == 'E' && b[2] == 'L' && b[3] == 'F'))
            .Order(StringComparer.Ordinal).Take(200).ToList();

    // --- names close to popular packages ---

    /// <summary>A popular name that <paramref name="name"/> is one or two edits (or a separator) away from, else null.</summary>
    internal static string? CloseTo(string name, IReadOnlyCollection<string> popular)
    {
        var bare = Normalize(name);
        if (popular.Contains(name, StringComparer.OrdinalIgnoreCase)) return null;
        foreach (var p in popular)
        {
            // a scope is owned by its publisher: @swc/core is no copy of cors
            if (name.StartsWith('@') && !p.StartsWith('@')) continue;
            var q = Normalize(p);
            if (q == bare) return p; // separators or case only
            if (Math.Abs(q.Length - bare.Length) > 2 || q.Length < 4) continue;
            int d = Distance(bare, q);
            if (d == 1 || d == 2 && q.Length >= 8) return p;
        }
        return null;
    }

    private static string Normalize(string name)
    {
        // the scope stays: @swc/core and @babel/core are different names
        return Regex.Replace(name.ToLowerInvariant(), @"[-_.@/]", "");
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
}
