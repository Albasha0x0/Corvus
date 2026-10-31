namespace Corvus.Services.Analysis;

/// <summary>The rule table every review path emits from, the renamed ids a baseline reads, and the maps from rule-pack vocabularies.</summary>
// Noteworthy needs an exact list match, or code that runs without asking
// combined with hidden, decoded or remote content; one heuristic alone is review.
public static class FindingRules
{
    private const string AtInstall = "runs at install, without asking";
    private const string RunsDecoded = "code that runs combined with content it decodes";
    private const string RunsRemote = "code that runs combined with code or a program it downloads";
    private const string RunsHidden = "code that runs combined with hidden or encoded text";

    private static FindingRule N(string id, string noteworthy, string reason) => new(id, FindingLevel.Noteworthy, noteworthy, reason);
    private static FindingRule R(string id, string reason) => new(id, FindingLevel.Review, null, reason);
    private static FindingRule I(string id, string reason) => new(id, FindingLevel.Info, null, reason);

    private static readonly FindingRule[] Rows =
    [
        // Package code rules.
        R("package/child-process", "starts processes (child_process)"),
        R("package/python-process", "starts processes (subprocess, os.system)"),
        R("package/network", "opens network connections"),
        R("package/python-network", "opens network connections (Python)"),
        R("package/download-tool", "downloads with a command-line tool"),
        R("package/eval", "evaluates code built at run time"),
        N("package/exec-decoded", RunsDecoded, "executes decoded code (exec of base64, zlib, marshal)"),
        N("package/exec-download", RunsRemote, "executes code it downloads"),
        N("package/eval-response", RunsRemote, "runs code from a response"),
        N("package/file-host-program", "exact list: file-sharing hosts serving a program", "downloads a program from a file-sharing host"),
        N("package/download-and-run", RunsRemote, "downloads a program or script and runs it"),
        N("package/download-and-start", RunsRemote, "downloads a program to a file and starts it"),
        N("package/decoded-file-run", RunsDecoded, "writes a decoded base64 literal to a file and runs it with Python"),
        N("package/decoded-command", RunsDecoded, "runs a decoded command"),
        N("package/account-listing", "exact list: account and privilege listing commands", "runs account and privilege listing commands"),
        N("package/credential-files", AtInstall + ", with an exact list of credential paths and publish token variables", "reads credential files or publish tokens"),
        R("package/environment-dump", "collects all environment variables"),
        R("package/host-details", "reads host and user details"),
        N("package/collection-url", "exact list: paste sites, tunnels and request catchers", "sends to a collection endpoint"),
        N("package/chat-webhook", AtInstall + ", or beside credentials, host details, processes or decoded code", "sends to a chat webhook"),
        N("package/raw-address-url", AtInstall + ", or beside credentials, host details, processes or decoded code", "sends to a raw address"),
        N("package/raw-address-socket", "exact form: a socket opened to a literal address", "opens a socket to a raw address"),
        N("package/reverse-shell", "exact list: reverse shell forms", "hands a shell to a network connection"),
        N("package/download-to-shell", RunsRemote, "runs a downloaded script through a shell"),
        N("package/hidden-powershell", RunsHidden, "runs a hidden or encoded PowerShell command"),
        N("package/logon-start", "exact list: locations that start programs at logon", "writes to a logon start location"),
        N("package/access-persistence", "exact form: a write to an authorized_keys path in a file holding a public key literal", "appends a public key to authorized_keys"),
        N("package/global-hooks-path", AtInstall + ", setting git config --global core.hooksPath to a value", "sets a global git hooks path"),
        N("package/shell-startup", AtInstall + ", or beside network, process or decoded code findings", "writes a shell startup file in the home folder"),
        N("package/string-array", "exact form: obfuscator.io string array names or rotation loop, or a Function body literal of escapes", "obfuscator.io-style transformed code"),
        N("package/escaped-call", RunsHidden, "calls functions named by escaped strings"),
        N("package/eval-decoded", RunsDecoded, "evaluates decoded code"),
        N("package/eval-inflated", RunsDecoded + ": inflate or jsQR output within 1,500 characters of eval or new Function, in a file of at most 64 KiB", "evaluates inflated or image-decoded content"),
        R("package/long-base64", "a base64 literal over 2,000 characters"),
        R("package/comment-filler", "a code file over 32 MiB padded with NUL bytes or archive data inside /* */ comments"),
        N("package/hidden-url", "in a file of at most 64 KiB (bundles encode their own endpoints)", "a URL hidden in base64 or hex"),
        N("package/exec-char-codes", RunsDecoded, "executes code built from character codes"),
        N("package/pyobfuscate", "exact list: pyobfuscate markers", "pyobfuscate-style transformed code"),
        N("package/space-run", "exact form: code after spaces and tabs 300 or more columns wide on one line (a tab is 4)", "code placed out of view in an editor"),
        N("package/normalized-exec", "exact form: a non-ASCII name called outside strings and comments that NFKC folds to exec, eval, compile, __import__ or getattr", "calls a builtin under a name that normalizes to it"),
        N("package/clipboard-address", "a file that runs at install or as a content script on every site", "reads and writes the clipboard beside a cryptocurrency address pattern"),
        N("package/network-override", "a global fetch assigned a function, or XMLHttpRequest open or send replaced, beside a cryptocurrency address pattern or window.ethereum, outside an if (!fetch) guard", "replaces fetch or XMLHttpRequest beside a cryptocurrency address pattern"),
        // Package combinations.
        N("package/peeled-layers", AtInstall + ", with transformation layers peeled", "transformation layers peeled"),
        N("package/install-bundled-program", AtInstall + ", running a program the package carries", "runs a program the package carries"),
        N("package/install-compiled-eval", AtInstall + ", evaluating code compiled from a string", "evaluates code compiled from a string"),
        N("package/collector-host", "exact list: request catchers and out-of-band test hosts", "contacts a collection endpoint"),
        N("package/dns-send", "a host name whose leftmost label is built from values: encoded, at install, or beside host details or credentials; a constant host name at install beside them or from the package's only code file", "sends data in a DNS lookup"),
        N("package/install-network-collect", AtInstall + ", reaching the network with host details, secrets or decoded code", "install-time code reaches the network and collects"),
        N("package/install-network-launch", AtInstall + ", reaching the network and launching a shell or a background process", "install-time code reaches the network and launches"),
        N("package/socket-shell", "exact form: a socket piped into a spawned shell", "pipes a socket into a spawned shell"),
        N("package/install-detached", AtInstall + ", leaving a process that outlives the install", "starts a background process"),
        N("package/loaded-detached", "entry code that starts node or a file in its own folder detached, beside network, credentials, host details or transformed code; Python starting a program from its own folder in a new session with DEVNULL streams", "starts a background process from its own files"),
        N("package/install-xor", AtInstall + ", decoding its strings with XOR", "decodes its strings with XOR"),
        N("package/stdin-remote-code", RunsRemote, "runs fetched code through an interpreter's standard input"),
        N("package/response-command", RunsRemote, "runs a command read from a network response or socket"),
        N("package/webhook-secrets", "a chat webhook combined with passwords, keys, tokens or wallet secrets", "sends secrets to a chat webhook"),
        N("package/secret-collector", "home credential folders read beside token patterns and a network connection, at install or in a file of at most 64 KiB", "collects credential files and tokens"),
        N("package/secret-prompt", "a prompt for a seed phrase, mnemonic or private key beside a chat webhook, collection endpoint, raw-address socket or browser automation", "asks for wallet secrets"),
        N("package/redirect-entry", "entry JavaScript assigning the browser's location a URL literal that carries an email address", "redirects the browser with an email address"),
        N("package/load-beacon", "entry code that runs when loaded, sending host identity or the environment; or a small source file outside test folders POSTing two kinds of host identity near a literal URL", "sends host identity when loaded"),
        N("package/self-publish", "exact form: rewrites package.json and runs npm publish", "publishes itself"),
        N("package/self-spreading", "a token variable read, a workflow or repository write through the GitHub API and a registry publish in one file, or two of the steps at install; a scanner download or repository write alone is review", "reads publish tokens, writes repositories or workflows and publishes"),
        N("package/ci-config-write", AtInstall + ", opening a CI pipeline file for writing", "writes a CI pipeline file"),
        N("package/nested-install", "a named package manager install after cd .., or of a package the file loads from outside its root", "installs another package outside its own folder"),
        N("package/workspace-upload", "in a file of at most 64 KiB, one call archiving the working folder with dotfiles and a request body", "uploads the working folder"),
        N("package/provenance-failed", "exact check: a digest, signature, chain or log entry check failed", "provenance does not hold"),
        R("package/provenance-repository", "an attested source repository other than the one the manifest declares"),
        // Package manifests.
        R("package/install-script", "a script the package manager runs at install"),
        N("package/install-network-tool", AtInstall + ", running a network tool", "an install script runs a network tool"),
        N("package/builtin-dependency", "a Node built-in name aliased to another package or fetched from outside the registry", "a dependency named after a Node built-in module"),
        N("package/carrier", "the only code file, at most 200 bytes, loads nothing, beside runtime dependencies; or holds only a base64 literal decoding to JSON or a URL", "an entry file that only installs its dependencies"),
        N("package/dependency-source", AtInstall + ", with a dependency fetched from outside the registry, or, in an npm manifest, a dependency over http, git+http or git://, or a git dependency pinned to a commit that no shipped code names", "a dependency fetched from outside the registry"),
        N("package/dependency-alias", "exact form: an unscoped dependency installing npm:@scope/name of the package's own scope or at latest, * or no range", "installs another package under an unscoped dependency name"),
        N("package/locked-source", "a lockfile entry resolved over plain HTTP; git and HTTPS sources are review", "a locked package resolves from outside the registry"),
        R("package/self-dependency", "a package that lists its own name as a dependency"),
        R("package/high-version", "a major version of 99 or higher on a name without a scope"),
        R("package/binary", "native or executable files"),
        N("package/disguised-binary", "package code that XORs file bytes and writes the result", "a .py file that is an executable under a one-byte XOR key"),
        N("package/asset-trailing-data", AtInstall + ", in an asset that install-time code names", "an image, sound or font with data after its format's end, named by the package's code"),
        N("package/extension-clone", "exact list: the source repository of a popular editor extension named under another publisher", "names a popular extension's repository under another publisher"),
        N("package/close-name", AtInstall + ", under a name close to a popular package", "a name close to a popular package"),
        N("package/dependency-lookalike", AtInstall + ", or the unused dependency is from outside the registry", "an unused dependency named like a popular package"),
        N("package/command-name", AtInstall + ", installing a command named like a system command", "a package command named like a system or toolchain command"),
        N("package/command-replace", AtInstall + ", editing command files under the global npm prefix", "install-time code deletes, links, copies over or writes a command file under the global npm prefix"),
        R("package/member-name", "a file name with bidirectional controls, a runnable double extension or long padding"),
        R("package/startup-pth", "a .pth file runs at every interpreter start"),
        R("package/setup-cmdclass", "setup.py replaces a setuptools command"),
        R("package/in-tree-backend", "an in-tree build backend runs while installing"),
        N("package/setup-absent-import", AtInstall + ", calling a module the archive does not hold", "setup.py calls into a module that is not shipped, standard or a build requirement"),
        N("package/compiled-only", AtInstall + ", loaded by a .pth file or setup.py", "modules shipped as .pyc without .py source"),
        N("package/pickle-code", "exact list: a model pickle imports exec, eval, compile, __import__, os.system, os.popen, os.exec*, os.spawn*, os.posix_spawn*, posix, nt, subprocess, runpy or importlib, outside tests and examples or named by a loader; other globals outside the weights-only allowlist are review", "a shipped model pickle runs code when loaded"),
        N("package/model-code", "a Keras Lambda layer, a GGUF chat_template walking __class__ or __globals__, or an ONNX data path with .. or an absolute path; custom Keras layers and .npy object arrays are review", "a model file carries code or reaches outside its folder"),
        N("package/pickle-load", AtInstall + ", setup.py loading with weights_only=False or pickle.load a model that runs code or is not shipped; or such a load at module level of a package setup.py imports", "loads a pickle with code allowed"),
        N("package/credential-collection-dependencies", "exact list: cookie, webhook and session libraries together", "depends on credential collection libraries"),
        N("package/record-differs", "exact check: a file differs from its RECORD hash", "files differ from RECORD"),
        R("package/record-unlisted", "files not listed in RECORD"),
        // Browser and editor extensions.
        R("package/system-permissions", "permissions that reach the browser or system"),
        R("package/all-sites-permissions", "every site, with sensitive permissions"),
        R("package/all-sites", "runs on or reads every site"),
        N("package/csp-remote-code", "a content security policy that lets remote or evaluated code run", "the CSP allows eval or remote scripts"),
        N("package/header-removal", "a rule on every URL beside a content script on every site", "a network rule removes a page security header"),
        R("package/external-update", "updates from outside the store"),
        R("package/externally-connectable", "any site can message the extension"),
        N("package/fetched-eval", RunsRemote, "evaluates code it fetches"),
        N("package/code-store-eval", "exact list: JSON storage and chain RPC hosts, with fetched text reaching eval or Function", "evaluates code fetched from a JSON storage or chain RPC host"),
        N("package/cookie-send", "every cookie read combined with sending to a fixed address", "reads every cookie and sends data"),
        N("package/crx-proof-failed", "exact check: a CRX key proof does not verify", "CRX key proofs do not verify"),
        R("package/startup-activation", "activates when the editor starts"),
        R("package/uninstall-script", "runs when uninstalled"),
        N("package/foreign-extension-id", "activation on '*' with code that reads the install data of its own name or repository under another publisher", "looks up its own name or repository owner under another publisher"),
        N("package/invisible-name", "exact form: invisible characters in a display name", "a display name with invisible characters"),
        N("package/extension-sideload", RunsRemote, "installs an extension from a file it downloads"),
        N("package/editor-content-send", "a POST to a fixed plain-http remote host", "posts editor document text to a fixed host"),
        N("package/hidden-frame", "exact form: a zero-size or hidden iframe to a remote host", "a hidden iframe loads a remote page"),
        // Agent configuration and repository hooks.
        N("package/tag-characters", "exact form: Unicode tag characters that read as text", "Unicode tag characters"),
        N("package/bidi-controls", "in a file an agent reads as instructions", "bidirectional control characters"),
        N("package/zero-width", "8 or more on one line of a file an agent reads as instructions", "zero-width characters"),
        N("package/hidden-bytes", "exact form: 8 or more variation selectors or private-use characters in a row", "characters in a row that decode to hidden bytes"),
        N("package/ansi-escape", "in a file an agent reads as instructions", "terminal escape sequences"),
        N("package/markdown-hidden", "a comment in an instruction file that names a tool, path, URL or command", "text not shown when Markdown is rendered"),
        N("package/agent-hook", "a hook on an event that runs without a tool call", "an agent hook runs a command"),
        N("package/agent-cli-unconfirmed", "exact list: flags that skip the confirmation of claude, codex, gemini and copilot", "runs an AI command-line tool with confirmation off"),
        N("package/agent-confirmation-off", "exact form: Codex approval_policy never", "agent settings run every command without confirmation"),
        N("package/agent-env-endpoint", "exact list: request endpoint, proxy and certificate variables with a non-loopback value in agent settings", "agent settings send requests or trust elsewhere"),
        N("package/agent-env-loader", "exact list: variables that load code into a process, set in agent settings", "agent settings load code into the agent's processes"),
        R("package/agent-helper-command", "an agent settings key that runs a command"),
        R("package/agent-permission-widening", "a permission that approves a whole shell tool, every command or a program that runs code"),
        R("package/agent-plugin", "a plugin turned on or listed from outside the repository"),
        R("package/agent-marketplace", "a plugin marketplace added by agent settings"),
        R("package/agent-auto-approve", "agent tools run without confirmation in editor settings"),
        R("package/agent-settings-hook", "a compiled program installs agent hooks and reads transcripts"),
        R("package/mcp-approve-all", "every project MCP server approved without asking"),
        R("package/mcp-approve", "named project MCP servers approved without asking"),
        R("package/mcp-unpinned", "an MCP server launcher or package without a pinned version"),
        R("package/mcp-plain-http", "an MCP remote over plain HTTP outside loopback"),
        R("package/mcp-raw-address", "an MCP remote at a raw IP address outside loopback"),
        R("package/mcp-secret-env", "an MCP server environment key named like a credential"),
        N("package/mcp-hidden-description", "a comment in a tool description, not shown when rendered", "a tool description hides text"),
        N("package/folder-open-task", "a folder-open task with automatic tasks allowed", "a task runs when the folder opens"),
        N("package/workflow-pr-checkout", "a pull_request_target or workflow_run job that checks out the change's own code", "a privileged workflow checks out code from the change"),
        N("package/workflow-secrets-dump", "exact form: toJSON(secrets)", "a workflow reads every secret as one value"),
        N("package/workflow-run-expression", "exact list: author-controlled event fields inside a run command", "a run command holds an event field an author controls"),
        R("package/direnv", "direnv runs .envrc on entering the folder"),
        N("package/git-config-command", "exact list: git config keys that run without asking", "git config runs a command"),
        N("package/git-hook", "a hook placed in the checkout, which runs without asking", "a git hook runs"),
        N("package/devcontainer-command", "initializeCommand, which runs on the host", "a dev container command"),
        N("package/msbuild-exec", "a target the design-time build runs when the project opens", "an MSBuild target runs a command"),
        N("package/msbuild-inline-task", "exact list: inline code task factories", "an inline MSBuild task compiles and runs code"),
        R("package/cargo-build-script", "a Cargo build script"),
        R("package/gradle-process", "a Gradle script starts a process"),
        N("package/gradle-wrapper-url", "a build tool downloaded and run from outside services.gradle.org", "the Gradle wrapper downloads its tool"),
        R("package/cmake-process", "CMake runs a process at configure"),
        N("guarddog/*", "a GuardDog threat-* rule", "a GuardDog rule matches"),
        // Archive and disk image entries.
        R("archive/unsafe-path", "an entry path with a '..', rooted, drive or stream part, or a part ending in a blank or a dot"),
        R("archive/name-collision", "one name used for a file and a folder"),
        R("archive/nested-executable", "an executable inside an archive that is inside another archive"),
        R("archive/hidden-entry", "an entry with the hidden attribute in an ISO, UDF, FAT or NTFS image"),
        // Native images.
        R("sideload/unsigned-dll", "an unsigned DLL a signed image imports from its folder, not a KnownDLL"),
        I("packer/packing-tool", "a packing tool's section names or header"),
        I("packer/hardening-tool", "a hardening tool's section names"),
        R("packer/empty-code-section", "a code section empty on disk and filled at run time"),
        R("packer/high-entropy-code", "a code section of high entropy"),
        R("packer/writable-entry", "the entry point in a writable and executable section"),
        R("native/host-entry", "an export a host program calls by name"),
        // Documents, shortcuts and installers (olevba vocabulary).
        I("office/autoexec", "a macro that runs when the document opens, closes or changes"),
        N("office/suspicious", "a decoded keyword in a document whose macros run on open", "a keyword worth reviewing in macro text"),
        I("office/ioc", "a URL, address or file name in macro text"),
        I("office/encoded-string", "hex or base64 strings in macro text"),
        N("office/ole-class", "exact list: Equation Editor and OLE Package objects", "an embedded or linked object of a class that runs code"),
        R("office/template", "a remote template or linked object target"),
        R("pdf/suspicious", "a PDF action or keyword worth reviewing"),
        I("pdf/ioc", "a URL a PDF action opens"),
        R("shortcut/suspicious", "a shortcut target or argument worth reviewing"),
        I("shortcut/ioc", "a URL in shortcut arguments"),
        R("link/local-handler", "a link, relationship or action target that starts a local handler (ms-msdt:, search-ms:, an Office scheme, file://) or reaches a UNC path"),
        R("launcher/command-line", "a program that starts other code, with an argument shape that downloads, decodes or hides"),
        R("installer/suspicious", "an installer action or keyword worth reviewing"),
        I("installer/ioc", "a URL, address or file name in installer script"),
        N("page/blob-payload", "exact form: a standalone page's own script builds a Blob from a base64 literal over 4 KiB that decodes to an archive, program or document, and saves it", "a page builds a file in a Blob and saves it"),
        R("page/foreign-form", "a POST form whose action is an absolute http(s) URL, a different origin from the saved file"),
        R("page/password-foreign-form", "a password input in a POST form to an absolute http(s) URL"),
        R("page/meta-refresh", "a meta refresh that redirects to a URL"),
        R("page/script-redirect", "script that assigns location a URL literal or calls location.replace or location.assign with one"),
        R("capture/pattern", "a request pattern worth reviewing in captured traffic"),
        N("malcontent/*", "pack risk critical", "a malcontent behaviour"),
    ];

    /// <summary>Every row: the fixed table, then one per app rule with a MASVS control.</summary>
    public static IReadOnlyList<FindingRule> All { get; } =
        [.. Rows, .. MobileRules.All.Select(r => new FindingRule(r.Id!, FromMasvs(r.Severity), null, r.Name))];

    private static readonly Dictionary<string, FindingRule> ById = All.ToDictionary(r => r.Id, StringComparer.Ordinal);

    /// <summary>Old id to new id for every renamed rule; a baseline maps its ids through it. Ids are never reused.</summary>
    public static IReadOnlyDictionary<string, string> Renamed { get; } = new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>Each rule whose level changed, by id: the release, the level alone before and after, and what keeps it noteworthy; empty in 2.8.0.</summary>
    public static IReadOnlyDictionary<string, FindingRelevel> Relevelled { get; } = new Dictionary<string, FindingRelevel>(StringComparer.Ordinal);

    /// <summary>The table's version: the first 16 hex digits of the SHA-256 of every row, rename and level change; any edit changes it.</summary>
    // Static properties initialize in text order, so this follows the maps it reads.
    public static string Digest { get; } = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(
        string.Join("\n", All.Select(r => $"{r.Id}\t{r.Level}\t{r.Noteworthy}")
            .Concat(Renamed.OrderBy(r => r.Key, StringComparer.Ordinal).Select(r => $"renamed\t{r.Key}\t{r.Value}"))
            .Concat(Relevelled.Values.OrderBy(r => r.Id, StringComparer.Ordinal).Select(r => $"relevelled\t{r.Id}\t{r.Release}\t{r.Old}\t{r.New}"))))))[..16];

    /// <summary>The row for <paramref name="id"/> after renames, or the family row of its prefix; null for an unknown id.</summary>
    public static FindingRule? Find(string id)
    {
        if (Renamed.TryGetValue(id, out var renamed)) id = renamed;
        if (ById.TryGetValue(id, out var rule)) return rule;
        int slash = id.IndexOf('/');
        return slash > 0 && ById.TryGetValue(id[..(slash + 1)] + "*", out var family) ? family : null;
    }

    /// <summary>Returns <paramref name="level"/>; throws when the id is not in the table or the level is above its row.</summary>
    public static string Check(string id, string level)
    {
        var rule = Find(id) ?? throw new InvalidOperationException($"Rule '{id}' is not in the rule table.");
        if (FindingLevel.Rank(level) == 0 || FindingLevel.Rank(level) > FindingLevel.Rank(rule.Level))
            throw new InvalidOperationException($"Rule '{id}' emits {level}; its row allows {rule.Level}.");
        return level;
    }

    /// <summary>malcontent risk to level: critical noteworthy, high and medium review, low or none info.</summary>
    public static string FromMalcontent(string? risk) => risk switch
    {
        "critical" => FindingLevel.Noteworthy,
        "high" or "medium" => FindingLevel.Review,
        _ => FindingLevel.Info,
    };

    /// <summary>MASVS rule severity to level: high and medium review, low, info or none info.</summary>
    public static string FromMasvs(string? severity) => severity is "high" or "medium" ? FindingLevel.Review : FindingLevel.Info;

    /// <summary>Packer kind to level: suspicious review; a named packing or hardening tool info.</summary>
    public static string FromPacker(string kind) => kind == "suspicious" ? FindingLevel.Review : FindingLevel.Info;

    /// <summary>A packer finding as the shared record.</summary>
    public static Finding ToFinding(Native.PackerFinding p) => new(Check(p.Rule, FromPacker(p.Kind)), p.Rule, "packer", $"{p.Name}: {p.Evidence}", null, "packer");

    /// <summary>The launcher uses of one view as shared records under launcher/command-line; empty when none.</summary>
    internal static IEnumerable<Finding> FromLaunchers(IEnumerable<Core.Documents.Launchers.Use> uses, string source, string? location = null) =>
        uses.Select(u => new Finding(Check("launcher/command-line", FindingLevel.Review), "launcher/command-line", "process", $"{u.Program} {u.Shape}: {u.What}", location, source));

    /// <summary>olevba-type findings of one view as shared records, rule ids "&lt;source&gt;/&lt;type&gt;"; AutoExec, IOC and encoded strings are info.</summary>
    internal static IReadOnlyList<Finding> FromMacros(IEnumerable<Core.Documents.MacroFinding> found, string source)
    {
        var list = found.ToList();
        // A keyword found only after decoding, in macros that run on their own, is
        // decoded content in code that runs without asking.
        bool autorun = list.Any(f => f.Type == "AutoExec");
        return [.. list.Select(f =>
        {
            var (type, category) = f.Type switch
            {
                "AutoExec" => ("autoexec", "autorun"),
                "Suspicious" => ("suspicious", "keyword"),
                "IOC" => ("ioc", "address"),
                "OleClass" => ("ole-class", "object class"),
                "Template" => ("template", "remote target"),
                _ => ("encoded-string", "encoded string"),
            };
            var level = type == "ole-class" ? FindingLevel.Noteworthy : type == "template" ? FindingLevel.Review : type != "suspicious" ? FindingLevel.Info : autorun && f.Decoded != null ? FindingLevel.Noteworthy : FindingLevel.Review;
            var rule = $"{source}/{type}";
            var evidence = f.Decoded != null ? $"{f.Keyword} (decoded from {f.Decoded}): {f.Description}" : $"{f.Keyword}: {f.Description}";
            return new Finding(Check(rule, level), rule, category, evidence, f.Location, source);
        })];
    }
}
