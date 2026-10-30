using Corvus.Core;
using Corvus.Services;
using Corvus.Services.Analysis;
using Corvus.Services.Web.Packages;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Lockfiles written here in each tool's documented layout, read as resolved packages, compared and searched.</summary>
public sealed class LockfileTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private const string Sri = "sha512-AAAA";

    private static string NpmLock(params (string Key, string Body)[] packages) =>
        "{\"name\":\"app\",\"lockfileVersion\":3,\"packages\":{\"\":{\"name\":\"app\"}" + string.Concat(packages.Select(p => $",\"{p.Key}\":{p.Body}")) + "}}";

    private static string Registry(string name, string version, string integrity = Sri, bool script = false) =>
        $"{{\"version\":\"{version}\",\"resolved\":\"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz\",\"integrity\":\"{integrity}\"" +
        (script ? ",\"hasInstallScript\":true" : "") + "}";

    [Fact]
    public void An_npm_lockfile_names_each_installed_copy_with_its_source()
    {
        var lockfile = Lockfiles.Read("package-lock.json", NpmLock(
            ("node_modules/left-pad", Registry("left-pad", "1.3.0")),
            ("node_modules/@scope/util", Registry("util", "2.0.0", script: true)),
            ("node_modules/a/node_modules/left-pad", Registry("left-pad", "1.1.0")),
            ("node_modules/from-git", "{\"version\":\"0.1.0\",\"resolved\":\"git+ssh://git@github.com/example/from-git.git#0123abc\"}"),
            ("node_modules/plain", "{\"version\":\"1.0.0\",\"resolved\":\"http://packages.example.invalid/plain-1.0.0.tgz\"}"),
            ("packages/tool", "{\"version\":\"0.0.1\"}")))!;
        Assert.Equal("package-lock", lockfile.Format);
        Assert.Equal(
            ["left-pad 1.3.0 registry", "@scope/util 2.0.0 registry", "left-pad 1.1.0 registry", "from-git 0.1.0 git", "plain 1.0.0 url", "packages/tool 0.0.1 path"],
            lockfile.Packages.Select(p => $"{p.Name} {p.Version} {p.Source}"));
        Assert.True(lockfile.Packages[1].InstallScript);
    }

    [Fact]
    public void An_npm_lockfile_version_1_reads_nested_dependencies_and_git_versions()
    {
        var lockfile = Lockfiles.Read("npm-shrinkwrap.json", """
            {"name":"app","lockfileVersion":1,"dependencies":{
              "a":{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","integrity":"sha512-AAAA",
                   "dependencies":{"b":{"version":"2.0.0","resolved":"https://registry.npmjs.org/b/-/b-2.0.0.tgz"}}},
              "c":{"version":"github:example/c#0123abc"}}}
            """)!;
        Assert.Equal(["a 1.0.0 registry", "b 2.0.0 registry", "c github:example/c#0123abc git"], lockfile.Packages.Select(p => $"{p.Name} {p.Version} {p.Source}"));
    }

    [Fact]
    public void A_pnpm_lockfile_reads_keys_of_versions_5_6_and_9_without_peer_suffixes()
    {
        var v5 = Lockfiles.Read("pnpm-lock.yaml", """
            lockfileVersion: 5.4
            packages:
              /react-dom/17.0.2_react@17.0.2:
                resolution: {integrity: sha512-BBBB}
                requiresBuild: true
                dev: false
              /@babel/core/7.0.0:
                resolution: {integrity: sha512-CCCC}
            """)!;
        Assert.Equal(["react-dom 17.0.2 registry True", "@babel/core 7.0.0 registry False"], v5.Packages.Select(p => $"{p.Name} {p.Version} {p.Source} {p.InstallScript}"));
        var v9 = Lockfiles.Read("pnpm-lock.yaml", """
            lockfileVersion: '9.0'
            importers:
              .:
                dependencies:
                  ms:
                    specifier: ^2.1.3
                    version: 2.1.3
            packages:
              '@types/node@20.0.0':
                resolution: {integrity: sha512-DDDD}
              ms@2.1.3:
                resolution: {integrity: sha512-EEEE}
              styled@1.0.0(react@18.2.0):
                resolution: {integrity: sha512-FFFF}
              remote@https://example.invalid/remote-1.0.0.tgz:
                resolution: {tarball: https://example.invalid/remote-1.0.0.tgz}
                name: remote
                version: 1.0.0
              vendored@git+https://github.com/example/vendored.git#0123abc:
                resolution: {commit: 0123abc, repo: https://github.com/example/vendored.git, type: git}
                name: vendored
                version: 0.2.0
            snapshots:
              ms@2.1.3: {}
            """)!;
        Assert.Equal(["@types/node 20.0.0 registry", "ms 2.1.3 registry", "styled 1.0.0 registry", "remote 1.0.0 url", "vendored 0.2.0 git"],
            v9.Packages.Select(p => $"{p.Name} {p.Version} {p.Source}"));
        Assert.Equal("https://github.com/example/vendored.git#0123abc", v9.Packages[4].Resolved);
    }

    [Fact]
    public void A_yarn_lockfile_reads_version_1_and_berry_entries()
    {
        var v1 = Lockfiles.Read("yarn.lock", """
            # THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
            # yarn lockfile v1


            "@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
              version "7.12.13"
              resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.12.13.tgz#dcfc826beef65e75c50e21d3837d7d95798dd658"
              integrity sha512-GGGG
              dependencies:
                "@babel/highlight" "^7.12.13"

            forked@git+ssh://git@github.com/example/forked.git#0123abc:
              version "1.0.0"
              resolved "git+ssh://git@github.com/example/forked.git#0123abc"
            """)!;
        Assert.Equal("yarn.lock (v1)", v1.Format);
        Assert.Equal(["@babel/code-frame 7.12.13 registry sha512-GGGG", "forked 1.0.0 git "], v1.Packages.Select(p => $"{p.Name} {p.Version} {p.Source} {p.Integrity}"));
        var berry = Lockfiles.Read("yarn.lock", """
            __metadata:
              version: 8
              cacheKey: 10c0

            "ms@npm:^2.1.1":
              version: 2.1.3
              resolution: "ms@npm:2.1.3"
              checksum: 10c0/aaaa
              languageName: node
              linkType: hard

            "tool@workspace:packages/tool":
              version: 0.0.0-use.local
              resolution: "tool@workspace:packages/tool"
              languageName: unknown
              linkType: soft

            "remote@https://example.invalid/remote-1.0.0.tgz":
              version: 1.0.0
              resolution: "remote@https://example.invalid/remote-1.0.0.tgz"
              languageName: node
              linkType: hard
            """)!;
        Assert.Equal("yarn.lock (berry)", berry.Format);
        Assert.Equal(["ms 2.1.3 registry", "tool 0.0.0-use.local path", "remote 1.0.0 url"], berry.Packages.Select(p => $"{p.Name} {p.Version} {p.Source}"));
    }

    [Fact]
    public void Poetry_and_uv_lockfiles_read_sources_and_file_hashes()
    {
        var poetry = Lockfiles.Read("poetry.lock", """
            [[package]]
            name = "Requests"
            version = "2.31.0"
            description = "Python HTTP for Humans."
            optional = false
            python-versions = ">=3.7"
            files = [
                {file = "requests-2.31.0-py3-none-any.whl", hash = "sha256:58cd"},
                {file = "requests-2.31.0.tar.gz", hash = "sha256:942c"},
            ]

            [package.dependencies]
            idna = ">=2.5,<4"

            [[package]]
            name = "forked"
            version = "0.1.0"
            description = ""
            optional = false
            python-versions = "*"
            files = []

            [package.source]
            type = "git"
            url = "https://github.com/example/forked.git"
            reference = "main"
            resolved_reference = "0123abc"

            [metadata]
            lock-version = "2.0"
            python-versions = "^3.11"
            content-hash = "ffff"
            """)!;
        Assert.Equal(["requests 2.31.0 registry sha256:58cd sha256:942c", "forked 0.1.0 git "], poetry.Packages.Select(p => $"{p.Name} {p.Version} {p.Source} {p.Integrity}"));
        Assert.Equal("https://github.com/example/forked.git#0123abc", poetry.Packages[1].Resolved);
        var uv = Lockfiles.Read("uv.lock", """
            version = 1
            requires-python = ">=3.12"

            [[package]]
            name = "idna"
            version = "3.7"
            source = { registry = "https://pypi.org/simple" }
            sdist = { url = "https://files.pythonhosted.org/packages/idna-3.7.tar.gz", hash = "sha256:028f", size = 189575 }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/idna-3.7-py3-none-any.whl", hash = "sha256:82fe", size = 66836 },
            ]

            [[package]]
            name = "app"
            version = "0.1.0"
            source = { editable = "." }
            dependencies = [
                { name = "idna" },
            ]

            [[package]]
            name = "direct"
            version = "1.0.0"
            source = { url = "https://example.invalid/direct-1.0.0.tar.gz" }
            """)!;
        Assert.Equal(["idna 3.7 registry sha256:028f sha256:82fe", "app 0.1.0 path ", "direct 1.0.0 url "], uv.Packages.Select(p => $"{p.Name} {p.Version} {p.Source} {p.Integrity}"));
    }

    [Fact]
    public void A_hashed_requirements_file_reads_pins_and_direct_references_and_an_unhashed_one_is_not_a_lockfile()
    {
        var pip = Lockfiles.Read("requirements.txt", """
            # generated by pip-compile
            Django==4.2.7 \
                --hash=sha256:bbbb \
                --hash=sha256:aaaa
                # via -r requirements.in
            direct @ https://example.invalid/direct-1.0.0.tar.gz --hash=sha256:cccc
            """)!;
        Assert.Equal(["django 4.2.7 registry sha256:aaaa sha256:bbbb", "direct  url sha256:cccc"], pip.Packages.Select(p => $"{p.Name} {p.Version} {p.Source} {p.Integrity}"));
        Assert.Null(Lockfiles.Read("requirements.txt", "requests>=2\n"));
    }

    [Fact]
    public async Task A_lockfile_pair_names_each_change_at_its_entry()
    {
        var old = Write("old/package-lock.json", NpmLock(
            ("node_modules/kept", Registry("kept", "1.0.0")),
            ("node_modules/repinned", Registry("repinned", "2.0.0", "sha512-OLD")),
            ("node_modules/builder", Registry("builder", "3.0.0")),
            ("node_modules/moved", Registry("moved", "4.0.0")),
            ("node_modules/dropped", Registry("dropped", "5.0.0"))));
        var @new = Write("new/package-lock.json", NpmLock(
            ("node_modules/kept", Registry("kept", "1.0.0")),
            ("node_modules/repinned", Registry("repinned", "2.0.0", "sha512-NEW")),
            ("node_modules/builder", Registry("builder", "3.0.0", script: true)),
            ("node_modules/moved", "{\"version\":\"4.0.0\",\"resolved\":\"git+https://github.com/example/moved.git#0123abc\"}"),
            ("node_modules/kept/node_modules/transitive", Registry("transitive", "6.0.0"))));
        var result = await new FolderTools(new FolderCompare()).CompareFolders(Path.GetDirectoryName(old), Path.GetDirectoryName(@new));
        var rows = result.Changes!.ToDictionary(c => c.Key);
        Assert.Equal(["package-lock.json: builder@3.0.0", "package-lock.json: dropped@5.0.0", "package-lock.json: moved@4.0.0",
            "package-lock.json: repinned@2.0.0", "package-lock.json: transitive@6.0.0"], rows.Keys.Order(StringComparer.Ordinal));
        Assert.Equal(["install script"], rows["package-lock.json: builder@3.0.0"].Fields!);
        Assert.Equal("removed", rows["package-lock.json: dropped@5.0.0"].Kind);
        Assert.Equal(["source"], rows["package-lock.json: moved@4.0.0"].Fields!);
        Assert.StartsWith("noteworthy: git git+https://github.com/example/moved.git", rows["package-lock.json: moved@4.0.0"].New, StringComparison.Ordinal);
        Assert.Equal(["integrity"], rows["package-lock.json: repinned@2.0.0"].Fields!);
        Assert.StartsWith("noteworthy: ", rows["package-lock.json: repinned@2.0.0"].New, StringComparison.Ordinal);
        Assert.Equal(("added", "registry"), (rows["package-lock.json: transitive@6.0.0"].Kind, rows["package-lock.json: transitive@6.0.0"].New));
        Assert.Contains(result.Notes, n => n == "lockfile package-lock.json: 1 package(s) added, 1 removed, 3 changed, 2 noteworthy");
    }

    [Fact]
    public void A_folder_of_three_projects_names_the_one_resolving_a_listed_version()
    {
        Write("projects/web/package-lock.json", NpmLock(("node_modules/left-pad", Registry("left-pad", "1.3.0"))));
        Write("projects/api/package-lock.json", NpmLock(("node_modules/left-pad", Registry("left-pad", "1.1.0"))));
        Write("projects/api/node_modules/left-pad/package-lock.json", NpmLock(("node_modules/left-pad", Registry("left-pad", "1.1.0"))));
        Write("projects/tool/poetry.lock", "[[package]]\nname = \"left-pad\"\nversion = \"1.1.0\"\n");
        var found = new UnpackService(new AssemblyWorkspace()).Search(_dir.File("projects"), "left-pad@1.1.0", "dependency", 10, AnalysisLimits.Default, default);
        Assert.Equal(["api/package-lock.json", "tool/poetry.lock"], found.Items.Select(i => i.Path).Order(StringComparer.Ordinal));
        Assert.Equal(3, found.Searched);
        Assert.Empty(new UnpackService(new AssemblyWorkspace()).Search(_dir.File("projects"), "left-pad@1.1", "dependency", 10, AnalysisLimits.Default, default).Items);
    }

    [Fact]
    public void The_lockfile_view_reviews_a_git_source_and_marks_a_plain_http_source_noteworthy()
    {
        var path = Write("app/package-lock.json", NpmLock(
            ("node_modules/left-pad", Registry("left-pad", "1.3.0")),
            ("node_modules/from-git", "{\"version\":\"0.1.0\",\"resolved\":\"git+https://github.com/example/from-git.git#0123abc\"}"),
            ("node_modules/plain", "{\"version\":\"1.0.0\",\"resolved\":\"http://packages.example.invalid/plain-1.0.0.tgz\"}"),
            ("packages/tool", "{\"version\":\"0.0.1\"}")));
        var view = new InspectionService(new AssemblyWorkspace()).Summarize(null, path, default, new FileViewOptions("lockfile")).Views["lockfile"];
        var facts = Assert.IsType<LockfileFileView.Facts>(view.Detail);
        Assert.Equal(new Dictionary<string, int> { ["git"] = 1, ["path"] = 1, ["registry"] = 1, ["url"] = 1 }, facts.BySource);
        Assert.Equal(["review from-git", "noteworthy plain"], view.Findings.Select(f => $"{f.Level} {f.Evidence.Split('@')[0]}"));
    }

    [Fact]
    [FuzzEntry(typeof(Lockfiles), typeof(LockfileFileView))]
    public void Fuzzed_lockfiles_never_throw()
    {
        var seeds = new[]
        {
            ("package-lock.json", NpmLock(("node_modules/a", Registry("a", "1.0.0", script: true)), ("node_modules/b", "{\"version\":\"github:example/b#0123abc\"}"))),
            ("pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  a@1.0.0(b@2.0.0):\n    resolution: {integrity: sha512-AAAA}\n"),
            ("yarn.lock", "\"a@^1.0.0\":\n  version \"1.0.0\"\n  resolved \"https://registry.yarnpkg.com/a/-/a-1.0.0.tgz\"\n"),
            ("poetry.lock", "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n\n[package.source]\ntype = \"git\"\nurl = \"https://example.invalid/a.git\"\n"),
            ("uv.lock", "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n"),
            ("requirements.txt", "a==1.0.0 \\\n    --hash=sha256:aaaa\n"),
        };
        foreach (var (name, text) in seeds)
        {
            var folder = Directory.CreateDirectory(_dir.File("fuzz-" + Path.GetFileNameWithoutExtension(name))).FullName;
            var path = Path.Combine(folder, name);
            var failures = FormatFuzz.Run(System.Text.Encoding.UTF8.GetBytes(text), b =>
            {
                var lockfile = Lockfiles.Read(name, System.Text.Encoding.UTF8.GetString(b));
                if (lockfile != null) Lockfiles.Diff(lockfile, lockfile, name);
                File.WriteAllBytes(path, b);
                new LockfileFileView().Inspect(FileInput.Open(path), default);
            }, 100);
            Assert.True(failures.Count == 0, name + ": " + string.Join("\n", failures.Take(20)));
        }
    }

    private string Write(string relative, string text)
    {
        var path = _dir.File(relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, text);
        return path;
    }
}
