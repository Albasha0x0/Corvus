using System.Diagnostics;
using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Corvus.Setup;
using static Corvus.Setup.ReleaseSigning;

namespace Corvus.Tests;

/// <summary>How <c>corvus update</c> and the install scripts check SHA256SUMS.sig; keys are generated per test and gh is faked.</summary>
public class ReleaseSigningTests
{
    private static readonly string Root = DocsTests.RepoRoot();
    private static readonly byte[] Archive = Encoding.UTF8.GetBytes("archive");
    private static readonly string[] Assets = ["corvus-linux-x64.tar.gz", "corvus-linux-musl-x64.tar.gz", "corvus-win-x64.zip", "corvus-win-arm64.zip"];

    private static ECDsa NewKey() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    private static string PublicKeyOf(ECDsa key) => Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());

    // A 72-byte DER signature pads r and s with a zero byte; install.ps1 strips it.
    private static byte[] Sign(ECDsa key, byte[] data)
    {
        var signature = key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        for (var i = 0; i < 200 && signature.Length != 72; i++)
            signature = key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        return signature;
    }

    private static byte[] Manifest(byte[] archive)
    {
        var hash = Convert.ToHexStringLower(SHA256.HashData(archive));
        return Encoding.UTF8.GetBytes(string.Concat(Assets.Select(a => $"{hash}  {a}\n")));
    }

    private static (bool Passed, string Output) Verify(byte[]? signature, string publicKey, Installation.GhRunner gh, string? require = null)
    {
        var output = new StringWriter();
        var passed = Installation.VerifyDownload(output, "corvus-linux-x64.tar.gz", Archive, Manifest(Archive), signature, publicKey,
            "owner/name", "v2.0.0", require, gh);
        return (passed, output.ToString());
    }

    [Fact]
    public void A_correctly_signed_manifest_passes()
    {
        using var key = NewKey();
        var (passed, output) = Verify(Sign(key, Manifest(Archive)), PublicKeyOf(key), _ => (0, ""));
        Assert.True(passed, output);
        Assert.Contains("Signature verified", output);
        Assert.Contains("Provenance verified", output);
    }

    [Fact]
    public void A_manifest_signed_by_another_key_is_refused_with_and_without_gh()
    {
        using var key = NewKey();
        using var other = NewKey();
        var signature = Sign(other, Manifest(Archive));
        var asked = false;
        var (withGh, output) = Verify(signature, PublicKeyOf(key), _ => { asked = true; return (0, ""); });
        Assert.False(withGh);
        Assert.Contains("does not verify with the release key", output);
        Assert.False(asked);
        Assert.False(Verify(signature, PublicKeyOf(key), _ => null).Passed);
    }

    [Fact]
    public void An_unsigned_or_altered_manifest_is_refused_once_a_key_is_published()
    {
        using var key = NewKey();
        var (unsigned, output) = Verify(null, PublicKeyOf(key), _ => (0, ""));
        Assert.False(unsigned);
        Assert.Contains("has no SHA256SUMS.sig", output);
        var altered = Check("altered"u8, Sign(key, Manifest(Archive)), PublicKeyOf(key), null);
        Assert.Equal(SignatureState.Refused, altered.State);
    }

    [Fact]
    public void The_placeholder_key_reports_the_signature_unknown_and_continues()
    {
        var (passed, output) = Verify(null, Placeholder, _ => null);
        Assert.True(passed, output);
        Assert.Contains("no release signing key is published yet", output);
        Assert.Contains("Provenance not checked (gh is not on PATH)", output);
    }

    [Fact]
    public void Require_attestation_0_skips_the_signature()
    {
        using var key = NewKey();
        var result = Check(Manifest(Archive), null, PublicKeyOf(key), "0");
        Assert.Equal(SignatureState.Unknown, result.State);
        Assert.Contains("CORVUS_REQUIRE_ATTESTATION=0", result.Message);
    }

    [Fact]
    public void The_scripts_hold_the_same_key_as_the_program()
    {
        Assert.Contains($"SIGNING_KEY=\"{PublicKey}\"", File.ReadAllText(Path.Combine(Root, "install.sh")), StringComparison.Ordinal);
        Assert.Contains($"$signingKey = '{PublicKey}'", File.ReadAllText(Path.Combine(Root, "install.ps1")), StringComparison.Ordinal);
        Assert.Contains($"= \"{Placeholder}\" ]", File.ReadAllText(Path.Combine(Root, "install.sh")), StringComparison.Ordinal);
        Assert.Contains($"-eq '{Placeholder}'", File.ReadAllText(Path.Combine(Root, "install.ps1")), StringComparison.Ordinal);
    }

    /// <summary>A release in a temporary folder: archive, SHA256SUMS, optional .sig, a fake gh and a copy of a script with <c>key</c>.</summary>
    private sealed class Fixture : IDisposable
    {
        private readonly TempDir _dir = new();
        public string Dir => _dir.Path;
        public string ArchivePath { get; }
        public string SumsPath => Path.Combine(Dir, "SHA256SUMS");
        public string StubDir => Path.Combine(Dir, "bin");

        public Fixture(byte[] archive)
        {
            ArchivePath = Path.Combine(Dir, "package");
            File.WriteAllBytes(ArchivePath, archive);
            File.WriteAllBytes(SumsPath, Manifest(archive));
            Directory.CreateDirectory(StubDir);
        }

        public void SignWith(ECDsa key) => File.WriteAllBytes(SumsPath + ".sig", Sign(key, File.ReadAllBytes(SumsPath)));

        public string Script(string name, string key)
        {
            var text = File.ReadAllText(Path.Combine(Root, name)).Replace("\r\n", "\n");
            if (key != Placeholder)
            {
                var line = name.EndsWith(".sh", StringComparison.Ordinal) ? $"SIGNING_KEY=\"{Placeholder}\"" : $"$signingKey = '{Placeholder}'";
                Assert.Contains(line, text, StringComparison.Ordinal);
                text = text.Replace(line, line.Replace(Placeholder, key));
            }
            var path = Path.Combine(Dir, name);
            File.WriteAllText(path, text);
            return path;
        }

        public void Dispose() => _dir.Dispose();
    }

    // PATH without the folders that hold gh, so a host with gh runs without it.
    private static string PathWithout(string first) =>
        string.Join(Path.PathSeparator, new[] { first }.Concat((Environment.GetEnvironmentVariable("PATH") ?? "")
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Where(d => !new[] { "gh", "gh.exe", "gh.cmd" }.Any(n => File.Exists(Path.Combine(d.Trim('"'), n))))));

    private static (int ExitCode, string Output) Run(string exe, IEnumerable<string> args, IDictionary<string, string> env)
    {
        var start = new ProcessStartInfo(exe) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true };
        foreach (var a in args) start.ArgumentList.Add(a);
        foreach (var (k, v) in env) start.Environment[k] = v;
        using var p = Process.Start(start)!;
        p.StandardInput.Close();
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(TimeSpan.FromMinutes(1))) { p.Kill(entireProcessTree: true); throw new TimeoutException(exe); }
        return (p.ExitCode, stdout.Result + stderr.Result);
    }

    private static string? Pwsh() => OperatingSystem.IsWindows() ? BundleTests.FindOnPath("pwsh.exe") : null;

    // Git for Windows ships sh beside the tools install.sh calls (openssl, tar).
    private static string? Sh()
    {
        if (!OperatingSystem.IsWindows()) return BundleTests.FindOnPath("sh");
        if (BundleTests.FindOnPath("sh.exe") is { } sh) return sh;
        return BundleTests.FindOnPath("git.exe") is { } git && Path.GetFullPath(Path.Combine(Path.GetDirectoryName(git)!, "..", "usr", "bin", "sh.exe")) is var found
            && File.Exists(found) ? found : null;
    }

    private static string Unix(string path) => path.Replace('\\', '/');

    private static (int ExitCode, string Output) RunPwsh(string pwsh, Fixture f, string key, bool gh)
    {
        if (gh) File.WriteAllText(Path.Combine(f.StubDir, "gh.cmd"), "@exit /b 0\r\n");
        return Run(pwsh, ["-NoProfile", "-NonInteractive", "-File", f.Script("install.ps1", key), "-DryRun", "-Yes"], new Dictionary<string, string>
        {
            ["PATH"] = PathWithout(f.StubDir),
            ["CORVUS_ARCHIVE"] = f.ArchivePath,
            ["CORVUS_SHA256SUMS"] = f.SumsPath,
            ["CORVUS_REQUIRE_ATTESTATION"] = "",
        });
    }

    private static (int ExitCode, string Output) RunSh(string sh, Fixture f, string key, bool gh)
    {
        // uname reports Linux x64 so the script reaches its checks on any host.
        File.WriteAllText(Path.Combine(f.StubDir, "uname"), "#!/bin/sh\ncase \"$1\" in -s) echo Linux ;; -m) echo x86_64 ;; *) echo Linux ;; esac\n");
        if (gh) File.WriteAllText(Path.Combine(f.StubDir, "gh"), "#!/bin/sh\nexit 0\n");
        if (!OperatingSystem.IsWindows())
            foreach (var stub in Directory.EnumerateFiles(f.StubDir)) File.SetUnixFileMode(stub, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var path = PathWithout(f.StubDir);
        if (OperatingSystem.IsWindows()) path = f.StubDir + Path.PathSeparator + Path.GetDirectoryName(sh) + Path.PathSeparator + path;
        return Run(sh, [Unix(f.Script("install.sh", key)), "--dry-run", "--yes"], new Dictionary<string, string>
        {
            ["PATH"] = path,
            ["CORVUS_ARCHIVE"] = Unix(f.ArchivePath),
            ["CORVUS_SHA256SUMS"] = Unix(f.SumsPath),
            ["CORVUS_REQUIRE_ATTESTATION"] = "",
            ["CORVUS_HOME"] = Unix(Path.Combine(f.Dir, "home")),
        });
    }

    private static byte[] ZipArchive()
    {
        using var stream = new MemoryStream();
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
            using (var writer = new StreamWriter(zip.CreateEntry("readme.txt").Open())) writer.Write("build");
        return stream.ToArray();
    }

    // A program that answers "version" and accepts the dry-run registration.
    private static byte[] TarArchive()
    {
        using var stream = new MemoryStream();
        using (var gzip = new GZipStream(stream, CompressionLevel.Fastest, leaveOpen: true))
        using (var tar = new TarWriter(gzip))
        {
            var entry = new PaxTarEntry(TarEntryType.RegularFile, "corvus")
            {
                Mode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute,
                DataStream = new MemoryStream(Encoding.UTF8.GetBytes("#!/bin/sh\n[ \"$1\" = version ] && echo 9.9.9\nexit 0\n")),
            };
            tar.WriteEntry(entry);
        }
        return stream.ToArray();
    }

    [Fact]
    public void Install_ps1_refuses_another_key_with_and_without_gh_and_passes_its_own()
    {
        if (Pwsh() is not { } pwsh) return;
        using var key = NewKey();
        using var other = NewKey();
        foreach (var gh in new[] { false, true })
        {
            using var f = new Fixture(ZipArchive());
            f.SignWith(other);
            var (code, output) = RunPwsh(pwsh, f, PublicKeyOf(key), gh);
            Assert.True(code != 0, output);
            Assert.Contains("does not verify with the release key", output);
            Assert.DoesNotContain("Provenance verified", output);
        }
        using (var f = new Fixture(ZipArchive()))
        {
            f.SignWith(key);
            var (_, output) = RunPwsh(pwsh, f, PublicKeyOf(key), gh: false);
            Assert.Contains("Signature verified", output);
            Assert.Contains("Provenance not checked (gh is not on PATH)", output);
        }
        using (var f = new Fixture(ZipArchive()))
        {
            var (_, output) = RunPwsh(pwsh, f, Placeholder, gh: false);
            Assert.Contains("no release signing key is published yet", output);
            Assert.Contains("Provenance not checked", output);
        }
    }

    [Fact]
    public void Install_sh_refuses_another_key_with_and_without_gh_and_passes_its_own()
    {
        if (Sh() is not { } sh) return;
        using var key = NewKey();
        using var other = NewKey();
        foreach (var gh in new[] { false, true })
        {
            using var f = new Fixture(TarArchive());
            f.SignWith(other);
            var (code, output) = RunSh(sh, f, PublicKeyOf(key), gh);
            Assert.True(code != 0, output);
            Assert.Contains("does not verify with the release key", output);
            Assert.DoesNotContain("Provenance verified", output);
        }
        using (var f = new Fixture(TarArchive()))
        {
            f.SignWith(key);
            var (code, output) = RunSh(sh, f, PublicKeyOf(key), gh: true);
            Assert.True(code == 0, output);
            Assert.Contains("Signature verified", output);
            Assert.Contains("Provenance verified", output);
        }
        using (var f = new Fixture(TarArchive()))
        {
            var (code, output) = RunSh(sh, f, Placeholder, gh: false);
            Assert.True(code == 0, output);
            Assert.Contains("no release signing key is published yet", output);
        }
    }
}
