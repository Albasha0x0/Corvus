using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Annotations;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>save_assembly / save_native: the original is recognized by file identity, replaced only with replaceOriginal, and never once changed on disk.</summary>
public class SaveIdentityTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private string CopyFixture()
    {
        var real = Directory.CreateDirectory(_dir.File("real")).FullName;
        var copy = Path.Combine(real, "App.dll");
        File.Copy(Env.FixturePath, copy);
        return copy;
    }

    private static void Rename(Env env) => env.Edit(() => env.Edits.Rename(env.One("Account::CheckPreview"), "HasPreview"));

    [DirectoryLinkFact]
    public void OriginalThroughADirectoryLink_IsBackedUpBeforeItIsReplaced()
    {
        var original = CopyFixture();
        var before = File.ReadAllBytes(original);
        Links.CreateDirectoryLink(_dir.File("link"), Path.GetDirectoryName(original)!);
        using var env = new Env(original);
        Rename(env);

        var message = env.Edits.Save(env.Fixture, Path.Combine(_dir.File("link"), "App.dll"), overwrite: false, replaceOriginal: true);
        Assert.Contains("backed up", message);
        Assert.Equal(before, File.ReadAllBytes(original + ".bak"));
        Assert.NotEqual(before, File.ReadAllBytes(original));
    }

    [HardLinkFact]
    public void OriginalThroughAHardLink_IsRecognized()
    {
        var original = CopyFixture();
        var before = File.ReadAllBytes(original);
        var hard = _dir.File("hard.dll");
        Links.CreateHardLink(hard, original);
        Assert.True(FileIdentity.Same(hard, original));
        Assert.False(FileIdentity.Same(hard, Env.FixturePath));
        using var env = new Env(original);
        Rename(env);

        Assert.Contains("is the loaded original", Assert.Throws<ToolError>(() => env.Edits.Save(env.Fixture, hard, overwrite: true)).Message);
        Assert.Contains("backed up", env.Edits.Save(env.Fixture, hard, overwrite: false, replaceOriginal: true));
        Assert.Equal(before, File.ReadAllBytes(hard + ".bak"));
    }

    [Fact]
    public void ShortAndRelativeSpellings_AreTheSameFile()
    {
        var original = CopyFixture();
        var dotted = Path.Combine(_dir.Path, "real", ".", "..", "real", "App.dll");
        Assert.True(FileIdentity.Same(dotted, original));
        Assert.True(FileIdentity.Same(original.ToUpperInvariant(), original) || !OperatingSystem.IsWindows());
        Assert.NotNull(FileIdentity.Id(original));
    }

    [Fact]
    public void Original_IsReplacedOnlyWithReplaceOriginal()
    {
        var original = CopyFixture();
        var loaded = File.ReadAllBytes(original);
        using var env = new Env(original);
        Rename(env);

        var error = Assert.Throws<ToolError>(() => env.Edits.Save(env.Fixture, original, overwrite: true));
        Assert.Equal(ErrorCode.Conflict, error.Code);
        Assert.Contains("replaceOriginal=true", error.Message);
        Assert.Equal(loaded, File.ReadAllBytes(original));
        Assert.False(File.Exists(original + ".bak"));
    }

    [Fact]
    public void Versioned_WritesTheNextFreeNumberedCopy()
    {
        var original = CopyFixture();
        var loaded = File.ReadAllBytes(original);
        using var env = new Env(original);
        Rename(env);
        var dir = Path.GetDirectoryName(original)!;

        env.Edits.Save(env.Fixture, null, overwrite: false, versioned: true);
        env.Edits.Save(env.Fixture, null, overwrite: false, versioned: true);
        env.Edits.Save(env.Fixture, original, overwrite: false, versioned: true);
        Assert.True(File.Exists(Path.Combine(dir, "App.patched.1.dll")));
        Assert.True(File.Exists(Path.Combine(dir, "App.patched.2.dll")));
        Assert.True(File.Exists(Path.Combine(dir, "App.1.dll")));
        Assert.Equal(loaded, File.ReadAllBytes(original));
    }

    [Fact]
    public void OriginalSavedOverBefore_IsReplacedAgain()
    {
        var original = CopyFixture();
        var loaded = File.ReadAllBytes(original);
        using var env = new Env(original);
        Rename(env);
        env.Edits.Save(env.Fixture, original, overwrite: false, replaceOriginal: true);
        env.Edit(() => env.Edits.Rename(env.One("Account::Score"), "Rating"));

        env.Edits.Save(env.Fixture, original, overwrite: false, replaceOriginal: true);
        Assert.Equal(loaded, File.ReadAllBytes(original + ".bak"));
        using var saved = new Env(original);
        Assert.Equal("Rating", saved.One("Account::Rating").Member.Name.String);
    }

    [Fact]
    public void OriginalChangedOnDiskSinceLoad_IsNotReplaced()
    {
        var original = CopyFixture();
        using var env = new Env(original);
        Rename(env);
        var changed = File.ReadAllBytes(original).Append((byte)0x42).ToArray();
        File.WriteAllBytes(original, changed);

        var error = Assert.Throws<ToolError>(() => env.Edits.Save(env.Fixture, original, overwrite: false, replaceOriginal: true));
        Assert.Equal(ErrorCode.ChangedOnDisk, error.Code);
        Assert.Contains("changed on disk since load", error.Message);
        Assert.Equal(changed, File.ReadAllBytes(original));
        Assert.False(File.Exists(original + ".bak"));
    }

    [Fact]
    public void FailedCheckBeforeReplace_LeavesTheTargetUntouched()
    {
        var path = _dir.File("target.bin");
        File.WriteAllText(path, "old");
        string? seen = null;
        Assert.Throws<InvalidOperationException>(() => SafeFile.WriteAllBytes(path, "new"u8, overwrite: true, temp =>
        {
            seen = temp;
            Assert.Equal("new", File.ReadAllText(temp));
            throw new InvalidOperationException("verification failed");
        }));
        Assert.Equal("old", File.ReadAllText(path));
        Assert.False(File.Exists(seen));
    }

    // ---- native ----

    private static byte[] TinyImage()
    {
        var b = new PeBuilder { Is64 = true, Machine = 0x8664, ImageBase = 0x140000000 };
        var code = new byte[64];
        code[0] = 0xB8; code[1] = 0x01; code[5] = 0xC3; // mov eax,1 ; ret
        for (int i = 6; i < code.Length; i++) code[i] = 0x90;
        b.EntryPoint = b.Add(".text", code, 0x60000020).Rva;
        return b.Build();
    }

    private sealed class NativeHarness : IDisposable
    {
        public readonly Env Env = new();
        public readonly NativeCodeService Code;
        public readonly NativeEditService Edits;

        public NativeHarness(string annotations)
        {
            Code = new NativeCodeService(Env.Workspace, Env.Options, null, new AnnotationStore(annotations));
            Edits = new NativeEditService(Env.Workspace, Code);
        }

        public async Task<LoadedNative> Patched(string path)
        {
            var native = Env.Workspace.LoadAny(path).Native!;
            var index = await Code.Index(native, null, default);
            Edits.ApplyPatch(native, index, Edits.PreparePatch(index, native.Image.EntryPointRva, [0xCC], force: false, "int3"), dryRun: false);
            return native;
        }

        public void Dispose() => Env.Dispose();
    }

    [DirectoryLinkFact]
    public async Task Native_OriginalThroughALink_IsVerifiedAndBackedUp()
    {
        var real = Directory.CreateDirectory(_dir.File("nreal")).FullName;
        var original = Path.Combine(real, "tiny.dll");
        var before = TinyImage();
        File.WriteAllBytes(original, before);
        Links.CreateDirectoryLink(_dir.File("nlink"), real);
        using var h = new NativeHarness(_dir.File("ann"));
        var native = await h.Patched(original);

        var report = h.Edits.Save(native, Path.Combine(_dir.File("nlink"), "tiny.dll"), overwrite: false, stripSignature: false, replaceOriginal: true);
        Assert.Contains("Verified", report);
        Assert.Contains("backed up", report);
        Assert.Equal(before, File.ReadAllBytes(original + ".bak"));
        Assert.Equal(0xCC, File.ReadAllBytes(original)[(int)Offset(native)]);
        Assert.Empty(Directory.GetFiles(real, "*.tmp"));
    }

    [Fact]
    public async Task Native_OriginalIsReplacedOnlyWithReplaceOriginal_AndVersionedSkipsIt()
    {
        var original = _dir.File("tiny.dll");
        File.WriteAllBytes(original, TinyImage());
        using var h = new NativeHarness(_dir.File("ann"));
        var native = await h.Patched(original);

        Assert.Contains("replaceOriginal=true", Assert.Throws<ToolError>(() => h.Edits.Save(native, original, overwrite: true, stripSignature: false)).Message);
        Assert.Equal(TinyImage(), File.ReadAllBytes(original));
        Assert.Contains("Verified", h.Edits.Save(native, original, overwrite: false, stripSignature: false, versioned: true));
        Assert.Equal(0xCC, File.ReadAllBytes(_dir.File("tiny.1.dll"))[(int)Offset(native)]);
        Assert.Equal(TinyImage(), File.ReadAllBytes(original));
    }

    [Fact]
    public async Task Native_OriginalSavedOverBefore_IsReplacedAgain()
    {
        var original = _dir.File("tiny.dll");
        File.WriteAllBytes(original, TinyImage());
        using var h = new NativeHarness(_dir.File("ann"));
        var native = await h.Patched(original);
        h.Edits.Save(native, original, overwrite: false, stripSignature: false, replaceOriginal: true);

        Assert.Contains("Verified", h.Edits.Save(native, original, overwrite: false, stripSignature: false, replaceOriginal: true));
        Assert.Equal(TinyImage(), File.ReadAllBytes(original + ".bak"));
        Assert.Equal(0xCC, File.ReadAllBytes(original)[(int)Offset(native)]);
    }

    [Fact]
    public async Task Native_OriginalChangedOnDiskSinceLoad_IsNotReplaced()
    {
        var original = _dir.File("tiny.dll");
        File.WriteAllBytes(original, TinyImage());
        using var h = new NativeHarness(_dir.File("ann"));
        var native = await h.Patched(original);
        var changed = TinyImage().Append((byte)1).ToArray();
        File.WriteAllBytes(original, changed);

        var error = Assert.Throws<ToolError>(() => h.Edits.Save(native, original, overwrite: false, stripSignature: false, replaceOriginal: true));
        Assert.Contains("changed on disk since load", error.Message);
        Assert.Equal(changed, File.ReadAllBytes(original));
        Assert.False(File.Exists(original + ".bak"));
    }

    private static long Offset(LoadedNative native)
    {
        native.Image.TryRvaToFileOffset(native.Image.EntryPointRva, out var off);
        return off;
    }
}
