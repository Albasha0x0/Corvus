using Corvus.Native.Annotations;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Names migrated to a new build are saved names after a restart.</summary>
public sealed class RestartStateBuildTests
{
    // The second process starts with only the saved sidecars.
    [Fact]
    public async Task Names_migrated_in_one_process_are_carried_in_the_next()
    {
        using var dir = new TempDir();
        var (v1, v2) = (dir.File("a.dll"), dir.File("b.dll"));
        File.WriteAllBytes(v1, NativePeTests.KitchenSink(is64: true));
        File.WriteAllBytes(v2, [.. NativePeTests.KitchenSink(is64: true), 0]);
        var annotations = dir.File("ann");
        uint first;
        using (var a = new Env())
        {
            var code = new NativeCodeService(a.Workspace, a.Options, null, new AnnotationStore(annotations));
            var oldNative = a.Workspace.LoadAny(v1).Native!;
            a.Workspace.LoadAny(v2);
            var oldIndex = await code.Index(oldNative, null, default);
            first = oldIndex.AddressOfName("First")!.Value;
            var edit = new NativeEditTools(a.Workspace, code, new NativeEditService(a.Workspace, code));
            await edit.RenameNative(v1, "First", "Renamed", dryRun: false);
            var (done, _) = await BuildToolCalls.Collected<NativeDiffTools.MigrationReport>(() => new NativeDiffTools(a.Workspace, code).MigrateNativeNames(v1, v2, dryRun: false));
            Assert.Equal((1, true), (done.Set, done.Applied));
        }

        using var b = new Env();
        var restored = new NativeCodeService(b.Workspace, b.Options, null, new AnnotationStore(annotations));
        b.Workspace.LoadAny(v1);
        var newNative = b.Workspace.LoadAny(v2).Native!;
        Assert.Equal("Renamed", restored.Annotations(newNative).NameAt(first));
        Assert.Equal("Renamed", (await restored.Index(newNative, null, default)).NameAt(first));
        var (again, _) = await BuildToolCalls.Collected<NativeDiffTools.MigrationReport>(() => new NativeDiffTools(b.Workspace, restored).MigrateNativeNames(v1, v2));
        Assert.Equal("same_name", Assert.Single(again.Items).Reason);
        Assert.Equal(0, again.Set);
    }
}
