using Corvus.Native.Providers.Live;

namespace Corvus.Tests;

/// <summary>Worker folders left by ended servers are swept when the next worker starts.</summary>
public sealed class FridaWorkerFolderTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private string Folder(string name)
    {
        var folder = Directory.CreateDirectory(Path.Combine(_dir.File("live-temp"), name)).FullName;
        File.WriteAllText(Path.Combine(folder, "frida-agent.dll"), "x");
        return folder;
    }

    [Fact]
    public void A_worker_folder_of_an_ended_server_is_removed_at_start()
    {
        var ended = Folder("999999999-0123456789ab");
        var old = Folder("0123456789ab");
        var live = Folder($"{Environment.ProcessId}-0123456789ab");
        FridaBackend.SweepWorkerFolders(_dir.File("live-temp"));
        Assert.False(Directory.Exists(ended));
        Assert.False(Directory.Exists(old));
        Assert.True(Directory.Exists(live));
    }

    [Fact]
    public void A_worker_folder_with_a_held_file_stays_until_it_is_released()
    {
        var held = Folder("999999999-0123456789ab");
        var file = Path.Combine(held, "frida-agent.dll");
        using (new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            FridaBackend.SweepWorkerFolders(_dir.File("live-temp"));
            if (OperatingSystem.IsWindows()) Assert.True(File.Exists(file));
        }
        FridaBackend.SweepWorkerFolders(_dir.File("live-temp"));
        Assert.False(Directory.Exists(held));
    }
}
