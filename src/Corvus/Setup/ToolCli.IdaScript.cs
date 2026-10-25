using Corvus.Native.Providers;
using Corvus.Native.Providers.Ida;

namespace Corvus.Setup;

internal static partial class ToolCli
{
    // Writes the connect script and the worker it imports; default folder: <IDA user directory>/corvus.
    private static int IdaScript(CliArgs a, CliIo io)
    {
        if (a.Positionals.Count > 1) throw new UsageException("ida-script takes at most one folder.");
        var folder = Path.GetFullPath(a.Positionals is [var given] ? given : Path.Combine(IdaInstallation.UserDirectories()[^1], "corvus"));
        var script = WriteIdaScripts(folder);
        io.Out.WriteLine(script);
        io.Error.WriteLine($"In IDA, with the database open: File > Script file > {script}. Then start Corvus with {IdaConnection.Variable}=1.");
        return Exit.Ok;
    }

    /// <summary>Writes corvus_connect.py and ida_worker.py into <paramref name="folder"/> and returns the connect script's path.</summary>
    internal static string WriteIdaScripts(string folder)
    {
        Directory.CreateDirectory(folder);
        File.WriteAllBytes(Path.Combine(folder, "ida_worker.py"), EmbeddedScript.Read(IdaProvider.WorkerResource));
        var script = Path.Combine(folder, "corvus_connect.py");
        File.WriteAllBytes(script, EmbeddedScript.Read(IdaConnection.ScriptResource));
        return script;
    }
}
