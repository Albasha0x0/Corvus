using Corvus.Native.Dump.Managed;
using Corvus.Native.Live;
using Microsoft.Diagnostics.Runtime;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>Assemblies the .NET runtime loaded from memory rather than from a mapped file.</summary>
public static class ManagedImages
{
    /// <summary>
    /// The in-memory assemblies the runtime lists, emitted ones with base 0; empty without a readable runtime.
    /// </summary>
    public static IReadOnlyList<RebuildTarget> InMemoryAssemblies(IProcessMemory memory, CancellationToken ct)
    {
        // The DAC is signature-checked and never downloaded, as open_minidump does by default.
        var request = new DacRequest();
        try
        {
            ClrDecoder? decoder = null;
            switch (memory)
            {
                case MinidumpFile dump when ClrDecoder.RuntimeModule(dump) != null:
                    decoder = ClrDecoder.Open(MinidumpFile.Open(dump.Path), _ => null, [], request, ct).GetAwaiter().GetResult();
                    break;
                case LiveProcess process when ClrDecoder.RuntimeModule(process) != null:
                    decoder = OpenLive(process.Pid, request, ct);
                    break;
            }
            if (decoder == null) return [];
            using (decoder)
            {
                lock (decoder.Gate)
                {
                    if (decoder.Runtime is not { } runtime) return [];
                    return List(runtime, memory, ct);
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return [];
        }
    }

    private static ClrDecoder? OpenLive(int pid, DacRequest request, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return null;
        var reader = new LiveDataReader(LiveProcess.Attach(pid, ct));
        try
        {
            // The decoder owns the reader once it opens.
            return ClrDecoder.OpenLive(reader, request, ct).GetAwaiter().GetResult();
        }
        catch
        {
            reader.Dispose();
            throw;
        }
    }

    private static List<RebuildTarget> List(ClrRuntime runtime, IProcessMemory memory, CancellationToken ct)
    {
        var found = new List<RebuildTarget>();
        foreach (var module in runtime.EnumerateModules())
        {
            ct.ThrowIfCancellationRequested();
            bool dynamic = module.IsDynamic;
            if (!dynamic && (module.ImageBase == 0 || module.Size == 0)) continue;
            if (!dynamic && !string.IsNullOrEmpty(module.Name) && memory.ModuleAt(module.ImageBase) != null) continue;
            found.Add(new RebuildTarget(SimpleName(module) + ".dll", dynamic ? 0 : module.ImageBase,
                dynamic ? 0 : (uint)Math.Min(module.Size, uint.MaxValue), ModuleOrigin.Managed));
        }
        return found;
    }

    private static string SimpleName(ClrModule module)
    {
        string? name = module.AssemblyName;
        if (string.IsNullOrEmpty(name)) name = module.Name;
        if (string.IsNullOrEmpty(name)) return "assembly_" + module.Address.ToString("x");
        try { return new System.Reflection.AssemblyName(name).Name ?? name; }
        catch (Exception ex) when (ex is ArgumentException or System.IO.FileLoadException) { return Path.GetFileNameWithoutExtension(name); }
    }
}
