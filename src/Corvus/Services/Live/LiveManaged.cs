using dnlib.DotNet;
using Corvus.Core;

namespace Corvus.Services;

/// <summary>A managed method named for a stop point or watch: its assembly's path, its tokens, and how it was named and is shown.</summary>
internal sealed record LiveManagedTarget(string Path, int TypeToken, int MethodToken, string Member, string Label)
{
    /// <summary>The file name the process loads the assembly by.</summary>
    public string File => System.IO.Path.GetFileName(Path);
    public string Display => $"{File}!{Label}";
}

public sealed partial class LiveSessionService
{
    private static readonly TimeSpan CompileCheckPeriod = TimeSpan.FromMilliseconds(250);

    /// <summary>
    /// The session's .NET runtime, opened on first use once the program has loaded one and read afresh on each call; null
    /// for a program without one. A runtime whose DAC could not be loaded is returned with the reason in
    /// <see cref="LiveClr.Unavailable"/>; one that could not be read yet (still starting) is tried again when the modules change.
    /// </summary>
    public async Task<LiveClr?> ClrAsync(LiveSession session, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows() || session.ProcessId == 0) return null;
        await session.ClrOpen.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            int modules;
            lock (session.Modules) modules = session.Modules.Count;
            if (session.Clr is { } open)
            {
                if (!(open.Unavailable?.StartsWith("load_failed", StringComparison.Ordinal) ?? false) || modules == session.ClrTriedAt)
                {
                    open.Refresh();
                    return open;
                }
                open.Dispose();
                session.Clr = null;
            }
            if (session.Closed || session.Ended != null || modules == session.ClrTriedAt || !HostsRuntime(session)) return null;
            session.ClrTriedAt = modules;
            try { session.Clr = await LiveClr.OpenAsync(session.ProcessId, ct).ConfigureAwait(false); }
            catch (ToolError) { session.Clr = null; } // the process exited meanwhile
            return session.Clr;
        }
        finally { session.ClrOpen.Release(); }
    }

    /// <summary>Whether the program has loaded a .NET runtime: its library, or a single-file host's runtime export.</summary>
    private bool HostsRuntime(LiveSession session)
    {
        List<LiveModuleState> modules;
        lock (session.Modules) modules = [.. session.Modules];
        return modules.Any(m => m.Name.Equals("coreclr.dll", StringComparison.OrdinalIgnoreCase) || m.Name.Equals("clr.dll", StringComparison.OrdinalIgnoreCase))
               || modules.FirstOrDefault() is { } main && ExportTable(main.Path).Any(e => e.Name == "DotNetRuntimeInfo");
    }

    /// <summary>A JIT-compiled or ReadyToRun method's name at <paramref name="address"/>, from the session's runtime as last read.</summary>
    private static LiveFrameName? ManagedName(LiveSession session, ulong address, LiveModuleState? module)
    {
        if (session.Clr is not { Unavailable: null } clr || clr.MethodAt(address) is not { } m) return null;
        return new(address, m.Assembly, null, module != null ? (uint)(address - module.Base) : 0, m.Signature, (uint)(address - m.Start), null, null);
    }

    /// <summary>
    /// A stop's frames with its managed part walked by the runtime: the backend's native frames down to the first managed
    /// one, then the managed frames the runtime finds from the stop's registers. The backend's frames when the runtime
    /// cannot walk the thread.
    /// </summary>
    public IReadOnlyList<ulong> StopFrames(LiveSession session, LiveHeldStop held)
    {
        if (session.Clr is not { Unavailable: null } clr) return held.Frames;
        var managed = clr.Frames(held.Thread, held.Registers, LiveStackWalk.MaxFrames);
        if (managed.Count == 0) return held.Frames;
        int first = -1;
        for (int i = 0; i < held.Frames.Count && first < 0; i++)
            if (held.Frames[i] == managed[0] || clr.MethodAt(held.Frames[i]) != null) first = i;
        return [.. held.Frames.Take(first < 0 ? held.Frames.Count : first), .. managed];
    }

    /// <summary>
    /// The managed method <paramref name="where"/> names (<c>Ns.Type::Method</c>, with a parameter list for an overload,
    /// or <c>assembly!Ns.Type::Method</c>), when it names no native code; null for a native name. Without an assembly the
    /// program's own assembly and the loaded ones of its modules are searched; a name none of them defines is not_found.
    /// </summary>
    private async Task<LiveManagedTarget?> ManagedTargetAsync(LiveSession session, string where, CancellationToken ct)
    {
        var t = where.Trim();
        if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase) || FileLine.IsMatch(t)) return null;
        List<LiveModuleState> modules;
        lock (session.Modules) modules = [.. session.Modules];
        var candidates = new List<LoadedAssembly>();
        string member = t;
        if (t.IndexOf('!') is > 0 and var bang)
        {
            var name = t[..bang];
            member = t[(bang + 1)..];
            if (modules.FirstOrDefault(m => ModuleNamed(m, name)) is { } m)
            {
                if (NativeImageOf(m.Name) is { } assembly) { if (GlobalAssembly(session, assembly) is { } gac) candidates.Add(gac); }
                else if (Match(m) != null) return null;
                else if (Managed(m.Path) is { } asm) candidates.Add(asm);
            }
            else if (AssemblyToLoad(session, name) is { } later) candidates.Add(later);
        }
        else
        {
            if (!t.Contains("::", StringComparison.Ordinal)) return null;
            try
            {
                await ResolveNativeAsync(session, t, ct).ConfigureAwait(false);
                return null;
            }
            catch (ToolError e) when (e.Code is ErrorCode.NotFound or ErrorCode.InvalidArgument) { }
            candidates.AddRange(ProgramAssemblies(session));
            candidates.AddRange(workspace.Assemblies.Where(a => modules.Any(m => InputFiles.SamePath(m.Path, a.FilePath))));
        }
        return workspace.Read(() =>
        {
            var found = new List<ResolvedSymbol>();
            ToolError? missing = null;
            foreach (var asm in candidates.Distinct())
            {
                try { found.AddRange(SymbolResolver.Resolve(workspace, asm.Id, member, SymbolKind.Method)); }
                catch (ToolError e) when (e.Code == ErrorCode.NotFound) { missing ??= e; }
            }
            if (found.Count == 0) return missing != null ? throw missing : (LiveManagedTarget?)null;
            var one = SymbolResolver.Single(found, member);
            var method = (MethodDef)one.Member;
            return new LiveManagedTarget(one.Assembly.FilePath, (int)method.DeclaringType.MDToken.Raw, (int)method.MDToken.Raw, member, Format.MemberLabel(method));
        });
    }

    /// <summary>The managed assembly at <paramref name="path"/>, loaded into the workspace; null for a native file.</summary>
    private LoadedAssembly? Managed(string path)
    {
        if (!File.Exists(path)) return null;
        try { return workspace.LoadAny(path) is { Native: null, Assembly: { } asm } ? asm : null; }
        catch (ToolError) { return null; }
    }

    /// <summary>The program's own managed assembly: the program file itself (.NET Framework), or the .dll an apphost runs.</summary>
    private IEnumerable<LoadedAssembly> ProgramAssemblies(LiveSession session)
    {
        var path = session.Spawned ? session.Program : session.Modules.FirstOrDefault()?.Path;
        if (path == null) yield break;
        if (Managed(path) is { } own) yield return own;
        else if ((Managed(Path.ChangeExtension(path, ".dll")) ?? Bundled(path, Path.GetFileNameWithoutExtension(path) + ".dll")) is { } app) yield return app;
    }

    private static string BundleCache => Native.Providers.DataFolder.Combine("bundles");

    /// <summary>
    /// An assembly bundled into the single-file app at <paramref name="program"/>, by its bundle-relative path, saved once to
    /// a cache folder named for the app's path, size and time, and loaded; null when the app bundles no such assembly.
    /// </summary>
    private LoadedAssembly? Bundled(string program, string entry)
    {
        try
        {
            var info = new FileInfo(program);
            if (!info.Exists) return null;
            var key = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes($"{info.FullName.ToUpperInvariant()}|{info.Length}|{info.LastWriteTimeUtc.Ticks}")))[..16];
            var root = Path.Combine(BundleCache, key);
            var file = SafeFile.UnderRoot(root, entry);
            if (!File.Exists(file))
            {
                if (Containers.BundleEntry(program, entry, AnalysisLimits.Default, CancellationToken.None) is not { } bytes) return null;
                SafeFile.WriteUnderRoot(root, entry, bytes, overwrite: true);
            }
            return Managed(file);
        }
        catch (Exception e) when (e is ToolError or IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>
    /// The global assembly cache's copy of <paramref name="file"/> (the newest .NET Framework 4 version), which a
    /// native image loaded in its place was compiled from; null when the cache has none.
    /// </summary>
    private LoadedAssembly? GlobalAssembly(LiveSession session, string file)
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Microsoft.NET", "assembly");
        foreach (var cache in new[] { "GAC_MSIL", session.Arch is "ia32" ? "GAC_32" : "GAC_64" })
        {
            var dir = Path.Combine(root, cache, Path.GetFileNameWithoutExtension(file));
            if (!Directory.Exists(dir)) continue;
            var path = Directory.EnumerateDirectories(dir, "v4.0_*").Select(d => Path.Combine(d, file)).Where(File.Exists)
                .OrderBy(d => d, StringComparer.OrdinalIgnoreCase).LastOrDefault();
            if (path != null && Managed(path) is { } asm) return asm;
        }
        return null;
    }

    /// <summary>True for an assembly <see cref="Bundled"/> saved: the runtime maps it from the app, never as a module of its own.</summary>
    private static bool IsBundled(string path) => path.StartsWith(BundleCache + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);

    /// <summary>A managed assembly the program has not loaded yet, by file name: its own, or one next to the program it starts.</summary>
    private LoadedAssembly? AssemblyToLoad(LiveSession session, string name)
    {
        if (ProgramAssemblies(session).FirstOrDefault(a => Path.GetFileName(a.FilePath).Equals(name, StringComparison.OrdinalIgnoreCase)
                                                           || Path.GetFileNameWithoutExtension(a.FilePath).Equals(name, StringComparison.OrdinalIgnoreCase)) is { } own)
            return own;
        if (!session.Spawned || Path.GetDirectoryName(session.Program) is not { } dir || name.Contains('/') || name.Contains('\\')) return null;
        var file = name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? name : name + ".dll";
        return Managed(Path.Combine(dir, file)) ?? Bundled(session.Program, file);
    }

    /// <summary>Where a managed method has code in the program now; null when it has none yet (or the runtime cannot be read).</summary>
    private async Task<(ulong Code, string Kind)?> ManagedCodeAsync(LiveSession session, LiveManagedTarget target, CancellationToken ct)
    {
        LiveModuleState? module;
        lock (session.Modules) module = session.Modules.FirstOrDefault(m => InputFiles.SamePath(m.Path, target.Path));
        if (await ClrAsync(session, ct).ConfigureAwait(false) is not { Unavailable: null } clr) return null;
        return clr.CodeOf(target.Path, target.TypeToken, target.MethodToken, module?.Base ?? 0);
    }

    /// <summary>
    /// Defers a stop point or watch on a managed method that has no code yet: until its assembly loads (the loading thread
    /// held, as for any module), then, for a method the runtime compiles at its first call, until it is compiled. Null
    /// when <paramref name="where"/> names no managed method or the method has code.
    /// </summary>
    private async Task<(LiveDeferred Point, bool Held)?> DeferManagedAsync(LiveSession session, string where, bool watch, int perSecond, int rawArguments, string? id, CancellationToken ct)
    {
        if (await ManagedTargetAsync(session, where, ct).ConfigureAwait(false) is not { } target) return null;
        bool loaded;
        lock (session.Modules)
            loaded = IsBundled(target.Path) || session.Modules.Any(m => InputFiles.SamePath(m.Path, target.Path)
                || NativeImageOf(m.Name)?.Equals(target.File, StringComparison.OrdinalIgnoreCase) == true);
        if (!loaded) return await DeferAsync(session, $"{target.File}!{target.Member}", watch, perSecond, rawArguments, ct, id).ConfigureAwait(false);
        if (await ManagedCodeAsync(session, target, ct).ConfigureAwait(false) != null) return null;
        var clr = session.Clr;
        if (clr?.Unavailable is { } reason && !reason.StartsWith("load_failed", StringComparison.Ordinal))
            throw new ToolError(ErrorCode.Unsupported, $"{target.Display} is JIT-compiled code, and the program's runtime cannot be read: {reason}.",
                "publish the program ReadyToRun (its methods then have code before they run), or stop at a native function it calls");
        var d = new LiveDeferred(id ?? (watch ? session.NextWatchId() : session.NextPointId()), $"{target.File}!{target.Member}", target.Display, watch, perSecond, rawArguments)
        {
            UntilCompiled = true,
        };
        lock (session.Deferred) session.Deferred.Add(d);
        session.CompileCheck ??= new Timer(_ => _ = CheckCompiledAsync(session), null, CompileCheckPeriod, CompileCheckPeriod);
        return (d, false);
    }

    /// <summary>Sets the points deferred until their method is compiled whose method has code now.</summary>
    private async Task CheckCompiledAsync(LiveSession session)
    {
        if (Interlocked.Exchange(ref session.CompileChecking, 1) == 1) return;
        try
        {
            List<LiveDeferred> waiting;
            lock (session.Deferred) waiting = [.. session.Deferred.Where(d => d.UntilCompiled)];
            if (waiting.Count == 0 || session.Closed || session.Ended != null) return;
            foreach (var d in waiting)
            {
                if (await ManagedTargetAsync(session, d.Where, CancellationToken.None).ConfigureAwait(false) is not { } target
                    || await ManagedCodeAsync(session, target, CancellationToken.None).ConfigureAwait(false) is not { } code) continue;
                lock (session.Deferred)
                    if (!session.Deferred.Remove(d)) continue; // cleared meanwhile
                await SetDueAsync(session, $"{d.Module} {(code.Kind == "JIT" ? "compiled" : "bound to its ReadyToRun code")}", [d]).ConfigureAwait(false);
            }
        }
        catch (Exception e) when (e is ToolError or TimeoutException or OperationCanceledException or ObjectDisposedException) { }
        finally { Volatile.Write(ref session.CompileChecking, 0); }
    }
}
