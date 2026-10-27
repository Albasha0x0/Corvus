using System.Text.Json.Nodes;
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
    // A held thread loads no module, so a runtime that could not be read at a stop is also tried again on time.
    internal static readonly TimeSpan ClrRetryPeriod = TimeSpan.FromSeconds(5);

    /// <summary>Whether the runtime is tried again: the program's modules changed, or <see cref="ClrRetryPeriod"/> passed since the last try.</summary>
    internal static bool ClrRetryDue(int modules, int triedAt, long nowTicks, long triedTicks) =>
        modules != triedAt || nowTicks - triedTicks >= (long)ClrRetryPeriod.TotalMilliseconds;

    // A runtime not yet readable is tried again when the modules change or ClrRetryPeriod has passed.
    /// <summary>The session's .NET runtime, refreshed on each call; null without one; an unloadable DAC is named in <see cref="LiveClr.Unavailable"/>.</summary>
    public async Task<LiveClr?> ClrAsync(LiveSession session, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows() || session.ProcessId == 0) return null;
        await session.ClrOpen.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            int modules;
            lock (session.Modules) modules = session.Modules.Count;
            bool due = ClrRetryDue(modules, session.ClrTriedAt, Environment.TickCount64, session.ClrTriedTicks);
            if (session.Clr is { } open)
            {
                if (!(open.Unavailable?.StartsWith("load_failed", StringComparison.Ordinal) ?? false) || !due)
                {
                    open.Refresh();
                    return open;
                }
                open.Dispose();
                session.Clr = null;
            }
            if (session.Closed || session.Ended != null || !due || !HostsRuntime(session)) return null;
            (session.ClrTriedAt, session.ClrTriedTicks) = (modules, Environment.TickCount64);
            try { session.Clr = await LiveClr.OpenAsync(session.ProcessId, new Native.Dump.Managed.DacRequest(Download: session.DownloadDac) { Decoder = DecoderPath }, ct).ConfigureAwait(false); }
            catch (ToolError e)
            {
                // The process exited meanwhile, or the open failed (a 32-bit decoder that did not start in time).
                session.Clr = null;
                if (!session.ClrOpenFailureNoted && !session.Closed && session.Ended == null)
                {
                    session.ClrOpenFailureNoted = true;
                    session.Add("error", null, null, $"the program's runtime could not be read ({e.Message}); retried at the next module load or after {ClrRetryPeriod.TotalSeconds:0} s");
                }
            }
            if (session.Clr != null)
            {
                session.Clr.Stopped = why => DecoderStopped(session, why);
                session.Clr.Failed = why => session.Add("error", null, null, $"a read of the program's runtime failed ({why}); failed reads give no managed names and the decoder keeps running");
            }
            return session.Clr;
        }
        finally { session.ClrOpen.Release(); }
    }

    /// <summary>After the 32-bit decoder stops, names managed code and counts managed coverage from JIT compiles; noted once.</summary>
    private void DecoderStopped(LiveSession session, string why) => _ = DecoderStoppedAsync(session, why);

    private async Task DecoderStoppedAsync(LiveSession session, string why)
    {
        var runs = _coverage.Values.Where(r => r.Session == session.Id && r.AssemblyPath != null && r.JitBodies == null && r.State == "recording").ToList();
        // Arm the counting first, so the event marks where "from now on" starts.
        await Task.WhenAll(runs.Select(run => CountCompilesAsync(session, run))).ConfigureAwait(false);
        session.Add("error", null, null, $"the 32-bit .NET decoder stopped ({why}); managed frames are named from the JIT's compiles only"
                                         + (runs.Count > 0 ? $", and {string.Join(", ", runs.Select(r => r.Id))} count{(runs.Count == 1 ? "s" : "")} first compiles from now on" : ""));
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
        return new(address, m.Assembly, null, module != null ? (uint)(address - module.Base) : 0, m.Signature, m.Start == 0 ? 0 : (uint)(address - m.Start), null, null)
            { OffsetUnknown = m.Start == 0 };
    }

    /// <summary>A stop's native frames down to the first managed one, then the runtime's managed walk; the backend's frames when it cannot walk.</summary>
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

    // Without an assembly, the program's own assembly and its loaded modules are searched.
    /// <summary>The managed method <paramref name="where"/> names (<c>[assembly!]Ns.Type::Method</c>); null for a native name; throws not_found when undefined.</summary>
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

    /// <summary>An assembly from a single-file app's bundle, extracted once to a cache keyed by the app's path, size and time; null when absent.</summary>
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

    /// <summary>The newest .NET Framework 4 GAC copy of <paramref name="file"/>, source of its loaded native image; null when absent.</summary>
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

    /// <summary>Defers a point on a managed method until its assembly loads, then until it is compiled; null when not managed or it has code.</summary>
    private async Task<(LiveDeferred Point, bool Held)?> DeferManagedAsync(LiveSession session, string where, bool watch, int perSecond, int rawArguments, string? id, CancellationToken ct)
    {
        if (await ManagedTargetAsync(session, where, ct).ConfigureAwait(false) is not { } target) return null;
        bool loaded;
        lock (session.Modules)
            loaded = IsBundled(target.Path) || session.Modules.Any(m => InputFiles.SamePath(m.Path, target.Path)
                || NativeImageOf(m.Name)?.Equals(target.File, StringComparison.OrdinalIgnoreCase) == true);
        if (!loaded) return await DeferAsync(session, $"{target.File}!{target.Member}", watch, perSecond, rawArguments, ct, id).ConfigureAwait(false);
        if (await ManagedCodeAsync(session, target, ct).ConfigureAwait(false) != null) return null;
        // Without the runtime only the backend's JIT hook tells when the method is compiled.
        var unreadable = session.Clr?.Unavailable is { } reason && !reason.StartsWith("load_failed", StringComparison.Ordinal) ? reason : null;
        ToolError Unreadable() => new(ErrorCode.Unsupported, $"{target.Display} is JIT-compiled and the program's runtime cannot be read: {unreadable}.",
            "publish the program ReadyToRun so its methods have code before they run, or stop at a native function it calls");
        var d = new LiveDeferred(id ?? (watch ? session.NextWatchId() : session.NextPointId()), $"{target.File}!{target.Member}", target.Display, watch, perSecond, rawArguments)
        {
            UntilCompiled = true,
            Unreadable = unreadable,
            IlBodies = IlBodies(session, target),
        };
        if (unreadable != null && d.IlBodies.Count == 0) throw Unreadable();
        lock (session.Deferred) session.Deferred.Add(d);
        // The backend holds the compiling thread so the first call stops; without the hook the runtime is polled for code.
        foreach (var il in d.IlBodies)
            try { await session.Worker.RequestAsync("watch_jit", new JsonObject { ["il"] = $"0x{il:X}" }, RequestTimeout, ct).ConfigureAwait(false); }
            catch (ToolError) when (unreadable != null)
            {
                lock (session.Deferred) session.Deferred.Remove(d);
                throw Unreadable();
            }
            // A worker without the op.
            catch (ToolError) { break; }
        session.CompileCheck ??= new Timer(_ => _ = CheckCompiledAsync(session), null, CompileCheckPeriod, CompileCheckPeriod);
        return (d, false);
    }

    /// <summary>Addresses of the method's IL body in the loader's image and, when different, the runtime's own mapping; empty when unmapped.</summary>
    private IReadOnlyList<ulong> IlBodies(LiveSession session, LiveManagedTarget target)
    {
        var bases = new List<(ulong Base, bool Flat)>();
        lock (session.Modules)
            if (session.Modules.FirstOrDefault(m => InputFiles.SamePath(m.Path, target.Path)) is { } module) bases.Add((module.Base, false));
        if (session.Clr is { Unavailable: null } clr && clr.ModuleImage(target.Path) is { } image && !bases.Contains(image)) bases.Add(image);
        if (bases.Count == 0) return [];
        return workspace.Read(() =>
        {
            if (workspace.FindByPath(target.Path) is not { } asm || asm.Module.ResolveToken(target.MethodToken) is not MethodDef { RVA: var rva } || rva == 0)
                return (IReadOnlyList<ulong>)[];
            var pe = asm.Module.Metadata.PEImage;
            var offset = pe.ToFileOffset(rva);
            var reader = pe.CreateReader(offset);
            var flags = reader.ReadUInt16();
            // A tiny header is one byte; a fat header gives its size in dwords.
            uint header = (flags & 3) == 2 ? 1u : (uint)(flags >> 12) * 4;
            return [.. bases.Select(b => b.Base + (b.Flat ? (uint)offset : (uint)rva) + header)];
        });
    }

    /// <summary>Sets the point deferred on the IL body at <paramref name="il"/> at its new <paramref name="code"/>, then releases the held thread.</summary>
    private async Task SetCompiledAsync(LiveSession session, ulong il, ulong code, IReadOnlyList<ulong> callers, long? thread)
    {
        try
        {
            LiveDeferred? d;
            lock (session.Deferred)
            {
                d = session.Deferred.FirstOrDefault(x => x.UntilCompiled && x.IlBodies.Contains(il));
                if (d != null) session.Deferred.Remove(d);
            }
            if (d == null)
            {
                if (session.Bound(il) is { } bound) await RecompiledAsync(session, bound, code, callers).ConfigureAwait(false);
                return;
            }
            var bang = d.Module.IndexOf('!');
            session.AddCompiled(new(code, d.Module[..bang], null, 0, d.Module[(bang + 1)..], 0, null, null));
            try
            {
                LiveFrameName at;
                string plan = "";
                if (d.Watch)
                {
                    var w = await WatchAsync(session, $"0x{code:X}", d.PerSecond, d.RawArguments, CancellationToken.None, d.Id).ConfigureAwait(false);
                    (at, plan) = (w.At, $": {w.Plan.Prototype} ({w.Plan.Source})");
                }
                else
                {
                    var p = await SetAsync(session, $"0x{code:X}", CancellationToken.None, d.Id).ConfigureAwait(false);
                    lock (session.StopPoints) session.StopPoints[d.Id] = p with { Where = d.Where };
                    at = p.At;
                }
                session.Add("module", null, at.Address, $"deferred {(d.Watch ? "watch" : "stop point")} {d.Id} set at {at.Display}{plan} ({d.Module} compiled)");
                await BindAsync(session, new LiveJitBinding(d.Id, d.Watch, d.Module, d.IlBodies), code, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception e) when (e is ToolError or TimeoutException or OperationCanceledException)
            {
                session.Add("error", null, null, $"deferred {d.Id} at {d.Where} could not be set ({d.Module} compiled): {e.Message}");
            }
        }
        finally
        {
            if (thread is { } tid)
                try { await session.Worker.RequestAsync("release_load", new JsonObject { ["thread"] = tid }, RequestTimeout, CancellationToken.None).ConfigureAwait(false); }
                catch (Exception e) when (e is ToolError or TimeoutException or OperationCanceledException) { }
        }
    }

    /// <summary>Makes a point at a managed method's code follow its recompiles, since tiered compilation moves calls to new code.</summary>
    private async Task FollowRecompilesAsync(LiveSession session, string where, ulong address, string id, bool watch, CancellationToken ct)
    {
        try
        {
            if (await ManagedTargetAsync(session, where, ct).ConfigureAwait(false) is not { } target
                || await ManagedCodeAsync(session, target, ct).ConfigureAwait(false) is not { } code || code.Code != address) return;
            await BindAsync(session, new LiveJitBinding(id, watch, target.Display, IlBodies(session, target)), address, ct).ConfigureAwait(false);
        }
        // The point is set; only later versions of the method go unhooked.
        catch (ToolError) { }
    }

    private static async Task BindAsync(LiveSession session, LiveJitBinding binding, ulong code, CancellationToken ct)
    {
        if (binding.IlBodies.Count == 0) return;
        binding.Code.Add(code);
        session.Bind(binding);
        foreach (var il in binding.IlBodies)
            try { await session.Worker.RequestAsync("watch_jit", new JsonObject { ["il"] = $"0x{il:X}" }, RequestTimeout, ct).ConfigureAwait(false); }
            // A worker without the op.
            catch (ToolError) { break; }
    }

    // An on-stack replacement compile is entered mid-method; it is recognized by the method among the compiling thread's callers.
    /// <summary>Adds a hook at a recompiled method's new code; the old code runs until calls switch over.</summary>
    private async Task RecompiledAsync(LiveSession session, LiveJitBinding bound, ulong code, IReadOnlyList<ulong> callers)
    {
        List<ulong> known;
        lock (bound.Code) known = [.. bound.Code];
        if (known.Contains(code)) return;
        LiveWatchState? w = null;
        bool live;
        if (bound.Watch) lock (session.Watches) live = session.Watches.TryGetValue(bound.Id, out w) && !w.Cleared;
        else lock (session.StopPoints) live = session.StopPoints.ContainsKey(bound.Id);
        if (!live) return;
        if (await ClrAsync(session, CancellationToken.None).ConfigureAwait(false) is { Unavailable: null } clr
            && callers.Any(f => clr.MethodAt(f) is { } m && known.Contains(m.Start))) return;
        var bang = bound.Name.IndexOf('!');
        session.AddCompiled(new(code, bound.Name[..bang], null, 0, bound.Name[(bang + 1)..], 0, null, null));
        try
        {
            var args = new JsonObject { ["id"] = bound.Id, ["address"] = $"0x{code:X}" };
            if (w != null)
            {
                args["args"] = new JsonArray(w.Plan.ScriptKinds.Select(k => (JsonNode)k).ToArray());
                args["perSecond"] = w.PerSecond;
            }
            await session.Worker.RequestAsync(w != null ? "watch" : "set", args, RequestTimeout, CancellationToken.None).ConfigureAwait(false);
            lock (bound.Code) bound.Code.Add(code);
            session.Add("module", null, code, $"{(w != null ? "watch" : "stop point")} {bound.Id} also set at 0x{code:X}: {bound.Name} compiled again");
        }
        catch (Exception e) when (e is ToolError or TimeoutException or OperationCanceledException)
        {
            session.Add("error", null, code, $"{bound.Id} could not follow {bound.Name} to its new code at 0x{code:X}: {e.Message}");
        }
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
                    // Cleared meanwhile.
                    if (!session.Deferred.Remove(d)) continue;
                await SetDueAsync(session, $"{d.Module} {(code.Kind == "JIT" ? "compiled" : "bound to its ReadyToRun code")}", [d]).ConfigureAwait(false);
            }
        }
        catch (Exception e) when (e is ToolError or TimeoutException or OperationCanceledException or ObjectDisposedException) { }
        finally { Volatile.Write(ref session.CompileChecking, 0); }
    }
}
