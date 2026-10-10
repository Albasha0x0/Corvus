using System.Diagnostics;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Pe;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Services.Analysis;
using NetDecompilerMcp.Tools;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Calls every native tool in process on one image with arguments taken from the image itself (entry point, exports,
/// imports, functions, strings, resources) and records each call: time, result size, typed error or unexpected exception.
/// </summary>
internal sealed class NativeToolHarness : IDisposable
{
    public sealed record Call(string File, string Tool, string Args, TimeSpan Elapsed, int Chars, ErrorCode? Error, string? ErrorText, Exception? Unexpected,
        bool MustSucceed)
    {
        /// <summary>An unexpected exception, an unclassified error, or a typed error where the arguments came from the image itself.</summary>
        public bool Failed => Unexpected != null || Error == ErrorCode.Failed || (MustSucceed && Error != null);

        public override string ToString() =>
            $"{Path.GetFileName(File)} {Tool}({Args}) {Elapsed.TotalMilliseconds:0} ms, {Chars} chars: " +
            (Unexpected != null ? $"{Unexpected.GetType().Name}: {Unexpected.Message}\n{Unexpected.StackTrace}" : Error != null ? ErrorText : "ok");
    }

    /// <summary>Largest result a tool may return with default paging: the server's page size plus the response budget slack.</summary>
    public static int MaxChars => new Core.ServerOptions().MaxOutputChars + 16_000;

    public ServerOptions Options { get; } = new() { TimeoutSeconds = 120 };
    public AssemblyWorkspace Workspace { get; }
    public OutputPager Pager { get; }
    public NativeCodeService Code { get; }
    public NativeTools Native { get; }
    public NativeCodeTools CodeTools { get; }
    public NativeAnalysisTools Analysis { get; }
    public ResourceTools Resources { get; }
    public WorkspaceTools WorkspaceTools { get; }
    public NativeEngineService Engines { get; } = new();
    public List<Call> Calls { get; } = [];

    /// <summary>Typed errors are accepted everywhere (mutated images): only unexpected exceptions, unclassified errors and time count.</summary>
    public bool Lenient { get; init; }

    /// <summary>Time limit of a call that does not name its own.</summary>
    public TimeSpan CallLimit { get; init; } = TimeSpan.FromSeconds(60);

    public NativeToolHarness(bool backgroundIndexing = true)
    {
        Options.BackgroundIndexing = backgroundIndexing;
        Workspace = new AssemblyWorkspace(Options);
        Pager = new OutputPager(Options);
        Code = new NativeCodeService(Workspace, Options);
        Native = new NativeTools(Workspace, Pager);
        CodeTools = new NativeCodeTools(Workspace, Code, Pager);
        Analysis = new NativeAnalysisTools(Workspace, Engines, Pager);
        var il2cpp = new Il2CppService(Workspace);
        Resources = new ResourceTools(Workspace, new ResourceService(), new DecompilerService(Workspace, Options), Pager);
        WorkspaceTools = new WorkspaceTools(Workspace, il2cpp, new AssemblyReport(Workspace, il2cpp),
            new IndexingService(Workspace, new CallGraphService(Workspace), Options), new UnpackService(Workspace));
    }

    /// <summary>Runs one tool call and records it; returns the text, or null when it failed.</summary>
    public async Task<string?> Run(string file, string tool, string args, Func<CancellationToken, Task<string>> call, bool mustSucceed = false,
        TimeSpan? limit = null)
    {
        var bound = limit ?? CallLimit;
        using var cts = new CancellationTokenSource(bound);
        var sw = Stopwatch.StartNew();
        string? text = null;
        ErrorCode? error = null;
        string? errorText = null;
        Exception? unexpected = null;
        // A call that ignores its cancellation is abandoned after a grace period and reported as a hang.
        try { text = await call(cts.Token).WaitAsync(bound + TimeSpan.FromSeconds(30)); }
        catch (ToolError e) { error = e.Code; errorText = e.Render(tool); }
        catch (OperationCanceledException e) when (cts.IsCancellationRequested) { unexpected = new TimeoutException($"cancelled after {sw.Elapsed.TotalSeconds:0.0} s", e); }
        catch (TimeoutException) { unexpected = new TimeoutException($"still running {sw.Elapsed.TotalSeconds:0} s after it was cancelled (hang)"); }
        catch (Exception e) { unexpected = e; }
        sw.Stop();
        lock (Calls) Calls.Add(new Call(file, tool, args, sw.Elapsed, text?.Length ?? 0, error, errorText, unexpected, mustSucceed && !Lenient));
        return text;
    }

    /// <summary>
    /// Loads <paramref name="path"/> through load_assembly and calls every native tool on it; <paramref name="ida"/> also
    /// decompiles the entry point. Reload and unload run last when <paramref name="unload"/> is set.
    /// </summary>
    public async Task Exercise(string path, bool ida = false, bool unload = true, TimeSpan? indexLimit = null)
    {
        var loaded = await Run(path, "load_assembly", "path", ct => WorkspaceTools.LoadAssembly(path, cancellationToken: ct));
        if (loaded == null) return;
        var native = Workspace.Read(() => Workspace.FindNative(path));
        if (native == null)
        {
            // A .NET assembly: not this harness's business.
            await Run(path, "unload_assembly", "", ct => WorkspaceTools.UnloadAssembly(path, ct));
            return;
        }
        try { await Body(path, native, ida, indexLimit); }
        finally
        {
            if (unload)
            {
                var id = native.Id;
                await Run(path, "reload_assembly", "", ct => WorkspaceTools.ReloadAssembly(id, ct), mustSucceed: true);
                await Run(path, "get_pe_info", "after reload", ct => Native.GetPeInfo(id, cancellationToken: ct), mustSucceed: true);
                await Run(path, "unload_assembly", "", ct => WorkspaceTools.UnloadAssembly(id, ct), mustSucceed: true);
            }
        }
    }

    private async Task Body(string path, LoadedNative native, bool ida, TimeSpan? indexLimit)
    {
        var id = native.Id;
        var pe = native.Image;
        string Va(uint rva) => $"0x{pe.ImageBase + rva:X}";

        await Run(path, "get_pe_info", "", ct => Native.GetPeInfo(id, cancellationToken: ct), mustSucceed: true);
        await Run(path, "get_pe_info", "page 2", ct => Native.GetPeInfo(id, offset: 1000, maxChars: 1000, cancellationToken: ct)); // offset past the end is invalid_argument
        await Run(path, "list_imports", "", ct => Native.ListImports(id, cancellationToken: ct), mustSucceed: true);
        await Run(path, "list_exports", "", ct => Native.ListExports(id, cancellationToken: ct), mustSucceed: true);
        await Run(path, "list_exports", "filter, page", ct => Native.ListExports(id, filter: "a", offset: 3, limit: 7, cancellationToken: ct), mustSucceed: true);
        var import = pe.Imports.FirstOrDefault(i => i.Name != null);
        if (import != null)
        {
            var imp = $"{import.Module}!{import.Name}";
            await Run(path, "list_imports", "module", ct => Native.ListImports(id, module: import.Module, cancellationToken: ct), mustSucceed: true);
            await Run(path, "resolve_address", imp, ct => Native.ResolveAddress(id, imp, ct), mustSucceed: true);
        }
        var export = pe.Exports.FirstOrDefault(e => e.Name != null && e.ForwardedTo == null && e.Rva < pe.SizeOfImage);
        if (export != null)
            await Run(path, "resolve_address", "export", ct => Native.ResolveAddress(id, export.Name!, ct), mustSucceed: true);
        if (pe.EntryPointRva != 0 && pe.EntryPointRva < pe.SizeOfImage)
        {
            await Run(path, "resolve_address", "entry", ct => Native.ResolveAddress(id, Va(pe.EntryPointRva), ct), mustSucceed: true);
            await Run(path, "read_bytes", "entry", ct => Native.ReadBytes(id, $"rva:0x{pe.EntryPointRva:X}", 4096, ct), mustSucceed: true);
            var head = new byte[6];
            if (pe.Read(pe.EntryPointRva, head) == head.Length && head[0] != 0)
                await Run(path, "search_bytes", "entry bytes", ct => Native.SearchBytes(id, Convert.ToHexString(head), cancellationToken: ct), mustSucceed: true);
        }
        await Run(path, "read_bytes", "image end", ct => Native.ReadBytes(id, $"rva:0x{pe.SizeOfImage - 1:X}", 65_536, ct), mustSucceed: true);
        await Run(path, "read_bytes", "headers", ct => Native.ReadBytes(id, "off:0", 512, ct), mustSucceed: pe.SizeOfImage > 0);
        await Run(path, "search_bytes", "text", ct => Native.SearchBytes(id, "dll", text: true, limit: 50, cancellationToken: ct), mustSucceed: true);
        await Run(path, "search_bytes", "wildcards", ct => Native.SearchBytes(id, "00 ?? ?? 00", limit: 10_000, cancellationToken: ct), mustSucceed: true);

        await Run(path, "list_resources", "", ct => Resources.ListResources(id, ct), mustSucceed: true);
        foreach (var r in pe.Resources.GroupBy(r => r.TypeName).Select(g => g.First()).Take(12))
        {
            var key = NativeResourceService.Key(r);
            await Run(path, "get_resource", key, ct => Resources.GetResource(id, key, cancellationToken: ct));
        }

        await Run(path, "list_cpp_classes", "", ct => Analysis.ListCppClasses(id, cancellationToken: ct), mustSucceed: true, limit: TimeSpan.FromSeconds(120));

        // Code tools: the first waits for the index.
        var limit = indexLimit ?? TimeSpan.FromSeconds(120);
        bool decoded = pe.Arch is NativeArch.X86 or NativeArch.X64;
        var listed = await Run(path, "list_functions", "", ct => CodeTools.ListFunctions(id, cancellationToken: ct), mustSucceed: true, limit: limit);
        var index = Code.Ready(native);
        if (listed == null || index == null) return;
        await Run(path, "list_functions", "sort size", ct => CodeTools.ListFunctions(id, sort: "size", limit: 50, cancellationToken: ct), mustSucceed: true);
        await Run(path, "list_functions", "sort callers", ct => CodeTools.ListFunctions(id, sort: "callers", limit: 50, cancellationToken: ct), mustSucceed: true);
        await Run(path, "search_native_strings", "", ct => CodeTools.SearchNativeStrings(id, cancellationToken: ct), mustSucceed: true);
        await Run(path, "search_native_strings", "regex", ct => CodeTools.SearchNativeStrings(id, "^[a-z]+\\.dll$", regex: true, cancellationToken: ct), mustSucceed: true);

        var functions = index.Functions;
        var targets = new List<(string Label, NativeFunction F)>();
        if (functions.Count > 0)
        {
            targets.Add(("first", functions[0]));
            targets.Add(("largest", functions.MaxBy(f => f.Size)!));
            targets.Add(("most called", functions.MaxBy(f => index.CountRefsTo(f.Start))!));
            targets.Add(("middle", functions[functions.Count / 2]));
        }
        if (pe.EntryPointRva != 0 && index.FunctionAt(pe.EntryPointRva) is { } entry) targets.Add(("entry", entry));
        foreach (var (label, f) in targets)
        {
            var at = Va(f.Start);
            await Run(path, "disassemble", label, ct => CodeTools.Disassemble(id, at, cancellationToken: ct), mustSucceed: decoded);
            await Run(path, "get_cfg", label, ct => CodeTools.GetCfg(id, at, cancellationToken: ct), mustSucceed: decoded);
            await Run(path, "find_xrefs", label, ct => CodeTools.FindXrefs(id, at, cancellationToken: ct), mustSucceed: true);
            await Run(path, "native_call_tree", label + " callees", ct => CodeTools.NativeCallTree(id, at, depth: 4, cancellationToken: ct), mustSucceed: true);
            await Run(path, "native_call_tree", label + " callers", ct => CodeTools.NativeCallTree(id, at, direction: "callers", depth: 4, cancellationToken: ct), mustSucceed: true);
            await Run(path, "resolve_address", label + " function", ct => Native.ResolveAddress(id, at, ct), mustSucceed: true);
        }
        if (functions.Count > 0 && functions[0].KnownName == null)
            await Run(path, "disassemble", "sub_ name", ct => CodeTools.Disassemble(id, functions[0].Name, cancellationToken: ct), mustSucceed: decoded);
        if (import != null)
            await Run(path, "find_xrefs", "import", ct => CodeTools.FindXrefs(id, $"{import.Module}!{import.Name}", cancellationToken: ct), mustSucceed: true);
        if (index.Strings.Count > 0)
        {
            var s = index.Strings[index.Strings.Count / 2];
            await Run(path, "find_xrefs", "string", ct => CodeTools.FindXrefs(id, Va(s.Rva), cancellationToken: ct), mustSucceed: true);
            await Run(path, "disassemble", "raw at string", ct => CodeTools.Disassemble(id, Va(s.Rva), function: false, maxInstructions: 64, cancellationToken: ct), mustSucceed: decoded);
        }
        // Arbitrary addresses: every section start and the last byte of the image.
        foreach (var section in pe.Sections.Take(16))
        {
            var at = $"rva:0x{section.Rva:X}";
            if (section.Rva >= pe.SizeOfImage) continue;
            await Run(path, "disassemble", "section " + section.Name, ct => CodeTools.Disassemble(id, at, cancellationToken: ct), mustSucceed: decoded);
            await Run(path, "find_xrefs", "section " + section.Name, ct => CodeTools.FindXrefs(id, at, cancellationToken: ct), mustSucceed: true);
            await Run(path, "get_cfg", "section " + section.Name, ct => CodeTools.GetCfg(id, at, cancellationToken: ct));
        }
        await Run(path, "disassemble", "image end", ct => CodeTools.Disassemble(id, $"rva:0x{pe.SizeOfImage - 1:X}", function: false, cancellationToken: ct), mustSucceed: decoded);

        if (ida && Engines.Providers[0].CheckAvailability().IsAvailable && pe.EntryPointRva != 0)
            await Run(path, "decompile_native", "entry", ct => Analysis.DecompileNative(id, Va(pe.EntryPointRva), cancellationToken: ct), limit: TimeSpan.FromMinutes(10));
    }

    /// <summary>Native PE files in a directory (not .NET); files that cannot be read or are not PE are skipped.</summary>
    public static IEnumerable<string> NativeFiles(string directory, bool recursive = false, long maxSize = PeLimits.MaxFileSize)
    {
        if (!Directory.Exists(directory)) yield break;
        var options = new EnumerationOptions { RecurseSubdirectories = recursive, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
        IEnumerable<string> files;
        try { files = Directory.EnumerateFiles(directory, "*", options).ToList(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { yield break; }
        foreach (var f in files)
        {
            var ext = Path.GetExtension(f).ToLowerInvariant();
            if (ext is not (".dll" or ".exe" or ".sys" or ".cpl" or ".ocx" or ".drv" or ".scr" or ".efi" or ".ax" or ".acm" or ".tsp" or ".mui")) continue;
            if (IsNativePe(f, maxSize)) yield return f;
        }
    }

    /// <summary>MZ / PE signature and no CLR header, read from the first 4 KB.</summary>
    public static bool IsNativePe(string path, long maxSize = PeLimits.MaxFileSize)
    {
        try
        {
            var info = new FileInfo(path);
            if (info.Length < 0x200 || info.Length > maxSize) return false;
            var head = new byte[4096];
            int n;
            using (var s = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) n = s.ReadAtLeast(head, head.Length, false);
            if (n < 0x40 || head[0] != 'M' || head[1] != 'Z') return false;
            int pe = BitConverter.ToInt32(head, 0x3C);
            if (pe <= 0 || pe + 0x18 + 0x70 > n || head[pe] != 'P' || head[pe + 1] != 'E' || head[pe + 2] != 0 || head[pe + 3] != 0) return false;
            int opt = pe + 0x18;
            ushort magic = BitConverter.ToUInt16(head, opt);
            int dirs = opt + (magic == 0x20B ? 0x70 : 0x60);
            int clr = dirs + 14 * 8;
            return clr + 8 > n || BitConverter.ToUInt32(head, clr) == 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }

    public void Dispose()
    {
        Workspace.Dispose();
        Engines.Dispose();
    }
}
