using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>view=wasm: a WebAssembly module's imports, exports, memories, functions, toolchain and custom sections.</summary>
internal sealed class WasmFileView : IFileSummaryView
{
    private const int MaxListed = 100;

    public sealed record Facts(int Version, string? Toolchain, IReadOnlyList<string> Producers, int ImportedFunctions, int DefinedFunctions, int Globals,
        IReadOnlyList<string> Memories, int DataSegments, IReadOnlyDictionary<string, int> ImportsByModule, IReadOnlyList<string> Imports,
        IReadOnlyList<string> Exports, int NamedFunctions, IReadOnlyList<string> Sections, IReadOnlyList<string> Issues);

    public string Name => "wasm";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (!WasmModule.IsWasm(file.Bytes)) return null;
        var m = WasmModule.Read(file.Bytes);
        var toolchain = Toolchain(m);
        var facts = new Facts(m.Version, toolchain, [.. m.Producers.Select(p => $"{p.Field}: {p.Value}")],
            m.Imports.Count(i => i.Kind == "func"), m.DefinedFunctions, m.Globals,
            [.. m.Memories.Select(x => $"{x.Min} pages" + (x.Max is { } max ? $" (max {max})" : ""))], m.DataSegments,
            m.Imports.GroupBy(i => i.Module ?? "").ToDictionary(g => g.Key, g => g.Count()),
            [.. m.Imports.Take(MaxListed).Select(i => $"{i.Module}.{i.Name} ({i.Kind})")],
            [.. m.Exports.Take(MaxListed).Select(e => $"{e.Name} ({e.Kind})")], m.FunctionNames.Count,
            [.. m.Sections.Select(s => $"{s.Name} ({s.Size:N0} bytes)")], m.Issues);
        var highlights = new List<string>
        {
            $"WebAssembly module: {m.DefinedFunctions:N0} functions, {m.Imports.Count} imports from {facts.ImportsByModule.Count} module(s), {m.Exports.Count} exports" +
            (toolchain != null ? $"; built by {toolchain}" : "") + ".",
        };
        if (m.FunctionNames.Count > 0) highlights.Add($"Name section: {m.FunctionNames.Count:N0} function names (debug names kept).");
        if (m.Issues.Count > 0) highlights.Add($"{m.Issues.Count} structure issue(s): {m.Issues[0]}.");
        return new FileView(facts, highlights);
    }

    /// <summary>The toolchain: the producers section first, else the import shapes each runtime is known by.</summary>
    private static string? Toolchain(WasmModule m)
    {
        var producers = m.Producers.Where(p => p.Field is "processed-by" or "language").Select(p => p.Value).ToList();
        if (producers.Count > 0) return string.Join(", ", producers.Take(4));
        bool Imports(Func<WasmSymbol, bool> test) => m.Imports.Any(test);
        if (Imports(i => i.Module is "go" or "gojs")) return "Go (syscall/js)";
        if (Imports(i => i.Name.StartsWith("__wbindgen", StringComparison.Ordinal) || i.Module?.Contains("wbg") == true)) return "Rust (wasm-bindgen)";
        if (Imports(i => i.Name.StartsWith("emscripten_", StringComparison.Ordinal) || i.Name.StartsWith("__syscall", StringComparison.Ordinal))) return "Emscripten";
        if (Imports(i => i.Module?.StartsWith("wasi_", StringComparison.Ordinal) == true)) return "WASI";
        return null;
    }
}
