using Corvus.Services.Web;

namespace Corvus.Tests;

/// <summary>analyze_js view=runtime: the webpack 5 runtime's require name, helpers, chunk file names and async loads.</summary>
public sealed class JsRuntimeTests
{
    private const string Runtime = """
        (()=>{"use strict";var e,t={},r={};function o(e){var n=r[e];if(void 0!==n)return n.exports;var a=r[e]={exports:{}};return t[e].call(a.exports,a,a.exports,o),a.exports}
        o.m=t,o.d=(e,t)=>{},o.e=e=>Promise.all([]),o.u=e=>"static/js/"+({12:"settings",40:"admin"}[e]||e)+"."+{12:"a1b2c3",40:"d4e5f6",77:"0a0b0c"}[e]+".chunk.js",
        o.p="/app/";var n=self.webpackChunkdemo=self.webpackChunkdemo||[];
        Promise.all([o.e(12),o.e(77)]).then(o.bind(o,345));o.e(40).then(()=>o(678));})();
        """;

    [Fact]
    public void Webpack_runtime_names_chunks_and_async_loads()
    {
        var r = JsRuntime.Read(JsProgram.Build("runtime.js", Runtime, [], default)!, default);
        Assert.Equal(("o", "t", "/app/"), (r.Require, r.ModuleTable, r.PublicPath));
        Assert.Equal(["self.webpackChunkdemo"], r.ChunkGlobals);
        Assert.Equal(["12 static/js/settings.a1b2c3.chunk.js", "40 static/js/admin.d4e5f6.chunk.js", "77 static/js/77.0a0b0c.chunk.js"],
            r.Chunks.Select(c => $"{c.Id} {c.File}").Order(StringComparer.Ordinal));
        Assert.Contains("u: chunk file name", r.Helpers);
        Assert.Equal(["12,77 -> 345", "40 -> 678"], r.AsyncLoads.Select(l => $"{string.Join(",", l.Chunks)} -> {l.Module}"));
    }

    [Fact]
    public void Chunk_files_name_their_pushed_ids()
    {
        var r = JsRuntime.Read(JsProgram.Build("12.js", """(self.webpackChunkdemo=self.webpackChunkdemo||[]).push([[12,99],{345:(e,t,n)=>{}}]);""", [], default)!, default);
        Assert.Equal(["12", "99"], r.ChunkIds);
        Assert.Null(r.Require);
    }

    /// <summary>Real webpack 5 apps: every chunk file the runtime names exists beside it (the chunk map is right).</summary>
    [RequiresRealDataFact(RealData.WebpackApps)]
    [Trait("Speed", "Slow")]
    public void Real_runtimes_name_existing_chunk_files()
    {
        foreach (var app in Directory.EnumerateDirectories(RealData.Path(RealData.WebpackApps)))
        {
            var files = Directory.EnumerateFiles(app, "*.js", SearchOption.AllDirectories).ToList();
            foreach (var file in files)
            {
                var text = File.ReadAllText(file);
                if (!text.Contains(".u=", StringComparison.Ordinal) && !text.Contains(".u = ", StringComparison.Ordinal)) continue;
                if (JsProgram.Build(Path.GetFileName(file), text, [], default) is not { } p) continue;
                var r = JsRuntime.Read(p, default);
                if (r.Chunks.Count == 0) continue;
                var dir = Path.GetDirectoryName(file)!;
                int found = r.Chunks.Count(c => c.File != null && (File.Exists(Path.Combine(dir, c.File)) || File.Exists(Path.Combine(app, c.File))
                                                                   || files.Any(f => f.Replace('\\', '/').EndsWith("/" + c.File.TrimStart('.', '/'), StringComparison.Ordinal))));
                Console.WriteLine($"{Path.GetFileName(app)}/{Path.GetRelativePath(app, file)}: require {r.Require}, {r.ChunkGlobals.Count} global(s), public path {r.PublicPath}, " +
                                  $"{r.Chunks.Count} chunk(s), {r.Chunks.Count(c => c.File != null)} folded, {found} exist; {r.AsyncLoads.Count} async load(s)");
            }
        }
    }

    [Fact]
    [FuzzEntry(typeof(JsRuntime))]
    public void Fuzzed_runtimes_never_throw()
    {
        var failures = FormatFuzz.Run(System.Text.Encoding.UTF8.GetBytes(Runtime), b =>
        {
            if (JsProgram.Build("r.js", System.Text.Encoding.UTF8.GetString(b), [], default) is { } p) JsRuntime.Read(p, default);
        }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
