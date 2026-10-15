using Corvus.Services.Web;

namespace Corvus.Tests;

/// <summary>analyze_js view=diff: modules paired by path, normalized shape and strings across two builds.</summary>
public sealed class JsDiffTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private string Write(string name, string text)
    {
        var path = _dir.File(name);
        File.WriteAllText(path, text);
        return path;
    }

    [Fact]
    public void Renumbered_ids_pair_as_identical_and_changes_are_named()
    {
        var old = Write("old.js", """
            (()=>{var m={12:(e,t,n)=>{const a=n(34);e.exports=function(x){return a.render(x,"header")}},
            34:(e,t,n)=>{e.exports={render:(x,y)=>"<"+y+">"+x,name:"renderer",version:"1.0"}},
            56:(e,t,n)=>{e.exports=["gone","module","strings"]}};})();
            """);
        var @new = Write("new.js", """
            (()=>{var r={7:(o,i,s)=>{const c=s(9);o.exports=function(q){return c.render(q,"header")}},
            9:(o,i,s)=>{o.exports={render:(x,y)=>"<"+y+">"+x,name:"renderer",version:"1.1"}},
            99:(o,i,s)=>{o.exports="brand new"}};})();
            """);
        var d = JsDiff.Compare(old, @new, null, default);
        Assert.Equal((3, 3, 1, 1, 1, 1, 2), (d.OldModules, d.NewModules, d.Identical, d.Changed, d.Added, d.Removed, d.Renumbered));
        var changed = Assert.Single(d.Rows, r => r.Change == "changed");
        Assert.Equal(("34", "9", "strings"), (changed.OldId, changed.NewId, changed.Tier));
        Assert.Contains("+\"1.1\"", changed.Detail);
        var one = JsDiff.Compare(old, @new, "9", default);
        Assert.Contains("-\"1.0\"", one.TokenDiff);
        Assert.Contains("+\"1.1\"", one.TokenDiff);
        Assert.Equal(("12", "7", "shape"), JsDiff.Compare(old, @new, "identical", default).Rows.Select(r => (r.OldId!, r.NewId!, r.Tier!)).Single());
    }

    [Fact]
    public void Esbuild_paths_pair_by_name()
    {
        var old = Write("a.js", """var a=__commonJS({"src/util.js"(e,m){m.exports=1}});var b=__commonJS({"src/app.js"(e,m){m.exports=a()}});""");
        var @new = Write("b.js", """var x=__commonJS({"src/app.js"(e,m){m.exports=y()+1}});var y=__commonJS({"src/util.js"(e,m){m.exports=1}});""");
        var d = JsDiff.Compare(old, @new, null, default);
        Assert.Equal(("src/app.js", "path"), (Assert.Single(d.Rows).Name, d.Rows[0].Tier));
        Assert.Equal(1, d.Identical);
    }

    /// <summary>A mutated build compared with its original: rows or a typed error, never a crash.</summary>
    [Fact]
    [FuzzEntry(typeof(JsDiff))]
    public void Fuzzed_builds_never_throw()
    {
        var seed = System.Text.Encoding.UTF8.GetBytes("""(()=>{var m={12:(e,t,n)=>{const a=n(34);e.exports=a.x("one","two","three")},34:(e,t,n)=>{e.exports={x:(p,q,r)=>p+q+r}}};})();""");
        var old = Write("seed.js", System.Text.Encoding.UTF8.GetString(seed));
        var mutated = _dir.File("mutated.js");
        var failures = FormatFuzz.Run(seed, b =>
        {
            File.WriteAllBytes(mutated, b);
            try { JsDiff.Compare(old, mutated, null, default); }
            catch (Corvus.Core.ToolError) { }
        }, 150);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    /// <summary>Pairs of real bundle builds (a folder of folders, each with old.* and new.*): pairing rate and time.</summary>
    [RequiresRealDataFact(RealData.BundlePairs)]
    [Trait("Speed", "Slow")]
    public void Real_bundle_pairs()
    {
        foreach (var folder in Directory.EnumerateDirectories(RealData.Path(RealData.BundlePairs)))
        {
            var files = Directory.GetFiles(folder).Where(f => !f.EndsWith(".map", StringComparison.Ordinal)).ToList();
            var (old, @new) = (files.Single(f => Path.GetFileName(f).StartsWith("old.", StringComparison.Ordinal)), files.Single(f => Path.GetFileName(f).StartsWith("new.", StringComparison.Ordinal)));
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var d = JsDiff.Compare(old, @new, null, default);
            int paired = d.Identical + d.Changed;
            Console.WriteLine($"{Path.GetFileName(folder)} ({new FileInfo(old).Length / 1e6:0.0} + {new FileInfo(@new).Length / 1e6:0.0} MB): {d.OldModules} -> {d.NewModules}, " +
                              $"{d.Identical} identical, {d.Changed} changed, {d.Added} added, {d.Removed} removed, {d.Renumbered} renumbered; " +
                              $"paired {100.0 * paired / Math.Min(d.OldModules, d.NewModules):0.0}% of the smaller side in {sw.Elapsed.TotalSeconds:0.00} s");
        }
    }
}
